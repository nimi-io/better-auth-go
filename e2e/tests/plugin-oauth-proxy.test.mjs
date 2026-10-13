// oauth-proxy parity: sign-in packs the OAuth state for the production callback, the
// callback forwards an encrypted profile to the preview deployment's
// /callback/:id/oauth-proxy, which creates the session.
import { test, before, after } from "node:test";
import { startServers, startIdp, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let idp;
let servers;
before(async () => {
  idp = await startIdp();
  servers = await startServers("oauth-proxy", { env: { IDP_URL: idp.base } });
});
after(async () => {
  await servers?.stop();
  idp?.stop();
});

const code = (profile) => "code-" + Buffer.from(JSON.stringify(profile)).toString("base64url");

function maskURL(raw, base) {
  const u = new URL(raw);
  const params = {};
  for (const [k, v] of u.searchParams) {
    params[k] = ["state", "code_challenge", "nonce", "profile"].includes(k) ? `<${k}>` : v.split(base).join("<base>");
  }
  return { endpoint: `${u.origin}${u.pathname}`.split(base).join("<base>"), params };
}

test("oauth-proxy: passthrough sign-in through the proxy callback", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const r = await record(t, "sign-in google", c, () => c.client.signIn.social({ provider: "google", callbackURL: "/dashboard", newUserCallbackURL: "/welcome", disableRedirect: true }));
    t[t.length - 1].data = { ...t[t.length - 1].data, url: maskURL(r.data.url, server.base) };
    const state = new URL(r.data.url).searchParams.get("state");
    const cb = await recordFetch(t, "provider callback", c, `/callback/google?code=${code({ sub: "g-proxy", email: "proxy@example.com", name: "Proxy User" })}&state=${encodeURIComponent(state)}`);
    const loc = cb.res.headers.get("location");
    t[t.length - 1].location = maskURL(loc, server.base);
    const proxied = new URL(loc);
    await recordFetch(t, "proxy completion", c, `/callback/google/oauth-proxy${proxied.search}`);
    await record(t, "session", c, () => c.client.getSession());
    await recordFetch(t, "replay is rejected", c, `/callback/google/oauth-proxy${proxied.search}`);
    await recordFetch(t, "provider mismatch", makeClient(server), `/callback/github/oauth-proxy${proxied.search}`);
  });
});

test("oauth-proxy: invalid payloads and legacy endpoint", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await recordFetch(t, "missing profile", c, "/oauth-proxy-callback?callbackURL=%2Fdashboard");
    await recordFetch(t, "invalid profile", c, "/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=garbage");
    await recordFetch(t, "missing callbackURL", c, "/oauth-proxy-callback?profile=garbage");
    await recordFetch(t, "untrusted callbackURL", c, "/oauth-proxy-callback?callbackURL=https%3A%2F%2Fevil.example.com&profile=x");
    await recordFetch(t, "completion invalid profile", c, "/callback/google/oauth-proxy?callbackURL=%2Fd&profile=bad");
    await recordFetch(t, "regular state falls back", c, "/callback/google?code=x&state=not-a-package");
    const skip = await c.fetch(`${server.base}/api/auth/sign-in/social`, {
      method: "POST", headers: { "content-type": "application/json", "x-skip-oauth-proxy": "1" },
      body: JSON.stringify({ provider: "google", callbackURL: "/dashboard", disableRedirect: true }),
    });
    const body = await skip.json();
    const u = new URL(body.url);
    t.push({ name: "skip header keeps plain state", status: skip.status, stateLength: u.searchParams.get("state").length,
      redirect_uri: u.searchParams.get("redirect_uri").split(server.base).join("<base>") });
  });
});
