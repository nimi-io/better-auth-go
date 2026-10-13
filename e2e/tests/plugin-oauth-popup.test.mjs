// oauth-popup parity: /oauth-popup/start redirects to the (generic) provider and the
// callback renders the completion page carrying the bearer token for the opener.
import { test, before, after } from "node:test";
import { oauthPopupClient } from "better-auth/client/plugins";
import { startServers, startIdp, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let idp;
let servers;
before(async () => {
  idp = await startIdp();
  servers = await startServers("oauth-popup", { env: { IDP_URL: idp.base } });
});
after(async () => {
  await servers?.stop();
  idp?.stop();
});

const code = (profile) => "code-" + Buffer.from(JSON.stringify(profile)).toString("base64url");

function normalizePage(text, base) {
  return text.split(base).join("<base>").replace(/"token":"[^"]+"/, '"token":"<token>"');
}

test("oauth-popup: start, completion page, bearer token, errors", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins: [oauthPopupClient()] });
    const q = (extra = "") => `/oauth-popup/start?provider=oidc&popupOrigin=${encodeURIComponent(server.base)}&popupNonce=n1&callbackURL=${encodeURIComponent(server.base + "/dashboard")}${extra}`;
    const s = await recordFetch(t, "start", c, q());
    const loc = new URL(s.res.headers.get("location"));
    t[t.length - 1].location = `${loc.origin}${loc.pathname}`.split(idp.base).join("<idp>");
    const cb = await recordFetch(t, "callback", c, `/callback/oidc?code=${code({ sub: "pop-1", email: "popup@example.com", email_verified: true, nonce: loc.searchParams.get("nonce") })}&state=${encodeURIComponent(loc.searchParams.get("state"))}`);
    const last = t[t.length - 1];
    last.data = normalizePage(String(cb.data), server.base);
    last.headers = { ct: cb.res.headers.get("content-type"), csp: cb.res.headers.get("content-security-policy"), cache: cb.res.headers.get("cache-control") };
    const token = /"token":"([^"]+)"/.exec(String(cb.data))?.[1];
    const bearer = makeClient(server);
    await record(t, "bearer session", bearer, () => bearer.client.getSession({ fetchOptions: { headers: { authorization: `Bearer ${token}` } } }));

    const s2 = await recordFetch(t, "start for error", c, q());
    const loc2 = new URL(s2.res.headers.get("location"));
    t[t.length - 1].location = "<idp>";
    const err = await recordFetch(t, "error relayed", c, `/callback/oidc?error=access_denied&error_description=nope&state=${encodeURIComponent(loc2.searchParams.get("state"))}`);
    t[t.length - 1].data = normalizePage(String(err.data), server.base);
    const unknown = await recordFetch(t, "unknown provider", c, `/oauth-popup/start?provider=nope&popupOrigin=${encodeURIComponent(server.base)}&popupNonce=n2`);
    t[t.length - 1].data = normalizePage(String(unknown.data), server.base);
    const bad = await recordFetch(t, "untrusted callbackURL", c, q().replace(encodeURIComponent(server.base + "/dashboard"), encodeURIComponent("https://evil.example.com")));
    t[t.length - 1].data = normalizePage(String(bad.data), server.base);
    await recordFetch(t, "untrusted popup origin", c, `/oauth-popup/start?provider=oidc&popupOrigin=${encodeURIComponent("https://evil.example.com")}`);
    await recordFetch(t, "missing provider", c, `/oauth-popup/start?popupOrigin=${encodeURIComponent(server.base)}`);
  });
});
