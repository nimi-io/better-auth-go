// generic-oauth parity: config-driven providers (OIDC discovery and plain OAuth 2.0) on both
// servers talk to the mock IdP's generic issuer (servers/mock-idp.mjs /oidc).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startServers, startIdp, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let idp;
let servers;
before(async () => {
  idp = await startIdp();
  servers = await startServers("generic-oauth", { env: { IDP_URL: idp.base } });
});
after(async () => {
  await servers?.stop();
  idp?.stop();
});

const code = (profile) => "code-" + Buffer.from(JSON.stringify(profile)).toString("base64url");

function authURL(raw, base) {
  const u = new URL(raw);
  const params = {};
  for (const [k, v] of u.searchParams) {
    params[k] = ["state", "code_challenge", "nonce"].includes(k) ? `<${k}>` : v.split(base).join("<base>").split(idp.base).join("<idp>");
  }
  return { endpoint: `${u.origin}${u.pathname}`.split(idp.base).join("<idp>"), params, order: [...u.searchParams.keys()].join(",") };
}

async function start(t, c, name, body) {
  const r = await record(t, name, c, () => c.client.signIn.social({ ...body, disableRedirect: true }));
  const url = r.data?.url;
  if (url) t[t.length - 1].data = { ...t[t.length - 1].data, url: authURL(url, c.server.base) };
  return url ? new URL(url) : null;
}

async function idToken(claims) {
  const r = await fetch(`${idp.base}/__idp/id-token?claims=${encodeURIComponent(JSON.stringify(claims))}`);
  return (await r.json()).token;
}

test("generic-oauth: OIDC discovery sign-in, session, accounts, tokens", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const u = await start(t, c, "sign-in oidc", { provider: "oidc", callbackURL: "/dashboard", newUserCallbackURL: "/welcome", scopes: ["extra"] });
    const profile = { sub: "oidc-user-1", email: "oidc@example.com", name: "Oidc User", email_verified: true, nonce: u.searchParams.get("nonce") };
    await recordFetch(t, "callback", c, `/callback/oidc?code=${code(profile)}&state=${encodeURIComponent(u.searchParams.get("state"))}`);
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "accounts", c, () => c.client.listAccounts());
    await record(t, "get-access-token", c, () => c.client.getAccessToken({ providerId: "oidc" }));
    await record(t, "refresh-token", c, () => c.client.refreshToken({ providerId: "oidc" }));
    await record(t, "account-info", c, () => c.client.accountInfo({ query: {} }).catch(() => null));
    // second sign-in reuses the account
    const c2 = makeClient(server);
    const u2 = await start(t, c2, "second sign-in", { provider: "oidc", callbackURL: "/dashboard", newUserCallbackURL: "/welcome" });
    await recordFetch(t, "second callback", c2, `/callback/oidc?code=${code({ ...profile, nonce: u2.searchParams.get("nonce") })}&state=${encodeURIComponent(u2.searchParams.get("state"))}`);
    await record(t, "second session", c2, () => c2.client.getSession());
    await record(t, "sign-out", c2, () => c2.client.signOut());
    const mask = (v) => typeof v === "string" ? v.replace(/id_token_hint=[^&]+/, "id_token_hint=<jwt>").split(idp.base).join("<idp>").split(encodeURIComponent(server.base)).join("<base>") : v;
    const last = t[t.length - 1];
    last.location = mask(last.location);
    if (last.data?.url) last.data = { ...last.data, url: mask(last.data.url) };
    await record(t, "signed out", c2, () => c2.client.getSession());
  });
  assert.equal(t[1].location, "/welcome");
  assert.equal(t[2].data.user.email, "oidc@example.com");
});

test("generic-oauth: id-token claims, nonce binding and error redirects", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const u = await start(t, c, "sign-in with id token claims", { provider: "oidc", callbackURL: "/d", errorCallbackURL: "/oops" });
    const p = { sub: "oidc-claims", nonce: u.searchParams.get("nonce"), idTokenClaims: { email: "claims@example.com", email_verified: true, name: "Claims" } };
    await recordFetch(t, "callback", c, `/callback/oidc?code=${code(p)}&state=${encodeURIComponent(u.searchParams.get("state"))}`);
    await record(t, "session", c, () => c.client.getSession());

    const c2 = makeClient(server);
    const u2 = await start(t, c2, "nonce mismatch start", { provider: "oidc", callbackURL: "/d", errorCallbackURL: "/oops" });
    await recordFetch(t, "nonce mismatch", c2, `/callback/oidc?code=${code({ sub: "x", email: "x@example.com", nonce: "wrong" })}&state=${encodeURIComponent(u2.searchParams.get("state"))}`);
    const u3 = await start(t, c2, "missing email start", { provider: "oidc", callbackURL: "/d", errorCallbackURL: "/oops" });
    await recordFetch(t, "missing email", c2, `/callback/oidc?code=${code({ sub: "no-email", nonce: u3.searchParams.get("nonce") })}&state=${encodeURIComponent(u3.searchParams.get("state"))}`);
    const u4 = await start(t, c2, "missing subject start", { provider: "oidc", callbackURL: "/d", errorCallbackURL: "/oops" });
    await recordFetch(t, "missing subject", c2, `/callback/oidc?code=${code({ email: "nosub@example.com", nonce: u4.searchParams.get("nonce") })}&state=${encodeURIComponent(u4.searchParams.get("state"))}`);
    const u5 = await start(t, c2, "signup disabled start", { provider: "oidc-nosignup", callbackURL: "/d", errorCallbackURL: "/oops" });
    await recordFetch(t, "signup disabled", c2, `/callback/oidc-nosignup?code=${code({ sub: "ns", email: "ns@example.com", email_verified: true, nonce: u5.searchParams.get("nonce") })}&state=${encodeURIComponent(u5.searchParams.get("state"))}`);
    const u6 = await start(t, c2, "signup requested start", { provider: "oidc-nosignup", callbackURL: "/d", requestSignUp: true });
    await recordFetch(t, "signup requested", c2, `/callback/oidc-nosignup?code=${code({ sub: "ns2", email: "ns2@example.com", email_verified: true, nonce: u6.searchParams.get("nonce") })}&state=${encodeURIComponent(u6.searchParams.get("state"))}`);
    await recordFetch(t, "missing state", c2, "/callback/oidc?code=abc");
    await recordFetch(t, "unknown state", c2, "/callback/oidc?code=abc&state=bogus");
    await record(t, "unknown provider", c2, () => c2.client.signIn.social({ provider: "nope", disableRedirect: true }));
  });
});

test("generic-oauth: client-submitted id token and plain OAuth 2.0 provider", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const iss = `${idp.base}/oidc`;
    const tok = await idToken({ iss, aud: "oidc-client", sub: "front-1", email: "front@example.com", email_verified: true, name: "Front" });
    await record(t, "id token sign-in", c, () => c.client.signIn.social({ provider: "oidc", idToken: { token: tok } }));
    await record(t, "id token session", c, () => c.client.getSession());
    const bad = await idToken({ iss, aud: "someone-else", sub: "front-2", email: "f2@example.com" });
    await record(t, "wrong audience", c, () => c.client.signIn.social({ provider: "oidc", idToken: { token: bad } }));
    await record(t, "plain has no id token support", c, () => c.client.signIn.social({ provider: "plain", idToken: { token: tok } }));

    const c2 = makeClient(server);
    const u = await start(t, c2, "plain sign-in", { provider: "plain", callbackURL: "/home", loginHint: "p@example.com", additionalParams: { zeta: "1", alpha: "2" } });
    await recordFetch(t, "plain callback", c2, `/callback/plain?code=${code({ id: 4242, email: "Plain@Example.com", display_name: "Plain Person", email_verified: true })}&state=${encodeURIComponent(u.searchParams.get("state"))}`);
    await record(t, "plain session", c2, () => c2.client.getSession());
    await record(t, "plain accounts", c2, () => c2.client.listAccounts());
  });
});

test("generic-oauth: link-social and unlink", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "linker@example.com", password: "password1234", name: "Linker" }));
    const r = await record(t, "link-social", c, () => c.client.linkSocial({ provider: "oidc", callbackURL: "/linked", disableRedirect: true }));
    t[t.length - 1].data = { ...t[t.length - 1].data, url: authURL(r.data.url, c.server.base) };
    const u = new URL(r.data.url);
    await recordFetch(t, "link callback", c, `/callback/oidc?code=${code({ sub: "link-1", email: "linker@example.com", email_verified: true, nonce: u.searchParams.get("nonce") })}&state=${encodeURIComponent(u.searchParams.get("state"))}`);
    const accs = await record(t, "accounts after link", c, () => c.client.listAccounts());
    const linked = accs.data.find((a) => a.providerId === "oidc");
    await record(t, "unlink", c, () => c.client.unlinkAccount({ providerId: "oidc", accountId: linked.accountId }));
    await record(t, "accounts after unlink", c, () => c.client.listAccounts());
  });
});
