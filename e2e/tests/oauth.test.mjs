// Social OAuth parity: the real provider code on both servers talks to the mock IdP
// (servers/mock-idp.mjs) and the redirect, callback, linking and id-token flows must
// produce identical transcripts.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startServers, startIdp, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

let idp;
let servers;
before(async () => {
  idp = await startIdp();
  servers = await startServers("oauth", { env: { IDP_URL: idp.base } });
});
after(async () => {
  await servers?.stop();
  idp?.stop();
});

const code = (profile) => "code-" + Buffer.from(JSON.stringify(profile)).toString("base64url");

/** Splits an authorization URL into origin, path and params with volatile values masked. */
function authURL(raw, base) {
  const u = new URL(raw);
  const params = {};
  for (const [k, v] of u.searchParams) {
    params[k] = ["state", "code_challenge", "nonce"].includes(k) ? `<${k}>` : v.split(base).join("<base>");
  }
  // deepEqual ignores key order, so the parameter sequence is recorded separately.
  return { endpoint: `${u.origin}${u.pathname}`, params, order: [...u.searchParams.keys()].join(",") };
}

async function startSocial(t, c, name, body) {
  const r = await record(t, name, c, () => c.client.signIn.social({ ...body, disableRedirect: true }));
  const url = r.data?.url;
  if (url) t[t.length - 1].data = { ...t[t.length - 1].data, url: authURL(url, c.server.base) };
  return url ? new URL(url).searchParams.get("state") : null;
}

async function idToken(claims) {
  const r = await fetch(`${idp.base}/__idp/id-token?claims=${encodeURIComponent(JSON.stringify(claims))}`);
  return (await r.json()).token;
}

test("github: redirect sign-in, callback, session, accounts, repeat sign-in", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const state = await startSocial(t, c, "sign-in/social github", { provider: "github", callbackURL: "/dashboard", newUserCallbackURL: "/welcome" });
    const profile = { id: 4242, name: "Octo Cat", email: "octo@example.com" };
    await recordFetch(t, "callback", c, `/callback/github?code=${code(profile)}&state=${encodeURIComponent(state)}`);
    await record(t, "get-session", c, () => c.client.getSession());
    await record(t, "list-accounts", c, () => c.client.listAccounts());
    const c2 = makeClient(server);
    const state2 = await startSocial(t, c2, "second sign-in", { provider: "github", callbackURL: "/dashboard", newUserCallbackURL: "/welcome" });
    await recordFetch(t, "second callback", c2, `/callback/github?code=${code(profile)}&state=${encodeURIComponent(state2)}`);
    await record(t, "second session", c2, () => c2.client.getSession());
  });
  assert.equal(t[1].status, 302);
  assert.equal(t[1].location, "/welcome");
  assert.equal(t[2].data.user.email, "octo@example.com");
  assert.equal(t[5].location, "/dashboard");
});

test("callback errors and validation", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await recordFetch(t, "missing state", c, "/callback/github?code=x");
    await recordFetch(t, "unknown state", c, "/callback/github?code=x&state=unknown");
    const s1 = await startSocial(t, c, "start with errorCallbackURL", { provider: "github", callbackURL: "/d", errorCallbackURL: "/oops" });
    await recordFetch(t, "provider error", c, `/callback/github?error=access_denied&error_description=denied&state=${encodeURIComponent(s1)}`);
    const s2 = await startSocial(t, c, "start", { provider: "github", callbackURL: "/d" });
    const other = makeClient(server);
    await recordFetch(t, "state cookie from other browser", other, `/callback/github?code=x&state=${encodeURIComponent(s2)}`);
    const s3 = await startSocial(t, c, "start again", { provider: "github", callbackURL: "/d" });
    await recordFetch(t, "bad code", c, `/callback/github?code=bogus&state=${encodeURIComponent(s3)}`);
    await record(t, "unknown provider", c, () => c.client.signIn.social({ provider: "nope", disableRedirect: true }));
    await startSocial(t, c, "additionalParams order", { provider: "github", callbackURL: "/d", additionalParams: { zeta: "1", 2: "two", alpha: "3", allow_signup: "false" } });
    await startSocial(t, c, "google additionalParams order", { provider: "google", callbackURL: "/d", additionalParams: { zeta: "1", access_type: "offline", include_granted_scopes: "false" } });
    await record(t, "untrusted callbackURL", c, () => c.client.signIn.social({ provider: "github", callbackURL: "http://evil.example.com", disableRedirect: true }));
    await recordFetch(t, "form_post callback", c, "/callback/github", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "code=abc&state=xyz",
    });
  });
});

test("link-social via callback, email mismatch, implicit linking", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "linker@example.com", password: "password1234", name: "Linker" }));
    const r = await record(t, "link-social", c, () => c.client.linkSocial({ provider: "github", callbackURL: "/linked", disableRedirect: true }));
    t[t.length - 1].data = { ...t[t.length - 1].data, url: authURL(r.data.url, c.server.base) };
    const state = new URL(r.data.url).searchParams.get("state");
    await recordFetch(t, "link callback", c, `/callback/github?code=${code({ id: 1, email: "linker@example.com" })}&state=${encodeURIComponent(state)}`);
    await record(t, "accounts after link", c, () => c.client.listAccounts());

    const r2 = await record(t, "link-social other email", c, () => c.client.linkSocial({ provider: "github", callbackURL: "/linked", disableRedirect: true }));
    t[t.length - 1].data = { ...t[t.length - 1].data, url: authURL(r2.data.url, c.server.base) };
    const state2 = new URL(r2.data.url).searchParams.get("state");
    await recordFetch(t, "mismatch callback", c, `/callback/github?code=${code({ id: 2, email: "someone@example.com" })}&state=${encodeURIComponent(state2)}`);

    // implicit linking: existing credential user, provider email unverified -> refused
    const c2 = makeClient(server);
    await record(t, "sign-up existing", c2, () => c2.client.signUp.email({ email: "exists@example.com", password: "password1234", name: "Exists" }));
    const c3 = makeClient(server);
    const s3 = await startSocial(t, c3, "start unverified", { provider: "github", callbackURL: "/d" });
    await recordFetch(t, "unverified implicit link", c3, `/callback/github?code=${code({ id: 3, email: "exists@example.com", verified: false })}&state=${encodeURIComponent(s3)}`);
    const s4 = await startSocial(t, c3, "start verified", { provider: "github", callbackURL: "/d" });
    await recordFetch(t, "verified provider, unverified local user", c3, `/callback/github?code=${code({ id: 3, email: "exists@example.com" })}&state=${encodeURIComponent(s4)}`);
    await record(t, "linked session", c3, () => c3.client.getSession());
  });
});

test("google: id-token sign-in and code flow", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const base = { iss: "https://accounts.google.com", aud: "google-client", email_verified: true };
    const tok = await idToken({ ...base, sub: "g-1", email: "g@example.com", name: "Gee", picture: "https://p/g.png", nonce: "n1" });
    await record(t, "id-token sign-in", c, () => c.client.signIn.social({ provider: "google", idToken: { token: tok, nonce: "n1" } }));
    await record(t, "id-token session", c, () => c.client.getSession());
    await record(t, "nonce mismatch", c, () => c.client.signIn.social({ provider: "google", idToken: { token: tok, nonce: "other" } }));
    const wrongAud = await idToken({ ...base, aud: "someone-else", sub: "g-2", email: "x@example.com" });
    await record(t, "wrong audience", c, () => c.client.signIn.social({ provider: "google", idToken: { token: wrongAud } }));
    await record(t, "id token unsupported", c, () => c.client.signIn.social({ provider: "github", idToken: { token: tok } }));

    const c2 = makeClient(server);
    const state = await startSocial(t, c2, "google redirect", { provider: "google", callbackURL: "/home" });
    await recordFetch(t, "google callback", c2, `/callback/google?code=${code({ sub: "g-3", email: "g3@example.com", name: "Gee Three" })}&state=${encodeURIComponent(state)}`);
    await record(t, "google session", c2, () => c2.client.getSession());
  });
});

const ALL_PROVIDERS = ["apple", "atlassian", "cloudflare", "cognito", "discord", "dropbox", "facebook", "figma", "github", "gitlab",
  "google", "huggingface", "kakao", "kick", "line", "linear", "linkedin", "microsoft", "naver", "notion", "paybin", "paypal",
  "polar", "railway", "reddit", "roblox", "salesforce", "slack", "spotify", "tiktok", "twitch", "twitter", "vercel", "vk",
  "wechat", "zoom"];

test("authorization URL parity for every provider", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    for (const provider of ALL_PROVIDERS) {
      await startSocial(t, c, `${provider} default`, { provider, callbackURL: "/d" });
      await startSocial(t, c, `${provider} scopes, loginHint, additionalParams`, {
        provider, callbackURL: "/d", scopes: ["extra.scope"], loginHint: "user@example.com",
        additionalParams: { zeta: "1", 2: "two", alpha: "3" },
      });
    }
  });
});
