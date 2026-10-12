// Core endpoint parity: every step runs through the official better-auth client against the
// Go server and the reference TypeScript server; normalised responses and Set-Cookie headers
// must be identical.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startServers, makeClient, dual, record, recordFetch, lastEmail } from "../lib/harness.mjs";

let servers;
before(async () => { servers = await startServers(""); });
after(async () => { await servers?.stop(); });

test("sign-up, get-session, sign-out", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "alice@example.com", password: "password1234", name: "Alice" }));
    await record(t, "get-session", c, () => c.client.getSession());
    await record(t, "duplicate sign-up", c, () => c.client.signUp.email({ email: "alice@example.com", password: "password1234", name: "Alice" }));
    await record(t, "sign-out", c, () => c.client.signOut());
    await record(t, "get-session after sign-out", c, () => c.client.getSession());
  });
  assert.equal(t[0].status, 200);
  assert.equal(t[1].data.user.email, "alice@example.com");
  assert.equal(t[2].error.code, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
  assert.equal(t[4].data, null);
});

test("sign-in validation and errors", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "bob@example.com", password: "password1234", name: "Bob" }));
    await record(t, "sign-out", c, () => c.client.signOut());
    await record(t, "wrong password", c, () => c.client.signIn.email({ email: "bob@example.com", password: "wrong-password" }));
    await record(t, "unknown user", c, () => c.client.signIn.email({ email: "nobody@example.com", password: "password1234" }));
    await record(t, "invalid email", c, () => c.client.signIn.email({ email: "not-an-email", password: "password1234" }));
    await record(t, "short password sign-up", c, () => c.client.signUp.email({ email: "short@example.com", password: "123", name: "S" }));
    await record(t, "missing name", c, () => c.client.signUp.email({ email: "noname@example.com", password: "password1234" }));
    await record(t, "sign-in ok", c, () => c.client.signIn.email({ email: "bob@example.com", password: "password1234" }));
    await record(t, "sign-in remember false", c, () => c.client.signIn.email({ email: "bob@example.com", password: "password1234", rememberMe: false }));
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "sign-in with callback", c, () => c.client.signIn.email({ email: "bob@example.com", password: "password1234", callbackURL: "/dashboard" }));
    await record(t, "untrusted callback", c, () => c.client.signIn.email({ email: "bob@example.com", password: "password1234", callbackURL: "http://evil.example.com" }));
  });
});

test("raw protocol: malformed JSON, media types, 404s, trailing slash, ok, disabled methods", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await recordFetch(t, "invalid json", c, "/sign-in/email", { method: "POST", headers: { "content-type": "application/json" }, body: "{bad" });
    await recordFetch(t, "text body", c, "/sign-in/email", { method: "POST", headers: { "content-type": "text/plain" }, body: "hello" });
    await recordFetch(t, "form body", c, "/sign-in/email", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "email=x%40example.com&password=password1234" });
    await recordFetch(t, "no body", c, "/sign-in/email", { method: "POST" });
    await recordFetch(t, "unknown path", c, "/does-not-exist", {});
    await recordFetch(t, "trailing slash", c, "/ok/", {});
    await recordFetch(t, "double slash", c, "//ok", {});
    await recordFetch(t, "wrong method", c, "/sign-in/email", {});
    await recordFetch(t, "ok", c, "/ok", {});
    await recordFetch(t, "get-session POST without defer", c, "/get-session", { method: "POST" });
    await recordFetch(t, "update-user unauthenticated", c, "/update-user", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  });
});

test("update-user, change-password, sessions", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const c2 = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "carol@example.com", password: "password1234", name: "Carol" }));
    await record(t, "second device", c2, () => c2.client.signIn.email({ email: "carol@example.com", password: "password1234" }));
    await record(t, "update name", c, () => c.client.updateUser({ name: "Carol Updated", image: "https://img.example.com/c.png" }));
    await record(t, "update email rejected", c, () => c.client.updateUser({ email: "x@example.com" }));
    await record(t, "update nothing", c, () => c.client.updateUser({}));
    await record(t, "session after update", c, () => c.client.getSession());
    await record(t, "list sessions", c, () => c.client.listSessions());
    await record(t, "change password wrong current", c, () => c.client.changePassword({ currentPassword: "nope-nope", newPassword: "newpassword123" }));
    await record(t, "change password revoke others", c, () => c.client.changePassword({ currentPassword: "password1234", newPassword: "newpassword123", revokeOtherSessions: true }));
    await record(t, "other device session revoked", c2, () => c2.client.getSession());
    await record(t, "sign-in new password", c2, () => c2.client.signIn.email({ email: "carol@example.com", password: "newpassword123" }));
    await record(t, "revoke other sessions", c, () => c.client.revokeOtherSessions());
    await record(t, "other device after revoke", c2, () => c2.client.getSession());
    await record(t, "update-session no fields", c, () => c.client.updateSession({}));
    await record(t, "revoke sessions", c, () => c.client.revokeSessions());
    await record(t, "session after revoke all", c, () => c.client.getSession());
  });
});

test("password reset flow", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "dave@example.com", password: "password1234", name: "Dave" }));
    await record(t, "request reset", c, () => c.client.requestPasswordReset({ email: "dave@example.com", redirectTo: "/reset" }));
    await record(t, "request reset unknown", c, () => c.client.requestPasswordReset({ email: "ghost@example.com" }));
    await record(t, "request reset bad redirect", c, () => c.client.requestPasswordReset({ email: "dave@example.com", redirectTo: "http://evil.example.com/x" }));
    const mail = await lastEmail(server, "dave@example.com", "reset-password");
    t.push({ name: "reset email url", url: mail.url.replace(server.base, "<base>").replace(/reset-password\/[A-Za-z0-9]+/, "reset-password/<token>") });
    const cbPath = new URL(mail.url).pathname.replace("/api/auth", "") + new URL(mail.url).search;
    await recordFetch(t, "reset callback", c, cbPath, {});
    await recordFetch(t, "reset callback bad token", c, "/reset-password/badtoken?callbackURL=%2Freset", {});
    await record(t, "reset short password", c, () => c.client.resetPassword({ newPassword: "x", token: mail.token }));
    await record(t, "reset", c, () => c.client.resetPassword({ newPassword: "brandnewpass1", token: mail.token }));
    await record(t, "reset reuse token", c, () => c.client.resetPassword({ newPassword: "brandnewpass1", token: mail.token }));
    await record(t, "sign-in new password", c, () => c.client.signIn.email({ email: "dave@example.com", password: "brandnewpass1" }));
  });
});

test("email verification flow", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "erin@example.com", password: "password1234", name: "Erin" }));
    const mail = await lastEmail(server, "erin@example.com", "verify-email");
    t.push({ name: "verify url", url: normalizeURL(mail.url, server.base) });
    await record(t, "send verification (session)", c, () => c.client.sendVerificationEmail({ email: "erin@example.com", callbackURL: "/verified" }));
    await record(t, "send verification mismatch", c, () => c.client.sendVerificationEmail({ email: "other@example.com" }));
    await record(t, "verify bad token", c, () => c.client.verifyEmail({ query: { token: "bad.token.value" } }));
    await recordFetch(t, "verify bad token with callback", c, "/verify-email?token=bad&callbackURL=%2Fdone", {});
    await record(t, "verify", c, () => c.client.verifyEmail({ query: { token: mail.token } }));
    await record(t, "session verified", c, () => c.client.getSession());
    await record(t, "verify again", c, () => c.client.verifyEmail({ query: { token: mail.token } }));
    await record(t, "send verification already verified", c, () => c.client.sendVerificationEmail({ email: "erin@example.com" }));
  });
});

test("change email and delete user", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "frank@example.com", password: "password1234", name: "Frank" }));
    await record(t, "change email same", c, () => c.client.changeEmail({ newEmail: "frank@example.com" }));
    await record(t, "change email", c, () => c.client.changeEmail({ newEmail: "frank2@example.com", callbackURL: "/changed" }));
    const mail = await lastEmail(server, "frank2@example.com", "verify-email");
    t.push({ name: "change email verification url", url: normalizeURL(mail.url, server.base) });
    await recordFetch(t, "verify change email", c, `/verify-email?token=${mail.token}&callbackURL=%2Fchanged`, {});
    await record(t, "session after change", c, () => c.client.getSession());
    await record(t, "delete user wrong password", c, () => c.client.deleteUser({ password: "bad-password" }));
    await record(t, "delete user", c, () => c.client.deleteUser({ password: "password1234" }));
    await record(t, "session after delete", c, () => c.client.getSession());
    await record(t, "sign-in deleted", c, () => c.client.signIn.email({ email: "frank2@example.com", password: "password1234" }));
  });
});

test("accounts", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "gina@example.com", password: "password1234", name: "Gina" }));
    const accounts = await record(t, "list accounts", c, () => c.client.listAccounts());
    await record(t, "unlink last account", c, () => c.client.unlinkAccount({ accountId: accounts.data[0].id }));
    await record(t, "unlink unknown", c, () => c.client.unlinkAccount({ accountId: "nope" }));
    await record(t, "link unknown provider", c, () => c.client.linkSocial({ provider: "unknown-provider" }));
    await record(t, "access token unknown account", c, () => c.client.getAccessToken({ accountId: "nope" }));
    await record(t, "access token bad body", c, () => c.$fetch ? null : c.client.$fetch("/get-access-token", { method: "POST", body: { foo: 1 } }));
    await record(t, "account info unknown", c, () => c.client.accountInfo({ query: { accountId: "nope" } }));
  });
});

test("CSRF / origin protection", async () => {
  await dual(servers, async (server, t) => {
    const good = makeClient(server);
    await record(t, "sign-up", good, () => good.client.signUp.email({ email: "hank@example.com", password: "password1234", name: "Hank" }));
    const evil = makeClient(server, { origin: "http://evil.example.com" });
    for (const [k, v] of good.jar.cookies) evil.jar.set(k, v);
    await record(t, "cross-origin update with cookies", evil, () => evil.client.updateUser({ name: "pwned" }));
    const trusted = makeClient(server, { origin: "http://trusted.example.com" });
    for (const [k, v] of good.jar.cookies) trusted.jar.set(k, v);
    await record(t, "trusted origin update", trusted, () => trusted.client.updateUser({ name: "Hank 2" }));
    const noOrigin = makeClient(server, { origin: null });
    for (const [k, v] of good.jar.cookies) noOrigin.jar.set(k, v);
    await record(t, "missing origin with cookies", noOrigin, () => noOrigin.client.updateUser({ name: "x" }));
    const crossNav = makeClient(server, { origin: null });
    await recordFetch(t, "cross-site navigation sign-in", crossNav, "/sign-in/email", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate" },
      body: "email=hank%40example.com&password=password1234",
    });
    await recordFetch(t, "error page", good, "/error?error=SOMETHING_BAD&error_description=%3Cb%3Ehi%3C%2Fb%3E", {});
  });
});

function normalizeURL(u, base) {
  return u.split(base).join("<base>").replace(/token=[^&]+/, "token=<token>");
}
