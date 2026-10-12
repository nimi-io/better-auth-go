// Parity for alternative configurations: secondary storage, rate limiting, stateless mode
// and email-verified account deletion.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { startServers, makeClient, dual, record, recordFetch, lastEmail } from "../lib/harness.mjs";

const running = [];
after(async () => { for (const s of running) await s.stop(); });

test("secondary storage sessions", async () => {
  const servers = await startServers("secondary");
  running.push(servers);
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    const c2 = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "ss@example.com", password: "password1234", name: "SS" }));
    await record(t, "sign-in second", c2, () => c2.client.signIn.email({ email: "ss@example.com", password: "password1234" }));
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "list sessions", c, () => c.client.listSessions());
    await record(t, "update user", c, () => c.client.updateUser({ name: "SS Updated" }));
    await record(t, "second sees updated user", c2, () => c2.client.getSession());
    await record(t, "request reset", c, () => c.client.requestPasswordReset({ email: "ss@example.com" }));
    const mail = await lastEmail(server, "ss@example.com", "reset-password");
    await record(t, "reset", c, () => c.client.resetPassword({ newPassword: "otherpassword1", token: mail.token }));
    await record(t, "reset reuse", c, () => c.client.resetPassword({ newPassword: "otherpassword1", token: mail.token }));
    await record(t, "revoke other sessions", c, () => c.client.revokeOtherSessions());
    await record(t, "second revoked", c2, () => c2.client.getSession());
    await record(t, "sign-out", c, () => c.client.signOut());
    await record(t, "signed out", c, () => c.client.getSession());
  });
});

test("rate limiting", async () => {
  const servers = await startServers("ratelimit");
  running.push(servers);
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server);
    for (let i = 0; i < 4; i++) {
      await recordFetch(t, `sign-in attempt ${i + 1}`, c, "/sign-in/email", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "10.0.0.1" },
        body: JSON.stringify({ email: "rl@example.com", password: "password1234" }),
      });
    }
    await recordFetch(t, "other ip allowed", c, "/sign-in/email", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "10.0.0.2" },
      body: JSON.stringify({ email: "rl@example.com", password: "password1234" }),
    });
    await recordFetch(t, "ok not limited by sign-in rule", c, "/ok", { headers: { "x-forwarded-for": "10.0.0.1" } });
  });
  assert.equal(t[3].status, 429);
  assert.deepEqual(t[3].data, { message: "Too many requests. Please try again later." });
});

test("stateless mode (no database)", async () => {
  const servers = await startServers("stateless");
  running.push(servers);
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "get-session empty", c, () => c.client.getSession());
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "nodb@example.com", password: "password1234", name: "NoDB" }));
    await record(t, "get-session", c, () => c.client.getSession());
    await record(t, "sign-out", c, () => c.client.signOut());
  }, { imageNullEqualsAbsent: true });
});

test("delete user with email verification", async () => {
  const servers = await startServers("delete-verify");
  running.push(servers);
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "del@example.com", password: "password1234", name: "Del" }));
    await record(t, "request delete", c, () => c.client.deleteUser({ callbackURL: "/goodbye" }));
    const mail = await lastEmail(server, "del@example.com", "delete-account");
    t.push({ name: "delete url", url: mail.url.split(server.base).join("<base>").replace(/token=[^&]+/, "token=<token>") });
    await recordFetch(t, "delete callback bad token", c, "/delete-user/callback?token=nope", {});
    await recordFetch(t, "delete callback", c, `/delete-user/callback?token=${mail.token}&callbackURL=%2Fgoodbye`, {});
    await record(t, "session gone", c, () => c.client.getSession());
  });
});
