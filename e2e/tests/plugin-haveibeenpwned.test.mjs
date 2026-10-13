// haveibeenpwned plugin parity; both servers answer the k-anonymity range API in-process.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startServers, makeClient, dual, record } from "../lib/harness.mjs";

let servers;
before(async () => { servers = await startServers("haveibeenpwned", { envFor: { go: { MIGRATE: "1" } } }); });
after(async () => { await servers?.stop(); });

const lastRange = async (server) => (await fetch(`${server.base}/__test/pwned`)).json();

test("haveibeenpwned: sign-up, change-password and reset are checked", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server);
    await record(t, "sign-up breached", c, () => c.client.signUp.email({ email: "hibp@example.com", password: "password123", name: "H" }));
    t.push({ name: "range request", req: await lastRange(server) });
    await record(t, "sign-up safe", c, () => c.client.signUp.email({ email: "hibp@example.com", password: "a-very-safe-passphrase", name: "H" }));
    await record(t, "change to breached", c, () => c.client.changePassword({ currentPassword: "a-very-safe-passphrase", newPassword: "breached-password" }));
    await record(t, "change to safe", c, () => c.client.changePassword({ currentPassword: "a-very-safe-passphrase", newPassword: "another-safe-passphrase" }));
    await record(t, "sign-in breached (not checked)", c, () => c.client.signIn.email({ email: "hibp@example.com", password: "password123" }));
    await record(t, "request reset", c, () => c.client.requestPasswordReset({ email: "hibp@example.com" }));
    const mail = await (await fetch(`${server.base}/__test/email?to=hibp@example.com&type=reset-password`)).json();
    await record(t, "reset to breached", c, () => c.client.resetPassword({ token: mail.token, newPassword: "breached-password" }));
    await record(t, "reset invalid token breached", c, () => c.client.resetPassword({ token: "nope", newPassword: "breached-password" }));
  });
});
