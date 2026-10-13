// username plugin parity through the official usernameClient.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { usernameClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

const plugins = [usernameClient()];
let servers;
before(async () => { servers = await startServers("username", { envFor: { go: { MIGRATE: "1" } } }); });
after(async () => { await servers?.stop(); });

test("username: sign-up, sign-in, availability, updates and errors", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const c2 = makeClient(server, { plugins });
    await record(t, "sign-up with username", c, () => c.client.signUp.email({ email: "un1@example.com", password: "password1234", name: "U1", username: "Alice_01" }));
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "sign-up display only", c2, () => c2.client.signUp.email({ email: "un2@example.com", password: "password1234", name: "U2", displayUsername: "Bob.Two" }));
    await record(t, "sign-up invalid display only", c2, () => c2.client.signUp.email({ email: "un3@example.com", password: "password1234", name: "U3", displayUsername: "Not Valid" }));
    await record(t, "duplicate username", c2, () => c2.client.signUp.email({ email: "un4@example.com", password: "password1234", name: "U4", username: "ALICE_01" }));
    await record(t, "too short", c2, () => c2.client.signUp.email({ email: "un5@example.com", password: "password1234", name: "U5", username: "abc" }));
    await record(t, "invalid chars", c2, () => c2.client.signUp.email({ email: "un6@example.com", password: "password1234", name: "U6", username: "bad name" }));
    await record(t, "empty username", c2, () => c2.client.signUp.email({ email: "un7@example.com", password: "password1234", name: "U7", username: "", displayUsername: "fine_name" }));
    await record(t, "available taken", c2, () => c2.client.isUsernameAvailable({ username: "alice_01" }));
    await record(t, "available free", c2, () => c2.client.isUsernameAvailable({ username: "someone_new" }));
    await record(t, "available too long", c2, () => c2.client.isUsernameAvailable({ username: "x".repeat(31) }));
    await record(t, "available invalid", c2, () => c2.client.isUsernameAvailable({ username: "no way!" }));
    await record(t, "sign-out", c, () => c.client.signOut());
    await record(t, "sign-in username", c, () => c.client.signIn.username({ username: "Alice_01", password: "password1234" }));
    await record(t, "sign-in callbackURL", c, () => c.client.signIn.username({ username: "alice_01", password: "password1234", callbackURL: "/dashboard" }));
    await record(t, "sign-in wrong password", c2, () => c2.client.signIn.username({ username: "alice_01", password: "wrong-password" }));
    await record(t, "sign-in unknown", c2, () => c2.client.signIn.username({ username: "nobody_here", password: "password1234" }));
    await record(t, "sign-in too short", c2, () => c2.client.signIn.username({ username: "ab", password: "password1234" }));
    await record(t, "sign-in too long password", c2, () => c2.client.signIn.username({ username: "alice_01", password: "x".repeat(129) }));
    await record(t, "update username", c, () => c.client.updateUser({ username: "Alice_Renamed" }));
    await record(t, "update to taken", c, () => c.client.updateUser({ username: "bob.two" }));
    await record(t, "update to own", c, () => c.client.updateUser({ username: "ALICE_RENAMED" }));
    await record(t, "update display", c, () => c.client.updateUser({ displayUsername: "Alice R." }));
    await record(t, "session after updates", c, () => c.client.getSession());
    await recordFetch(t, "raw missing body field", c, "/sign-in/username", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: "alice_renamed" }) });
    await recordFetch(t, "raw is-username-available wrong type", c, "/is-username-available", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: 5 }) });
  }, { imageNullEqualsAbsent: true });
  assert.equal(t[1].data.user.username, "alice_01");
  assert.equal(t[1].data.user.displayUsername, "Alice_01");
  assert.equal(t[4].error.code, "USERNAME_IS_ALREADY_TAKEN");
  assert.equal(t[13].status, 200);
});
