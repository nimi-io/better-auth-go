// last-login-method plugin parity (cookie + database column) with lastLoginMethodClient.
import { test, after } from "node:test";
import { lastLoginMethodClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record } from "../lib/harness.mjs";

let servers;
after(async () => { await servers?.stop(); });

test("last-login-method: email sign-up / sign-in, failures, database field", async () => {
  servers = await startServers("last-login-method");
  await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins: [lastLoginMethodClient()] });
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "llm@example.com", password: "password1234", name: "LLM" }));
    t.push({ name: "cookie after sign-up", value: c.jar.get("better-auth.last_used_login_method") ?? null });
    await record(t, "session has lastLoginMethod", c, () => c.client.getSession());
    await record(t, "sign-out", c, () => c.client.signOut());
    c.jar.delete("better-auth.last_used_login_method");
    await record(t, "failed sign-in", c, () => c.client.signIn.email({ email: "llm@example.com", password: "wrong-password" }));
    t.push({ name: "cookie after failure", value: c.jar.get("better-auth.last_used_login_method") ?? null });
    await record(t, "sign-in", c, () => c.client.signIn.email({ email: "llm@example.com", password: "password1234" }));
    t.push({ name: "cookie after sign-in", value: c.jar.get("better-auth.last_used_login_method") ?? null });
    await record(t, "update user cannot set lastLoginMethod", c, () => c.client.updateUser({ lastLoginMethod: "hacked" }));
    await record(t, "session after update", c, () => c.client.getSession());
  });
});
