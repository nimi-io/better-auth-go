// multi-session plugin parity with the official multiSessionClient.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { multiSessionClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record } from "../lib/harness.mjs";

let servers;

// Multi-session cookie names embed the (random) session token; device session order
// follows the database's natural order (SQLite index vs. the Go memory adapter).
function normalizeMulti(t) {
  for (const e of t) {
    if (Array.isArray(e.setCookie)) e.setCookie = e.setCookie.map((c) => c.replace(/_multi-[a-z0-9]+=/, "_multi-<token>=")).sort();
    if (Array.isArray(e.data)) e.data = [...e.data].sort((a, b) => String(a?.user?.email).localeCompare(String(b?.user?.email)));
  }
}

after(async () => { await servers?.stop(); });

test("multi-session: list, set-active, revoke, maximum, sign-out", async () => {
  servers = await startServers("multi-session");
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins: [multiSessionClient()] });
    const other = makeClient(server);
    await record(t, "sign-up a", c, () => c.client.signUp.email({ email: "ms-a@example.com", password: "password1234", name: "A" }));
    await record(t, "sign-up b", c, () => c.client.signUp.email({ email: "ms-b@example.com", password: "password1234", name: "B" }));
    await record(t, "sign-up c (over maximum)", c, () => c.client.signUp.email({ email: "ms-c@example.com", password: "password1234", name: "C" }));
    await record(t, "list", c, () => c.client.multiSession.listDeviceSessions());
    const list = (await c.client.multiSession.listDeviceSessions()).data;
    const a = list.find((s) => s.user.email === "ms-a@example.com");
    await record(t, "set-active a", c, () => c.client.multiSession.setActive({ sessionToken: a.session.token }));
    await record(t, "session is a", c, () => c.client.getSession());
    await record(t, "set-active unknown", c, () => c.client.multiSession.setActive({ sessionToken: "nope" }));
    await record(t, "set-active missing body", c, () => c.client.$fetch("/multi-session/set-active", { method: "POST", body: {} }));
    await record(t, "same user signs in again", c, () => c.client.signIn.email({ email: "ms-a@example.com", password: "password1234" }));
    await record(t, "list after re-sign-in", c, () => c.client.multiSession.listDeviceSessions());
    const cur = (await c.client.getSession()).data;
    await record(t, "revoke active", c, () => c.client.multiSession.revoke({ sessionToken: cur.session.token }));
    await record(t, "session after revoke", c, () => c.client.getSession());
    await record(t, "revoke unauthenticated", other, () => other.client.multiSession.revoke({ sessionToken: "x" }));
    await record(t, "list unauthenticated", other, () => other.client.multiSession.listDeviceSessions());
    await record(t, "sign-out", c, () => c.client.signOut());
    await record(t, "list after sign-out", c, () => c.client.multiSession.listDeviceSessions());
    normalizeMulti(t);
  });
  assert.equal(t.find((e) => e.name === "list").data.length, 2);
});
