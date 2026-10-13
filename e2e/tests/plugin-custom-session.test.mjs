// custom-session plugin parity with the official customSessionClient.
import { test, after } from "node:test";
import { customSessionClient, multiSessionClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";

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

test("custom-session: get-session and list-device-sessions", async () => {
  servers = await startServers("custom-session");
  await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins: [customSessionClient(), multiSessionClient()] });
    await record(t, "signed out", c, () => c.client.getSession());
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "cs@example.com", password: "password1234", name: "Custom Session" }));
    await record(t, "custom session", c, () => c.client.getSession());
    await record(t, "disableRefresh query", c, () => c.client.getSession({ query: { disableRefresh: true } }));
    await recordFetch(t, "invalid query", c, "/get-session?disableCookieCache=maybe", {});
    await record(t, "device sessions mapped", c, () => c.client.multiSession.listDeviceSessions());
    await record(t, "list-sessions still works", c, () => c.client.listSessions());
    await recordFetch(t, "post get-session", c, "/get-session", { method: "POST" });
    normalizeMulti(t);
  });
});
