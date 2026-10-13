// bearer plugin parity: set-auth-token, Authorization: Bearer for signed/unsigned tokens.
import { test, after } from "node:test";
import { startServers, makeClient, dual, record } from "../lib/harness.mjs";

const running = [];
after(async () => { for (const s of running) await s.stop(); });

async function bearerFetch(t, name, server, path, token, init = {}) {
  const headers = new Headers(init.headers);
  if (token !== null) headers.set("authorization", token);
  const res = await fetch(`${server.base}/api/auth${path}`, { ...init, headers });
  const text = await res.text();
  let data = text;
  try { data = JSON.parse(text); } catch {}
  t.push({ name, status: res.status, email: data?.user?.email ?? (Array.isArray(data) ? data.length : data?.code ?? data) });
}

for (const profile of ["bearer", "bearer-signed"]) {
  test(`${profile}: authorization header`, async () => {
    const servers = await startServers(profile);
    running.push(servers);
    await dual(servers, async (server, t) => {
      const c = makeClient(server);
      await record(t, "sign-up", c, () => c.client.signUp.email({ email: "bearer@example.com", password: "password1234", name: "Bearer" }));
      const token = c.state.last.headers.get("set-auth-token");
      t.push({ name: "set-auth-token", ok: decodeURIComponent(c.jar.get("better-auth.session_token")) === token, expose: c.state.last.headers.get("access-control-expose-headers") });
      await bearerFetch(t, "signed", server, "/get-session", `Bearer ${token}`);
      await bearerFetch(t, "unsigned", server, "/get-session", `Bearer ${token.split(".")[0]}`);
      await bearerFetch(t, "url-encoded", server, "/get-session", `Bearer ${encodeURIComponent(token)}`);
      await bearerFetch(t, "lowercase scheme", server, "/get-session", `bearer ${token}`);
      await bearerFetch(t, "bad signature", server, "/get-session", `Bearer ${token.split(".")[0]}.AAAA`);
      await bearerFetch(t, "basic scheme", server, "/get-session", `Basic ${token}`);
      await bearerFetch(t, "list sessions", server, "/list-sessions", `Bearer ${token}`);
      await bearerFetch(t, "sign-in returns token", server, "/sign-in/email", null, {
        method: "POST", headers: { "content-type": "application/json", origin: server.base },
        body: JSON.stringify({ email: "bearer@example.com", password: "password1234" }),
      });
      await record(t, "sign-out", c, () => c.client.signOut());
      await bearerFetch(t, "after sign-out", server, "/get-session", `Bearer ${token}`);
    });
  });
}
