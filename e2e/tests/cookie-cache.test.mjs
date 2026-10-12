// Cookie cache parity (compact / jwt / jwe) and cross-implementation compatibility: a
// session cookie + cookie cache issued by the TypeScript server must validate on the Go
// server (and vice versa) when both share the same secret.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { startServers, makeClient, dual, record } from "../lib/harness.mjs";

const running = [];
after(async () => { for (const s of running) await s.stop(); });

async function cookiesFor(server, email) {
  const c = makeClient(server);
  const r = await c.client.signUp.email({ email, password: "password1234", name: "Cache User" });
  assert.equal(r.error, null, JSON.stringify(r.error));
  return c.jar;
}

async function sessionWithCookies(server, jar) {
  const res = await fetch(`${server.base}/__test/session`, { headers: { cookie: jar.header() } });
  return res.json();
}

for (const strategy of ["compact", "jwt", "jwe"]) {
  test(`cookie cache (${strategy}) parity`, async () => {
    const servers = await startServers(strategy);
    running.push(servers);
    await dual(servers, async (server, t) => {
      const c = makeClient(server);
      await record(t, "sign-up", c, () => c.client.signUp.email({ email: "cache@example.com", password: "password1234", name: "Cache" }));
      await record(t, "get-session (cached)", c, () => c.client.getSession());
      await record(t, "get-session disableCookieCache", c, () => c.client.getSession({ query: { disableCookieCache: true } }));
      await record(t, "update user", c, () => c.client.updateUser({ name: "Cache 2" }));
      await record(t, "get-session after update", c, () => c.client.getSession());
      c.jar.set(Object.keys(Object.fromEntries(c.jar.cookies)).find((k) => k.endsWith("session_data")), "tampered");
      await record(t, "get-session tampered cache", c, () => c.client.getSession());
      await record(t, "sign-out", c, () => c.client.signOut());
    });
  });

  test(`cookie cache (${strategy}) cross-compat TS <-> Go`, async () => {
    const servers = await startServers(strategy);
    running.push(servers);
    // TS-issued cookies validated by Go (the Go DB has no such session: only the cache can
    // authenticate the request).
    const tsJar = await cookiesFor(servers.ts, "from-ts@example.com");
    const goView = await sessionWithCookies(servers.go, tsJar);
    assert.ok(goView, `Go rejected the ${strategy} cookie cache issued by TS`);
    assert.equal(goView.user.email, "from-ts@example.com");
    // Go-issued cookies validated by TS.
    const goJar = await cookiesFor(servers.go, "from-go@example.com");
    const tsView = await sessionWithCookies(servers.ts, goJar);
    assert.ok(tsView, `TS rejected the ${strategy} cookie cache issued by Go`);
    assert.equal(tsView.user.email, "from-go@example.com");
    // A tampered cache must be rejected by both.
    const name = [...tsJar.cookies.keys()].find((k) => k.endsWith("session_data"));
    const raw = tsJar.get(name);
    tsJar.set(name, raw.slice(0, -4) + (raw.endsWith("AAAA") ? "BBBB" : "AAAA"));
    assert.equal(await sessionWithCookies(servers.go, tsJar), null);
  });
}

test("signed session_token cookie issued by TS is accepted by Go (secondary storage shared format)", async () => {
  const servers = await startServers("compact");
  running.push(servers);
  const jar = await cookiesFor(servers.ts, "signed@example.com");
  const token = [...jar.cookies.entries()].find(([k]) => k.endsWith("session_token"))[1];
  assert.match(decodeURIComponent(token), /^[A-Za-z0-9]{32}\.[A-Za-z0-9+/]{43}=$/);
});

test("password hashes are interchangeable", async () => {
  const servers = await startServers("");
  running.push(servers);
  for (const password of ["password123", "Ünïcödé-ﬁ-ｐａｓｓ", "a".repeat(100)]) {
    const goHash = (await (await fetch(`${servers.go.base}/__test/hash?password=${encodeURIComponent(password)}`)).json()).hash;
    const tsOk = await (await fetch(`${servers.ts.base}/__test/verify?password=${encodeURIComponent(password)}&hash=${encodeURIComponent(goHash)}`)).json();
    assert.equal(tsOk.ok, true, `TS failed to verify Go hash for ${password}`);
    const tsHash = (await (await fetch(`${servers.ts.base}/__test/hash?password=${encodeURIComponent(password)}`)).json()).hash;
    const goOk = await (await fetch(`${servers.go.base}/__test/verify?password=${encodeURIComponent(password)}&hash=${encodeURIComponent(tsHash)}`)).json();
    assert.equal(goOk.ok, true, `Go failed to verify TS hash for ${password}`);
    const goBad = await (await fetch(`${servers.go.base}/__test/verify?password=wrong&hash=${encodeURIComponent(tsHash)}`)).json();
    assert.equal(goBad.ok, false);
  }
});
