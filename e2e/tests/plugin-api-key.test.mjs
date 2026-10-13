// api-key plugin parity: the same flows run against the Go and TypeScript servers through
// the official apiKeyClient; transcripts must match. A shared SQLite database checks that
// keys created by one implementation verify (and yield sessions) on the other.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { apiKeyClient } from "@better-auth/api-key/client";
import { startServers, makeClient, dual, record, recordFetch, normalize } from "../lib/harness.mjs";

const plugins = [apiKeyClient()];
let servers;
before(async () => { servers = await startServers("api-key"); });
after(async () => { await servers?.stop(); });

// Generated key material differs between runs; replace it with placeholders.
function scrub(v) {
  if (Array.isArray(v)) return v.map(scrub);
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if ((k === "key" || k === "start" || k === "token") && typeof x === "string") out[k] = `<${k}:${x.length}>`;
      else if (k === "tryAgainIn" && typeof x === "number") out[k] = "<ms>";
      else out[k] = scrub(x);
    }
    return out;
  }
  return v;
}

async function rec(t, name, c, call) {
  const r = await record(t, name, c, call);
  t[t.length - 1] = scrub(t[t.length - 1]);
  return r;
}

async function verify(t, name, server, body) {
  const res = await fetch(`${server.base}/__test/verify-api-key`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await res.json();
  if (t) t.push(scrub({ name, status: res.status, data: normalize(data, server.base) }));
  return data;
}

const withKey = (key) => ({ fetchOptions: { headers: { "x-api-key": key } } });

test("api-key: create, list, get, update, verify, delete", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const anon = makeClient(server, { plugins });
    await rec(t, "create unauthenticated", anon, () => anon.client.apiKey.create({}));
    await rec(t, "sign-up", c, () => c.client.signUp.email({ email: "keys@example.com", password: "password1234", name: "Keys" }));
    const k1 = await rec(t, "create", c, () => c.client.apiKey.create({ name: "first", metadata: { plan: "pro" } }));
    const k2 = await rec(t, "create with prefix", c, () => c.client.apiKey.create({ name: "second", prefix: "sk_live_", expiresIn: 60 * 60 * 24 * 7 }));
    t.push({ name: "prefix applied", ok: k2.data.key.startsWith("sk_live_") && k2.data.start === k2.data.key.slice(0, 6) });
    await rec(t, "create server-only remaining", c, () => c.client.apiKey.create({ remaining: 5 }));
    await rec(t, "create server-only permissions", c, () => c.client.apiKey.create({ permissions: { files: ["write"] } }));
    await rec(t, "create bad prefix", c, () => c.client.apiKey.create({ prefix: "bad prefix!" }));
    await rec(t, "create long name", c, () => c.client.apiKey.create({ name: "x".repeat(40) }));
    await rec(t, "create expiresIn too small", c, () => c.client.apiKey.create({ expiresIn: 60 }));
    await rec(t, "create bad metadata", c, () => c.client.apiKey.create({ metadata: "nope" }));
    await rec(t, "create userId from client", c, () => c.client.apiKey.create({ userId: "someone" }));
    await rec(t, "list", c, () => c.client.apiKey.list({ query: { sortBy: "name", sortDirection: "asc" } }));
    await rec(t, "list paginated", c, () => c.client.apiKey.list({ query: { limit: 1, offset: 1, sortBy: "name", sortDirection: "desc" } }));
    await rec(t, "list bad limit", c, () => c.client.apiKey.list({ query: { limit: -1 } }));
    await rec(t, "list unauthenticated", anon, () => anon.client.apiKey.list());
    await rec(t, "get", c, () => c.client.apiKey.get({ query: { id: k1.data.id } }));
    await rec(t, "get missing", c, () => c.client.apiKey.get({ query: { id: "missing" } }));
    await rec(t, "get without id", c, () => c.client.apiKey.get({ query: {} }));
    await rec(t, "update name", c, () => c.client.apiKey.update({ keyId: k1.data.id, name: "renamed" }));
    await rec(t, "update metadata", c, () => c.client.apiKey.update({ keyId: k1.data.id, metadata: { plan: "enterprise", seats: 3 } }));
    await rec(t, "update nothing", c, () => c.client.apiKey.update({ keyId: k1.data.id }));
    await rec(t, "update server-only", c, () => c.client.apiKey.update({ keyId: k1.data.id, remaining: 10 }));
    await rec(t, "update disable", c, () => c.client.apiKey.update({ keyId: k2.data.id, enabled: false }));
    await verify(t, "verify", server, { key: k1.data.key });
    await verify(t, "verify permissions ok", server, { key: k1.data.key, permissions: { files: ["read"] } });
    await verify(t, "verify permissions denied", server, { key: k1.data.key, permissions: { files: ["write"] } });
    await verify(t, "verify disabled", server, { key: k2.data.key });
    await verify(t, "verify invalid", server, { key: "not-a-real-key" });
    await verify(t, "verify wrong config", server, { key: k1.data.key, configId: "other" });
    await rec(t, "get after verify", c, () => c.client.apiKey.get({ query: { id: k1.data.id } }));
    await rec(t, "delete", c, () => c.client.apiKey.delete({ keyId: k2.data.id }));
    await rec(t, "delete again", c, () => c.client.apiKey.delete({ keyId: k2.data.id }));
    await rec(t, "list after delete", c, () => c.client.apiKey.list());
    const other = makeClient(server, { plugins });
    await rec(t, "other user sign-up", other, () => other.client.signUp.email({ email: "other@example.com", password: "password1234", name: "Other" }));
    await rec(t, "other user cannot get", other, () => other.client.apiKey.get({ query: { id: k1.data.id } }));
    await rec(t, "other user cannot delete", other, () => other.client.apiKey.delete({ keyId: k1.data.id }));
  }, { imageNullEqualsAbsent: true });
  assert.equal(t.find((e) => e.name === "create").status, 200);
  assert.equal(t.find((e) => e.name === "create unauthenticated").error.code, "UNAUTHORIZED_SESSION");
  assert.equal(t.find((e) => e.name === "verify").data.valid, true);
  assert.equal(t.find((e) => e.name === "verify permissions denied").data.error.code, "KEY_NOT_FOUND");
});

test("api-key: sessions from API keys and per-key rate limiting", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    await rec(t, "sign-up", c, () => c.client.signUp.email({ email: "session-key@example.com", password: "password1234", name: "Session Key" }));
    const k = await rec(t, "create", c, () => c.client.apiKey.create({ name: "session" }));
    const bare = makeClient(server, { plugins });
    await rec(t, "session from key", bare, () => bare.client.getSession(withKey(k.data.key)));
    await rec(t, "list with key only", bare, () => bare.client.apiKey.list(withKey(k.data.key)));
    await rec(t, "short key", bare, () => bare.client.getSession(withKey("short")));
    await rec(t, "unknown key", bare, () => bare.client.getSession(withKey("x".repeat(64))));
    await rec(t, "no key", bare, () => bare.client.getSession());
    // the per-key limit is 3 per minute and the two uses above already counted
    await verify(t, "verify 3", server, { key: k.data.key });
    await verify(t, "verify rate limited", server, { key: k.data.key });
    await rec(t, "session rate limited", bare, () => bare.client.getSession(withKey(k.data.key)));
    await recordFetch(t, "verify not routed", bare, "/api-key/verify", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: k.data.key }),
    });
  }, { imageNullEqualsAbsent: true });
  assert.equal(t.find((e) => e.name === "session from key").status, 200);
  assert.equal(t.find((e) => e.name === "verify rate limited").data.error.code, "RATE_LIMITED");
  assert.equal(t.find((e) => e.name === "session rate limited").status, 429);
});

test("api-key: keys are interchangeable through a shared database", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-apikey-"));
  const shared = await startServers("api-key", { env: { DB_URL: `sqlite:${path.join(dir, "keys.db")}` } });
  try {
    for (const [from, to] of [["ts", "go"], ["go", "ts"]]) {
      const owner = makeClient(shared[from], { plugins });
      const email = `shared-${from}@example.com`;
      const up = await owner.client.signUp.email({ email, password: "password1234", name: "Shared" });
      assert.equal(up.error, null, JSON.stringify(up.error));
      const created = await owner.client.apiKey.create({ name: `from-${from}`, metadata: { origin: from } });
      assert.equal(created.error, null, JSON.stringify(created.error));
      const v = await verify(null, "", shared[to], { key: created.data.key, permissions: { files: ["read"] } });
      assert.equal(v.valid, true, `${from}->${to}: ${JSON.stringify(v.error)}`);
      assert.equal(v.key.id, created.data.id);
      assert.deepEqual(v.key.metadata, { origin: from });
      assert.deepEqual(v.key.permissions, { files: ["read"] });
      const bare = makeClient(shared[to], { plugins });
      const s = await bare.client.getSession(withKey(created.data.key));
      assert.equal(s.error, null, JSON.stringify(s.error));
      assert.equal(s.data.user.email, email);
      // the other implementation reads, updates and deletes the key with the owner's session
      const other = makeClient(shared[to], { plugins });
      const signIn = await other.client.signIn.email({ email, password: "password1234" });
      assert.equal(signIn.error, null);
      const got = await other.client.apiKey.get({ query: { id: created.data.id } });
      assert.equal(got.data.name, `from-${from}`);
      assert.equal(got.data.requestCount, 2);
      const upd = await other.client.apiKey.update({ keyId: created.data.id, metadata: { origin: to } });
      assert.deepEqual(upd.data.metadata, { origin: to });
      const back = await owner.client.apiKey.get({ query: { id: created.data.id } });
      assert.deepEqual(back.data.metadata, { origin: to });
      const del = await other.client.apiKey.delete({ keyId: created.data.id });
      assert.equal(del.data?.success, true);
      const gone = await verify(null, "", shared[from], { key: created.data.key });
      assert.equal(gone.valid, false);
    }
  } finally {
    await shared.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
