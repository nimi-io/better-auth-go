// jwt plugin parity: /token, /jwks, the set-auth-jwt header and the JWKS-backed cookie cache
// on the Go server and the reference TypeScript server. Tokens and keys are volatile, so
// transcripts normalise them; every token is additionally verified against the issuing
// server's JWKS with `jose` (the library better-auth uses), and Go tokens are verified with
// better-auth's own helpers.
import { test, after, describe } from "node:test";
import assert from "node:assert/strict";
import { createLocalJWKSet, jwtVerify, decodeProtectedHeader } from "jose";
import { jwtClient } from "better-auth/client/plugins";
import { getCookieCache } from "better-auth/cookies";
import { startServers, makeClient, dual, record, recordFetch, uniqueEmail } from "../lib/harness.mjs";
import { databases } from "../lib/databases.mjs";

const running = [];
after(async () => { for (const s of running) await s.stop(); });

function shapeOfJwks(data) {
  return { keys: (data?.keys ?? []).map((k) => ({ ...k, kid: "<kid>", x: k.x ? `<${k.x.length}>` : undefined, y: k.y ? `<${k.y.length}>` : undefined, n: k.n ? `<${k.n.length}>` : undefined })) };
}

function claimShape(payload, base) {
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (["iat", "exp"].includes(k)) out[k] = typeof v;
    else if (typeof v === "string") out[k] = v.split(base).join("<base>").replace(/^[A-Za-z0-9]{24,32}$/, "<id>").replace(/^\d{4}-\d{2}-\d{2}T.*Z$/, "<date>");
    else out[k] = v;
  }
  return out;
}

test("jwt plugin: token, jwks and set-auth-jwt", async () => {
  const servers = await startServers("jwt-plugin");
  running.push(servers);
  await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins: [jwtClient()] });
    await record(t, "jwks before keys exist", c, async () => {
      const r = await c.client.jwks();
      return { data: shapeOfJwks(r.data), error: r.error };
    });
    await record(t, "token unauthenticated", c, () => c.client.token());
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "jwt@example.com", password: "password1234", name: "Jwt User" }));
    const sess = await c.client.getSession();
    const headerJwt = c.state.last.headers.get("set-auth-jwt");
    t.push({ name: "set-auth-jwt", present: JWT_RE.test(headerJwt ?? ""), expose: c.state.last.headers.get("access-control-expose-headers") });
    const tok = await c.client.token();
    const jwks = await c.client.jwks();
    const set = createLocalJWKSet(jwks.data);
    for (const [name, token] of [["token", tok.data.token], ["header", headerJwt]]) {
      const { payload, protectedHeader } = await jwtVerify(token, set, { issuer: server.base, audience: server.base });
      assert.equal(payload.sub, sess.data.user.id);
      assert.equal(payload.exp - payload.iat, 3600);
      t.push({ name: `${name} claims`, header: { ...protectedHeader, kid: "<kid>" }, claims: claimShape(payload, server.base) });
    }
    await recordFetch(t, "sign-jwt not routed", c, "/sign-jwt", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    await recordFetch(t, "verify-jwt not routed", c, "/verify-jwt", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    // bearer + jwt: the session token header works and still yields set-auth-jwt
    const bearerToken = c.state.last.headers.get("set-auth-token");
    const raw = await fetch(`${server.base}/api/auth/get-session`, { headers: { authorization: `Bearer ${c.jar.get("better-auth.session_token")}` } });
    t.push({ name: "get-session via bearer", status: raw.status, jwt: JWT_RE.test(raw.headers.get("set-auth-jwt") ?? ""), bearerToken: bearerToken === null ? null : "<set>" });
  });
});

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

test("jwt plugin: ES256 keys on a custom jwksPath", async () => {
  const servers = await startServers("jwt-es256");
  running.push(servers);
  await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins: [jwtClient({ jwks: { jwksPath: "/.well-known/jwks.json" } })] });
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "es@example.com", password: "password1234", name: "ES" }));
    const tok = await c.client.token();
    const jwks = await c.client.jwks();
    t.push({ name: "jwks", data: shapeOfJwks(jwks.data) });
    await recordFetch(t, "default jwks path gone", c, "/jwks", {});
    const { protectedHeader } = await jwtVerify(tok.data.token, createLocalJWKSet(jwks.data));
    t.push({ name: "alg", alg: protectedHeader.alg });
  });
});

test("jwt plugin: JWKS-backed session cookie cache", async () => {
  const servers = await startServers("jwt-cookie-cache");
  running.push(servers);
  await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins: [jwtClient()] });
    await record(t, "sign-up", c, () => c.client.signUp.email({ email: "cc@example.com", password: "password1234", name: "CC" }));
    const cache = c.jar.get("better-auth.session_data");
    const header = decodeProtectedHeader(cache);
    t.push({ name: "cache header", header: { ...header, kid: "<kid>" } });
    const jwks = (await c.client.jwks()).data;
    const { payload } = await jwtVerify(cache, createLocalJWKSet(jwks), { audience: "better-auth:session-cache", issuer: server.base });
    t.push({ name: "cache claims", keys: Object.keys(payload), aud: payload.aud, iss: payload.iss.split(server.base).join("<base>") });
    // better-auth's getCookieCache helper verifies the cache with the server's JWKS
    const helper = await getCookieCache(new Headers({ cookie: `better-auth.session_data=${cache}` }), { strategy: "jwt", isSecure: false, jwt: { jwks } });
    t.push({ name: "getCookieCache(jwt.jwks)", email: helper?.user?.email ?? null });
    await record(t, "session from cache", c, () => c.client.getSession());
    // a secret-signed cache is rejected and replaced
    c.jar.set("better-auth.session_data", "invalid.jwt.token");
    await record(t, "session after tamper", c, () => c.client.getSession());
  });
});

// Cross-implementation JWKS: both servers share one SQLite database, so a key minted (and
// encrypted with the shared secret) by one implementation signs on the other, and tokens
// verify against either server's /jwks.
describe("jwt plugin: shared JWKS table", () => {
  for (const first of ["ts", "go"]) {
    test(`key minted by ${first}`, async () => {
      const db = await databases()[0].create();
      const servers = await startServers("jwt-shared", { env: { DB_URL: db.url } });
      try {
        const second = first === "ts" ? "go" : "ts";
        const a = makeClient(servers[first], { plugins: [jwtClient()] });
        const email = uniqueEmail("jwks");
        assert.equal((await a.client.signUp.email({ email, password: "password1234", name: "Shared" })).error, null);
        const t1 = (await a.client.token()).data.token;
        const b = makeClient(servers[second], { plugins: [jwtClient()] });
        b.jar.set("better-auth.session_token", a.jar.get("better-auth.session_token"));
        const t2 = (await b.client.token()).data.token;
        const kid1 = decodeProtectedHeader(t1).kid;
        assert.equal(decodeProtectedHeader(t2).kid, kid1, "second implementation must reuse the stored (encrypted) key");
        const jwksA = (await a.client.jwks()).data;
        const jwksB = (await b.client.jwks()).data;
        assert.deepEqual(jwksA, jwksB);
        for (const tok of [t1, t2]) {
          for (const set of [jwksA, jwksB]) {
            const { payload } = await jwtVerify(tok, createLocalJWKSet(set));
            assert.equal(payload.email, email);
          }
        }
      } finally {
        await servers.stop();
        await new Promise((r) => setTimeout(r, 200));
        await db.drop();
      }
    });
  }
});
