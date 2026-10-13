// OAuth provider parity (@better-auth/oauth-provider 1.7.7): discovery, dynamic client
// registration, authorization code + PKCE with consent, token / refresh / userinfo /
// introspection / revocation, management endpoints, end-session and error cases on the Go
// server and the reference TypeScript server (profile "oauth-provider"); normalised
// transcripts must be identical. A second suite shares one SQLite database between both
// servers and moves clients, codes and tokens across implementations, and verifies Go id
// tokens with jose against the Go JWKS.
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createLocalJWKSet, jwtVerify } from "jose";
import { startServers, makeClient, dual, normalize, uniqueEmail } from "../lib/harness.mjs";
import { databases } from "../lib/databases.mjs";

const REDIRECT = "https://rp.example.com/callback";
const verifier = "e2e-verifier-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGH";
const challenge = createHash("sha256").update(verifier).digest("base64url");

// Volatile values: signed-query parameters, timestamps and generated secrets.
function scrubURL(u, base) {
  if (typeof u !== "string") return u;
  let s = u.split(base).join("<base>").split(encodeURIComponent(base)).join("<base>");
  s = s.replace(/([?&](?:sig|exp|ba_iat|code|ba_pl|client_id)=)[^&#]+/g, "$1<v>");
  return s;
}

function scrub(v, base) {
  if (Array.isArray(v)) return v.map((x) => scrub(x, base));
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if (["iat", "exp", "expires_at", "expires_in", "client_id_issued_at", "auth_time", "client_secret_expires_at"].includes(k) && typeof x === "number") out[k] = x > 0 ? "<num>" : x;
      else if (["createdAt", "updatedAt"].includes(k)) out[k] = "<date>";
      else if (["url", "location"].includes(k)) out[k] = scrubURL(x, base);
      else out[k] = scrub(x, base);
    }
    return out;
  }
  if (typeof v === "string") return normalize(scrubURL(v, base), base);
  return v;
}

async function call(server, path, { method = "GET", headers = {}, form, json, jar } = {}) {
  const h = new Headers(headers);
  if (jar) { const c = jar.header(); if (c) h.set("cookie", c); }
  let body;
  if (form) { body = new URLSearchParams(form).toString(); h.set("content-type", "application/x-www-form-urlencoded"); }
  if (json) { body = JSON.stringify(json); h.set("content-type", "application/json"); }
  if (method !== "GET" && !h.has("origin")) h.set("origin", server.base);
  const res = await fetch(path.startsWith("http") ? path : `${server.base}/api/auth${path}`, { method, headers: h, body, redirect: "manual" });
  if (jar) jar.apply(res.headers.getSetCookie());
  const text = await res.text();
  let data = text;
  try { data = JSON.parse(text); } catch {}
  return { res, data };
}

function entry(name, server, r, extra = {}) {
  return scrub({
    name,
    status: r.res.status,
    data: r.data,
    location: r.res.headers.get("location"),
    cacheControl: r.res.headers.get("cache-control"),
    wwwAuthenticate: r.res.headers.get("www-authenticate"),
    ...extra,
  }, server.base);
}

// Node's fetch sends Sec-Fetch-Mode: cors, so redirects come back as {redirect, url}.
const redirectOf = (r) => r.res.headers.get("location") ?? r.data?.url;

const basic = (id, secret) => ({ authorization: `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString("base64")}` });

function authorizeQuery(clientId, extra = {}) {
  return new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    scope: "openid profile email offline_access", state: "xyz",
    code_challenge: challenge, code_challenge_method: "S256", ...extra,
  }).toString();
}

let servers;
describe("oauth-provider parity", () => {
  before(async () => { servers = await startServers("oauth-provider"); });
  after(async () => { await servers?.stop(); });

  test("discovery documents", async () => {
    await dual(servers, async (server, t) => {
      for (const p of ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]) {
        t.push(entry(`GET ${p}`, server, await call(server, p)));
        t.push(entry(`POST ${p}`, server, await call(server, p, { method: "POST", json: {} })));
      }
      const head = await fetch(`${server.base}/api/auth/.well-known/openid-configuration`, { method: "HEAD" });
      t.push({ name: "HEAD openid-configuration", status: head.status, type: head.headers.get("content-type"), cache: head.headers.get("cache-control") });
    });
  });

  test("registration, authorization code + PKCE, tokens, introspection and revocation", async () => {
    await dual(servers, async (server, t) => {
      const c = makeClient(server);
      // dynamic registration
      t.push(entry("register invalid redirect", server, await call(server, "/oauth2/register", { method: "POST", json: { redirect_uris: ["not a url"] } })));
      t.push(entry("register http redirect", server, await call(server, "/oauth2/register", { method: "POST", json: { redirect_uris: ["http://rp.example.com/cb"] } })));
      t.push(entry("register skip_consent", server, await call(server, "/oauth2/register", { method: "POST", json: { redirect_uris: [REDIRECT], skip_consent: true } })));
      t.push(entry("register unauthenticated confidential", server, await call(server, "/oauth2/register", { method: "POST", json: { redirect_uris: [REDIRECT], grant_types: ["client_credentials"] } })));
      const pub = await call(server, "/oauth2/register", { method: "POST", json: { redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", client_name: "Public App" } });
      t.push(entry("register public client", server, pub));
      const publicId = pub.data.client_id;

      // authorize unauthenticated -> login page
      t.push(entry("authorize unauthenticated", server, await call(server, `/oauth2/authorize?${authorizeQuery(publicId)}`, { jar: c.jar })));
      t.push(entry("authorize unknown client", server, await call(server, `/oauth2/authorize?${authorizeQuery("nope")}`, { jar: c.jar })));
      t.push(entry("authorize bad redirect", server, await call(server, `/oauth2/authorize?${authorizeQuery(publicId, { redirect_uri: "https://evil.example.com/cb" })}`, { jar: c.jar })));
      t.push(entry("authorize missing pkce", server, await call(server, `/oauth2/authorize?${new URLSearchParams({ response_type: "code", client_id: publicId, redirect_uri: REDIRECT, scope: "openid", state: "s" })}`, { jar: c.jar })));
      t.push(entry("authorize invalid scope", server, await call(server, `/oauth2/authorize?${authorizeQuery(publicId, { scope: "openid admin" })}`, { jar: c.jar })));
      t.push(entry("authorize bad prompt", server, await call(server, `/oauth2/authorize?${authorizeQuery(publicId, { prompt: "none login" })}`, { jar: c.jar })));

      // sign up and authorize -> consent page
      await c.client.signUp.email({ email: "oauth-user@example.com", password: "password1234", name: "OAuth User" });
      t.push(entry("authorize prompt=none needs consent", server, await call(server, `/oauth2/authorize?${authorizeQuery(publicId, { prompt: "none" })}`, { jar: c.jar })));
      const az = await call(server, `/oauth2/authorize?${authorizeQuery(publicId)}`, { jar: c.jar });
      t.push(entry("authorize signed in", server, az));
      const consentQuery = redirectOf(az).split("?")[1];
      t.push(entry("consent tampered", server, await call(server, "/oauth2/consent", { method: "POST", json: { accept: true, oauth_query: consentQuery.replace("state=xyz", "state=abc") }, jar: c.jar })));
      t.push(entry("consent deny", server, await call(server, "/oauth2/consent", { method: "POST", json: { accept: false, oauth_query: consentQuery }, jar: c.jar })));
      const consent = await call(server, "/oauth2/consent", { method: "POST", json: { accept: true, oauth_query: consentQuery }, jar: c.jar });
      t.push(entry("consent accept", server, consent));
      const code = new URL(consent.data.url).searchParams.get("code");

      // token errors
      t.push(entry("token unsupported grant", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "password", client_id: publicId } })));
      t.push(entry("token missing grant", server, await call(server, "/oauth2/token", { method: "POST", form: { client_id: publicId } })));
      t.push(entry("token json body", server, await call(server, "/oauth2/token", { method: "POST", json: { grant_type: "authorization_code" } })));
      t.push(entry("token wrong verifier", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: publicId, code: "bogus", code_verifier: "x".repeat(50), redirect_uri: REDIRECT } })));
      const tok = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: publicId, code, code_verifier: verifier, redirect_uri: REDIRECT } });
      t.push(entry("token exchange", server, tok, { idClaims: tok.data.id_token ? Object.keys(JSON.parse(Buffer.from(tok.data.id_token.split(".")[1], "base64url"))) : null }));
      t.push(entry("token code replay", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: publicId, code, code_verifier: verifier, redirect_uri: REDIRECT } })));
      const at = tok.data.access_token;

      // userinfo
      t.push(entry("userinfo", server, await call(server, "/oauth2/userinfo", { headers: { authorization: `Bearer ${at}` } })));
      t.push(entry("userinfo missing token", server, await call(server, "/oauth2/userinfo")));
      t.push(entry("userinfo bad token", server, await call(server, "/oauth2/userinfo", { headers: { authorization: "Bearer nope" } })));

      // confidential client via create-client (session)
      const created = await call(server, "/oauth2/create-client", { method: "POST", json: { redirect_uris: [REDIRECT], client_name: "Confidential" }, jar: c.jar });
      t.push(entry("create-client", server, created));
      const confId = created.data.client_id;
      const confSecret = created.data.client_secret;
      t.push(entry("get-client", server, await call(server, `/oauth2/get-client?client_id=${confId}`, { jar: c.jar })));
      t.push(entry("public-client", server, await call(server, `/oauth2/public-client?client_id=${confId}`, { jar: c.jar })));
      t.push(entry("get-clients", server, await call(server, "/oauth2/get-clients", { jar: c.jar })));
      t.push(entry("get-consents", server, await call(server, "/oauth2/get-consents", { jar: c.jar })));

      // introspection
      t.push(entry("introspect no credentials", server, await call(server, "/oauth2/introspect", { method: "POST", form: { token: at } })));
      t.push(entry("introspect bad secret", server, await call(server, "/oauth2/introspect", { method: "POST", form: { token: at }, headers: basic(confId, "wrong") })));
      t.push(entry("introspect access token (other client)", server, await call(server, "/oauth2/introspect", { method: "POST", form: { token: at }, headers: basic(confId, confSecret) })));
      t.push(entry("introspect unknown", server, await call(server, "/oauth2/introspect", { method: "POST", form: { token: "unknown-token" }, headers: basic(confId, confSecret) })));

      // refresh + revoke with the public client
      const rt = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", client_id: publicId, refresh_token: tok.data.refresh_token } });
      t.push(entry("refresh", server, rt));
      t.push(entry("refresh replay", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", client_id: publicId, refresh_token: tok.data.refresh_token } })));
      t.push(entry("refresh scope escalation", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", client_id: publicId, refresh_token: rt.data.refresh_token ?? "x", scope: "openid admin" } })));

      // confidential: client_credentials not allowed, full code flow with basic auth
      t.push(entry("client_credentials unauthorized", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "client_credentials" }, headers: basic(confId, confSecret) })));
      const az2 = await call(server, `/oauth2/authorize?${authorizeQuery(confId)}`, { jar: c.jar });
      const q2 = redirectOf(az2).split("?")[1];
      const consent2 = await call(server, "/oauth2/consent", { method: "POST", json: { accept: true, scope: "openid email", oauth_query: q2 }, jar: c.jar });
      t.push(entry("consent narrowed scope", server, consent2));
      const code2 = new URL(consent2.data.url).searchParams.get("code");
      const tok2 = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", code: code2, code_verifier: verifier, redirect_uri: REDIRECT }, headers: basic(confId, confSecret) });
      t.push(entry("token confidential", server, tok2));
      t.push(entry("introspect own token", server, await call(server, "/oauth2/introspect", { method: "POST", form: { token: tok2.data.access_token, token_type_hint: "access_token" }, headers: basic(confId, confSecret) })));
      t.push(entry("revoke", server, await call(server, "/oauth2/revoke", { method: "POST", form: { token: tok2.data.access_token }, headers: basic(confId, confSecret) })));
      t.push(entry("introspect revoked", server, await call(server, "/oauth2/introspect", { method: "POST", form: { token: tok2.data.access_token }, headers: basic(confId, confSecret) })));
      t.push(entry("revoke unknown", server, await call(server, "/oauth2/revoke", { method: "POST", form: { token: "unknown" }, headers: basic(confId, confSecret) })));
      t.push(entry("rotate secret", server, await call(server, "/oauth2/client/rotate-secret", { method: "POST", json: { client_id: confId }, jar: c.jar })));
      t.push(entry("old secret rejected", server, await call(server, "/oauth2/introspect", { method: "POST", form: { token: "x" }, headers: basic(confId, confSecret) })));

      // end-session
      t.push(entry("end-session json no hint", server, await call(server, "/oauth2/end-session", { jar: c.jar })));
      t.push(entry("end-session unknown client", server, await call(server, "/oauth2/end-session?client_id=nope")));
      t.push(entry("end-session navigation", server, await call(server, "/oauth2/end-session", { jar: c.jar, headers: { accept: "text/html", "sec-fetch-mode": "navigate" } })));
      t.push(entry("delete-client", server, await call(server, "/oauth2/delete-client", { method: "POST", json: { client_id: confId }, jar: c.jar })));
      t.push(entry("get-client after delete", server, await call(server, `/oauth2/get-client?client_id=${confId}`, { jar: c.jar })));
    });
  });
});

describe("oauth-provider shared database (cross-compatibility)", () => {
  for (const [issuer, consumer] of [["ts", "go"], ["go", "ts"]]) {
    test(`client and code from ${issuer}, tokens on ${consumer}`, async () => {
      const db = await databases()[0].create();
      const srv = await startServers("oauth-provider-shared", { env: { DB_URL: db.url } });
      try {
        const A = srv[issuer];
        const B = srv[consumer];
        // TS migrates on start; register a confidential client on the issuer.
        const a = makeClient(A);
        await a.client.signUp.email({ email: uniqueEmail("xcompat"), password: "password1234", name: "X" });
        const created = await call(A, "/oauth2/create-client", { method: "POST", json: { redirect_uris: [REDIRECT] }, jar: a.jar });
        assert.equal(created.res.status, 201, JSON.stringify(created.data));
        const { client_id: id, client_secret: secret } = created.data;
        // authorize + consent on the issuer
        const az = await call(A, `/oauth2/authorize?${authorizeQuery(id)}`, { jar: a.jar });
        const q = redirectOf(az).split("?")[1];
        const consent = await call(A, "/oauth2/consent", { method: "POST", json: { accept: true, oauth_query: q }, jar: a.jar });
        const code = new URL(consent.data.url).searchParams.get("code");
        assert.ok(code, JSON.stringify(consent.data));
        // the consumer exchanges the issuer's code with the (hashed) secret stored by the issuer
        const tok = await call(B, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: REDIRECT }, headers: basic(id, secret) });
        assert.equal(tok.res.status, 200, JSON.stringify(tok.data));
        // tokens issued by the consumer work on the issuer
        const intro = await call(A, "/oauth2/introspect", { method: "POST", form: { token: tok.data.access_token }, headers: basic(id, secret) });
        assert.equal(intro.data.active, true, JSON.stringify(intro.data));
        const ui = await call(A, "/oauth2/userinfo", { headers: { authorization: `Bearer ${tok.data.access_token}` } });
        assert.equal(ui.res.status, 200, JSON.stringify(ui.data));
        const refreshed = await call(A, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", refresh_token: tok.data.refresh_token }, headers: basic(id, secret) });
        assert.equal(refreshed.res.status, 200, JSON.stringify(refreshed.data));
        const revoke = await call(B, "/oauth2/revoke", { method: "POST", form: { token: refreshed.data.refresh_token, token_type_hint: "refresh_token" }, headers: basic(id, secret) });
        assert.equal(revoke.res.status, 200, JSON.stringify(revoke.data));
        const intro2 = await call(A, "/oauth2/introspect", { method: "POST", form: { token: refreshed.data.refresh_token, token_type_hint: "refresh_token" }, headers: basic(id, secret) });
        assert.equal(intro2.data.active, false);
        // id tokens verify with jose against the issuing server's JWKS (shared keys)
        for (const [srvName, s] of [[consumer, B], [issuer, A]]) {
          const jwks = (await call(s, "/jwks")).data;
          const { payload, protectedHeader } = await jwtVerify(tok.data.id_token, createLocalJWKSet(jwks), { issuer: `${B.base}/api/auth`, audience: id });
          assert.equal(protectedHeader.alg, "EdDSA", srvName);
          assert.ok(payload.sub);
        }
      } finally {
        await srv.stop();
        await new Promise((r) => setTimeout(r, 200));
        await db.drop();
      }
    });
  }

  test("Go id tokens verify with jose; consent written by Go is honoured by TS", async () => {
    const db = await databases()[0].create();
    const srv = await startServers("oauth-provider-shared", { env: { DB_URL: db.url } });
    try {
      const g = makeClient(srv.go);
      await g.client.signUp.email({ email: uniqueEmail("consent"), password: "password1234", name: "C" });
      const pub = await call(srv.go, "/oauth2/register", { method: "POST", json: { redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" } });
      const id = pub.data.client_id;
      const az = await call(srv.go, `/oauth2/authorize?${authorizeQuery(id, { nonce: randomBytes(8).toString("hex") })}`, { jar: g.jar });
      const q = redirectOf(az).split("?")[1];
      await call(srv.go, "/oauth2/consent", { method: "POST", json: { accept: true, oauth_query: q }, jar: g.jar });
      // the TypeScript server sees the Go consent: authorize redirects straight to the client
      const t = makeClient(srv.ts);
      t.jar.set("better-auth.session_token", g.jar.get("better-auth.session_token"));
      const az2 = await call(srv.ts, `/oauth2/authorize?${authorizeQuery(id)}`, { jar: t.jar });
      const loc = redirectOf(az2);
      assert.ok(loc?.startsWith(REDIRECT), loc);
      const code = new URL(loc).searchParams.get("code");
      const tok = await call(srv.go, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: id, code, code_verifier: verifier, redirect_uri: REDIRECT } });
      assert.equal(tok.res.status, 200, JSON.stringify(tok.data));
      const jwks = (await call(srv.go, "/jwks")).data;
      const { payload } = await jwtVerify(tok.data.id_token, createLocalJWKSet(jwks), { issuer: `${srv.go.base}/api/auth`, audience: id });
      assert.equal(typeof payload.at_hash, "string");
    } finally {
      await srv.stop();
      await new Promise((r) => setTimeout(r, 200));
      await db.drop();
    }
  });
});
