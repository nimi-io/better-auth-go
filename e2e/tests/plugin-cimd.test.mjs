// Client ID Metadata Document parity (@better-auth/cimd 1.7.7 with
// @better-auth/oauth-provider): discovery advertisement, registration of a client by its
// metadata-document URL on /oauth2/authorize, consent, token exchange, userinfo and refresh
// with the URL client_id, conditional revalidation, and validation failures (client_id
// mismatch, symmetric auth method, forbidden fields, wrong media type, unreachable and
// private URLs) on the Go server and the reference TypeScript server (profile "cimd");
// normalised transcripts must be identical.
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { startServers, makeClient, dual, normalize } from "../lib/harness.mjs";

const CLIENT = "https://client.e2e.example/client.json";
const REDIRECT = "https://client.e2e.example/callback";
const verifier = "e2e-cimd-verifier-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEF";
const challenge = createHash("sha256").update(verifier).digest("base64url");

function scrubURL(u, base) {
  if (typeof u !== "string") return u;
  let s = u.split(base).join("<base>").split(encodeURIComponent(base)).join("<base>");
  s = s.replace(/([?&](?:sig|exp|ba_iat|code|ba_pl)=)[^&#]+/g, "$1<v>");
  return s;
}

function scrub(v, base) {
  if (Array.isArray(v)) return v.map((x) => scrub(x, base));
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if (["iat", "exp", "expires_at", "expires_in", "auth_time"].includes(k) && typeof x === "number") out[k] = x > 0 ? "<num>" : x;
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
    ...extra,
  }, server.base);
}

const redirectOf = (r) => r.res.headers.get("location") ?? r.data?.url;

function authorizeQuery(clientId, redirectUri = REDIRECT, extra = {}) {
  return new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    scope: "openid profile email offline_access", state: "cimd-state",
    code_challenge: challenge, code_challenge_method: "S256", ...extra,
  }).toString();
}

let servers;
describe("cimd parity", () => {
  before(async () => { servers = await startServers("cimd"); });
  after(async () => { await servers?.stop(); });

  test("discovery advertises Client ID Metadata Documents", async () => {
    await dual(servers, async (server, t) => {
      for (const p of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
        const r = await call(server, p);
        t.push(entry(`GET ${p}`, server, r, {
          cimd: r.data.client_id_metadata_document_supported ?? null,
          registration: r.data.registration_endpoint ?? null,
        }));
      }
    });
  });

  test("registers a client by metadata-document URL and authorizes with it", async () => {
    await dual(servers, async (server, t) => {
      const c = makeClient(server);
      // unauthenticated: the document is fetched and the login redirect carries the URL client_id
      t.push(entry("authorize unauthenticated", server, await call(server, `/oauth2/authorize?${authorizeQuery(CLIENT)}`, { jar: c.jar })));
      await c.client.signUp.email({ email: "cimd-user@example.com", password: "password1234", name: "CIMD User" });
      t.push(entry("public-client", server, await call(server, `/oauth2/public-client?client_id=${encodeURIComponent(CLIENT)}`, { jar: c.jar })));
      t.push(entry("authorize unregistered redirect", server, await call(server, `/oauth2/authorize?${authorizeQuery(CLIENT, "https://client.e2e.example/other")}`, { jar: c.jar })));
      const az = await call(server, `/oauth2/authorize?${authorizeQuery(CLIENT)}`, { jar: c.jar });
      t.push(entry("authorize signed in", server, az));
      const consentQuery = redirectOf(az).split("?")[1];
      const consent = await call(server, "/oauth2/consent", { method: "POST", json: { accept: true, oauth_query: consentQuery }, jar: c.jar });
      t.push(entry("consent accept", server, consent));
      const cb = new URL(consent.data.url);
      t.push({ name: "callback params", params: [...cb.searchParams.keys()].sort(), iss: scrubURL(cb.searchParams.get("iss"), server.base) });
      const code = cb.searchParams.get("code");
      t.push(entry("token wrong verifier", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: CLIENT, code: "bogus", code_verifier: "x".repeat(50), redirect_uri: REDIRECT } })));
      const tok = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: CLIENT, code, code_verifier: verifier, redirect_uri: REDIRECT } });
      t.push(entry("token exchange", server, tok, {
        idClaims: tok.data.id_token ? JSON.parse(Buffer.from(tok.data.id_token.split(".")[1], "base64url")).aud === CLIENT : null,
      }));
      t.push(entry("userinfo", server, await call(server, "/oauth2/userinfo", { headers: { authorization: `Bearer ${tok.data.access_token}` } })));
      const rt = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", client_id: CLIENT, refresh_token: tok.data.refresh_token } });
      t.push(entry("refresh", server, rt));
      t.push(entry("refresh replay", server, await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", client_id: CLIENT, refresh_token: tok.data.refresh_token } })));
      // A second authorization revalidates the no-cache document with its ETag (304) and
      // goes straight back to the client thanks to the stored consent.
      const again = await call(server, `/oauth2/authorize?${authorizeQuery(CLIENT)}`, { jar: c.jar });
      t.push(entry("authorize again (consented)", server, again));
      // native client with a loopback redirect
      const nat = await call(server, `/oauth2/authorize?${authorizeQuery("https://native.e2e.example/client.json", "http://127.0.0.1:7777/callback")}`, { jar: c.jar });
      t.push(entry("authorize native", server, nat));
      t.push(entry("get-clients", server, await call(server, "/oauth2/get-clients", { jar: c.jar })));
    });
  });

  test("rejects invalid metadata documents and client_id URLs", async () => {
    await dual(servers, async (server, t) => {
      const c = makeClient(server);
      await c.client.signUp.email({ email: "cimd-errors@example.com", password: "password1234", name: "CIMD Errors" });
      for (const [name, id, redirect] of [
        ["client_id mismatch", "https://mismatch.e2e.example/client.json", "https://mismatch.e2e.example/callback"],
        ["symmetric auth method", "https://secret.e2e.example/client.json", "https://secret.e2e.example/callback"],
        ["forbidden field", "https://forbidden.e2e.example/client.json", "https://forbidden.e2e.example/callback"],
        ["wrong media type", "https://plain.e2e.example/client.json", "https://plain.e2e.example/callback"],
        ["unreachable document", "https://missing.e2e.example/client.json", "https://missing.e2e.example/callback"],
        ["private address", "https://127.0.0.1/client.json", "https://127.0.0.1/callback"],
        ["dot segments", "https://client.e2e.example/a/../client.json", REDIRECT],
        ["fragment-free authority form", "https:client.e2e.example/client.json", REDIRECT],
      ]) {
        t.push(entry(name, server, await call(server, `/oauth2/authorize?${authorizeQuery(id, redirect)}`, { jar: c.jar })));
      }
      t.push(entry("http client_id is not a CIMD candidate", server, await call(server, `/oauth2/authorize?${authorizeQuery("http://client.e2e.example/client.json")}`, { jar: c.jar })));
    });
    assert.ok(true);
  });
});
