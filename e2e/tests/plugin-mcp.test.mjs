// MCP parity (@better-auth/mcp 1.7.7): RFC 9728 protected resource metadata (root and
// resource-path alias, HEAD, 405), authorization-server discovery, dynamic registration
// bound to the MCP resource, authorization code + PKCE with the resource indicator, a
// protected JSON-RPC endpoint (requireMcpAuth) accepting and rejecting tokens with RFC
// 6750 challenges (missing token, invalid token, wrong scheme, insufficient scope step-up)
// and the MCP refresh-token reuse interval, on the Go server and the reference TypeScript
// server (profile "mcp"); normalised transcripts must be identical.
import { test, before, after, describe } from "node:test";
import { createHash } from "node:crypto";
import { startServers, makeClient, dual, normalize } from "../lib/harness.mjs";

const REDIRECT = "https://mcp-client.example.com/callback";
const verifier = "e2e-mcp-verifier-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGH";
const challenge = createHash("sha256").update(verifier).digest("base64url");

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
      else if (["url", "location"].includes(k)) out[k] = scrubURL(x, base);
      else out[k] = scrub(x, base);
    }
    return out;
  }
  if (typeof v === "string") return normalize(scrubURL(v, base), base);
  return v;
}

async function call(server, path, { method = "GET", headers = {}, form, json, raw, jar } = {}) {
  const h = new Headers(headers);
  if (jar) { const c = jar.header(); if (c) h.set("cookie", c); }
  let body;
  if (form) { body = new URLSearchParams(form).toString(); h.set("content-type", "application/x-www-form-urlencoded"); }
  if (json) { body = JSON.stringify(json); h.set("content-type", "application/json"); }
  if (raw !== undefined) body = raw;
  if (method !== "GET" && method !== "HEAD" && !h.has("origin")) h.set("origin", server.base);
  const url = path.startsWith("http") ? path : path.startsWith("/.well-known/oauth-protected-resource") || path === "/mcp" ? `${server.base}${path}` : `${server.base}/api/auth${path}`;
  const res = await fetch(url, { method, headers: h, body, redirect: "manual" });
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
    contentType: r.res.headers.get("content-type"),
    cacheControl: r.res.headers.get("cache-control"),
    allow: r.res.headers.get("allow"),
    wwwAuthenticate: r.res.headers.get("www-authenticate"),
    ...extra,
  }, server.base);
}

const redirectOf = (r) => r.res.headers.get("location") ?? r.data?.url;
const rpc = (method, id = 1) => JSON.stringify({ jsonrpc: "2.0", id, method });
const bearer = (token) => ({ authorization: `Bearer ${token}`, "content-type": "application/json" });

let servers;
describe("mcp parity", () => {
  before(async () => { servers = await startServers("mcp"); });
  after(async () => { await servers?.stop(); });

  test("protected resource and authorization server discovery", async () => {
    await dual(servers, async (server, t) => {
      for (const p of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
        t.push(entry(`GET ${p}`, server, await call(server, p)));
        t.push(entry(`HEAD ${p}`, server, await call(server, p, { method: "HEAD" })));
        t.push(entry(`POST ${p}`, server, await call(server, p, { method: "POST", json: {} })));
      }
      for (const p of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
        t.push(entry(`GET ${p}`, server, await call(server, p)));
      }
    });
  });

  test("protected MCP resource accepts bound tokens and rejects others", async () => {
    await dual(servers, async (server, t) => {
      const resource = `${server.base}/mcp`;
      // unauthenticated / invalid tokens
      t.push(entry("mcp no token", server, await call(server, "/mcp", { method: "POST", raw: rpc("initialize"), headers: { "content-type": "application/json" } })));
      t.push(entry("mcp invalid token", server, await call(server, "/mcp", { method: "POST", raw: rpc("initialize"), headers: bearer("not-a-token") })));
      t.push(entry("mcp basic scheme", server, await call(server, "/mcp", { method: "POST", raw: rpc("initialize"), headers: { authorization: "Basic abc" } })));

      // dynamic registration is bound to the MCP resource
      const reg = await call(server, "/oauth2/register", { method: "POST", json: { redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", client_name: "MCP Client" } });
      t.push(entry("register", server, reg));
      const clientId = reg.data.client_id;

      const c = makeClient(server);
      await c.client.signUp.email({ email: "mcp-user@example.com", password: "password1234", name: "MCP User" });
      const authorize = async (scope, extra = {}) => {
        const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, scope, state: "mcp-state",
          code_challenge: challenge, code_challenge_method: "S256", resource, prompt: "consent", ...extra });
        const az = await call(server, `/oauth2/authorize?${q}`, { jar: c.jar });
        const consent = await call(server, "/oauth2/consent", { method: "POST", json: { accept: true, oauth_query: redirectOf(az).split("?")[1] }, jar: c.jar });
        return { az, consent, code: new URL(consent.data.url).searchParams.get("code") };
      };
      const first = await authorize("openid offline_access mcp:read");
      t.push(entry("authorize", server, first.az));
      t.push(entry("consent", server, first.consent));
      const tok = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: clientId, code: first.code, code_verifier: verifier, redirect_uri: REDIRECT, resource } });
      const claims = JSON.parse(Buffer.from(tok.data.access_token.split(".")[1], "base64url"));
      t.push(entry("token", server, tok, { aud: scrub(claims.aud, server.base), scope: claims.scope, azp: claims.azp ?? null }));
      const at = tok.data.access_token;

      t.push(entry("mcp initialize", server, await call(server, "/mcp", { method: "POST", raw: rpc("initialize"), headers: bearer(at) })));
      t.push(entry("mcp tools/call insufficient scope", server, await call(server, "/mcp", { method: "POST", raw: rpc("tools/call", 2), headers: bearer(at) })));
      t.push(entry("mcp dpop scheme for bearer token", server, await call(server, "/mcp", { method: "POST", raw: rpc("initialize"), headers: { authorization: `DPoP ${at}` } })));

      // without a resource indicator the token is bound to the client's registered default
      // resource (the MCP resource, linked at registration)
      const unbound = await authorize("openid mcp:read");
      const tok2 = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: clientId, code: unbound.code, code_verifier: verifier, redirect_uri: REDIRECT } });
      t.push(entry("token without resource", server, tok2));
      t.push(entry("mcp token from default resource", server, await call(server, "/mcp", { method: "POST", raw: rpc("initialize"), headers: bearer(tok2.data.access_token) })));

      // step up to mcp:write
      const step = await authorize("openid offline_access mcp:read mcp:write");
      const tok3 = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", client_id: clientId, code: step.code, code_verifier: verifier, redirect_uri: REDIRECT, resource } });
      t.push(entry("step-up token", server, tok3));
      t.push(entry("mcp tools/call", server, await call(server, "/mcp", { method: "POST", raw: rpc("tools/call", 3), headers: bearer(tok3.data.access_token) })));

      // MCP defaults refreshTokenReuseInterval to 30s: a retried refresh returns the same response
      const r1 = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", client_id: clientId, refresh_token: tok3.data.refresh_token, resource } });
      t.push(entry("refresh", server, r1));
      const r2 = await call(server, "/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", client_id: clientId, refresh_token: tok3.data.refresh_token, resource } });
      t.push(entry("refresh retry", server, r2, { sameAccessToken: r2.data.access_token === r1.data.access_token, sameRefreshToken: r2.data.refresh_token === r1.data.refresh_token }));
      t.push(entry("mcp refreshed token", server, await call(server, "/mcp", { method: "POST", raw: rpc("tools/list", 4), headers: bearer(r1.data.access_token) })));
    });
  });
});
