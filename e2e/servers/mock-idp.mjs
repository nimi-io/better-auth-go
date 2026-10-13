// Mock identity provider for the OAuth e2e tests. Both the Go and the TypeScript servers
// rewrite requests for provider hosts (github.com, googleapis.com, ...) to this server as
// http://127.0.0.1:<port>/<original-host>/<original-path>, so the real provider code runs on
// both sides.
//
// Conventions:
//   - the authorization code is "code-<base64url(json profile)>"; the access token echoes it,
//     so user-info endpoints can return that profile.
//   - GET /__idp/id-token?claims=<json> returns an RS256 id token signed by this IdP.
import { createServer } from "node:http";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

const port = Number(process.env.PORT || 4900);
const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...(await exportJWK(publicKey)), kid: "e2e-key", alg: "RS256", use: "sig" };

function profileFromToken(token) {
  try {
    return JSON.parse(Buffer.from(String(token).replace(/^(code-|Bearer )/, ""), "base64url").toString());
  } catch {
    return null;
  }
}

async function readBody(req) {
  let body = "";
  for await (const chunk of req) body += chunk;
  return body;
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const path = url.pathname;
  const auth = req.headers.authorization || "";
  if (path === "/__idp/health") return res.end("ok");
  if (path === "/__idp/id-token") {
    const claims = JSON.parse(url.searchParams.get("claims") || "{}");
    const token = await new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "e2e-key", typ: "JWT" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
    return json(res, 200, { token });
  }
  // GitHub
  if (path === "/github.com/login/oauth/access_token" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    const code = form.get("code");
    if (!code?.startsWith("code-")) return json(res, 200, { error: "bad_verification_code" });
    return json(res, 200, { access_token: code.slice(5), token_type: "bearer", scope: "read:user,user:email" });
  }
  if (path === "/api.github.com/user") {
    const p = profileFromToken(auth.replace(/^Bearer /i, ""));
    if (!p) return json(res, 401, { message: "Bad credentials" });
    return json(res, 200, { id: p.id, login: p.login ?? "octo", name: p.name ?? null, email: null, avatar_url: p.avatar ?? "https://avatars.example/u.png" });
  }
  if (path === "/api.github.com/user/emails") {
    const p = profileFromToken(auth.replace(/^Bearer /i, ""));
    if (!p) return json(res, 401, { message: "Bad credentials" });
    return json(res, 200, [{ email: p.email, primary: true, verified: p.verified !== false, visibility: "public" }]);
  }
  // Google
  if (path === "/www.googleapis.com/oauth2/v3/certs") return json(res, 200, { keys: [jwk] });
  if (path === "/oauth2.googleapis.com/token" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    const p = profileFromToken(form.get("code"));
    if (!p) return json(res, 400, { error: "invalid_grant" });
    const idToken = await new SignJWT({ iss: "https://accounts.google.com", aud: form.get("client_id"), email_verified: true, ...p })
      .setProtectedHeader({ alg: "RS256", kid: "e2e-key", typ: "JWT" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
    return json(res, 200, { access_token: "ya29.e2e", refresh_token: "1//refresh", expires_in: 3599, scope: "openid email profile", token_type: "Bearer", id_token: idToken });
  }
  // Generic OpenID provider (generic-oauth / oauth-popup profiles), served over plain http at
  // /oidc. The code is "code-<base64url(json profile)>"; profile.nonce is echoed in the id
  // token, profile.idTokenClaims are merged into it, the rest is returned by /userinfo.
  if (path.startsWith("/oidc/") || path.startsWith("/oidc-plain/")) {
    const issuer = `http://127.0.0.1:${port}/oidc`;
    if (path === "/oidc/.well-known/openid-configuration") {
      return json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
        end_session_endpoint: `${issuer}/logout`,
        id_token_signing_alg_values_supported: ["RS256"],
        response_types_supported: ["code"],
      });
    }
    if (path === "/oidc/jwks") return json(res, 200, { keys: [jwk] });
    if ((path === "/oidc/token" || path === "/oidc-plain/token") && req.method === "POST") {
      const form = new URLSearchParams(await readBody(req));
      let clientId = form.get("client_id");
      if (auth.startsWith("Basic ")) clientId = decodeURIComponent(Buffer.from(auth.slice(6), "base64").toString().split(":")[0]);
      if (form.get("grant_type") === "refresh_token") {
        return json(res, 200, { access_token: `refreshed-${form.get("refresh_token")}`, refresh_token: "rotated-refresh", expires_in: 3600, token_type: "Bearer", scope: "openid profile" });
      }
      const p = profileFromToken(form.get("code"));
      if (!p) return json(res, 400, { error: "invalid_grant" });
      const out = { access_token: form.get("code").slice(5), refresh_token: "oidc-refresh", expires_in: 3600, token_type: "Bearer", scope: p.scope ?? "openid profile email" };
      if (path === "/oidc/token") {
        out.id_token = await new SignJWT({ iss: issuer, aud: clientId, sub: p.sub ?? "unknown", ...(p.nonce ? { nonce: p.nonce } : {}), ...(p.idTokenClaims ?? {}) })
          .setProtectedHeader({ alg: "RS256", kid: "e2e-key", typ: "JWT" })
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(privateKey);
      }
      return json(res, 200, out);
    }
    if (path === "/oidc/userinfo" || path === "/oidc-plain/userinfo") {
      const p = profileFromToken(auth.replace(/^Bearer /i, ""));
      if (!p) return json(res, 401, { error: "invalid_token" });
      const { nonce, idTokenClaims, scope, ...info } = p;
      return json(res, 200, info);
    }
  }
  json(res, 404, { error: "not_found", path });
}).listen(port, "127.0.0.1", () => console.log(`mock idp on http://127.0.0.1:${port}`));
