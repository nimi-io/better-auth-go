// MCP profile (mirrors e2e/goserver/profile_mcp.go): the MCP authorization server with
// resource <base>/mcp, dynamic registration, and a protected JSON-RPC endpoint at /mcp
// (requireMcpAuth requiring mcp:read; tools/call steps up to mcp:write). The RFC 9728
// protected resource metadata lives outside /api/auth, so its paths are forwarded to the
// auth handler.
import { jwt } from "better-auth/plugins";
import { toNodeHandler } from "better-auth/node";
import { createInsufficientScopeError } from "better-auth/oauth2";
import { mcp, requireMcpAuth } from "@better-auth/mcp";

let resource = "";

export default async function (options, { baseURL }) {
  resource = `${baseURL}/mcp`;
  options.plugins = [
    ...(options.plugins ?? []),
    jwt(),
    mcp({
      loginPage: "/login",
      consentPage: "/consent",
      resource,
      allowDynamicClientRegistration: true,
      allowUnauthenticatedClientRegistration: true,
      scopes: ["openid", "profile", "email", "offline_access", "mcp:read", "mcp:write"],
    }),
  ];
}

async function toolHandler(request, claims) {
  const body = await request.json().catch(() => ({}));
  const scopes = typeof claims.scope === "string" ? claims.scope.split(" ") : [];
  if (body.method === "tools/call" && !scopes.includes("mcp:write")) {
    throw createInsufficientScopeError(["mcp:write"], "tool requires mcp:write");
  }
  return Response.json({
    jsonrpc: "2.0",
    id: body.id,
    result: { method: body.method, sub: claims.sub, client_id: claims.client_id, scope: claims.scope, aud: claims.aud },
  });
}

async function readBody(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  return raw;
}

// ts-server.mjs presets content-type for non-/api/auth paths; the auth handler sets its own.
const forward = (req, res, _url, auth) => {
  res.removeHeader("content-type");
  return toNodeHandler(auth.handler)(req, res);
};

export const testRoutes = {
  "/.well-known/oauth-protected-resource": forward,
  "/.well-known/oauth-protected-resource/mcp": forward,
  "/mcp": async (req, res, url, auth) => {
    const body = req.method === "GET" || req.method === "HEAD" ? undefined : await readBody(req);
    const request = new Request(url, { method: req.method, headers: req.headers, body });
    try {
      const response = await requireMcpAuth(auth, toolHandler, { resource, requiredScopes: ["mcp:read"] })(request);
      res.statusCode = response.status;
      response.headers.forEach((v, k) => res.setHeader(k, v));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (e) {
      res.statusCode = 500;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: String(e?.message ?? e) }));
    }
  },
};
