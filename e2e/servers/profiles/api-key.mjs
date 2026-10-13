// API key profile (mirrors e2e/goserver/profile_apikey.go): sessions from API keys,
// metadata, default permissions and a small per-key rate limit. DB_URL (sqlite:) shares a
// database with the Go server. /__test/verify-api-key exposes the server-only verifyApiKey.
import Database from "better-sqlite3";
import { apiKey } from "@better-auth/api-key";

export default async function (options) {
  const dbURL = process.env.DB_URL;
  if (dbURL) {
    if (!dbURL.startsWith("sqlite:")) throw new Error(`unsupported DB_URL ${dbURL}`);
    options.database = new Database(dbURL.slice("sqlite:".length));
  }
  options.plugins = [
    ...(options.plugins ?? []),
    apiKey({
      enableSessionForAPIKeys: true,
      enableMetadata: true,
      rateLimit: { enabled: true, maxRequests: 3, timeWindow: 60000 },
      permissions: { defaultPermissions: { files: ["read"] } },
    }),
  ];
}

export const testRoutes = {
  "/__test/verify-api-key": async (req, res, _url, auth) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    try {
      res.end(JSON.stringify(await auth.api.verifyApiKey({ body: JSON.parse(raw || "{}") })));
    } catch (e) {
      res.statusCode = 500;
      res.end(JSON.stringify({ error: String(e?.message ?? e) }));
    }
  },
};
