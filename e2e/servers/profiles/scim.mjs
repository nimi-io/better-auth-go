// SCIM profile (mirrors e2e/goserver/profile_scim.go): a static "workforce" connection, a
// read-only credential, a second connection sharing the provisioning domain, and the
// managed connection catalog. DB_URL (sqlite:) shares a database with the Go server.
// /__test/scim/call invokes any server-only SCIM endpoint with a JSON body.
import Database from "better-sqlite3";
import { scim } from "@better-auth/scim";

export default async function (options) {
  const dbURL = process.env.DB_URL;
  if (dbURL) {
    if (!dbURL.startsWith("sqlite:")) throw new Error(`unsupported DB_URL ${dbURL}`);
    options.database = new Database(dbURL.slice("sqlite:".length));
  }
  options.plugins = [
    ...(options.plugins ?? []),
    scim({
      connections: [
        {
          id: "workforce",
          credentials: [
            { type: "bearer", id: "workforce-admin", token: "e2e-scim-token" },
            {
              type: "bearer",
              id: "workforce-reader",
              token: "e2e-scim-read-token",
              scopes: ["scim.users.read", "scim.groups.read"],
            },
          ],
        },
        {
          id: "partners",
          provisioningDomainId: "workforce",
          credentials: [{ type: "bearer", id: "partners-admin", token: "e2e-scim-partners-token" }],
        },
      ],
      managedConnections: { credentialHashSecret: "e2e-scim-managed-credential-hash-secret-0123456789" },
    }),
  ];
}

export const testRoutes = {
  "/__test/scim/call": async (req, res, _url, auth) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const { endpoint, body = {} } = JSON.parse(raw || "{}");
    if (typeof body.expiresAt === "string") body.expiresAt = new Date(body.expiresAt);
    try {
      res.end(JSON.stringify({ data: await auth.api[endpoint]({ body }) }));
    } catch (e) {
      if (e?.statusCode) res.end(JSON.stringify({ error: { status: e.statusCode, body: e.body } }));
      else res.end(JSON.stringify({ error: { status: 500, message: String(e?.message ?? e) } }));
    }
  },
};
