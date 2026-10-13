// Generates plugins/scim/openapi.json and plugins/scim/discovery.json from the published
// @better-auth/scim package (endpoint metadata.openapi blocks and the discovery documents).
// Usage: node e2e/scripts/gen-scim-fixtures.mjs
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { scim } from "@better-auth/scim";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "plugins", "scim");
const plugin = scim({
  connections: [{ id: "c", credentials: [{ type: "bearer", id: "t", token: "t" }] }],
  managedConnections: { credentialHashSecret: "x".repeat(32) },
});
const openapi = {};
for (const [key, ep] of Object.entries(plugin.endpoints)) {
  const meta = ep.options?.metadata;
  if (meta?.openapi) openapi[key] = meta.openapi;
}
writeFileSync(join(root, "openapi.json"), JSON.stringify(openapi, null, 2) + "\n");

const BASE = "http://base.invalid/api/auth";
const auth = betterAuth({ baseURL: "http://base.invalid", database: memoryAdapter({}), plugins: [plugin] });
const strip = (v) => JSON.parse(JSON.stringify(v).replaceAll(BASE, ""));
const schemas = strip(await auth.api.getSCIMSchemas());
const resourceTypes = strip(await auth.api.getSCIMResourceTypes());
const spc = strip(await auth.api.getSCIMServiceProviderConfig());
writeFileSync(
  join(root, "discovery.json"),
  JSON.stringify({ schemas: schemas.Resources, resourceTypes: resourceTypes.Resources, serviceProviderConfig: spc }, null, 2) + "\n",
);
console.log("wrote", Object.keys(openapi).length, "openapi entries");
