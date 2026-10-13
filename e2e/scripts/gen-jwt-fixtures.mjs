// Generates jwt plugin fixtures with better-auth@1.7.7 for plugins/jwt/ts_compat_test.go:
// JWKS rows exactly as stored by TypeScript (private keys encrypted with the secret via
// symmetricEncrypt), the public /jwks document and tokens signed by signJWT.
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import Database from "better-sqlite3";
import { writeFileSync } from "node:fs";

const secret = "jwt-fixture-secret-that-is-long-enough-for-better-auth";
const baseURL = "http://localhost:3000";
const out = { secret, baseURL, cases: [] };
for (const [alg, encrypt] of [["EdDSA", true], ["ES256", true], ["ES512", true], ["RS256", true], ["PS256", true], ["EdDSA", false]]) {
  const auth = betterAuth({
    baseURL, secret, database: new Database(":memory:"), logger: { level: "error" }, telemetry: { enabled: false },
    plugins: [jwt({ jwks: { keyPairConfig: { alg }, disablePrivateKeyEncryption: !encrypt } })],
  });
  const ctx = await auth.$context;
  await ctx.runMigrations();
  const jwks = await auth.api.getJwks();
  const { token } = await auth.api.signJWT({ body: { payload: { sub: "user-1", custom: "value", exp: 4102444800 } } });
  const rows = (await ctx.adapter.findMany({ model: "jwks" })).map((r) => ({
    ...r, createdAt: r.createdAt.toISOString(), expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
  }));
  out.cases.push({ alg, encrypted: encrypt, rows, jwks, token });
}
writeFileSync(new URL("../../plugins/jwt/testdata/ts-fixtures.json", import.meta.url), JSON.stringify(out, null, 2));
console.log("wrote plugins/jwt/testdata/ts-fixtures.json");
