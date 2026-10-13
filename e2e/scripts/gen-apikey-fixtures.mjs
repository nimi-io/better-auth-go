// Generates plugins/apikey/testdata/hash-fixtures.json with the TypeScript api-key plugin's
// defaultKeyHasher, so the Go DefaultKeyHasher can be checked byte-for-byte.
// Run from e2e/: node scripts/gen-apikey-fixtures.mjs
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defaultKeyHasher } from "@better-auth/api-key";

const keys = [
  "",
  "a",
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl",
  "pub_XyZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
  "sk-live_0123456789",
  "ünïcödé-🔑-key",
  "x".repeat(300),
];
const fixtures = [];
for (const key of keys) fixtures.push({ key, hash: await defaultKeyHasher(key) });
const out = fileURLToPath(new URL("../../plugins/apikey/testdata/hash-fixtures.json", import.meta.url));
writeFileSync(out, JSON.stringify(fixtures, null, 2) + "\n");
console.log(`wrote ${fixtures.length} fixtures to ${out}`);
