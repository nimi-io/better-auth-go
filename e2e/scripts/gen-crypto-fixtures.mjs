// Generates fixtures produced by the official TypeScript implementation.
// The Go test suite (crypto/compat_test.go) verifies them.
import { hashPassword, symmetricEncrypt, symmetricEncodeJWT, signJWT, makeSignature } from "better-auth/crypto";
import { writeFileSync } from "node:fs";

const secret = "test-secret-at-least-32-characters-long!!";
const rotating = {
  keys: new Map([[2, "second-secret-value-that-is-long-enough"], [1, "first-secret-value-that-is-long-enough!"]]),
  currentVersion: 2,
  legacySecret: secret,
};
const passwords = ["password123", "Ünïcödé-ﬁ-ｐａｓｓ", "", "a".repeat(128)];
const out = {
  secret,
  rotating: { keys: [...rotating.keys.entries()], currentVersion: 2, legacySecret: secret },
  passwords: await Promise.all(passwords.map(async (p) => ({ password: p, hash: await hashPassword(p) }))),
  symmetric: { plaintext: "hello world ✓", ciphertext: await symmetricEncrypt({ key: secret, data: "hello world ✓" }) },
  symmetricRotating: {
    plaintext: "rotated",
    ciphertext: await symmetricEncrypt({ key: rotating, data: "rotated" }),
    legacyCiphertext: await symmetricEncrypt({ key: secret, data: "legacy" }),
  },
  jwe: {
    payload: { session: { token: "abc" }, user: { id: "u1", name: "Ann" }, updatedAt: 1736000000000, version: "1" },
    token: await symmetricEncodeJWT({ session: { token: "abc" }, user: { id: "u1", name: "Ann" }, updatedAt: 1736000000000, version: "1" }, secret, "better-auth-session", 3153600000),
    rotatingToken: await symmetricEncodeJWT({ hello: "rotating" }, rotating, "better-auth-session", 3153600000),
  },
  jwt: { token: await signJWT({ email: "a@b.co", updateTo: undefined }, secret, 3153600000) },
  signature: { value: "session-token-value", signature: await makeSignature("session-token-value", secret) },
};
writeFileSync(new URL("../../crypto/testdata/ts_fixtures.json", import.meta.url), JSON.stringify(out, null, 2));
console.log("wrote crypto/testdata/ts_fixtures.json");
