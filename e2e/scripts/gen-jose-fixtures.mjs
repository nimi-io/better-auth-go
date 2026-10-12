// Generates JWTs signed by the `jose` npm library (used by better-auth) so the Go jose
// package can be verified against an independent implementation.
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from "jose";
import { writeFileSync } from "node:fs";

const algs = [["RS256", {}], ["PS256", {}], ["ES256", {}], ["ES384", {}], ["ES512", {}], ["EdDSA", { crv: "Ed25519" }]];
const out = { keys: [], tokens: [] };
for (const [alg, opts] of algs) {
  const { publicKey, privateKey } = await generateKeyPair(alg, { ...opts, extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  pub.kid = priv.kid = `kid-${alg}`;
  pub.alg = priv.alg = alg;
  const token = await new SignJWT({ sub: "user-1", email: "a@example.com", nonce: "n-1" })
    .setProtectedHeader({ alg, kid: pub.kid })
    .setIssuer("https://issuer.example.com")
    .setAudience("client-1")
    .setIssuedAt()
    .setExpirationTime("100y")
    .sign(privateKey);
  out.keys.push({ alg, public: pub, private: priv, thumbprint: await calculateJwkThumbprint(pub) });
  out.tokens.push({ alg, token });
}
writeFileSync(new URL("../../jose/testdata/fixtures.json", import.meta.url), JSON.stringify(out, null, 2));
console.log("wrote jose/testdata/fixtures.json");
