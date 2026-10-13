// SIWE profile (mirrors e2e/goserver/profile_siwe.go): verifyMessage performs real EIP-191
// signature recovery (secp256k1) and compares the signer with the message address.
import { randomBytes } from "node:crypto";
import { siwe } from "better-auth/plugins";
import { recoverAddress } from "../../lib/secp256k1.mjs";

const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

export default async function (options) {
  options.plugins = [
    ...(options.plugins ?? []),
    siwe({
      domain: "example.com",
      async getNonce() {
        return [...randomBytes(32)].map((b) => ALPHABET[b % ALPHABET.length]).join("");
      },
      async verifyMessage({ message, signature, address }) {
        const signer = recoverAddress(message, signature);
        return !!signer && signer.toLowerCase() === address.toLowerCase();
      },
    }),
  ];
}
