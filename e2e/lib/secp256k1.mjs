// Minimal secp256k1 / EIP-191 helpers (BigInt) for the SIWE e2e tests: the test signs
// SIWE messages with a fixed key, and the TypeScript server profile recovers the signer
// (the Go profile implements the same recovery with math/big).
import { randomBytes } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];

const mod = (a, m = P) => ((a % m) + m) % m;
function pow(b, e, m) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
const inv = (a, m = P) => pow(mod(a, m), m - 2n, m);

function add(a, b) {
  if (!a) return b;
  if (!b) return a;
  let l;
  if (a[0] === b[0]) {
    if (mod(a[1] + b[1]) === 0n) return null;
    l = mod(3n * a[0] * a[0] * inv(2n * a[1]));
  } else {
    l = mod((b[1] - a[1]) * inv(b[0] - a[0]));
  }
  const x = mod(l * l - a[0] - b[0]);
  return [x, mod(l * (a[0] - x) - a[1])];
}
function mul(k, p) {
  let r = null;
  for (let i = BigInt(k.toString(2).length) - 1n; i >= 0n; i--) {
    r = add(r, r);
    if ((k >> i) & 1n) r = add(r, p);
  }
  return r;
}

const hex = (b) => Buffer.from(b).toString("hex");
const big = (b) => BigInt("0x" + (hex(b) || "0"));
const be32 = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");

function addressOf(pub) {
  return "0x" + hex(keccak_256(Buffer.concat([be32(pub[0]), be32(pub[1])]))).slice(24);
}

export function hashMessage(message) {
  const bytes = Buffer.from(message, "utf8");
  return keccak_256(Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${bytes.length}`, "utf8"), bytes]));
}

export function toChecksumAddress(address) {
  const a = address.toLowerCase().replace("0x", "");
  const h = hex(keccak_256(Buffer.from(a, "utf8")));
  let out = "0x";
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}

export function addressFromPrivateKey(privHex) {
  return toChecksumAddress(addressOf(mul(BigInt("0x" + privHex), G)));
}

/** personal_sign: returns a 0x-prefixed 65-byte r||s||v signature. */
export function signMessage(privHex, message) {
  const d = BigInt("0x" + privHex);
  const e = big(hashMessage(message));
  for (;;) {
    const k = mod(big(randomBytes(32)), N);
    if (k === 0n) continue;
    const R = mul(k, G);
    const r = mod(R[0], N);
    if (r === 0n) continue;
    let s = mod(inv(k, N) * (e + r * d), N);
    if (s === 0n) continue;
    let recid = Number(R[1] & 1n);
    if (s > N / 2n) { s = N - s; recid ^= 1; }
    return "0x" + hex(be32(r)) + hex(be32(s)) + (27 + recid).toString(16);
  }
}

/** Recovers the signer address of a personal_sign signature (null when invalid). */
export function recoverAddress(message, signature) {
  const sig = Buffer.from(String(signature).replace(/^0x/, ""), "hex");
  if (sig.length !== 65) return null;
  let v = sig[64];
  if (v >= 27) v -= 27;
  if (v !== 0 && v !== 1) return null;
  const r = big(sig.subarray(0, 32));
  const s = big(sig.subarray(32, 64));
  if (r === 0n || s === 0n || r >= N || s >= N) return null;
  const e = big(hashMessage(message));
  const y2 = mod(r ** 3n + 7n);
  let y = pow(y2, (P + 1n) / 4n, P);
  if (mod(y * y) !== y2) return null;
  if (Number(y & 1n) !== v) y = P - y;
  const rInv = inv(r, N);
  const Q = add(mul(mod(-e * rInv, N), G), mul(mod(s * rInv, N), [r, y]));
  return Q ? addressOf(Q) : null;
}
