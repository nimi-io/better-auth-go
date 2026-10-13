// Software WebAuthn authenticator (ES256, node:crypto) for the passkey e2e tests and
// fixtures. It answers the options JSON returned by generate-register-options /
// generate-authenticate-options with RegistrationResponseJSON / AuthenticationResponseJSON,
// exactly what @simplewebauthn/browser would send.
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (buf) => createHash("sha256").update(buf).digest();

// Minimal CBOR encoder (unsigned/negative ints, byte/text strings, maps, arrays).
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}
export function cbor(v) {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (typeof v === "string") { const b = Buffer.from(v, "utf8"); return Buffer.concat([head(3, b.length), b]); }
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error(`cbor: unsupported ${typeof v}`);
}

export class SoftAuthenticator {
  constructor({ origin, attestation = "none", aaguid = "ea9b8d664d011d213ce4b6b48cb575d4" } = {}) {
    this.origin = origin;
    this.attestation = attestation;
    this.aaguid = Buffer.from(aaguid, "hex");
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.x = Buffer.from(jwk.x, "base64url");
    this.y = Buffer.from(jwk.y, "base64url");
    this.credID = randomBytes(16);
    this.counter = 0;
    this.userHandle = undefined;
  }
  get id() { return b64url(this.credID); }
  coseKey() { return cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, this.x], [-3, this.y]])); }
  authData(rpID, attested) {
    const counter = Buffer.alloc(4); counter.writeUInt32BE(this.counter);
    const flags = 0x01 | 0x04 | (attested ? 0x40 : 0);
    const parts = [sha256(Buffer.from(rpID)), Buffer.from([flags]), counter];
    if (attested) {
      const len = Buffer.alloc(2); len.writeUInt16BE(this.credID.length);
      parts.push(this.aaguid, len, this.credID, this.coseKey());
    }
    return Buffer.concat(parts);
  }
  clientData(type, challenge) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }));
  }
  register(options) {
    this.userHandle = options.user.id;
    const cd = this.clientData("webauthn.create", options.challenge);
    const authData = this.authData(options.rp.id, true);
    let attStmt = new Map();
    if (this.attestation === "packed") {
      const sig = sign("sha256", Buffer.concat([authData, sha256(cd)]), this.privateKey);
      attStmt = new Map([["alg", -7], ["sig", sig]]);
    }
    const att = cbor(new Map([["fmt", this.attestation], ["attStmt", attStmt], ["authData", authData]]));
    return {
      id: this.id, rawId: this.id, type: "public-key",
      response: { clientDataJSON: b64url(cd), attestationObject: b64url(att), transports: ["internal", "hybrid"], publicKeyAlgorithm: -7 },
      clientExtensionResults: { credProps: { rk: true } },
      authenticatorAttachment: "platform",
    };
  }
  authenticate(options) {
    this.counter++;
    const cd = this.clientData("webauthn.get", options.challenge);
    const authData = this.authData(options.rpId, false);
    const sig = sign("sha256", Buffer.concat([authData, sha256(cd)]), this.privateKey);
    return {
      id: this.id, rawId: this.id, type: "public-key",
      response: { clientDataJSON: b64url(cd), authenticatorData: b64url(authData), signature: b64url(sig), userHandle: this.userHandle },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }
}
