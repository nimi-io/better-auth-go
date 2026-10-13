// SIWE plugin parity through the official siweClient. Messages are EIP-4361 formatted and
// signed with a real secp256k1 key (EIP-191 personal_sign); both servers recover the signer.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { siweClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch } from "../lib/harness.mjs";
import { addressFromPrivateKey, signMessage } from "../lib/secp256k1.mjs";

const plugins = [siweClient()];
const KEY = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const OTHER_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const address = addressFromPrivateKey(KEY);

let servers;
before(async () => { servers = await startServers("siwe", { envFor: { go: { MIGRATE: "1" } } }); });
after(async () => { await servers?.stop(); });

const message = ({ nonce, domain = "example.com", addr = address, chainId = 1, extra = "" }) =>
  `${domain} wants you to sign in with your Ethereum account:\n${addr}\n\nSign in to the e2e suite.\n\nURI: https://${domain}\nVersion: 1\nChain ID: ${chainId}\nNonce: ${nonce}\nIssued At: 2024-01-01T00:00:00.000Z${extra}`;

test("siwe: nonce, signed verification and message binding", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const n1 = await record(t, "nonce", c, () => c.client.siwe.nonce());
    const msg = message({ nonce: n1.data.nonce });
    await record(t, "verify signed", c, () => c.client.siwe.verify({ message: msg, signature: signMessage(KEY, msg) }));
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "nonce replay", c, () => c.client.siwe.verify({ message: msg, signature: signMessage(KEY, msg) }));
    const n2 = await record(t, "get-nonce alias", c, () => c.client.siwe.getNonce());
    const lower = message({ nonce: n2.data.nonce, addr: address.toLowerCase() });
    await record(t, "verify lowercase address (same user)", c, () => c.client.siwe.verify({ message: lower, signature: signMessage(KEY, lower) }));
    const n3 = await record(t, "nonce 3", c, () => c.client.siwe.nonce());
    const polygon = message({ nonce: n3.data.nonce, chainId: 137 });
    await record(t, "verify other chain", c, () => c.client.siwe.verify({ message: polygon, signature: signMessage(KEY, polygon) }));
    const n4 = await record(t, "nonce 4", c, () => c.client.siwe.nonce());
    const m4 = message({ nonce: n4.data.nonce });
    await record(t, "signature by other key", c, () => c.client.siwe.verify({ message: m4, signature: signMessage(OTHER_KEY, m4) }));
    const n5 = await record(t, "nonce 5", c, () => c.client.siwe.nonce());
    const m5 = message({ nonce: n5.data.nonce, domain: "evil.example.com" });
    await record(t, "wrong domain", c, () => c.client.siwe.verify({ message: m5, signature: signMessage(KEY, m5) }));
    const n6 = await record(t, "nonce 6", c, () => c.client.siwe.nonce());
    const m6 = message({ nonce: n6.data.nonce, extra: "\nExpiration Time: 2020-01-01T00:00:00.000Z" });
    await record(t, "expired message", c, () => c.client.siwe.verify({ message: m6, signature: signMessage(KEY, m6) }));
    const n7 = await record(t, "nonce 7", c, () => c.client.siwe.nonce());
    const m7 = message({ nonce: n7.data.nonce, extra: "\nNot Before: 2999-01-01T00:00:00.000Z" });
    await record(t, "not yet valid", c, () => c.client.siwe.verify({ message: m7, signature: signMessage(KEY, m7) }));
    const m8 = message({ nonce: "short1" });
    await record(t, "invalid nonce", c, () => c.client.siwe.verify({ message: m8, signature: signMessage(KEY, m8) }));
    await record(t, "unknown nonce", c, () => c.client.siwe.verify({ message: message({ nonce: "UnknownNonce12345" }), signature: "0x00" }));
    await record(t, "garbage message", c, () => c.client.siwe.verify({ message: "gm", signature: "0x00" }));
    await record(t, "invalid email", c, () => c.client.siwe.verify({ message: msg, signature: "0x00", email: "nope" }));
    await record(t, "empty signature", c, () => c.client.siwe.verify({ message: msg, signature: "" }));
    await recordFetch(t, "obsolete nonce inputs", c, "/siwe/nonce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ walletAddress: address }) });
    await recordFetch(t, "obsolete verify inputs", c, "/siwe/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: msg, signature: "0x00", chainId: 1 }) });
  }, { imageNullEqualsAbsent: true });
  assert.equal(t[1].data.success, true);
  assert.equal(t[1].data.user.walletAddress, address);
  assert.equal(t[2].data.user.email, `${address.toLowerCase()}@siwe.placeholder.invalid`);
  assert.equal(t[3].error.code, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
  assert.equal(t[5].data.user.id, t[1].data.user.id);
  assert.equal(t[9].status, 401);
});
