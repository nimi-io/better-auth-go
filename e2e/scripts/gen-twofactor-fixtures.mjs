// Two-factor cross-compatibility fixtures, produced by the official TypeScript
// implementation (better-auth@1.7.7, @better-auth/utils@0.4.2).
//
//   node e2e/scripts/gen-twofactor-fixtures.mjs            -> writes plugins/twofactor/testdata/ts_fixtures.json
//   node e2e/scripts/gen-twofactor-fixtures.mjs verify F   -> checks values written by Go (F is JSON),
//                                                            prints {"ok":true} or the failures
//
// The Go tests (plugins/twofactor/compat_test.go) read the fixtures (TS -> Go) and run the
// verify mode on values produced by Go (Go -> TS).
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createOTP } from "@better-auth/utils/otp";
import { symmetricEncrypt, symmetricDecrypt } from "better-auth/crypto";

// The backup-code helpers are not part of the package exports; load the dist files directly.
const pkgDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../node_modules/better-auth");
const tfDir = path.join(pkgDir, "dist/plugins/two-factor");
const { generateBackupCodes } = await import(path.join(tfDir, "backup-codes/index.mjs"));
const { defaultKeyHasher } = await import(path.join(tfDir, "utils.mjs"));

const secret = "better-auth-secret-12345678901234567890";
const rotating = {
  keys: new Map([[2, "second-secret-value-that-is-long-enough"], [1, "first-secret-value-that-is-long-enough!"]]),
  currentVersion: 2,
  legacySecret: secret,
};

async function withNow(ms, fn) {
  const real = Date.now;
  Date.now = () => ms;
  try { return await fn(); } finally { Date.now = real; }
}

async function generate() {
  const totpSecrets = ["abcdefghijklmnopqrstuvwxyz012345", "Zx-_9QwErTyUiOpAsDfGhJkLzXcVbNm1", "12345678901234567890"];
  const times = [0, 59000, 1111111109000, 1234567890000, 2000000000000, 1760000012345];
  const totp = [];
  for (const s of totpSecrets) {
    for (const digits of [6, 8]) {
      for (const period of [30, 60]) {
        for (const t of times) {
          totp.push({ secret: s, digits, period, time: t, code: await withNow(t, () => createOTP(s, { digits, period }).totp()) });
        }
      }
    }
  }
  const hotp = [];
  for (const counter of [0, 1, 2, 9, 1234567, 4294967296]) {
    hotp.push({ secret: "12345678901234567890", counter, code: await createOTP("12345678901234567890").hotp(counter) });
  }
  const uris = [
    { secret: totpSecrets[0], digits: 6, period: 30, issuer: "Better Auth", account: "test@test.com" },
    { secret: totpSecrets[1], digits: 8, period: 60, issuer: "My App: *test* ~(x)!'", account: "ü+tag@example.com" },
    { secret: totpSecrets[2], digits: 6, period: 30, issuer: "a&b=c/d?e#f%g", account: "name with space" },
  ].map((u) => ({ ...u, uri: createOTP(u.secret, { digits: u.digits, period: u.period }).url(u.issuer, u.account) }));

  const encryptedSecrets = [];
  for (const s of totpSecrets) {
    encryptedSecrets.push({ key: "plain", secret: s, encrypted: await symmetricEncrypt({ key: secret, data: s }) });
    encryptedSecrets.push({ key: "rotating", secret: s, encrypted: await symmetricEncrypt({ key: rotating, data: s }) });
  }
  const backupCodes = [];
  for (const [key, k] of [["plain", secret], ["rotating", rotating]]) {
    const enc = await generateBackupCodes(k, { storeBackupCodes: "encrypted" });
    backupCodes.push({ key, storage: "encrypted", codes: enc.backupCodes, stored: enc.encryptedBackupCodes });
  }
  const plain = await generateBackupCodes(secret, { storeBackupCodes: "plain", amount: 3, length: 12 });
  backupCodes.push({ key: "plain", storage: "plain", codes: plain.backupCodes, stored: plain.encryptedBackupCodes });
  const custom = ["a<b>& c", "ünï-cödé", "plain"];
  const customEnc = await generateBackupCodes(secret, { storeBackupCodes: "encrypted", customBackupCodesGenerate: () => custom });
  backupCodes.push({ key: "plain", storage: "encrypted", codes: customEnc.backupCodes, stored: customEnc.encryptedBackupCodes });

  const hashed = ["000000", "123456", "98765432"].map((otp) => ({ otp, hash: null }));
  for (const h of hashed) h.hash = await defaultKeyHasher(h.otp);

  return {
    secret,
    rotating: { keys: [...rotating.keys.entries()], currentVersion: 2, legacySecret: secret },
    totp, hotp, uris, encryptedSecrets, backupCodes, hashedOTP: hashed,
  };
}

async function verify(file) {
  const v = JSON.parse(readFileSync(file, "utf8"));
  const failures = [];
  const keyOf = (k) => (k === "rotating" ? rotating : secret);
  for (const e of v.encryptedSecrets ?? []) {
    try {
      const d = await symmetricDecrypt({ key: keyOf(e.key), data: e.encrypted });
      if (d !== e.secret) failures.push(`secret ${e.key}: got ${d}`);
    } catch (err) { failures.push(`secret ${e.key}: ${err}`); }
  }
  for (const b of v.backupCodes ?? []) {
    try {
      const raw = b.storage === "encrypted" ? await symmetricDecrypt({ key: keyOf(b.key), data: b.stored }) : b.stored;
      if (raw !== JSON.stringify(b.codes)) failures.push(`backup ${b.key}/${b.storage}: ${raw}`);
    } catch (err) { failures.push(`backup ${b.key}: ${err}`); }
  }
  for (const t of v.totp ?? []) {
    const ok = await withNow(t.time, () => createOTP(t.secret, { digits: t.digits, period: t.period }).verify(t.code));
    if (!ok) failures.push(`totp ${t.secret}@${t.time} ${t.code} rejected`);
  }
  for (const u of v.uris ?? []) {
    const want = createOTP(u.secret, { digits: u.digits, period: u.period }).url(u.issuer, u.account);
    if (want !== u.uri) failures.push(`uri ${u.uri} != ${want}`);
  }
  for (const h of v.hashedOTP ?? []) {
    if ((await defaultKeyHasher(h.otp)) !== h.hash) failures.push(`hash ${h.otp}`);
  }
  console.log(JSON.stringify({ ok: failures.length === 0, failures }));
  if (failures.length) process.exitCode = 1;
}

if (process.argv[2] === "verify") {
  await verify(process.argv[3]);
} else {
  const out = await generate();
  const dir = new URL("../../plugins/twofactor/testdata/", import.meta.url);
  mkdirSync(dir, { recursive: true });
  writeFileSync(new URL("ts_fixtures.json", dir), JSON.stringify(out, null, 2));
  console.log("wrote plugins/twofactor/testdata/ts_fixtures.json");
}
