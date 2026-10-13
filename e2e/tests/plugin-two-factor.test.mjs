// Two-factor plugin parity: the official twoFactorClient against the Go server and the
// reference TypeScript server (profile "two-factor"); normalised transcripts must be
// identical. A second suite shares one SQLite database between both servers (profile
// "two-factor-shared"): 2FA enrolled on Go is verified on TypeScript and vice versa.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { twoFactorClient } from "better-auth/client/plugins";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";
import { startServers, makeClient, dual, record, lastEmail, uniqueEmail } from "../lib/harness.mjs";

const PASSWORD = "password1234";
const tfOf = (server) => makeClient(server, { plugins: [twoFactorClient()] });

/** Decodes the raw TOTP secret from an otpauth:// URI. */
function secretOf(uri) {
  const b32 = new URL(uri).searchParams.get("secret");
  return new TextDecoder().decode(base32.decode(b32));
}
const totpOf = (uri) => createOTP(secretOf(uri)).totp();

// TOTP secrets and backup codes are random: replace them with placeholders.
function scrub(v) {
  if (Array.isArray(v)) return v.map(scrub);
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === "backupCodes" && Array.isArray(x)) out[k] = x.map((c) => (/^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/.test(c) ? "<code>" : c));
      else out[k] = scrub(x);
    }
    return out;
  }
  if (typeof v === "string") return v.replace(/secret=[A-Z2-7]+/g, "secret=<secret>");
  return v;
}
async function rec(t, name, c, call) {
  const r = await record(t, name, c, call);
  t[t.length - 1] = scrub(t[t.length - 1]);
  return r;
}

describe("two-factor parity", () => {
  let servers;
  before(async () => { servers = await startServers("two-factor"); });
  after(async () => { await servers?.stop(); });

  test("enable TOTP, sign-in challenge, TOTP / OTP / backup code, trusted device, disable", async () => {
    const t = await dual(servers, async (server, t) => {
      const email = "tf-flow@example.com";
      const c = tfOf(server);
      const tf = c.client.twoFactor;
      await rec(t, "sign-up", c, () => c.client.signUp.email({ email, password: PASSWORD, name: "TF" }));
      await rec(t, "get-totp-uri before enable", c, () => tf.getTotpUri({ password: PASSWORD }));
      await rec(t, "enable wrong password", c, () => tf.enable({ password: "wrong-password" }));
      const en = await rec(t, "enable totp", c, () => tf.enable({ password: PASSWORD, issuer: "E2E App" }));
      const uri = en.data.totpURI;
      const backupCodes = en.data.backupCodes;
      await rec(t, "get-totp-uri", c, () => tf.getTotpUri({ password: PASSWORD }));
      await rec(t, "verify-totp wrong code (enrollment)", c, () => tf.verifyTotp({ code: "000000" }));
      await rec(t, "verify-totp (enrollment)", c, async () => tf.verifyTotp({ code: await totpOf(uri) }));
      await rec(t, "session enabled", c, () => c.client.getSession());
      await rec(t, "enable again rejected", c, () => tf.enable({ password: PASSWORD }));
      await rec(t, "sign-out", c, () => c.client.signOut());

      // TOTP challenge with trust device
      await rec(t, "sign-in challenge", c, () => c.client.signIn.email({ email, password: PASSWORD }));
      await rec(t, "session during challenge", c, () => c.client.getSession());
      await rec(t, "verify-totp wrong", c, () => tf.verifyTotp({ code: "000000" }));
      await rec(t, "verify-totp trust device", c, async () => tf.verifyTotp({ code: await totpOf(uri), trustDevice: true }));
      await rec(t, "session after totp", c, () => c.client.getSession());
      await rec(t, "sign-out keeps trust", c, () => c.client.signOut());
      await rec(t, "sign-in trusted device", c, () => c.client.signIn.email({ email, password: PASSWORD }));
      await rec(t, "sign-out 2", c, () => c.client.signOut());
      c.jar.delete("better-auth.trust_device");

      // OTP challenge
      await rec(t, "sign-in challenge 2", c, () => c.client.signIn.email({ email, password: PASSWORD }));
      await rec(t, "send-otp", c, () => tf.sendOtp());
      const otp = (await lastEmail(server, email, "two-factor-otp")).token;
      await rec(t, "verify-otp wrong", c, () => tf.verifyOtp({ code: otp === "000000" ? "111111" : "000000" }));
      await rec(t, "verify-otp", c, () => tf.verifyOtp({ code: otp }));
      await rec(t, "verify-otp replay", c, () => tf.verifyOtp({ code: otp }));
      await rec(t, "sign-out 3", c, () => c.client.signOut());

      // backup code challenge
      await rec(t, "sign-in challenge 3", c, () => c.client.signIn.email({ email, password: PASSWORD }));
      await rec(t, "verify-backup-code wrong", c, () => tf.verifyBackupCode({ code: "aaaaa-bbbbb" }));
      await rec(t, "verify-backup-code", c, () => tf.verifyBackupCode({ code: backupCodes[0] }));
      await rec(t, "generate-backup-codes", c, () => tf.generateBackupCodes({ password: PASSWORD }));
      await rec(t, "disable wrong password", c, () => tf.disable({ password: "wrong-password" }));
      await rec(t, "disable", c, () => tf.disable({ password: PASSWORD }));
      await rec(t, "session disabled", c, () => c.client.getSession());
      await rec(t, "sign-out 4", c, () => c.client.signOut());
      await rec(t, "sign-in without 2fa", c, () => c.client.signIn.email({ email, password: PASSWORD }));
    });
    const byName = Object.fromEntries(t.map((e) => [e.name, e]));
    assert.equal(byName["enable totp"].data.method, "totp");
    assert.match(byName["enable totp"].data.totpURI, /^otpauth:\/\/totp\/E2E%20App:tf-flow%40example\.com\?secret=<secret>&issuer=E2E\+App&digits=6&period=30$/);
    assert.deepEqual(byName["sign-in challenge"].data, { twoFactorRedirect: true, twoFactorMethods: ["totp", "otp"] });
    assert.equal(byName["verify-totp wrong"].error.code, "INVALID_CODE");
    assert.ok(byName["sign-in trusted device"].data.user);
    assert.equal(byName["verify-otp replay"].error.code, "OTP_HAS_EXPIRED");
    assert.equal(byName["verify-backup-code wrong"].error.code, "INVALID_BACKUP_CODE");
    assert.equal(byName["disable"].data.status, true);
    assert.ok(byName["sign-in without 2fa"].data.user);
  });

  test("OTP-only enablement, validation errors and missing challenge", async () => {
    await dual(servers, async (server, t) => {
      const email = "tf-otp@example.com";
      const c = tfOf(server);
      const tf = c.client.twoFactor;
      await rec(t, "verify-totp without challenge", c, () => tf.verifyTotp({ code: "123456" }));
      await rec(t, "send-otp without challenge", c, () => tf.sendOtp());
      await rec(t, "sign-up", c, () => c.client.signUp.email({ email, password: PASSWORD, name: "OTP" }));
      await rec(t, "enable missing password", c, () => tf.enable({}));
      await rec(t, "enable invalid method", c, () => tf.enable({ password: PASSWORD, method: "sms" }));
      await rec(t, "verify-totp missing code", c, () => tf.verifyTotp({}));
      await rec(t, "generate backup codes not enabled", c, () => tf.generateBackupCodes({ password: PASSWORD }));
      await rec(t, "enable otp", c, () => tf.enable({ password: PASSWORD, method: "otp" }));
      await rec(t, "session", c, () => c.client.getSession());
      await rec(t, "sign-out", c, () => c.client.signOut());
      await rec(t, "sign-in challenge", c, () => c.client.signIn.email({ email, password: PASSWORD, rememberMe: false }));
      await rec(t, "verify-totp no totp row", c, () => tf.verifyTotp({ code: "123456" }));
      await rec(t, "verify-otp before send", c, () => tf.verifyOtp({ code: "123456" }));
      await rec(t, "send-otp", c, () => tf.sendOtp());
      const otp = (await lastEmail(server, email, "two-factor-otp")).token;
      for (let i = 0; i < 5; i++) await rec(t, `verify-otp wrong ${i}`, c, () => tf.verifyOtp({ code: otp === "000000" ? "111111" : "000000" }));
      await rec(t, "verify-otp too many attempts", c, () => tf.verifyOtp({ code: otp }));
      await rec(t, "send-otp again", c, () => tf.sendOtp());
      const otp2 = (await lastEmail(server, email, "two-factor-otp")).token;
      await rec(t, "verify-otp (dont remember)", c, () => tf.verifyOtp({ code: otp2 }));
      await rec(t, "session", c, () => c.client.getSession());
      await rec(t, "view-backup-codes is server-only", c, () => c.client.$fetch("/two-factor/view-backup-codes", { method: "POST", body: { userId: "x" } }));
    });
  });
});

describe("two-factor shared database (sqlite)", () => {
  let servers;
  let dir;
  before(async () => {
    dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-tf-"));
    servers = await startServers("two-factor-shared", { env: { DB_URL: `sqlite:${path.join(dir, "shared.db")}` } });
  });
  after(async () => {
    await servers?.stop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  test("2FA enrolled on Go is verified on TypeScript, and vice versa", async () => {
    const email = uniqueEmail("tf-shared");
    const goC = tfOf(servers.go);
    assert.equal((await goC.client.signUp.email({ email, password: PASSWORD, name: "Shared" })).error, null);
    const en = await goC.client.twoFactor.enable({ password: PASSWORD });
    assert.equal(en.error, null, JSON.stringify(en.error));
    const uri = en.data.totpURI;
    const verified = await goC.client.twoFactor.verifyTotp({ code: await totpOf(uri) });
    assert.equal(verified.error, null, JSON.stringify(verified.error));

    // TOTP secret encrypted by Go, decrypted by TypeScript; trust device issued by TypeScript
    const tsC = tfOf(servers.ts);
    const challenge = await tsC.client.signIn.email({ email, password: PASSWORD });
    assert.deepEqual(challenge.data, { twoFactorRedirect: true, twoFactorMethods: ["totp", "otp"] });
    const tsTotp = await tsC.client.twoFactor.verifyTotp({ code: await totpOf(uri), trustDevice: true });
    assert.equal(tsTotp.error, null, JSON.stringify(tsTotp.error));
    assert.equal(tsTotp.data.user.email, email);

    // trust_device cookie + verification row written by TypeScript accepted by Go
    const goTrusted = tfOf(servers.go);
    goTrusted.jar.set("better-auth.trust_device", tsC.jar.get("better-auth.trust_device"));
    const trustedSignIn = await goTrusted.client.signIn.email({ email, password: PASSWORD });
    assert.equal(trustedSignIn.data?.user?.email, email, JSON.stringify(trustedSignIn.data));

    // backup codes encrypted by Go used on TypeScript
    const tsC2 = tfOf(servers.ts);
    await tsC2.client.signIn.email({ email, password: PASSWORD });
    const tsBackup = await tsC2.client.twoFactor.verifyBackupCode({ code: en.data.backupCodes[0] });
    assert.equal(tsBackup.error, null, JSON.stringify(tsBackup.error));

    // backup codes regenerated (and re-encrypted) by TypeScript used on Go; the code used on TS is gone
    const regen = await tsC2.client.twoFactor.generateBackupCodes({ password: PASSWORD });
    assert.equal(regen.error, null, JSON.stringify(regen.error));
    const goC2 = tfOf(servers.go);
    await goC2.client.signIn.email({ email, password: PASSWORD });
    assert.equal((await goC2.client.twoFactor.verifyBackupCode({ code: en.data.backupCodes[1] })).error?.code, "INVALID_BACKUP_CODE");
    const goC3 = tfOf(servers.go);
    await goC3.client.signIn.email({ email, password: PASSWORD });
    const goBackup = await goC3.client.twoFactor.verifyBackupCode({ code: regen.data.backupCodes[0] });
    assert.equal(goBackup.error, null, JSON.stringify(goBackup.error));

    // OTP challenge started on Go, completed on TypeScript (verification rows are shared)
    const goC4 = tfOf(servers.go);
    await goC4.client.signIn.email({ email, password: PASSWORD });
    assert.equal((await goC4.client.twoFactor.sendOtp()).error, null);
    const otp = (await lastEmail(servers.go, email, "two-factor-otp")).token;
    const tsC3 = tfOf(servers.ts);
    tsC3.jar.set("better-auth.two_factor", goC4.jar.get("better-auth.two_factor"));
    const tsOtp = await tsC3.client.twoFactor.verifyOtp({ code: otp });
    assert.equal(tsOtp.error, null, JSON.stringify(tsOtp.error));

    // disabled on TypeScript, sign-in on Go no longer challenged
    assert.equal((await tsC3.client.twoFactor.disable({ password: PASSWORD })).error, null);
    const plain = await tfOf(servers.go).client.signIn.email({ email, password: PASSWORD });
    assert.equal(plain.data?.user?.email, email, JSON.stringify(plain.data));
  });
});
