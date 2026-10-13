// email-otp plugin parity: the same flows run against the Go and TypeScript servers through
// the official emailOTPClient; transcripts must match. A shared SQLite database also checks
// that stored OTPs (plain, hashed, encrypted) are interchangeable between implementations.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { emailOTPClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch, lastEmail } from "../lib/harness.mjs";

const plugins = [emailOTPClient()];
let servers;
before(async () => { servers = await startServers("email-otp"); });
after(async () => { await servers?.stop(); });

const otpOf = async (server, email, type) => (await lastEmail(server, email, type))?.token;

test("email-otp: sign-in, sign-up, verification and errors", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const email = "otp-new@example.com";
    await record(t, "send sign-in (new user)", c, () => c.client.emailOtp.sendVerificationOtp({ email, type: "sign-in" }));
    const otp = await otpOf(server, email, "sign-in");
    t.push({ name: "otp shape", ok: /^\d{6}$/.test(otp) });
    await record(t, "sign-in wrong otp", c, () => c.client.signIn.emailOtp({ email, otp: otp === "000000" ? "111111" : "000000" }));
    await record(t, "sign-up via otp", c, () => c.client.signIn.emailOtp({ email: email.toUpperCase(), otp, name: "OTP User" }));
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "replay otp", c, () => c.client.signIn.emailOtp({ email, otp }));
    await record(t, "invalid email", c, () => c.client.emailOtp.sendVerificationOtp({ email: "nope", type: "sign-in" }));
    await record(t, "change-email type rejected", c, () => c.client.emailOtp.sendVerificationOtp({ email, type: "change-email" }));
    await record(t, "invalid type", c, () => c.client.emailOtp.sendVerificationOtp({ email, type: "bogus" }));
    await record(t, "missing otp field", c, () => c.client.signIn.emailOtp({ email }));
    await record(t, "unknown user verification send", c, () => c.client.emailOtp.sendVerificationOtp({ email: "ghost@example.com", type: "email-verification" }));
    t.push({ name: "no mail for unknown user", mail: await lastEmail(server, "ghost@example.com") });

    // sign-up sends an email-verification OTP (sendVerificationOnSignUp)
    const c2 = makeClient(server, { plugins });
    const email2 = "otp-verify@example.com";
    await record(t, "sign-up email", c2, () => c2.client.signUp.email({ email: email2, password: "password1234", name: "Verify Me" }));
    const vOtp = await otpOf(server, email2, "email-verification");
    await record(t, "check otp wrong", c2, () => c2.client.emailOtp.checkVerificationOtp({ email: email2, type: "email-verification", otp: "x" }));
    await record(t, "check otp", c2, () => c2.client.emailOtp.checkVerificationOtp({ email: email2, type: "email-verification", otp: vOtp }));
    await record(t, "verify email", c2, () => c2.client.emailOtp.verifyEmail({ email: email2, otp: vOtp }));
    await record(t, "session verified", c2, () => c2.client.getSession());
    await record(t, "verify again", c2, () => c2.client.emailOtp.verifyEmail({ email: email2, otp: vOtp }));

    // attempt budget
    await record(t, "resend verification", c2, () => c2.client.emailOtp.sendVerificationOtp({ email: email2, type: "email-verification" }));
    for (let i = 1; i <= 3; i++) {
      await record(t, `wrong attempt ${i}`, c2, () => c2.client.emailOtp.verifyEmail({ email: email2, otp: "wrong" }));
    }
    await record(t, "too many attempts", c2, () => c2.client.emailOtp.verifyEmail({ email: email2, otp: "wrong" }));
  }, { imageNullEqualsAbsent: true });
  assert.equal(t.find((e) => e.name === "sign-up via otp").status, 200);
  assert.equal(t.find((e) => e.name === "too many attempts").error.code, "TOO_MANY_ATTEMPTS");
});

test("email-otp: password reset and email change", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const email = "otp-reset@example.com";
    await record(t, "sign-up", c, () => c.client.signUp.email({ email, password: "password1234", name: "Reset" }));
    await record(t, "request reset", c, () => c.client.emailOtp.requestPasswordReset({ email }));
    const otp = await otpOf(server, email, "forget-password");
    await record(t, "reset too short", c, () => c.client.emailOtp.resetPassword({ email, otp, password: "short" }));
    await record(t, "reset", c, () => c.client.emailOtp.resetPassword({ email, otp, password: "newpassword1234" }));
    await record(t, "reset replay", c, () => c.client.emailOtp.resetPassword({ email, otp, password: "newpassword1234" }));
    await record(t, "sign-in new password", c, () => c.client.signIn.email({ email, password: "newpassword1234" }));
    await record(t, "deprecated forget-password", c, () => c.client.forgetPassword.emailOtp({ email }));
    await record(t, "reset unknown user", c, () => c.client.emailOtp.requestPasswordReset({ email: "ghost2@example.com" }));

    await record(t, "change email same", c, () => c.client.emailOtp.requestEmailChange({ newEmail: email }));
    await record(t, "request change", c, () => c.client.emailOtp.requestEmailChange({ newEmail: "otp-changed@example.com" }));
    const changeOtp = await otpOf(server, "otp-changed@example.com", "change-email");
    await record(t, "change wrong otp", c, () => c.client.emailOtp.changeEmail({ newEmail: "otp-changed@example.com", otp: "000" }));
    await record(t, "change email", c, () => c.client.emailOtp.changeEmail({ newEmail: "otp-changed@example.com", otp: changeOtp }));
    await record(t, "session after change", c, () => c.client.getSession());
    const anon = makeClient(server, { plugins });
    await record(t, "change unauthenticated", anon, () => anon.client.emailOtp.changeEmail({ newEmail: "x@example.com", otp: "1" }));
    await recordFetch(t, "cross-site send blocked", anon, "/email-otp/send-verification-otp", {
      method: "POST",
      headers: { "content-type": "application/json", "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", origin: "https://evil.example.com" },
      body: JSON.stringify({ email, type: "sign-in" }),
    });
  });
  assert.equal(t.find((e) => e.name === "change email").status, 200);
  assert.equal(t.find((e) => e.name === "session after change").data.user.email, "otp-changed@example.com");
});

for (const store of ["plain", "hashed", "encrypted"]) {
  test(`email-otp: ${store} OTPs are interchangeable through a shared database`, async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-otp-"));
    const shared = await startServers("email-otp", { env: { DB_URL: `sqlite:${path.join(dir, "otp.db")}`, OTP_STORE: store } });
    try {
      for (const [from, to] of [["ts", "go"], ["go", "ts"]]) {
        const email = `otp-${store}-${from}@example.com`;
        const sender = makeClient(shared[from], { plugins });
        const verifier = makeClient(shared[to], { plugins });
        const sent = await sender.client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
        assert.equal(sent.error, null, JSON.stringify(sent.error));
        const otp = await otpOf(shared[from], email, "sign-in");
        const wrong = await verifier.client.signIn.emailOtp({ email, otp: otp === "000000" ? "111111" : "000000" });
        assert.equal(wrong.error?.code, "INVALID_OTP");
        const ok = await verifier.client.signIn.emailOtp({ email, otp });
        assert.equal(ok.error, null, `${store} ${from}->${to}: ${JSON.stringify(ok.error)}`);
        assert.equal(ok.data.user.email, email);
      }
    } finally {
      await shared.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
