// phone-number plugin parity through the official phoneNumberClient. OTPs are read from
// /__test/email (type "phone-otp" / "phone-reset", addressed to the phone number).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { phoneNumberClient } from "better-auth/client/plugins";
import { startServers, makeClient, dual, record, recordFetch, lastEmail } from "../lib/harness.mjs";

const plugins = [phoneNumberClient()];
let servers;
before(async () => { servers = await startServers("phone-number", { envFor: { go: { MIGRATE: "1" } } }); });
after(async () => { await servers?.stop(); });

const code = async (server, phone, type = "phone-otp") => (await lastEmail(server, phone, type))?.token;

test("phone-number: OTP sign-up, verification, password sign-in and reset", async () => {
  const t = await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const other = makeClient(server, { plugins });
    const phone = "+15550001111";
    await record(t, "invalid phone", c, () => c.client.phoneNumber.sendOtp({ phoneNumber: "123" }));
    await record(t, "send otp", c, () => c.client.phoneNumber.sendOtp({ phoneNumber: phone }));
    const otp = await code(server, phone);
    t.push({ name: "otp shape", ok: /^\d{6}$/.test(otp) });
    await record(t, "verify wrong code", c, () => c.client.phoneNumber.verify({ phoneNumber: phone, code: otp === "000000" ? "111111" : "000000" }));
    await record(t, "verify (sign-up)", c, () => c.client.phoneNumber.verify({ phoneNumber: phone, code: otp }));
    await record(t, "session", c, () => c.client.getSession());
    await record(t, "verify replay", c, () => c.client.phoneNumber.verify({ phoneNumber: phone, code: otp }));
    await record(t, "verify unknown", c, () => c.client.phoneNumber.verify({ phoneNumber: "+15550009999", code: "123456" }));
    await record(t, "update-user phone blocked", c, () => c.client.updateUser({ phoneNumber: "+15550002222" }));
    await record(t, "sign-in no password yet", other, () => other.client.signIn.phoneNumber({ phoneNumber: phone, password: "password1234" }));
    await record(t, "request reset", other, () => other.client.phoneNumber.requestPasswordReset({ phoneNumber: phone }));
    await record(t, "request reset unknown", other, () => other.client.phoneNumber.requestPasswordReset({ phoneNumber: "+15550003333" }));
    const reset = await code(server, phone, "phone-reset");
    await record(t, "reset short password", other, () => other.client.phoneNumber.resetPassword({ phoneNumber: phone, otp: reset, newPassword: "short" }));
    await record(t, "request reset again", other, () => other.client.phoneNumber.requestPasswordReset({ phoneNumber: phone }));
    const reset2 = await code(server, phone, "phone-reset");
    await record(t, "reset wrong otp", other, () => other.client.phoneNumber.resetPassword({ phoneNumber: phone, otp: reset2 === "000000" ? "111111" : "000000", newPassword: "password1234" }));
    await record(t, "reset", other, () => other.client.phoneNumber.resetPassword({ phoneNumber: phone, otp: reset2, newPassword: "password1234" }));
    await record(t, "reset replay", other, () => other.client.phoneNumber.resetPassword({ phoneNumber: phone, otp: reset2, newPassword: "password1234" }));
    await record(t, "sign-in phone", other, () => other.client.signIn.phoneNumber({ phoneNumber: phone, password: "password1234" }));
    await record(t, "sign-in phone wrong password", other, () => other.client.signIn.phoneNumber({ phoneNumber: phone, password: "wrong-password" }));
    await record(t, "sign-in unknown phone", other, () => other.client.signIn.phoneNumber({ phoneNumber: "+15550004444", password: "password1234" }));
    // change number on an authenticated session
    const newPhone = "+15550005555";
    await record(t, "send otp new number", c, () => c.client.phoneNumber.sendOtp({ phoneNumber: newPhone }));
    const otp2 = await code(server, newPhone);
    await record(t, "verify updatePhoneNumber", c, () => c.client.phoneNumber.verify({ phoneNumber: newPhone, code: otp2, updatePhoneNumber: true }));
    await record(t, "session after update", c, () => c.client.getSession());
    await record(t, "update-user null phone", c, () => c.client.updateUser({ phoneNumber: null }));
    await record(t, "session after null", c, () => c.client.getSession());
    await record(t, "send otp disableSession", other, () => other.client.phoneNumber.sendOtp({ phoneNumber: "+15550006666" }));
    const otp3 = await code(server, "+15550006666");
    await record(t, "verify disableSession", other, () => other.client.phoneNumber.verify({ phoneNumber: "+15550006666", code: otp3, disableSession: true }));
    await recordFetch(t, "consume-otp not routed", other, "/phone-number/consume-otp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ phoneNumber: phone, code: "123456" }) });
    await recordFetch(t, "raw verify missing code", other, "/phone-number/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ phoneNumber: phone }) });
  }, { imageNullEqualsAbsent: true });
  assert.equal(t[4].data.status, true);
  assert.equal(t[5].data.user.phoneNumberVerified, true);
  assert.equal(t[15].data.status, true);
  assert.equal(t[17].status, 200);
});

test("phone-number: attempt limiting", async () => {
  await dual(servers, async (server, t) => {
    const c = makeClient(server, { plugins });
    const phone = "+15550007777";
    await record(t, "send otp", c, () => c.client.phoneNumber.sendOtp({ phoneNumber: phone }));
    const otp = await code(server, phone);
    const wrong = otp === "000000" ? "111111" : "000000";
    for (let i = 1; i <= 3; i++) await record(t, `wrong ${i}`, c, () => c.client.phoneNumber.verify({ phoneNumber: phone, code: wrong }));
    await record(t, "blocked", c, () => c.client.phoneNumber.verify({ phoneNumber: phone, code: otp }));
    await record(t, "after block", c, () => c.client.phoneNumber.verify({ phoneNumber: phone, code: otp }));
  });
});
