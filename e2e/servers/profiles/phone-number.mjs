// Phone number profile (mirrors e2e/goserver/profile_phone_number.go). OTPs are recorded as
// "phone-otp" / "phone-reset" messages addressed to the phone number.
import { phoneNumber } from "better-auth/plugins";

export default async function (options, { record }) {
  options.plugins = [
    ...(options.plugins ?? []),
    phoneNumber({
      async sendOTP({ phoneNumber, code }) { record("phone-otp", phoneNumber, "", code); },
      async sendPasswordResetOTP({ phoneNumber, code }) { record("phone-reset", phoneNumber, "", code); },
      signUpOnVerification: { getTempEmail: (p) => `u${p.slice(1)}@phone.example.com` },
      phoneNumberValidator: (p) => p.length >= 8 && p[0] === "+",
    }),
  ];
}
