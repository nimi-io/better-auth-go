// Mirrors e2e/goserver/profile_twofactor.go ("two-factor").
import { twoFactor } from "better-auth/plugins";

export default async function (options, { record }) {
  options.plugins = [
    ...(options.plugins ?? []),
    twoFactor({
      otpOptions: {
        async sendOTP({ user, otp }) {
          record("two-factor-otp", user.email, "", otp);
        },
      },
    }),
  ];
}
