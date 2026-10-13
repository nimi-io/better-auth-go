// Email OTP profile (mirrors e2e/goserver/profile_email_otp.go). OTPs are recorded under
// their type with the code in `token`. OTP_STORE selects storeOTP; DB_URL (sqlite:) shares
// a database with the Go server.
import Database from "better-sqlite3";
import { emailOTP } from "better-auth/plugins";

export default async function (options, { record }) {
  const dbURL = process.env.DB_URL;
  if (dbURL) {
    if (!dbURL.startsWith("sqlite:")) throw new Error(`unsupported DB_URL ${dbURL}`);
    options.database = new Database(dbURL.slice("sqlite:".length));
  }
  options.plugins = [
    ...(options.plugins ?? []),
    emailOTP({
      async sendVerificationOTP({ email, otp, type }) {
        record(type, email, "", otp);
      },
      sendVerificationOnSignUp: true,
      storeOTP: process.env.OTP_STORE || "plain",
      changeEmail: { enabled: true },
    }),
  ];
}
