// Passkey profile (mirrors e2e/goserver/profile_passkey.go). DB_URL (sqlite:) shares a
// database with the Go server for the passkey cross-compatibility tests.
import Database from "better-sqlite3";
import { passkey } from "@better-auth/passkey";

export default async function (options) {
  const dbURL = process.env.DB_URL;
  if (dbURL) {
    if (!dbURL.startsWith("sqlite:")) throw new Error(`unsupported DB_URL ${dbURL}`);
    options.database = new Database(dbURL.slice("sqlite:".length));
  }
  options.plugins = [
    ...(options.plugins ?? []),
    passkey({
      rpName: "E2E Passkey",
      registration: { extensions: { credProps: false, minPinLength: true } },
      authentication: { extensions: { uvm: true } },
    }),
  ];
}
