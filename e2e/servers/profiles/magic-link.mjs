// Magic link profile (mirrors e2e/goserver/profile_magic_link.go). Links are recorded under
// "magic-link". TOKEN_STORE selects storeToken; DB_URL (sqlite:) shares a database with the
// Go server.
import Database from "better-sqlite3";
import { magicLink } from "better-auth/plugins";

export default async function (options, { record }) {
  const dbURL = process.env.DB_URL;
  if (dbURL) {
    if (!dbURL.startsWith("sqlite:")) throw new Error(`unsupported DB_URL ${dbURL}`);
    options.database = new Database(dbURL.slice("sqlite:".length));
  }
  options.plugins = [
    ...(options.plugins ?? []),
    magicLink({
      async sendMagicLink({ email, url, token }) {
        record("magic-link", email, url, token);
      },
      storeToken: process.env.TOKEN_STORE || "plain",
    }),
  ];
}
