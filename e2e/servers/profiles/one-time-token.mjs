// One-time token profile (mirrors e2e/goserver/profile_one_time_token.go). TOKEN_STORE
// selects storeToken; DB_URL (sqlite:) shares a database with the Go server.
import Database from "better-sqlite3";
import { oneTimeToken } from "better-auth/plugins";

export default async function (options) {
  const dbURL = process.env.DB_URL;
  if (dbURL) {
    if (!dbURL.startsWith("sqlite:")) throw new Error(`unsupported DB_URL ${dbURL}`);
    options.database = new Database(dbURL.slice("sqlite:".length));
  }
  options.plugins = [
    ...(options.plugins ?? []),
    oneTimeToken({ setOttHeaderOnNewSession: true, storeToken: process.env.TOKEN_STORE || "plain" }),
  ];
}
