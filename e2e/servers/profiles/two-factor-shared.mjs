// Mirrors e2e/goserver/profile_twofactor.go ("two-factor-shared"): the two-factor profile on
// the shared DB_URL database (SQLite), migrated by this server at startup.
import Database from "better-sqlite3";
import configureTwoFactor from "./two-factor.mjs";

export default async function (options, ctx) {
  const dbURL = process.env.DB_URL;
  if (!dbURL?.startsWith("sqlite:")) throw new Error(`two-factor-shared supports sqlite only, got ${dbURL}`);
  options.database = new Database(dbURL.slice("sqlite:".length));
  await configureTwoFactor(options, ctx);
}
