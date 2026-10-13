// Shares DB_URL (sqlite) with the Go server; JWKS rows are interchangeable.
import Database from "better-sqlite3";
import { jwt } from "better-auth/plugins";
export default async function (options) {
  const dbURL = process.env.DB_URL;
  if (!dbURL.startsWith("sqlite:")) throw new Error(`jwt-shared supports sqlite only, got ${dbURL}`);
  options.database = new Database(dbURL.slice("sqlite:".length));
  options.plugins = [...(options.plugins ?? []), jwt()];
}
