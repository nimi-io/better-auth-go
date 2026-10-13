// Shares DB_URL (sqlite) with the Go server (mirrors profile_oauthprovider.go).
import Database from "better-sqlite3";
import { jwt } from "better-auth/plugins";
import { oauthProviderPlugin } from "./oauth-provider.mjs";

export default async function (options) {
  const dbURL = process.env.DB_URL;
  if (!dbURL.startsWith("sqlite:")) throw new Error(`oauth-provider-shared supports sqlite only, got ${dbURL}`);
  options.database = new Database(dbURL.slice("sqlite:".length));
  options.plugins = [...(options.plugins ?? []), jwt(), oauthProviderPlugin()];
}
