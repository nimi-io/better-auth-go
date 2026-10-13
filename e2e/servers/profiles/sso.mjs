// SSO profile (mirrors e2e/goserver/profile_sso.go): the @better-auth/sso plugin with SAML
// single logout and IdP-initiated SAML enabled, trusting the mock IdP (IDP_URL) for OIDC
// discovery and SAML. DB_URL (sqlite:) shares a database with the Go server.
import Database from "better-sqlite3";
import { sso } from "@better-auth/sso";

export default async function (options) {
  const dbURL = process.env.DB_URL;
  if (dbURL) {
    if (!dbURL.startsWith("sqlite:")) throw new Error(`unsupported DB_URL ${dbURL}`);
    options.database = new Database(dbURL.slice("sqlite:".length));
  }
  if (process.env.IDP_URL) options.trustedOrigins = [...(options.trustedOrigins ?? []), process.env.IDP_URL];
  options.plugins = [
    ...(options.plugins ?? []),
    sso({
      trustEmailVerified: true,
      saml: { enableSingleLogout: true, allowIdpInitiated: true },
    }),
  ];
}
