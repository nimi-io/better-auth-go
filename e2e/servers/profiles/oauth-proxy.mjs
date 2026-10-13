import { oAuthProxy } from "better-auth/plugins";
import { googleE2E, rewriteIdP } from "./_oauth-shared.mjs";
export default async function (options) {
  rewriteIdP();
  options.socialProviders = { google: googleE2E };
  options.plugins = [...(options.plugins ?? []), oAuthProxy({ currentURL: "http://preview.example.com", secret: "e2e-oauth-proxy-shared-secret" })];
}
