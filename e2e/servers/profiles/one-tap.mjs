import { oneTap } from "better-auth/plugins";
import { googleE2E, rewriteIdP } from "./_oauth-shared.mjs";
export default async function (options) {
  rewriteIdP();
  options.socialProviders = { google: googleE2E };
  options.plugins = [...(options.plugins ?? []), oneTap()];
}
