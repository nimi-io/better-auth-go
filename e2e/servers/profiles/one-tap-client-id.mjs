import { oneTap } from "better-auth/plugins";
import { rewriteIdP } from "./_oauth-shared.mjs";
export default async function (options) {
  rewriteIdP();
  options.plugins = [...(options.plugins ?? []), oneTap({ clientId: "one-tap-client", disableSignup: true })];
}
