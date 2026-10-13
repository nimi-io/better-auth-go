import { genericOAuth } from "better-auth/plugins";
import { genericOAuthConfigs, rewriteIdP } from "./_oauth-shared.mjs";
export default async function (options) {
  options.plugins = [...(options.plugins ?? []), genericOAuth({ config: genericOAuthConfigs(rewriteIdP()) })];
}
