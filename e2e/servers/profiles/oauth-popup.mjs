import { bearer, genericOAuth, oauthPopup } from "better-auth/plugins";
import { genericOAuthConfigs, rewriteIdP } from "./_oauth-shared.mjs";
export default async function (options) {
  const idp = rewriteIdP();
  options.plugins = [...(options.plugins ?? []), genericOAuth({ config: genericOAuthConfigs(idp).slice(0, 1) }), oauthPopup(), bearer()];
}
