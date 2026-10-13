// OAuth provider profile (mirrors e2e/goserver/profile_oauthprovider.go).
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

export const oauthProviderPlugin = () =>
  oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    allowDynamicClientRegistration: true,
    allowUnauthenticatedClientRegistration: true,
  });

export default async function (options) {
  options.plugins = [...(options.plugins ?? []), jwt(), oauthProviderPlugin()];
}
