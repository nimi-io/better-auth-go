// Shared helpers for the OAuth plugin profiles (mirrors e2e/goserver/profile_generic_oauth.go).
export function rewriteIdP() {
  // Route https provider hosts to the mock IdP: https://host/path -> <IDP_URL>/host/path.
  const idp = process.env.IDP_URL;
  if (!idp || globalThis.__idpRewrite) return idp;
  globalThis.__idpRewrite = true;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const u = new URL(typeof input === "string" || input instanceof URL ? String(input) : input.url);
    if (u.protocol === "https:") {
      const target = `${idp}/${u.host}${u.pathname}${u.search}`;
      if (input instanceof Request) return realFetch(new Request(target, input), init);
      return realFetch(target, init);
    }
    return realFetch(input, init);
  };
  return idp;
}

export function genericOAuthConfigs(idp) {
  return [
    { providerId: "oidc", discoveryUrl: `${idp}/oidc/.well-known/openid-configuration`, clientId: "oidc-client", clientSecret: "oidc-secret",
      postLogoutRedirectURI: "/signed-out" },
    { providerId: "plain", authorizationUrl: `${idp}/oidc-plain/authorize`, tokenUrl: `${idp}/oidc-plain/token`,
      userInfoUrl: `${idp}/oidc-plain/userinfo`, clientId: "plain-client", clientSecret: "plain-secret",
      scopes: ["profile", "email"], authentication: "basic", pkce: false,
      mapProfileToUser: (p) => ("display_name" in p ? { name: p.display_name } : {}) },
    { providerId: "oidc-nosignup", discoveryUrl: `${idp}/oidc/.well-known/openid-configuration`, clientId: "oidc-client",
      clientSecret: "oidc-secret", disableImplicitSignUp: true },
  ];
}

export const googleE2E = { clientId: "google-client", clientSecret: "google-secret" };
