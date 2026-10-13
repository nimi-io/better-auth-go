package main

import (
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
	"github.com/nimi-io/better-auth-go/plugins/genericoauth"
	"github.com/nimi-io/better-auth-go/plugins/oauthpopup"
	"github.com/nimi-io/better-auth-go/plugins/oauthproxy"
	"github.com/nimi-io/better-auth-go/plugins/onetap"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// OAuth plugin profiles (mirror e2e/servers/profiles/{generic-oauth,oauth-popup,oauth-proxy,one-tap}.mjs).
// The generic providers talk to the mock IdP over plain http (IDP_URL/oidc); Google requests
// are rewritten to the mock IdP like the "oauth" profile.

func genericOAuthConfigs(idp string) []genericoauth.Config {
	return []genericoauth.Config{
		{ProviderID: "oidc", DiscoveryURL: idp + "/oidc/.well-known/openid-configuration", ClientID: "oidc-client", ClientSecret: "oidc-secret",
			PostLogoutRedirectURI: "/signed-out"},
		{ProviderID: "plain", AuthorizationURL: idp + "/oidc-plain/authorize", TokenURL: idp + "/oidc-plain/token",
			UserInfoURL: idp + "/oidc-plain/userinfo", ClientID: "plain-client", ClientSecret: "plain-secret",
			Scopes: []string{"profile", "email"}, Authentication: "basic", PKCE: betterauth.Bool(false),
			MapProfileToUser: func(p map[string]any) (map[string]any, error) {
				out := map[string]any{}
				if v, ok := p["display_name"]; ok {
					out["name"] = v
				}
				return out, nil
			}},
		{ProviderID: "oidc-nosignup", DiscoveryURL: idp + "/oidc/.well-known/openid-configuration", ClientID: "oidc-client",
			ClientSecret: "oidc-secret", DisableImplicitSignUp: true},
	}
}

func rewriteIdP() string {
	idp := os.Getenv("IDP_URL")
	if idp != "" {
		oauth2.HTTPClient.Transport = idpTransport{target: idp}
	}
	return idp
}

func googleE2E() oauth2.Provider {
	return google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "google-client", ClientSecret: "google-secret"}})
}

func init() {
	profiles["generic-oauth"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, genericoauth.New(genericoauth.Options{Config: genericOAuthConfigs(rewriteIdP())}))
	}
	profiles["oauth-popup"] = func(cfg *betterauth.Config, _ profileEnv) {
		idp := rewriteIdP()
		cfg.Plugins = append(cfg.Plugins, genericoauth.New(genericoauth.Options{Config: genericOAuthConfigs(idp)[:1]}), oauthpopup.New(), bearer.New())
	}
	profiles["oauth-proxy"] = func(cfg *betterauth.Config, _ profileEnv) {
		rewriteIdP()
		cfg.SocialProviders = []oauth2.Provider{googleE2E()}
		cfg.Plugins = append(cfg.Plugins, oauthproxy.New(oauthproxy.Options{CurrentURL: "http://preview.example.com", Secret: "e2e-oauth-proxy-shared-secret"}))
	}
	profiles["one-tap"] = func(cfg *betterauth.Config, _ profileEnv) {
		rewriteIdP()
		cfg.SocialProviders = []oauth2.Provider{googleE2E()}
		cfg.Plugins = append(cfg.Plugins, onetap.New(onetap.Options{}))
	}
	profiles["one-tap-client-id"] = func(cfg *betterauth.Config, _ profileEnv) {
		rewriteIdP()
		cfg.Plugins = append(cfg.Plugins, onetap.New(onetap.Options{ClientID: "one-tap-client", DisableSignup: true}))
	}
}
