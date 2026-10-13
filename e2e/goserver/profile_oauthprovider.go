package main

import (
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// OAuth provider profiles (mirror e2e/servers/profiles/oauth-provider.mjs and
// oauth-provider-shared.mjs).

func oauthProviderPlugin() *betterauth.Plugin {
	return oauthprovider.New(oauthprovider.Options{
		LoginPage:                              "/login",
		ConsentPage:                            "/consent",
		AllowDynamicClientRegistration:         true,
		AllowUnauthenticatedClientRegistration: true,
	})
}

func init() {
	profiles["oauth-provider"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, jwt.New(), oauthProviderPlugin())
	}
	// Shares DB_URL (sqlite) with the TypeScript server: clients, codes, tokens, consents
	// and JWKS written by one implementation are used by the other.
	profiles["oauth-provider-shared"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Database = sharedDatabase(os.Getenv("DB_URL"))
		cfg.Plugins = append(cfg.Plugins, jwt.New(), oauthProviderPlugin())
	}
}
