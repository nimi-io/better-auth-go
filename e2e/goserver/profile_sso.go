package main

import (
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/sso"
)

// SSO profile (mirrors e2e/servers/profiles/sso.mjs): SAML single logout and IdP-initiated
// SAML enabled, the mock IdP (IDP_URL) trusted for OIDC discovery and SAML. DB_URL shares
// a database with the TypeScript server.
func init() {
	profiles["sso"] = func(cfg *betterauth.Config, _ profileEnv) {
		if u := os.Getenv("DB_URL"); u != "" {
			cfg.Database = sharedDatabase(u)
		}
		if idp := os.Getenv("IDP_URL"); idp != "" {
			cfg.TrustedOrigins = append(cfg.TrustedOrigins, idp)
		}
		cfg.Plugins = append(cfg.Plugins, sso.New(sso.Options{
			TrustEmailVerified: true,
			SAML:               &sso.SAMLOptions{EnableSingleLogout: true, AllowIdpInitiated: true},
		}))
	}
}
