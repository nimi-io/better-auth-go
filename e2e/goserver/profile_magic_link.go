package main

import (
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/magiclink"
)

// Magic link profile (mirrors e2e/servers/profiles/magic-link.mjs). Links are recorded
// under "magic-link". TOKEN_STORE selects storeToken; DB_URL shares a database with the
// TypeScript server.
func init() {
	profiles["magic-link"] = func(cfg *betterauth.Config, env profileEnv) {
		if u := os.Getenv("DB_URL"); u != "" {
			cfg.Database = sharedDatabase(u)
		}
		cfg.Plugins = append(cfg.Plugins, magiclink.New(magiclink.Options{
			SendMagicLink: func(_ *betterauth.EndpointContext, d magiclink.SendMagicLinkData) error {
				env.Mail.Record("magic-link", d.Email, d.URL, d.Token)
				return nil
			},
			StoreToken: magiclink.StoreToken{Mode: os.Getenv("TOKEN_STORE")},
		}))
	}
}
