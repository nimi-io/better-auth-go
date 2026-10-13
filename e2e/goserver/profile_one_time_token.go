package main

import (
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/onetimetoken"
)

// One-time token profile (mirrors e2e/servers/profiles/one-time-token.mjs). TOKEN_STORE
// selects storeToken; DB_URL shares a database with the TypeScript server.
func init() {
	profiles["one-time-token"] = func(cfg *betterauth.Config, _ profileEnv) {
		if u := os.Getenv("DB_URL"); u != "" {
			cfg.Database = sharedDatabase(u)
		}
		cfg.Plugins = append(cfg.Plugins, onetimetoken.New(onetimetoken.Options{
			SetOttHeaderOnNewSession: true,
			StoreToken:               onetimetoken.StoreToken{Mode: os.Getenv("TOKEN_STORE")},
		}))
	}
}
