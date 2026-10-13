package main

import (
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/passkey"
)

// Passkey profile (mirrors e2e/servers/profiles/passkey.mjs). DB_URL shares a database
// with the TypeScript server for the passkey cross-compatibility tests.
func init() {
	profiles["passkey"] = func(cfg *betterauth.Config, _ profileEnv) {
		if u := os.Getenv("DB_URL"); u != "" {
			cfg.Database = sharedDatabase(u)
		}
		cfg.Plugins = append(cfg.Plugins, passkey.New(passkey.Options{
			RPName: "E2E Passkey",
			Registration: &passkey.RegistrationOptions{
				Extensions: passkey.StaticExtensions(jsonx.O("credProps", false, "minPinLength", true)),
			},
			Authentication: &passkey.AuthenticationOptions{
				Extensions: passkey.StaticExtensions(jsonx.O("uvm", true)),
			},
		}))
	}
}
