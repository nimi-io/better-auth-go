package main

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/anonymous"
)

// Anonymous profile (mirrors e2e/servers/profiles/anonymous.mjs).
func init() {
	profiles["anonymous"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, anonymous.New(anonymous.Options{
			GenerateName: func(*betterauth.EndpointContext) (string, error) { return "Guest", nil },
		}))
	}
}
