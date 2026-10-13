package main

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
)

func init() {
	profiles["bearer"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, bearer.New())
	}
	profiles["bearer-signed"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, bearer.New(bearer.Options{RequireSignature: true}))
	}
}
