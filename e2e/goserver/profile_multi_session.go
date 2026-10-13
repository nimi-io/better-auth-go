package main

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/multisession"
)

func init() {
	profiles["multi-session"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, multisession.New(multisession.Options{MaximumSessions: 2}))
	}
}
