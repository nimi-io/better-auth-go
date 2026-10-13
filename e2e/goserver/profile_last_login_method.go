package main

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/lastloginmethod"
)

func init() {
	profiles["last-login-method"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true}))
	}
}
