package main

import (
	"context"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/admin"
	"github.com/nimi-io/better-auth-go/plugins/anonymous"
	"github.com/nimi-io/better-auth-go/plugins/deviceauthorization"
	"github.com/nimi-io/better-auth-go/plugins/openapi"
	"github.com/nimi-io/better-auth-go/plugins/twofactor"
	"github.com/nimi-io/better-auth-go/plugins/username"
)

// Device authorization and open-api profiles (mirror e2e/servers/profiles/
// device-authorization.mjs, open-api.mjs and open-api-plugins.mjs).

func deviceAuthorizationPlugin() *betterauth.Plugin {
	return deviceauthorization.New(deviceauthorization.Options{
		ExpiresIn:       "5min",
		Interval:        "2s",
		VerificationURI: "/device?lang=en",
		ValidateClient: func(_ context.Context, clientID string) (bool, error) {
			return clientID != "bad-client", nil
		},
	})
}

func init() {
	profiles["device-authorization"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, deviceAuthorizationPlugin())
	}
	profiles["open-api"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, openapi.New(openapi.Options{}))
	}
	profiles["open-api-plugins"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins,
			openapi.New(openapi.Options{}),
			deviceAuthorizationPlugin(),
			username.New(username.Options{}),
			anonymous.New(anonymous.Options{}),
			admin.New(admin.Options{}),
			twofactor.New(twofactor.Options{}),
		)
	}
}
