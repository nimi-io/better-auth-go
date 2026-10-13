package main

import (
	"context"
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/twofactor"
)

// Mirrors e2e/servers/profiles/two-factor.mjs and two-factor-shared.mjs.
func twoFactorPlugin(env profileEnv) *betterauth.Plugin {
	return twofactor.New(twofactor.Options{
		OTPOptions: &twofactor.OTPOptions{
			SendOTP: func(_ context.Context, d twofactor.OTPData, _ *betterauth.EndpointContext) error {
				env.Mail.Record("two-factor-otp", d.User.Email, "", d.OTP)
				return nil
			},
		},
	})
}

func init() {
	profiles["two-factor"] = func(cfg *betterauth.Config, env profileEnv) {
		cfg.Plugins = append(cfg.Plugins, twoFactorPlugin(env))
	}
	// Shares DB_URL with the TypeScript server (the TS server migrates it).
	profiles["two-factor-shared"] = func(cfg *betterauth.Config, env profileEnv) {
		cfg.Database = sharedDatabase(os.Getenv("DB_URL"))
		cfg.Plugins = append(cfg.Plugins, twoFactorPlugin(env))
	}
}
