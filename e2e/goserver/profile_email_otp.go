package main

import (
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/emailotp"
)

// Email OTP profile (mirrors e2e/servers/profiles/email-otp.mjs). OTPs are recorded under
// their type ("sign-in", "email-verification", ...) with the code in Token. OTP_STORE
// selects storeOTP; DB_URL shares a database with the TypeScript server.
func init() {
	profiles["email-otp"] = func(cfg *betterauth.Config, env profileEnv) {
		if u := os.Getenv("DB_URL"); u != "" {
			cfg.Database = sharedDatabase(u)
		}
		store := emailotp.StoreOTP{Mode: os.Getenv("OTP_STORE")}
		cfg.Plugins = append(cfg.Plugins, emailotp.New(emailotp.Options{
			SendVerificationOTP: func(_ *betterauth.EndpointContext, d emailotp.SendVerificationOTPData) error {
				env.Mail.Record(d.Type, d.Email, "", d.OTP)
				return nil
			},
			SendVerificationOnSignUp: true,
			StoreOTP:                 store,
			ChangeEmail:              &emailotp.ChangeEmailOptions{Enabled: true},
		}))
	}
}
