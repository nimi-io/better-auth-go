package main

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/phonenumber"
)

// Phone number profile (mirrors e2e/servers/profiles/phone-number.mjs). OTPs are recorded
// as "phone-otp" / "phone-reset" messages addressed to the phone number.
func init() {
	profiles["phone-number"] = func(cfg *betterauth.Config, env profileEnv) {
		cfg.Database = pluginSQLite()
		cfg.Plugins = append(cfg.Plugins, phonenumber.New(phonenumber.Options{
			SendOTP: func(d phonenumber.OTPData, _ *betterauth.EndpointContext) error {
				env.Mail.Record("phone-otp", d.PhoneNumber, "", d.Code)
				return nil
			},
			SendPasswordResetOTP: func(d phonenumber.OTPData, _ *betterauth.EndpointContext) error {
				env.Mail.Record("phone-reset", d.PhoneNumber, "", d.Code)
				return nil
			},
			SignUpOnVerification: &phonenumber.SignUpOnVerification{
				GetTempEmail: func(p string) string { return "u" + p[1:] + "@phone.example.com" },
			},
			PhoneNumberValidator: func(p string) bool { return len(p) >= 8 && p[0] == '+' },
		}))
	}
}
