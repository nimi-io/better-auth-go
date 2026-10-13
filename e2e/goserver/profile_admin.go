package main

import (
	"context"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/admin"
)

// Admin profile (mirrors e2e/servers/profiles/admin.mjs): users named "Admin" get the
// admin role on sign-up.
func init() {
	profiles["admin"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, admin.New(admin.Options{DefaultBanReason: "Spamming"}))
		cfg.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
			Before: func(_ context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
				if data["name"] == "Admin" {
					return &betterauth.DBHookResult{Data: adapter.Record{"role": "admin"}}, nil
				}
				return nil, nil
			},
		}}}
	}
}
