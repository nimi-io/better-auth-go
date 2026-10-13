package main

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/apikey"
)

// API key profile (mirrors e2e/servers/profiles/api-key.mjs): sessions from API keys,
// metadata, default permissions and a small per-key rate limit. DB_URL shares a database
// with the TypeScript server. /__test/verify-api-key exposes the server-only verifyApiKey.
func init() {
	profiles["api-key"] = func(cfg *betterauth.Config, env profileEnv) {
		if u := os.Getenv("DB_URL"); u != "" {
			cfg.Database = sharedDatabase(u)
		}
		cfg.Plugins = append(cfg.Plugins, apikey.New(apikey.Options{Configuration: apikey.Configuration{
			EnableSessionForAPIKeys: true,
			EnableMetadata:          true,
			RateLimit:               &apikey.RateLimit{Enabled: apikey.Bool(true), MaxRequests: apikey.Float(3), TimeWindow: apikey.Float(60000)},
			Permissions:             &apikey.Permissions{DefaultPermissions: apikey.Statements{"files": {"read"}}},
		}}))
	}
	testHandlers["/__test/verify-api-key"] = func(w http.ResponseWriter, r *http.Request, auth *betterauth.Auth) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		res, err := auth.API.Call(r.Context(), "verifyApiKey", betterauth.CallInput{Body: body})
		if err != nil {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":` + jsonString(err.Error()) + `}`))
			return
		}
		b, _ := res.JSON()
		_, _ = w.Write(b)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
