package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/scim"
)

// SCIM profile (mirrors e2e/servers/profiles/scim.mjs): a static "workforce" connection,
// a read-only credential, a second connection sharing the provisioning domain, and the
// managed connection catalog. DB_URL shares a database with the TypeScript server.
// /__test/scim/managed creates a managed connection (the server-only endpoint) and
// /__test/scim/call invokes any server-only SCIM endpoint with a JSON body.
func init() {
	profiles["scim"] = func(cfg *betterauth.Config, env profileEnv) {
		if u := os.Getenv("DB_URL"); u != "" {
			cfg.Database = sharedDatabase(u)
		}
		cfg.Plugins = append(cfg.Plugins, scim.New(scim.Options{
			Connections: []scim.ConnectionOptions{
				{ID: "workforce", Credentials: []scim.BearerCredential{
					{Type: "bearer", ID: "workforce-admin", Token: "e2e-scim-token"},
					{Type: "bearer", ID: "workforce-reader", Token: "e2e-scim-read-token", Scopes: []scim.Scope{scim.ScopeUsersRead, scim.ScopeGroupsRead}},
				}},
				{ID: "partners", ProvisioningDomainID: "workforce", Credentials: []scim.BearerCredential{
					{Type: "bearer", ID: "partners-admin", Token: "e2e-scim-partners-token"},
				}},
			},
			ManagedConnections: &scim.ManagedConnectionOptions{CredentialHashSecret: "e2e-scim-managed-credential-hash-secret-0123456789"},
		}))
	}
	testHandlers["/__test/scim/call"] = func(w http.ResponseWriter, r *http.Request, auth *betterauth.Auth) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		key, _ := body["endpoint"].(string)
		input, _ := body["body"].(map[string]any)
		if exp, ok := input["expiresAt"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, exp); err == nil {
				input["expiresAt"] = t
			}
		}
		w.Header().Set("Content-Type", "application/json")
		res, err := auth.API.Call(r.Context(), key, betterauth.CallInput{Body: input})
		if err != nil {
			if ae, ok := betterauth.AsAPIError(err); ok {
				b, _ := json.Marshal(map[string]any{"error": map[string]any{"status": ae.StatusCode, "body": ae.Body}})
				_, _ = w.Write(b)
				return
			}
			_, _ = w.Write([]byte(`{"error":{"status":500,"message":` + jsonString(err.Error()) + `}}`))
			return
		}
		b, _ := res.JSON()
		_, _ = w.Write([]byte(`{"data":` + string(b) + `}`))
	}
}
