package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

func infoJSON(t *testing.T, opts Options) map[string]any {
	t.Helper()
	r := run(t, opts, "", "info", "--json")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, r.stdout)
	}
	return out
}

func TestInfoJSONSections(t *testing.T) {
	out := infoJSON(t, Options{NewAuth: func(context.Context, string) (*betterauth.Auth, error) {
		return nil, NoConfig("No database configured.")
	}})
	sys := out["system"].(map[string]any)
	for _, k := range []string{"platform", "arch", "version", "release", "cpuCount", "cpuModel", "totalMemory", "freeMemory"} {
		if _, ok := sys[k]; !ok {
			t.Fatalf("system.%s missing: %v", k, sys)
		}
	}
	g := out["go"].(map[string]any)
	if !strings.HasPrefix(g["version"].(string), "go") || g["env"] == "" {
		t.Fatalf("go section %v", g)
	}
	if _, ok := out["module"]; !ok {
		t.Fatal("module missing")
	}
	ba := out["betterAuth"].(map[string]any)
	if ba["config"] != nil || ba["error"] != "No database configured." || ba["upstreamVersion"] != betterauth.Version {
		t.Fatalf("betterAuth %v", ba)
	}
	if _, ok := ba["version"]; !ok {
		t.Fatal("betterAuth.version missing")
	}
	// the test binary links pgx/mysql/sqlite through the betterauth dependency graph only if
	// imported; databases is either null or a list of {name, version}
	if dbs, ok := out["databases"].([]any); ok {
		for _, d := range dbs {
			m := d.(map[string]any)
			if m["name"] == "" || m["version"] == "" {
				t.Fatalf("bad database entry %v", m)
			}
		}
	}
}

func TestInfoSanitizesConfig(t *testing.T) {
	auth := newAuth(t, betterauth.Config{
		AppName: "My App",
		Secret:  "super-secret-key-1234567890-abcdefgh",
		BaseURL: "https://example.com",
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{
			Enabled: true,
			SendResetPassword: func(context.Context, betterauth.EmailData, *http.Request) error {
				return nil
			},
		},
		SocialProviders: []oauth2.Provider{
			github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "github-client-id", ClientSecret: "github-client-secret"}}),
			google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "google-client-id", ClientIDs: []string{"ios-client-id"}, ClientSecret: "google-client-secret", Scope: []string{"openid"}}}),
		},
		TrustedOrigins: []string{"https://app.example.com"},
		Plugins: []*betterauth.Plugin{
			{ID: "stripe", Options: struct {
				StripeKey           string
				StripeWebhookSecret string
				CreateCustomer      bool
			}{"sk_live_123", "whsec_123", true}},
			{ID: "bare", Version: "1.0.0"},
		},
		User: &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{
			ModelName:        "users",
			AdditionalFields: []db.Field{{Name: "plan", Type: db.TypeString, Required: db.True}},
		}},
	})
	r := run(t, Options{Auth: auth}, "", "info", "--json")
	if r.code != 0 {
		t.Fatal(r.stderr)
	}
	for _, leaked := range []string{"super-secret-key", "github-client", "google-client", "ios-client-id", "sk_live_123", "whsec_123"} {
		notContains(t, r.stdout, leaked)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatal(err)
	}
	ba := out["betterAuth"].(map[string]any)
	cfg := ba["config"].(map[string]any)
	if cfg["secret"] != redacted {
		t.Fatalf("secret %v", cfg["secret"])
	}
	if cfg["baseURL"] != "https://example.com" || cfg["appName"] != "My App" {
		t.Fatalf("baseURL/appName %v %v", cfg["baseURL"], cfg["appName"])
	}
	ep, _ := json.Marshal(cfg["emailAndPassword"])
	if string(ep) != `{"enabled":true}` {
		t.Fatalf("emailAndPassword %s", ep)
	}
	sp := cfg["socialProviders"].(map[string]any)
	gh := sp["github"].(map[string]any)
	if gh["clientId"] != redacted || gh["clientSecret"] != redacted {
		t.Fatalf("github %v", gh)
	}
	gg := sp["google"].(map[string]any)
	if gg["clientId"] != redacted || gg["clientSecret"] != redacted {
		t.Fatalf("google %v", gg)
	}
	if _, ok := gg["clientIds"]; ok {
		t.Fatalf("clientIds should be folded into clientId: %v", gg)
	}
	if s, _ := json.Marshal(gg["scope"]); string(s) != `["openid"]` {
		t.Fatalf("scope %s", s)
	}
	if s, _ := json.Marshal(cfg["trustedOrigins"]); string(s) != `["https://app.example.com"]` {
		t.Fatalf("trustedOrigins %s", s)
	}
	plugins := cfg["plugins"].([]any)
	stripe := plugins[0].(map[string]any)
	if stripe["name"] != "stripe" {
		t.Fatalf("plugin %v", stripe)
	}
	sc := stripe["config"].(map[string]any)
	if sc["stripeKey"] != redacted || sc["stripeWebhookSecret"] != redacted || sc["createCustomer"] != true {
		t.Fatalf("stripe config %v", sc)
	}
	bare, _ := json.Marshal(plugins[1])
	if string(bare) != `{"config":{"id":"bare","version":"1.0.0"},"name":"bare"}` {
		t.Fatalf("bare plugin %s", bare)
	}
	user := cfg["user"].(map[string]any)
	if user["modelName"] != "users" {
		t.Fatalf("user %v", user)
	}
	af, _ := json.Marshal(user["additionalFields"])
	if string(af) != `{"plan":{"required":true,"type":"string"}}` {
		t.Fatalf("additionalFields %s", af)
	}
	if ba["database"].(map[string]any)["adapter"] != "memory" {
		t.Fatalf("database %v", ba["database"])
	}
}

func TestInfoSecretsArray(t *testing.T) {
	auth := newAuth(t, betterauth.Config{Secrets: []betterauth.SecretEntry{
		{Version: 2, Value: "new-rotation-secret-4567890123456789"},
		{Version: 1, Value: "old-rotation-secret-1234567890123456"},
	}})
	r := run(t, Options{Auth: auth}, "", "info", "-j")
	notContains(t, r.stdout, "rotation-secret")
	var out map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatal(err)
	}
	cfg := out["betterAuth"].(map[string]any)["config"].(map[string]any)
	if cfg["secrets"] != redacted {
		t.Fatalf("secrets %v", cfg["secrets"])
	}
}

func TestInfoDialect(t *testing.T) {
	fake := &fakeSQL{dialect: "postgres", plan: pendingPlan(nil)}
	out := infoJSON(t, migrateAuth(t, fake, betterauth.Config{}))
	d := out["betterAuth"].(map[string]any)["database"].(map[string]any)
	if d["adapter"] != "kysely" || d["dialect"] != "postgres" {
		t.Fatalf("database %v", d)
	}
	out = infoJSON(t, Options{Auth: memoryAuth(t), Dialect: func() string { return "sqlite" }})
	d = out["betterAuth"].(map[string]any)["database"].(map[string]any)
	if d["dialect"] != "sqlite" {
		t.Fatalf("database %v", d)
	}
}

func TestInfoText(t *testing.T) {
	r := run(t, Options{Auth: newAuth(t, betterauth.Config{
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
	})}, "", "info")
	if r.code != 0 {
		t.Fatal(r.stderr)
	}
	for _, want := range []string{
		"📊 Better Auth System Information",
		"🖥️  System Information:",
		"  platform: ",
		"📦 Go:",
		"🔐 Better Auth:",
		"  Version: ",
		"  Database:\n    adapter: memory",
		"  Configuration:\n",
		"    emailAndPassword:\n      enabled: true",
		"    secret: [REDACTED]",
		"💡 Tip: Use --json flag for JSON output",
	} {
		contains(t, r.stdout, want)
	}

	r = run(t, Options{NewAuth: func(context.Context, string) (*betterauth.Auth, error) {
		return nil, errors.New("cannot load config")
	}}, "", "info")
	if r.code != 0 {
		t.Fatal(r.code)
	}
	contains(t, r.stdout, "  Error: cannot load config")
	notContains(t, r.stdout, "Configuration:")
}

func TestRedactSensitive(t *testing.T) {
	in := newObject().
		set("secret", "s").
		set("emptySecret", "").
		set("apiKey", "k").
		set("myApiKey", "k").
		set("callbackURL", "https://x").
		set("count", int64(3)).
		set("webhook", newObject().set("url", "https://hook").set("token", "t")).
		set("clientId", []any{"a", "b"}).
		set("password", false).
		set("nested", newObject().set("authToken", "x").set("list", []any{newObject().set("privateKey", "p")})).
		set("providers", newObject().set("TOKEN", "upper"))
	got, _ := json.Marshal(redactSensitive(in, ""))
	want := `{"secret":"[REDACTED]","emptySecret":"","apiKey":"[REDACTED]","myApiKey":"[REDACTED]","callbackURL":"https://x","count":3,"webhook":{"url":"https://hook","token":"[REDACTED]"},"clientId":"[REDACTED]","password":false,"nested":{"authToken":"[REDACTED]","list":[{"privateKey":"[REDACTED]"}]},"providers":{"TOKEN":"[REDACTED]"}}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// strings under a sensitive parent key are redacted
	if v := redactSensitive("abc", "clientSecret"); v != redacted {
		t.Fatal(v)
	}
	if v := redactSensitive([]any{"a"}, "trustedOrigins"); v.([]any)[0] != "a" {
		t.Fatal(v)
	}
}

func TestJSONKey(t *testing.T) {
	for in, want := range map[string]string{
		"BaseURL":              "baseURL",
		"AppName":              "appName",
		"ClientID":             "clientId",
		"ClientIDs":            "clientIds",
		"DisableIDTokenSignIn": "disableIdTokenSignIn",
		"IPAddress":            "ipAddress",
		"IDMode":               "idMode",
		"HTTPOnly":             "httpOnly",
		"IPv6Subnet":           "ipv6Subnet",
		"URL":                  "url",
		"EmailAndPassword":     "emailAndPassword",
		"TrustedOrigins":       "trustedOrigins",
		"RedirectURI":          "redirectURI",
	} {
		if got := jsonKey(in); got != want {
			t.Errorf("jsonKey(%q) = %q, want %q", in, got, want)
		}
	}
}
