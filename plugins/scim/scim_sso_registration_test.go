package scim

// Port of scim-sso-registration.test.ts (SCIM and SSO registration coexistence).

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/sso"
)

const (
	ssoRegSharedProviderID = "shared-enterprise"
	ssoRegTestCert         = `MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcm9markup
temporary cert for testing`
)

// ssoRegInstrumentedAdapter records the models queried with findOne and fails on the
// removed scimProvider model (the instrumentedDatabase of the upstream test).
type ssoRegInstrumentedAdapter struct {
	adapter.Adapter
	mu      *sync.Mutex
	queried *[]string
}

func (a *ssoRegInstrumentedAdapter) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	a.mu.Lock()
	*a.queried = append(*a.queried, in.Model)
	a.mu.Unlock()
	if in.Model == "scimProvider" {
		return nil, &ssoRegError{"Unexpected query of removed scimProvider model"}
	}
	return a.Adapter.FindOne(ctx, in)
}

func (a *ssoRegInstrumentedAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return a.Adapter.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
		return fn(ctx, &ssoRegInstrumentedAdapter{Adapter: tx, mu: a.mu, queried: a.queried})
	})
}

// Custom exposes the driver so migrations still work through the wrapper.
func (a *ssoRegInstrumentedAdapter) Custom() adapter.CustomAdapter {
	if c, ok := a.Adapter.(interface{ Custom() adapter.CustomAdapter }); ok {
		return c.Custom()
	}
	return nil
}

type ssoRegError struct{ msg string }

func (e *ssoRegError) Error() string { return e.msg }

// ssoRegCookieHeader joins the name=value pairs of the Set-Cookie headers.
func ssoRegCookieHeader(h http.Header) string {
	var parts []string
	for _, sc := range h.Values("Set-Cookie") {
		parts = append(parts, strings.SplitN(sc, ";", 2)[0])
	}
	return strings.Join(parts, "; ")
}

func ssoRegProvisioningCounts(t *testing.T, e *testEnv) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for key, model := range map[string]string{
		"connections": "scimConnectionBinding",
		"tombstones":  "scimIdentityTombstone",
		"subjects":    "scimSubject",
		"users":       "scimUser",
		"groups":      "scimGroup",
		"memberships": "scimGroupMember",
		"grants":      "scimProjectionGrant",
	} {
		n, err := e.db().Count(context.Background(), model, nil)
		if err != nil {
			t.Fatalf("count %s: %v", model, err)
		}
		out[key] = n
	}
	return out
}

func TestSSORegCoexistence(t *testing.T) {
	t.Run("registers an SSO provider whose providerId equals a SCIM connection ID", func(t *testing.T) {
		t.Setenv("NODE_ENV", "test")
		var mu sync.Mutex
		var queried []string
		instrument := false
		e := newEnv(t, Options{Connections: []ConnectionOptions{{
			ID:          ssoRegSharedProviderID,
			Credentials: []BearerCredential{{Type: "bearer", ID: "shared-scim-credential", Token: "shared-scim-token"}},
		}}}, envOptions{
			sqlite:       true,
			extraPlugins: []*betterauth.Plugin{sso.New(sso.Options{})},
			mutate: func(cfg *betterauth.Config) {
				cfg.EmailAndPassword = &betterauth.EmailAndPasswordConfig{Enabled: true}
				inner := cfg.Database
				cfg.Database = func(o adapter.Options) (adapter.Adapter, error) {
					a, err := inner(o)
					if err != nil {
						return nil, err
					}
					instrument = true
					return &ssoRegInstrumentedAdapter{Adapter: a, mu: &mu, queried: &queried}, nil
				}
			},
		})
		if !instrument {
			t.Fatal("database was not instrumented")
		}
		base := e.auth.Options().BaseURL

		rows, err := e.sqlDB.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
		if err != nil {
			t.Fatal(err)
		}
		var tables []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			tables = append(tables, strings.ToLower(strings.ReplaceAll(name, "_", "")))
		}
		rows.Close()
		for _, name := range tables {
			if name == "scimprovider" {
				t.Fatalf("unexpected scimProvider table: %v", tables)
			}
		}

		signUp := e.request("POST", "/api/auth/sign-up/email", map[string]any{
			"email": "sso-admin@example.com", "password": "password123", "name": "SSO Admin",
		}, map[string]string{"Content-Type": "application/json", "Origin": base})
		if signUp.Status != 200 {
			t.Fatalf("sign-up: %d %s", signUp.Status, signUp.text())
		}
		cookie := ssoRegCookieHeader(signUp.Header)
		if cookie == "" {
			t.Fatal("sign-up set no cookie")
		}

		beforeSSOProviders := len(e.rows("ssoProvider"))
		beforeAccounts := e.rows("account")
		beforeProvisioning := ssoRegProvisioningCounts(t, e)

		res := e.request("POST", "/api/auth/sso/register", map[string]any{
			"providerId": ssoRegSharedProviderID,
			"issuer":     "https://idp.example.com",
			"domain":     "example.com",
			"samlConfig": map[string]any{
				"entryPoint":           "https://idp.example.com/sso",
				"cert":                 ssoRegTestCert,
				"callbackUrl":          base + "/api/auth/sso/callback",
				"audience":             "better-auth-slice-c",
				"wantAssertionsSigned": true,
				"idpMetadata":          map[string]any{"entityID": "https://idp.example.com"},
				"spMetadata":           map[string]any{},
			},
		}, map[string]string{"Content-Type": "application/json", "Cookie": cookie, "Origin": base})
		if res.Status != 200 {
			t.Fatalf("register: %d %s", res.Status, res.text())
		}
		mu.Lock()
		for _, m := range queried {
			if m == "scimProvider" {
				t.Errorf("scimProvider was queried")
			}
		}
		mu.Unlock()
		if got := res.json()["providerId"]; got != ssoRegSharedProviderID {
			t.Errorf("providerId = %v; body %s", got, res.text())
		}
		providers := e.rows("ssoProvider")
		if beforeSSOProviders != 0 {
			t.Errorf("ssoProviders before = %d", beforeSSOProviders)
		}
		if len(providers) != 1 || providers[0]["providerId"] != ssoRegSharedProviderID {
			t.Errorf("ssoProviders = %v", providers)
		}
		if after := e.rows("account"); !reflect.DeepEqual(after, beforeAccounts) {
			t.Errorf("accounts changed: before %v after %v", beforeAccounts, after)
		}
		for _, a := range beforeAccounts {
			if a["providerId"] == ssoRegSharedProviderID {
				t.Errorf("account with shared providerId before registration: %v", a)
			}
		}
		zero := map[string]int64{"connections": 0, "tombstones": 0, "subjects": 0, "users": 0, "groups": 0, "memberships": 0, "grants": 0}
		if !reflect.DeepEqual(beforeProvisioning, zero) {
			t.Errorf("provisioning before = %v", beforeProvisioning)
		}
		if after := ssoRegProvisioningCounts(t, e); !reflect.DeepEqual(after, beforeProvisioning) {
			t.Errorf("provisioning after = %v; want %v", after, beforeProvisioning)
		}
	})
}
