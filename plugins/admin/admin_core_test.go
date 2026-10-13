package admin

import (
	"context"
	"net/http"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Core tests that need the admin plugin. They live here because betterauth cannot import
// plugins (import cycle); the corresponding betterauth tests skip with a pointer here.

// Port of db/secondary-storage.test.ts — describe("secondary storage - admin removeUser
// cleans up sessions") (GHSA-2vg6-77g8-24mp).
func TestPortDBSecondaryStorage_AdminRemoveUserCleansUpSessions(t *testing.T) {
	store := betterauth.NewMemoryStorage()
	e := newEnv(t, func(c *betterauth.Config) {
		c.Plugins = []*betterauth.Plugin{New(Options{})}
		c.SecondaryStorage = store
		c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
			Before: func(_ context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
				if data["email"] == "admin@test.com" {
					return &betterauth.DBHookResult{Data: adapter.Record{"role": "admin"}}, nil
				}
				return nil, nil
			},
		}}}
	}, instanceOpts{})

	t.Run("should clear secondary storage sessions when removing a user via admin", func(t *testing.T) {
		e.signUp("admin@test.com", "password", "Admin", nil)
		adminHeaders, _ := e.signIn("admin@test.com", "password")
		e.signUp("victim@test.com", "password", "Victim", nil)
		victimHeaders, _ := e.signIn("victim@test.com", "password")
		s := e.get("/get-session", nil, victimHeaders).data(t)
		victimID := s["user"].(map[string]any)["id"]
		token := s["session"].(map[string]any)["token"].(string)
		if _, ok, _ := store.Get(context.Background(), token); !ok {
			t.Fatal("victim session missing from secondary storage")
		}
		e.post("/admin/remove-user", map[string]any{"userId": victimID}, adminHeaders).data(t)
		if _, ok, _ := store.Get(context.Background(), token); ok {
			t.Fatal("victim session still in secondary storage")
		}
		if res := e.get("/get-session", nil, victimHeaders); string(res.Body) != "null" {
			t.Fatalf("session after removal: %s", res.Body)
		}
	})
}

// Port of api/routes/sign-up.test.ts — describe("sign-up enumeration protection —
// customSyntheticUser with admin plugin").
func TestPortAuthSignUpCustomSyntheticUserAdmin(t *testing.T) {
	e := newEnv(t, func(c *betterauth.Config) {
		c.EmailAndPassword = &betterauth.EmailAndPasswordConfig{Enabled: true, RequireEmailVerification: true,
			CustomSyntheticUser: func(p betterauth.SyntheticUserParams) map[string]any {
				out := map[string]any{}
				for k, v := range p.CoreFields {
					out[k] = v
				}
				out["role"], out["banned"], out["banReason"], out["banExpires"] = "user", false, nil, nil
				for k, v := range p.AdditionalFields {
					out[k] = v
				}
				out["id"] = p.ID
				return out
			}}
		c.EmailVerification = &betterauth.EmailVerificationConfig{
			SendVerificationEmail: func(context.Context, betterauth.EmailData, *http.Request) error { return nil },
		}
		c.Plugins = []*betterauth.Plugin{New(Options{})}
	}, instanceOpts{disableTestUser: true})

	t.Run("should return indistinguishable response with admin plugin fields", func(t *testing.T) {
		call := func(password, name string) *jsonx.Object {
			res, err := e.auth.API.Call(context.Background(), "signUpEmail", betterauth.CallInput{Body: map[string]any{
				"email": "admin-enum@test.com", "password": password, "name": name}})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := res.JSON()
			v, err := jsonx.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := v.(*jsonx.Object).Get("user")
			return u.(*jsonx.Object)
		}
		first, second := call("password123", "First"), call("password456", "Second")
		if k1, k2 := first.Keys(), second.Keys(); len(k1) != len(k2) {
			t.Fatalf("keys differ:\nreal:      %v\nsynthetic: %v", k1, k2)
		} else {
			for i := range k1 {
				if k1[i] != k2[i] {
					t.Fatalf("keys differ:\nreal:      %v\nsynthetic: %v", k1, k2)
				}
			}
		}
		get := func(o *jsonx.Object, k string) any { v, _ := o.Get(k); return v }
		if get(first, "role") != "user" || get(second, "role") != "user" || get(second, "banned") != false {
			t.Fatalf("first %v second %v", first.Map(), second.Map())
		}
		for _, k := range []string{"banReason", "banExpires"} {
			if v, ok := second.Get(k); !ok || v != nil {
				t.Fatalf("%s = %v (present %v)", k, v, ok)
			}
		}
	})
}

// Port of api/routes/session-api.test.ts — describe("updateSession plugin authority
// fields"), the impersonatedBy case (the other cases need the organization plugin).
func TestPortSessionUpdateSessionPluginAuthorityFields(t *testing.T) {
	e := newEnv(t, func(c *betterauth.Config) {
		c.Plugins = []*betterauth.Plugin{New(Options{})}
	}, instanceOpts{})
	t.Run("should reject forging the impersonatedBy session field", func(t *testing.T) {
		h, _ := e.signInTestUser()
		expectStatus(t, e.post("/update-session", map[string]any{"impersonatedBy": "forged-value"}, h), 400, "")
	})
}
