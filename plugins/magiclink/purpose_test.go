package magiclink_test

// Port of packages/better-auth/src/plugins/magic-link/purpose.test.ts (v1.7.7).

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/magiclink"
)

var backends = []string{"database", "secondaryStorage"}

func withBackend(backend string) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		if backend == "secondaryStorage" {
			c.SecondaryStorage = betterauth.NewMemoryStorage()
		}
	}
}

func chain(fns ...func(c *betterauth.Config)) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		for _, f := range fns {
			f(c)
		}
	}
}

func socialState(t *testing.T, in *inst, additional map[string]any) string {
	t.Helper()
	m := in.mustAPI("signInSocial", betterauth.CallInput{Body: map[string]any{
		"provider": "github", "disableRedirect": true, "additionalData": additional}})
	raw, _ := m["url"].(string)
	if raw == "" {
		t.Fatal("OAuth authorization URL missing")
	}
	u, _ := url.Parse(raw)
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("no state")
	}
	return state
}

func findVerification(t *testing.T, in *inst, id string) *betterauth.Verification {
	t.Helper()
	v, err := in.ctx().InternalAdapter.FindVerificationValue(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerificationRecordPurpose(t *testing.T) {
	for _, backend := range backends {
		t.Run("rejects OAuth state when a custom hasher collapses purpose prefixes on "+backend, func(t *testing.T) {
			mb := &mailbox{}
			in := newInst(t, chain(withMagicLink(mb, magiclink.Options{}), withBackend(backend), func(c *betterauth.Config) {
				c.Verification = &betterauth.VerificationConfig{StoreIdentifier: &betterauth.StoreIdentifier{Hash: func(id string) (string, error) {
					for _, p := range []string{"magic-link:", "auth-state:"} {
						if strings.HasPrefix(id, p) {
							return strings.TrimPrefix(id, p), nil
						}
					}
					return id, nil
				}}}
			}))
			state := socialState(t, in, map[string]any{"type": "magic-link", "email": testEmail})
			before := findVerification(t, in, "auth-state:"+state)
			if before == nil {
				t.Fatal("state missing")
			}
			c := in.client(false)
			expectErrorRedirect(t, c.get(verifyPath(state)), "error=INVALID_TOKEN")
			after := findVerification(t, in, "auth-state:"+state)
			if after == nil || after.Value != before.Value || after.Identifier != before.Identifier || !after.ExpiresAt.Equal(before.ExpiresAt) {
				t.Fatalf("state changed: %+v vs %+v", after, before)
			}
			c.post("/sign-in/magic-link", map[string]any{"email": testEmail})
			if mb.get().Token == "" {
				t.Fatal("no token sent")
			}
			res := c.get(verifyPath(mb.get().Token))
			expectStatus(t, res, 200, "")
			if res.str("user", "email") != testEmail || res.val("user", "emailVerified") != true {
				t.Fatalf("response %s", res.Body)
			}
		})
	}

	for _, tc := range []struct{ backend, strategy string }{
		{"database", "global"}, {"secondaryStorage", "global"}, {"database", "overrides"}, {"secondaryStorage", "overrides"},
	} {
		t.Run("keeps OAuth state separate from Magic Link on "+tc.backend+" with "+tc.strategy+" identifier storage", func(t *testing.T) {
			mb := &mailbox{}
			in := newInst(t, chain(withMagicLink(mb, magiclink.Options{StoreToken: magiclink.StoreToken{Mode: "hashed"}}), withBackend(tc.backend), func(c *betterauth.Config) {
				if tc.strategy == "global" {
					c.Verification = &betterauth.VerificationConfig{StoreIdentifier: &betterauth.StoreIdentifier{Mode: "hashed"}}
				} else {
					c.Verification = &betterauth.VerificationConfig{
						StoreIdentifier: &betterauth.StoreIdentifier{Mode: "plain"},
						StoreIdentifierOverrides: map[string]betterauth.StoreIdentifier{
							"magic-link:": {Mode: "hashed"}, "auth-state:": {Mode: "hashed"},
						},
					}
				}
			}))
			state := socialState(t, in, map[string]any{"email": testEmail})
			if findVerification(t, in, "auth-state:"+state) == nil {
				t.Fatal("state missing")
			}
			c := in.client(false)
			expectErrorRedirect(t, c.get(verifyPath(state)), "error=INVALID_TOKEN")
			if findVerification(t, in, "auth-state:"+state) == nil {
				t.Fatal("state consumed")
			}
			for _, email := range []string{testEmail, "new-" + strings.ToLower(tc.backend) + "-" + tc.strategy + "@test.com"} {
				c.post("/sign-in/magic-link", map[string]any{"email": email})
				sent := mb.get().Token
				rec := findVerification(t, in, "magic-link:"+magiclink.DefaultKeyHasher(sent))
				if rec == nil {
					t.Fatal("record missing")
				}
				var parsed map[string]any
				_ = json.Unmarshal([]byte(rec.Value), &parsed)
				if parsed["type"] != "magic-link" || parsed["email"] != email {
					t.Fatalf("record %s", rec.Value)
				}
				res := c.get(verifyPath(sent))
				if res.str("user", "email") != email || res.val("user", "emailVerified") != true {
					t.Fatalf("response %d %s", res.Status, res.Body)
				}
			}
		})
	}

	for _, backend := range backends {
		t.Run("preserves date-shaped display names during Magic Link verification on "+backend, func(t *testing.T) {
			mb := &mailbox{}
			in := newInst(t, chain(withMagicLink(mb, magiclink.Options{}), withBackend(backend)))
			name := "2025-01-01T00:00:00Z"
			email := "date-name-" + strings.ToLower(backend) + "@test.com"
			c := in.client(false)
			c.post("/sign-in/magic-link", map[string]any{"email": email, "name": name})
			res := c.get(verifyPath(mb.get().Token))
			expectStatus(t, res, 200, "")
			if res.str("user", "email") != email {
				t.Fatalf("response %s", res.Body)
			}
			u, _ := in.ctx().InternalAdapter.FindUserByEmail(context.Background(), email, false)
			if u == nil || u.User.Name != name {
				t.Fatalf("user %+v", u)
			}
		})
	}

	t.Run("validates the atomically consumed record again before issuing a session", func(t *testing.T) {
		// Upstream spies on internalAdapter.consumeVerificationValue; here the adapter's
		// ConsumeOne is wrapped to return a record of the wrong shape.
		mb := &mailbox{}
		var tamper atomic.Bool
		var sessionsCreated atomic.Int32
		in := newInst(t, chain(withMagicLink(mb, magiclink.Options{}), func(c *betterauth.Config) {
			c.Database = tamperingFactory(memory.New(), &tamper, &sessionsCreated)
		}))
		c := in.client(false)
		c.post("/sign-in/magic-link", map[string]any{"email": testEmail})
		tamper.Store(true)
		sessionsCreated.Store(0)
		expectErrorRedirect(t, c.get(verifyPath(mb.get().Token)), "error=INVALID_TOKEN")
		if n := sessionsCreated.Load(); n != 0 {
			t.Fatalf("sessions created = %d", n)
		}
	})

	for _, mode := range []string{"wrong-purpose", "malformed"} {
		t.Run("rejects a namespaced "+mode+" record", func(t *testing.T) {
			in := newInst(t, withMagicLink(&mailbox{}, magiclink.Options{}))
			token := "synthetic-wrong-purpose"
			value := `{"email":"` + testEmail + `"}`
			if mode == "malformed" {
				value = "invalid JSON"
			}
			if _, err := in.ctx().InternalAdapter.CreateVerificationValue(context.Background(), "magic-link:"+token, value, time.Now().Add(time.Minute), nil); err != nil {
				t.Fatal(err)
			}
			expectErrorRedirect(t, in.client(false).get(verifyPath(token)), "error=INVALID_TOKEN")
			if findVerification(t, in, "magic-link:"+token) == nil {
				t.Fatal("record consumed")
			}
		})
	}

	for _, mode := range []string{"plain", "hashed", "overrides"} {
		t.Run("does not redeem an unprefixed "+mode+" legacy record", func(t *testing.T) {
			hashed := mode != "plain"
			in := newInst(t, func(c *betterauth.Config) {
				switch mode {
				case "overrides":
					c.Verification = &betterauth.VerificationConfig{StoreIdentifier: &betterauth.StoreIdentifier{Mode: "plain"},
						StoreIdentifierOverrides: map[string]betterauth.StoreIdentifier{"magic-link:": {Mode: "hashed"}}}
				default:
					c.Verification = &betterauth.VerificationConfig{StoreIdentifier: &betterauth.StoreIdentifier{Mode: mode}}
				}
				st := magiclink.StoreToken{Mode: "plain"}
				if hashed {
					st.Mode = "hashed"
				}
				withMagicLink(&mailbox{}, magiclink.Options{StoreToken: st})(c)
			})
			token := "synthetic-legacy-record"
			stored := token
			if hashed {
				stored = magiclink.DefaultKeyHasher(token)
			}
			if _, err := in.ctx().InternalAdapter.CreateVerificationValue(context.Background(), stored, `{"email":"`+testEmail+`"}`, time.Now().Add(time.Minute), nil); err != nil {
				t.Fatal(err)
			}
			expectErrorRedirect(t, in.client(false).get(verifyPath(token)), "error=INVALID_TOKEN")
			if findVerification(t, in, stored) == nil {
				t.Fatal("legacy record consumed")
			}
		})
	}

	for _, mode := range []string{"plain", "hashed", "custom"} {
		t.Run("keeps "+mode+" Magic Link sign-in and sign-up working with hashed identifiers", func(t *testing.T) {
			mb := &mailbox{}
			st := magiclink.StoreToken{Mode: mode}
			if mode == "custom" {
				st = magiclink.StoreToken{Hash: func(tok string) (string, error) { return "custom:" + tok, nil }}
			}
			in := newInst(t, func(c *betterauth.Config) {
				c.Verification = &betterauth.VerificationConfig{StoreIdentifier: &betterauth.StoreIdentifier{Mode: "hashed"}}
				withMagicLink(mb, magiclink.Options{StoreToken: st})(c)
			})
			c := in.client(false)
			for _, email := range []string{testEmail, "new-" + mode + "@test.com"} {
				c.post("/sign-in/magic-link", map[string]any{"email": email})
				sent := mb.get().Token
				stored := sent
				switch mode {
				case "hashed":
					stored = magiclink.DefaultKeyHasher(sent)
				case "custom":
					stored = "custom:" + sent
				}
				row := findVerification(t, in, "magic-link:"+stored)
				if row == nil {
					t.Fatal("row missing")
				}
				var parsed map[string]any
				_ = json.Unmarshal([]byte(row.Value), &parsed)
				if parsed["type"] != "magic-link" || parsed["email"] != email {
					t.Fatalf("row %s", row.Value)
				}
				if findVerification(t, in, stored) != nil {
					t.Fatal("unprefixed row found")
				}
				res := c.get(verifyPath(sent))
				if res.str("user", "email") != email || res.val("user", "emailVerified") != true {
					t.Fatalf("response %d %s", res.Status, res.Body)
				}
			}
		})
	}

	t.Run("namespaces state created by social linking and popup start", func(t *testing.T) {
		// The oauth-popup half needs the oauth-popup plugin (ported separately); the
		// social-linking state is checked here.
		in := newInst(t, withMagicLink(&mailbox{}, magiclink.Options{}))
		h := in.signIn(testEmail, testPassword)
		m := in.mustAPI("linkSocialAccount", betterauth.CallInput{Body: map[string]any{"provider": "github"}, Headers: h})
		raw, _ := m["url"].(string)
		u, _ := url.Parse(raw)
		state := u.Query().Get("state")
		if state == "" {
			t.Fatalf("no state in %q", raw)
		}
		if findVerification(t, in, "auth-state:"+state) == nil {
			t.Fatal("state missing")
		}
		expectErrorRedirect(t, in.client(false).get(verifyPath(state)), "error=INVALID_TOKEN")
	})
}

// tamperingAdapter rewrites consumed verification rows and counts created sessions.
type tamperingAdapter struct {
	adapter.Adapter
	tamper   *atomic.Bool
	sessions *atomic.Int32
}

func tamperingFactory(inner adapter.Factory, tamper *atomic.Bool, sessions *atomic.Int32) adapter.Factory {
	return func(opts adapter.Options) (adapter.Adapter, error) {
		a, err := inner(opts)
		if err != nil {
			return nil, err
		}
		return &tamperingAdapter{Adapter: a, tamper: tamper, sessions: sessions}, nil
	}
}

func (t *tamperingAdapter) ConsumeOne(ctx context.Context, model string, where []adapter.Where) (adapter.Record, error) {
	rec, err := t.Adapter.ConsumeOne(ctx, model, where)
	if err == nil && rec != nil && model == "verification" && t.tamper.Load() {
		rec["value"] = `{"type":"magic-link","email":"` + testEmail + `","callbackURL":"/dashboard"}`
	}
	return rec, err
}

func (t *tamperingAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if in.Model == "session" {
		t.sessions.Add(1)
	}
	return t.Adapter.Create(ctx, in)
}
