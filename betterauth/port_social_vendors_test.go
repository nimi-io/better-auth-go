package betterauth

// Port of better-auth/src/social.test.ts (upstream v1.7.7): "Vercel Provider",
// "Cloudflare Provider", "Railway Provider".

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/cloudflare"
	"github.com/nimi-io/better-auth-go/providers/railway"
	"github.com/nimi-io/better-auth-go/providers/vercel"
)

// psocChecks collects expectations evaluated inside mocked provider handlers.
type psocChecks struct {
	mu   sync.Mutex
	errs []string
}

func (c *psocChecks) failf(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, msg)
}

func (c *psocChecks) assert(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.errs {
		t.Error("mock expectation: " + e)
	}
	c.errs = nil
}

func psocWriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func psocForm(r *http.Request) url.Values {
	_ = r.ParseForm()
	return r.PostForm
}

// ---- describe("Vercel Provider") ----

func psocVercelMocks(m *oauth2test.Server, checks *psocChecks) {
	m.Handle("POST api.vercel.com/login/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if cv := psocForm(r).Get("code_verifier"); cv == "" {
			checks.failf("vercel token: code_verifier must be present")
		}
		profile := map[string]any{"sub": "vercel_user_123", "email": "vercel@test.com", "email_verified": true, "name": "Vercel User",
			"preferred_username": "verceluser", "picture": "https://vercel.com/avatar.png"}
		psocWriteJSON(w, 200, map[string]any{"access_token": "vercel_access_token", "refresh_token": "vercel_refresh_token",
			"id_token": m.IDToken(profile), "token_type": "Bearer", "expires_in": 3600})
	})
	m.JSON("GET api.vercel.com/login/oauth/userinfo", 200, map[string]any{"sub": "vercel_user_123", "email": "vercel@test.com",
		"email_verified": true, "name": "Vercel User", "preferred_username": "verceluser", "picture": "https://vercel.com/avatar.png"})
}

func psocVercelOpts() oauth2.ProviderOptions {
	return oauth2.ProviderOptions{ClientID: "vercel-test-client-id", ClientSecret: "vercel-test-client-secret"}
}

func TestPortSocialVercelProvider(t *testing.T) {
	m := psocMock(t)
	checks := &psocChecks{}
	psocVercelMocks(m, checks)
	defer checks.assert(t)
	vercelEnv := func(t *testing.T, o oauth2.ProviderOptions, mutate func(c *Config), disableTestUser bool) *testEnv {
		return psocEnv(t, func(c *Config) {
			c.SocialProviders = []oauth2.Provider{vercel.New(vercel.Options{ProviderOptions: o})}
			if mutate != nil {
				mutate(c)
			}
		}, disableTestUser)
	}

	t.Run("should configure Vercel provider correctly", func(t *testing.T) {
		env := vercelEnv(t, psocVercelOpts(), nil, false)
		p := env.auth.Context().FindProvider("vercel")
		if p == nil || p.ID() != "vercel" || p.Name() != "Vercel" {
			t.Fatalf("provider %v", p)
		}
	})

	t.Run("should initiate Vercel OAuth flow with PKCE", func(t *testing.T) {
		env := vercelEnv(t, psocVercelOpts(), nil, false)
		_, u, _ := psocStart(t, env.client(), map[string]any{"provider": "vercel", "callbackURL": "/dashboard"})
		if !strings.Contains(u.String(), "vercel.com/oauth/authorize") {
			t.Fatalf("url %s", u)
		}
		if !u.Query().Has("code_challenge") || u.Query().Get("code_challenge_method") != "S256" {
			t.Fatalf("url %s", u)
		}
	})

	t.Run("should complete Vercel OAuth flow and create user", func(t *testing.T) {
		env := vercelEnv(t, psocVercelOpts(), nil, true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "vercel", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
		res := psocCallback(c, "vercel", state, "vercel_test_code")
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/welcome") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
		u := psocSessionUser(t, c)
		if u["email"] != "vercel@test.com" || u["name"] != "Vercel User" || u["image"] != "https://vercel.com/avatar.png" || u["emailVerified"] != true {
			t.Fatalf("user %v", u)
		}
		accs := psocAccounts(t, env, u["id"].(string))
		if len(accs) != 1 || accs[0].ProviderID != "vercel" || accs[0].AccountID != "vercel_user_123" {
			t.Fatalf("accounts %+v", accs)
		}
	})

	t.Run("should use preferred_username as fallback for name", func(t *testing.T) {
		profile := map[string]any{"sub": "vercel_user_456", "email": "noname@vercel.com", "email_verified": true,
			"preferred_username": "cooldev", "picture": "https://vercel.com/avatar2.png"}
		m.JSON("POST api.vercel.com/login/oauth/token", 200, map[string]any{"access_token": "vercel_access_token_2",
			"id_token": m.IDToken(profile), "token_type": "Bearer", "expires_in": 3600})
		m.JSON("GET api.vercel.com/login/oauth/userinfo", 200, profile)
		defer psocVercelMocks(m, checks)
		env := vercelEnv(t, psocVercelOpts(), nil, true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "vercel", "callbackURL": "/dashboard"})
		psocCallback(c, "vercel", state, "vercel_test_code_2")
		if u := psocSessionUser(t, c); u["name"] != "cooldev" {
			t.Fatalf("name %v", u["name"])
		}
	})

	t.Run("should allow additional scopes", func(t *testing.T) {
		o := psocVercelOpts()
		o.Scope = []string{"openid", "email", "profile", "offline_access"}
		env := vercelEnv(t, o, nil, false)
		_, u, _ := psocStart(t, env.client(), map[string]any{"provider": "vercel", "callbackURL": "/dashboard"})
		sc := u.Query().Get("scope")
		for _, s := range []string{"openid", "email", "profile", "offline_access"} {
			if !strings.Contains(sc, s) {
				t.Fatalf("scope %q missing %s", sc, s)
			}
		}
	})

	t.Run("should support mapProfileToUser", func(t *testing.T) {
		o := psocVercelOpts()
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"vercelUserId": profile["sub"]}, nil
		}
		env := vercelEnv(t, o, func(c *Config) {
			c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{{Name: "vercelUserId", Type: db.TypeString}}}}
		}, true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "vercel", "callbackURL": "/dashboard"})
		psocCallback(c, "vercel", state, "vercel_test_code_3")
		u := psocSessionUser(t, c)
		if v, ok := u["vercelUserId"]; !ok || v == nil {
			t.Fatalf("user should have vercelUserId: %v", u)
		}
	})

	t.Run("should redirect existing Vercel users to callback URL", func(t *testing.T) {
		env := vercelEnv(t, psocVercelOpts(), nil, false)
		c := env.client()
		_, _, s1 := psocStart(t, c, map[string]any{"provider": "vercel", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
		if loc := psocCallback(c, "vercel", s1, "vercel_test_code_existing").Header.Get("Location"); !strings.Contains(loc, "/welcome") {
			t.Fatalf("first location %s", loc)
		}
		_, _, s2 := psocStart(t, c, map[string]any{"provider": "vercel", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
		res := psocCallback(c, "vercel", s2, "vercel_test_code_existing_2")
		loc := psocExpect302(t, res)
		if !strings.Contains(loc, "/dashboard") || strings.Contains(loc, "/welcome") {
			t.Fatalf("second location %s", loc)
		}
	})
}

// ---- describe("Cloudflare Provider") ----

var psocBasic = regexp.MustCompile(`^Basic `)
var psocBearer = regexp.MustCompile(`^Bearer `)

func psocCloudflareMocks(m *oauth2test.Server, checks *psocChecks, userInfoCount *int32) {
	m.Handle("POST dash.cloudflare.com/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if !psocBasic.MatchString(r.Header.Get("Authorization")) {
			checks.failf("cloudflare token: authorization should match ^Basic, got " + r.Header.Get("Authorization"))
		}
		f := psocForm(r)
		if f.Get("grant_type") != "authorization_code" {
			checks.failf("cloudflare token: grant_type " + f.Get("grant_type"))
		}
		if !f.Has("code_verifier") {
			checks.failf("cloudflare token: code_verifier should not be null")
		}
		if f.Has("client_secret") {
			checks.failf("cloudflare token: client_secret should be null")
		}
		psocWriteJSON(w, 200, map[string]any{"access_token": "cloudflare_access_token", "refresh_token": "cloudflare_refresh_token",
			"token_type": "Bearer", "expires_in": 3600})
	})
	m.Handle("GET api.cloudflare.com/client/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if !psocBearer.MatchString(r.Header.Get("Authorization")) {
			checks.failf("cloudflare user: authorization should match ^Bearer")
		}
		psocWriteJSON(w, 200, map[string]any{"success": true, "errors": []any{}, "messages": []any{},
			"result": map[string]any{"id": "cloudflare_user_123", "email": "cloudflare@test.com", "first_name": "Cloudflare", "last_name": "User"}})
	})
	m.Handle("GET dash.cloudflare.com/oauth2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(userInfoCount, 1)
		psocWriteJSON(w, 200, map[string]any{"sub": "cloudflare_user_123"})
	})
}

func TestPortSocialCloudflareProvider(t *testing.T) {
	m := psocMock(t)
	checks := &psocChecks{}
	var userInfoCount int32
	psocCloudflareMocks(m, checks, &userInfoCount)
	defer checks.assert(t)
	cfEnv := func(t *testing.T, o cloudflare.Options, disableTestUser bool) *testEnv {
		return psocEnv(t, func(c *Config) { c.SocialProviders = []oauth2.Provider{cloudflare.New(o)} }, disableTestUser)
	}
	defOpts := func() cloudflare.Options {
		return cloudflare.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cloudflare-test-client-id", ClientSecret: "cloudflare-test-client-secret"}}
	}
	// once: true handlers are emulated by re-registering the defaults after the test.
	restore := func() { psocCloudflareMocks(m, checks, &userInfoCount) }

	t.Run("should configure Cloudflare provider correctly", func(t *testing.T) {
		p := cfEnv(t, defOpts(), false).auth.Context().FindProvider("cloudflare")
		if p == nil || p.ID() != "cloudflare" || p.Name() != "Cloudflare" {
			t.Fatalf("provider %v", p)
		}
	})

	t.Run("should initiate Cloudflare OAuth flow with PKCE", func(t *testing.T) {
		_, u, _ := psocStart(t, cfEnv(t, defOpts(), false).client(), map[string]any{"provider": "cloudflare", "callbackURL": "/dashboard"})
		if !strings.Contains(u.String(), "dash.cloudflare.com/oauth2/auth") {
			t.Fatalf("url %s", u)
		}
		sc := u.Query().Get("scope")
		if !strings.Contains(sc, "user-details.read") || strings.Contains(sc, "openid") {
			t.Fatalf("scope %q", sc)
		}
		if !u.Query().Has("code_challenge") || u.Query().Get("code_challenge_method") != "S256" {
			t.Fatalf("url %s", u)
		}
	})

	t.Run("should not send an empty scope parameter when default scopes are disabled", func(t *testing.T) {
		o := defOpts()
		o.DisableDefaultScope = true
		o.Scope = []string{}
		_, u, _ := psocStart(t, cfEnv(t, o, false).client(), map[string]any{"provider": "cloudflare", "callbackURL": "/dashboard"})
		if u.Query().Has("scope") {
			t.Fatalf("scope should be null: %s", u)
		}
	})

	t.Run("should include additional Cloudflare API scopes", func(t *testing.T) {
		o := defOpts()
		o.Scope = []string{"workers-platform.read"}
		_, u, _ := psocStart(t, cfEnv(t, o, false).client(), map[string]any{"provider": "cloudflare", "callbackURL": "/dashboard"})
		sc := u.Query().Get("scope")
		if !strings.Contains(sc, "user-details.read") || !strings.Contains(sc, "workers-platform.read") || strings.Contains(sc, "openid") {
			t.Fatalf("scope %q", sc)
		}
	})

	t.Run("should complete Cloudflare OAuth flow and create user", func(t *testing.T) {
		env := cfEnv(t, defOpts(), true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "cloudflare", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
		res := psocCallback(c, "cloudflare", state, "cloudflare_test_code")
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/welcome") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
		u := psocSessionUser(t, c)
		if u["email"] != "cloudflare@test.com" || u["name"] != "Cloudflare User" || u["emailVerified"] != false {
			t.Fatalf("user %v", u)
		}
		if img, ok := u["image"]; !ok || img != nil {
			t.Fatalf("image should be null: %v (present=%v)", img, ok)
		}
		accs := psocAccounts(t, env, u["id"].(string))
		if len(accs) != 1 || accs[0].ProviderID != "cloudflare" || accs[0].AccountID != "cloudflare_user_123" {
			t.Fatalf("accounts %+v", accs)
		}
	})

	t.Run("should support client_secret_post token authentication", func(t *testing.T) {
		m.Handle("POST dash.cloudflare.com/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				checks.failf("client_secret_post: authorization should be null")
			}
			f := psocForm(r)
			if f.Get("client_id") != "cloudflare-post-client-id" || f.Get("client_secret") != "cloudflare-post-client-secret" {
				checks.failf("client_secret_post: body " + f.Encode())
			}
			psocWriteJSON(w, 200, map[string]any{"access_token": "cloudflare_post_access_token", "token_type": "Bearer", "expires_in": 3600})
		})
		defer restore()
		env := cfEnv(t, cloudflare.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cloudflare-post-client-id",
			ClientSecret: "cloudflare-post-client-secret"}, TokenEndpointAuthMethod: oauth2.AuthClientSecretPost}, true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "cloudflare", "callbackURL": "/dashboard"})
		psocCallback(c, "cloudflare", state, "cloudflare_post_code")
		if u := psocSessionUser(t, c); u["email"] != "cloudflare@test.com" {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("should support public clients", func(t *testing.T) {
		m.Handle("POST dash.cloudflare.com/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				checks.failf("public client: authorization should be null")
			}
			f := psocForm(r)
			if f.Get("client_id") != "cloudflare-public-client-id" || f.Has("client_secret") {
				checks.failf("public client: body " + f.Encode())
			}
			psocWriteJSON(w, 200, map[string]any{"access_token": "cloudflare_public_access_token", "token_type": "Bearer", "expires_in": 3600})
		})
		defer restore()
		env := cfEnv(t, cloudflare.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cloudflare-public-client-id"},
			TokenEndpointAuthMethod: oauth2.AuthNone}, true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "cloudflare", "callbackURL": "/dashboard"})
		psocCallback(c, "cloudflare", state, "cloudflare_public_code")
		if u := psocSessionUser(t, c); u["email"] != "cloudflare@test.com" {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("derives the profile from the Cloudflare API /user endpoint, not the OIDC userinfo endpoint", func(t *testing.T) {
		atomic.StoreInt32(&userInfoCount, 0)
		m.JSON("GET api.cloudflare.com/client/v4/user", 200, map[string]any{"success": true, "errors": []any{}, "messages": []any{},
			"result": map[string]any{"id": "cloudflare_user_123", "email": "first-only@test.com", "first_name": "First"}})
		defer restore()
		env := cfEnv(t, defOpts(), true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "cloudflare", "callbackURL": "/dashboard"})
		psocCallback(c, "cloudflare", state, "cloudflare_user_endpoint_code")
		u := psocSessionUser(t, c)
		if u["email"] != "first-only@test.com" || u["name"] != "First" {
			t.Fatalf("user %v", u)
		}
		if n := atomic.LoadInt32(&userInfoCount); n != 0 {
			t.Fatalf("userinfo requests %d", n)
		}
	})
}

// ---- describe("Railway Provider") ----

func TestPortSocialRailwayProvider(t *testing.T) {
	m := psocMock(t)
	checks := &psocChecks{}
	defer checks.assert(t)
	m.Handle("POST backboard.railway.com/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if !psocBasic.MatchString(r.Header.Get("Authorization")) {
			checks.failf("railway token: authorization should match ^Basic")
		}
		f := psocForm(r)
		if f.Get("grant_type") != "authorization_code" {
			checks.failf("railway token: grant_type " + f.Get("grant_type"))
		}
		if f.Get("code_verifier") == "" {
			checks.failf("railway token: code_verifier must be present")
		}
		psocWriteJSON(w, 200, map[string]any{"access_token": "railway_access_token", "token_type": "Bearer", "expires_in": 3600})
	})
	m.JSON("GET backboard.railway.com/oauth/me", 200, map[string]any{"sub": "user_railway_123", "email": "railway@test.com",
		"name": "Railway User", "picture": "https://avatars.githubusercontent.com/u/12345"})
	opts := railway.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "railway-test-client-id", ClientSecret: "railway-test-client-secret"}}
	rwEnv := func(t *testing.T, disableTestUser bool) *testEnv {
		return psocEnv(t, func(c *Config) { c.SocialProviders = []oauth2.Provider{railway.New(opts)} }, disableTestUser)
	}

	t.Run("should configure Railway provider correctly", func(t *testing.T) {
		p := rwEnv(t, false).auth.Context().FindProvider("railway")
		if p == nil || p.ID() != "railway" || p.Name() != "Railway" {
			t.Fatalf("provider %v", p)
		}
	})

	t.Run("should initiate Railway OAuth flow with PKCE", func(t *testing.T) {
		_, u, _ := psocStart(t, rwEnv(t, false).client(), map[string]any{"provider": "railway", "callbackURL": "/dashboard"})
		if !strings.Contains(u.String(), "backboard.railway.com/oauth/auth") {
			t.Fatalf("url %s", u)
		}
		sc := u.Query().Get("scope")
		for _, s := range []string{"openid", "email", "profile"} {
			if !strings.Contains(sc, s) {
				t.Fatalf("scope %q missing %s", sc, s)
			}
		}
		if !u.Query().Has("code_challenge") || u.Query().Get("code_challenge_method") != "S256" {
			t.Fatalf("url %s", u)
		}
	})

	t.Run("should complete Railway OAuth flow and create user", func(t *testing.T) {
		env := rwEnv(t, true)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "railway", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
		res := psocCallback(c, "railway", state, "railway_test_code")
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/welcome") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
		u := psocSessionUser(t, c)
		if u["email"] != "railway@test.com" || u["name"] != "Railway User" ||
			u["image"] != "https://avatars.githubusercontent.com/u/12345" || u["emailVerified"] != false {
			t.Fatalf("user %v", u)
		}
		accs := psocAccounts(t, env, u["id"].(string))
		if len(accs) != 1 || accs[0].ProviderID != "railway" || accs[0].AccountID != "user_railway_123" {
			t.Fatalf("accounts %+v", accs)
		}
	})
}
