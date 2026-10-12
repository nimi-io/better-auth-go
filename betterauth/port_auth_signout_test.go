package betterauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Port of better-auth/src/api/routes/sign-out.test.ts and error.test.ts

// paLogoutProvider stands in for a genericOAuth provider config. Its CreateEndSessionURL
// mirrors plugins/generic-oauth createEndSessionURL so the core /sign-out provider-logout
// logic can be exercised before the generic-oauth plugin is ported.
type paLogoutProvider struct {
	id, clientID          string
	endSessionEndpoint    string
	disableProviderLogout bool
	baseURL               string
}

func (p *paLogoutProvider) ID() string   { return p.id }
func (p *paLogoutProvider) Name() string { return p.id }
func (p *paLogoutProvider) CreateAuthorizationURL(context.Context, oauth2.AuthorizationURLParams) (*url.URL, error) {
	return nil, errors.New("not implemented")
}
func (p *paLogoutProvider) ValidateAuthorizationCode(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
	return nil, errors.New("not implemented")
}
func (p *paLogoutProvider) GetUserInfo(context.Context, oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
	return nil, errors.New("not implemented")
}
func (p *paLogoutProvider) AccountSubject(context.Context, *oauth2.Tokens, map[string]any) (string, error) {
	return "", errors.New("not implemented")
}

func (p *paLogoutProvider) CreateEndSessionURL(_ context.Context, d oauth2.EndSessionParams) (*url.URL, error) {
	if p.disableProviderLogout || p.endSessionEndpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(p.endSessionEndpoint)
	if err != nil {
		return nil, nil
	}
	q := u.Query()
	if d.IDToken != "" {
		q.Set("id_token_hint", d.IDToken)
	}
	if d.PostLogoutRedirectURI != "" {
		base, _ := url.Parse(p.baseURL)
		ref, err := url.Parse(d.PostLogoutRedirectURI)
		if err == nil {
			q.Set("post_logout_redirect_uri", base.ResolveReference(ref).String())
			q.Set("client_id", p.clientID)
		}
	}
	if d.State != "" {
		q.Set("state", d.State)
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func paBaseOAuth() *paLogoutProvider {
	return &paLogoutProvider{id: "oidc-provider", clientID: "test-client-id", baseURL: paBaseURL + "/api/auth"}
}

// setupGenericOAuthSignOut
func paSetupGenericOAuthSignOut(t *testing.T, p *paLogoutProvider, mutate func(c *Config)) (*paEnv, http.Header) {
	t.Helper()
	env := paNewEnv(t, func(c *Config) {
		if mutate != nil {
			mutate(c)
		}
		c.SocialProviders = append(c.SocialProviders, p)
	})
	data, headers := env.signInWithTestUser()
	userID := data["user"].(map[string]any)["id"].(string)
	if _, err := env.auth.Context().InternalAdapter.CreateAccount(context.Background(), adapter.Record{
		"userId": userID, "providerId": "oidc-provider", "accountId": "oauth-user", "idToken": "id-token",
	}); err != nil {
		t.Fatal(err)
	}
	return env, headers
}

// describe("sign-out")
func TestPortAuthSignOut(t *testing.T) {
	var afterDeleted atomic.Int32
	env := paNewEnv(t, func(c *Config) {
		c.DatabaseHooks = &DatabaseHooks{Session: DBModelHooks{Delete: DBOperationHooks{
			After: func(context.Context, adapter.Record) error {
				afterDeleted.Add(1)
				return nil
			},
		}}}
	})

	t.Run("should sign out", func(t *testing.T) {
		_, headers := env.signInWithTestUser()
		res := env.do("POST", "/sign-out", nil, paHeaderMap(headers))
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if res.JSON(t)["success"] != true {
			t.Fatalf("body = %s", res.Body)
		}
		if afterDeleted.Load() == 0 {
			t.Fatalf("session.delete.after hook should have been called")
		}
	})

	t.Run("should clear local session cookie when reading the session fails", func(t *testing.T) {
		var fail atomic.Bool
		inst := paNewEnv(t, nil, paInstanceOpts{wrap: paWrapFailing(&fail)})
		_, headers := inst.signInWithTestUser()
		fail.Store(true)
		res := inst.do("POST", "/sign-out", nil, paHeaderMap(headers))
		fail.Store(false)
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if string(res.Body) != `{"success":true}` {
			t.Fatalf("body = %s, want {\"success\":true}", res.Body)
		}
		v, attrs, ok := paSetCookie(res.Header, "better-auth.session_token")
		if !ok {
			t.Fatalf("expected session cookie to be cleared, got %v", res.Header.Values("Set-Cookie"))
		}
		if v != "" {
			t.Fatalf("cookie value = %q, want empty", v)
		}
		if attrs["max-age"] != "0" {
			t.Fatalf("max-age = %q, want 0 (%v)", attrs["max-age"], attrs)
		}
	})

	t.Run("should return provider logout url with id_token_hint", func(t *testing.T) {
		p := paBaseOAuth()
		p.endSessionEndpoint = "https://idp.example.com/logout"
		inst, headers := paSetupGenericOAuthSignOut(t, p, nil)
		res := inst.do("POST", "/sign-out", nil, paHeaderMap(headers))
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		u, _ := m["url"].(string)
		if m["success"] != true || m["redirect"] != true || !strings.Contains(u, "https://idp.example.com/logout") {
			t.Fatalf("body = %s", res.Body)
		}
		pu, _ := url.Parse(u)
		if pu.Query().Get("id_token_hint") != "id-token" {
			t.Fatalf("id_token_hint = %q", pu.Query().Get("id_token_hint"))
		}
		if loc := res.Header.Get("Location"); loc != u {
			t.Fatalf("location = %q, want %q", loc, u)
		}
	})

	t.Run("should keep local-only sign out when provider has no logout endpoint", func(t *testing.T) {
		inst, headers := paSetupGenericOAuthSignOut(t, paBaseOAuth(), nil)
		res := inst.do("POST", "/sign-out", nil, paHeaderMap(headers))
		if res.Status != 200 || string(res.Body) != `{"success":true}` {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})

	t.Run("should keep local-only sign out when provider logout is disabled", func(t *testing.T) {
		p := paBaseOAuth()
		p.endSessionEndpoint = "https://idp.example.com/logout"
		p.disableProviderLogout = true
		inst, headers := paSetupGenericOAuthSignOut(t, p, nil)
		res := inst.do("POST", "/sign-out", nil, paHeaderMap(headers))
		if res.Status != 200 || string(res.Body) != `{"success":true}` {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})

	t.Run("should include callbackURL as post_logout_redirect_uri with state", func(t *testing.T) {
		p := paBaseOAuth()
		p.endSessionEndpoint = "https://idp.example.com/logout"
		inst, headers := paSetupGenericOAuthSignOut(t, p, nil)
		res := inst.do("POST", "/sign-out", map[string]any{"callbackURL": "/login", "state": "logout-state"}, paHeaderMap(headers))
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		u, _ := res.JSON(t)["url"].(string)
		pu, err := url.Parse(u)
		if err != nil || u == "" {
			t.Fatalf("url = %q", u)
		}
		q := pu.Query()
		if q.Get("post_logout_redirect_uri") != "http://localhost:3000/login" {
			t.Fatalf("post_logout_redirect_uri = %q", q.Get("post_logout_redirect_uri"))
		}
		if q.Get("client_id") != "test-client-id" {
			t.Fatalf("client_id = %q", q.Get("client_id"))
		}
		if q.Get("state") != "logout-state" {
			t.Fatalf("state = %q", q.Get("state"))
		}
	})

	t.Run("should reject untrusted callbackURL", func(t *testing.T) {
		p := paBaseOAuth()
		p.endSessionEndpoint = "https://idp.example.com/logout"
		inst, headers := paSetupGenericOAuthSignOut(t, p, func(c *Config) {
			c.TrustedOrigins = []string{"http://localhost:3000"}
			c.Advanced = &AdvancedConfig{DisableOriginCheck: Bool(false)}
		})
		headers.Set("Origin", "http://localhost:3000")
		res := inst.do("POST", "/sign-out", map[string]any{"callbackURL": "https://evil.example.com/logout"}, paHeaderMap(headers))
		if res.Status != 403 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if m := res.JSON(t); m["message"] != "Invalid callbackURL" {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should return provider logout url without redirect when disabled", func(t *testing.T) {
		p := paBaseOAuth()
		p.endSessionEndpoint = "https://idp.example.com/logout"
		inst, headers := paSetupGenericOAuthSignOut(t, p, nil)
		res := inst.do("POST", "/sign-out", map[string]any{"disableRedirect": true}, paHeaderMap(headers))
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		u, _ := m["url"].(string)
		if m["success"] != true || m["redirect"] != false || !strings.Contains(u, "https://idp.example.com/logout") {
			t.Fatalf("body = %s", res.Body)
		}
		if loc := res.Header.Get("Location"); loc != "" {
			t.Fatalf("location should be null, got %q", loc)
		}
	})

	t.Run("should use the most recently updated provider when multiple linked accounts exist", func(t *testing.T) {
		first := paBaseOAuth()
		first.endSessionEndpoint = "https://idp.example.com/logout"
		second := paBaseOAuth()
		second.id = "second-provider"
		second.endSessionEndpoint = "https://idp2.example.com/logout"
		inst := paNewEnv(t, func(c *Config) { c.SocialProviders = []oauth2.Provider{first, second} })
		data, headers := inst.signInWithTestUser()
		userID := data["user"].(map[string]any)["id"].(string)
		ia := inst.auth.Context().InternalAdapter
		if _, err := ia.CreateAccount(context.Background(), adapter.Record{
			"userId": userID, "providerId": "oidc-provider", "accountId": "oauth-user", "idToken": "id-token-first",
			"updatedAt": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := ia.CreateAccount(context.Background(), adapter.Record{
			"userId": userID, "providerId": "second-provider", "accountId": "oauth-user-2", "idToken": "id-token-second",
			"updatedAt": time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		}); err != nil {
			t.Fatal(err)
		}
		res := inst.do("POST", "/sign-out", nil, paHeaderMap(headers))
		m := res.JSON(t)
		u, _ := m["url"].(string)
		if m["success"] != true || m["redirect"] != true || !strings.Contains(u, "https://idp2.example.com/logout") {
			t.Fatalf("body = %s", res.Body)
		}
	})
}

// describe("error page security") — error.test.ts
func TestPortAuthErrorPageSecurity(t *testing.T) {
	env := paNewEnv(t, nil)

	t.Run("should sanitize error description to prevent XSS", func(t *testing.T) {
		attack := "<script>alert(1)</script>"
		res := env.do("GET", "/error?error=TEST&error_description="+url.QueryEscape(attack), nil, nil)
		text := string(res.Body)
		if strings.Contains(text, "<script>") {
			t.Fatalf("response contains raw <script>")
		}
		if !strings.Contains(text, "&lt;script&gt;") {
			t.Fatalf("response should contain escaped script tag")
		}
	})

	t.Run("should sanitize code parameter", func(t *testing.T) {
		res := env.do("GET", "/error?error="+url.QueryEscape("<script>"), nil, nil)
		if !strings.Contains(string(res.Body), "UNKNOWN") {
			t.Fatalf("invalid code should default to UNKNOWN")
		}
	})
}
