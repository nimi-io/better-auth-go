package betterauth

// Port of better-auth/src/social.test.ts (upstream v1.7.7): Google multiple client ids,
// hosted domain, includeGrantedScopes, verifyIdToken request ctx (linking) and
// account.scope path-dependent semantics.

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/google"
)

func psocGoogleEnv(t *testing.T, o google.Options, mutate func(c *Config)) *testEnv {
	return psocEnv(t, func(c *Config) {
		c.SocialProviders = []oauth2.Provider{google.New(o)}
		if mutate != nil {
			mutate(c)
		}
	}, true)
}

func psocIDTokenSignIn(c *testClient, provider, token string, extra map[string]any, mutate ...func(*http.Request)) *testResponse {
	body := map[string]any{"provider": provider, "idToken": map[string]any{"token": token}}
	for k, v := range extra {
		body[k] = v
	}
	return c.post("/sign-in/social", body, mutate...)
}

// ---- describe("Google Provider — multiple client IDs") ----

func TestPortSocialGoogleMultipleClientIDs(t *testing.T) {
	m := psocMock(t)
	m.ServeJWKS("GET www.googleapis.com/oauth2/v3/certs")
	const web, ios, android = "123-web.googleusercontent.com", "456-ios.googleusercontent.com", "789-android.googleusercontent.com"
	signIDToken := func(aud string) string {
		return m.IDToken(map[string]any{"email": "mobile-user@example.com", "email_verified": true, "name": "Mobile User",
			"sub": "google-sub-999", "iss": "https://accounts.google.com", "aud": aud})
	}

	for _, tc := range []struct{ name, aud string }{{"web", web}, {"iOS", ios}, {"Android", android}} {
		t.Run("accepts an id token issued for the "+tc.name+" client", func(t *testing.T) {
			env := psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{web, ios, android}, ClientSecret: "test-secret"}}, nil)
			res := psocIDTokenSignIn(env.client(), "google", signIDToken(tc.aud), nil)
			if res.Status != 200 {
				t.Fatalf("%d %s", res.Status, res.Body)
			}
			d := res.JSON(t)
			if d["redirect"] != false || d["user"].(map[string]any)["email"] != "mobile-user@example.com" {
				t.Fatalf("data %v", d)
			}
		})
	}

	t.Run("rejects an id token whose audience is not configured", func(t *testing.T) {
		env := psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{web, ios}, ClientSecret: "test-secret"}}, nil)
		res := psocIDTokenSignIn(env.client(), "google", signIDToken("999-unknown.googleusercontent.com"), nil)
		if res.Status != 401 {
			t.Fatalf("expected 401, got %d %s", res.Status, res.Body)
		}
	})

	t.Run("returns 401 over HTTP when a verified profile resolves an invalid account subject", func(t *testing.T) {
		env := psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: web, ClientSecret: "test-secret"}}, nil)
		p := psocFindProvider(t, env, "google")
		p.S.Subject = func(*oauth2.Tokens, map[string]any) (string, error) { return "", nil }
		res := psocIDTokenSignIn(env.client(), "google", signIDToken(web), nil)
		psocExpectAPIError(t, res, 401, ErrFailedToGetUserInfo.Code, ErrFailedToGetUserInfo.Message)
	})

	t.Run("uses the first configured client id when building the authorization URL", func(t *testing.T) {
		env := psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{web, ios, android}, ClientSecret: "test-secret"}}, nil)
		_, u, _ := psocStart(t, env.client(), map[string]any{"provider": "google", "callbackURL": "/callback"})
		if !strings.Contains(u.String(), url.QueryEscape(web)) || strings.Contains(u.String(), url.QueryEscape(ios)) {
			t.Fatalf("url %s", u)
		}
	})

	t.Run("rejects an empty clientId array at sign-in time", func(t *testing.T) {
		env := psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{}, ClientSecret: "test-secret"}}, nil)
		res := env.client().post("/sign-in/social", map[string]any{"provider": "google", "callbackURL": "/callback"})
		if res.Status != 500 {
			t.Fatalf("expected 500, got %d %s", res.Status, res.Body)
		}
	})

	t.Run("returns 403 EMAIL_NOT_VERIFIED for an unverified id token when the provider requires verification", func(t *testing.T) {
		tok := m.IDToken(map[string]any{"email": "mobile-unverified@example.com", "email_verified": false, "name": "Mobile Unverified",
			"sub": "google-sub-unverified", "iss": "https://accounts.google.com", "aud": web})
		env := psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{web, ios, android},
			ClientSecret: "test-secret", RequireEmailVerification: true}}, func(c *Config) {
			c.EmailAndPassword = &EmailAndPasswordConfig{Enabled: true, RequireEmailVerification: false}
		})
		res := psocIDTokenSignIn(env.client(), "google", tok, nil)
		psocExpectAPIError(t, res, 403, "EMAIL_NOT_VERIFIED", "")
		u, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user",
			Where: []adapter.Where{{Field: "email", Value: "mobile-unverified@example.com"}}})
		if err != nil {
			t.Fatal(err)
		}
		if u == nil || u["emailVerified"] != false {
			t.Fatalf("user should be created unverified: %v", u)
		}
	})
}

// ---- describe("Google Provider — hosted domain on id_token sign-in") ----

func TestPortSocialGoogleHostedDomain(t *testing.T) {
	m := psocMock(t)
	m.ServeJWKS("GET www.googleapis.com/oauth2/v3/certs")
	const clientID = "hd-web.googleusercontent.com"
	sign := func(claims map[string]any) string {
		base := map[string]any{"email": "hd-user@example.com", "email_verified": true, "name": "HD User", "sub": "google-hd-sub",
			"iss": "https://accounts.google.com", "aud": clientID}
		for k, v := range claims {
			base[k] = v
		}
		return m.IDToken(base)
	}
	inst := func(t *testing.T) *testEnv {
		return psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: "test-secret"}, HD: "example.com"}, nil)
	}

	t.Run("accepts an id token whose hd claim matches the configured hosted domain", func(t *testing.T) {
		res := psocIDTokenSignIn(inst(t).client(), "google", sign(map[string]any{"hd": "example.com"}), nil)
		if res.Status != 200 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
		d := res.JSON(t)
		if d["redirect"] != false || d["user"].(map[string]any)["email"] != "hd-user@example.com" {
			t.Fatalf("data %v", d)
		}
	})
	t.Run("rejects an id token whose hd claim is a different hosted domain", func(t *testing.T) {
		res := psocIDTokenSignIn(inst(t).client(), "google", sign(map[string]any{"hd": "other.com"}), nil)
		if res.Status != 401 {
			t.Fatalf("expected 401, got %d %s", res.Status, res.Body)
		}
	})
	t.Run("rejects an id token with no hd claim when a hosted domain is configured", func(t *testing.T) {
		res := psocIDTokenSignIn(inst(t).client(), "google", sign(nil), nil)
		if res.Status != 401 {
			t.Fatalf("expected 401, got %d %s", res.Status, res.Body)
		}
	})
}

// ---- describe("verifyIdToken request ctx — account linking") ----

func TestPortSocialVerifyIDTokenCtxAccountLinking(t *testing.T) {
	m := psocMock(t)
	t.Run("should pass request ctx to verifyIdToken for id-token account linking", func(t *testing.T) {
		tok := m.IDToken(map[string]any{
			"email": "test@test.com", "email_verified": true, "name": "Ctx Link", "picture": "https://example.com/picture.png",
			"exp": float64(1234567890), "sub": "ctx-link-google-sub", "iat": float64(1234567890), "aud": "test", "azp": "test",
			"nbf": float64(1234567890), "iss": "test", "locale": "en", "jti": "ctx-link", "given_name": "Ctx", "family_name": "Link",
		})
		var seenPlatform *string
		env := psocEnv(t, func(c *Config) {
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{
				ClientID: "test", ClientSecret: "test",
				VerifyIDToken: func(ctx context.Context, _, _ string) (bool, error) {
					var v string
					if ec := EndpointContextFrom(ctx); ec != nil && ec.Headers != nil {
						v = ec.Headers.Get("x-platform")
					}
					seenPlatform = &v
					return v == "ios", nil
				},
			}})}
		}, false)
		c := env.client()
		if res := c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"}); res.Status != 200 {
			t.Fatalf("sign in test user: %d %s", res.Status, res.Body)
		}
		platform := func(p string) func(*http.Request) { return func(r *http.Request) { r.Header.Set("x-platform", p) } }
		body := map[string]any{"provider": "google", "idToken": map[string]any{"token": tok}}

		rejected := c.post("/link-social", body, platform("android"))
		if seenPlatform == nil || *seenPlatform != "android" {
			t.Fatalf("seenPlatform %v", seenPlatform)
		}
		if rejected.Status != 401 {
			t.Fatalf("expected 401, got %d %s", rejected.Status, rejected.Body)
		}
		accepted := c.post("/link-social", body, platform("ios"))
		if *seenPlatform != "ios" {
			t.Fatalf("seenPlatform %v", *seenPlatform)
		}
		if accepted.Status != 200 {
			t.Fatalf("error should be null: %d %s", accepted.Status, accepted.Body)
		}
		found := false
		for _, a := range c.get("/list-accounts", platform("ios")).JSON2(t) {
			if a["providerId"] == "google" {
				found = true
			}
		}
		if !found {
			t.Fatal("google account should be linked")
		}
	})
}

// ---- describe("account.scope path-dependent semantics") ----

func TestPortSocialAccountScopeSemantics(t *testing.T) {
	m := psocMock(t)
	env := psocEnv(t, func(c *Config) {
		c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}})}
	}, true)
	ctx := env.auth.Context()
	buildIDToken := func(sub string) map[string]any {
		return map[string]any{
			"email": sub + "@email.com", "email_verified": true, "name": "Scope User", "picture": "https://test.com/picture.png",
			"exp": float64(1234567890), "sub": sub, "iat": float64(1234567890), "aud": "test", "azp": "test",
			"nbf": float64(1234567890), "iss": "test", "locale": "en", "jti": "test", "given_name": "Scope", "family_name": "User",
		}
	}
	mockGoogleTokenResponse := func(claims map[string]any, scope *string) {
		body := map[string]any{"access_token": "test-access-token", "refresh_token": "test-refresh-token",
			"id_token": m.IDToken(claims), "token_type": "Bearer", "expires_in": 3600}
		if scope != nil {
			body["scope"] = *scope
		}
		m.JSON("POST oauth2.googleapis.com/token", 200, body)
	}
	s := func(v string) *string { return &v }
	completeSignIn := func(t *testing.T, c *testClient) {
		_, _, state := psocStart(t, c, map[string]any{"provider": "google", "callbackURL": "/callback"})
		psocCallback(c, "google", state, "test")
	}
	const drive = "https://www.googleapis.com/auth/drive.readonly"

	t.Run("preserves stored scope on sign-in re-authentication when token claim is narrower", func(t *testing.T) {
		c := env.client()
		claims := buildIDToken("scope-reauth-sub")
		mockGoogleTokenResponse(claims, s("openid email profile "+drive))
		completeSignIn(t, c)
		uid := psocSessionUser(t, c)["id"].(string)
		if sc := psocStr(psocAccounts(t, env, uid)[0].Scope); !strings.Contains(sc, drive) {
			t.Fatalf("initial scope %q", sc)
		}
		mockGoogleTokenResponse(claims, s("openid email"))
		completeSignIn(t, c)
		if sc := psocStr(psocAccounts(t, env, uid)[0].Scope); !strings.Contains(sc, drive) {
			t.Fatalf("after scope %q", sc)
		}
	})

	t.Run("unions stored scope with newly granted scopes on linkSocial incremental authorization", func(t *testing.T) {
		c := env.client()
		claims := buildIDToken("scope-link-sub")
		mockGoogleTokenResponse(claims, s("openid email profile"))
		completeSignIn(t, c)
		uid := psocSessionUser(t, c)["id"].(string)
		initial := strings.Split(psocStr(psocAccounts(t, env, uid)[0].Scope), ",")
		sort.Strings(initial)
		if strings.Join(initial, " ") != "email openid profile" {
			t.Fatalf("initial scope %v", initial)
		}
		mockGoogleTokenResponse(claims, s(drive))
		linkRes := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback", "scopes": []string{drive}})
		if linkRes.Status != 200 {
			t.Fatalf("linkSocial did not return an authorization URL: %d %s", linkRes.Status, linkRes.Body)
		}
		raw, _ := linkRes.JSON(t)["url"].(string)
		if raw == "" {
			t.Fatalf("linkSocial did not return an authorization URL: %s", linkRes.Body)
		}
		lu, _ := url.Parse(raw)
		psocCallback(c, "google", lu.Query().Get("state"), "test")
		merged := strings.Split(psocStr(psocAccounts(t, env, uid)[0].Scope), ",")
		for _, want := range []string{"openid", "email", "profile", drive} {
			found := false
			for _, g := range merged {
				if g == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("merged scope %v missing %s", merged, want)
			}
		}
	})

	t.Run("preserves stored scope on /refresh-token when the refresh response is narrower", func(t *testing.T) {
		c := env.client()
		mockGoogleTokenResponse(buildIDToken("scope-refresh-sub"), s("openid email profile "+drive))
		completeSignIn(t, c)
		uid := psocSessionUser(t, c)["id"].(string)
		accs := psocAccounts(t, env, uid)
		if !strings.Contains(psocStr(accs[0].Scope), drive) {
			t.Fatalf("scope %q", psocStr(accs[0].Scope))
		}
		m.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{"access_token": "refreshed-access-token",
			"refresh_token": "refreshed-refresh-token", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email"})
		res := c.post("/refresh-token", map[string]any{"accountId": accs[0].ID})
		if res.Status != 200 {
			t.Fatalf("refresh %d %s", res.Status, res.Body)
		}
		if sc, _ := res.JSON(t)["scope"].(string); !strings.Contains(sc, drive) {
			t.Fatalf("refresh scope %q", sc)
		}
		if sc := psocStr(psocAccounts(t, env, uid)[0].Scope); !strings.Contains(sc, drive) {
			t.Fatalf("stored scope %q", sc)
		}
	})

	t.Run("does not write stale account cookie scope on /refresh-token", func(t *testing.T) {
		c := env.client()
		mockGoogleTokenResponse(buildIDToken("scope-refresh-cookie-sub"), s("openid email"))
		completeSignIn(t, c)
		uid := psocSessionUser(t, c)["id"].(string)
		accs := psocAccounts(t, env, uid)
		accumulated := "openid,email,profile," + drive
		if _, err := ctx.InternalAdapter.UpdateAccount(context.Background(), accs[0].ID, adapter.Record{"scope": accumulated}); err != nil {
			t.Fatal(err)
		}
		m.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{"access_token": "cookie-refreshed-access-token",
			"refresh_token": "cookie-refreshed-refresh-token", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email"})
		res := c.post("/refresh-token", map[string]any{"accountId": accs[0].ID})
		if res.Status != 200 {
			t.Fatalf("refresh %d %s", res.Status, res.Body)
		}
		if sc := res.JSON(t)["scope"]; sc != accumulated {
			t.Fatalf("refresh scope %v", sc)
		}
		if sc := psocStr(psocAccounts(t, env, uid)[0].Scope); sc != accumulated {
			t.Fatalf("stored scope %q", sc)
		}
	})
}

// ---- describe("Google Provider - includeGrantedScopes") ----

func TestPortSocialGoogleIncludeGrantedScopes(t *testing.T) {
	psocMock(t)
	authURL := func(t *testing.T, include *bool, body map[string]any) *url.URL {
		env := psocGoogleEnv(t, google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}, IncludeGrantedScopes: include}, nil)
		b := map[string]any{"provider": "google", "callbackURL": "/callback"}
		for k, v := range body {
			b[k] = v
		}
		_, u, _ := psocStart(t, env.client(), b)
		return u
	}
	t.Run("includes `include_granted_scopes=true` in the authorization URL by default", func(t *testing.T) {
		if v := authURL(t, nil, nil).Query().Get("include_granted_scopes"); v != "true" {
			t.Fatalf("include_granted_scopes=%q", v)
		}
	})
	t.Run("includes `include_granted_scopes=true` when explicitly enabled", func(t *testing.T) {
		if v := authURL(t, Bool(true), nil).Query().Get("include_granted_scopes"); v != "true" {
			t.Fatalf("include_granted_scopes=%q", v)
		}
	})
	t.Run("lets additionalParams disable `include_granted_scopes` for a single flow", func(t *testing.T) {
		u := authURL(t, nil, map[string]any{"additionalParams": map[string]any{"include_granted_scopes": "false"}})
		if v := u.Query().Get("include_granted_scopes"); v != "false" {
			t.Fatalf("include_granted_scopes=%q", v)
		}
	})
	t.Run("omits `include_granted_scopes` from the authorization URL when disabled", func(t *testing.T) {
		u := authURL(t, Bool(false), map[string]any{"scopes": []string{"https://www.googleapis.com/auth/drive.file"}})
		if u.Query().Has("include_granted_scopes") {
			t.Fatalf("url %s", u)
		}
		if sc := u.Query().Get("scope"); !strings.Contains(sc, "openid") || !strings.Contains(sc, "https://www.googleapis.com/auth/drive.file") {
			t.Fatalf("scope %q", sc)
		}
	})
	t.Run("lets additionalParams re-enable `include_granted_scopes` for a single flow", func(t *testing.T) {
		u := authURL(t, Bool(false), map[string]any{"additionalParams": map[string]any{"include_granted_scopes": "true"}})
		if v := u.Query().Get("include_granted_scopes"); v != "true" {
			t.Fatalf("include_granted_scopes=%q", v)
		}
	})
}
