package betterauth

// Port of better-auth/src/social.test.ts (upstream v1.7.7): "Social Providers",
// "Redirect URI", "Disable implicit signup", "Disable signup", "signin",
// "updateAccountOnSignIn".

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/apple"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// ---- helpers ----

// psocDefaultProviders mirrors getTestInstance's default socialProviders.
func psocDefaultProviders() []oauth2.Provider {
	return []oauth2.Provider{
		github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
		google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
	}
}

// psocEnv mirrors getTestInstance: default github+google providers, and the test user
// (test@test.com / test123456) unless disableTestUser.
func psocEnv(t *testing.T, mutate func(c *Config), disableTestUser bool) *testEnv {
	t.Helper()
	env := newTestEnv(t, func(c *Config) {
		c.SocialProviders = psocDefaultProviders()
		if mutate != nil {
			mutate(c)
		}
	})
	if !disableTestUser {
		env.client().signUp("test@test.com", "test123456", "test user")
	}
	return env
}

func psocGoogleProvider(o google.Options) *oauth2.GenericProvider { return google.New(o) }

func psocFindProvider(t *testing.T, env *testEnv, id string) *oauth2.GenericProvider {
	t.Helper()
	p := env.auth.Context().FindProvider(id)
	if p == nil {
		t.Fatalf("provider %s not found", id)
	}
	g, ok := p.(*oauth2.GenericProvider)
	if !ok {
		t.Fatalf("provider %s is %T", id, p)
	}
	return g
}

// psocProfile is the default mocked Google profile (shouldUseUpdatedProfile=false).
func psocProfile() map[string]any {
	return map[string]any{
		"email": "user@email.com", "email_verified": true, "name": "First Last",
		"picture": "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw", "exp": float64(1234567890),
		"sub": "1234567890", "iat": float64(1234567890), "aud": "test", "azp": "test",
		"nbf": float64(1234567890), "iss": "test", "locale": "en", "jti": "test",
		"given_name": "First", "family_name": "Last",
	}
}

// psocUpdatedProfile is the mocked Google profile with shouldUseUpdatedProfile=true.
func psocUpdatedProfile() map[string]any {
	p := psocProfile()
	p["name"] = "Updated User"
	p["picture"] = "https://test.com/picture.png"
	p["given_name"] = "Updated"
	p["family_name"] = "User"
	return p
}

// psocMock installs the outbound HTTP fake with the global msw handlers of social.test.ts:
// Google and Apple token endpoints answering an id_token for the default profile.
func psocMock(t *testing.T) *oauth2test.Server {
	m := oauth2test.New(t)
	psocTokenEndpoint(m, "POST oauth2.googleapis.com/token", psocProfile(), nil)
	psocTokenEndpoint(m, "POST appleid.apple.com/auth/token", psocProfile(), nil)
	return m
}

// psocTokenEndpoint (re)registers a token endpoint answering
// {access_token:"test", refresh_token:"test", id_token, ...extra}; extra keys with a nil
// value are removed.
func psocTokenEndpoint(m *oauth2test.Server, pattern string, claims map[string]any, extra map[string]any) {
	body := map[string]any{"access_token": "test", "refresh_token": "test", "id_token": m.IDToken(claims)}
	for k, v := range extra {
		if v == nil {
			delete(body, k)
		} else {
			body[k] = v
		}
	}
	m.JSON(pattern, 200, body)
}

// psocStart calls /sign-in/social and returns the response, the authorization URL and state.
func psocStart(t *testing.T, c *testClient, body map[string]any) (*testResponse, *url.URL, string) {
	t.Helper()
	res := c.post("/sign-in/social", body)
	if res.Status != 200 {
		t.Fatalf("sign-in/social: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if m["redirect"] != true {
		t.Fatalf("redirect should be true: %v", m)
	}
	raw, _ := m["url"].(string)
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		t.Fatalf("url %q: %v", raw, err)
	}
	return res, u, u.Query().Get("state")
}

func psocCallback(c *testClient, provider, state, code string) *testResponse {
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	if code != "" {
		q.Set("code", code)
	}
	return c.get("/callback/" + provider + "?" + q.Encode())
}

// psocSignInFlow runs sign-in/social + callback and returns the callback response.
func psocSignInFlow(t *testing.T, c *testClient, provider string, body map[string]any) *testResponse {
	t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	body["provider"] = provider
	_, _, state := psocStart(t, c, body)
	return psocCallback(c, provider, state, "test")
}

func psocExpect302(t *testing.T, res *testResponse) string {
	t.Helper()
	if res.Status != 302 {
		t.Fatalf("expected 302, got %d: %s", res.Status, res.Body)
	}
	loc := res.Header.Get("Location")
	if loc == "" {
		t.Fatal("location should be defined")
	}
	return loc
}

func psocExpectSessionCookie(t *testing.T, res *testResponse) {
	t.Helper()
	if v, ok := res.cookie("better-auth.session_token"); !ok || v == "" {
		t.Fatalf("better-auth.session_token cookie should be set: %v", res.Header.Values("Set-Cookie"))
	}
}

func psocSessionUser(t *testing.T, c *testClient) map[string]any {
	t.Helper()
	s := c.session()
	if s == nil {
		t.Fatal("session should be defined")
	}
	return s["user"].(map[string]any)
}

func psocAccounts(t *testing.T, env *testEnv, userID string) []*Account {
	t.Helper()
	accs, err := env.auth.Context().InternalAdapter.FindAccounts(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return accs
}

func psocStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func psocStrField(name string) db.Field { return db.Field{Name: name, Type: db.TypeString} }

// ---- describe("Social Providers") ----

func TestPortSocialProviders(t *testing.T) {
	m := psocMock(t)
	env := psocEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			psocStrField("firstName"), psocStrField("lastName"), {Name: "isOAuth", Type: db.TypeBoolean},
		}}}
		c.SocialProviders = []oauth2.Provider{
			google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test",
				MapProfileToUser: func(profile map[string]any) (map[string]any, error) {
					return map[string]any{"firstName": profile["given_name"], "lastName": profile["family_name"], "isOAuth": true}, nil
				}}}),
			// apple: async () => ({ clientId, clientSecret }) — Go has no async config form.
			apple.New(apple.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
		}
		c.Advanced = &AdvancedConfig{DisableOriginCheck: Bool(false)}
	}, true)

	t.Run("should be able to add social providers", func(t *testing.T) {
		_, u, _ := psocStart(t, env.client(), map[string]any{"provider": "google", "callbackURL": "/callback", "newUserCallbackURL": "/welcome"})
		if !strings.Contains(u.String(), "google.com") {
			t.Fatalf("url %s", u)
		}
	})

	t.Run("should forward additionalParams to the authorization URL", func(t *testing.T) {
		_, u, _ := psocStart(t, env.client(), map[string]any{"provider": "google", "callbackURL": "/callback",
			"additionalParams": map[string]any{"access_type": "offline", "hd": "example.com"}})
		if u.Query().Get("access_type") != "offline" || u.Query().Get("hd") != "example.com" {
			t.Fatalf("url %s", u)
		}
	})

	t.Run("should reject additionalParams that collide with reserved OAuth params", func(t *testing.T) {
		res := env.client().post("/sign-in/social", map[string]any{"provider": "google", "callbackURL": "/callback",
			"additionalParams": map[string]any{"redirect_uri": "https://attacker.example/callback"}})
		if res.Status != 400 {
			t.Fatalf("expected 400, got %d %s", res.Status, res.Body)
		}
	})

	t.Run("should be able to sign in with social providers", func(t *testing.T) {
		res := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/callback", "newUserCallbackURL": "/welcome"})
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/welcome") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
	})

	t.Run("redirects a built-in callback with no state to error=state_not_found", func(t *testing.T) {
		res := psocCallback(env.client(), "google", "", "test")
		loc := psocExpect302(t, res)
		if !strings.Contains(loc, "error=state_not_found") || strings.Contains(loc, "state=state_not_found") {
			t.Fatalf("location %s", loc)
		}
	})

	t.Run("redirects to the per-flow errorCallbackURL when state validation fails", func(t *testing.T) {
		_, _, state := psocStart(t, env.client(), map[string]any{"provider": "google", "callbackURL": "/callback",
			"errorCallbackURL": "/oauth-error?source=oauth#retry"})
		// Omit the state cookie (fresh client) so the signed-cookie check fails.
		res := psocCallback(env.client(), "google", state, "test")
		loc := psocExpect302(t, res)
		if !strings.Contains(loc, "/oauth-error?source=oauth&error=state_mismatch#retry") || strings.Contains(loc, "/api/auth/error") {
			t.Fatalf("location %s", loc)
		}
	})

	t.Run("should be able to sign in with async social provider", func(t *testing.T) {
		res := psocSignInFlow(t, env.client(), "apple", map[string]any{"callbackURL": "/callback", "newUserCallbackURL": "/welcome"})
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/callback") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
	})

	t.Run("Should use callback URL if the user is already registered", func(t *testing.T) {
		c := env.client()
		_, u, state := psocStart(t, c, map[string]any{"provider": "google", "callbackURL": "/callback", "newUserCallbackURL": "/welcome"})
		if !strings.Contains(u.String(), "google.com") {
			t.Fatalf("url %s", u)
		}
		res := psocCallback(c, "google", state, "test")
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/callback") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
	})

	t.Run("should be able to map profile to user", func(t *testing.T) {
		c := env.client()
		psocSignInFlow(t, c, "google", map[string]any{"callbackURL": "/callback"})
		u := psocSessionUser(t, c)
		if u["isOAuth"] != true || u["firstName"] != "First" || u["lastName"] != "Last" {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("should be protected from callback URL attacks", func(t *testing.T) {
		res := env.client().post("/sign-in/social", map[string]any{"provider": "google", "callbackURL": "https://evil.com/callback"})
		if res.Status != 403 {
			t.Fatalf("expected 403, got %d %s", res.Status, res.Body)
		}
		if msg := res.JSON(t)["message"]; msg != "Invalid callbackURL" {
			t.Fatalf("message %v", msg)
		}
	})

	t.Run("should refresh the access token", func(t *testing.T) {
		c := env.client()
		_, u, state := psocStart(t, c, map[string]any{"provider": "google", "callbackURL": "/callback"})
		if !strings.Contains(u.String(), "google.com") {
			t.Fatalf("url %s", u)
		}
		res := psocCallback(c, "google", state, "test")
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/callback") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
		accs := c.get("/list-accounts").JSON2(t)
		var accountID any
		if len(accs) > 0 {
			accountID = accs[0]["id"]
		}
		// result intentionally unchecked upstream
		c.post("/refresh-token", map[string]any{"accountId": accountID})

		// simulateOAuthFlowRefresh: refreshAccessToken against the mock issuer's token endpoint.
		m.JSON("POST localhost:8005/token", 200, map[string]any{
			"access_token": "new-access-token", "refresh_token": "new-refresh-token",
			"id_token": m.IDToken(psocProfile()), "token_type": "Bearer", "expires_in": 3600,
		})
		tokens, err := oauth2.RefreshAccessToken(context.Background(), oauth2.RefreshRequest{
			RefreshToken: "mock-refresh-token", TokenEndpoint: "http://localhost:8005/token",
			Client: oauth2.ClientCredentials{ClientID: "test-client-id", ClientKey: "test-client-key", ClientSecret: "test-client-secret"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if tokens.AccessToken != "new-access-token" || tokens.RefreshToken != "new-refresh-token" {
			t.Fatalf("tokens %+v", tokens)
		}
	})
}

// ---- describe("Redirect URI") ----

func TestPortSocialRedirectURI(t *testing.T) {
	psocMock(t)
	t.Run("should infer redirect uri", func(t *testing.T) {
		mux := http.NewServeMux()
		srv := httptest.NewServer(mux)
		defer srv.Close()
		a, err := New(Config{
			BaseURL: srv.URL, BasePath: "/custom/path", Secret: testSecret, Database: memory.New(memory.NewDB()),
			EmailAndPassword: &EmailAndPasswordConfig{Enabled: true}, Logger: NopLogger{},
			SocialProviders: []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}})},
		})
		if err != nil {
			t.Fatal(err)
		}
		mux.Handle("/custom/path/", a.Handler())
		req, _ := http.NewRequest("POST", srv.URL+"/custom/path/sign-in/social", strings.NewReader(`{"provider":"google","callbackURL":"/callback"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", srv.URL)
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		want := url.QueryEscape(srv.URL + "/custom/path/callback/google")
		if !strings.Contains(body.URL, want) {
			t.Fatalf("url %s should contain %s", body.URL, want)
		}
	})

	t.Run("should respect custom redirect uri", func(t *testing.T) {
		env := psocEnv(t, func(c *Config) {
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{
				ClientID: "test", ClientSecret: "test", RedirectURI: "https://test.com/callback"}})}
		}, false)
		_, u, _ := psocStart(t, env.client(), map[string]any{"provider": "google", "callbackURL": "/callback"})
		if !strings.Contains(u.String(), "redirect_uri=https%3A%2F%2Ftest.com%2Fcallback") {
			t.Fatalf("url %s", u)
		}
	})
}

// ---- describe("Disable implicit signup") ----

func TestPortSocialDisableImplicitSignUp(t *testing.T) {
	psocMock(t)
	mk := func(t *testing.T) *testEnv {
		return psocEnv(t, func(c *Config) {
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{
				ClientID: "test", ClientSecret: "test", DisableImplicitSignUp: true}})}
		}, false)
	}
	t.Run("Should not create user when implicit sign up is disabled", func(t *testing.T) {
		env := mk(t)
		res := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/callback", "newUserCallbackURL": "/welcome"})
		loc := psocExpect302(t, res)
		if !strings.Contains(loc, env.server.URL+"/api/auth/error?error=signup_disabled") {
			t.Fatalf("location %s", loc)
		}
	})
	t.Run("Should create user when implicit sign up is disabled but it is requested", func(t *testing.T) {
		env := mk(t)
		res := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/callback", "newUserCallbackURL": "/welcome", "requestSignUp": true})
		if loc := psocExpect302(t, res); !strings.Contains(loc, "/welcome") {
			t.Fatalf("location %s", loc)
		}
		psocExpectSessionCookie(t, res)
	})
}

// ---- describe("Disable signup") ----

func psocGoogleIDTokenOptions(email string) oauth2.ProviderOptions {
	profile := map[string]any{
		"aud": "test", "azp": "test", "email": email, "email_verified": true, "exp": float64(2_000_000_000),
		"family_name": "User", "given_name": "Google", "iat": float64(1_900_000_000),
		"iss": "https://accounts.google.com", "name": "Google User", "picture": "https://example.com/avatar.png",
		"sub": "google-id-token-user",
	}
	return oauth2.ProviderOptions{
		ClientID: "test", ClientSecret: "test",
		VerifyIDToken: func(context.Context, string, string) (bool, error) { return true, nil },
		GetUserInfo: func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Email: email, Name: "Google User", EmailVerified: true}, Data: profile}, nil
		},
	}
}

func psocExpectAPIError(t *testing.T, res *testResponse, status int, code, message string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("expected %d, got %d: %s", status, res.Status, res.Body)
	}
	m := res.JSON(t)
	if code != "" && m["code"] != code {
		t.Fatalf("code: want %s, got %v (%s)", code, m["code"], res.Body)
	}
	if message != "" && m["message"] != message {
		t.Fatalf("message: want %q, got %v (%s)", message, m["message"], res.Body)
	}
}

func TestPortSocialDisableSignUp(t *testing.T) {
	psocMock(t)
	for _, tc := range []struct {
		scenario      string
		requestSignUp any
	}{{"without requestSignUp", nil}, {"with requestSignUp", true}} {
		t.Run("ID-token sign-in/rejects ID-token sign-in for a new user "+tc.scenario, func(t *testing.T) {
			email := "new-id-token-user@example.com"
			env := psocEnv(t, func(c *Config) {
				o := psocGoogleIDTokenOptions(email)
				o.DisableSignUp = true
				c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: o})}
			}, true)
			body := map[string]any{"provider": "google", "idToken": map[string]any{"token": "a.b.c"}}
			if tc.requestSignUp != nil {
				body["requestSignUp"] = tc.requestSignUp
			}
			res := env.client().post("/sign-in/social", body)
			u, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: email}}})
			if err != nil {
				t.Fatal(err)
			}
			if u != nil {
				t.Fatalf("user should be null: %v", u)
			}
			psocExpectAPIError(t, res, 401, "OAUTH_LINK_ERROR", "signup disabled")
		})
	}

	t.Run("ID-token sign-in/allows an existing ID-token user to sign in when provider sign-up is disabled", func(t *testing.T) {
		email := "existing-id-token-user@example.com"
		env := psocEnv(t, func(c *Config) {
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: psocGoogleIDTokenOptions(email)})}
		}, true)
		signIn := func() *testResponse {
			return env.client().post("/sign-in/social", map[string]any{"provider": "google", "idToken": map[string]any{"token": "a.b.c"}})
		}
		if res := signIn(); res.Status != 200 {
			t.Fatalf("first: %d %s", res.Status, res.Body)
		}
		p := psocFindProvider(t, env, "google")
		// provider.options.disableSignUp = true
		p.S.Options.DisableSignUp = true
		p.S.Settings.DisableSignUp = true
		res := signIn()
		if res.Status != 200 {
			t.Fatalf("second: %d %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		if m["redirect"] != false || m["user"].(map[string]any)["email"] != email {
			t.Fatalf("data %v", m)
		}
	})

	t.Run("ID-token sign-in/keeps the top-level provider sign-up restriction for ID-token sign-in", func(t *testing.T) {
		env := psocEnv(t, func(c *Config) {
			o := psocGoogleIDTokenOptions("top-level-id-token-user@example.com")
			o.DisableSignUp = false
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: o})}
		}, true)
		p := psocFindProvider(t, env, "google")
		// provider.disableSignUp = true (top-level)
		p.S.Settings.DisableSignUp = true
		res := env.client().post("/sign-in/social", map[string]any{"provider": "google", "idToken": map[string]any{"token": "a.b.c"}})
		psocExpectAPIError(t, res, 401, "OAUTH_LINK_ERROR", "signup disabled")
	})

	t.Run("Should not create user when sign up is disabled", func(t *testing.T) {
		env := psocEnv(t, func(c *Config) {
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{
				ClientID: "test", ClientSecret: "test", DisableSignUp: true}})}
		}, false)
		res := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/callback", "newUserCallbackURL": "/welcome"})
		loc := psocExpect302(t, res)
		if !strings.Contains(loc, env.server.URL+"/api/auth/error?error=signup_disabled") {
			t.Fatalf("location %s", loc)
		}
	})
}

// ---- describe("signin") ----

func TestPortSocialSignin(t *testing.T) {
	m := psocMock(t)
	shared := memory.NewDB()
	useShared := func(c *Config) { c.Database = memory.New(shared) }

	t.Run("should allow user info override during sign in", func(t *testing.T) {
		env := psocEnv(t, func(c *Config) {
			useShared(c)
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}})}
		}, false)
		c := env.client()
		psocSignInFlow(t, c, "google", map[string]any{"callbackURL": "/callback"})
		if u := psocSessionUser(t, c); u["name"] != "First Last" {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("should allow user info override during sign in (overrideUserInfoOnSignIn)", func(t *testing.T) {
		psocTokenEndpoint(m, "POST oauth2.googleapis.com/token", psocUpdatedProfile(), nil)
		defer psocTokenEndpoint(m, "POST oauth2.googleapis.com/token", psocProfile(), nil)
		env := psocEnv(t, func(c *Config) {
			useShared(c)
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{
				ClientID: "test", ClientSecret: "test", OverrideUserInfoOnSignIn: true}})}
		}, true)
		c := env.client()
		psocSignInFlow(t, c, "google", map[string]any{"callbackURL": "/callback"})
		if u := psocSessionUser(t, c); u["name"] != "Updated User" {
			t.Fatalf("user %v", u)
		}
	})

	captureEnv := func(t *testing.T, out *map[string]any) *testEnv {
		return psocEnv(t, func(c *Config) {
			useShared(c)
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{
				ClientID: "test", ClientSecret: "test", OverrideUserInfoOnSignIn: true}})}
			c.Hooks = &HooksConfig{After: func(ctx *EndpointContext) (any, error) {
				if ctx.Path == "/callback/:id" {
					if sd := GetOAuthState(ctx.Context()); sd != nil {
						*out = sd.toObject().Map()
					}
				}
				return nil, nil
			}}
		}, true)
	}

	t.Run("should allow additional data in oauth state", func(t *testing.T) {
		var additional map[string]any
		env := captureEnv(t, &additional)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "google", "callbackURL": "/callback",
			"additionalData": map[string]any{"invitedBy": "user-123"}})
		if state == "" {
			t.Fatal("state should be truthy")
		}
		psocCallback(c, "google", state, "test")
		if additional == nil {
			t.Fatal("additionalData not captured")
		}
		if _, ok := additional["codeVerifier"].(string); !ok {
			t.Fatalf("codeVerifier %v", additional["codeVerifier"])
		}
		if _, ok := additional["expiresAt"].(float64); !ok {
			t.Fatalf("expiresAt %v", additional["expiresAt"])
		}
		want := map[string]any{"callbackURL": "/callback", "invitedBy": "user-123",
			"errorURL": env.server.URL + "/api/auth/error", "oauthState": state}
		for k, v := range want {
			if additional[k] != v {
				t.Fatalf("%s: want %v, got %v (%v)", k, v, additional[k], additional)
			}
		}
		if len(additional) != len(want)+2 {
			t.Fatalf("unexpected keys in state: %v", additional)
		}
	})

	t.Run("should not allow overriding oauth code verifier, expiresAt, callbackURL, errorURL, newUserURL, link, requestSignUp", func(t *testing.T) {
		var additional map[string]any
		env := captureEnv(t, &additional)
		c := env.client()
		expiresAt := float64(1_700_000_000_000)
		_, _, state := psocStart(t, c, map[string]any{"provider": "google", "callbackURL": "/callback",
			"additionalData": map[string]any{
				"codeVerifier": "test-code-verifier", "callbackURL": "test-callback-url", "errorURL": "test-error-url",
				"newUserURL": "test-new-user-url", "link": map[string]any{"email": "test-email", "userId": "test-user-id"},
				"requestSignUp": true, "expiresAt": expiresAt, "serverContext": map[string]any{"spoofed": true},
			}})
		cbRes := psocCallback(c, "google", state, "test")
		if additional == nil {
			t.Fatalf("additionalData not captured (callback %d %s)", cbRes.Status, cbRes.Header.Get("Location"))
		}
		if additional["codeVerifier"] == "test-code-verifier" {
			t.Error("codeVerifier was overridden")
		}
		if additional["callbackURL"] == "test-callback-url" {
			t.Error("callbackURL was overridden")
		}
		if additional["errorURL"] == "test-error-url" {
			t.Error("errorURL was overridden")
		}
		if additional["newUserURL"] == "test-new-user-url" {
			t.Error("newUserURL was overridden")
		}
		if l, ok := additional["link"].(map[string]any); ok && l["email"] == "test-email" && l["userId"] == "test-user-id" {
			t.Error("link was overridden")
		}
		if additional["requestSignUp"] == true {
			t.Error("requestSignUp was overridden")
		}
		if additional["expiresAt"] == expiresAt {
			t.Error("expiresAt was overridden")
		}
		if v, ok := additional["serverContext"]; ok {
			t.Errorf("serverContext must be undefined, got %v", v)
		}
	})
}

// ---- describe("updateAccountOnSignIn") ----

func TestPortSocialUpdateAccountOnSignIn(t *testing.T) {
	psocMock(t)
	env := psocEnv(t, func(c *Config) {
		c.Account = &AccountConfig{UpdateAccountOnSignIn: Bool(false)}
	}, false)
	t.Run("should not update account on sign in", func(t *testing.T) {
		c := env.client()
		psocSignInFlow(t, c, "google", map[string]any{"callbackURL": "/callback"})
		uid := psocSessionUser(t, c)["id"].(string)
		accs := psocAccounts(t, env, uid)
		if _, err := env.auth.Context().InternalAdapter.UpdateAccount(context.Background(), accs[0].ID, adapter.Record{"accessToken": "new-access-token"}); err != nil {
			t.Fatal(err)
		}
		psocSignInFlow(t, c, "google", map[string]any{"callbackURL": "/callback"})
		uid2 := psocSessionUser(t, c)["id"].(string)
		accs2 := psocAccounts(t, env, uid2)
		if got := psocStr(accs2[0].AccessToken); got != "new-access-token" {
			t.Fatalf("accessToken %q", got)
		}
	})
}
