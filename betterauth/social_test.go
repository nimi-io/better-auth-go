package betterauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

func githubMock(t *testing.T, email string, verified bool) *oauth2test.Server {
	m := oauth2test.New(t)
	m.JSON("POST github.com/login/oauth/access_token", 200, map[string]any{"access_token": "gho_token", "token_type": "bearer", "scope": "read:user,user:email"})
	m.JSON("GET api.github.com/user", 200, map[string]any{"id": 4242, "login": "octo", "name": "Octo Cat", "email": nil, "avatar_url": "https://avatars/octo.png"})
	m.JSON("GET api.github.com/user/emails", 200, []map[string]any{{"email": email, "primary": true, "verified": verified}})
	return m
}

func socialEnv(t *testing.T, mutate func(c *Config)) *testEnv {
	return newTestEnv(t, func(c *Config) {
		c.SocialProviders = []oauth2.Provider{
			github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "gh-client", ClientSecret: "gh-secret"}}),
			google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "google-client", ClientSecret: "google-secret"}}),
		}
		if mutate != nil {
			mutate(c)
		}
	})
}

func startSocial(t *testing.T, c *testClient, body map[string]any) (string, *url.URL) {
	t.Helper()
	res := c.post("/sign-in/social", body)
	if res.Status != 200 {
		t.Fatalf("sign-in/social: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	u, err := url.Parse(m["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state"), u
}

func TestSocialGitHubSignInFlow(t *testing.T) {
	mock := githubMock(t, "octo@example.com", true)
	env := socialEnv(t, nil)
	c := env.client()
	state, authURL := startSocial(t, c, map[string]any{"provider": "github", "callbackURL": "/dashboard"})
	if authURL.Host != "github.com" || authURL.Query().Get("client_id") != "gh-client" ||
		authURL.Query().Get("scope") != "read:user user:email" || authURL.Query().Get("code_challenge_method") != "S256" ||
		authURL.Query().Get("redirect_uri") != env.server.URL+"/api/auth/callback/github" {
		t.Fatalf("authorization url %s", authURL)
	}
	res := c.get("/callback/github?code=the-code&state=" + url.QueryEscape(state))
	if res.Status != 302 || res.Header.Get("Location") != "/dashboard" {
		t.Fatalf("callback: %d %v %s", res.Status, res.Header, res.Body)
	}
	tokenReq := mock.Last("github.com/login/oauth/access_token")
	if tokenReq.Form.Get("code") != "the-code" || tokenReq.Form.Get("code_verifier") == "" || tokenReq.Form.Get("client_secret") != "gh-secret" {
		t.Fatalf("token request %v", tokenReq.Form)
	}
	s := c.session()
	if s == nil {
		t.Fatal("no session after callback")
	}
	u := s["user"].(map[string]any)
	if u["email"] != "octo@example.com" || u["name"] != "Octo Cat" || u["emailVerified"] != true || u["image"] != "https://avatars/octo.png" {
		t.Fatalf("user %v", u)
	}
	accs := c.get("/list-accounts").JSON2(t)
	if len(accs) != 1 || accs[0]["providerId"] != "github" || accs[0]["accountId"] != "4242" {
		t.Fatalf("accounts %v", accs)
	}
	// second sign-in reuses the account
	c2 := env.client()
	state2, _ := startSocial(t, c2, map[string]any{"provider": "github", "callbackURL": "/again"})
	res = c2.get("/callback/github?code=c2&state=" + url.QueryEscape(state2))
	if res.Status != 302 || res.Header.Get("Location") != "/again" {
		t.Fatalf("second callback: %d %s", res.Status, res.Header.Get("Location"))
	}
	if n, _ := env.auth.Context().Adapter.Count(t.Context(), "user", nil); n != 1 {
		t.Fatalf("expected 1 user, got %d", n)
	}
}

func TestSocialCallbackErrors(t *testing.T) {
	githubMock(t, "octo@example.com", true)
	env := socialEnv(t, nil)
	c := env.client()
	base := env.server.URL + "/api/auth/error"
	res := c.get("/callback/github?code=x")
	if res.Status != 302 || res.Header.Get("Location") != base+"?error=state_not_found" {
		t.Fatalf("missing state: %s", res.Header.Get("Location"))
	}
	res = c.get("/callback/github?code=x&state=unknown")
	if res.Header.Get("Location") != base+"?error=state_mismatch" {
		t.Fatalf("unknown state: %s", res.Header.Get("Location"))
	}
	state, _ := startSocial(t, c, map[string]any{"provider": "github", "callbackURL": "/d", "errorCallbackURL": "/oops"})
	res = c.get("/callback/github?error=access_denied&error_description=denied&state=" + url.QueryEscape(state))
	if res.Header.Get("Location") != "/oops?error=access_denied&error_description=denied" {
		t.Fatalf("provider error: %s", res.Header.Get("Location"))
	}
	// state cookie missing (different browser) -> state_mismatch
	state, _ = startSocial(t, c, map[string]any{"provider": "github", "callbackURL": "/d"})
	other := env.client()
	res = other.get("/callback/github?code=x&state=" + url.QueryEscape(state))
	if res.Header.Get("Location") != base+"?error=state_mismatch" {
		t.Fatalf("cookie mismatch: %s", res.Header.Get("Location"))
	}
	res = c.post("/sign-in/social", map[string]any{"provider": "nope"})
	expectError(t, res, 404, "PROVIDER_NOT_FOUND")
	res = c.post("/sign-in/social", map[string]any{"provider": "github", "additionalParams": map[string]any{"state": "x"}})
	expectError(t, res, 400, "VALIDATION_ERROR")
}

func TestSocialFormPostRedirectsToGet(t *testing.T) {
	env := socialEnv(t, nil)
	c := env.client()
	c.origin = ""
	res := c.post("/callback/github", "code=abc&state=xyz&user=%7B%7D", func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	want := env.server.URL + "/api/auth/callback/github?code=abc&state=xyz&user=%7B%7D"
	if res.Status != 302 || res.Header.Get("Location") != want {
		t.Fatalf("form_post: %d %q", res.Status, res.Header.Get("Location"))
	}
}

func TestSocialLinkAccountViaCallback(t *testing.T) {
	githubMock(t, "linker@example.com", true)
	env := socialEnv(t, nil)
	c := env.client()
	c.signUp("linker@example.com", "password1234", "Linker")
	res := c.post("/link-social", map[string]any{"provider": "github", "callbackURL": "/linked"})
	if res.Status != 200 {
		t.Fatalf("link-social %d %s", res.Status, res.Body)
	}
	u, _ := url.Parse(res.JSON(t)["url"].(string))
	res = c.get("/callback/github?code=c&state=" + url.QueryEscape(u.Query().Get("state")))
	if res.Header.Get("Location") != "/linked" {
		t.Fatalf("link callback: %d %s %s", res.Status, res.Header.Get("Location"), res.Body)
	}
	accs := c.get("/list-accounts").JSON2(t)
	if len(accs) != 2 {
		t.Fatalf("expected credential + github accounts: %v", accs)
	}
}

func TestSocialLinkRejectsDifferentEmail(t *testing.T) {
	githubMock(t, "someone-else@example.com", true)
	env := socialEnv(t, nil)
	c := env.client()
	c.signUp("me@example.com", "password1234", "Me")
	res := c.post("/link-social", map[string]any{"provider": "github", "callbackURL": "/linked"})
	u, _ := url.Parse(res.JSON(t)["url"].(string))
	res = c.get("/callback/github?code=c&state=" + url.QueryEscape(u.Query().Get("state")))
	if !strings.HasSuffix(res.Header.Get("Location"), "/api/auth/error?error=email_does_not_match") {
		t.Fatalf("expected email_does_not_match: %s", res.Header.Get("Location"))
	}
}

func TestSocialImplicitLinkingRequiresVerifiedEmails(t *testing.T) {
	githubMock(t, "exists@example.com", false)
	env := socialEnv(t, nil)
	c := env.client()
	c.signUp("exists@example.com", "password1234", "Exists")
	c2 := env.client()
	state, _ := startSocial(t, c2, map[string]any{"provider": "github", "callbackURL": "/d"})
	res := c2.get("/callback/github?code=c&state=" + url.QueryEscape(state))
	if !strings.HasSuffix(res.Header.Get("Location"), "error=account_not_linked") {
		t.Fatalf("expected account_not_linked: %s", res.Header.Get("Location"))
	}
}

func TestSocialGoogleIDTokenSignIn(t *testing.T) {
	mock := oauth2test.New(t)
	mock.ServeJWKS("GET www.googleapis.com/oauth2/v3/certs")
	env := socialEnv(t, nil)
	c := env.client()
	tok := mock.IDToken(map[string]any{"iss": "https://accounts.google.com", "aud": "google-client", "sub": "g-1",
		"email": "g@example.com", "email_verified": true, "name": "Gee", "picture": "https://p/g.png", "nonce": "n1"})
	res := c.post("/sign-in/social", map[string]any{"provider": "google", "idToken": map[string]any{"token": tok, "nonce": "n1"}})
	if res.Status != 200 {
		t.Fatalf("id token sign-in: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if m["redirect"] != false || m["token"] == nil || m["user"].(map[string]any)["email"] != "g@example.com" {
		t.Fatalf("response %v", m)
	}
	if _, has := m["url"]; has {
		t.Fatal("url must be undefined")
	}
	bad := mock.IDToken(map[string]any{"iss": "https://accounts.google.com", "aud": "someone-else", "sub": "g-2", "email": "x@example.com"})
	res = c.post("/sign-in/social", map[string]any{"provider": "google", "idToken": map[string]any{"token": bad}})
	expectError(t, res, 401, "INVALID_TOKEN")
	res = c.post("/sign-in/social", map[string]any{"provider": "google", "idToken": map[string]any{"token": tok, "nonce": "other"}})
	expectError(t, res, 401, "INVALID_TOKEN")
	res = c.post("/sign-in/social", map[string]any{"provider": "github", "idToken": map[string]any{"token": tok}})
	expectError(t, res, 404, "ID_TOKEN_NOT_SUPPORTED")
	acc, _ := env.auth.Context().Adapter.FindOne(t.Context(), adapter.FindOneInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: "google"}}})
	if acc == nil || acc["accountId"] != "g-1" || acc["idToken"] != tok {
		t.Fatalf("account %v", acc)
	}
}

func (r *testResponse) JSON2(t *testing.T) []map[string]any {
	t.Helper()
	var arr []map[string]any
	if err := jsonUnmarshal(r.Body, &arr); err != nil {
		t.Fatalf("decode %s: %v", r.Body, err)
	}
	return arr
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
