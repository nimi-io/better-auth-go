package reddit

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "reddit-app", ClientSecret: "reddit-secret"}}
}

func basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("reddit-app:reddit-secret"))
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "reddit" || p.Name() != "Reddit" {
		t.Fatalf("id/name = %s/%s", p.ID(), p.Name())
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{}, map[string]any{"id": "abc", "oauth_client_id": "client"})
	if err != nil || sub != "abc" {
		t.Fatalf("subject = %q %v", sub, err)
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := opts()
	o.Duration = "permanent"
	o.Scope = []string{"read"}
	u, err := New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "v", RedirectURI: "https://app.example.com/cb", Scopes: []string{"history"},
		LoginHint: "x", AdditionalParams: map[string]string{"custom": "1", "state": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint = %s", u)
	}
	want := map[string]string{"response_type": "code", "client_id": "reddit-app", "state": "st",
		"scope": "identity read history", "redirect_uri": "https://app.example.com/cb", "duration": "permanent", "custom": "1"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	// Reddit does not send PKCE nor login_hint.
	for _, k := range []string{"code_challenge", "login_hint", "prompt"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}

	o = opts()
	o.DisableDefaultScope = true
	o.RedirectURI = "https://override/cb"
	o.AuthorizationEndpoint = "https://proxy.example/authorize"
	u, _ = New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "https://app/cb"})
	if u.Host != "proxy.example" || u.Query().Has("scope") || u.Query().Get("redirect_uri") != "https://override/cb" || u.Query().Has("duration") {
		t.Fatalf("override url = %s", u)
	}
}

// exchanges an authorization code with Basic authentication
func TestExchangeBasicAuth(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST www.reddit.com/api/v1/access_token", 200, map[string]any{
		"access_token": "access-token", "expires_in": 3600, "refresh_token": "refresh-token", "token_type": "bearer",
	})
	tok, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{
		Code: "authorization-code", RedirectURI: "https://app.example.com/api/auth/callback/reddit", CodeVerifier: "ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-token" || tok.RefreshToken != "refresh-token" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("tokens = %+v", tok)
	}
	r := m.Last("www.reddit.com/api/v1/access_token")
	if r.Header.Get("Accept") != "text/plain" {
		t.Errorf("accept = %q", r.Header.Get("Accept"))
	}
	if r.Header.Get("Authorization") != basic() {
		t.Errorf("authorization = %q", r.Header.Get("Authorization"))
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
	}
	if r.Header.Get("User-Agent") == "" {
		t.Error("missing user-agent")
	}
	if r.Body != "grant_type=authorization_code&code=authorization-code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fapi%2Fauth%2Fcallback%2Freddit" {
		t.Errorf("body = %s", r.Body)
	}
}

func TestExchangeUsesRedirectOverrideAndNoClientKey(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST www.reddit.com/api/v1/access_token", 200, map[string]any{"access_token": "a"})
	o := opts()
	o.RedirectURI = "https://override/cb"
	o.ClientKey = "key"
	if _, err := New(o).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c", RedirectURI: "https://app/cb"}); err != nil {
		t.Fatal(err)
	}
	r := m.Last("www.reddit.com/api/v1/access_token")
	if r.Form.Get("redirect_uri") != "https://override/cb" || r.Form.Has("client_key") || r.Form.Has("client_secret") {
		t.Fatalf("form = %v", r.Form)
	}
}

func TestExchangeError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST www.reddit.com/api/v1/access_token", 401, map[string]any{"error": "invalid_grant"})
	if _, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c", RedirectURI: "r"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestExchangeRefusesRedirect(t *testing.T) {
	m := oauth2test.New(t)
	m.Handle("POST www.reddit.com/api/v1/access_token", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/", http.StatusFound)
	})
	if _, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c", RedirectURI: "r"}); err == nil {
		t.Fatal("expected redirect refusal")
	}
}

// refreshes an access token with Basic authentication
func TestRefreshBasicAuth(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST www.reddit.com/api/v1/access_token", 200, map[string]any{
		"access_token": "refreshed-access-token", "expires_in": 3600, "token_type": "bearer",
	})
	tok, err := New(opts()).RefreshAccessToken(ctx, "refresh-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "refreshed-access-token" {
		t.Fatalf("tokens = %+v", tok)
	}
	r := m.Last("www.reddit.com/api/v1/access_token")
	if r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != basic() ||
		r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("headers = %v", r.Header)
	}
	if r.Body != "grant_type=refresh_token&refresh_token=refresh-token" {
		t.Errorf("body = %s", r.Body)
	}
}

func TestRefreshOverride(t *testing.T) {
	o := opts()
	o.RefreshAccessToken = func(_ context.Context, rt string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom-" + rt}, nil
	}
	tok, err := New(o).RefreshAccessToken(ctx, "r", nil)
	if err != nil || tok.AccessToken != "custom-r" {
		t.Fatalf("tok = %+v %v", tok, err)
	}
}

func serveProfile(m *oauth2test.Server, profile map[string]any) {
	m.JSON("GET oauth.reddit.com/api/v1/me", 200, profile)
}

// creates a non-routable placeholder email and never trusts oauth_client_id
func TestUserInfoPlaceholderEmail(t *testing.T) {
	m := oauth2test.New(t)
	serveProfile(m, map[string]any{
		"id": "reddit-user-1", "name": "spez", "icon_img": "https://example.com/avatar.png?size=256",
		"has_verified_email": true, "oauth_client_id": "shared-app-client-id", "verified": true,
	})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res == nil {
		t.Fatal(res, err)
	}
	if res.User.Email != "reddit-user-1@reddit.placeholder.invalid" {
		t.Errorf("email = %q", res.User.Email)
	}
	if res.User.EmailVerified {
		t.Error("placeholder email must not be verified")
	}
	if res.User.Name != "spez" || res.User.Image != "https://example.com/avatar.png" {
		t.Errorf("user = %+v", res.User)
	}
	if res.Data["oauth_client_id"] != "shared-app-client-id" {
		t.Errorf("data = %v", res.Data)
	}
	r := m.Last("oauth.reddit.com/api/v1/me")
	if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("User-Agent") != "better-auth" {
		t.Errorf("headers = %v", r.Header)
	}
}

// gives distinct users distinct placeholder emails
func TestUserInfoDistinctPlaceholders(t *testing.T) {
	m := oauth2test.New(t)
	p := New(opts())
	serveProfile(m, map[string]any{"id": "user-a", "name": "a", "icon_img": nil, "oauth_client_id": "same-client"})
	a, _ := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t-a"}})
	serveProfile(m, map[string]any{"id": "user-b", "name": "b", "icon_img": nil, "oauth_client_id": "same-client"})
	b, _ := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t-b"}})
	if a.User.Email != "user-a@reddit.placeholder.invalid" || b.User.Email != "user-b@reddit.placeholder.invalid" {
		t.Fatalf("emails = %q %q", a.User.Email, b.User.Email)
	}
	if a.User.Image != "" {
		t.Errorf("image = %q", a.User.Image)
	}
}

// lets mapProfileToUser supply a real email
func TestUserInfoMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	serveProfile(m, map[string]any{"id": "reddit-user-2", "name": "mapped", "icon_img": nil})
	o := opts()
	o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
		return map[string]any{"email": "real@example.com", "emailVerified": true, "karma": 10}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Email != "real@example.com" || !res.User.EmailVerified || res.User.Extra["karma"] != 10 {
		t.Fatalf("user = %+v", res.User)
	}

	// an empty mapped email falls back to the placeholder
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return map[string]any{"email": ""}, nil }
	res, _ = New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if res.User.Email != "reddit-user-2@reddit.placeholder.invalid" {
		t.Fatalf("email = %q", res.User.Email)
	}
}

func TestUserInfoErrorReturnsNil(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET oauth.reddit.com/api/v1/me", 401, map[string]any{"error": 401})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestUserInfoInvalidPlaceholder(t *testing.T) {
	m := oauth2test.New(t)
	serveProfile(m, map[string]any{"id": "bad id", "name": "x"})
	if _, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}}); err == nil {
		t.Fatal("expected invalid placeholder error")
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	o := opts()
	o.GetUserInfo = func(_ context.Context, tok *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: tok.AccessToken}, Data: map[string]any{"id": "1"}}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "custom"}})
	if err != nil || res.User.Name != "custom" {
		t.Fatalf("res = %+v %v", res, err)
	}
}
