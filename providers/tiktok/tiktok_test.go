package tiktok

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientKey: "tiktok-client-key", ClientSecret: "tiktok-client-secret"}}
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "tiktok" || p.Name() != "TikTok" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("no id token sign-in")
	}
}

// social-providers.test.ts: "preserves the manual authorize URL shape with non-standard client_key"
func TestAuthorizationURLShape(t *testing.T) {
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientKey: "tk-key-1", ClientSecret: "secret"}})
	u, err := p.CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "state-xyz", CodeVerifier: strings.Repeat("v", 64), RedirectURI: "https://app.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{"client_key": "tk-key-1", "response_type": "code", "redirect_uri": "https://app.example/callback", "state": "state-xyz", "scope": "user.info.profile"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	for _, k := range []string{"client_id", "code_challenge", "code_challenge_method"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
	if !strings.HasPrefix(u.RawQuery, "scope=user.info.profile&response_type=code&client_key=tk-key-1&redirect_uri=") {
		t.Fatalf("param order %s", u.RawQuery)
	}
}

// social-providers.test.ts: "forwards additionalParams but drops reserved keys and client_key"
func TestAuthorizationURLAdditionalParams(t *testing.T) {
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientKey: "tk-key-1", ClientSecret: "secret"}})
	u, err := p.CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "state-xyz", RedirectURI: "https://app.example/callback",
		AdditionalParams: map[string]string{"custom": "value", "state": "attacker", "client_key": "attacker-key"}})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("custom") != "value" || q.Get("state") != "state-xyz" || q.Get("client_key") != "tk-key-1" {
		t.Fatalf("query %v", q)
	}
}

func TestAuthorizationURLCommaScopesAndOverrides(t *testing.T) {
	o := opts()
	o.Scope = []string{"user.info.stats"}
	o.RedirectURI = "https://override/cb"
	u, _ := New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r", Scopes: []string{"video.list"}})
	if u.Query().Get("scope") != "user.info.profile,user.info.stats,video.list" || u.Query().Get("redirect_uri") != "https://override/cb" {
		t.Fatalf("query %v", u.Query())
	}
	if !strings.Contains(u.RawQuery, "user.info.profile%2Cuser.info.stats") {
		t.Fatalf("comma should be form-encoded: %s", u.RawQuery)
	}
	o = opts()
	o.DisableDefaultScope = true
	u, _ = New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	if !u.Query().Has("scope") || u.Query().Get("scope") != "" {
		t.Fatalf("scope is always set: %v", u.Query())
	}
}

// tiktok.test.ts: "exchanges an authorization code with TikTok client credentials"
func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST open.tiktokapis.com/v2/oauth/token/", 200, map[string]any{"access_token": "access-token", "refresh_token": "refresh-token", "expires_in": 86400, "token_type": "Bearer"})
	tokens, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "authorization-code", CodeVerifier: "code-verifier", RedirectURI: "https://app.example.com/api/auth/callback/tiktok"})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "access-token" {
		t.Fatalf("tokens %+v", tokens)
	}
	r := m.Last("open.tiktokapis.com/v2/oauth/token/")
	want := map[string]string{
		"client_key": "tiktok-client-key", "client_secret": "tiktok-client-secret", "code": "authorization-code",
		"code_verifier": "code-verifier", "grant_type": "authorization_code", "redirect_uri": "https://app.example.com/api/auth/callback/tiktok",
	}
	if len(r.Form) != len(want) {
		t.Fatalf("form %v", r.Form)
	}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.Form.Get(k), v)
		}
	}
	if r.Header.Get("Authorization") != "" {
		t.Fatal("unexpected Authorization header")
	}
}

// tiktok.test.ts: "refreshes an access token with TikTok client credentials"
func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST open.tiktokapis.com/v2/oauth/token/", 200, map[string]any{"access_token": "refreshed-access-token", "refresh_token": "rotated-refresh-token", "expires_in": 86400, "token_type": "Bearer"})
	tokens, err := New(opts()).RefreshAccessToken(ctx, "refresh-token", nil)
	if err != nil || tokens.AccessToken != "refreshed-access-token" {
		t.Fatalf("%+v %v", tokens, err)
	}
	r := m.Last("open.tiktokapis.com/v2/oauth/token/")
	want := map[string]string{"client_key": "tiktok-client-key", "client_secret": "tiktok-client-secret", "grant_type": "refresh_token", "refresh_token": "refresh-token"}
	if len(r.Form) != len(want) {
		t.Fatalf("form %v", r.Form)
	}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.Form.Get(k), v)
		}
	}
	o := opts()
	o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom"}, nil
	}
	if tk, _ := New(o).RefreshAccessToken(ctx, "x", nil); tk.AccessToken != "custom" {
		t.Fatal("override ignored")
	}
}

// tiktok.test.ts: "uses the open id for the placeholder email"
func TestGetUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET open.tiktokapis.com/v2/user/info/", 200, map[string]any{"data": map[string]any{"user": map[string]any{
		"open_id": "tiktok-user-1", "avatar_large_url": "https://example.com/avatar.png", "display_name": "TikTok User", "username": "tiktok-user",
	}}, "error": map[string]any{"code": "ok"}})
	p := New(opts())
	res, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Email != "tiktok-user-1@tiktok.placeholder.invalid" || res.User.Name != "TikTok User" ||
		res.User.Image != "https://example.com/avatar.png" || res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	r := m.Last("open.tiktokapis.com/v2/user/info/")
	if r.URL.Query().Get("fields") != "open_id,avatar_large_url,display_name,username" || r.Header.Get("Authorization") != "Bearer access-token" {
		t.Fatalf("request %s %v", r.URL, r.Header)
	}
	sub, err := p.AccountSubject(ctx, nil, res.Data)
	if err != nil || sub != "tiktok-user-1" {
		t.Fatalf("subject %q %v", sub, err)
	}
}

func TestGetUserInfoUsernameFallbackAndErrors(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET open.tiktokapis.com/v2/user/info/", 200, map[string]any{"data": map[string]any{"user": map[string]any{"open_id": "o1", "username": "handle"}}})
	res, _ := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res.User.Name != "handle" {
		t.Fatalf("name %q", res.User.Name)
	}
	m.JSON("GET open.tiktokapis.com/v2/user/info/", 401, map[string]any{"error": map[string]any{"code": "access_token_invalid"}})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "bad"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUserIsNotApplied(t *testing.T) {
	// Upstream tiktok.getUserInfo never calls mapProfileToUser.
	m := oauth2test.New(t)
	m.JSON("GET open.tiktokapis.com/v2/user/info/", 200, map[string]any{"data": map[string]any{"user": map[string]any{"open_id": "o1", "display_name": "N"}}})
	o := opts()
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return map[string]any{"name": "mapped"}, nil }
	res, _ := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res.User.Name != "N" {
		t.Fatalf("name %q", res.User.Name)
	}
	o = opts()
	o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}}, nil
	}
	res, _ = New(o).GetUserInfo(ctx, oauth2.UserInfoParams{})
	if res.User.Name != "custom" {
		t.Fatal("getUserInfo override ignored")
	}
}
