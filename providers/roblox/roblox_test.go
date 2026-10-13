package roblox

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

const (
	baseCallback = "https://app.example/callback"
	baseState    = "state-xyz"
)

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"}}
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "roblox" || p.Name() != "Roblox" {
		t.Fatalf("id/name = %s/%s", p.ID(), p.Name())
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{}, map[string]any{"sub": "42", "id": "x"})
	if err != nil || sub != "42" {
		t.Fatalf("subject = %q %v", sub, err)
	}
}

// preserves the authorize URL shape after the shared-helper refactor
func TestAuthorizationURLShape(t *testing.T) {
	u, err := New(opts()).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: baseState, CodeVerifier: "verifier", RedirectURI: baseCallback,
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint = %s", u)
	}
	if q.Get("client_id") != "client-123" || q.Get("response_type") != "code" || q.Get("scope") != "openid profile" ||
		q.Get("prompt") != "select_account consent" || q.Get("state") != baseState || q.Get("redirect_uri") != baseCallback {
		t.Fatalf("query = %v", q)
	}
	if q.Has("code_challenge") {
		t.Error("roblox does not send PKCE")
	}
}

// forwards additionalParams while dropping reserved keys
func TestAuthorizationURLAdditionalParams(t *testing.T) {
	u, _ := New(opts()).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: baseState, RedirectURI: baseCallback, AdditionalParams: map[string]string{"custom": "value", "scope": "admin"},
	})
	if u.Query().Get("custom") != "value" || u.Query().Get("scope") != "openid profile" {
		t.Fatalf("query = %v", u.Query())
	}
}

func TestAuthorizationURLOptions(t *testing.T) {
	o := opts()
	o.Prompt = "login"
	o.Scope = []string{"email"}
	o.DisableDefaultScope = true
	u, _ := New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r", Scopes: []string{"x"}})
	if u.Query().Get("prompt") != "login" || u.Query().Get("scope") != "email x" {
		t.Fatalf("query = %v", u.Query())
	}
}

func TestExchange(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST apis.roblox.com/oauth/v1/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "id_token": "idt", "expires_in": 900, "scope": "openid profile",
	})
	o := opts()
	o.ClientKey = "ck"
	tok, err := New(o).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "code", RedirectURI: baseCallback, CodeVerifier: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.IDToken != "idt" || len(tok.Scopes) != 2 {
		t.Fatalf("tokens = %+v", tok)
	}
	r := m.Last("apis.roblox.com/oauth/v1/token")
	want := "grant_type=authorization_code&code=code&client_key=ck&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=client-123&client_secret=secret-abc"
	if r.Body != want {
		t.Fatalf("body = %s", r.Body)
	}
	if r.Header.Get("Authorization") != "" {
		t.Error("unexpected basic auth")
	}
}

func TestRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST apis.roblox.com/oauth/v1/token", 200, map[string]any{"access_token": "new", "refresh_token": "rt2", "expires_in": 900})
	tok, err := New(opts()).RefreshAccessToken(ctx, "rt", nil)
	if err != nil || tok.AccessToken != "new" || tok.RefreshToken != "rt2" {
		t.Fatalf("tok = %+v %v", tok, err)
	}
	r := m.Last("apis.roblox.com/oauth/v1/token")
	if r.Body != "grant_type=refresh_token&refresh_token=rt&client_id=client-123&client_secret=secret-abc" {
		t.Fatalf("body = %s", r.Body)
	}
}

func robloxProfile() map[string]any {
	return map[string]any{
		"sub": "roblox-user-1", "preferred_username": "builderman", "nickname": "Builderman", "name": "Builderman",
		"created_at": 0, "profile": "https://www.roblox.com/users/1/profile", "picture": "https://example.com/avatar.png",
	}
}

// uses the user ID in the placeholder email
func TestUserInfoPlaceholderEmail(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET apis.roblox.com/oauth/v1/userinfo", 200, robloxProfile())
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res == nil {
		t.Fatal(res, err)
	}
	if res.User.Email != "roblox-user-1@roblox.placeholder.invalid" || res.User.EmailVerified {
		t.Fatalf("user = %+v", res.User)
	}
	if res.User.Name != "Builderman" || res.User.Image != "https://example.com/avatar.png" {
		t.Fatalf("user = %+v", res.User)
	}
	if got := m.Last("apis.roblox.com/oauth/v1/userinfo").Header.Get("Authorization"); got != "Bearer access-token" {
		t.Fatalf("authorization = %q", got)
	}
}

func TestUserInfoNameFallbacks(t *testing.T) {
	m := oauth2test.New(t)
	p := robloxProfile()
	p["nickname"] = ""
	m.JSON("GET apis.roblox.com/oauth/v1/userinfo", 200, p)
	res, _ := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if res.User.Name != "builderman" {
		t.Fatalf("name = %q", res.User.Name)
	}
	delete(p, "preferred_username")
	m.JSON("GET apis.roblox.com/oauth/v1/userinfo", 200, p)
	res, _ = New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if res.User.Name != "" {
		t.Fatalf("name = %q", res.User.Name)
	}
}

func TestUserInfoMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET apis.roblox.com/oauth/v1/userinfo", 200, robloxProfile())
	o := opts()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"email": "real@example.com", "emailVerified": true, "robloxProfile": p["profile"]}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Email != "real@example.com" || !res.User.EmailVerified || res.User.Extra["robloxProfile"] != "https://www.roblox.com/users/1/profile" {
		t.Fatalf("user = %+v", res.User)
	}
}

func TestUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET apis.roblox.com/oauth/v1/userinfo", 500, map[string]any{})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}
