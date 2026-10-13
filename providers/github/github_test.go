package github

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var verifier = strings.Repeat("v", 64)

func newProvider(mut ...func(*Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "gh-client", ClientSecret: "gh-secret"}}
	for _, m := range mut {
		m(&o)
	}
	return New(o)
}

func TestIdentity(t *testing.T) {
	p := newProvider()
	if p.ID() != "github" || p.Name() != "GitHub" || !p.SupportsRefresh() || p.SupportsIDToken() {
		t.Fatalf("identity/capabilities mismatch")
	}
}

func TestAuthorizationURL(t *testing.T) {
	u, err := newProvider().CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: verifier, RedirectURI: "https://app.example/cb", Scopes: []string{"repo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "response_type=code&client_id=gh-client&state=st&scope=read%3Auser+user%3Aemail+repo&redirect_uri=https%3A%2F%2Fapp.example%2Fcb" +
		"&code_challenge_method=S256&code_challenge=" + oauth2.GenerateCodeChallenge(verifier)
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint || u.RawQuery != want {
		t.Fatalf("got %s", u)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST github.com/login/oauth/access_token", 200, map[string]any{"access_token": "gho", "token_type": "bearer", "scope": "read:user,user:email"})
	tok, err := newProvider().ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", CodeVerifier: verifier, RedirectURI: "https://app.example/cb"})
	if err != nil || tok == nil || tok.AccessToken != "gho" || len(tok.Scopes) != 1 { // upstream splits scope on spaces only
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("github.com/login/oauth/access_token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "c" || f.Get("code_verifier") != verifier || f.Get("client_secret") != "gh-secret" {
		t.Fatalf("form %v", f)
	}
}

func TestValidateAuthorizationCodeErrorYieldsNil(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST github.com/login/oauth/access_token", 200, map[string]any{"error": "bad_verification_code"})
	tok, err := newProvider().ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c"})
	if tok != nil || err != nil {
		t.Fatalf("want nil tokens, got %+v %v", tok, err)
	}
}

func TestGetUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.github.com/user", 200, map[string]any{"id": 7, "login": "octo", "name": "", "email": nil, "avatar_url": "https://a/x.png"})
	m.JSON("GET api.github.com/user/emails", 200, []map[string]any{
		{"email": "other@example.com", "primary": false, "verified": false},
		{"email": "primary@example.com", "primary": true, "verified": true},
	})
	p := newProvider()
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "gho"}})
	if err != nil || info == nil {
		t.Fatalf("%v %v", info, err)
	}
	if info.User.Name != "octo" || info.User.Email != "primary@example.com" || !info.User.EmailVerified || info.User.Image != "https://a/x.png" {
		t.Fatalf("user %+v", info.User)
	}
	req := m.Last("api.github.com/user")
	if req.Header.Get("Authorization") != "Bearer gho" || req.Header.Get("User-Agent") != "better-auth" {
		t.Fatalf("headers %v", req.Header)
	}
	if sub, _ := p.AccountSubject(context.Background(), nil, info.Data); sub != "7" {
		t.Fatalf("subject %q", sub)
	}
}

func TestGetUserInfoProfileEmailVerification(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.github.com/user", 200, map[string]any{"id": 8, "login": "l", "name": "N", "email": "public@example.com"})
	m.JSON("GET api.github.com/user/emails", 200, []map[string]any{{"email": "primary@example.com", "primary": true, "verified": true}})
	info, _ := newProvider(func(o *Options) {
		o.MapProfileToUser = func(p map[string]any) (map[string]any, error) { return map[string]any{"name": "Mapped"}, nil }
	}).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	// the profile email wins and is unverified because it is not in the verified list
	if info.User.Email != "public@example.com" || info.User.EmailVerified || info.User.Name != "Mapped" {
		t.Fatalf("user %+v", info.User)
	}
}

func TestGetUserInfoFailureYieldsNil(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.github.com/user", 401, map[string]any{"message": "Bad credentials"})
	info, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if info != nil || err != nil {
		t.Fatalf("got %v %v", info, err)
	}
}
