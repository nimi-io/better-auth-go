package polar

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	cb       = "https://app.example/callback"
	state    = "state-xyz"
	clientID = "client-123"
	secret   = "secret-abc"
)

var verifier = strings.Repeat("v", 64)

func newP(mut func(o *Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: secret}}
	if mut != nil {
		mut(&o)
	}
	return New(o)
}

func TestIdentity(t *testing.T) {
	p := newP(nil)
	if p.ID() != "polar" || p.Name() != "Polar" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newP(func(o *Options) { o.Prompt = "consent" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: cb, LoginHint: "ignored@x.y",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := AuthorizationEndpoint + "?response_type=code&client_id=client-123&state=state-xyz&scope=openid+profile+email" +
		"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&prompt=consent&code_challenge_method=S256&code_challenge=" + oauth2.GenerateCodeChallenge(verifier)
	if u.String() != want {
		t.Fatalf("got  %s\nwant %s", u, want)
	}
	p = newP(func(o *Options) { o.Scope = []string{"user:read"}; o.RedirectURI = "https://o.example/cb" })
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: cb, Scopes: []string{"orders:read"}})
	if u.Query().Get("scope") != "openid profile email user:read orders:read" || u.Query().Get("redirect_uri") != "https://o.example/cb" || u.Query().Has("code_challenge") {
		t.Fatalf("url %s", u)
	}
	p = newP(func(o *Options) { o.DisableDefaultScope = true })
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: cb})
	if u.Query().Has("scope") {
		t.Fatalf("url %s", u)
	}
}

func TestExchangeUserInfoAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.polar.sh/v1/oauth2/token", 200, map[string]any{
		"access_token": "polar_at", "refresh_token": "polar_rt", "token_type": "Bearer", "expires_in": 3600,
	})
	m.JSON("GET api.polar.sh/v1/oauth2/userinfo", 200, map[string]any{
		"id": "polar-1", "email": "polar@test.com", "username": "polaruser", "public_name": "Polar User",
		"avatar_url": "https://polar/avatar.png", "email_verified": true,
	})
	p := newP(nil)
	ctx := context.Background()
	tok, err := p.ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c0de", CodeVerifier: verifier, RedirectURI: cb})
	if err != nil || tok.AccessToken != "polar_at" || tok.RefreshToken != "polar_rt" {
		t.Fatalf("tokens %+v %v", tok, err)
	}
	r := m.Last("api.polar.sh/v1/oauth2/token")
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "c0de" || r.Form.Get("code_verifier") != verifier ||
		r.Form.Get("redirect_uri") != cb || r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
		t.Fatalf("token request %s", r.Body)
	}
	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: *tok})
	if err != nil || info == nil {
		t.Fatalf("user info %v %v", info, err)
	}
	if m.Last("api.polar.sh/v1/oauth2/userinfo").Header.Get("Authorization") != "Bearer polar_at" {
		t.Fatal("missing bearer")
	}
	if info.User.Name != "Polar User" || info.User.Email != "polar@test.com" || info.User.Image != "https://polar/avatar.png" || !info.User.EmailVerified {
		t.Fatalf("user %+v", info.User)
	}
	if sub, _ := p.AccountSubject(ctx, tok, info.Data); sub != "polar-1" {
		t.Fatalf("subject %q", sub)
	}
	if _, err := p.RefreshAccessToken(ctx, "polar_rt", nil); err != nil {
		t.Fatal(err)
	}
	r = m.Last("api.polar.sh/v1/oauth2/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "polar_rt" ||
		r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
		t.Fatalf("refresh request %s", r.Body)
	}
}

func TestUserInfoFallbacksAndErrors(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.polar.sh/v1/oauth2/userinfo", 200, map[string]any{"id": "p", "email": "e@x.y", "username": "polaruser", "avatar_url": "a"})
	p := newP(nil)
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || info.User.Name != "polaruser" || info.User.EmailVerified {
		t.Fatalf("user %+v %v", info, err)
	}
	m.JSON("GET api.polar.sh/v1/oauth2/userinfo", 401, map[string]any{"error": "invalid_token"})
	info, err = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if info != nil || err != nil {
		t.Fatalf("expected nil: %+v %v", info, err)
	}
}

func TestMapProfileToUserAndOverrides(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.polar.sh/v1/oauth2/userinfo", 200, map[string]any{"id": "p", "username": "u", "github_username": "gh"})
	p := newP(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"image": "https://mapped", "githubUsername": profile["github_username"]}, nil
		}
	})
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || info.User.Image != "https://mapped" || info.User.Extra["githubUsername"] != "gh" || info.User.Name != "u" {
		t.Fatalf("user %+v %v", info, err)
	}
	p = newP(func(o *Options) {
		o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) {
			return &oauth2.Tokens{AccessToken: "custom"}, nil
		}
	})
	if tok, _ := p.RefreshAccessToken(context.Background(), "rt", nil); tok.AccessToken != "custom" {
		t.Fatal("refresh override not applied")
	}
}
