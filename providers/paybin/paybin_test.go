package paybin

import (
	"context"
	"errors"
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
	if p.ID() != "paybin" || p.Name() != "Paybin" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("id token sign-in should not be supported (upstream has no verifyIdToken)")
	}
	if AuthorizationEndpoint("") != "https://idp.paybin.io/oauth2/authorize" || TokenEndpoint("") != "https://idp.paybin.io/oauth2/token" {
		t.Fatal("default endpoints")
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newP(func(o *Options) { o.Prompt = "login" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: cb, LoginHint: "user@paybin.io", Display: "popup",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "https://idp.paybin.io/oauth2/authorize?response_type=code&client_id=client-123&state=state-xyz&scope=openid+email+profile" +
		"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=user%40paybin.io&prompt=login&code_challenge_method=S256&code_challenge=" +
		oauth2.GenerateCodeChallenge(verifier)
	if u.String() != want {
		t.Fatalf("got  %s\nwant %s", u, want)
	}
}

func TestCustomIssuerAndScopes(t *testing.T) {
	p := newP(func(o *Options) {
		o.Issuer = "https://idp.custom.example"
		o.Scope = []string{"wallet"}
	})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: cb, Scopes: []string{"offline_access"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "idp.custom.example" || u.Path != "/oauth2/authorize" || u.Query().Get("scope") != "openid email profile wallet offline_access" {
		t.Fatalf("url %s", u)
	}
	m := oauth2test.New(t)
	m.JSON("POST idp.custom.example/oauth2/token", 200, map[string]any{"access_token": "at"})
	if _, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", CodeVerifier: verifier, RedirectURI: cb}); err != nil {
		t.Fatal(err)
	}
	if m.Last("idp.custom.example/oauth2/token") == nil {
		t.Fatal("custom token endpoint not used")
	}
	p = newP(func(o *Options) { o.DisableDefaultScope = true })
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb})
	if u.Query().Has("scope") {
		t.Fatalf("url %s", u)
	}
}

func TestAuthorizationURLRequirements(t *testing.T) {
	p := newP(func(o *Options) { o.ClientSecret = "" })
	if _, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb}); !errors.Is(err, ErrClientIDAndSecretRequired) {
		t.Fatalf("err %v", err)
	}
	p = newP(nil)
	if _, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: cb}); err == nil || err.Error() != "codeVerifier is required for Paybin" {
		t.Fatalf("err %v", err)
	}
}

func TestExchangeIDTokenProfileAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	idToken := m.IDToken(map[string]any{
		"sub": "pb-sub-1", "email": "pb@test.com", "email_verified": true, "preferred_username": "pbuser",
		"picture": "https://paybin/avatar.png", "given_name": "Pay", "family_name": "Bin",
	})
	m.JSON("POST idp.paybin.io/oauth2/token", 200, map[string]any{
		"access_token": "pb_at", "refresh_token": "pb_rt", "id_token": idToken, "token_type": "Bearer", "expires_in": 3600,
	})
	p := newP(nil)
	ctx := context.Background()
	tok, err := p.ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c0de", CodeVerifier: verifier, RedirectURI: cb})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "pb_at" || tok.IDToken != idToken || tok.RefreshToken != "pb_rt" {
		t.Fatalf("tokens %+v", tok)
	}
	r := m.Last("idp.paybin.io/oauth2/token")
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "c0de" || r.Form.Get("code_verifier") != verifier ||
		r.Form.Get("redirect_uri") != cb || r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
		t.Fatalf("token request %s", r.Body)
	}

	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: *tok})
	if err != nil || info == nil {
		t.Fatalf("user info %v %v", info, err)
	}
	if info.User.Name != "pbuser" || info.User.Email != "pb@test.com" || info.User.Image != "https://paybin/avatar.png" || !info.User.EmailVerified {
		t.Fatalf("user %+v", info.User)
	}
	if info.Data["given_name"] != "Pay" {
		t.Fatalf("data %+v", info.Data)
	}
	if sub, _ := p.AccountSubject(ctx, tok, info.Data); sub != "pb-sub-1" {
		t.Fatalf("subject %q", sub)
	}
	// No HTTP user-info request is made: the profile comes from the id token.
	if len(m.Requests) != 1 {
		t.Fatalf("unexpected requests: %d", len(m.Requests))
	}

	if _, err := p.RefreshAccessToken(ctx, "pb_rt", nil); err != nil {
		t.Fatal(err)
	}
	r = m.Last("idp.paybin.io/oauth2/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "pb_rt" ||
		r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
		t.Fatalf("refresh request %s", r.Body)
	}
}

func TestUserInfoFromIDTokenEdgeCases(t *testing.T) {
	m := oauth2test.New(t)
	p := newP(nil)
	ctx := context.Background()
	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if info != nil || err != nil {
		t.Fatalf("expected nil without id token: %+v %v", info, err)
	}
	tok := m.IDToken(map[string]any{"sub": "s", "email": "e@x.y", "name": "Real Name", "preferred_username": "u"})
	info, err = p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: tok}})
	if err != nil || info.User.Name != "Real Name" || info.User.EmailVerified {
		t.Fatalf("user %+v %v", info, err)
	}
	if _, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: "not-a-jwt"}}); err == nil {
		t.Fatal("expected decode error for malformed id token")
	}
}

func TestMapProfileToUserAndOverrides(t *testing.T) {
	m := oauth2test.New(t)
	tok := m.IDToken(map[string]any{"sub": "s", "email": "e@x.y", "given_name": "Pay", "family_name": "Bin"})
	p := newP(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"name": oauth2.JoinName(oauth2.String(profile, "given_name"), oauth2.String(profile, "family_name")), "paybinId": profile["sub"]}, nil
		}
	})
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: tok}})
	if err != nil || info.User.Name != "Pay Bin" || info.User.Extra["paybinId"] != "s" {
		t.Fatalf("user %+v %v", info, err)
	}
	p = newP(func(o *Options) {
		o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}, Data: map[string]any{"sub": "c"}}, nil
		}
	})
	if info, _ := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{}); info.User.Name != "custom" {
		t.Fatal("getUserInfo override not applied")
	}
}
