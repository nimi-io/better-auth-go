package huggingface

import (
	"context"
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

var verifier = func() string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = 'v'
	}
	return string(b)
}()

func newP(mut func(o *Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: secret}}
	if mut != nil {
		mut(&o)
	}
	return New(o)
}

func TestIdentity(t *testing.T) {
	p := newP(nil)
	if p.ID() != "huggingface" || p.Name() != "Hugging Face" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("id token sign-in should not be supported")
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newP(func(o *Options) { o.Prompt = "consent" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: cb, LoginHint: "x@y.z",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := AuthorizationEndpoint + "?response_type=code&client_id=client-123&state=state-xyz&scope=openid+profile+email" +
		"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=" + oauth2.GenerateCodeChallenge(verifier)
	if u.String() != want {
		t.Fatalf("got  %s\nwant %s", u, want)
	}
}

func TestAuthorizationURLScopesAndOverrides(t *testing.T) {
	p := newP(func(o *Options) {
		o.Scope = []string{"read-repos"}
		o.RedirectURI = "https://override.example/cb"
		o.AuthorizationEndpoint = "https://hf.example/authorize"
	})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: cb, Scopes: []string{"inference-api"},
		AdditionalParams: map[string]string{"orgIds": "org1", "state": "evil"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "hf.example" || q.Get("scope") != "openid profile email read-repos inference-api" ||
		q.Get("redirect_uri") != "https://override.example/cb" || q.Get("orgIds") != "org1" || q.Get("state") != state {
		t.Fatalf("url %s", u)
	}
	p = newP(func(o *Options) { o.DisableDefaultScope = true; o.Scope = []string{"a"} })
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: cb})
	if u.Query().Get("scope") != "a" || u.Query().Has("code_challenge") {
		t.Fatalf("url %s", u)
	}
}

func TestExchangeUserInfoAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST huggingface.co/oauth/token", 200, map[string]any{
		"access_token": "hf_at", "refresh_token": "hf_rt", "token_type": "Bearer", "expires_in": 3600, "scope": "openid profile email",
	})
	m.JSON("GET huggingface.co/oauth/userinfo", 200, map[string]any{
		"sub": "hf-sub-1", "name": "", "preferred_username": "hfuser", "picture": "https://hf/avatar.png",
		"email": "hf@test.com", "email_verified": true, "isPro": false,
	})
	p := newP(nil)
	ctx := context.Background()
	tok, err := p.ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "the-code", CodeVerifier: verifier, RedirectURI: cb, DeviceID: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "hf_at" || tok.RefreshToken != "hf_rt" || tok.AccessTokenExpiresAt == nil || len(tok.Scopes) != 3 {
		t.Fatalf("tokens %+v", tok)
	}
	r := m.Last("huggingface.co/oauth/token")
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "the-code" || r.Form.Get("code_verifier") != verifier ||
		r.Form.Get("redirect_uri") != cb || r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret ||
		r.Form.Has("device_id") || r.Header.Get("Authorization") != "" {
		t.Fatalf("token request %s", r.Body)
	}

	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: *tok})
	if err != nil || info == nil {
		t.Fatalf("user info %v %v", info, err)
	}
	if got := m.Last("huggingface.co/oauth/userinfo").Header.Get("Authorization"); got != "Bearer hf_at" {
		t.Fatalf("auth header %q", got)
	}
	if info.User.Name != "hfuser" || info.User.Email != "hf@test.com" || info.User.Image != "https://hf/avatar.png" || !info.User.EmailVerified {
		t.Fatalf("user %+v", info.User)
	}
	sub, _ := p.AccountSubject(ctx, tok, info.Data)
	if sub != "hf-sub-1" {
		t.Fatalf("subject %q", sub)
	}

	rt, err := p.RefreshAccessToken(ctx, "hf_rt", nil)
	if err != nil || rt.AccessToken != "hf_at" {
		t.Fatalf("refresh %v %v", rt, err)
	}
	r = m.Last("huggingface.co/oauth/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "hf_rt" ||
		r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
		t.Fatalf("refresh request %s", r.Body)
	}
}

func TestUserInfoDefaultsAndErrors(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET huggingface.co/oauth/userinfo", 200, map[string]any{"sub": "s", "name": "Full Name", "picture": "p"})
	p := newP(nil)
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || info.User.Name != "Full Name" || info.User.EmailVerified || info.User.Email != "" {
		t.Fatalf("user %+v %v", info, err)
	}
	m.JSON("GET huggingface.co/oauth/userinfo", 401, map[string]any{"error": "invalid_token"})
	info, err = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || info != nil {
		t.Fatalf("expected nil user info, got %+v %v", info, err)
	}
}

func TestMapProfileToUserAndOverrides(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET huggingface.co/oauth/userinfo", 200, map[string]any{"sub": "s1", "name": "N", "isPro": true})
	p := newP(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"name": "Mapped", "isPro": profile["isPro"], "id": "ignored"}, nil
		}
	})
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || info.User.Name != "Mapped" || info.User.Extra["isPro"] != true || info.User.Extra["id"] != nil {
		t.Fatalf("user %+v %v", info, err)
	}

	called := false
	p = newP(func(o *Options) {
		o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}, Data: map[string]any{"sub": "c"}}, nil
		}
		o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) {
			called = true
			return &oauth2.Tokens{AccessToken: "custom"}, nil
		}
	})
	info, _ = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{})
	tok, _ := p.RefreshAccessToken(context.Background(), "rt", nil)
	if info.User.Name != "custom" || !called || tok.AccessToken != "custom" {
		t.Fatal("overrides not applied")
	}
}
