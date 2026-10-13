package naver

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	callback = "https://app.example/callback"
	state    = "state-xyz"
)

var verifier = strings.Repeat("v", 64)

func newProvider(mut ...func(*Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"}}
	for _, m := range mut {
		m(&o)
	}
	return New(o)
}

func TestIdentity(t *testing.T) {
	p := newProvider()
	if p.ID() != "naver" || p.Name() != "Naver" {
		t.Fatalf("got %q %q", p.ID(), p.Name())
	}
	if p.S.Subject == nil || !p.SupportsRefresh() || p.SupportsIDToken() {
		t.Fatal("capabilities mismatch")
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newProvider(func(o *Options) { o.Prompt = "consent" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: callback, LoginHint: "hint",
		AdditionalParams: map[string]string{"auth_type": "reprompt", "client_id": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantRaw := "response_type=code&client_id=client-123&state=state-xyz&scope=profile+email&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&auth_type=reprompt"
	if got := u.Scheme + "://" + u.Host + u.Path; got != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", got)
	}
	if u.RawQuery != wantRaw {
		t.Fatalf("raw query\n got %s\nwant %s", u.RawQuery, wantRaw)
	}
}

func TestAuthorizationURLOptions(t *testing.T) {
	p := newProvider(func(o *Options) {
		o.Scope = []string{"birthday"}
		o.RedirectURI = "https://override.example/cb"
		o.AuthorizationEndpoint = "https://proxy.example/authorize"
	})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback, Scopes: []string{"mobile"}})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "proxy.example" || q.Get("scope") != "profile email birthday mobile" || q.Get("redirect_uri") != "https://override.example/cb" {
		t.Fatalf("got %s", u)
	}
	u, _ = newProvider(func(o *Options) { o.DisableDefaultScope = true }).CreateAuthorizationURL(context.Background(),
		oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Has("scope") {
		t.Fatal("scope must be omitted")
	}
	if _, err := New(Options{}).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state}); err == nil {
		t.Fatal("expected clientId error")
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST nid.naver.com/oauth2.0/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "token_type": "bearer", "expires_in": "3600",
	})
	tok, err := newProvider().ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "auth-code", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil {
		t.Fatal(err)
	}
	// Naver returns expires_in as a string
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("tokens %+v", tok)
	}
	f := m.Last("nid.naver.com/oauth2.0/token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "auth-code" || f.Get("redirect_uri") != callback ||
		f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" || f.Has("code_verifier") {
		t.Fatalf("form %v", f)
	}
	p := newProvider(func(o *Options) { o.RedirectURI = "https://override.example/cb" })
	_, _ = p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", RedirectURI: callback})
	if got := m.Last("nid.naver.com/oauth2.0/token").Form.Get("redirect_uri"); got != "https://override.example/cb" {
		t.Fatalf("redirect_uri %s", got)
	}
}

var profile = map[string]any{
	"resultcode": "00", "message": "success",
	"response": map[string]any{
		"id": "naver-id-1", "nickname": "nick", "name": "Real Name", "email": "user@naver.com",
		"profile_image": "https://img/p.png", "gender": "M", "mobile": "010-0000-0000",
	},
}

func TestGetUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET openapi.naver.com/v1/nid/me", 200, profile)
	p := newProvider()
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if h := m.Last("openapi.naver.com/v1/nid/me").Header.Get("Authorization"); h != "Bearer at" {
		t.Fatalf("auth %q", h)
	}
	u := res.User
	if u.Name != "Real Name" || u.Email != "user@naver.com" || u.Image != "https://img/p.png" || u.EmailVerified {
		t.Fatalf("user %+v", u)
	}
	if res.Data["resultcode"] != "00" {
		t.Fatal("data must be the full API envelope")
	}
	sub, err := p.AccountSubject(context.Background(), nil, res.Data)
	if err != nil || sub != "naver-id-1" {
		t.Fatalf("subject %q %v", sub, err)
	}
	if sub, _ := p.AccountSubject(context.Background(), nil, map[string]any{}); sub != "" {
		t.Fatalf("missing response must yield no subject, got %q", sub)
	}
}

func TestGetUserInfoNicknameFallback(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("openapi.naver.com/v1/nid/me", 200, map[string]any{"resultcode": "00", "response": map[string]any{"id": "1", "nickname": "nick"}})
	res, _ := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res == nil || res.User.Name != "nick" {
		t.Fatalf("%+v", res)
	}
}

func TestGetUserInfoFailures(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("openapi.naver.com/v1/nid/me", 200, map[string]any{"resultcode": "024", "message": "Authentication failed"})
	if res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}}); res != nil || err != nil {
		t.Fatalf("non-00 resultcode must yield null: %v %v", res, err)
	}
	m.JSON("openapi.naver.com/v1/nid/me", 401, map[string]any{"resultcode": "024"})
	if res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}}); res != nil || err != nil {
		t.Fatalf("HTTP error must yield null: %v %v", res, err)
	}
}

func TestMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("openapi.naver.com/v1/nid/me", 200, profile)
	p := newProvider(func(o *Options) {
		o.MapProfileToUser = func(pr map[string]any) (map[string]any, error) {
			r := pr["response"].(map[string]any)
			return map[string]any{"name": r["nickname"], "emailVerified": true, "gender": r["gender"]}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "nick" || !res.User.EmailVerified || res.User.Extra["gender"] != "M" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	oauth2test.New(t)
	p := newProvider(func(o *Options) {
		o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}}, nil
		}
	})
	res, _ := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{})
	if res.User.Name != "custom" {
		t.Fatal("override not used")
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST nid.naver.com/oauth2.0/token", 200, map[string]any{"access_token": "new-at", "token_type": "bearer", "expires_in": "3600"})
	tok, err := newProvider().RefreshAccessToken(context.Background(), "old-rt", nil)
	if err != nil || tok.AccessToken != "new-at" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("nid.naver.com/oauth2.0/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "old-rt" || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	p := newProvider(func(o *Options) {
		o.RefreshAccessToken = func(_ context.Context, rt string) (*oauth2.Tokens, error) {
			return &oauth2.Tokens{AccessToken: "custom-" + rt}, nil
		}
	})
	if tok, _ := p.RefreshAccessToken(context.Background(), "rt", nil); tok.AccessToken != "custom-rt" {
		t.Fatal("override not used")
	}
}
