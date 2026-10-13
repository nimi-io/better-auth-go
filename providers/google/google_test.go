package google

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var verifier = strings.Repeat("v", 64)

func newProvider(mut ...func(*Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "google-client", ClientSecret: "google-secret"}}
	for _, m := range mut {
		m(&o)
	}
	return New(o)
}

func claims(extra map[string]any) map[string]any {
	c := map[string]any{"iss": "https://accounts.google.com", "aud": "google-client", "sub": "g-1",
		"email": "g@example.com", "email_verified": true, "name": "Gee", "picture": "https://p/g.png"}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestAuthorizationURL(t *testing.T) {
	p := newProvider(func(o *Options) { o.AccessType = "offline"; o.Prompt = "consent"; o.HD = "example.com" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: verifier, RedirectURI: "https://app.example/cb", LoginHint: "a@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint || q.Get("scope") != "email profile openid" ||
		q.Get("access_type") != "offline" || q.Get("prompt") != "consent" || q.Get("hd") != "example.com" ||
		q.Get("include_granted_scopes") != "true" || q.Get("login_hint") != "a@example.com" ||
		q.Get("code_challenge") != oauth2.GenerateCodeChallenge(verifier) {
		t.Fatalf("got %s", u)
	}
	off := false
	u, _ = newProvider(func(o *Options) { o.IncludeGrantedScopes = &off }).CreateAuthorizationURL(context.Background(),
		oauth2.AuthorizationURLParams{State: "st", CodeVerifier: verifier, RedirectURI: "https://app.example/cb"})
	if u.Query().Has("include_granted_scopes") {
		t.Fatal("include_granted_scopes must be omitted")
	}
}

func TestAuthorizationURLRequirements(t *testing.T) {
	if _, err := newProvider().CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: "s"}); err == nil {
		t.Fatal("code verifier is required")
	}
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "id"}})
	if _, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: "s", CodeVerifier: verifier}); err == nil {
		t.Fatal("client secret is required")
	}
}

func TestVerifyIDToken(t *testing.T) {
	m := oauth2test.New(t)
	m.ServeJWKS("GET www.googleapis.com/oauth2/v3/certs")
	p := newProvider()
	ctx := context.Background()
	cases := []struct {
		name  string
		token string
		nonce string
		ok    bool
	}{
		{"valid", m.IDToken(claims(nil)), "", true},
		{"short issuer", m.IDToken(claims(map[string]any{"iss": "accounts.google.com"})), "", true},
		{"nonce", m.IDToken(claims(map[string]any{"nonce": "n"})), "n", true},
		{"nonce mismatch", m.IDToken(claims(map[string]any{"nonce": "n"})), "x", false},
		{"wrong audience", m.IDToken(claims(map[string]any{"aud": "other"})), "", false},
		{"wrong issuer", m.IDToken(claims(map[string]any{"iss": "https://evil.example"})), "", false},
		{"too old", m.IDToken(claims(map[string]any{"iat": time.Now().Add(-2 * time.Hour).Unix()})), "", false},
	}
	for _, c := range cases {
		ok, _ := p.VerifyIDToken(ctx, c.token, c.nonce)
		if ok != c.ok {
			t.Errorf("%s: got %v want %v", c.name, ok, c.ok)
		}
	}
	multi := newProvider(func(o *Options) { o.ClientIDs = []string{"web", "ios"}; o.ClientID = "" })
	if ok, _ := multi.VerifyIDToken(ctx, m.IDToken(claims(map[string]any{"aud": "ios"})), ""); !ok {
		t.Error("any configured client id is an accepted audience")
	}
	hd := newProvider(func(o *Options) { o.HD = "example.com" })
	if ok, _ := hd.VerifyIDToken(ctx, m.IDToken(claims(nil)), ""); ok {
		t.Error("hd restriction must reject tokens without hd")
	}
	if ok, _ := hd.VerifyIDToken(ctx, m.IDToken(claims(map[string]any{"hd": "example.com"})), ""); !ok {
		t.Error("matching hd must be accepted")
	}
	disabled := newProvider(func(o *Options) { o.DisableIDTokenSignIn = true })
	if ok, _ := disabled.VerifyIDToken(ctx, m.IDToken(claims(nil)), ""); ok {
		t.Error("disableIdTokenSignIn must reject")
	}
}

func TestExchangeAndUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	idToken := m.IDToken(claims(map[string]any{"hd": "corp.example"}))
	m.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{"access_token": "ya29", "refresh_token": "rt", "expires_in": 3599,
		"scope": "openid email profile", "token_type": "Bearer", "id_token": idToken})
	p := newProvider()
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", CodeVerifier: verifier, RedirectURI: "https://app.example/cb"})
	if err != nil || tok.AccessToken != "ya29" || tok.IDToken != idToken || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("oauth2.googleapis.com/token").Form
	if f.Get("client_id") != "google-client" || f.Get("client_secret") != "google-secret" || f.Get("code_verifier") != verifier {
		t.Fatalf("form %v", f)
	}
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: *tok})
	if err != nil || info.User.Email != "g@example.com" || info.User.Name != "Gee" || info.User.Image != "https://p/g.png" || !info.User.EmailVerified {
		t.Fatalf("%+v %v", info, err)
	}
	if sub, _ := p.AccountSubject(context.Background(), tok, info.Data); sub != "g-1" {
		t.Fatalf("subject %q", sub)
	}
	if info, _ := newProvider(func(o *Options) { o.HD = "example.com" }).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: *tok}); info != nil {
		t.Fatal("hosted domain mismatch must yield nil user info")
	}
	if info, _ := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{}); info != nil {
		t.Fatal("no id token yields nil")
	}
}

func TestHostedDomainAllowed(t *testing.T) {
	for _, c := range []struct {
		cfg string
		hd  any
		ok  bool
	}{{"", nil, true}, {"*", "x.com", true}, {"*", nil, false}, {"a.com", "a.com", true}, {"a.com", "b.com", false}, {"a.com", "", false}} {
		if HostedDomainAllowed(c.cfg, c.hd) != c.ok {
			t.Errorf("%q %v", c.cfg, c.hd)
		}
	}
}
