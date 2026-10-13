package linkedin

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	callback = "https://app.example/callback"
	state    = "state-xyz"
	verifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
)

func creds() oauth2.ProviderOptions {
	return oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"}
}

func TestIdentity(t *testing.T) {
	p := New(Options{ProviderOptions: creds()})
	if p.ID() != "linkedin" || p.Name() != "Linkedin" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok || oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("capabilities")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := creds()
	o.Scope = []string{"w_member_social"}
	p := New(Options{ProviderOptions: o})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: callback, Scopes: []string{"extra"},
		LoginHint: "user@example.com", AdditionalParams: map[string]string{"custom": "value", "redirect_uri": "https://attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint || q.Get("client_id") != "client-123" || q.Get("state") != state ||
		q.Get("response_type") != "code" || q.Get("redirect_uri") != callback ||
		q.Get("scope") != "profile email openid w_member_social extra" || q.Get("login_hint") != "user@example.com" ||
		q.Get("custom") != "value" || q.Has("code_challenge") {
		t.Fatalf("url %s", u)
	}
	o.DisableDefaultScope = true
	o.RedirectURI = "https://override.example/cb"
	u, _ = New(Options{ProviderOptions: o}).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Get("scope") != "w_member_social" || u.Query().Get("redirect_uri") != "https://override.example/cb" {
		t.Fatalf("url %s", u)
	}
}

func TestValidateAuthorizationCodeAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST www.linkedin.com/oauth/v2/accessToken", 200, map[string]any{"access_token": "li-at", "expires_in": 5184000, "refresh_token": "li-rt", "refresh_token_expires_in": 31536000, "scope": "email,openid,profile", "id_token": "x.y.z"})
	p := New(Options{ProviderOptions: creds()})
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "code-1", RedirectURI: callback, CodeVerifier: verifier})
	if err != nil || tok.AccessToken != "li-at" || tok.RefreshToken != "li-rt" || tok.RefreshTokenExpiresAt == nil || tok.IDToken != "x.y.z" {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("www.linkedin.com/oauth/v2/accessToken").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "code-1" || f.Has("code_verifier") ||
		f.Get("redirect_uri") != callback || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	if _, err := p.RefreshAccessToken(context.Background(), "li-rt", nil); err != nil {
		t.Fatal(err)
	}
	f = m.Last("www.linkedin.com/oauth/v2/accessToken").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "li-rt" || f.Get("client_id") != "client-123" {
		t.Fatalf("form %v", f)
	}
}

func userInfo(t *testing.T, o Options, prof map[string]any) *oauth2.UserInfoResult {
	t.Helper()
	m := oauth2test.New(t)
	m.JSON("GET api.linkedin.com/v2/userinfo", 200, prof)
	res, err := New(o).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "li-at"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := m.Last("api.linkedin.com/v2/userinfo"); r.Header.Get("Authorization") != "Bearer li-at" {
		t.Fatalf("headers %v", r.Header)
	}
	return res
}

func TestGetUserInfo(t *testing.T) {
	prof := map[string]any{"sub": "782bbtaQ", "name": "John Doe", "given_name": "John", "family_name": "Doe",
		"picture": "https://media.licdn.com/pic.jpg", "locale": map[string]any{"country": "US", "language": "en"},
		"email": "doe@email.com", "email_verified": true}
	res := userInfo(t, Options{ProviderOptions: creds()}, prof)
	u := res.User
	if u.Name != "John Doe" || u.Email != "doe@email.com" || !u.EmailVerified || u.Image != "https://media.licdn.com/pic.jpg" {
		t.Fatalf("user %+v", u)
	}
	if sub, err := New(Options{ProviderOptions: creds()}).AccountSubject(context.Background(), nil, res.Data); err != nil || sub != "782bbtaQ" {
		t.Fatalf("subject %q %v", sub, err)
	}
	// email_verified ?? false, email optional
	res = userInfo(t, Options{ProviderOptions: creds()}, map[string]any{"sub": "s", "name": "N"})
	if res.User.EmailVerified || res.User.Email != "" {
		t.Fatalf("user %+v", res.User)
	}
}

func TestMapProfileToUserAndErrors(t *testing.T) {
	o := creds()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"name": p["given_name"], "firstName": p["given_name"]}, nil
	}
	res := userInfo(t, Options{ProviderOptions: o}, map[string]any{"sub": "s", "name": "John Doe", "given_name": "John"})
	if res.User.Name != "John" || res.User.Extra["firstName"] != "John" {
		t.Fatalf("%+v", res.User)
	}
	m := oauth2test.New(t)
	m.JSON("GET api.linkedin.com/v2/userinfo", 401, map[string]any{"message": "Invalid access token"})
	r, err := New(Options{ProviderOptions: creds()}).GetUserInfo(context.Background(), oauth2.UserInfoParams{})
	if r != nil || err != nil {
		t.Fatalf("%v %v", r, err)
	}
}
