package spotify

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
	if p.ID() != "spotify" || p.Name() != "Spotify" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok || oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("capabilities")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := creds()
	o.Scope = []string{"user-read-private"}
	u, err := New(Options{ProviderOptions: o}).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: callback, Scopes: []string{"playlist-read-private"},
		LoginHint: "ignored", AdditionalParams: map[string]string{"show_dialog": "true", "code_challenge": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint || q.Get("client_id") != "client-123" || q.Get("state") != state ||
		q.Get("response_type") != "code" || q.Get("redirect_uri") != callback ||
		q.Get("scope") != "user-read-email user-read-private playlist-read-private" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != oauth2.GenerateCodeChallenge(verifier) ||
		q.Get("show_dialog") != "true" || q.Has("login_hint") {
		t.Fatalf("url %s", u)
	}
	o.DisableDefaultScope = true
	u, _ = New(Options{ProviderOptions: o}).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Get("scope") != "user-read-private" || u.Query().Has("code_challenge") {
		t.Fatalf("url %s", u)
	}
}

func TestValidateAuthorizationCodeAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST accounts.spotify.com/api/token", 200, map[string]any{"access_token": "sp-at", "token_type": "Bearer", "scope": "user-read-email", "expires_in": 3600, "refresh_token": "sp-rt"})
	p := New(Options{ProviderOptions: creds()})
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "code-1", RedirectURI: callback, CodeVerifier: verifier})
	if err != nil || tok.AccessToken != "sp-at" || tok.RefreshToken != "sp-rt" || len(tok.Scopes) != 1 {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("accounts.spotify.com/api/token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "code-1" || f.Get("code_verifier") != verifier ||
		f.Get("redirect_uri") != callback || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	if _, err := p.RefreshAccessToken(context.Background(), "sp-rt", nil); err != nil {
		t.Fatal(err)
	}
	f = m.Last("accounts.spotify.com/api/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "sp-rt" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
}

func userInfo(t *testing.T, o Options, prof map[string]any) (*oauth2.UserInfoResult, error) {
	t.Helper()
	m := oauth2test.New(t)
	m.JSON("GET api.spotify.com/v1/me", 200, prof)
	res, err := New(o).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "sp-at"}})
	if r := m.Last("api.spotify.com/v1/me"); r.Header.Get("Authorization") != "Bearer sp-at" {
		t.Fatalf("headers %v", r.Header)
	}
	return res, err
}

func TestGetUserInfo(t *testing.T) {
	prof := map[string]any{"id": "wizzler", "display_name": "Wizzler", "email": "w@example.com",
		"images": []any{map[string]any{"url": "https://i.scdn.co/image/1"}, map[string]any{"url": "https://i.scdn.co/image/2"}}}
	res, err := userInfo(t, Options{ProviderOptions: creds()}, prof)
	if err != nil {
		t.Fatal(err)
	}
	u := res.User
	if u.Name != "Wizzler" || u.Email != "w@example.com" || u.EmailVerified || u.Image != "https://i.scdn.co/image/1" {
		t.Fatalf("user %+v", u)
	}
	if sub, err := New(Options{ProviderOptions: creds()}).AccountSubject(context.Background(), nil, res.Data); err != nil || sub != "wizzler" {
		t.Fatalf("subject %q %v", sub, err)
	}
	prof["images"] = []any{}
	prof["display_name"] = nil
	res, _ = userInfo(t, Options{ProviderOptions: creds()}, prof)
	if res.User.Image != "" || res.User.Name != "" {
		t.Fatalf("user %+v", res.User)
	}
	// profile.images[0] throws upstream when images is missing
	delete(prof, "images")
	if _, err := userInfo(t, Options{ProviderOptions: creds()}, prof); err == nil {
		t.Fatal("expected error")
	}
}

func TestMapProfileToUserAndErrors(t *testing.T) {
	o := creds()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"emailVerified": true, "country": p["country"]}, nil
	}
	res, err := userInfo(t, Options{ProviderOptions: o}, map[string]any{"id": "x", "country": "SE", "images": []any{}})
	if err != nil || !res.User.EmailVerified || res.User.Extra["country"] != "SE" {
		t.Fatalf("%+v %v", res, err)
	}
	m := oauth2test.New(t)
	m.JSON("GET api.spotify.com/v1/me", 401, map[string]any{"error": map[string]any{"status": 401, "message": "Invalid access token"}})
	r, err := New(Options{ProviderOptions: creds()}).GetUserInfo(context.Background(), oauth2.UserInfoParams{})
	if r != nil || err != nil {
		t.Fatalf("%v %v", r, err)
	}
}
