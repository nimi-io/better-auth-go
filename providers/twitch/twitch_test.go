package twitch

import (
	"context"
	"encoding/json"
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
	if p.ID() != "twitch" || p.Name() != "Twitch" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok || oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("capabilities")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := creds()
	o.Scope = []string{"channel:read:subscriptions"}
	u, err := New(Options{ProviderOptions: o}).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: callback, Scopes: []string{"bits:read"},
		AdditionalParams: map[string]string{"force_verify": "true", "nonce": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint || q.Get("client_id") != "client-123" || q.Get("state") != state ||
		q.Get("response_type") != "code" || q.Get("redirect_uri") != callback ||
		q.Get("scope") != "user:read:email openid channel:read:subscriptions bits:read" ||
		q.Get("force_verify") != "true" || q.Has("nonce") || q.Has("code_challenge") {
		t.Fatalf("url %s", u)
	}
	if q.Get("claims") != `{"id_token":{"email":null,"email_verified":null,"preferred_username":null,"picture":null}}` {
		t.Fatalf("claims %s", q.Get("claims"))
	}
}

func TestAuthorizationURLClaims(t *testing.T) {
	u, _ := New(Options{ProviderOptions: creds(), Claims: []string{"picture", "updated_at"}}).CreateAuthorizationURL(context.Background(),
		oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Get("claims") != `{"id_token":{"email":null,"email_verified":null,"picture":null,"updated_at":null}}` {
		t.Fatalf("claims %s", u.Query().Get("claims"))
	}
	// [] is truthy upstream: only the base claims are requested
	u, _ = New(Options{ProviderOptions: creds(), Claims: []string{}}).CreateAuthorizationURL(context.Background(),
		oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Get("claims") != `{"id_token":{"email":null,"email_verified":null}}` {
		t.Fatalf("claims %s", u.Query().Get("claims"))
	}
	o := creds()
	o.DisableDefaultScope = true
	u, _ = New(Options{ProviderOptions: o}).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Has("scope") {
		t.Fatalf("url %s", u)
	}
}

func TestValidateAuthorizationCodeAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST id.twitch.tv/oauth2/token", 200, map[string]any{"access_token": "tw-at", "refresh_token": "tw-rt", "expires_in": 14124,
		"scope": []string{"openid", "user:read:email"}, "token_type": "bearer", "id_token": "h.p.s"})
	p := New(Options{ProviderOptions: creds()})
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "code-1", RedirectURI: callback, CodeVerifier: verifier})
	if err != nil || tok.AccessToken != "tw-at" || tok.IDToken != "h.p.s" || len(tok.Scopes) != 2 || tok.Scopes[1] != "user:read:email" {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("id.twitch.tv/oauth2/token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "code-1" || f.Has("code_verifier") ||
		f.Get("redirect_uri") != callback || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	if _, err := p.RefreshAccessToken(context.Background(), "tw-rt", nil); err != nil {
		t.Fatal(err)
	}
	f = m.Last("id.twitch.tv/oauth2/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "tw-rt" || f.Get("client_id") != "client-123" {
		t.Fatalf("form %v", f)
	}
}

func TestGetUserInfoFromIDToken(t *testing.T) {
	m := oauth2test.New(t)
	idToken := m.IDToken(map[string]any{"iss": "https://id.twitch.tv/oauth2", "aud": "client-123", "sub": "713936733",
		"preferred_username": "streamer", "email": "s@example.com", "email_verified": true, "picture": "https://static-cdn.jtvnw.net/p.png"})
	p := New(Options{ProviderOptions: creds()})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "tw-at", IDToken: idToken}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	u := res.User
	if u.Name != "streamer" || u.Email != "s@example.com" || !u.EmailVerified || u.Image != "https://static-cdn.jtvnw.net/p.png" {
		t.Fatalf("user %+v", u)
	}
	if sub, err := p.AccountSubject(context.Background(), nil, res.Data); err != nil || sub != "713936733" {
		t.Fatalf("subject %q %v", sub, err)
	}
	// no HTTP request is made: the id token is decoded locally
	if len(m.Requests) != 0 {
		t.Fatalf("unexpected requests %v", m.Requests)
	}
	// missing id token -> null
	res, err = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "tw-at"}})
	if res != nil || err != nil {
		t.Fatalf("%v %v", res, err)
	}
	// malformed id token -> decodeJwt throws
	if _, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: "not-a-jwt"}}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	idToken := m.IDToken(map[string]any{"sub": "1", "preferred_username": "streamer", "email": "s@example.com", "email_verified": false})
	o := creds()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"id": "ignored", "name": "Mapped " + p["preferred_username"].(string), "emailVerified": true, "login": p["preferred_username"]}, nil
	}
	p := New(Options{ProviderOptions: o})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idToken}})
	if err != nil || res.User.Name != "Mapped streamer" || !res.User.EmailVerified || res.User.Extra["login"] != "streamer" {
		t.Fatalf("%+v %v", res, err)
	}
	if sub, _ := p.AccountSubject(context.Background(), nil, res.Data); sub != "1" {
		t.Fatalf("subject %q", sub)
	}
	b, _ := json.Marshal(res.Data)
	if len(b) == 0 {
		t.Fatal("data")
	}
}
