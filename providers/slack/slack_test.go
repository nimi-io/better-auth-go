package slack

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

func base() oauth2.AuthorizationURLParams {
	return oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: callback}
}

func TestIdentity(t *testing.T) {
	p := New(Options{ProviderOptions: creds()})
	if p.ID() != "slack" || p.Name() != "Slack" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok || oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("capabilities")
	}
}

// upstream: "preserves the authorize URL shape after the shared-helper refactor"
func TestAuthorizationURLShape(t *testing.T) {
	u, err := New(Options{ProviderOptions: creds()}).CreateAuthorizationURL(context.Background(), base())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint || q.Get("client_id") != "client-123" ||
		q.Get("response_type") != "code" || q.Get("scope") != "openid profile email" || q.Get("state") != state ||
		q.Get("redirect_uri") != callback || q.Has("code_challenge") || q.Has("prompt") {
		t.Fatalf("url %s", u)
	}
}

// upstream: "forwards additionalParams while dropping reserved keys"
func TestAuthorizationURLAdditionalParams(t *testing.T) {
	in := base()
	in.AdditionalParams = map[string]string{"team": "T01ABC", "client_id": "attacker"}
	u, _ := New(Options{ProviderOptions: creds()}).CreateAuthorizationURL(context.Background(), in)
	if u.Query().Get("team") != "T01ABC" || u.Query().Get("client_id") != "client-123" {
		t.Fatalf("url %s", u)
	}
}

func TestAuthorizationURLScopeOrder(t *testing.T) {
	o := creds()
	o.Scope = []string{"opt"}
	in := base()
	in.Scopes = []string{"req"}
	in.LoginHint = "ignored"
	u, _ := New(Options{ProviderOptions: o}).CreateAuthorizationURL(context.Background(), in)
	// upstream order: defaults, request scopes, options.scope
	if u.Query().Get("scope") != "openid profile email req opt" || u.Query().Has("login_hint") {
		t.Fatalf("url %s", u)
	}
	o.DisableDefaultScope = true
	u, _ = New(Options{ProviderOptions: o}).CreateAuthorizationURL(context.Background(), in)
	if u.Query().Get("scope") != "req opt" {
		t.Fatalf("url %s", u)
	}
}

func TestValidateAuthorizationCodeAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST slack.com/api/openid.connect.token", 200, map[string]any{"ok": true, "access_token": "xoxp-1", "token_type": "Bearer", "id_token": "a.b.c", "refresh_token": "xoxe-1", "expires_in": 43200})
	p := New(Options{ProviderOptions: creds()})
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "code-1", RedirectURI: callback, CodeVerifier: verifier})
	if err != nil || tok.AccessToken != "xoxp-1" || tok.IDToken != "a.b.c" || tok.RefreshToken != "xoxe-1" {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("slack.com/api/openid.connect.token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "code-1" || f.Has("code_verifier") ||
		f.Get("redirect_uri") != callback || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	if _, err := p.RefreshAccessToken(context.Background(), "xoxe-1", nil); err != nil {
		t.Fatal(err)
	}
	f = m.Last("slack.com/api/openid.connect.token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "xoxe-1" {
		t.Fatalf("form %v", f)
	}
}

func userInfo(t *testing.T, o Options, prof map[string]any) *oauth2.UserInfoResult {
	t.Helper()
	m := oauth2test.New(t)
	m.JSON("GET slack.com/api/openid.connect.userInfo", 200, prof)
	res, err := New(o).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "xoxp-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := m.Last("slack.com/api/openid.connect.userInfo"); r.Header.Get("Authorization") != "Bearer xoxp-1" {
		t.Fatalf("headers %v", r.Header)
	}
	return res
}

func TestGetUserInfo(t *testing.T) {
	prof := map[string]any{"ok": true, "sub": "U0R7JM", "https://slack.com/user_id": "U0R7JM", "https://slack.com/team_id": "T0R7GR",
		"email": "krane@slack-corp.com", "email_verified": true, "name": "krane", "picture": "https://secure.gravatar.com/krane.jpg",
		"https://slack.com/user_image_512": "https://secure.gravatar.com/krane-512.jpg"}
	res := userInfo(t, Options{ProviderOptions: creds()}, prof)
	u := res.User
	if u.Name != "krane" || u.Email != "krane@slack-corp.com" || !u.EmailVerified || u.Image != "https://secure.gravatar.com/krane.jpg" {
		t.Fatalf("user %+v", u)
	}
	if sub, err := New(Options{ProviderOptions: creds()}).AccountSubject(context.Background(), nil, res.Data); err != nil || sub != "U0R7JM" {
		t.Fatalf("subject %q %v", sub, err)
	}
	// image falls back to user_image_512; name || ""
	delete(prof, "picture")
	delete(prof, "name")
	res = userInfo(t, Options{ProviderOptions: creds()}, prof)
	if res.User.Image != "https://secure.gravatar.com/krane-512.jpg" || res.User.Name != "" {
		t.Fatalf("user %+v", res.User)
	}
	// subject comes from the slack user_id claim, not sub
	delete(prof, "https://slack.com/user_id")
	if sub, _ := New(Options{ProviderOptions: creds()}).AccountSubject(context.Background(), nil, prof); sub != "" {
		t.Fatalf("subject %q", sub)
	}
}

func TestMapProfileToUserAndErrors(t *testing.T) {
	o := creds()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"image": p["https://slack.com/user_image_512"], "teamId": p["https://slack.com/team_id"]}, nil
	}
	res := userInfo(t, Options{ProviderOptions: o}, map[string]any{"https://slack.com/user_id": "U1", "picture": "p",
		"https://slack.com/user_image_512": "big", "https://slack.com/team_id": "T1"})
	if res.User.Image != "big" || res.User.Extra["teamId"] != "T1" {
		t.Fatalf("%+v", res.User)
	}
	m := oauth2test.New(t)
	m.JSON("GET slack.com/api/openid.connect.userInfo", 500, map[string]any{"ok": false})
	r, err := New(Options{ProviderOptions: creds()}).GetUserInfo(context.Background(), oauth2.UserInfoParams{})
	if r != nil || err != nil {
		t.Fatalf("%v %v", r, err)
	}
}
