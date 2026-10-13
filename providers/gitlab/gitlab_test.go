package gitlab

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
	if p.ID() != "gitlab" || p.Name() != "Gitlab" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok || oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("capabilities")
	}
}

func TestIssuerEndpoints(t *testing.T) {
	e := IssuerEndpoints("")
	if e.Authorization != AuthorizationEndpoint || e.Token != TokenEndpoint || e.UserInfo != UserEndpoint {
		t.Fatalf("%+v", e)
	}
	e = IssuerEndpoints("https://git.example.com/")
	if e.Authorization != "https://git.example.com/oauth/authorize" || e.Token != "https://git.example.com/oauth/token" || e.UserInfo != "https://git.example.com/api/v4/user" {
		t.Fatalf("%+v", e)
	}
	e = IssuerEndpoints("https://git.example.com//gitlab//")
	if e.Authorization != "https://git.example.com/gitlab/oauth/authorize" {
		t.Fatalf("%+v", e)
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := creds()
	o.Scope = []string{"api"}
	o.Prompt = "consent" // not forwarded upstream
	p := New(Options{ProviderOptions: o})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: callback, Scopes: []string{"openid"},
		LoginHint: "user@example.com", AdditionalParams: map[string]string{"custom": "value", "scope": "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint || q.Get("client_id") != "client-123" || q.Get("state") != state ||
		q.Get("response_type") != "code" || q.Get("redirect_uri") != callback ||
		// order: defaults, options.scope, request scopes
		q.Get("scope") != "read_user api openid" || q.Get("login_hint") != "user@example.com" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != oauth2.GenerateCodeChallenge(verifier) ||
		q.Get("custom") != "value" || q.Has("prompt") {
		t.Fatalf("url %s", u)
	}
	// self-hosted issuer + disableDefaultScope
	o = creds()
	o.DisableDefaultScope = true
	p = New(Options{ProviderOptions: o, Issuer: "https://git.example.com"})
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Host != "git.example.com" || u.Path != "/oauth/authorize" || u.Query().Has("scope") || u.Query().Has("code_challenge") {
		t.Fatalf("url %s", u)
	}
}

func TestValidateAuthorizationCodeAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST git.example.com/oauth/token", 200, map[string]any{"access_token": "glat", "refresh_token": "glrt", "token_type": "Bearer", "expires_in": 7200, "scope": "read_user"})
	p := New(Options{ProviderOptions: creds(), Issuer: "https://git.example.com"})
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "code-1", RedirectURI: callback, CodeVerifier: verifier})
	if err != nil || tok.AccessToken != "glat" || tok.RefreshToken != "glrt" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("git.example.com/oauth/token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "code-1" || f.Get("code_verifier") != verifier ||
		f.Get("redirect_uri") != callback || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	tok, err = p.RefreshAccessToken(context.Background(), "glrt", nil)
	if err != nil || tok.AccessToken != "glat" {
		t.Fatalf("%+v %v", tok, err)
	}
	f = m.Last("git.example.com/oauth/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "glrt" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
}

func profile(over map[string]any) map[string]any {
	p := map[string]any{"id": 12345, "username": "jdoe", "name": "Jane Doe", "email": "jane@example.com",
		"state": "active", "avatar_url": "https://gitlab.com/avatar.png", "web_url": "https://gitlab.com/jdoe"}
	for k, v := range over {
		if v == "<delete>" {
			delete(p, k)
		} else {
			p[k] = v
		}
	}
	return p
}

func userInfo(t *testing.T, o Options, prof map[string]any) *oauth2.UserInfoResult {
	t.Helper()
	m := oauth2test.New(t)
	m.JSON("GET gitlab.com/api/v4/user", 200, prof)
	res, err := New(o).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "glat"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := m.Last("gitlab.com/api/v4/user"); r.Header.Get("Authorization") != "Bearer glat" {
		t.Fatalf("headers %v", r.Header)
	}
	return res
}

func TestGetUserInfo(t *testing.T) {
	res := userInfo(t, Options{ProviderOptions: creds()}, profile(nil))
	u := res.User
	if u.Name != "Jane Doe" || u.Email != "jane@example.com" || u.Image != "https://gitlab.com/avatar.png" || u.EmailVerified {
		t.Fatalf("user %+v", u)
	}
	sub, err := New(Options{ProviderOptions: creds()}).AccountSubject(context.Background(), nil, res.Data)
	if err != nil || sub != "12345" {
		t.Fatalf("subject %q %v", sub, err)
	}
	if u := userInfo(t, Options{ProviderOptions: creds()}, profile(map[string]any{"email_verified": true})).User; !u.EmailVerified {
		t.Fatal("email_verified")
	}
	// name ?? username ?? ""
	if u := userInfo(t, Options{ProviderOptions: creds()}, profile(map[string]any{"name": nil})).User; u.Name != "jdoe" {
		t.Fatalf("name %q", u.Name)
	}
	if u := userInfo(t, Options{ProviderOptions: creds()}, profile(map[string]any{"name": ""})).User; u.Name != "" {
		t.Fatalf("name %q", u.Name)
	}
	if u := userInfo(t, Options{ProviderOptions: creds()}, profile(map[string]any{"name": "<delete>", "username": "<delete>"})).User; u.Name != "" {
		t.Fatalf("name %q", u.Name)
	}
}

func TestGetUserInfoRejectsInactiveOrLocked(t *testing.T) {
	for _, over := range []map[string]any{{"state": "blocked"}, {"state": "<delete>"}, {"locked": true}} {
		if res := userInfo(t, Options{ProviderOptions: creds()}, profile(over)); res != nil {
			t.Fatalf("%v: expected null, got %+v", over, res)
		}
	}
	if res := userInfo(t, Options{ProviderOptions: creds()}, profile(map[string]any{"locked": false})); res == nil {
		t.Fatal("locked:false should be accepted")
	}
	m := oauth2test.New(t)
	m.JSON("GET gitlab.com/api/v4/user", 401, map[string]any{"message": "401 Unauthorized"})
	res, err := New(Options{ProviderOptions: creds()}).GetUserInfo(context.Background(), oauth2.UserInfoParams{})
	if res != nil || err != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUser(t *testing.T) {
	o := creds()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"id": "nope", "image": p["web_url"], "emailVerified": true, "username": p["username"]}, nil
	}
	res := userInfo(t, Options{ProviderOptions: o}, profile(nil))
	if res.User.Image != "https://gitlab.com/jdoe" || !res.User.EmailVerified || res.User.Extra["username"] != "jdoe" {
		t.Fatalf("%+v", res.User)
	}
	if sub, _ := New(Options{ProviderOptions: o}).AccountSubject(context.Background(), nil, res.Data); sub != "12345" {
		t.Fatalf("subject %q", sub)
	}
}
