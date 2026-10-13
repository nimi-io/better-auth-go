package atlassian

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
	if p.ID() != "atlassian" || p.Name() != "Atlassian" {
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
		State: state, CodeVerifier: verifier, RedirectURI: cb, LoginHint: "ignored@x.y",
		AdditionalParams: map[string]string{"audience": "evil.example", "foo": "bar"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := AuthorizationEndpoint + "?response_type=code&client_id=client-123&state=state-xyz&scope=read%3Ajira-user+offline_access" +
		"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&prompt=consent&code_challenge_method=S256&code_challenge=" +
		oauth2.GenerateCodeChallenge(verifier) + "&audience=api.atlassian.com&foo=bar"
	if u.String() != want {
		t.Fatalf("got  %s\nwant %s", u, want)
	}
}

func TestAuthorizationURLScopes(t *testing.T) {
	p := newP(func(o *Options) { o.Scope = []string{"read:me"} })
	u, _ := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: cb, Scopes: []string{"write:jira-work"},
	})
	if got := u.Query().Get("scope"); got != "read:jira-user offline_access read:me write:jira-work" {
		t.Fatalf("scope %q", got)
	}
	p = newP(func(o *Options) { o.DisableDefaultScope = true; o.Scope = []string{"read:me"} })
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb})
	if got := u.Query().Get("scope"); got != "read:me" {
		t.Fatalf("scope %q", got)
	}
}

func TestAuthorizationURLRequirements(t *testing.T) {
	p := newP(func(o *Options) { o.ClientSecret = "" })
	if _, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb}); !errors.Is(err, ErrClientIDAndSecretRequired) {
		t.Fatalf("err %v", err)
	}
	p = newP(func(o *Options) { o.ClientID = "" })
	if _, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb}); err == nil || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
		t.Fatalf("err %v", err)
	}
	p = newP(nil)
	if _, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: cb}); err == nil || err.Error() != "codeVerifier is required for Atlassian" {
		t.Fatalf("err %v", err)
	}
}

func TestExchangeUserInfoAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST auth.atlassian.com/oauth/token", 200, map[string]any{
		"access_token": "atl_at", "refresh_token": "atl_rt", "token_type": "Bearer", "expires_in": 3600, "scope": "read:jira-user offline_access",
	})
	m.JSON("GET api.atlassian.com/me", 200, map[string]any{
		"account_id": "acc-123", "account_type": "atlassian", "name": "Atl User", "email": "atl@test.com",
		"picture": "https://atl/avatar.png", "email_verified": true,
	})
	p := newP(func(o *Options) { o.ClientKey = "ck" })
	ctx := context.Background()
	tok, err := p.ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c0de", CodeVerifier: verifier, RedirectURI: cb})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "atl_at" || tok.RefreshToken != "atl_rt" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("tokens %+v", tok)
	}
	r := m.Last("auth.atlassian.com/oauth/token")
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "c0de" || r.Form.Get("code_verifier") != verifier ||
		r.Form.Get("redirect_uri") != cb || r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret ||
		r.Form.Get("client_key") != "ck" {
		t.Fatalf("token request %s", r.Body)
	}

	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: *tok})
	if err != nil || info == nil {
		t.Fatalf("user info %v %v", info, err)
	}
	if m.Last("api.atlassian.com/me").Header.Get("Authorization") != "Bearer atl_at" {
		t.Fatal("missing bearer")
	}
	// Atlassian always reports emailVerified=false.
	if info.User.Name != "Atl User" || info.User.Email != "atl@test.com" || info.User.Image != "https://atl/avatar.png" || info.User.EmailVerified {
		t.Fatalf("user %+v", info.User)
	}
	if sub, _ := p.AccountSubject(ctx, tok, info.Data); sub != "acc-123" {
		t.Fatalf("subject %q", sub)
	}

	if _, err := p.RefreshAccessToken(ctx, "atl_rt", nil); err != nil {
		t.Fatal(err)
	}
	r = m.Last("auth.atlassian.com/oauth/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "atl_rt" ||
		r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret || r.Form.Has("client_key") {
		t.Fatalf("refresh request %s", r.Body)
	}
}

func TestUserInfoFailures(t *testing.T) {
	m := oauth2test.New(t)
	p := newP(nil)
	ctx := context.Background()
	// No access token: no request, null result.
	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{})
	if info != nil || err != nil || len(m.Requests) != 0 {
		t.Fatalf("expected nil without access token: %+v %v", info, err)
	}
	m.JSON("GET api.atlassian.com/me", 500, map[string]any{"error": "boom"})
	info, err = p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if info != nil || err != nil {
		t.Fatalf("expected nil on failure: %+v %v", info, err)
	}
	// mapProfileToUser errors are swallowed (upstream try/catch).
	m.JSON("GET api.atlassian.com/me", 200, map[string]any{"account_id": "a", "name": "n"})
	p = newP(func(o *Options) {
		o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return nil, errors.New("bad") }
	})
	info, err = p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if info != nil || err != nil {
		t.Fatalf("expected nil on mapper failure: %+v %v", info, err)
	}
}

func TestMapProfileToUserAndOverrides(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.atlassian.com/me", 200, map[string]any{
		"account_id": "a1", "name": "N", "extended_profile": map[string]any{"job_title": "Engineer"},
	})
	p := newP(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"emailVerified": true, "jobTitle": oauth2.Path(profile, "extended_profile", "job_title")}, nil
		}
	})
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || !info.User.EmailVerified || info.User.Extra["jobTitle"] != "Engineer" || info.User.Name != "N" {
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
