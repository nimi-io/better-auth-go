package railway

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	cb       = "https://app.example/callback"
	state    = "state-xyz"
	clientID = "railway-test-client-id"
	secret   = "railway-test-client-secret"
)

var verifier = strings.Repeat("v", 64)

func newP(mut func(o *Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: secret}}
	if mut != nil {
		mut(&o)
	}
	return New(o)
}

// upstream: "should configure Railway provider correctly"
func TestIdentity(t *testing.T) {
	p := newP(nil)
	if p.ID() != "railway" || p.Name() != "Railway" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
}

// upstream: "should initiate Railway OAuth flow with PKCE"
func TestAuthorizationURL(t *testing.T) {
	p := newP(func(o *Options) { o.Prompt = "consent" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb})
	if err != nil {
		t.Fatal(err)
	}
	want := AuthorizationEndpoint + "?response_type=code&client_id=railway-test-client-id&state=state-xyz&scope=openid+email+profile" +
		"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=" + oauth2.GenerateCodeChallenge(verifier)
	if u.String() != want {
		t.Fatalf("got  %s\nwant %s", u, want)
	}
	p = newP(func(o *Options) { o.DisableDefaultScope = true; o.Scope = []string{"workspace:viewer"} })
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb, Scopes: []string{"offline_access"}})
	if u.Query().Get("scope") != "workspace:viewer offline_access" {
		t.Fatalf("url %s", u)
	}
}

// upstream: "should complete Railway OAuth flow and create user"
func TestExchangeUserInfoAndRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST backboard.railway.com/oauth/token", 200, map[string]any{
		"access_token": "railway_access_token", "token_type": "Bearer", "expires_in": 3600,
	})
	m.JSON("GET backboard.railway.com/oauth/me", 200, map[string]any{
		"sub": "user_railway_123", "email": "railway@test.com", "name": "Railway User",
		"picture": "https://avatars.githubusercontent.com/u/12345",
	})
	p := newP(nil)
	ctx := context.Background()
	tok, err := p.ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "railway_test_code", CodeVerifier: verifier, RedirectURI: cb})
	if err != nil || tok.AccessToken != "railway_access_token" {
		t.Fatalf("tokens %+v %v", tok, err)
	}
	r := m.Last("backboard.railway.com/oauth/token")
	wantAuth := oauth2.EncodeBasicCredentials(clientID, secret)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") || r.Header.Get("Authorization") != wantAuth {
		t.Fatalf("authorization %q", r.Header.Get("Authorization"))
	}
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "railway_test_code" ||
		r.Form.Get("redirect_uri") != cb || r.Form.Get("code_verifier") != verifier ||
		r.Form.Has("client_secret") || r.Form.Has("client_id") {
		t.Fatalf("token request %s", r.Body)
	}

	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: *tok})
	if err != nil || info == nil {
		t.Fatalf("user info %v %v", info, err)
	}
	if m.Last("backboard.railway.com/oauth/me").Header.Get("Authorization") != "Bearer railway_access_token" {
		t.Fatal("missing bearer")
	}
	// Railway does not provide email_verified; it defaults to false.
	if info.User.Email != "railway@test.com" || info.User.Name != "Railway User" ||
		info.User.Image != "https://avatars.githubusercontent.com/u/12345" || info.User.EmailVerified {
		t.Fatalf("user %+v", info.User)
	}
	if sub, _ := p.AccountSubject(ctx, tok, info.Data); sub != "user_railway_123" {
		t.Fatalf("subject %q", sub)
	}

	if _, err := p.RefreshAccessToken(ctx, "railway_rt", nil); err != nil {
		t.Fatal(err)
	}
	r = m.Last("backboard.railway.com/oauth/token")
	if r.Header.Get("Authorization") != wantAuth || r.Form.Get("grant_type") != "refresh_token" ||
		r.Form.Get("refresh_token") != "railway_rt" || r.Form.Has("client_secret") {
		t.Fatalf("refresh request %s %v", r.Body, r.Header)
	}
}

func TestBasicRequiresSecret(t *testing.T) {
	oauth2test.New(t)
	p := newP(func(o *Options) { o.ClientSecret = "" })
	if _, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", RedirectURI: cb}); err == nil {
		t.Fatal("expected client_secret_basic error without client secret")
	}
}

func TestUserInfoErrorsAndMapping(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET backboard.railway.com/oauth/me", 403, map[string]any{"error": "forbidden"})
	p := newP(nil)
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if info != nil || err != nil {
		t.Fatalf("expected nil: %+v %v", info, err)
	}
	m.JSON("GET backboard.railway.com/oauth/me", 200, map[string]any{"sub": "s", "email": "e@x.y", "name": "N"})
	p = newP(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"emailVerified": true, "railwayId": profile["sub"]}, nil
		}
	})
	info, err = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || !info.User.EmailVerified || info.User.Extra["railwayId"] != "s" {
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
