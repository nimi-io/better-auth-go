package vercel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	cb       = "https://app.example/callback"
	state    = "state-xyz"
	clientID = "vercel-test-client-id"
	secret   = "vercel-test-client-secret"
)

var verifier = strings.Repeat("v", 64)

func newP(mut func(o *Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: secret}}
	if mut != nil {
		mut(&o)
	}
	return New(o)
}

// upstream: "should configure Vercel provider correctly"
func TestIdentity(t *testing.T) {
	p := newP(func(o *Options) {
		o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) { return &oauth2.Tokens{}, nil }
	})
	if p.ID() != "vercel" || p.Name() != "Vercel" {
		t.Fatalf("%s %s", p.ID(), p.Name())
	}
	// Upstream Vercel exposes no refreshAccessToken (even when the option is set).
	if _, ok := oauth2.AsRefresher(p); ok {
		t.Fatal("refresh should not be supported")
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("id token sign-in should not be supported")
	}
}

// upstream: "should initiate Vercel OAuth flow with PKCE"
func TestAuthorizationURL(t *testing.T) {
	p := newP(func(o *Options) { o.Prompt = "consent" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb})
	if err != nil {
		t.Fatal(err)
	}
	// No default scopes: the scope parameter is omitted.
	want := AuthorizationEndpoint + "?response_type=code&client_id=vercel-test-client-id&state=state-xyz" +
		"&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=" + oauth2.GenerateCodeChallenge(verifier)
	if u.String() != want {
		t.Fatalf("got  %s\nwant %s", u, want)
	}
	if _, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: cb}); !errors.Is(err, ErrCodeVerifierRequired) ||
		err.Error() != "codeVerifier is required for Vercel" {
		t.Fatalf("err %v", err)
	}
}

// upstream: "should allow additional scopes"
func TestAdditionalScopes(t *testing.T) {
	p := newP(func(o *Options) {
		o.Scope = []string{"openid", "email", "profile", "offline_access"}
		o.DisableDefaultScope = true // no effect: Vercel has no defaults
	})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: cb, Scopes: []string{"extra"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("scope"); got != "openid email profile offline_access extra" {
		t.Fatalf("scope %q", got)
	}
}

// upstream: "should complete Vercel OAuth flow and create user"
func TestExchangeAndUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	idToken := m.IDToken(map[string]any{"sub": "vercel_user_123", "email": "vercel@test.com"})
	m.Handle("POST api.vercel.com/login/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code_verifier") == "" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"vercel_access_token","refresh_token":"vercel_refresh_token","id_token":"` + idToken + `","token_type":"Bearer","expires_in":3600}`))
	})
	m.JSON("GET api.vercel.com/login/oauth/userinfo", 200, map[string]any{
		"sub": "vercel_user_123", "email": "vercel@test.com", "email_verified": true, "name": "Vercel User",
		"preferred_username": "verceluser", "picture": "https://vercel.com/avatar.png",
	})
	p := newP(nil)
	ctx := context.Background()
	tok, err := p.ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "vercel_test_code", CodeVerifier: verifier, RedirectURI: cb})
	if err != nil || tok.AccessToken != "vercel_access_token" || tok.RefreshToken != "vercel_refresh_token" || tok.IDToken != idToken {
		t.Fatalf("tokens %+v %v", tok, err)
	}
	r := m.Last("api.vercel.com/login/oauth/token")
	if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "vercel_test_code" || r.Form.Get("code_verifier") != verifier ||
		r.Form.Get("redirect_uri") != cb || r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
		t.Fatalf("token request %s", r.Body)
	}
	info, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: *tok})
	if err != nil || info == nil {
		t.Fatalf("user info %v %v", info, err)
	}
	if m.Last("api.vercel.com/login/oauth/userinfo").Header.Get("Authorization") != "Bearer vercel_access_token" {
		t.Fatal("missing bearer")
	}
	if info.User.Email != "vercel@test.com" || info.User.Name != "Vercel User" || info.User.Image != "https://vercel.com/avatar.png" || !info.User.EmailVerified {
		t.Fatalf("user %+v", info.User)
	}
	if sub, _ := p.AccountSubject(ctx, tok, info.Data); sub != "vercel_user_123" {
		t.Fatalf("subject %q", sub)
	}
	if _, err := p.RefreshAccessToken(ctx, "vercel_refresh_token", nil); err == nil {
		t.Fatal("refresh should be unsupported")
	}
}

// upstream: "should use preferred_username as fallback for name"
func TestPreferredUsernameFallback(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.vercel.com/login/oauth/userinfo", 200, map[string]any{
		"sub": "vercel_user_456", "email": "noname@vercel.com", "email_verified": true,
		"preferred_username": "cooldev", "picture": "https://vercel.com/avatar2.png",
	})
	p := newP(nil)
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || info.User.Name != "cooldev" {
		t.Fatalf("user %+v %v", info, err)
	}
	// name ?? preferred_username: an empty (non-null) name is kept.
	m.JSON("GET api.vercel.com/login/oauth/userinfo", 200, map[string]any{"sub": "s", "name": "", "preferred_username": "cooldev"})
	info, _ = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if info.User.Name != "" || info.User.EmailVerified {
		t.Fatalf("user %+v", info.User)
	}
	m.JSON("GET api.vercel.com/login/oauth/userinfo", 401, map[string]any{"error": "invalid_token"})
	info, err = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if info != nil || err != nil {
		t.Fatalf("expected nil: %+v %v", info, err)
	}
}

// upstream: "should support mapProfileToUser"
func TestMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.vercel.com/login/oauth/userinfo", 200, map[string]any{"sub": "vercel_user_123", "name": "Vercel User"})
	p := newP(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"vercelUserId": profile["sub"]}, nil
		}
	})
	info, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if err != nil || info.User.Extra["vercelUserId"] != "vercel_user_123" || info.User.Name != "Vercel User" {
		t.Fatalf("user %+v %v", info, err)
	}
}
