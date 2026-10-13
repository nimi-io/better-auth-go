package figma

import (
	"context"
	"errors"
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
	if p.ID() != "figma" || p.Name() != "Figma" {
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
		AdditionalParams: map[string]string{"custom": "value", "response_type": "token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", got)
	}
	wantRaw := "response_type=code&client_id=client-123&state=state-xyz&scope=current_user%3Aread&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
		"&code_challenge_method=S256&code_challenge=" + oauth2.GenerateCodeChallenge(verifier) + "&custom=value"
	if u.RawQuery != wantRaw {
		t.Fatalf("raw query\n got %s\nwant %s", u.RawQuery, wantRaw)
	}
}

func TestAuthorizationURLRequirements(t *testing.T) {
	ctx := context.Background()
	in := oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: callback}
	if _, err := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "id"}}).CreateAuthorizationURL(ctx, in); !errors.Is(err, ErrClientIDAndSecretRequired) || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
		t.Fatalf("missing secret: %v", err)
	}
	if _, err := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientSecret: "s"}}).CreateAuthorizationURL(ctx, in); !errors.Is(err, ErrClientIDAndSecretRequired) {
		t.Fatalf("missing id: %v", err)
	}
	in.CodeVerifier = ""
	if _, err := newProvider().CreateAuthorizationURL(ctx, in); err == nil || err.Error() != "codeVerifier is required for Figma" {
		t.Fatalf("missing verifier: %v", err)
	}
}

func TestAuthorizationURLOptions(t *testing.T) {
	p := newProvider(func(o *Options) {
		o.Scope = []string{"file_content:read"}
		o.RedirectURI = "https://override.example/cb"
		o.AuthorizationEndpoint = "https://proxy.example/oauth"
	})
	u, _ := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: callback, Scopes: []string{"file_comments:write"}})
	q := u.Query()
	if u.Host != "proxy.example" || q.Get("scope") != "current_user:read file_content:read file_comments:write" || q.Get("redirect_uri") != "https://override.example/cb" {
		t.Fatalf("got %s", u)
	}
	u, _ = newProvider(func(o *Options) { o.DisableDefaultScope = true }).CreateAuthorizationURL(context.Background(),
		oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: callback})
	if u.Query().Has("scope") {
		t.Fatal("scope must be omitted")
	}
}

func TestValidateAuthorizationCodeBasicAuth(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.figma.com/v1/oauth/token", 200, map[string]any{
		"user_id": float64(123), "user_id_string": "123", "access_token": "figu_at", "refresh_token": "figur_rt", "expires_in": 7776000,
	})
	tok, err := newProvider().ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "auth-code", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil || tok.AccessToken != "figu_at" || tok.RefreshToken != "figur_rt" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last("api.figma.com/v1/oauth/token")
	if got := r.Header.Get("Authorization"); got != oauth2.EncodeBasicCredentials("client-123", "secret-abc") {
		t.Fatalf("authorization %q", got)
	}
	f := r.Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "auth-code" || f.Get("code_verifier") != verifier || f.Get("redirect_uri") != callback {
		t.Fatalf("form %v", f)
	}
	if f.Has("client_id") || f.Has("client_secret") {
		t.Fatalf("client_secret_basic must not send credentials in the body: %v", f)
	}
}

var me = map[string]any{"id": "figma-1", "email": "f@figma.com", "handle": "Fig", "img_url": "https://img/f.png"}

func TestGetUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.figma.com/v1/me", 200, me)
	p := newProvider()
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if h := m.Last("api.figma.com/v1/me").Header.Get("Authorization"); h != "Bearer at" {
		t.Fatalf("auth %q", h)
	}
	u := res.User
	if u.Name != "Fig" || u.Email != "f@figma.com" || u.Image != "https://img/f.png" || u.EmailVerified {
		t.Fatalf("user %+v", u)
	}
	sub, err := p.AccountSubject(context.Background(), nil, res.Data)
	if err != nil || sub != "figma-1" {
		t.Fatalf("subject %q %v", sub, err)
	}
}

func TestGetUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("api.figma.com/v1/me", 403, map[string]any{"status": 403, "err": "Invalid token"})
	if res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}}); res != nil || err != nil {
		t.Fatalf("expected null: %v %v", res, err)
	}
}

func TestMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("api.figma.com/v1/me", 200, me)
	p := newProvider(func(o *Options) {
		o.MapProfileToUser = func(pr map[string]any) (map[string]any, error) {
			return map[string]any{"emailVerified": true, "handle": pr["handle"]}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || !res.User.EmailVerified || res.User.Extra["handle"] != "Fig" || res.User.Name != "Fig" {
		t.Fatalf("%+v %v", res, err)
	}
	// errors thrown by the mapper are caught upstream and yield null
	p = newProvider(func(o *Options) {
		o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return nil, errors.New("boom") }
	})
	if res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}}); res != nil || err != nil {
		t.Fatalf("expected null: %v %v", res, err)
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	oauth2test.New(t)
	p := newProvider(func(o *Options) {
		o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}}, nil
		}
	})
	if res, _ := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{}); res.User.Name != "custom" {
		t.Fatal("override not used")
	}
}

func TestRefreshAccessTokenBasicAuth(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.figma.com/v1/oauth/token", 200, map[string]any{"access_token": "new-at", "expires_in": 7776000})
	tok, err := newProvider().RefreshAccessToken(context.Background(), "old-rt", nil)
	if err != nil || tok.AccessToken != "new-at" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last("api.figma.com/v1/oauth/token")
	if r.Header.Get("Authorization") != oauth2.EncodeBasicCredentials("client-123", "secret-abc") {
		t.Fatalf("authorization %q", r.Header.Get("Authorization"))
	}
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-rt" || r.Form.Has("client_secret") || r.Form.Has("client_id") {
		t.Fatalf("form %v", r.Form)
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
