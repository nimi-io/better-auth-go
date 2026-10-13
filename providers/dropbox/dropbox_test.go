package dropbox

import (
	"context"
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
	if p.ID() != "dropbox" || p.Name() != "Dropbox" {
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
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", got)
	}
	wantRaw := "response_type=code&client_id=client-123&state=state-xyz&scope=account_info.read&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" +
		"&code_challenge_method=S256&code_challenge=" + oauth2.GenerateCodeChallenge(verifier)
	if u.RawQuery != wantRaw {
		t.Fatalf("raw query\n got %s\nwant %s", u.RawQuery, wantRaw)
	}
}

func TestAuthorizationURLAccessType(t *testing.T) {
	p := newProvider(func(o *Options) { o.AccessType = "offline" })
	u, _ := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: callback})
	if u.Query().Get("token_access_type") != "offline" {
		t.Fatalf("got %s", u)
	}
	// call-time additionalParams override the configured access type
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback,
		AdditionalParams: map[string]string{"token_access_type": "online", "nonce": "attacker"}})
	if u.Query().Get("token_access_type") != "online" || u.Query().Has("nonce") {
		t.Fatalf("got %s", u)
	}
	u, _ = newProvider().CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Has("token_access_type") {
		t.Fatal("token_access_type must be omitted by default")
	}
}

func TestAuthorizationURLOptions(t *testing.T) {
	p := newProvider(func(o *Options) {
		o.DisableDefaultScope = true
		o.Scope = []string{"files.content.read"}
		o.RedirectURI = "https://override.example/cb"
	})
	u, _ := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback, Scopes: []string{"files.metadata.read"}})
	q := u.Query()
	if q.Get("scope") != "files.content.read files.metadata.read" || q.Get("redirect_uri") != "https://override.example/cb" {
		t.Fatalf("got %s", u)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.dropboxapi.com/oauth2/token", 200, map[string]any{
		"access_token": "sl.at", "refresh_token": "rt", "token_type": "bearer", "expires_in": 14400,
		"scope": "account_info.read", "account_id": "dbid:abc", "uid": "123",
	})
	tok, err := newProvider().ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "auth-code", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil || tok.AccessToken != "sl.at" || tok.RefreshToken != "rt" || tok.AccessTokenExpiresAt == nil || tok.Raw["account_id"] != "dbid:abc" {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("api.dropboxapi.com/oauth2/token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "auth-code" || f.Get("code_verifier") != verifier ||
		f.Get("redirect_uri") != callback || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
}

var account = map[string]any{
	"account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
	"name": map[string]any{
		"given_name": "Franz", "surname": "Ferdinand", "familiar_name": "Franz",
		"display_name": "Franz Ferdinand (Personal)", "abbreviated_name": "FF",
	},
	"email": "franz@dropbox.com", "email_verified": true, "profile_photo_url": "https://dl-web.dropbox.com/account_photo",
}

func TestGetUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.dropboxapi.com/2/users/get_current_account", 200, account)
	p := newProvider()
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	r := m.Last("api.dropboxapi.com/2/users/get_current_account")
	if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer at" || r.Body != "" {
		t.Fatalf("request %+v", r)
	}
	u := res.User
	if u.Name != "Franz Ferdinand (Personal)" || u.Email != "franz@dropbox.com" || !u.EmailVerified || u.Image != "https://dl-web.dropbox.com/account_photo" {
		t.Fatalf("user %+v", u)
	}
	sub, err := p.AccountSubject(context.Background(), nil, res.Data)
	if err != nil || sub != "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc" {
		t.Fatalf("subject %q %v", sub, err)
	}
}

func TestGetUserInfoDefaults(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("api.dropboxapi.com/2/users/get_current_account", 200, map[string]any{"account_id": "dbid:x", "email": "e@x"})
	res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "" || res.User.EmailVerified || res.User.Image != "" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGetUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("api.dropboxapi.com/2/users/get_current_account", 401, map[string]any{"error_summary": "invalid_access_token/"})
	if res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}}); res != nil || err != nil {
		t.Fatalf("expected null: %v %v", res, err)
	}
}

func TestMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("api.dropboxapi.com/2/users/get_current_account", 200, account)
	p := newProvider(func(o *Options) {
		o.MapProfileToUser = func(pr map[string]any) (map[string]any, error) {
			return map[string]any{"name": oauth2.Path(pr, "name", "given_name"), "email": "mapped@x"}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "Franz" || res.User.Email != "mapped@x" || !res.User.EmailVerified {
		t.Fatalf("%+v %v", res, err)
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

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.dropboxapi.com/oauth2/token", 200, map[string]any{"access_token": "new-at", "token_type": "bearer", "expires_in": 14400})
	tok, err := newProvider().RefreshAccessToken(context.Background(), "old-rt", nil)
	if err != nil || tok.AccessToken != "new-at" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("api.dropboxapi.com/oauth2/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "old-rt" || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
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
