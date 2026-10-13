package cloudflare

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const callback = "https://app.example/callback"

var verifier = strings.Repeat("v", 64)

func ctx() context.Context { return context.Background() }

func confidential() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cloudflare-client", ClientSecret: "cloudflare-secret"}}
}

func TestIdentity(t *testing.T) {
	p := New(confidential())
	if p.ID() != "cloudflare" || p.Name() != "Cloudflare" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsIDTokenVerifier(p); ok {
		t.Fatal("cloudflare has no id token sign-in")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := confidential()
	o.Scope = []string{"account.read", "user-details.read"}
	o.Prompt = "consent"
	u, err := New(o).CreateAuthorizationURL(ctx(), oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: verifier, RedirectURI: callback, Scopes: []string{"account.read", "zone.read"},
		LoginHint: "x@y", AdditionalParams: map[string]string{"foo": "bar"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{"response_type": "code", "client_id": "cloudflare-client", "state": "st",
		"redirect_uri": callback, "scope": "user-details.read account.read zone.read", "code_challenge_method": "S256"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q", k, q.Get(k), v)
		}
	}
	for _, k := range []string{"foo", "prompt", "login_hint"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
}

func TestAuthorizationURLWithoutScopes(t *testing.T) {
	o := confidential()
	o.DisableDefaultScope = true
	u, err := New(o).CreateAuthorizationURL(ctx(), oauth2.AuthorizationURLParams{State: "st", RedirectURI: callback})
	if err != nil || u.Query().Has("scope") {
		t.Fatalf("%v %v", u, err)
	}
	_, err = New(Options{}).CreateAuthorizationURL(ctx(), oauth2.AuthorizationURLParams{State: "st", RedirectURI: callback})
	if err == nil || err.Error() != "OAuth provider requires clientId" {
		t.Fatalf("err %v", err)
	}
}

func tokenMock(t *testing.T) *oauth2test.Server {
	m := oauth2test.New(t)
	m.JSON("POST dash.cloudflare.com/oauth2/token", 200, map[string]any{"access_token": "at", "refresh_token": "rt", "expires_in": 3600, "scope": "user-details.read"})
	return m
}

func TestExchangeDefaultsToClientSecretBasic(t *testing.T) {
	m := tokenMock(t)
	tok, err := New(confidential()).ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil || tok.AccessToken != "at" || len(tok.Scopes) != 1 {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last("dash.cloudflare.com/oauth2/token")
	if r.Header.Get("Authorization") != oauth2.EncodeBasicCredentials("cloudflare-client", "cloudflare-secret") {
		t.Fatalf("auth header %q", r.Header.Get("Authorization"))
	}
	if r.Form.Has("client_secret") || r.Form.Has("client_id") || r.Form.Get("code") != "c" ||
		r.Form.Get("code_verifier") != verifier || r.Form.Get("redirect_uri") != callback || r.Form.Get("grant_type") != "authorization_code" {
		t.Fatalf("form %v", r.Form)
	}
}

func TestExchangeClientSecretPost(t *testing.T) {
	m := tokenMock(t)
	o := confidential()
	o.TokenEndpointAuthMethod = oauth2.AuthClientSecretPost
	if _, err := New(o).ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", RedirectURI: callback}); err != nil {
		t.Fatal(err)
	}
	r := m.Last("dash.cloudflare.com/oauth2/token")
	if r.Header.Get("Authorization") != "" || r.Form.Get("client_id") != "cloudflare-client" || r.Form.Get("client_secret") != "cloudflare-secret" {
		t.Fatalf("request %v %v", r.Header, r.Form)
	}
}

func TestExchangePublicClientUsesNone(t *testing.T) {
	m := tokenMock(t)
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cloudflare-client"}}
	if _, err := New(o).ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", CodeVerifier: verifier, RedirectURI: callback}); err != nil {
		t.Fatal(err)
	}
	r := m.Last("dash.cloudflare.com/oauth2/token")
	if r.Header.Get("Authorization") != "" || r.Form.Get("client_id") != "cloudflare-client" || r.Form.Has("client_secret") {
		t.Fatalf("request %v %v", r.Header, r.Form)
	}
}

func TestExchangeRejectsMismatchedAuthentication(t *testing.T) {
	tokenMock(t)
	// client secret with "none" (a type error upstream) fails at runtime
	o := confidential()
	o.TokenEndpointAuthMethod = oauth2.AuthNone
	if _, err := New(o).ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", RedirectURI: callback}); err == nil {
		t.Fatal("expected error")
	}
	// client_secret_basic without a secret
	o = Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cloudflare-client"}, TokenEndpointAuthMethod: oauth2.AuthClientSecretBasic}
	if _, err := New(o).ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", RedirectURI: callback}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRefresh(t *testing.T) {
	m := tokenMock(t)
	tok, err := New(confidential()).RefreshAccessToken(ctx(), "old-rt", nil)
	if err != nil || tok.AccessToken != "at" {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last("dash.cloudflare.com/oauth2/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-rt" ||
		r.Header.Get("Authorization") != oauth2.EncodeBasicCredentials("cloudflare-client", "cloudflare-secret") || r.Form.Has("client_secret") {
		t.Fatalf("request %v %v", r.Header, r.Form)
	}
	// public client
	if _, err := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "pub"}}).RefreshAccessToken(ctx(), "rt", nil); err != nil {
		t.Fatal(err)
	}
	r = m.Last("dash.cloudflare.com/oauth2/token")
	if r.Form.Get("client_id") != "pub" || r.Header.Get("Authorization") != "" {
		t.Fatalf("request %v %v", r.Header, r.Form)
	}
}

func userMock(t *testing.T, status int, body map[string]any) *oauth2test.Server {
	m := oauth2test.New(t)
	m.JSON("GET api.cloudflare.com/client/v4/user", status, body)
	return m
}

func okResponse(profile map[string]any) map[string]any {
	return map[string]any{"success": true, "errors": []any{}, "result": profile}
}

// cloudflare.getUserInfo: maps the Cloudflare profile without redefining provider identity
func TestGetUserInfoMapsProfile(t *testing.T) {
	m := userMock(t, 200, okResponse(map[string]any{"id": "cloudflare-user-1", "email": "user@example.com",
		"first_name": "Cloudflare", "last_name": "User"}))
	p := New(confidential())
	res, err := p.GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if u := res.User; u.Name != "Cloudflare User" || u.Email != "user@example.com" || u.EmailVerified || u.Image != "" || u.Extra != nil {
		t.Fatalf("user %+v", res.User)
	}
	sub, err := p.AccountSubject(ctx(), &oauth2.Tokens{AccessToken: "access-token"}, res.Data)
	if err != nil || sub != "cloudflare-user-1" {
		t.Fatalf("sub %q %v", sub, err)
	}
	if r := m.Last("api.cloudflare.com/client/v4/user"); r.Header.Get("Authorization") != "Bearer access-token" {
		t.Fatalf("headers %v", r.Header)
	}
}

// cloudflare.getUserInfo: uses the email as the display name when Cloudflare omits both names
func TestGetUserInfoEmailAsName(t *testing.T) {
	userMock(t, 200, okResponse(map[string]any{"id": "cloudflare-user-2", "email": "nameless@example.com"}))
	res, err := New(confidential()).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res.User.Name != "nameless@example.com" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGetUserInfoPartialName(t *testing.T) {
	userMock(t, 200, okResponse(map[string]any{"id": "x", "email": "e@x", "first_name": nil, "last_name": "Only"}))
	res, _ := New(confidential()).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "a"}})
	if res.User.Name != "Only" {
		t.Fatalf("name %q", res.User.Name)
	}
}

// cloudflare.getUserInfo: returns null when the request fails / Cloudflare reports an error / omits the profile
func TestGetUserInfoReturnsNull(t *testing.T) {
	cases := map[string]struct {
		status int
		body   map[string]any
	}{
		"the request fails":            {500, map[string]any{"message": "Internal Server Error"}},
		"Cloudflare reports an error":  {200, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1000, "message": "Unable to fetch user"}}, "result": nil}},
		"Cloudflare omits the profile": {200, map[string]any{"success": true, "errors": []any{}, "result": nil}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			userMock(t, c.status, c.body)
			res, err := New(confidential()).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
			if res != nil || err != nil {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}

func TestMapProfileToUserOverride(t *testing.T) {
	userMock(t, 200, okResponse(map[string]any{"id": "u", "email": "e@x", "country": "NG"}))
	o := confidential()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"emailVerified": true, "country": p["country"], "image": "https://img"}, nil
	}
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "a"}})
	if err != nil || !res.User.EmailVerified || res.User.Image != "https://img" || res.User.Extra["country"] != "NG" || res.User.Name != "e@x" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	o := confidential()
	o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}, Data: map[string]any{"id": "c"}}, nil
	}
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "a"}})
	if err != nil || res.User.Name != "custom" {
		t.Fatalf("%+v %v", res, err)
	}
}
