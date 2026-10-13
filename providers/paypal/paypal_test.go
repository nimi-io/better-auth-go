package paypal

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "paypal-client-id", ClientSecret: "paypal-client-secret"}, Environment: "live"}
}

func profile(subject string, overrides map[string]any) map[string]any {
	p := map[string]any{
		"user_id": subject, "name": "PayPal User", "given_name": "PayPal", "family_name": "User",
		"email": "paypal-user@example.com", "email_verified": true, "picture": "https://example.com/avatar.png",
	}
	for k, v := range overrides {
		p[k] = v
	}
	return p
}

var basicAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte("paypal-client-id:paypal-client-secret"))

func TestIdentityAndEnvironments(t *testing.T) {
	p := New(opts())
	if p.ID() != "paypal" || p.Name() != "PayPal" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("no id token sign-in")
	}
	a, tk, u := Endpoints("")
	if a != SandboxAuthorizationEndpoint || tk != SandboxTokenEndpoint || u != SandboxUserInfoEndpoint {
		t.Fatal("sandbox is the default environment")
	}
	a, tk, u = Endpoints("live")
	if a != LiveAuthorizationEndpoint || tk != LiveTokenEndpoint || u != LiveUserInfoEndpoint {
		t.Fatal("live endpoints")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := opts()
	o.Environment = ""
	o.Prompt = "login"
	o.Scope = []string{"openid"}
	u, err := New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "verifier", RedirectURI: "https://app/cb", Scopes: []string{"email"}, LoginHint: "x",
		AdditionalParams: map[string]string{"flowEntry": "static"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != SandboxAuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{"response_type": "code", "client_id": "paypal-client-id", "state": "st", "redirect_uri": "https://app/cb",
		"prompt": "login", "code_challenge_method": "S256", "code_challenge": oauth2.GenerateCodeChallenge("verifier"), "flowEntry": "static"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	for _, k := range []string{"scope", "login_hint"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
	u, _ = New(opts()).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	if u.Scheme+"://"+u.Host+u.Path != LiveAuthorizationEndpoint {
		t.Fatalf("live endpoint %s", u)
	}
	for _, po := range []oauth2.ProviderOptions{{ClientID: "id"}, {ClientSecret: "s"}} {
		if _, err := New(Options{ProviderOptions: po}).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s"}); err == nil || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
			t.Fatalf("err %v", err)
		}
	}
}

// paypal.test.ts: "exchanges an authorization code with Basic authentication"
func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api-m.paypal.com/v1/oauth2/token", 200, map[string]any{"access_token": "access-token", "expires_in": 3600, "refresh_token": "refresh-token", "token_type": "Bearer"})
	tokens, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "authorization-code", CodeVerifier: "code-verifier", RedirectURI: "https://app.example.com/api/auth/callback/paypal"})
	if err != nil || tokens.AccessToken != "access-token" {
		t.Fatalf("%+v %v", tokens, err)
	}
	r := m.Last("api-m.paypal.com/v1/oauth2/token")
	if r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != basicAuth || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("headers %v", r.Header)
	}
	want := map[string]string{"code": "authorization-code", "code_verifier": "code-verifier", "grant_type": "authorization_code", "redirect_uri": "https://app.example.com/api/auth/callback/paypal"}
	if len(r.Form) != len(want) {
		t.Fatalf("form %v", r.Form)
	}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q", k, r.Form.Get(k))
		}
	}
	m.JSON("POST api-m.paypal.com/v1/oauth2/token", 401, map[string]any{"error": "invalid_client"})
	if _, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c"}); err == nil || err.Error() != "FAILED_TO_GET_ACCESS_TOKEN" {
		t.Fatalf("err %v", err)
	}
}

func TestValidateAuthorizationCodeSandboxAndRedirectOverride(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api-m.sandbox.paypal.com/v1/oauth2/token", 200, map[string]any{"access_token": "sbx"})
	o := opts()
	o.Environment = "sandbox"
	o.RedirectURI = "https://override/cb"
	tokens, err := New(o).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c", RedirectURI: "r"})
	if err != nil || tokens.AccessToken != "sbx" {
		t.Fatalf("%+v %v", tokens, err)
	}
	if got := m.Last("api-m.sandbox.paypal.com/v1/oauth2/token").Form.Get("redirect_uri"); got != "https://override/cb" {
		t.Fatalf("redirect_uri %q", got)
	}
}

// paypal.test.ts: "refreshes an access token with Basic authentication"
func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api-m.paypal.com/v1/oauth2/token", 200, map[string]any{"access_token": "refreshed-access-token", "expires_in": 3600, "refresh_token": "rotated-refresh-token", "token_type": "Bearer"})
	tokens, err := New(opts()).RefreshAccessToken(ctx, "refresh-token", nil)
	if err != nil || tokens.AccessToken != "refreshed-access-token" {
		t.Fatalf("%+v %v", tokens, err)
	}
	r := m.Last("api-m.paypal.com/v1/oauth2/token")
	if r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != basicAuth || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("headers %v", r.Header)
	}
	if len(r.Form) != 2 || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-token" {
		t.Fatalf("form %v", r.Form)
	}
	m.JSON("POST api-m.paypal.com/v1/oauth2/token", 400, map[string]any{"error": "invalid_grant"})
	if _, err := New(opts()).RefreshAccessToken(ctx, "x", nil); err == nil || err.Error() != "FAILED_TO_REFRESH_ACCESS_TOKEN" {
		t.Fatalf("err %v", err)
	}
	o := opts()
	o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom"}, nil
	}
	if tk, _ := New(o).RefreshAccessToken(ctx, "x", nil); tk.AccessToken != "custom" {
		t.Fatal("override ignored")
	}
}

func userInfo(t *testing.T, prof map[string]any, idSub string) (*oauth2.UserInfoResult, *oauth2test.Server, *oauth2.GenericProvider) {
	m := oauth2test.New(t)
	m.JSON("GET api-m.paypal.com/v1/identity/oauth2/userinfo", 200, prof)
	p := New(opts())
	params := oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "paypal-access-token"}}
	if idSub != "" {
		params.IDToken = m.IDToken(map[string]any{"sub": idSub})
	}
	res, err := p.GetUserInfo(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	return res, m, p
}

// paypal.test.ts: "returns user info when the id token subject matches the profile"
func TestGetUserInfoMatchingSubject(t *testing.T) {
	res, m, p := userInfo(t, profile("paypal-user-123", nil), "paypal-user-123")
	if res == nil || res.User.Email != "paypal-user@example.com" || res.User.Name != "PayPal User" || res.User.Image != "https://example.com/avatar.png" || !res.User.EmailVerified {
		t.Fatalf("%+v", res)
	}
	if _, ok := res.User.Extra["id"]; ok {
		t.Fatal("user must not carry id")
	}
	if sub, _ := p.AccountSubject(ctx, &oauth2.Tokens{AccessToken: "paypal-access-token"}, res.Data); sub != "paypal-user-123" {
		t.Fatalf("subject %q", sub)
	}
	r := m.Last("api-m.paypal.com/v1/identity/oauth2/userinfo")
	if r.URL.RawQuery != "schema=paypalv1.1" || r.Header.Get("Authorization") != "Bearer paypal-access-token" || r.Header.Get("Accept") != "application/json" {
		t.Fatalf("request %s %v", r.URL, r.Header)
	}
}

// paypal.test.ts: "keeps the PayPal user id when the profile subject matches"
func TestGetUserInfoKeepsUserID(t *testing.T) {
	res, _, p := userInfo(t, profile("paypal-user-123", map[string]any{"sub": "paypal-subject-123"}), "paypal-subject-123")
	if res == nil {
		t.Fatal("nil result")
	}
	if sub, _ := p.AccountSubject(ctx, nil, res.Data); sub != "paypal-user-123" {
		t.Fatalf("subject %q", sub)
	}
}

// paypal.test.ts: "returns null when the id token subject does not match the profile"
func TestGetUserInfoSubjectMismatch(t *testing.T) {
	if res, _, _ := userInfo(t, profile("paypal-user-123", nil), "paypal-user-456"); res != nil {
		t.Fatalf("%+v", res)
	}
}

// paypal.test.ts: "prefers the profile subject over user_id when validating the id token"
func TestGetUserInfoPrefersProfileSub(t *testing.T) {
	if res, _, _ := userInfo(t, profile("paypal-user-123", map[string]any{"sub": "paypal-user-456"}), "paypal-user-123"); res != nil {
		t.Fatalf("%+v", res)
	}
}

func TestGetUserInfoWithoutIDTokenAndErrors(t *testing.T) {
	res, _, _ := userInfo(t, profile("u1", map[string]any{"email_verified": false}), "")
	if res == nil || res.User.EmailVerified {
		t.Fatalf("%+v", res)
	}
	// no access token
	m := oauth2test.New(t)
	if res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{}); err != nil || res != nil || len(m.Requests) != 0 {
		t.Fatalf("%v %v", res, err)
	}
	// userinfo failure
	m.JSON("GET api-m.paypal.com/v1/identity/oauth2/userinfo", 401, map[string]any{"error": "invalid_token"})
	if res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "bad"}}); err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
	// undecodable id token
	m.JSON("GET api-m.paypal.com/v1/identity/oauth2/userinfo", 200, profile("u1", nil))
	if res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at", IDToken: "not-a-jwt"}}); err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUserAndGetUserInfoOverride(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api-m.paypal.com/v1/identity/oauth2/userinfo", 200, profile("u1", map[string]any{"payer_id": "PAYER"}))
	o := opts()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"name": p["given_name"], "payerId": p["payer_id"]}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "PayPal" || res.User.Extra["payerId"] != "PAYER" || res.User.Email != "paypal-user@example.com" {
		t.Fatalf("%+v %v", res, err)
	}
	o = opts()
	o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}}, nil
	}
	if res, _ := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{}); res == nil || res.User.Name != "custom" {
		t.Fatal("override ignored")
	}
}
