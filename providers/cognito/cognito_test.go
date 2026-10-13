package cognito

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	domain   = "test.auth.us-east-1.amazoncognito.com"
	region   = "us-east-1"
	pool     = "us-east-1_pool"
	callback = "https://app.example/callback"
	issuer   = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool"
	jwksPath = "cognito-idp.us-east-1.amazonaws.com/us-east-1_pool/.well-known/jwks.json"
)

var verifier = strings.Repeat("v", 64)

func ctx() context.Context { return context.Background() }

func baseOptions() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"},
		Domain: domain, Region: region, UserPoolID: pool}
}

func baseInput() oauth2.AuthorizationURLParams {
	return oauth2.AuthorizationURLParams{State: "state-xyz", CodeVerifier: verifier, RedirectURI: callback}
}

func TestIdentityAndEndpoints(t *testing.T) {
	p := New(baseOptions())
	if p.ID() != "cognito" || p.Name() != "Cognito" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	o := baseOptions()
	o.Domain = "https://" + domain
	if o.AuthorizationEndpoint() != "https://"+domain+"/oauth2/authorize" || o.TokenEndpoint() != "https://"+domain+"/oauth2/token" ||
		o.UserInfoEndpoint() != "https://"+domain+"/oauth2/userinfo" || o.Issuer() != issuer || o.JWKSEndpoint() != "https://"+jwksPath {
		t.Fatal("endpoints")
	}
}

func TestConstructionRequiresDomainRegionPool(t *testing.T) {
	for _, mut := range []func(o *Options){
		func(o *Options) { o.Domain = "" }, func(o *Options) { o.Region = "" }, func(o *Options) { o.UserPoolID = "" },
	} {
		o := baseOptions()
		mut(&o)
		if _, err := TryNew(o); !errors.Is(err, ErrDomainAndRegionRequired) || err.Error() != "DOMAIN_AND_REGION_REQUIRED" {
			t.Fatalf("err %v", err)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("New should panic")
		}
	}()
	New(Options{})
}

func TestAuthorizationURL(t *testing.T) {
	o := baseOptions()
	o.Prompt = "login"
	o.Scope = []string{"aws.cognito.signin.user.admin"}
	in := baseInput()
	in.Scopes = []string{"phone"}
	in.LoginHint = "ignored@example.com"
	u, err := New(o).CreateAuthorizationURL(ctx(), in)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://"+domain+"/oauth2/authorize" {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{"response_type": "code", "client_id": "client-123", "state": "state-xyz",
		"redirect_uri": callback, "prompt": "login", "code_challenge_method": "S256",
		"scope": "openid profile email aws.cognito.signin.user.admin phone"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q", k, q.Get(k), v)
		}
	}
	if q.Has("login_hint") || q.Has("identity_provider") {
		t.Errorf("unexpected params %s", u.RawQuery)
	}
	// scope is moved to the end and encoded with %20
	if !strings.HasSuffix(u.RawQuery, "&scope=openid%20profile%20email%20aws.cognito.signin.user.admin%20phone") ||
		strings.Count(u.RawQuery, "scope=") != 1 || strings.Contains(u.RawQuery, "+") {
		t.Fatalf("raw query %s", u.RawQuery)
	}
	if !strings.Contains(u.String(), "scope=openid%20profile") {
		t.Fatalf("string %s", u.String())
	}
}

func TestAuthorizationURLNoScope(t *testing.T) {
	o := baseOptions()
	o.DisableDefaultScope = true
	u, err := New(o).CreateAuthorizationURL(ctx(), baseInput())
	if err != nil || u.Query().Has("scope") {
		t.Fatalf("%v %v", u, err)
	}
}

// cognito provider: applies the configured identityProvider as identity_provider
func TestIdentityProviderOption(t *testing.T) {
	o := baseOptions()
	o.IdentityProvider = "Google"
	u, err := New(o).CreateAuthorizationURL(ctx(), baseInput())
	if err != nil || u.Query().Get("identity_provider") != "Google" {
		t.Fatalf("%v %v", u, err)
	}
}

// cognito provider: lets call-time additionalParams override the configured identityProvider
func TestIdentityProviderOverride(t *testing.T) {
	o := baseOptions()
	o.IdentityProvider = "Google"
	in := baseInput()
	in.AdditionalParams = map[string]string{"identity_provider": "Okta"}
	u, err := New(o).CreateAuthorizationURL(ctx(), in)
	if err != nil || u.Query().Get("identity_provider") != "Okta" {
		t.Fatalf("%v %v", u, err)
	}
}

// cognito provider: omits identity_provider when neither config nor additionalParams set it
func TestIdentityProviderOmitted(t *testing.T) {
	u, err := New(baseOptions()).CreateAuthorizationURL(ctx(), baseInput())
	if err != nil || u.Query().Has("identity_provider") {
		t.Fatalf("%v %v", u, err)
	}
}

func TestAuthorizationURLRequiredOptions(t *testing.T) {
	o := baseOptions()
	o.ClientID = ""
	if _, err := New(o).CreateAuthorizationURL(ctx(), baseInput()); err == nil || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
		t.Fatalf("err %v", err)
	}
	o = baseOptions()
	o.ClientSecret = ""
	if _, err := New(o).CreateAuthorizationURL(ctx(), baseInput()); err != nil {
		t.Fatalf("public client should work: %v", err)
	}
	o.RequireClientSecret = true
	if _, err := New(o).CreateAuthorizationURL(ctx(), baseInput()); err == nil || err.Error() != "CLIENT_SECRET_REQUIRED" {
		t.Fatalf("err %v", err)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST "+domain+"/oauth2/token", 200, map[string]any{"access_token": "at", "id_token": "idt", "refresh_token": "rt", "expires_in": 3600})
	tok, err := New(baseOptions()).ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil || tok.AccessToken != "at" || tok.IDToken != "idt" || tok.RefreshToken != "rt" {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last(domain + "/oauth2/token")
	want := map[string]string{"grant_type": "authorization_code", "code": "c", "code_verifier": verifier,
		"redirect_uri": callback, "client_id": "client-123", "client_secret": "secret-abc"}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q want %q", k, r.Form.Get(k), v)
		}
	}
	// public client: client_id only
	o := baseOptions()
	o.ClientSecret = ""
	if _, err := New(o).ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", RedirectURI: callback}); err != nil {
		t.Fatal(err)
	}
	r = m.Last(domain + "/oauth2/token")
	if r.Form.Get("client_id") != "client-123" || r.Form.Has("client_secret") {
		t.Fatalf("form %v", r.Form)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST "+domain+"/oauth2/token", 200, map[string]any{"access_token": "new", "expires_in": 3600})
	tok, err := New(baseOptions()).RefreshAccessToken(ctx(), "rt", nil)
	if err != nil || tok.AccessToken != "new" {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last(domain + "/oauth2/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "rt" || r.Form.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", r.Form)
	}
}

func TestGetUserInfoFromIDToken(t *testing.T) {
	m := oauth2test.New(t)
	idt := m.IDToken(map[string]any{"sub": "cog-sub", "email": "u@example.com", "email_verified": true,
		"given_name": "Given", "username": "user1", "picture": "https://pic"})
	p := New(baseOptions())
	res, err := p.GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt, AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Name != "Given" || res.User.Email != "u@example.com" || !res.User.EmailVerified || res.User.Image != "https://pic" {
		t.Fatalf("user %+v", res.User)
	}
	if res.Data["name"] != "Given" {
		t.Fatalf("enriched %v", res.Data)
	}
	if sub, _ := p.AccountSubject(ctx(), nil, res.Data); sub != "cog-sub" {
		t.Fatalf("sub %q", sub)
	}
	if len(m.Requests) != 0 {
		t.Fatal("userinfo endpoint should not be called")
	}
}

func TestGetUserInfoNameFallbacks(t *testing.T) {
	m := oauth2test.New(t)
	for _, c := range []struct {
		claims map[string]any
		want   string
	}{
		{map[string]any{"sub": "s", "name": "Full", "given_name": "G"}, "Full"},
		{map[string]any{"sub": "s", "username": "user1"}, "user1"},
		{map[string]any{"sub": "s"}, ""},
	} {
		res, _ := New(baseOptions()).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: m.IDToken(c.claims)}})
		if res.User.Name != c.want {
			t.Fatalf("name %q want %q", res.User.Name, c.want)
		}
	}
}

func TestGetUserInfoFromUserInfoEndpoint(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET "+domain+"/oauth2/userinfo", 200, map[string]any{"sub": "cog-sub", "email": "u@example.com",
		"email_verified": "true", "username": "user1"})
	var mapped map[string]any
	o := baseOptions()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) { mapped = p; return nil, nil }
	// an undecodable id token falls through to the userinfo endpoint
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: "not-a-jwt", AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Name != "user1" || res.User.Email != "u@example.com" || !res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	if _, ok := res.Data["name"]; ok {
		t.Fatal("userinfo profile must not be enriched")
	}
	if mapped["sub"] != "cog-sub" {
		t.Fatalf("mapper got %v", mapped)
	}
	r := m.Last(domain + "/oauth2/userinfo")
	if r.Header.Get("Authorization") != "Bearer at" {
		t.Fatalf("headers %v", r.Header)
	}
}

func TestGetUserInfoFailures(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET "+domain+"/oauth2/userinfo", 401, map[string]any{"error": "invalid_token"})
	res, err := New(baseOptions()).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("%v %v", res, err)
	}
	res, err = New(baseOptions()).GetUserInfo(ctx(), oauth2.UserInfoParams{})
	if res != nil || err != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUserOverride(t *testing.T) {
	m := oauth2test.New(t)
	o := baseOptions()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"name": "Mapped " + p["name"].(string), "phone": p["phone_number"]}, nil
	}
	idt := m.IDToken(map[string]any{"sub": "s", "given_name": "G", "phone_number": "+1"})
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}})
	if err != nil || res.User.Name != "Mapped G" || res.User.Extra["phone"] != "+1" {
		t.Fatalf("%+v %v", res, err)
	}
}

func verify(t *testing.T, o Options, tok string) bool {
	t.Helper()
	v, ok := oauth2.AsIDTokenVerifier(New(o))
	if !ok {
		t.Fatal("id token sign-in unsupported")
	}
	res, err := v.VerifyIDToken(ctx(), tok, "")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestVerifyIDToken(t *testing.T) {
	m := oauth2test.New(t)
	m.ServeJWKS("GET " + jwksPath)
	good := map[string]any{"sub": "s", "iss": issuer, "aud": "client-123", "token_use": "id"}
	if !verify(t, baseOptions(), m.IDToken(good)) {
		t.Fatal("expected valid")
	}
	if m.Last(jwksPath) == nil {
		t.Fatal("jwks not fetched")
	}
	bad := []map[string]any{
		{"sub": "s", "iss": "https://cognito-idp.us-east-1.amazonaws.com/other", "aud": "client-123"},
		{"sub": "s", "iss": issuer, "aud": "other-client"},
		{"sub": "s", "iss": issuer, "aud": "client-123", "iat": float64(time.Now().Add(-2 * time.Hour).Unix())},
		{"sub": "s", "iss": issuer, "aud": "client-123", "exp": float64(time.Now().Add(-time.Minute).Unix())},
	}
	for i, c := range bad {
		if verify(t, baseOptions(), m.IDToken(c)) {
			t.Fatalf("case %d accepted", i)
		}
	}
	// nonce must match when provided
	v, _ := oauth2.AsIDTokenVerifier(New(baseOptions()))
	withNonce := map[string]any{"sub": "s", "iss": issuer, "aud": "client-123", "nonce": "n1"}
	if ok, _ := v.VerifyIDToken(ctx(), m.IDToken(withNonce), "n2"); ok {
		t.Fatal("nonce mismatch accepted")
	}
	if ok, _ := v.VerifyIDToken(ctx(), m.IDToken(withNonce), "n1"); !ok {
		t.Fatal("nonce match rejected")
	}
}

func TestVerifyIDTokenJWKSFailure(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET "+jwksPath, 500, map[string]any{"error": "boom"})
	if verify(t, baseOptions(), m.IDToken(map[string]any{"sub": "s", "iss": issuer, "aud": "client-123"})) {
		t.Fatal("expected invalid")
	}
}
