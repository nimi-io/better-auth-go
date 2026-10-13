package microsoft

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	clientID     = "ms-app"
	authority    = "https://login.microsoftonline.com"
	workTenantID = "11111111-2222-3333-4444-555555555555"
	callback     = "https://app.example/callback"
)

var verifier = strings.Repeat("v", 64)

func ctx() context.Context { return context.Background() }

func TestIdentityAndEndpoints(t *testing.T) {
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID}})
	if p.ID() != "microsoft" || p.Name() != "Microsoft EntraID" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	o := Options{TenantID: "tid", Authority: "https://x.ciamlogin.com//"}
	if o.AuthorizationEndpoint() != "https://x.ciamlogin.com/tid/oauth2/v2.0/authorize" ||
		o.TokenEndpoint() != "https://x.ciamlogin.com/tid/oauth2/v2.0/token" ||
		o.JWKSEndpoint() != "https://x.ciamlogin.com/tid/discovery/v2.0/keys" {
		t.Fatal("endpoints", o.AuthorizationEndpoint(), o.TokenEndpoint(), o.JWKSEndpoint())
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, Prompt: "select_account", Scope: []string{"Mail.Read"}, ResponseMode: "form_post"}})
	u, err := p.CreateAuthorizationURL(ctx(), oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: verifier, RedirectURI: callback, Scopes: []string{"Calendars.Read"},
		LoginHint: "user@example.com", Display: "popup", AdditionalParams: map[string]string{"domain_hint": "example.com", "client_id": "evil"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != authority+"/common/oauth2/v2.0/authorize" {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": clientID, "state": "st", "redirect_uri": callback,
		"scope":  "openid profile email User.Read offline_access Mail.Read Calendars.Read",
		"prompt": "select_account", "login_hint": "user@example.com", "code_challenge_method": "S256",
		"domain_hint": "example.com",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q", k, q.Get(k), v)
		}
	}
	if q.Has("display") || q.Has("response_mode") {
		t.Errorf("unexpected params %s", u.RawQuery)
	}
}

func TestAuthorizationURLTenantAndPublicClient(t *testing.T) {
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, DisableDefaultScope: true}, TenantID: "organizations", Authority: authority + "/"})
	u, err := p.CreateAuthorizationURL(ctx(), oauth2.AuthorizationURLParams{State: "st", RedirectURI: callback})
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/organizations/oauth2/v2.0/authorize" || u.Query().Has("scope") {
		t.Fatalf("url %s", u)
	}
	_, err = New(Options{}).CreateAuthorizationURL(ctx(), oauth2.AuthorizationURLParams{State: "st", RedirectURI: callback})
	if err == nil || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
		t.Fatalf("err %v", err)
	}
}

func TestValidateAuthorizationCodeClientSecret(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST login.microsoftonline.com/common/oauth2/v2.0/token", 200, map[string]any{"access_token": "at", "id_token": "idt", "expires_in": 3600})
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: "sec"}})
	tok, err := p.ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "c", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil || tok.AccessToken != "at" || tok.IDToken != "idt" {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last("login.microsoftonline.com/common/oauth2/v2.0/token")
	if r.Form.Get("client_secret") != "sec" || r.Form.Get("client_id") != clientID || r.Form.Get("code") != "c" ||
		r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != callback {
		t.Fatalf("form %v", r.Form)
	}
}

// microsoft provider: sends client assertions instead of client secrets for authorization code exchange
func TestValidateAuthorizationCodeClientAssertion(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST login.microsoftonline.com/common/oauth2/v2.0/token", 200, map[string]any{
		"access_token": "access-token", "refresh_token": "refresh-token", "token_type": "Bearer", "expires_in": 3600})
	var gotArgs []string
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123"},
		ClientAssertion: func(cid, ep, gt string) (string, error) {
			gotArgs = []string{cid, ep, gt}
			return "test-microsoft-client-assertion", nil
		}})
	tok, err := p.ValidateAuthorizationCode(ctx(), oauth2.CodeParams{Code: "auth-code", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil || tok.AccessToken != "access-token" {
		t.Fatalf("%+v %v", tok, err)
	}
	if strings.Join(gotArgs, "|") != "client-123|https://login.microsoftonline.com/common/oauth2/v2.0/token|authorization_code" {
		t.Fatalf("assertion args %v", gotArgs)
	}
	r := m.Last("login.microsoftonline.com/common/oauth2/v2.0/token")
	want := map[string]string{"grant_type": "authorization_code", "code": "auth-code", "code_verifier": verifier,
		"redirect_uri": callback, "client_id": "client-123", "client_assertion_type": oauth2.ClientAssertionType,
		"client_assertion": "test-microsoft-client-assertion"}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q want %q", k, r.Form.Get(k), v)
		}
	}
	if r.Form.Has("client_secret") {
		t.Error("client_secret must not be sent")
	}
}

// microsoft provider: sends client assertions instead of client secrets for refresh token exchange
func TestRefreshClientAssertion(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST login.microsoftonline.com/common/oauth2/v2.0/token", 200, map[string]any{
		"access_token": "refreshed-access-token", "refresh_token": "refreshed-refresh-token", "token_type": "Bearer", "expires_in": 3600})
	var gotArgs []string
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123"},
		ClientAssertion: func(cid, ep, gt string) (string, error) {
			gotArgs = []string{cid, ep, gt}
			return "test-microsoft-refresh-client-assertion", nil
		}})
	tok, err := p.RefreshAccessToken(ctx(), "old-refresh-token", nil)
	if err != nil || tok.AccessToken != "refreshed-access-token" {
		t.Fatalf("%+v %v", tok, err)
	}
	if strings.Join(gotArgs, "|") != "client-123|https://login.microsoftonline.com/common/oauth2/v2.0/token|refresh_token" {
		t.Fatalf("assertion args %v", gotArgs)
	}
	r := m.Last("login.microsoftonline.com/common/oauth2/v2.0/token")
	want := map[string]string{"grant_type": "refresh_token", "refresh_token": "old-refresh-token",
		"scope": "openid profile email User.Read offline_access", "client_id": "client-123",
		"client_assertion_type": oauth2.ClientAssertionType, "client_assertion": "test-microsoft-refresh-client-assertion"}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q want %q", k, r.Form.Get(k), v)
		}
	}
	if r.Form.Has("client_secret") {
		t.Error("client_secret must not be sent")
	}
}

func TestRefreshScopesAndSecret(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST login.microsoftonline.com/tenant-x/oauth2/v2.0/token", 200, map[string]any{"access_token": "a"})
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: "sec", Scope: []string{"Mail.Read"}}, TenantID: "tenant-x"})
	if _, err := p.RefreshAccessToken(ctx(), "rt", nil); err != nil {
		t.Fatal(err)
	}
	r := m.Last("login.microsoftonline.com/tenant-x/oauth2/v2.0/token")
	if r.Form.Get("scope") != "openid profile email User.Read offline_access Mail.Read" || r.Form.Get("client_secret") != "sec" {
		t.Fatalf("form %v", r.Form)
	}
	// disableDefaultScope with no extra scope sends an empty scope
	p = New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: "sec", DisableDefaultScope: true}, TenantID: "tenant-x"})
	if _, err := p.RefreshAccessToken(ctx(), "rt", nil); err != nil {
		t.Fatal(err)
	}
	r = m.Last("login.microsoftonline.com/tenant-x/oauth2/v2.0/token")
	if !r.Form.Has("scope") || r.Form.Get("scope") != "" {
		t.Fatalf("form %v", r.Form)
	}
}

// microsoft provider: rejects client assertions combined with client secrets
func TestRejectsClientAssertionWithSecret(t *testing.T) {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"},
		ClientAssertion: func(string, string, string) (string, error) { return "client-assertion", nil }}
	if _, err := TryNew(o); !errors.Is(err, ErrClientAssertionWithSecret) ||
		err.Error() != "Microsoft Entra ID clientAssertion cannot be combined with clientSecret" {
		t.Fatalf("err %v", err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("New should panic")
		}
	}()
	New(o)
}

// ---- id_token tenant enforcement ----

func signToken(m *oauth2test.Server, tid any, iss, aud string) string {
	claims := map[string]any{"sub": "ms-user-1", "aud": aud}
	if tid != nil {
		claims["tid"] = tid
	}
	if iss == "" {
		iss = authority + "/" + tid.(string) + "/v2.0"
	}
	claims["iss"] = iss
	return m.IDToken(claims)
}

func verifyWith(t *testing.T, o Options, token string) bool {
	t.Helper()
	v, ok := oauth2.AsIDTokenVerifier(New(o))
	if !ok {
		t.Fatal("id token sign-in unsupported")
	}
	res, err := v.VerifyIDToken(ctx(), token, "")
	if err != nil {
		t.Fatalf("verify error %v", err)
	}
	return res
}

func opts(tenant string) Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID}, TenantID: tenant}
}

func TestIDTokenTenantEnforcement(t *testing.T) {
	cases := []struct {
		name   string
		tenant string
		tid    string
		iss    string
		want   bool
	}{
		{"rejects a consumer-tenant token when restricted to organizations", "organizations", ConsumerTenantID, "", false},
		{"rejects a work-tenant token when restricted to consumers", "consumers", workTenantID, "", false},
		{"accepts a work-tenant token under organizations", "organizations", workTenantID, "", true},
		{"accepts a consumer-tenant token under consumers", "consumers", ConsumerTenantID, "", true},
		{"accepts a work tenant under common", "common", workTenantID, "", true},
		{"accepts a consumer tenant under common", "common", ConsumerTenantID, "", true},
		{"rejects a token whose issuer does not name its own tenant", "common", workTenantID, authority + "/" + ConsumerTenantID + "/v2.0", false},
		{"accepts a token for the configured specific tenant", workTenantID, workTenantID, "", true},
		{"rejects a token from another tenant when a specific tenant is configured", workTenantID, ConsumerTenantID, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := oauth2test.New(t)
			m.ServeJWKS("login.microsoftonline.com/" + c.tenant + "/discovery/v2.0/keys")
			if got := verifyWith(t, opts(c.tenant), signToken(m, c.tid, c.iss, clientID)); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestIDTokenAuthorityTrailingSlash(t *testing.T) {
	m := oauth2test.New(t)
	m.ServeJWKS("login.microsoftonline.com/common/discovery/v2.0/keys")
	o := opts("common")
	o.Authority = authority + "/"
	if !verifyWith(t, o, signToken(m, workTenantID, "", clientID)) {
		t.Fatal("expected valid")
	}
	if r := m.Last("login.microsoftonline.com/common/discovery/v2.0/keys"); r == nil {
		t.Fatal("jwks not fetched from discovery endpoint")
	}
}

func TestIDTokenRejectsNonStringTid(t *testing.T) {
	m := oauth2test.New(t)
	m.ServeJWKS("login.microsoftonline.com/common/discovery/v2.0/keys")
	tok := signToken(m, nil, authority+"/"+workTenantID+"/v2.0", clientID)
	if verifyWith(t, opts("common"), tok) {
		t.Fatal("expected invalid")
	}
	tok = signToken(m, 123.0, authority+"/123/v2.0", clientID)
	if verifyWith(t, opts("common"), tok) {
		t.Fatal("expected invalid")
	}
}

func TestIDTokenAudienceAndAge(t *testing.T) {
	m := oauth2test.New(t)
	m.ServeJWKS("login.microsoftonline.com/common/discovery/v2.0/keys")
	if verifyWith(t, opts("common"), signToken(m, workTenantID, "", "other-client")) {
		t.Fatal("wrong audience accepted")
	}
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{clientID, "second"}}}
	if !verifyWith(t, o, signToken(m, workTenantID, "", "second")) {
		t.Fatal("secondary client id audience rejected")
	}
	old := m.IDToken(map[string]any{"tid": workTenantID, "iss": authority + "/" + workTenantID + "/v2.0", "aud": clientID,
		"iat": float64(time.Now().Add(-2 * time.Hour).Unix())})
	if verifyWith(t, opts("common"), old) {
		t.Fatal("old token accepted")
	}
}

// ---- account subject / getUserInfo ----

func profileToken(m *oauth2test.Server, claims map[string]any) string { return m.IDToken(claims) }

func baseProfile() map[string]any {
	return map[string]any{"sub": "ms-pairwise-sub", "oid": "ms-stable-oid", "tid": workTenantID,
		"email": "user@example.com", "name": "Microsoft User"}
}

func photoRequests(m *oauth2test.Server) int {
	n := 0
	for _, r := range m.Requests {
		if r.URL.Host == "graph.microsoft.com" {
			n++
		}
	}
	return n
}

// uses the stable oid claim instead of the pairwise sub claim (#10194)
func TestAccountSubjectUsesOid(t *testing.T) {
	m := oauth2test.New(t)
	p := New(opts("common"))
	idt := profileToken(m, baseProfile())
	res, err := p.GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt, AccessToken: "ms-access-token"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	sub, err := p.AccountSubject(ctx(), &oauth2.Tokens{IDToken: idt}, res.Data)
	if err != nil || sub != "ms-stable-oid" || res.Data["oid"] != "ms-stable-oid" || res.Data["sub"] != "ms-pairwise-sub" {
		t.Fatalf("sub %q data %v", sub, res.Data)
	}
	if res.User.Name != "Microsoft User" || res.User.Email != "user@example.com" || res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
}

func TestGetUserInfoFetchesProfilePhoto(t *testing.T) {
	m := oauth2test.New(t)
	photo := []byte{0xff, 0xd8, 0xff, 0x00, 0x01}
	m.Handle("GET graph.microsoft.com/v1.0/me/photos/96x96/$value", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(photo)
	})
	o := opts("common")
	o.ProfilePhotoSize = 96
	var mapped map[string]any
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) { mapped = p; return nil, nil }
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: profileToken(m, baseProfile()), AccessToken: "ms-access-token"}})
	if err != nil || res == nil {
		t.Fatal(err)
	}
	want := "data:image/jpeg;base64, " + base64.StdEncoding.EncodeToString(photo)
	if res.User.Image != want || res.Data["picture"] != want || mapped["picture"] != want {
		t.Fatalf("image %q", res.User.Image)
	}
	r := m.Last("graph.microsoft.com/v1.0/me/photos/96x96/$value")
	if r == nil || r.Header.Get("Authorization") != "Bearer ms-access-token" {
		t.Fatalf("photo request %+v", r)
	}
}

func TestGetUserInfoPhotoFailureIgnored(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET graph.microsoft.com/v1.0/me/photos/48x48/$value", 404, map[string]any{"error": "not found"})
	claims := baseProfile()
	claims["picture"] = "https://claim/picture"
	res, err := New(opts("common")).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: profileToken(m, claims), AccessToken: "at"}})
	if err != nil || res.User.Image != "https://claim/picture" || photoRequests(m) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

// does not fetch a photo when profile photos are disabled and still maps the profile
func TestNoPhotoWhenDisabled(t *testing.T) {
	m := oauth2test.New(t)
	o := opts("common")
	o.DisableProfilePhoto = true
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return map[string]any{"name": "Mapped User"}, nil }
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: profileToken(m, baseProfile()), AccessToken: "ms-access-token"}})
	if err != nil || res.User.Name != "Mapped User" || photoRequests(m) != 0 {
		t.Fatalf("%+v %v %d", res, err, photoRequests(m))
	}
}

// does not fetch a photo when accessToken is missing and still maps the profile
func TestNoPhotoWithoutAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	o := opts("common")
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return map[string]any{"name": "Mapped User"}, nil }
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: profileToken(m, baseProfile())}})
	if err != nil || res.User.Name != "Mapped User" || photoRequests(m) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

// returns null without fetching a photo when oid is missing / not a string
func TestNullWhenOidInvalid(t *testing.T) {
	for _, oid := range []any{nil, 123.0, "  "} {
		m := oauth2test.New(t)
		claims := baseProfile()
		if oid == nil {
			delete(claims, "oid")
		} else {
			claims["oid"] = oid
		}
		res, err := New(opts("common")).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: profileToken(m, claims), AccessToken: "ms-access-token"}})
		if res != nil || err != nil || photoRequests(m) != 0 {
			t.Fatalf("oid %v: %+v %v", oid, res, err)
		}
	}
}

func TestGetUserInfoWithoutIDToken(t *testing.T) {
	res, err := New(opts("common")).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestEmailVerifiedRules(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]any
		want  bool
	}{
		{"default false", nil, false},
		{"claim true", map[string]any{"email_verified": true}, true},
		{"claim false wins over arrays", map[string]any{"email_verified": false, "verified_primary_email": []any{"user@example.com"}}, false},
		{"primary list", map[string]any{"verified_primary_email": []any{"user@example.com"}}, true},
		{"secondary list", map[string]any{"verified_secondary_email": []any{"x@y", "user@example.com"}}, true},
		{"other email in list", map[string]any{"verified_primary_email": []any{"other@example.com"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := oauth2test.New(t)
			claims := baseProfile()
			for k, v := range c.extra {
				claims[k] = v
			}
			res, err := New(opts("common")).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: profileToken(m, claims)}})
			if err != nil || res.User.EmailVerified != c.want {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}

func TestMapProfileToUserOverride(t *testing.T) {
	m := oauth2test.New(t)
	o := opts("common")
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"email": "mapped@example.com", "emailVerified": true, "tenant": p["tid"]}, nil
	}
	res, err := New(o).GetUserInfo(ctx(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: profileToken(m, baseProfile())}})
	if err != nil || res.User.Email != "mapped@example.com" || !res.User.EmailVerified || res.User.Name != "Microsoft User" || res.User.Extra["tenant"] != workTenantID {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestCustomVerifyIDToken(t *testing.T) {
	o := opts("common")
	o.VerifyIDToken = func(_ context.Context, tok, nonce string) (bool, error) {
		return tok == "opaque" && nonce == "n", nil
	}
	v, _ := oauth2.AsIDTokenVerifier(New(o))
	if ok, _ := v.VerifyIDToken(ctx(), "opaque", "n"); !ok {
		t.Fatal("custom verifier not used")
	}
}
