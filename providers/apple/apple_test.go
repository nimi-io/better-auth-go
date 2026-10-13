package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const redirect = "https://example.com/api/auth/callback/apple"

func newApple(mut func(o *Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "service.example.app", ClientSecret: "test-secret"}}
	if mut != nil {
		mut(&o)
	}
	return New(o)
}

func challenge(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestIdentity(t *testing.T) {
	p := newApple(nil)
	if p.ID() != "apple" || p.Name() != "Apple" {
		t.Fatalf("id/name %q %q", p.ID(), p.Name())
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newApple(func(o *Options) { o.Prompt = "consent"; o.Scope = []string{"extra"} })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: "state", RedirectURI: redirect, CodeVerifier: "apple-code-verifier",
		Scopes: []string{"req"}, LoginHint: "hint@example.com",
		AdditionalParams: map[string]string{"foo": "bar", "state": "evil"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	want := map[string]string{
		"response_type": "code id_token", "client_id": "service.example.app", "state": "state",
		"scope": "email name extra req", "redirect_uri": redirect, "response_mode": "form_post",
		"code_challenge_method": "S256", "code_challenge": challenge("apple-code-verifier"), "foo": "bar",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	// upstream apple does not forward prompt or login_hint
	for _, k := range []string{"prompt", "login_hint", "code_verifier"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
	if !strings.HasPrefix(u.RawQuery, "response_type=code+id_token&client_id=") {
		t.Errorf("param order %s", u.RawQuery)
	}
}

// apple.createAuthorizationURL: sends a PKCE code challenge when a code verifier is provided
func TestAuthorizationURLPKCE(t *testing.T) {
	u, err := newApple(nil).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: "state", RedirectURI: redirect, CodeVerifier: "apple-code-verifier"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") != challenge("apple-code-verifier") || u.Query().Has("code_verifier") {
		t.Fatalf("pkce %s", u)
	}
}

// apple.createAuthorizationURL: omits PKCE parameters when no code verifier is provided
func TestAuthorizationURLNoPKCE(t *testing.T) {
	u, err := newApple(nil).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: "state", RedirectURI: redirect})
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Has("code_challenge_method") || u.Query().Has("code_challenge") {
		t.Fatalf("pkce %s", u)
	}
}

func TestAuthorizationURLDisableDefaultScopeAndOverrides(t *testing.T) {
	p := newApple(func(o *Options) {
		o.DisableDefaultScope = true
		o.RedirectURI = "https://override/cb"
		o.AuthorizationEndpoint = "https://custom.example/authorize"
	})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: "s", RedirectURI: redirect})
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Has("scope") || u.Host != "custom.example" || u.Query().Get("redirect_uri") != "https://override/cb" {
		t.Fatalf("url %s", u)
	}
}

func TestAuthorizationURLRequiresClientIDAndSecret(t *testing.T) {
	for _, o := range []Options{
		{ProviderOptions: oauth2.ProviderOptions{ClientID: "id"}},
		{ProviderOptions: oauth2.ProviderOptions{ClientSecret: "secret"}},
	} {
		_, err := New(o).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: "s", RedirectURI: redirect})
		if err == nil || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
			t.Fatalf("err %v", err)
		}
	}
	// clientId as an array uses the first entry
	u, err := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{"a", "b"}, ClientSecret: "s"}}).
		CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: "s", RedirectURI: redirect})
	if err != nil || u.Query().Get("client_id") != "a" {
		t.Fatalf("%v %v", u, err)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST appleid.apple.com/auth/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "id_token": "idt", "token_type": "Bearer", "expires_in": 3600})
	tok, err := newApple(nil).ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{
		Code: "the-code", CodeVerifier: "ver", RedirectURI: redirect, DeviceID: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.IDToken != "idt" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("tokens %+v", tok)
	}
	r := m.Last("appleid.apple.com/auth/token")
	want := map[string]string{"grant_type": "authorization_code", "code": "the-code", "code_verifier": "ver",
		"redirect_uri": redirect, "client_id": "service.example.app", "client_secret": "test-secret"}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q want %q", k, r.Form.Get(k), v)
		}
	}
	if r.Form.Has("device_id") || r.Header.Get("Authorization") != "" {
		t.Errorf("unexpected request shape %v %v", r.Form, r.Header)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST appleid.apple.com/auth/token", 200, map[string]any{"access_token": "new-at", "token_type": "Bearer", "expires_in": 3600})
	tok, err := newApple(nil).RefreshAccessToken(context.Background(), "old-rt", nil)
	if err != nil || tok.AccessToken != "new-at" {
		t.Fatalf("%+v %v", tok, err)
	}
	r := m.Last("appleid.apple.com/auth/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-rt" ||
		r.Form.Get("client_id") != "service.example.app" || r.Form.Get("client_secret") != "test-secret" {
		t.Fatalf("form %v", r.Form)
	}
}

func TestRefreshOverride(t *testing.T) {
	p := newApple(func(o *Options) {
		o.RefreshAccessToken = func(_ context.Context, rt string) (*oauth2.Tokens, error) {
			return &oauth2.Tokens{AccessToken: "custom-" + rt}, nil
		}
	})
	tok, err := p.RefreshAccessToken(context.Background(), "x", nil)
	if err != nil || tok.AccessToken != "custom-x" {
		t.Fatalf("%+v %v", tok, err)
	}
}

func unsignedToken(claims map[string]any) string {
	p := jsonx.NewObject()
	for k, v := range claims {
		p.Set(k, v)
	}
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	return h + "." + base64.RawURLEncoding.EncodeToString(jsonx.MustMarshal(p)) + ".sig"
}

func TestGetUserInfoFromIDToken(t *testing.T) {
	idt := unsignedToken(map[string]any{"sub": "apple-sub", "email": "u@privaterelay.appleid.com", "email_verified": "true", "is_private_email": "true"})
	res, err := newApple(nil).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Name != "" || res.User.Email != "u@privaterelay.appleid.com" || !res.User.EmailVerified || res.User.Image != "" {
		t.Fatalf("user %+v", res.User)
	}
	if res.Data["name"] != "" {
		t.Fatalf("enriched name %v", res.Data["name"])
	}
	sub, _ := newApple(nil).AccountSubject(context.Background(), nil, res.Data)
	if sub != "apple-sub" {
		t.Fatalf("subject %q", sub)
	}
}

func TestGetUserInfoUsesFirstSignInUserName(t *testing.T) {
	idt := unsignedToken(map[string]any{"sub": "s", "email": "a@b.c", "email_verified": true, "name": "Token Name"})
	var seen map[string]any
	p := newApple(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			seen = profile
			return nil, nil
		}
	})
	user := &struct {
		Name  *oauth2.AppleUserName
		Email string
	}{Name: &oauth2.AppleUserName{FirstName: "Jane", LastName: ""}, Email: "other@b.c"}
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}, User: user})
	if err != nil || res == nil {
		t.Fatal(err)
	}
	if res.User.Name != "Jane" || res.User.Email != "a@b.c" || !res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	if seen["name"] != "Jane" || res.Data["name"] != "Jane" {
		t.Fatalf("mapper profile %v data %v", seen, res.Data)
	}
	// without a user payload the token name is used
	res, _ = p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}})
	if res.User.Name != "Token Name" {
		t.Fatalf("name %q", res.User.Name)
	}
}

func TestGetUserInfoEmailVerifiedFalse(t *testing.T) {
	for _, v := range []any{false, "false", nil} {
		idt := unsignedToken(map[string]any{"sub": "s", "email_verified": v})
		res, _ := newApple(nil).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}})
		if res.User.EmailVerified {
			t.Fatalf("verified for %v", v)
		}
	}
}

func TestGetUserInfoWithoutIDToken(t *testing.T) {
	res, err := newApple(nil).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUserOverride(t *testing.T) {
	idt := unsignedToken(map[string]any{"sub": "s", "email": "a@b.c", "email_verified": true})
	p := newApple(func(o *Options) {
		o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
			return map[string]any{"name": "Mapped", "image": "https://img", "emailVerified": false, "custom": profile["sub"]}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Name != "Mapped" || res.User.Image != "https://img" || res.User.EmailVerified || res.User.Email != "a@b.c" || res.User.Extra["custom"] != "s" {
		t.Fatalf("user %+v", res.User)
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	p := newApple(func(o *Options) {
		o.GetUserInfo = func(_ context.Context, tok *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom " + tok.AccessToken}, Data: map[string]any{"sub": "x"}}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "custom at" {
		t.Fatalf("%+v %v", res, err)
	}
}

// ---- id token verification (apple.test.ts "apple id_token verification") ----

func signAppleToken(t *testing.T, m *oauth2test.Server, nonce string, mut func(c *jsonx.Object, h *jsonx.Object)) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.JWKFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk.Kid, jwk.Alg, jwk.Use = "test-apple-key", "ES256", "sig"
	m.JSON("GET appleid.apple.com/auth/keys", 200, jose.JWKS{Keys: []jose.JWK{jwk}})
	now := float64(time.Now().Unix())
	claims := jsonx.O("sub", "apple-user-123", "email", "user@example.com", "email_verified", true, "nonce", nonce,
		"iss", Issuer, "aud", "com.example.app", "iat", now, "exp", now+3600)
	header := jsonx.O("alg", "ES256", "kid", "test-apple-key")
	if mut != nil {
		mut(claims, header)
	}
	tok, err := jose.SignJWT(header, claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func bundleProvider() *oauth2.GenericProvider {
	return newApple(func(o *Options) { o.AppBundleIdentifier = "com.example.app" })
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func verify(t *testing.T, p oauth2.Provider, token, nonce string) bool {
	t.Helper()
	v, ok := oauth2.AsIDTokenVerifier(p)
	if !ok {
		t.Fatal("id token sign-in not supported")
	}
	res, err := v.VerifyIDToken(context.Background(), token, nonce)
	if err != nil {
		t.Fatalf("verify error %v", err)
	}
	return res
}

func TestVerifyIDTokenAcceptsRawNonce(t *testing.T) {
	m := oauth2test.New(t)
	tok := signAppleToken(t, m, "raw-nonce", nil)
	if !verify(t, bundleProvider(), tok, "raw-nonce") {
		t.Fatal("expected valid")
	}
}

func TestVerifyIDTokenAcceptsHashedNonce(t *testing.T) {
	m := oauth2test.New(t)
	tok := signAppleToken(t, m, sha256Hex("raw-native-ios-nonce"), nil)
	if !verify(t, bundleProvider(), tok, "raw-native-ios-nonce") {
		t.Fatal("expected valid")
	}
}

func TestVerifyIDTokenRejectsMismatchedNonce(t *testing.T) {
	m := oauth2test.New(t)
	tok := signAppleToken(t, m, sha256Hex("raw-native-ios-nonce"), nil)
	if verify(t, bundleProvider(), tok, "different-nonce") {
		t.Fatal("expected invalid")
	}
}

func TestVerifyIDTokenAudienceSelection(t *testing.T) {
	m := oauth2test.New(t)
	tok := signAppleToken(t, m, "n", nil)
	// default audience is the client id: the bundle-id token is rejected
	if verify(t, newApple(nil), tok, "") {
		t.Fatal("client-id audience must reject bundle-id token")
	}
	// explicit audience wins over appBundleIdentifier
	p := newApple(func(o *Options) {
		o.AppBundleIdentifier = "other.bundle"
		o.Audience = []string{"x", "com.example.app"}
	})
	if !verify(t, p, tok, "") {
		t.Fatal("audience override should accept")
	}
	// clientId array is accepted as audience
	p = New(Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{"service.example.app", "com.example.app"}, ClientSecret: "s"}})
	if !verify(t, p, tok, "") {
		t.Fatal("clientId array audience should accept")
	}
}

func TestVerifyIDTokenRejections(t *testing.T) {
	cases := map[string]func(c, h *jsonx.Object){
		"wrong issuer":  func(c, _ *jsonx.Object) { c.Set("iss", "https://evil.test") },
		"expired":       func(c, _ *jsonx.Object) { c.Set("exp", float64(time.Now().Add(-time.Minute).Unix())) },
		"too old (iat)": func(c, _ *jsonx.Object) { c.Set("iat", float64(time.Now().Add(-2*time.Hour).Unix())) },
		"unknown kid":   func(_, h *jsonx.Object) { h.Set("kid", "other") },
		"missing kid":   func(_, h *jsonx.Object) { h.Delete("kid") },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			m := oauth2test.New(t)
			tok := signAppleToken(t, m, "n", mut)
			if verify(t, bundleProvider(), tok, "n") {
				t.Fatal("expected invalid")
			}
		})
	}
}

func TestVerifyIDTokenJWKSFailure(t *testing.T) {
	m := oauth2test.New(t)
	tok := signAppleToken(t, m, "n", nil)
	m.JSON("GET appleid.apple.com/auth/keys", 500, map[string]any{"error": "boom"})
	oauth2.ResetJWKSCache()
	if verify(t, bundleProvider(), tok, "n") {
		t.Fatal("expected invalid")
	}
}

// forwards request ctx to a custom verifyIdToken option (issue #1214)
func TestVerifyIDTokenCustomVerifierReceivesContext(t *testing.T) {
	type key struct{}
	var seen string
	p := newApple(func(o *Options) {
		o.VerifyIDToken = func(ctx context.Context, _, _ string) (bool, error) {
			seen, _ = ctx.Value(key{}).(string)
			return seen == "ios", nil
		}
	})
	v, _ := oauth2.AsIDTokenVerifier(p)
	ok, err := v.VerifyIDToken(context.WithValue(context.Background(), key{}, "ios"), "token", "nonce")
	if err != nil || !ok || seen != "ios" {
		t.Fatalf("%v %v %q", ok, err, seen)
	}
}

func TestDisableIDTokenSignIn(t *testing.T) {
	p := newApple(func(o *Options) { o.DisableIDTokenSignIn = true })
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("id token sign-in should be disabled")
	}
}
