package oauthprovider

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of token.test.ts (part 2): client_credentials, claims, config, client secrets,
// loopback redirects, scopes, at_hash and customTokenResponseFields.

func tkAllow(PrivilegeContext) (bool, error) { return true, nil }

func TestTk_OauthTokenClientCredentials(t *testing.T) {
	opts := tkResourceOpts(tkValidResource)
	opts.AllowDynamicClientRegistration = true
	opts.Scopes = []string{"openid", "profile", "email", "read:posts", "write:posts"}
	opts.ClientPrivileges = tkAllow
	e := tkNewEnv(t, opts)
	redirectURI := tkRPBase + "/api/auth/callback/test"
	oc := e.admin(map[string]any{
		"grant_types":               []any{"authorization_code", "client_credentials", "refresh_token"},
		"redirect_uris":             []any{redirectURI},
		"application_type":          "native",
		"skip_consent":              true,
		"scope":                     "read:posts write:posts",
		"client_credentials_scopes": []any{"read:posts", "write:posts"},
	})
	clientID, secret := tkStr(oc, "client_id"), tkStr(oc, "client_secret")
	if clientID == "" || secret == "" || oc["user_id"] == nil || oc["scope"] != "read:posts write:posts" {
		t.Fatalf("client: %v", oc)
	}
	if ru, _ := oc["redirect_uris"].([]any); len(ru) != 1 || ru[0] != redirectURI {
		t.Fatalf("redirect_uris: %v", oc["redirect_uris"])
	}
	ccBasic := func(scope string, resources ...string) *response {
		f := url.Values{"grant_type": {"client_credentials"}}
		if scope != "" {
			f.Set("scope", scope)
		}
		for _, r := range resources {
			f.Add("resource", r)
		}
		return e.token(f, basicAuth(clientID, secret))
	}
	checkCC := func(t *testing.T, m map[string]any, scope string) {
		t.Helper()
		if m["access_token"] == nil || m["id_token"] != nil || m["refresh_token"] != nil || m["scope"] != scope ||
			tkNum(m["expires_in"]) != 3600 || m["expires_at"] == nil {
			t.Fatalf("tokens: %v", m)
		}
	}

	t.Run("should obtain an opaque access token", func(t *testing.T) {
		checkCC(t, tkOK(t, ccBasic("read:posts")), "read:posts")
	})
	t.Run("returns invalid_request when client_credentials omits client_id", func(t *testing.T) {
		tkExpectErr(t, e.token(url.Values{"grant_type": {"client_credentials"}}, nil), 400, "invalid_request")
	})
	t.Run("rejects repeated form client authentication fields", func(t *testing.T) {
		body := "grant_type=client_credentials&client_id=repeated-auth-client&client_secret=first&client_secret=second"
		tkExpectErr(t, e.do("POST", "/oauth2/token", body, nil), 400, "invalid_request")
	})
	t.Run("rejects repeated non-empty form client IDs", func(t *testing.T) {
		body := "grant_type=client_credentials&client_id=" + url.QueryEscape(clientID) + "&client_id=duplicate-client&scope=read%3Aposts"
		tkExpectErr(t, e.do("POST", "/oauth2/token", body, tkBasic(clientID, secret)), 400, "invalid_request")
	})
	t.Run("rejects a secret method different from the registered method", func(t *testing.T) {
		r := e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {secret}}, nil)
		m := tkExpectErr(t, r, 400, "invalid_client")
		if !strings.Contains(tkStr(m, "error_description"), "registered for client_secret_basic") {
			t.Fatalf("description: %v", m)
		}
	})
	t.Run("returns 400 for failed client_secret_post authentication", func(t *testing.T) {
		pc := e.admin(map[string]any{
			"grant_types":                []any{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_post",
			"client_credentials_scopes":  []any{"read:posts"},
		})
		r := e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {tkStr(pc, "client_id")}, "client_secret": {"wrong-secret"}}, nil)
		tkExpectErr(t, r, 400, "invalid_client")
		if _, ok := r.header["Www-Authenticate"]; ok {
			t.Fatalf("unexpected WWW-Authenticate: %v", r.header)
		}
	})
	basicChallenge := func(name, authorization string) {
		t.Run(name, func(t *testing.T) {
			h := map[string][]string{"Authorization": {authorization}}
			r := e.token(url.Values{"grant_type": {"client_credentials"}}, h)
			tkExpectErr(t, r, 401, "invalid_client")
			if r.header.Get("WWW-Authenticate") != "Basic" {
				t.Fatalf("WWW-Authenticate: %q", r.header.Get("WWW-Authenticate"))
			}
		})
	}
	b64 := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	basicChallenge("challenges failed client_secret_basic authentication", b64(clientID+":wrong-secret"))
	basicChallenge("challenges client_secret_basic authentication without a secret", b64(clientID+":"))
	basicChallenge("challenges an unknown client_secret_basic client", b64("unknown-client:secret"))
	t.Run("should match created client scopes", func(t *testing.T) {
		checkCC(t, tkOK(t, ccBasic("")), "read:posts write:posts")
	})
	t.Run("should obtain a JWT access token", func(t *testing.T) {
		m := tkOK(t, ccBasic("read:posts", tkValidResource))
		checkCC(t, m, "read:posts")
		at := tkVerify(t, tkStr(m, "access_token"), e.jwks(), tkValidResource, testBaseURL)
		if tkGet(at, "azp") != clientID || tkGet(at, "sub") != clientID || tkGet(at, "iat") == nil ||
			tkNum(tkGet(at, "exp")) != tkNum(m["expires_at"]) || tkGet(at, "scope") != "read:posts" {
			t.Fatalf("access token: %v", at)
		}
	})
	t.Run("rejects a client_credentials scope outside the administrator-owned ceiling", func(t *testing.T) {
		tkExpectErr(t, ccBasic("delete:posts"), 400, "invalid_scope")
	})
}

// tkCodeFlow runs authorize + token exchange (client_secret_post) for a client.
func (e *tkEnv) codeFlow(t *testing.T, clientID, secret, redirectURI string, scopes []string, basic bool) *response {
	t.Helper()
	v := tkVerifier()
	loc := e.authorize(clientID, redirectURI, "123", scopes, v)
	if loc == "" || !strings.Contains(loc, redirectURI) {
		t.Fatalf("callback: %q", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") != "123" {
		t.Fatalf("state: %q", loc)
	}
	code := tkCode(t, loc)
	if basic {
		return e.token(tkCodeForm(code, v, redirectURI, "", ""), basicAuth(clientID, secret))
	}
	return e.token(tkCodeForm(code, v, redirectURI, clientID, secret), nil)
}

func TestTk_OauthTokenCustomIdTokenClaimsPrecedence(t *testing.T) {
	e := tkNewEnv(t, Options{CustomIDTokenClaims: func(IDTokenClaimsInput) (*jsonx.Object, error) {
		return jsonx.O("given_name", "CustomFirst", "family_name", "CustomLast", "custom_field", "custom_value"), nil
	}})
	redirectURI := tkRPBase + "/api/auth/callback/test"
	oc := e.admin(tkStdClientBody(redirectURI))
	t.Run("custom claims can add profile claim names to id_token", func(t *testing.T) {
		m := tkOK(t, e.codeFlow(t, tkStr(oc, "client_id"), tkStr(oc, "client_secret"), redirectURI, []string{"openid", "profile"}, false))
		p := tkVerify(t, tkStr(m, "id_token"), e.jwks(), "", "")
		if tkGet(p, "given_name") != "CustomFirst" || tkGet(p, "family_name") != "CustomLast" ||
			tkGet(p, "custom_field") != "custom_value" || tkGet(p, "name") != nil || tkGet(p, "sub") == nil {
			t.Fatalf("id token: %v", p)
		}
	})
}

func TestTk_OauthTokenConfig(t *testing.T) {
	redirectURI := tkRPBase + "/api/auth/callback/test"
	scopes := []string{"openid", "email", "profile", "offline_access", "read:payments", "write:payments", "read:profile"}
	create := func(t *testing.T, mut func(o *Options)) (*tkEnv, string, string) {
		t.Helper()
		opts := tkResourceOpts(tkValidResource)
		opts.Scopes = scopes
		opts.ClientPrivileges = tkAllow
		if mut != nil {
			mut(&opts)
		}
		e := tkNewEnv(t, opts)
		oc := e.admin(map[string]any{
			"token_endpoint_auth_method": "client_secret_post",
			"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
			"redirect_uris":              []any{redirectURI},
			"application_type":           "native",
			"skip_consent":               true,
			"client_credentials_scopes":  []any{"read:payments", "write:payments", "read:profile"},
		})
		return e, tkStr(oc, "client_id"), tkStr(oc, "client_secret")
	}
	lifetime := func(t *testing.T, m map[string]any, want float64) {
		t.Helper()
		if tkNum(m["expires_in"]) != want {
			t.Fatalf("expires_in %v != %v (%v)", m["expires_in"], want, m)
		}
		p := decodeJWTPayload(t, tkStr(m, "access_token"))
		if tkNum(p["exp"])-tkNum(p["iat"]) != want {
			t.Fatalf("exp-iat: %v", p)
		}
	}
	expirations := map[string]any{"read:payments": "30m", "write:payments": "5m"}
	for _, tc := range []struct {
		scopes []string
		result float64
	}{{[]string{"read:payments"}, 1800}, {[]string{"read:payments", "write:payments"}, 300}, {[]string{"read:profile"}, 7200}} {
		t.Run("scopeExpirations - access token expiration ["+strings.Join(tc.scopes, ", ")+"]", func(t *testing.T) {
			e, id, secret := create(t, func(o *Options) {
				o.M2MAccessTokenExpiresIn = 7200
				o.ScopeExpirations = expirations
			})
			m := tkOK(t, e.token(url.Values{"resource": {tkValidResource}, "grant_type": {"client_credentials"},
				"client_id": {id}, "client_secret": {secret}, "scope": {strings.Join(tc.scopes, " ")}}, nil))
			lifetime(t, m, tc.result)
		})
	}
	for _, tc := range []struct {
		scopes []string
		result float64
	}{{[]string{"read:payments", "offline_access"}, 1800}, {[]string{"read:payments", "write:payments", "offline_access"}, 300},
		{[]string{"profile", "offline_access"}, 7200}} {
		t.Run("scopeExpirations - access token expiration ["+strings.Join(tc.scopes, ", ")+"]", func(t *testing.T) {
			e, id, secret := create(t, func(o *Options) {
				o.AccessTokenExpiresIn = 7200
				o.ScopeExpirations = expirations
			})
			v := tkVerifier()
			loc := e.authorize(id, redirectURI, "123", tc.scopes, v)
			if !strings.Contains(loc, redirectURI) || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=123") {
				t.Fatalf("callback: %q", loc)
			}
			m := tkOK(t, e.token(url.Values{"code": {tkCode(t, loc)}, "code_verifier": {v}, "grant_type": {"authorization_code"},
				"resource": {tkValidResource}, "client_id": {id}, "client_secret": {secret}, "redirect_uri": {redirectURI}}, nil))
			lifetime(t, m, tc.result)
			rm := tkOK(t, e.token(url.Values{"resource": {tkValidResource}, "refresh_token": {tkStr(m, "refresh_token")},
				"grant_type": {"refresh_token"}, "client_id": {id}, "client_secret": {secret}}, nil))
			lifetime(t, rm, tc.result)
		})
	}
	t.Run("opaqueAccessTokenPrefix - client_credentials", func(t *testing.T) {
		e, id, secret := create(t, func(o *Options) { o.Prefix = &PrefixOptions{OpaqueAccessToken: "hello_"} })
		m := tkOK(t, e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {"read:profile"}}, nil))
		if !strings.HasPrefix(tkStr(m, "access_token"), "hello_") {
			t.Fatalf("access_token: %v", m)
		}
	})
	t.Run("opaqueAccessTokenPrefix, refreshTokenPrefix - code_authorization, refresh_token", func(t *testing.T) {
		atp, rtp := "hello__ac_", "hello_rt_"
		e, id, secret := create(t, func(o *Options) { o.Prefix = &PrefixOptions{OpaqueAccessToken: atp, RefreshToken: rtp} })
		v := tkVerifier()
		loc := e.authorize(id, redirectURI, "123", scopes, v)
		if !strings.Contains(loc, redirectURI) || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=123") {
			t.Fatalf("callback: %q", loc)
		}
		m := tkOK(t, e.token(url.Values{"code": {tkCode(t, loc)}, "code_verifier": {v}, "grant_type": {"authorization_code"},
			"client_id": {id}, "client_secret": {secret}, "redirect_uri": {redirectURI}}, nil))
		if !strings.HasPrefix(tkStr(m, "access_token"), atp) || !strings.HasPrefix(tkStr(m, "refresh_token"), rtp) {
			t.Fatalf("tokens: %v", m)
		}
		rm := tkOK(t, e.token(url.Values{"refresh_token": {tkStr(m, "refresh_token")}, "grant_type": {"refresh_token"},
			"client_id": {id}, "client_secret": {secret}}, nil))
		if !strings.HasPrefix(tkStr(rm, "access_token"), atp) || !strings.HasPrefix(tkStr(rm, "refresh_token"), rtp) {
			t.Fatalf("refreshed: %v", rm)
		}
	})
	t.Run("clientSecretPrefix - client_credentials", func(t *testing.T) {
		e, id, secret := create(t, func(o *Options) { o.Prefix = &PrefixOptions{ClientSecret: "hello_cs_"} })
		if !strings.HasPrefix(secret, "hello_cs_") {
			t.Fatalf("secret: %q", secret)
		}
		m := tkOK(t, e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {"read:profile"}}, nil))
		if m["access_token"] == nil {
			t.Fatalf("tokens: %v", m)
		}
	})
}

func TestTk_OauthTokenClientSecretValidation(t *testing.T) {
	redirectURI := "http://localhost:5010/api/auth/callback/test"
	create := func(t *testing.T, mut func(o *Options)) (*tkEnv, string, string) {
		t.Helper()
		opts := tkResourceOpts(tkValidResource)
		opts.Scopes = []string{"openid", "email", "profile", "offline_access", "read:profile"}
		mut(&opts)
		e := tkNewEnv(t, opts, envOptions{noJwt: opts.DisableJwtPlugin})
		oc := e.admin(tkStdClientBody(redirectURI))
		return e, tkStr(oc, "client_id"), tkStr(oc, "client_secret")
	}
	ccForm := func(id, secret string) url.Values {
		return url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {"read:profile"}}
	}
	t.Run("should return invalid_client for encrypted client secret format mismatch", func(t *testing.T) {
		e, id, secret := create(t, func(o *Options) {
			o.StoreClientSecret = &StoreClientSecretOptions{Mode: "encrypted"}
			o.DisableJwtPlugin = true
		})
		if id == "" || secret == "" {
			t.Fatal("client not created")
		}
		e.update("oauthClient", map[string]any{"clientSecret": "Mda8BIefhR8eFkYfFq8H7XAW-fj8GNjQYKPfN8LZ6u8"}, eq("clientId", id))
		m := tkExpectErr(t, e.token(ccForm(id, secret), nil), 400, "invalid_client")
		if m["error_description"] != "invalid client_secret" {
			t.Fatalf("description: %v", m)
		}
	})
	t.Run("should propagate custom decrypt storage errors during client secret verification", func(t *testing.T) {
		e, id, secret := create(t, func(o *Options) {
			o.StoreClientSecret = &StoreClientSecretOptions{
				Encrypt: func(s string) (string, error) { return s, nil },
				Decrypt: func(string) (string, error) { return "", errors.New("decrypt service unavailable") },
			}
			o.DisableJwtPlugin = true
		})
		if id == "" || secret == "" {
			t.Fatal("client not created")
		}
		r := e.token(ccForm(id, secret), nil)
		if r.status != 500 {
			t.Fatalf("expected 500, got %d %s", r.status, r.body)
		}
	})
}

func TestTk_IdTokenClaimOverrideSecurity(t *testing.T) {
	e := tkNewEnv(t, Options{CustomIDTokenClaims: func(IDTokenClaimsInput) (*jsonx.Object, error) {
		return jsonx.O("acr", "silver", "auth_time", 0, "amr", []any{"evil"}, "sub", "evil", "iss", "https://evil.com",
			"aud", "evil-client", "nonce", "evil-nonce", "iat", 0, "nbf", 0, "exp", 0, "jti", "evil-jti",
			"azp", "evil-authorized-party", "sid", "evil-sid", "at_hash", "evil-at-hash", "c_hash", "evil-code-hash",
			"s_hash", "evil-state-hash", "https://example.com/custom", "safe-custom-claim"), nil
	}})
	redirectURI := tkRPBase + "/api/auth/callback/test"
	oc := e.admin(tkStdClientBody(redirectURI))
	claims := func(t *testing.T) map[string]any {
		m := tkOK(t, e.codeFlow(t, tkStr(oc, "client_id"), tkStr(oc, "client_secret"), redirectURI, []string{"openid", "profile"}, false))
		if m["id_token"] == nil {
			t.Fatalf("tokens: %v", m)
		}
		return decodeJWTPayload(t, tkStr(m, "id_token"))
	}
	t.Run("customIdTokenClaims cannot override authentication context claims", func(t *testing.T) {
		c := claims(t)
		if c["acr"] != "0" || tkNum(c["auth_time"]) == 0 || c["amr"] != nil {
			t.Fatalf("claims: %v", c)
		}
	})
	t.Run("customIdTokenClaims cannot override provider-owned id token claims", func(t *testing.T) {
		c := claims(t)
		for k, evil := range map[string]any{"sub": "evil", "iss": "https://evil.com", "aud": "evil-client", "nonce": "evil-nonce",
			"jti": "evil-jti", "azp": "evil-authorized-party", "sid": "evil-sid", "at_hash": "evil-at-hash",
			"c_hash": "evil-code-hash", "s_hash": "evil-state-hash"} {
			if c[k] == evil {
				t.Fatalf("%s overridden: %v", k, c)
			}
		}
		for _, k := range []string{"iat", "nbf", "exp"} {
			if v, ok := c[k]; ok && tkNum(v) == 0 {
				t.Fatalf("%s overridden: %v", k, c)
			}
		}
		if c["https://example.com/custom"] != "safe-custom-claim" {
			t.Fatalf("custom claim: %v", c)
		}
	})
}

func TestTk_LoopbackRedirectURIMatching(t *testing.T) {
	e := tkNewEnv(t, Options{})
	succeed := func(name, registered, requested string) {
		t.Run(name, func(t *testing.T) {
			oc := e.admin(map[string]any{
				"token_endpoint_auth_method": "client_secret_post",
				"redirect_uris":              []any{registered},
				"application_type":           "native",
				"skip_consent":               true,
			})
			id, secret := tkStr(oc, "client_id"), tkStr(oc, "client_secret")
			v := tkVerifier()
			loc := e.authorize(id, requested, "123", []string{"openid"}, v)
			if !strings.Contains(loc, "code=") {
				t.Fatalf("callback: %q", loc)
			}
			m := tkOK(t, e.token(tkCodeForm(tkCode(t, loc), v, requested, id, secret), nil))
			if m["access_token"] == nil {
				t.Fatalf("tokens: %v", m)
			}
		})
	}
	succeed("127.0.0.1 with different ports should succeed", "http://127.0.0.1:8080/callback", "http://127.0.0.1:9090/callback")
	succeed("[::1] with different ports should succeed", "http://[::1]:8080/callback", "http://[::1]:3000/callback")
	t.Run("loopback with different path should be rejected", func(t *testing.T) {
		oc := e.admin(map[string]any{
			"redirect_uris":    []any{"http://127.0.0.1:8080/callback"},
			"application_type": "native",
			"skip_consent":     true,
		})
		loc := e.authorize(tkStr(oc, "client_id"), "http://127.0.0.1:8080/other-path", "123", []string{"openid"}, tkVerifier())
		if !strings.Contains(loc, "invalid_redirect") || strings.Contains(loc, "code=") {
			t.Fatalf("callback: %q", loc)
		}
	})
}

func TestTk_ScopePreservationThroughAuthorizationCodeFlow(t *testing.T) {
	e := tkNewEnv(t, Options{})
	redirectURI := tkRPBase + "/api/auth/callback/test"
	t.Run("scopes from authorization request should survive into token response", func(t *testing.T) {
		oc := e.admin(map[string]any{
			"token_endpoint_auth_method": "client_secret_post",
			"redirect_uris":              []any{redirectURI},
			"application_type":           "native",
			"skip_consent":               true,
		})
		m := tkOK(t, e.codeFlow(t, tkStr(oc, "client_id"), tkStr(oc, "client_secret"), redirectURI, []string{"openid", "profile", "email"}, false))
		if m["scope"] != "openid profile email" {
			t.Fatalf("scope: %v", m)
		}
	})
}

func TestTk_AtHashInIdTokens(t *testing.T) {
	e := tkNewEnv(t, tkResourceOpts(tkValidResource))
	redirectURI := tkRPBase + "/api/auth/oauth2/callback/test"
	nativeBody := map[string]any{"redirect_uris": []any{redirectURI}, "application_type": "native", "skip_consent": true}
	oc := e.admin(nativeBody)
	if oc["client_id"] == nil || oc["client_secret"] == nil {
		t.Fatalf("client: %v", oc)
	}
	getTokens := func(t *testing.T, scopes []string, resource string) map[string]any {
		t.Helper()
		v := tkVerifier()
		loc := e.authorize(tkStr(oc, "client_id"), redirectURI, "123", scopes, v)
		f := tkCodeForm(tkCode(t, loc), v, redirectURI, "", "")
		if resource != "" {
			f.Set("resource", resource)
		}
		return e.token(f, basicAuth(tkStr(oc, "client_id"), tkStr(oc, "client_secret"))).json()
	}
	t.Run("should include at_hash when id token is issued with access token", func(t *testing.T) {
		m := getTokens(t, []string{"openid"}, "")
		if m["id_token"] == nil || m["access_token"] == nil {
			t.Fatalf("tokens: %v", m)
		}
		if s, _ := decodeJWTPayload(t, tkStr(m, "id_token"))["at_hash"].(string); s == "" {
			t.Fatalf("at_hash missing")
		}
	})
	t.Run("at_hash should match manual computation for EdDSA", func(t *testing.T) {
		m := getTokens(t, []string{"openid"}, "")
		d := sha512.Sum512([]byte(tkStr(m, "access_token")))
		want := base64.RawURLEncoding.EncodeToString(d[:len(d)/2])
		if got := decodeJWTPayload(t, tkStr(m, "id_token"))["at_hash"]; got != want {
			t.Fatalf("at_hash %v != %v", got, want)
		}
	})
	t.Run("at_hash should not be present without openid scope", func(t *testing.T) {
		m := getTokens(t, []string{"offline_access"}, tkValidResource)
		if m["id_token"] != nil {
			t.Fatalf("tokens: %v", m)
		}
	})
	t.Run("customIdTokenClaims should not receive accessToken", func(t *testing.T) {
		var received []string
		e2 := tkNewEnv(t, Options{CustomIDTokenClaims: func(in IDTokenClaimsInput) (*jsonx.Object, error) {
			rt := reflect.TypeOf(in)
			received = nil
			for i := 0; i < rt.NumField(); i++ {
				received = append(received, rt.Field(i).Name)
			}
			return jsonx.NewObject(), nil
		}})
		oc2 := e2.admin(nativeBody)
		e2.codeFlow(t, tkStr(oc2, "client_id"), tkStr(oc2, "client_secret"), redirectURI, []string{"openid"}, true)
		has := func(n string) bool {
			for _, r := range received {
				if r == n {
					return true
				}
			}
			return false
		}
		if !has("User") || !has("Scopes") || !has("Metadata") || has("AccessToken") {
			t.Fatalf("received: %v", received)
		}
	})
}

func TestTk_CustomTokenResponseFields(t *testing.T) {
	e := tkNewEnv(t, Options{
		Scopes:           []string{"openid", "profile", "email", "offline_access", "service:read"},
		ClientPrivileges: tkAllow,
		CustomTokenResponseFields: func(in TokenResponseFieldsInput) (*jsonx.Object, error) {
			if in.GrantType == "authorization_code" && in.VerificationValue != nil && in.VerificationValue.ReferenceID != "" {
				return jsonx.O("org_id", in.VerificationValue.ReferenceID), nil
			}
			return jsonx.O("server_time", "2024-01-01"), nil
		},
	})
	redirectURI := tkRPBase + "/api/auth/oauth2/callback/test"
	body := tkStdClientBody(redirectURI)
	body["client_credentials_scopes"] = []any{"service:read"}
	oc := e.admin(body)
	id, secret := tkStr(oc, "client_id"), tkStr(oc, "client_secret")
	t.Run("should include custom fields in authorization_code token response", func(t *testing.T) {
		v := tkVerifier()
		loc := e.authorize(id, redirectURI, "custom-fields-test", []string{"openid"}, v)
		m := tkOK(t, e.token(tkCodeForm(tkCode(t, loc), v, redirectURI, id, secret), nil))
		if m["access_token"] == nil || m["server_time"] != "2024-01-01" {
			t.Fatalf("tokens: %v", m)
		}
	})
	t.Run("should not allow custom fields to override standard OAuth fields", func(t *testing.T) {
		e2 := tkNewEnv(t, Options{CustomTokenResponseFields: func(TokenResponseFieldsInput) (*jsonx.Object, error) {
			return jsonx.O("access_token", "should-be-ignored", "token_type", "should-be-ignored", "custom_field", "should-be-present"), nil
		}})
		oc2 := e2.admin(tkStdClientBody(redirectURI))
		id2, secret2 := tkStr(oc2, "client_id"), tkStr(oc2, "client_secret")
		v := tkVerifier()
		loc := e2.authorize(id2, redirectURI, "custom-fields-test", []string{"openid"}, v)
		m := tkOK(t, e2.token(tkCodeForm(tkCode(t, loc), v, redirectURI, id2, secret2), nil))
		if m["access_token"] == "should-be-ignored" || m["token_type"] != "Bearer" || m["custom_field"] != "should-be-present" {
			t.Fatalf("tokens: %v", m)
		}
	})
	t.Run("should include custom fields in client_credentials token response", func(t *testing.T) {
		m := tkOK(t, e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, nil))
		if m["access_token"] == nil || m["server_time"] != "2024-01-01" {
			t.Fatalf("tokens: %v", m)
		}
	})
}
