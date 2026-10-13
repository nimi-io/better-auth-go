package oauthprovider

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/genericoauth"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of oauth.test.ts: describe("oauth - config") and describe("oauth - rate limiting").

func oaM2MPrivileges(c PrivilegeContext) (bool, error) {
	return c.Action == "create" || c.Action == "configure-client-credentials-scopes", nil
}

// oaSignedInJar signs the test user in over HTTP and returns the session jar.
func oaSignedInJar(t *testing.T, env *testEnv) (*oaJar, string) {
	t.Helper()
	jar := oaNewJar()
	res := oaSignInEmail(t, env, "", jar, nil)
	if res.status != 200 {
		t.Fatalf("sign in: %d %s", res.status, res.body)
	}
	jar.apply(res.header)
	u, _ := res.json()["user"].(map[string]any)
	return jar, oaStr(u, "id")
}

func oaCheckCreatedClient(t *testing.T, c map[string]any, wantSecret bool) {
	t.Helper()
	if oaStr(c, "client_id") == "" || c["user_id"] == nil {
		t.Fatalf("client: %v", c)
	}
	if _, has := c["client_secret"]; has != wantSecret {
		t.Fatalf("client_secret presence %v, want %v: %v", has, wantSecret, c)
	}
	if ru, _ := c["redirect_uris"].([]any); len(ru) != 1 || ru[0] != oaRedirectURI {
		t.Fatalf("redirect_uris: %v", c["redirect_uris"])
	}
}

// oaCodeFlowToCallback runs sign-in/social at the RP, authorize at the AS with the
// session jar (skip_consent) and the RP callback; it returns the callback response.
func oaCodeFlowToCallback(t *testing.T, env *testEnv, rp *oaRP, clientID string, session *oaJar) *response {
	t.Helper()
	rpJar := oaNewJar()
	authURL := rp.signInSocial(t, env, rpJar)
	oaContains(t, authURL, testAuthBase+"/oauth2/authorize")
	oaContains(t, authURL, "client_id="+clientID)
	loc, res := oaAuthorize(t, env, authURL, session)
	if loc == "" {
		t.Fatalf("authorize: %d %s", res.status, res.body)
	}
	oaContains(t, loc, oaRedirectURI)
	oaContains(t, loc, "code=")
	cb := oaFetch(t, env, "GET", loc, nil, rpJar, nil)
	oaContains(t, cb.location(), "/success")
	return cb
}

func TestOa_OAuthConfig(t *testing.T) {
	t.Run("should preserve form-urlencoded token body when req.body was pre-parsed", func(t *testing.T) {
		// Upstream simulates a Node framework that pre-parsed req.body; in Go the handler
		// always reads the raw form body, so this checks the form-encoded token request.
		env := newEnv(t, Options{Scopes: []string{"m2m:read"}, ClientPrivileges: oaM2MPrivileges})
		headers := env.signInWithTestUser()
		c := env.adminCreateClient(headers, map[string]any{
			"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
			"redirect_uris":              []any{oaRedirectURI},
			"application_type":           "native",
			"token_endpoint_auth_method": "client_secret_post",
			"skip_consent":               true,
			"client_credentials_scopes":  []any{"m2m:read"},
		})
		if oaStr(c, "client_id") == "" || oaStr(c, "client_secret") == "" {
			t.Fatalf("client: %v", c)
		}
		res := env.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {oaStr(c, "client_id")},
			"client_secret": {oaStr(c, "client_secret")}}, nil)
		m := res.json()
		if res.status != 200 || m["error"] != nil || m["access_token"] == nil || m["token_type"] != "Bearer" {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
	})

	storeCase := func(t *testing.T, opts Options, eo envOptions) {
		env := newEnv(t, opts, eo)
		oaRouteOAuth2(t, env)
		session, _ := oaSignedInJar(t, env)
		c := env.adminCreateClient(session.header(), map[string]any{
			"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
			"redirect_uris":              []any{oaRedirectURI},
			"application_type":           "native",
			"token_endpoint_auth_method": "client_secret_post",
			"skip_consent":               true,
		})
		oaCheckCreatedClient(t, c, true)
		rp := oaNewRP(t, env, oaStr(c, "client_id"), oaStr(c, "client_secret"), genericoauth.Config{})
		oaCodeFlowToCallback(t, env, rp, oaStr(c, "client_id"), session)
	}
	t.Run("storeClientSecret: undefined", func(t *testing.T) {
		storeCase(t, Options{}, envOptions{})
	})
	t.Run("storeClientSecret: hashed", func(t *testing.T) {
		storeCase(t, Options{StoreClientSecret: &StoreClientSecretOptions{Mode: "hashed"}}, envOptions{})
	})
	t.Run("storeClientSecret: encrypted", func(t *testing.T) {
		storeCase(t, Options{StoreClientSecret: &StoreClientSecretOptions{Mode: "encrypted"}, DisableJwtPlugin: true}, envOptions{noJwt: true})
	})

	for _, tc := range []struct{ disableJwtPlugin, publicClient, resource bool }{
		{false, false, false}, {true, false, false}, {false, true, false}, {true, true, false},
		{false, false, true}, {true, false, true}, {false, true, true}, {true, true, true},
	} {
		name := fmt.Sprintf("token return type - disableJwtPlugin: %v, publicClient: %v, resource: %v", tc.disableJwtPlugin, tc.publicClient, tc.resource)
		t.Run(name, func(t *testing.T) { oaTokenReturnType(t, tc.disableJwtPlugin, tc.publicClient, tc.resource) })
	}
}

func oaTokenReturnType(t *testing.T, disableJwtPlugin, publicClient, resource bool) {
	validResource := "https://api.example.com"
	if disableJwtPlugin {
		validResource = testAuthBase
	}
	opts := Options{DisableJwtPlugin: disableJwtPlugin, EnforcePerClientResources: new(bool)}
	if resource {
		opts.Resources = []ResourceInput{{Identifier: validResource}}
	}
	env := newEnv(t, opts, envOptions{noJwt: disableJwtPlugin})
	oaRouteOAuth2(t, env)
	session, userID := oaSignedInJar(t, env)
	method := "client_secret_post"
	if publicClient {
		method = "none"
	}
	c := env.adminCreateClient(session.header(), map[string]any{
		"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
		"redirect_uris":              []any{oaRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": method,
		"skip_consent":               true,
	})
	oaCheckCreatedClient(t, c, !publicClient)
	clientID, secret := oaStr(c, "client_id"), oaStr(c, "client_secret")
	cfg := genericoauth.Config{}
	if resource {
		cfg.TokenURLParams = map[string]string{"resource": validResource}
	}
	rp := oaNewRP(t, env, clientID, secret, cfg)
	cb := oaCodeFlowToCallback(t, env, rp, clientID, session)
	authToken := cb.header.Get("set-auth-token")
	if authToken == "" {
		t.Fatalf("missing session bearer token: %v", cb.header)
	}
	bearerH := map[string][]string{"Authorization": {"Bearer " + authToken}}
	accRes := oaFetch(t, env, "GET", oaRPBase+"/api/auth/list-accounts", nil, nil, bearerH)
	var accounts []map[string]any
	_ = jsonUnmarshalOa(accRes.body, &accounts)
	accountID := ""
	for _, a := range accounts {
		if a["providerId"] == oaProviderID {
			accountID = oaStr(a, "id")
		}
	}
	if accountID == "" {
		t.Fatalf("missing provider account: %s", accRes.body)
	}
	tok := oaFetch(t, env, "POST", oaRPBase+"/api/auth/get-access-token", map[string]any{"accountId": accountID, "userId": userID}, nil, bearerH)
	tm := tok.json()
	accessToken, idToken := oaStr(tm, "accessToken"), oaStr(tm, "idToken")
	if accessToken == "" {
		t.Fatalf("get-access-token: %d %s", tok.status, tok.body)
	}
	vo := ResourceVerifyOptions{Audience: []string{validResource}, Issuer: []string{testAuthBase}}
	if !disableJwtPlugin {
		vo.JWKSURL = testAuthBase + "/jwks"
	}
	rc := &ResourceClient{}
	if publicClient && !(resource && !disableJwtPlugin) {
		if _, err := rc.VerifyBearerToken(context.Background(), accessToken, vo); err == nil {
			t.Fatal("expected verifyBearerToken to fail")
		}
	} else {
		if !publicClient {
			vo.RemoteVerify = &oauthcore.RemoteVerify{IntrospectURL: testAuthBase + "/oauth2/introspect", ClientID: clientID,
				ClientSecret: secret, AllowMissingAudience: !(resource && !disableJwtPlugin)}
		}
		p, err := rc.VerifyBearerToken(context.Background(), accessToken, vo)
		if err != nil {
			t.Fatalf("verifyBearerToken: %v", err)
		}
		m := p.Map()
		if s, _ := m["sub"].(string); s == "" {
			t.Fatalf("sub: %v", m)
		}
		if m["iss"] != testAuthBase || m["scope"] != "openid profile email" || m["client_id"] != clientID {
			t.Fatalf("payload: %v", m)
		}
		if _, ok := m["iat"].(float64); !ok {
			t.Fatalf("iat: %v", m)
		}
		if _, ok := m["exp"].(float64); !ok {
			t.Fatalf("exp: %v", m)
		}
		if resource {
			want := []any{validResource, testAuthBase + "/oauth2/userinfo"}
			if !reflect.DeepEqual(m["aud"], want) {
				t.Fatalf("aud: %v, want %v", m["aud"], want)
			}
		} else if _, has := m["aud"]; has {
			t.Fatalf("aud should be undefined: %v", m["aud"])
		}
	}
	if disableJwtPlugin {
		if !publicClient {
			if _, err := oauthcore.JWTVerify(idToken, oauthcore.StaticKey([]byte(secret)), oauthcore.VerifyOptions{Algorithms: []string{"HS256"}}); err != nil {
				t.Fatalf("id token HS256: %v", err)
			}
		}
	} else {
		if idToken == "" {
			t.Fatal("missing id token")
		}
		jwks := env.mustCall("getJwks", betterauth.CallInput{})
		set, err := oauthcore.LocalJWKSet(jwks)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oauthcore.JWTVerify(idToken, set, oauthcore.VerifyOptions{Algorithms: []string{"EdDSA"}}); err != nil {
			t.Fatalf("id token EdDSA: %v", err)
		}
	}
}

func oaFindRule(p *betterauth.Plugin, path string) *betterauth.PluginRateLimit {
	for i := range p.RateLimit {
		if p.RateLimit[i].PathMatcher(path) {
			return &p.RateLimit[i]
		}
	}
	return nil
}

func oaExpectRule(t *testing.T, p *betterauth.Plugin, path string, window, max int) {
	t.Helper()
	r := oaFindRule(p, path)
	if r == nil || r.Window != time.Duration(window)*time.Second || r.Max != max {
		t.Fatalf("%s rule: %+v, want window %d max %d", path, r, window, max)
	}
}

func TestOa_OAuthRateLimiting(t *testing.T) {
	t.Run("should have default rate limits configured", func(t *testing.T) {
		env := newEnv(t, Options{})
		if len(env.plugin.RateLimit) != 6 {
			t.Fatalf("rules: %d", len(env.plugin.RateLimit))
		}
		oaExpectRule(t, env.plugin, "/oauth2/token", 60, 20)
		oaExpectRule(t, env.plugin, "/oauth2/authorize", 60, 30)
		oaExpectRule(t, env.plugin, "/oauth2/introspect", 60, 100)
		oaExpectRule(t, env.plugin, "/oauth2/revoke", 60, 30)
		oaExpectRule(t, env.plugin, "/oauth2/register", 60, 5)
		oaExpectRule(t, env.plugin, "/oauth2/userinfo", 60, 60)
	})
	t.Run("should allow custom rate limit values", func(t *testing.T) {
		env := newEnv(t, Options{RateLimit: &RateLimitOptions{
			Token:      &RateLimitRule{Window: 1, Max: 4},
			Introspect: &RateLimitRule{Window: 1, Max: 50},
		}})
		oaExpectRule(t, env.plugin, "/oauth2/token", 1, 4)
		oaExpectRule(t, env.plugin, "/oauth2/introspect", 1, 50)
		oaExpectRule(t, env.plugin, "/oauth2/authorize", 60, 30)
	})
	t.Run("should allow disabling rate limit for specific endpoints", func(t *testing.T) {
		env := newEnv(t, Options{RateLimit: &RateLimitOptions{
			Token:      &RateLimitRule{Disabled: true},
			Introspect: &RateLimitRule{Disabled: true},
		}})
		if len(env.plugin.RateLimit) != 4 {
			t.Fatalf("rules: %d", len(env.plugin.RateLimit))
		}
		if oaFindRule(env.plugin, "/oauth2/token") != nil || oaFindRule(env.plugin, "/oauth2/introspect") != nil {
			t.Fatal("expected token/introspect rules to be disabled")
		}
		if oaFindRule(env.plugin, "/oauth2/authorize") == nil {
			t.Fatal("expected authorize rule")
		}
	})

	m2mClient := func(t *testing.T, env *testEnv) (string, string) {
		headers := env.signInWithTestUser()
		c := env.adminCreateClient(headers, map[string]any{
			"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
			"redirect_uris":              []any{"http://localhost:5000/callback"},
			"application_type":           "native",
			"token_endpoint_auth_method": "client_secret_post",
			"client_credentials_scopes":  []any{"m2m:read"},
		})
		return oaStr(c, "client_id"), oaStr(c, "client_secret")
	}
	enableRL := func(c *betterauth.Config) { c.RateLimit = &betterauth.RateLimitConfig{Enabled: betterauth.Bool(true)} }

	t.Run("should enforce rate limits on token endpoint", func(t *testing.T) {
		env := newEnv(t, Options{Scopes: []string{"m2m:read"}, ClientPrivileges: oaM2MPrivileges,
			RateLimit: &RateLimitOptions{Token: &RateLimitRule{Window: 60, Max: 3}}}, envOptions{mutate: enableRL})
		id, secret := m2mClient(t, env)
		var statuses []int
		for i := 0; i < 5; i++ {
			res := env.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, nil)
			statuses = append(statuses, res.status)
		}
		if !reflect.DeepEqual(statuses, []int{200, 200, 200, 429, 429}) {
			t.Fatalf("statuses: %v", statuses)
		}
	})
	t.Run("should not rate limit when endpoint rate limit is disabled", func(t *testing.T) {
		env := newEnv(t, Options{Scopes: []string{"m2m:read"}, ClientPrivileges: oaM2MPrivileges,
			RateLimit: &RateLimitOptions{Token: &RateLimitRule{Disabled: true}}}, envOptions{mutate: enableRL})
		id, secret := m2mClient(t, env)
		for i := 0; i < 10; i++ {
			res := env.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}, nil)
			if res.status != 200 {
				t.Fatalf("request %d: %d %s", i, res.status, res.body)
			}
		}
	})
}
