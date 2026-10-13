package oauthprovider

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/introspect.test.ts.

func TestIr_OAuthIntrospect(t *testing.T) {
	var enabled atomic.Bool
	var jwksReads atomic.Int64
	env := irMainEnv(t, envOptions{mutate: func(c *betterauth.Config) {
		base := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := base(o)
			if err != nil {
				return nil, err
			}
			return irCountingAdapter{Adapter: a, model: "jwks", enabled: &enabled, count: &jwksReads}, nil
		}
	}})
	headers := env.signInWithTestUser()
	c := irClientFrom(t, env.adminCreateClient(headers, map[string]any{
		"redirect_uris":              []any{irRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      "openid profile email offline_access",
		"skip_consent":               true,
	}))
	if c.raw["user_id"] == nil || c.secret == "" {
		t.Fatalf("client: %v", c.raw)
	}
	if ru, _ := c.raw["redirect_uris"].([]any); len(ru) != 1 || ru[0] != irRedirectURI {
		t.Fatalf("redirect_uris: %v", c.raw["redirect_uris"])
	}
	fullMatch := func() map[string]any {
		return map[string]any{
			"active":    true,
			"client_id": c.id,
			"scope":     "openid profile email offline_access",
			"sub":       irAnyString,
			"iss":       testBaseURL,
			"exp":       irAnyNumber,
			"iat":       irAnyNumber,
			"sid":       irAnyString,
		}
	}
	t.Run("should fail unauthenticated request - no client_id or client_secret", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, "")
		res := irIntrospect(env, headers, nil, tokens["access_token"].(string), "")
		if res.status != 401 {
			t.Fatalf("expected 401, got %d %s", res.status, res.body)
		}
	})

	t.Run("should pass with token_type_hint access_token and sent jwt access_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, irValidResource)
		res := irIntrospect(env, headers, &c, tokens["access_token"].(string), "access_token")
		irMatch(t, res.json(), fullMatch())
	})

	t.Run("should pass with token_type_hint access_token and sent opaque access_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, "")
		res := irIntrospect(env, headers, &c, tokens["access_token"].(string), "access_token")
		irMatch(t, res.json(), fullMatch())
	})

	t.Run("should fail with token_type_hint access_token and sent refresh_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, "")
		res := irIntrospect(env, headers, &c, tokens["refresh_token"].(string), "access_token")
		irExpectInactive(t, res)
	})

	t.Run("should return inactive for an unknown access token", func(t *testing.T) {
		res := irIntrospect(env, headers, &c, "this-is-not-a-valid-access-token", "access_token")
		irExpectInactive(t, res)
	})

	t.Run("should pass with token_type_hint refresh_token and sent refresh_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, "")
		res := irIntrospect(env, headers, &c, tokens["refresh_token"].(string), "refresh_token")
		irMatch(t, res.json(), fullMatch())
	})

	t.Run("should fail with token_type_hint refresh_token and sent access_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, "")
		res := irIntrospect(env, headers, &c, tokens["access_token"].(string), "refresh_token")
		if v := res.json()["active"]; v != nil && v != false {
			t.Fatalf("expected falsy active, got %s", res.body)
		}
	})

	t.Run("should pass without token_type_hint and sent jwt access_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, irValidResource)
		res := irIntrospect(env, headers, &c, tokens["access_token"].(string), "")
		irMatch(t, res.json(), fullMatch())
	})

	t.Run("should read the signing keys once across repeated jwt introspections", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, irValidResource)
		// Upstream fakes Date 6 minutes ahead so the 5-minute JWKS cache is stale; clearing
		// the cache is the equivalent here.
		oauthcore.ResetJWKSCache()
		jwksReads.Store(0)
		enabled.Store(true)
		defer enabled.Store(false)
		for i := 0; i < 2; i++ {
			res := irIntrospect(env, headers, &c, tokens["access_token"].(string), "access_token")
			irMatch(t, res.json(), map[string]any{"active": true})
		}
		if n := jwksReads.Load(); n != 1 {
			t.Fatalf("expected 1 jwks read, got %d", n)
		}
	})

	t.Run("should pass without token_type_hint and sent opaque access_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, "")
		res := irIntrospect(env, headers, &c, tokens["access_token"].(string), "")
		irMatch(t, res.json(), fullMatch())
	})

	t.Run("should pass without token_type_hint and sent refresh_token", func(t *testing.T) {
		tokens := irGetTokens(env, headers, c, nil, "")
		res := irIntrospect(env, headers, &c, tokens["refresh_token"].(string), "")
		irMatch(t, res.json(), fullMatch())
	})

	t.Run("reports opaque access_token as inactive after the user signs out", func(t *testing.T) {
		testHeaders := env.signInWithTestUser()
		tokens := irGetTokens(env, testHeaders, c, nil, "")
		so := env.mustCall("signOut", betterauth.CallInput{Headers: testHeaders})
		if so["success"] != true {
			t.Fatalf("signOut: %v", so)
		}
		irExpectInactive(t, irIntrospect(env, headers, &c, tokens["access_token"].(string), "access_token"))
	})

	t.Run("reports opaque access_token as inactive when its bound session has expired, without a revoked flag", func(t *testing.T) {
		testHeaders := env.signInWithTestUser()
		sessionID := irSessionID(env, testHeaders)
		tokens := irGetTokens(env, testHeaders, c, nil, "")
		env.update("session", adapter.Record{"expiresAt": time.Now().Add(-time.Minute)}, eq("id", sessionID))
		rows := env.findMany("oauthAccessToken", eq("sessionId", sessionID))
		if len(rows) == 0 {
			t.Fatal("expected access token rows")
		}
		for _, r := range rows {
			if r["revoked"] != nil {
				t.Fatalf("revoked set: %v", r)
			}
		}
		irExpectInactive(t, irIntrospect(env, headers, &c, tokens["access_token"].(string), "access_token"))
	})

	t.Run("reports opaque access_token as inactive when the revoked flag is set while the session is live", func(t *testing.T) {
		testHeaders := env.signInWithTestUser()
		sessionID := irSessionID(env, testHeaders)
		tokens := irGetTokens(env, testHeaders, c, nil, "")
		irUpdateMany(env, "oauthAccessToken", adapter.Record{"revoked": time.Now()}, eq("sessionId", sessionID))
		irExpectInactive(t, irIntrospect(env, headers, &c, tokens["access_token"].(string), "access_token"))
	})

	t.Run("reports jwt access_token as inactive after the user signs out", func(t *testing.T) {
		testHeaders := env.signInWithTestUser()
		tokens := irGetTokens(env, testHeaders, c, nil, irValidResource)
		so := env.mustCall("signOut", betterauth.CallInput{Headers: testHeaders})
		if so["success"] != true {
			t.Fatalf("signOut: %v", so)
		}
		irExpectInactive(t, irIntrospect(env, headers, &c, tokens["access_token"].(string), "access_token"))
	})

	t.Run("should pass refresh_token introspection with logged out user", func(t *testing.T) {
		testHeaders := env.signInWithTestUser()
		tokens := irGetTokens(env, testHeaders, c, nil, "")
		so := env.mustCall("signOut", betterauth.CallInput{Headers: testHeaders})
		if so["success"] != true {
			t.Fatalf("signOut: %v", so)
		}
		res := irIntrospect(env, headers, &c, tokens["refresh_token"].(string), "refresh_token")
		m := res.json()
		want := fullMatch()
		delete(want, "sid")
		irMatch(t, m, want)
		if _, ok := m["sid"]; ok {
			t.Fatalf("sid should be undefined: %s", res.body)
		}
	})
}

func TestIr_OAuthIntrospectConfig(t *testing.T) {
	t.Run("should pass with the correct opaqueAccessTokenPrefix", func(t *testing.T) {
		prefix := "hello_"
		testScopes := []string{"read:profile"}
		env, h, c := irConfigEnv(t, func(o *Options) {
			o.Prefix = &PrefixOptions{OpaqueAccessToken: prefix}
			o.Scopes = testScopes
		})
		tok := irClientCredentials(env, h, c, strings.Join(testScopes, " "))
		at, _ := tok.json()["access_token"].(string)
		if !strings.HasPrefix(at, prefix) {
			t.Fatalf("access token %q lacks prefix (%d %s)", at, tok.status, tok.body)
		}
		res := irIntrospect(env, h, &c, at, "access_token")
		irMatch(t, res.json(), map[string]any{
			"active":    true,
			"client_id": c.id,
			"scope":     strings.Join(testScopes, " "),
			"iss":       testBaseURL,
			"exp":       irAnyNumber,
			"iat":       irAnyNumber,
		})
	})

	t.Run("should pass with the correct refreshTokenPrefix", func(t *testing.T) {
		rtPrefix := "hello_rt_"
		testScopes := []string{"openid", "offline_access"}
		env, h, c := irConfigEnv(t, func(o *Options) {
			o.Prefix = &PrefixOptions{RefreshToken: rtPrefix}
			o.Scopes = testScopes
		})
		tokens := irCodeTokens(env, h, c, testScopes, "")
		rt, ok := tokens["refresh_token"].(string)
		if !ok {
			t.Fatalf("no refresh_token: %v", tokens)
		}
		if !strings.HasPrefix(rt, rtPrefix) {
			t.Fatalf("refresh token %q lacks prefix", rt)
		}
		res := irIntrospect(env, h, &c, rt, "refresh_token")
		irMatch(t, res.json(), map[string]any{
			"active":    true,
			"client_id": c.id,
			"scope":     strings.Join(testScopes, " "),
			"iss":       testBaseURL,
			"sub":       irAnyString,
			"exp":       irAnyNumber,
			"iat":       irAnyNumber,
		})
	})

	t.Run("should include aud in opaque access token introspection response", func(t *testing.T) {
		testScopes := []string{"openid", "profile", "email", "offline_access"}
		env, h, c := irConfigEnv(t, func(o *Options) {
			o.DisableJwtPlugin = true
			o.Scopes = testScopes
		})
		tokens := irCodeTokens(env, h, c, testScopes, irValidResource)
		res := irIntrospect(env, h, &c, tokens["access_token"].(string), "access_token")
		irMatch(t, res.json(), map[string]any{
			"active":    true,
			"client_id": c.id,
			"aud":       []any{irValidResource, testAuthBase + "/oauth2/userinfo"},
		})
	})

	t.Run("should pass resources to customAccessTokenClaims for jwt and opaque introspection", func(t *testing.T) {
		testScopes := []string{"openid", "profile", "email", "offline_access"}
		custom := func(in AccessTokenClaimsInput) (*jsonx.Object, error) {
			o := jsonx.O("resource_count", len(in.Resources))
			if len(in.Resources) > 0 {
				o.Set("first_resource", in.Resources[0])
			} else {
				o.Set("first_resource", jsonx.Undefined)
			}
			return o, nil
		}
		for _, disableJwt := range []bool{false, true} {
			env, h, c := irConfigEnv(t, func(o *Options) {
				o.DisableJwtPlugin = disableJwt
				o.Scopes = testScopes
				o.CustomAccessTokenClaims = custom
			})
			tokens := irCodeTokens(env, h, c, testScopes, irValidResource)
			res := irIntrospect(env, h, &c, tokens["access_token"].(string), "access_token")
			irMatch(t, res.json(), map[string]any{
				"active":         true,
				"resource_count": float64(1),
				"first_resource": irValidResource,
			})
		}
	})
}

func TestIr_OAuthIntrospectRejectsNonOAuthSameIssuerJWTs(t *testing.T) {
	redirectURI := irRPBaseURL + "/api/auth/oauth2/callback/test"
	env := newEnv(t, Options{
		Resources:                 []ResourceInput{{Identifier: testBaseURL}},
		EnforcePerClientResources: betterauth.Bool(false),
	}, envOptions{jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL, Audience: testBaseURL}}})
	headers := env.signInWithTestUser()
	c := irClientFrom(t, env.adminCreateClient(headers, map[string]any{
		"redirect_uris":              []any{redirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      "openid profile email offline_access",
		"skip_consent":               true,
	}))
	getOAuthJwtAccessToken := func() string {
		verifier := irRandomString(32)
		code := env.authorizeCode(headers, "response_type", "code", "client_id", c.id, "state", irState,
			"scope", "openid profile email offline_access", "redirect_uri", redirectURI,
			"code_challenge", challengeFor(verifier), "code_challenge_method", "S256")
		res := env.token(map[string][]string{"grant_type": {"authorization_code"}, "code": {code},
			"code_verifier": {verifier}, "redirect_uri": {redirectURI}, "resource": {testBaseURL},
			"client_id": {c.id}, "client_secret": {c.secret}}, irWithHeaders(headers, "Accept", "application/json"))
		at, _ := res.json()["access_token"].(string)
		if at == "" {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
		return at
	}

	t.Run("treats a real OAuth JWT access token as active", func(t *testing.T) {
		at := getOAuthJwtAccessToken()
		m := irIntrospect(env, headers, &c, at, "access_token").json()
		if m["active"] != true || m["client_id"] != c.id {
			t.Fatalf("introspection: %v", m)
		}
	})

	t.Run("rejects a JWT plugin session token presented as an access token", func(t *testing.T) {
		m := env.mustCall("getToken", betterauth.CallInput{Headers: headers})
		sessionJwt, _ := m["token"].(string)
		if len(strings.Split(sessionJwt, ".")) != 3 {
			t.Fatalf("token: %v", m)
		}
		res := irIntrospect(env, headers, &c, sessionJwt, "access_token")
		if res.json()["active"] != false {
			t.Fatalf("expected inactive, got %s", res.body)
		}
	})
}
