package oauthprovider

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/userinfo.test.ts.

const irInvalidAccessTokenChallenge = `Bearer error="invalid_token", error_description="Invalid access token"`

type irDPoPKey struct {
	priv      any
	publicJwk *jsonx.Object
	jkt       string
}

func irCreateDPoPKey(t *testing.T) irDPoPKey {
	t.Helper()
	pub, priv, err := jose.GenerateKeyPair("ES256", jose.GenerateKeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.JWKFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return irDPoPKey{priv: priv, publicJwk: jose.ExportJWK(jwk), jkt: jwk.Thumbprint()}
}

func irCreateDPoPProof(t *testing.T, k irDPoPKey, method, u, jti, accessToken string) string {
	t.Helper()
	payload := jsonx.O("jti", jti, "htm", method, "htu", u, "iat", time.Now().Unix())
	if accessToken != "" {
		payload.Set("ath", oauthcore.DeriveDPoPAth(accessToken))
	}
	proof, err := jose.SignJWT(jsonx.O("typ", "dpop+jwt", "alg", "ES256", "jwk", k.publicJwk), payload, k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestIr_OAuthUserinfo(t *testing.T) {
	env := irMainEnv(t)
	headers := env.signInWithTestUser()
	sess := env.mustCall("getSession", betterauth.CallInput{Headers: headers})
	user, _ := sess["user"].(map[string]any)
	c := irClientFrom(t, env.adminCreateClient(headers, map[string]any{
		"redirect_uris":              []any{irRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
	}))
	if c.raw["user_id"] == nil || c.secret == "" {
		t.Fatalf("client: %v", c.raw)
	}
	if ru, _ := c.raw["redirect_uris"].([]any); len(ru) != 1 || ru[0] != irRedirectURI {
		t.Fatalf("redirect_uris: %v", c.raw["redirect_uris"])
	}
	getTokens := func(scopes []string, resource string, extra ...string) map[string]any {
		tokens := irGetTokens(env, headers, c, scopes, resource, extra...)
		if tokens["access_token"] == nil {
			t.Fatalf("no access_token: %v", tokens)
		}
		return tokens
	}
	get := func(authorization string) *response {
		return env.do("GET", "/oauth2/userinfo", nil, irWithHeaders(headers, "Authorization", authorization))
	}
	fullProfile := func() map[string]any {
		return map[string]any{
			"sub":            user["id"],
			"name":           user["name"],
			"given_name":     irAnyString,
			"family_name":    irAnyString,
			"email":          user["email"],
			"email_verified": user["emailVerified"],
		}
	}
	expectUndefined := func(t *testing.T, m map[string]any, keys ...string) {
		t.Helper()
		for _, k := range keys {
			if _, ok := m[k]; ok {
				t.Fatalf("%s should be undefined: %v", k, m)
			}
		}
	}

	t.Run("should fail unauthenticated request", func(t *testing.T) {
		getTokens(nil, "")
		res := env.do("GET", "/oauth2/userinfo", nil, headers)
		if res.status != 401 {
			t.Fatalf("expected 401, got %d %s", res.status, res.body)
		}
	})

	t.Run("should return an invalid_token challenge for an unknown bearer token", func(t *testing.T) {
		res := get("Bearer this-is-not-a-valid-access-token")
		if res.status != 401 || res.json()["error"] != "invalid_token" {
			t.Fatalf("got %d %s", res.status, res.body)
		}
		if v := res.header.Get("WWW-Authenticate"); v != irInvalidAccessTokenChallenge {
			t.Fatalf("WWW-Authenticate = %q", v)
		}
	})

	t.Run("should fail without the openid scope", func(t *testing.T) {
		tokens := getTokens([]string{"profile"}, "")
		res := get(tokens["access_token"].(string))
		if res.status != 400 {
			t.Fatalf("expected 400, got %d %s", res.status, res.body)
		}
	})

	t.Run("rejects a revoked access token with invalid_token (401), not invalid_scope", func(t *testing.T) {
		tokens := getTokens(nil, "")
		irUpdateMany(env, "oauthAccessToken", adapter.Record{"revoked": time.Now()}, eq("sessionId", irSessionID(env, headers)))
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tokens["access_token"].(string))
		_, err := env.call("oauth2UserInfo", betterauth.CallInput{Headers: h})
		if err == nil {
			t.Fatal("expected error")
		}
		if err.StatusCode != 401 || errBody(err)["error"] != "invalid_token" {
			t.Fatalf("got %d %v", err.StatusCode, errBody(err))
		}
		if v := err.Headers.Get("WWW-Authenticate"); v != irInvalidAccessTokenChallenge {
			t.Fatalf("WWW-Authenticate = %q", v)
		}
	})

	t.Run("should pass provide all user information - opaque", func(t *testing.T) {
		tokens := getTokens(nil, "")
		irMatch(t, get(tokens["access_token"].(string)).json(), fullProfile())
	})

	t.Run("should accept POST with the bearer token in the Authorization header", func(t *testing.T) {
		tokens := getTokens(nil, "")
		res := env.do("POST", "/oauth2/userinfo", nil, irWithHeaders(headers, "Authorization", "Bearer "+tokens["access_token"].(string)))
		irMatch(t, res.json(), map[string]any{"sub": user["id"]})
	})

	t.Run("should accept POST with the bearer token in the form body", func(t *testing.T) {
		tokens := getTokens(nil, "")
		res := env.do("POST", "/oauth2/userinfo", url.Values{"access_token": {tokens["access_token"].(string)}}, headers)
		irMatch(t, res.json(), map[string]any{"sub": user["id"]})
	})

	t.Run("should reject UserInfo requests with bearer tokens in both header and body", func(t *testing.T) {
		tokens := getTokens(nil, "")
		at := tokens["access_token"].(string)
		res := env.do("POST", "/oauth2/userinfo", url.Values{"access_token": {at}}, irWithHeaders(headers, "Authorization", "Bearer "+at))
		m := res.json()
		if res.status != 400 || m["error"] != "invalid_request" ||
			m["error_description"] != "Multiple access token transport methods are not allowed" {
			t.Fatalf("got %d %s", res.status, res.body)
		}
	})

	t.Run("should return userinfo via auth.api with headers only (no Request)", func(t *testing.T) {
		tokens := getTokens(nil, "")
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tokens["access_token"].(string))
		m := env.mustCall("oauth2UserInfo", betterauth.CallInput{Headers: h})
		irMatch(t, m, fullProfile())
	})

	t.Run("should reject auth.api userinfo when Authorization header is missing", func(t *testing.T) {
		_, err := env.call("oauth2UserInfo", betterauth.CallInput{Headers: http.Header{}})
		if err == nil {
			t.Fatal("expected error")
		}
		b := errBody(err)
		if err.StatusCode != 401 || b["error"] != "invalid_request" || b["error_description"] != "access token not found" {
			t.Fatalf("got %d %v", err.StatusCode, b)
		}
	})

	t.Run("should pass provide all user information - jwt", func(t *testing.T) {
		tokens := getTokens(nil, irValidResource)
		irMatch(t, get(tokens["access_token"].(string)).json(), fullProfile())
	})

	t.Run("enforces DPoP proof for DPoP-bound userinfo access", func(t *testing.T) {
		key := irCreateDPoPKey(t)
		code, verifier := irAuthorize(env, headers, c.id, irDefaultScopes, "dpop_jkt", key.jkt)
		tokenProof := irCreateDPoPProof(t, key, "POST", testAuthBase+"/oauth2/token", "token-proof", "")
		tr := irExchange(env, headers, c, code, verifier, irValidResource, http.Header{"Dpop": {tokenProof}})
		tokens := tr.json()
		if tokens["token_type"] != "DPoP" || tokens["access_token"] == nil {
			t.Fatalf("token: %d %s", tr.status, tr.body)
		}
		at := tokens["access_token"].(string)
		if res := get("Bearer " + at); res.status != 401 {
			t.Fatalf("bearer userinfo: expected 401, got %d %s", res.status, res.body)
		}
		bodyRes := env.do("POST", "/oauth2/userinfo", url.Values{"access_token": {at}}, headers)
		bm := bodyRes.json()
		if bodyRes.status != 401 || bm["error"] != "invalid_token" ||
			bm["error_description"] != "DPoP-bound access token requires the DPoP authorization scheme" {
			t.Fatalf("body userinfo: %d %s", bodyRes.status, bodyRes.body)
		}
		proof := irCreateDPoPProof(t, key, "GET", testAuthBase+"/oauth2/userinfo", "userinfo-proof", at)
		res := env.do("GET", "/oauth2/userinfo", nil, irWithHeaders(headers, "Authorization", "DPoP "+at, "DPoP", proof))
		irMatch(t, res.json(), map[string]any{"sub": user["id"], "name": user["name"], "email": user["email"]})
	})

	t.Run("should pass provide scoped user information - sub only", func(t *testing.T) {
		tokens := getTokens([]string{"openid"}, "")
		m := get(tokens["access_token"].(string)).json()
		irMatch(t, m, map[string]any{"sub": user["id"]})
		expectUndefined(t, m, "name", "given_name", "family_name", "email", "email_verified")
	})

	t.Run("returns explicitly requested UserInfo claims without granting the full scope bundle", func(t *testing.T) {
		tokens := getTokens([]string{"openid"}, "", "claims", `{"userinfo":{"name":{"essential":true},"email":null}}`)
		at := tokens["access_token"].(string)
		m := get(at).json()
		irMatch(t, m, map[string]any{"sub": user["id"], "name": user["name"], "email": user["email"]})
		expectUndefined(t, m, "given_name", "family_name", "email_verified")
		in := irIntrospect(env, headers, &c, at, "access_token").json()
		if in["active"] != true {
			t.Fatalf("introspection: %v", in)
		}
		expectUndefined(t, in, "name", "email")
	})

	t.Run("preserves requested UserInfo claims across refresh-token rotation", func(t *testing.T) {
		tokens := getTokens([]string{"openid", "offline_access"}, "", "claims", `{"userinfo":{"name":{"essential":true}}}`)
		rt, _ := tokens["refresh_token"].(string)
		if rt == "" {
			t.Fatalf("no refresh_token: %v", tokens)
		}
		rr := irPostForm(env, headers, "/oauth2/token", url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {rt}, "client_id": {c.id}, "client_secret": {c.secret}})
		at, _ := rr.json()["access_token"].(string)
		if at == "" {
			t.Fatalf("refresh: %d %s", rr.status, rr.body)
		}
		m := get(at).json()
		irMatch(t, m, map[string]any{"sub": user["id"], "name": user["name"]})
		expectUndefined(t, m, "given_name", "email")
	})

	t.Run("resolves JWT access-token UserInfo claims by scope, omitting individually requested claims", func(t *testing.T) {
		tokens := getTokens([]string{"openid"}, irValidResource, "claims", `{"userinfo":{"name":{"essential":true}}}`)
		m := get(tokens["access_token"].(string)).json()
		irMatch(t, m, map[string]any{"sub": user["id"]})
		expectUndefined(t, m, "name", "email")
	})

	t.Run("should pass provide scoped user information - profile only", func(t *testing.T) {
		tokens := getTokens([]string{"openid", "profile"}, "")
		m := get(tokens["access_token"].(string)).json()
		irMatch(t, m, map[string]any{"sub": user["id"], "name": user["name"], "given_name": irAnyString, "family_name": irAnyString})
		expectUndefined(t, m, "email", "email_verified")
	})

	t.Run("should pass provide scoped user information - email only", func(t *testing.T) {
		tokens := getTokens([]string{"openid", "email"}, "")
		m := get(tokens["access_token"].(string)).json()
		irMatch(t, m, map[string]any{"sub": user["id"], "email": user["email"], "email_verified": user["emailVerified"]})
		expectUndefined(t, m, "name", "given_name", "family_name")
	})
}
