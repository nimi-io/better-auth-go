package oauthprovider

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of token.test.ts (part 3): verificationValueSchema, per-client grant enforcement,
// DPoP and confirmationTokenType.

func tkParseVV(t *testing.T, v map[string]any) (*jsonx.Object, bool) {
	t.Helper()
	raw, _ := json.Marshal(v)
	pv, err := jsonx.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, issues := zParse(verificationValueSchema, pv)
	if len(issues) > 0 {
		return nil, false
	}
	o, _ := out.(*jsonx.Object)
	return o, true
}

func TestTk_VerificationValueSchema(t *testing.T) {
	vv := func(query map[string]any, extra ...any) map[string]any {
		m := map[string]any{"type": "authorization_code", "query": query, "userId": "u1", "sessionId": "s1"}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i].(string)] = extra[i+1]
		}
		return m
	}
	expectOK := func(t *testing.T, v map[string]any, want bool) *jsonx.Object {
		t.Helper()
		o, ok := tkParseVV(t, v)
		if ok != want {
			t.Fatalf("success = %v, want %v (%v)", ok, want, v)
		}
		return o
	}
	full := func(extra map[string]any) map[string]any {
		q := map[string]any{"response_type": "code", "client_id": "test-client", "redirect_uri": "https://example.com/callback", "scope": "openid"}
		for k, v := range extra {
			q[k] = v
		}
		return map[string]any{"type": "authorization_code", "query": q, "userId": "user-1", "sessionId": "session-1"}
	}
	t.Run("should validate a well-formed verification value", func(t *testing.T) {
		expectOK(t, full(map[string]any{"state": "abc123"}), true)
	})
	t.Run("should validate a verification value without state", func(t *testing.T) {
		expectOK(t, full(nil), true)
	})
	t.Run("should validate a headless verification value without redirect_uri", func(t *testing.T) {
		v := full(nil)
		delete(v["query"].(map[string]any), "redirect_uri")
		expectOK(t, v, true)
	})
	t.Run("should validate a verification value with UserInfo claims", func(t *testing.T) {
		expectOK(t, full(map[string]any{"claims": `{"userinfo":{"name":{"essential":true}}}`}), true)
	})
	t.Run("should reject a verification value with malformed claims", func(t *testing.T) {
		expectOK(t, full(map[string]any{"claims": "not-json"}), false)
	})
	base := func() map[string]any {
		return map[string]any{"client_id": "test", "redirect_uri": "https://example.com", "state": "abc"}
	}
	t.Run("should reject a verification value with wrong type", func(t *testing.T) {
		v := vv(base())
		v["type"] = "password_reset"
		expectOK(t, v, false)
	})
	t.Run("should reject a verification value missing required fields", func(t *testing.T) {
		expectOK(t, map[string]any{"type": "authorization_code", "query": base()}, false)
	})
	t.Run("should pass through unknown fields for extensibility", func(t *testing.T) {
		o := expectOK(t, vv(base(), "futureField", "should-pass-through"), true)
		if tkGet(o, "futureField") != "should-pass-through" {
			t.Fatalf("futureField: %v", o)
		}
	})
	withQuery := func(k string, v any) map[string]any {
		return vv(map[string]any{"client_id": "test", "redirect_uri": "https://example.com", k: v})
	}
	t.Run("should coerce valid max_age values in stored authorization queries", func(t *testing.T) {
		o := expectOK(t, withQuery("max_age", "30"), true)
		q, _ := tkGet(o, "query").(*jsonx.Object)
		if q == nil || tkNum(tkGet(q, "max_age")) != 30 {
			t.Fatalf("max_age: %v", o)
		}
	})
	t.Run("should reject invalid max_age values in stored authorization queries", func(t *testing.T) {
		expectOK(t, withQuery("max_age", -1), false)
	})
	t.Run("should reject empty max_age values in stored authorization queries", func(t *testing.T) {
		for _, m := range []string{"", "   "} {
			expectOK(t, withQuery("max_age", m), false)
		}
	})
	t.Run("should accept valid prompt values in any order", func(t *testing.T) {
		expectOK(t, withQuery("prompt", "consent login"), true)
	})
	t.Run("should reject prompt=none combined with other prompt values", func(t *testing.T) {
		expectOK(t, withQuery("prompt", "none login"), false)
	})
}

func TestTk_OauthTokenPerClientGrantTypeEnforcement(t *testing.T) {
	e := tkNewEnv(t, Options{
		Scopes:           []string{"openid", "profile", "email", "offline_access", "m2m:read", "m2m:write"},
		ClientPrivileges: tkAllow,
	})
	redirectURI := tkRPBase + "/api/auth/oauth2/callback/test"
	acOnly := e.admin(map[string]any{
		"grant_types":      []any{"authorization_code"},
		"redirect_uris":    []any{redirectURI},
		"application_type": "native",
		"skip_consent":     true,
	})
	if acOnly["client_secret"] == nil {
		t.Fatalf("client: %v", acOnly)
	}
	cc := func(id, secret string) *response {
		return e.token(url.Values{"grant_type": {"client_credentials"}}, basicAuth(id, secret))
	}
	t.Run("rejects client_credentials for an authorization_code-only client", func(t *testing.T) {
		m := tkExpectErr(t, cc(tkStr(acOnly, "client_id"), tkStr(acOnly, "client_secret")), 400, "unauthorized_client")
		if m["access_token"] != nil {
			t.Fatal(m)
		}
	})
	t.Run("still issues refresh tokens to an authorization_code client with offline_access", func(t *testing.T) {
		v := tkVerifier()
		loc := e.authorize(tkStr(acOnly, "client_id"), redirectURI, "grant-enforcement", []string{"openid", "offline_access"}, v)
		m := tkOK(t, e.token(tkCodeForm(tkCode(t, loc), v, redirectURI, "", ""), basicAuth(tkStr(acOnly, "client_id"), tkStr(acOnly, "client_secret"))))
		if m["access_token"] == nil || m["refresh_token"] == nil {
			t.Fatalf("tokens: %v", m)
		}
	})
	t.Run("fails closed when a client_credentials client has no M2M scope authority", func(t *testing.T) {
		c := e.admin(map[string]any{
			"grant_types":      []any{"client_credentials"},
			"redirect_uris":    []any{redirectURI},
			"application_type": "native",
			"skip_consent":     true,
		})
		if s, ok := c["client_credentials_scopes"].([]any); !ok || len(s) != 0 {
			t.Fatalf("client_credentials_scopes: %v", c["client_credentials_scopes"])
		}
		m := tkExpectErr(t, cc(tkStr(c, "client_id"), tkStr(c, "client_secret")), 400, "unauthorized_client")
		if m["access_token"] != nil {
			t.Fatal(m)
		}
	})
	t.Run("fails closed when a legacy client has a null M2M scope authority", func(t *testing.T) {
		c := e.admin(map[string]any{
			"grant_types":               []any{"client_credentials"},
			"client_credentials_scopes": []any{"m2m:read"},
		})
		e.update("oauthClient", map[string]any{"clientCredentialsScopes": nil}, eq("clientId", tkStr(c, "client_id")))
		tkExpectErr(t, cc(tkStr(c, "client_id"), tkStr(c, "client_secret")), 400, "unauthorized_client")
	})
	t.Run("classifies public client_credentials clients as unauthorized_client", func(t *testing.T) {
		c := e.admin(map[string]any{
			"grant_types":                []any{"client_credentials"},
			"token_endpoint_auth_method": "none",
		})
		e.update("oauthClient", map[string]any{"clientCredentialsScopes": []any{"m2m:read"}}, eq("clientId", tkStr(c, "client_id")))
		r := e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {tkStr(c, "client_id")}}, nil)
		m := tkExpectErr(t, r, 400, "unauthorized_client")
		if m["error_description"] != "public clients cannot use the client_credentials grant" {
			t.Fatalf("description: %v", m)
		}
	})
	t.Run("allows client_credentials for a client registered for it", func(t *testing.T) {
		c := e.admin(map[string]any{
			"grant_types":               []any{"client_credentials"},
			"redirect_uris":             []any{redirectURI},
			"application_type":          "native",
			"skip_consent":              true,
			"client_credentials_scopes": []any{"m2m:read", "m2m:read"},
		})
		if s, _ := c["client_credentials_scopes"].([]any); len(s) != 1 || s[0] != "m2m:read" {
			t.Fatalf("client_credentials_scopes: %v", c["client_credentials_scopes"])
		}
		m := tkOK(t, cc(tkStr(c, "client_id"), tkStr(c, "client_secret")))
		if m["access_token"] == nil || m["scope"] != "m2m:read" {
			t.Fatalf("tokens: %v", m)
		}
	})
	t.Run("rejects /authorize for a client not registered for authorization_code", func(t *testing.T) {
		c := e.admin(map[string]any{
			"grant_types":      []any{"client_credentials"},
			"redirect_uris":    []any{redirectURI},
			"application_type": "native",
			"skip_consent":     true,
		})
		loc := e.authorize(tkStr(c, "client_id"), redirectURI, "authorize-grant-enforcement", []string{"openid"}, tkVerifier())
		if !strings.Contains(loc, "error=unauthorized_client") {
			t.Fatalf("location: %q", loc)
		}
	})
}

// tkDPoPKey is an ES256 DPoP key pair.
type tkDPoPKey struct {
	priv any
	pub  *jsonx.Object
	jkt  string
}

func tkNewDPoPKey(t *testing.T) *tkDPoPKey {
	t.Helper()
	pub, priv, err := jose.GenerateKeyPair("ES256", jose.GenerateKeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.JWKFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &tkDPoPKey{priv: priv, pub: jose.ExportJWK(jwk), jkt: jwk.Thumbprint()}
}

func (k *tkDPoPKey) proof(t *testing.T, method, u, jti string) string {
	t.Helper()
	tok, err := jose.SignJWT(jsonx.O("typ", "dpop+jwt", "alg", "ES256", "jwk", k.pub),
		jsonx.O("jti", jti, "htm", method, "htu", u, "iat", time.Now().Unix()), k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestTk_OauthTokenDPoP(t *testing.T) {
	jwtResource := "https://dpop-api.example.com"
	requiredResource := "https://dpop-required.example.com"
	tokenEndpoint := testAuthBase + "/oauth2/token"
	tr := true
	f := false
	e := tkNewEnv(t, Options{
		AllowDynamicClientRegistration: true,
		RefreshTokenReuseInterval:      30,
		Resources:                      []ResourceInput{{Identifier: jwtResource}, {Identifier: requiredResource, DPoPBoundAccessTokensRequired: &tr}},
		EnforcePerClientResources:      &f,
	})
	redirectURI := tkRPBase + "/api/auth/callback/test"
	oc := e.admin(map[string]any{
		"token_endpoint_auth_method": "client_secret_post",
		"grant_types":                []any{"authorization_code", "refresh_token"},
		"redirect_uris":              []any{redirectURI},
		"application_type":           "native",
		"skip_consent":               true,
	})
	id, secret := tkStr(oc, "client_id"), tkStr(oc, "client_secret")
	withProof := func(proof string) http.Header {
		if proof == "" {
			return nil
		}
		return http.Header{"Dpop": {proof}}
	}
	exchange := func(code, verifier, resource, proof string) *response {
		return e.token(tkCodeForm(code, verifier, redirectURI, id, secret, resource), withProof(proof))
	}
	authorizeForCode := func(t *testing.T, jkt, resource string) (string, string) {
		t.Helper()
		v := tkVerifier()
		var extra []string
		if jkt != "" {
			extra = append(extra, "dpop_jkt", jkt)
		}
		extra = append(extra, "resource", resource)
		loc := e.authorize(id, redirectURI, "123", []string{"openid", "offline_access"}, v, extra...)
		return tkCode(t, loc), v
	}
	cnfJKT := func(t *testing.T, token string) any {
		t.Helper()
		cnf, _ := decodeJWTPayload(t, token)["cnf"].(map[string]any)
		return cnf["jkt"]
	}

	t.Run("issues a JWT access token bound to the proof key via cnf.jkt", func(t *testing.T) {
		k := tkNewDPoPKey(t)
		code, v := authorizeForCode(t, k.jkt, jwtResource)
		m := tkOK(t, exchange(code, v, jwtResource, k.proof(t, "POST", tokenEndpoint, "issue-proof")))
		if m["token_type"] != "DPoP" || cnfJKT(t, tkStr(m, "access_token")) != k.jkt {
			t.Fatalf("tokens: %v", m)
		}
	})
	t.Run("rejects a token request without a proof when the resource requires DPoP", func(t *testing.T) {
		code, v := authorizeForCode(t, "", requiredResource)
		m := tkExpectErr(t, exchange(code, v, requiredResource, ""), 0, "invalid_dpop_proof")
		if m["access_token"] != nil {
			t.Fatal(m)
		}
	})
	refresh := func(rt, proof string) *response {
		return e.token(tkRefreshForm(rt, id, secret, ""), withProof(proof))
	}
	t.Run("preserves the key binding across refresh and rejects a proofless refresh", func(t *testing.T) {
		k := tkNewDPoPKey(t)
		code, v := authorizeForCode(t, k.jkt, jwtResource)
		tokens := tkOK(t, exchange(code, v, jwtResource, k.proof(t, "POST", tokenEndpoint, "rotate-issue-proof")))
		rt := tkStr(tokens, "refresh_token")
		if rt == "" {
			t.Fatalf("tokens: %v", tokens)
		}
		tkExpectErr(t, refresh(rt, ""), 0, "invalid_dpop_proof")
		rotated := tkOK(t, refresh(rt, k.proof(t, "POST", tokenEndpoint, "rotate-refresh-proof")))
		if rotated["token_type"] != "DPoP" || cnfJKT(t, tkStr(rotated, "access_token")) != k.jkt {
			t.Fatalf("rotated: %v", rotated)
		}
	})
	t.Run("replays a DPoP-bound refresh response only after validating the proof key", func(t *testing.T) {
		k := tkNewDPoPKey(t)
		code, v := authorizeForCode(t, k.jkt, jwtResource)
		tokens := tkOK(t, exchange(code, v, jwtResource, k.proof(t, "POST", tokenEndpoint, "reuse-issue-proof")))
		rt := tkStr(tokens, "refresh_token")
		if rt == "" {
			t.Fatalf("tokens: %v", tokens)
		}
		first := tkOK(t, refresh(rt, k.proof(t, "POST", tokenEndpoint, "reuse-refresh-proof-1")))
		if first["token_type"] != "DPoP" || first["refresh_token"] == nil {
			t.Fatalf("first: %v", first)
		}
		tkExpectErr(t, refresh(rt, ""), 0, "invalid_dpop_proof")
		replay := tkOK(t, refresh(rt, k.proof(t, "POST", tokenEndpoint, "reuse-refresh-proof-2")))
		for _, key := range []string{"access_token", "expires_at", "refresh_token", "scope", "id_token"} {
			if replay[key] != first[key] {
				t.Fatalf("replay %s: %v != %v", key, replay[key], first[key])
			}
		}
		if replay["token_type"] != "DPoP" || tkNum(replay["expires_in"]) > tkNum(first["expires_in"]) {
			t.Fatalf("replay: %v", replay)
		}
	})
	t.Run("rejects a replayed DPoP proof at the token endpoint", func(t *testing.T) {
		k := tkNewDPoPKey(t)
		proof := k.proof(t, "POST", tokenEndpoint, "replayed-proof")
		c1, v1 := authorizeForCode(t, k.jkt, jwtResource)
		m := tkOK(t, exchange(c1, v1, jwtResource, proof))
		if m["token_type"] != "DPoP" {
			t.Fatalf("tokens: %v", m)
		}
		c2, v2 := authorizeForCode(t, k.jkt, jwtResource)
		r := tkExpectErr(t, exchange(c2, v2, jwtResource, proof), 0, "invalid_dpop_proof")
		if r["access_token"] != nil {
			t.Fatal(r)
		}
	})
	t.Run("persists dpop_bound_access_tokens through dynamic client registration", func(t *testing.T) {
		r := e.do("POST", "/oauth2/register", map[string]any{
			"redirect_uris":              []any{redirectURI},
			"application_type":           "native",
			"grant_types":                []any{"authorization_code"},
			"token_endpoint_auth_method": "client_secret_basic",
			"dpop_bound_access_tokens":   true,
		}, e.h)
		m := r.json()
		if r.status >= 400 || m["dpop_bound_access_tokens"] != true {
			t.Fatalf("register: %d %s", r.status, r.body)
		}
	})
	t.Run("enforces DPoP from the client dpop_bound_access_tokens flag alone", func(t *testing.T) {
		fc := e.admin(map[string]any{
			"token_endpoint_auth_method": "client_secret_post",
			"grant_types":                []any{"authorization_code"},
			"redirect_uris":              []any{redirectURI},
			"application_type":           "native",
			"skip_consent":               true,
			"dpop_bound_access_tokens":   true,
		})
		v := tkVerifier()
		loc := e.authorize(tkStr(fc, "client_id"), redirectURI, "123", []string{"openid"}, v)
		r := e.token(tkCodeForm(tkCode(t, loc), v, redirectURI, tkStr(fc, "client_id"), tkStr(fc, "client_secret")), nil)
		m := tkExpectErr(t, r, 0, "invalid_dpop_proof")
		if m["access_token"] != nil {
			t.Fatal(m)
		}
	})
}

func TestTk_ConfirmationTokenType(t *testing.T) {
	t.Run("falls back to Bearer for a malformed confirmation instead of throwing", func(t *testing.T) {
		for _, malformed := range []any{"garbage", 42, []any{"jkt"}, map[string]any{"jkt": ""}} {
			if got := confirmationTokenType(malformed); got != "Bearer" {
				t.Fatalf("%v: %s", malformed, got)
			}
		}
		if got := confirmationTokenType(map[string]any{"jkt": "thumbprint"}); got != "DPoP" {
			t.Fatalf("got %s", got)
		}
		if got := confirmationTokenType(nil); got != "Bearer" {
			t.Fatalf("got %s", got)
		}
	})
}
