package oauthprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of private-key-jwt.test.ts.

// pkRSAKey is an RS256 key pair with its exported JWKs (generateKeyPair + exportJWK).
type pkRSAKey struct {
	priv       any
	publicJwk  *jsonx.Object
	privateJwk *jsonx.Object
}

func pkGenRSA(t *testing.T) *pkRSAKey {
	t.Helper()
	pub, priv, err := jose.GenerateKeyPair("RS256", jose.GenerateKeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pj, err := jose.JWKFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sj, err := jose.JWKFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return &pkRSAKey{priv: priv, publicJwk: jose.ExportJWK(pj), privateJwk: jose.ExportJWK(sj)}
}

// pkJwkWith returns {...jwk, ...extra}.
func pkJwkWith(jwk *jsonx.Object, kv ...any) *jsonx.Object {
	o := jwk.Clone()
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i].(string), kv[i+1])
	}
	return o
}

func pkUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type pkAssertion struct {
	clientID string
	aud      any
	exp      int64
	iat      int64
	jti      string
	kid      string
	alg      string
	key      any
	omitJti  bool
	omitKid  bool
}

func pkSignAssertion(t *testing.T, a pkAssertion) string {
	t.Helper()
	now := time.Now().Unix()
	alg := a.alg
	if alg == "" {
		alg = "RS256"
	}
	header := jsonx.O("alg", alg)
	if !a.omitKid {
		header.Set("kid", a.kid)
	}
	iat := a.iat
	if iat == 0 {
		iat = now
	}
	exp := a.exp
	if exp == 0 {
		exp = now + 120
	}
	payload := jsonx.O("iss", a.clientID, "sub", a.clientID, "aud", a.aud, "iat", iat, "exp", exp)
	if !a.omitJti {
		jti := a.jti
		if jti == "" {
			jti = pkUUID()
		}
		payload.Set("jti", jti)
	}
	s, err := jose.SignJWT(header, payload, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pkJSONResponse is Response.json(v).
func pkJSONResponse(req *http.Request, v any) *http.Response {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	b, _ := jsonx.Marshal(v)
	rec.WriteHeader(200)
	_, _ = rec.Write(b)
	res := rec.Result()
	res.Request = req
	return res
}

// pkDiscoveredVerifier is createDiscoveredClientVerifier: a provider instance with a
// discovery-owned private_key_jwt client row.
func pkDiscoveredVerifier(t *testing.T, baseURL, clientID, discoveryID, jwksURI string, fetch ClientMetadataResourceFetch) (*betterauth.EndpointContext, *resolved) {
	t.Helper()
	opts := Options{Extensions: []*Extension{{ClientDiscovery: []*ClientDiscovery{{
		ID:      discoveryID,
		Matches: func(candidate string) bool { return candidate == clientID },
		Resolve: func(_ *betterauth.EndpointContext, _ string, existing *SchemaClient) (*SchemaClient, error) {
			return existing, nil
		},
		FetchClientMetadataResource: fetch,
	}}}}}
	env := newEnv(t, opts, envOptions{disableTestUser: true, mutate: func(c *betterauth.Config) { c.BaseURL = baseURL }})
	now := time.Now()
	if _, err := env.db.Create(context.Background(), adapter.CreateInput{Model: modelClient, Data: adapter.Record{
		"clientId": clientID, "clientDiscoveryId": discoveryID, "name": "Discovered private_key_jwt client",
		"redirectUris": []any{"https://client.example.com/callback"}, "tokenEndpointAuthMethod": "private_key_jwt",
		"applicationType": "web", "grantTypes": []any{"authorization_code"}, "responseTypes": []any{"code"},
		"jwksUri": jwksURI, "createdAt": now, "updatedAt": now,
	}}); err != nil {
		t.Fatal(err)
	}
	ac := env.auth.Context()
	o, err := pluginOptions(ac)
	if err != nil {
		t.Fatal(err)
	}
	return &betterauth.EndpointContext{Auth: ac}, o
}

func pkSignDiscovered(t *testing.T, audience, clientID string, key any, keyID string) string {
	return pkSignAssertion(t, pkAssertion{clientID: clientID, aud: audience, kid: keyID, key: key})
}

func TestPk_PrivateKeyJwtAuthentication(t *testing.T) {
	customIssuer := "https://issuer.example.com"
	rpBaseURL := "http://localhost:5000"
	tokenEndpoint := testAuthBase + "/oauth2/token"
	introspectEndpoint := testAuthBase + "/oauth2/introspect"
	revokeEndpoint := testAuthBase + "/oauth2/revoke"
	redirectURI := rpBaseURL + "/callback"
	var discoveryCalls atomic.Int32
	discoveryMetadataFetch := func(*http.Request) (*http.Response, error) {
		discoveryCalls.Add(1)
		return nil, errors.New("managed client must not use a discovery transport")
	}
	env := newEnv(t, Options{AssertionMaxLifetime: 300, Extensions: []*Extension{{ClientDiscovery: []*ClientDiscovery{{
		ID:                          "test-discovery",
		Matches:                     func(string) bool { return false },
		Resolve:                     func(*betterauth.EndpointContext, string, *SchemaClient) (*SchemaClient, error) { return nil, nil },
		FetchClientMetadataResource: discoveryMetadataFetch,
	}}}}}, envOptions{
		jwt:    &jwt.Options{JWT: &jwt.JWTOptions{Issuer: customIssuer}},
		mutate: func(c *betterauth.Config) { c.TrustedOrigins = append(c.TrustedOrigins, "https://trusted.example.com") },
	})
	headers := env.signInWithTestUser()
	rsa := pkGenRSA(t)

	assertionClient := env.adminCreateClient(headers, map[string]any{
		"redirect_uris": []any{redirectURI}, "application_type": "native", "skip_consent": true,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       map[string]any{"keys": []any{pkJwkWith(rsa.publicJwk, "kid", "test-key-1", "alg", "RS256", "use", "sig")}},
	})
	if assertionClient["client_id"] == nil || assertionClient["client_secret"] != nil {
		t.Fatalf("assertion client: %v", assertionClient)
	}
	jwksURIClient := env.adminCreateClient(headers, map[string]any{
		"redirect_uris": []any{redirectURI}, "application_type": "native", "skip_consent": true,
		"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://trusted.example.com/.well-known/jwks.json",
	})
	if jwksURIClient["client_id"] == nil || jwksURIClient["client_secret"] != nil {
		t.Fatalf("jwks_uri client: %v", jwksURIClient)
	}
	secretClient := env.adminCreateClient(headers, map[string]any{
		"redirect_uris": []any{redirectURI}, "application_type": "native", "skip_consent": true,
	})
	if secretClient["client_secret"] == nil {
		t.Fatalf("secret client: %v", secretClient)
	}
	assertionClientID := assertionClient["client_id"].(string)

	sign := func(t *testing.T, a pkAssertion) string {
		if a.clientID == "" {
			a.clientID = assertionClientID
		}
		if a.aud == nil {
			a.aud = tokenEndpoint
		}
		if a.kid == "" {
			a.kid = "test-key-1"
		}
		if a.key == nil {
			a.key = rsa.priv
		}
		return pkSignAssertion(t, a)
	}
	getAuthCode := func(t *testing.T, clientID, verifier string, scopes string) string {
		if scopes == "" {
			scopes = "openid profile"
		}
		return env.authorizeCode(headers, "response_type", "code", "client_id", clientID, "state", "test-state",
			"scope", scopes, "redirect_uri", redirectURI, "code_challenge", challengeFor(verifier),
			"code_challenge_method", "S256")
	}
	exchange := func(clientID, code, verifier, assertion string) *response {
		if clientID == "" {
			clientID = assertionClientID
		}
		return env.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			"client_id": {clientID}, "client_assertion_type": {oauthcore.ClientAssertionType},
			"client_assertion": {assertion}, "code_verifier": {verifier}}, nil)
	}
	newVerifier := func() string { return crypto.RandomString(32) }
	expect4xx := func(t *testing.T, res *response) {
		t.Helper()
		if res.status < 400 || res.status >= 500 {
			t.Fatalf("expected 4xx, got %d %s", res.status, res.body)
		}
	}

	t.Run("isolates discovery-owned JWKS caches between provider instances", func(t *testing.T) {
		clientID := "https://cache-isolation.example.com/client.json"
		jwksURI := "https://cache-isolation.example.com/jwks.json"
		discoveryID := "shared-cache-isolation-discovery"
		keyID := "shared-key-id"
		keyA, keyB := pkGenRSA(t), pkGenRSA(t)
		var callsA, callsB atomic.Int32
		transportA := func(req *http.Request) (*http.Response, error) {
			callsA.Add(1)
			return pkJSONResponse(req, jsonx.O("keys", []any{pkJwkWith(keyA.publicJwk, "kid", keyID, "alg", "RS256", "use", "sig")})), nil
		}
		transportB := func(req *http.Request) (*http.Response, error) {
			callsB.Add(1)
			return pkJSONResponse(req, jsonx.O("keys", []any{pkJwkWith(keyB.publicJwk, "kid", keyID, "alg", "RS256", "use", "sig")})), nil
		}
		ctxA, optsA := pkDiscoveredVerifier(t, "https://provider-a.example.com", clientID, discoveryID, jwksURI, transportA)
		ctxB, optsB := pkDiscoveredVerifier(t, "https://provider-b.example.com", clientID, discoveryID, jwksURI, transportB)
		audA := "https://provider-a.example.com/oauth2/token"
		audB := "https://provider-b.example.com/oauth2/token"
		got, err := verifyClientAssertion(ctxA, optsA, pkSignDiscovered(t, audA, clientID, keyA.priv, keyID),
			oauthcore.ClientAssertionType, clientID, audA)
		if err != nil || got != clientID {
			t.Fatalf("provider A: %q %v", got, err)
		}
		got, err = verifyClientAssertion(ctxB, optsB, pkSignDiscovered(t, audB, clientID, keyB.priv, keyID),
			oauthcore.ClientAssertionType, clientID, audB)
		if err != nil || got != clientID {
			t.Fatalf("provider B: %q %v", got, err)
		}
		if callsA.Load() != 1 || callsB.Load() != 1 {
			t.Fatalf("transport calls: %d %d", callsA.Load(), callsB.Load())
		}
	})

	badJwks := []struct {
		name string
		jwks func() any
	}{
		{"bare-array", func() any {
			return []any{pkJwkWith(rsa.publicJwk, "kid", "remote-validation-key", "alg", "RS256")}
		}},
		{"symmetric", func() any {
			return jsonx.O("keys", []any{jsonx.O("kty", "oct", "k", "c3ltbWV0cmljLXNlY3JldA", "kid", "remote-validation-key", "alg", "RS256")})
		}},
		{"private", func() any {
			return jsonx.O("keys", []any{pkJwkWith(rsa.privateJwk, "kid", "remote-validation-key", "alg", "RS256")})
		}},
		{"malformed", func() any {
			n, _ := rsa.publicJwk.Get("n")
			return jsonx.O("keys", []any{jsonx.O("kty", "RSA", "n", n, "kid", "remote-validation-key", "alg", "RS256")})
		}},
		{"unsupported-algorithm", func() any {
			return jsonx.O("keys", []any{pkJwkWith(rsa.publicJwk, "kid", "remote-validation-key", "alg", "HS256")})
		}},
		{"incompatible-algorithm", func() any {
			return jsonx.O("keys", []any{pkJwkWith(rsa.publicJwk, "kid", "remote-validation-key", "alg", "ES256")})
		}},
		{"ec-curve-algorithm-mismatch", func() any {
			return jsonx.O("keys", []any{jsonx.O("kty", "EC", "crv", "P-256", "x", "public-x", "y", "public-y",
				"kid", "remote-validation-key", "alg", "ES384")})
		}},
		{"unsupported-ed448-curve", func() any {
			return jsonx.O("keys", []any{jsonx.O("kty", "OKP", "crv", "Ed448", "x", "public-x", "kid", "remote-validation-key", "alg", "EdDSA")})
		}},
	}
	for _, tc := range badJwks {
		t.Run("does not cache a "+tc.name+" discovery-owned JWKS response", func(t *testing.T) {
			clientID := "https://" + tc.name + "-remote-jwks.example.com/client.json"
			jwksURI := "https://" + tc.name + "-remote-jwks.example.com/jwks.json"
			audience := "https://" + tc.name + "-provider.example.com/oauth2/token"
			serveValid := false
			var calls atomic.Int32
			transport := func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				if serveValid {
					return pkJSONResponse(req, jsonx.O("keys", []any{pkJwkWith(rsa.publicJwk, "kid", "remote-validation-key", "alg", "RS256")})), nil
				}
				return pkJSONResponse(req, tc.jwks()), nil
			}
			u, _ := url.Parse(audience)
			ctx, o := pkDiscoveredVerifier(t, u.Scheme+"://"+u.Host, clientID, tc.name+"-remote-jwks-discovery", jwksURI, transport)
			if _, err := verifyClientAssertion(ctx, o, pkSignDiscovered(t, audience, clientID, rsa.priv, "remote-validation-key"),
				oauthcore.ClientAssertionType, clientID, audience); err == nil {
				t.Fatal("expected rejection")
			}
			if calls.Load() != 1 {
				t.Fatalf("calls: %d", calls.Load())
			}
			serveValid = true
			got, err := verifyClientAssertion(ctx, o, pkSignDiscovered(t, audience, clientID, rsa.priv, "remote-validation-key"),
				oauthcore.ClientAssertionType, clientID, audience)
			if err != nil || got != clientID {
				t.Fatalf("second verify: %q %v", got, err)
			}
			if calls.Load() != 2 {
				t.Fatalf("calls: %d", calls.Load())
			}
		})
	}

	t.Run("should exchange code with valid private_key_jwt assertion", func(t *testing.T) {
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		res := exchange("", code, v, sign(t, pkAssertion{}))
		m := res.json()
		if m["access_token"] == nil || m["token_type"] != "Bearer" {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
	})

	t.Run("should accept the configured issuer as a token audience", func(t *testing.T) {
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		res := exchange("", code, v, sign(t, pkAssertion{aud: customIssuer}))
		m := res.json()
		if m["access_token"] == nil || m["token_type"] != "Bearer" {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
	})

	t.Run("should exchange code using a trusted jwks_uri", func(t *testing.T) {
		var mu sync.Mutex
		var fetched []string
		var accepts []string
		env.serveHost("trusted.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			fetched = append(fetched, "https://"+r.Host+r.URL.Path)
			accepts = append(accepts, r.Header.Get("Accept"))
			mu.Unlock()
			w.Header().Set("content-type", "application/json")
			b, _ := jsonx.Marshal(jsonx.O("keys", []any{pkJwkWith(rsa.publicJwk, "kid", "trusted-jwks-key", "alg", "RS256", "use", "sig")}))
			_, _ = w.Write(b)
		}))
		clientID := jwksURIClient["client_id"].(string)
		v := newVerifier()
		code := getAuthCode(t, clientID, v, "")
		res := exchange(clientID, code, v, sign(t, pkAssertion{clientID: clientID, kid: "trusted-jwks-key"}))
		if res.json()["access_token"] == nil {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(fetched) == 0 || fetched[0] != "https://trusted.example.com/.well-known/jwks.json" || accepts[0] != "application/json" {
			t.Fatalf("fetches: %v %v", fetched, accepts)
		}
		// redirect: "error" — the default transport (DefaultClientMetadataFetch) refuses redirects.
		if discoveryCalls.Load() != 0 {
			t.Fatalf("discovery transport called %d times", discoveryCalls.Load())
		}
	})

	t.Run("should reject assertion signed with wrong key", func(t *testing.T) {
		wrong := pkGenRSA(t)
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		expect4xx(t, exchange("", code, v, sign(t, pkAssertion{key: wrong.priv})))
	})

	t.Run("should reject expired assertion", func(t *testing.T) {
		now := time.Now().Unix()
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		expect4xx(t, exchange("", code, v, sign(t, pkAssertion{exp: now - 60})))
	})

	t.Run("should reject assertion with exp too far in the future", func(t *testing.T) {
		now := time.Now().Unix()
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		expect4xx(t, exchange("", code, v, sign(t, pkAssertion{exp: now + 3600})))
	})

	t.Run("should reject assertion without jti", func(t *testing.T) {
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		expect4xx(t, exchange("", code, v, sign(t, pkAssertion{omitJti: true})))
	})

	t.Run("should reject reused jti (replay prevention)", func(t *testing.T) {
		jti := pkUUID()
		v1 := newVerifier()
		code1 := getAuthCode(t, assertionClientID, v1, "")
		r1 := exchange("", code1, v1, sign(t, pkAssertion{jti: jti}))
		if r1.json()["access_token"] == nil {
			t.Fatalf("first: %d %s", r1.status, r1.body)
		}
		v2 := newVerifier()
		code2 := getAuthCode(t, assertionClientID, v2, "")
		expect4xx(t, exchange("", code2, v2, sign(t, pkAssertion{jti: jti})))
	})

	t.Run("should reject concurrent reuse of the same jti", func(t *testing.T) {
		jti := pkUUID()
		v1, v2 := newVerifier(), newVerifier()
		code1 := getAuthCode(t, assertionClientID, v1, "")
		code2 := getAuthCode(t, assertionClientID, v2, "")
		assertion := sign(t, pkAssertion{jti: jti})
		results := make([]*response, 2)
		var wg sync.WaitGroup
		for i, p := range [][2]string{{code1, v1}, {code2, v2}} {
			wg.Add(1)
			go func(i int, code, v string) {
				defer wg.Done()
				results[i] = exchange("", code, v, assertion)
			}(i, p[0], p[1])
		}
		wg.Wait()
		success, failure := 0, 0
		for _, r := range results {
			if r.json()["access_token"] != nil {
				success++
			}
			if r.status >= 400 {
				failure++
			}
		}
		if success != 1 || failure != 1 {
			t.Fatalf("success=%d failure=%d: %s | %s", success, failure, results[0].body, results[1].body)
		}
	})

	t.Run("should reject wrong audience", func(t *testing.T) {
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		expect4xx(t, exchange("", code, v, sign(t, pkAssertion{aud: "https://wrong-server.example.com/token"})))
	})

	t.Run("should reject assertion signed with HS256 (symmetric algorithm)", func(t *testing.T) {
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		assertion := pkSignAssertion(t, pkAssertion{clientID: assertionClientID, aud: tokenEndpoint, alg: "HS256",
			omitKid: true, key: []byte("a]?Y^w0S@}I-lI%i|{5BW?Wl:jLz[I_M")})
		expect4xx(t, exchange("", code, v, assertion))
	})

	t.Run("should reject assertion with iat too far in the past", func(t *testing.T) {
		now := time.Now().Unix()
		v := newVerifier()
		code := getAuthCode(t, assertionClientID, v, "")
		expect4xx(t, exchange("", code, v, sign(t, pkAssertion{iat: now - 600, exp: now + 60})))
	})

	t.Run("should enforce auth method — secret client cannot use assertion", func(t *testing.T) {
		clientID := secretClient["client_id"].(string)
		v := newVerifier()
		code := getAuthCode(t, clientID, v, "")
		expect4xx(t, exchange(clientID, code, v, sign(t, pkAssertion{clientID: clientID})))
	})

	for _, tc := range []struct {
		name     string
		audience any
	}{
		{"issuer audience array", []any{customIssuer, "https://unrelated.example.com/introspect"}},
		{"endpoint audience", introspectEndpoint},
	} {
		t.Run("should introspect an access token using private_key_jwt with "+tc.name, func(t *testing.T) {
			v := newVerifier()
			code := getAuthCode(t, assertionClientID, v, "")
			tokens := exchange("", code, v, sign(t, pkAssertion{})).json()
			at, _ := tokens["access_token"].(string)
			if at == "" {
				t.Fatalf("tokens: %v", tokens)
			}
			res := env.do("POST", "/oauth2/introspect", url.Values{"client_id": {assertionClientID},
				"client_assertion_type": {oauthcore.ClientAssertionType},
				"client_assertion":      {sign(t, pkAssertion{aud: tc.audience})},
				"token":                 {at}, "token_type_hint": {"access_token"}}, nil)
			m := res.json()
			if m["active"] != true || m["client_id"] != assertionClientID {
				t.Fatalf("introspect: %d %s", res.status, res.body)
			}
		})
	}

	for _, tc := range []struct {
		name     string
		audience any
	}{
		{"issuer audience", customIssuer},
		{"endpoint audience", revokeEndpoint},
	} {
		t.Run("should revoke a refresh token using private_key_jwt with "+tc.name, func(t *testing.T) {
			v := newVerifier()
			code := getAuthCode(t, assertionClientID, v, "openid profile offline_access")
			tokens := exchange("", code, v, sign(t, pkAssertion{})).json()
			rt, _ := tokens["refresh_token"].(string)
			if rt == "" {
				t.Fatalf("tokens: %v", tokens)
			}
			res := env.do("POST", "/oauth2/revoke", url.Values{"client_id": {assertionClientID},
				"client_assertion_type": {oauthcore.ClientAssertionType},
				"client_assertion":      {sign(t, pkAssertion{aud: tc.audience})},
				"token":                 {rt}, "token_type_hint": {"refresh_token"}}, nil)
			if res.status != 200 {
				t.Fatalf("revoke: %d %s", res.status, res.body)
			}
			if b := string(res.body); b != "" && b != "null" {
				t.Fatalf("revoke body: %s", b)
			}
		})
	}
}

func TestPk_IsPrivateHostname(t *testing.T) {
	check := func(t *testing.T, want bool, hosts ...string) {
		t.Helper()
		for _, h := range hosts {
			if got := isPrivateHostname(h); got != want {
				t.Errorf("isPrivateHostname(%q) = %v, want %v", h, got, want)
			}
		}
	}
	t.Run("should block standard private IPv4 ranges", func(t *testing.T) {
		check(t, true, "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254")
	})
	t.Run("should block localhost and IPv6 loopback", func(t *testing.T) {
		check(t, true, "localhost", "::1", "[::1]")
	})
	t.Run("should block link-local and unique-local IPv6", func(t *testing.T) {
		check(t, true, "[fe80::1]", "fe80::1", "[fd00::1]", "[fc00::1]")
	})
	t.Run("should block IPv4-mapped IPv6 addresses with private IPv4", func(t *testing.T) {
		check(t, true, "[::ffff:127.0.0.1]", "::ffff:127.0.0.1", "[::ffff:169.254.169.254]", "[::ffff:10.0.0.1]", "[::ffff:192.168.1.1]")
	})
	t.Run("should NOT block legitimate DNS hostnames starting with fc/fd/fe", func(t *testing.T) {
		check(t, false, "fd-services.com", "fc-platform.example.com", "february.example.com", "fe80.example.com")
	})
	t.Run("should NOT block public IPv4 addresses", func(t *testing.T) {
		check(t, false, "8.8.8.8", "1.1.1.1")
	})
	t.Run("should NOT block IPv4-mapped IPv6 with public IPv4", func(t *testing.T) {
		check(t, false, "[::ffff:8.8.8.8]")
	})
	t.Run("should block IPv4-mapped IPv6 written in hex", func(t *testing.T) {
		check(t, true, "[::ffff:7f00:1]", "[::ffff:a9fe:a9fe]")
	})
	t.Run("should block NAT64 and 6to4 tunnels to private targets", func(t *testing.T) {
		check(t, true, "[64:ff9b::7f00:1]", "[2002:a9fe:a9fe::]")
	})
	t.Run("should block shared address space (carrier-grade NAT)", func(t *testing.T) {
		check(t, true, "100.64.0.1")
	})
	t.Run("should block cloud metadata endpoints", func(t *testing.T) {
		check(t, true, "metadata.google.internal", "metadata.goog", "instance-data")
	})
}

func TestPk_PrivateKeyJwtRegistrationValidation(t *testing.T) {
	authServerBaseURL := "http://localhost:3001"
	env := newEnv(t, Options{}, envOptions{
		jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: authServerBaseURL}},
		mutate: func(c *betterauth.Config) {
			c.BaseURL = authServerBaseURL
			c.TrustedOrigins = append(c.TrustedOrigins, authServerBaseURL, "https://trusted.example.com")
		},
	})
	headers := env.signInWithTestUser()
	create := func(body map[string]any) (*betterauth.CallResult, *betterauth.APIError) {
		return env.call("adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: body})
	}
	expectRejected := func(t *testing.T, body map[string]any) {
		t.Helper()
		_, err := create(body)
		if err == nil || err.StatusCode < 400 {
			t.Fatalf("expected >= 400, got %v", err)
		}
	}
	t.Run("should reject registration with both jwks and jwks_uri", func(t *testing.T) {
		expectRejected(t, map[string]any{"redirect_uris": []any{"https://example.com/callback"},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       map[string]any{"keys": []any{map[string]any{"kty": "RSA", "n": "test", "e": "test-exponent"}}},
			"jwks_uri":                   "https://example.com/.well-known/jwks.json"})
	})
	t.Run("should reject registration without jwks or jwks_uri", func(t *testing.T) {
		expectRejected(t, map[string]any{"redirect_uris": []any{"https://example.com/callback"},
			"token_endpoint_auth_method": "private_key_jwt"})
	})
	t.Run("should reject jwks_uri with non-HTTPS scheme", func(t *testing.T) {
		expectRejected(t, map[string]any{"redirect_uris": []any{"https://example.com/callback"},
			"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "http://example.com/.well-known/jwks.json"})
	})
	t.Run("should reject jwks_uri from an untrusted origin", func(t *testing.T) {
		expectRejected(t, map[string]any{"redirect_uris": []any{"https://example.com/callback"},
			"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://untrusted.example.com/.well-known/jwks.json"})
	})
	t.Run("should accept jwks on client_secret clients", func(t *testing.T) {
		res, err := create(map[string]any{"redirect_uris": []any{"https://example.com/callback"},
			"token_endpoint_auth_method": "client_secret_post",
			"jwks":                       map[string]any{"keys": []any{map[string]any{"kty": "RSA", "n": "test", "e": "test-exponent"}}}})
		if err != nil {
			t.Fatalf("create: %d %v", err.StatusCode, errBody(err))
		}
		if res.Status != 201 {
			t.Fatalf("status: %d", res.Status)
		}
	})
}
