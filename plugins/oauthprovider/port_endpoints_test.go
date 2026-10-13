package oauthprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// ---- shared helpers for the rg ports (endpoints, endpoints-privileges, register) ----

const rgSecret = "better-auth.secret-for-tests-1234567890abcdef"

// rgRes is a decoded HTTP response (createAuthClient-style result).
type rgRes struct {
	status int
	header http.Header
	data   any
	raw    []byte
}

func (r rgRes) m() map[string]any { mm, _ := r.data.(map[string]any); return mm }
func (r rgRes) ok() bool          { return r.status >= 200 && r.status < 300 }

// rgClient mimics createAuthClient with the oauthProviderClient plugin.
type rgClient struct {
	env     *testEnv
	headers http.Header
}

func (c rgClient) req(method, path string, body any) rgRes {
	c.env.t.Helper()
	h := http.Header{}
	for k, v := range c.headers {
		h[k] = append([]string{}, v...)
	}
	res := c.env.do(method, path, body, h)
	var data any
	_ = json.Unmarshal(res.body, &data)
	return rgRes{status: res.status, header: res.header, data: data, raw: res.body}
}

func (c rgClient) createClient(body map[string]any) rgRes {
	return c.req("POST", "/oauth2/create-client", body)
}
func (c rgClient) register(body map[string]any) rgRes { return c.req("POST", "/oauth2/register", body) }
func (c rgClient) getClient(id string) rgRes {
	return c.req("GET", "/oauth2/get-client?client_id="+url.QueryEscape(id), nil)
}
func (c rgClient) publicClient(id string) rgRes {
	return c.req("GET", "/oauth2/public-client?client_id="+url.QueryEscape(id), nil)
}
func (c rgClient) publicClientPrelogin(body map[string]any) rgRes {
	return c.req("POST", "/oauth2/public-client-prelogin", body)
}
func (c rgClient) getClients() rgRes { return c.req("GET", "/oauth2/get-clients", nil) }
func (c rgClient) updateClient(id string, update map[string]any) rgRes {
	return c.req("POST", "/oauth2/update-client", map[string]any{"client_id": id, "update": update})
}
func (c rgClient) rotateSecret(id string) rgRes {
	return c.req("POST", "/oauth2/client/rotate-secret", map[string]any{"client_id": id})
}
func (c rgClient) deleteClient(id string) rgRes {
	return c.req("POST", "/oauth2/delete-client", map[string]any{"client_id": id})
}

// rgNorm round-trips a value through JSON so numbers/maps compare uniformly.
func rgNorm(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

// rgMatches implements vitest's toMatchObject semantics on JSON values.
func rgMatches(got, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, wv := range w {
			gv, has := g[k]
			if !has {
				return false
			}
			if !rgMatches(gv, wv) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !rgMatches(g[i], w[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(got, want)
	}
}

func rgMatch(t *testing.T, got, want any) {
	t.Helper()
	g, w := rgNorm(got), rgNorm(want)
	if !rgMatches(g, w) {
		gb, _ := json.Marshal(g)
		wb, _ := json.Marshal(w)
		t.Fatalf("toMatchObject failed:\n got:  %s\n want: %s", gb, wb)
	}
}

func rgEqual(t *testing.T, got, want any) {
	t.Helper()
	g, w := rgNorm(got), rgNorm(want)
	if !reflect.DeepEqual(g, w) {
		gb, _ := json.Marshal(g)
		wb, _ := json.Marshal(w)
		t.Fatalf("toEqual failed:\n got:  %s\n want: %s", gb, wb)
	}
}

// rgWithout copies m without the given keys.
func rgWithout(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

func rgMerge(ms ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func rgHas(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// rgDefined reports toBeDefined (present and not undefined; JSON null counts as defined).
func rgDefined(m map[string]any, k string) bool { return rgHas(m, k) }

func rgExpectDefined(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if !rgDefined(m, k) {
			t.Fatalf("expected %s to be defined in %v", k, m)
		}
	}
}

func rgExpectUndefined(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if rgHas(m, k) {
			t.Fatalf("expected %s to be undefined in %v", k, m)
		}
	}
}

// rgCall invokes auth.api.<key> and returns (data, status code or 0 on success, body).
func rgCall(env *testEnv, key string, in betterauth.CallInput) (map[string]any, *betterauth.APIError) {
	env.t.Helper()
	res, err := env.call(key, in)
	if err != nil {
		return nil, err
	}
	return decodeMap(env.t, res), nil
}

func rgMustCall(t *testing.T, env *testEnv, key string, in betterauth.CallInput) map[string]any {
	t.Helper()
	res, err := env.auth.API.Call(env.ctx(), key, in)
	if err != nil {
		if apiErr, ok := betterauth.AsAPIError(err); ok {
			t.Fatalf("%s failed: %d %v", key, apiErr.StatusCode, errBody(apiErr))
		}
		t.Fatalf("%s: %v", key, err)
	}
	return decodeMap(t, res)
}

func rgExpectStatus(t *testing.T, err *betterauth.APIError, status string, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got success", status)
	}
	if err.Status != status || (code != 0 && err.StatusCode != code) {
		t.Fatalf("expected %s (%d), got %s (%d) %v", status, code, err.Status, err.StatusCode, errBody(err))
	}
}

// rgErr asserts an HTTP client error {status, statusText}.
func rgErr(t *testing.T, r rgRes, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("expected status %d, got %d %s", status, r.status, r.raw)
	}
}

// rgPublicRSAJWK returns the public JWK of a fresh RSA key.
func rgPublicRSAJWK(t *testing.T) map[string]any {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

// rgPublicECJWK returns the public JWK of a fresh P-256 key.
func rgPublicECJWK(t *testing.T) map[string]any {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(b []byte) []byte {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(pad(k.X.Bytes())),
		"y": base64.RawURLEncoding.EncodeToString(pad(k.Y.Bytes())),
	}
}

// rgSignedQuery returns a signed oauth_query (makeSignature over the params).
func rgSignedQuery(params url.Values) string {
	p := newSearchParams()
	for k, vs := range params {
		for _, v := range vs {
			p.append(k, v)
		}
	}
	sig := bacrypto.MakeSignature(p.String(), rgSecret)
	p.set("sig", sig)
	return p.String()
}

// ---- endpoints.test.ts ----

var rgUiClientInput = map[string]any{
	"client_name": "accept name",
	"client_uri":  "https://example.com/ok",
	"logo_uri":    "https://example.com/logo.png",
	"contacts":    []any{"test@example.com"},
	"tos_uri":     "https://example.com/terms",
	"policy_uri":  "https://example.com/policy",
}

func TestRg_OauthClient(t *testing.T) {
	providerID := "test"
	rpBaseURL := "https://rp.example.com"
	redirectURI := rpBaseURL + "/api/auth/callback/" + providerID
	env := newEnv(t, Options{
		Scopes:                    []string{"openid", "profile", "email", "offline_access", "m2m:read"},
		AllowPublicClientPrelogin: true,
	})
	headers := env.signInWithTestUser()
	client := rgClient{env, headers}
	var oauthClient, oauthPublicClient, oauthUiClient map[string]any

	t.Run("round-trips application_type through user create and update with redirect revalidation", func(t *testing.T) {
		created := client.createClient(map[string]any{
			"application_type":           "native",
			"redirect_uris":              []any{"com.example.desktop:/callback"},
			"token_endpoint_auth_method": "client_secret_post",
		})
		if !created.ok() {
			t.Fatalf("create: %d %s", created.status, created.raw)
		}
		rgMatch(t, created.m(), map[string]any{"application_type": "native", "token_endpoint_auth_method": "client_secret_post"})
		rgExpectDefined(t, created.m(), "client_secret")
		rgExpectUndefined(t, created.m(), "public", "type")
		id := created.m()["client_id"].(string)
		invalid := client.updateClient(id, map[string]any{"application_type": "web"})
		rgErr(t, invalid, 400)
		updated := client.updateClient(id, map[string]any{
			"application_type": "web",
			"redirect_uris":    []any{"https://client.example.com/callback"},
		})
		if !updated.ok() || updated.m()["application_type"] != "web" {
			t.Fatalf("update: %d %s", updated.status, updated.raw)
		}
		client.deleteClient(id)
	})

	t.Run("round-trips application_type through admin create and update", func(t *testing.T) {
		created := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"application_type":           "native",
			"redirect_uris":              []any{"com.example.admin:/callback"},
			"token_endpoint_auth_method": "client_secret_basic",
		}})
		if created["application_type"] != "native" {
			t.Fatalf("created: %v", created)
		}
		rgExpectDefined(t, created, "client_secret")
		id := created["client_id"].(string)
		_, err := rgCall(env, "adminUpdateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"client_id": id, "update": map[string]any{"application_type": "web"},
		}})
		if err == nil || errBody(err)["error"] != "invalid_redirect_uri" {
			t.Fatalf("expected invalid_redirect_uri, got %v", errBody(err))
		}
		updated := rgMustCall(t, env, "adminUpdateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"client_id": id, "update": map[string]any{
				"application_type": "web",
				"redirect_uris":    []any{"https://admin.example.com/callback"},
			},
		}})
		if updated["application_type"] != "web" {
			t.Fatalf("updated: %v", updated)
		}
		rgExpectUndefined(t, updated, "public", "type")
		client.deleteClient(id)
	})

	t.Run("fails closed when no privilege callback can configure client_credentials scopes", func(t *testing.T) {
		_, err := rgCall(env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"grant_types":               []any{"client_credentials"},
			"client_credentials_scopes": []any{"m2m:read"},
		}})
		rgExpectStatus(t, err, "UNAUTHORIZED", 0)
	})

	t.Run("rejects client_credentials scope authority for public clients", func(t *testing.T) {
		_, err := rgCall(env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"grant_types":                []any{"client_credentials"},
			"token_endpoint_auth_method": "none",
			"client_credentials_scopes":  []any{"m2m:read"},
		}})
		rgExpectStatus(t, err, "BAD_REQUEST", 0)
		pub := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"grant_types":                []any{"client_credentials"},
			"token_endpoint_auth_method": "none",
		}})
		_, err = rgCall(env, "adminUpdateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"client_id": pub["client_id"], "update": map[string]any{"client_credentials_scopes": []any{"m2m:read"}},
		}})
		rgExpectStatus(t, err, "BAD_REQUEST", 0)
		client.deleteClient(pub["client_id"].(string))
	})

	t.Run("does not let an administrative update mutate unowned client metadata", func(t *testing.T) {
		created := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"redirect_uris": []any{redirectURI},
		}})
		id := created["client_id"].(string)
		env.update("oauthClient", map[string]any{"userId": nil, "referenceId": nil}, eq("clientId", id))
		_, err := rgCall(env, "adminUpdateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"client_id": id, "update": map[string]any{"client_name": "Cross-owner mutation"},
		}})
		rgExpectStatus(t, err, "UNAUTHORIZED", 0)
		if err := env.db.Delete(env.ctx(), "oauthClient", []adapter.Where{eq("clientId", id)}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("should create clients with minimum requirements", func(t *testing.T) {
		c := client.createClient(map[string]any{"redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, c.m(), "client_id", "user_id", "client_secret", "client_id_issued_at")
		oauthClient = c.m()
		pc := client.createClient(map[string]any{"token_endpoint_auth_method": "none", "redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, pc.m(), "client_id", "user_id", "client_id_issued_at")
		rgExpectUndefined(t, pc.m(), "client_secret")
		oauthPublicClient = pc.m()
		uc := client.createClient(rgMerge(rgUiClientInput, map[string]any{"redirect_uris": []any{redirectURI}}))
		rgExpectDefined(t, uc.m(), "client_id", "user_id", "client_secret", "client_id_issued_at")
		oauthUiClient = uc.m()
	})

	t.Run("should get a client", func(t *testing.T) {
		c := client.getClient(oauthClient["client_id"].(string))
		rgExpectUndefined(t, c.m(), "client_secret")
		rgMatch(t, c.m(), rgWithout(oauthClient, "client_secret"))
	})

	t.Run("should get public-only information about a client", func(t *testing.T) {
		c := client.publicClient(oauthUiClient["client_id"].(string))
		rgMatch(t, c.m(), rgMerge(map[string]any{"client_id": oauthUiClient["client_id"]}, rgUiClientInput))
	})

	t.Run("should get public-only information about a client prelogin", func(t *testing.T) {
		q := rgSignedQuery(url.Values{"exp": {strconv.FormatInt(time.Now().Unix()+60, 10)}})
		c := client.publicClientPrelogin(map[string]any{"client_id": oauthUiClient["client_id"], "oauth_query": q})
		rgMatch(t, c.m(), rgMerge(map[string]any{"client_id": oauthUiClient["client_id"]}, rgUiClientInput))
	})

	t.Run("should get user's clients", func(t *testing.T) {
		r := client.getClients()
		list, _ := r.data.([]any)
		if len(list) != 3 {
			t.Fatalf("expected 3 clients, got %d: %s", len(list), r.raw)
		}
		c0, _ := list[0].(map[string]any)
		c1, _ := list[1].(map[string]any)
		rgExpectUndefined(t, c0, "client_secret")
		rgMatch(t, c0, rgWithout(oauthClient, "client_secret"))
		rgExpectUndefined(t, c1, "client_secret")
		rgMatch(t, c1, rgWithout(oauthPublicClient, "client_secret"))
	})

	t.Run("should not allow token endpoint authentication method updates", func(t *testing.T) {
		c := client.updateClient(oauthClient["client_id"].(string), map[string]any{"token_endpoint_auth_method": "none"})
		rgExpectUndefined(t, c.m(), "client_secret")
		rgMatch(t, c.m(), rgWithout(oauthClient, "client_secret"))
	})

	t.Run("should not allow updates to client_secret", func(t *testing.T) {
		c := client.updateClient(oauthClient["client_id"].(string), map[string]any{"client_secret": "bad_request"})
		rgExpectUndefined(t, c.m(), "client_secret")
		rgMatch(t, c.m(), rgWithout(oauthClient, "client_secret"))
	})

	t.Run("should update the client", func(t *testing.T) {
		newRedirectURI := "https://example.com/api/auth/callback/" + providerID
		c := client.updateClient(oauthClient["client_id"].(string), map[string]any{"redirect_uris": []any{redirectURI, newRedirectURI}})
		rgExpectUndefined(t, c.m(), "client_secret")
		rgMatch(t, c.m(), rgMerge(rgWithout(oauthClient, "client_secret"), map[string]any{"redirect_uris": []any{redirectURI, newRedirectURI}}))
		oauthClient = c.m()
	})

	t.Run("should rotate the client secret", func(t *testing.T) {
		c := client.rotateSecret(oauthClient["client_id"].(string))
		rgExpectDefined(t, c.m(), "client_secret")
		if c.m()["client_secret"] == oauthClient["client_secret"] {
			t.Fatal("secret not rotated")
		}
		rgMatch(t, rgWithout(c.m(), "client_secret"), rgWithout(oauthClient, "client_secret"))
		if c.header.Get("Cache-Control") != "no-store" || c.header.Get("Pragma") != "no-cache" {
			t.Fatalf("headers: %v", c.header)
		}
		oauthClient = c.m()
	})

	t.Run("should delete the client", func(t *testing.T) {
		c := client.deleteClient(oauthClient["client_id"].(string))
		if !c.ok() || c.data != nil {
			t.Fatalf("delete: %d %s", c.status, c.raw)
		}
	})
}

func TestRg_OauthClientPrivateKeyJwtClients(t *testing.T) {
	redirectURI := "https://rp.example.com/callback"
	trustedJwksURI := "https://trusted.example.com/.well-known/jwks.json"
	env := newEnv(t, Options{AllowPublicClientPrelogin: true}, envOptions{mutate: func(c *betterauth.Config) {
		c.TrustedOrigins = append(c.TrustedOrigins, "https://trusted.example.com", "https://trusted-updated.example.com")
	}})
	headers := env.signInWithTestUser()
	client := rgClient{env, headers}
	publicJwk := rgPublicRSAJWK(t)
	var jwksClient, jwksURIClient map[string]any

	t.Run("rejects a bare JWK array when a user creates a client", func(t *testing.T) {
		r := client.createClient(map[string]any{
			"redirect_uris":              []any{redirectURI},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       []any{rgMerge(publicJwk, map[string]any{"kid": "bare-user-key", "alg": "RS256", "use": "sig"})},
		})
		rgErr(t, r, 400)
	})

	t.Run("should create private_key_jwt clients with jwks and jwks_uri", func(t *testing.T) {
		inlineJwks := map[string]any{"keys": []any{rgMerge(publicJwk, map[string]any{"kid": "crud-inline-key", "alg": "RS256", "use": "sig"})}}
		ic := client.createClient(map[string]any{
			"redirect_uris":              []any{redirectURI},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       inlineJwks,
		})
		rgExpectDefined(t, ic.m(), "client_id")
		rgExpectUndefined(t, ic.m(), "client_secret")
		if ic.m()["token_endpoint_auth_method"] != "private_key_jwt" {
			t.Fatalf("inline: %s", ic.raw)
		}
		rgEqual(t, ic.m()["jwks"], inlineJwks)
		jwksClient = ic.m()
		rc := client.createClient(map[string]any{
			"redirect_uris":              []any{redirectURI},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks_uri":                   trustedJwksURI,
		})
		rgExpectDefined(t, rc.m(), "client_id")
		rgExpectUndefined(t, rc.m(), "client_secret")
		if rc.m()["token_endpoint_auth_method"] != "private_key_jwt" || rc.m()["jwks_uri"] != trustedJwksURI {
			t.Fatalf("remote: %s", rc.raw)
		}
		jwksURIClient = rc.m()
	})

	t.Run("should get private_key_jwt clients without leaking secrets", func(t *testing.T) {
		ic := client.getClient(jwksClient["client_id"].(string))
		rgExpectUndefined(t, ic.m(), "client_secret")
		rgEqual(t, ic.m()["jwks"], jwksClient["jwks"])
		rc := client.getClient(jwksURIClient["client_id"].(string))
		rgExpectUndefined(t, rc.m(), "client_secret")
		if rc.m()["jwks_uri"] != trustedJwksURI {
			t.Fatalf("remote: %s", rc.raw)
		}
	})

	t.Run("should include private_key_jwt clients in the client list", func(t *testing.T) {
		r := client.getClients()
		byID := map[string]map[string]any{}
		list, _ := r.data.([]any)
		for _, c := range list {
			cm, _ := c.(map[string]any)
			id, _ := cm["client_id"].(string)
			byID[id] = cm
		}
		ic := byID[jwksClient["client_id"].(string)]
		if ic["token_endpoint_auth_method"] != "private_key_jwt" {
			t.Fatalf("list: %s", r.raw)
		}
		rgEqual(t, ic["jwks"], jwksClient["jwks"])
		if byID[jwksURIClient["client_id"].(string)]["jwks_uri"] != trustedJwksURI {
			t.Fatalf("list: %s", r.raw)
		}
	})

	t.Run("should preserve inline jwks metadata when updating a private_key_jwt client", func(t *testing.T) {
		u := client.updateClient(jwksClient["client_id"].(string), map[string]any{
			"client_name":   "Updated inline client",
			"redirect_uris": []any{redirectURI, "https://example.com/callback"},
		})
		if u.m()["client_name"] != "Updated inline client" {
			t.Fatalf("update: %d %s", u.status, u.raw)
		}
		rgEqual(t, u.m()["jwks"], jwksClient["jwks"])
		rgEqual(t, u.m()["redirect_uris"], []any{redirectURI, "https://example.com/callback"})
		jwksClient = u.m()
	})

	t.Run("should preserve jwks_uri metadata when updating a private_key_jwt client", func(t *testing.T) {
		u := client.updateClient(jwksURIClient["client_id"].(string), map[string]any{
			"client_name":   "Updated remote client",
			"redirect_uris": []any{redirectURI, "https://trusted-updated.example.com/callback"},
		})
		if u.m()["client_name"] != "Updated remote client" || u.m()["jwks_uri"] != trustedJwksURI {
			t.Fatalf("update: %d %s", u.status, u.raw)
		}
		rgEqual(t, u.m()["redirect_uris"], []any{redirectURI, "https://trusted-updated.example.com/callback"})
		jwksURIClient = u.m()
	})

	t.Run("should reject client secret rotation for private_key_jwt clients", func(t *testing.T) {
		r := client.rotateSecret(jwksClient["client_id"].(string))
		if r.status < 400 || r.status >= 500 {
			t.Fatalf("rotate: %d %s", r.status, r.raw)
		}
	})
}

func rgWhere(field string, v any) []adapter.Where { return []adapter.Where{eq(field, v)} }
