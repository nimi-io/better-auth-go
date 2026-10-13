package oauthprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Shared helpers for the introspect / revoke / userinfo / no-store ports.

const (
	irRPBaseURL     = "http://localhost:5000"
	irRedirectURI   = irRPBaseURL + "/api/auth/callback/test"
	irValidResource = "https://myapi.example.com"
	irState         = "123"
)

var irDefaultScopes = []string{"openid", "profile", "email", "offline_access"}

// irClient is a registered OAuth client.
type irClient struct {
	id, secret string
	raw        map[string]any
}

func irClientFrom(t *testing.T, m map[string]any) irClient {
	t.Helper()
	id, _ := m["client_id"].(string)
	secret, _ := m["client_secret"].(string)
	if id == "" {
		t.Fatalf("client not created: %v", m)
	}
	return irClient{id: id, secret: secret, raw: m}
}

func irJWTOptions() *jwt.Options {
	return &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}}
}

// irMainEnv mirrors the top-level describe setup shared by introspect/revoke/userinfo:
// jwt({ jwt: { issuer } }) + oauthProvider({ resources: [validResource], enforcePerClientResources: false }).
func irMainEnv(t *testing.T, eo ...envOptions) *testEnv {
	t.Helper()
	o := envOptions{}
	if len(eo) > 0 {
		o = eo[0]
	}
	o.jwt = irJWTOptions()
	return newEnv(t, Options{
		Resources:                 []ResourceInput{{Identifier: irValidResource}},
		EnforcePerClientResources: betterauth.Bool(false),
	}, o)
}

// irRandomString mirrors generateRandomString(32).
func irRandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	s := base64.RawURLEncoding.EncodeToString(b)
	return s[:n]
}

func irWithHeaders(base http.Header, kv ...string) http.Header {
	h := base.Clone()
	if h == nil {
		h = http.Header{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

// irAuthorize mirrors createAuthorizationURL + following the authorize redirect, returning
// the code and verifier.
func irAuthorize(env *testEnv, h http.Header, clientID string, scopes []string, extra ...string) (string, string) {
	env.t.Helper()
	verifier := irRandomString(32)
	kv := []string{"response_type", "code", "client_id", clientID, "state", irState,
		"scope", strings.Join(scopes, " "), "redirect_uri", irRedirectURI,
		"code_challenge", challengeFor(verifier), "code_challenge_method", "S256"}
	kv = append(kv, extra...)
	return env.authorizeCode(h, kv...), verifier
}

// irExchange mirrors authorizationCodeRequest (client_secret_post) posted to /oauth2/token.
func irExchange(env *testEnv, h http.Header, c irClient, code, verifier, resource string, extra http.Header) *response {
	env.t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {irRedirectURI}, "client_id": {c.id}, "client_secret": {c.secret}}
	if resource != "" {
		form.Set("resource", resource)
	}
	hdr := irWithHeaders(h, "Accept", "application/json")
	for k, vs := range extra {
		hdr[k] = vs
	}
	return env.token(form, hdr)
}

// irGetTokens runs authorize + token exchange and returns the token response JSON.
func irGetTokens(env *testEnv, h http.Header, c irClient, scopes []string, resource string, extra ...string) map[string]any {
	env.t.Helper()
	if scopes == nil {
		scopes = irDefaultScopes
	}
	code, verifier := irAuthorize(env, h, c.id, scopes, extra...)
	res := irExchange(env, h, c, code, verifier, resource, nil)
	if res.status != 200 {
		env.t.Fatalf("token exchange failed: %d %s", res.status, res.body)
	}
	return res.json()
}

// irPostForm posts form to path with the session headers plus accept json.
func irPostForm(env *testEnv, h http.Header, path string, form url.Values) *response {
	env.t.Helper()
	return env.do("POST", path, form, irWithHeaders(h, "Accept", "application/json"))
}

func irIntrospect(env *testEnv, h http.Header, c *irClient, token, hint string) *response {
	env.t.Helper()
	form := url.Values{"token": {token}}
	if c != nil {
		form.Set("client_id", c.id)
		form.Set("client_secret", c.secret)
	}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	return irPostForm(env, h, "/oauth2/introspect", form)
}

func irRevoke(env *testEnv, h http.Header, c *irClient, token, hint string) *response {
	env.t.Helper()
	form := url.Values{"token": {token}}
	if c != nil {
		form.Set("client_id", c.id)
		form.Set("client_secret", c.secret)
	}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	return irPostForm(env, h, "/oauth2/revoke", form)
}

type irAnyType int

const (
	irAnyString irAnyType = iota
	irAnyNumber
)

// irMatch mirrors toMatchObject for flat maps.
func irMatch(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	if got == nil {
		t.Fatalf("expected object matching %v, got nil", want)
	}
	for k, w := range want {
		g, ok := got[k]
		switch w := w.(type) {
		case irAnyType:
			if !ok {
				t.Fatalf("%s missing in %v", k, got)
			}
			if w == irAnyString {
				if _, ok := g.(string); !ok {
					t.Fatalf("%s: expected string, got %T %v (%v)", k, g, g, got)
				}
			} else if _, ok := g.(float64); !ok {
				t.Fatalf("%s: expected number, got %T %v (%v)", k, g, g, got)
			}
		case []any:
			ga, _ := g.([]any)
			if len(ga) != len(w) {
				t.Fatalf("%s: expected %v, got %v", k, w, g)
			}
			for i := range w {
				if ga[i] != w[i] {
					t.Fatalf("%s: expected %v, got %v", k, w, g)
				}
			}
		default:
			if !ok || g != w {
				t.Fatalf("%s: expected %v, got %v (%v)", k, w, g, got)
			}
		}
	}
}

// irExpectInactive mirrors toEqual({ active: false }).
func irExpectInactive(t *testing.T, res *response) {
	t.Helper()
	m := res.json()
	if res.status != 200 || len(m) != 1 || m["active"] != false {
		t.Fatalf("expected {active:false}, got %d %s", res.status, res.body)
	}
}

func irSessionID(env *testEnv, h http.Header) string {
	env.t.Helper()
	m := env.mustCall("getSession", betterauth.CallInput{Headers: h})
	s, _ := m["session"].(map[string]any)
	id, _ := s["id"].(string)
	if id == "" {
		env.t.Fatalf("no session: %v", m)
	}
	return id
}

func irUpdateMany(env *testEnv, model string, update adapter.Record, where ...adapter.Where) {
	env.t.Helper()
	if _, err := env.db.UpdateMany(context.Background(), model, where, update); err != nil {
		env.t.Fatal(err)
	}
}

// irCountingAdapter counts findMany calls on a model while enabled (vi.spyOn(adapter, "findMany")).
type irCountingAdapter struct {
	adapter.Adapter
	model   string
	enabled *atomic.Bool
	count   *atomic.Int64
}

func (a irCountingAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	if a.enabled.Load() && in.Model == a.model {
		a.count.Add(1)
	}
	return a.Adapter.FindMany(ctx, in)
}

var irConfigScopes = []string{"openid", "email", "profile", "offline_access", "read:profile"}

// irConfigEnv mirrors createTestInstance of the "- config" describes: oauthProvider first,
// then jwt (unless disableJwtPlugin), and an admin-created client with all grant types.
func irConfigEnv(t *testing.T, mod func(o *Options)) (*testEnv, http.Header, irClient) {
	t.Helper()
	o := Options{
		Resources:                 []ResourceInput{{Identifier: irValidResource}},
		EnforcePerClientResources: betterauth.Bool(false),
		Scopes:                    append([]string{}, irConfigScopes...),
		ClientPrivileges: func(c PrivilegeContext) (bool, error) {
			return c.Action == "create" || c.Action == "configure-client-credentials-scopes", nil
		},
	}
	if mod != nil {
		mod(&o)
	}
	var ccScopes []any
	for _, s := range o.Scopes {
		if s != "openid" && s != "profile" && s != "email" && s != "offline_access" {
			ccScopes = append(ccScopes, s)
		}
	}
	eo := envOptions{noJwt: true}
	if !o.DisableJwtPlugin {
		eo.plugins = []*betterauth.Plugin{jwt.New(*irJWTOptions())}
	}
	env := newEnv(t, o, eo)
	h := env.signInWithTestUser()
	body := map[string]any{
		"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
		"token_endpoint_auth_method": "client_secret_post",
		"redirect_uris":              []any{irRedirectURI},
		"application_type":           "native",
		"skip_consent":               true,
	}
	if ccScopes != nil {
		body["client_credentials_scopes"] = ccScopes
	} else {
		body["client_credentials_scopes"] = []any{}
	}
	c := irClientFrom(t, env.adminCreateClient(h, body))
	return env, h, c
}

// irClientCredentials posts a client_credentials grant (client.oauth2.token).
func irClientCredentials(env *testEnv, h http.Header, c irClient, scope string) *response {
	env.t.Helper()
	return irPostForm(env, h, "/oauth2/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {c.id}, "client_secret": {c.secret}, "scope": {scope}, "redirect_uri": {irRedirectURI}})
}

// irCodeTokens mirrors client.oauth2.token with grant_type authorization_code (plus scope).
func irCodeTokens(env *testEnv, h http.Header, c irClient, scopes []string, resource string) map[string]any {
	env.t.Helper()
	code, verifier := irAuthorize(env, h, c.id, scopes)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {c.id}, "client_secret": {c.secret}, "scope": {strings.Join(scopes, " ")},
		"redirect_uri": {irRedirectURI}}
	if resource != "" {
		form.Set("resource", resource)
	}
	res := irPostForm(env, h, "/oauth2/token", form)
	if res.status != 200 {
		env.t.Fatalf("token: %d %s", res.status, res.body)
	}
	return res.json()
}

// Custom exposes the wrapped adapter's CustomAdapter (migrations).
func (a irCountingAdapter) Custom() adapter.CustomAdapter {
	if c, ok := a.Adapter.(interface{ Custom() adapter.CustomAdapter }); ok {
		return c.Custom()
	}
	return nil
}
