package oauthprovider

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Shared helpers for the port of token.test.ts (prefix tk).

const tkRPBase = "http://localhost:5000"

// tkEnv is a test instance with a signed-in test user (getTestInstance + signInWithTestUser).
type tkEnv struct {
	*testEnv
	h       http.Header
	hooks   *tkHookAdapter
	logs    *tkLogger
	jwksKey oauthcore.KeyResolver
}

// tkHookAdapter wraps the database adapter to inject failures (vi.spyOn(adapter, ...)).
type tkHookAdapter struct {
	adapter.Adapter
	mu              sync.Mutex
	deleteManyCalls []string
	failDeleteMany  error
	updateHook      func(model string, update adapter.Record) error
}

func (a *tkHookAdapter) DeleteMany(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	a.mu.Lock()
	a.deleteManyCalls = append(a.deleteManyCalls, model)
	err := a.failDeleteMany
	a.failDeleteMany = nil
	a.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return a.Adapter.DeleteMany(ctx, model, where)
}

func (a *tkHookAdapter) Update(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (adapter.Record, error) {
	a.mu.Lock()
	hook := a.updateHook
	a.mu.Unlock()
	if hook != nil {
		if err := hook(model, update); err != nil {
			return nil, err
		}
	}
	return a.Adapter.Update(ctx, model, where, update)
}

func (a *tkHookAdapter) PlanMigrations(ctx context.Context, schema *db.Schema) (*adapter.MigrationPlan, error) {
	m, ok := adapter.AsMigrator(a.Adapter)
	if !ok {
		return nil, adapter.ErrMigrationsNotSupported
	}
	return m.PlanMigrations(ctx, schema)
}

// tkLogger records error logs.
type tkLogger struct {
	mu     sync.Mutex
	errors []string
}

func (l *tkLogger) Debug(string, ...any) {}
func (l *tkLogger) Info(string, ...any)  {}
func (l *tkLogger) Warn(string, ...any)  {}
func (l *tkLogger) Error(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, msg)
	_ = args
}

func (l *tkLogger) has(msg string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.errors {
		if m == msg {
			return true
		}
	}
	return false
}

// tkNewEnv builds an instance with jwt({jwt:{issuer: baseURL}}) unless noJwt is set.
func tkNewEnv(t *testing.T, opts Options, eo ...envOptions) *tkEnv {
	t.Helper()
	var o envOptions
	if len(eo) > 0 {
		o = eo[0]
	}
	if !o.noJwt && o.jwt == nil {
		o.jwt = &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}}
	}
	hooks := &tkHookAdapter{}
	logs := &tkLogger{}
	prevMutate := o.mutate
	o.mutate = func(c *betterauth.Config) {
		orig := c.Database
		c.Database = func(ao adapter.Options) (adapter.Adapter, error) {
			a, err := orig(ao)
			if err != nil {
				return nil, err
			}
			hooks.Adapter = a
			return hooks, nil
		}
		c.Logger = logs
		if prevMutate != nil {
			prevMutate(c)
		}
	}
	env := newEnv(t, opts, o)
	return &tkEnv{testEnv: env, h: env.signInWithTestUser(), hooks: hooks, logs: logs}
}

func (e *tkEnv) admin(body map[string]any) map[string]any {
	e.t.Helper()
	return e.adminCreateClient(e.h, body)
}

// jwks returns a local JWK set resolver over GET /jwks (createLocalJWKSet).
func (e *tkEnv) jwks() oauthcore.KeyResolver {
	e.t.Helper()
	if e.jwksKey != nil {
		return e.jwksKey
	}
	res := e.do("GET", "/jwks", nil, nil)
	if res.status != 200 {
		e.t.Fatalf("jwks: %d %s", res.status, res.body)
	}
	k, err := oauthcore.LocalJWKSet(res.json())
	if err != nil {
		e.t.Fatalf("jwks: %v", err)
	}
	e.jwksKey = k
	return k
}

// tkVerify is jwtVerify(token, jwks, {audience, issuer}).
func tkVerify(t *testing.T, token string, keys oauthcore.KeyResolver, audience, issuer string) *jsonx.Object {
	t.Helper()
	o := oauthcore.VerifyOptions{}
	if audience != "" {
		o.Audience = []string{audience}
	}
	if issuer != "" {
		o.Issuer = []string{issuer}
	}
	v, err := oauthcore.JWTVerify(token, keys, o)
	if err != nil {
		t.Fatalf("jwtVerify: %v", err)
	}
	return v.Payload
}

func tkGet(o *jsonx.Object, k string) any {
	v, _ := o.Get(k)
	if v == jsonx.Undefined {
		return nil
	}
	return v
}

func tkNum(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return -1
}

func tkVerifier() string { return bacrypto.RandomString(32) }

// tkAuthURL mirrors createAuthorizationURL (state "" omits the state parameter).
func tkAuthURL(clientID, redirectURI, state string, scopes []string, verifier string, extra ...string) string {
	kv := []string{"response_type", "code", "client_id", clientID}
	if state != "" {
		kv = append(kv, "state", state)
	}
	if len(scopes) > 0 {
		kv = append(kv, "scope", strings.Join(scopes, " "))
	}
	kv = append(kv, "redirect_uri", redirectURI)
	if verifier != "" {
		kv = append(kv, "code_challenge_method", "S256", "code_challenge", challengeFor(verifier))
	}
	kv = append(kv, extra...)
	return authorizeURL(kv...)
}

// authorize runs the authorization request with the session and returns the Location.
func (e *tkEnv) authorize(clientID, redirectURI, state string, scopes []string, verifier string, extra ...string) string {
	e.t.Helper()
	res := e.do("GET", tkAuthURL(clientID, redirectURI, state, scopes, verifier, extra...), nil, e.h)
	return res.location()
}

func tkCode(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("expected code redirect, got %q", loc)
	}
	return u.Query().Get("code")
}

// tkCodeForm is authorizationCodeRequest with client_secret_post authentication.
func tkCodeForm(code, verifier, redirectURI, clientID, secret string, resources ...string) url.Values {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		f.Set("code_verifier", verifier)
	}
	for _, r := range resources {
		f.Add("resource", r)
	}
	if secret != "" {
		f.Set("client_id", clientID)
		f.Set("client_secret", secret)
	}
	return f
}

// tkRefreshForm is refreshAccessTokenRequest with client_secret_post authentication.
func tkRefreshForm(refreshToken, clientID, secret, scope string, resources ...string) url.Values {
	f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	for _, r := range resources {
		f.Add("resource", r)
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	f.Set("client_id", clientID)
	f.Set("client_secret", secret)
	return f
}

func tkStr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func tkOK(t *testing.T, r *response) map[string]any {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("expected 200, got %d %s", r.status, r.body)
	}
	return r.json()
}

func tkExpectErr(t *testing.T, r *response, status int, code string) map[string]any {
	t.Helper()
	m := r.json()
	if r.status < 400 {
		t.Fatalf("expected error %s, got %d %s", code, r.status, r.body)
	}
	if status != 0 && r.status != status {
		t.Fatalf("expected status %d, got %d %s", status, r.status, r.body)
	}
	if code != "" && m["error"] != code {
		t.Fatalf("expected error %q, got %d %s", code, r.status, r.body)
	}
	return m
}

func tkFatalIf(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()
	if cond {
		t.Fatalf(format, args...)
	}
}

func tkBasic(id, secret string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))
	return h
}
