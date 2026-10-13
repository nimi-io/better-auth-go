package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/internal/testdb"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Test helpers mirroring upstream's getTestInstance + createAuthClient (modelled on
// plugins/oauthprovider/testutil_test.go): a migrated SQLite database, a test user, direct
// API calls and HTTP requests against the handler.

const (
	testUserEmail    = "test@test.com"
	testUserPassword = "test123456"
	testUserName     = "test user"
)

type envOptions struct {
	baseURL string
	plugins []*betterauth.Plugin
	mutate  func(c *betterauth.Config)
}

type testEnv struct {
	t       *testing.T
	baseURL string
	auth    *betterauth.Auth
	db      adapter.Adapter
	mu      sync.Mutex
	hosts   map[string]http.Handler
}

func newEnv(t *testing.T, o envOptions) *testEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	if o.baseURL == "" {
		o.baseURL = "http://localhost:3000"
	}
	env := &testEnv{t: t, baseURL: o.baseURL, hosts: map[string]http.Handler{}}
	conn := testdb.SQLite(t)
	base := sqladapter.New(conn, sqladapter.Config{})
	factory := func(ao adapter.Options) (adapter.Adapter, error) {
		a, err := base(ao)
		if err != nil {
			return nil, err
		}
		env.db = a
		return a, nil
	}
	cfg := betterauth.Config{
		BaseURL:          o.baseURL,
		Secret:           "better-auth.secret-for-tests-1234567890abcdef",
		Database:         factory,
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		TrustedOrigins:   []string{o.baseURL},
		Plugins:          o.plugins,
	}
	if o.mutate != nil {
		o.mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.RunMigrations(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	env.auth = a
	prev := oauthcore.HTTPClient
	oauthcore.HTTPClient = &http.Client{Transport: env}
	oauthcore.ResetJWKSCache()
	t.Cleanup(func() {
		oauthcore.HTTPClient = prev
		oauthcore.ResetJWKSCache()
	})
	env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": testUserEmail, "password": testUserPassword, "name": testUserName}})
	return env
}

// RoundTrip routes requests for the auth host to the handler and other hosts to
// registered handlers (stands in for the network).
func (e *testEnv) RoundTrip(req *http.Request) (*http.Response, error) {
	e.mu.Lock()
	h, ok := e.hosts[req.URL.Host]
	e.mu.Unlock()
	if u, _ := url.Parse(e.baseURL); !ok && u != nil && req.URL.Host == u.Host {
		h, ok = e.auth.Handler(), true
	}
	if !ok {
		return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: io.ErrUnexpectedEOF}
	}
	rec := httptest.NewRecorder()
	r2 := req.Clone(req.Context())
	if r2.Body == nil {
		r2.Body = http.NoBody
	}
	r2.RequestURI = req.URL.RequestURI()
	h.ServeHTTP(rec, r2)
	res := rec.Result()
	res.Request = req
	return res, nil
}

func (e *testEnv) serveHost(host string, h http.Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hosts[host] = h
}

func (e *testEnv) call(key string, in betterauth.CallInput) (*betterauth.CallResult, *betterauth.APIError) {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), key, in)
	if err != nil {
		apiErr, ok := betterauth.AsAPIError(err)
		if !ok {
			e.t.Fatalf("%s: %v", key, err)
		}
		return res, apiErr
	}
	return res, nil
}

func (e *testEnv) mustCall(key string, in betterauth.CallInput) map[string]any {
	e.t.Helper()
	res, err := e.call(key, in)
	if err != nil {
		e.t.Fatalf("%s failed: %d %v", key, err.StatusCode, errBody(err))
	}
	return decodeMap(res)
}

func decodeMap(res *betterauth.CallResult) map[string]any {
	if res == nil {
		return nil
	}
	if raw, ok := res.Data.(*betterauth.Response); ok {
		var m map[string]any
		_ = json.Unmarshal(raw.Body, &m)
		return m
	}
	var m map[string]any
	_ = res.Decode(&m)
	return m
}

func errBody(err *betterauth.APIError) map[string]any {
	if err == nil || err.Body == nil {
		return nil
	}
	b, _ := json.Marshal(err.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (e *testEnv) signInWithTestUser() http.Header {
	e.t.Helper()
	res, err := e.call("signInEmail", betterauth.CallInput{Body: map[string]any{"email": testUserEmail, "password": testUserPassword}})
	if err != nil {
		e.t.Fatalf("sign in: %v", errBody(err))
	}
	return cookieHeader(res.Headers)
}

func cookieHeader(h http.Header) http.Header {
	var parts []string
	for _, sc := range h.Values("Set-Cookie") {
		name, value, attrs := betterauth.ParseSetCookie(sc)
		if attrs["max-age"] == "0" {
			continue
		}
		parts = append(parts, name+"="+value)
	}
	out := http.Header{}
	if len(parts) > 0 {
		out.Set("Cookie", strings.Join(parts, "; "))
	}
	return out
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r *response) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.body, &m)
	return m
}

func (r *response) location() string { return r.header.Get("Location") }

// do sends an HTTP request to path (relative to the auth base path, or absolute). body may
// be url.Values (form) or any JSON value.
func (e *testEnv) do(method, path string, body any, headers http.Header) *response {
	e.t.Helper()
	target := path
	if !strings.HasPrefix(path, "http") {
		target = e.baseURL + "/api/auth" + path
	}
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case url.Values:
		rd = strings.NewReader(b.Encode())
		ct = "application/x-www-form-urlencoded"
	default:
		raw, _ := jsonx.Marshal(b)
		rd = bytes.NewReader(raw)
		ct = "application/json"
	}
	req := httptest.NewRequest(method, target, rd)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if ct != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", ct)
	}
	if req.Header.Get("Origin") == "" && method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Origin", e.baseURL)
	}
	rec := httptest.NewRecorder()
	e.auth.Handler().ServeHTTP(rec, req)
	return &response{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

// consent accepts the consent page the authorize redirect pointed to and returns the
// client redirect URL (oauthProviderClient's consent with window.location.search).
func (e *testEnv) consent(headers http.Header, consentLocation string) string {
	e.t.Helper()
	u, err := url.Parse(consentLocation)
	if err != nil {
		e.t.Fatal(err)
	}
	res := e.do("POST", "/oauth2/consent", map[string]any{"accept": true,
		"oauth_query": oauthprovider.BuildSignedOAuthQuery("?" + u.RawQuery)}, headers)
	m := res.json()
	out, _ := m["url"].(string)
	if out == "" {
		e.t.Fatalf("consent: %d %s", res.status, res.body)
	}
	return out
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func basicAuth(id, secret string) string { return oauthcore.EncodeBasicCredentials(id, secret) }

func mustPlugin(t *testing.T, o Options) *betterauth.Plugin {
	t.Helper()
	if o.LoginPage == "" {
		o.LoginPage = "/login"
	}
	if o.ConsentPage == "" {
		o.ConsentPage = "/consent"
	}
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
