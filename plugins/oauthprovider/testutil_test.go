package oauthprovider

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
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Test helpers mirroring upstream's getTestInstance + createAuthClient: a migrated SQLite
// database, a test user, direct API calls and HTTP requests against the handler at
// http://localhost:3000/api/auth.

const (
	testBaseURL      = "http://localhost:3000"
	testAuthBase     = testBaseURL + "/api/auth"
	testUserEmail    = "test@test.com"
	testUserPassword = "test123456"
	testUserName     = "test user"
)

// envOptions customise newEnv.
type envOptions struct {
	// noJwt omits the jwt plugin.
	noJwt bool
	// jwt configures the jwt plugin.
	jwt *jwt.Options
	// plugins are added after the default ones.
	plugins []*betterauth.Plugin
	// before are added before the jwt / oauth-provider plugins.
	before []*betterauth.Plugin
	// mutate adjusts the config.
	mutate func(c *betterauth.Config)
	// disableTestUser skips creating the test user.
	disableTestUser bool
	// expectInitError makes newEnv return the betterauth.New error instead of failing.
	expectInitError bool
}

type testEnv struct {
	t       *testing.T
	auth    *betterauth.Auth
	db      adapter.Adapter
	plugin  *betterauth.Plugin
	initErr error
	// external handlers for other hosts (RP callbacks, JWKS servers, ...).
	mu    sync.Mutex
	hosts map[string]http.Handler
}

// newEnv builds an auth instance with the jwt and oauth-provider plugins.
func newEnv(t *testing.T, opts Options, eo ...envOptions) *testEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	var o envOptions
	if len(eo) > 0 {
		o = eo[0]
	}
	if opts.LoginPage == "" {
		opts.LoginPage = "/login"
	}
	if opts.ConsentPage == "" {
		opts.ConsentPage = "/consent"
	}
	env := &testEnv{t: t, hosts: map[string]http.Handler{}}
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
	plugins := append([]*betterauth.Plugin{}, o.before...)
	if !o.noJwt {
		jo := jwt.Options{}
		if o.jwt != nil {
			jo = *o.jwt
		}
		plugins = append(plugins, jwt.New(jo))
	}
	env.plugin = New(opts)
	plugins = append(plugins, env.plugin)
	plugins = append(plugins, o.plugins...)
	cfg := betterauth.Config{
		BaseURL:          testBaseURL,
		Secret:           "better-auth.secret-for-tests-1234567890abcdef",
		Database:         factory,
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		TrustedOrigins:   []string{testBaseURL},
		Plugins:          plugins,
	}
	if o.mutate != nil {
		o.mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		if o.expectInitError {
			env.initErr = err
			return env
		}
		t.Fatalf("New: %v", err)
	}
	if o.expectInitError {
		t.Fatalf("expected init error, got none")
	}
	if err := a.RunMigrations(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	env.auth = a
	prevClient, prevBackchannel := oauthcore.HTTPClient, BackchannelHTTPClient
	prevFetch := DefaultClientMetadataFetch
	oauthcore.HTTPClient = &http.Client{Transport: env, CheckRedirect: prevClient.CheckRedirect}
	BackchannelHTTPClient = &http.Client{Transport: env, CheckRedirect: prevBackchannel.CheckRedirect}
	DefaultClientMetadataFetch = func(req *http.Request) (*http.Response, error) {
		return (&http.Client{Transport: env, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}).Do(req)
	}
	oauthcore.ResetJWKSCache()
	t.Cleanup(func() {
		oauthcore.HTTPClient, BackchannelHTTPClient, DefaultClientMetadataFetch = prevClient, prevBackchannel, prevFetch
		oauthcore.ResetJWKSCache()
	})
	if !o.disableTestUser {
		env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": testUserEmail, "password": testUserPassword, "name": testUserName}})
	}
	return env
}

// RoundTrip routes requests for localhost:3000 to the auth handler and other hosts to
// registered handlers (stands in for the network in tests).
func (e *testEnv) RoundTrip(req *http.Request) (*http.Response, error) {
	e.mu.Lock()
	h, ok := e.hosts[req.URL.Host]
	e.mu.Unlock()
	if !ok && req.URL.Host == "localhost:3000" {
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

// serveHost registers a handler for host (e.g. "rp.example.com").
func (e *testEnv) serveHost(host string, h http.Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hosts[host] = h
}

func (e *testEnv) ctx() context.Context { return context.Background() }

// call invokes auth.api.<key>; the second result is the API error.
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
	return decodeMap(e.t, res)
}

func decodeMap(t *testing.T, res *betterauth.CallResult) map[string]any {
	t.Helper()
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

// expectOAuthError asserts body.error == code (and the description when non-empty).
func expectOAuthError(t *testing.T, err *betterauth.APIError, code, description string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got success", code)
	}
	body := errBody(err)
	if body["error"] != code {
		t.Fatalf("expected error %q, got %v (status %d)", code, body, err.StatusCode)
	}
	if description != "" && body["error_description"] != description {
		t.Fatalf("expected error_description %q, got %q", description, body["error_description"])
	}
}

// signIn signs in and returns request headers with the session cookie.
func (e *testEnv) signIn(email, password string) http.Header {
	e.t.Helper()
	res, err := e.call("signInEmail", betterauth.CallInput{Body: map[string]any{"email": email, "password": password}})
	if err != nil {
		e.t.Fatalf("sign in: %v", errBody(err))
	}
	return cookieHeader(res.Headers)
}

func (e *testEnv) signInWithTestUser() http.Header { return e.signIn(testUserEmail, testUserPassword) }

// signUp creates a user and returns session headers.
func (e *testEnv) signUp(email, password, name string) http.Header {
	e.t.Helper()
	res, err := e.call("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": email, "password": password, "name": name}})
	if err != nil {
		e.t.Fatalf("sign up: %v", errBody(err))
	}
	return cookieHeader(res.Headers)
}

// cookieHeader turns Set-Cookie response headers into a request Cookie header.
func cookieHeader(h http.Header) http.Header {
	jar := map[string]string{}
	var order []string
	for _, sc := range h.Values("Set-Cookie") {
		name, value, attrs := betterauth.ParseSetCookie(sc)
		if _, seen := jar[name]; !seen {
			order = append(order, name)
		}
		if attrs["max-age"] == "0" {
			delete(jar, name)
			continue
		}
		jar[name] = value
	}
	var parts []string
	for _, n := range order {
		if v, ok := jar[n]; ok {
			parts = append(parts, n+"="+v)
		}
	}
	out := http.Header{}
	if len(parts) > 0 {
		out.Set("Cookie", strings.Join(parts, "; "))
	}
	return out
}

// mergeCookies applies Set-Cookie headers from res onto the request headers h.
func mergeCookies(h http.Header, res http.Header) http.Header {
	jar := map[string]string{}
	var order []string
	for _, c := range betterauth.ParseCookies(h.Get("Cookie")) {
		jar[c.Name] = c.Value
		order = append(order, c.Name)
	}
	for _, sc := range res.Values("Set-Cookie") {
		name, value, attrs := betterauth.ParseSetCookie(sc)
		if _, seen := jar[name]; !seen {
			order = append(order, name)
		}
		if attrs["max-age"] == "0" {
			delete(jar, name)
			continue
		}
		jar[name] = value
	}
	out := h.Clone()
	if out == nil {
		out = http.Header{}
	}
	var parts []string
	for _, n := range order {
		if v, ok := jar[n]; ok {
			parts = append(parts, n+"="+url.QueryEscape(v))
		}
	}
	out.Set("Cookie", strings.Join(parts, "; "))
	return out
}

// response is an HTTP response from the handler.
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

// do sends an HTTP request to path (relative to /api/auth, or absolute). body may be
// url.Values (form), a string (sent as-is) or any JSON value.
func (e *testEnv) do(method, path string, body any, headers http.Header) *response {
	e.t.Helper()
	target := path
	if !strings.HasPrefix(path, "http") {
		target = testAuthBase + path
	}
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case url.Values:
		rd = strings.NewReader(b.Encode())
		ct = "application/x-www-form-urlencoded"
	case string:
		rd = strings.NewReader(b)
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
	if req.Header.Get("Origin") == "" && method != http.MethodGet {
		req.Header.Set("Origin", testBaseURL)
	}
	rec := httptest.NewRecorder()
	e.auth.Handler().ServeHTTP(rec, req)
	return &response{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

// registerClient creates a client through /oauth2/create-client for the signed-in user.
func (e *testEnv) createClient(headers http.Header, body map[string]any) map[string]any {
	e.t.Helper()
	return e.mustCall("createOAuthClient", betterauth.CallInput{Headers: headers, Body: body})
}

// adminCreateClient creates a client through the server-only admin endpoint.
func (e *testEnv) adminCreateClient(headers http.Header, body map[string]any) map[string]any {
	e.t.Helper()
	return e.mustCall("adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: body})
}

// pkcePair returns a code verifier and its S256 challenge.
func pkcePair() (string, string) {
	verifier := "test-verifier-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFG"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizeURL builds /oauth2/authorize?params (params in the given order).
func authorizeURL(kv ...string) string {
	p := newSearchParams()
	for i := 0; i+1 < len(kv); i += 2 {
		p.append(kv[i], kv[i+1])
	}
	return "/oauth2/authorize?" + p.String()
}

// authorizeCode runs /oauth2/authorize with the session headers and returns the code from
// the redirect.
func (e *testEnv) authorizeCode(headers http.Header, kv ...string) string {
	e.t.Helper()
	res := e.do("GET", authorizeURL(kv...), nil, headers)
	loc := res.location()
	if loc == "" {
		if m := res.json(); m != nil {
			loc, _ = m["url"].(string)
		}
	}
	u, err := url.Parse(loc)
	if err != nil || u.Query().Get("code") == "" {
		e.t.Fatalf("expected code redirect, got %d %q %s", res.status, loc, res.body)
	}
	return u.Query().Get("code")
}

// token posts a form to /oauth2/token.
func (e *testEnv) token(form url.Values, headers http.Header) *response {
	return e.do("POST", "/oauth2/token", form, headers)
}

func basicAuth(id, secret string) http.Header {
	h := http.Header{}
	h.Set("Authorization", oauthcore.EncodeBasicCredentials(id, secret))
	return h
}

// decodeJWTPayload returns the unverified claims of a JWT.
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

func decodeJWTHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func (e *testEnv) findOne(model string, where ...adapter.Where) adapter.Record {
	e.t.Helper()
	r, err := e.db.FindOne(context.Background(), adapter.FindOneInput{Model: model, Where: where})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *testEnv) findMany(model string, where ...adapter.Where) []adapter.Record {
	e.t.Helper()
	r, err := e.db.FindMany(context.Background(), adapter.FindManyInput{Model: model, Where: where})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *testEnv) update(model string, update adapter.Record, where ...adapter.Where) {
	e.t.Helper()
	if _, err := e.db.Update(context.Background(), model, where, update); err != nil {
		e.t.Fatal(err)
	}
}

func eq(field string, v any) adapter.Where { return adapter.Where{Field: field, Value: v} }
