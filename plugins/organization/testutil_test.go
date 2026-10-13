package organization

// Test helpers: the Go equivalent of getTestInstance (memory database, the default test
// user test@test.com / test123456) plus small HTTP and direct-API clients.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const (
	testEmail    = "test@test.com"
	testPassword = "test123456"
	testName     = "test user"
)

type testEnv struct {
	t      *testing.T
	auth   *betterauth.Auth
	db     *memory.DB
	server *httptest.Server
	plugin *betterauth.Plugin

	mu     sync.Mutex
	emails []InvitationEmailData
}

type envConfig struct {
	// mutate adjusts the auth config.
	mutate func(c *betterauth.Config)
	// verifyUsers pre-verifies every created user (a user.create.before hook).
	verifyUsers bool
	// noTestUser skips creating test@test.com.
	noTestUser bool
	// extraPlugins are added after the organization plugin.
	extraPlugins []*betterauth.Plugin
}

// newEnv builds an auth instance with the organization plugin. When opts.SendInvitationEmail
// is nil, invitation emails are captured in env.emails.
func newEnv(t *testing.T, opts Options, cfgs ...envConfig) *testEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	var ec envConfig
	if len(cfgs) > 0 {
		ec = cfgs[0]
	}
	e := &testEnv{t: t, db: memory.NewDB()}
	if opts.SendInvitationEmail == nil {
		opts.SendInvitationEmail = func(ctx *Ctx, d InvitationEmailData, r *http.Request) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.emails = append(e.emails, d)
			return nil
		}
	}
	mux := http.NewServeMux()
	e.server = httptest.NewServer(mux)
	t.Cleanup(e.server.Close)
	e.plugin = New(opts)
	cfg := betterauth.Config{
		BaseURL:          e.server.URL,
		Secret:           "better-auth-secret-that-is-long-enough-for-validation-test",
		Database:         memory.New(e.db),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Plugins:          append([]*betterauth.Plugin{e.plugin}, ec.extraPlugins...),
	}
	if ec.verifyUsers {
		cfg.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
			Before: func(ctx context.Context, data map[string]any) (*betterauth.DBHookResult, error) {
				return &betterauth.DBHookResult{Data: map[string]any{"emailVerified": true}}, nil
			},
		}}}
	}
	if ec.mutate != nil {
		ec.mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.auth = a
	mux.Handle("/api/auth/", a.Handler())
	if !ec.noTestUser {
		e.signUp(testEmail, testPassword, testName)
	}
	return e
}

func (e *testEnv) lastEmail() InvitationEmailData {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.emails) == 0 {
		e.t.Fatal("no invitation email captured")
	}
	return e.emails[len(e.emails)-1]
}

func (e *testEnv) emailCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.emails)
}

// cookieHeaders converts Set-Cookie response headers into request headers with Cookie.
func cookieHeaders(h http.Header) http.Header {
	var parts []string
	for _, sc := range h.Values("Set-Cookie") {
		name, value, attrs := betterauth.ParseSetCookie(sc)
		if ma, ok := attrs["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) {
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

// mergeCookies applies Set-Cookie headers from h onto the Cookie header of base.
func mergeCookies(base http.Header, h http.Header) http.Header {
	jar := map[string]string{}
	var order []string
	for _, part := range strings.Split(base.Get("Cookie"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if _, ok := jar[k]; !ok {
			order = append(order, k)
		}
		jar[k] = v
	}
	for _, sc := range h.Values("Set-Cookie") {
		name, value, attrs := betterauth.ParseSetCookie(sc)
		if ma, ok := attrs["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) || value == "" {
			delete(jar, name)
			continue
		}
		if _, ok := jar[name]; !ok {
			order = append(order, name)
		}
		jar[name] = value
	}
	var parts []string
	for _, k := range order {
		if v, ok := jar[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	out := base.Clone()
	if out == nil {
		out = http.Header{}
	}
	out.Set("Cookie", strings.Join(parts, "; "))
	return out
}

// signUp creates a user and returns its session headers.
func (e *testEnv) signUp(email, password, name string) http.Header {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), "signUpEmail", betterauth.CallInput{
		Body: map[string]any{"email": email, "password": password, "name": name}})
	if err != nil {
		e.t.Fatalf("sign up %s: %v", email, err)
	}
	return cookieHeaders(res.Headers)
}

// signIn signs in and returns session headers.
func (e *testEnv) signIn(email, password string) http.Header {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), "signInEmail", betterauth.CallInput{
		Body: map[string]any{"email": email, "password": password}})
	if err != nil {
		e.t.Fatalf("sign in %s: %v", email, err)
	}
	return cookieHeaders(res.Headers)
}

// signInTestUser is signInWithTestUser.
func (e *testEnv) signInTestUser() http.Header { return e.signIn(testEmail, testPassword) }

// result is a decoded endpoint result.
type result struct {
	Status  int
	Data    any
	Headers http.Header
	Err     *betterauth.APIError
}

func (r *result) m() map[string]any {
	m, _ := r.Data.(map[string]any)
	return m
}

func (r *result) list() []any {
	l, _ := r.Data.([]any)
	return l
}

// code returns the error code ("" when successful).
func (r *result) code() string {
	if r.Err == nil {
		return ""
	}
	return r.Err.Code()
}

func (r *result) message() string {
	if r.Err == nil {
		return ""
	}
	return r.Err.Message()
}

// api calls an endpoint directly (auth.api.X). Pass nil headers for a server call.
func (e *testEnv) api(key string, headers http.Header, body any, query map[string]any) *result {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), key, betterauth.CallInput{Headers: headers, Body: body, Query: query})
	out := &result{}
	if err != nil {
		apiErr, ok := betterauth.AsAPIError(err)
		if !ok {
			e.t.Fatalf("%s: %v", key, err)
		}
		out.Err = apiErr
		out.Status = apiErr.StatusCode
		out.Headers = apiErr.Headers
		return out
	}
	out.Status, out.Headers = res.Status, res.Headers
	b, jerr := res.JSON()
	if jerr != nil {
		e.t.Fatalf("%s: encode: %v", key, jerr)
	}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out.Data)
	}
	return out
}

// mustAPI is api failing the test on error.
func (e *testEnv) mustAPI(key string, headers http.Header, body any, query map[string]any) *result {
	e.t.Helper()
	r := e.api(key, headers, body, query)
	if r.Err != nil {
		e.t.Fatalf("%s: %d %s %s", key, r.Status, r.code(), r.message())
	}
	return r
}

// do performs an HTTP request against the handler (the client path). path is relative to
// /api/auth; query may be nil.
func (e *testEnv) do(method, path string, headers http.Header, body any, query url.Values) *result {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	u := e.server.URL + "/api/auth" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", e.server.URL)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	out := &result{Status: res.StatusCode, Headers: res.Header}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out.Data)
	}
	if res.StatusCode >= 400 {
		m, _ := out.Data.(map[string]any)
		apiErr := betterauth.NewAPIErrorCode(res.StatusCode, nil)
		if m != nil {
			apiErr = betterauth.NewAPIErrorCode(res.StatusCode, jsonObj(m))
		}
		out.Err = apiErr
	}
	return out
}

func (e *testEnv) post(path string, headers http.Header, body any) *result {
	e.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	return e.do("POST", path, headers, body, nil)
}

func (e *testEnv) get(path string, headers http.Header, query url.Values) *result {
	e.t.Helper()
	return e.do("GET", path, headers, nil, query)
}

// session returns the current session map (get-session with disabled cookie cache).
func (e *testEnv) session(headers http.Header) map[string]any {
	e.t.Helper()
	r := e.api("getSession", headers, nil, map[string]any{"disableCookieCache": "true"})
	m := r.m()
	if m == nil {
		return nil
	}
	s, _ := m["session"].(map[string]any)
	return s
}

// createOrg creates an organization as headers' user and returns the response map.
func (e *testEnv) createOrg(headers http.Header, name, slug string, extra ...map[string]any) map[string]any {
	e.t.Helper()
	body := map[string]any{"name": name, "slug": slug}
	for _, x := range extra {
		for k, v := range x {
			body[k] = v
		}
	}
	return e.mustAPI("createOrganization", headers, body, nil).m()
}

func jsonObj(m map[string]any) *jsonx.Object {
	raw, _ := json.Marshal(m)
	v, _ := jsonx.Parse(raw)
	o, _ := v.(*jsonx.Object)
	return o
}

func s(v any) string {
	str, _ := v.(string)
	return str
}

func expectCode(t *testing.T, r *result, status int, code string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected status %d, got %d (%s %s) data=%v", status, r.Status, r.code(), r.message(), r.Data)
	}
	if code != "" && r.code() != code {
		t.Fatalf("expected code %s, got %s (%s)", code, r.code(), r.message())
	}
}

func expectOK(t *testing.T, r *result) {
	t.Helper()
	if r.Err != nil || r.Status >= 400 {
		t.Fatalf("expected success, got %d %s %s", r.Status, r.code(), r.message())
	}
}
