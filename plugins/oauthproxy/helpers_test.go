package oauthproxy

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

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// ---- Better Auth test instance (getTestInstance equivalent) ----

const testSecret = "better-auth-secret-that-is-long-enough-for-validation-test"

type inst struct {
	t    *testing.T
	auth *betterauth.Auth
	logs *logRecorder
	base string
}

type logRecorder struct {
	mu      sync.Mutex
	entries []string
}

func (l *logRecorder) add(level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	parts := []string{level, msg}
	for _, a := range args {
		parts = append(parts, jsString2(a))
	}
	l.entries = append(l.entries, strings.Join(parts, " "))
}

func jsString2(a any) string {
	switch t := a.(type) {
	case string:
		return t
	case error:
		return t.Error()
	}
	b, _ := json.Marshal(a)
	return string(b)
}

func (l *logRecorder) Debug(msg string, args ...any) { l.add("debug", msg, args...) }
func (l *logRecorder) Info(msg string, args ...any)  { l.add("info", msg, args...) }
func (l *logRecorder) Warn(msg string, args ...any)  { l.add("warn", msg, args...) }
func (l *logRecorder) Error(msg string, args ...any) { l.add("error", msg, args...) }

func (l *logRecorder) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if strings.Contains(e, s) {
			return true
		}
	}
	return false
}

type instOpts struct {
	disableTestUser bool
	noDatabase      bool
}

func baseConfig(logs *logRecorder) betterauth.Config {
	return betterauth.Config{
		SocialProviders:  []oauth2.Provider{githubProvider(), googleProvider(nil)},
		BaseURL:          "http://localhost:3000",
		Secret:           testSecret,
		Database:         memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Logger:           logs,
	}
}

func newInstE(t *testing.T, mutate func(c *betterauth.Config), o instOpts) (*inst, error) {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	logs := &logRecorder{}
	cfg := baseConfig(logs)
	if o.noDatabase {
		cfg.Database = nil
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		return nil, err
	}
	in := &inst{t: t, auth: a, logs: logs, base: cfg.BaseURL}
	if !o.disableTestUser && cfg.Database != nil {
		res := in.client().post("/sign-up/email", map[string]any{"email": "test@test.com", "password": "test123456", "name": "test user"})
		if res.Status != 200 {
			t.Fatalf("test user sign-up: %d %s", res.Status, res.Body)
		}
	}
	return in, nil
}

func newInst(t *testing.T, mutate func(c *betterauth.Config), o ...instOpts) *inst {
	t.Helper()
	var opts instOpts
	if len(o) > 0 {
		opts = o[0]
	}
	in, err := newInstE(t, mutate, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return in
}

func (in *inst) ctx() *betterauth.AuthContext { return in.auth.Context() }

func (in *inst) provider(id string) oauth2.Provider {
	return in.ctx().FindProvider(id)
}

func (in *inst) providerIDs() []string {
	var ids []string
	for _, p := range in.ctx().SocialProviders {
		ids = append(ids, p.ID())
	}
	return ids
}

type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *response) JSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("decode %q: %v", r.Body, err)
	}
	return m
}

func (r *response) location() string { return r.Header.Get("Location") }

func (r *response) setCookie(name string) (value string, attrs map[string]string, ok bool) {
	for _, sc := range r.Header.Values("Set-Cookie") {
		n, v, a := betterauth.ParseSetCookie(sc)
		if n == name {
			value, attrs, ok = v, a, true
		}
	}
	return
}

type client struct {
	in      *inst
	cookies map[string]string
	order   []string
	headers http.Header
}

func (in *inst) client() *client {
	return &client{in: in, cookies: map[string]string{}, headers: http.Header{}}
}

func (c *client) clone() *client {
	n := in2(c)
	for _, k := range c.order {
		n.setCookieValue(k, c.cookies[k])
	}
	return n
}

func in2(c *client) *client { return c.in.client() }

func (c *client) setCookieValue(name, value string) {
	if _, ok := c.cookies[name]; !ok {
		c.order = append(c.order, name)
	}
	c.cookies[name] = value
}

func (c *client) apply(h http.Header) {
	for _, sc := range h.Values("Set-Cookie") {
		n, v, a := betterauth.ParseSetCookie(sc)
		if ma, ok := a["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) {
			delete(c.cookies, n)
			continue
		}
		c.setCookieValue(n, v)
	}
}

func (c *client) cookieHeader() string {
	var parts []string
	for _, k := range c.order {
		if v, ok := c.cookies[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// do sends a request. target is a path below /api/auth or an absolute URL.
func (c *client) do(method, target string, body any, mutate ...func(*http.Request)) *response {
	c.in.t.Helper()
	u := target
	if !strings.HasPrefix(u, "http") {
		u = c.in.base + "/api/auth" + target
	}
	var rd io.Reader
	isJSON := false
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
		isJSON = true
	}
	req := httptest.NewRequest(method, u, rd)
	if isJSON {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range c.headers {
		req.Header[k] = vs
	}
	if ch := c.cookieHeader(); ch != "" {
		req.Header.Set("Cookie", ch)
	}
	for _, m := range mutate {
		m(req)
	}
	rec := httptest.NewRecorder()
	c.in.auth.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	c.apply(res.Header)
	return &response{Status: res.StatusCode, Header: res.Header, Body: b}
}

func (c *client) post(path string, body any, mutate ...func(*http.Request)) *response {
	return c.do("POST", path, body, mutate...)
}

func (c *client) get(path string, mutate ...func(*http.Request)) *response {
	return c.do("GET", path, nil, mutate...)
}

// session returns the get-session result (nil when signed out).
func (c *client) session() map[string]any {
	c.in.t.Helper()
	res := c.get("/get-session")
	if res.Status != 200 {
		c.in.t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if string(res.Body) == "null" {
		return nil
	}
	return res.JSON(c.in.t)
}

func sessionUser(s map[string]any) map[string]any {
	u, _ := s["user"].(map[string]any)
	return u
}

// signInSocial posts /sign-in/social and returns the authorization URL.
func (c *client) signInSocial(body map[string]any) (*response, string) {
	c.in.t.Helper()
	res := c.post("/sign-in/social", body)
	if res.Status != 200 {
		return res, ""
	}
	u, _ := res.JSON(c.in.t)["url"].(string)
	return res, u
}

// flowResult is the outcome of simulateOAuthFlow.
type flowResult struct {
	callbackURL string
	res         *response
}

// simulateOAuthFlow follows the authorization URL at the IdP and calls the callback with
// the client's cookies.
func (c *client) simulateOAuthFlow(authURL string) flowResult {
	c.in.t.Helper()
	req, _ := http.NewRequest("GET", authURL, nil)
	res, err := oauth2.HTTPClient.Do(req)
	if err != nil {
		c.in.t.Fatalf("authorize: %v", err)
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	if loc == "" {
		c.in.t.Fatalf("no redirect location from %s (status %d)", authURL, res.StatusCode)
	}
	cb := c.get(loc)
	return flowResult{callbackURL: cb.location(), res: cb}
}

func (in *inst) accounts(userID string) []*betterauth.Account {
	in.t.Helper()
	accs, err := in.ctx().InternalAdapter.FindAccounts(context.Background(), userID)
	if err != nil {
		in.t.Fatal(err)
	}
	return accs
}

func (in *inst) accountsByProvider(providerID string) []map[string]any {
	in.t.Helper()
	recs, err := in.ctx().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: providerID}}})
	if err != nil {
		in.t.Fatal(err)
	}
	var out []map[string]any
	for _, r := range recs {
		out = append(out, r)
	}
	return out
}

func strp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("expected %q to contain %q", s, sub)
	}
}

func mustNotContain(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("expected %q not to contain %q", s, sub)
	}
}

func mustEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func decodeJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		t.Fatalf("not an object: %s", s)
	}
	return o.Map()
}

func queryParam(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func ptrBool(b bool) *bool { return &b }

// emailVerifiedOnCreate is databaseHooks.user.create.before => emailVerified: true.
func emailVerifiedOnCreate(c *betterauth.Config) {
	c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
		Before: func(_ context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
			return &betterauth.DBHookResult{Data: adapter.Record{"emailVerified": true}}, nil
		},
	}}}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func googleProvider(mutate func(o *google.Options)) oauth2.Provider {
	o := google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}
	if mutate != nil {
		mutate(&o)
	}
	return google.New(o)
}

func githubProvider() oauth2.Provider {
	return github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}})
}

// signInWithTestUser signs in test@test.com and returns the client and user id.
func (in *inst) signInWithTestUser() (*client, string) {
	in.t.Helper()
	c := in.client()
	res := c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"})
	if res.Status != 200 {
		in.t.Fatalf("sign-in: %d %s", res.Status, res.Body)
	}
	return c, res.JSON(in.t)["user"].(map[string]any)["id"].(string)
}

func (in *inst) listUsers() []*betterauth.User {
	in.t.Helper()
	u, err := in.ctx().InternalAdapter.ListUsers(context.Background(), 0, 0, nil, nil)
	if err != nil {
		in.t.Fatal(err)
	}
	return u
}
