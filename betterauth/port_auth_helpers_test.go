package betterauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"golang.org/x/text/unicode/norm"
)

// Helpers mirroring upstream test-utils/test-instance.ts (getTestInstance).

const paBaseURL = "http://localhost:3000"

const paTestHashPrefix = "$test$sha256$"

func paTestHash(pw string) string {
	sum := sha256.Sum256([]byte(norm.NFKC.String(pw)))
	return paTestHashPrefix + hex.EncodeToString(sum[:])
}

// paTestPassword is the fast test hasher used by getTestInstance.
func paTestPassword() *PasswordConfig {
	return &PasswordConfig{
		Hash:   func(p string) (string, error) { return paTestHash(p), nil },
		Verify: func(h, p string) (bool, error) { return h == paTestHash(p), nil },
	}
}

type paUser struct {
	Email, Password, Name string
}

type paEnv struct {
	t        *testing.T
	auth     *Auth
	db       *memory.DB
	testUser paUser
}

type paInstanceOpts struct {
	disableTestUser bool
	// wrap wraps the adapter factory (e.g. to inject failures).
	wrap func(adapter.Factory) adapter.Factory
}

// paNewEnv mirrors getTestInstance(options, config): baseURL http://localhost:3000,
// email+password enabled, rate limiting disabled, fast test hasher, and a test user
// (test@test.com / test123456) unless disabled.
func paNewEnv(t *testing.T, mutate func(c *Config), opts ...paInstanceOpts) *paEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	var o paInstanceOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	store := memory.NewDB()
	var factory adapter.Factory = memory.New(store)
	if o.wrap != nil {
		factory = o.wrap(factory)
	}
	cfg := Config{
		BaseURL:          paBaseURL,
		Secret:           "better-auth-secret-that-is-long-enough-for-validation-test",
		Database:         factory,
		EmailAndPassword: &EmailAndPasswordConfig{Enabled: true},
		RateLimit:        &RateLimitConfig{Enabled: Bool(false)},
		Logger:           NopLogger{},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if cfg.EmailAndPassword != nil && cfg.EmailAndPassword.Password == nil {
		cfg.EmailAndPassword.Password = paTestPassword()
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env := &paEnv{t: t, auth: a, db: store, testUser: paUser{Email: "test@test.com", Password: "test123456", Name: "test user"}}
	if !o.disableTestUser {
		if _, err := a.API.Call(context.Background(), "signUpEmail", CallInput{Body: map[string]any{
			"email": env.testUser.Email, "password": env.testUser.Password, "name": env.testUser.Name,
		}}); err != nil {
			t.Fatalf("create test user: %v", err)
		}
	}
	return env
}

// call invokes auth.api.<key> directly (no HTTP request).
func (e *paEnv) call(key string, body any, headers http.Header) (*CallResult, *APIError) {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), key, CallInput{Body: body, Headers: headers})
	if err != nil {
		apiErr, ok := AsAPIError(err)
		if !ok {
			e.t.Fatalf("%s: non-API error: %v", key, err)
		}
		return res, apiErr
	}
	return res, nil
}

// mustCall is call that fails the test on error and returns the decoded JSON result.
func (e *paEnv) mustCall(key string, body any, headers http.Header) (map[string]any, *CallResult) {
	e.t.Helper()
	res, apiErr := e.call(key, body, headers)
	if apiErr != nil {
		e.t.Fatalf("%s: unexpected error %d %s %q", key, apiErr.StatusCode, apiErr.Code(), apiErr.Message())
	}
	return paDecode(e.t, res), res
}

func paDecode(t *testing.T, res *CallResult) map[string]any {
	t.Helper()
	b, err := res.JSON()
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return m
}

func paRaw(t *testing.T, res *CallResult) []byte {
	t.Helper()
	b, err := res.JSON()
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	return b
}

// paKeys returns the top-level keys of a JSON object (or of the object at path) in order.
func paKeys(t *testing.T, raw []byte, path ...string) []string {
	t.Helper()
	cur := json.RawMessage(raw)
	for _, p := range path {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(cur, &m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		cur = m[p]
	}
	dec := json.NewDecoder(bytes.NewReader(cur))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", cur)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

type paResponse = testResponse

// do sends an HTTP request through auth.handler. target is either a path under
// /api/auth (e.g. "/sign-in/email") or an absolute URL.
func (e *paEnv) do(method, target string, body any, headers map[string]string) *paResponse {
	e.t.Helper()
	u := target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		u = paBaseURL + "/api/auth" + target
	}
	var r io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	case url.Values:
		r = strings.NewReader(b.Encode())
		ct = "application/x-www-form-urlencoded"
	default:
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
		ct = "application/json"
	}
	req := httptest.NewRequest(method, u, r)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.auth.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &paResponse{Status: res.StatusCode, Header: res.Header, Body: b}
}

// signIn signs in through the handler (client.signIn.email) and returns the response and
// a Cookie header carrying the session token (as signInWithTestUser does).
func (e *paEnv) signIn(email, password string) (*paResponse, http.Header) {
	e.t.Helper()
	res := e.do("POST", "/sign-in/email", map[string]any{"email": email, "password": password}, nil)
	if res.Status != 200 {
		e.t.Fatalf("sign-in failed: %d %s", res.Status, res.Body)
	}
	tok, ok := res.cookie("better-auth.session_token")
	if !ok {
		e.t.Fatalf("no session cookie in sign-in response")
	}
	h := http.Header{}
	h.Set("Cookie", "better-auth.session_token="+tok)
	return res, h
}

func (e *paEnv) signInWithTestUser() (map[string]any, http.Header) {
	e.t.Helper()
	res, h := e.signIn(e.testUser.Email, e.testUser.Password)
	return res.JSON(e.t), h
}

func paHeaderMap(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// paSetCookie returns the parsed Set-Cookie for name (value and lower-cased attributes).
func paSetCookie(h http.Header, name string) (string, map[string]string, bool) {
	for _, sc := range h.Values("Set-Cookie") {
		n, v, attrs := ParseSetCookie(sc)
		if n == name {
			return v, attrs, true
		}
	}
	return "", nil, false
}

// paMock counts calls and records arguments (vi.fn()).
type paMock struct {
	mu    sync.Mutex
	calls [][]any
}

func (m *paMock) record(args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, args)
}

func (m *paMock) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *paMock) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func (m *paMock) last() []any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return nil
	}
	return m.calls[len(m.calls)-1]
}

// paLogEntry / paRecLogger record logs (logger: { level: "info", log }).
type paLogEntry struct {
	level, msg string
}

type paRecLogger struct {
	mu      sync.Mutex
	entries []paLogEntry
}

func (l *paRecLogger) add(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, paLogEntry{level, msg})
}
func (l *paRecLogger) Debug(string, ...any)       {}
func (l *paRecLogger) Info(msg string, _ ...any)  { l.add("info", msg) }
func (l *paRecLogger) Warn(msg string, _ ...any)  { l.add("warn", msg) }
func (l *paRecLogger) Error(msg string, _ ...any) { l.add("error", msg) }
func (l *paRecLogger) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = nil
}
func (l *paRecLogger) snapshot() []paLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]paLogEntry(nil), l.entries...)
}

// paFailingAdapter wraps an adapter and fails session reads while failSessionReads is set
// (vi.spyOn(internalAdapter, "findSession").mockRejectedValueOnce(...)).
type paFailingAdapter struct {
	adapter.Adapter
	failSessionReads *atomic.Bool
}

var errPaDatabaseUnavailable = errors.New("database unavailable")

func (f *paFailingAdapter) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	if in.Model == "session" && f.failSessionReads.Load() {
		return nil, errPaDatabaseUnavailable
	}
	return f.Adapter.FindOne(ctx, in)
}

func (f *paFailingAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	if in.Model == "session" && f.failSessionReads.Load() {
		return nil, errPaDatabaseUnavailable
	}
	return f.Adapter.FindMany(ctx, in)
}

func paWrapFailing(flag *atomic.Bool) func(adapter.Factory) adapter.Factory {
	return func(inner adapter.Factory) adapter.Factory {
		return func(o adapter.Options) (adapter.Adapter, error) {
			a, err := inner(o)
			if err != nil {
				return nil, err
			}
			return &paFailingAdapter{Adapter: a, failSessionReads: flag}, nil
		}
	}
}

func paFormatErr(e *APIError) string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d %s %q", e.StatusCode, e.Code(), e.Message())
}
