package apikey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	_ "modernc.org/sqlite"
)

// This file mirrors packages/better-auth/src/test-utils/test-instance.ts: an in-memory
// SQLite instance (migrated like upstream's getTestInstance) with email/password enabled,
// a fast test password hasher and a pre-created test user (test@test.com / test123456).

const testBaseURL = "http://localhost:3000"

func testHash(pw string) (string, error) {
	sum := sha256.Sum256([]byte(pw))
	return "$test$sha256$" + hex.EncodeToString(sum[:]), nil
}

func testVerify(hash, pw string) (bool, error) {
	h, _ := testHash(pw)
	return h == hash, nil
}

type instance struct {
	t    *testing.T
	auth *betterauth.Auth
	p    *plugin
	// offset is the fake-timer offset applied to the plugin clock (vi.advanceTimersByTime).
	offset atomic.Int64
}

// newInstance builds an Auth instance with the api-key plugin (plus extra plugins).
func newInstance(t *testing.T, o Options, mutate func(c *betterauth.Config), extra ...*betterauth.Plugin) *instance {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
	return newInstanceOn(t, conn, o, mutate, extra...)
}

// newInstanceOn is newInstance on a given SQL database.
func newInstanceOn(t *testing.T, conn *sql.DB, o Options, mutate func(c *betterauth.Config), extra ...*betterauth.Plugin) *instance {
	t.Helper()
	p, err := newPlugin(o)
	if err != nil {
		t.Fatal(err)
	}
	inst := &instance{t: t, p: p}
	p.now = func() time.Time { return time.Now().Add(time.Duration(inst.offset.Load())) }
	plugins := append(append([]*betterauth.Plugin{}, extra...), p.build())
	cfg := betterauth.Config{
		BaseURL:  testBaseURL,
		Secret:   "better-auth-secret-that-is-long-enough-for-validation-test",
		Database: sqladapter.New(conn, sqladapter.Config{}),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true,
			Password: &betterauth.PasswordConfig{Hash: testHash, Verify: testVerify}},
		RateLimit: &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Logger:    betterauth.NopLogger{},
		Plugins:   plugins,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst.auth = a
	if err := a.RunMigrations(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := a.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: "test@test.com", Password: "test123456", Name: "test user"}, nil); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return inst
}

// advance moves the plugin clock forward (vi.advanceTimersByTimeAsync).
func (i *instance) advance(d time.Duration) { i.offset.Add(int64(d)) }

// useRealTimers resets the plugin clock.
func (i *instance) useRealTimers() { i.offset.Store(0) }

// signedIn is the result of signInWithTestUser.
type signedIn struct {
	headers http.Header
	user    map[string]any
	userID  string
}

func (i *instance) signIn(email, password string) signedIn {
	i.t.Helper()
	res, err := i.auth.API.SignInEmail(context.Background(), email, password, nil, nil)
	if err != nil {
		i.t.Fatalf("sign in: %v", err)
	}
	var cookies []string
	for _, sc := range res.Headers.Values("Set-Cookie") {
		nv, _, _ := strings.Cut(sc, ";")
		cookies = append(cookies, strings.TrimSpace(nv))
	}
	var m map[string]any
	_ = res.Decode(&m)
	u, _ := m["user"].(map[string]any)
	h := http.Header{}
	h.Set("Cookie", strings.Join(cookies, "; "))
	return signedIn{headers: h, user: u, userID: u["id"].(string)}
}

func (i *instance) signInWithTestUser() signedIn {
	i.t.Helper()
	return i.signIn("test@test.com", "test123456")
}

func (i *instance) signUp(email, password, name string) string {
	i.t.Helper()
	res, err := i.auth.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: email, Password: password, Name: name}, nil)
	if err != nil {
		i.t.Fatalf("sign up: %v", err)
	}
	var m map[string]any
	_ = res.Decode(&m)
	return m["user"].(map[string]any)["id"].(string)
}

// call invokes a server endpoint (auth.api.<key>). It returns the decoded JSON result or
// the APIError.
func (i *instance) call(key string, body any, headers http.Header, query ...map[string]any) (map[string]any, *betterauth.APIError) {
	i.t.Helper()
	in := betterauth.CallInput{Body: body, Headers: headers}
	if len(query) > 0 {
		in.Query = query[0]
	}
	res, err := i.auth.API.Call(context.Background(), key, in)
	if err != nil {
		e, ok := betterauth.AsAPIError(err)
		if !ok {
			i.t.Fatalf("%s: %v", key, err)
		}
		return nil, e
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		i.t.Fatalf("decode %s: %v", key, err)
	}
	return m, nil
}

// mustCall fails the test on error.
func (i *instance) mustCall(key string, body any, headers http.Header, query ...map[string]any) map[string]any {
	i.t.Helper()
	m, e := i.call(key, body, headers, query...)
	if e != nil {
		i.t.Fatalf("%s: %d %v", key, e.StatusCode, e.Body)
	}
	return m
}

func (i *instance) createKey(body map[string]any, headers http.Header) map[string]any {
	i.t.Helper()
	return i.mustCall("createApiKey", body, headers)
}

func (i *instance) verify(body map[string]any) map[string]any {
	i.t.Helper()
	return i.mustCall("verifyApiKey", body, nil)
}

func (i *instance) getKey(id, configID string, headers http.Header) (map[string]any, *betterauth.APIError) {
	q := map[string]any{"id": id}
	if configID != "" {
		q["configId"] = configID
	}
	return i.call("getApiKey", nil, headers, q)
}

// response is an HTTP response seen by the client.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *response) JSON() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}

// Data is the client's `data` (nil on error responses).
func (r *response) Data() map[string]any {
	if r.Status >= 400 {
		return nil
	}
	return r.JSON()
}

// Code is error.code.
func (r *response) Code() string {
	if r.Status < 400 {
		return ""
	}
	s, _ := r.JSON()["code"].(string)
	return s
}

func (r *response) Message() string {
	if r.Status < 400 {
		return ""
	}
	s, _ := r.JSON()["message"].(string)
	return s
}

// http performs a client request (the official client with fetchOptions.headers).
func (i *instance) http(method, path string, body any, headers http.Header) *response {
	i.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			i.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", testBaseURL)
	for k, vs := range headers {
		req.Header[k] = vs
	}
	rec := httptest.NewRecorder()
	i.auth.Handler().ServeHTTP(rec, req)
	return &response{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
}

func (i *instance) clientCreate(body map[string]any, headers http.Header) *response {
	i.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	return i.http("POST", "/api-key/create", body, headers)
}

func (i *instance) clientGet(query string, headers http.Header) *response {
	i.t.Helper()
	return i.http("GET", "/api-key/get?"+query, nil, headers)
}

func (i *instance) clientList(query string, headers http.Header) *response {
	i.t.Helper()
	p := "/api-key/list"
	if query != "" {
		p += "?" + query
	}
	return i.http("GET", p, nil, headers)
}

func (i *instance) clientUpdate(body map[string]any, headers http.Header) *response {
	i.t.Helper()
	return i.http("POST", "/api-key/update", body, headers)
}

func (i *instance) clientDelete(body map[string]any, headers http.Header) *response {
	i.t.Helper()
	return i.http("POST", "/api-key/delete", body, headers)
}

// ---- assertions ----

func eq(t *testing.T, got, want any) {
	t.Helper()
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func isNil(t *testing.T, v any) {
	t.Helper()
	if v != nil {
		t.Fatalf("expected null, got %#v", v)
	}
}

func notNil(t *testing.T, v any) {
	t.Helper()
	if v == nil {
		t.Fatal("expected a value, got null")
	}
}

func expectAPIError(t *testing.T, e *betterauth.APIError, status string, code betterauth.ErrorCode) {
	t.Helper()
	if e == nil {
		t.Fatalf("expected %s error, got success", status)
	}
	if e.Status != status {
		t.Fatalf("expected status %s, got %s (%v)", status, e.Status, e.Body)
	}
	if code.Message != "" && e.Message() != code.Message {
		t.Fatalf("expected message %q, got %q", code.Message, e.Message())
	}
}

func expectStatus(t *testing.T, res *response, status int, code string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("expected status %d, got %d: %s", status, res.Status, res.Body)
	}
	if code != "" && res.Code() != code {
		t.Fatalf("expected code %s, got %q: %s", code, res.Code(), res.Body)
	}
}

func expectOK(t *testing.T, res *response) map[string]any {
	t.Helper()
	if res.Status != 200 {
		t.Fatalf("expected 200, got %d: %s", res.Status, res.Body)
	}
	return res.JSON()
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func parseTime(t *testing.T, v any) time.Time {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("expected a date string, got %#v", v)
	}
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func errCode(m map[string]any) string {
	e := obj(m["error"])
	s, _ := e["code"].(string)
	return s
}

// ---- secondary storage used by the tests (a Map like upstream) ----

type mapStorage struct {
	mu       sync.Mutex
	data     map[string]string
	ttls     map[string]time.Duration
	getHook  func(key string)
	setHook  func(key string)
	gets     []string
	sets     []string
	deletes  []string
	recordOp bool
}

func newMapStorage() *mapStorage {
	return &mapStorage{data: map[string]string{}, ttls: map[string]time.Duration{}}
}

func (s *mapStorage) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	hook := s.getHook
	if s.recordOp {
		s.gets = append(s.gets, key)
	}
	s.mu.Unlock()
	if hook != nil {
		hook(key)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok && v != "", nil
}

func (s *mapStorage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	hook := s.setHook
	if s.recordOp {
		s.sets = append(s.sets, key)
	}
	s.mu.Unlock()
	if hook != nil {
		hook(key)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	if ttl > 0 {
		s.ttls[key] = ttl
	}
	return nil
}

func (s *mapStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recordOp {
		s.deletes = append(s.deletes, key)
	}
	delete(s.data, key)
	delete(s.ttls, key)
	return nil
}

func (s *mapStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	delete(s.data, key)
	delete(s.ttls, key)
	return v, ok, nil
}

func (s *mapStorage) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	if v, ok := s.data[key]; ok {
		_ = json.Unmarshal([]byte(v), &n)
	}
	n++
	b, _ := json.Marshal(n)
	s.data[key] = string(b)
	if ttl > 0 {
		s.ttls[key] = ttl
	}
	return n, nil
}

func (s *mapStorage) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[key]
	return ok
}

func (s *mapStorage) get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok
}

func (s *mapStorage) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string]string{}
	s.ttls = map[string]time.Duration{}
	s.getHook, s.setHook = nil, nil
	s.gets, s.sets, s.deletes = nil, nil, nil
	s.recordOp = false
}

func (s *mapStorage) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.data))
	for k := range s.data {
		out = append(out, k)
	}
	return out
}

func (s *mapStorage) startRecording() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets, s.sets, s.deletes = nil, nil, nil
	s.recordOp = true
}

func count(list []string, key string) int {
	n := 0
	for _, k := range list {
		if k == key {
			n++
		}
	}
	return n
}

func (s *mapStorage) counts(key string) (gets, sets, deletes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return count(s.gets, key), count(s.sets, key), count(s.deletes, key)
}
