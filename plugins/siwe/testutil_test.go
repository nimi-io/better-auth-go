package siwe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"database/sql"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	_ "modernc.org/sqlite"
)

// This file mirrors packages/better-auth/src/test-utils/test-instance.ts: an in-memory
// SQLite instance (migrated like upstream's getTestInstance) with email/password enabled, a fast test password hasher and a pre-created
// test user (test@test.com / test123456).

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
	mu   sync.Mutex
}

type instanceOpts struct {
	disableTestUser bool
}

func newInstance(t *testing.T, plugins []*betterauth.Plugin, mutate func(c *betterauth.Config), o ...instanceOpts) *instance {
	t.Helper()
	inst := &instance{t: t}
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
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
	if cfg.EmailAndPassword != nil && cfg.EmailAndPassword.Password == nil {
		cfg.EmailAndPassword.Password = &betterauth.PasswordConfig{Hash: testHash, Verify: testVerify}
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst.auth = a
	if err := a.RunMigrations(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(o) == 0 || !o[0].disableTestUser {
		if _, err := a.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: "test@test.com", Password: "test123456", Name: "test user"}, nil); err != nil {
			t.Fatalf("create test user: %v", err)
		}
	}
	return inst
}

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

type client struct {
	inst    *instance
	cookies map[string]string
	order   []string
}

func (i *instance) client() *client { return &client{inst: i, cookies: map[string]string{}} }

func (c *client) cookieHeader() string {
	var parts []string
	for _, k := range c.order {
		if v, ok := c.cookies[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

func (c *client) apply(h http.Header) {
	for _, sc := range h.Values("Set-Cookie") {
		_, _, attrs := betterauth.ParseSetCookie(sc)
		nv, _, _ := strings.Cut(sc, ";")
		name, value, _ := strings.Cut(strings.TrimSpace(nv), "=")
		if ma, ok := attrs["max-age"]; (ok && strings.HasPrefix(ma, "0")) || (ok && strings.HasPrefix(ma, "-")) || value == "" {
			delete(c.cookies, name)
			continue
		}
		if _, ok := c.cookies[name]; !ok {
			c.order = append(c.order, name)
		}
		c.cookies[name] = value
	}
}

func (c *client) do(method, path string, body any, headers ...http.Header) *response {
	c.inst.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.inst.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", testBaseURL)
	if ck := c.cookieHeader(); ck != "" {
		req.Header.Set("Cookie", ck)
	}
	for _, h := range headers {
		for k, vs := range h {
			req.Header[k] = vs
		}
	}
	rec := httptest.NewRecorder()
	c.inst.auth.Handler().ServeHTTP(rec, req)
	c.apply(rec.Header())
	return &response{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
}

func (c *client) post(path string, body any, headers ...http.Header) *response {
	c.inst.t.Helper()
	return c.do("POST", path, body, headers...)
}

func (c *client) get(path string, headers ...http.Header) *response {
	c.inst.t.Helper()
	return c.do("GET", path, nil, headers...)
}

// session returns get-session's user (nil when signed out).
func (c *client) sessionUser() map[string]any {
	c.inst.t.Helper()
	res := c.get("/get-session")
	if res.Status != 200 {
		c.inst.t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	m := res.JSON()
	if m == nil {
		return nil
	}
	u, _ := m["user"].(map[string]any)
	return u
}

// signInWithTestUser returns a client signed in as the test user.
func (i *instance) signInWithTestUser() *client {
	i.t.Helper()
	c := i.client()
	res := c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"})
	if res.Status != 200 {
		i.t.Fatalf("sign in test user: %d %s", res.Status, res.Body)
	}
	return c
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

func eq(t *testing.T, got, want any) {
	t.Helper()
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
