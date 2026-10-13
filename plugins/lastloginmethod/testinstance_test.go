package lastloginmethod_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// instance mirrors upstream's getTestInstance: an in-memory database, email/password
// enabled, the bearer plugin, rate limiting off and a signed-up test user.
type instance struct {
	t        *testing.T
	auth     *betterauth.Auth
	db       *memory.DB
	baseURL  string
	email    string
	password string
	name     string
}

type instanceOpts struct {
	disableTestUser bool
}

const testSecret = "better-auth-secret-that-is-long-enough-for-validation-test"

func newInstance(t *testing.T, mutate func(c *betterauth.Config), o ...instanceOpts) *instance {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	in := &instance{t: t, db: memory.NewDB(), baseURL: "http://localhost:3000",
		email: "test@test.com", password: "test123456", name: "test user"}
	cfg := betterauth.Config{
		BaseURL:          in.baseURL,
		Secret:           testSecret,
		Database:         memory.New(in.db),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Logger:           betterauth.NopLogger{},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.Plugins = append([]*betterauth.Plugin{bearerPlugin()}, cfg.Plugins...)
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("betterauth.New: %v", err)
	}
	in.auth = a
	if len(o) == 0 || !o[0].disableTestUser {
		if _, err := a.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: in.email, Password: in.password, Name: in.name}, nil); err != nil {
			t.Fatalf("create test user: %v", err)
		}
	}
	return in
}

type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *response) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("decode %q: %v", r.Body, err)
	}
	return m
}

// do sends a request through the HTTP handler (the client's customFetchImpl).
func (in *instance) do(method, path string, body any, headers http.Header) *response {
	in.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, in.baseURL+"/api/auth"+path, rd)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	in.auth.ServeHTTP(rec, req)
	return &response{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
}

func setCookieValue(h http.Header, name string) (string, bool) {
	// parseSetCookieHeader: the last entry for a name wins
	val, found := "", false
	for _, sc := range h.Values("Set-Cookie") {
		n, v, _ := betterauth.ParseSetCookie(sc)
		if n == name {
			val, found = v, true
		}
	}
	return val, found
}

// signIn signs in and returns headers carrying the signed session cookie
// (signInWithTestUser).
func (in *instance) signIn(email, password string) http.Header {
	in.t.Helper()
	res := in.do("POST", "/sign-in/email", map[string]any{"email": email, "password": password}, nil)
	if res.Status != 200 {
		in.t.Fatalf("sign-in: %d %s", res.Status, res.Body)
	}
	v, _ := setCookieValue(res.Header, "better-auth.session_token")
	h := http.Header{}
	h.Set("Cookie", "better-auth.session_token="+betterauth.EncodeURIComponent(v))
	return h
}

func (in *instance) signInWithTestUser() http.Header { return in.signIn(in.email, in.password) }

func (in *instance) call(key string, ci betterauth.CallInput) (*betterauth.CallResult, error) {
	return in.auth.API.Call(context.Background(), key, ci)
}

func (in *instance) ctx() *betterauth.EndpointContext {
	return &betterauth.EndpointContext{Auth: in.auth.Context()}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
