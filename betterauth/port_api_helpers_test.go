package betterauth

// Shared helpers for the port_api_* tests (ports of better-auth/src/api/*.test.ts and
// better-auth/src/auth/*.test.ts, upstream v1.7.7).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// ppServe calls auth.handler(new Request(rawURL, ...)) directly, like the upstream tests
// that bypass the client. It returns an error when the URL cannot be parsed (the
// equivalent of `new Request()` throwing).
func ppServe(a *Auth, method, rawURL, body string, headers map[string]string) (*Response, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, r)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &Response{Status: res.StatusCode, Header: res.Header, Body: b}, nil
}

func ppMustServe(t *testing.T, a *Auth, method, rawURL, body string, headers map[string]string) *Response {
	t.Helper()
	res, err := ppServe(a, method, rawURL, body, headers)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, rawURL, err)
	}
	return res
}

// ppPluginEnv is getTestInstance/init with a custom plugin exposing endpoints.
func ppPluginEnv(t *testing.T, eps []*Endpoint, mutate func(c *Config)) *testEnv {
	t.Helper()
	return newTestEnv(t, func(c *Config) {
		if len(eps) > 0 {
			c.Plugins = append(c.Plugins, &Plugin{ID: "pp-test-endpoints", Endpoints: eps})
		}
		if mutate != nil {
			mutate(c)
		}
	})
}

// ppAsResponse is the Go translation of `asResponse: true` for a direct API call: it
// renders the call outcome with the same toResponse used by the router.
func ppAsResponse(res *CallResult, err error) *Response {
	if err != nil {
		e, ok := AsAPIError(err)
		if !ok {
			return &Response{Status: 500, Header: http.Header{}}
		}
		return toResponse(e, e.Headers, e.StatusCode)
	}
	return toResponse(res.Data, res.Headers, res.Status)
}

// ppSetCookie mirrors headers.get("set-cookie") (values joined with ", ").
func ppSetCookie(h http.Header) string { return strings.Join(h.Values("Set-Cookie"), ", ") }

// ppCookieHeader turns Set-Cookie response headers into a Cookie request header.
func ppCookieHeader(h http.Header) string {
	var parts []string
	for _, sc := range h.Values("Set-Cookie") {
		n, v, _ := ParseSetCookie(sc)
		if v == "" {
			continue
		}
		parts = append(parts, n+"="+v)
	}
	return strings.Join(parts, "; ")
}

// ppDecode JSON round-trips a handler result into plain Go values.
func ppDecode(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := jsonx.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %#v: %v", v, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return m
}

func ppBodyJSON(t *testing.T, r *Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("decode %q: %v", r.Body, err)
	}
	return m
}

// ppCaptureLogger records log lines.
type ppCaptureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *ppCaptureLogger) add(level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := level + " " + msg
	for _, a := range args {
		s += " " + fmt.Sprint(a)
	}
	l.lines = append(l.lines, s)
}
func (l *ppCaptureLogger) Debug(msg string, args ...any) { l.add("debug", msg, args...) }
func (l *ppCaptureLogger) Info(msg string, args ...any)  { l.add("info", msg, args...) }
func (l *ppCaptureLogger) Warn(msg string, args ...any)  { l.add("warn", msg, args...) }
func (l *ppCaptureLogger) Error(msg string, args ...any) { l.add("error", msg, args...) }

func (l *ppCaptureLogger) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ppStringRecorder is a goroutine-safe string slice.
type ppStringRecorder struct {
	mu   sync.Mutex
	vals []string
}

func (r *ppStringRecorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vals = append(r.vals, s)
}

func (r *ppStringRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vals = nil
}

func (r *ppStringRecorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.vals...)
}

func (r *ppStringRecorder) contains(s string) bool {
	for _, v := range r.list() {
		if v == s {
			return true
		}
	}
	return false
}

func (r *ppStringRecorder) count(s string) int {
	n := 0
	for _, v := range r.list() {
		if v == s {
			n++
		}
	}
	return n
}

// ppNoEnvBaseURL clears the env vars getBaseURL would load (baseURL: undefined).
func ppNoEnvBaseURL(t *testing.T) {
	t.Helper()
	for _, k := range []string{"BETTER_AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL", "PUBLIC_BETTER_AUTH_URL",
		"NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL", "BETTER_AUTH_TRUSTED_ORIGINS"} {
		t.Setenv(k, "")
	}
}

// ppSignUpTestUser creates the getTestInstance test user and returns its cookie headers.
func ppSignUpTestUser(t *testing.T, a *Auth) http.Header {
	t.Helper()
	res, err := a.API.SignUpEmail(t.Context(), SignUpEmailInput{Email: "test@test.com", Password: "test123456", Name: "test user"}, nil)
	if err != nil {
		t.Fatalf("sign-up: %v", err)
	}
	h := http.Header{}
	h.Set("Cookie", ppCookieHeader(res.Headers))
	return h
}
