package betterauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
)

const testSecret = "test-secret-that-is-long-enough-for-tests-1234567890"

type testEnv struct {
	t      *testing.T
	auth   *Auth
	server *httptest.Server
	db     *memory.DB
	mu     sync.Mutex
	emails []EmailData
}

func (e *testEnv) lastEmail() EmailData {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.emails) == 0 {
		e.t.Fatal("no email captured")
	}
	return e.emails[len(e.emails)-1]
}

// newTestEnv builds an Auth instance mounted on an httptest server. mutate may adjust the
// config; BaseURL is set to the server URL.
func newTestEnv(t *testing.T, mutate func(c *Config)) *testEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	env := &testEnv{t: t, db: memory.NewDB()}
	mux := http.NewServeMux()
	env.server = httptest.NewServer(mux)
	t.Cleanup(env.server.Close)
	cfg := Config{
		BaseURL:          env.server.URL,
		Secret:           testSecret,
		Database:         memory.New(env.db),
		EmailAndPassword: &EmailAndPasswordConfig{Enabled: true},
		Logger:           NopLogger{},
		Advanced:         &AdvancedConfig{DisableOriginCheck: Bool(false)},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env.auth = a
	mux.Handle("/api/auth/", a.Handler())
	return env
}

type testClient struct {
	env    *testEnv
	jar    *cookiejar.Jar
	client *http.Client
	origin string
}

func (e *testEnv) client() *testClient {
	jar, _ := cookiejar.New(nil)
	return &testClient{env: e, jar: jar, origin: e.server.URL,
		client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type testResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *testResponse) JSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("decode %q: %v", r.Body, err)
	}
	return m
}

func (r *testResponse) cookie(name string) (string, bool) {
	for _, sc := range r.Header.Values("Set-Cookie") {
		n, v, _ := ParseSetCookie(sc)
		if n == name {
			return v, true
		}
	}
	return "", false
}

func (c *testClient) do(method, path string, body any, mutate ...func(*http.Request)) *testResponse {
	c.env.t.Helper()
	var r io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			r = strings.NewReader(b)
		default:
			raw, _ := json.Marshal(body)
			r = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequest(method, c.env.server.URL+"/api/auth"+path, r)
	if err != nil {
		c.env.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	for _, m := range mutate {
		m(req)
	}
	res, err := c.client.Do(req)
	if err != nil {
		c.env.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &testResponse{Status: res.StatusCode, Header: res.Header, Body: b}
}

func (c *testClient) post(path string, body any, mutate ...func(*http.Request)) *testResponse {
	return c.do("POST", path, body, mutate...)
}

func (c *testClient) get(path string, mutate ...func(*http.Request)) *testResponse {
	return c.do("GET", path, nil, mutate...)
}

func (c *testClient) cookieValue(name string) string {
	u, _ := url.Parse(c.env.server.URL)
	for _, ck := range c.jar.Cookies(u) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

func (c *testClient) signUp(email, password, name string) *testResponse {
	c.env.t.Helper()
	res := c.post("/sign-up/email", map[string]any{"email": email, "password": password, "name": name})
	if res.Status != 200 {
		c.env.t.Fatalf("sign-up failed: %d %s", res.Status, res.Body)
	}
	return res
}

func (c *testClient) session() map[string]any {
	c.env.t.Helper()
	res := c.get("/get-session")
	if res.Status != 200 {
		c.env.t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if string(res.Body) == "null" {
		return nil
	}
	return res.JSON(c.env.t)
}

func expectError(t *testing.T, res *testResponse, status int, code string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("expected %d, got %d: %s", status, res.Status, res.Body)
	}
	if code == "" {
		return
	}
	m := res.JSON(t)
	if m["code"] != code {
		t.Fatalf("expected code %s, got %v (%s)", code, m["code"], res.Body)
	}
}
