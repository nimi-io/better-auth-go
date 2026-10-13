package anonymous

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// A small port of test-utils/test-instance.ts: an Auth instance mounted on an httptest
// server, a test user and helpers emulating the TS client (headers objects / cookie setters).

const testSecret = "better-auth-secret-that-is-long-enough-for-validation-test"

type testUser struct {
	Email, Password, Name string
}

type instanceOpts struct {
	testUser        testUser
	disableTestUser bool
}

type env struct {
	t        *testing.T
	auth     *betterauth.Auth
	server   *httptest.Server
	db       *memory.DB
	testUser testUser
}

func newEnv(t *testing.T, mutate func(c *betterauth.Config), io instanceOpts) *env {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	e := &env{t: t, db: memory.NewDB()}
	mux := http.NewServeMux()
	e.server = httptest.NewServer(mux)
	t.Cleanup(e.server.Close)
	cfg := betterauth.Config{
		BaseURL:  e.server.URL,
		Secret:   testSecret,
		Database: memory.New(e.db),
		SocialProviders: []oauth2.Provider{
			github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
			google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
		},
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Logger:           betterauth.NopLogger{},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("betterauth.New: %v", err)
	}
	e.auth = a
	mux.Handle("/api/auth/", a.Handler())
	e.testUser = testUser{Email: "test@test.com", Password: "test123456", Name: "test user"}
	if io.testUser.Name != "" {
		e.testUser.Name = io.testUser.Name
	}
	if io.testUser.Email != "" {
		e.testUser.Email = io.testUser.Email
	}
	if !io.disableTestUser {
		res := e.post("/sign-up/email", map[string]any{"email": e.testUser.Email, "password": e.testUser.Password, "name": e.testUser.Name}, nil)
		if res.Status != 200 {
			t.Fatalf("create test user: %d %s", res.Status, res.Body)
		}
	}
	return e
}

// jar is a TS `Headers` object carrying cookies (cookieSetter / sessionSetter).
type jar struct {
	cookies map[string]string
	order   []string
	extra   http.Header
}

func newJar() *jar { return &jar{cookies: map[string]string{}, extra: http.Header{}} }

func (j *jar) apply(setCookies []string) {
	for _, h := range setCookies {
		for _, sc := range betterauth.SplitSetCookieHeader(h) {
			name, _, attrs := betterauth.ParseSetCookie(sc)
			if name == "" {
				continue
			}
			nv, _, _ := strings.Cut(sc, ";")
			_, value, _ := strings.Cut(strings.TrimSpace(nv), "=")
			if ma, ok := attrs["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) {
				delete(j.cookies, name)
				continue
			}
			if _, ok := j.cookies[name]; !ok {
				j.order = append(j.order, name)
			}
			j.cookies[name] = value
		}
	}
}

func (j *jar) header() http.Header {
	h := j.extra.Clone()
	var parts []string
	for _, n := range j.order {
		if v, ok := j.cookies[n]; ok {
			parts = append(parts, n+"="+v)
		}
	}
	if len(parts) > 0 {
		h.Set("Cookie", strings.Join(parts, "; "))
	}
	return h
}

func (j *jar) clone() *jar {
	c := newJar()
	for _, n := range j.order {
		if v, ok := j.cookies[n]; ok {
			c.order = append(c.order, n)
			c.cookies[n] = v
		}
	}
	c.extra = j.extra.Clone()
	return c
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

func (r *response) code(t *testing.T) string {
	t.Helper()
	if len(r.Body) == 0 {
		return ""
	}
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	s, _ := m["code"].(string)
	return s
}

func (r *response) message() string {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	s, _ := m["message"].(string)
	return s
}

func (r *response) data(t *testing.T) map[string]any {
	t.Helper()
	if r.Status != 200 {
		t.Fatalf("expected 200, got %d: %s", r.Status, r.Body)
	}
	return r.json(t)
}

// do sends a request; j (optional) supplies cookies and receives Set-Cookie (cookieSetter).
func (e *env) do(method, path string, body any, j *jar, query url.Values) *response {
	e.t.Helper()
	return e.doTo(method, path, body, j, j, query)
}

// doTo sends cookies from j and applies Set-Cookie to capture (onSuccess: cookieSetter(capture)).
func (e *env) doTo(method, path string, body any, j, capture *jar, query url.Values) *response {
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", e.server.URL)
	if j != nil {
		for k, vs := range j.header() {
			req.Header[k] = vs
		}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if capture != nil {
		capture.apply(res.Header.Values("Set-Cookie"))
	}
	return &response{Status: res.StatusCode, Header: res.Header, Body: b}
}

func (e *env) post(path string, body any, j *jar) *response {
	e.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	return e.do("POST", path, body, j, nil)
}

func (e *env) get(path string, query url.Values, j *jar) *response {
	e.t.Helper()
	return e.do("GET", path, nil, j, query)
}

// signIn signs in with email/password and returns the cookie headers (signInWithUser).
func (e *env) signIn(email, password string) (*jar, map[string]any) {
	e.t.Helper()
	j := newJar()
	res := e.post("/sign-in/email", map[string]any{"email": email, "password": password}, j)
	if res.Status != 200 {
		e.t.Fatalf("sign-in %s: %d %s", email, res.Status, res.Body)
	}
	return j, res.json(e.t)
}

func (e *env) signInTestUser() (*jar, map[string]any) {
	e.t.Helper()
	j, res := e.signIn(e.testUser.Email, e.testUser.Password)
	return j, res["user"].(map[string]any)
}

// signUp signs up and returns the response; j (optional) receives cookies.
func (e *env) signUp(email, password, name string, j *jar) map[string]any {
	e.t.Helper()
	res := e.post("/sign-up/email", map[string]any{"email": email, "password": password, "name": name}, j)
	if res.Status != 200 {
		e.t.Fatalf("sign-up %s: %d %s", email, res.Status, res.Body)
	}
	return res.json(e.t)
}

// call invokes an endpoint directly (auth.api.<key>).
func (e *env) call(key string, body any, query map[string]any, headers http.Header) (map[string]any, error) {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), key, betterauth.CallInput{Body: body, Query: query, Headers: headers})
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		e.t.Fatalf("decode %s: %v", key, err)
	}
	return m, nil
}

func (e *env) mustCall(key string, body any, query map[string]any, headers http.Header) map[string]any {
	e.t.Helper()
	m, err := e.call(key, body, query, headers)
	if err != nil {
		e.t.Fatalf("%s: %v", key, err)
	}
	return m
}

func (e *env) findUser(id string) *betterauth.User {
	e.t.Helper()
	u, err := e.auth.Context().InternalAdapter.FindUserByID(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) updateRaw(model string, where []adapter.Where, data adapter.Record) {
	e.t.Helper()
	if _, err := e.auth.Context().Adapter.UpdateMany(context.Background(), model, where, data); err != nil {
		e.t.Fatal(err)
	}
}

func expectStatus(t *testing.T, r *response, status int, code string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected %d, got %d: %s", status, r.Status, r.Body)
	}
	if code != "" && r.code(t) != code {
		t.Fatalf("expected code %s, got %s", code, r.Body)
	}
}

func users(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	list, _ := m["users"].([]any)
	out := make([]map[string]any, len(list))
	for i, u := range list {
		out[i] = u.(map[string]any)
	}
	return out
}

func q(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func googleProvider(clientID, secret string) oauth2.Provider {
	return google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: clientID, ClientSecret: secret}})
}
