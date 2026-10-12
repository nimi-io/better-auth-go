package betterauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"
)

// Helpers mirroring packages/better-auth/src/test-utils/test-instance.ts for the
// email-verification / update-user ports.

const puTestHashPrefix = "$test$sha256$"

// puTestPassword mirrors the fast testPassword hasher of getTestInstance.
func puTestPassword() *PasswordConfig {
	h := func(pw string) string {
		sum := sha256.Sum256([]byte(norm.NFKC.String(pw)))
		return puTestHashPrefix + hex.EncodeToString(sum[:])
	}
	return &PasswordConfig{
		Hash:   func(pw string) (string, error) { return h(pw), nil },
		Verify: func(hash, pw string) (bool, error) { return hash == h(pw), nil },
	}
}

type puUser struct {
	Email, Password, Name string
	Image                 string
}

type puOpts struct {
	DisableTestUser bool
	TestUser        *puUser
}

type puInst struct {
	t        *testing.T
	env      *testEnv
	auth     *Auth
	testUser puUser
	http     *http.Client
}

// puInstance mirrors getTestInstance: rate limit disabled, emailAndPassword enabled, fast
// password hashing (unless overridden), and a test user signed up via auth.api.signUpEmail.
func puInstance(t *testing.T, mutate func(c *Config), o puOpts) *puInst {
	t.Helper()
	env := newTestEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(false)}
		if mutate != nil {
			mutate(c)
		}
		if c.EmailAndPassword == nil {
			c.EmailAndPassword = &EmailAndPasswordConfig{}
		}
		c.EmailAndPassword.Enabled = true
		if c.EmailAndPassword.Password == nil {
			c.EmailAndPassword.Password = puTestPassword()
		}
	})
	p := &puInst{t: t, env: env, auth: env.auth, testUser: puUser{Email: "test@test.com", Password: "test123456", Name: "test user"},
		http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if o.TestUser != nil {
		if o.TestUser.Email != "" {
			p.testUser.Email = o.TestUser.Email
		}
		if o.TestUser.Password != "" {
			p.testUser.Password = o.TestUser.Password
		}
		if o.TestUser.Name != "" {
			p.testUser.Name = o.TestUser.Name
		}
		p.testUser.Image = o.TestUser.Image
	}
	if !o.DisableTestUser {
		_, err := p.auth.API.SignUpEmail(context.Background(), SignUpEmailInput{Name: p.testUser.Name, Email: p.testUser.Email,
			Password: p.testUser.Password, Image: p.testUser.Image}, nil)
		if err != nil {
			t.Fatalf("create test user: %v", err)
		}
	}
	return p
}

// puMerge mirrors customFetchImpl: the runWithUser headers overlaid with explicit headers.
func puMerge(hs ...http.Header) http.Header {
	out := http.Header{}
	for _, h := range hs {
		for k, v := range h {
			out[k] = append([]string(nil), v...)
		}
	}
	return out
}

// do performs a request with exactly the given headers (no cookie jar), like the
// upstream client with customFetchImpl.
func (p *puInst) do(method, path string, body any, headers http.Header) *testResponse {
	p.t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, p.env.server.URL+"/api/auth"+path, r)
	if err != nil {
		p.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", p.env.server.URL)
	for k, v := range headers {
		req.Header[k] = append([]string(nil), v...)
	}
	res, err := p.http.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &testResponse{Status: res.StatusCode, Header: res.Header, Body: b}
}

func (p *puInst) post(path string, body any, hs ...http.Header) *testResponse {
	p.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	return p.do("POST", path, body, puMerge(hs...))
}

func (p *puInst) get(path string, hs ...http.Header) *testResponse {
	p.t.Helper()
	return p.do("GET", path, nil, puMerge(hs...))
}

// getSession returns the decoded session or nil (data null).
func (p *puInst) getSession(hs ...http.Header) map[string]any {
	p.t.Helper()
	res := p.get("/get-session", hs...)
	if res.Status != 200 {
		p.t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if strings.TrimSpace(string(res.Body)) == "null" {
		return nil
	}
	return res.JSON(p.t)
}

func (p *puInst) verifyEmail(query url.Values, hs ...http.Header) *testResponse {
	p.t.Helper()
	return p.get("/verify-email?"+query.Encode(), hs...)
}

func (p *puInst) signUp(email, password, name string, hs ...http.Header) *testResponse {
	p.t.Helper()
	return p.post("/sign-up/email", map[string]any{"email": email, "password": password, "name": name}, hs...)
}

func (p *puInst) signIn(email, password string, hs ...http.Header) *testResponse {
	p.t.Helper()
	return p.post("/sign-in/email", map[string]any{"email": email, "password": password}, hs...)
}

// signInWithUser mirrors signInWithUser: headers carry only the session_token cookie.
func (p *puInst) signInWithUser(email, password string) (http.Header, map[string]any) {
	p.t.Helper()
	headers := http.Header{}
	res := p.signIn(email, password)
	var data map[string]any
	if res.Status == 200 {
		puSessionSetter(headers, res)
		data = res.JSON(p.t)
	}
	return headers, data
}

func (p *puInst) signInWithTestUser() (http.Header, map[string]any) {
	p.t.Helper()
	return p.signInWithUser(p.testUser.Email, p.testUser.Password)
}

func (p *puInst) ctx() context.Context { return context.Background() }

// puSessionSetter mirrors sessionSetter: copies only better-auth.session_token.
func puSessionSetter(h http.Header, res *testResponse) {
	if len(res.Header.Values("Set-Cookie")) == 0 {
		return
	}
	v, ok := res.cookie("better-auth.session_token")
	if !ok {
		v = "undefined"
	}
	h.Set("Cookie", "better-auth.session_token="+v)
}

// puCookieSetter mirrors setCookieToHeader / applySetCookies: merges every Set-Cookie into
// the cookie header.
func puCookieSetter(h http.Header, res *testResponse) {
	scs := res.Header.Values("Set-Cookie")
	if len(scs) == 0 {
		return
	}
	type kv struct{ k, v string }
	var order []kv
	idx := map[string]int{}
	for _, part := range strings.Split(h.Get("Cookie"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if dv, err := url.QueryUnescape(strings.ReplaceAll(v, "+", "%2B")); err == nil {
			v = dv
		}
		if i, ok := idx[k]; ok {
			order[i].v = v
		} else {
			idx[k] = len(order)
			order = append(order, kv{k, v})
		}
	}
	for _, sc := range scs {
		k, v, _ := ParseSetCookie(sc)
		if i, ok := idx[k]; ok {
			order[i].v = v
		} else {
			idx[k] = len(order)
			order = append(order, kv{k, v})
		}
	}
	parts := make([]string, 0, len(order))
	for _, e := range order {
		parts = append(parts, e.k+"="+EncodeURIComponent(e.v))
	}
	h.Set("Cookie", strings.Join(parts, "; "))
}

func puGet(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

// puStore mirrors the Map-backed secondaryStorage of the upstream tests (TTL ignored).
type puStore struct {
	mu       sync.Mutex
	data     map[string]string
	writeLog []string
}

func newPuStore() *puStore { return &puStore{data: map[string]string{}} }

func (s *puStore) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok, nil
}

func (s *puStore) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeLog = append(s.writeLog, key)
	s.data[key] = value
	return nil
}

func (s *puStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *puStore) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	delete(s.data, key)
	return v, ok, nil
}

func (s *puStore) Increment(_ context.Context, key string, _ time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, _ := strconv.ParseInt(s.data[key], 10, 64)
	n++
	s.data[key] = strconv.FormatInt(n, 10)
	return n, nil
}

func (s *puStore) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.data))
	for k := range s.data {
		out = append(out, k)
	}
	return out
}

func (s *puStore) get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok
}

func (s *puStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}

func (s *puStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string]string{}
	s.writeLog = nil
}

func (s *puStore) resetLog() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeLog = nil
}

func (s *puStore) writes(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, k := range s.writeLog {
		if k == key {
			n++
		}
	}
	return n
}
