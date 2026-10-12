package betterauth

// Port of better-auth/src/api/routes/session-api.test.ts (v1.7.7).
//
// There is no fake clock in the Go port, so "advance time by d" is emulated in two ways:
//   - for database-backed session state, every stored session timestamp is shifted back by
//     d (psShift), which is equivalent to the wall clock moving forward by d;
//   - for state embedded in signed cookies (cookie cache exp), the relevant window is
//     configured so that a short real sleep crosses it (documented per test).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const (
	psEmail    = "test@test.com"
	psPassword = "test123456"
	psName     = "test user"
)

// ---- adapter spy (vi.spyOn(ctx.adapter, "findOne") / internalAdapter.updateSession) ----

type psSpy struct {
	mu         sync.Mutex
	findOne    int
	sessUpdate int
	sessDelete int
	raw        adapter.Adapter
}

func (s *psSpy) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findOne, s.sessUpdate, s.sessDelete = 0, 0, 0
}

func (s *psSpy) get() (findOne, sessUpdate, sessDelete int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findOne, s.sessUpdate, s.sessDelete
}

func (s *psSpy) findOneCalls() int { f, _, _ := s.get(); return f }

type psSpyAdapter struct {
	adapter.Adapter
	spy *psSpy
}

func (a *psSpyAdapter) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	a.spy.mu.Lock()
	a.spy.findOne++
	a.spy.mu.Unlock()
	rec, err := a.Adapter.FindOne(ctx, in)
	if len(in.Select) == 0 {
		a.nullFill(in.Model, rec)
	}
	return rec, err
}

func (a *psSpyAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	recs, err := a.Adapter.FindMany(ctx, in)
	for _, r := range recs {
		if len(in.Select) == 0 {
			a.nullFill(in.Model, r)
		}
	}
	return recs, err
}

func (a *psSpyAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	rec, err := a.Adapter.Create(ctx, in)
	if len(in.Select) == 0 {
		a.nullFill(in.Model, rec)
	}
	return rec, err
}

// nullFill emulates upstream's default test database (sqlite): columns that were never
// written read back as NULL instead of being absent (upstream's memoryAdapter, like the Go
// one, omits them). Only whole-row reads are filled; joined rows included.
func (a *psSpyAdapter) nullFill(model string, rec adapter.Record) {
	if rec == nil {
		return
	}
	t := a.Adapter.Schema().Table(model)
	if t == nil {
		return
	}
	for _, f := range t.Fields {
		if _, ok := rec[f.Name]; !ok {
			rec[f.Name] = nil
		}
	}
	for k, v := range rec {
		switch j := v.(type) {
		case adapter.Record:
			a.nullFill(k, j)
		case []adapter.Record:
			for _, r := range j {
				a.nullFill(k, r)
			}
		}
	}
}

func (a *psSpyAdapter) Update(ctx context.Context, model string, where []adapter.Where, upd adapter.Record) (adapter.Record, error) {
	if model == "session" {
		a.spy.mu.Lock()
		a.spy.sessUpdate++
		a.spy.mu.Unlock()
	}
	return a.Adapter.Update(ctx, model, where, upd)
}

func (a *psSpyAdapter) Delete(ctx context.Context, model string, where []adapter.Where) error {
	if model == "session" {
		a.spy.mu.Lock()
		a.spy.sessDelete++
		a.spy.mu.Unlock()
	}
	return a.Adapter.Delete(ctx, model, where)
}

func (a *psSpyAdapter) DeleteMany(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	if model == "session" {
		a.spy.mu.Lock()
		a.spy.sessDelete++
		a.spy.mu.Unlock()
	}
	return a.Adapter.DeleteMany(ctx, model, where)
}

// ---- secondary storage mirroring the upstream Map-backed store ----

type psMapStore struct {
	mu sync.Mutex
	m  map[string]string
}

func psNewMapStore() *psMapStore { return &psMapStore{m: map[string]string{}} }

func (s *psMapStore) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	return v, ok, nil
}

func (s *psMapStore) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}

func (s *psMapStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *psMapStore) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	delete(s.m, key)
	return v, ok, nil
}

func (s *psMapStore) Increment(_ context.Context, key string, _ time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	fmt.Sscan(s.m[key], &n)
	n++
	s.m[key] = fmt.Sprint(n)
	return n, nil
}

func (s *psMapStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func (s *psMapStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = map[string]string{}
}

// ---- test instance (getTestInstance) ----

type psInst struct {
	t   *testing.T
	env *testEnv
	spy *psSpy
}

func psFastPassword() *PasswordConfig {
	h := func(p string) (string, error) {
		sum := sha256.Sum256([]byte(p))
		return "$test$sha256$" + hex.EncodeToString(sum[:]), nil
	}
	return &PasswordConfig{Hash: h, Verify: func(hash, p string) (bool, error) {
		x, _ := h(p)
		return x == hash, nil
	}}
}

// psNew mirrors getTestInstance: email+password enabled, a test user created through
// sign-up, and an adapter spy whose counters start after setup.
func psNew(t *testing.T, mutate func(c *Config)) *psInst {
	t.Helper()
	spy := &psSpy{}
	env := newTestEnv(t, func(c *Config) {
		c.EmailAndPassword.Password = psFastPassword()
		inner := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			ad, err := inner(o)
			if err != nil {
				return nil, err
			}
			spy.raw = ad
			return &psSpyAdapter{Adapter: ad, spy: spy}, nil
		}
		if mutate != nil {
			mutate(c)
		}
	})
	p := &psInst{t: t, env: env, spy: spy}
	if _, err := env.auth.API.SignUpEmail(context.Background(), SignUpEmailInput{Email: psEmail, Password: psPassword, Name: psName}, http.Header{}); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	spy.reset()
	return p
}

func (p *psInst) ctx() *AuthContext { return p.env.auth.Context() }

func (p *psInst) rawAdapter() adapter.Adapter {
	if p.spy.raw != nil {
		return p.spy.raw
	}
	return p.ctx().Adapter
}

// psShift emulates the clock advancing by d by moving every stored session timestamp back.
func (p *psInst) shift(d time.Duration) {
	p.t.Helper()
	ad := p.rawAdapter()
	rows, err := ad.FindMany(context.Background(), adapter.FindManyInput{Model: "session"})
	if err != nil {
		p.t.Fatal(err)
	}
	for _, r := range rows {
		s := SessionFromRecord(r)
		if _, err := ad.Update(context.Background(), "session", []adapter.Where{{Field: "id", Value: s.ID}}, adapter.Record{
			"expiresAt": s.ExpiresAt.Add(-d), "createdAt": s.CreatedAt.Add(-d), "updatedAt": s.UpdatedAt.Add(-d),
		}); err != nil {
			p.t.Fatal(err)
		}
	}
}

func (p *psInst) tryDo(method, path, cookie string, body any, mut ...func(*http.Request)) (*testResponse, error) {
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, p.env.server.URL+"/api/auth"+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", p.env.server.URL)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for _, m := range mut {
		m(req)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &testResponse{Status: res.StatusCode, Header: res.Header, Body: b}, nil
}

func (p *psInst) do(method, path, cookie string, body any, mut ...func(*http.Request)) *testResponse {
	p.t.Helper()
	res, err := p.tryDo(method, path, cookie, body, mut...)
	if err != nil {
		p.t.Fatal(err)
	}
	return res
}

// signIn signs the test user in (client.signIn.email) and applies cookies to jar.
func (p *psInst) signIn(jar *psJar, extra map[string]any) *testResponse {
	p.t.Helper()
	body := map[string]any{"email": psEmail, "password": psPassword}
	for k, v := range extra {
		body[k] = v
	}
	res := p.do("POST", "/sign-in/email", "", body)
	if res.Status != 200 {
		p.t.Fatalf("sign-in failed: %d %s", res.Status, res.Body)
	}
	if jar != nil {
		jar.apply(res)
	}
	return res
}

// getSession performs client.getSession with the given cookie header and query string.
// It returns the response and the decoded body (nil for a null body).
func (p *psInst) getSession(cookie, query string) (*testResponse, map[string]any) {
	p.t.Helper()
	path := "/get-session"
	if query != "" {
		path += "?" + query
	}
	res := p.do("GET", path, cookie, nil)
	return res, psBody(p.t, res)
}

func psBody(t *testing.T, res *testResponse) map[string]any {
	t.Helper()
	if res.Status != 200 {
		return nil
	}
	if strings.TrimSpace(string(res.Body)) == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(res.Body, &m); err != nil {
		t.Fatalf("decode %q: %v", res.Body, err)
	}
	return m
}

// ---- cookie header model (Headers + cookieSetter / setCookieToHeader) ----

type psJar struct {
	order []string
	vals  map[string]string
}

func psNewJar() *psJar { return &psJar{vals: map[string]string{}} }

func (j *psJar) set(name, value string) {
	if _, ok := j.vals[name]; !ok {
		j.order = append(j.order, name)
	}
	j.vals[name] = value
}

func (j *psJar) apply(res *testResponse) {
	for _, sc := range res.Header.Values("Set-Cookie") {
		n, v, _ := ParseSetCookie(sc)
		j.set(n, v)
	}
}

func (j *psJar) get(name string) (string, bool) {
	v, ok := j.vals[name]
	return v, ok
}

func (j *psJar) header() string {
	parts := make([]string, 0, len(j.order))
	for _, n := range j.order {
		parts = append(parts, n+"="+EncodeURIComponent(j.vals[n]))
	}
	return strings.Join(parts, "; ")
}

func (j *psJar) clone() *psJar {
	c := psNewJar()
	for _, n := range j.order {
		c.set(n, j.vals[n])
	}
	return c
}

type psSetCookie struct {
	value string
	attrs map[string]string
}

// psSetCookies parses Set-Cookie headers by name (last one wins, like parseSetCookieHeader).
func psSetCookies(h http.Header) map[string]psSetCookie {
	out := map[string]psSetCookie{}
	for _, sc := range h.Values("Set-Cookie") {
		n, v, attrs := ParseSetCookie(sc)
		out[n] = psSetCookie{value: v, attrs: attrs}
	}
	return out
}

func psMaxAge(h http.Header, name string) (int, bool) {
	c, ok := psSetCookies(h)[name]
	if !ok {
		return 0, false
	}
	v, ok := c.attrs["max-age"]
	if !ok {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscan(v, &n); err != nil {
		return 0, false
	}
	return n, true
}

func psMap(t *testing.T, v any, path string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: expected object, got %T (%v)", path, v, v)
	}
	return m
}

func psTime(t *testing.T, v any) time.Time {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("expected date string, got %T (%v)", v, v)
	}
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse date %q: %v", s, err)
	}
	return tm
}

func psDur(d time.Duration) *time.Duration { return &d }

func psSessionCfg(c *Config) *SessionConfig {
	if c.Session == nil {
		c.Session = &SessionConfig{}
	}
	return c.Session
}

func psSensitiveField() db.Field {
	return db.Field{Name: "sensitiveData", Type: db.TypeString, Returned: Bool(false), DefaultValue: "sensitive-data"}
}

func psFreshPlugin(id, key, path string) *Plugin {
	return &Plugin{ID: id, Endpoints: []*Endpoint{{
		Key: key, Path: path, Methods: []string{"GET"}, Use: []Middleware{FreshSessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) { return jsonx.O("status", true), nil },
	}}}
}

// psCallSession calls auth.api.getSession with a raw cookie header.
func (p *psInst) apiGetSession(cookie string, method string) (*CallResult, error) {
	h := http.Header{}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return p.env.auth.API.Call(context.Background(), "getSession", CallInput{Headers: h, Method: method})
}

func (p *psInst) apiSignIn() *CallResult {
	p.t.Helper()
	res, err := p.env.auth.API.SignInEmail(context.Background(), psEmail, psPassword, nil, http.Header{})
	if err != nil {
		p.t.Fatalf("signInEmail: %v", err)
	}
	return res
}

func psSessionResult(t *testing.T, res *CallResult) *SessionResult {
	t.Helper()
	sr, _ := res.Data.(*SessionResult)
	return sr
}

// =====================================================================================
// describe("session")
// =====================================================================================

func TestPortSessionSetsCookiesOnSignIn(t *testing.T) {
	for _, name := range []string{"should set cookies correctly on sign in", "should set cookies correctly on sign in after changing config"} {
		t.Run(name, func(t *testing.T) {
			p := psNew(t, nil)
			jar := psNewJar()
			res := p.signIn(jar, nil)
			c, ok := psSetCookies(res.Header)["better-auth.session_token"]
			if !ok || c.value == "" {
				t.Fatalf("missing session_token cookie: %v", res.Header.Values("Set-Cookie"))
			}
			if c.attrs["max-age"] != fmt.Sprint(60*60*24*7) {
				t.Fatalf("max-age = %q", c.attrs["max-age"])
			}
			if c.attrs["path"] != "/" {
				t.Fatalf("path = %q", c.attrs["path"])
			}
			if strings.ToLower(c.attrs["samesite"]) != "lax" {
				t.Fatalf("samesite = %q", c.attrs["samesite"])
			}
			if _, ok := c.attrs["httponly"]; !ok {
				t.Fatalf("httponly missing: %v", c.attrs)
			}
			_, data := p.getSession(jar.header(), "")
			if data == nil {
				t.Fatal("expected session")
			}
			exp := psTime(t, psMap(t, data["session"], "session")["expiresAt"])
			if !exp.After(time.Now().Add(6 * 24 * time.Hour)) {
				t.Fatalf("expiresAt %v not > now+6d", exp)
			}
		})
	}
}

func TestPortSessionReturnsNullWhenNotAuthenticated(t *testing.T) {
	p := psNew(t, nil)
	res, data := p.getSession("", "")
	if res.Status != 200 || data != nil || strings.TrimSpace(string(res.Body)) != "null" {
		t.Fatalf("expected null, got %d %s", res.Status, res.Body)
	}
}

func TestPortSessionRequiresFreshSessionByCreationTime(t *testing.T) {
	p := psNew(t, func(c *Config) {
		psSessionCfg(c).FreshAge = psDur(60 * time.Second)
		c.Plugins = append(c.Plugins, psFreshPlugin("fresh-session-test", "freshSessionCheck", "/fresh-session-check"))
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	cur, err := p.env.auth.API.GetSession(context.Background(), http.Header{"Cookie": {jar.header()}})
	if err != nil || cur == nil {
		t.Fatalf("getSession: %v %v", cur, err)
	}
	now := time.Now()
	if _, err := p.rawAdapter().Update(context.Background(), "session", []adapter.Where{{Field: "id", Value: cur.Session.ID}},
		adapter.Record{"createdAt": now.Add(-5 * time.Minute), "updatedAt": now}); err != nil {
		t.Fatal(err)
	}
	res := p.do("GET", "/fresh-session-check", jar.header(), nil)
	// upstream also asserts statusText "FORBIDDEN"; Go's net/http always writes the
	// canonical reason phrase, so only status and code are checked.
	expectError(t, res, 403, "SESSION_NOT_FRESH")
}

func TestPortSessionRequiresFreshSessionToListSessions(t *testing.T) {
	p := psNew(t, func(c *Config) { psSessionCfg(c).FreshAge = psDur(60 * time.Second) })
	jar := psNewJar()
	p.signIn(jar, nil)
	_, data := p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("expected session")
	}
	id := psMap(t, data["session"], "session")["id"]
	now := time.Now()
	if _, err := p.rawAdapter().Update(context.Background(), "session", []adapter.Where{{Field: "id", Value: id}},
		adapter.Record{"createdAt": now.Add(-5 * time.Minute), "updatedAt": now}); err != nil {
		t.Fatal(err)
	}
	res := p.do("GET", "/list-sessions", jar.header(), nil)
	expectError(t, res, 403, "SESSION_NOT_FRESH")
}

func TestPortSessionUpdatesWhenUpdateAgeReached(t *testing.T) {
	p := psNew(t, func(c *Config) {
		s := psSessionCfg(c)
		s.UpdateAge = psDur(60 * time.Second)
		s.ExpiresIn = 120 * time.Second
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	_, data := p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("No session found")
	}
	exp := psTime(t, psMap(t, data["session"], "session")["expiresAt"])
	if !exp.After(time.Now().Add(2 * 59 * time.Second)) {
		t.Fatalf("expiresAt %v not > now+118s", exp)
	}
	if !exp.Before(time.Now().Add(2 * 60 * time.Second)) {
		t.Fatalf("expiresAt %v not < now+120s", exp)
	}
	for _, sec := range []int{60, 80, 100, 121} {
		p.shift(time.Duration(sec) * time.Second) // vi.setSystemTime(now + t), cumulative
		res, data := p.getSession(jar.header(), "")
		want := 60 * 2
		if sec == 121 {
			want = 0
		}
		got, ok := psMaxAge(res.Header, "better-auth.session_token")
		if !ok || got != want {
			t.Fatalf("t=%d: session_token max-age = %v (present=%v), want %d; set-cookie=%v", sec, got, ok, want, res.Header.Values("Set-Cookie"))
		}
		if sec == 121 {
			if data != nil {
				t.Fatalf("t=121: expected null session, got %v", data)
			}
		} else {
			if data == nil {
				t.Fatalf("t=%d: expected session", sec)
			}
			e := psTime(t, psMap(t, data["session"], "session")["expiresAt"])
			if !e.After(time.Now().Add(2 * 59 * time.Second)) {
				t.Fatalf("t=%d: expiresAt %v not > now+118s", sec, e)
			}
		}
	}
}

func TestPortSessionUpdatesEveryTimeWhenUpdateAgeZero(t *testing.T) {
	p := psNew(t, func(c *Config) { psSessionCfg(c).UpdateAge = psDur(0) })
	jar := psNewJar()
	p.signIn(jar, nil)
	_, s1 := p.getSession(jar.header(), "")
	if s1 == nil {
		t.Fatal("expected session")
	}
	advance := 5 * time.Minute
	p.shift(advance)
	_, s2 := p.getSession(jar.header(), "")
	if s2 == nil {
		t.Fatal("expected session")
	}
	// In the shifted frame the first observation is 5 minutes earlier.
	e1 := psTime(t, psMap(t, s1["session"], "session")["expiresAt"]).Add(-advance)
	e2 := psTime(t, psMap(t, s2["session"], "session")["expiresAt"])
	if e1.Equal(e2) {
		t.Fatal("expiresAt was not updated")
	}
	if !e2.After(e1) {
		t.Fatalf("expiresAt %v not > %v", e2, e1)
	}
}

func TestPortSessionDontRememberMe(t *testing.T) {
	p := psNew(t, nil)
	jar := psNewJar()
	p.signIn(jar, map[string]any{"rememberMe": false})
	_, data := p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("No session found")
	}
	limit := time.Now().Add(24 * time.Hour)
	if e := psTime(t, psMap(t, data["session"], "session")["expiresAt"]); e.After(limit) {
		t.Fatalf("expiresAt %v > now+1d", e)
	}
	_, data = p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("No session found")
	}
	if e := psTime(t, psMap(t, data["session"], "session")["expiresAt"]); e.After(time.Now().Add(24 * time.Hour)) {
		t.Fatalf("session was updated: expiresAt %v > now+1d", e)
	}
}

func TestPortSessionClearsSessionOnSignOut(t *testing.T) {
	p := psNew(t, nil)
	jar := psNewJar()
	p.signIn(jar, nil)
	_, data := p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("expected session")
	}
	p.do("POST", "/sign-out", jar.header(), nil)
	// upstream: `expect(response.data)` (no matcher); the request headers were not updated
	// after sign-out, so the server-side deletion must make this null.
	res, data := p.getSession(jar.header(), "")
	if res.Status != 200 || data != nil {
		t.Fatalf("expected null session after sign out: %d %s", res.Status, res.Body)
	}
}

func TestPortSessionListSessions(t *testing.T) {
	p := psNew(t, nil)
	// The upstream shared instance already holds sessions from the test-user sign-up and
	// previous tests; sign-up created one here, so sign in once more.
	jar := psNewJar()
	p.signIn(jar, nil)
	res := p.do("GET", "/list-sessions", jar.header(), nil)
	if res.Status != 200 {
		t.Fatalf("list-sessions: %d %s", res.Status, res.Body)
	}
	var list []any
	if err := json.Unmarshal(res.Body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) <= 1 {
		t.Fatalf("expected > 1 sessions, got %d", len(list))
	}
}

func TestPortSessionRevokeSession(t *testing.T) {
	// upstream uses sessionSetter (bearer plugin); cookies carry the same session token.
	p := psNew(t, nil)
	h1, h2 := psNewJar(), psNewJar()
	p.signIn(h1, nil)
	p.signIn(h2, nil)
	_, s := p.getSession(h1.header(), "")
	if s == nil {
		t.Fatal("expected session")
	}
	token, _ := psMap(t, s["session"], "session")["token"].(string)
	p.do("POST", "/revoke-session", h1.header(), map[string]any{"token": token})
	if _, ns := p.getSession(h1.header(), ""); ns != nil {
		t.Fatalf("expected null after revoke, got %v", ns)
	}
	res := p.do("POST", "/revoke-sessions", h2.header(), map[string]any{})
	m := psBody(t, res)
	if m == nil || m["status"] != true {
		t.Fatalf("revoke-sessions: %d %s", res.Status, res.Body)
	}
}

func TestPortSessionReturnsSessionHeaders(t *testing.T) {
	p := psNew(t, nil)
	signIn := p.apiSignIn()
	cookie := signIn.Headers.Values("Set-Cookie")[0]
	without, err := p.apiGetSession(cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	with, err := p.apiGetSession(cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	if with.Headers == nil {
		t.Fatal("expected headers")
	}
	sr := psSessionResult(t, with)
	if sr == nil || sr.User == nil || sr.Session == nil {
		t.Fatalf("expected session and user, got %#v", with.Data)
	}
	if psSessionResult(t, without) == nil {
		t.Fatal("expected session without returnHeaders")
	}
	if with.Status != 200 {
		t.Fatalf("status = %d", with.Status)
	}
	// asResponse: the HTTP handler path.
	res := p.do("GET", "/get-session", cookie, nil)
	if res.Status != 200 {
		t.Fatalf("asResponse status = %d", res.Status)
	}
}

// @see https://github.com/better-auth/better-auth/issues/9609
func TestPortSessionMaxAgeCeilingOnRefresh(t *testing.T) {
	const ceiling = 400 * 24 * 60 * 60
	p := psNew(t, func(c *Config) {
		s := psSessionCfg(c)
		s.ExpiresIn = ceiling * time.Second
		s.UpdateAge = psDur(30 * time.Second)
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	p.shift(31 * time.Second)
	res, _ := p.getSession(jar.header(), "")
	jar.apply(res)
	got, ok := psMaxAge(res.Header, "better-auth.session_token")
	if !ok {
		t.Fatalf("expected refreshed session_token cookie; set-cookie=%v", res.Header.Values("Set-Cookie"))
	}
	if got > ceiling {
		t.Fatalf("max-age %d > %d", got, ceiling)
	}
}

// =====================================================================================
// describe("session storage")
// =====================================================================================

func psStorageInstance(t *testing.T) (*psInst, *psMapStore) {
	store := psNewMapStore()
	p := psNew(t, func(c *Config) {
		c.SecondaryStorage = store
		c.RateLimit = &RateLimitConfig{Enabled: Bool(false)}
	})
	store.clear() // beforeEach
	return p, store
}

func TestPortSessionStorageStoresSession(t *testing.T) {
	p, store := psStorageInstance(t)
	if store.size() != 0 {
		t.Fatalf("store size = %d", store.size())
	}
	jar := psNewJar()
	p.signIn(jar, nil)
	if store.size() != 2 {
		t.Fatalf("store size = %d, want 2 (%v)", store.size(), store.m)
	}
	_, data := p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("expected session")
	}
	s := psMap(t, data["session"], "session")
	u := psMap(t, data["user"], "user")
	for _, k := range []string{"userId", "token", "expiresAt", "ipAddress", "userAgent"} {
		if _, ok := s[k].(string); !ok {
			t.Fatalf("session.%s: expected string, got %T (%v)", k, s[k], s[k])
		}
	}
	psTime(t, s["expiresAt"])
	if _, ok := u["id"].(string); !ok {
		t.Fatalf("user.id = %v", u["id"])
	}
	if u["name"] != psName || u["email"] != psEmail || u["emailVerified"] != false {
		t.Fatalf("user = %v", u)
	}
	if v, ok := u["image"]; !ok || v != nil {
		t.Fatalf("user.image = %v (present=%v), want null", v, ok)
	}
	psTime(t, u["createdAt"])
	psTime(t, u["updatedAt"])
}

func TestPortSessionStorageListSessions(t *testing.T) {
	p, _ := psStorageInstance(t)
	jar := psNewJar()
	p.signIn(jar, nil)
	res := p.do("GET", "/list-sessions", jar.header(), nil)
	var list []any
	if err := json.Unmarshal(res.Body, &list); err != nil || len(list) != 1 {
		t.Fatalf("list-sessions: %d %s", res.Status, res.Body)
	}
}

func TestPortSessionStorageRevokeAndList(t *testing.T) {
	p, store := psStorageInstance(t)
	jar := psNewJar()
	p.signIn(jar, nil)
	_, data := p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("expected session")
	}
	s := psMap(t, data["session"], "session")
	token, _ := s["token"].(string)
	if token == "" {
		t.Fatal("token missing")
	}
	userID, _ := s["userId"].(string)
	raw, ok, _ := store.Get(context.Background(), "active-sessions-"+userID)
	var sessions []any
	if !ok || json.Unmarshal([]byte(raw), &sessions) != nil || len(sessions) != 1 {
		t.Fatalf("active sessions = %q", raw)
	}
	res := p.do("POST", "/revoke-session", jar.header(), map[string]any{"token": token})
	if m := psBody(t, res); m == nil || m["status"] != true {
		t.Fatalf("revoke-session: %d %s", res.Status, res.Body)
	}
	list := p.do("GET", "/list-sessions", jar.header(), nil)
	if list.Status == 200 {
		t.Fatalf("expected list-sessions error (data null), got %d %s", list.Status, list.Body)
	}
	if store.size() != 0 {
		t.Fatalf("store size = %d, want 0 (%v)", store.size(), store.m)
	}
}

func TestPortSessionStorageRevokeSession(t *testing.T) {
	p, _ := psStorageInstance(t)
	jar := psNewJar()
	p.signIn(jar, nil)
	_, data := p.getSession(jar.header(), "")
	if data == nil {
		t.Fatal("expected session")
	}
	token, _ := psMap(t, data["session"], "session")["token"].(string)
	p.do("POST", "/revoke-session", jar.header(), map[string]any{"token": token})
	if _, d := p.getSession(jar.header(), ""); d != nil {
		t.Fatalf("expected null, got %v", d)
	}
}

// =====================================================================================
// describe("cookie cache") / describe("cookie cache with JWE strategy")
// =====================================================================================

// psCachedSession mirrors createCachedSession. maxAge is the cookie cache max age.
func psCachedSession(t *testing.T, strategy string, maxAge time.Duration) (*psInst, *psJar) {
	p := psNew(t, func(c *Config) {
		s := psSessionCfg(c)
		s.AdditionalFields = append(s.AdditionalFields, psSensitiveField())
		s.CookieCache = &CookieCacheConfig{Enabled: true, Strategy: strategy, MaxAge: maxAge}
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	p.spy.reset()
	return p, jar
}

func TestPortSessionCookieCache(t *testing.T) {
	for _, strategy := range []string{"compact", "jwe"} {
		t.Run(strategy+"/serves cached sessions without querying the database", func(t *testing.T) {
			p, jar := psCachedSession(t, strategy, 300*time.Second)
			_, data := p.getSession(jar.header(), "")
			if data == nil {
				t.Fatal("expected session")
			}
			if _, ok := psMap(t, data["session"], "session")["sensitiveData"]; ok {
				t.Fatal("session exposes sensitiveData")
			}
			if n := p.spy.findOneCalls(); n != 0 {
				t.Fatalf("findOne called %d times", n)
			}
		})
		t.Run(strategy+"/reads fresh user data when cookie caching is bypassed", func(t *testing.T) {
			p, jar := psCachedSession(t, strategy, 300*time.Second)
			_, cached := p.getSession(jar.header(), "")
			u := psMap(t, cached["user"], "user")
			if u["emailVerified"] != false {
				t.Fatalf("emailVerified = %v", u["emailVerified"])
			}
			if _, err := p.ctx().InternalAdapter.UpdateUser(context.Background(), u["id"].(string), adapter.Record{"emailVerified": true}); err != nil {
				t.Fatal(err)
			}
			_, data := p.getSession(jar.header(), "disableCookieCache=true")
			if data == nil || psMap(t, data["user"], "user")["emailVerified"] != true {
				t.Fatalf("expected fresh user, got %v", data)
			}
			if n := p.spy.findOneCalls(); n != 1 {
				t.Fatalf("findOne called %d times, want 1", n)
			}
		})
		t.Run(strategy+"/refreshes expired cache and reuses the replacement cookie", func(t *testing.T) {
			// upstream: maxAge 300s + advance 301s; here maxAge 2s + sleep 2.1s.
			p, jar := psCachedSession(t, strategy, 2*time.Second)
			p.getSession(jar.header(), "")
			if n := p.spy.findOneCalls(); n != 0 {
				t.Fatalf("findOne called %d times before expiry", n)
			}
			time.Sleep(2100 * time.Millisecond)
			res, refreshed := p.getSession(jar.header(), "")
			jar.apply(res)
			if refreshed == nil {
				t.Fatal("expected refreshed session")
			}
			if n := p.spy.findOneCalls(); n != 1 {
				t.Fatalf("findOne called %d times, want 1", n)
			}
			_, cached := p.getSession(jar.header(), "")
			if !jsonEqual(cached, refreshed) {
				t.Fatalf("cached %v != refreshed %v", cached, refreshed)
			}
			if n := p.spy.findOneCalls(); n != 1 {
				t.Fatalf("findOne called %d times after reuse, want 1", n)
			}
		})
	}
	t.Run("jwe/serves concurrent requests from the cache", func(t *testing.T) {
		p, jar := psCachedSession(t, "jwe", 300*time.Second)
		psConcurrentSessions(t, p, jar.header())
		if n := p.spy.findOneCalls(); n != 0 {
			t.Fatalf("findOne called %d times", n)
		}
	})
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func psConcurrentSessions(t *testing.T, p *psInst, cookie string) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan string, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := p.tryDo("GET", "/get-session", cookie, nil)
			if err != nil {
				errs <- err.Error()
				return
			}
			var m map[string]any
			if json.Unmarshal(res.Body, &m) != nil || m == nil {
				errs <- fmt.Sprintf("null session: %d %s", res.Status, res.Body)
				return
			}
			if u, _ := m["user"].(map[string]any); u == nil || u["email"] != psEmail {
				errs <- fmt.Sprintf("wrong user: %s", res.Body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// =====================================================================================
// describe("cookie cache with JWT strategy") — shared instance and headers
// =====================================================================================

func TestPortSessionCookieCacheJWTStrategy(t *testing.T) {
	p := psNew(t, func(c *Config) {
		s := psSessionCfg(c)
		s.AdditionalFields = append(s.AdditionalFields, psSensitiveField())
		s.CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwt"}
	})
	ctx := p.ctx()
	headers := psNewJar()

	t.Run("should cache cookies with JWT strategy", func(t *testing.T) {
		p.t = t
		p.signIn(headers, nil)
		if n := p.spy.findOneCalls(); n != 1 {
			t.Fatalf("findOne called %d times after sign-in, want 1", n)
		}
		_, data := p.getSession(headers.header(), "")
		token, ok := headers.get("better-auth.session_data")
		if !ok || token == "" {
			t.Fatal("JWT not found")
		}
		payload, err := bacrypto.VerifyJWT(token, ctx.Secret)
		if err != nil || payload == nil {
			t.Fatalf("verifyJWT: %v", err)
		}
		if data == nil {
			t.Fatal("expected session")
		}
		if _, ok := psMap(t, data["session"], "session")["sensitiveData"]; ok {
			t.Fatal("session exposes sensitiveData")
		}
		if n := p.spy.findOneCalls(); n != 1 {
			t.Fatalf("findOne called %d times, want 1 (cache hit)", n)
		}
	})

	t.Run("should not allow tampering with the cookie", func(t *testing.T) {
		p.t = t
		p.signIn(headers, nil)
		token, ok := headers.get("better-auth.session_data")
		if !ok || token == "" {
			t.Fatal("JWT not found")
		}
		payload, err := bacrypto.VerifyJWT(token, ctx.Secret)
		if err != nil {
			t.Fatal(err)
		}
		sv, _ := payload.Get("session")
		uv, _ := payload.Get("user")
		user := uv.(*jsonx.Object).Clone().Set("id", "tampered-id")
		forged, err := bacrypto.SignJWT(jsonx.O("session", sv, "user", user), "tampered-secret", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		st, ok := headers.get("better-auth.session_token")
		if !ok {
			t.Fatal("Session cookie not found")
		}
		tampered := psNewJar()
		tampered.set("better-auth.session_data", forged)
		tampered.set("better-auth.session_token", st)
		// headers.set(...) replaces the shared headers upstream.
		headers = tampered
		_, data := p.getSession(headers.header(), "")
		if data == nil {
			t.Fatal("expected DB fallback session")
		}
		u := psMap(t, data["user"], "user")
		if u["id"] == "tampered-id" || u["email"] != psEmail {
			t.Fatalf("user = %v", u)
		}
	})

	t.Run("should have max age expiry", func(t *testing.T) {
		p.t = t
		p.signIn(headers, nil)
		token, ok := headers.get("better-auth.session_data")
		if !ok || token == "" {
			t.Fatal("JWT not found")
		}
		payload, err := bacrypto.VerifyJWT(token, ctx.Secret)
		if err != nil {
			t.Fatal(err)
		}
		exp, _ := payload.Get("exp")
		if f, _ := exp.(float64); f < float64(time.Now().Unix()+299) {
			t.Fatalf("exp %v < now+299", exp)
		}
	})

	t.Run("should handle multiple concurrent requests with JWT cache", func(t *testing.T) {
		p.t = t
		h := psNewJar()
		p.signIn(h, nil)
		psConcurrentSessions(t, p, h.header())
	})
}

func TestPortSessionCookieCacheJWKS(t *testing.T) {
	for _, name := range []string{
		"should cache cookies with JWKS-backed JWT strategy",
		"should ignore a JWKS cookie cache from a different session token",
		"should not allow tampering with the cookie in JWKS mode",
		"should reject a secret-signed cookie cache and fall back to the database",
		"should verify existing cookie-cache JWTs across JWKS rotation grace period",
	} {
		t.Run(name, func(t *testing.T) {
			t.Skip("requires the jwt plugin (jwt({ sessionCookieCache: true }), getJwks/signJWT endpoints), which is not implemented in the Go port")
		})
	}
}

// =====================================================================================
// describe("cookie cache refreshCache")
// =====================================================================================

// psRefreshCacheFixture mirrors refreshCacheTest: stateful JWE cache with
// refreshCache { updateAge } (which a database disables).
func psRefreshCacheFixture(t *testing.T, updateAge time.Duration) (*psInst, *psJar) {
	p := psNew(t, func(c *Config) {
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe", MaxAge: 300 * time.Second,
			RefreshCache: &RefreshCacheConfig{Enabled: true, UpdateAge: psDur(updateAge)}}
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	p.spy.reset()
	return p, jar
}

func TestPortSessionRefreshCacheUsesCachedDataBeforeThreshold(t *testing.T) {
	p, jar := psRefreshCacheFixture(t, 60*time.Second)
	if _, d := p.getSession(jar.header(), ""); d == nil {
		t.Fatal("expected session")
	}
	if n := p.spy.findOneCalls(); n != 0 {
		t.Fatalf("findOne called %d times", n)
	}
	if _, d := p.getSession(jar.header(), ""); d == nil {
		t.Fatal("expected session")
	}
	if n := p.spy.findOneCalls(); n != 0 {
		t.Fatalf("findOne called %d times", n)
	}
}

func TestPortSessionRefreshCacheNoStatelessRefreshWithDatabase(t *testing.T) {
	// upstream: updateAge 60 + advance 241s (inside the refresh window). Here the window is
	// widened to updateAge 299s and crossed with a 1.1s sleep.
	p, jar := psRefreshCacheFixture(t, 299*time.Second)
	time.Sleep(1100 * time.Millisecond)
	res, d := p.getSession(jar.header(), "")
	jar.apply(res)
	if d == nil {
		t.Fatal("expected session")
	}
	if n := p.spy.findOneCalls(); n != 0 {
		t.Fatalf("findOne called %d times", n)
	}
	p.getSession(jar.header(), "")
	if n := p.spy.findOneCalls(); n != 0 {
		t.Fatalf("findOne called %d times", n)
	}
}

func TestPortSessionRefreshCacheDisabled(t *testing.T) {
	p := psNew(t, func(c *Config) {
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe"}
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	after := p.spy.findOneCalls()
	// upstream advances 2 minutes; the 5-minute cache is still valid either way and
	// refreshCache is disabled, so no clock change is required to exercise the path.
	p.getSession(jar.header(), "")
	if n := p.spy.findOneCalls(); n != after {
		t.Fatalf("findOne calls %d, want %d", n, after)
	}
	p.getSession(jar.header(), "")
	if n := p.spy.findOneCalls(); n != after {
		t.Fatalf("findOne calls %d, want %d", n, after)
	}
}

func TestPortSessionRefreshCacheWithoutDatabaseCookieOnly(t *testing.T) {
	p := psNew(t, func(c *Config) {
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe", RefreshCache: &RefreshCacheConfig{Enabled: true}}
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	_, first := p.getSession(jar.header(), "")
	if first == nil {
		t.Fatal("expected session")
	}
	token, _ := psMap(t, first["session"], "session")["token"].(string)
	if token != "" {
		if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
			t.Fatal(err)
		}
	}
	_, cached := p.getSession(jar.header(), "")
	if cached == nil {
		t.Fatal("expected session from cookie cache")
	}
	if psMap(t, cached["user"], "user")["email"] != psEmail {
		t.Fatalf("user = %v", cached["user"])
	}
	if psMap(t, cached["session"], "session")["token"] != token {
		t.Fatalf("token mismatch")
	}
}

// statelessRefresh builds a DB-less instance with a JWE cache whose refresh window is
// reachable after a short sleep (upstream: maxAge 300, updateAge 60, advance 241s; here
// maxAge 300, updateAge 299s, sleep 1.1s).
func psStatelessRefresh(t *testing.T, expiresIn time.Duration) *psInst {
	return psNew(t, func(c *Config) {
		c.Database = nil
		s := psSessionCfg(c)
		s.ExpiresIn = expiresIn
		s.CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe", MaxAge: 300 * time.Second,
			RefreshCache: &RefreshCacheConfig{Enabled: true, UpdateAge: psDur(299 * time.Second)}}
	})
}

// @see https://github.com/better-auth/better-auth/pull/8817
func TestPortSessionRefreshCachePreservesSessionExpiry(t *testing.T) {
	const cacheMaxAge = 300
	p := psStatelessRefresh(t, time.Hour)
	headers := psNewJar()
	p.signIn(headers, nil)
	res, first := p.getSession(headers.header(), "")
	headers.apply(res)
	if first == nil {
		t.Fatal("expected session")
	}
	fs := psMap(t, first["session"], "session")
	token, _ := fs["token"].(string)
	originalExpiresAt := psTime(t, fs["expiresAt"])
	initialData, ok := headers.get("better-auth.session_data")
	if !ok {
		t.Fatal("initial session_data missing")
	}
	if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	res, fromCache := p.getSession(headers.header(), "")
	sc := psSetCookies(res.Header)
	headers.apply(res)
	if fromCache == nil {
		t.Fatal("expected session")
	}
	data, ok := sc["better-auth.session_data"]
	if !ok {
		t.Fatalf("session_data not refreshed: %v", res.Header.Values("Set-Cookie"))
	}
	if data.value == initialData {
		t.Fatal("session_data cookie unchanged")
	}
	if _, ok := sc["better-auth.session_token"]; !ok {
		t.Fatalf("session_token not refreshed: %v", res.Header.Values("Set-Cookie"))
	}
	s := psMap(t, fromCache["session"], "session")
	if s["token"] != token {
		t.Fatalf("token = %v", s["token"])
	}
	if got := psTime(t, s["expiresAt"]); !got.Equal(originalExpiresAt) {
		t.Fatalf("expiresAt %v != original %v", got, originalExpiresAt)
	}
	if time.Until(originalExpiresAt) <= (cacheMaxAge+1)*time.Second {
		t.Fatalf("original expiry too close: %v", originalExpiresAt)
	}
}

func TestPortSessionRefreshCacheWithoutDatabaseThresholdReached(t *testing.T) {
	p := psStatelessRefresh(t, 0)
	headers := psNewJar()
	p.signIn(headers, nil)
	res, first := p.getSession(headers.header(), "")
	headers.apply(res)
	if first == nil {
		t.Fatal("expected session")
	}
	token, _ := psMap(t, first["session"], "session")["token"].(string)
	if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	res, s := p.getSession(headers.header(), "")
	headers.apply(res)
	if s == nil {
		t.Fatal("expected stateless refresh to keep the session")
	}
	if psMap(t, s["user"], "user")["email"] != psEmail {
		t.Fatalf("user = %v", s["user"])
	}
	if psMap(t, s["session"], "session")["token"] != token {
		t.Fatalf("token mismatch")
	}
}

// @see https://github.com/better-auth/better-auth/issues/8763
func TestPortSessionForwardsCookieCacheHeadersFromGetSessionFromCtx(t *testing.T) {
	p := psNew(t, func(c *Config) {
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe"}
	})
	ac := p.ctx()
	headers := psNewJar()
	p.signIn(headers, nil)
	dataName := ac.AuthCookies.SessionData.Name
	req := psNewJar()
	for _, n := range headers.order {
		if n == dataName || strings.HasPrefix(n, dataName+".") {
			continue
		}
		req.set(n, headers.vals[n])
	}
	ep := p.env.auth.endpoint("getSession")
	ec := p.env.auth.newEndpointContext(context.Background(), ep, callInput{Headers: http.Header{"Cookie": {req.header()}}, Auth: ac.clone()})
	sw, err := GetSessionFromCtx(ec, nil)
	if err != nil || sw == nil || sw.User.Email != psEmail {
		t.Fatalf("GetSessionFromCtx = %v, %v", sw, err)
	}
	forwarded := false
	for n := range psSetCookies(ec.ResponseHeaders) {
		if n == dataName || strings.HasPrefix(n, dataName+".") {
			forwarded = true
		}
	}
	if !forwarded {
		t.Fatalf("session_data not forwarded: %v", ec.ResponseHeaders.Values("Set-Cookie"))
	}
}

// @see https://github.com/better-auth/better-auth/issues/7994
func TestPortSessionRefreshCacheExtendsSessionTokenExpiry(t *testing.T) {
	const expiresIn = 60 * 5
	p := psStatelessRefresh(t, expiresIn*time.Second)
	headers := psNewJar()
	p.signIn(headers, nil)
	res, first := p.getSession(headers.header(), "")
	headers.apply(res)
	if first == nil {
		t.Fatal("expected session")
	}
	token, _ := psMap(t, first["session"], "session")["token"].(string)
	if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	res, _ = p.getSession(headers.header(), "")
	headers.apply(res)
	got, ok := psMaxAge(res.Header, "better-auth.session_token")
	if !ok || got != expiresIn {
		t.Fatalf("session_token max-age = %v (present=%v), want %d; set-cookie=%v", got, ok, expiresIn, res.Header.Values("Set-Cookie"))
	}
}

// =====================================================================================
// describe("cookie cache versioning")
// =====================================================================================

func TestPortSessionCookieCacheVersionChangeInvalidates(t *testing.T) {
	p1 := psNew(t, func(c *Config) {
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe", Version: "1"}
	})
	h1 := psNewJar()
	p1.signIn(h1, nil)
	_, s1 := p1.getSession(h1.header(), "")
	if s1 == nil || psMap(t, s1["user"], "user")["email"] != psEmail {
		t.Fatalf("session1 = %v", s1)
	}
	p2 := psNew(t, func(c *Config) {
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe", Version: "2"}
	})
	if _, s2 := p2.getSession(h1.header(), ""); s2 != nil {
		t.Fatalf("expected null with version mismatch, got %v", s2)
	}
}

func TestPortSessionCookieCacheVersionVariants(t *testing.T) {
	cases := []struct {
		name string
		cc   CookieCacheConfig
	}{
		{"should work with function-based version", CookieCacheConfig{Enabled: true, Strategy: "jwe", VersionFunc: func(_ *Session, u *User) string {
			if strings.Contains(u.Email, "test") {
				return "test-v1"
			}
			return "prod-v1"
		}}},
		{"should work with async function-based version", CookieCacheConfig{Enabled: true, Strategy: "jwe", VersionFunc: func(_ *Session, u *User) string {
			time.Sleep(10 * time.Millisecond)
			return "async-" + u.ID[:8]
		}}},
		{"should work with compact strategy", CookieCacheConfig{Enabled: true, Strategy: "compact", Version: "compact-v1"}},
		{"should work with jwt strategy", CookieCacheConfig{Enabled: true, Strategy: "jwt", Version: "jwt-v1"}},
		{"should default to version '1' when not specified", CookieCacheConfig{Enabled: true, Strategy: "jwe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := tc.cc
			p := psNew(t, func(c *Config) { psSessionCfg(c).CookieCache = &cc })
			headers := psNewJar()
			p.signIn(headers, nil)
			res, s := p.getSession(headers.header(), "")
			headers.apply(res)
			if s == nil || psMap(t, s["user"], "user")["email"] != psEmail {
				t.Fatalf("session = %v (%d %s)", s, res.Status, res.Body)
			}
		})
	}
}

func TestPortSessionCookieCacheIncludesAdditionalFields(t *testing.T) {
	p := psNew(t, func(c *Config) {
		s := psSessionCfg(c)
		s.AdditionalFields = append(s.AdditionalFields,
			db.Field{Name: "role", Type: db.TypeString, DefaultValue: "user", Returned: Bool(true)},
			db.Field{Name: "preferences", Type: db.TypeJSON, DefaultValue: "{}", Returned: Bool(true)},
		)
		s.CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "compact"}
	})
	headers := psNewJar()
	p.signIn(headers, nil)
	first := p.spy.findOneCalls()
	_, s1 := p.getSession(headers.header(), "")
	if s1 == nil {
		t.Fatal("expected session")
	}
	ss1 := psMap(t, s1["session"], "session")
	for _, k := range []string{"role", "preferences"} {
		if _, ok := ss1[k]; !ok {
			t.Fatalf("session1 missing %s: %v", k, ss1)
		}
	}
	_, s2 := p.getSession(headers.header(), "")
	if n := p.spy.findOneCalls(); n != first {
		t.Fatalf("findOne calls %d, want %d", n, first)
	}
	ss2 := psMap(t, s2["session"], "session")
	for _, k := range []string{"role", "preferences"} {
		if _, ok := ss2[k]; !ok {
			t.Fatalf("session2 missing %s: %v", k, ss2)
		}
	}
	if ss2["role"] != ss1["role"] {
		t.Fatalf("role %v != %v", ss2["role"], ss1["role"])
	}
}

// =====================================================================================
// describe("deferSessionRefresh")
// =====================================================================================

func psDeferInstance(t *testing.T, mutate func(s *SessionConfig)) (*psInst, string) {
	p := psNew(t, func(c *Config) { mutate(psSessionCfg(c)) })
	signIn := p.apiSignIn()
	cookie := signIn.Headers.Values("Set-Cookie")[0]
	p.spy.reset()
	return p, cookie
}

func TestPortSessionDeferSessionRefresh(t *testing.T) {
	t.Run("should return needsRefresh flag on GET when enabled", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) { s.DeferSessionRefresh = true; s.UpdateAge = psDur(0) })
		p.shift(time.Second)
		res, err := p.apiGetSession(cookie, "")
		if err != nil {
			t.Fatal(err)
		}
		sr := psSessionResult(t, res)
		if sr == nil || sr.NeedsRefresh == nil || !*sr.NeedsRefresh {
			t.Fatalf("needsRefresh = %v", sr)
		}
	})
	t.Run("should return needsRefresh: false when session is fresh", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) { s.DeferSessionRefresh = true; s.UpdateAge = psDur(24 * time.Hour) })
		res, err := p.apiGetSession(cookie, "")
		if err != nil {
			t.Fatal(err)
		}
		sr := psSessionResult(t, res)
		if sr == nil || sr.NeedsRefresh == nil || *sr.NeedsRefresh {
			t.Fatalf("needsRefresh = %v", sr)
		}
	})
	t.Run("should not update session on GET when deferSessionRefresh is enabled", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) { s.DeferSessionRefresh = true; s.UpdateAge = psDur(0) })
		p.shift(time.Second)
		if _, err := p.apiGetSession(cookie, ""); err != nil {
			t.Fatal(err)
		}
		if _, u, _ := p.spy.get(); u != 0 {
			t.Fatalf("updateSession called %d times", u)
		}
	})
	t.Run("should update session on POST when deferSessionRefresh is enabled", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) { s.DeferSessionRefresh = true; s.UpdateAge = psDur(0) })
		p.shift(time.Second)
		res, err := p.apiGetSession(cookie, "POST")
		if err != nil {
			t.Fatal(err)
		}
		if _, u, _ := p.spy.get(); u == 0 {
			t.Fatal("updateSession not called")
		}
		sr := psSessionResult(t, res)
		if sr == nil || sr.NeedsRefresh != nil {
			t.Fatalf("result = %v", sr)
		}
	})
	t.Run("should reject POST when deferSessionRefresh is not enabled", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) {})
		_, err := p.apiGetSession(cookie, "POST")
		if err == nil || !strings.Contains(err.Error(), "POST method requires deferSessionRefresh to be enabled") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("should not delete expired session on GET when deferSessionRefresh is enabled", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) { s.DeferSessionRefresh = true; s.ExpiresIn = 60 * time.Second })
		p.shift(61 * time.Second)
		res, err := p.apiGetSession(cookie, "")
		if err != nil {
			t.Fatal(err)
		}
		if psSessionResult(t, res) != nil {
			t.Fatal("expected null")
		}
		if _, _, d := p.spy.get(); d != 0 {
			t.Fatalf("deleteSession called %d times", d)
		}
	})
	t.Run("should delete expired session on POST when deferSessionRefresh is enabled", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) { s.DeferSessionRefresh = true; s.ExpiresIn = 60 * time.Second })
		p.shift(61 * time.Second)
		res, err := p.apiGetSession(cookie, "POST")
		if err != nil {
			t.Fatal(err)
		}
		if psSessionResult(t, res) != nil {
			t.Fatal("expected null")
		}
		if _, _, d := p.spy.get(); d == 0 {
			t.Fatal("deleteSession not called")
		}
	})
	t.Run("should still update session on GET when deferSessionRefresh is not enabled (default behavior)", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) { s.UpdateAge = psDur(0) })
		p.shift(time.Second)
		res, err := p.apiGetSession(cookie, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, u, _ := p.spy.get(); u == 0 {
			t.Fatal("updateSession not called")
		}
		sr := psSessionResult(t, res)
		if sr == nil || sr.NeedsRefresh != nil {
			t.Fatalf("result = %v", sr)
		}
	})
	t.Run("should respect disableSessionRefresh config when deferSessionRefresh is enabled", func(t *testing.T) {
		p, cookie := psDeferInstance(t, func(s *SessionConfig) {
			s.DeferSessionRefresh = true
			s.DisableSessionRefresh = true
			s.UpdateAge = psDur(0)
		})
		p.shift(time.Second)
		res, err := p.apiGetSession(cookie, "")
		if err != nil {
			t.Fatal(err)
		}
		sr := psSessionResult(t, res)
		if sr == nil || sr.NeedsRefresh == nil || *sr.NeedsRefresh {
			t.Fatalf("needsRefresh = %v", sr)
		}
	})
}

// =====================================================================================
// describe("date field type consistency")
// =====================================================================================

func TestPortSessionDateFieldTypeConsistency(t *testing.T) {
	p := psStatelessRefresh(t, 0)
	signIn := p.apiSignIn()
	cookie := strings.Join(signIn.Headers.Values("Set-Cookie"), "; ")
	decode := func(res *CallResult) map[string]any {
		var m map[string]any
		if err := res.Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	initialRes, err := p.apiGetSession(cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	initial := decode(initialRes)
	if initial == nil {
		t.Fatal("expected initial session")
	}
	time.Sleep(1100 * time.Millisecond) // into the refresh window (see psStatelessRefresh)
	refreshedRes, err := p.apiGetSession(cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	refreshed := decode(refreshedRes)
	if refreshed == nil {
		t.Fatal("expected refreshed session")
	}
	is, rs := psMap(t, initial["session"], "session"), psMap(t, refreshed["session"], "session")
	for _, k := range []string{"expiresAt", "createdAt"} {
		if fmt.Sprintf("%T", is[k]) != fmt.Sprintf("%T", rs[k]) {
			t.Fatalf("%s type %T != %T", k, rs[k], is[k])
		}
	}
	// Typed API: both paths must produce time.Time values.
	if sr := psSessionResult(t, refreshedRes); sr == nil || sr.Session.ExpiresAt.IsZero() || sr.Session.CreatedAt.IsZero() {
		t.Fatalf("refreshed typed session dates missing: %#v", refreshedRes.Data)
	}
}

// =====================================================================================
// describe("updateSession")
// =====================================================================================

func psUpdateSessionInstance(t *testing.T) (*psInst, *psJar) {
	p := psNew(t, func(c *Config) {
		s := psSessionCfg(c)
		s.AdditionalFields = append(s.AdditionalFields,
			db.Field{Name: "theme", Type: db.TypeString, DefaultValue: "light"},
			db.Field{Name: "language", Type: db.TypeString, Required: false},
			db.Field{Name: "internalNote", Type: db.TypeString, Input: Bool(false), Required: false},
		)
	})
	jar := psNewJar()
	p.signIn(jar, nil)
	return p, jar
}

func TestPortSessionUpdateSession(t *testing.T) {
	t.Run("should update a custom additional field on a session", func(t *testing.T) {
		p, jar := psUpdateSessionInstance(t)
		if _, s := p.getSession(jar.header(), ""); s == nil {
			t.Fatal("expected session")
		}
		res := p.do("POST", "/update-session", jar.header(), map[string]any{"theme": "dark"})
		m := psBody(t, res)
		if m == nil {
			t.Fatalf("update-session: %d %s", res.Status, res.Body)
		}
		if psMap(t, m["session"], "session")["theme"] != "dark" {
			t.Fatalf("theme = %v", m["session"])
		}
		_, s := p.getSession(jar.header(), "")
		if s == nil || psMap(t, s["session"], "session")["theme"] != "dark" {
			t.Fatalf("session after update = %v", s)
		}
	})
	for _, tc := range []struct{ name, field, value string }{
		{"should ignore core session fields", "token", "malicious-token"},
		{"should ignore core field userId", "userId", "another-user"},
		{"should return error when no fields to update", "unknownField", "value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, jar := psUpdateSessionInstance(t)
			res := p.do("POST", "/update-session", jar.header(), map[string]any{tc.field: tc.value})
			if res.Status != 400 {
				t.Fatalf("status = %d %s", res.Status, res.Body)
			}
			if msg, _ := res.JSON(t)["message"].(string); !strings.Contains(msg, "No fields to update") {
				t.Fatalf("message = %q", msg)
			}
		})
	}
	t.Run("should reject input: false fields", func(t *testing.T) {
		p, jar := psUpdateSessionInstance(t)
		res := p.do("POST", "/update-session", jar.header(), map[string]any{"internalNote": "should-fail"})
		if res.Status != 400 {
			t.Fatalf("status = %d %s", res.Status, res.Body)
		}
	})
	t.Run("should update session cookie after mutation", func(t *testing.T) {
		p, jar := psUpdateSessionInstance(t)
		p.do("POST", "/update-session", jar.header(), map[string]any{"theme": "blue"})
		_, s := p.getSession(jar.header(), "")
		if s == nil || psMap(t, s["session"], "session")["theme"] != "blue" {
			t.Fatalf("session = %v", s)
		}
	})
}

func TestPortSessionUpdateSessionPluginAuthorityFields(t *testing.T) {
	for _, f := range []string{"activeOrganizationId", "activeTeamId", "impersonatedBy"} {
		t.Run("should reject forging the "+f+" session field", func(t *testing.T) {
			t.Skip("requires the organization and admin plugins, which are not implemented in the Go port")
		})
	}
}

// =====================================================================================
// describe("update-session cookie cache revocation")
// =====================================================================================

func TestPortSessionUpdateSessionCookieCacheRevocation(t *testing.T) {
	theme := db.Field{Name: "theme", Type: db.TypeString, DefaultValue: "light"}
	t.Run("fails closed when the backing session is revoked in a stateful deployment", func(t *testing.T) {
		p := psNew(t, func(c *Config) {
			s := psSessionCfg(c)
			s.CookieCache = &CookieCacheConfig{Enabled: true, MaxAge: 60 * time.Second}
			s.AdditionalFields = append(s.AdditionalFields, theme)
		})
		headers := psNewJar()
		p.signIn(headers, nil)
		res, initial := p.getSession(headers.header(), "")
		headers.apply(res)
		if initial == nil {
			t.Fatal("expected session")
		}
		token := psMap(t, initial["session"], "session")["token"].(string)
		if !strings.Contains(headers.header(), "session_data") {
			t.Fatalf("cookie header lacks session_data: %s", headers.header())
		}
		if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		upd := p.do("POST", "/update-session", headers.header(), map[string]any{"theme": "dark"})
		if upd.Status != 401 {
			t.Fatalf("update-session status = %d %s", upd.Status, upd.Body)
		}
		if _, strict := p.getSession(headers.header(), "disableCookieCache=true"); strict != nil {
			t.Fatalf("expected null, got %v", strict)
		}
	})
	t.Run("still refreshes the cookie in a DB-less deployment when no row exists", func(t *testing.T) {
		p := psNew(t, func(c *Config) {
			c.Database = nil
			s := psSessionCfg(c)
			s.AdditionalFields = append(s.AdditionalFields, theme)
		})
		headers := psNewJar()
		p.signIn(headers, nil)
		res, initial := p.getSession(headers.header(), "")
		headers.apply(res)
		if initial == nil {
			t.Fatal("expected session")
		}
		token := psMap(t, initial["session"], "session")["token"].(string)
		if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		upd := p.do("POST", "/update-session", headers.header(), map[string]any{"theme": "dark"})
		headers.apply(upd)
		if upd.Status != 200 {
			t.Fatalf("update-session: %d %s", upd.Status, upd.Body)
		}
		m := psBody(t, upd)
		if m == nil || psMap(t, m["session"], "session")["theme"] != "dark" {
			t.Fatalf("update-session body = %s", upd.Body)
		}
	})
}

// =====================================================================================
// describe("forced strict session validation")
// =====================================================================================

func TestPortSessionForcedStrictValidation(t *testing.T) {
	t.Run("a request cannot re-enable the cookie cache on a route that forces it off", func(t *testing.T) {
		p := psNew(t, func(c *Config) {
			psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, MaxAge: 60 * time.Second}
		})
		headers := psNewJar()
		p.signIn(headers, nil)
		res, initial := p.getSession(headers.header(), "")
		headers.apply(res)
		if initial == nil {
			t.Fatal("expected session")
		}
		token := psMap(t, initial["session"], "session")["token"].(string)
		if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		r := p.do("POST", "/change-password?disableCookieCache=", headers.header(),
			map[string]any{"currentPassword": psPassword, "newPassword": "new-password-1234"})
		if r.Status != 401 {
			t.Fatalf("change-password status = %d %s", r.Status, r.Body)
		}
	})
	t.Run("uses the signed cookie as the authoritative session record without a server store", func(t *testing.T) {
		p := psNew(t, func(c *Config) {
			c.Database = nil
			psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: "jwe"}
		})
		headers := psNewJar()
		p.signIn(headers, nil)
		res, cached := p.getSession(headers.header(), "")
		headers.apply(res)
		if cached == nil {
			t.Fatal("expected session")
		}
		token := psMap(t, cached["session"], "session")["token"].(string)
		if err := p.ctx().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		ac := p.ctx()
		ep := p.env.auth.endpoint("getSession")
		ec := p.env.auth.newEndpointContext(context.Background(), ep, callInput{Headers: http.Header{"Cookie": {headers.header()}}, Auth: ac.clone()})
		sw, err := GetAuthoritativeSessionFromCtx(ec)
		if err != nil || sw == nil || sw.User.Email != psEmail {
			t.Fatalf("GetAuthoritativeSessionFromCtx = %v, %v", sw, err)
		}
	})
}

// =====================================================================================
// describe("get-session cache headers")
// =====================================================================================

// @see https://github.com/better-auth/better-auth/issues/10217
func TestPortSessionGetSessionCacheHeaders(t *testing.T) {
	t.Run("sets Cache-Control: no-store on authenticated GET /get-session responses", func(t *testing.T) {
		p := psNew(t, nil)
		headers := psNewJar()
		p.signIn(headers, nil)
		res := p.do("GET", "/get-session", headers.header(), nil, func(r *http.Request) { r.Header.Del("Origin") })
		if res.Status != 200 {
			t.Fatalf("status = %d", res.Status)
		}
		m := psBody(t, res)
		if m == nil || psMap(t, m["user"], "user")["id"] == "" {
			t.Fatalf("body = %s", res.Body)
		}
		if !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
			t.Fatalf("cache-control = %q", res.Header.Get("Cache-Control"))
		}
	})
	t.Run("sets Cache-Control: no-store on unauthenticated GET /get-session responses", func(t *testing.T) {
		p := psNew(t, nil)
		res := p.do("GET", "/get-session", "", nil, func(r *http.Request) { r.Header.Del("Origin") })
		if res.Status != 200 || strings.TrimSpace(string(res.Body)) != "null" {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
		if !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
			t.Fatalf("cache-control = %q", res.Header.Get("Cache-Control"))
		}
	})
	// @see https://github.com/better-auth/better-auth/pull/10222
	t.Run("does not set Cache-Control: no-store on session-gated endpoints", func(t *testing.T) {
		p := psNew(t, func(c *Config) {
			c.Plugins = append(c.Plugins, psFreshPlugin("session-gated-cache-test", "sessionGatedCheck", "/session-gated-cache-check"))
		})
		headers := psNewJar()
		p.signIn(headers, nil)
		res := p.do("GET", "/session-gated-cache-check", headers.header(), nil, func(r *http.Request) { r.Header.Del("Origin") })
		if res.Status != 200 {
			t.Fatalf("status = %d %s", res.Status, res.Body)
		}
		if v, ok := res.Header["Cache-Control"]; ok {
			t.Fatalf("cache-control = %v, want absent", v)
		}
	})
}
