package emailotp_test

// Test harness mirroring upstream getTestInstance: an Auth instance at
// http://localhost:3000 with email/password enabled, rate limiting disabled, the GitHub and
// Google providers configured and a test user (test@test.com / test123456).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

const (
	testBase     = "http://localhost:3000"
	testEmail    = "test@test.com"
	testPassword = "test123456"
	testName     = "test user"
)

type inst struct {
	t    *testing.T
	auth *betterauth.Auth
}

type instOpts struct {
	disableTestUser bool
}

// fastHash replaces scrypt like upstream's test password hasher.
func fastHash(pw string) (string, error) {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:]), nil
}

func newInst(t *testing.T, mutate func(c *betterauth.Config), o ...instOpts) *inst {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	cfg := betterauth.Config{
		BaseURL:  testBase,
		Secret:   "better-auth-secret-that-is-long-enough-for-validation-test",
		Database: memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true, Password: &betterauth.PasswordConfig{
			Hash:   fastHash,
			Verify: func(hash, pw string) (bool, error) { h, _ := fastHash(pw); return h == hash, nil },
		}},
		RateLimit: &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Logger:    betterauth.NopLogger{},
		SocialProviders: []oauth2.Provider{
			github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
			google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if cfg.EmailAndPassword != nil && cfg.EmailAndPassword.Password == nil {
		cfg.EmailAndPassword.Password = &betterauth.PasswordConfig{
			Hash:   fastHash,
			Verify: func(hash, pw string) (bool, error) { h, _ := fastHash(pw); return h == hash, nil },
		}
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("betterauth.New: %v", err)
	}
	in := &inst{t: t, auth: a}
	if len(o) == 0 || !o[0].disableTestUser {
		if _, err := in.api("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": testEmail, "password": testPassword, "name": testName}}); err != nil {
			t.Fatalf("create test user: %v", err)
		}
	}
	return in
}

func (in *inst) ctx() *betterauth.AuthContext { return in.auth.Context() }

func (in *inst) api(key string, ci betterauth.CallInput) (*betterauth.CallResult, error) {
	return in.auth.API.Call(context.Background(), key, ci)
}

func (in *inst) mustAPI(key string, ci betterauth.CallInput) map[string]any {
	in.t.Helper()
	res, err := in.api(key, ci)
	if err != nil {
		in.t.Fatalf("%s: %v", key, err)
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		in.t.Fatalf("%s decode: %v", key, err)
	}
	return m
}

// advance emulates vi.advanceTimersByTime by shifting stored expirations/timestamps back.
func (in *inst) advance(d time.Duration) {
	in.t.Helper()
	ctx := context.Background()
	ad := in.ctx().Adapter
	for model, fields := range map[string][]string{
		"verification": {"expiresAt", "createdAt", "updatedAt"},
		"session":      {"expiresAt", "createdAt", "updatedAt"},
	} {
		rows, err := ad.FindMany(ctx, adapter.FindManyInput{Model: model})
		if err != nil {
			in.t.Fatal(err)
		}
		for _, r := range rows {
			upd := adapter.Record{}
			for _, f := range fields {
				if tm, ok := adapter.ToTime(r[f]); ok {
					upd[f] = tm.Add(-d)
				}
			}
			if _, err := ad.Update(ctx, model, []adapter.Where{{Field: "id", Value: r["id"]}}, upd); err != nil {
				in.t.Fatal(err)
			}
		}
	}
	rows, err := ad.FindMany(ctx, adapter.FindManyInput{Model: "rateLimit"})
	if err == nil {
		for _, r := range rows {
			last, _ := adapter.ToInt64(r["lastRequest"])
			_, _ = ad.Update(ctx, "rateLimit", []adapter.Where{{Field: "key", Value: r["key"]}}, adapter.Record{"lastRequest": last - d.Milliseconds()})
		}
	}
}

// ---- HTTP client ----

type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

type client struct {
	in     *inst
	jar    *cookiejar.Jar
	hc     *http.Client
	header http.Header
}

// client returns an HTTP client; with persist the cookies are kept between requests.
func (in *inst) client(persist bool) *client {
	c := &client{in: in, header: http.Header{}}
	c.hc = &http.Client{Transport: handlerTransport{in.auth.Handler()},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if persist {
		c.jar, _ = cookiejar.New(nil)
		c.hc.Jar = c.jar
	}
	return c
}

type resp struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *resp) JSON() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}

func (r *resp) str(path ...string) string {
	var cur any = r.JSON()
	for _, p := range path {
		m, _ := cur.(map[string]any)
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

func (r *resp) val(path ...string) any {
	var cur any = r.JSON()
	for _, p := range path {
		m, _ := cur.(map[string]any)
		cur = m[p]
	}
	return cur
}

func (r *resp) code() string { return r.str("code") }

func (c *client) do(method, path string, body any, hdr http.Header) *resp {
	c.in.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	u := path
	if !strings.HasPrefix(u, "http") {
		u = testBase + "/api/auth" + path
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		c.in.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range c.header {
		req.Header[k] = vs
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	res, err := c.hc.Do(req)
	if err != nil {
		c.in.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &resp{Status: res.StatusCode, Header: res.Header, Body: b}
}

func (c *client) post(path string, body any, hdr ...http.Header) *resp {
	return c.do("POST", path, body, first(hdr))
}

func (c *client) get(path string, hdr ...http.Header) *resp {
	return c.do("GET", path, nil, first(hdr))
}

func first(h []http.Header) http.Header {
	if len(h) > 0 {
		return h[0]
	}
	return nil
}

// cookieHeader converts the Set-Cookie headers of a response into a Cookie header.
func cookieHeader(res http.Header) http.Header {
	var parts []string
	for _, sc := range res.Values("Set-Cookie") {
		_, _, attrs := betterauth.ParseSetCookie(sc)
		if ma, ok := attrs["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) {
			continue
		}
		nv, _, _ := strings.Cut(sc, ";")
		parts = append(parts, strings.TrimSpace(nv))
	}
	return http.Header{"Cookie": {strings.Join(parts, "; ")}}
}

// signIn signs in with email/password and returns request headers carrying the session.
func (in *inst) signIn(email, password string) http.Header {
	in.t.Helper()
	res := in.client(false).post("/sign-in/email", map[string]any{"email": email, "password": password})
	if res.Status != 200 {
		in.t.Fatalf("sign-in %s: %d %s", email, res.Status, res.Body)
	}
	return cookieHeader(res.Header)
}

func (in *inst) getSession(h http.Header) map[string]any {
	in.t.Helper()
	res := in.client(false).get("/get-session", h)
	if res.Status != 200 {
		in.t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if string(res.Body) == "null" {
		return nil
	}
	return res.JSON()
}

func tokenFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

func apiErr(t *testing.T, err error) *betterauth.APIError {
	t.Helper()
	e, ok := betterauth.AsAPIError(err)
	if !ok {
		t.Fatalf("expected APIError, got %v", err)
	}
	return e
}

func expectStatus(t *testing.T, r *resp, status int, code string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected status %d, got %d: %s", status, r.Status, r.Body)
	}
	if code != "" && r.code() != code {
		t.Fatalf("expected code %s, got %s (%s)", code, r.code(), r.Body)
	}
}
