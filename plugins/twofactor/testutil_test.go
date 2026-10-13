package twofactor

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
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Port of test-utils/test-instance.ts for the two-factor tests.

const (
	testEmail    = "test@test.com"
	testPassword = "test123456"
	testName     = "test user"
)

func testHash(pw string) string {
	s := sha256.Sum256([]byte(pw))
	return "$test$sha256$" + hex.EncodeToString(s[:])
}

type instance struct {
	t    *testing.T
	auth *betterauth.Auth
	ad   adapter.Adapter
	srv  *httptest.Server
}

type instanceOpts struct {
	mutate          func(c *betterauth.Config)
	disableTestUser bool
}

// newInstance mirrors getTestInstance({ secret: DEFAULT_SECRET, plugins }).
func newInstance(t *testing.T, plugins []*betterauth.Plugin, io ...instanceOpts) *instance {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	var o instanceOpts
	if len(io) > 0 {
		o = io[0]
	}
	inst := &instance{t: t}
	mux := http.NewServeMux()
	inst.srv = httptest.NewServer(mux)
	t.Cleanup(inst.srv.Close)
	cfg := betterauth.Config{
		BaseURL:  "http://localhost:3000",
		Secret:   betterauth.DefaultSecret,
		Database: memory.New(memory.NewDB()),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true, Password: &betterauth.PasswordConfig{
			Hash:   func(pw string) (string, error) { return testHash(pw), nil },
			Verify: func(h, pw string) (bool, error) { return h == testHash(pw), nil },
		}},
		Logger:   betterauth.NopLogger{},
		Plugins:  plugins,
		Advanced: &betterauth.AdvancedConfig{DisableOriginCheck: betterauth.Bool(true)},
	}
	if o.mutate != nil {
		o.mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inst.auth = a
	inst.ad = a.Context().Adapter
	mux.Handle("/api/auth/", a.Handler())
	if !o.disableTestUser {
		r := inst.api("signUpEmail", nil, map[string]any{"email": testEmail, "password": testPassword, "name": testName})
		if r.Status != 200 {
			t.Fatalf("test user sign-up: %d %v", r.Status, r.Data)
		}
	}
	return inst
}

// res is the "asResponse" view of a call.
type res struct {
	Status int
	Header http.Header
	Data   map[string]any
	Raw    any
	// GoErr is a non-API error (a thrown error upstream).
	GoErr error
}

func (r *res) str(key string) string {
	s, _ := r.Data[key].(string)
	return s
}

func (r *res) message() string { return r.str("message") }

func (r *res) code() string { return r.str("code") }

func (r *res) setCookies() []string { return r.Header.Values("Set-Cookie") }

type parsedCookie struct {
	Value string
	Attrs map[string]string
}

// cookie returns the last Set-Cookie for name (parseSetCookieHeader semantics).
func (r *res) cookie(name string) (parsedCookie, bool) {
	var out parsedCookie
	found := false
	for _, sc := range r.setCookies() {
		n, v, attrs := betterauth.ParseSetCookie(sc)
		if n == name {
			out = parsedCookie{Value: v, Attrs: attrs}
			found = true
		}
	}
	return out, found
}

// cookieHeaders is convertSetCookieToCookie: the Set-Cookie values as a Cookie header.
func (r *res) cookieHeaders() http.Header {
	return applySetCookies(http.Header{}, r.setCookies())
}

// applySetCookies merges Set-Cookie values into the request Cookie header.
func applySetCookies(h http.Header, setCookies []string) http.Header {
	type kv struct{ k, v string }
	var list []kv
	idx := map[string]int{}
	for _, part := range strings.Split(h.Get("Cookie"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if i, ok := idx[k]; ok {
			list[i].v = v
			continue
		}
		idx[k] = len(list)
		list = append(list, kv{k, v})
	}
	for _, sc := range setCookies {
		n, v, _ := betterauth.ParseSetCookie(sc)
		v = betterauth.EncodeURIComponent(v)
		if i, ok := idx[n]; ok {
			list[i].v = v
			continue
		}
		idx[n] = len(list)
		list = append(list, kv{n, v})
	}
	parts := make([]string, len(list))
	for i, e := range list {
		parts[i] = e.k + "=" + e.v
	}
	out := h.Clone()
	if out == nil {
		out = http.Header{}
	}
	out.Set("Cookie", strings.Join(parts, "; "))
	return out
}

func cookieHeader(pairs ...string) http.Header {
	h := http.Header{}
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, pairs[i]+"="+pairs[i+1])
	}
	h.Set("Cookie", strings.Join(parts, "; "))
	return h
}

// api calls auth.api[key] with asResponse semantics.
func (i *instance) api(key string, headers http.Header, body any) *res {
	i.t.Helper()
	return i.apiCtx(context.Background(), key, headers, body)
}

func (i *instance) apiCtx(ctx context.Context, key string, headers http.Header, body any) *res {
	r, err := i.auth.API.Call(ctx, key, betterauth.CallInput{Headers: headers, Body: body})
	out := &res{Header: http.Header{}}
	if err != nil {
		e, ok := betterauth.AsAPIError(err)
		if !ok {
			out.GoErr = err
			out.Status = 500
			return out
		}
		out.Status = e.StatusCode
		out.Header = e.Headers
		if e.Body != nil {
			out.Data = e.Body.Map()
		}
		return out
	}
	out.Status = r.Status
	if r.Headers != nil {
		out.Header = r.Headers
	}
	var v any
	if err := r.Decode(&v); err == nil {
		out.Raw = v
		out.Data, _ = v.(map[string]any)
	}
	return out
}

// http performs a real HTTP request against the mounted handler (customFetchImpl).
func (i *instance) http(method, path string, headers http.Header, body any) *res {
	i.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, i.srv.URL+"/api/auth"+path, rd)
	if err != nil {
		i.t.Fatal(err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		i.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	out := &res{Status: resp.StatusCode, Header: resp.Header}
	var v any
	if json.Unmarshal(b, &v) == nil {
		out.Raw = v
		out.Data, _ = v.(map[string]any)
	}
	return out
}

type signedIn struct {
	headers http.Header
	userID  string
	user    map[string]any
}

// signInWithTestUser signs in and keeps only the session token cookie.
func (i *instance) signInWithTestUser() signedIn {
	i.t.Helper()
	r := i.api("signInEmail", nil, map[string]any{"email": testEmail, "password": testPassword})
	if r.Status != 200 {
		i.t.Fatalf("sign-in: %d %v", r.Status, r.Data)
	}
	ck, _ := r.cookie("better-auth.session_token")
	user, _ := r.Data["user"].(map[string]any)
	id, _ := user["id"].(string)
	return signedIn{headers: cookieHeader("better-auth.session_token", betterauth.EncodeURIComponent(ck.Value)), userID: id, user: user}
}

func (i *instance) signIn() *res {
	return i.api("signInEmail", nil, map[string]any{"email": testEmail, "password": testPassword})
}

// startChallenge signs in a 2FA user and returns the challenge cookies.
func (i *instance) startChallenge() http.Header {
	i.t.Helper()
	r := i.signIn()
	if r.Status != 200 {
		i.t.Fatalf("sign-in: %d %v", r.Status, r.Data)
	}
	return r.cookieHeaders()
}

func (i *instance) session(headers http.Header) map[string]any {
	i.t.Helper()
	s, err := i.auth.API.GetSession(context.Background(), headers)
	if err != nil {
		i.t.Fatal(err)
	}
	if s == nil {
		return nil
	}
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (i *instance) findOne(model string, where ...adapter.Where) adapter.Record {
	i.t.Helper()
	r, err := i.ad.FindOne(context.Background(), adapter.FindOneInput{Model: model, Where: where})
	if err != nil {
		i.t.Fatal(err)
	}
	return r
}

func (i *instance) update(model string, data adapter.Record, where ...adapter.Where) {
	i.t.Helper()
	if _, err := i.ad.Update(context.Background(), model, where, data); err != nil {
		i.t.Fatal(err)
	}
}

func eq(field string, v any) adapter.Where { return adapter.Where{Field: field, Value: v} }

func (i *instance) twoFactorRow(userID string) adapter.Record {
	return i.findOne("twoFactor", eq("userId", userID))
}

func (i *instance) userRow(userID string) adapter.Record { return i.findOne("user", eq("id", userID)) }

func (i *instance) testUserID() string {
	u := i.findOne("user", eq("email", testEmail))
	if u == nil {
		i.t.Fatal("no test user")
	}
	return u["id"].(string)
}

// decryptSecret is symmetricDecrypt({ key: DEFAULT_SECRET, data }).
func decryptSecret(t *testing.T, data any) string {
	t.Helper()
	s, _ := data.(string)
	out, err := bacrypto.SymmetricDecrypt(bacrypto.PlainSecret(betterauth.DefaultSecret), s)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return out
}

func totpNow(t *testing.T, secret string) string {
	t.Helper()
	c, err := CreateOTP(secret, 0, 0).TOTP()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (i *instance) currentTOTP(userID string) string {
	return totpNow(i.t, decryptSecret(i.t, i.twoFactorRow(userID)["secret"]))
}

func anyStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, len(arr))
	for k, x := range arr {
		out[k], _ = x.(string)
	}
	return out
}

func expectStatus(t *testing.T, r *res, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("expected status %d, got %d: %v %v", status, r.Status, r.Data, r.GoErr)
	}
}

func expectMessage(t *testing.T, r *res, msg string) {
	t.Helper()
	if r.message() != msg {
		t.Fatalf("expected message %q, got %d %v", msg, r.Status, r.Data)
	}
}

func boolOf(v any) any {
	switch t := v.(type) {
	case bool:
		return t
	case nil:
		return nil
	}
	return v
}

func toTime(v any) time.Time {
	t, _ := adapter.ToTime(v)
	return t
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func timeNowAdd(ms int64) time.Time { return time.Now().Add(time.Duration(ms) * time.Millisecond) }

type memStore struct{ db *memory.DB }

func newStore() *memStore { return &memStore{db: memory.NewDB()} }

func (s *memStore) factory() adapter.Factory { return memory.New(s.db) }
