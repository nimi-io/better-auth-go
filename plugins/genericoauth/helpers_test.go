package genericoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/google"
)

func googleProvider() oauth2.Provider {
	return google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "google-client-id", ClientSecret: "google-client-secret"}})
}

// ---- mock OpenID provider (oauth2-mock-server equivalent) ----

const (
	idpHost = "localhost:4567"
	idpBase = "http://" + idpHost
)

// userinfoHook mutates the /userinfo response (beforeUserinfo).
type userinfoHook func(body *map[string]any, status *int)

// tokenHook mutates the id token payload before signing (beforeTokenSigning).
type tokenHook func(payload map[string]any, r *oauth2test.Request)

// responseHook mutates the /token response body (beforeResponse).
type responseHook func(body map[string]any, r *oauth2test.Request)

type mockIdP struct {
	*oauth2test.Server
	mu        sync.Mutex
	codes     map[string]codeInfo
	userinfo  []hookEntry[userinfoHook]
	tokenSign []hookEntry[tokenHook]
	response  []hookEntry[responseHook]
}

type hookEntry[T any] struct {
	fn   T
	once bool
	id   int
}

type codeInfo struct {
	nonce string
	scope string
}

var hookSeq int

func newIdP(t *testing.T) *mockIdP {
	t.Helper()
	m := &mockIdP{Server: oauth2test.New(t), codes: map[string]codeInfo{}}
	m.Handle("GET "+idpHost+"/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                                idpBase,
			"token_endpoint":                        idpBase + "/token",
			"authorization_endpoint":                idpBase + "/authorize",
			"userinfo_endpoint":                     idpBase + "/userinfo",
			"token_endpoint_auth_methods_supported": []string{"none"},
			"jwks_uri":                              idpBase + "/jwks",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"client_credentials", "authorization_code", "password"},
			"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
			"response_modes_supported":                         []string{"query"},
			"id_token_signing_alg_values_supported":            []string{"RS256"},
			"revocation_endpoint":                              idpBase + "/revoke",
			"subject_types_supported":                          []string{"public"},
			"end_session_endpoint":                             idpBase + "/endsession",
			"introspection_endpoint":                           idpBase + "/introspect",
			"code_challenge_methods_supported":                 []string{"plain", "S256"},
		})
	})
	m.ServeJWKS("GET " + idpHost + "/jwks")
	m.Handle("GET "+idpHost+"/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := bacrypto.RandomString(32)
		m.mu.Lock()
		m.codes[code] = codeInfo{nonce: q.Get("nonce"), scope: q.Get("scope")}
		m.mu.Unlock()
		u, _ := url.Parse(q.Get("redirect_uri"))
		rq := u.Query()
		rq.Set("code", code)
		if s := q.Get("state"); s != "" {
			rq.Set("state", s)
		}
		u.RawQuery = rq.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(302)
	})
	m.Handle("POST "+idpHost+"/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		req := &oauth2test.Request{Method: r.Method, URL: r.URL, Header: r.Header.Clone(), Form: form, Body: string(body)}
		clientID := form.Get("client_id")
		if user, _, ok := r.BasicAuth(); ok {
			clientID, _ = url.QueryUnescape(user)
		}
		out := map[string]any{"token_type": "Bearer", "expires_in": float64(3600)}
		out["access_token"] = m.sign(map[string]any{"sub": "johndoe", "aud": "https://example.com"})
		switch form.Get("grant_type") {
		case "authorization_code":
			m.mu.Lock()
			info := m.codes[form.Get("code")]
			delete(m.codes, form.Get("code"))
			m.mu.Unlock()
			scope := info.scope
			if scope == "" {
				scope = "dummy"
			}
			out["scope"] = scope
			payload := map[string]any{"sub": "johndoe", "aud": clientID}
			if info.nonce != "" {
				payload["nonce"] = info.nonce
			}
			for _, h := range m.takeToken() {
				h(payload, req)
			}
			out["id_token"] = m.sign(payload)
			out["refresh_token"] = bacrypto.RandomUUID()
		case "refresh_token":
			out["scope"] = "dummy"
			payload := map[string]any{"sub": "johndoe", "aud": clientID}
			for _, h := range m.takeToken() {
				h(payload, req)
			}
			out["id_token"] = m.sign(payload)
			out["refresh_token"] = bacrypto.RandomUUID()
		default:
			writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
			return
		}
		for _, h := range m.takeResponse() {
			h(out, req)
		}
		writeJSON(w, 200, out)
	})
	m.Handle("GET "+idpHost+"/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{"sub": "johndoe"}
		status := 200
		for _, h := range m.takeUserinfo() {
			h(&body, &status)
		}
		writeJSON(w, status, body)
	})
	return m
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// sign signs claims with the IdP key (iss/iat/exp/nbf defaults like buildToken).
func (m *mockIdP) sign(claims map[string]any) string {
	c := map[string]any{"iss": idpBase, "nbf": float64(time.Now().Unix())}
	for k, v := range claims {
		c[k] = v
	}
	return m.IDToken(c)
}

// buildToken mirrors issuer.buildToken({ scopesOrTransform }).
func (m *mockIdP) buildToken(claims map[string]any) string { return m.sign(claims) }

func (m *mockIdP) onUserinfo(h userinfoHook, once bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	hookSeq++
	m.userinfo = append(m.userinfo, hookEntry[userinfoHook]{fn: h, once: once, id: hookSeq})
	return hookSeq
}

// userinfoOnce responds once with body (status 200).
func (m *mockIdP) userinfoOnce(body map[string]any) {
	m.onUserinfo(func(b *map[string]any, _ *int) { *b = body }, true)
}

func (m *mockIdP) onTokenSigning(h tokenHook, once bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	hookSeq++
	m.tokenSign = append(m.tokenSign, hookEntry[tokenHook]{fn: h, once: once, id: hookSeq})
	return hookSeq
}

func (m *mockIdP) onResponse(h responseHook) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	hookSeq++
	m.response = append(m.response, hookEntry[responseHook]{fn: h, id: hookSeq})
	return hookSeq
}

func take[T any](list *[]hookEntry[T]) []T {
	var out []T
	var keep []hookEntry[T]
	for _, e := range *list {
		out = append(out, e.fn)
		if !e.once {
			keep = append(keep, e)
		}
	}
	*list = keep
	return out
}

func (m *mockIdP) takeUserinfo() []userinfoHook {
	m.mu.Lock()
	defer m.mu.Unlock()
	return take(&m.userinfo)
}

func (m *mockIdP) takeToken() []tokenHook {
	m.mu.Lock()
	defer m.mu.Unlock()
	return take(&m.tokenSign)
}

func (m *mockIdP) takeResponse() []responseHook {
	m.mu.Lock()
	defer m.mu.Unlock()
	return take(&m.response)
}

const discoveryURL = idpBase + "/.well-known/openid-configuration"

// ---- Better Auth test instance (getTestInstance equivalent) ----

const testSecret = "better-auth-secret-that-is-long-enough-for-validation-test"

type inst struct {
	t    *testing.T
	auth *betterauth.Auth
	logs *logRecorder
}

type logRecorder struct {
	mu      sync.Mutex
	entries []string
}

func (l *logRecorder) add(level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	parts := []string{level, msg}
	for _, a := range args {
		parts = append(parts, jsString2(a))
	}
	l.entries = append(l.entries, strings.Join(parts, " "))
}

func jsString2(a any) string {
	switch t := a.(type) {
	case string:
		return t
	case error:
		return t.Error()
	}
	b, _ := json.Marshal(a)
	return string(b)
}

func (l *logRecorder) Debug(msg string, args ...any) { l.add("debug", msg, args...) }
func (l *logRecorder) Info(msg string, args ...any)  { l.add("info", msg, args...) }
func (l *logRecorder) Warn(msg string, args ...any)  { l.add("warn", msg, args...) }
func (l *logRecorder) Error(msg string, args ...any) { l.add("error", msg, args...) }

func (l *logRecorder) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if strings.Contains(e, s) {
			return true
		}
	}
	return false
}

type instOpts struct {
	disableTestUser bool
	noDatabase      bool
}

func baseConfig(logs *logRecorder) betterauth.Config {
	return betterauth.Config{
		BaseURL:          "http://localhost:3000",
		Secret:           testSecret,
		Database:         memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Logger:           logs,
	}
}

func newInstE(t *testing.T, mutate func(c *betterauth.Config), o instOpts) (*inst, error) {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	logs := &logRecorder{}
	cfg := baseConfig(logs)
	if o.noDatabase {
		cfg.Database = nil
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		return nil, err
	}
	in := &inst{t: t, auth: a, logs: logs}
	if !o.disableTestUser && cfg.Database != nil {
		res := in.client().post("/sign-up/email", map[string]any{"email": "test@test.com", "password": "test123456", "name": "test user"})
		if res.Status != 200 {
			t.Fatalf("test user sign-up: %d %s", res.Status, res.Body)
		}
	}
	return in, nil
}

func newInst(t *testing.T, mutate func(c *betterauth.Config), o ...instOpts) *inst {
	t.Helper()
	var opts instOpts
	if len(o) > 0 {
		opts = o[0]
	}
	in, err := newInstE(t, mutate, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return in
}

func (in *inst) ctx() *betterauth.AuthContext { return in.auth.Context() }

func (in *inst) provider(id string) oauth2.Provider {
	return in.ctx().FindProvider(id)
}

func (in *inst) providerIDs() []string {
	var ids []string
	for _, p := range in.ctx().SocialProviders {
		ids = append(ids, p.ID())
	}
	return ids
}

type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *response) JSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("decode %q: %v", r.Body, err)
	}
	return m
}

func (r *response) location() string { return r.Header.Get("Location") }

func (r *response) setCookie(name string) (value string, attrs map[string]string, ok bool) {
	for _, sc := range r.Header.Values("Set-Cookie") {
		n, v, a := betterauth.ParseSetCookie(sc)
		if n == name {
			value, attrs, ok = v, a, true
		}
	}
	return
}

type client struct {
	in      *inst
	cookies map[string]string
	order   []string
	headers http.Header
}

func (in *inst) client() *client {
	return &client{in: in, cookies: map[string]string{}, headers: http.Header{}}
}

func (c *client) clone() *client {
	n := in2(c)
	for _, k := range c.order {
		n.setCookieValue(k, c.cookies[k])
	}
	return n
}

func in2(c *client) *client { return c.in.client() }

func (c *client) setCookieValue(name, value string) {
	if _, ok := c.cookies[name]; !ok {
		c.order = append(c.order, name)
	}
	c.cookies[name] = value
}

func (c *client) apply(h http.Header) {
	for _, sc := range h.Values("Set-Cookie") {
		n, v, a := betterauth.ParseSetCookie(sc)
		if ma, ok := a["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) {
			delete(c.cookies, n)
			continue
		}
		c.setCookieValue(n, v)
	}
}

func (c *client) cookieHeader() string {
	var parts []string
	for _, k := range c.order {
		if v, ok := c.cookies[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// do sends a request. target is a path below /api/auth or an absolute URL.
func (c *client) do(method, target string, body any, mutate ...func(*http.Request)) *response {
	c.in.t.Helper()
	u := target
	if !strings.HasPrefix(u, "http") {
		u = "http://localhost:3000/api/auth" + target
	}
	var rd io.Reader
	isJSON := false
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
		isJSON = true
	}
	req := httptest.NewRequest(method, u, rd)
	if isJSON {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range c.headers {
		req.Header[k] = vs
	}
	if ch := c.cookieHeader(); ch != "" {
		req.Header.Set("Cookie", ch)
	}
	for _, m := range mutate {
		m(req)
	}
	rec := httptest.NewRecorder()
	c.in.auth.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	c.apply(res.Header)
	return &response{Status: res.StatusCode, Header: res.Header, Body: b}
}

func (c *client) post(path string, body any, mutate ...func(*http.Request)) *response {
	return c.do("POST", path, body, mutate...)
}

func (c *client) get(path string, mutate ...func(*http.Request)) *response {
	return c.do("GET", path, nil, mutate...)
}

// session returns the get-session result (nil when signed out).
func (c *client) session() map[string]any {
	c.in.t.Helper()
	res := c.get("/get-session")
	if res.Status != 200 {
		c.in.t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if string(res.Body) == "null" {
		return nil
	}
	return res.JSON(c.in.t)
}

func sessionUser(s map[string]any) map[string]any {
	u, _ := s["user"].(map[string]any)
	return u
}

// signInSocial posts /sign-in/social and returns the authorization URL.
func (c *client) signInSocial(body map[string]any) (*response, string) {
	c.in.t.Helper()
	res := c.post("/sign-in/social", body)
	if res.Status != 200 {
		return res, ""
	}
	u, _ := res.JSON(c.in.t)["url"].(string)
	return res, u
}

// flowResult is the outcome of simulateOAuthFlow.
type flowResult struct {
	callbackURL string
	res         *response
}

// simulateOAuthFlow follows the authorization URL at the IdP and calls the callback with
// the client's cookies.
func (c *client) simulateOAuthFlow(authURL string) flowResult {
	c.in.t.Helper()
	req, _ := http.NewRequest("GET", authURL, nil)
	res, err := oauth2.HTTPClient.Do(req)
	if err != nil {
		c.in.t.Fatalf("authorize: %v", err)
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	if loc == "" {
		c.in.t.Fatalf("no redirect location from %s (status %d)", authURL, res.StatusCode)
	}
	cb := c.get(loc)
	return flowResult{callbackURL: cb.location(), res: cb}
}

func (in *inst) accounts(userID string) []*betterauth.Account {
	in.t.Helper()
	accs, err := in.ctx().InternalAdapter.FindAccounts(context.Background(), userID)
	if err != nil {
		in.t.Fatal(err)
	}
	return accs
}

func (in *inst) accountsByProvider(providerID string) []map[string]any {
	in.t.Helper()
	recs, err := in.ctx().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: providerID}}})
	if err != nil {
		in.t.Fatal(err)
	}
	var out []map[string]any
	for _, r := range recs {
		out = append(out, r)
	}
	return out
}

func strp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("expected %q to contain %q", s, sub)
	}
}

func mustNotContain(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("expected %q not to contain %q", s, sub)
	}
}

func mustEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func decodeJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		t.Fatalf("not an object: %s", s)
	}
	return o.Map()
}

func queryParam(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func ptrBool(b bool) *bool { return &b }

// genericPlugin is shorthand for a single-config plugin.
func genericPlugin(cfgs ...Config) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		c.Plugins = append(c.Plugins, New(Options{Config: cfgs}))
	}
}

// emailVerifiedOnCreate is databaseHooks.user.create.before => emailVerified: true.
func emailVerifiedOnCreate(c *betterauth.Config) {
	c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
		Before: func(_ context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
			return &betterauth.DBHookResult{Data: adapter.Record{"emailVerified": true}}, nil
		},
	}}}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
