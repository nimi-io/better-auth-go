package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

const (
	testBaseURL = "http://localhost:3000"
	testOrigin  = "http://localhost:3000"
	testSecret  = "test-secret-that-is-long-enough-for-tests-1234567890"
)

// instance mirrors getTestInstance: an Auth with the passkey plugin, a memory database
// and a pre-created test user (test@test.com / test123456).
type instance struct {
	t    *testing.T
	auth *betterauth.Auth
	db   *memory.DB
}

func newInstance(t *testing.T, opts Options, mutate ...func(c *betterauth.Config)) *instance {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	mdb := memory.NewDB()
	cfg := betterauth.Config{
		BaseURL:          testBaseURL,
		Secret:           testSecret,
		Database:         memory.New(mdb),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Plugins:          []*betterauth.Plugin{New(opts)},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ti := &instance{t: t, auth: a, db: mdb}
	if _, err := a.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Name: "test user", Email: "test@test.com", Password: "test123456"}, nil); err != nil {
		t.Fatalf("sign up test user: %v", err)
	}
	return ti
}

func (ti *instance) ctx() *betterauth.AuthContext { return ti.auth.Context() }

// applyCookies merges Set-Cookie headers into the Cookie request header (cookieSetter).
func applyCookies(h http.Header, setCookies []string) {
	jar := map[string]string{}
	var order []string
	for _, part := range strings.Split(h.Get("Cookie"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if _, ok := jar[k]; !ok {
			order = append(order, k)
		}
		jar[k] = v
	}
	for _, sc := range setCookies {
		name, value, _ := betterauth.ParseSetCookie(sc)
		if _, ok := jar[name]; !ok {
			order = append(order, name)
		}
		jar[name] = value
	}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, k+"="+jar[k])
	}
	h.Set("Cookie", strings.Join(parts, "; "))
}

// signIn signs a user in and returns headers carrying the session cookie.
func (ti *instance) signIn(email, password string) (http.Header, map[string]any) {
	ti.t.Helper()
	res, err := ti.auth.API.SignInEmail(context.Background(), email, password, nil, nil)
	if err != nil {
		ti.t.Fatalf("sign in: %v", err)
	}
	var out map[string]any
	if err := res.Decode(&out); err != nil {
		ti.t.Fatal(err)
	}
	h := http.Header{}
	applyCookies(h, res.Headers.Values("Set-Cookie"))
	user, _ := out["user"].(map[string]any)
	return h, user
}

func (ti *instance) signInWithTestUser() (http.Header, map[string]any) {
	return ti.signIn("test@test.com", "test123456")
}

func (ti *instance) signUpAndIn(email, password, name string) (http.Header, map[string]any) {
	ti.t.Helper()
	if _, err := ti.auth.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Name: name, Email: email, Password: password}, nil); err != nil {
		ti.t.Fatalf("sign up: %v", err)
	}
	return ti.signIn(email, password)
}

type httpResult struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *httpResult) JSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("decode %q: %v", r.Body, err)
	}
	return m
}

// fetch performs an HTTP request through the handler (client.$fetch / customFetchImpl).
// When setCookie is true, Set-Cookie headers are merged into h (onResponse: cookieSetter).
func (ti *instance) fetch(method, path string, h http.Header, query url.Values, body any, setCookie bool) *httpResult {
	ti.t.Helper()
	u := testBaseURL + "/api/auth" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, u, rd)
	for k, vs := range h {
		req.Header[k] = append([]string(nil), vs...)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if req.Header.Get("Origin") == "" && method != http.MethodGet {
		req.Header.Set("Origin", testOrigin)
	}
	rec := httptest.NewRecorder()
	ti.auth.Handler().ServeHTTP(rec, req)
	res := &httpResult{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
	if setCookie {
		applyCookies(h, rec.Header().Values("Set-Cookie"))
	}
	return res
}

// call is auth.api.<key>(...).
func (ti *instance) call(key string, h http.Header, body any, query map[string]any) (map[string]any, *betterauth.CallResult, error) {
	ti.t.Helper()
	if h == nil {
		h = http.Header{}
	}
	res, err := ti.auth.API.Call(context.Background(), key, betterauth.CallInput{Headers: h.Clone(), Body: body, Query: query})
	if err != nil {
		return nil, res, err
	}
	var out map[string]any
	b, _ := res.JSON()
	_ = json.Unmarshal(b, &out)
	return out, res, nil
}

func (ti *instance) callList(key string, h http.Header) []map[string]any {
	ti.t.Helper()
	res, err := ti.auth.API.Call(context.Background(), key, betterauth.CallInput{Headers: h.Clone()})
	if err != nil {
		ti.t.Fatalf("%s: %v", key, err)
	}
	var out []map[string]any
	if err := res.Decode(&out); err != nil {
		ti.t.Fatal(err)
	}
	return out
}

func (ti *instance) createPasskey(data adapter.Record) adapter.Record {
	ti.t.Helper()
	row, err := ti.ctx().Adapter.Create(context.Background(), adapter.CreateInput{Model: "passkey", Data: data})
	if err != nil {
		ti.t.Fatal(err)
	}
	return row
}

func (ti *instance) findPasskeys(where ...adapter.Where) []adapter.Record {
	ti.t.Helper()
	rows, err := ti.ctx().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "passkey", Where: where})
	if err != nil {
		ti.t.Fatal(err)
	}
	return rows
}

func mockPasskey(userID, credentialID, name, transports string) adapter.Record {
	return adapter.Record{
		"userId": userID, "publicKey": "mockPublicKey", "name": name, "counter": 0,
		"deviceType": "singleDevice", "credentialID": credentialID, "createdAt": time.Now(),
		"backedUp": false, "transports": transports, "aaguid": "mockAAGUID",
	}
}

// ---- verifier mocks (vi.mock("@simplewebauthn/server")) ----

type verifierMocks struct {
	mu        sync.Mutex
	regCalls  atomic.Int32
	authCalls atomic.Int32
	reg       func(VerifyRegistrationInput) (*VerifiedRegistrationResponse, error)
	auth      func(VerifyAuthenticationInput) (*VerifiedAuthenticationResponse, error)
}

// mockVerifiers replaces the WebAuthn verifiers until the test ends. Unconfigured mocks
// return (nil, nil), like a reset vi.fn().
func mockVerifiers(t *testing.T) *verifierMocks {
	m := &verifierMocks{}
	origReg, origAuth := verifyRegistration, verifyAuthentication
	verifyRegistration = func(in VerifyRegistrationInput) (*VerifiedRegistrationResponse, error) {
		m.regCalls.Add(1)
		m.mu.Lock()
		f := m.reg
		m.mu.Unlock()
		if f == nil {
			return nil, nil
		}
		return f(in)
	}
	verifyAuthentication = func(in VerifyAuthenticationInput) (*VerifiedAuthenticationResponse, error) {
		m.authCalls.Add(1)
		m.mu.Lock()
		f := m.auth
		m.mu.Unlock()
		if f == nil {
			return nil, nil
		}
		return f(in)
	}
	t.Cleanup(func() { verifyRegistration, verifyAuthentication = origReg, origAuth })
	return m
}

func (m *verifierMocks) setReg(v *VerifiedRegistrationResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reg = func(VerifyRegistrationInput) (*VerifiedRegistrationResponse, error) { return v, nil }
}

func (m *verifierMocks) setAuth(v *VerifiedAuthenticationResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auth = func(VerifyAuthenticationInput) (*VerifiedAuthenticationResponse, error) { return v, nil }
}

func (m *verifierMocks) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reg, m.auth = nil, nil
	m.regCalls.Store(0)
	m.authCalls.Store(0)
}

var mockRegistrationResponse = map[string]any{
	"id":       "credential-id",
	"response": map[string]any{"transports": []any{"internal"}},
}

func buildRegistrationVerification(aaguid, credentialID string) *VerifiedRegistrationResponse {
	return &VerifiedRegistrationResponse{Verified: true, RegistrationInfo: &RegistrationInfo{
		AAGUID: aaguid, CredentialDeviceType: "singleDevice", CredentialBackedUp: false,
		Credential: RegistrationCredential{ID: credentialID, PublicKey: []byte{1, 2, 3}, Counter: 0},
	}}
}

var mockRegistrationVerification = buildRegistrationVerification("test-aaguid", "credential-id")

func mockAuthenticationBody(id string) map[string]any {
	return map[string]any{"response": map[string]any{
		"id": id, "rawId": id,
		"response": map[string]any{
			"clientDataJSON": "mockClientDataJSON", "authenticatorData": "mockAuthenticatorData",
			"signature": "mockSignature", "userHandle": "mockUserHandle",
		},
		"type": "public-key", "clientExtensionResults": map[string]any{},
	}}
}

func apiErr(t *testing.T, err error) *betterauth.APIError {
	t.Helper()
	e, ok := betterauth.AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %v", err)
	}
	return e
}

func expectAPIError(t *testing.T, err error, status, code string) {
	t.Helper()
	e := apiErr(t, err)
	if e.Status != status || (code != "" && e.Code() != code) {
		t.Fatalf("expected %s/%s, got %s/%s (%s)", status, code, e.Status, e.Code(), e.Message())
	}
}
