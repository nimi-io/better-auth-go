package deviceauthorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// Test helpers mirroring upstream's getTestInstance: a SQLite database (with migrations,
// so unique indexes are enforced), a test user, and direct API calls.

const (
	testUserEmail    = "test@test.com"
	testUserPassword = "test123456"
)

type hookedAdapter struct {
	adapter.Adapter
	create       func(ctx context.Context, in adapter.CreateInput) (adapter.Record, error)
	findOne      func(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error)
	incrementOne func(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error)
}

// PlanMigrations exposes the wrapped adapter's migrator.
func (h *hookedAdapter) PlanMigrations(ctx context.Context, schema *db.Schema) (*adapter.MigrationPlan, error) {
	m, ok := adapter.AsMigrator(h.Adapter)
	if !ok {
		return nil, adapter.ErrMigrationsNotSupported
	}
	return m.PlanMigrations(ctx, schema)
}

func (h *hookedAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if h.create != nil {
		return h.create(ctx, in)
	}
	return h.Adapter.Create(ctx, in)
}

func (h *hookedAdapter) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	if h.findOne != nil {
		return h.findOne(ctx, in)
	}
	return h.Adapter.FindOne(ctx, in)
}

func (h *hookedAdapter) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	if h.incrementOne != nil {
		return h.incrementOne(ctx, in)
	}
	return h.Adapter.IncrementOne(ctx, in)
}

type testEnv struct {
	t    *testing.T
	auth *betterauth.Auth
	db   *hookedAdapter // the adapter (with optional hooks)
	base adapter.Adapter
	srv  *httptest.Server
	user map[string]any
}

type envOptions struct {
	disableTestUser bool
	mutate          func(c *betterauth.Config)
}

func newEnv(t *testing.T, opts Options, eo ...envOptions) *testEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	var o envOptions
	if len(eo) > 0 {
		o = eo[0]
	}
	env := &testEnv{t: t}
	conn := testdb.SQLite(t)
	base := sqladapter.New(conn, sqladapter.Config{})
	factory := func(ao adapter.Options) (adapter.Adapter, error) {
		a, err := base(ao)
		if err != nil {
			return nil, err
		}
		env.base = a
		env.db = &hookedAdapter{Adapter: a}
		return env.db, nil
	}
	mux := http.NewServeMux()
	env.srv = httptest.NewServer(mux)
	t.Cleanup(env.srv.Close)
	cfg := betterauth.Config{
		BaseURL:          "http://localhost:3000",
		Secret:           "test-secret-that-is-long-enough-for-tests-1234567890",
		Database:         factory,
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Plugins:          []*betterauth.Plugin{New(opts)},
	}
	if o.mutate != nil {
		o.mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.RunMigrations(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	env.auth = a
	mux.Handle("/api/auth/", a.Handler())
	if !o.disableTestUser {
		env.signUp(testUserEmail, testUserPassword, "test user")
	}
	return env
}

// call invokes auth.api.<key>. The second result is the API error (nil on success).
func (e *testEnv) call(key string, in betterauth.CallInput) (map[string]any, *betterauth.APIError) {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), key, in)
	if err != nil {
		apiErr, ok := betterauth.AsAPIError(err)
		if !ok {
			e.t.Fatalf("%s: %v", key, err)
		}
		return nil, apiErr
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		e.t.Fatalf("%s decode: %v", key, err)
	}
	return m, nil
}

func (e *testEnv) mustCall(key string, in betterauth.CallInput) map[string]any {
	e.t.Helper()
	m, err := e.call(key, in)
	if err != nil {
		e.t.Fatalf("%s failed: %d %v", key, err.StatusCode, errBody(err))
	}
	return m
}

func errBody(err *betterauth.APIError) map[string]any {
	if err == nil || err.Body == nil {
		return nil
	}
	b, _ := json.Marshal(err.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// expectOAuthError asserts an error with body.error == code (and description when set).
func expectOAuthError(t *testing.T, err *betterauth.APIError, code, description string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got success", code)
	}
	body := errBody(err)
	if body["error"] != code {
		t.Fatalf("expected error %q, got %v (status %d)", code, body, err.StatusCode)
	}
	if description != "" && body["error_description"] != description {
		t.Fatalf("expected error_description %q, got %q", description, body["error_description"])
	}
}

func (e *testEnv) signUp(email, password, name string) {
	e.t.Helper()
	e.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": email, "password": password, "name": name}})
}

// signIn returns request headers carrying the session cookie and the signed-in user.
func (e *testEnv) signIn(email, password string) (http.Header, map[string]any) {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), "signInEmail", betterauth.CallInput{
		Body: map[string]any{"email": email, "password": password}})
	if err != nil {
		e.t.Fatalf("sign in: %v", err)
	}
	var cookies []string
	for _, sc := range res.Headers.Values("Set-Cookie") {
		name, value, _ := betterauth.ParseSetCookie(sc)
		cookies = append(cookies, name+"="+value)
	}
	h := http.Header{}
	h.Set("Cookie", strings.Join(cookies, "; "))
	var m map[string]any
	_ = res.Decode(&m)
	user, _ := m["user"].(map[string]any)
	return h, user
}

func (e *testEnv) signInWithTestUser() (http.Header, map[string]any) {
	return e.signIn(testUserEmail, testUserPassword)
}

func (e *testEnv) deviceCode(body map[string]any) map[string]any {
	e.t.Helper()
	return e.mustCall("deviceCode", betterauth.CallInput{Body: body})
}

func tokenBody(deviceCode, clientID string) map[string]any {
	return map[string]any{"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": deviceCode, "client_id": clientID}
}

func (e *testEnv) findDeviceCode(field, value string) adapter.Record {
	e.t.Helper()
	rec, err := e.base.FindOne(context.Background(), adapter.FindOneInput{Model: "deviceCode", Where: []adapter.Where{{Field: field, Value: value}}})
	if err != nil {
		e.t.Fatal(err)
	}
	return rec
}

func (e *testEnv) updateDeviceCode(deviceCode string, update adapter.Record) {
	e.t.Helper()
	if _, err := e.base.Update(context.Background(), "deviceCode", []adapter.Where{{Field: "deviceCode", Value: deviceCode}}, update); err != nil {
		e.t.Fatal(err)
	}
}

func (e *testEnv) handler(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.auth.Handler().ServeHTTP(rec, req)
	return rec
}
