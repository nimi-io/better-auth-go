package scim

// Shared test helpers (the Go equivalents of the upstream test fixtures): an auth instance
// with the memory adapter (betterAuth({ database: memoryAdapter(data) })) or an in-memory
// SQLite database with migrations (getTestInstance / node:sqlite + kysely), a request
// helper mirroring auth.handler(new Request(...)), and direct API calls (auth.api.*).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	_ "modernc.org/sqlite"
)

const (
	testBaseURL    = "http://localhost:3000"
	scimUsersURL   = "/api/auth/scim/v2/Users"
	scimGroupsURL  = "/api/auth/scim/v2/Groups"
	testAuthSecret = "better-auth-secret-that-is-long-enough-for-validation-test"
)

// testEnv is an auth instance with the SCIM plugin.
type testEnv struct {
	t    *testing.T
	auth *betterauth.Auth
	// mem is set for memory-adapter instances.
	mem *memory.DB
	// sqlDB is set for SQLite instances.
	sqlDB *sql.DB
}

type envOptions struct {
	// sqlite selects an in-memory SQLite database (with migrations) instead of memory.
	sqlite bool
	// noTransactions disables native transactions on the SQLite adapter.
	noTransactions bool
	// mutate adjusts the auth config before New.
	mutate func(cfg *betterauth.Config)
	// extraPlugins are registered before the SCIM plugin.
	extraPlugins []*betterauth.Plugin
	// baseURL overrides http://localhost:3000.
	baseURL string
}

// newEnv builds an auth instance with scim.New(opts) using the memory adapter.
func newEnv(t *testing.T, opts Options, eo ...envOptions) *testEnv {
	t.Helper()
	var o envOptions
	if len(eo) > 0 {
		o = eo[0]
	}
	e := &testEnv{t: t}
	base := o.baseURL
	if base == "" {
		base = testBaseURL
	}
	cfg := betterauth.Config{
		BaseURL:   base,
		Secret:    testAuthSecret,
		Logger:    betterauth.NopLogger{},
		RateLimit: &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Plugins:   append(append([]*betterauth.Plugin{}, o.extraPlugins...), New(opts)),
	}
	if o.sqlite {
		conn, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		conn.SetMaxOpenConns(1)
		t.Cleanup(func() { conn.Close() })
		e.sqlDB = conn
		sc := sqladapter.Config{}
		if o.noTransactions {
			sc.Transaction = betterauth.Bool(false)
		}
		cfg.Database = sqladapter.New(conn, sc)
	} else {
		e.mem = memory.NewDB()
		cfg.Database = memory.New(e.mem)
	}
	if o.mutate != nil {
		o.mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("betterauth.New: %v", err)
	}
	e.auth = a
	if o.sqlite {
		if err := a.RunMigrations(context.Background()); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	return e
}

// db is the auth adapter (logical model and field names).
func (e *testEnv) db() adapter.Adapter { return e.auth.Context().Adapter }

// rows lists all rows of a model through the adapter.
func (e *testEnv) rows(model string) []adapter.Record {
	e.t.Helper()
	rs, err := e.db().FindMany(context.Background(), adapter.FindManyInput{Model: model})
	if err != nil {
		e.t.Fatalf("findMany %s: %v", model, err)
	}
	return rs
}

// insert creates a row (forceAllowId) through the adapter.
func (e *testEnv) insert(model string, data adapter.Record) adapter.Record {
	e.t.Helper()
	r, err := e.db().Create(context.Background(), adapter.CreateInput{Model: model, Data: data, ForceAllowID: true})
	if err != nil {
		e.t.Fatalf("create %s: %v", model, err)
	}
	return r
}

// response is an HTTP response.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *response) text() string { return string(r.Body) }

// json decodes the body into a map (nil on failure).
func (r *response) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}

// obj decodes the body preserving key order.
func (r *response) obj() *jsonx.Object {
	v, err := jsonx.Parse(r.Body)
	if err != nil {
		return nil
	}
	o, _ := v.(*jsonx.Object)
	return o
}

// request performs an HTTP request through auth.Handler(). path is relative to the base
// URL origin (e.g. "/api/auth/scim/v2/Users"). body may be nil, a string (sent raw) or a
// JSON-encodable value.
func (e *testEnv) request(method, path string, body any, headers map[string]string) *response {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		case []byte:
			rd = bytes.NewReader(b)
		default:
			enc, err := jsonx.Marshal(b)
			if err != nil {
				e.t.Fatalf("encode body: %v", err)
			}
			rd = bytes.NewReader(enc)
		}
	}
	base := e.auth.Options().BaseURL
	if base == "" {
		base = testBaseURL
	}
	req := httptest.NewRequest(method, strings.TrimRight(base, "/")+path, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.auth.Handler().ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	return &response{Status: res.StatusCode, Header: res.Header, Body: b}
}

// scimHeaders are the usual SCIM request headers for a bearer token ("" omits auth).
func scimHeaders(token string, withBody bool) map[string]string {
	h := map[string]string{"Accept": MediaType}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	if withBody {
		h["Content-Type"] = MediaType
	}
	return h
}

// scim performs a SCIM request with a bearer token; body nil means no body.
func (e *testEnv) scim(method, path, token string, body any) *response {
	e.t.Helper()
	return e.request(method, path, body, scimHeaders(token, body != nil))
}

// call invokes auth.api.<key>. On error it returns the APIError (status/body).
func (e *testEnv) call(key string, in betterauth.CallInput) (*betterauth.CallResult, *betterauth.APIError) {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), key, in)
	if err != nil {
		ae, ok := betterauth.AsAPIError(err)
		if !ok {
			e.t.Fatalf("%s: %v", key, err)
		}
		return res, ae
	}
	return res, nil
}

// callErr invokes auth.api.<key> and returns any error (including non-API errors).
func (e *testEnv) callErr(key string, in betterauth.CallInput) (*betterauth.CallResult, error) {
	return e.auth.API.Call(context.Background(), key, in)
}

// mustCall invokes auth.api.<key> and decodes the JSON result.
func (e *testEnv) mustCall(key string, in betterauth.CallInput) map[string]any {
	e.t.Helper()
	res, ae := e.call(key, in)
	if ae != nil {
		e.t.Fatalf("%s: %d %s", key, ae.StatusCode, string(jsonx.MustMarshal(ae.Body)))
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		e.t.Fatalf("decode %s: %v", key, err)
	}
	return m
}

// bearer returns headers with an Authorization bearer token.
func bearer(token string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	return h
}

// staticConnection is a connection with one bearer credential whose id equals its token.
func staticConnection(id, token string) ConnectionOptions {
	return ConnectionOptions{ID: id, Credentials: []BearerCredential{{Type: "bearer", ID: token, Token: token}}}
}

func errBody(ae *betterauth.APIError) map[string]any {
	if ae == nil || ae.Body == nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(jsonx.MustMarshal(ae.Body), &m)
	return m
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }
