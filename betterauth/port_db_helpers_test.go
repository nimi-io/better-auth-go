package betterauth

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
)

// ---- secondary storage (createStringSecondaryStorage upstream) ----

// pdStorage mirrors the upstream test helper createStringSecondaryStorage(store, ttlStore):
// values are JSON strings, TTLs (in whole seconds) are recorded per key.
type pdStorage struct {
	mu   sync.Mutex
	data map[string]string
	ttl  map[string]int
	// ttlLog captures every TTL passed to Set (capturedTTLs upstream).
	ttlLog []int
	// failSet makes Set fail.
	failSet error
	// failGet makes Get fail for the keys it returns an error for.
	failGet func(key string) error
	// getAndDeleteKeys records GetAndDelete calls.
	getAndDeleteKeys []string
}

func newPDStorage() *pdStorage {
	return &pdStorage{data: map[string]string{}, ttl: map[string]int{}}
}

func (s *pdStorage) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failGet != nil {
		if err := s.failGet(key); err != nil {
			return "", false, err
		}
	}
	v, ok := s.data[key]
	// `store.get(key) || null`
	return v, ok && v != "", nil
}

func (s *pdStorage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSet != nil {
		return s.failSet
	}
	s.data[key] = value
	secs := int(ttl / time.Second)
	s.ttl[key] = secs
	s.ttlLog = append(s.ttlLog, secs)
	return nil
}

func (s *pdStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	delete(s.ttl, key)
	return nil
}

func (s *pdStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getAndDeleteKeys = append(s.getAndDeleteKeys, key)
	v, ok := s.data[key]
	delete(s.data, key)
	delete(s.ttl, key)
	return v, ok && v != "", nil
}

func (s *pdStorage) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cur int64
	if v, ok := s.data[key]; ok {
		_ = json.Unmarshal([]byte(v), &cur)
	}
	cur++
	b, _ := json.Marshal(cur)
	s.data[key] = string(b)
	if cur == 1 && ttl > 0 {
		s.ttl[key] = int(ttl / time.Second)
	}
	return cur, nil
}

func (s *pdStorage) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[key]
	return ok
}

func (s *pdStorage) raw(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok
}

func (s *pdStorage) ttlOf(key string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.ttl[key]
	return v, ok
}

func (s *pdStorage) put(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
}

func (s *pdStorage) del(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
}

func (s *pdStorage) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}

func (s *pdStorage) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.data {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *pdStorage) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string]string{}
}

func (s *pdStorage) lastTTL() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ttlLog) == 0 {
		return 0, false
	}
	return s.ttlLog[len(s.ttlLog)-1], true
}

func (s *pdStorage) resetTTLLog() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttlLog = nil
}

// ---- auth construction (init(opts) / getTestInstance upstream) ----

// pdNewAuth builds an Auth without an HTTP server (the `init(opts)` calls upstream).
func pdNewAuth(t *testing.T, cfg Config) *Auth {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	if cfg.Secret == "" {
		cfg.Secret = testSecret
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:3000"
	}
	if cfg.Logger == nil {
		cfg.Logger = NopLogger{}
	}
	if cfg.Database == nil {
		cfg.Database = memory.New(memory.NewDB())
	}
	if cfg.EmailAndPassword == nil {
		cfg.EmailAndPassword = &EmailAndPasswordConfig{Enabled: true}
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func pdIA(a *Auth) *InternalAdapter { return a.Context().InternalAdapter }

// pdWithEndpoint mirrors runWithEndpointContext({ context }, fn).
func pdWithEndpoint(a *Auth) context.Context {
	return context.WithValue(context.Background(), endpointCtxKey{}, &EndpointContext{Auth: a.Context()})
}

var pdTestSource = UserInfoSource{Method: "test"}

func pdCreateUser(t *testing.T, ia *InternalAdapter, name, email string) *User {
	t.Helper()
	u, err := ia.CreateUser(context.Background(), adapter.Record{"name": name, "email": email}, pdTestSource)
	if err != nil || u == nil {
		t.Fatalf("createUser: %v %v", u, err)
	}
	return u
}

func pdCreateSession(t *testing.T, ia *InternalAdapter, userID string) *Session {
	t.Helper()
	s, err := ia.CreateSession(context.Background(), userID, nil)
	if err != nil || s == nil {
		t.Fatalf("createSession: %v %v", s, err)
	}
	return s
}

// ---- hook call recorder (vi.fn upstream) ----

type pdCalls struct {
	mu    sync.Mutex
	calls []adapter.Record
	ctxs  []context.Context
}

func (c *pdCalls) record(ctx context.Context, data adapter.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, data)
	c.ctxs = append(c.ctxs, ctx)
}

func (c *pdCalls) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func (c *pdCalls) at(i int) (adapter.Record, context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[i], c.ctxs[i]
}

func (c *pdCalls) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls, c.ctxs = nil, nil
}

// ---- JSON helpers ----

func pdJSON(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return v
}

func pdToMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	return m
}

// pdMatchObject asserts got contains every key of want with an equal value (toMatchObject).
func pdMatchObject(t *testing.T, label string, got, want map[string]any) {
	t.Helper()
	for k, wv := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("%s: missing key %q (want %v); got %v", label, k, wv, got)
			continue
		}
		if !reflect.DeepEqual(gv, wv) {
			t.Errorf("%s: key %q = %#v, want %#v", label, k, gv, wv)
		}
	}
}

type pdActiveRef struct {
	Token     string  `json:"token"`
	ExpiresAt float64 `json:"expiresAt"`
}

func pdActiveList(t *testing.T, st *pdStorage, userID string) ([]pdActiveRef, bool) {
	t.Helper()
	raw, ok := st.raw("active-sessions-" + userID)
	if !ok {
		return nil, false
	}
	var list []pdActiveRef
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatalf("parse active list %q: %v", raw, err)
	}
	return list, true
}

// pdISO formats like JavaScript Date#toJSON.
func pdISO(tm time.Time) string { return tm.UTC().Format("2006-01-02T15:04:05.000Z") }

// ---- adapters ----

// pdUniqueIDAdapter enforces primary-key uniqueness on create, as the SQLite database the
// upstream tests run against does (the memory adapters, Go and TS, do not).
type pdUniqueIDAdapter struct {
	adapter.Adapter
	mu *sync.Mutex
}

func (u pdUniqueIDAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if id, ok := in.Data["id"]; ok && in.ForceAllowID && id != nil {
		existing, err := u.Adapter.FindOne(ctx, adapter.FindOneInput{Model: in.Model, Where: []adapter.Where{{Field: "id", Value: id}}})
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, errors.New("UNIQUE constraint failed: " + in.Model + ".id")
		}
	}
	return u.Adapter.Create(ctx, in)
}

func (u pdUniqueIDAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return u.Adapter.Transaction(ctx, func(c context.Context, tx adapter.Adapter) error {
		return fn(c, pdUniqueIDAdapter{Adapter: tx, mu: u.mu})
	})
}

func pdUniqueIDFactory(inner adapter.Factory) adapter.Factory {
	return func(o adapter.Options) (adapter.Adapter, error) {
		a, err := inner(o)
		if err != nil {
			return nil, err
		}
		return pdUniqueIDAdapter{Adapter: a, mu: &sync.Mutex{}}, nil
	}
}

// pdSpyAdapter records adapter.delete calls (vi.spyOn(adapter, "delete")).
type pdSpyAdapter struct {
	adapter.Adapter
	mu      sync.Mutex
	deletes []string
}

func (s *pdSpyAdapter) Delete(ctx context.Context, model string, where []adapter.Where) error {
	s.mu.Lock()
	s.deletes = append(s.deletes, model)
	s.mu.Unlock()
	return s.Adapter.Delete(ctx, model, where)
}
