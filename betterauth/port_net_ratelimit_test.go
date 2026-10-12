package betterauth

// Port of packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts (upstream v1.7.7).
//
// Upstream advances time with vi.useFakeTimers()/advanceTimersByTime. Go reads time.Now()
// directly, so pnAdvanceClock emulates "advance the clock by d" by shifting every stored
// rate-limit timestamp back by d (memory store entries and database rows). The limiter
// only compares `now` against those timestamps, so this is equivalent.
//
// Upstream's test client never persists cookies and sends no Origin header; requests are
// made with pnServe (defined in port_net_origin_check_test.go) to mirror that.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

func pnAdvanceClock(t *testing.T, env *testEnv, d time.Duration) {
	t.Helper()
	ms := d.Milliseconds()
	m := env.auth.memoryRL
	m.mu.Lock()
	for k, e := range m.data {
		e.lastRequest -= ms
		e.expiresAt -= ms
		m.data[k] = e
	}
	m.mu.Unlock()
	if env.auth.ctx.RateLimit.Storage != "database" {
		return
	}
	ctx := context.Background()
	ad := env.auth.ctx.Adapter
	rows, err := ad.FindMany(ctx, adapter.FindManyInput{Model: "rateLimit"})
	if err != nil {
		t.Fatalf("find rateLimit rows: %v", err)
	}
	for _, r := range rows {
		last, _ := adapter.ToInt64(r["lastRequest"])
		if _, err := ad.Update(ctx, "rateLimit", []adapter.Where{{Field: "key", Value: r["key"]}},
			adapter.Record{"lastRequest": last - ms}); err != nil {
			t.Fatalf("shift rateLimit row: %v", err)
		}
	}
}

func pnSignIn(t *testing.T, env *testEnv, headers map[string]string) *testResponse {
	t.Helper()
	return pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), headers, pnSignInBody())
}

// pnNoError mirrors `expect(response.error).toBeNull()`.
func pnNoError(t *testing.T, res *testResponse, label string) {
	t.Helper()
	if res.Status >= 400 {
		t.Fatalf("%s: expected no error, got %d %s", label, res.Status, res.Body)
	}
}

func pnRateEnv(t *testing.T, mutate func(c *Config)) *testEnv {
	t.Helper()
	env := newTestEnv(t, mutate)
	pnCreateTestUser(t, env)
	return env
}

func TestPortNetRateLimiter(t *testing.T) {
	env := pnRateEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Window: 10 * time.Second, Max: 20}
	})

	t.Run("should send JSON content type for rate limit responses", func(t *testing.T) {
		env2 := newTestEnv(t, func(c *Config) {
			c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Window: 10 * time.Second, Max: 1}
		})
		h := map[string]string{"x-forwarded-for": "203.0.113.114"}
		first := pnServe(t, env2, "GET", pnURL(env2, "/get-session"), h, nil)
		pnExpectStatus(t, first, 200)
		limited := pnServe(t, env2, "GET", pnURL(env2, "/get-session"), h, nil)
		pnExpectStatus(t, limited, 429)
		if ct := limited.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q", ct)
		}
		if limited.Header.Get("X-Retry-After") == "" {
			t.Fatal("expected x-retry-after")
		}
		var body map[string]any
		if err := json.Unmarshal(limited.Body, &body); err != nil || len(body) != 1 ||
			body["message"] != "Too many requests. Please try again later." {
			t.Fatalf("body = %s", limited.Body)
		}
	})

	t.Run("should return 429 after 3 request for sign-in", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			res := pnSignIn(t, env, nil)
			if i >= 3 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
		}
	})

	t.Run("should reset the limit after the window period", func(t *testing.T) {
		pnAdvanceClock(t, env, 11*time.Second)
		for i := 0; i < 5; i++ {
			res := pnSignIn(t, env, nil)
			if i >= 3 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
		}
	})

	t.Run("should respond the correct retry-after header", func(t *testing.T) {
		pnAdvanceClock(t, env, 3*time.Second)
		res := pnSignIn(t, env, nil)
		if got := res.Header.Get("X-Retry-After"); got != "7" {
			t.Fatalf("X-Retry-After = %q (status %d)", got, res.Status)
		}
	})

	t.Run("should rate limit based on the path", func(t *testing.T) {
		pnExpectStatus(t, pnSignIn(t, env, nil), 429)
		res := pnServe(t, env, "POST", pnURL(env, "/sign-up/email"), nil,
			map[string]any{"email": "new-test@email.com", "password": pnTestPassword, "name": "test"})
		pnNoError(t, res, "sign-up")
	})

	t.Run("non-special-rules limits", func(t *testing.T) {
		for i := 0; i < 25; i++ {
			res := pnServe(t, env, "GET", pnURL(env, "/get-session"), nil, nil)
			if i >= 20 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
		}
	})

	t.Run("query params should be ignored", func(t *testing.T) {
		for i := 0; i < 25; i++ {
			res := pnServe(t, env, "GET", pnURL(env, "/list-sessions?test-query="+strconv.FormatInt(time.Now().UnixNano(), 10)), nil, nil)
			if i >= 20 {
				pnExpectStatus(t, res, 429)
			} else {
				pnExpectStatus(t, res, 401)
			}
		}
	})
}

func TestPortNetRateLimiterAtomicConcurrent(t *testing.T) {
	for _, storage := range []string{"memory", "database"} {
		t.Run(storage+" storage", func(t *testing.T) {
			env := pnRateEnv(t, func(c *Config) {
				c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Storage: storage,
					CustomRules: map[string]CustomRateLimitRule{"/sign-in/email": {Rule: &RateLimitRule{Window: 10 * time.Second, Max: 1}}}}
			})

			t.Run("lets exactly one of two simultaneous requests through", func(t *testing.T) {
				pnAdvanceClock(t, env, 120*time.Second)
				var wg sync.WaitGroup
				statuses := make([]int, 2)
				for i := range statuses {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						statuses[i] = pnSignIn(t, env, nil).Status
					}(i)
				}
				wg.Wait()
				sort.Ints(statuses)
				if statuses[0] != 200 || statuses[1] != 429 {
					t.Fatalf("statuses = %v, want [200 429]", statuses)
				}
			})
			t.Run("resets the count once the window elapses", func(t *testing.T) {
				pnAdvanceClock(t, env, 240*time.Second)
				pnExpectNotStatus(t, pnSignIn(t, env, nil), 429)
				pnExpectStatus(t, pnSignIn(t, env, nil), 429)
				pnAdvanceClock(t, env, 11*time.Second)
				pnExpectNotStatus(t, pnSignIn(t, env, nil), 429)
			})
			t.Run("resets the count at the exact window boundary", func(t *testing.T) {
				pnAdvanceClock(t, env, 360*time.Second)
				pnExpectNotStatus(t, pnSignIn(t, env, nil), 429)
				pnExpectStatus(t, pnSignIn(t, env, nil), 429)
				pnAdvanceClock(t, env, 10*time.Second)
				pnExpectNotStatus(t, pnSignIn(t, env, nil), 429)
			})
		})
	}
}

// pnBackground collects advanced.backgroundTasks so the test can await them.
type pnBackground struct{ wg sync.WaitGroup }

func (b *pnBackground) handler(task func()) {
	b.wg.Add(1)
	go func() { defer b.wg.Done(); task() }()
}

func pnCreateRLRow(t *testing.T, env *testEnv, key string, lastRequest int64) {
	t.Helper()
	if _, err := env.auth.ctx.Adapter.Create(context.Background(), adapter.CreateInput{Model: "rateLimit",
		Data: adapter.Record{"key": key, "count": 1, "lastRequest": lastRequest}}); err != nil {
		t.Fatal(err)
	}
}

func pnFindRLRow(t *testing.T, env *testEnv, key string) adapter.Record {
	t.Helper()
	r, err := env.auth.ctx.Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "rateLimit",
		Where: []adapter.Where{{Field: "key", Value: key}}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPortNetRateLimiterDatabasePruning(t *testing.T) {
	bg := &pnBackground{}
	env := pnRateEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Storage: "database",
			CustomRules: map[string]CustomRateLimitRule{"/get-session": {Rule: &RateLimitRule{Window: 120 * time.Second, Max: 10}}}}
		c.Advanced.BackgroundTasks = bg.handler
	})
	t.Run("keeps active rows from longer configured windows", func(t *testing.T) {
		now := time.Now().UnixMilli()
		longKey := "127.0.0.1|/get-session"
		pnCreateRLRow(t, env, longKey, now-90_000)
		pnCreateRLRow(t, env, "127.0.0.1|/sign-in/email", now-11_000)
		pnSignIn(t, env, nil)
		bg.wg.Wait()
		if pnFindRLRow(t, env, longKey) == nil {
			t.Fatal("active long-window row was pruned")
		}
	})
}

func TestPortNetRateLimiterDatabasePruningDynamicRules(t *testing.T) {
	bg := &pnBackground{}
	env := pnRateEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Storage: "database",
			CustomRules: map[string]CustomRateLimitRule{"/sign-in/email": {Func: func(*http.Request, RateLimitRule) (*RateLimitRule, error) {
				return &RateLimitRule{Window: 120 * time.Second, Max: 10}, nil
			}}}}
		c.Advanced.BackgroundTasks = bg.handler
	})
	t.Run("prunes stale rows using the longest observed dynamic window", func(t *testing.T) {
		now := time.Now().UnixMilli()
		activeKey, staleKey := "127.0.0.1|/dynamic-active", "127.0.0.1|/dynamic-stale"
		pnCreateRLRow(t, env, activeKey, now-90_000)
		pnCreateRLRow(t, env, staleKey, now-130_000)
		pnCreateRLRow(t, env, "127.0.0.1|/sign-in/email", now-130_000)
		pnSignIn(t, env, nil)
		bg.wg.Wait()
		if pnFindRLRow(t, env, activeKey) == nil {
			t.Error("active dynamic-window row (90s old, observed window 120s) was pruned")
		}
		if pnFindRLRow(t, env, staleKey) != nil {
			t.Error("stale dynamic-window row (130s old) was not pruned")
		}
	})
}

// pnGateAdapter blocks DeleteMany until released (vi.spyOn(ctx.adapter, "deleteMany")).
type pnGateAdapter struct {
	adapter.Adapter
	called  chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *pnGateAdapter) DeleteMany(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	if model == "rateLimit" {
		g.once.Do(func() { close(g.called) })
		<-g.release
	}
	return g.Adapter.DeleteMany(ctx, model, where)
}

func TestPortNetRateLimiterCleanupScheduling(t *testing.T) {
	gate := &pnGateAdapter{called: make(chan struct{}), release: make(chan struct{})}
	env := newTestEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Storage: "database", Window: 10 * time.Second, Max: 20}
		inner := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := inner(o)
			if err != nil {
				return nil, err
			}
			gate.Adapter = a
			return gate, nil
		}
	})
	t.Run("awaits expired row cleanup when no background handler is configured", func(t *testing.T) {
		pnCreateRLRow(t, env, "127.0.0.1|/get-session", time.Now().UnixMilli()-11_000)
		done := make(chan struct{})
		go func() {
			pnServe(t, env, "GET", pnURL(env, "/get-session"), nil, nil)
			close(done)
		}()
		select {
		case <-gate.called:
		case <-time.After(5 * time.Second):
			close(gate.release)
			t.Fatal("deleteMany was not called")
		}
		settledBeforeCleanup := false
		select {
		case <-done:
			settledBeforeCleanup = true
		case <-time.After(50 * time.Millisecond):
		}
		close(gate.release)
		<-done
		if settledBeforeCleanup {
			t.Fatal("request settled before cleanup completed")
		}
	})
}

// pnRLSecondaryStorage mirrors createRateLimitSecondaryStorage.
type pnRLSecondaryStorage struct {
	mu    sync.Mutex
	store map[string]string
	exp   map[string]int // ttl in seconds, as upstream records it
}

func newPNRLSecondaryStorage() *pnRLSecondaryStorage {
	return &pnRLSecondaryStorage{store: map[string]string{}, exp: map[string]int{}}
}

func (s *pnRLSecondaryStorage) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.store[key]
	return v, ok && v != "", nil
}

func (s *pnRLSecondaryStorage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = value
	if ttl != 0 {
		s.exp[key] = int(ttl / time.Second)
	}
	return nil
}

func (s *pnRLSecondaryStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
	delete(s.exp, key)
	return nil
}

func (s *pnRLSecondaryStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.store[key]
	delete(s.store, key)
	delete(s.exp, key)
	return v, ok && v != "", nil
}

type pnRLRecord struct {
	Key         string `json:"key"`
	Count       int    `json:"count"`
	LastRequest int64  `json:"lastRequest"`
}

func (s *pnRLSecondaryStorage) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cur *pnRLRecord
	if existing, ok := s.store[key]; ok && existing != "" {
		cur = &pnRLRecord{}
		_ = json.Unmarshal([]byte(existing), cur)
	}
	count := 1
	if cur != nil {
		count = cur.Count + 1
	}
	raw, _ := json.Marshal(pnRLRecord{Key: key, Count: count, LastRequest: time.Now().UnixMilli()})
	s.store[key] = string(raw)
	if cur == nil && ttl != 0 {
		s.exp[key] = int(ttl / time.Second)
	}
	return int64(count), nil
}

func (s *pnRLSecondaryStorage) size() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.store) }

func (s *pnRLSecondaryStorage) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.store[key]
	return ok
}

func (s *pnRLSecondaryStorage) record(key string) (pnRLRecord, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r pnRLRecord
	_ = json.Unmarshal([]byte(s.store[key]), &r)
	ttl, ok := s.exp[key]
	return r, ttl, ok
}

func (s *pnRLSecondaryStorage) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.store))
	for k := range s.store {
		out = append(out, k)
	}
	return out
}

func TestPortNetRateLimiterCustomStorage(t *testing.T) {
	store := newPNRLSecondaryStorage()
	env := pnRateEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(true)}
		c.SecondaryStorage = store
	})
	t.Run("should use custom storage", func(t *testing.T) {
		pnServe(t, env, "GET", pnURL(env, "/get-session"), nil, nil)
		if n := store.size(); n != 3 {
			t.Errorf("store size = %d, want 3 (keys %v)", n, store.keys())
		}
		lastRequest := time.Now().UnixMilli()
		for i := 0; i < 4; i++ {
			res := pnSignIn(t, env, nil)
			rec, ttl, hasTTL := store.record("127.0.0.1|/sign-in/email")
			if rec.LastRequest < lastRequest {
				t.Fatalf("lastRequest went backwards: %d < %d", rec.LastRequest, lastRequest)
			}
			lastRequest = rec.LastRequest
			if i >= 3 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
			if rec.Count != i+1 {
				t.Fatalf("count = %d, want %d", rec.Count, i+1)
			}
			if !hasTTL || ttl != 10 {
				t.Fatalf("ttl = %d (set=%v), want 10", ttl, hasTTL)
			}
		}
	})
}

func TestPortNetRateLimiterCustomRules(t *testing.T) {
	env := pnRateEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Storage: "database",
			CustomRules: map[string]CustomRateLimitRule{
				"/sign-in/*":     {Rule: &RateLimitRule{Window: 10 * time.Second, Max: 2}},
				"/sign-up/email": {Rule: &RateLimitRule{Window: 10 * time.Second, Max: 3}},
				"/get-session":   {Disabled: true},
			}}
	})
	t.Run("should use custom rules", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			res := pnSignIn(t, env, nil)
			if i >= 2 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
		}
		for i := 0; i < 5; i++ {
			res := pnServe(t, env, "POST", pnURL(env, "/sign-up/email"), nil,
				map[string]any{"email": strconv.FormatInt(time.Now().UnixNano(), 10) + "@test.com", "password": pnTestPassword, "name": "test"})
			if i >= 3 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
		}
	})
	t.Run("should use default rules if custom rules are not defined", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			pnNoError(t, pnServe(t, env, "GET", pnURL(env, "/get-session"), nil, nil), strconv.Itoa(i))
		}
	})
	t.Run("should not rate limit if custom rule is false", func(t *testing.T) {
		var last *testResponse
		i := 0
		for ; i < 110; i++ {
			last = pnServe(t, env, "GET", pnURL(env, "/get-session"), nil, nil)
		}
		pnNoError(t, last, "last")
		if i != 110 {
			t.Fatalf("i = %d", i)
		}
	})
}

func TestPortNetRateLimiterDevTestEnvironment(t *testing.T) {
	for _, nodeEnv := range []string{"development", "test"} {
		t.Run("should work in "+nodeEnv+" environment", func(t *testing.T) {
			store := newPNRLSecondaryStorage()
			env := pnRateEnv(t, func(c *Config) {
				t.Setenv("NODE_ENV", nodeEnv)
				c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Window: 10 * time.Second, Max: 3}
				c.SecondaryStorage = store
			})
			for i := 0; i < 4; i++ {
				res := pnSignIn(t, env, nil)
				if i >= 3 {
					pnExpectStatus(t, res, 429)
				} else {
					pnNoError(t, res, strconv.Itoa(i))
				}
			}
			var signInKeys []string
			for _, k := range store.keys() {
				if strings.HasSuffix(k, "/sign-in/email") {
					signInKeys = append(signInKeys, k)
				}
			}
			if len(signInKeys) == 0 || signInKeys[0] != "127.0.0.1|/sign-in/email" {
				t.Fatalf("sign-in keys = %v", signInKeys)
			}
		})
	}
}

// pnLevelLogger records every warn/error call as (level, message), standing in for
// upstream's `logger: { level: "warn", log }`.
type pnLevelLogger struct {
	mu    sync.Mutex
	calls [][2]string
}

func (l *pnLevelLogger) add(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, [2]string{level, msg})
}
func (l *pnLevelLogger) Debug(string, ...any)          {}
func (l *pnLevelLogger) Info(string, ...any)           {}
func (l *pnLevelLogger) Warn(msg string, args ...any)  { l.add("warn", msg) }
func (l *pnLevelLogger) Error(msg string, args ...any) { l.add("error", msg) }

func pnProduction(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	t.Setenv("TEST", "false")
}

func TestPortNetRateLimiterMissingClientIP(t *testing.T) {
	warning := "Rate limiting could not determine a client IP and is falling back to a " +
		"single shared per-path bucket. Ensure your runtime forwards a trusted " +
		"client IP header, then set `advanced.ipAddress.ipAddressHeaders` or " +
		"`advanced.ipAddress.trustedProxies` so the address can be resolved."

	t.Run("should point users to ipAddressHeaders and trustedProxies when no client IP is available outside dev/test", func(t *testing.T) {
		log := &pnLevelLogger{}
		env := pnRateEnv(t, func(c *Config) {
			pnProduction(t)
			c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Window: 10 * time.Second, Max: 3}
			c.Logger = log
		})
		res := pnServe(t, env, "GET", pnURL(env, "/get-session"), nil, nil)
		pnExpectNotStatus(t, res, 429)
		log.mu.Lock()
		defer log.mu.Unlock()
		if len(log.calls) != 1 || log.calls[0] != [2]string{"warn", warning} {
			t.Fatalf("log calls = %q", log.calls)
		}
	})
	t.Run("should fail closed and still enforce the limit when no client IP is available", func(t *testing.T) {
		env := pnRateEnv(t, func(c *Config) {
			pnProduction(t)
			c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Window: 10 * time.Second, Max: 3}
		})
		limited := false
		for i := 0; i < 6; i++ {
			if pnServe(t, env, "GET", pnURL(env, "/get-session"), nil, nil).Status == 429 {
				limited = true
				break
			}
		}
		if !limited {
			t.Fatal("expected requests without a client IP to be limited")
		}
	})
}

func TestPortNetRateLimiterForwardedIPChains(t *testing.T) {
	t.Run("should not key limits by untrusted forwarded chain entries", func(t *testing.T) {
		store := newPNRLSecondaryStorage()
		env := pnRateEnv(t, func(c *Config) {
			pnProduction(t)
			c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Window: 10 * time.Second, Max: 20}
			c.SecondaryStorage = store
		})
		for i := 0; i < 4; i++ {
			res := pnSignIn(t, env, map[string]string{"x-forwarded-for": "198.51.100." + strconv.Itoa(i+20) + ", 10.0.0.5"})
			if i >= 3 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
		}
		if !store.has("no-trusted-ip|/sign-in/email") {
			t.Fatalf("keys = %v", store.keys())
		}
	})
	t.Run("should key the real client when trusted proxies are configured", func(t *testing.T) {
		store := newPNRLSecondaryStorage()
		env := pnRateEnv(t, func(c *Config) {
			pnProduction(t)
			c.RateLimit = &RateLimitConfig{Enabled: Bool(true), Window: 10 * time.Second, Max: 20}
			c.Advanced.IPAddress = &IPAddressConfig{TrustedProxies: []string{"10.0.0.0/8"}}
			c.SecondaryStorage = store
		})
		for i := 0; i < 4; i++ {
			res := pnSignIn(t, env, map[string]string{"x-forwarded-for": "203.0.113." + strconv.Itoa(i+20) + ", 198.51.100.10, 10.0.0.5"})
			if i >= 3 {
				pnExpectStatus(t, res, 429)
			} else {
				pnNoError(t, res, strconv.Itoa(i))
			}
		}
		if !store.has("198.51.100.10|/sign-in/email") || store.has("no-trusted-ip|/sign-in/email") {
			t.Fatalf("keys = %v", store.keys())
		}
	})
}

func TestPortNetRateLimiterIPv6Normalization(t *testing.T) {
	t.Run("should normalize IPv6 addresses to canonical form", func(t *testing.T) {
		seen := map[string]bool{}
		var first string
		for i, ip := range []string{"2001:db8::1", "2001:DB8::1", "2001:0db8::1", "2001:db8:0::1", "2001:0db8:0:0:0:0:0:1"} {
			n := normalizeIP(ip, 0)
			if i == 0 {
				first = n
			}
			seen[n] = true
		}
		if len(seen) != 1 || first != "2001:0db8:0000:0000:0000:0000:0000:0000" {
			t.Fatalf("got %v", seen)
		}
	})
	t.Run("should convert IPv4-mapped IPv6 to IPv4", func(t *testing.T) {
		for _, ip := range []string{"::ffff:192.0.2.1", "::FFFF:192.0.2.1", "::ffff:c000:0201"} {
			pnExpectNorm(t, ip, 0, "192.0.2.1")
		}
	})
	t.Run("should support IPv6 subnet rate limiting", func(t *testing.T) {
		seen := map[string]bool{}
		for _, ip := range []string{"2001:db8:abcd:1234:0000:0000:0000:0001", "2001:db8:abcd:1234:1111:2222:3333:4444", "2001:db8:abcd:1234:ffff:ffff:ffff:ffff"} {
			seen[normalizeIP(ip, 64)] = true
		}
		if len(seen) != 1 || !seen["2001:0db8:abcd:1234:0000:0000:0000:0000"] {
			t.Fatalf("got %v", seen)
		}
	})
	t.Run("should rate limit different IPv6 subnets separately", func(t *testing.T) {
		a1, a2 := normalizeIP("2001:db8:abcd:1111::1", 64), normalizeIP("2001:db8:abcd:1111::2", 64)
		b1, b2 := normalizeIP("2001:db8:abcd:2222::1", 64), normalizeIP("2001:db8:abcd:2222::2", 64)
		if a1 != a2 || b1 != b2 || a1 == b1 {
			t.Fatalf("got %s %s %s %s", a1, a2, b1, b2)
		}
	})
	t.Run("should handle localhost IPv6 addresses", func(t *testing.T) {
		pnExpectNorm(t, "::1", 0, "0000:0000:0000:0000:0000:0000:0000:0000")
	})
	t.Run("should handle link-local IPv6 addresses", func(t *testing.T) {
		pnExpectNorm(t, "fe80::1", 0, "fe80:0000:0000:0000:0000:0000:0000:0000")
	})
	t.Run("IPv6 subnet should not affect IPv4 addresses", func(t *testing.T) {
		pnExpectNorm(t, "192.168.1.1", 64, "192.168.1.1")
	})
}
