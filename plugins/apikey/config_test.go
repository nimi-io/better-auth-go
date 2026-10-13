package apikey

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// describe("multiple configurations") of api-key.test.ts.
func TestAPIKeyMultipleConfigurations(t *testing.T) {
	inst := newInstance(t, Options{Configurations: []Configuration{
		{ConfigID: "public-api", DefaultPrefix: "pub_", RateLimit: &RateLimit{Enabled: Bool(true), MaxRequests: Float(100), TimeWindow: Float(60000)}},
		{ConfigID: "internal-api", DefaultPrefix: "int_", RateLimit: &RateLimit{Enabled: Bool(true), MaxRequests: Float(1000), TimeWindow: Float(60000)}},
		{ConfigID: "default", DefaultPrefix: "def_"},
	}}, nil)

	t.Run("should create API key with specific configId", func(t *testing.T) {
		s := inst.signInWithTestUser()
		pub := inst.createKey(map[string]any{"configId": "public-api", "userId": s.userID}, nil)
		eq(t, pub["configId"], "public-api")
		eq(t, pub["prefix"], "pub_")
		eq(t, pub["rateLimitMax"], float64(100))
		in := inst.createKey(map[string]any{"configId": "internal-api", "userId": s.userID}, nil)
		eq(t, in["configId"], "internal-api")
		eq(t, in["prefix"], "int_")
		eq(t, in["rateLimitMax"], float64(1000))
	})

	t.Run("should use default config when no configId is provided", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"userId": s.userID}, nil)
		eq(t, k["configId"], "default")
		eq(t, k["prefix"], "def_")
	})

	t.Run("should list keys filtered by configId", func(t *testing.T) {
		s := inst.signInWithTestUser()
		for _, c := range []string{"public-api", "internal-api", "default"} {
			inst.createKey(map[string]any{"configId": c, "userId": s.userID}, nil)
		}
		all := inst.mustCall("listApiKeys", nil, s.headers)
		if len(all["apiKeys"].([]any)) < 3 {
			t.Fatal("expected at least 3 keys")
		}
		for _, c := range []string{"public-api", "internal-api"} {
			r := expectOK(t, inst.clientList(q("configId", c), s.headers))
			for _, k := range r["apiKeys"].([]any) {
				eq(t, obj(k)["configId"], c)
			}
		}
	})

	t.Run("should verify key and apply correct config rate limits", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"configId": "public-api", "userId": s.userID}, nil)
		r := inst.verify(map[string]any{"configId": "public-api", "key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["configId"], "public-api")
		eq(t, obj(r["key"])["rateLimitMax"], float64(100))
	})

	// @see https://github.com/better-auth/better-auth/issues/9779
	t.Run("verify scoping by configId", func(t *testing.T) {
		t.Run("should verify a non-default key when configId is omitted", func(t *testing.T) {
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{"configId": "public-api", "userId": s.userID}, nil)
			r := inst.verify(map[string]any{"key": k["key"]})
			eq(t, r["valid"], true)
			eq(t, obj(r["key"])["configId"], "public-api")
		})
		t.Run("should still verify a default key when configId is omitted", func(t *testing.T) {
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{"userId": s.userID}, nil)
			r := inst.verify(map[string]any{"key": k["key"]})
			eq(t, r["valid"], true)
			eq(t, obj(r["key"])["configId"], "default")
		})
		t.Run("should reject a key when scoped to a different configId", func(t *testing.T) {
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{"configId": "public-api", "userId": s.userID}, nil)
			r := inst.verify(map[string]any{"configId": "internal-api", "key": k["key"]})
			eq(t, r["valid"], false)
			eq(t, errCode(r), "INVALID_API_KEY")
		})
		t.Run("should apply the key's own config when configId is omitted", func(t *testing.T) {
			in := newInstance(t, Options{Configurations: []Configuration{
				{ConfigID: "limited", DefaultPrefix: "lim_", RateLimit: &RateLimit{Enabled: Bool(true), MaxRequests: Float(1), TimeWindow: Float(60000)}},
				{ConfigID: "default", DefaultPrefix: "def_", RateLimit: &RateLimit{Enabled: Bool(false)}},
			}}, nil)
			s := in.signInWithTestUser()
			k := in.createKey(map[string]any{"configId": "limited", "userId": s.userID}, nil)
			eq(t, in.verify(map[string]any{"key": k["key"]})["valid"], true)
			r := in.verify(map[string]any{"key": k["key"]})
			eq(t, r["valid"], false)
			eq(t, errCode(r), "RATE_LIMITED")
		})
		t.Run("should run the key's own customAPIKeyValidator when configId is omitted", func(t *testing.T) {
			in := newInstance(t, Options{Configurations: []Configuration{
				{ConfigID: "guarded", DefaultPrefix: "grd_", CustomAPIKeyValidator: func(*betterauth.EndpointContext, string) (bool, error) { return false, nil }},
				{ConfigID: "default", DefaultPrefix: "def_"},
			}}, nil)
			s := in.signInWithTestUser()
			k := in.createKey(map[string]any{"configId": "guarded", "userId": s.userID}, nil)
			r := in.verify(map[string]any{"key": k["key"]})
			eq(t, r["valid"], false)
			eq(t, errCode(r), "KEY_NOT_FOUND")
		})
		t.Run("should not apply the default config validator to a non-default key", func(t *testing.T) {
			in := newInstance(t, Options{Configurations: []Configuration{
				{ConfigID: "default", DefaultPrefix: "def_", CustomAPIKeyValidator: func(*betterauth.EndpointContext, string) (bool, error) { return false, nil }},
				{ConfigID: "open", DefaultPrefix: "opn_"},
			}}, nil)
			s := in.signInWithTestUser()
			k := in.createKey(map[string]any{"configId": "open", "userId": s.userID}, nil)
			r := in.verify(map[string]any{"key": k["key"]})
			eq(t, r["valid"], true)
			eq(t, obj(r["key"])["configId"], "open")
		})
	})

	t.Run("should get key and resolve correct config", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"configId": "internal-api", "userId": s.userID}, nil)
		r, e := inst.getKey(str(k["id"]), "internal-api", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, r["configId"], "internal-api")
		eq(t, r["prefix"], "int_")
	})

	t.Run("should update key while preserving configId", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"configId": "public-api", "name": "original-name", "userId": s.userID}, nil)
		u := inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "name": "updated-name", "configId": "public-api"}, s.headers)
		eq(t, u["configId"], "public-api")
		eq(t, u["name"], "updated-name")
	})

	t.Run("should delete key from specific config", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"configId": "internal-api", "userId": s.userID}, nil)
		d := inst.mustCall("deleteApiKey", map[string]any{"keyId": k["id"], "configId": "internal-api"}, s.headers)
		eq(t, d["success"], true)
		if _, e := inst.getKey(str(k["id"]), "internal-api", s.headers); e == nil {
			t.Fatal("Should have thrown an error")
		}
	})

	expectPanic := func(t *testing.T, want string, fn func()) {
		t.Helper()
		defer func() {
			r := recover()
			if r == nil || !strings.Contains(r.(error).Error(), want) {
				t.Fatalf("expected panic containing %q, got %v", want, r)
			}
		}()
		fn()
	}
	t.Run("should throw error when configId array has non-unique configIds", func(t *testing.T) {
		expectPanic(t, "configId must be unique", func() {
			New(Options{Configurations: []Configuration{{ConfigID: "duplicate"}, {ConfigID: "duplicate"}}})
		})
	})
	t.Run("should throw error when configId is missing in array config", func(t *testing.T) {
		expectPanic(t, "configId is required", func() {
			New(Options{Configurations: []Configuration{{ConfigID: "valid"}, {}}})
		})
	})
}

// describe("verify should not write back stale state").
func TestVerifyShouldNotWriteBackStaleState(t *testing.T) {
	var mu sync.Mutex
	var onValidate func()
	validator := func(*betterauth.EndpointContext, string) (bool, error) {
		mu.Lock()
		fn := onValidate
		onValidate = nil
		mu.Unlock()
		if fn != nil {
			fn()
		}
		return true, nil
	}
	set := func(fn func()) { mu.Lock(); onValidate = fn; mu.Unlock() }

	t.Run("database storage", func(t *testing.T) {
		inst := newInstance(t, Options{Configuration: Configuration{CustomAPIKeyValidator: validator}}, nil)
		t.Run("should not re-enable a key disabled during verification", func(t *testing.T) {
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{}, s.headers)
			set(func() { inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "enabled": false}, s.headers) })
			eq(t, inst.verify(map[string]any{"key": k["key"]})["valid"], true)
			stored, e := inst.getKey(str(k["id"]), "", s.headers)
			if e != nil {
				t.Fatal(e)
			}
			eq(t, stored["enabled"], false)
		})
	})

	t.Run("secondary storage", func(t *testing.T) {
		store := newMapStorage()
		inst := newInstance(t, Options{Configuration: Configuration{Storage: StorageSecondary, CustomAPIKeyValidator: validator}},
			func(c *betterauth.Config) { c.SecondaryStorage = store })
		t.Run("should not re-enable a key disabled during verification", func(t *testing.T) {
			store.clear()
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{}, s.headers)
			set(func() { inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "enabled": false}, s.headers) })
			eq(t, inst.verify(map[string]any{"key": k["key"]})["valid"], true)
			data, ok := store.get("api-key:by-id:" + str(k["id"]))
			eq(t, ok, true)
			eq(t, keyFromJSON(t, data)["enabled"], false)
		})
		t.Run("should not recreate a key deleted during verification", func(t *testing.T) {
			store.clear()
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{}, s.headers)
			set(func() { inst.mustCall("deleteApiKey", map[string]any{"keyId": k["id"]}, s.headers) })
			eq(t, inst.verify(map[string]any{"key": k["key"]})["valid"], false)
			for _, key := range store.keys() {
				if strings.HasPrefix(key, "api-key:") {
					t.Fatalf("unexpected entry %s", key)
				}
			}
		})
	})
}

// describe("concurrent verification enforces atomic counters").
func TestConcurrentVerificationEnforcesAtomicCounters(t *testing.T) {
	t.Run("database storage", func(t *testing.T) {
		const concurrency = 8
		var gateMu sync.Mutex
		var gate func()
		validator := func(*betterauth.EndpointContext, string) (bool, error) {
			gateMu.Lock()
			g := gate
			gateMu.Unlock()
			if g != nil {
				g()
			}
			return true, nil
		}
		arrivalGate := func(size int) func() {
			var wg sync.WaitGroup
			wg.Add(size)
			return func() { wg.Done(); wg.Wait() }
		}
		setGate := func(g func()) { gateMu.Lock(); gate = g; gateMu.Unlock() }
		inst := newInstance(t, Options{Configuration: Configuration{CustomAPIKeyValidator: validator}}, nil)
		burst := func(key any) []map[string]any {
			out := make([]map[string]any, concurrency)
			var wg sync.WaitGroup
			for i := range out {
				wg.Add(1)
				go func() { defer wg.Done(); out[i] = inst.verify(map[string]any{"key": key}) }()
			}
			wg.Wait()
			return out
		}

		t.Run("does not let concurrent verifications drop remaining below zero", func(t *testing.T) {
			defer setGate(nil)
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{"remaining": 1, "userId": s.userID}, nil)
			setGate(arrivalGate(concurrency))
			accepted := 0
			for _, r := range burst(k["key"]) {
				if r["valid"] == true {
					accepted++
				} else {
					eq(t, errCode(r), "USAGE_EXCEEDED")
				}
			}
			eq(t, accepted, 1)
			stored, e := inst.getKey(str(k["id"]), "", s.headers)
			if e != nil {
				t.Fatal(e)
			}
			eq(t, stored["remaining"], float64(0))
		})

		t.Run("does not let concurrent verifications exceed the per-key rate limit", func(t *testing.T) {
			defer setGate(nil)
			s := inst.signInWithTestUser()
			k := inst.createKey(map[string]any{"rateLimitEnabled": true, "rateLimitMax": 2, "rateLimitTimeWindow": 60000, "userId": s.userID}, nil)
			inst.verify(map[string]any{"key": k["key"]})
			setGate(arrivalGate(concurrency))
			accepted := 0
			for _, r := range burst(k["key"]) {
				if r["valid"] == true {
					accepted++
				} else {
					eq(t, errCode(r), "RATE_LIMITED")
				}
			}
			eq(t, accepted, 1)
			stored, e := inst.getKey(str(k["id"]), "", s.headers)
			if e != nil {
				t.Fatal(e)
			}
			eq(t, stored["requestCount"], float64(2))
		})
	})

	t.Run("secondary storage reference list", func(t *testing.T) {
		store := newMapStorage()
		inst := newInstance(t, Options{Configuration: Configuration{Storage: StorageSecondary}},
			func(c *betterauth.Config) { c.SecondaryStorage = store })
		t.Run("does not hide an active key when two creates run concurrently", func(t *testing.T) {
			store.clear()
			s := inst.signInWithTestUser()
			gated := "api-key:by-ref:" + s.userID
			store.getHook = func(key string) {
				if key == gated {
					sleep5ms()
				}
			}
			var a, b map[string]any
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); a = inst.createKey(map[string]any{}, s.headers) }()
			go func() { defer wg.Done(); b = inst.createKey(map[string]any{}, s.headers) }()
			wg.Wait()
			store.getHook = nil
			ids := listIDs(inst.mustCall("listApiKeys", nil, s.headers))
			for _, k := range []map[string]any{a, b} {
				found := false
				for _, id := range ids {
					found = found || id == str(k["id"])
				}
				eq(t, found, true)
				eq(t, inst.verify(map[string]any{"key": k["key"]})["valid"], true)
			}
		})
	})
}

// describe("listApiKeys with integer user.id (postgres + serial)").
func TestListAPIKeysWithIntegerUserIDPostgresSerial(t *testing.T) {
	conn := testdb.Postgres(t)
	inst := newInstanceOn(t, conn, Options{}, func(c *betterauth.Config) {
		c.Advanced = &betterauth.AdvancedConfig{Database: &betterauth.DatabaseAdvancedConfig{GenerateID: adapter.IDSerial}}
	})
	s := inst.signInWithTestUser()
	t.Run("returns the key that createApiKey just wrote", func(t *testing.T) {
		k := inst.createKey(map[string]any{}, s.headers)
		notNil(t, k["id"])
		r := inst.mustCall("listApiKeys", nil, s.headers)
		if num(r["total"]) <= 0 {
			t.Fatal("expected keys")
		}
		found := false
		for _, id := range listIDs(r) {
			found = found || id == adapter.ToString(k["id"])
		}
		eq(t, found, true)
	})
}

// describe("api key creation uses a fresh session").
func TestAPIKeyCreationUsesAFreshSession(t *testing.T) {
	inst := newInstance(t, Options{}, func(c *betterauth.Config) {
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, MaxAge: 5 * 60 * 1e9}}
	})
	t.Run("rejects creation when the session was revoked but the cookie cache is still valid", func(t *testing.T) {
		res := inst.http("POST", "/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"}, nil)
		m := expectOK(t, res)
		userID := str(obj(m["user"])["id"])
		var cookies []string
		for _, sc := range res.Header.Values("Set-Cookie") {
			nv, _, _ := strings.Cut(sc, ";")
			if name, v, _ := strings.Cut(nv, "="); v != "" {
				cookies = append(cookies, name+"="+v)
			}
		}
		h := http.Header{}
		h.Set("Cookie", strings.Join(cookies, "; "))
		if !strings.Contains(h.Get("Cookie"), "better-auth.session_data") {
			t.Fatal("cookie cache missing")
		}
		first := expectOK(t, inst.clientCreate(map[string]any{}, h))
		notNil(t, first["key"])
		if err := inst.auth.Context().InternalAdapter.DeleteUserSessions(context.Background(), userID); err != nil {
			t.Fatal(err)
		}
		second := inst.clientCreate(map[string]any{}, h)
		eq(t, second.Status, 401)
	})
}

func sleep5ms() { time.Sleep(5 * time.Millisecond) }

func keyFromJSON(t *testing.T, data string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		t.Fatal(err)
	}
	return m
}
