package apikey

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// Ports of the storage-related describes of api-key.test.ts (nested in describe("api-key")).

func TestAPIKeySecondaryStorage(t *testing.T) {
	store := newMapStorage()
	inst := newInstance(t, Options{Configuration: Configuration{Storage: StorageSecondary, EnableMetadata: true}},
		func(c *betterauth.Config) { c.SecondaryStorage = store })
	run := func(name string, fn func(t *testing.T)) {
		store.clear() // beforeEach
		t.Run(name, fn)
	}

	run("should create API key in secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		notNil(t, k["key"])
		eq(t, store.has("api-key:by-id:"+str(k["id"])), true)
		eq(t, store.has("api-key:by-ref:"+s.userID), true)
		data, _ := store.get("api-key:by-id:" + str(k["id"]))
		var parsed map[string]any
		_ = json.Unmarshal([]byte(data), &parsed)
		eq(t, parsed["id"], k["id"])
		eq(t, parsed["referenceId"], s.userID)
	})

	run("should get API key from secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		r := expectOK(t, inst.clientGet(q("id", str(k["id"])), s.headers))
		eq(t, r["id"], k["id"])
		eq(t, r["referenceId"], s.userID)
	})

	run("should list API keys from secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k1 := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		k2 := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		r := expectOK(t, inst.clientList("", s.headers))
		ids := listIDs(r)
		if len(ids) < 2 || !slices.Contains(ids, str(k1["id"])) || !slices.Contains(ids, str(k2["id"])) {
			t.Fatalf("missing keys: %v", ids)
		}
	})

	run("should fetch keys from secondary storage in parallel, not sequentially", func(t *testing.T) {
		s := inst.signInWithTestUser()
		const keyCount = 5
		for i := 0; i < keyCount; i++ {
			expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		}
		var cur, maxC atomic.Int32
		store.getHook = func(key string) {
			if !strings.HasPrefix(key, "api-key:by-id:") {
				return
			}
			n := cur.Add(1)
			for {
				m := maxC.Load()
				if n <= m || maxC.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			cur.Add(-1)
		}
		r := expectOK(t, inst.clientList("", s.headers))
		store.getHook = nil
		eq(t, len(listIDs(r)), keyCount)
		eq(t, int(maxC.Load()), keyCount)
	})

	run("should update API key in secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{"name": "Original Name"}, s.headers))
		u := expectOK(t, inst.clientUpdate(map[string]any{"keyId": k["id"], "name": "Updated Name"}, s.headers))
		eq(t, u["name"], "Updated Name")
		eq(t, u["id"], k["id"])
	})

	run("should delete API key from secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		d := expectOK(t, inst.clientDelete(map[string]any{"keyId": k["id"]}, s.headers))
		eq(t, d["success"], true)
		eq(t, store.has("api-key:by-id:"+str(k["id"])), false)
		if data, ok := store.get("api-key:by-ref:" + s.userID); ok {
			var ids []string
			_ = json.Unmarshal([]byte(data), &ids)
			eq(t, slices.Contains(ids, str(k["id"])), false)
		}
	})

	run("should verify API key from secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["id"], k["id"])
	})

	run("should set TTL when API key has expiration", func(t *testing.T) {
		s := inst.signInWithTestUser()
		expiresIn := 60 * 60 * 24
		k := expectOK(t, inst.clientCreate(map[string]any{"expiresIn": expiresIn}, s.headers))
		notNil(t, k["expiresAt"])
		store.mu.Lock()
		ttl := store.ttls["api-key:by-id:"+str(k["id"])]
		store.mu.Unlock()
		if ttl <= 0 || math.Abs(ttl.Seconds()-float64(expiresIn)) >= 5 {
			t.Fatalf("unexpected ttl %v", ttl)
		}
	})

	run("should handle metadata in secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		md := map[string]any{"plan": "premium", "environment": "production"}
		k := expectOK(t, inst.clientCreate(map[string]any{"metadata": md}, s.headers))
		eq(t, obj(k["metadata"])["plan"], "premium")
		r := expectOK(t, inst.clientGet(q("id", str(k["id"])), s.headers))
		eq(t, obj(r["metadata"])["plan"], "premium")
		eq(t, obj(r["metadata"])["environment"], "production")
	})

	run("should handle rate limiting with secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"rateLimitEnabled": true, "rateLimitMax": 2, "rateLimitTimeWindow": 60000, "userId": s.userID}, nil)
		eq(t, inst.verify(map[string]any{"key": k["key"]})["valid"], true)
		eq(t, inst.verify(map[string]any{"key": k["key"]})["valid"], true)
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "RATE_LIMITED")
	})

	run("should handle remaining count with secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"remaining": 5, "userId": s.userID}, nil)
		eq(t, k["remaining"], float64(5))
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(4))
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(3))
	})

	run("should handle expired keys with TTL in secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		expiresIn := 60*60*24 + 1
		k := expectOK(t, inst.clientCreate(map[string]any{"expiresIn": expiresIn}, s.headers))
		notNil(t, k["expiresAt"])
		inst.advance(time.Duration(expiresIn+1) * time.Second)
		defer inst.useRealTimers()
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "KEY_EXPIRED")
	})

	run("should maintain user's API key list in secondary storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k1 := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		k2 := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		k3 := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		ids := listIDs(expectOK(t, inst.clientList("", s.headers)))
		for _, k := range []map[string]any{k1, k2, k3} {
			if !slices.Contains(ids, str(k["id"])) {
				t.Fatal("missing key")
			}
		}
		expectOK(t, inst.clientDelete(map[string]any{"keyId": k2["id"]}, s.headers))
		after := listIDs(expectOK(t, inst.clientList("", s.headers)))
		eq(t, len(after), len(ids)-1)
		eq(t, slices.Contains(after, str(k2["id"])), false)
	})
}

func listIDs(r map[string]any) []string {
	var ids []string
	list, _ := r["apiKeys"].([]any)
	for _, k := range list {
		ids = append(ids, str(obj(k)["id"]))
	}
	return ids
}

// rawKey builds a key row created directly through the database adapter.
func rawKey(userID, name, hashed string) adapter.Record {
	now := time.Now()
	return adapter.Record{
		"configId": "default", "createdAt": now, "updatedAt": now, "name": name, "prefix": "test",
		"start": "test_", "key": hashed, "enabled": true, "expiresAt": nil, "referenceId": userID,
		"lastRefillAt": nil, "lastRequest": nil, "metadata": nil, "rateLimitMax": nil,
		"rateLimitTimeWindow": nil, "remaining": nil, "refillAmount": nil, "refillInterval": nil,
		"rateLimitEnabled": false, "requestCount": 0, "permissions": nil,
	}
}

func (i *instance) dbCreateKey(rec adapter.Record) string {
	i.t.Helper()
	out, err := i.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: TableName, Data: rec})
	if err != nil || out == nil {
		i.t.Fatalf("create: %v", err)
	}
	return adapter.ToString(out["id"])
}

func TestAPIKeySecondaryStorageWithFallback(t *testing.T) {
	store := newMapStorage()
	inst := newInstance(t, Options{Configuration: Configuration{Storage: StorageSecondary, FallbackToDatabase: true, EnableMetadata: true}},
		func(c *betterauth.Config) { c.SecondaryStorage = store })
	run := func(name string, fn func(t *testing.T)) {
		store.clear()
		t.Run(name, fn)
	}

	run("should read from secondary storage first", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		eq(t, store.has("api-key:by-id:"+str(k["id"])), true)
		r := expectOK(t, inst.clientGet(q("id", str(k["id"])), s.headers))
		eq(t, r["id"], k["id"])
	})

	run("verifyApiKey should persist quota updates to the database when fallbackToDatabase is true", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"remaining": 1, "userId": s.userID}, nil)
		first := inst.verify(map[string]any{"key": k["key"]})
		eq(t, first["valid"], true)
		eq(t, obj(first["key"])["remaining"], float64(0))
		db, e := inst.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, db["remaining"], float64(0))
		store.clear()
		second := inst.verify(map[string]any{"key": k["key"]})
		eq(t, second["valid"], false)
		eq(t, errCode(second), "USAGE_EXCEEDED")
	})

	run("should fallback to database when not found in storage and auto-populate storage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		hashed := "test_hashed_key_123"
		id := inst.dbCreateKey(rawKey(s.userID, "Test Key", hashed))
		eq(t, store.has("api-key:by-id:"+id), false)
		eq(t, store.has("api-key:"+hashed), false)
		r := expectOK(t, inst.clientGet(q("id", id), s.headers))
		eq(t, r["id"], id)
		eq(t, store.has("api-key:by-id:"+id), true)
		eq(t, store.has("api-key:"+hashed), true)
	})

	run("should populate storage when listing keys falls back to database", func(t *testing.T) {
		s := inst.signInWithTestUser()
		id1 := inst.dbCreateKey(rawKey(s.userID, "Test Key 1", "test_hashed_key_1"))
		id2 := inst.dbCreateKey(rawKey(s.userID, "Test Key 2", "test_hashed_key_2"))
		eq(t, store.has("api-key:by-id:"+id1), false)
		eq(t, store.has("api-key:by-id:"+id2), false)
		eq(t, store.has("api-key:by-ref:"+s.userID), false)
		ids := listIDs(expectOK(t, inst.clientList("", s.headers)))
		if !slices.Contains(ids, id1) || !slices.Contains(ids, id2) {
			t.Fatal("missing keys")
		}
		eq(t, store.has("api-key:by-id:"+id1), true)
		eq(t, store.has("api-key:by-id:"+id2), true)
		eq(t, store.has("api-key:test_hashed_key_1"), true)
		eq(t, store.has("api-key:test_hashed_key_2"), true)
		eq(t, store.has("api-key:by-ref:"+s.userID), true)
	})

	run("should populate storage in parallel when listing falls back to database", func(t *testing.T) {
		s := inst.signInWithTestUser()
		const keyCount = 5
		for i := 0; i < keyCount; i++ {
			inst.dbCreateKey(rawKey(s.userID, "Parallel Key", "hashed_parallel_"+string(rune('0'+i))))
		}
		var cur, maxC atomic.Int32
		store.setHook = func(key string) {
			if !strings.HasPrefix(key, "api-key:by-id:") {
				return
			}
			n := cur.Add(1)
			for {
				m := maxC.Load()
				if n <= m || maxC.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			cur.Add(-1)
		}
		r := expectOK(t, inst.clientList("", s.headers))
		store.setHook = nil
		if len(listIDs(r)) < keyCount {
			t.Fatal("missing keys")
		}
		if int(maxC.Load()) < keyCount {
			t.Fatalf("max concurrent sets %d", maxC.Load())
		}
	})

	run("should not touch the ref list per key while populating", func(t *testing.T) {
		s := inst.signInWithTestUser()
		for i := 0; i < 5; i++ {
			inst.dbCreateKey(rawKey(s.userID, "Ref List Key", "hashed_ref_list_"+string(rune('0'+i))))
		}
		refKey := "api-key:by-ref:" + s.userID
		store.startRecording()
		r := expectOK(t, inst.clientList("", s.headers))
		if len(listIDs(r)) < 5 {
			t.Fatal("missing keys")
		}
		gets, sets, _ := store.counts(refKey)
		if gets > 1 {
			t.Fatalf("ref list read %d times", gets)
		}
		eq(t, sets, 1)
	})

	run("should invalidate (not mutate) the ref list on create", func(t *testing.T) {
		s := inst.signInWithTestUser()
		refKey := "api-key:by-ref:" + s.userID
		expectOK(t, inst.clientList("", s.headers))
		store.startRecording()
		expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		gets, sets, dels := store.counts(refKey)
		eq(t, gets, 0)
		eq(t, sets, 0)
		eq(t, dels, 1)
	})

	run("should invalidate (not mutate) the ref list on delete", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		expectOK(t, inst.clientList("", s.headers))
		refKey := "api-key:by-ref:" + s.userID
		store.startRecording()
		expectOK(t, inst.clientDelete(map[string]any{"keyId": k["id"]}, s.headers))
		gets, sets, dels := store.counts(refKey)
		eq(t, gets, 0)
		eq(t, sets, 0)
		eq(t, dels, 1)
	})

	run("should not lose ids when two creates race on the ref list", func(t *testing.T) {
		s := inst.signInWithTestUser()
		store.getHook = func(key string) {
			if strings.HasPrefix(key, "api-key:by-ref:") {
				time.Sleep(30 * time.Millisecond)
			}
		}
		var a, b map[string]any
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); a = inst.clientCreate(map[string]any{"name": "race-a"}, s.headers).Data() }()
		go func() { defer wg.Done(); b = inst.clientCreate(map[string]any{"name": "race-b"}, s.headers).Data() }()
		wg.Wait()
		ids := listIDs(expectOK(t, inst.clientList("", s.headers)))
		store.getHook = nil
		if !slices.Contains(ids, str(a["id"])) || !slices.Contains(ids, str(b["id"])) {
			t.Fatalf("lost ids: %v", ids)
		}
	})

	run("should write to secondary storage only", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{"name": "Test Key"}, s.headers))
		eq(t, store.has("api-key:by-id:"+str(k["id"])), true)
	})

	run("should create in both database and secondary storage when fallbackToDatabase is true", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{"name": "Fallback Test Key"}, s.headers))
		eq(t, store.has("api-key:by-id:"+str(k["id"])), true)
		db, e := inst.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, db["id"], k["id"])
		eq(t, db["name"], "Fallback Test Key")
	})

	run("should update both database and secondary storage when fallbackToDatabase is true", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{"name": "Original Name"}, s.headers))
		u := expectOK(t, inst.clientUpdate(map[string]any{"keyId": k["id"], "name": "Updated Name"}, s.headers))
		eq(t, u["name"], "Updated Name")
		data, ok := store.get("api-key:by-id:" + str(k["id"]))
		eq(t, ok, true)
		var parsed map[string]any
		_ = json.Unmarshal([]byte(data), &parsed)
		eq(t, parsed["name"], "Updated Name")
		db, e := inst.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, db["name"], "Updated Name")
	})

	run("should delete from both database and secondary storage when fallbackToDatabase is true", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		eq(t, store.has("api-key:by-id:"+str(k["id"])), true)
		if _, e := inst.getKey(str(k["id"]), "", s.headers); e != nil {
			t.Fatal(e)
		}
		d := expectOK(t, inst.clientDelete(map[string]any{"keyId": k["id"]}, s.headers))
		eq(t, d["success"], true)
		eq(t, store.has("api-key:by-id:"+str(k["id"])), false)
		_, e := inst.getKey(str(k["id"]), "", s.headers)
		expectAPIError(t, e, "NOT_FOUND", betterauth.ErrorCode{})
	})
}

func TestAPIKeyDeferUpdatesOption(t *testing.T) {
	type tasks struct {
		mu   sync.Mutex
		list []func()
	}
	withTasks := func(tk *tasks) func(c *betterauth.Config) {
		return func(c *betterauth.Config) {
			c.Advanced = &betterauth.AdvancedConfig{BackgroundTasks: func(fn func()) {
				tk.mu.Lock()
				tk.list = append(tk.list, fn)
				tk.mu.Unlock()
			}}
		}
	}
	runAll := func(tk *tasks) int {
		tk.mu.Lock()
		list := tk.list
		tk.list = nil
		tk.mu.Unlock()
		for _, fn := range list {
			fn()
		}
		return len(list)
	}

	t.Run("should defer updates when deferUpdates is enabled with global backgroundTasks", func(t *testing.T) {
		tk := &tasks{}
		in := newInstance(t, Options{Configuration: Configuration{DeferUpdates: true}}, withTasks(tk))
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID}, s.headers)
		r := in.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		if runAll(tk) == 0 {
			t.Fatal("expected deferred tasks")
		}
		u, e := in.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		notNil(t, u["lastRequest"])
	})

	t.Run("should still validate rate limits correctly with deferred updates", func(t *testing.T) {
		tk := &tasks{}
		in := newInstance(t, Options{Configuration: Configuration{DeferUpdates: true,
			RateLimit: &RateLimit{Enabled: Bool(true), MaxRequests: Float(2), TimeWindow: Float(60000)}}}, withTasks(tk))
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID}, s.headers)
		eq(t, in.verify(map[string]any{"key": k["key"]})["valid"], true)
		runAll(tk)
		eq(t, in.verify(map[string]any{"key": k["key"]})["valid"], true)
		runAll(tk)
		r := in.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "RATE_LIMITED")
		details := obj(obj(r["error"])["details"])
		if _, ok := details["tryAgainIn"]; !ok {
			t.Fatalf("missing tryAgainIn: %v", r["error"])
		}
	})

	t.Run("should defer remaining count updates", func(t *testing.T) {
		tk := &tasks{}
		in := newInstance(t, Options{Configuration: Configuration{DeferUpdates: true}}, withTasks(tk))
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID, "remaining": 10}, nil)
		r := in.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(9))
		if runAll(tk) == 0 {
			t.Fatal("expected deferred tasks")
		}
		u, e := in.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, u["remaining"], float64(9))
	})

	t.Run("should not defer updates when backgroundTasks handler is not configured", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{DeferUpdates: true}}, nil)
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID}, s.headers)
		eq(t, in.verify(map[string]any{"key": k["key"]})["valid"], true)
		u, e := in.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		notNil(t, u["lastRequest"])
	})
}

// flagStorage records which methods were called (custom storage methods describe).
type flagStorage struct {
	*mapStorage
	getCalled, setCalled, deleteCalled atomic.Bool
}

func (f *flagStorage) Get(ctx context.Context, k string) (string, bool, error) {
	f.getCalled.Store(true)
	return f.mapStorage.Get(ctx, k)
}

func (f *flagStorage) Set(ctx context.Context, k, v string, ttl time.Duration) error {
	f.setCalled.Store(true)
	return f.mapStorage.Set(ctx, k, v, ttl)
}

func (f *flagStorage) Delete(ctx context.Context, k string) error {
	f.deleteCalled.Store(true)
	return f.mapStorage.Delete(ctx, k)
}

func TestAPIKeyCustomStorageMethods(t *testing.T) {
	cs := &flagStorage{mapStorage: newMapStorage()}
	inst := newInstance(t, Options{Configuration: Configuration{Storage: StorageSecondary, CustomStorage: cs, EnableMetadata: true}}, nil)
	run := func(name string, fn func(t *testing.T)) {
		cs.clear()
		cs.getCalled.Store(false)
		cs.setCalled.Store(false)
		cs.deleteCalled.Store(false)
		t.Run(name, fn)
	}
	run("should use custom storage methods instead of global secondaryStorage", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		eq(t, cs.setCalled.Load(), true)
		eq(t, cs.has("api-key:by-id:"+str(k["id"])), true)
	})
	run("should use custom get method", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		cs.getCalled.Store(false)
		expectOK(t, inst.clientGet(q("id", str(k["id"])), s.headers))
		eq(t, cs.getCalled.Load(), true)
	})
	run("should use custom delete method", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{}, s.headers))
		cs.deleteCalled.Store(false)
		d := expectOK(t, inst.clientDelete(map[string]any{"keyId": k["id"]}, s.headers))
		eq(t, d["success"], true)
		eq(t, cs.deleteCalled.Load(), true)
		eq(t, cs.has("api-key:by-id:"+str(k["id"])), false)
	})
}

func TestAPIKeyLegacyDoubleStringifiedMetadataMigration(t *testing.T) {
	inst := newInstance(t, Options{Configuration: Configuration{EnableMetadata: true}}, nil)
	ad := inst.auth.Context().Adapter
	setLegacy := func(t *testing.T, id string, md map[string]any) {
		b, _ := json.Marshal(md)
		if _, err := ad.Update(context.Background(), TableName, []adapter.Where{{Field: "id", Value: id}},
			adapter.Record{"metadata": string(b)}); err != nil {
			t.Fatal(err)
		}
	}
	rawMetadata := func(t *testing.T, id string) any {
		rec, err := ad.FindOne(context.Background(), adapter.FindOneInput{Model: TableName, Where: []adapter.Where{{Field: "id", Value: id}}})
		if err != nil || rec == nil {
			t.Fatalf("findOne: %v", err)
		}
		return rec["metadata"]
	}
	field := func(t *testing.T, md any, k string) any {
		t.Helper()
		b, _ := json.Marshal(md)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("metadata is not an object: %s", b)
		}
		return m[k]
	}

	t.Run("should migrate double-stringified metadata on getApiKey", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"metadata": map[string]any{"organizationId": "test-org"}}, s.headers)
		setLegacy(t, str(k["id"]), map[string]any{"organizationId": "legacy-org"})
		if _, ok := rawMetadata(t, str(k["id"])).(string); !ok {
			t.Fatal("expected a string in the database")
		}
		r, e := inst.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, obj(r["metadata"])["organizationId"], "legacy-org")
		eq(t, field(t, rawMetadata(t, str(k["id"])), "organizationId"), "legacy-org")
	})

	t.Run("should migrate double-stringified metadata on listApiKeys", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k1 := inst.createKey(map[string]any{"name": "key-1", "metadata": map[string]any{"plan": "pro"}}, s.headers)
		k2 := inst.createKey(map[string]any{"name": "key-2", "metadata": map[string]any{"plan": "enterprise"}}, s.headers)
		setLegacy(t, str(k1["id"]), map[string]any{"plan": "legacy-1"})
		setLegacy(t, str(k2["id"]), map[string]any{"plan": "legacy-2"})
		r := inst.mustCall("listApiKeys", nil, s.headers)
		found := map[string]map[string]any{}
		for _, k := range r["apiKeys"].([]any) {
			found[str(obj(k)["id"])] = obj(k)
		}
		eq(t, obj(found[str(k1["id"])]["metadata"])["plan"], "legacy-1")
		eq(t, obj(found[str(k2["id"])]["metadata"])["plan"], "legacy-2")
		eq(t, field(t, rawMetadata(t, str(k1["id"])), "plan"), "legacy-1")
		eq(t, field(t, rawMetadata(t, str(k2["id"])), "plan"), "legacy-2")
	})

	t.Run("should migrate double-stringified metadata on updateApiKey", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"name": "test-key", "metadata": map[string]any{"tier": "free"}}, s.headers)
		setLegacy(t, str(k["id"]), map[string]any{"tier": "legacy-tier"})
		r := inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "name": "updated-name"}, s.headers)
		eq(t, r["name"], "updated-name")
		eq(t, obj(r["metadata"])["tier"], "legacy-tier")
		eq(t, field(t, rawMetadata(t, str(k["id"])), "tier"), "legacy-tier")
	})

	t.Run("should migrate double-stringified metadata on verifyApiKey", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"metadata": map[string]any{"scope": "read"}}, s.headers)
		setLegacy(t, str(k["id"]), map[string]any{"scope": "legacy-scope"})
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(obj(r["key"])["metadata"])["scope"], "legacy-scope")
		eq(t, field(t, rawMetadata(t, str(k["id"])), "scope"), "legacy-scope")
	})

	t.Run("should handle already properly formatted metadata (no migration needed)", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"metadata": map[string]any{"alreadyCorrect": true, "value": 123}}, s.headers)
		r, e := inst.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, obj(r["metadata"])["alreadyCorrect"], true)
		eq(t, obj(r["metadata"])["value"], float64(123))
	})

	t.Run("should handle null metadata gracefully", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{}, s.headers)
		r, e := inst.getKey(str(k["id"]), "", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		isNil(t, r["metadata"])
	})
}
