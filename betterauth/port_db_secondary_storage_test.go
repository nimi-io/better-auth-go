package betterauth

// Port of packages/better-auth/src/db/secondary-storage.test.ts (v1.7.7).

import (
	"context"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

// pdStorageEnv is getTestInstance({ secondaryStorage, rateLimit: { enabled: false }, ... })
// with the default test user created, followed by `beforeEach(() => store.clear())`.
func pdStorageEnv(t *testing.T, mutate func(c *Config)) (*testEnv, *pdStorage) {
	t.Helper()
	store := newPDStorage()
	env := newTestEnv(t, func(c *Config) {
		c.SecondaryStorage = store
		c.RateLimit = &RateLimitConfig{Enabled: Bool(false)}
		if mutate != nil {
			mutate(c)
		}
	})
	pdTestUser(t, env)
	store.clear()
	return env, store
}

// pdSignInWithTestUser is signInWithTestUser().
func pdSignInWithTestUser(t *testing.T, env *testEnv) *testClient {
	t.Helper()
	c := env.client()
	if res := c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"}); res.Status != 200 {
		t.Fatalf("sign-in: %d %s", res.Status, res.Body)
	}
	return c
}

func pdGetSession(t *testing.T, c *testClient) map[string]any {
	t.Helper()
	res := c.get("/get-session")
	if res.Status != 200 {
		t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if string(res.Body) == "null" {
		return nil
	}
	return res.JSON(t)
}

func pdListSessions(t *testing.T, c *testClient) []any {
	t.Helper()
	res := c.get("/list-sessions")
	if res.Status != 200 {
		t.Fatalf("list-sessions: %d %s", res.Status, res.Body)
	}
	list, ok := pdJSON(t, string(res.Body)).([]any)
	if !ok {
		t.Fatalf("list-sessions body = %s", res.Body)
	}
	return list
}

func pdRevoke(t *testing.T, c *testClient, token string) {
	t.Helper()
	res := c.post("/revoke-session", map[string]any{"token": token})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("revoke-session: %d %s", res.Status, res.Body)
	}
}

func pdIsISODate(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func TestPortDBSecondaryStorage_GetReturnsJSONString(t *testing.T) {
	env, store := pdStorageEnv(t, nil)
	if store.size() != 0 {
		t.Fatalf("store size = %d", store.size())
	}
	c := pdSignInWithTestUser(t, env)
	if store.size() != 2 {
		t.Fatalf("store size after sign-in = %d, want 2: %v", store.size(), store.keys())
	}
	s1 := pdGetSession(t, c)
	if s1 == nil {
		t.Fatal("no session")
	}
	sess, _ := s1["session"].(map[string]any)
	user, _ := s1["user"].(map[string]any)
	for _, k := range []string{"userId", "token", "ipAddress", "userAgent"} {
		if _, ok := sess[k].(string); !ok {
			t.Errorf("session.%s = %#v, want string", k, sess[k])
		}
	}
	if !pdIsISODate(sess["expiresAt"]) {
		t.Errorf("session.expiresAt = %#v", sess["expiresAt"])
	}
	if _, ok := user["id"].(string); !ok {
		t.Errorf("user.id = %#v", user["id"])
	}
	pdMatchObject(t, "user", user, map[string]any{"name": "test user", "email": "test@test.com", "emailVerified": false})
	// `image: null` upstream comes from SQLite materialising NULL for the unset column. The
	// memory adapters (TS and Go) never store the key, so the factory output omits it
	// (undefined upstream). Assert null when present; the SQL adapters (Phase 3) must
	// produce it.
	if v, ok := user["image"]; ok && v != nil {
		t.Errorf("user.image = %#v, want null", v)
	} else if !ok {
		t.Log("user.image absent: memory adapter does not materialise NULL columns (SQL-specific)")
	}
	if !pdIsISODate(user["createdAt"]) || !pdIsISODate(user["updatedAt"]) {
		t.Errorf("user dates = %v %v", user["createdAt"], user["updatedAt"])
	}
	if n := len(pdListSessions(t, c)); n != 1 {
		t.Fatalf("list-sessions = %d", n)
	}
	pdRevoke(t, c, sess["token"].(string))
	if after := pdGetSession(t, c); after != nil {
		t.Fatalf("session after revoke = %v", after)
	}
	if store.size() != 0 {
		t.Fatalf("store size after revoke = %d: %v", store.size(), store.keys())
	}
}

// Upstream: "get returns already-parsed object". The Go SecondaryStorage interface returns
// strings, so a storage that hands back parsed objects cannot exist; the active-session
// list assertions are ported against the string storage.
func TestPortDBSecondaryStorage_ActiveSessionsListLifecycle(t *testing.T) {
	env, store := pdStorageEnv(t, nil)
	c := pdSignInWithTestUser(t, env)
	s1 := pdGetSession(t, c)
	if s1 == nil {
		t.Fatal("no session")
	}
	sess := s1["session"].(map[string]any)
	userID := sess["userId"].(string)
	list, ok := pdActiveList(t, store, userID)
	if !ok || len(list) != 1 {
		t.Fatalf("active list = %+v (ok=%v)", list, ok)
	}
	if n := len(pdListSessions(t, c)); n != 1 {
		t.Fatalf("list-sessions = %d", n)
	}
	pdRevoke(t, c, sess["token"].(string))
	if after := pdGetSession(t, c); after != nil {
		t.Fatalf("session after revoke = %v", after)
	}
	if store.has("active-sessions-" + userID) {
		t.Fatal("active-sessions list should be removed")
	}
}

func TestPortDBSecondaryStorage_StoreSessionInDatabase(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		name := "preserveSessionInDatabase: false"
		if preserve {
			name = "preserveSessionInDatabase: true"
		}
		t.Run(name, func(t *testing.T) {
			env, store := pdStorageEnv(t, func(c *Config) {
				c.Session = &SessionConfig{StoreSessionInDatabase: true, PreserveSessionInDatabase: preserve}
			})
			c := pdSignInWithTestUser(t, env)
			s1 := pdGetSession(t, c)
			if s1 == nil {
				t.Fatal("no session")
			}
			token := s1["session"].(map[string]any)["token"].(string)
			if !store.has(token) {
				t.Fatal("session not in secondary storage")
			}
			pdRevoke(t, c, token)
			if store.has(token) {
				t.Fatal("session still in secondary storage")
			}
			if after := pdGetSession(t, c); after != nil {
				t.Fatalf("revoked session still usable: %v", after)
			}
		})
	}
}

func TestPortDBSecondaryStorage_PreservedSessionDeleteHookAndEndedRow(t *testing.T) {
	var deleted pdCalls
	env, store := pdStorageEnv(t, func(c *Config) {
		c.Session = &SessionConfig{StoreSessionInDatabase: true, PreserveSessionInDatabase: true}
		c.DatabaseHooks = &DatabaseHooks{Session: DBModelHooks{Delete: DBOperationHooks{
			Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
				deleted.record(ctx, d)
				return nil, nil
			},
		}}}
	})
	_ = store
	c := pdSignInWithTestUser(t, env)
	s := pdGetSession(t, c)
	if s == nil {
		t.Fatal("no session")
	}
	token := s["session"].(map[string]any)["token"].(string)
	pdRevoke(t, c, token)
	if deleted.count() != 1 {
		t.Fatalf("delete hook called %d times, want 1", deleted.count())
	}
	ctx := context.Background()
	row, err := env.auth.Context().Adapter.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "token", Value: token}}})
	if err != nil || row == nil {
		t.Fatalf("preserved row = %v %v", row, err)
	}
	exp, ok := adapter.ToTime(row["expiresAt"])
	if !ok || exp.After(time.Now()) {
		t.Fatalf("preserved row expiresAt = %v, want <= now", row["expiresAt"])
	}
	if err := env.auth.Context().InternalAdapter.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if deleted.count() != 1 {
		t.Fatalf("delete hook re-fired: %d calls", deleted.count())
	}
}

// @see https://github.com/better-auth/better-auth/pull/10687#discussion_r3716703104
func TestPortDBSecondaryStorage_KeepsCachedSessionsWhenUserDeletionVetoed(t *testing.T) {
	env, store := pdStorageEnv(t, func(c *Config) {
		c.DatabaseHooks = &DatabaseHooks{User: DBModelHooks{Delete: DBOperationHooks{
			Before: func(context.Context, adapter.Record) (*DBHookResult, error) { return &DBHookResult{Abort: true}, nil },
		}}}
	})
	ia := env.auth.Context().InternalAdapter
	ctx := context.Background()
	user := pdCreateUser(t, ia, "Retained User", "retained-user@test.com")
	session := pdCreateSession(t, ia, user.ID)
	if err := ia.DeleteUser(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if u, err := ia.FindUserByID(ctx, user.ID); err != nil || u == nil {
		t.Fatalf("user should remain: %v %v", u, err)
	}
	if !store.has(session.Token) || !store.has("active-sessions-"+user.ID) {
		t.Fatalf("cached sessions removed: %v", store.keys())
	}
}

// @see https://github.com/better-auth/better-auth/pull/10687#discussion_r3716703104
func TestPortDBSecondaryStorage_KeepsCachedSessionsWhenSessionDeletionVetoed(t *testing.T) {
	env, store := pdStorageEnv(t, func(c *Config) {
		c.Session = &SessionConfig{StoreSessionInDatabase: true}
		c.DatabaseHooks = &DatabaseHooks{Session: DBModelHooks{Delete: DBOperationHooks{
			Before: func(context.Context, adapter.Record) (*DBHookResult, error) { return &DBHookResult{Abort: true}, nil },
		}}}
	})
	ia := env.auth.Context().InternalAdapter
	ctx := context.Background()
	user := pdCreateUser(t, ia, "Retained Session User", "retained-session-user@test.com")
	session := pdCreateSession(t, ia, user.ID)
	if err := ia.DeleteUserSessions(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := env.auth.Context().Adapter.FindMany(ctx, adapter.FindManyInput{Model: "session", Where: []adapter.Where{{Field: "userId", Value: user.ID}}})
	if err != nil || len(rows) != 1 {
		t.Fatalf("db sessions = %d %v", len(rows), err)
	}
	if !store.has(session.Token) || !store.has("active-sessions-"+user.ID) {
		t.Fatalf("cached sessions removed: %v", store.keys())
	}
}

func TestPortDBSecondaryStorage_DeletesUserSessionsFromBothStores(t *testing.T) {
	env, store := pdStorageEnv(t, func(c *Config) {
		c.Session = &SessionConfig{StoreSessionInDatabase: true, PreserveSessionInDatabase: true}
	})
	ia := env.auth.Context().InternalAdapter
	ctx := context.Background()
	user := pdCreateUser(t, ia, "Deleted User", "deleted-user@test.com")
	session := pdCreateSession(t, ia, user.ID)
	count := func() int {
		rows, err := env.auth.Context().Adapter.FindMany(ctx, adapter.FindManyInput{Model: "session", Where: []adapter.Where{{Field: "userId", Value: user.ID}}})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if !store.has(session.Token) || !store.has("active-sessions-"+user.ID) || count() != 1 {
		t.Fatalf("setup: keys=%v db=%d", store.keys(), count())
	}
	if err := ia.DeleteUser(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if store.has(session.Token) || store.has("active-sessions-"+user.ID) {
		t.Errorf("cached sessions remain: %v", store.keys())
	}
	if n := count(); n != 0 {
		t.Errorf("db sessions = %d, want 0", n)
	}
}

// @see https://github.com/better-auth/better-auth/security/advisories/GHSA-2vg6-77g8-24mp
func TestPortDBSecondaryStorage_AdminRemoveUserCleansUpSessions(t *testing.T) {
	t.Skip("requires the admin plugin (admin().removeUser), not implemented in the Go port")
}

// @see https://github.com/better-auth/better-auth/security/advisories/GHSA-2vg6-77g8-24mp
func TestPortDBSecondaryStorage_DeleteAnonymousUserCleansUpSessions(t *testing.T) {
	t.Skip("requires the anonymous plugin (/delete-anonymous-user), not implemented in the Go port")
}
