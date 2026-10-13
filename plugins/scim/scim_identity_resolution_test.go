package scim

// Port of upstream scim-identity-resolution.test.ts (@better-auth/scim v1.7.7).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

var (
	identityResConnA = staticConnection("workforce-a", "connection-a-token")
	identityResConnB = staticConnection("workforce-b", "connection-b-token")
)

const identityResUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const identityResPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

func identityResBackingUser(id string) adapter.Record {
	if id == "" {
		id = "existing-user"
	}
	now := time.Now()
	return adapter.Record{
		"id": id, "name": "Original Profile", "email": "original@example.com", "emailVerified": true,
		"image": nil, "createdAt": now, "updatedAt": now,
	}
}

func identityResSession(userID string) adapter.Record {
	now := time.Now()
	return adapter.Record{
		"id": "existing-session", "userId": userID, "token": "existing-session-token",
		"expiresAt": now.Add(time.Hour), "ipAddress": nil, "userAgent": nil, "createdAt": now, "updatedAt": now,
	}
}

// identityResStorage is createStringSecondaryStorage (a Map-backed SecondaryStorage).
type identityResStorage struct {
	mu      sync.Mutex
	store   map[string]string
	failSet bool
}

func (s *identityResStorage) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.store[key]
	return v, ok, nil
}

func (s *identityResStorage) Set(_ context.Context, key, value string, _ time.Duration) error {
	if s.failSet {
		return errors.New("cache unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = value
	return nil
}

func (s *identityResStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
	return nil
}

func (s *identityResStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.store[key]
	delete(s.store, key)
	return v, ok, nil
}

func (s *identityResStorage) Increment(_ context.Context, key string, _ time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	_ = json.Unmarshal([]byte(s.store[key]), &n)
	n++
	b, _ := json.Marshal(n)
	s.store[key] = string(b)
	return n, nil
}

func (s *identityResStorage) get(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store[key]
}

// identityResSeedCache stores the session and its user like Better Auth does.
func identityResSeedCache(s *identityResStorage, session, user adapter.Record) {
	iso := func(v any) any {
		if t, ok := v.(time.Time); ok {
			return t.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		return v
	}
	conv := func(r adapter.Record) map[string]any {
		out := map[string]any{}
		for k, v := range r {
			out[k] = iso(v)
		}
		return out
	}
	expiresAt := session["expiresAt"].(time.Time)
	list, _ := json.Marshal([]map[string]any{{"token": session["token"], "expiresAt": expiresAt.UnixMilli()}})
	s.store["active-sessions-"+user["id"].(string)] = string(list)
	payload, _ := json.Marshal(map[string]any{"session": conv(session), "user": conv(user)})
	s.store[session["token"].(string)] = string(payload)
}

type identityResFixtureOptions struct {
	connections   []ConnectionOptions
	identity      *Identity
	databaseHooks *betterauth.DatabaseHooks
	storage       betterauth.SecondaryStorage
	sessions      []adapter.Record
	users         []adapter.Record
}

// identityResFixture is createIdentityFixture.
func identityResFixture(t *testing.T, o identityResFixtureOptions) *testEnv {
	t.Helper()
	conns := o.connections
	if conns == nil {
		conns = []ConnectionOptions{identityResConnA}
	}
	e := newEnv(t, Options{Connections: conns, Identity: o.identity}, envOptions{mutate: func(cfg *betterauth.Config) {
		if o.databaseHooks != nil {
			cfg.DatabaseHooks = o.databaseHooks
		}
		if o.storage != nil {
			cfg.SecondaryStorage = o.storage
		}
	}})
	for _, u := range o.users {
		e.insert("user", u)
	}
	// With secondary storage the session table is not part of the schema (upstream's
	// data.session rows are inert there too); sessions then live only in the cache.
	if o.storage == nil {
		for _, s := range o.sessions {
			e.insert("session", s)
		}
	}
	return e
}

func identityResPreserve(userID string) *Identity {
	return &Identity{ResolveUser: func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
		return &IdentityResolution{Action: "link", UserID: userID, Profile: "preserve"}, nil
	}}
}

func identityResManage(userID string) func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
	return func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
		return &IdentityResolution{Action: "link", UserID: userID, Profile: "manage"}, nil
	}
}

func identityResCreate(e *testEnv, token string, body map[string]any) map[string]any {
	e.t.Helper()
	if _, ok := body["schemas"]; !ok {
		body["schemas"] = []any{identityResUserSchema}
	}
	return e.mustCall("createSCIMUser", betterauth.CallInput{Body: body, Headers: bearer(token)})
}

func identityResCreateErr(e *testEnv, token string, body map[string]any) *betterauth.APIError {
	e.t.Helper()
	body["schemas"] = []any{identityResUserSchema}
	_, ae := e.call("createSCIMUser", betterauth.CallInput{Body: body, Headers: bearer(token)})
	if ae == nil {
		e.t.Fatal("expected createSCIMUser to fail")
	}
	return ae
}

func identityResPatch(e *testEnv, token, id string, ops ...map[string]any) (map[string]any, *betterauth.APIError) {
	e.t.Helper()
	list := make([]any, len(ops))
	for i, op := range ops {
		list[i] = op
	}
	res, ae := e.call("patchSCIMUser", betterauth.CallInput{
		Params:  map[string]string{"userId": id},
		Body:    map[string]any{"schemas": []any{identityResPatchSchema}, "Operations": list},
		Headers: bearer(token),
	})
	if ae != nil {
		return nil, ae
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		e.t.Fatal(err)
	}
	return m, nil
}

func identityResMustPatch(e *testEnv, token, id string, ops ...map[string]any) {
	e.t.Helper()
	if _, ae := identityResPatch(e, token, id, ops...); ae != nil {
		e.t.Fatalf("patchSCIMUser: %d %v", ae.StatusCode, errBody(ae))
	}
}

func identityResFind(rows []adapter.Record, field string, value any) adapter.Record {
	for _, r := range rows {
		if adapter.Equal(r[field], value) {
			return r
		}
	}
	return nil
}

func identityResExpectFields(t *testing.T, label string, rec adapter.Record, want map[string]any) {
	t.Helper()
	if rec == nil {
		t.Fatalf("%s: record is missing", label)
	}
	for k, v := range want {
		if !adapter.Equal(rec[k], v) {
			t.Errorf("%s.%s = %#v, want %#v", label, k, rec[k], v)
		}
	}
}

func identityResExpectUniqueness(t *testing.T, ae *betterauth.APIError) {
	t.Helper()
	b := errBody(ae)
	if ae.StatusCode != 409 || b["status"] != "409" || b["scimType"] != "uniqueness" {
		t.Fatalf("expected 409 uniqueness, got %d %v", ae.StatusCode, b)
	}
}

// identityResAcquire is acquireUserLink: acquireActiveSCIMUserLink inside a transaction.
func identityResAcquire(e *testEnv, ref UserExternalIDReference) (*ActiveUserLink, error) {
	var link *ActiveUserLink
	err := e.db().Transaction(context.Background(), func(txCtx context.Context, tx adapter.Adapter) error {
		l, err := AcquireActiveUserLink(txCtx, ref, tx)
		link = l
		return err
	})
	return link, err
}

func identityResMustAcquire(t *testing.T, e *testEnv, ref UserExternalIDReference) *ActiveUserLink {
	t.Helper()
	l, err := identityResAcquire(e, ref)
	if err != nil {
		t.Fatalf("acquire %+v: %v", ref, err)
	}
	return l
}

func TestIdentityResExplicitIdentityResolution(t *testing.T) {
	t.Run("exposes the canonical User invariants to identity resolvers", func(t *testing.T) {
		// Upstream is a compile-time expectTypeOf check. In Go the resolver input's resource
		// is CanonicalUser (checked at compile time below); the canonical name.formatted
		// string and boolean emails[].primary invariants are checked at runtime.
		var _ func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) = Identity{}.ResolveUser
		var _ CanonicalUser = IdentityResolutionInput{}.Resource
		var seen *CanonicalUser
		e := identityResFixture(t, identityResFixtureOptions{identity: &Identity{
			ResolveUser: func(in IdentityResolutionInput, _ DatabaseContext) (*IdentityResolution, error) {
				r := in.Resource
				seen = &r
				return nil, nil
			},
		}})
		identityResCreate(e, "connection-a-token", map[string]any{"userName": "typed@example.com"})
		if seen == nil || seen.Resource == nil {
			t.Fatal("resolver was not called with a canonical resource")
		}
		var res map[string]any
		if err := json.Unmarshal(jsonx.MustMarshal(seen.Resource), &res); err != nil {
			t.Fatal(err)
		}
		name, _ := res["name"].(map[string]any)
		if _, ok := name["formatted"].(string); !ok {
			t.Errorf("name.formatted is not a string: %#v", res["name"])
		}
		emails, _ := res["emails"].([]any)
		if len(emails) == 0 {
			t.Fatalf("emails missing: %#v", res)
		}
		for _, em := range emails {
			if _, ok := em.(map[string]any)["primary"].(bool); !ok {
				t.Errorf("emails[].primary is not a boolean: %#v", em)
			}
		}
	})

	t.Run("defaults to creating a new Better Auth User when no resolver is configured", func(t *testing.T) {
		e := identityResFixture(t, identityResFixtureOptions{})
		resource := identityResCreate(e, "connection-a-token", map[string]any{"userName": "created@example.com"})
		identityResMustPatch(e, "connection-a-token", resource["id"].(string), map[string]any{
			"op": "replace",
			"value": map[string]any{
				"displayName": "Updated Directory Name",
				"emails":      []any{map[string]any{"value": "updated-directory@example.com", "primary": true}},
			},
		})
		users := e.rows("user")
		if len(users) != 1 {
			t.Fatalf("users = %d", len(users))
		}
		if n := len(e.rows("account")); n != 0 {
			t.Fatalf("accounts = %d", n)
		}
		identityResExpectFields(t, "user[0]", users[0], map[string]any{
			"name": "Updated Directory Name", "email": "updated-directory@example.com"})
		identityResExpectFields(t, "scimUser", identityResFind(e.rows("scimUser"), "id", resource["id"]),
			map[string]any{"userId": users[0]["id"]})
	})

	t.Run("links with preserved profile authority without creating or overwriting identity records", func(t *testing.T) {
		target := identityResBackingUser("")
		e := identityResFixture(t, identityResFixtureOptions{users: []adapter.Record{target},
			identity: identityResPreserve(target["id"].(string))})
		resource := identityResCreate(e, "connection-a-token", map[string]any{
			"userName":    "directory-ada",
			"displayName": "Directory Managed Name",
			"emails":      []any{map[string]any{"value": "directory-managed@example.com", "primary": true}},
		})
		identityResMustPatch(e, "connection-a-token", resource["id"].(string), map[string]any{
			"op": "replace",
			"value": map[string]any{
				"displayName": "Updated Directory Name",
				"emails":      []any{map[string]any{"value": "updated-directory@example.com", "primary": true}},
			},
		})
		users := e.rows("user")
		if len(users) != 1 || len(e.rows("account")) != 0 {
			t.Fatalf("users = %d, accounts = %d", len(users), len(e.rows("account")))
		}
		identityResExpectFields(t, "user[0]", users[0], map[string]any{"name": target["name"], "email": target["email"]})
		identityResExpectFields(t, "scimUser", identityResFind(e.rows("scimUser"), "id", resource["id"]), map[string]any{
			"userId": target["id"], "displayName": "Updated Directory Name", "primaryEmail": "updated-directory@example.com"})
	})

	t.Run("revokes email verification whenever a managing source changes the backing email", func(t *testing.T) {
		target := identityResBackingUser("")
		e := identityResFixture(t, identityResFixtureOptions{users: []adapter.Record{target},
			identity: &Identity{ResolveUser: identityResManage(target["id"].(string))}})
		source := identityResCreate(e, "connection-a-token", map[string]any{
			"userName":    "managed-directory-user",
			"displayName": "Managed Profile",
			"emails":      []any{map[string]any{"value": "managed@example.com", "primary": true}},
		})
		identityResExpectFields(t, "user[0]", e.rows("user")[0], map[string]any{
			"id": target["id"], "name": "Managed Profile", "email": "managed@example.com", "emailVerified": false})
		identityResExpectFields(t, "scimSubject[0]", e.rows("scimSubject")[0], map[string]any{"profileSourceId": source["id"]})

		verify := func() {
			if _, err := e.db().Update(context.Background(), "user", []adapter.Where{{Field: "id", Value: target["id"]}},
				adapter.Record{"emailVerified": true}); err != nil {
				t.Fatal(err)
			}
		}
		verify()
		e.mustCall("replaceSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": source["id"].(string)},
			Body: map[string]any{
				"schemas":     []any{identityResUserSchema},
				"userName":    "managed-directory-user",
				"displayName": "Replaced Managed Profile",
				"emails":      []any{map[string]any{"value": "replaced@example.com", "primary": true}},
			},
			Headers: bearer("connection-a-token"),
		})
		identityResExpectFields(t, "user[0]", e.rows("user")[0], map[string]any{
			"email": "replaced@example.com", "emailVerified": false})

		verify()
		identityResMustPatch(e, "connection-a-token", source["id"].(string), map[string]any{
			"op": "replace", "path": "emails",
			"value": []any{map[string]any{"value": "patched@example.com", "primary": true}},
		})
		identityResExpectFields(t, "user[0]", e.rows("user")[0], map[string]any{
			"email": "patched@example.com", "emailVerified": false})
	})

	t.Run("runs User hooks and refreshes cached sessions only after a successful commit", func(t *testing.T) {
		target := identityResBackingUser("")
		session := identityResSession(target["id"].(string))
		cache := &identityResStorage{store: map[string]string{}}
		identityResSeedCache(cache, session, target)
		var rejectReconciliation atomic.Bool
		var beforeUpdates, afterUpdates atomic.Int32
		e := identityResFixture(t, identityResFixtureOptions{
			users:    []adapter.Record{target},
			sessions: []adapter.Record{session},
			storage:  cache,
			databaseHooks: &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Update: betterauth.DBOperationHooks{
				Before: func(_ context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
					beforeUpdates.Add(1)
					return &betterauth.DBHookResult{Data: data}, nil
				},
				After: func(context.Context, adapter.Record) error {
					afterUpdates.Add(1)
					return nil
				},
			}}},
			identity: &Identity{
				ResolveUser: identityResManage(target["id"].(string)),
				ReconcileUser: func(IdentityState, DatabaseContext) error {
					if rejectReconciliation.Load() {
						return errors.New("reject reconciliation")
					}
					return nil
				},
			},
		})
		source := identityResCreate(e, "connection-a-token", map[string]any{
			"userName":    "hook-managed-user",
			"displayName": "Committed Profile",
			"emails":      []any{map[string]any{"value": "committed@example.com", "primary": true}},
		})
		cachedUser := func() map[string]any {
			var v struct {
				User map[string]any `json:"user"`
			}
			if err := json.Unmarshal([]byte(cache.get(session["token"].(string))), &v); err != nil {
				t.Fatalf("cache: %v", err)
			}
			return v.User
		}
		if b, a := beforeUpdates.Load(), afterUpdates.Load(); b != 1 || a != 1 {
			t.Fatalf("hooks = {before: %d, after: %d}, want {1, 1}", b, a)
		}
		cu := cachedUser()
		if cu["name"] != "Committed Profile" || cu["email"] != "committed@example.com" {
			t.Fatalf("cached user = %v", cu)
		}

		rejectReconciliation.Store(true)
		_, ae := identityResPatch(e, "connection-a-token", source["id"].(string), map[string]any{
			"op": "replace", "path": "displayName", "value": "Rolled Back Profile"})
		if ae == nil {
			t.Fatal("expected patch to fail")
		}
		if d := errBody(ae)["detail"]; d != "SCIM identity reconciliation failed" {
			t.Fatalf("detail = %v", d)
		}
		if b, a := beforeUpdates.Load(), afterUpdates.Load(); b != 2 || a != 1 {
			t.Fatalf("hooks = {before: %d, after: %d}, want {2, 1}", b, a)
		}
		if n := cachedUser()["name"]; n != "Committed Profile" {
			t.Fatalf("cached name = %v", n)
		}
		if n := e.rows("user")[0]["name"]; n != "Committed Profile" {
			t.Fatalf("user name = %v", n)
		}
	})

	t.Run("does not report a committed User as failed when cache refresh fails", func(t *testing.T) {
		target := identityResBackingUser("")
		session := identityResSession(target["id"].(string))
		storage := &identityResStorage{store: map[string]string{}}
		identityResSeedCache(storage, session, target)
		storage.failSet = true
		e := identityResFixture(t, identityResFixtureOptions{
			users:    []adapter.Record{target},
			sessions: []adapter.Record{session},
			storage:  storage,
			identity: &Identity{ResolveUser: identityResManage(target["id"].(string))},
		})
		source := identityResCreate(e, "connection-a-token", map[string]any{
			"userName":    "cache-failure-managed-user",
			"displayName": "Committed Despite Cache Failure",
			"emails":      []any{map[string]any{"value": "cache-failure@example.com", "primary": true}},
		})
		if source["id"] != e.rows("scimUser")[0]["id"] {
			t.Fatalf("source id %v != scimUser[0].id %v", source["id"], e.rows("scimUser")[0]["id"])
		}
		identityResExpectFields(t, "user[0]", e.rows("user")[0], map[string]any{
			"name": "Committed Despite Cache Failure", "email": "cache-failure@example.com"})
	})

	t.Run("rejects a second profile-managing source atomically", func(t *testing.T) {
		target := identityResBackingUser("")
		e := identityResFixture(t, identityResFixtureOptions{
			users:       []adapter.Record{target},
			connections: []ConnectionOptions{identityResConnA, identityResConnB},
			identity:    &Identity{ResolveUser: identityResManage(target["id"].(string))},
		})
		sourceA := identityResCreate(e, "connection-a-token", map[string]any{
			"userName": "source-a@example.com", "displayName": "Source A Profile"})
		ae := identityResCreateErr(e, "connection-b-token", map[string]any{
			"userName": "source-b@example.com", "displayName": "Source B Profile"})
		identityResExpectUniqueness(t, ae)

		sources := e.rows("scimUser")
		if len(sources) != 1 || sources[0]["id"] != sourceA["id"] {
			t.Fatalf("scimUser = %v", sources)
		}
		identityResExpectFields(t, "scimSubject[0]", e.rows("scimSubject")[0], map[string]any{"profileSourceId": sourceA["id"]})
		identityResExpectFields(t, "user[0]", e.rows("user")[0], map[string]any{"name": "Source A Profile"})
	})

	t.Run("allows two connections to link independent sources to one User", func(t *testing.T) {
		target := identityResBackingUser("")
		e := identityResFixture(t, identityResFixtureOptions{
			users:       []adapter.Record{target},
			connections: []ConnectionOptions{identityResConnA, identityResConnB},
			identity:    identityResPreserve(target["id"].(string)),
		})
		sourceA := identityResCreate(e, "connection-a-token", map[string]any{"userName": "source-a@example.com"})
		sourceB := identityResCreate(e, "connection-b-token", map[string]any{"userName": "source-b@example.com"})

		if len(e.rows("user")) != 1 || len(e.rows("account")) != 0 {
			t.Fatalf("users = %d, accounts = %d", len(e.rows("user")), len(e.rows("account")))
		}
		subjects := e.rows("scimSubject")
		if len(subjects) != 1 || subjects[0]["userId"] != target["id"] {
			t.Fatalf("scimSubject = %v", subjects)
		}
		sources := e.rows("scimUser")
		identityResExpectFields(t, "sourceA", identityResFind(sources, "id", sourceA["id"]), map[string]any{
			"connectionId": identityResConnA.ID, "userId": target["id"]})
		identityResExpectFields(t, "sourceB", identityResFind(sources, "id", sourceB["id"]), map[string]any{
			"connectionId": identityResConnB.ID, "userId": target["id"]})
	})

	t.Run("reprovisions a deleted externalId onto the same Better Auth User", func(t *testing.T) {
		e := identityResFixture(t, identityResFixtureOptions{})
		first := identityResCreate(e, "connection-a-token", map[string]any{
			"userName": "first-name@example.com", "externalId": "stable-directory-user"})
		originalSource := identityResFind(e.rows("scimUser"), "id", first["id"])
		if originalSource == nil {
			t.Fatal("Expected the original SCIM source")
		}
		if _, ae := e.call("deleteSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": first["id"].(string)},
			Headers: bearer("connection-a-token")}); ae != nil {
			t.Fatalf("delete: %d %v", ae.StatusCode, errBody(ae))
		}
		tombstones := e.rows("scimIdentityTombstone")
		if len(tombstones) != 1 {
			t.Fatalf("tombstones = %v", tombstones)
		}
		identityResExpectFields(t, "tombstone", tombstones[0], map[string]any{
			"connectionId": identityResConnA.ID, "externalId": "stable-directory-user",
			"userId": originalSource["userId"], "profile": "manage"})

		recreated := identityResCreate(e, "connection-a-token", map[string]any{
			"userName": "renamed@example.com", "externalId": "stable-directory-user"})
		recreatedSource := identityResFind(e.rows("scimUser"), "id", recreated["id"])
		if len(e.rows("user")) != 1 {
			t.Fatalf("users = %d", len(e.rows("user")))
		}
		if recreatedSource == nil || recreatedSource["userId"] != originalSource["userId"] {
			t.Fatalf("recreated source = %v, want userId %v", recreatedSource, originalSource["userId"])
		}
		if n := len(e.rows("scimIdentityTombstone")); n != 0 {
			t.Fatalf("tombstones = %d", n)
		}
	})

	t.Run("revokes sessions only when the final linked source becomes inactive", func(t *testing.T) {
		target := identityResBackingUser("")
		session := identityResSession(target["id"].(string))
		e := identityResFixture(t, identityResFixtureOptions{
			users: []adapter.Record{target}, sessions: []adapter.Record{session},
			connections: []ConnectionOptions{identityResConnA, identityResConnB},
			identity:    identityResPreserve(target["id"].(string)),
		})
		sourceA := identityResCreate(e, "connection-a-token", map[string]any{"userName": "source-a@example.com"})
		sourceB := identityResCreate(e, "connection-b-token", map[string]any{"userName": "source-b@example.com"})
		identityResMustPatch(e, "connection-a-token", sourceA["id"].(string),
			map[string]any{"op": "replace", "path": "active", "value": false})
		sessionsAfterFirstDeactivation := e.rows("session")
		identityResMustPatch(e, "connection-b-token", sourceB["id"].(string),
			map[string]any{"op": "replace", "path": "active", "value": false})

		if len(sessionsAfterFirstDeactivation) != 1 || sessionsAfterFirstDeactivation[0]["id"] != session["id"] ||
			sessionsAfterFirstDeactivation[0]["token"] != session["token"] {
			t.Fatalf("sessions after first deactivation = %v", sessionsAfterFirstDeactivation)
		}
		if n := len(e.rows("session")); n != 0 {
			t.Fatalf("sessions = %d, want 0", n)
		}
	})

	t.Run("does not let application callback mutation redirect session revocation", func(t *testing.T) {
		target := identityResBackingUser("")
		session := identityResSession(target["id"].(string))
		identity := identityResPreserve(target["id"].(string))
		identity.ReconcileUser = func(state IdentityState, _ DatabaseContext) error {
			if state.Active {
				return nil
			}
			state.Active = true
			state.UserID = "different-user"
			return nil
		}
		e := identityResFixture(t, identityResFixtureOptions{
			users: []adapter.Record{target}, sessions: []adapter.Record{session}, identity: identity})
		source := identityResCreate(e, "connection-a-token", map[string]any{"userName": "mutation-attempt@example.com"})
		identityResMustPatch(e, "connection-a-token", source["id"].(string),
			map[string]any{"op": "replace", "path": "active", "value": false})
		if n := len(e.rows("session")); n != 0 {
			t.Fatalf("sessions = %d, want 0", n)
		}
	})

	t.Run("rejects a second source for the same User in one connection", func(t *testing.T) {
		target := identityResBackingUser("")
		e := identityResFixture(t, identityResFixtureOptions{users: []adapter.Record{target},
			identity: identityResPreserve(target["id"].(string))})
		identityResCreate(e, "connection-a-token", map[string]any{"userName": "first-source@example.com"})
		ae := identityResCreateErr(e, "connection-a-token", map[string]any{"userName": "second-source@example.com"})
		identityResExpectUniqueness(t, ae)
		if len(e.rows("user")) != 1 || len(e.rows("account")) != 0 || len(e.rows("scimUser")) != 1 {
			t.Fatalf("users = %d, accounts = %d, sources = %d",
				len(e.rows("user")), len(e.rows("account")), len(e.rows("scimUser")))
		}
	})

	t.Run("rejects a missing link target without persisting partial identity state", func(t *testing.T) {
		e := identityResFixture(t, identityResFixtureOptions{identity: identityResPreserve("missing-user")})
		res := e.request(http.MethodPost, scimUsersURL, map[string]any{
			"schemas":  []any{identityResUserSchema},
			"userName": "missing-target@example.com",
		}, map[string]string{"authorization": "Bearer connection-a-token", "content-type": MediaType})
		if res.Status >= 200 && res.Status < 300 {
			t.Fatalf("expected failure, got %d %s", res.Status, res.text())
		}
		got := [4]int{len(e.rows("user")), len(e.rows("account")), len(e.rows("scimSubject")), len(e.rows("scimUser"))}
		if got != [4]int{} {
			t.Fatalf("users/accounts/subjects/sources = %v, want zeros", got)
		}
	})

	t.Run("rolls back profile, lifecycle, and session changes when reconciliation fails", func(t *testing.T) {
		target := identityResBackingUser("")
		session := identityResSession(target["id"].(string))
		var reject atomic.Bool
		e := identityResFixture(t, identityResFixtureOptions{
			users: []adapter.Record{target}, sessions: []adapter.Record{session},
			identity: &Identity{
				ResolveUser: identityResManage(target["id"].(string)),
				ReconcileUser: func(IdentityState, DatabaseContext) error {
					if reject.Load() {
						return errors.New("Application lifecycle reconciliation failed")
					}
					return nil
				},
			},
		})
		source := identityResCreate(e, "connection-a-token", map[string]any{
			"userName": "managed-source@example.com", "displayName": "Managed Before Failure"})
		revisionBeforeFailure := e.rows("scimSubject")[0]["revision"]
		reject.Store(true)

		_, ae := identityResPatch(e, "connection-a-token", source["id"].(string), map[string]any{
			"op": "replace", "value": map[string]any{"active": false, "displayName": "Managed After Failure"}})
		if ae == nil {
			t.Fatal("expected patch to fail")
		}
		if d := errBody(ae)["detail"]; d != "SCIM identity reconciliation failed" {
			t.Fatalf("detail = %v", d)
		}
		identityResExpectFields(t, "scimUser[0]", e.rows("scimUser")[0], map[string]any{
			"id": source["id"], "active": true, "displayName": "Managed Before Failure"})
		identityResExpectFields(t, "user[0]", e.rows("user")[0], map[string]any{"name": "Managed Before Failure"})
		sessions := e.rows("session")
		if len(sessions) != 1 || sessions[0]["id"] != session["id"] {
			t.Fatalf("sessions = %v", sessions)
		}
		if r := e.rows("scimSubject")[0]["revision"]; !adapter.Equal(r, revisionBeforeFailure) {
			t.Fatalf("subject revision = %v, want %v", r, revisionBeforeFailure)
		}
	})
}

func TestIdentityResActiveUserLinks(t *testing.T) {
	t.Run("acquires exact case-sensitive links isolated by connection", func(t *testing.T) {
		e := identityResFixture(t, identityResFixtureOptions{connections: []ConnectionOptions{identityResConnA, identityResConnB}})
		sourceA := identityResCreate(e, "connection-a-token", map[string]any{
			"userName": "connection-a@example.com", "externalId": "Case-Exact-Subject"})
		sourceB := identityResCreate(e, "connection-b-token", map[string]any{
			"userName": "connection-b@example.com", "externalId": "Case-Exact-Subject"})
		rows := e.rows("scimUser")

		for _, c := range []struct {
			conn   string
			source map[string]any
		}{{identityResConnA.ID, sourceA}, {identityResConnB.ID, sourceB}} {
			got := identityResMustAcquire(t, e, UserExternalIDReference{ConnectionID: c.conn, ExternalID: "Case-Exact-Subject"})
			want := ActiveUserLink{SCIMUserID: c.source["id"].(string),
				UserID: identityResFind(rows, "id", c.source["id"])["userId"].(string)}
			if got == nil || *got != want {
				t.Fatalf("%s link = %+v, want %+v", c.conn, got, want)
			}
		}
		if got := identityResMustAcquire(t, e, UserExternalIDReference{ConnectionID: identityResConnA.ID,
			ExternalID: "case-exact-subject"}); got != nil {
			t.Fatalf("case-insensitive link = %+v, want nil", got)
		}
	})

	t.Run("rejects inactive and deleted links, then follows explicit reprovisioning", func(t *testing.T) {
		e := identityResFixture(t, identityResFixtureOptions{})
		ref := UserExternalIDReference{ConnectionID: identityResConnA.ID, ExternalID: "lifecycle-subject"}
		firstSource := identityResCreate(e, "connection-a-token", map[string]any{
			"userName": "lifecycle@example.com", "externalId": "lifecycle-subject"})
		originalUserID := e.rows("scimUser")[0]["userId"]

		identityResMustPatch(e, "connection-a-token", firstSource["id"].(string),
			map[string]any{"op": "replace", "path": "active", "value": false})
		if got := identityResMustAcquire(t, e, ref); got != nil {
			t.Fatalf("inactive link = %+v", got)
		}
		if _, ae := e.call("deleteSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": firstSource["id"].(string)},
			Headers: bearer("connection-a-token")}); ae != nil {
			t.Fatalf("delete: %d %v", ae.StatusCode, errBody(ae))
		}
		if got := identityResMustAcquire(t, e, ref); got != nil {
			t.Fatalf("deleted link = %+v", got)
		}
		reprovisioned := identityResCreate(e, "connection-a-token", map[string]any{
			"userName": "restored@example.com", "externalId": "lifecycle-subject"})
		got := identityResMustAcquire(t, e, ref)
		want := ActiveUserLink{SCIMUserID: reprovisioned["id"].(string), UserID: originalUserID.(string)}
		if got == nil || *got != want {
			t.Fatalf("reprovisioned link = %+v, want %+v", got, want)
		}
	})

	t.Run("rejects tombstoned, orphaned, and missing-subject links", func(t *testing.T) {
		provisioned := func(externalID string) *testEnv {
			e := identityResFixture(t, identityResFixtureOptions{})
			identityResCreate(e, "connection-a-token", map[string]any{
				"userName": externalID + "@example.com", "externalId": externalID})
			return e
		}
		bg := context.Background()

		tombstoned := provisioned("tombstoned-subject")
		src := tombstoned.rows("scimUser")[0]
		tombstoned.insert("scimIdentityTombstone", adapter.Record{
			"id": "stale-tombstone", "connectionId": identityResConnA.ID,
			"provisioningDomainId": src["provisioningDomainId"], "externalId": "tombstoned-subject",
			"externalIdKey": CreateUserExternalIDKey(identityResConnA.ID, "tombstoned-subject"),
			"userId":        src["userId"], "profile": "preserve", "deletedAt": time.Now(),
		})
		if got := identityResMustAcquire(t, tombstoned, UserExternalIDReference{ConnectionID: identityResConnA.ID,
			ExternalID: "tombstoned-subject"}); got != nil {
			t.Fatalf("tombstoned link = %+v", got)
		}

		orphaned := provisioned("orphaned-subject")
		for _, u := range orphaned.rows("user") {
			if err := orphaned.db().Delete(bg, "user", []adapter.Where{{Field: "id", Value: u["id"]}}); err != nil {
				t.Fatal(err)
			}
		}
		if got := identityResMustAcquire(t, orphaned, UserExternalIDReference{ConnectionID: identityResConnA.ID,
			ExternalID: "orphaned-subject"}); got != nil {
			t.Fatalf("orphaned link = %+v", got)
		}

		missingSubject := provisioned("missing-subject")
		for _, s := range missingSubject.rows("scimSubject") {
			if err := missingSubject.db().Delete(bg, "scimSubject", []adapter.Where{{Field: "id", Value: s["id"]}}); err != nil {
				t.Fatal(err)
			}
		}
		if got := identityResMustAcquire(t, missingSubject, UserExternalIDReference{ConnectionID: identityResConnA.ID,
			ExternalID: "missing-subject"}); got != nil {
			t.Fatalf("missing-subject link = %+v", got)
		}
	})

	t.Run("rejects decommissioned and provisioning-domain-inconsistent links", func(t *testing.T) {
		bg := context.Background()
		decommissioned := identityResFixture(t, identityResFixtureOptions{})
		identityResCreate(decommissioned, "connection-a-token", map[string]any{
			"userName": "decommissioned@example.com", "externalId": "decommissioned-subject"})
		binding := decommissioned.rows("scimConnectionBinding")[0]
		if _, err := decommissioned.db().Update(bg, "scimConnectionBinding", []adapter.Where{{Field: "id", Value: binding["id"]}},
			adapter.Record{"decommissionStatus": "complete"}); err != nil {
			t.Fatal(err)
		}
		if got := identityResMustAcquire(t, decommissioned, UserExternalIDReference{ConnectionID: identityResConnA.ID,
			ExternalID: "decommissioned-subject"}); got != nil {
			t.Fatalf("decommissioned link = %+v", got)
		}

		inconsistent := identityResFixture(t, identityResFixtureOptions{})
		identityResCreate(inconsistent, "connection-a-token", map[string]any{
			"userName": "inconsistent@example.com", "externalId": "inconsistent-subject"})
		src := inconsistent.rows("scimUser")[0]
		if _, err := inconsistent.db().Update(bg, "scimUser", []adapter.Where{{Field: "id", Value: src["id"]}},
			adapter.Record{"provisioningDomainId": "different-domain"}); err != nil {
			t.Fatal(err)
		}
		if got := identityResMustAcquire(t, inconsistent, UserExternalIDReference{ConnectionID: identityResConnA.ID,
			ExternalID: "inconsistent-subject"}); got != nil {
			t.Fatalf("inconsistent link = %+v", got)
		}
	})
}
