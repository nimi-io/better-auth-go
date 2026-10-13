package scim

// Port of upstream scim-user-concurrency.test.ts (@better-auth/scim v1.7.7).
//
// Upstream wraps the memory adapter's transaction adapter to inject pauses and stale-fence
// failures, and interleaves requests with Promise.all/deferreds. Here the auth adapter is
// wrapped (userConcAdapter) so calls made inside a transaction (identified by a context
// value set by the wrapper's Transaction) are routed through hooks, and requests are
// interleaved with goroutines and channels.

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

const (
	userConcUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	userConcGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	userConcPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	userConcToken       = "test-scim-token"
	userConcWaitTimeout = 10 * time.Second
)

// userConcTx is the per-transaction state of a wrapped transaction.
type userConcTx struct {
	mu       sync.Mutex
	held     map[string]bool
	releases []func()
	// order records scimGroup lock acquisitions (membership race).
	order *[]string
}

func (s *userConcTx) holds(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held[id]
}

func (s *userConcTx) hold(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held[id] = true
}

type userConcTxKey struct{}

// userConcAdapter wraps the auth adapter; the hooks only see calls made inside a
// transaction opened through the wrapper (upstream wraps the transaction adapter).
type userConcAdapter struct {
	adapter.Adapter
	onBegin      func(st *userConcTx)
	incrementOne func(ctx context.Context, st *userConcTx, in adapter.IncrementInput, next func() (adapter.Record, error)) (adapter.Record, error)
	create       func(ctx context.Context, st *userConcTx, in adapter.CreateInput, next func() (adapter.Record, error)) (adapter.Record, error)
	count        func(ctx context.Context, st *userConcTx, model string, where []adapter.Where, next func() (int64, error)) (int64, error)
}

func (a *userConcAdapter) SupportsNativeTransactions() bool { return true }

func userConcState(ctx context.Context) *userConcTx {
	st, _ := ctx.Value(userConcTxKey{}).(*userConcTx)
	return st
}

func (a *userConcAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	if userConcState(ctx) != nil {
		return a.Adapter.Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error { return fn(txCtx, a) })
	}
	st := &userConcTx{held: map[string]bool{}}
	if a.onBegin != nil {
		a.onBegin(st)
	}
	defer func() {
		st.mu.Lock()
		releases := st.releases
		st.mu.Unlock()
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	return a.Adapter.Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error {
		return fn(context.WithValue(txCtx, userConcTxKey{}, st), a)
	})
}

func (a *userConcAdapter) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	next := func() (adapter.Record, error) { return a.Adapter.IncrementOne(ctx, in) }
	if st := userConcState(ctx); st != nil && a.incrementOne != nil {
		return a.incrementOne(ctx, st, in, next)
	}
	return next()
}

func (a *userConcAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	next := func() (adapter.Record, error) { return a.Adapter.Create(ctx, in) }
	if st := userConcState(ctx); st != nil && a.create != nil {
		return a.create(ctx, st, in, next)
	}
	return next()
}

func (a *userConcAdapter) Count(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	next := func() (int64, error) { return a.Adapter.Count(ctx, model, where) }
	if st := userConcState(ctx); st != nil && a.count != nil {
		return a.count(ctx, st, model, where, next)
	}
	return next()
}

// userConcWrap installs the wrapper as the auth adapter.
func userConcWrap(w *userConcAdapter) func(cfg *betterauth.Config) {
	return func(cfg *betterauth.Config) {
		inner := cfg.Database
		cfg.Database = func(opts adapter.Options) (adapter.Adapter, error) {
			a, err := inner(opts)
			if err != nil {
				return nil, err
			}
			w.Adapter = a
			return w, nil
		}
	}
}

func userConcWhereValue(where []adapter.Where, field string) any {
	for _, c := range where {
		if c.Field == field {
			return c.Value
		}
	}
	return nil
}

// userConcLive reads a committed row outside any transaction.
func userConcLive(e *testEnv, model, id string) adapter.Record {
	e.t.Helper()
	r, err := e.db().FindOne(context.Background(), adapter.FindOneInput{Model: model, Where: []adapter.Where{{Field: "id", Value: id}}})
	if err != nil {
		panic(err)
	}
	return r
}

func userConcSameNumber(a, b any) bool {
	fa, oka := adapter.ToFloat(a)
	fb, okb := adapter.ToFloat(b)
	return oka && okb && fa == fb
}

func userConcEnv(t *testing.T, opts Options, w *userConcAdapter) *testEnv {
	t.Helper()
	if opts.Connections == nil {
		opts.Connections = []ConnectionOptions{staticConnection("workforce", userConcToken)}
	}
	eo := envOptions{}
	if w != nil {
		eo.mutate = userConcWrap(w)
	}
	return newEnv(t, opts, eo)
}

func userConcAsync(e *testEnv, key string, in betterauth.CallInput) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := e.callErr(key, in)
		done <- err
	}()
	return done
}

// userConcAwait waits for reached (or an early result of the paused request).
func userConcAwait(t *testing.T, reached <-chan struct{}, done <-chan error) {
	t.Helper()
	select {
	case <-reached:
	case err := <-done:
		t.Fatalf("paused request finished before reaching the pause: %v", err)
	case <-time.After(userConcWaitTimeout):
		t.Fatal("timed out waiting for the paused request")
	}
}

func userConcResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(userConcWaitTimeout):
		t.Fatal("timed out waiting for the request")
		return nil
	}
}

func userConcRevisions(e *testEnv) [2]any {
	return [2]any{e.rows("scimSubject")[0]["revision"], e.rows("scimConnectionBinding")[0]["decommissionRevision"]}
}

func userConcBody(m map[string]any) betterauth.CallInput {
	return betterauth.CallInput{Body: m, Headers: bearer(userConcToken)}
}

// userConcLinkDB is a LinkDatabase built from functions.
type userConcLinkDB struct {
	findOne      func(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error)
	incrementOne func(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error)
}

func (d userConcLinkDB) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	return d.findOne(ctx, in)
}

func (d userConcLinkDB) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	return d.incrementOne(ctx, in)
}

func userConcExpect409(t *testing.T, err error) {
	t.Helper()
	ae, ok := betterauth.AsAPIError(err)
	if !ok || ae.StatusCode != 409 {
		t.Fatalf("expected a 409 error, got %v", err)
	}
}

func TestUserConcSCIMUserConcurrency(t *testing.T) {
	t.Run("retries concurrent first-time links to the same Better Auth User", func(t *testing.T) {
		reached, release := make(chan struct{}), make(chan struct{})
		var paused atomic.Bool
		var e *testEnv
		w := &userConcAdapter{}
		w.create = func(ctx context.Context, _ *userConcTx, in adapter.CreateInput, next func() (adapter.Record, error)) (adapter.Record, error) {
			if in.Model != "scimSubject" {
				return next()
			}
			if paused.CompareAndSwap(false, true) {
				close(reached)
				<-release
			}
			n, err := e.db().Count(context.Background(), "scimSubject", nil)
			if err != nil {
				return nil, err
			}
			if n > 0 {
				return nil, errors.New("Simulated unique scimSubject userId conflict")
			}
			return next()
		}
		e = userConcEnv(t, Options{
			Connections: []ConnectionOptions{
				staticConnection("workforce-a", "connection-a-token"),
				staticConnection("workforce-b", "connection-b-token"),
			},
			Identity: &Identity{ResolveUser: func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
				return &IdentityResolution{Action: "link", UserID: "existing-user", Profile: "preserve"}, nil
			}},
		}, w)
		now := time.Now()
		e.insert("user", adapter.Record{"id": "existing-user", "name": "Existing User", "email": "existing@example.com",
			"emailVerified": true, "image": nil, "createdAt": now, "updatedAt": now})

		firstLink := userConcAsync(e, "createSCIMUser", betterauth.CallInput{
			Body: map[string]any{"schemas": []any{userConcUserSchema}, "userName": "first-link@example.com",
				"externalId": "first-link"},
			Headers: bearer("connection-a-token"),
		})
		userConcAwait(t, reached, firstLink)
		func() {
			defer close(release)
			if _, ae := e.call("createSCIMUser", betterauth.CallInput{
				Body: map[string]any{"schemas": []any{userConcUserSchema}, "userName": "second-link@example.com",
					"externalId": "second-link"},
				Headers: bearer("connection-b-token"),
			}); ae != nil {
				t.Errorf("second link: %d %v", ae.StatusCode, errBody(ae))
			}
		}()
		if err := userConcResult(t, firstLink); err != nil {
			t.Fatalf("first link: %v", err)
		}

		if n := len(e.rows("scimSubject")); n != 1 {
			t.Fatalf("scimSubject rows = %d, want 1", n)
		}
		found := map[string]bool{}
		for _, s := range e.rows("scimUser") {
			if s["userId"] == "existing-user" {
				found[s["connectionId"].(string)] = true
			}
		}
		if !found["workforce-a"] || !found["workforce-b"] {
			t.Fatalf("scimUser rows = %v", e.rows("scimUser"))
		}
	})

	t.Run("retries PATCH against the source committed before its subject lock", func(t *testing.T) {
		reached, release := make(chan struct{}), make(chan struct{})
		var enabled, paused, secondCommitted atomic.Bool
		var e *testEnv
		w := &userConcAdapter{}
		w.incrementOne = func(ctx context.Context, st *userConcTx, in adapter.IncrementInput, next func() (adapter.Record, error)) (adapter.Record, error) {
			if in.Model != "scimSubject" {
				return next()
			}
			subjectID, ok := userConcWhereValue(in.Where, "id").(string)
			expected := userConcWhereValue(in.Where, "revision")
			if !ok || st.holds(subjectID) {
				return next()
			}
			if enabled.Load() && paused.CompareAndSwap(false, true) {
				close(reached)
				<-release
			}
			if enabled.Load() && secondCommitted.Load() {
				live := userConcLive(e, "scimSubject", subjectID)
				if live == nil || !userConcSameNumber(live["revision"], expected) {
					return nil, nil
				}
			}
			st.hold(subjectID)
			return next()
		}
		e = userConcEnv(t, Options{}, w)
		user := e.mustCall("createSCIMUser", userConcBody(map[string]any{"schemas": []any{userConcUserSchema},
			"userName": "patch-race@example.com", "displayName": "Initial display name", "active": true}))
		id := user["id"].(string)
		enabled.Store(true)

		displayNamePatch := userConcAsync(e, "patchSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id},
			Body: map[string]any{"schemas": []any{userConcPatchSchema}, "Operations": []any{
				map[string]any{"op": "replace", "path": "displayName", "value": "Committed display name"}}},
			Headers: bearer(userConcToken),
		})
		userConcAwait(t, reached, displayNamePatch)
		func() {
			defer close(release)
			if _, ae := e.call("patchSCIMUser", betterauth.CallInput{
				Params: map[string]string{"userId": id},
				Body: map[string]any{"schemas": []any{userConcPatchSchema}, "Operations": []any{
					map[string]any{"op": "replace", "path": "active", "value": false}}},
				Headers: bearer(userConcToken),
			}); ae != nil {
				t.Errorf("active patch: %d %v", ae.StatusCode, errBody(ae))
				return
			}
			secondCommitted.Store(true)
		}()
		if err := userConcResult(t, displayNamePatch); err != nil {
			t.Fatalf("displayName patch: %v", err)
		}

		current := e.mustCall("getSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": id},
			Headers: bearer(userConcToken)})
		if current["active"] != false || current["displayName"] != "Committed display name" {
			t.Fatalf("current = active %v, displayName %v", current["active"], current["displayName"])
		}
	})

	t.Run("tombstones the source state committed before the subject lock", func(t *testing.T) {
		reached, release := make(chan struct{}), make(chan struct{})
		var enabled, groupLockPaused, patchCommitted atomic.Bool
		var e *testEnv
		w := &userConcAdapter{}
		w.incrementOne = func(ctx context.Context, st *userConcTx, in adapter.IncrementInput, next func() (adapter.Record, error)) (adapter.Record, error) {
			if enabled.Load() && in.Model == "scimGroup" && groupLockPaused.CompareAndSwap(false, true) {
				close(reached)
				<-release
			}
			if in.Model == "scimSubject" {
				subjectID, ok := userConcWhereValue(in.Where, "id").(string)
				expected := userConcWhereValue(in.Where, "revision")
				if ok && !st.holds(subjectID) {
					if enabled.Load() && patchCommitted.Load() {
						live := userConcLive(e, "scimSubject", subjectID)
						if live == nil || !userConcSameNumber(live["revision"], expected) {
							return nil, nil
						}
					}
					st.hold(subjectID)
				}
			}
			return next()
		}
		e = userConcEnv(t, Options{}, w)
		user := e.mustCall("createSCIMUser", userConcBody(map[string]any{"schemas": []any{userConcUserSchema},
			"userName": "source-race@example.com", "externalId": "old-directory-id"}))
		id := user["id"].(string)
		e.mustCall("createSCIMGroup", userConcBody(map[string]any{"schemas": []any{userConcGroupSchema},
			"displayName": "source-race", "members": []any{map[string]any{"value": id}}}))
		enabled.Store(true)

		deletion := userConcAsync(e, "deleteSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": id},
			Headers: bearer(userConcToken)})
		userConcAwait(t, reached, deletion)
		func() {
			defer close(release)
			if _, ae := e.call("patchSCIMUser", betterauth.CallInput{
				Params: map[string]string{"userId": id},
				Body: map[string]any{"schemas": []any{userConcPatchSchema}, "Operations": []any{
					map[string]any{"op": "replace", "path": "externalId", "value": "new-directory-id"}}},
				Headers: bearer(userConcToken),
			}); ae != nil {
				t.Errorf("externalId patch: %d %v", ae.StatusCode, errBody(ae))
				return
			}
			patchCommitted.Store(true)
		}()
		if err := userConcResult(t, deletion); err != nil {
			t.Fatalf("deletion: %v", err)
		}

		tombstones := e.rows("scimIdentityTombstone")
		users := e.rows("user")
		if len(tombstones) != 1 || len(users) == 0 || tombstones[0]["externalId"] != "new-directory-id" ||
			tombstones[0]["userId"] != users[0]["id"] {
			t.Fatalf("tombstones = %v", tombstones)
		}
	})

	t.Run("retries a new membership and updates every Group in sorted lock order", func(t *testing.T) {
		type raceInput struct{ concurrentGroupID, scimUserID string }
		var race atomic.Pointer[raceInput]
		var injected atomic.Bool
		var orderMu sync.Mutex
		var lockOrderByAttempt []*[]string
		var e *testEnv
		w := &userConcAdapter{}
		w.onBegin = func(st *userConcTx) {
			if race.Load() == nil {
				return
			}
			order := &[]string{}
			st.order = order
			orderMu.Lock()
			lockOrderByAttempt = append(lockOrderByAttempt, order)
			orderMu.Unlock()
		}
		w.incrementOne = func(ctx context.Context, st *userConcTx, in adapter.IncrementInput, next func() (adapter.Record, error)) (adapter.Record, error) {
			if st.order == nil {
				return next()
			}
			active := race.Load()
			if _, hasRevision := in.Increment["revision"]; in.Model == "scimGroup" && hasRevision {
				if groupID, ok := userConcWhereValue(in.Where, "id").(string); ok {
					orderMu.Lock()
					*st.order = append(*st.order, groupID)
					orderMu.Unlock()
				}
			}
			if in.Model == "scimSubject" {
				subjectID, ok := userConcWhereValue(in.Where, "id").(string)
				if ok && !st.holds(subjectID) {
					if injected.CompareAndSwap(false, true) {
						bg := context.Background()
						source := userConcLive(e, "scimUser", active.scimUserID)
						liveSubject := userConcLive(e, "scimSubject", subjectID)
						liveGroup := userConcLive(e, "scimGroup", active.concurrentGroupID)
						if source == nil || liveSubject == nil || liveGroup == nil {
							return nil, errors.New("Expected live SCIM race state")
						}
						committedAt := time.Now()
						if _, err := e.db().Create(bg, adapter.CreateInput{Model: "scimGroupMember", ForceAllowID: true, Data: adapter.Record{
							"id": "concurrent-membership", "connectionId": "workforce", "groupId": liveGroup["id"],
							"scimUserId": source["id"], "membershipKey": "concurrent-membership-key", "createdAt": committedAt,
						}}); err != nil {
							return nil, err
						}
						gr, _ := adapter.ToFloat(liveGroup["revision"])
						if _, err := e.db().Update(bg, "scimGroup", []adapter.Where{{Field: "id", Value: liveGroup["id"]}},
							adapter.Record{"revision": int(gr) + 1, "updatedAt": committedAt}); err != nil {
							return nil, err
						}
						sr, _ := adapter.ToFloat(liveSubject["revision"])
						if _, err := e.db().Update(bg, "scimSubject", []adapter.Where{{Field: "id", Value: subjectID}},
							adapter.Record{"revision": int(sr) + 1, "updatedAt": committedAt}); err != nil {
							return nil, err
						}
						return nil, nil
					}
					st.hold(subjectID)
				}
			}
			return next()
		}
		e = userConcEnv(t, Options{}, w)
		user := e.mustCall("createSCIMUser", userConcBody(map[string]any{"schemas": []any{userConcUserSchema},
			"userName": "membership-race@example.com"}))
		id := user["id"].(string)
		initialGroup := e.mustCall("createSCIMGroup", userConcBody(map[string]any{"schemas": []any{userConcGroupSchema},
			"displayName": "initial-membership", "members": []any{map[string]any{"value": id}}}))
		concurrentGroup := e.mustCall("createSCIMGroup", userConcBody(map[string]any{"schemas": []any{userConcGroupSchema},
			"displayName": "concurrent-membership"}))
		for _, g := range e.rows("scimGroup") {
			if _, err := e.db().Update(context.Background(), "scimGroup", []adapter.Where{{Field: "id", Value: g["id"]}},
				adapter.Record{"updatedAt": time.UnixMilli(0)}); err != nil {
				t.Fatal(err)
			}
		}
		race.Store(&raceInput{concurrentGroupID: concurrentGroup["id"].(string), scimUserID: id})

		if _, ae := e.call("deleteSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": id},
			Headers: bearer(userConcToken)}); ae != nil {
			t.Fatalf("delete: %d %v", ae.StatusCode, errBody(ae))
		}

		initialID, concurrentID := initialGroup["id"].(string), concurrentGroup["id"].(string)
		sorted := []string{initialID, concurrentID}
		sort.Strings(sorted)
		var got [][]string
		for _, o := range lockOrderByAttempt {
			got = append(got, *o)
		}
		if len(got) != 2 || len(got[0]) != 1 || got[0][0] != initialID || len(got[1]) != 2 ||
			got[1][0] != sorted[0] || got[1][1] != sorted[1] {
			t.Fatalf("group lock order by attempt = %v, want [[%s] %v]", got, initialID, sorted)
		}
		if n := len(e.rows("scimGroupMember")); n != 0 {
			t.Fatalf("scimGroupMember rows = %d, want 0", n)
		}
		groups := e.rows("scimGroup")
		for _, c := range []struct {
			id       string
			revision int
		}{{initialID, 1}, {concurrentID, 2}} {
			g := identityResFind(groups, "id", c.id)
			if g == nil || !userConcSameNumber(g["revision"], c.revision) {
				t.Errorf("group %s = %v, want revision %d", c.id, g, c.revision)
			}
		}
		for _, g := range groups {
			if ts, ok := adapter.ToTime(g["updatedAt"]); !ok || ts.UnixMilli() <= 0 {
				t.Errorf("group %v updatedAt = %v, want > 0", g["id"], g["updatedAt"])
			}
		}
	})

	t.Run("aborts active-link acquisition when the subject revision fence is lost", func(t *testing.T) {
		e := userConcEnv(t, Options{}, nil)
		e.mustCall("createSCIMUser", userConcBody(map[string]any{"schemas": []any{userConcUserSchema},
			"userName": "subject-race@example.com", "externalId": "subject-race"}))
		before := userConcRevisions(e)
		err := e.db().Transaction(context.Background(), func(txCtx context.Context, tx adapter.Adapter) error {
			_, err := AcquireActiveUserLink(txCtx, UserExternalIDReference{ConnectionID: "workforce", ExternalID: "subject-race"},
				userConcLinkDB{findOne: tx.FindOne, incrementOne: func(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
					if in.Model == "scimSubject" {
						return nil, nil
					}
					return tx.IncrementOne(ctx, in)
				}})
			return err
		})
		userConcExpect409(t, err)
		if after := userConcRevisions(e); !adapter.Equal(after[0], before[0]) || !adapter.Equal(after[1], before[1]) {
			t.Fatalf("revisions = %v, want %v", after, before)
		}
	})

	t.Run("returns one success and one retryable conflict when acquisitions lose the same revision race", func(t *testing.T) {
		e := userConcEnv(t, Options{}, nil)
		resource := e.mustCall("createSCIMUser", userConcBody(map[string]any{"schemas": []any{userConcUserSchema},
			"userName": "parallel-acquisition@example.com", "externalId": "parallel-acquisition"}))
		base := e.db()
		incrementsReady := make(chan struct{})
		var pending atomic.Int32
		db := userConcLinkDB{findOne: base.FindOne, incrementOne: func(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
			if in.Model == "scimSubject" {
				if pending.Add(1) == 2 {
					close(incrementsReady)
				} else {
					<-incrementsReady
				}
			}
			return base.IncrementOne(ctx, in)
		}}
		type result struct {
			link *ActiveUserLink
			err  error
		}
		results := make(chan result, 2)
		for range 2 {
			go func() {
				l, err := AcquireActiveUserLink(context.Background(),
					UserExternalIDReference{ConnectionID: "workforce", ExternalID: "parallel-acquisition"}, db)
				results <- result{l, err}
			}()
		}
		var fulfilled []*ActiveUserLink
		var rejected []error
		for range 2 {
			select {
			case r := <-results:
				if r.err != nil {
					rejected = append(rejected, r.err)
				} else {
					fulfilled = append(fulfilled, r.link)
				}
			case <-time.After(userConcWaitTimeout):
				t.Fatal("timed out waiting for acquisitions")
			}
		}
		want := ActiveUserLink{SCIMUserID: resource["id"].(string), UserID: e.rows("scimUser")[0]["userId"].(string)}
		if len(fulfilled) != 1 || fulfilled[0] == nil || *fulfilled[0] != want {
			t.Fatalf("fulfilled = %v, want one %+v", fulfilled, want)
		}
		if len(rejected) != 1 {
			t.Fatalf("rejected = %v, want one", rejected)
		}
		userConcExpect409(t, rejected[0])
	})

	t.Run("aborts when the source changes after subject acquisition", func(t *testing.T) {
		e := userConcEnv(t, Options{}, nil)
		e.mustCall("createSCIMUser", userConcBody(map[string]any{"schemas": []any{userConcUserSchema},
			"userName": "source-race@example.com", "externalId": "source-race"}))
		before := userConcRevisions(e)
		err := e.db().Transaction(context.Background(), func(txCtx context.Context, tx adapter.Adapter) error {
			subjectAcquired := false
			_, err := AcquireActiveUserLink(txCtx, UserExternalIDReference{ConnectionID: "workforce", ExternalID: "source-race"},
				userConcLinkDB{
					incrementOne: func(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
						updated, err := tx.IncrementOne(ctx, in)
						if in.Model == "scimSubject" && updated != nil {
							subjectAcquired = true
						}
						return updated, err
					},
					findOne: func(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
						if subjectAcquired && in.Model == "scimUser" {
							return nil, nil
						}
						return tx.FindOne(ctx, in)
					},
				})
			return err
		})
		userConcExpect409(t, err)
		if after := userConcRevisions(e); !adapter.Equal(after[0], before[0]) || !adapter.Equal(after[1], before[1]) {
			t.Fatalf("revisions = %v, want %v", after, before)
		}
	})

	t.Run("aborts when connection decommissioning wins the final fence", func(t *testing.T) {
		e := userConcEnv(t, Options{}, nil)
		e.mustCall("createSCIMUser", userConcBody(map[string]any{"schemas": []any{userConcUserSchema},
			"userName": "connection-race@example.com", "externalId": "connection-race"}))
		before := userConcRevisions(e)
		err := e.db().Transaction(context.Background(), func(txCtx context.Context, tx adapter.Adapter) error {
			_, err := AcquireActiveUserLink(txCtx, UserExternalIDReference{ConnectionID: "workforce", ExternalID: "connection-race"},
				userConcLinkDB{findOne: tx.FindOne, incrementOne: func(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
					if in.Model == "scimConnectionBinding" {
						return nil, nil
					}
					return tx.IncrementOne(ctx, in)
				}})
			return err
		})
		userConcExpect409(t, err)
		if after := userConcRevisions(e); !adapter.Equal(after[0], before[0]) || !adapter.Equal(after[1], before[1]) {
			t.Fatalf("revisions = %v, want %v", after, before)
		}
	})
}
