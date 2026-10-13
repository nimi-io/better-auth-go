package scim

// Port of upstream scim-group-patch-delta.test.ts ("SCIM incremental Group PATCH").

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

const (
	gpdToken       = "test-scim-token"
	gpdPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	gpdUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	gpdGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

func gpdNewEnv(t *testing.T, projection *Projection, wrap func(adapter.Adapter) adapter.Adapter) *testEnv {
	t.Helper()
	eo := envOptions{}
	if wrap != nil {
		eo.mutate = func(cfg *betterauth.Config) {
			inner := cfg.Database
			cfg.Database = func(opts adapter.Options) (adapter.Adapter, error) {
				a, err := inner(opts)
				if err != nil {
					return nil, err
				}
				return wrap(a), nil
			}
		}
	}
	return newEnv(t, Options{
		Connections: []ConnectionOptions{staticConnection("workforce", gpdToken)},
		Projection:  projection,
	}, eo)
}

func gpdCall(e *testEnv, key string, in betterauth.CallInput) map[string]any {
	e.t.Helper()
	in.Headers = bearer(gpdToken)
	return e.mustCall(key, in)
}

func gpdCreateUser(e *testEnv, body map[string]any) string {
	e.t.Helper()
	body["schemas"] = []any{gpdUserSchema}
	return gpdCall(e, "createSCIMUser", betterauth.CallInput{Body: body})["id"].(string)
}

func gpdCreateGroup(e *testEnv, displayName string, members ...string) string {
	e.t.Helper()
	body := map[string]any{"schemas": []any{gpdGroupSchema}, "displayName": displayName}
	if len(members) > 0 {
		ms := []any{}
		for _, m := range members {
			ms = append(ms, map[string]any{"value": m})
		}
		body["members"] = ms
	}
	return gpdCall(e, "createSCIMGroup", betterauth.CallInput{Body: body})["id"].(string)
}

// gpdMembersPatchInput is a patchSCIMGroup call with one members operation.
func gpdMembersPatchInput(groupID, op, userID string) betterauth.CallInput {
	return betterauth.CallInput{
		Headers: bearer(gpdToken),
		Params:  map[string]string{"groupId": groupID},
		Body: map[string]any{"schemas": []any{gpdPatchSchema}, "Operations": []any{
			map[string]any{"op": op, "path": "members", "value": []any{map[string]any{"value": userID}}},
		}},
	}
}

func gpdRow(e *testEnv, model, field string, value any) adapter.Record {
	for _, r := range e.rows(model) {
		if fmt.Sprint(r[field]) == fmt.Sprint(value) {
			return r
		}
	}
	return nil
}

func gpdNum(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func gpdWhereValue(where []adapter.Where, field string) any {
	for _, w := range where {
		if w.Field == field {
			return w.Value
		}
	}
	return nil
}

// ---- createSubjectLockingMemoryAdapter ----

type gpdLockStateKey struct{}

type gpdLockState struct {
	held     map[string]bool
	releases []func()
}

// gpdSubjectLockingAdapter emulates per-subject row locks held until the transaction ends:
// a subject revision fence waits for any other transaction holding the subject and then
// checks the live (committed) revision.
type gpdSubjectLockingAdapter struct {
	adapter.Adapter
	mu     sync.Mutex
	tails  map[string]chan struct{}
	onWait func()
}

func (a *gpdSubjectLockingAdapter) SupportsNativeTransactions() bool { return true }

func (a *gpdSubjectLockingAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	st := &gpdLockState{held: map[string]bool{}}
	defer func() {
		for i := len(st.releases) - 1; i >= 0; i-- {
			st.releases[i]()
		}
	}()
	return a.Adapter.Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error {
		return fn(context.WithValue(txCtx, gpdLockStateKey{}, st), a)
	})
}

func (a *gpdSubjectLockingAdapter) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	st, _ := ctx.Value(gpdLockStateKey{}).(*gpdLockState)
	if in.Model != modelSubject || st == nil {
		return a.Adapter.IncrementOne(ctx, in)
	}
	subjectID, ok := gpdWhereValue(in.Where, "id").(string)
	expected, okRev := gpdNum(gpdWhereValue(in.Where, "revision"))
	if !ok || !okRev || st.held[subjectID] {
		return a.Adapter.IncrementOne(ctx, in)
	}
	a.mu.Lock()
	previous := a.tails[subjectID]
	current := make(chan struct{})
	a.tails[subjectID] = current
	a.mu.Unlock()
	if previous != nil {
		a.onWait()
		<-previous
	}
	st.held[subjectID] = true
	st.releases = append(st.releases, func() {
		close(current)
		a.mu.Lock()
		if a.tails[subjectID] == current {
			delete(a.tails, subjectID)
		}
		a.mu.Unlock()
	})
	// Read the committed row (outside the transaction snapshot).
	live, err := a.Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: modelSubject,
		Where: []adapter.Where{{Field: "id", Value: subjectID}}})
	if err != nil {
		return nil, err
	}
	if live == nil {
		return a.Adapter.IncrementOne(ctx, in)
	}
	if rev, _ := gpdNum(live["revision"]); rev != expected {
		return nil, nil
	}
	return a.Adapter.IncrementOne(ctx, in)
}

// ---- createMutationOrderMemoryAdapter ----

type gpdMutationOrderAdapter struct {
	adapter.Adapter
	mu         sync.Mutex
	operations []string
}

func (a *gpdMutationOrderAdapter) SupportsNativeTransactions() bool { return true }

func (a *gpdMutationOrderAdapter) record(op string) {
	a.mu.Lock()
	a.operations = append(a.operations, op)
	a.mu.Unlock()
}

func (a *gpdMutationOrderAdapter) reset() {
	a.mu.Lock()
	a.operations = nil
	a.mu.Unlock()
}

func (a *gpdMutationOrderAdapter) ops() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string{}, a.operations...)
}

func (a *gpdMutationOrderAdapter) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	if betterauth.InTransaction(ctx) {
		switch in.Model {
		case modelGroup:
			a.record("group-lock")
		case modelSubject:
			a.record("subject-lock")
		}
	}
	return a.Adapter.IncrementOne(ctx, in)
}

func (a *gpdMutationOrderAdapter) DeleteMany(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	if betterauth.InTransaction(ctx) && model == modelGroupMember {
		a.record("membership-write")
	}
	return a.Adapter.DeleteMany(ctx, model, where)
}

func gpdExpectLockOrder(t *testing.T, ops []string) {
	t.Helper()
	g, s, m := slices.Index(ops, "group-lock"), slices.Index(ops, "subject-lock"), slices.Index(ops, "membership-write")
	if g < 0 || s < 0 || m < 0 {
		t.Fatalf("operations = %v, want group-lock, subject-lock and membership-write", ops)
	}
	if g >= s || s >= m {
		t.Fatalf("operations = %v, want group-lock < subject-lock < membership-write", ops)
	}
}

func TestScimGroupPatchDelta(t *testing.T) {
	t.Run("returns the updated resource and reconciles only the membership delta", func(t *testing.T) {
		var mu sync.Mutex
		var reconciled []string
		e := gpdNewEnv(t, &Projection{ReconcileUser: func(state ProjectedUserState, _ DatabaseContext) error {
			mu.Lock()
			reconciled = append(reconciled, state.UserID)
			mu.Unlock()
			return nil
		}}, nil)
		first := gpdCreateUser(e, map[string]any{"userName": "first@example.com"})
		second := gpdCreateUser(e, map[string]any{"userName": "second@example.com"})
		added := gpdCreateUser(e, map[string]any{"userName": "added@example.com"})
		groupID := gpdCreateGroup(e, "Engineering", first, second)
		mu.Lock()
		reconciled = nil
		mu.Unlock()

		res := e.request("PATCH", scimGroupsURL+"/"+groupID, map[string]any{
			"schemas": []any{gpdPatchSchema},
			"Operations": []any{
				map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": added}}},
			},
		}, map[string]string{"Authorization": "Bearer " + gpdToken, "Content-Type": "application/scim+json"})
		addedSource := gpdRow(e, "scimUser", "id", added)
		if addedSource == nil {
			t.Fatal("Expected the added SCIM User")
		}

		if res.Status != 200 {
			t.Fatalf("status = %d %s", res.Status, res.text())
		}
		if loc := res.Header.Get("Location"); !strings.Contains(loc, "/Groups/"+groupID) {
			t.Fatalf("location = %q", loc)
		}
		body := res.json()
		if body["id"] != groupID {
			t.Fatalf("body = %v", body)
		}
		found := false
		ms, _ := body["members"].([]any)
		for _, m := range ms {
			if mm, ok := m.(map[string]any); ok && mm["value"] == added {
				found = true
			}
		}
		if !found {
			t.Fatalf("members = %v, want %s", body["members"], added)
		}
		mu.Lock()
		got := append([]string{}, reconciled...)
		mu.Unlock()
		if !reflect.DeepEqual(got, []string{addedSource["userId"].(string)}) {
			t.Fatalf("reconciled = %v, want [%v]", got, addedSource["userId"])
		}
		count := 0
		for _, r := range e.rows("scimGroupMember") {
			if r["groupId"] == groupID {
				count++
			}
		}
		if count != 3 {
			t.Fatalf("memberships = %d, want 3", count)
		}

		persisted := gpdRow(e, "scimGroup", "id", groupID)
		if persisted == nil {
			t.Fatal("Expected the persisted SCIM Group")
		}
		updatedAtAfterChange := persisted["updatedAt"]
		mu.Lock()
		reconciled = nil
		mu.Unlock()
		e.mustCall("patchSCIMGroup", gpdMembersPatchInput(groupID, "add", added))

		after := gpdRow(e, "scimGroup", "id", groupID)
		if !reflect.DeepEqual(after["updatedAt"], updatedAtAfterChange) {
			t.Fatalf("updatedAt = %v, want %v", after["updatedAt"], updatedAtAfterChange)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(reconciled) != 0 {
			t.Fatalf("reconciled = %v, want none", reconciled)
		}
	})

	t.Run("serializes complete role projection for concurrent Group membership changes", func(t *testing.T) {
		firstCallbackStarted := make(chan struct{})
		releaseFirstCallback := make(chan struct{})
		secondCallbackStarted := make(chan struct{})
		secondSubjectLockWaited := make(chan struct{})
		var onceFirst, onceSecond, onceWait sync.Once
		var mu sync.Mutex
		concurrentPhase := false
		active, maxActive, callbackCount := 0, 0, 0
		var projectedRoles []string
		isConcurrent := func() bool {
			mu.Lock()
			defer mu.Unlock()
			return concurrentPhase
		}

		e := gpdNewEnv(t, &Projection{
			Roles: &RoleProjection{
				Map: func(in RoleMappingInput, _ DatabaseContext) ([]string, error) {
					return []string{"role:" + in.Source.DisplayName}, nil
				},
				Exists: func(RoleExistenceInput, DatabaseContext) (bool, error) { return true, nil },
			},
			ReconcileUser: func(state ProjectedUserState, _ DatabaseContext) error {
				mu.Lock()
				if !concurrentPhase {
					mu.Unlock()
					return nil
				}
				active++
				maxActive = max(maxActive, active)
				callbackCount++
				n := callbackCount
				mu.Unlock()
				defer func() {
					mu.Lock()
					active--
					mu.Unlock()
				}()
				if n == 1 {
					onceFirst.Do(func() { close(firstCallbackStarted) })
					<-releaseFirstCallback
				} else {
					onceSecond.Do(func() { close(secondCallbackStarted) })
				}
				roles := []string{}
				for _, g := range state.Grants {
					roles = append(roles, g.Role)
				}
				sort.Strings(roles)
				mu.Lock()
				projectedRoles = roles
				mu.Unlock()
				return nil
			},
		}, func(inner adapter.Adapter) adapter.Adapter {
			return &gpdSubjectLockingAdapter{Adapter: inner, tails: map[string]chan struct{}{}, onWait: func() {
				if isConcurrent() {
					onceWait.Do(func() { close(secondSubjectLockWaited) })
				}
			}}
		})
		user := gpdCreateUser(e, map[string]any{"userName": "concurrent@example.com"})
		firstGroup := gpdCreateGroup(e, "engineering")
		secondGroup := gpdCreateGroup(e, "finance")
		mu.Lock()
		concurrentPhase = true
		mu.Unlock()

		addUser := func(groupID string) <-chan error {
			done := make(chan error, 1)
			go func() {
				_, err := e.callErr("patchSCIMGroup", gpdMembersPatchInput(groupID, "add", user))
				done <- err
			}()
			return done
		}
		timeout := time.After(10 * time.Second)
		firstPatch := addUser(firstGroup)
		select {
		case <-firstCallbackStarted:
		case err := <-firstPatch:
			t.Fatalf("first patch finished before its callback blocked: %v", err)
		case <-timeout:
			t.Fatal("timed out waiting for the first callback")
		}
		secondPatch := addUser(secondGroup)
		select {
		case <-secondCallbackStarted:
		case <-secondSubjectLockWaited:
		case <-timeout:
			t.Fatal("timed out waiting for the second patch")
		}
		close(releaseFirstCallback)
		for _, ch := range []<-chan error{firstPatch, secondPatch} {
			select {
			case err := <-ch:
				if err != nil {
					t.Fatalf("patch: %v", err)
				}
			case <-timeout:
				t.Fatal("timed out waiting for the patches")
			}
		}

		mu.Lock()
		defer mu.Unlock()
		if maxActive != 1 {
			t.Fatalf("maximumActiveCallbacks = %d, want 1", maxActive)
		}
		if !reflect.DeepEqual(projectedRoles, []string{"role:engineering", "role:finance"}) {
			t.Fatalf("projectedRoles = %v", projectedRoles)
		}
	})

	t.Run("acquires the Group and affected subjects before changing membership rows", func(t *testing.T) {
		var recorder *gpdMutationOrderAdapter
		e := gpdNewEnv(t, nil, func(inner adapter.Adapter) adapter.Adapter {
			recorder = &gpdMutationOrderAdapter{Adapter: inner}
			return recorder
		})
		user := gpdCreateUser(e, map[string]any{"userName": "lock-order@example.com"})
		groupID := gpdCreateGroup(e, "lock-order", user)
		recorder.reset()

		e.mustCall("patchSCIMGroup", gpdMembersPatchInput(groupID, "remove", user))

		gpdExpectLockOrder(t, recorder.ops())
	})

	t.Run("locks affected Groups before the subject when deleting a User", func(t *testing.T) {
		var recorder *gpdMutationOrderAdapter
		e := gpdNewEnv(t, nil, func(inner adapter.Adapter) adapter.Adapter {
			recorder = &gpdMutationOrderAdapter{Adapter: inner}
			return recorder
		})
		user := gpdCreateUser(e, map[string]any{"userName": "delete-lock-order@example.com"})
		gpdCreateGroup(e, "delete-lock-order", user)
		recorder.reset()

		gpdCall(e, "deleteSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": user}})

		gpdExpectLockOrder(t, recorder.ops())
	})

	t.Run("rolls back internal adapter writes when Group projection fails", func(t *testing.T) {
		var mu sync.Mutex
		rejectProjection := false
		e := gpdNewEnv(t, &Projection{ReconcileUser: func(state ProjectedUserState, ctx DatabaseContext) error {
			mu.Lock()
			reject := rejectProjection
			mu.Unlock()
			if !reject {
				return nil
			}
			if _, err := ctx.Database.Update(ctx.Context, "user", []adapter.Where{{Field: "id", Value: state.UserID}},
				adapter.Record{"name": "Projection write that must roll back"}); err != nil {
				return err
			}
			return errors.New("Application projection failed")
		}}, nil)
		user := gpdCreateUser(e, map[string]any{"userName": "rollback@example.com", "displayName": "Before projection failure"})
		groupID := gpdCreateGroup(e, "rollback-group")
		source := gpdRow(e, "scimUser", "id", user)
		if source == nil {
			t.Fatal("Expected the provisioned SCIM User source")
		}
		mu.Lock()
		rejectProjection = true
		mu.Unlock()

		_, err := e.callErr("patchSCIMGroup", gpdMembersPatchInput(groupID, "add", user))
		if err == nil {
			t.Fatal("expected the PATCH to fail")
		}
		detail := ""
		if ae, ok := betterauth.AsAPIError(err); ok {
			detail, _ = errBody(ae)["detail"].(string)
		}
		if detail != "SCIM projection reconciliation failed" {
			t.Fatalf("error = %v, detail = %q", err, detail)
		}

		if u := gpdRow(e, "user", "id", source["userId"]); u == nil || u["name"] != "Before projection failure" {
			t.Fatalf("user = %v", u)
		}
		for _, m := range e.rows("scimGroupMember") {
			if m["groupId"] == groupID && m["scimUserId"] == user {
				t.Fatalf("membership persisted: %v", m)
			}
		}
		// Upstream: rejects.toThrow("SCIM projection reconciliation failed") (error.message).
		// Go's APIError.Error() reads body.message (core), so the detail carries the message.
		ae, ok := betterauth.AsAPIError(err)
		if !ok || !strings.Contains(getStr(ae.Body, "detail"), "SCIM projection reconciliation failed") {
			t.Fatalf("err = %v", err)
		}
	})
}
