package scim

// Port of upstream scim-group-cardinality.test.ts (@better-auth/scim v1.7.7).

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

const (
	groupCardUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupCardGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	groupCardPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	groupCardToken       = "test-scim-token"
)

func groupCardFixture(t *testing.T, w *userConcAdapter) *testEnv {
	t.Helper()
	eo := envOptions{}
	if w != nil {
		eo.mutate = userConcWrap(w)
	}
	return newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("workforce", groupCardToken)}}, eo)
}

func groupCardMemberReferences(count int, prefix string) []any {
	out := make([]any, count)
	for i := range out {
		out[i] = map[string]any{"value": fmt.Sprintf("%s-%d", prefix, i)}
	}
	return out
}

func groupCardExpectCardinalityError(t *testing.T, ae *betterauth.APIError, expectSCIMType bool) {
	t.Helper()
	if ae == nil {
		t.Fatal("expected a cardinality error")
	}
	b := errBody(ae)
	if ae.StatusCode != 400 || b["status"] != "400" || (expectSCIMType && b["scimType"] != "invalidValue") {
		t.Fatalf("expected 400 cardinality error, got %d %v", ae.StatusCode, b)
	}
}

func groupCardAllRows(e *testEnv, model string) []adapter.Record {
	e.t.Helper()
	rows, err := e.db().FindMany(context.Background(), adapter.FindManyInput{Model: model, Limit: 1_000_000})
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func groupCardCall(e *testEnv, key string, in betterauth.CallInput) map[string]any {
	in.Headers = bearer(groupCardToken)
	return e.mustCall(key, in)
}

func groupCardSeedMembers(e *testEnv, groupID, prefix, idPrefix, keyPrefix string, count int) {
	createdAt := time.Now()
	for i := range count {
		e.insert("scimGroupMember", adapter.Record{
			"id": fmt.Sprintf("%s-%d", idPrefix, i), "connectionId": "workforce", "groupId": groupID,
			"scimUserId": fmt.Sprintf("%s-%d", prefix, i), "membershipKey": fmt.Sprintf("%s-%d", keyPrefix, i),
			"createdAt": createdAt,
		})
	}
}

func TestGroupCardDirectMemberCardinality(t *testing.T) {
	t.Run("rejects an over-limit Group create without writing the Group", func(t *testing.T) {
		e := groupCardFixture(t, nil)
		_, ae := e.call("createSCIMGroup", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardGroupSchema}, "displayName": "Engineering",
			"members": groupCardMemberReferences(MaxGroupMembers+1, "candidate"),
		}, Headers: bearer(groupCardToken)})
		groupCardExpectCardinalityError(t, ae, false)
		if g, m := len(e.rows("scimGroup")), len(e.rows("scimGroupMember")); g != 0 || m != 0 {
			t.Fatalf("groups = %d, members = %d", g, m)
		}
	})

	t.Run("rejects an over-limit Group replacement without partial writes", func(t *testing.T) {
		e := groupCardFixture(t, nil)
		user := groupCardCall(e, "createSCIMUser", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardUserSchema}, "userName": "ada@example.com"}})
		group := groupCardCall(e, "createSCIMGroup", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardGroupSchema}, "displayName": "Engineering",
			"members": []any{map[string]any{"value": user["id"]}}}})

		_, ae := e.call("replaceSCIMGroup", betterauth.CallInput{
			Params: map[string]string{"groupId": group["id"].(string)},
			Body: map[string]any{"schemas": []any{groupCardGroupSchema}, "displayName": "Renamed Engineering",
				"members": groupCardMemberReferences(MaxGroupMembers+1, "candidate")},
			Headers: bearer(groupCardToken),
		})
		groupCardExpectCardinalityError(t, ae, false)

		identityResExpectFields(t, "group", identityResFind(e.rows("scimGroup"), "id", group["id"]),
			map[string]any{"displayName": "Engineering"})
		members := e.rows("scimGroupMember")
		if len(members) != 1 || members[0]["groupId"] != group["id"] || members[0]["scimUserId"] != user["id"] {
			t.Fatalf("members = %v", members)
		}
	})

	t.Run("rejects an over-limit membership add without partial writes", func(t *testing.T) {
		e := groupCardFixture(t, nil)
		user := groupCardCall(e, "createSCIMUser", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardUserSchema}, "userName": "ada@example.com"}})
		group := groupCardCall(e, "createSCIMGroup", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardGroupSchema}, "displayName": "Engineering"}})
		groupID := group["id"].(string)
		groupCardSeedMembers(e, groupID, "existing", "membership", "membership-key", MaxGroupMembers)
		groupUpdatedAt := identityResFind(e.rows("scimGroup"), "id", groupID)["updatedAt"]

		_, ae := e.call("patchSCIMGroup", betterauth.CallInput{
			Params: map[string]string{"groupId": groupID},
			Body: map[string]any{"schemas": []any{groupCardPatchSchema}, "Operations": []any{
				map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": user["id"]}}}}},
			Headers: bearer(groupCardToken),
		})
		groupCardExpectCardinalityError(t, ae, true)

		members := groupCardAllRows(e, "scimGroupMember")
		if len(members) != MaxGroupMembers {
			t.Fatalf("members = %d, want %d", len(members), MaxGroupMembers)
		}
		if identityResFind(members, "scimUserId", user["id"]) != nil {
			t.Fatal("the rejected member was persisted")
		}
		if got := identityResFind(e.rows("scimGroup"), "id", groupID)["updatedAt"]; !adapter.Equal(got, groupUpdatedAt) {
			t.Fatalf("group updatedAt = %v, want %v", got, groupUpdatedAt)
		}
	})

	t.Run("bounds a Group response when persisted state violates the invariant", func(t *testing.T) {
		e := groupCardFixture(t, nil)
		group := groupCardCall(e, "createSCIMGroup", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardGroupSchema}, "displayName": "Engineering"}})
		groupID := group["id"].(string)
		for i := range MaxGroupMembers + 1 {
			id := fmt.Sprintf("persisted-%d", i)
			e.insert("scimUser", adapter.Record{"id": id, "connectionId": "workforce", "displayName": id})
		}
		groupCardSeedMembers(e, groupID, "persisted", "persisted-membership", "persisted-membership-key", MaxGroupMembers+1)

		_, ae := e.call("getSCIMGroup", betterauth.CallInput{Params: map[string]string{"groupId": groupID},
			Headers: bearer(groupCardToken)})
		if ae == nil || ae.StatusCode != 500 || errBody(ae)["status"] != "500" {
			if ae == nil {
				t.Fatal("expected getSCIMGroup to fail with 500")
			}
			t.Fatalf("expected 500, got %d %v", ae.StatusCode, errBody(ae))
		}
	})

	t.Run("serializes concurrent additions before enforcing the member limit", func(t *testing.T) {
		// createCardinalityRaceAdapter: a per-Group lock queue on the first fenced scimGroup
		// increment of each transaction (released after the transaction settles), and
		// cardinality reads that wait until a second transaction queues on the lock.
		var mu sync.Mutex
		tails := map[string]chan struct{}{}
		mayContinue := make(chan struct{})
		var continueOnce sync.Once
		release := func() { continueOnce.Do(func() { close(mayContinue) }) }
		readCount := 0
		var e *testEnv
		w := &userConcAdapter{}
		w.incrementOne = func(ctx context.Context, st *userConcTx, in adapter.IncrementInput, next func() (adapter.Record, error)) (adapter.Record, error) {
			if in.Model != "scimGroup" {
				return next()
			}
			groupID, ok := userConcWhereValue(in.Where, "id").(string)
			expected := userConcWhereValue(in.Where, "revision")
			if _, isNum := adapter.ToFloat(expected); !ok || expected == nil || !isNum || st.holds(groupID) {
				return next()
			}
			mu.Lock()
			previous := tails[groupID]
			current := make(chan struct{})
			tails[groupID] = current
			mu.Unlock()
			if previous != nil {
				release()
				<-previous
			}
			st.hold(groupID)
			st.mu.Lock()
			st.releases = append(st.releases, func() {
				close(current)
				mu.Lock()
				if tails[groupID] == current {
					delete(tails, groupID)
				}
				mu.Unlock()
			})
			st.mu.Unlock()
			live := userConcLive(e, "scimGroup", groupID)
			if live == nil || !userConcSameNumber(live["revision"], expected) {
				return nil, nil
			}
			return next()
		}
		w.count = func(ctx context.Context, st *userConcTx, model string, where []adapter.Where, next func() (int64, error)) (int64, error) {
			if _, ok := userConcWhereValue(where, "groupId").(string); model == "scimGroupMember" && ok {
				mu.Lock()
				readCount++
				if readCount == 2 {
					release()
				}
				mu.Unlock()
				<-mayContinue
			}
			return next()
		}
		e = groupCardFixture(t, w)
		firstCandidate := groupCardCall(e, "createSCIMUser", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardUserSchema}, "userName": "first@example.com"}})
		secondCandidate := groupCardCall(e, "createSCIMUser", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardUserSchema}, "userName": "second@example.com"}})
		group := groupCardCall(e, "createSCIMGroup", betterauth.CallInput{Body: map[string]any{
			"schemas": []any{groupCardGroupSchema}, "displayName": "Engineering"}})
		groupID := group["id"].(string)
		groupCardSeedMembers(e, groupID, "existing", "membership", "membership-key", MaxGroupMembers-1)

		results := make([]error, 2)
		var wg sync.WaitGroup
		for i, candidate := range []map[string]any{firstCandidate, secondCandidate} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, results[i] = e.callErr("patchSCIMGroup", betterauth.CallInput{
					Params: map[string]string{"groupId": groupID},
					Body: map[string]any{"schemas": []any{groupCardPatchSchema}, "Operations": []any{
						map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": candidate["id"]}}}}},
					Headers: bearer(groupCardToken),
				})
			}()
		}
		finished := make(chan struct{})
		go func() { wg.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(userConcWaitTimeout):
			t.Fatal("timed out waiting for concurrent Group mutations")
		}

		fulfilled := 0
		var rejected error
		for _, err := range results {
			if err == nil {
				fulfilled++
			} else {
				rejected = err
			}
		}
		if fulfilled != 1 || rejected == nil {
			t.Fatalf("results = %v, want one success and one rejection", results)
		}
		ae, ok := betterauth.AsAPIError(rejected)
		if !ok {
			t.Fatalf("rejection is not an API error: %v", rejected)
		}
		groupCardExpectCardinalityError(t, ae, true)

		count := 0
		for _, m := range groupCardAllRows(e, "scimGroupMember") {
			if m["groupId"] == groupID {
				count++
			}
		}
		if count != MaxGroupMembers {
			t.Fatalf("group members = %d, want %d", count, MaxGroupMembers)
		}
		got := groupCardCall(e, "getSCIMGroup", betterauth.CallInput{Params: map[string]string{"groupId": groupID}})
		if got["id"] != groupID {
			t.Fatalf("getSCIMGroup id = %v", got["id"])
		}
	})
}
