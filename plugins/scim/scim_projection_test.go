package scim

// Port of scim-projection.test.ts (SCIM role projection, lifecycle reconciliation and
// connection decommissioning).

import (
	"context"
	"fmt"
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
	projTUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	projTGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	projTPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// projTRecorder collects callback inputs (callbacks may run concurrently with the test).
type projTRecorder[T any] struct {
	mu    sync.Mutex
	items []T
}

func (r *projTRecorder[T]) add(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, v)
}

func (r *projTRecorder[T]) all() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]T{}, r.items...)
}

func (r *projTRecorder[T]) last(t *testing.T) T {
	t.Helper()
	all := r.all()
	if len(all) == 0 {
		t.Fatalf("no recorded items")
	}
	return all[len(all)-1]
}

func projTConn(id, token, domain string) ConnectionOptions {
	return ConnectionOptions{ID: id, Credentials: []BearerCredential{{Type: "bearer", ID: token, Token: token}}, ProvisioningDomainID: domain}
}

func projTCreateUser(t *testing.T, e *testEnv, token, userName string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{"schemas": []string{projTUserSchema}, "userName": userName}
	for k, v := range extra {
		body[k] = v
	}
	return e.mustCall("createSCIMUser", betterauth.CallInput{Body: body, Headers: bearer(token)})
}

func projTCreateGroup(t *testing.T, e *testEnv, token, externalID, displayName string, memberIDs ...string) map[string]any {
	t.Helper()
	members := []any{}
	for _, id := range memberIDs {
		members = append(members, map[string]any{"value": id})
	}
	return e.mustCall("createSCIMGroup", betterauth.CallInput{Body: map[string]any{
		"schemas": []string{projTGroupSchema}, "externalId": externalID, "displayName": displayName, "members": members,
	}, Headers: bearer(token)})
}

// projTErrText returns the error message plus any SCIM detail.
func projTErrText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if ae, ok := betterauth.AsAPIError(err); ok {
		if d, ok := errBody(ae)["detail"].(string); ok {
			s += " " + d
		}
	}
	return s
}

func projTExpectErr(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", msg)
	}
	if !strings.Contains(projTErrText(err), msg) {
		t.Fatalf("expected error containing %q, got %q", msg, projTErrText(err))
	}
}

func projTFind(rows []adapter.Record, field string, value any) adapter.Record {
	for _, r := range rows {
		if r[field] == value {
			return r
		}
	}
	return nil
}

func projTRoles(rows []adapter.Record) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, recStr(r, "role"))
	}
	return out
}

func projTSourcesEqual(t *testing.T, got []IdentitySource, want []IdentitySource) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sources = %+v, want %+v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("sources = %+v, want %+v", got, want)
		}
	}
}

func projTIsTime(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

// projTExpectDecommissionResult checks a decommission result against the upstream shape
// (decommissionedAt/completedAt: expect.any(Date)).
func projTExpectDecommissionResult(t *testing.T, got map[string]any, connectionID, domain string, users, batches int) {
	t.Helper()
	if got["connectionId"] != connectionID || got["provisioningDomainId"] != domain || got["status"] != "complete" ||
		!projTIsTime(got["decommissionedAt"]) || !projTIsTime(got["completedAt"]) || got["retryAfter"] != nil ||
		got["reconciledUsers"] != float64(users) || got["batches"] != float64(batches) || len(got) != 8 {
		t.Fatalf("decommission result = %#v", got)
	}
}

func projTSeedNumberedUsers(t *testing.T, e *testEnv, n int, createdAt time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		suffix := fmt.Sprintf("%03d", i)
		e.insert(modelUser, adapter.Record{"id": "scim-user-" + suffix, "connectionId": "workforce",
			"provisioningDomainId": "workspace-acme", "userId": "user-" + suffix, "active": true})
		e.insert(modelSubject, adapter.Record{"id": "subject-" + suffix, "userId": "user-" + suffix, "revision": 0,
			"createdAt": createdAt, "updatedAt": createdAt})
	}
}

func projTBinding(e *testEnv, connectionID string) adapter.Record {
	for _, r := range e.mem.Rows(modelConnectionBinding) {
		if r["connectionId"] == connectionID {
			return r
		}
	}
	return nil
}

// it("exposes source-aware projection contracts without persistence details"): the
// upstream test is a type-level assertion; these compile-time checks are its Go analogue.
var (
	_ AuthorizationSource = RoleMappingInput{}.Source
	_ AuthorizationSource = ProjectedRoleGrant{}.Source
)

func TestProjTContracts(t *testing.T) {
	t.Run("exposes source-aware projection contracts without persistence details", func(t *testing.T) {
		var m func(RoleMappingInput, DatabaseContext) ([]string, error) = (&RoleProjection{}).Map
		_ = m
		var src AuthorizationSource = ProjectedRoleGrant{}.Source
		src.Type = "group"
		_ = src
	})
}

func TestProjTRoleProjection(t *testing.T) {
	t.Run("projects an allowlisted custom role with source-aware provenance", func(t *testing.T) {
		reconciliations := &projTRecorder[ProjectedUserState]{}
		var mu sync.Mutex
		mappedRoles := []string{"billing-manager", "missing-role"}
		var mapErr error
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Projection: &Projection{
				Roles: &RoleProjection{
					Map: func(in RoleMappingInput, _ DatabaseContext) ([]string, error) {
						mu.Lock()
						defer mu.Unlock()
						if mapErr != nil {
							return nil, mapErr
						}
						if in.Source.ExternalID == "finance-admins" {
							return mappedRoles, nil
						}
						return nil, nil
					},
					Exists: func(in RoleExistenceInput, _ DatabaseContext) (bool, error) {
						return in.Role == "billing-manager", nil
					},
				},
				ReconcileUser: func(s ProjectedUserState, _ DatabaseContext) error {
					reconciliations.add(s)
					return nil
				},
			},
		})
		createdUser := projTCreateUser(t, e, "test-scim-token", "ada@example.com", nil)
		userID := createdUser["id"].(string)
		userLink := projTFind(e.rows(modelUser), "id", userID)
		if userLink == nil {
			t.Fatal("Expected a SCIM User link")
		}
		linkedUserID := recStr(userLink, "userId")
		createdGroup := projTCreateGroup(t, e, "test-scim-token", "finance-admins", "Finance administrators", userID)
		groupID := createdGroup["id"].(string)

		grant := projTFind(e.rows(modelProjectionGrant), "scimUserId", userID)
		if grant == nil {
			t.Fatal("expected a projection grant")
		}
		if grant["connectionId"] != "workforce" || grant["provisioningDomainId"] != "workspace-acme" ||
			grant["userId"] != linkedUserID || grant["sourceKind"] != "group" || grant["sourceId"] != groupID ||
			grant["role"] != "billing-manager" || recStr(grant, "grantKey") == "" {
			t.Fatalf("grant = %#v", grant)
		}
		last := reconciliations.last(t)
		if last.ProvisioningDomainID != "workspace-acme" || last.UserID != linkedUserID || !last.Active {
			t.Fatalf("reconciliation = %+v", last)
		}
		projTSourcesEqual(t, last.Sources, []IdentitySource{{ID: userID, ConnectionID: "workforce", ProvisioningDomainID: "workspace-acme", Active: true}})
		wantGrant := ProjectedRoleGrant{Source: AuthorizationSource{Type: "group", ID: groupID, ExternalID: "finance-admins",
			DisplayName: "Finance administrators"}, Role: "billing-manager"}
		if len(last.Grants) != 1 || last.Grants[0] != wantGrant {
			t.Fatalf("grants = %+v", last.Grants)
		}
		for _, model := range []string{"organization", "member"} {
			if rows := e.mem.Rows(model); len(rows) != 0 {
				t.Fatalf("%s rows = %v", model, rows)
			}
		}
		if rows := e.rows("account"); len(rows) != 0 {
			t.Fatalf("account rows = %v", rows)
		}

		mu.Lock()
		mappedRoles = []string{}
		mu.Unlock()
		result := e.mustCall("reconcileSCIMProjection", betterauth.CallInput{Body: map[string]any{"provisioningDomainId": "workspace-acme"}})
		if len(result) != 3 || result["provisioningDomainId"] != "workspace-acme" || result["reconciledUsers"] != float64(1) || result["batches"] != float64(1) {
			t.Fatalf("result = %#v", result)
		}
		if rows := e.rows(modelProjectionGrant); len(rows) != 0 {
			t.Fatalf("grants = %v", rows)
		}
		last = reconciliations.last(t)
		if last.ProvisioningDomainID != "workspace-acme" || last.UserID != linkedUserID || !last.Active || len(last.Grants) != 0 {
			t.Fatalf("reconciliation = %+v", last)
		}

		// Upstream maps to [42] (a non-string role); Go's typed callback cannot return a
		// non-string, so an invalid mapping is expressed as a callback error.
		mu.Lock()
		mapErr = fmt.Errorf("invalid role mapping: 42")
		mu.Unlock()
		_, err := e.callErr("reconcileSCIMProjection", betterauth.CallInput{Body: map[string]any{"provisioningDomainId": "workspace-acme"}})
		projTExpectErr(t, err, "SCIM role mapping failed")
	})

	t.Run("reconciles complete User lifecycle state without Groups", func(t *testing.T) {
		reconciliations := &projTRecorder[ProjectedUserState]{}
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Projection: &Projection{ReconcileUser: func(s ProjectedUserState, _ DatabaseContext) error {
				reconciliations.add(s)
				return nil
			}},
		})
		createdUser := projTCreateUser(t, e, "test-scim-token", "grace@example.com", map[string]any{"active": true})
		id := createdUser["id"].(string)
		userLink := projTFind(e.rows(modelUser), "id", id)
		if userLink == nil {
			t.Fatal("Expected a SCIM User link")
		}
		e.mustCall("patchSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": id}, Body: map[string]any{
			"schemas":    []string{projTPatchSchema},
			"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}},
		}, Headers: bearer("test-scim-token")})
		if _, ae := e.call("deleteSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": id}, Headers: bearer("test-scim-token")}); ae != nil {
			t.Fatalf("delete: %d %v", ae.StatusCode, errBody(ae))
		}

		got := reconciliations.all()
		want := []bool{true, false, false}
		if len(got) != len(want) {
			t.Fatalf("reconciliations = %+v", got)
		}
		for i, s := range got {
			if s.Active != want[i] || len(s.Grants) != 0 {
				t.Fatalf("reconciliation[%d] = %+v", i, s)
			}
		}
		if projTFind(e.rows("user"), "id", recStr(userLink, "userId")) == nil {
			t.Fatalf("Better Auth user was removed")
		}
	})

	t.Run("rolls back User creation when the application projection fails", func(t *testing.T) {
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")},
			Projection: &Projection{ReconcileUser: func(ProjectedUserState, DatabaseContext) error {
				return fmt.Errorf("Application projection failed")
			}},
		})
		_, err := e.callErr("createSCIMUser", betterauth.CallInput{Body: map[string]any{
			"schemas": []string{projTUserSchema}, "userName": "rollback@example.com",
		}, Headers: bearer("test-scim-token")})
		projTExpectErr(t, err, "SCIM projection reconciliation failed")
		for _, model := range []string{"user", "account", modelSubject, modelUser, modelProjectionGrant} {
			if rows := e.rows(model); len(rows) != 0 {
				t.Fatalf("%s rows = %v", model, rows)
			}
		}
	})

	t.Run("decommissions one connection without resurrecting its grants", func(t *testing.T) {
		now := time.Now()
		reconciliations := &projTRecorder[ProjectedUserState]{}
		identityReconciliations := &projTRecorder[IdentityState]{}
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{
				projTConn("workforce-a", "token-a", "workspace-acme"),
				projTConn("workforce-b", "token-b", "workspace-acme"),
			},
			Identity: &Identity{
				ResolveUser: func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
					return &IdentityResolution{Action: "link", UserID: "shared-user", Profile: "preserve"}, nil
				},
				ReconcileUser: func(s IdentityState, _ DatabaseContext) error {
					identityReconciliations.add(s)
					return nil
				},
			},
			Projection: &Projection{
				Roles: &RoleProjection{
					Map: func(in RoleMappingInput, _ DatabaseContext) ([]string, error) {
						if in.Source.ExternalID != "" {
							return []string{in.Source.ExternalID}, nil
						}
						return nil, nil
					},
					Exists: func(RoleExistenceInput, DatabaseContext) (bool, error) { return true, nil },
				},
				ReconcileUser: func(s ProjectedUserState, _ DatabaseContext) error {
					reconciliations.add(s)
					return nil
				},
			},
		})
		e.insert("user", adapter.Record{"id": "shared-user", "name": "Shared User", "email": "shared@example.com",
			"emailVerified": true, "image": nil, "createdAt": now, "updatedAt": now})

		userA := projTCreateUser(t, e, "token-a", "source-a@example.com", nil)
		userB := projTCreateUser(t, e, "token-b", "source-b@example.com", nil)
		userAID, userBID := userA["id"].(string), userB["id"].(string)
		projTCreateGroup(t, e, "token-a", "role-a", "Role A", userAID)
		projTCreateGroup(t, e, "token-b", "role-b", "Role B", userBID)

		roles := projTRoles(e.rows(modelProjectionGrant))
		sort.Strings(roles)
		if !slices.Equal(roles, []string{"role-a", "role-b"}) {
			t.Fatalf("roles = %v", roles)
		}

		result := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce-a"}})
		projTExpectDecommissionResult(t, result, "workforce-a", "workspace-acme", 1, 1)
		if roles := projTRoles(e.rows(modelProjectionGrant)); !slices.Equal(roles, []string{"role-b"}) {
			t.Fatalf("roles after decommission = %v", roles)
		}
		wantSources := []IdentitySource{{ID: userBID, ConnectionID: "workforce-b", ProvisioningDomainID: "workspace-acme", Active: true}}
		last := reconciliations.last(t)
		if last.ProvisioningDomainID != "workspace-acme" || last.UserID != "shared-user" || !last.Active ||
			len(last.Grants) != 1 || last.Grants[0].Role != "role-b" {
			t.Fatalf("reconciliation = %+v", last)
		}
		projTSourcesEqual(t, last.Sources, wantSources)
		lastIdentity := identityReconciliations.last(t)
		if lastIdentity.UserID != "shared-user" || !lastIdentity.Active {
			t.Fatalf("identity reconciliation = %+v", lastIdentity)
		}
		projTSourcesEqual(t, lastIdentity.Sources, wantSources)
		var scimUserIDs []string
		for _, r := range e.rows(modelUser) {
			scimUserIDs = append(scimUserIDs, recStr(r, "id"))
		}
		sort.Strings(scimUserIDs)
		wantIDs := []string{userAID, userBID}
		sort.Strings(wantIDs)
		if !slices.Equal(scimUserIDs, wantIDs) {
			t.Fatalf("scim users = %v", scimUserIDs)
		}

		rejected := e.request("GET", scimUsersURL, nil, map[string]string{"Authorization": "Bearer token-a"})
		if rejected.Status != 401 {
			t.Fatalf("rejected status = %d", rejected.Status)
		}
		if got := rejected.Header.Get("WWW-Authenticate"); got != `Bearer realm="SCIM"` {
			t.Fatalf("www-authenticate = %q", got)
		}

		firstDecommissionedAt := projTBinding(e, "workforce-a")["decommissionedAt"]
		repeated := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce-a"}})
		if fmt.Sprint(repeated) != fmt.Sprint(result) {
			t.Fatalf("repeated = %#v, want %#v", repeated, result)
		}
		if got := projTBinding(e, "workforce-a")["decommissionedAt"]; fmt.Sprint(got) != fmt.Sprint(firstDecommissionedAt) {
			t.Fatalf("decommissionedAt changed: %v -> %v", firstDecommissionedAt, got)
		}
		if roles := projTRoles(e.rows(modelProjectionGrant)); !slices.Equal(roles, []string{"role-b"}) {
			t.Fatalf("roles after repeat = %v", roles)
		}
	})

	t.Run("rolls back an authenticated mutation fenced after decommissioning", func(t *testing.T) {
		resolutionStarted := make(chan struct{})
		releaseResolution := make(chan struct{})
		var startOnce sync.Once
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Identity: &Identity{ResolveUser: func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
				startOnce.Do(func() { close(resolutionStarted) })
				<-releaseResolution
				return &IdentityResolution{Action: "create"}, nil
			}},
		})
		createErr := make(chan error, 1)
		go func() {
			_, err := e.callErr("createSCIMUser", betterauth.CallInput{Body: map[string]any{
				"schemas": []string{projTUserSchema}, "userName": "in-flight@example.com",
			}, Headers: bearer("test-scim-token")})
			createErr <- err
		}()
		select {
		case <-resolutionStarted:
		case <-time.After(10 * time.Second):
			close(releaseResolution)
			t.Fatal("resolution never started")
		}
		decommissioned, derr := e.callErr("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce"}})
		close(releaseResolution)
		err := <-createErr
		projTExpectErr(t, err, "SCIM connection is decommissioned")
		if derr != nil {
			t.Fatalf("decommission: %v", projTErrText(derr))
		}
		var dres map[string]any
		if err := decommissioned.Decode(&dres); err != nil {
			t.Fatal(err)
		}
		if dres["status"] != "complete" {
			t.Fatalf("decommission = %#v", dres)
		}
		for _, model := range []string{"user", modelSubject, modelUser} {
			if rows := e.rows(model); len(rows) != 0 {
				t.Fatalf("%s rows = %v", model, rows)
			}
		}
	})

	t.Run("fails closed on a non-active binding without retirement metadata", func(t *testing.T) {
		createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		sources := &projTRecorder[[]IdentitySource]{}
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{
				projTConn("workforce-a", "token-a", "workspace-acme"),
				projTConn("workforce-b", "token-b", "workspace-acme"),
			},
			Projection: &Projection{ReconcileUser: func(s ProjectedUserState, _ DatabaseContext) error {
				sources.add(s.Sources)
				return nil
			}},
		})
		e.insert(modelConnectionBinding, adapter.Record{"id": "binding-a", "connectionId": "workforce-a",
			"connectionKey": CreateConnectionKey("workforce-a"), "provisioningDomainId": "workspace-acme",
			"createdAt": createdAt, "decommissionStatus": "complete", "decommissionReconciledUserCount": 1,
			"decommissionBatchCount": 1, "decommissionRevision": 3})
		e.insert(modelSubject, adapter.Record{"id": "subject", "userId": "user", "revision": 0, "createdAt": createdAt, "updatedAt": createdAt})
		e.insert(modelUser, adapter.Record{"id": "scim-user-a", "connectionId": "workforce-a", "provisioningDomainId": "workspace-acme", "userId": "user", "active": true})
		e.insert(modelUser, adapter.Record{"id": "scim-user-b", "connectionId": "workforce-b", "provisioningDomainId": "workspace-acme", "userId": "user", "active": true})

		e.mustCall("reconcileSCIMProjection", betterauth.CallInput{Body: map[string]any{"provisioningDomainId": "workspace-acme"}})
		rejected := e.request("GET", scimUsersURL, nil, map[string]string{"Authorization": "Bearer token-a"})

		projTSourcesEqual(t, sources.last(t), []IdentitySource{{ID: "scim-user-b", ConnectionID: "workforce-b", ProvisioningDomainID: "workspace-acme", Active: true}})
		if rejected.Status != 401 {
			t.Fatalf("rejected status = %d", rejected.Status)
		}
		if got := rejected.Header.Get("WWW-Authenticate"); got != `Bearer realm="SCIM"` {
			t.Fatalf("www-authenticate = %q", got)
		}
	})

	t.Run("checkpoints failed decommissioning and resumes from the next user", func(t *testing.T) {
		createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		var mu sync.Mutex
		attempts := map[string]int{}
		failLastUser := true
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Projection: &Projection{ReconcileUser: func(s ProjectedUserState, _ DatabaseContext) error {
				mu.Lock()
				defer mu.Unlock()
				attempts[s.UserID]++
				if failLastUser && s.UserID == "user-050" {
					return fmt.Errorf("Projection unavailable")
				}
				return nil
			}},
		})
		e.insert(modelConnectionBinding, adapter.Record{"id": "binding", "connectionId": "workforce",
			"connectionKey": CreateConnectionKey("workforce"), "provisioningDomainId": "workspace-acme",
			"createdAt": createdAt, "decommissionStatus": "active", "decommissionReconciledUserCount": 0,
			"decommissionBatchCount": 0, "decommissionRevision": 0})
		projTSeedNumberedUsers(t, e, 51, createdAt)

		_, err := e.callErr("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce"}})
		projTExpectErr(t, err, "SCIM projection reconciliation failed")

		b := projTBinding(e, "workforce")
		if b["decommissionStatus"] != "reconciling" || b["decommissionCursorUserId"] != "user-049" ||
			recInt(b, "decommissionReconciledUserCount") != 50 || recInt(b, "decommissionBatchCount") != 1 ||
			b["decommissionCompletedAt"] != nil || b["decommissionLeaseId"] != nil || b["decommissionLeaseExpiresAt"] != nil ||
			recOptTime(b, "decommissionedAt") == nil {
			t.Fatalf("binding after failure = %#v", b)
		}
		rejected := e.request("GET", scimUsersURL, nil, map[string]string{"Authorization": "Bearer test-scim-token"})
		if rejected.Status != 401 {
			t.Fatalf("rejected status = %d", rejected.Status)
		}

		mu.Lock()
		failLastUser = false
		mu.Unlock()
		result := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce"}})
		projTExpectDecommissionResult(t, result, "workforce", "workspace-acme", 51, 2)
		mu.Lock()
		if attempts["user-000"] != 1 || attempts["user-049"] != 1 || attempts["user-050"] != 2 {
			t.Fatalf("attempts: 000=%d 049=%d 050=%d", attempts["user-000"], attempts["user-049"], attempts["user-050"])
		}
		mu.Unlock()
		b = projTBinding(e, "workforce")
		if b["decommissionStatus"] != "complete" || b["decommissionCursorUserId"] != "user-050" ||
			recInt(b, "decommissionReconciledUserCount") != 51 || recInt(b, "decommissionBatchCount") != 2 ||
			recOptTime(b, "decommissionCompletedAt") == nil || b["decommissionLeaseId"] != nil || b["decommissionLeaseExpiresAt"] != nil {
			t.Fatalf("binding after resume = %#v", b)
		}
	})

	t.Run("prevents takeover after the renewed lease expires during reconciliation", func(t *testing.T) {
		// Upstream fakes Date and advances it 10 minutes while the first worker's
		// reconcileUser callback is blocked. The Go implementation has no injectable
		// clock, so the committed lease is expired directly in the store instead, which
		// is what the concurrent worker observes either way.
		clockStart := time.Now().Add(-time.Minute)
		releaseReconciliation := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseReconciliation) }) }
		defer release()
		reconciliationStarted := make(chan struct{})
		var startedOnce sync.Once
		outcome := make(chan string, 4)
		var mu sync.Mutex
		calls := 0
		lockOrder := []string{}
		record := func(s string) {
			mu.Lock()
			lockOrder = append(lockOrder, s)
			mu.Unlock()
		}
		var locking *projTLockingAdapter
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Projection: &Projection{ReconcileUser: func(ProjectedUserState, DatabaseContext) error {
				record("callback")
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				if n > 1 {
					outcome <- "duplicate-callback"
				}
				startedOnce.Do(func() { close(reconciliationStarted) })
				<-releaseReconciliation
				return nil
			}},
		}, envOptions{mutate: func(cfg *betterauth.Config) {
			inner := cfg.Database
			cfg.Database = func(opts adapter.Options) (adapter.Adapter, error) {
				a, err := inner(opts)
				if err != nil {
					return nil, err
				}
				locking = &projTLockingAdapter{Adapter: a,
					onBindingLockWait:      func() { outcome <- "blocked" },
					onTransactionIncrement: record}
				return locking, nil
			}
		}})
		e.insert(modelConnectionBinding, adapter.Record{"id": "binding", "connectionId": "workforce",
			"connectionKey": CreateConnectionKey("workforce"), "provisioningDomainId": "workspace-acme",
			"createdAt": clockStart, "decommissionStatus": "active", "decommissionReconciledUserCount": 0,
			"decommissionBatchCount": 0, "decommissionRevision": 0})
		e.insert(modelSubject, adapter.Record{"id": "subject", "userId": "user", "revision": 0, "createdAt": clockStart, "updatedAt": clockStart})
		e.insert(modelUser, adapter.Record{"id": "scim-user", "connectionId": "workforce", "provisioningDomainId": "workspace-acme", "userId": "user", "active": true})

		type callOutcome struct {
			res map[string]any
			err error
		}
		decommission := func(out chan<- callOutcome) {
			r, err := e.callErr("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce"}})
			var m map[string]any
			if err == nil {
				err = r.Decode(&m)
			}
			out <- callOutcome{m, err}
		}
		first := make(chan callOutcome, 1)
		go decommission(first)
		select {
		case <-reconciliationStarted:
		case <-time.After(10 * time.Second):
			t.Fatal("reconciliation never started")
		}
		// "vi.setSystemTime(clockStart + 10 minutes)": the committed lease is now expired.
		if _, err := e.db().Update(context.Background(), modelConnectionBinding, []adapter.Where{w("id", "binding")},
			adapter.Record{"decommissionLeaseExpiresAt": time.Now().Add(-5 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		concurrent := make(chan callOutcome, 1)
		go decommission(concurrent)
		var got string
		select {
		case got = <-outcome:
		case <-time.After(10 * time.Second):
			t.Fatal("no concurrency outcome")
		}
		release()
		completed, concurrentResult := <-first, <-concurrent

		if got != "blocked" {
			t.Fatalf("outcome = %q", got)
		}
		for name, r := range map[string]callOutcome{"completed": completed, "concurrent": concurrentResult} {
			if r.err != nil {
				t.Fatalf("%s: %v", name, projTErrText(r.err))
			}
			if r.res["status"] != "complete" || r.res["reconciledUsers"] != float64(1) || r.res["batches"] != float64(1) {
				t.Fatalf("%s = %#v", name, r.res)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if len(lockOrder) < 3 || !slices.Equal(lockOrder[:3], []string{"scimSubject", "scimConnectionBinding", "callback"}) {
			t.Fatalf("lockOrder = %v", lockOrder)
		}
		if calls != 1 {
			t.Fatalf("calls = %d", calls)
		}
	})

	t.Run("takes over an expired decommission worker lease", func(t *testing.T) {
		createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		decommissionedAt := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
		reconciledUsers := &projTRecorder[string]{}
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Projection: &Projection{ReconcileUser: func(s ProjectedUserState, _ DatabaseContext) error {
				reconciledUsers.add(s.UserID)
				return nil
			}},
		})
		e.insert(modelConnectionBinding, adapter.Record{"id": "binding", "connectionId": "workforce",
			"connectionKey": CreateConnectionKey("workforce"), "provisioningDomainId": "workspace-acme",
			"createdAt": createdAt, "decommissionStatus": "reconciling", "decommissionCursorUserId": "user-049",
			"decommissionReconciledUserCount": 50, "decommissionBatchCount": 1, "decommissionRevision": 3,
			"decommissionedAt": decommissionedAt, "decommissionLeaseId": "stopped-worker",
			"decommissionLeaseExpiresAt": time.Now().Add(-time.Minute)})
		e.insert(modelSubject, adapter.Record{"id": "subject", "userId": "user-050", "revision": 0, "createdAt": createdAt, "updatedAt": createdAt})
		e.insert(modelUser, adapter.Record{"id": "scim-user-050", "connectionId": "workforce", "provisioningDomainId": "workspace-acme", "userId": "user-050", "active": true})

		result := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce"}})
		projTExpectDecommissionResult(t, result, "workforce", "workspace-acme", 51, 2)
		if result["decommissionedAt"] != "2026-01-02T00:00:00.000Z" {
			t.Fatalf("decommissionedAt = %#v", result["decommissionedAt"])
		}
		if got := reconciledUsers.all(); !slices.Equal(got, []string{"user-050"}) {
			t.Fatalf("reconciled = %v", got)
		}
		b := projTBinding(e, "workforce")
		if b["decommissionStatus"] != "complete" || recInt(b, "decommissionReconciledUserCount") != 51 ||
			recInt(b, "decommissionBatchCount") != 2 || b["decommissionLeaseId"] != nil || b["decommissionLeaseExpiresAt"] != nil {
			t.Fatalf("binding = %#v", b)
		}
	})

	t.Run("bounds explicit domain reconciliation batches and keeps both APIs server-only", func(t *testing.T) {
		createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		reconciled := &projTRecorder[string]{}
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Projection: &Projection{ReconcileUser: func(s ProjectedUserState, _ DatabaseContext) error {
				reconciled.add(s.UserID)
				return nil
			}},
		})
		projTSeedNumberedUsers(t, e, 51, createdAt)

		result := e.mustCall("reconcileSCIMProjection", betterauth.CallInput{Body: map[string]any{"provisioningDomainId": "workspace-acme"}})
		if len(result) != 3 || result["provisioningDomainId"] != "workspace-acme" || result["reconciledUsers"] != float64(51) || result["batches"] != float64(2) {
			t.Fatalf("result = %#v", result)
		}
		unique := map[string]bool{}
		for _, id := range reconciled.all() {
			unique[id] = true
		}
		if len(unique) != 51 {
			t.Fatalf("unique reconciled = %d", len(unique))
		}
		for _, key := range []string{"reconcileSCIMProjection", "decommissionSCIMConnection"} {
			var found *betterauth.Endpoint
			for _, ep := range e.auth.Endpoints() {
				if ep.Key == key {
					found = ep
				}
			}
			if found == nil {
				t.Fatalf("endpoint %s missing", key)
			}
			if found.Path != "" || !found.ServerOnly {
				t.Fatalf("endpoint %s path = %q serverOnly = %v", key, found.Path, found.ServerOnly)
			}
		}
	})

	t.Run("decommissions lifecycle state without requiring an access projection", func(t *testing.T) {
		identityReconciliations := &projTRecorder[IdentityState]{}
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{projTConn("workforce", "test-scim-token", "workspace-acme")},
			Identity: &Identity{ReconcileUser: func(s IdentityState, _ DatabaseContext) error {
				identityReconciliations.add(s)
				return nil
			}},
		})
		createdUser := projTCreateUser(t, e, "test-scim-token", "managed@example.com", nil)
		id := createdUser["id"].(string)
		linkedUser := projTFind(e.rows(modelUser), "id", id)
		if linkedUser == nil {
			t.Fatal("Expected linked SCIM User")
		}
		linkedUserID := recStr(linkedUser, "userId")
		e.insert(modelProjectionGrant, adapter.Record{"id": "stale-grant", "connectionId": "workforce",
			"provisioningDomainId": "workspace-acme", "scimUserId": id, "userId": linkedUserID, "sourceKind": "group",
			"sourceId": "retired-group", "role": "retired-role", "grantKey": "stale-grant-key"})
		sessionTime := time.Now()
		e.insert("session", adapter.Record{"id": "session", "userId": linkedUserID, "token": "session-token",
			"expiresAt": sessionTime.Add(time.Minute), "ipAddress": nil, "userAgent": nil,
			"createdAt": sessionTime, "updatedAt": sessionTime})

		result := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{"connectionId": "workforce"}})
		projTExpectDecommissionResult(t, result, "workforce", "workspace-acme", 1, 1)
		last := identityReconciliations.last(t)
		if last.UserID != linkedUserID || last.Active || last.ProfileSourceID != "" || len(last.Sources) != 0 {
			t.Fatalf("identity reconciliation = %+v", last)
		}
		if rows := e.rows("session"); len(rows) != 0 {
			t.Fatalf("sessions = %v", rows)
		}
		if rows := e.rows(modelProjectionGrant); len(rows) != 0 {
			t.Fatalf("grants = %v", rows)
		}
		subjects := e.mem.Rows(modelSubject)
		if len(subjects) == 0 || subjects[0]["profileSourceId"] != nil {
			t.Fatalf("subjects = %v", subjects)
		}
		if rows := e.rows(modelUser); len(rows) != 1 {
			t.Fatalf("scim users = %v", rows)
		}
	})
}

// projTLockingAdapter is createBindingLockingMemoryAdapter: incrementOne on
// scimConnectionBinding takes a lock that a transaction holds until it finishes.
type projTLockingAdapter struct {
	adapter.Adapter
	mu                     sync.Mutex
	onBindingLockWait      func()
	onTransactionIncrement func(model string)
}

type projTTxKey struct{}

type projTTxState struct{ held bool }

func (a *projTLockingAdapter) acquire() {
	if !a.mu.TryLock() {
		a.onBindingLockWait()
		a.mu.Lock()
	}
}

func (a *projTLockingAdapter) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	if st, ok := ctx.Value(projTTxKey{}).(*projTTxState); ok {
		if a.onTransactionIncrement != nil {
			a.onTransactionIncrement(in.Model)
		}
		if in.Model == modelConnectionBinding && !st.held {
			a.acquire()
			st.held = true
		}
		return a.Adapter.IncrementOne(ctx, in)
	}
	if in.Model != modelConnectionBinding {
		return a.Adapter.IncrementOne(ctx, in)
	}
	a.acquire()
	defer a.mu.Unlock()
	return a.Adapter.IncrementOne(ctx, in)
}

func (a *projTLockingAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	st := &projTTxState{}
	err := a.Adapter.Transaction(context.WithValue(ctx, projTTxKey{}, st), fn)
	if st.held {
		a.mu.Unlock()
	}
	return err
}
