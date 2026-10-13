package organization

// Port of upstream routes/crud-members.test.ts.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

// cmemCreateUser is ctx.adapter.create({ model: "user", data }).
func cmemCreateUser(t *testing.T, e *testEnv, email, name string) string {
	t.Helper()
	u, err := e.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{
		Model: "user", Data: adapter.Record{"email": email, "name": name},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return s(u["id"])
}

// cmemSignUp is auth.api.signUpEmail returning the session headers (instead of the bearer
// token) and the user id.
func cmemSignUp(t *testing.T, e *testEnv, email, name, password string) (http.Header, string) {
	t.Helper()
	r := e.mustAPI("signUpEmail", nil, map[string]any{"email": email, "name": name, "password": password}, nil)
	return cookieHeaders(r.Headers), s(r.m()["user"].(map[string]any)["id"])
}

func cmemAddMember(t *testing.T, e *testEnv, orgID, userID, role string) map[string]any {
	t.Helper()
	return e.mustAPI("addMember", nil, map[string]any{"organizationId": orgID, "userId": userID, "role": role}, nil).m()
}

func cmemCounts(t *testing.T, r *result, n, total int) {
	t.Helper()
	expectOK(t, r)
	ms, _ := r.m()["members"].([]any)
	tot, _ := r.m()["total"].(float64)
	if len(ms) != n || int(tot) != total {
		t.Fatalf("expected %d members / total %d, got %d / %v", n, total, len(ms), r.m()["total"])
	}
}

func TestCrudMembersListMembers(t *testing.T) {
	e := newEnv(t, Options{})
	headers := e.signInTestUser()
	org := e.createOrg(headers, "test", "test", map[string]any{"metadata": map[string]any{"test": "test"}})
	secondOrg := e.createOrg(headers, "test-second", "test-second", map[string]any{"metadata": map[string]any{"test": "second-org"}})
	orgID := s(org["id"])
	for i := 0; i < 10; i++ {
		uid := cmemCreateUser(t, e, fmt.Sprintf("test%d@test.com", i), fmt.Sprintf("test%d", i))
		cmemAddMember(t, e, orgID, uid, "member")
	}
	list := func(q url.Values) *result { return e.get("/organization/list-members", headers, q) }

	t.Run("should return all members", func(t *testing.T) {
		expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": orgID}))
		cmemCounts(t, list(nil), 11, 11)
	})

	t.Run("should return all members by organization slug", func(t *testing.T) {
		cmemCounts(t, list(url.Values{"organizationSlug": {"test-second"}}), 1, 1)
	})

	t.Run("should limit the number of members", func(t *testing.T) {
		cmemCounts(t, list(url.Values{"limit": {"5"}}), 5, 11)
	})

	t.Run("should offset the members", func(t *testing.T) {
		cmemCounts(t, list(url.Values{"offset": {"5"}}), 6, 11)
	})

	t.Run("should filter the members", func(t *testing.T) {
		cmemCounts(t, list(url.Values{
			"filterField":    {"createdAt"},
			"filterOperator": {"gt"},
			"filterValue":    {time.Now().Add(-30 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")},
		}), 11, 11)
	})

	t.Run("should filter the members verifying the operator functionality", func(t *testing.T) {
		cmemCounts(t, list(url.Values{"filterField": {"role"}, "filterOperator": {"ne"}, "filterValue": {"owner"}}), 10, 10)
	})

	t.Run("should filter the members with 'in' operator", func(t *testing.T) {
		cmemCounts(t, list(url.Values{"filterField": {"role"}, "filterOperator": {"in"}, "filterValue": {"member", "owner"}}), 11, 11)
	})

	t.Run("should filter the members with 'not_in' operator", func(t *testing.T) {
		// A single-element array is serialized as one query value by the client; send it
		// through the API to keep the array type.
		r := e.api("listMembers", headers, nil, map[string]any{"filterField": "role", "filterOperator": "not_in", "filterValue": []any{"owner"}})
		cmemCounts(t, r, 10, 10)
	})

	t.Run("should filter the members with 'starts_with' operator", func(t *testing.T) {
		cmemCounts(t, list(url.Values{"filterField": {"role"}, "filterOperator": {"starts_with"}, "filterValue": {"mem"}}), 10, 10)
	})

	t.Run("should sort the members", func(t *testing.T) {
		def := list(nil)
		expectOK(t, def)
		ms := def.m()["members"].([]any)
		id := func(v any) string { return s(v.(map[string]any)["id"]) }
		if len(ms) < 4 {
			t.Fatalf("members = %v", ms)
		}
		first, second := id(ms[0]), id(ms[1])
		last, oneBeforeLast := id(ms[len(ms)-1]), id(ms[len(ms)-2])
		ad := e.auth.Context().Adapter
		if _, err := ad.Update(context.Background(), "member", []adapter.Where{{Field: "id", Value: second}},
			adapter.Record{"createdAt": time.Now().Add(-30 * 24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if _, err := ad.Update(context.Background(), "member", []adapter.Where{{Field: "id", Value: oneBeforeLast}},
			adapter.Record{"createdAt": time.Now().Add(30 * 24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
		r := list(url.Values{"sortBy": {"createdAt"}, "sortDirection": {"asc"}})
		expectOK(t, r)
		sorted := r.m()["members"].([]any)
		if id(sorted[0]) == first || id(sorted[len(sorted)-1]) == last {
			t.Fatalf("sort did not change order")
		}
		if id(sorted[0]) != second || id(sorted[len(sorted)-1]) != oneBeforeLast {
			t.Fatalf("sorted first=%s last=%s, want %s %s", id(sorted[0]), id(sorted[len(sorted)-1]), second, oneBeforeLast)
		}
	})

	t.Run("should list members by organization id", func(t *testing.T) {
		cmemCounts(t, list(url.Values{"organizationId": {s(secondOrg["id"])}}), 1, 1)
	})

	t.Run("should not list members if not a member", func(t *testing.T) {
		nh := e.signUp("test21@test.com", "password", "test22")
		r := e.get("/organization/list-members", nh, url.Values{"organizationId": {orgID}})
		if r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
		if r.message() != ErrYouAreNotAMemberOfThisOrganization.Message {
			t.Fatalf("message = %q", r.message())
		}
	})
}

func TestCrudMembersListMembersOver100(t *testing.T) {
	e := newEnv(t, Options{MembershipLimit: 500})
	headers := e.signInTestUser()
	org := e.createOrg(headers, "large-org", "large-org")
	orgID := s(org["id"])
	for i := 0; i < 110; i++ {
		uid := cmemCreateUser(t, e, fmt.Sprintf("large-org-%d@test.com", i), fmt.Sprintf("large-org-%d", i))
		cmemAddMember(t, e, orgID, uid, "member")
	}
	// The adapter default findMany limit is 100 (upstream patches findMany to default to 100).

	t.Run("should list all members when membershipLimit is above the adapter default", func(t *testing.T) {
		r := e.get("/organization/list-members", headers, url.Values{"organizationId": {orgID}})
		cmemCounts(t, r, 111, 111)
		for _, m := range r.m()["members"].([]any) {
			u, _ := m.(map[string]any)["user"].(map[string]any)
			if _, ok := u["id"].(string); !ok {
				t.Fatalf("member user = %v", u)
			}
			if _, ok := u["email"].(string); !ok {
				t.Fatalf("member user = %v", u)
			}
		}
	})
}

func TestCrudMembersUpdateMemberRole(t *testing.T) {
	e := newEnv(t, Options{})

	t.Run("should update the member role", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.createOrg(h, "test", "test", map[string]any{"metadata": map[string]any{"test": "test"}})
		_, uid := cmemSignUp(t, e, "test2@test.com", "test", "password")
		member := cmemAddMember(t, e, s(org["id"]), uid, "member")
		r := e.post("/organization/update-member-role", h, map[string]any{"organizationId": org["id"], "memberId": member["id"], "role": "admin"})
		expectOK(t, r)
		if s(r.m()["role"]) != "admin" {
			t.Fatalf("role = %v", r.m()["role"])
		}
	})

	t.Run("should not update the member role if the member updating is not a member	", func(t *testing.T) {
		h := e.signInTestUser()
		userID := s(e.session(h)["userId"])
		// Upstream ignores the result (the "test" slug is taken by the previous case).
		e.api("createOrganization", h, map[string]any{"name": "test", "slug": "test", "metadata": map[string]any{"test": "test"}}, nil)
		nh, _ := cmemSignUp(t, e, "test3@test.com", "test", "password")
		newOrg := e.createOrg(nh, "test2", "test2", map[string]any{"metadata": map[string]any{"test": "test"}})
		cmemAddMember(t, e, s(newOrg["id"]), userID, "admin")
		ownerMemberID := newOrg["members"].([]any)[0].(map[string]any)["id"]
		r := e.post("/organization/update-member-role", h, map[string]any{"organizationId": newOrg["id"], "memberId": ownerMemberID, "role": "admin"})
		if r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
		if r.message() != ErrYouAreNotAllowedToUpdateThisMember.Message {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should not allow a comma-delimited role string", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.createOrg(h, "escalation", "escalation")
		adminHeaders, adminID := cmemSignUp(t, e, "admin-escalation@test.com", "admin", "password")
		adminMember := cmemAddMember(t, e, s(org["id"]), adminID, "admin")
		r := e.post("/organization/update-member-role", adminHeaders, map[string]any{"organizationId": org["id"], "memberId": adminMember["id"], "role": "admin,owner"})
		expectCode(t, r, 403, "")
		if r.Data != nil && r.Err == nil {
			t.Fatalf("data = %v", r.Data)
		}
		persisted, err := e.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "member", Where: []adapter.Where{{Field: "id", Value: adminMember["id"]}}})
		if err != nil {
			t.Fatal(err)
		}
		if s(persisted["role"]) != "admin" {
			t.Fatalf("persisted role = %v", persisted["role"])
		}
	})

	t.Run("should reject updating a member to an unknown role", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.createOrg(h, "unknown-role", "unknown-role")
		_, uid := cmemSignUp(t, e, "unknown-role@test.com", "test", "password")
		member := cmemAddMember(t, e, s(org["id"]), uid, "member")
		r := e.post("/organization/update-member-role", h, map[string]any{"organizationId": org["id"], "memberId": member["id"], "role": "superadmin"})
		expectCode(t, r, 400, "")
		if !strings.Contains(r.message(), ErrRoleNotFound.Code) {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should reject updating a member to an empty role list", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.createOrg(h, "empty-role", "empty-role")
		_, uid := cmemSignUp(t, e, "empty-role@test.com", "test", "password")
		member := cmemAddMember(t, e, s(org["id"]), uid, "member")
		for _, role := range []any{[]any{}, ","} {
			r := e.post("/organization/update-member-role", h, map[string]any{"organizationId": org["id"], "memberId": member["id"], "role": role})
			expectCode(t, r, 400, "")
		}
	})
}

func TestCrudMembersActiveMemberRole(t *testing.T) {
	e := newEnv(t, Options{})
	headers := e.signInTestUser()
	org := e.createOrg(headers, "test", "test", map[string]any{"metadata": map[string]any{"test": "test"}})
	e.createOrg(headers, "test-second", "test-second", map[string]any{"metadata": map[string]any{"test": "second-org"}})
	orgID := s(org["id"])
	selectedUserID := ""
	for i := 0; i < 10; i++ {
		uid := cmemCreateUser(t, e, fmt.Sprintf("test%d@test.com", i), fmt.Sprintf("test%d", i))
		if i == 0 {
			selectedUserID = uid
		}
		cmemAddMember(t, e, orgID, uid, "member")
	}

	t.Run("should return the active member role on active organization", func(t *testing.T) {
		expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": orgID}))
		r := e.get("/organization/get-active-member-role", headers, nil)
		expectOK(t, r)
		if s(r.m()["role"]) != "owner" {
			t.Fatalf("role = %v", r.Data)
		}
	})

	t.Run("should return active member role on organization", func(t *testing.T) {
		expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": orgID}))
		r := e.get("/organization/get-active-member-role", headers, url.Values{"userId": {selectedUserID}})
		expectOK(t, r)
		if s(r.m()["role"]) != "member" {
			t.Fatalf("role = %v", r.Data)
		}
	})

	t.Run("should clear active member role hook data after sign out", func(t *testing.T) {
		t.Skip("TS-only: client useActiveMemberRole atom reactivity after sign out")
	})
}

func TestCrudMembersInviteMemberRoleValidation(t *testing.T) {
	e := newEnv(t, Options{})

	t.Run("should fail when inviting with a non-existent role", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.createOrg(h, "Test Org Validation", "test-org-validation")
		r := e.post("/organization/invite-member", h, map[string]any{"email": "fake-role@test.com", "role": "super-invalid-role-123", "organizationId": org["id"]})
		expectCode(t, r, 400, "")
		if !strings.Contains(r.message(), ErrRoleNotFound.Code) {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should succeed when inviting with a valid default role", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.createOrg(h, "Test Org Validation 2", "test-org-validation-2")
		r := e.post("/organization/invite-member", h, map[string]any{"email": "valid@test.com", "role": "admin", "organizationId": org["id"]})
		expectOK(t, r)
		if r.Data == nil {
			t.Fatal("expected data")
		}
	})
}
