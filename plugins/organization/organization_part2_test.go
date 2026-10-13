package organization

// Port of organization.test.ts (upstream v1.7.7), part 2: the describe blocks "access
// control" through "types" and "organization hooks" through "delete cascade rollback".

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/plugins/access"
	"github.com/nimi-io/better-auth-go/plugins/admin"
)

// orgP2Merge merges statement sets ({...a, ...b}).
func orgP2Merge(parts ...access.Statements) access.Statements {
	out := access.Statements{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

// orgP2CheckRolePermission is the client's checkRolePermission (clientSideHasPermission).
func orgP2CheckRolePermission(roles map[string]access.Role, role string, perms Permissions) bool {
	if roles == nil {
		roles = DefaultRoles()
	}
	return hasPermissionFn(&Options{Roles: roles}, HasPermissionInput{Role: role, Permissions: perms}, roles)
}

func orgP2Perm(t *testing.T, e *testEnv, h http.Header, body map[string]any) bool {
	t.Helper()
	r := e.mustAPI("hasPermission", h, body, nil)
	return r.m()["success"] == true
}

func TestOrgP2AccessControl(t *testing.T) {
	ac := access.New(orgP2Merge(access.Statements{
		"project": {"create", "read", "update", "delete"},
		"sales":   {"create", "read", "update", "delete"},
	}, DefaultStatements))
	owner := ac.NewRole(orgP2Merge(access.Statements{
		"project": {"create", "delete", "update", "read"},
		"sales":   {"create", "read", "update", "delete"},
	}, OwnerAC.Statements))
	adminRole := ac.NewRole(orgP2Merge(access.Statements{
		"project": {"create", "read"},
		"sales":   {"create", "read"},
	}, AdminAC.Statements))
	member := ac.NewRole(orgP2Merge(access.Statements{
		"project": {"read"},
		"sales":   {"read"},
	}, MemberAC.Statements))
	roles := map[string]access.Role{"admin": adminRole, "member": member, "owner": owner}
	e := newEnv(t, Options{AC: ac, Roles: roles, DynamicAccessControl: &DynamicAccessControlOptions{Enabled: true}})
	h := e.signInTestUser()
	org := e.post("/organization/create", h, map[string]any{"name": "test", "slug": "test", "metadata": map[string]any{"test": "test"}})
	expectOK(t, org)
	h = mergeCookies(h, org.Headers)

	t.Run("should return success", func(t *testing.T) {
		if !orgP2CheckRolePermission(roles, "admin", Permissions{"project": {"create"}}) {
			t.Fatal("expected admin to create project")
		}
		if !orgP2CheckRolePermission(roles, "admin", Permissions{"project": {"create"}}) {
			t.Fatal("expected admin to create project (legacy)")
		}
		r := e.post("/organization/has-permission", h, map[string]any{"permissions": map[string]any{"project": []any{"create"}}})
		expectOK(t, r)
		if r.m()["success"] != true {
			t.Fatalf("server hasPermission = %v", r.Data)
		}
	})

	t.Run("should return not success", func(t *testing.T) {
		if orgP2CheckRolePermission(roles, "admin", Permissions{"project": {"delete"}}) {
			t.Fatal("admin must not delete project")
		}
	})

	t.Run("should return not success", func(t *testing.T) {
		if orgP2CheckRolePermission(roles, "admin", Permissions{"project": {"read"}, "sales": {"delete"}}) {
			t.Fatal("admin must not delete sales")
		}
	})
}

func TestOrgP2DynamicAccessControlMerge(t *testing.T) {
	ac := access.New(orgP2Merge(DefaultStatements, access.Statements{"sales": {"create", "read", "update", "delete"}}))
	e := newEnv(t, Options{
		AC:                   ac,
		Roles:                map[string]access.Role{"owner": OwnerAC, "admin": AdminAC, "member": MemberAC},
		DynamicAccessControl: &DynamicAccessControlOptions{Enabled: true},
	})
	h := e.signInTestUser()
	org := e.createOrg(h, "test-dac", "test-dac")
	orgID := s(org["id"])
	ad := e.auth.Context().Adapter
	ctx := context.Background()
	perm := func(p map[string]any) bool {
		return orgP2Perm(t, e, h, map[string]any{"permissions": p})
	}

	t.Run("should merge DB permissions with built-in role permissions", func(t *testing.T) {
		if _, err := ad.Create(ctx, adapter.CreateInput{Model: "organizationRole", Data: adapter.Record{
			"organizationId": orgID, "role": "owner",
			"permission": `{"sales":["create","read","delete"]}`, "createdAt": time.Now(),
		}}); err != nil {
			t.Fatal(err)
		}
		if !perm(map[string]any{"sales": []any{"delete"}}) {
			t.Fatal("expected sales:delete from DB role")
		}
		if !perm(map[string]any{"organization": []any{"delete"}}) {
			t.Fatal("expected organization:delete from built-in role")
		}
	})

	t.Run("should not lose built-in actions when DB defines partial actions for the same resource", func(t *testing.T) {
		if _, err := ad.DeleteMany(ctx, "organizationRole", []adapter.Where{{Field: "organizationId", Value: orgID}}); err != nil {
			t.Fatal(err)
		}
		if _, err := ad.Create(ctx, adapter.CreateInput{Model: "organizationRole", Data: adapter.Record{
			"organizationId": orgID, "role": "owner",
			"permission": `{"organization":["update"]}`, "createdAt": time.Now(),
		}}); err != nil {
			t.Fatal(err)
		}
		if !perm(map[string]any{"organization": []any{"update"}}) {
			t.Fatal("expected organization:update")
		}
		if !perm(map[string]any{"organization": []any{"delete"}}) {
			t.Fatal("expected built-in organization:delete to be preserved")
		}
	})
}

func TestOrgP2InvitationLimit(t *testing.T) {
	e := newEnv(t, Options{InvitationLimit: betterauth.Int(1)})
	h := e.signInTestUser()
	org := e.post("/organization/create", h, map[string]any{"name": "test", "slug": "test"})
	expectOK(t, org)
	orgID := s(org.m()["id"])

	t.Run("should invite member to organization", func(t *testing.T) {
		r := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test6@test.com", "role": "member"})
		expectOK(t, r)
		if r.m()["status"] != "pending" {
			t.Fatalf("invite = %v", r.Data)
		}
	})

	t.Run("should throw error when invitation limit is reached", func(t *testing.T) {
		r := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test7@test.com", "role": "member"})
		expectCode(t, r, 403, "")
		if r.message() != ErrInvitationLimitReached.Message {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should throw error with custom invitation limit", func(t *testing.T) {
		e := newEnv(t, Options{InvitationLimitFunc: func(ctx *Ctx, data InvitationLimitData) (int, error) { return 0, nil }})
		h := e.signInTestUser()
		org := e.createOrg(h, "test", "test")
		r := e.api("createInvitation", h, map[string]any{"email": "test8@test.com", "role": "member", "organizationId": org["id"]}, nil)
		if r.Err == nil {
			t.Fatal("expected an error")
		}
		if r.message() != ErrInvitationLimitReached.Message {
			t.Fatalf("message = %q", r.message())
		}
	})
}

func orgP2CountInvites(t *testing.T, e *testEnv, h http.Header, email, status string) int {
	t.Helper()
	r := e.get("/organization/list-invitations", h, nil)
	expectOK(t, r)
	n := 0
	for _, x := range r.list() {
		inv, _ := x.(map[string]any)
		if (email == "" || inv["email"] == email) && inv["status"] == status {
			n++
		}
	}
	return n
}

func TestOrgP2CancelPendingInvitationsOnReInvite(t *testing.T) {
	e := newEnv(t, Options{CancelPendingInvitationsOnReInvite: true})
	h := e.signInTestUser()
	org := e.post("/organization/create", h, map[string]any{"name": "test", "slug": "test"})
	expectOK(t, org)
	h = mergeCookies(h, org.Headers)
	orgID := s(org.m()["id"])

	t.Run("should cancel pending invitations on re-invite", func(t *testing.T) {
		r := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test9@test.com", "role": "member"})
		expectOK(t, r)
		if r.m()["status"] != "pending" {
			t.Fatalf("invite = %v", r.Data)
		}
		r2 := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test9@test.com", "role": "member", "resend": true})
		expectOK(t, r2)
		if r2.m()["status"] != "pending" {
			t.Fatalf("invite2 = %v", r2.Data)
		}
		if n := orgP2CountInvites(t, e, h, "", "pending"); n != 1 {
			t.Fatalf("pending = %d", n)
		}
	})

	t.Run("should cancel pending invitation and create a new one when re-inviting without resend", func(t *testing.T) {
		r := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test9b@test.com", "role": "member"})
		expectOK(t, r)
		if r.m()["status"] != "pending" {
			t.Fatalf("invite = %v", r.Data)
		}
		original := r.m()["id"]
		r2 := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test9b@test.com", "role": "member"})
		expectOK(t, r2)
		if r2.m()["status"] != "pending" || r2.m()["id"] == original {
			t.Fatalf("invite2 = %v (original %v)", r2.Data, original)
		}
		if n := orgP2CountInvites(t, e, h, "test9b@test.com", "pending"); n != 1 {
			t.Fatalf("pending = %d", n)
		}
		if n := orgP2CountInvites(t, e, h, "test9b@test.com", "canceled"); n != 1 {
			t.Fatalf("canceled = %d", n)
		}
	})
}

func TestOrgP2ReInviteWithoutCancelStillThrows(t *testing.T) {
	e := newEnv(t, Options{})
	h := e.signInTestUser()
	org := e.post("/organization/create", h, map[string]any{"name": "test", "slug": "test"})
	expectOK(t, org)
	orgID := s(org.m()["id"])

	t.Run("should still throw USER_IS_ALREADY_INVITED when option is disabled", func(t *testing.T) {
		r := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test9c@test.com", "role": "member"})
		expectOK(t, r)
		if r.m()["status"] != "pending" {
			t.Fatalf("invite = %v", r.Data)
		}
		r2 := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test9c@test.com", "role": "member"})
		if r2.Err == nil || r2.message() != ErrUserIsAlreadyInvitedToThisOrganization.Message {
			t.Fatalf("invite2 = %d %v", r2.Status, r2.Data)
		}
	})
}

func TestOrgP2ResendInvitationReusesExisting(t *testing.T) {
	e := newEnv(t, Options{})
	h := e.signInTestUser()
	org := e.post("/organization/create", h, map[string]any{"name": "test", "slug": "test"})
	expectOK(t, org)
	h = mergeCookies(h, org.Headers)
	orgID := s(org.m()["id"])

	t.Run("should reuse existing invitation when resend is true", func(t *testing.T) {
		r := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test10@test.com", "role": "member"})
		expectOK(t, r)
		if r.m()["status"] != "pending" {
			t.Fatalf("invite = %v", r.Data)
		}
		r2 := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "test10@test.com", "role": "member", "resend": true})
		expectOK(t, r2)
		if r2.m()["status"] != "pending" || r2.m()["id"] != r.m()["id"] {
			t.Fatalf("invite2 = %v, original id %v", r2.Data, r.m()["id"])
		}
		if n := orgP2CountInvites(t, e, h, "", "pending"); n != 1 {
			t.Fatalf("pending = %d", n)
		}
	})
}

func TestOrgP2OwnerCanUpdateRoles(t *testing.T) {
	ac := access.New(access.Statements{"custom": {"custom"}})
	custom := ac.NewRole(access.Statements{"custom": {"custom"}})
	e := newEnv(t, Options{AC: ac, Roles: map[string]access.Role{"custom": custom, "owner": OwnerAC}},
		envConfig{extraPlugins: []*betterauth.Plugin{admin.New(admin.Options{})}})

	const adminEmail, adminPassword = "admin@email.com", "adminpassword"
	e.mustAPI("createUser", nil, map[string]any{"email": adminEmail, "password": adminPassword, "name": "Admin", "role": "admin"}, nil)
	adminH := e.signIn(adminEmail, adminPassword)
	org := e.createOrg(adminH, "Org", "org")
	orgID := s(org["id"])
	members, _ := org["members"].([]any)
	if len(members) == 0 {
		t.Fatal("couldn't get the owner id")
	}
	ownerID := s(members[0].(map[string]any)["id"])

	t.Run("allows setting custom role to a user", func(t *testing.T) {
		const userEmail, userPassword = "user@email.com", "userpassword"
		u := e.mustAPI("createUser", adminH, map[string]any{"name": "user", "email": userEmail, "password": userPassword}, nil)
		userID := s(u.m()["user"].(map[string]any)["id"])
		added := e.mustAPI("addMember", adminH, map[string]any{"organizationId": orgID, "userId": userID, "role": []any{}}, nil)
		e.mustAPI("updateMemberRole", adminH, map[string]any{"organizationId": orgID, "memberId": added.m()["id"], "role": []any{"custom", "owner"}}, nil)
		userH := e.signIn(userEmail, userPassword)
		r := e.mustAPI("hasPermission", userH, map[string]any{"organizationId": orgID, "permissions": map[string]any{"custom": []any{"custom"}}}, nil)
		if r.m()["success"] != true || r.m()["error"] != nil {
			t.Fatalf("permission = %v", r.Data)
		}
	})

	t.Run("allows org owner to set a custom role for themselves", func(t *testing.T) {
		e.mustAPI("updateMemberRole", adminH, map[string]any{"organizationId": orgID, "memberId": ownerID, "role": []any{"owner", "custom"}}, nil)
		r := e.mustAPI("hasPermission", adminH, map[string]any{"organizationId": orgID, "permissions": map[string]any{"custom": []any{"custom"}}}, nil)
		if r.m()["success"] != true || r.m()["error"] != nil {
			t.Fatalf("permission = %v", r.Data)
		}
	})

	t.Run("allows an org owner to remove their own creator role if not sole owner", func(t *testing.T) {
		r := e.mustAPI("updateMemberRole", adminH, map[string]any{"organizationId": orgID, "memberId": ownerID, "role": []any{"custom"}}, nil)
		if r.m()["role"] != "custom" {
			t.Fatalf("updated = %v", r.Data)
		}
	})

	t.Run("should throw error if sole org owner tries to remove creator role", func(t *testing.T) {
		t.Skip("upstream: it() is declared without a test body (the callback is outside the call), so vitest registers it as a todo")
	})
}

func TestOrgP2Types(t *testing.T) {
	t.Run("should infer active organization", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf type inference of $Infer.ActiveOrganization")
	})
}

func TestOrgP2OrganizationHooks(t *testing.T) {
	var mu sync.Mutex
	var called []string
	rec := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		called = append(called, name)
	}
	reset := func() {
		mu.Lock()
		defer mu.Unlock()
		called = nil
	}
	has := func(name string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range called {
			if c == name {
				return true
			}
		}
		return false
	}
	e := newEnv(t, Options{OrganizationHooks: &OrganizationHooks{
		BeforeCreateOrganization: func(ctx *Ctx, d HookData) (map[string]any, error) {
			rec("beforeCreateOrganization")
			out := map[string]any{}
			for k, v := range d.Organization {
				out[k] = v
			}
			out["metadata"] = map[string]any{"hookCalled": true}
			return out, nil
		},
		AfterCreateOrganization: func(ctx *Ctx, d HookData) error { rec("afterCreateOrganization"); return nil },
		BeforeCreateInvitation: func(ctx *Ctx, d HookData) (map[string]any, error) {
			rec("beforeCreateInvitation")
			return nil, nil
		},
		AfterCreateInvitation: func(ctx *Ctx, d HookData) error { rec("afterCreateInvitation"); return nil },
		BeforeAddMember: func(ctx *Ctx, d HookData) (map[string]any, error) {
			rec("beforeAddMember")
			return nil, nil
		},
		AfterAddMember: func(ctx *Ctx, d HookData) error { rec("afterAddMember"); return nil },
	}})
	h := e.signInTestUser()

	t.Run("should call organization creation hooks", func(t *testing.T) {
		reset()
		r := e.post("/organization/create", h, map[string]any{"name": "Test Org with Hooks", "slug": "test-org-hooks"})
		expectOK(t, r)
		h = mergeCookies(h, r.Headers)
		if !has("beforeCreateOrganization") || !has("afterCreateOrganization") {
			t.Fatalf("called = %v", called)
		}
		md, _ := r.m()["metadata"].(map[string]any)
		if len(md) != 1 || md["hookCalled"] != true {
			t.Fatalf("metadata = %#v", r.m()["metadata"])
		}
	})

	t.Run("should call invitation hooks", func(t *testing.T) {
		reset()
		r := e.post("/organization/invite-member", h, map[string]any{"email": "test@example.com", "role": "member"})
		expectOK(t, r)
		if !has("beforeCreateInvitation") || !has("afterCreateInvitation") {
			t.Fatalf("called = %v", called)
		}
	})
}

func TestOrgP2DeleteHooksReceiveEndpointContext(t *testing.T) {
	type seenT struct{ hasCtx, hasRequest bool }
	var mu sync.Mutex
	seen := map[string]seenT{}
	mark := func(name string, ctx *Ctx) {
		mu.Lock()
		defer mu.Unlock()
		seen[name] = seenT{hasCtx: ctx != nil, hasRequest: ctx != nil && ctx.Request != nil}
	}
	e := newEnv(t, Options{OrganizationHooks: &OrganizationHooks{
		BeforeDeleteOrganization: func(ctx *Ctx, d HookData) error { mark("beforeDeleteOrganization", ctx); return nil },
		AfterDeleteOrganization:  func(ctx *Ctx, d HookData) error { mark("afterDeleteOrganization", ctx); return nil },
	}})
	h := e.signInTestUser()

	t.Run("passes endpoint context to beforeDeleteOrganization and afterDeleteOrganization", func(t *testing.T) {
		created := e.post("/organization/create", h, map[string]any{"name": "Org For Delete Ctx", "slug": "org-for-delete-ctx"})
		expectOK(t, created)
		id := s(created.m()["id"])
		if id == "" {
			t.Fatal("no id")
		}
		expectOK(t, e.post("/organization/delete", h, map[string]any{"organizationId": id}))
		mu.Lock()
		defer mu.Unlock()
		for _, k := range []string{"beforeDeleteOrganization", "afterDeleteOrganization"} {
			if v := seen[k]; !v.hasCtx || !v.hasRequest {
				t.Fatalf("%s = %+v", k, v)
			}
		}
	})
}

func orgP2FindRow(rows []adapter.Record, id any) adapter.Record {
	for _, r := range rows {
		if r["id"] == id {
			return r
		}
	}
	return nil
}

func TestOrgP2AdditionalFieldsReturnedFalse(t *testing.T) {
	pub := func(name string) db.Field { return db.Field{Name: name, Type: db.TypeString, Required: db.True} }
	secret := func(name string) db.Field {
		return db.Field{Name: name, Type: db.TypeString, Required: db.False, Returned: db.False, Input: db.True}
	}
	e := newEnv(t, Options{
		Schema: &SchemaOptions{
			Organization: db.ModelOptions{AdditionalFields: []db.Field{pub("publicField"), secret("secretField")}},
			Member:       db.ModelOptions{AdditionalFields: []db.Field{pub("memberPublicField"), secret("memberSecretField")}},
			Invitation:   db.ModelOptions{AdditionalFields: []db.Field{pub("invitationPublicField"), secret("invitationSecretField")}},
		},
		InvitationLimit: betterauth.Int(3),
	})
	h := e.signInTestUser()

	t.Run("inferOrgAdditionalFields should filter out schema keys without additionalFields", func(t *testing.T) {
		t.Skip("TS-only: inferOrgAdditionalFields client type inference")
	})

	t.Run("should save field with returned: false but not return it in response", func(t *testing.T) {
		r := e.post("/organization/create", h, map[string]any{"name": "Test Org", "slug": "test-org-secret", "publicField": "public-value", "secretField": "secret-value"})
		expectOK(t, r)
		if r.m()["publicField"] != "public-value" {
			t.Fatalf("publicField = %v", r.m()["publicField"])
		}
		if _, ok := r.m()["secretField"]; ok {
			t.Fatalf("secretField returned: %v", r.m()["secretField"])
		}
		row := orgP2FindRow(e.db.Rows("organization"), r.m()["id"])
		if row == nil || row["secretField"] != "secret-value" {
			t.Fatalf("db row = %v", row)
		}
	})

	t.Run("should not return secret field when getting organization by slug", func(t *testing.T) {
		expectOK(t, e.post("/organization/create", h, map[string]any{"name": "Test Org 2", "slug": "test-org-secret-2", "publicField": "public-value-2", "secretField": "secret-value-2"}))
		r := e.get("/organization/get-full-organization", h, url.Values{"organizationSlug": {"test-org-secret-2"}})
		expectOK(t, r)
		if r.m()["publicField"] != "public-value-2" {
			t.Fatalf("full = %v", r.Data)
		}
		if _, ok := r.m()["secretField"]; ok {
			t.Fatalf("secretField returned: %v", r.Data)
		}
	})

	t.Run("should not return secret field when listing organizations", func(t *testing.T) {
		r := e.get("/organization/list", h, nil)
		expectOK(t, r)
		if len(r.list()) == 0 {
			t.Fatal("no organizations")
		}
		for _, x := range r.list() {
			o := x.(map[string]any)
			if _, ok := o["secretField"]; ok {
				t.Fatalf("secretField returned: %v", o)
			}
			if o["publicField"] == nil {
				t.Fatalf("publicField missing: %v", o)
			}
		}
	})

	t.Run("should not return member secret field in full organization response", func(t *testing.T) {
		org := e.post("/organization/create", h, map[string]any{"name": "Member Test Org", "slug": "member-test-org", "publicField": "public"})
		expectOK(t, org)
		orgID := s(org.m()["id"])
		su := e.mustAPI("signUpEmail", nil, map[string]any{"email": "member-test@example.com", "password": "password123", "name": "Member Test"}, nil)
		userID := s(su.m()["user"].(map[string]any)["id"])
		e.mustAPI("addMember", h, map[string]any{"userId": userID, "role": "member", "organizationId": orgID,
			"memberPublicField": "member-public", "memberSecretField": "member-secret"}, nil)
		r := e.get("/organization/get-full-organization", h, url.Values{"organizationId": {orgID}})
		expectOK(t, r)
		members, _ := r.m()["members"].([]any)
		var added map[string]any
		for _, x := range members {
			if m := x.(map[string]any); m["userId"] == userID {
				added = m
			}
		}
		if added == nil {
			t.Fatalf("member not found: %v", r.Data)
		}
		if added["memberPublicField"] != "member-public" {
			t.Fatalf("member = %v", added)
		}
		if _, ok := added["memberSecretField"]; ok {
			t.Fatalf("memberSecretField returned: %v", added)
		}
		row := orgP2FindRow(e.db.Rows("member"), added["id"])
		if row == nil || row["memberSecretField"] != "member-secret" {
			t.Fatalf("db row = %v", row)
		}
	})

	t.Run("should not return invitation secret field", func(t *testing.T) {
		org := e.post("/organization/create", h, map[string]any{"name": "Invitation Test Org", "slug": "invitation-test-org", "publicField": "public"})
		expectOK(t, org)
		orgID := s(org.m()["id"])
		expectOK(t, e.post("/organization/invite-member", h, map[string]any{"email": "invite-test@example.com", "role": "member", "organizationId": orgID,
			"invitationPublicField": "invite-public", "invitationSecretField": "invite-secret"}))
		r := e.get("/organization/get-full-organization", h, url.Values{"organizationId": {orgID}})
		expectOK(t, r)
		invs, _ := r.m()["invitations"].([]any)
		var inv map[string]any
		for _, x := range invs {
			if i := x.(map[string]any); i["email"] == "invite-test@example.com" {
				inv = i
			}
		}
		if inv == nil {
			t.Fatalf("invitation not found: %v", r.Data)
		}
		if inv["invitationPublicField"] != "invite-public" {
			t.Fatalf("invitation = %v", inv)
		}
		if _, ok := inv["invitationSecretField"]; ok {
			t.Fatalf("invitationSecretField returned: %v", inv)
		}
		row := orgP2FindRow(e.db.Rows("invitation"), inv["id"])
		if row == nil || row["invitationSecretField"] != "invite-secret" {
			t.Fatalf("db row = %v", row)
		}
	})

	t.Run("should not return secret field after updating organization", func(t *testing.T) {
		org := e.post("/organization/create", h, map[string]any{"name": "Update Test Org", "slug": "update-test-org", "publicField": "original-public", "secretField": "original-secret"})
		expectOK(t, org)
		orgID := s(org.m()["id"])
		r := e.post("/organization/update", h, map[string]any{"organizationId": orgID, "data": map[string]any{
			"name": "Updated Test Org", "publicField": "updated-public", "secretField": "updated-secret"}})
		expectOK(t, r)
		if r.m()["publicField"] != "updated-public" {
			t.Fatalf("updated = %v", r.Data)
		}
		if _, ok := r.m()["secretField"]; ok {
			t.Fatalf("secretField returned: %v", r.Data)
		}
		row := orgP2FindRow(e.db.Rows("organization"), orgID)
		if row == nil || row["secretField"] != "updated-secret" {
			t.Fatalf("db row = %v", row)
		}
	})
}

// orgP2FailingAdapter makes DeleteMany on failModel fail inside transactions while armed
// (the vi.spyOn(ctx.adapter, "transaction") mock upstream).
type orgP2FailingAdapter struct {
	adapter.Adapter
	armed     *atomic.Bool
	failModel string
}

func (f orgP2FailingAdapter) DeleteMany(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	if f.armed.Load() && betterauth.InTransaction(ctx) && model == f.failModel {
		return 0, errors.New("simulated mid-cascade failure")
	}
	return f.Adapter.DeleteMany(ctx, model, where)
}

func (f orgP2FailingAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return f.Adapter.Transaction(ctx, func(c context.Context, tx adapter.Adapter) error {
		return fn(c, orgP2FailingAdapter{Adapter: tx, armed: f.armed, failModel: f.failModel})
	})
}

func orgP2CascadeEnv(t *testing.T, failModel string) (*testEnv, *atomic.Bool) {
	armed := &atomic.Bool{}
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}}, envConfig{mutate: func(c *betterauth.Config) {
		inner := c.Database
		if inner == nil {
			inner = memory.New()
		}
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := inner(o)
			if err != nil {
				return nil, err
			}
			return orgP2FailingAdapter{Adapter: a, armed: armed, failModel: failModel}, nil
		}
	}})
	return e, armed
}

func TestOrgP2DeleteCascadeRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("rolls back deleteOrganization when an intermediate step throws", func(t *testing.T) {
		e, armed := orgP2CascadeEnv(t, "invitation")
		ad := e.auth.Context().Adapter
		h := e.signInTestUser()
		org := e.post("/organization/create", h, map[string]any{"name": "Cascade Org", "slug": "cascade-org"})
		expectOK(t, org)
		orgID := s(org.m()["id"])
		if orgID == "" {
			t.Fatal("no organization id")
		}
		expectOK(t, e.post("/organization/invite-member", h, map[string]any{"email": "invitee@email.com", "role": "member", "organizationId": orgID}))

		armed.Store(true)
		_, err := e.auth.API.Call(ctx, "deleteOrganization", betterauth.CallInput{Headers: h, Body: map[string]any{"organizationId": orgID}})
		armed.Store(false)
		if err == nil {
			t.Fatal("expected deleteOrganization to fail")
		}

		where := []adapter.Where{{Field: "organizationId", Value: orgID}}
		if n, err := ad.Count(ctx, "member", where); err != nil || n == 0 {
			t.Fatalf("members = %d, %v", n, err)
		}
		if n, err := ad.Count(ctx, "invitation", where); err != nil || n == 0 {
			t.Fatalf("invitations = %d, %v", n, err)
		}
		if o, err := ad.FindOne(ctx, adapter.FindOneInput{Model: "organization", Where: []adapter.Where{{Field: "id", Value: orgID}}}); err != nil || o == nil {
			t.Fatalf("organization = %v, %v", o, err)
		}
	})

	t.Run("rolls back removeMember when an intermediate step throws", func(t *testing.T) {
		e, armed := orgP2CascadeEnv(t, "teamMember")
		ad := e.auth.Context().Adapter
		h := e.signInTestUser()
		org := e.post("/organization/create", h, map[string]any{"name": "Cascade Member Org", "slug": "cascade-member-org"})
		expectOK(t, org)
		h = mergeCookies(h, org.Headers)
		orgID := s(org.m()["id"])
		team := e.post("/organization/create-team", h, map[string]any{"name": "Cascade Team", "organizationId": orgID})
		expectOK(t, team)
		teamID := s(team.m()["id"])
		su := e.post("/sign-up/email", nil, map[string]any{"email": "memberuser@email.com", "password": "password", "name": "Member User"})
		expectOK(t, su)
		newUserID := s(su.m()["user"].(map[string]any)["id"])
		added := e.mustAPI("addMember", nil, map[string]any{"organizationId": orgID, "userId": newUserID, "role": "member"}, nil)
		memberID := s(added.m()["id"])
		e.mustAPI("addTeamMember", h, map[string]any{"userId": newUserID, "teamId": teamID, "organizationId": orgID}, nil)

		armed.Store(true)
		_, err := e.auth.API.Call(ctx, "removeMember", betterauth.CallInput{Headers: h, Body: map[string]any{"organizationId": orgID, "memberIdOrEmail": memberID}})
		armed.Store(false)
		if err == nil {
			t.Fatal("expected removeMember to fail")
		}

		if m, err := ad.FindOne(ctx, adapter.FindOneInput{Model: "member", Where: []adapter.Where{{Field: "id", Value: memberID}}}); err != nil || m == nil {
			t.Fatalf("member = %v, %v", m, err)
		}
		n, err := ad.Count(ctx, "teamMember", []adapter.Where{{Field: "teamId", Value: teamID}, {Field: "userId", Value: newUserID}})
		if err != nil || n != 1 {
			t.Fatalf("teamMember count = %d, %v", n, err)
		}
	})
}
