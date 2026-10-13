package organization

// Port of upstream routes/crud-access-control.test.ts ("dynamic access control").

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

func cacUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func cacMerge(a, b access.Statements) access.Statements {
	out := access.Statements{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// cacPerm normalises a decoded permission object to map[string][]string.
func cacPerm(v any) map[string][]string {
	m, _ := v.(map[string]any)
	if m == nil {
		return nil
	}
	out := map[string][]string{}
	for k, raw := range m {
		l, _ := raw.([]any)
		actions := []string{}
		for _, a := range l {
			actions = append(actions, s(a))
		}
		out[k] = actions
	}
	return out
}

type cacEnv struct {
	*testEnv
	headers http.Header
	orgID   string
}

// cacCreateRole is authClient.organization.createRole (an HTTP call).
func (c *cacEnv) cacCreateRole(headers http.Header, role string, permission map[string]any, additional map[string]any) *result {
	c.t.Helper()
	body := map[string]any{"role": role, "permission": permission}
	if additional != nil {
		body["additionalFields"] = additional
	}
	return c.post("/organization/create-role", headers, body)
}

func (c *cacEnv) cacMustCreateRole(t *testing.T, headers http.Header, role string, permission map[string]any, additional map[string]any) map[string]any {
	t.Helper()
	r := c.cacCreateRole(headers, role, permission, additional)
	expectOK(t, r)
	rd, _ := r.m()["roleData"].(map[string]any)
	if rd == nil {
		t.Fatalf("roleData missing: %v", r.Data)
	}
	return rd
}

// cacCreateUser mirrors the upstream createUser helper.
func (c *cacEnv) cacCreateUser(role string) (http.Header, map[string]any) {
	c.t.Helper()
	email := "some-test-user-" + cacUUID() + "@email.com"
	password := "some-test-user-" + cacUUID()
	su := c.mustAPI("signUpEmail", nil, map[string]any{"email": email, "name": "some-test-user", "password": password}, nil)
	user, _ := su.m()["user"].(map[string]any)
	mem := c.mustAPI("addMember", c.headers, map[string]any{"role": role, "userId": user["id"], "organizationId": c.orgID}, nil).m()
	if mem == nil {
		c.t.Fatal("Member not found")
	}
	h := c.signIn(email, password)
	r := c.post("/organization/set-active", h, map[string]any{"organizationId": c.orgID})
	expectOK(c.t, r)
	return mergeCookies(h, r.Headers), mem
}

func TestCrudACDynamicAccessControl(t *testing.T) {
	t.Run("should preserve exact built-in organization role statement types", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf on readonly tuple statement types")
	})

	ac := access.New(cacMerge(access.Statements{
		"project": {"create", "read", "update", "delete"},
		"sales":   {"create", "read", "update", "delete"},
	}, DefaultStatements))
	owner := ac.NewRole(cacMerge(access.Statements{
		"project": {"create", "delete", "update", "read"},
		"sales":   {"create", "read", "update", "delete"},
	}, OwnerAC.Statements))
	admin := ac.NewRole(cacMerge(access.Statements{
		"project": {"create", "read", "delete", "update"},
		"sales":   {"create", "read"},
	}, AdminAC.Statements))
	member := ac.NewRole(cacMerge(access.Statements{
		"project": {"read"},
		"sales":   {"read"},
	}, MemberAC.Statements))

	env := newEnv(t, Options{
		AC:                   ac,
		Roles:                map[string]access.Role{"admin": admin, "member": member, "owner": owner},
		DynamicAccessControl: &DynamicAccessControlOptions{Enabled: true},
		Schema: &SchemaOptions{
			Organization: db.ModelOptions{ModelName: "organization"},
			OrganizationRole: db.ModelOptions{
				ModelName: "organizationRole",
				AdditionalFields: []db.Field{
					{Name: "color", Type: db.TypeString, DefaultValue: "#ffffff", Required: db.True},
					{Name: "serverOnlyValue", Type: db.TypeString, DefaultValue: "server-only-value", Input: db.False, Required: db.True},
				},
			},
		},
	})
	c := &cacEnv{testEnv: env}
	headers := env.signInTestUser()
	orgRes := env.api("createOrganization", headers, map[string]any{
		"name": "test", "slug": "test", "metadata": map[string]any{"test": "test"},
	}, nil)
	expectOK(t, orgRes)
	headers = mergeCookies(headers, orgRes.Headers)
	c.headers = headers
	c.orgID = s(orgRes.m()["id"])
	if c.orgID == "" {
		t.Fatal("Organization not created")
	}
	if mi := env.mustAPI("getActiveMember", headers, nil, nil).m(); mi == nil {
		t.Fatal("Member info not found")
	}
	adminHeaders, _ := c.cacCreateUser("admin")
	normalHeaders, normalMember := c.cacCreateUser("member")
	orgID := c.orgID

	t.Run("does not reveal dynamic role existence to members without update permission", func(t *testing.T) {
		_, targetMember := c.cacCreateUser("member")
		roleName := "hidden-role-" + cacUUID()
		created := c.cacCreateRole(headers, roleName, map[string]any{"project": []any{"read"}}, map[string]any{"color": "#ff0000"})
		expectOK(t, created)
		existing := c.post("/organization/update-member-role", normalHeaders, map[string]any{"memberId": targetMember["id"], "role": roleName})
		missing := c.post("/organization/update-member-role", normalHeaders, map[string]any{"memberId": targetMember["id"], "role": "missing-role-" + cacUUID()})
		if existing.Status != 403 || missing.Status != 403 {
			t.Fatalf("statuses = %d (%s), %d (%s)", existing.Status, existing.message(), missing.Status, missing.message())
		}
		if existing.message() != missing.message() {
			t.Fatalf("messages differ: %q vs %q", existing.message(), missing.message())
		}
		if existing.Err == nil || missing.Err == nil {
			t.Fatal("expected data null")
		}
	})

	t.Run("should successfully create a new role", func(t *testing.T) {
		permission := map[string]any{"project": []any{"create"}}
		r := c.cacCreateRole(headers, "test", permission, map[string]any{"color": "#000000"})
		expectOK(t, r)
		if r.m()["success"] != true {
			t.Fatalf("success = %v", r.Data)
		}
		rd := r.m()["roleData"].(map[string]any)
		if !reflect.DeepEqual(cacPerm(rd["permission"]), map[string][]string{"project": {"create"}}) {
			t.Fatalf("permission = %v", rd["permission"])
		}
		if rd["color"] != "#000000" {
			t.Fatalf("color = %v", rd["color"])
		}
		if rd["serverOnlyValue"] != "server-only-value" {
			t.Fatalf("serverOnlyValue = %v", rd["serverOnlyValue"])
		}
		env.mustAPI("updateMemberRole", headers, map[string]any{"memberId": normalMember["id"], "role": rd["role"]}, nil)
		shouldFail := env.mustAPI("hasPermission", normalHeaders, map[string]any{
			"organizationId": orgID, "permissions": map[string]any{"project": []any{"delete"}},
		}, nil)
		if shouldFail.m()["success"] != false {
			t.Fatalf("shouldFail = %v", shouldFail.Data)
		}
		shouldPass := env.mustAPI("hasPermission", normalHeaders, map[string]any{
			"organizationId": orgID, "permissions": map[string]any{"project": []any{"create"}},
		}, nil)
		if shouldPass.m()["success"] != true {
			t.Fatalf("shouldPass = %v", shouldPass.Data)
		}
	})

	t.Run("should not be allowed to create a role without the right ac resource permissions", func(t *testing.T) {
		r := c.cacCreateRole(normalHeaders, "test-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		if r.Err == nil {
			t.Fatal("Test role error not found")
		}
		if r.message() != ErrYouAreNotAllowedToCreateARole.Message {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should not be allowed to create a role with higher permissions than the current role", func(t *testing.T) {
		r := c.cacCreateRole(adminHeaders, "test-"+cacUUID(), map[string]any{
			"sales": []any{"create", "delete", "create", "update", "read"},
		}, map[string]any{"color": "#000000"})
		if r.Err == nil {
			t.Fatal("Test role created")
		}
		if !strings.HasPrefix(r.message(), ErrYouAreNotAllowedToCreateARole.Message) {
			t.Fatalf("message = %q", r.message())
		}
		mp, ok := r.m()["missingPermissions"]
		if !ok {
			t.Fatalf("missingPermissions missing: %v", r.Data)
		}
		if !reflect.DeepEqual(mp, []any{"sales:delete", "sales:update"}) {
			t.Fatalf("missingPermissions = %v", mp)
		}
	})

	t.Run("should not be allowed to create a role which is either predefined or already exists in DB", func(t *testing.T) {
		r := c.cacCreateRole(headers, "admin", map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		if r.Err == nil || r.message() != ErrRoleNameIsAlreadyTaken.Message {
			t.Fatalf("admin: %d %q", r.Status, r.message())
		}
		r2 := c.cacCreateRole(headers, "test", map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		if r2.Err == nil || r2.message() != ErrRoleNameIsAlreadyTaken.Message {
			t.Fatalf("test: %d %q", r2.Status, r2.message())
		}
	})

	t.Run("should delete a role by id", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "test-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		res := env.mustAPI("deleteOrgRole", headers, map[string]any{"roleId": rd["id"]}, nil)
		if res.Data == nil {
			t.Fatal("expected non-null result")
		}
	})

	t.Run("should delete a role by name", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "test-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		res := env.mustAPI("deleteOrgRole", headers, map[string]any{"roleName": rd["role"]}, nil)
		if res.Data == nil {
			t.Fatal("expected non-null result")
		}
	})

	cacMemberIDOf := func(t *testing.T, userID any) any {
		t.Helper()
		lm := env.mustAPI("listMembers", headers, nil, map[string]any{"organizationId": orgID}).m()
		members, _ := lm["members"].([]any)
		for _, m := range members {
			mm := m.(map[string]any)
			if mm["userId"] == userID {
				return mm["id"]
			}
		}
		t.Fatalf("member for user %v not found", userID)
		return nil
	}

	t.Run("should not be allowed to delete a role that is assigned to members", func(t *testing.T) {
		c.cacMustCreateRole(t, headers, "assigned-role", map[string]any{"project": []any{"read"}}, map[string]any{"color": "#000000"})
		su := env.mustAPI("signUpEmail", nil, map[string]any{
			"email": "delete-role-test-" + cacUUID() + "@email.com", "name": "test-member", "password": "password-" + cacUUID(),
		}, nil)
		userID := su.m()["user"].(map[string]any)["id"]
		env.mustAPI("addMember", headers, map[string]any{"role": "assigned-role", "userId": userID, "organizationId": orgID}, nil)
		r := env.api("deleteOrgRole", headers, map[string]any{"roleName": "assigned-role"}, nil)
		if r.Err == nil || !strings.Contains(r.message(), ErrRoleIsAssignedToMembers.Message) {
			t.Fatalf("delete assigned: %d %q", r.Status, r.message())
		}
		env.mustAPI("updateMemberRole", headers, map[string]any{"memberId": cacMemberIDOf(t, userID), "role": "member"}, nil)
		env.mustAPI("deleteOrgRole", headers, map[string]any{"roleName": "assigned-role"}, nil)
	})

	t.Run("should not be allowed to delete a role when member has multiple roles including that role", func(t *testing.T) {
		c.cacMustCreateRole(t, headers, "multi-role-1", map[string]any{"project": []any{"read"}}, map[string]any{"color": "#000000"})
		c.cacMustCreateRole(t, headers, "multi-role-2", map[string]any{"project": []any{"create"}}, map[string]any{"color": "#111111"})
		su := env.mustAPI("signUpEmail", nil, map[string]any{
			"email": "multi-role-test-" + cacUUID() + "@email.com", "name": "test-member", "password": "password-" + cacUUID(),
		}, nil)
		userID := su.m()["user"].(map[string]any)["id"]
		env.mustAPI("addMember", headers, map[string]any{"role": []any{"multi-role-1", "multi-role-2"}, "userId": userID, "organizationId": orgID}, nil)
		r := env.api("deleteOrgRole", headers, map[string]any{"roleName": "multi-role-1"}, nil)
		if r.Err == nil || !strings.Contains(r.message(), ErrRoleIsAssignedToMembers.Message) {
			t.Fatalf("delete assigned: %d %q", r.Status, r.message())
		}
		env.mustAPI("updateMemberRole", headers, map[string]any{"memberId": cacMemberIDOf(t, userID), "role": "member"}, nil)
		env.mustAPI("deleteOrgRole", headers, map[string]any{"roleName": "multi-role-1"}, nil)
		env.mustAPI("deleteOrgRole", headers, map[string]any{"roleName": "multi-role-2"}, nil)
	})

	t.Run("should not be allowed to delete a role without necessary permissions", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, adminHeaders, "test-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		r := env.api("deleteOrgRole", normalHeaders, map[string]any{"roleName": rd["role"]}, nil)
		if r.Err == nil || !strings.Contains(r.message(), ErrYouAreNotAllowedToDeleteARole.Message) {
			t.Fatalf("delete: %d %q", r.Status, r.message())
		}
	})

	t.Run("should not be allowed to delete a role that doesn't exist", func(t *testing.T) {
		r := env.api("deleteOrgRole", headers, map[string]any{"roleName": "non-existent-role"}, nil)
		if r.Err == nil {
			if r.Data != nil {
				t.Fatalf("expected null, got %v", r.Data)
			}
			return
		}
		if r.message() != ErrRoleNotFound.Message {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should list roles", func(t *testing.T) {
		permission := map[string]any{
			"project": []any{"create"},
			"ac":      []any{"read", "update", "create", "delete"},
		}
		c.cacCreateRole(headers, "list-test-role", permission, map[string]any{"color": "#123"})
		res := env.mustAPI("listOrgRoles", headers, nil, nil)
		roles := res.list()
		if len(roles) == 0 {
			t.Fatalf("roles = %v", res.Data)
		}
		if _, isStr := roles[0].(map[string]any)["permission"].(string); isStr {
			t.Fatal("permission should be parsed")
		}
		var found map[string]any
		for _, r := range roles {
			if rm := r.(map[string]any); rm["role"] == "list-test-role" {
				found = rm
			}
		}
		if found == nil {
			t.Fatal("list-test-role not found")
		}
		want := map[string][]string{"project": {"create"}, "ac": {"read", "update", "create", "delete"}}
		if !reflect.DeepEqual(cacPerm(found["permission"]), want) {
			t.Fatalf("permission = %v", found["permission"])
		}
		if found["color"] != "#123" {
			t.Fatalf("color = %v", found["color"])
		}
	})

	t.Run("should not be allowed to list roles without necessary permissions", func(t *testing.T) {
		r := env.api("listOrgRoles", normalHeaders, nil, nil)
		if r.Err == nil || !strings.Contains(r.message(), ErrYouAreNotAllowedToListARole.Message) {
			t.Fatalf("list: %d %q", r.Status, r.message())
		}
	})

	t.Run("should get a role by id", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "read-test-role-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		res := env.mustAPI("getOrgRole", headers, nil, map[string]any{"roleId": rd["id"], "organizationId": orgID}).m()
		if res == nil || res["role"] != rd["role"] || !reflect.DeepEqual(cacPerm(res["permission"]), cacPerm(rd["permission"])) || res["color"] != "#000000" {
			t.Fatalf("role = %v", res)
		}
	})

	t.Run("should get a role by name", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "read-test-role-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		res := env.mustAPI("getOrgRole", headers, nil, map[string]any{"roleName": rd["role"], "organizationId": orgID}).m()
		if res == nil || res["role"] != rd["role"] || !reflect.DeepEqual(cacPerm(res["permission"]), cacPerm(rd["permission"])) || res["color"] != "#000000" {
			t.Fatalf("role = %v", res)
		}
	})

	t.Run("should update a role's permission by id", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "update-test-role-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		res := env.mustAPI("updateOrgRole", headers, map[string]any{
			"roleId": rd["id"], "data": map[string]any{"permission": map[string]any{"project": []any{"create", "delete"}}},
		}, nil).m()
		nrd, _ := res["roleData"].(map[string]any)
		if nrd == nil || nrd["role"] != rd["role"] || !reflect.DeepEqual(cacPerm(nrd["permission"]), map[string][]string{"project": {"create", "delete"}}) {
			t.Fatalf("res = %v", res)
		}
	})

	t.Run("should update a role's name by name", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "test-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		roleName := s(rd["role"])
		res := env.mustAPI("updateOrgRole", headers, map[string]any{
			"roleName": roleName, "data": map[string]any{"roleName": "updated-" + roleName},
		}, nil).m()
		if nrd, _ := res["roleData"].(map[string]any); nrd == nil || nrd["role"] != "updated-"+roleName {
			t.Fatalf("res = %v", res)
		}
		res2 := env.mustAPI("getOrgRole", headers, nil, map[string]any{"roleName": "updated-" + roleName, "organizationId": orgID}).m()
		if res2 == nil || res2["role"] != "updated-"+roleName {
			t.Fatalf("res2 = %v", res2)
		}
	})

	t.Run("should not be allowed to update a role without the right ac resource permissions", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "update-not-allowed-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{"color": "#000000"})
		r := env.api("updateOrgRole", normalHeaders, map[string]any{
			"roleId": rd["id"], "data": map[string]any{"roleName": "updated-" + s(rd["role"])},
		}, nil)
		if r.Err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("should be able to update additional fields", func(t *testing.T) {
		rd := c.cacMustCreateRole(t, headers, "test-"+cacUUID(), map[string]any{"project": []any{"create"}}, map[string]any{
			"color": "#000000", "someInvalidKey": "this would be ignored by zod",
		})
		res := env.mustAPI("updateOrgRole", headers, map[string]any{"roleId": rd["id"], "data": map[string]any{"color": "#111111"}}, nil).m()
		nrd, _ := res["roleData"].(map[string]any)
		if nrd == nil || nrd["color"] != "#111111" {
			t.Fatalf("res = %v", res)
		}
		if _, ok := nrd["someInvalidKey"]; ok {
			t.Fatalf("someInvalidKey should be undefined: %v", nrd)
		}
	})

	t.Run("should not allow member to list roles using another member's permissions", func(t *testing.T) {
		fresh, _ := c.cacCreateUser("member")
		c.cacMustCreateRole(t, headers, "admin-only-"+cacUUID(), map[string]any{"project": []any{"delete"}}, map[string]any{"color": "#ff0000"})
		res := env.mustAPI("listOrgRoles", fresh, nil, map[string]any{"organizationId": orgID})
		if _, ok := res.Data.([]any); !ok {
			t.Fatalf("expected array, got %v", res.Data)
		}
	})

	t.Run("should not allow member to get role details using another member's permissions", func(t *testing.T) {
		fresh, _ := c.cacCreateUser("member")
		rd := c.cacMustCreateRole(t, headers, "test-get-role-"+cacUUID(), map[string]any{"project": []any{"read"}}, map[string]any{"color": "#ff0000"})
		res := env.mustAPI("getOrgRole", fresh, nil, map[string]any{"organizationId": orgID, "roleId": rd["id"]}).m()
		if res == nil || res["id"] != rd["id"] {
			t.Fatalf("res = %v", res)
		}
	})

	t.Run("should not allow member to update roles without proper permissions (privilege escalation test)", func(t *testing.T) {
		fresh, _ := c.cacCreateUser("member")
		rd := c.cacMustCreateRole(t, headers, "vulnerable-role-"+cacUUID(), map[string]any{"project": []any{"read"}}, map[string]any{"color": "#ff0000"})
		r := env.api("updateOrgRole", fresh, map[string]any{
			"roleId": rd["id"],
			"data": map[string]any{"permission": map[string]any{
				"ac":           []any{"create", "update", "delete"},
				"organization": []any{"update", "delete"},
				"project":      []any{"create", "read", "update", "delete"},
			}},
		}, nil)
		if r.Err == nil {
			t.Fatal("expected error")
		}
		check := env.mustAPI("getOrgRole", headers, nil, map[string]any{"organizationId": orgID, "roleId": rd["id"]}).m()
		if !reflect.DeepEqual(cacPerm(check["permission"]), map[string][]string{"project": {"read"}}) {
			t.Fatalf("permission = %v", check["permission"])
		}
	})

	t.Run("should properly identify the correct member when checking permissions", func(t *testing.T) {
		fresh, _ := c.cacCreateUser("member")
		rd := c.cacMustCreateRole(t, headers, "owner-only-update-"+cacUUID(), map[string]any{"sales": []any{"delete"}}, map[string]any{"color": "#ff0000"})
		r := env.api("updateOrgRole", fresh, map[string]any{"roleId": rd["id"], "data": map[string]any{"roleName": "hijacked-role"}}, nil)
		if r.Err == nil || !strings.Contains(r.message(), ErrYouAreNotAllowedToUpdateARole.Message) {
			t.Fatalf("update: %d %q", r.Status, r.message())
		}
		res := env.mustAPI("updateOrgRole", adminHeaders, map[string]any{
			"roleId": rd["id"], "data": map[string]any{"roleName": "admin-updated-" + s(rd["role"])},
		}, nil).m()
		nrd, _ := res["roleData"].(map[string]any)
		if nrd == nil || !strings.Contains(s(nrd["role"]), "admin-updated") {
			t.Fatalf("res = %v", res)
		}
	})

	t.Run("should not allow cross-organization privilege escalation", func(t *testing.T) {
		fresh, _ := c.cacCreateUser("member")
		org2 := env.api("createOrganization", headers, map[string]any{"name": "second-org", "slug": "second-org-" + cacUUID()}, nil)
		expectOK(t, org2)
		headers = mergeCookies(headers, org2.Headers)
		c.headers = headers
		org2ID := s(org2.m()["id"])
		// The member is not part of org2, so set-active fails (ignored upstream).
		sa := env.post("/organization/set-active", fresh, map[string]any{"organizationId": org2ID})
		fresh = mergeCookies(fresh, sa.Headers)
		r := env.api("listOrgRoles", fresh, nil, map[string]any{"organizationId": org2ID})
		if r.Err == nil || !strings.Contains(r.message(), "You are not a member of this organization") {
			t.Fatalf("list: %d %q", r.Status, r.message())
		}
		sa = env.post("/organization/set-active", fresh, map[string]any{"organizationId": orgID})
		expectOK(t, sa)
	})
}
