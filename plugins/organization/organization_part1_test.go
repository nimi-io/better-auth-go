package organization

// Port of upstream organization.test.ts lines 1-1665: describe blocks "organization type",
// "organization" and "invitation expiration and filtering".

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

func orgP1RandomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// orgP1UserID returns the user id of the session behind headers.
func orgP1UserID(e *testEnv, h http.Header) string {
	e.t.Helper()
	return s(e.session(h)["userId"])
}

// orgP1SignUpAPI signs up through auth.api.signUpEmail and returns the new user id.
func orgP1SignUpAPI(e *testEnv, email, password, name string) string {
	e.t.Helper()
	r := e.mustAPI("signUpEmail", nil, map[string]any{"email": email, "password": password, "name": name}, nil)
	u, _ := r.m()["user"].(map[string]any)
	return s(u["id"])
}

func orgP1Members(t *testing.T, r *result) []map[string]any {
	t.Helper()
	raw, _ := r.m()["members"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, m := range raw {
		mm, _ := m.(map[string]any)
		out = append(out, mm)
	}
	return out
}

func orgP1FindRole(members []map[string]any, role string) map[string]any {
	for _, m := range members {
		if s(m["role"]) == role {
			return m
		}
	}
	return nil
}

func orgP1TableIndex(tables []db.PluginTable, key string) int {
	for i, tb := range tables {
		if tb.Key == key {
			return i
		}
	}
	return -1
}

func TestOrgP1OrganizationType(t *testing.T) {
	t.Run("empty org type should works", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf satisfies OrganizationOptions")
	})
	t.Run("allows dynamic roles in create invitation input", func(t *testing.T) {
		t.Skip("TS-only: type-level check of createInvitation role input (code is never executed upstream)")
	})
}

func TestOrgP1Organization(t *testing.T) {
	e := newEnv(t, Options{
		MembershipLimit: 6,
		Schema: &SchemaOptions{
			Organization: db.ModelOptions{ModelName: "team"},
			Member:       db.ModelOptions{ModelName: "teamMembers", Fields: map[string]string{"userId": "user_id"}},
		},
		InvitationLimit: betterauth.Int(3),
	}, envConfig{verifyUsers: true, mutate: func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{ModelName: "users"}}
	}})
	headers := e.signInTestUser()

	t.Run("should have correct schema order when dynamicAccessControl is enabled", func(t *testing.T) {
		p := New(Options{DynamicAccessControl: &DynamicAccessControlOptions{Enabled: true}})
		orgIdx := orgP1TableIndex(p.Schema, "organization")
		roleIdx := orgP1TableIndex(p.Schema, "organizationRole")
		if orgIdx == -1 || roleIdx == -1 || orgIdx >= roleIdx {
			t.Fatalf("organization index %d, organizationRole index %d", orgIdx, roleIdx)
		}
	})

	t.Run("should include activeTeamId when both dynamicAccessControl and teams are enabled", func(t *testing.T) {
		p := New(Options{DynamicAccessControl: &DynamicAccessControlOptions{Enabled: true}, Teams: &TeamsOptions{Enabled: true}})
		si := orgP1TableIndex(p.Schema, "session")
		if si == -1 {
			t.Fatal("session schema missing")
		}
		var found *db.Field
		for i, f := range p.Schema[si].Fields {
			if f.Name == "activeTeamId" {
				found = &p.Schema[si].Fields[i]
			}
		}
		if found == nil {
			t.Fatal("activeTeamId missing")
		}
		if found.Type != db.TypeString || found.Required == nil || *found.Required {
			t.Fatalf("activeTeamId field = %+v", *found)
		}
		for _, k := range []string{"team", "teamMember", "organizationRole"} {
			if orgP1TableIndex(p.Schema, k) == -1 {
				t.Fatalf("%s schema missing", k)
			}
		}
	})

	var organizationID, organization2ID string

	t.Run("create organization", func(t *testing.T) {
		r := e.post("/organization/create", headers, map[string]any{
			"name": "test", "slug": "test", "metadata": map[string]any{"test": "test"},
		})
		expectOK(t, r)
		organizationID = s(r.m()["id"])
		if r.m()["name"] == nil || r.m()["metadata"] == nil {
			t.Fatalf("org = %v", r.Data)
		}
		members := orgP1Members(t, r)
		if len(members) != 1 || s(members[0]["role"]) != "owner" {
			t.Fatalf("members = %v", members)
		}
		if got := s(e.session(headers)["activeOrganizationId"]); got != organizationID {
			t.Fatalf("activeOrganizationId = %q, want %q", got, organizationID)
		}
	})

	t.Run("should check if organization slug is available", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/check-slug", h, map[string]any{"slug": "unused-slug"})
		expectOK(t, r)
		if r.m()["status"] != true {
			t.Fatalf("status = %v", r.Data)
		}
		r = e.post("/organization/check-slug", h, map[string]any{"slug": "test"})
		expectCode(t, r, 400, "")
		if r.message() != ErrOrganizationSlugAlreadyTaken.Message {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should prevent creating organization with empty slug", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/create", h, map[string]any{"name": "test-empty-slug", "slug": ""})
		expectCode(t, r, 400, "")
	})

	t.Run("should prevent creating organization with empty name", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/create", h, map[string]any{"name": "", "slug": "test-empty-name"})
		expectCode(t, r, 400, "")
	})

	t.Run("should create organization directly in the server without cookie", func(t *testing.T) {
		userID := orgP1UserID(e, headers)
		r := e.mustAPI("createOrganization", nil, map[string]any{"name": "test2", "slug": "test2", "userId": userID}, nil)
		organization2ID = s(r.m()["id"])
		if s(r.m()["name"]) != "test2" {
			t.Fatalf("name = %v", r.m()["name"])
		}
		members := orgP1Members(t, r)
		if len(members) != 1 || s(members[0]["role"]) != "owner" {
			t.Fatalf("members = %v", members)
		}
	})

	t.Run("should allow listing organizations", func(t *testing.T) {
		r := e.get("/organization/list", headers, nil)
		expectOK(t, r)
		if len(r.list()) != 2 {
			t.Fatalf("organizations = %v", r.Data)
		}
	})

	t.Run("should allow updating organization", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/update", h, map[string]any{"organizationId": organizationID, "data": map[string]any{"name": "test2"}})
		expectOK(t, r)
		if s(r.m()["name"]) != "test2" {
			t.Fatalf("name = %v", r.Data)
		}
	})

	t.Run("should prevent updating organization to duplicate slug", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/update", h, map[string]any{"organizationId": organization2ID, "data": map[string]any{"slug": "test"}})
		expectCode(t, r, 400, "")
		if !strings.Contains(r.code(), ErrOrganizationSlugAlreadyTaken.Code) {
			t.Fatalf("code = %q", r.code())
		}
	})

	t.Run("should allow updating organization metadata", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/update", h, map[string]any{"organizationId": organizationID, "data": map[string]any{"metadata": map[string]any{"test": "test2"}}})
		expectOK(t, r)
		md, _ := r.m()["metadata"].(map[string]any)
		if s(md["test"]) != "test2" {
			t.Fatalf("metadata = %v", r.m()["metadata"])
		}
	})

	t.Run("should prevent updating organization to empty slug", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/update", h, map[string]any{"organizationId": organizationID, "data": map[string]any{"slug": ""}})
		expectCode(t, r, 400, "")
	})

	t.Run("should prevent updating organization to empty name", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.post("/organization/update", h, map[string]any{"organizationId": organizationID, "data": map[string]any{"name": ""}})
		expectCode(t, r, 400, "")
	})

	t.Run("should allow activating organization and set session", func(t *testing.T) {
		r := e.post("/organization/set-active", headers, map[string]any{"organizationId": organizationID})
		expectOK(t, r)
		if s(r.m()["id"]) != organizationID {
			t.Fatalf("id = %v", r.m()["id"])
		}
		if got := s(e.session(headers)["activeOrganizationId"]); got != organizationID {
			t.Fatalf("activeOrganizationId = %q", got)
		}
	})

	t.Run("should allow activating organization by slug", func(t *testing.T) {
		h := e.signInTestUser()
		e.post("/organization/set-active", h, map[string]any{"organizationSlug": "test2"})
		if got := s(e.session(h)["activeOrganizationId"]); got != organization2ID {
			t.Fatalf("activeOrganizationId = %q, want %q", got, organization2ID)
		}
	})

	t.Run("should allow getting full org on server", func(t *testing.T) {
		r := e.mustAPI("getFullOrganization", headers, nil, nil)
		if n := len(orgP1Members(t, r)); n != 1 {
			t.Fatalf("members = %d", n)
		}
	})

	t.Run("should allow getting full org on server using slug", func(t *testing.T) {
		r := e.mustAPI("getFullOrganization", headers, nil, map[string]any{"organizationSlug": "test"})
		if n := len(orgP1Members(t, r)); n != 1 {
			t.Fatalf("members = %d", n)
		}
	})

	t.Run("invites user to organization with role", func(t *testing.T) {
		cases := []struct{ role, email, name string }{
			{"owner", "test2@test.com", "test2"},
			{"admin", "test3@test.com", "test3"},
			{"member", "test4@test.com", "test4"},
		}
		for _, c := range cases {
			t.Run(c.role, func(t *testing.T) {
				h := e.signInTestUser()
				invite := e.post("/organization/invite-member", h, map[string]any{"organizationId": organizationID, "email": c.email, "role": c.role})
				expectOK(t, invite)
				if s(invite.m()["email"]) != c.email || s(invite.m()["role"]) != c.role {
					t.Fatalf("invite = %v", invite.Data)
				}
				e.post("/sign-up/email", nil, map[string]any{"email": c.email, "password": "test123456", "name": c.name})
				h2 := e.signIn(c.email, "test123456")

				wrong := e.post("/organization/accept-invitation", h2, map[string]any{"invitationId": "123"})
				expectCode(t, wrong, 400, "")
				wrongPerson := e.post("/organization/accept-invitation", h, map[string]any{"invitationId": invite.m()["id"]})
				expectCode(t, wrongPerson, 403, "")
				acc := e.post("/organization/accept-invitation", h2, map[string]any{"invitationId": invite.m()["id"]})
				expectOK(t, acc)
				inv, _ := acc.m()["invitation"].(map[string]any)
				if s(inv["status"]) != "accepted" {
					t.Fatalf("accept = %v", acc.Data)
				}
				if got := s(e.session(h2)["activeOrganizationId"]); got != organizationID {
					t.Fatalf("activeOrganizationId = %q", got)
				}
			})
		}
	})

	t.Run("should create invitation with multiple roles", func(t *testing.T) {
		r := e.post("/organization/invite-member", headers, map[string]any{"organizationId": organizationID, "email": "test5@test.com", "role": []any{"admin", "member"}})
		expectOK(t, r)
		if s(r.m()["role"]) != "admin,member" {
			t.Fatalf("role = %v", r.m()["role"])
		}
	})

	t.Run("should not allow inviting a user twice regardless of email casing", func(t *testing.T) {
		rng := orgP1RandomID()
		email := rng + "@email.com"
		h := e.signInTestUser()
		invite := e.post("/organization/invite-member", h, map[string]any{"organizationId": organizationID, "email": email, "role": "member"})
		expectOK(t, invite)
		if _, err := time.Parse(time.RFC3339, s(invite.m()["createdAt"])); err != nil {
			t.Fatalf("createdAt = %v", invite.m()["createdAt"])
		}
		if s(invite.m()["email"]) != email {
			t.Fatalf("email = %v", invite.m()["email"])
		}
		for _, em := range []string{email, strings.ToUpper(email)} {
			r := e.post("/organization/invite-member", h, map[string]any{"organizationId": organizationID, "email": em, "role": "member"})
			if r.message() != ErrUserIsAlreadyInvitedToThisOrganization.Message {
				t.Fatalf("invite again (%s) = %d %q", em, r.Status, r.message())
			}
		}
		e.post("/sign-up/email", nil, map[string]any{"email": email, "password": rng, "name": rng})
		uh := e.signIn(email, rng)
		acc := e.post("/organization/accept-invitation", uh, map[string]any{"invitationId": invite.m()["id"]})
		expectOK(t, acc)
		if s(acc.m()["invitation"].(map[string]any)["status"]) != "accepted" {
			t.Fatalf("accept = %v", acc.Data)
		}
		for _, em := range []string{email, strings.ToUpper(email)} {
			r := e.post("/organization/invite-member", h, map[string]any{"organizationId": organizationID, "email": em, "role": "member"})
			if r.message() != ErrUserIsAlreadyAMemberOfThisOrganization.Message {
				t.Fatalf("invite member again (%s) = %d %q", em, r.Status, r.message())
			}
		}
	})

	t.Run("should allow accepting invitation when user signs up with different email casing", func(t *testing.T) {
		rng := orgP1RandomID()
		mixed := "Test.User." + rng + "@Example.COM"
		h := e.signInTestUser()
		org := e.post("/organization/create", h, map[string]any{"name": "test-org-" + rng, "slug": "test-org-" + rng})
		expectOK(t, org)
		invite := e.post("/organization/invite-member", h, map[string]any{"organizationId": org.m()["id"], "email": mixed, "role": "member"})
		expectOK(t, invite)
		if s(invite.m()["email"]) != strings.ToLower(mixed) {
			t.Fatalf("email = %v", invite.m()["email"])
		}
		e.post("/sign-up/email", nil, map[string]any{"email": strings.ToLower(mixed), "password": rng, "name": "Test User " + rng})
		uh := e.signIn(strings.ToLower(mixed), rng)
		list := e.get("/organization/list-user-invitations", uh, nil)
		expectOK(t, list)
		if len(list.list()) < 1 {
			t.Fatalf("invitations = %v", list.Data)
		}
		found := false
		for _, i := range list.list() {
			if s(i.(map[string]any)["id"]) == s(invite.m()["id"]) {
				found = true
			}
		}
		if !found {
			t.Fatalf("invitation not listed: %v", list.Data)
		}
		acc := e.post("/organization/accept-invitation", uh, map[string]any{"invitationId": invite.m()["id"]})
		expectOK(t, acc)
		if s(acc.m()["invitation"].(map[string]any)["status"]) != "accepted" {
			t.Fatalf("accept = %v", acc.Data)
		}
	})

	t.Run("should allow getting a member", func(t *testing.T) {
		h := e.signInTestUser()
		expectOK(t, e.post("/organization/set-active", h, map[string]any{"organizationId": organizationID}))
		r := e.get("/organization/get-active-member", h, nil)
		expectOK(t, r)
		if s(r.m()["role"]) != "owner" {
			t.Fatalf("member = %v", r.Data)
		}
	})

	fullOrg := func(t *testing.T, h http.Header) *result {
		t.Helper()
		r := e.get("/organization/get-full-organization", h, url.Values{"organizationId": {organizationID}})
		expectOK(t, r)
		return r
	}

	t.Run("should allow updating member", func(t *testing.T) {
		h := e.signInTestUser()
		org := fullOrg(t, h)
		m := orgP1FindRole(orgP1Members(t, org), "member")
		if m == nil {
			t.Fatal("Member not found")
		}
		r := e.post("/organization/update-member-role", h, map[string]any{"organizationId": org.m()["id"], "memberId": m["id"], "role": "admin"})
		expectOK(t, r)
		if s(r.m()["role"]) != "admin" {
			t.Fatalf("role = %v", r.Data)
		}
	})

	t.Run("should allow setting multiple roles", func(t *testing.T) {
		h := e.signInTestUser()
		org := fullOrg(t, h)
		m := orgP1FindRole(orgP1Members(t, org), "member")
		if m == nil {
			t.Fatal("Member not found")
		}
		r := e.post("/organization/update-member-role", h, map[string]any{"organizationId": org.m()["id"], "memberId": m["id"], "role": []any{"member", "admin"}})
		expectOK(t, r)
		if s(r.m()["role"]) != "member,admin" {
			t.Fatalf("role = %v", r.Data)
		}
	})

	t.Run("should allow setting multiple roles when you have multiple yourself", func(t *testing.T) {
		h := e.signInTestUser()
		userID := orgP1UserID(e, h)
		org := fullOrg(t, h)
		var active map[string]any
		for _, m := range orgP1Members(t, org) {
			if s(m["userId"]) == userID && s(m["role"]) == "owner" {
				active = m
			}
		}
		if active == nil {
			t.Fatal("Active member not found")
		}
		c1 := e.post("/organization/update-member-role", h, map[string]any{"organizationId": org.m()["id"], "memberId": active["id"], "role": []any{"owner", "admin"}})
		expectOK(t, c1)
		if s(c1.m()["role"]) != "owner,admin" {
			t.Fatalf("c1 role = %v", c1.Data)
		}
		c2 := e.post("/organization/update-member-role", h, map[string]any{"organizationId": org.m()["id"], "memberId": active["id"], "role": []any{"owner"}})
		expectOK(t, c2)
		if s(c2.m()["role"]) != "owner" {
			t.Fatalf("c2 role = %v", c2.Data)
		}
		e.post("/organization/update-member-role", h, map[string]any{"organizationId": org.m()["id"], "memberId": active["id"], "role": []any{"admin"}})
	})

	const adminEmail, adminPassword = "test3@test.com", "test123456"

	t.Run("should not allow inviting member with a creator role unless they are creator", func(t *testing.T) {
		h := e.signIn(adminEmail, adminPassword)
		r := e.post("/organization/invite-member", h, map[string]any{"organizationId": organizationID, "email": adminEmail, "role": "owner"})
		if r.message() != ErrYouAreNotAllowedToInviteUserWithThisRole.Message {
			t.Fatalf("invite = %d %q", r.Status, r.message())
		}
	})

	t.Run("should allow multi-role owner to invite with owner role", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.post("/organization/create", h, map[string]any{"name": "multi-role-test-org", "slug": "multi-role-test-org"})
		expectOK(t, org)
		orgID := s(org.m()["id"])
		memberID := orgP1Members(t, org)[0]["id"]
		upd := e.mustAPI("updateMemberRole", h, map[string]any{"organizationId": orgID, "role": []any{"owner", "admin"}, "memberId": memberID}, nil)
		if s(upd.m()["role"]) != "owner,admin" {
			t.Fatalf("role = %v", upd.Data)
		}
		inv := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": "multi-role-invite-test@test.com", "role": "owner"})
		expectOK(t, inv)
		if s(inv.m()["role"]) != "owner" {
			t.Fatalf("role = %v", inv.Data)
		}
	})

	t.Run("should allow leaving organization", func(t *testing.T) {
		su := e.post("/sign-up/email", nil, map[string]any{"email": "leave@org.com", "name": "leaving member", "password": "password"})
		expectOK(t, su)
		h := cookieHeaders(su.Headers)
		userID := s(su.m()["user"].(map[string]any)["id"])
		e.mustAPI("addMember", nil, map[string]any{"organizationId": organizationID, "userId": userID, "role": "admin"}, nil)
		r := e.post("/organization/leave", h, map[string]any{"organizationId": organizationID})
		expectOK(t, r)
		if s(r.m()["userId"]) != userID {
			t.Fatalf("leave = %v", r.Data)
		}
	})

	t.Run("shouldn't allow updating owner role if you're not owner", func(t *testing.T) {
		h := e.signInTestUser()
		org := fullOrg(t, h)
		owner := orgP1FindRole(orgP1Members(t, org), "owner")
		if owner == nil {
			t.Fatal("owner not found")
		}
		ah := e.signIn(adminEmail, adminPassword)
		r := e.post("/organization/update-member-role", ah, map[string]any{"organizationId": organizationID, "role": "admin", "memberId": owner["id"]})
		expectCode(t, r, 403, "")
	})

	t.Run("should allow removing member from organization", func(t *testing.T) {
		h := e.signInTestUser()
		if n := len(orgP1Members(t, fullOrg(t, h))); n != 5 {
			t.Fatalf("members before = %d", n)
		}
		e.post("/organization/remove-member", h, map[string]any{"organizationId": organizationID, "memberIdOrEmail": adminEmail})
		if n := len(orgP1Members(t, fullOrg(t, h))); n != 4 {
			t.Fatalf("members after = %d", n)
		}
	})

	t.Run("shouldn't allow removing last owner from organization", func(t *testing.T) {
		h := e.signInTestUser()
		org := fullOrg(t, h)
		owner := orgP1FindRole(orgP1Members(t, org), "owner")
		if owner == nil {
			t.Fatal("owner not found")
		}
		r := e.post("/organization/remove-member", h, map[string]any{"organizationId": org.m()["id"], "memberIdOrEmail": owner["id"]})
		expectCode(t, r, 400, "")
		e.post("/organization/update-member-role", h, map[string]any{"organizationId": organizationID, "role": []any{"owner", "admin"}, "memberId": owner["id"]})
		r = e.post("/organization/remove-member", h, map[string]any{"organizationId": org.m()["id"], "memberIdOrEmail": owner["id"]})
		expectCode(t, r, 400, "")
	})

	t.Run("should validate permissions", func(t *testing.T) {
		e.post("/organization/set-active", headers, map[string]any{"organizationId": organizationID})
		r := e.post("/organization/has-permission", headers, map[string]any{"permissions": map[string]any{"member": []any{"update"}}})
		expectOK(t, r)
		if r.m()["success"] != true {
			t.Fatalf("hasPermission = %v", r.Data)
		}
		r = e.post("/organization/has-permission", headers, map[string]any{"permissions": map[string]any{"member": []any{"update"}, "invitation": []any{"create"}}})
		expectOK(t, r)
		if r.m()["success"] != true {
			t.Fatalf("hasMultiplePermissions = %v", r.Data)
		}
	})

	t.Run("should return BAD_REQUEST when non-member tries to delete organization", func(t *testing.T) {
		org := e.post("/organization/create", headers, map[string]any{"name": "test-delete-org", "slug": "test-delete-org"})
		expectOK(t, org)
		e.post("/sign-up/email", nil, map[string]any{"email": "nonmember@test.com", "password": "password123", "name": "Non Member User"})
		nh := e.signIn("nonmember@test.com", "password123")
		r := e.post("/organization/delete", nh, map[string]any{"organizationId": org.m()["id"]})
		expectCode(t, r, 400, "")
		if r.message() != ErrUserIsNotAMemberOfTheOrganization.Message {
			t.Fatalf("message = %q", r.message())
		}
	})

	t.Run("should allow deleting organization", func(t *testing.T) {
		ah := e.signIn(adminEmail, adminPassword)
		e.post("/organization/delete", ah, map[string]any{"organizationId": organizationID})
		r := e.get("/organization/get-full-organization", ah, url.Values{"organizationId": {organizationID}})
		expectCode(t, r, 403, "")
	})

	t.Run("should have server side methods", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf(auth.api.X).toBeFunction()")
	})

	t.Run("should add member on the server directly", func(t *testing.T) {
		userID := orgP1SignUpAPI(e, "new-member@email.com", "password", "new member")
		org := e.mustAPI("createOrganization", headers, map[string]any{"name": "test2", "slug": "test3"}, nil)
		m := e.mustAPI("addMember", nil, map[string]any{"organizationId": org.m()["id"], "userId": userID, "role": "admin"}, nil)
		if s(m.m()["role"]) != "admin" {
			t.Fatalf("member = %v", m.Data)
		}
	})

	t.Run("should add member on the server with multiple roles", func(t *testing.T) {
		userID := orgP1SignUpAPI(e, "new-member-mr@email.com", "password", "new member mr")
		org := e.mustAPI("createOrganization", headers, map[string]any{"name": "test2", "slug": "test4"}, nil)
		m := e.mustAPI("addMember", nil, map[string]any{"organizationId": org.m()["id"], "userId": userID, "role": []any{"admin", "member"}}, nil)
		if s(m.m()["role"]) != "admin,member" {
			t.Fatalf("member = %v", m.Data)
		}
	})

	t.Run("should respect membershipLimit when adding members to organization", func(t *testing.T) {
		org := e.mustAPI("createOrganization", headers, map[string]any{"name": "test-5-membership-limit", "slug": "test-5-membership-limit"}, nil)
		orgID := s(org.m()["id"])
		for _, u := range []string{"user1@emial.com", "user2@email.com", "user3@email.com", "user4@email.com"} {
			id := orgP1SignUpAPI(e, u, "password", u)
			e.mustAPI("addMember", nil, map[string]any{"organizationId": orgID, "userId": id, "role": "admin"}, nil)
		}
		overID := orgP1SignUpAPI(e, "shouldthrowerror@email.com", "password", "name")
		// Upstream only asserts inside .catch: the sixth member is still within the limit of 6.
		if r := e.api("addMember", nil, map[string]any{"organizationId": orgID, "userId": overID, "role": "admin"}, nil); r.Err != nil {
			if r.code() != ErrOrganizationMembershipLimitReached.Code {
				t.Fatalf("addMember = %d %s", r.Status, r.code())
			}
		}
		invite := e.post("/organization/invite-member", headers, map[string]any{"organizationId": orgID, "email": "shouldthrowerror2@email.com", "role": "member"})
		expectOK(t, invite)
		su := e.post("/sign-up/email", nil, map[string]any{"email": "shouldthrowerror2@email.com", "password": "password", "name": "name"})
		expectOK(t, su)
		h2 := cookieHeaders(su.Headers)
		acc := e.post("/organization/accept-invitation", h2, map[string]any{"invitationId": invite.m()["id"]})
		if acc.message() != ErrOrganizationMembershipLimitReached.Message {
			t.Fatalf("accept = %d %q", acc.Status, acc.message())
		}
		full := e.get("/organization/get-full-organization", headers, url.Values{"organizationId": {orgID}})
		expectOK(t, full)
		if n := len(orgP1Members(t, full)); n != 6 {
			t.Fatalf("members = %d", n)
		}
	})

	t.Run("should respect membershipLimit function when adding members to organization", func(t *testing.T) {
		e2 := newEnv(t, Options{
			MembershipLimitFunc: func(ctx *Ctx, user *betterauth.User, organization Record) (int, error) {
				if strings.Contains(s(organization["name"]), "limit") {
					return 2, nil
				}
				return 100, nil
			},
		}, envConfig{mutate: func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{ModelName: "users"}}
		}})
		h2 := e2.signInTestUser()
		org := e2.mustAPI("createOrganization", h2, map[string]any{"name": "test-membership-limit-func", "slug": "test-membership-limit-func"}, nil)
		orgID := s(org.m()["id"])
		u1 := orgP1SignUpAPI(e2, "user1@email.com", "password", "user1")
		u2 := orgP1SignUpAPI(e2, "user2@email.com", "password", "user2")
		e2.mustAPI("addMember", nil, map[string]any{"organizationId": orgID, "userId": u1, "role": "admin"}, nil)
		r := e2.api("addMember", nil, map[string]any{"organizationId": orgID, "userId": u2, "role": "admin"}, nil)
		if r.Err == nil || r.message() != ErrOrganizationMembershipLimitReached.Message {
			t.Fatalf("addMember = %d %q", r.Status, r.message())
		}
		full := e2.get("/organization/get-full-organization", h2, url.Values{"organizationId": {orgID}})
		expectOK(t, full)
		if n := len(orgP1Members(t, full)); n != 2 {
			t.Fatalf("members = %d", n)
		}
	})

	t.Run("should allow listing invitations for an org", func(t *testing.T) {
		r := e.get("/organization/list-invitations", headers, url.Values{"organizationId": {organizationID}})
		expectOK(t, r)
		if len(r.list()) != 5 {
			t.Fatalf("invitations = %d", len(r.list()))
		}
	})

	t.Run("should allow listing invitations for a user using authClient", func(t *testing.T) {
		rng, rng2 := orgP1RandomID(), orgP1RandomID()
		email, adminEm := rng+"@email.com", rng2+"@email.com"
		orgP1SignUpAPI(e, email, rng, rng)
		orgP1SignUpAPI(e, adminEm, rng2, rng2)
		uh := e.signIn(email, rng)
		ah := e.signIn(adminEm, rng2)
		orgRng := orgP1RandomID()
		org := e.mustAPI("createOrganization", ah, map[string]any{"name": orgRng, "slug": orgRng}, nil)
		inv := e.post("/organization/invite-member", ah, map[string]any{"organizationId": org.m()["id"], "email": email, "role": "member"})
		expectOK(t, inv)
		list := e.get("/organization/list-user-invitations", uh, nil)
		expectOK(t, list)
		if len(list.list()) != 1 {
			t.Fatalf("invitations = %v", list.Data)
		}
		first := list.list()[0].(map[string]any)
		if s(first["id"]) != s(inv.m()["id"]) || s(first["organizationName"]) != orgRng {
			t.Fatalf("invitation = %v", first)
		}
	})

	t.Run("should allow listing invitations for a user using server", func(t *testing.T) {
		org := e.get("/organization/list-invitations", headers, nil)
		expectOK(t, org)
		if len(org.list()) == 0 {
			t.Fatal("No email found")
		}
		email := s(org.list()[0].(map[string]any)["email"])
		if email == "" {
			t.Fatal("No email found")
		}
		want := 0
		for _, x := range org.list() {
			if s(x.(map[string]any)["email"]) == email {
				want++
			}
		}
		for _, em := range []string{email, strings.ToUpper(email)} {
			r := e.mustAPI("listUserInvitations", nil, nil, map[string]any{"email": em})
			if len(r.list()) != want {
				t.Fatalf("listUserInvitations(%s) = %d, want %d", em, len(r.list()), want)
			}
		}
	})
}

func TestOrgP1InvitationExpirationAndFiltering(t *testing.T) {
	e := newEnv(t, Options{InvitationExpiresIn: time.Second}, envConfig{verifyUsers: true})

	setup := func(t *testing.T, prefix string) (rng string, adminH, invitedH http.Header, invitedEmail string) {
		t.Helper()
		rng = orgP1RandomID()
		adminEmail := prefix + "admin-" + rng + "@email.com"
		invitedEmail = prefix + "invited-" + rng + "@email.com"
		orgP1SignUpAPI(e, adminEmail, rng, "admin-"+rng)
		orgP1SignUpAPI(e, invitedEmail, rng, "invited-"+rng)
		return rng, e.signIn(adminEmail, rng), e.signIn(invitedEmail, rng), invitedEmail
	}

	t.Run("should allow rejecting expired invitations", func(t *testing.T) {
		rng, ah, ih, invited := setup(t, "")
		org := e.mustAPI("createOrganization", ah, map[string]any{"name": rng, "slug": rng}, nil)
		inv := e.post("/organization/invite-member", ah, map[string]any{"organizationId": org.m()["id"], "email": invited, "role": "member"})
		expectOK(t, inv)
		time.Sleep(1100 * time.Millisecond)
		r := e.post("/organization/reject-invitation", ih, map[string]any{"invitationId": inv.m()["id"]})
		expectOK(t, r)
		i, _ := r.m()["invitation"].(map[string]any)
		if s(i["status"]) != "rejected" {
			t.Fatalf("reject = %v", r.Data)
		}
	})

	t.Run("should only list pending invitations for a user", func(t *testing.T) {
		rng, ah, ih, invited := setup(t, "2")
		org1 := e.mustAPI("createOrganization", ah, map[string]any{"name": rng + "-org1", "slug": rng + "-org1"}, nil)
		org2 := e.mustAPI("createOrganization", ah, map[string]any{"name": rng + "-org2", "slug": rng + "-org2"}, nil)
		inv1 := e.post("/organization/invite-member", ah, map[string]any{"organizationId": org1.m()["id"], "email": invited, "role": "member"})
		expectOK(t, inv1)
		inv2 := e.post("/organization/invite-member", ah, map[string]any{"organizationId": org2.m()["id"], "email": invited, "role": "member"})
		expectOK(t, inv2)
		e.post("/organization/accept-invitation", ih, map[string]any{"invitationId": inv1.m()["id"]})
		list := e.get("/organization/list-user-invitations", ih, nil)
		expectOK(t, list)
		if len(list.list()) != 1 {
			t.Fatalf("invitations = %v", list.Data)
		}
		first := list.list()[0].(map[string]any)
		if s(first["id"]) != s(inv2.m()["id"]) || s(first["status"]) != "pending" {
			t.Fatalf("invitation = %v", first)
		}
	})

	t.Run("should not list rejected invitations", func(t *testing.T) {
		rng, ah, ih, invited := setup(t, "3")
		org := e.mustAPI("createOrganization", ah, map[string]any{"name": rng + "-org", "slug": rng + "-org"}, nil)
		inv := e.post("/organization/invite-member", ah, map[string]any{"organizationId": org.m()["id"], "email": invited, "role": "member"})
		expectOK(t, inv)
		e.post("/organization/reject-invitation", ih, map[string]any{"invitationId": inv.m()["id"]})
		list := e.get("/organization/list-user-invitations", ih, nil)
		expectOK(t, list)
		if len(list.list()) != 0 {
			t.Fatalf("invitations = %v", list.Data)
		}
	})
}
