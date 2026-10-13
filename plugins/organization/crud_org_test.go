package organization

// Port of upstream routes/crud-org.test.ts.

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func corgSetActive(t *testing.T, e *testEnv, h http.Header, orgID any) {
	t.Helper()
	expectOK(t, e.post("/organization/set-active", h, map[string]any{"organizationId": orgID}))
}

func TestCrudOrgGetFullOrganization(t *testing.T) {
	e := newEnv(t, Options{})
	headers := e.signInTestUser()
	org := e.createOrg(headers, "test", "test", map[string]any{"metadata": map[string]any{"test": "test"}})
	secondOrg := e.createOrg(headers, "test-second", "test-second", map[string]any{"metadata": map[string]any{"test": "second-org"}})
	orgID, secondID := s(org["id"]), s(secondOrg["id"])

	t.Run("should get organization by organizationId", func(t *testing.T) {
		h := e.signInTestUser()
		corgSetActive(t, e, h, secondID)
		r := e.get("/organization/get-full-organization", h, url.Values{"organizationId": {orgID}})
		expectOK(t, r)
		if s(r.m()["name"]) != "test" {
			t.Fatalf("name = %v", r.Data)
		}
	})

	t.Run("should get organization by organizationSlug", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.get("/organization/get-full-organization", h, url.Values{"organizationSlug": {"test"}})
		expectOK(t, r)
		if s(r.m()["name"]) != "test" {
			t.Fatalf("name = %v", r.Data)
		}
	})

	t.Run("should return null when no active organization and no query params", func(t *testing.T) {
		corgSetActive(t, e, headers, nil)
		r := e.get("/organization/get-full-organization", headers, nil)
		expectOK(t, r)
		if r.Data != nil {
			t.Fatalf("expected null, got %v", r.Data)
		}
	})

	t.Run("should throw FORBIDDEN when user is not a member of the organization", func(t *testing.T) {
		nh := e.signUp("test3@test.com", "password", "test3")
		r := e.get("/organization/get-full-organization", nh, url.Values{"organizationId": {orgID}})
		expectCode(t, r, 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	})

	t.Run("should throw BAD_REQUEST when organization doesn't exist", func(t *testing.T) {
		r := e.get("/organization/get-full-organization", headers, url.Values{"organizationId": {"non-existent-org-id"}})
		expectCode(t, r, 400, "ORGANIZATION_NOT_FOUND")
	})

	t.Run("should include invitations in the response", func(t *testing.T) {
		corgSetActive(t, e, headers, orgID)
		expectOK(t, e.post("/organization/invite-member", headers, map[string]any{"email": "invited@test.com", "role": "member"}))
		r := e.get("/organization/get-full-organization", headers, nil)
		expectOK(t, r)
		invs, ok := r.m()["invitations"].([]any)
		if !ok {
			t.Fatalf("invitations = %v", r.m()["invitations"])
		}
		var found map[string]any
		for _, i := range invs {
			if m := i.(map[string]any); s(m["email"]) == "invited@test.com" {
				found = m
			}
		}
		if found == nil || s(found["role"]) != "member" {
			t.Fatalf("invitation = %v", found)
		}
	})

	t.Run("should prioritize organizationSlug over organizationId when both are provided", func(t *testing.T) {
		r := e.get("/organization/get-full-organization", headers, url.Values{"organizationId": {orgID}, "organizationSlug": {s(secondOrg["slug"])}})
		expectOK(t, r)
		if s(r.m()["name"]) != s(secondOrg["name"]) {
			t.Fatalf("name = %v", r.Data)
		}
	})

	t.Run("should allow listing members with membersLimit", func(t *testing.T) {
		h := e.signInTestUser()
		corgSetActive(t, e, h, orgID)
		nu := e.mustAPI("signUpEmail", nil, map[string]any{"email": "test2@test.com", "password": "password", "name": "test2"}, nil)
		e.mustAPI("addMember", nil, map[string]any{"userId": nu.m()["user"].(map[string]any)["id"], "role": "member", "organizationId": orgID}, nil)
		r := e.get("/organization/get-full-organization", h, nil)
		expectOK(t, r)
		if n := len(r.m()["members"].([]any)); n != 2 {
			t.Fatalf("members = %d", n)
		}
		r = e.get("/organization/get-full-organization", h, url.Values{"membersLimit": {"1"}})
		expectOK(t, r)
		if n := len(r.m()["members"].([]any)); n != 1 {
			t.Fatalf("limited members = %d", n)
		}
	})

	t.Run("should use default membershipLimit when no membersLimit is specified", func(t *testing.T) {
		corgSetActive(t, e, headers, orgID)
		for i := 3; i <= 5; i++ {
			nu := e.mustAPI("signUpEmail", nil, map[string]any{"email": fmt.Sprintf("test-%d@test.com", i), "password": "password", "name": fmt.Sprintf("test%d", i)}, nil)
			e.mustAPI("addMember", nil, map[string]any{"userId": nu.m()["user"].(map[string]any)["id"], "role": "member", "organizationId": orgID}, nil)
		}
		r := e.get("/organization/get-full-organization", headers, nil)
		expectOK(t, r)
		n := len(r.m()["members"].([]any))
		if n <= 3 || n > 6 {
			t.Fatalf("members = %d", n)
		}
	})
}

func TestCrudOrgGetOrganization(t *testing.T) {
	e := newEnv(t, Options{})
	headers := e.signInTestUser()
	org := e.createOrg(headers, "meta-org", "meta-org", map[string]any{"metadata": map[string]any{"plan": "pro"}})
	secondOrg := e.createOrg(headers, "meta-org-second", "meta-org-second", map[string]any{"metadata": map[string]any{"plan": "free"}})
	orgID, secondID := s(org["id"]), s(secondOrg["id"])

	noProps := func(t *testing.T, m map[string]any, keys ...string) {
		t.Helper()
		for _, k := range keys {
			if _, ok := m[k]; ok {
				t.Fatalf("unexpected property %q in %v", k, m)
			}
		}
	}

	t.Run("should get organization metadata by organizationId", func(t *testing.T) {
		h := e.signInTestUser()
		corgSetActive(t, e, h, secondID)
		r := e.get("/organization/get-organization", h, url.Values{"organizationId": {orgID}})
		expectOK(t, r)
		m := r.m()
		if s(m["id"]) != orgID || s(m["name"]) != "meta-org" || s(m["slug"]) != "meta-org" {
			t.Fatalf("org = %v", m)
		}
		noProps(t, m, "members", "invitations", "teams")
	})

	t.Run("should get organization metadata by organizationSlug", func(t *testing.T) {
		h := e.signInTestUser()
		r := e.get("/organization/get-organization", h, url.Values{"organizationSlug": {"meta-org"}})
		expectOK(t, r)
		m := r.m()
		if s(m["name"]) != "meta-org" || s(m["slug"]) != "meta-org" {
			t.Fatalf("org = %v", m)
		}
		noProps(t, m, "members", "invitations")
	})

	t.Run("should fall back to the active organization", func(t *testing.T) {
		h := e.signInTestUser()
		corgSetActive(t, e, h, secondID)
		r := e.get("/organization/get-organization", h, nil)
		expectOK(t, r)
		m := r.m()
		if s(m["id"]) != secondID || s(m["name"]) != "meta-org-second" {
			t.Fatalf("org = %v", m)
		}
		noProps(t, m, "members")
	})

	t.Run("should return null when no active organization and no query params", func(t *testing.T) {
		corgSetActive(t, e, headers, nil)
		r := e.get("/organization/get-organization", headers, nil)
		expectOK(t, r)
		if r.Data != nil {
			t.Fatalf("expected null, got %v", r.Data)
		}
	})

	t.Run("should throw FORBIDDEN when user is not a member of the organization", func(t *testing.T) {
		nh := e.signUp("get-org-outsider@test.com", "password", "outsider")
		r := e.get("/organization/get-organization", nh, url.Values{"organizationId": {orgID}})
		expectCode(t, r, 403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
	})

	t.Run("should throw BAD_REQUEST when organization doesn't exist", func(t *testing.T) {
		r := e.get("/organization/get-organization", headers, url.Values{"organizationId": {"non-existent-org-id"}})
		expectCode(t, r, 400, "ORGANIZATION_NOT_FOUND")
	})

	t.Run("should not include members or invitations unlike getFullOrganization", func(t *testing.T) {
		h := e.signInTestUser()
		corgSetActive(t, e, h, orgID)
		expectOK(t, e.post("/organization/invite-member", h, map[string]any{"email": "get-org-invited@test.com", "role": "member"}))
		meta := e.get("/organization/get-organization", h, nil)
		expectOK(t, meta)
		full := e.get("/organization/get-full-organization", h, nil)
		expectOK(t, full)
		noProps(t, meta.m(), "members", "invitations")
		if _, ok := full.m()["members"].([]any); !ok {
			t.Fatalf("full members = %v", full.m()["members"])
		}
		if _, ok := full.m()["invitations"].([]any); !ok {
			t.Fatalf("full invitations = %v", full.m()["invitations"])
		}
		if s(meta.m()["id"]) != s(full.m()["id"]) || s(meta.m()["name"]) != s(full.m()["name"]) {
			t.Fatalf("meta = %v full = %v", meta.m(), full.m())
		}
	})
}

func TestCrudOrgOrganizationHooks(t *testing.T) {
	t.Run("should apply beforeCreateOrganization hook", func(t *testing.T) {
		called := false
		e := newEnv(t, Options{OrganizationHooks: &OrganizationHooks{
			BeforeCreateOrganization: func(ctx *Ctx, d HookData) (map[string]any, error) {
				called = true
				out := map[string]any{}
				for k, v := range d.Organization {
					out[k] = v
				}
				out["metadata"] = map[string]any{"hookCalled": true}
				out["name"] = "changed-name"
				return out, nil
			},
		}})
		h := e.signInTestUser()
		res := e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil).m()
		if !called {
			t.Fatal("hook not called")
		}
		if s(res["name"]) != "changed-name" {
			t.Fatalf("name = %v", res["name"])
		}
		if !reflect.DeepEqual(res["metadata"], map[string]any{"hookCalled": true}) {
			t.Fatalf("metadata = %#v", res["metadata"])
		}
	})

	t.Run("should apply afterCreateOrganization hook", func(t *testing.T) {
		called := false
		e := newEnv(t, Options{OrganizationHooks: &OrganizationHooks{
			AfterCreateOrganization: func(ctx *Ctx, d HookData) error { called = true; return nil },
		}})
		h := e.signInTestUser()
		e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil)
		if !called {
			t.Fatal("hook not called")
		}
	})

	t.Run("should apply beforeAddMember hook", func(t *testing.T) {
		called := false
		e := newEnv(t, Options{OrganizationHooks: &OrganizationHooks{
			BeforeAddMember: func(ctx *Ctx, d HookData) (map[string]any, error) {
				called = true
				return map[string]any{"role": "changed-role"}, nil
			},
		}})
		h := e.signInTestUser()
		e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil)
		if !called {
			t.Fatal("hook not called")
		}
		m := e.mustAPI("getActiveMember", h, nil, nil).m()
		if s(m["role"]) != "changed-role" {
			t.Fatalf("role = %v", m["role"])
		}
	})

	t.Run("should apply afterAddMember hook", func(t *testing.T) {
		called := false
		e := newEnv(t, Options{OrganizationHooks: &OrganizationHooks{
			AfterAddMember: func(ctx *Ctx, d HookData) error { called = true; return nil },
		}})
		h := e.signInTestUser()
		e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil)
		if !called {
			t.Fatal("hook not called")
		}
	})

	t.Run("should apply beforeCreateTeam hook", func(t *testing.T) {
		called := false
		e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}, OrganizationHooks: &OrganizationHooks{
			BeforeCreateTeam: func(ctx *Ctx, d HookData) (map[string]any, error) {
				called = true
				return map[string]any{"name": "changed-name"}, nil
			},
		}})
		h := e.signInTestUser()
		res := e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil).m()
		if !called {
			t.Fatal("hook not called")
		}
		teams := e.mustAPI("listOrganizationTeams", h, nil, map[string]any{"organizationId": res["id"]}).list()
		if len(teams) == 0 || s(teams[0].(map[string]any)["name"]) != "changed-name" {
			t.Fatalf("teams = %v", teams)
		}
	})

	t.Run("should apply afterCreateTeam hook", func(t *testing.T) {
		called := false
		e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}, OrganizationHooks: &OrganizationHooks{
			AfterCreateTeam: func(ctx *Ctx, d HookData) error { called = true; return nil },
		}})
		h := e.signInTestUser()
		e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil)
		if !called {
			t.Fatal("hook not called")
		}
	})

	t.Run("should allow passing id through `beforeCreateTeam`", func(t *testing.T) {
		const customTeamID = "custom-team-id"
		e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}, OrganizationHooks: &OrganizationHooks{
			BeforeCreateTeam: func(ctx *Ctx, d HookData) (map[string]any, error) {
				return map[string]any{"id": customTeamID}, nil
			},
		}})
		h := e.signInTestUser()
		res := e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil).m()
		teams := e.mustAPI("listOrganizationTeams", h, nil, map[string]any{"organizationId": res["id"]}).list()
		if len(teams) == 0 || s(teams[0].(map[string]any)["id"]) != customTeamID {
			t.Fatalf("teams = %v", teams)
		}
	})

	t.Run("should allow passing id through `beforeCreateInvitation`", func(t *testing.T) {
		const customInvitationID = "custom-invitation-id"
		e := newEnv(t, Options{OrganizationHooks: &OrganizationHooks{
			BeforeCreateInvitation: func(ctx *Ctx, d HookData) (map[string]any, error) {
				return map[string]any{"id": customInvitationID}, nil
			},
		}})
		h := e.signInTestUser()
		org := e.mustAPI("createOrganization", h, map[string]any{"name": "test", "slug": "test"}, nil).m()
		inv := e.mustAPI("createInvitation", h, map[string]any{"email": "invited@test.com", "role": "member", "organizationId": org["id"]}, nil).m()
		if s(inv["id"]) != customInvitationID {
			t.Fatalf("id = %v", inv["id"])
		}
	})

	t.Run("should allow internal organization creation when disabled for users", func(t *testing.T) {
		f := false
		e := newEnv(t, Options{AllowUserToCreateOrganization: &f})
		nu := e.mustAPI("signUpEmail", nil, map[string]any{"email": "internal@test.com", "password": "password", "name": "Internal User"}, nil)
		org := e.mustAPI("createOrganization", nil, map[string]any{"name": "Internal Org", "slug": "internal-org", "userId": nu.m()["user"].(map[string]any)["id"]}, nil).m()
		if org == nil || s(org["name"]) != "Internal Org" {
			t.Fatalf("org = %v", org)
		}
	})
}

func TestCrudOrgUpdateOrganization(t *testing.T) {
	e := newEnv(t, Options{})

	t.Run("should clear the logo when passing null", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.mustAPI("createOrganization", h, map[string]any{"name": "Logo Org", "slug": "logo-org", "logo": "https://example.com/logo.png"}, nil).m()
		if s(org["logo"]) != "https://example.com/logo.png" {
			t.Fatalf("logo = %v", org["logo"])
		}
		up := e.mustAPI("updateOrganization", h, map[string]any{"organizationId": org["id"], "data": map[string]any{"logo": nil}}, nil).m()
		if up["logo"] != nil {
			t.Fatalf("logo = %v", up["logo"])
		}
	})

	t.Run("should accept a null logo on create", func(t *testing.T) {
		h := e.signInTestUser()
		org := e.mustAPI("createOrganization", h, map[string]any{"name": "Null Logo Org", "slug": "null-logo-org", "logo": nil}, nil).m()
		if org["logo"] != nil {
			t.Fatalf("logo = %v", org["logo"])
		}
	})
}
