package organization

import (
	"net/url"
	"testing"

	"github.com/nimi-io/better-auth-go/plugins/access"
)

func TestSmokeMainFlow(t *testing.T) {
	ac := access.New(DefaultStatements)
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}, AC: ac, DynamicAccessControl: &DynamicAccessControlOptions{Enabled: true}}, envConfig{verifyUsers: true})
	h := e.signInTestUser()
	org := e.createOrg(h, "Acme", "acme", map[string]any{"metadata": map[string]any{"a": "b"}})
	if s(org["slug"]) != "acme" || len(org["members"].([]any)) != 1 {
		t.Fatalf("org = %v", org)
	}
	orgID := s(org["id"])
	r := e.get("/organization/get-full-organization", h, nil)
	expectOK(t, r)
	if s(r.m()["id"]) != orgID || len(r.m()["teams"].([]any)) != 1 {
		t.Fatalf("full = %v", r.Data)
	}
	h2 := e.signUp("b@b.com", "password1234", "B")
	inv := e.post("/organization/invite-member", h, map[string]any{"email": "b@b.com", "role": "admin"})
	expectOK(t, inv)
	acc := e.post("/organization/accept-invitation", h2, map[string]any{"invitationId": inv.m()["id"]})
	expectOK(t, acc)
	lm := e.get("/organization/list-members", h, url.Values{"limit": {"10"}})
	expectOK(t, lm)
	if lm.m()["total"].(float64) != 2 {
		t.Fatalf("members = %v", lm.Data)
	}
	team := e.post("/organization/create-team", h, map[string]any{"name": "T2"})
	expectOK(t, team)
	r = e.post("/organization/add-team-member", h, map[string]any{"teamId": team.m()["id"], "userId": acc.m()["member"].(map[string]any)["userId"]})
	expectOK(t, r)
	r = e.post("/organization/has-permission", h2, map[string]any{"permissions": map[string]any{"member": []any{"update"}}})
	expectOK(t, r)
	if r.m()["success"] != true {
		t.Fatalf("perm = %v", r.Data)
	}
	r = e.post("/organization/create-role", h, map[string]any{"role": "Sales", "permission": map[string]any{"member": []any{"update"}}})
	expectOK(t, r)
	r = e.get("/organization/list-roles", h, nil)
	expectOK(t, r)
	if len(r.list()) != 1 {
		t.Fatalf("roles = %v", r.Data)
	}
	r = e.post("/organization/update-member-role", h, map[string]any{"memberId": acc.m()["member"].(map[string]any)["id"], "role": "sales"})
	expectOK(t, r)
	r = e.post("/organization/delete", h, map[string]any{"organizationId": orgID})
	expectOK(t, r)
	r = e.get("/organization/list", h, nil)
	if len(r.list()) != 0 {
		t.Fatalf("list = %v", r.Data)
	}
}
