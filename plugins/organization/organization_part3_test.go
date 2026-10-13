package organization

// Port of upstream organization.test.ts describe("Additional Fields") (lines 2446-3563),
// including the nested describe("active organization hook refresh").

import (
	"net/http"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// orgP3Fields builds the required / optional / hidden (input: false) string fields used by
// every model in the upstream orgOptions.schema.
func orgP3Fields(prefix string) []db.Field {
	return []db.Field{
		{Name: prefix + "RequiredField", Type: db.TypeString},
		{Name: prefix + "OptionalField", Type: db.TypeString, Required: db.False},
		{Name: prefix + "HiddenField", Type: db.TypeString, Required: db.False, Input: db.False},
	}
}

func orgP3Options() Options {
	limit := 3
	return Options{
		Teams: &TeamsOptions{Enabled: true},
		Schema: &SchemaOptions{
			Organization: db.ModelOptions{AdditionalFields: orgP3Fields("some")},
			Member:       db.ModelOptions{AdditionalFields: orgP3Fields("member")},
			Team:         db.ModelOptions{AdditionalFields: orgP3Fields("team")},
			Invitation:   db.ModelOptions{AdditionalFields: orgP3Fields("invitation")},
		},
		InvitationLimit: &limit,
	}
}

// orgP3Absent reports whether key is null or absent in m (sqlite null == Go memory absent).
func orgP3Absent(m map[string]any, key string) bool {
	v, ok := m[key]
	return !ok || v == nil
}

func orgP3Row(rows []adapter.Record, id string) adapter.Record {
	for _, r := range rows {
		if s(r["id"]) == id {
			return r
		}
	}
	return nil
}

func orgP3Map(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func TestOrgP3AdditionalFields(t *testing.T) {
	e := newEnv(t, orgP3Options(), envConfig{
		verifyUsers: true,
		mutate: func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{ModelName: "users"}}
		},
	})
	headers := e.signInTestUser()

	var org map[string]any
	orgID := func(t *testing.T) string {
		t.Helper()
		if org == nil {
			t.Fatal("organization not created")
		}
		return s(org["id"])
	}

	t.Run("Expect team endpoints to still be defined", func(t *testing.T) {
		// Client-side the createTeam action must exist; server-side the endpoint is registered.
		r := e.post("/organization/create-team", nil, map[string]any{"name": "x"})
		if r.Status == http.StatusNotFound {
			t.Fatalf("create-team endpoint not defined: %d %v", r.Status, r.Data)
		}
	})

	t.Run("Should infer the organization schema", func(t *testing.T) {
		t.Skip("TS-only: client type inference (expectTypeOf)")
	})

	t.Run("create organization", func(t *testing.T) {
		r := e.mustAPI("createOrganization", headers, map[string]any{
			"name": "test", "slug": "test",
			"someRequiredField": "hey", "someOptionalField": "hey",
		}, nil)
		org = r.m()
		if org == nil {
			t.Fatal("Organization is null")
		}
		if org["someRequiredField"] != "hey" || org["someOptionalField"] != "hey" {
			t.Fatalf("org = %v", org)
		}
		if !orgP3Absent(org, "someHiddenField") {
			t.Fatalf("someHiddenField should be undefined: %v", org["someHiddenField"])
		}
		rows := e.db.Rows("organization")
		if len(rows) == 0 || rows[0]["someRequiredField"] != "hey" {
			t.Fatalf("db rows = %v", rows)
		}
	})

	t.Run("update organization", func(t *testing.T) {
		r := e.mustAPI("updateOrganization", headers, map[string]any{
			"data":           map[string]any{"someRequiredField": "hey2"},
			"organizationId": orgID(t),
		}, nil)
		if r.m()["someRequiredField"] != "hey2" {
			t.Fatalf("updated = %v", r.Data)
		}
		rows := e.db.Rows("organization")
		if len(rows) == 0 || rows[0]["someRequiredField"] != "hey2" {
			t.Fatalf("db rows = %v", rows)
		}
	})

	t.Run("list user organizations", func(t *testing.T) {
		r := e.mustAPI("listOrganizations", headers, nil, nil)
		orgs := r.list()
		if len(orgs) != 1 {
			t.Fatalf("orgs = %v", r.Data)
		}
		o := orgP3Map(orgs[0])
		if o["someRequiredField"] == nil || o["someOptionalField"] == nil {
			t.Fatalf("org = %v", o)
		}
		if !orgP3Absent(o, "someHiddenField") {
			t.Fatalf("someHiddenField should be undefined: %v", o)
		}
	})

	t.Run("useListOrganizations hook", func(t *testing.T) {
		// The listOrganizations atom fetches GET /organization/list.
		r := e.get("/organization/list", headers, nil)
		expectOK(t, r)
		data := r.list()
		if len(data) != 1 {
			t.Fatalf("data = %v", r.Data)
		}
		o := orgP3Map(data[0])
		if o["someRequiredField"] != "hey2" || o["someOptionalField"] != "hey" || !orgP3Absent(o, "someHiddenField") {
			t.Fatalf("org = %v", o)
		}
	})

	t.Run("set active organization", func(t *testing.T) {
		// Upstream only asserts types; ensure the call succeeds and carries the extra fields
		// (upstream returns the plain organization row despite the declared members/teams type).
		r := e.mustAPI("setActiveOrganization", headers, map[string]any{"organizationId": orgID(t)}, nil)
		m := r.m()
		if m["someRequiredField"] != "hey2" {
			t.Fatalf("active org = %v", m)
		}
	})

	t.Run("should infer team additional fields on $Infer.Team", func(t *testing.T) {
		t.Skip("TS-only: $Infer type inference")
	})

	t.Run("should infer organization additional fields on $Infer.Organization", func(t *testing.T) {
		t.Skip("TS-only: $Infer type inference")
	})

	t.Run("should infer member additional fields on $Infer.Member", func(t *testing.T) {
		t.Skip("TS-only: $Infer type inference")
	})

	t.Run("useActiveOrganization hook", func(t *testing.T) {
		// The activeOrganization atom fetches GET /organization/get-full-organization.
		r := e.get("/organization/get-full-organization", headers, nil)
		expectOK(t, r)
		data := r.m()
		if data == nil {
			t.Fatalf("data is null: %v", r.Data)
		}
		if data["someRequiredField"] != "hey2" || data["someOptionalField"] != "hey" || !orgP3Absent(data, "someHiddenField") {
			t.Fatalf("data = %v", data)
		}
	})

	t.Run("active organization hook refresh", func(t *testing.T) {
		// The client atoms refetch get-active-member / get-session after set-active and
		// create; the server behaviour behind that is that those endpoints reflect the
		// newly active organization. We assert that over HTTP.
		cleanup := func(t *testing.T) {
			t.Cleanup(func() {
				e.post("/organization/set-active", headers, map[string]any{"organizationId": s(org["id"])})
			})
		}
		activeMemberOrg := func(t *testing.T) string {
			t.Helper()
			r := e.get("/organization/get-active-member", headers, nil)
			expectOK(t, r)
			return s(r.m()["organizationId"])
		}

		t.Run("updates active member when setActive changes organization", func(t *testing.T) {
			expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": orgID(t)}))
			second := e.mustAPI("createOrganization", headers, map[string]any{
				"name": "test-issue-7981", "slug": "test-issue-7981",
				"someRequiredField":             "issue-7981-required",
				"keepCurrentActiveOrganization": true,
			}, nil).m()
			if second == nil {
				t.Fatal("Second organization is null")
			}
			cleanup(t)
			if got := activeMemberOrg(t); got != orgID(t) {
				t.Fatalf("active member org = %s, want %s", got, orgID(t))
			}
			expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": second["id"]}))
			if got := activeMemberOrg(t); got != s(second["id"]) {
				t.Fatalf("active member org = %s, want %s", got, s(second["id"]))
			}
		})

		t.Run("updates session and active member when create switches active organization", func(t *testing.T) {
			expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": orgID(t)}))
			cleanup(t)
			if got := activeMemberOrg(t); got != orgID(t) {
				t.Fatalf("active member org = %s", got)
			}
			if got := s(e.session(headers)["activeOrganizationId"]); got != orgID(t) {
				t.Fatalf("session active org = %s", got)
			}
			created := e.post("/organization/create", headers, map[string]any{
				"name": "test-issue-7981-create", "slug": "test-issue-7981-create",
				"someRequiredField": "issue-7981-create-required",
			})
			expectOK(t, created)
			createdID := s(created.m()["id"])
			if createdID == "" {
				t.Fatalf("Create failed: %v", created.Data)
			}
			if got := activeMemberOrg(t); got != createdID {
				t.Fatalf("active member org = %s, want %s", got, createdID)
			}
			if got := s(e.session(headers)["activeOrganizationId"]); got != createdID {
				t.Fatalf("session active org = %s, want %s", got, createdID)
			}
		})
	})

	t.Run("getFullOrganization", func(t *testing.T) {
		// Upstream only asserts types; check the call returns the additional fields shape.
		r := e.mustAPI("getFullOrganization", headers, nil, map[string]any{"organizationId": orgID(t)})
		m := r.m()
		if m["someRequiredField"] != "hey2" {
			t.Fatalf("full org = %v", m)
		}
		for _, k := range []string{"members", "invitations", "teams"} {
			if _, ok := m[k].([]any); !ok {
				t.Fatalf("%s missing: %v", k, m)
			}
		}
	})

	addedMemberHeaders := e.signUp("new-member-for-org@email.com", "password", "new member for org")
	addedMemberUser := orgP3Map(e.mustAPI("getSession", addedMemberHeaders, nil, nil).m()["user"])
	if addedMemberUser == nil {
		t.Fatal("added member sign up failed")
	}

	t.Run("add member", func(t *testing.T) {
		r := e.mustAPI("addMember", nil, map[string]any{
			"organizationId":      orgID(t),
			"userId":              addedMemberUser["id"],
			"role":                "member",
			"memberRequiredField": "hey",
			"memberOptionalField": "hey2",
		}, nil)
		member := r.m()
		if member == nil {
			t.Fatal("Member is null")
		}
		if member["memberRequiredField"] != "hey" || member["memberOptionalField"] != "hey2" || !orgP3Absent(member, "memberHiddenField") {
			t.Fatalf("member = %v", member)
		}
		row := orgP3Row(e.db.Rows("member"), s(member["id"]))
		if row == nil {
			t.Fatal("member row not found")
		}
		if row["memberRequiredField"] != "hey" || row["memberOptionalField"] != "hey2" {
			t.Fatalf("row = %v", row)
		}
	})

	t.Run("list members", func(t *testing.T) {
		r := e.mustAPI("listMembers", headers, nil, map[string]any{"organizationId": orgID(t)})
		members, _ := r.m()["members"].([]any)
		if len(members) < 2 {
			t.Fatalf("members = %v", r.Data)
		}
		m := orgP3Map(members[1])
		if m["memberRequiredField"] != "hey" || m["memberOptionalField"] != "hey2" {
			t.Fatalf("members[1] = %v", m)
		}
	})

	t.Run("get active member", func(t *testing.T) {
		e.mustAPI("setActiveOrganization", addedMemberHeaders, map[string]any{"organizationId": orgID(t)}, nil)
		r := e.mustAPI("getActiveMember", addedMemberHeaders, nil, nil)
		am := r.m()
		if am["memberRequiredField"] != "hey" || am["memberOptionalField"] != "hey2" || !orgP3Absent(am, "memberHiddenField") {
			t.Fatalf("active member = %v", am)
		}
		u := orgP3Map(am["user"])
		if u["email"] != addedMemberUser["email"] || u["name"] != addedMemberUser["name"] {
			t.Fatalf("user = %v", u)
		}
		if u["image"] != addedMemberUser["image"] {
			t.Fatalf("image = %v, want %v", u["image"], addedMemberUser["image"])
		}
	})

	t.Run("remove member", func(t *testing.T) {
		r := e.mustAPI("removeMember", headers, map[string]any{
			"organizationId":  orgID(t),
			"memberIdOrEmail": addedMemberUser["email"],
		}, nil)
		member := orgP3Map(r.m()["member"])
		if member == nil {
			t.Fatalf("removed = %v", r.Data)
		}
		if orgP3Map(member["user"])["email"] != addedMemberUser["email"] {
			t.Fatalf("member.user = %v", member["user"])
		}
		if member["memberRequiredField"] != "hey" || member["memberOptionalField"] != "hey2" || !orgP3Absent(member, "memberHiddenField") {
			t.Fatalf("member = %v", member)
		}
		if row := orgP3Row(e.db.Rows("member"), s(member["id"])); row != nil {
			t.Fatalf("member row still present: %v", row)
		}
	})

	// signInWithInvitationUser
	invitedHeaders := e.signUp("test-user-email-12333@test.com", "password", "test user")
	invitedUser := orgP3Map(e.mustAPI("getSession", invitedHeaders, nil, nil).m()["user"])
	if invitedUser == nil {
		t.Fatal("invited user sign up failed")
	}

	var invitation map[string]any
	invitationID := func(t *testing.T) string {
		t.Helper()
		if invitation == nil {
			t.Fatal("invitation not created")
		}
		return s(invitation["id"])
	}

	t.Run("create invitation", func(t *testing.T) {
		r := e.mustAPI("createInvitation", headers, map[string]any{
			"email":                   invitedUser["email"],
			"role":                    "member",
			"invitationRequiredField": "hey",
			"invitationOptionalField": "hey2",
			"organizationId":          orgID(t),
		}, nil)
		invitation = r.m()
		if invitation["invitationRequiredField"] != "hey" || invitation["invitationOptionalField"] != "hey2" || !orgP3Absent(invitation, "invitationHiddenField") {
			t.Fatalf("invitation = %v", invitation)
		}
		row := orgP3Row(e.db.Rows("invitation"), s(invitation["id"]))
		if row == nil {
			t.Fatal("invitation row not found")
		}
		if row["invitationRequiredField"] != "hey" || row["invitationOptionalField"] != "hey2" || !orgP3Absent(row, "invitationHiddenField") {
			t.Fatalf("row = %v", row)
		}
	})

	t.Run("get invitation", func(t *testing.T) {
		r := e.mustAPI("getInvitation", invitedHeaders, nil, map[string]any{"id": invitationID(t)})
		inv := r.m()
		if inv["invitationRequiredField"] != "hey" || inv["invitationOptionalField"] != "hey2" || !orgP3Absent(inv, "invitationHiddenField") {
			t.Fatalf("invitation = %v", inv)
		}
		if inv["organizationName"] != org["name"] || inv["organizationSlug"] != org["slug"] {
			t.Fatalf("invitation org = %v / %v", inv["organizationName"], inv["organizationSlug"])
		}
	})

	t.Run("accept invitation", func(t *testing.T) {
		r := e.mustAPI("acceptInvitation", invitedHeaders, map[string]any{"invitationId": invitationID(t)}, nil)
		m := r.m()
		member := orgP3Map(m["member"])
		inv := orgP3Map(m["invitation"])
		if member == nil || inv == nil {
			t.Fatalf("accepted = %v", m)
		}
		// Upstream: "memberRequiredField" / "memberOptionalField" / "memberHiddenField" in
		// member (the adapter returns them as null). Null and absent are equivalent here, so
		// we only require that none of them carries an unexpected value.
		for _, k := range []string{"memberRequiredField", "memberOptionalField", "memberHiddenField"} {
			if v, ok := member[k]; ok && v != nil {
				t.Fatalf("member.%s = %v, want null/absent", k, v)
			}
		}
		if !orgP3Absent(inv, "invitationHiddenField") {
			t.Fatalf("invitationHiddenField should be undefined: %v", inv)
		}
		if inv["invitationOptionalField"] != "hey2" || inv["status"] != "accepted" {
			t.Fatalf("invitation = %v", inv)
		}
	})

	t.Run("list invitations", func(t *testing.T) {
		r := e.mustAPI("listInvitations", headers, nil, map[string]any{"organizationId": orgID(t)})
		invs := r.list()
		if len(invs) != 1 {
			t.Fatalf("invitations = %v", r.Data)
		}
		inv := orgP3Map(invs[0])
		if inv["invitationRequiredField"] != "hey" || inv["invitationOptionalField"] != "hey2" {
			t.Fatalf("invitation = %v", inv)
		}
	})

	var team map[string]any

	t.Run("create team", func(t *testing.T) {
		r := e.mustAPI("createTeam", headers, map[string]any{
			"name":              "test",
			"teamRequiredField": "hey",
			"teamOptionalField": "hey2",
			"organizationId":    orgID(t),
		}, nil)
		team = r.m()
		if team["teamRequiredField"] != "hey" || team["teamOptionalField"] != "hey2" {
			t.Fatalf("team = %v", team)
		}
		row := orgP3Row(e.db.Rows("team"), s(team["id"]))
		if row == nil {
			t.Fatal("team row not found")
		}
		if row["teamRequiredField"] != "hey" || row["teamOptionalField"] != "hey2" {
			t.Fatalf("row = %v", row)
		}
	})

	t.Run("update team", func(t *testing.T) {
		if team == nil {
			t.Fatal("Team is null")
		}
		r := e.mustAPI("updateTeam", headers, map[string]any{
			"teamId": team["id"],
			"data": map[string]any{
				"teamOptionalField": "hey3",
				"teamRequiredField": "hey4",
			},
		}, nil)
		updated := r.m()
		if updated == nil {
			t.Fatal("Updated team is null")
		}
		if updated["teamOptionalField"] != "hey3" || updated["teamRequiredField"] != "hey4" {
			t.Fatalf("updated = %v", updated)
		}
		row := orgP3Row(e.db.Rows("team"), s(updated["id"]))
		if row == nil {
			t.Fatal("team row not found")
		}
		if row["teamOptionalField"] != "hey3" || row["teamRequiredField"] != "hey4" {
			t.Fatalf("row = %v", row)
		}
	})
}
