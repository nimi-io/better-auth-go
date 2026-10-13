package organization

// Port of upstream packages/better-auth/src/plugins/organization/team.test.ts.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"

	_ "modernc.org/sqlite"
)

// tmTSQLiteEnv is newEnv backed by an in-memory SQLite database (upstream's default
// getTestInstance database), whose transactions serialize concurrent writers.
func tmTSQLiteEnv(t *testing.T, opts Options, ec envConfig) *testEnv {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
	prev := ec.mutate
	ec.mutate = func(c *betterauth.Config) {
		c.Database = sqladapter.New(conn, sqladapter.Config{})
		if prev != nil {
			prev(c)
		}
	}
	ec.noTestUser = true
	e := newEnv(t, opts, ec)
	if err := e.auth.RunMigrations(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	e.signUp(testEmail, testPassword, testName)
	return e
}

// tmTSignUp signs a user up (auth.api.signUpEmail) and returns its session headers and id.
func tmTSignUp(e *testEnv, email, password, name string) (http.Header, string) {
	e.t.Helper()
	r := e.mustAPI("signUpEmail", nil, map[string]any{"email": email, "password": password, "name": name}, nil)
	u, _ := r.m()["user"].(map[string]any)
	return cookieHeaders(r.Headers), s(u["id"])
}

func tmTUsersModel(c *betterauth.Config) {
	c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{ModelName: "users"}}
}

func tmTMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func tmTHasUser(list []any, userID string) bool {
	for _, x := range list {
		if s(tmTMap(x)["userId"]) == userID {
			return true
		}
	}
	return false
}

func tmTFindUser(list []any, userID string) map[string]any {
	for _, x := range list {
		if m := tmTMap(x); s(m["userId"]) == userID {
			return m
		}
	}
	return nil
}

func tmTAdapter(e *testEnv) adapter.Adapter { return e.auth.Context().Adapter }

func tmTEq(field string, v any) adapter.Where { return adapter.Where{Field: field, Value: v} }

func tmTFindMany(t *testing.T, e *testEnv, model string, where ...adapter.Where) []adapter.Record {
	t.Helper()
	rows, err := tmTAdapter(e).FindMany(context.Background(), adapter.FindManyInput{Model: model, Where: where})
	if err != nil {
		t.Fatalf("findMany %s: %v", model, err)
	}
	return rows
}

func tmTFindOne(t *testing.T, e *testEnv, model string, where ...adapter.Where) adapter.Record {
	t.Helper()
	row, err := tmTAdapter(e).FindOne(context.Background(), adapter.FindOneInput{Model: model, Where: where})
	if err != nil {
		t.Fatalf("findOne %s: %v", model, err)
	}
	return row
}

func tmTRowsHaveUser(rows []adapter.Record, userID string) bool {
	for _, r := range rows {
		if s(r["userId"]) == userID {
			return true
		}
	}
	return false
}

func tmTNum(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case int32:
		return float64(n)
	}
	return -1
}

func tmTIDs(list []any) []string {
	var out []string
	for _, x := range list {
		out = append(out, s(tmTMap(x)["id"]))
	}
	return out
}

func TestTeam(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}}, envConfig{verifyUsers: true, mutate: tmTUsersModel})
	headers := e.signInTestUser()
	var organizationID, teamID, secondTeamID string
	invitedEmail, invitedPassword, invitedName := "invited@email.com", "password", "Invited User"
	signUpHeaders, signUpUserID := tmTSignUp(e, invitedEmail, invitedPassword, invitedName)

	t.Run("should create an organization and a team", func(t *testing.T) {
		r := e.post("/organization/create", headers, map[string]any{
			"name": "Test Organization", "slug": "test-org",
			"metadata": map[string]any{"test": "organization-metadata"},
		})
		expectOK(t, r)
		organizationID = s(r.m()["id"])
		if s(r.m()["name"]) != "Test Organization" || s(r.m()["slug"]) != "test-org" {
			t.Fatalf("org = %v", r.Data)
		}
		if l, _ := r.m()["members"].([]any); len(l) != 1 {
			t.Fatalf("members = %v", r.m()["members"])
		}
		if s(tmTMap(r.m()["metadata"])["test"]) != "organization-metadata" {
			t.Fatalf("metadata = %v", r.m()["metadata"])
		}
		ct := e.post("/organization/create-team", headers, map[string]any{"name": "Development Team", "organizationId": organizationID})
		expectOK(t, ct)
		teamID = s(ct.m()["id"])
		if s(ct.m()["name"]) != "Development Team" || s(ct.m()["organizationId"]) != organizationID {
			t.Fatalf("team = %v", ct.Data)
		}
		ct2 := e.post("/organization/create-team", headers, map[string]any{"name": "Marketing Team", "organizationId": organizationID})
		expectOK(t, ct2)
		secondTeamID = s(ct2.m()["id"])
		if s(ct2.m()["name"]) != "Marketing Team" || s(ct2.m()["organizationId"]) != organizationID {
			t.Fatalf("team2 = %v", ct2.Data)
		}
	})

	t.Run("should invite member to team", func(t *testing.T) {
		if teamID == "" {
			t.Fatal("teamId undefined")
		}
		r := e.post("/organization/invite-member", headers, map[string]any{"teamId": teamID, "email": invitedEmail, "role": "member"})
		expectOK(t, r)
		if s(r.m()["email"]) != invitedEmail || s(r.m()["role"]) != "member" || s(r.m()["teamId"]) != teamID {
			t.Fatalf("invitation = %v", r.Data)
		}
		acc := e.post("/organization/accept-invitation", signUpHeaders, map[string]any{"invitationId": r.m()["id"]})
		expectOK(t, acc)
		m := tmTMap(acc.m()["member"])
		if s(m["role"]) != "member" || s(m["userId"]) != signUpUserID {
			t.Fatalf("member = %v", m)
		}
	})

	t.Run("should add team to the member's list of teams", func(t *testing.T) {
		r := e.get("/organization/list-user-teams", signUpHeaders, nil)
		expectOK(t, r)
		if r.Data == nil || len(r.list()) != 1 {
			t.Fatalf("teams = %v", r.Data)
		}
	})

	t.Run("should be able to list team members in the current active team", func(t *testing.T) {
		sa := e.post("/organization/set-active-team", signUpHeaders, map[string]any{"teamId": teamID})
		activeTeamHeaders := cookieHeaders(sa.Headers)
		r := e.get("/organization/list-team-members", activeTeamHeaders, nil)
		expectOK(t, r)
		if r.Data == nil || len(r.list()) != 1 {
			t.Fatalf("members = %v", r.Data)
		}
	})

	t.Run("should get full organization", func(t *testing.T) {
		r := e.get("/organization/get-full-organization", headers, nil)
		expectOK(t, r)
		teams, ok := r.m()["teams"].([]any)
		if !ok || len(teams) != 3 {
			t.Fatalf("teams = %v", r.m()["teams"])
		}
		var names []string
		for _, x := range teams {
			names = append(names, s(tmTMap(x)["name"]))
		}
		joined := "|" + strings.Join(names, "|") + "|"
		if !strings.Contains(joined, "|Development Team|") || !strings.Contains(joined, "|Marketing Team|") {
			t.Fatalf("names = %v", names)
		}
	})

	t.Run("should get all teams", func(t *testing.T) {
		r := e.get("/organization/list-teams", headers, nil)
		expectOK(t, r)
		if _, ok := r.Data.([]any); !ok || len(r.list()) != 3 {
			t.Fatalf("teams = %v", r.Data)
		}
	})

	t.Run("should update a team", func(t *testing.T) {
		r := e.post("/organization/update-team", headers, map[string]any{"teamId": teamID, "data": map[string]any{"name": "Updated Development Team"}})
		expectOK(t, r)
		if s(r.m()["name"]) != "Updated Development Team" || s(r.m()["id"]) != teamID {
			t.Fatalf("team = %v", r.Data)
		}
	})

	t.Run("should remove a team", func(t *testing.T) {
		before := e.get("/organization/list-teams", headers, nil)
		if len(before.list()) != 3 {
			t.Fatalf("before = %v", before.Data)
		}
		r := e.post("/organization/remove-team", headers, map[string]any{"teamId": teamID, "organizationId": organizationID})
		expectOK(t, r)
		if s(r.m()["message"]) != "Team removed successfully." {
			t.Fatalf("remove = %v", r.Data)
		}
		after := e.get("/organization/list-teams", headers, nil)
		if len(after.list()) != 2 {
			t.Fatalf("after = %v", after.Data)
		}
	})

	t.Run("should not be able to remove the last team when allowRemovingAllTeams is not enabled", func(t *testing.T) {
		// Upstream's client call never throws, so its try/catch assertion is vacuous: the
		// organization still has two teams (default + Marketing) at this point, so the
		// removal is allowed. We mirror the call and only require a well-formed response.
		r := e.post("/organization/remove-team", headers, map[string]any{"teamId": secondTeamID, "organizationId": organizationID})
		if r.Status == 0 {
			t.Fatal("no response")
		}
	})

	t.Run("should update a team with explicit organizationId in data", func(t *testing.T) {
		currentActiveOrgID := e.session(headers)["activeOrganizationId"]
		newOrg := e.post("/organization/create", headers, map[string]any{"name": "New Test Organization", "slug": "new-test-org"})
		expectOK(t, newOrg)
		newOrgID := s(newOrg.m()["id"])
		if newOrgID == "" || newOrgID == currentActiveOrgID {
			t.Fatalf("newOrg = %v (active %v)", newOrg.Data, currentActiveOrgID)
		}
		nt := e.post("/organization/create-team", headers, map[string]any{"name": "Team in New Org", "organizationId": newOrgID})
		expectOK(t, nt)
		newTeamID := s(nt.m()["id"])
		if newTeamID == "" || s(nt.m()["organizationId"]) != newOrgID {
			t.Fatalf("team = %v", nt.Data)
		}
		up := e.post("/organization/update-team", headers, map[string]any{"teamId": newTeamID, "data": map[string]any{"name": "Updated Team Name", "organizationId": newOrgID}})
		expectOK(t, up)
		if s(up.m()["name"]) != "Updated Team Name" || s(up.m()["id"]) != newTeamID || s(up.m()["organizationId"]) != newOrgID {
			t.Fatalf("updated = %v", up.Data)
		}
	})

	t.Run("should add and remove team member with explicit organizationId", func(t *testing.T) {
		testOrgID := organizationID
		nt := e.post("/organization/create-team", headers, map[string]any{"name": "Team for Member Test", "organizationId": testOrgID})
		expectOK(t, nt)
		testTeamID := s(nt.m()["id"])
		if testTeamID == "" {
			t.Fatal("no team id")
		}
		gs := e.get("/get-session", headers, nil)
		currentUserID := s(tmTMap(gs.m()["user"])["id"])
		e.mustAPI("addTeamMember", headers, map[string]any{"userId": currentUserID, "teamId": testTeamID, "organizationId": testOrgID}, nil)
		su := e.post("/sign-up/email", nil, map[string]any{"email": "teamuser@email.com", "password": "password", "name": "Team User"})
		expectOK(t, su)
		newUserID := s(tmTMap(su.m()["user"])["id"])
		if newUserID == "" {
			t.Fatalf("signup = %v", su.Data)
		}
		e.mustAPI("addMember", nil, map[string]any{"organizationId": testOrgID, "userId": newUserID, "role": "member"}, nil)
		added := e.mustAPI("addTeamMember", headers, map[string]any{"userId": newUserID, "teamId": testTeamID, "organizationId": testOrgID}, nil)
		if s(added.m()["teamId"]) != testTeamID || s(added.m()["userId"]) != newUserID {
			t.Fatalf("added = %v", added.Data)
		}
		before := e.mustAPI("listTeamMembers", headers, nil, map[string]any{"teamId": testTeamID})
		if !tmTHasUser(before.list(), newUserID) {
			t.Fatalf("before = %v", before.Data)
		}
		rm := e.mustAPI("removeTeamMember", headers, map[string]any{"userId": newUserID, "teamId": testTeamID, "organizationId": testOrgID}, nil)
		if s(rm.m()["message"]) != "Team member removed successfully." {
			t.Fatalf("remove = %v", rm.Data)
		}
		after := e.mustAPI("listTeamMembers", headers, nil, map[string]any{"teamId": testTeamID})
		if tmTHasUser(after.list(), newUserID) {
			t.Fatalf("after = %v", after.Data)
		}
	})

	t.Run("should not be allowed to invite a member to a team that's reached maximum members", func(t *testing.T) {
		one := 1
		e2 := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true, MaximumMembersPerTeam: &one}}, envConfig{verifyUsers: true, mutate: tmTUsersModel})
		h := e2.signInTestUser()
		org := e2.post("/organization/create", h, map[string]any{
			"name": "Test Organization", "slug": "test-org",
			"metadata": map[string]any{"test": "organization-metadata"},
		})
		expectOK(t, org)
		ct := e2.post("/organization/create-team", h, map[string]any{"name": "Development Team", "organizationId": org.m()["id"]})
		expectOK(t, ct)
		tid := ct.m()["id"]
		res := e2.post("/organization/invite-member", h, map[string]any{"teamId": tid, "email": invitedEmail, "role": "member"})
		expectOK(t, res)
		su := e2.post("/sign-up/email", nil, map[string]any{"email": invitedEmail, "password": invitedPassword, "name": invitedName})
		expectOK(t, su)
		newHeaders := cookieHeaders(su.Headers)
		acc := e2.post("/organization/accept-invitation", newHeaders, map[string]any{"invitationId": res.m()["id"]})
		expectOK(t, acc)
		if s(tmTMap(acc.m()["member"])["userId"]) != s(tmTMap(su.m()["user"])["id"]) {
			t.Fatalf("accept = %v", acc.Data)
		}
		if s(tmTMap(acc.m()["invitation"])["status"]) != "accepted" {
			t.Fatalf("accept = %v", acc.Data)
		}
		res2 := e2.post("/organization/invite-member", h, map[string]any{"teamId": tid, "email": "test2@test.com", "role": "member"})
		if res2.Err == nil || res2.code() != "TEAM_MEMBER_LIMIT_REACHED" {
			t.Fatalf("res2 = %d %v", res2.Status, res2.Data)
		}
	})
}

func TestTeamSetActiveTeamOrgScoping(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}}, envConfig{verifyUsers: true})
	headers := e.signInTestUser()
	ctx := context.Background()

	gs := e.get("/get-session", headers, nil)
	userID := s(tmTMap(gs.m()["user"])["id"])
	sessionToken := s(tmTMap(gs.m()["session"])["token"])
	first := e.post("/organization/create", headers, map[string]any{"name": "Scoped Org One", "slug": "scoped-org-one"})
	expectOK(t, first)
	activeOrganizationID := s(first.m()["id"])
	st := e.post("/organization/create-team", headers, map[string]any{"name": "Scoped Team One", "organizationId": activeOrganizationID})
	expectOK(t, st)
	scopedTeamID := s(st.m()["id"])
	e.mustAPI("addTeamMember", headers, map[string]any{"userId": userID, "teamId": scopedTeamID, "organizationId": activeOrganizationID}, nil)
	second := e.post("/organization/create", headers, map[string]any{"name": "Scoped Org Two", "slug": "scoped-org-two", "keepCurrentActiveOrganization": true})
	expectOK(t, second)
	outOfScopeOrganizationID := s(second.m()["id"])
	ot := e.post("/organization/create-team", headers, map[string]any{"name": "Scoped Team Two", "organizationId": outOfScopeOrganizationID})
	expectOK(t, ot)
	outOfScopeTeamID := s(ot.m()["id"])
	e.mustAPI("addTeamMember", headers, map[string]any{"userId": userID, "teamId": outOfScopeTeamID, "organizationId": outOfScopeOrganizationID}, nil)
	expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": activeOrganizationID}))
	sst := e.post("/organization/set-active-team", headers, map[string]any{"teamId": scopedTeamID})
	expectOK(t, sst)
	if s(sst.m()["id"]) != scopedTeamID {
		t.Fatalf("setActiveTeam = %v", sst.Data)
	}
	sess := e.session(headers)
	if s(sess["activeOrganizationId"]) != activeOrganizationID || s(sess["activeTeamId"]) != scopedTeamID {
		t.Fatalf("session = %v", sess)
	}

	setSessionOrg := func(t *testing.T, orgID string) {
		t.Helper()
		if _, err := tmTAdapter(e).Update(ctx, "session", []adapter.Where{tmTEq("token", sessionToken)}, adapter.Record{"activeOrganizationId": orgID}); err != nil {
			t.Fatalf("update session: %v", err)
		}
	}

	t.Run("should reject teams outside the active organization and preserve the active team", func(t *testing.T) {
		r := e.post("/organization/set-active-team", headers, map[string]any{"teamId": outOfScopeTeamID})
		if r.Status != 400 || !strings.Contains(r.code(), "TEAM_NOT_FOUND") {
			t.Fatalf("r = %d %v", r.Status, r.Data)
		}
		sess := e.session(headers)
		if s(sess["activeOrganizationId"]) != activeOrganizationID || s(sess["activeTeamId"]) != scopedTeamID {
			t.Fatalf("session = %v", sess)
		}
	})

	t.Run("should reject refreshing the current active team when the session org changes externally", func(t *testing.T) {
		setSessionOrg(t, outOfScopeOrganizationID)
		r := e.api("setActiveTeam", headers, map[string]any{}, nil)
		if r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
		if r.message() != ErrTeamNotFound.Message {
			t.Fatalf("message = %q", r.message())
		}
		sess := e.session(headers)
		if s(sess["activeOrganizationId"]) != outOfScopeOrganizationID || s(sess["activeTeamId"]) != scopedTeamID {
			t.Fatalf("session = %v", sess)
		}
		setSessionOrg(t, activeOrganizationID)
	})

	t.Run("should require an active organization before setting the active team", func(t *testing.T) {
		if activeOrganizationID == "" || scopedTeamID == "" || userID == "" {
			t.Fatal("setup incomplete")
		}
		expectOK(t, e.post("/organization/set-active", headers, map[string]any{"organizationId": nil}))
		r := e.post("/organization/set-active-team", headers, map[string]any{"teamId": scopedTeamID})
		if r.Status != 400 || !strings.Contains(r.code(), "NO_ACTIVE_ORGANIZATION") {
			t.Fatalf("r = %d %v", r.Status, r.Data)
		}
		sess := e.session(headers)
		if v, ok := sess["activeOrganizationId"]; ok && v != nil {
			t.Fatalf("activeOrganizationId = %v", v)
		}
	})
}

func TestTeamMultiTeamSupport(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true, DefaultTeam: &DefaultTeamOptions{Enabled: betterauth.Bool(true)}}}, envConfig{verifyUsers: true})
	adminHeaders := e.signInTestUser()
	adminID := s(e.mustAPI("getSession", adminHeaders, nil, nil).m()["user"].(map[string]any)["id"])
	invitedEmail := "invited@email.com"
	invitedHeaders, invitedUserID := tmTSignUp(e, invitedEmail, "password", "Invited User")
	var organizationID, team1ID, team2ID, team3ID, invitationID string

	t.Run("should create an organization to test multi team support", func(t *testing.T) {
		org := e.mustAPI("createOrganization", adminHeaders, map[string]any{
			"name": "Test Organization", "slug": "test-org", "metadata": map[string]any{"test": "organization-metadata"},
		}, nil)
		if s(org.m()["id"]) == "" || s(org.m()["name"]) != "Test Organization" {
			t.Fatalf("org = %v", org.Data)
		}
		organizationID = s(org.m()["id"])
	})

	t.Run("should create 3 teams", func(t *testing.T) {
		if organizationID == "" {
			t.Fatal("can not run test")
		}
		mk := func(name string) string {
			r := e.mustAPI("createTeam", adminHeaders, map[string]any{"name": name, "organizationId": organizationID}, nil)
			if s(r.m()["id"]) == "" || s(r.m()["organizationId"]) != organizationID {
				t.Fatalf("team = %v", r.Data)
			}
			return s(r.m()["id"])
		}
		team1ID, team2ID, team3ID = mk("Team One"), mk("Team Two"), mk("Team Three")
	})

	t.Run("should invite user to all 3 teams", func(t *testing.T) {
		if organizationID == "" || team1ID == "" || team2ID == "" || team3ID == "" {
			t.Fatal("can not run test")
		}
		inv := e.mustAPI("createInvitation", adminHeaders, map[string]any{
			"email": invitedEmail, "role": "member", "organizationId": organizationID,
			"teamId": []any{team1ID, team2ID, team3ID},
		}, nil)
		if s(inv.m()["id"]) == "" || s(inv.m()["teamId"]) != strings.Join([]string{team1ID, team2ID, team3ID}, ",") {
			t.Fatalf("invitation = %v", inv.Data)
		}
		invitationID = s(inv.m()["id"])
	})

	t.Run("should accept invite and join all 3 teams", func(t *testing.T) {
		if invitationID == "" {
			t.Fatal("can not run test")
		}
		acc := e.mustAPI("acceptInvitation", invitedHeaders, map[string]any{"invitationId": invitationID}, nil)
		if acc.m()["member"] == nil || acc.m()["invitation"] == nil {
			t.Fatalf("accept = %v", acc.Data)
		}
	})

	t.Run("should have jonied all 3 teams", func(t *testing.T) {
		if invitationID == "" {
			t.Fatal("can not run test")
		}
		teams := e.mustAPI("listUserTeams", invitedHeaders, nil, nil)
		if len(teams.list()) != 3 {
			t.Fatalf("teams = %v", teams.Data)
		}
	})

	var activeTeamHeaders http.Header
	t.Run("should allow you to set one of the teams as active", func(t *testing.T) {
		if team1ID == "" || organizationID == "" {
			t.Fatal("can not run test")
		}
		r := e.mustAPI("setActiveTeam", invitedHeaders, map[string]any{"teamId": team1ID}, nil)
		if s(r.m()["id"]) != team1ID || s(r.m()["organizationId"]) != organizationID {
			t.Fatalf("team = %v", r.Data)
		}
		activeTeamHeaders = mergeCookies(invitedHeaders, r.Headers)
	})

	t.Run("should allow you to list team members of the current active team", func(t *testing.T) {
		if activeTeamHeaders == nil {
			t.Fatal("can not run test")
		}
		members := e.mustAPI("listTeamMembers", activeTeamHeaders, nil, nil)
		if len(members.list()) != 1 || s(tmTMap(members.list()[0])["teamId"]) != team1ID {
			t.Fatalf("members = %v", members.Data)
		}
	})

	t.Run("should allow user to list team members of any team the user is in", func(t *testing.T) {
		if team2ID == "" || team3ID == "" {
			t.Fatal("can not run test")
		}
		for _, tid := range []string{team2ID, team3ID} {
			m := e.mustAPI("listTeamMembers", invitedHeaders, nil, map[string]any{"teamId": tid})
			if len(m.list()) != 1 || s(tmTMap(m.list()[0])["teamId"]) != tid {
				t.Fatalf("members(%s) = %v", tid, m.Data)
			}
		}
	})

	var team4ID string
	t.Run("should directly add a member to a team", func(t *testing.T) {
		if organizationID == "" {
			t.Fatal("can not run test")
		}
		team := e.mustAPI("createTeam", adminHeaders, map[string]any{"name": "Team Four", "organizationId": organizationID}, nil)
		tid := s(team.m()["id"])
		tm := e.mustAPI("addTeamMember", adminHeaders, map[string]any{"userId": invitedUserID, "teamId": tid}, nil)
		if s(tm.m()["teamId"]) != tid || s(tm.m()["userId"]) != invitedUserID {
			t.Fatalf("teamMember = %v", tm.Data)
		}
		teams := e.mustAPI("listUserTeams", invitedHeaders, nil, nil)
		if len(teams.list()) != 4 {
			t.Fatalf("teams = %v", teams.Data)
		}
		team4ID = tid
	})

	t.Run("should remove a member from a team", func(t *testing.T) {
		if team4ID == "" {
			t.Fatal("can not run test")
		}
		e.mustAPI("removeTeamMember", adminHeaders, map[string]any{"userId": invitedUserID, "teamId": team4ID}, nil)
		teams := e.mustAPI("listUserTeams", invitedHeaders, nil, nil)
		if len(teams.list()) != 3 {
			t.Fatalf("teams = %v", teams.Data)
		}
	})

	t.Run("should create invitation without teamId", func(t *testing.T) {
		if organizationID == "" {
			t.Fatal("can not run test")
		}
		inv := e.mustAPI("createInvitation", adminHeaders, map[string]any{"email": "noteam@email.com", "role": "member", "organizationId": organizationID}, nil)
		if s(inv.m()["id"]) == "" {
			t.Fatalf("invitation = %v", inv.Data)
		}
		if v, ok := inv.m()["teamId"]; ok && v != nil {
			t.Fatalf("teamId = %#v", v)
		}
	})

	t.Run("should remove a member from the organization and all their teams when calling removeMember", func(t *testing.T) {
		userHeaders, newUserID := tmTSignUp(e, "removeteamorguser@email.com", "password", "Remove Team Org User")
		e.mustAPI("addMember", adminHeaders, map[string]any{"organizationId": organizationID, "userId": newUserID, "role": "member"}, nil)
		e.mustAPI("addTeamMember", adminHeaders, map[string]any{"teamId": team1ID, "userId": newUserID}, nil)
		e.mustAPI("addTeamMember", adminHeaders, map[string]any{"teamId": team1ID, "userId": adminID}, nil)
		membersBefore := e.mustAPI("listMembers", adminHeaders, nil, map[string]any{"organizationId": organizationID})
		found := tmTFindUser(membersBefore.m()["members"].([]any), newUserID)
		if found == nil {
			t.Fatal("member not found")
		}
		tmBefore := e.mustAPI("listTeamMembers", userHeaders, nil, map[string]any{"teamId": team1ID})
		if !tmTHasUser(tmBefore.list(), newUserID) {
			t.Fatalf("team members before = %v", tmBefore.Data)
		}
		removed := e.mustAPI("removeMember", adminHeaders, map[string]any{"memberIdOrEmail": found["id"], "organizationId": organizationID}, nil)
		if s(tmTMap(removed.m()["member"])["id"]) != s(found["id"]) {
			t.Fatalf("removed = %v", removed.Data)
		}
		membersAfter := e.mustAPI("listMembers", adminHeaders, nil, map[string]any{"organizationId": organizationID})
		if tmTHasUser(membersAfter.m()["members"].([]any), newUserID) {
			t.Fatal("still member")
		}
		tmAfter := e.mustAPI("listTeamMembers", adminHeaders, nil, map[string]any{"teamId": team1ID})
		if tmTHasUser(tmAfter.list(), newUserID) {
			t.Fatal("still team member")
		}
	})

	t.Run("should remove a member from the organization and all their teams when calling leaveOrganization", func(t *testing.T) {
		email := fmt.Sprintf("leaveorguser%d@email.com", time.Now().UnixNano())
		userHeaders, newUserID := tmTSignUp(e, email, "password", "Leave Org User")
		e.mustAPI("addMember", adminHeaders, map[string]any{"organizationId": organizationID, "userId": newUserID, "role": "member"}, nil)
		membersBefore := e.mustAPI("listMembers", adminHeaders, nil, map[string]any{"organizationId": organizationID})
		found := tmTFindUser(membersBefore.m()["members"].([]any), newUserID)
		if found == nil {
			t.Fatal("User was not added as organization member")
		}
		for _, tid := range []string{team1ID, team2ID} {
			e.mustAPI("addTeamMember", adminHeaders, map[string]any{"teamId": tid, "userId": newUserID}, nil)
			e.mustAPI("addTeamMember", adminHeaders, map[string]any{"teamId": tid, "userId": adminID}, nil)
		}
		for _, tid := range []string{team1ID, team2ID} {
			b := e.mustAPI("listTeamMembers", adminHeaders, nil, map[string]any{"teamId": tid})
			if !tmTHasUser(b.list(), newUserID) {
				t.Fatalf("team %s before = %v", tid, b.Data)
			}
		}
		left := e.mustAPI("leaveOrganization", userHeaders, map[string]any{"organizationId": organizationID}, nil)
		if s(left.m()["id"]) != s(found["id"]) {
			t.Fatalf("left = %v", left.Data)
		}
		membersAfter := e.mustAPI("listMembers", adminHeaders, nil, map[string]any{"organizationId": organizationID})
		if tmTHasUser(membersAfter.m()["members"].([]any), newUserID) {
			t.Fatal("still member")
		}
		for _, tid := range []string{team1ID, team2ID} {
			a := e.mustAPI("listTeamMembers", adminHeaders, nil, map[string]any{"teamId": tid})
			if tmTHasUser(a.list(), newUserID) {
				t.Fatalf("still team member of %s", tid)
			}
		}
	})
}

func TestTeamListUserTeamsWithUserIDParameter(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}})
	var ownerHeaders, memberHeaders, outsiderHeaders http.Header
	var organizationID, teamID, memberUserID, ownerUserID string

	t.Run("should setup organization with teams and members", func(t *testing.T) {
		_, ownerUserID = tmTSignUp(e, "team-owner@test.com", "password123", "Owner User")
		ownerHeaders = e.signIn("team-owner@test.com", "password123")
		org := e.mustAPI("createOrganization", ownerHeaders, map[string]any{"name": "Teams Test Org", "slug": "teams-test-org"}, nil)
		organizationID = s(org.m()["id"])
		e.mustAPI("setActiveOrganization", ownerHeaders, map[string]any{"organizationId": organizationID}, nil)
		team := e.mustAPI("createTeam", ownerHeaders, map[string]any{"name": "Alpha Team", "organizationId": organizationID}, nil)
		teamID = s(team.m()["id"])
		_, memberUserID = tmTSignUp(e, "team-member@test.com", "password123", "Member User")
		memberHeaders = e.signIn("team-member@test.com", "password123")
		e.mustAPI("addMember", ownerHeaders, map[string]any{"organizationId": organizationID, "userId": memberUserID, "role": "member"}, nil)
		e.mustAPI("addTeamMember", ownerHeaders, map[string]any{"teamId": teamID, "userId": memberUserID}, nil)
		e.mustAPI("setActiveOrganization", memberHeaders, map[string]any{"organizationId": organizationID}, nil)
		tmTSignUp(e, "team-outsider@test.com", "password123", "Outsider User")
		outsiderHeaders = e.signIn("team-outsider@test.com", "password123")
	})

	expectOne := func(t *testing.T, r *result) {
		t.Helper()
		expectOK(t, r)
		if len(r.list()) != 1 || s(tmTMap(r.list()[0])["id"]) != teamID {
			t.Fatalf("teams = %v", r.Data)
		}
	}

	t.Run("should list own teams without userId param (backwards compatible)", func(t *testing.T) {
		expectOne(t, e.api("listUserTeams", memberHeaders, nil, nil))
	})
	t.Run("should allow a user to list their own teams with userId param", func(t *testing.T) {
		expectOne(t, e.api("listUserTeams", memberHeaders, nil, map[string]any{"userId": memberUserID}))
	})
	t.Run("should allow an owner to list another user's teams", func(t *testing.T) {
		expectOne(t, e.api("listUserTeams", ownerHeaders, nil, map[string]any{"userId": memberUserID}))
	})
	t.Run("should not allow a member to list another user's teams", func(t *testing.T) {
		if r := e.api("listUserTeams", memberHeaders, nil, map[string]any{"userId": ownerUserID}); r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
	})
	t.Run("should not allow querying teams of a user not in the organization", func(t *testing.T) {
		if r := e.api("listUserTeams", ownerHeaders, nil, map[string]any{"userId": "non-existent-user-id"}); r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
	})
	t.Run("should fail when querying another user without an active organization", func(t *testing.T) {
		if r := e.api("listUserTeams", outsiderHeaders, nil, map[string]any{"userId": memberUserID}); r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
	})
}

func TestTeamListUserTeamsWithOrganizationIDParameter(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}})
	var ownerHeaders, memberHeaders http.Header
	var orgAID, orgBID, teamInAID, teamInBID, memberUserID string

	t.Run("should setup two organizations with teams", func(t *testing.T) {
		tmTSignUp(e, "multi-org-owner@test.com", "password123", "Multi Org Owner")
		ownerHeaders = e.signIn("multi-org-owner@test.com", "password123")
		orgAID = s(e.mustAPI("createOrganization", ownerHeaders, map[string]any{"name": "Org A", "slug": "multi-org-a"}, nil).m()["id"])
		orgBID = s(e.mustAPI("createOrganization", ownerHeaders, map[string]any{"name": "Org B", "slug": "multi-org-b"}, nil).m()["id"])
		e.mustAPI("setActiveOrganization", ownerHeaders, map[string]any{"organizationId": orgBID}, nil)
		teamInAID = s(e.mustAPI("createTeam", ownerHeaders, map[string]any{"name": "Team in A", "organizationId": orgAID}, nil).m()["id"])
		teamInBID = s(e.mustAPI("createTeam", ownerHeaders, map[string]any{"name": "Team in B", "organizationId": orgBID}, nil).m()["id"])
		_, memberUserID = tmTSignUp(e, "multi-org-member@test.com", "password123", "Multi Org Member")
		memberHeaders = e.signIn("multi-org-member@test.com", "password123")
		e.mustAPI("addMember", ownerHeaders, map[string]any{"organizationId": orgAID, "userId": memberUserID, "role": "member"}, nil)
		e.mustAPI("addMember", ownerHeaders, map[string]any{"organizationId": orgBID, "userId": memberUserID, "role": "member"}, nil)
		e.mustAPI("addTeamMember", ownerHeaders, map[string]any{"teamId": teamInAID, "userId": memberUserID, "organizationId": orgAID}, nil)
		e.mustAPI("addTeamMember", ownerHeaders, map[string]any{"teamId": teamInBID, "userId": memberUserID, "organizationId": orgBID}, nil)
		e.mustAPI("setActiveOrganization", memberHeaders, map[string]any{"organizationId": orgAID}, nil)
	})

	t.Run("should return self teams across all orgs when organizationId is omitted", func(t *testing.T) {
		r := e.mustAPI("listUserTeams", memberHeaders, nil, nil)
		ids := tmTIDs(r.list())
		sort.Strings(ids)
		want := []string{teamInAID, teamInBID}
		sort.Strings(want)
		if strings.Join(ids, ",") != strings.Join(want, ",") {
			t.Fatalf("ids = %v want %v", ids, want)
		}
	})
	t.Run("should scope self query to explicit organizationId", func(t *testing.T) {
		r := e.mustAPI("listUserTeams", memberHeaders, nil, map[string]any{"organizationId": orgBID})
		if len(r.list()) != 1 || s(tmTMap(r.list()[0])["id"]) != teamInBID {
			t.Fatalf("teams = %v", r.Data)
		}
	})
	t.Run("should allow owner to list another user's teams in a non-active org via explicit organizationId", func(t *testing.T) {
		r := e.mustAPI("listUserTeams", ownerHeaders, nil, map[string]any{"userId": memberUserID, "organizationId": orgAID})
		if len(r.list()) != 1 || s(tmTMap(r.list()[0])["id"]) != teamInAID {
			t.Fatalf("teams = %v", r.Data)
		}
	})
	t.Run("should forbid self query with explicit organizationId when user is not a member", func(t *testing.T) {
		tmTSignUp(e, "multi-org-outsider@test.com", "password123", "Multi Org Outsider")
		h := e.signIn("multi-org-outsider@test.com", "password123")
		if r := e.api("listUserTeams", h, nil, map[string]any{"organizationId": orgAID}); r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
	})
}

func TestTeamInvitationWithTeamIDContainingComma(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}}, envConfig{verifyUsers: true, mutate: func(c *betterauth.Config) {
		c.Advanced = &betterauth.AdvancedConfig{Database: &betterauth.DatabaseAdvancedConfig{
			GenerateIDFunc: func(model string, size int) (string, bool) {
				if model == "team" {
					return "team,id," + rand.Text(), true
				}
				return rand.Text(), true
			},
		}}
	}})
	admin := e.signInTestUser()
	org := e.mustAPI("createOrganization", admin, map[string]any{"name": "Comma Org", "slug": "comma-org"}, nil)
	organizationID := s(org.m()["id"])
	team := e.mustAPI("createTeam", admin, map[string]any{"name": "Comma Team", "organizationId": organizationID}, nil)
	teamID := s(team.m()["id"])

	t.Run("seeds a team whose generated id contains the storage separator", func(t *testing.T) {
		if !strings.Contains(teamID, ",") {
			t.Fatalf("team id = %q", teamID)
		}
	})
	for _, tc := range []struct {
		name   string
		teamID any
	}{
		{"string body", teamID},
		{"array body", []any{teamID}},
	} {
		t.Run("rejects createInvitation with "+tc.name, func(t *testing.T) {
			r := e.api("createInvitation", admin, map[string]any{
				"email": "comma-invitee@email.com", "role": "member", "organizationId": organizationID, "teamId": tc.teamID,
			}, nil)
			expectCode(t, r, 400, "INVALID_TEAM_ID")
		})
	}
}

func TestTeamInvitationTeamIDsAreScopedToTheInvitedOrganization(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}}, envConfig{verifyUsers: true})
	ctx := context.Background()
	orgAOwner := e.signInTestUser()
	orgAOwnerID := s(tmTMap(e.mustAPI("getSession", orgAOwner, nil, nil).m()["user"])["id"])
	orgA := e.mustAPI("createOrganization", orgAOwner, map[string]any{"name": "Org A", "slug": "org-a"}, nil)
	orgAID := s(orgA.m()["id"])
	inviteeEmail := "team-scope-invitee@email.com"
	expectOK(t, e.post("/sign-up/email", nil, map[string]any{"email": "org-b-owner@email.com", "password": "password12345", "name": "Org B Owner"}))
	orgBHeaders := e.signIn("org-b-owner@email.com", "password12345")
	orgB := e.mustAPI("createOrganization", orgBHeaders, map[string]any{"name": "Org B", "slug": "org-b"}, nil)
	teamB := e.mustAPI("createTeam", orgBHeaders, map[string]any{"name": "Org B Team", "organizationId": orgB.m()["id"]}, nil)
	otherOrgTeamID := s(teamB.m()["id"])

	t.Run("rejects createInvitation when the team belongs to another organization", func(t *testing.T) {
		r := e.api("createInvitation", orgAOwner, map[string]any{
			"email": inviteeEmail, "role": "member", "organizationId": orgAID, "teamId": otherOrgTeamID,
		}, nil)
		expectCode(t, r, 400, "TEAM_NOT_FOUND")
	})

	t.Run("does not add the member to another organization's team when accepting an invitation that stored one", func(t *testing.T) {
		invitationID := fmt.Sprintf("team-scope-invitation-%d", time.Now().UnixNano())
		_, err := tmTAdapter(e).Create(ctx, adapter.CreateInput{Model: "invitation", ForceAllowID: true, Data: adapter.Record{
			"id": invitationID, "email": inviteeEmail, "role": "member", "organizationId": orgAID,
			"teamId": otherOrgTeamID, "status": "pending", "inviterId": orgAOwnerID,
			"expiresAt": time.Now().Add(time.Hour), "createdAt": time.Now(),
		}})
		if err != nil {
			t.Fatalf("create invitation: %v", err)
		}
		su := e.post("/sign-up/email", nil, map[string]any{"email": inviteeEmail, "password": "password12345", "name": "Invitee"})
		expectOK(t, su)
		inviteeHeaders := cookieHeaders(su.Headers)
		inviteeUserID := s(tmTMap(su.m()["user"])["id"])
		r := e.api("acceptInvitation", inviteeHeaders, map[string]any{"invitationId": invitationID}, nil)
		expectCode(t, r, 400, "TEAM_NOT_FOUND")
		if tmTRowsHaveUser(tmTFindMany(t, e, "teamMember", tmTEq("teamId", otherOrgTeamID)), inviteeUserID) {
			t.Fatal("invitee was added to the other organization's team")
		}
	})
}

func TestTeamAcceptInvitationValidatesTeamCapacityBeforeAddingTheMember(t *testing.T) {
	two := 2
	e := tmTSQLiteEnv(t, Options{Teams: &TeamsOptions{Enabled: true, MaximumMembersPerTeam: &two}}, envConfig{verifyUsers: true})
	ctx := context.Background()
	owner := e.signInTestUser()
	org := e.mustAPI("createOrganization", owner, map[string]any{"name": "Capacity Org", "slug": "capacity-org"}, nil)
	orgID := s(org.m()["id"])

	seedCounter := 0
	seedTeamMember := func(t *testing.T, teamID string) {
		t.Helper()
		_, uid := tmTSignUp(e, fmt.Sprintf("seed-%d@email.com", seedCounter), "password12345", fmt.Sprintf("Seed %d", seedCounter))
		seedCounter++
		if _, err := tmTAdapter(e).Create(ctx, adapter.CreateInput{Model: "teamMember", Data: adapter.Record{
			"teamId": teamID, "userId": uid, "createdAt": time.Now(),
		}}); err != nil {
			t.Fatalf("seed team member: %v", err)
		}
	}
	type invite struct {
		invitationID string
		headers      http.Header
		userID       string
	}
	inviteAndSignUp := func(t *testing.T, teamID, email string) invite {
		t.Helper()
		inv := e.mustAPI("createInvitation", owner, map[string]any{"email": email, "role": "member", "organizationId": orgID, "teamId": teamID}, nil)
		h, uid := tmTSignUp(e, email, "password12345", email)
		return invite{s(inv.m()["id"]), h, uid}
	}
	createTeam := func(t *testing.T, name string) string {
		t.Helper()
		return s(e.mustAPI("createTeam", owner, map[string]any{"name": name, "organizationId": orgID}, nil).m()["id"])
	}

	t.Run("accepts the final member when the team is one below capacity", func(t *testing.T) {
		teamID := createTeam(t, "Almost Full Team")
		seedTeamMember(t, teamID)
		inv := inviteAndSignUp(t, teamID, "capacity-fits@email.com")
		acc := e.mustAPI("acceptInvitation", inv.headers, map[string]any{"invitationId": inv.invitationID}, nil)
		if s(tmTMap(acc.m()["member"])["userId"]) != inv.userID || s(tmTMap(acc.m()["invitation"])["status"]) != "accepted" {
			t.Fatalf("accept = %v", acc.Data)
		}
		rows := tmTFindMany(t, e, "teamMember", tmTEq("teamId", teamID))
		if len(rows) != 2 || !tmTRowsHaveUser(rows, inv.userID) {
			t.Fatalf("rows = %v", rows)
		}
		teamAfter := tmTFindOne(t, e, "team", tmTEq("id", teamID))
		if tmTNum(teamAfter["memberCount"]) != 2 {
			t.Fatalf("memberCount = %v", teamAfter["memberCount"])
		}
	})

	t.Run("enforces the team limit when adding an existing organization member directly", func(t *testing.T) {
		teamID := createTeam(t, "Direct Add Capacity Team")
		seedTeamMember(t, teamID)
		_, first := tmTSignUp(e, "direct-add-one@email.com", "password12345", "Direct Add One")
		_, second := tmTSignUp(e, "direct-add-two@email.com", "password12345", "Direct Add Two")
		for _, uid := range []string{first, second} {
			if _, err := tmTAdapter(e).Create(ctx, adapter.CreateInput{Model: "member", Data: adapter.Record{
				"organizationId": orgID, "userId": uid, "role": "member", "createdAt": time.Now(),
			}}); err != nil {
				t.Fatalf("create member: %v", err)
			}
		}
		added := e.mustAPI("addTeamMember", owner, map[string]any{"teamId": teamID, "userId": first, "organizationId": orgID}, nil)
		if s(added.m()["userId"]) != first {
			t.Fatalf("added = %v", added.Data)
		}
		r := e.api("addTeamMember", owner, map[string]any{"teamId": teamID, "userId": second, "organizationId": orgID}, nil)
		expectCode(t, r, 403, "TEAM_MEMBER_LIMIT_REACHED")
		rows := tmTFindMany(t, e, "teamMember", tmTEq("teamId", teamID))
		if len(rows) != 2 || !tmTRowsHaveUser(rows, first) || tmTRowsHaveUser(rows, second) {
			t.Fatalf("rows = %v", rows)
		}
	})

	t.Run("rolls back addMember when the requested team is already full", func(t *testing.T) {
		teamID := createTeam(t, "Add Member Full Team")
		seedTeamMember(t, teamID)
		seedTeamMember(t, teamID)
		_, uid := tmTSignUp(e, "full-team-add-member@email.com", "password12345", "Full Team Add Member")
		r := e.api("addMember", owner, map[string]any{"userId": uid, "role": "member", "organizationId": orgID, "teamId": teamID}, nil)
		expectCode(t, r, 403, "TEAM_MEMBER_LIMIT_REACHED")
		if m := tmTFindOne(t, e, "member", tmTEq("organizationId", orgID), tmTEq("userId", uid)); m != nil {
			t.Fatalf("member row = %v", m)
		}
	})

	t.Run("rejects with TEAM_MEMBER_LIMIT_REACHED and creates no membership row when the team fills between invite and accept", func(t *testing.T) {
		teamID := createTeam(t, "Filling Team")
		seedTeamMember(t, teamID)
		inv := inviteAndSignUp(t, teamID, "capacity-overflows@email.com")
		seedTeamMember(t, teamID)
		r := e.api("acceptInvitation", inv.headers, map[string]any{"invitationId": inv.invitationID}, nil)
		expectCode(t, r, 403, "TEAM_MEMBER_LIMIT_REACHED")
		rows := tmTFindMany(t, e, "teamMember", tmTEq("teamId", teamID))
		if len(rows) != 2 || tmTRowsHaveUser(rows, inv.userID) {
			t.Fatalf("rows = %v", rows)
		}
		after := tmTFindOne(t, e, "invitation", tmTEq("id", inv.invitationID))
		if s(after["status"]) != "pending" {
			t.Fatalf("invitation = %v", after)
		}
		if tmTRowsHaveUser(tmTFindMany(t, e, "member", tmTEq("organizationId", orgID)), inv.userID) {
			t.Fatal("org member row created")
		}
	})

	t.Run("accepts only one of two concurrent invitations competing for the final team slot", func(t *testing.T) {
		teamID := createTeam(t, "Final Slot Team")
		seedTeamMember(t, teamID)
		first := inviteAndSignUp(t, teamID, "final-slot-one@email.com")
		second := inviteAndSignUp(t, teamID, "final-slot-two@email.com")
		results := tmTConcurrent(e, []invite{first, second}, func(i invite) *result {
			return e.api("acceptInvitation", i.headers, map[string]any{"invitationId": i.invitationID}, nil)
		})
		ok, failed := 0, 0
		for _, r := range results {
			if r.Err == nil {
				ok++
			} else {
				failed++
			}
		}
		if ok != 1 || failed != 1 {
			t.Fatalf("fulfilled=%d rejected=%d", ok, failed)
		}
		rows := tmTFindMany(t, e, "teamMember", tmTEq("teamId", teamID))
		if len(rows) != 2 {
			t.Fatalf("rows = %v", rows)
		}
		n := 0
		for _, r := range rows {
			if u := s(r["userId"]); u == first.userID || u == second.userID {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("accepted invitee count = %d", n)
		}
		teamAfter := tmTFindOne(t, e, "team", tmTEq("id", teamID))
		if tmTNum(teamAfter["memberCount"]) != 2 {
			t.Fatalf("memberCount = %v", teamAfter["memberCount"])
		}
	})

	t.Run("accepts only once when the same invitation is accepted concurrently", func(t *testing.T) {
		teamID := createTeam(t, "Concurrent Team")
		inv := inviteAndSignUp(t, teamID, "concurrent-accept@email.com")
		results := tmTConcurrent(e, []invite{inv, inv}, func(i invite) *result {
			return e.api("acceptInvitation", i.headers, map[string]any{"invitationId": i.invitationID}, nil)
		})
		ok := 0
		for _, r := range results {
			if r.Err == nil {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("fulfilled = %d", ok)
		}
		n := 0
		for _, r := range tmTFindMany(t, e, "member", tmTEq("organizationId", orgID)) {
			if s(r["userId"]) == inv.userID {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("org member rows for invitee = %d", n)
		}
	})

	t.Run("does not reopen an invitation when a stale rollback loses its status guard", func(t *testing.T) {
		teamID := createTeam(t, "Rollback Guard Team")
		inv := inviteAndSignUp(t, teamID, "rollback-guard@email.com")
		ad := tmTAdapter(e)
		accepted, err := ad.Update(ctx, "invitation", []adapter.Where{tmTEq("id", inv.invitationID), tmTEq("status", "pending")}, adapter.Record{"status": "accepted"})
		if err != nil || s(accepted["status"]) != "accepted" {
			t.Fatalf("accepted = %v %v", accepted, err)
		}
		rejected, err := ad.Update(ctx, "invitation", []adapter.Where{tmTEq("id", inv.invitationID), tmTEq("status", "accepted")}, adapter.Record{"status": "rejected"})
		if err != nil || s(rejected["status"]) != "rejected" {
			t.Fatalf("rejected = %v %v", rejected, err)
		}
		stale, err := ad.Update(ctx, "invitation", []adapter.Where{tmTEq("id", inv.invitationID), tmTEq("status", "accepted")}, adapter.Record{"status": "pending"})
		if err != nil || stale != nil {
			t.Fatalf("stale = %v %v", stale, err)
		}
		after := tmTFindOne(t, e, "invitation", tmTEq("id", inv.invitationID))
		if s(after["status"]) != "rejected" {
			t.Fatalf("invitation = %v", after)
		}
	})
}

// tmTConcurrent runs fn for each input concurrently (Promise.allSettled) and returns the
// results in input order.
func tmTConcurrent[T any](e *testEnv, in []T, fn func(T) *result) []*result {
	out := make([]*result, len(in))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, x := range in {
		wg.Add(1)
		go func(i int, x T) {
			defer wg.Done()
			<-start
			out[i] = fn(x)
		}(i, x)
	}
	close(start)
	wg.Wait()
	return out
}
