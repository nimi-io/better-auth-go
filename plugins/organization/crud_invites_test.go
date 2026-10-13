package organization

// Port of upstream routes/crud-invites.test.ts.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

const (
	cinvVictimEmail      = "victim@target.example"
	cinvAttackerPassword = "attacker-password-123"
)

type cinvSetup struct {
	e            *testEnv
	adminHeaders http.Header
	orgID        string
	invitationID string
}

// cinvDatabaseOwnedIDs is advanced.database.generateId = "serial".
func cinvDatabaseOwnedIDs(c *betterauth.Config) {
	if c.Advanced == nil {
		c.Advanced = &betterauth.AdvancedConfig{}
	}
	c.Advanced.Database = &betterauth.DatabaseAdvancedConfig{GenerateID: "serial"}
}

// cinvCustomIDs is a custom advanced generateId function.
func cinvCustomIDs(c *betterauth.Config) {
	seq := 0
	if c.Advanced == nil {
		c.Advanced = &betterauth.AdvancedConfig{}
	}
	c.Advanced.Database = &betterauth.DatabaseAdvancedConfig{GenerateIDFunc: func(model string, size int) (string, bool) {
		id := fmt.Sprintf("%s-custom-id-%d", model, seq)
		seq++
		return id, true
	}}
}

func cinvSetupInvite(t *testing.T, opts Options, mutate func(c *betterauth.Config)) *cinvSetup {
	t.Helper()
	e := newEnv(t, opts, envConfig{mutate: mutate})
	admin := e.signInTestUser()
	org := e.post("/organization/create", admin, map[string]any{"name": "Acme", "slug": "acme"})
	expectOK(t, org)
	admin = mergeCookies(admin, org.Headers)
	inv := e.post("/organization/invite-member", admin, map[string]any{"organizationId": org.m()["id"], "email": cinvVictimEmail, "role": "member"})
	expectOK(t, inv)
	return &cinvSetup{e: e, adminHeaders: admin, orgID: fmt.Sprint(org.m()["id"]), invitationID: fmt.Sprint(inv.m()["id"])}
}

func cinvSignUpUnverifiedRecipient(t *testing.T, e *testEnv) http.Header {
	t.Helper()
	expectOK(t, e.post("/sign-up/email", nil, map[string]any{"email": cinvVictimEmail, "password": cinvAttackerPassword, "name": "recipient"}))
	h := e.signIn(cinvVictimEmail, cinvAttackerPassword)
	u, _ := e.mustAPI("getSession", h, nil, nil).m()["user"].(map[string]any)
	if s(u["email"]) != cinvVictimEmail || u["emailVerified"] != false {
		t.Fatalf("recipient user = %v", u)
	}
	return h
}

func cinvExpectMemberEmail(t *testing.T, st *cinvSetup, email string) {
	t.Helper()
	full := st.e.mustAPI("getFullOrganization", st.adminHeaders, nil, nil).m()
	ms, _ := full["members"].([]any)
	for _, m := range ms {
		u, _ := m.(map[string]any)["user"].(map[string]any)
		if s(u["email"]) == email {
			return
		}
	}
	t.Fatalf("%s not a member: %v", email, ms)
}

func cinvExpectAccepted(t *testing.T, r *result) {
	t.Helper()
	expectOK(t, r)
	inv, _ := r.m()["invitation"].(map[string]any)
	if s(inv["status"]) != "accepted" {
		t.Fatalf("invitation = %v", r.Data)
	}
}

func cinvExpect403(t *testing.T, r *result) {
	t.Helper()
	if r.Status != 403 {
		t.Fatalf("expected 403, got %d %v", r.Status, r.Data)
	}
}

func TestCrudInvitesRecipientOwnershipGates(t *testing.T) {
	t.Run("accepts an invitation by ID from an unverified matching session by default", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{}, nil)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpectAccepted(t, st.e.post("/organization/accept-invitation", h, map[string]any{"invitationId": st.invitationID}))
		cinvExpectMemberEmail(t, st, cinvVictimEmail)
	})

	t.Run("marks an invitation rejected by ID from an unverified matching session by default", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{}, nil)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		expectOK(t, st.e.post("/organization/reject-invitation", h, map[string]any{"invitationId": st.invitationID}))
	})

	t.Run("gets an invitation by ID from an unverified matching session by default", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{}, nil)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		r := st.e.get("/organization/get-invitation", h, url.Values{"id": {st.invitationID}})
		expectOK(t, r)
		if s(r.m()["email"]) != cinvVictimEmail {
			t.Fatalf("invitation = %v", r.Data)
		}
	})

	t.Run("rejects listUserInvitations from an unverified session", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{}, nil)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpect403(t, st.e.get("/organization/list-user-invitations", h, nil))
	})

	t.Run("keeps listUserInvitations gated when invitation ID verification is disabled", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{RequireEmailVerificationOnInvitation: betterauth.Bool(false)}, nil)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpect403(t, st.e.get("/organization/list-user-invitations", h, nil))
	})

	idCalls := func(t *testing.T, opts Options, mutate func(c *betterauth.Config)) {
		st := cinvSetupInvite(t, opts, mutate)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpect403(t, st.e.post("/organization/accept-invitation", h, map[string]any{"invitationId": st.invitationID}))
		st = cinvSetupInvite(t, opts, mutate)
		h = cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpect403(t, st.e.get("/organization/get-invitation", h, url.Values{"id": {st.invitationID}}))
		st = cinvSetupInvite(t, opts, mutate)
		h = cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpect403(t, st.e.post("/organization/reject-invitation", h, map[string]any{"invitationId": st.invitationID}))
	}

	t.Run("requires verified email for invitation ID calls when explicitly enabled", func(t *testing.T) {
		idCalls(t, Options{RequireEmailVerificationOnInvitation: betterauth.Bool(true)}, nil)
	})

	t.Run("requires verified email for invitation ID calls when the database owns IDs", func(t *testing.T) {
		idCalls(t, Options{}, cinvDatabaseOwnedIDs)
	})

	t.Run("requires verified email for invitation ID calls when advanced generateId is custom", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{}, cinvCustomIDs)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpect403(t, st.e.post("/organization/accept-invitation", h, map[string]any{"invitationId": st.invitationID}))
	})

	t.Run("accepts an invitation by ID with database-owned IDs when verification is explicitly disabled", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{RequireEmailVerificationOnInvitation: betterauth.Bool(false)}, cinvDatabaseOwnedIDs)
		h := cinvSignUpUnverifiedRecipient(t, st.e)
		cinvExpectAccepted(t, st.e.post("/organization/accept-invitation", h, map[string]any{"invitationId": st.invitationID}))
		cinvExpectMemberEmail(t, st, cinvVictimEmail)
	})

	t.Run("accepts the invitation once the recipient verifies their email when verification is required", func(t *testing.T) {
		st := cinvSetupInvite(t, Options{RequireEmailVerificationOnInvitation: betterauth.Bool(true)}, nil)
		e := st.e
		expectOK(t, e.post("/sign-up/email", nil, map[string]any{"email": cinvVictimEmail, "password": cinvAttackerPassword, "name": "victim"}))
		ia := e.auth.Context().InternalAdapter
		victim, err := ia.FindUserByEmail(context.Background(), cinvVictimEmail, false)
		if err != nil || victim == nil {
			t.Fatalf("find victim: %v", err)
		}
		if _, err := ia.UpdateUser(context.Background(), victim.User.ID, adapter.Record{"emailVerified": true}); err != nil {
			t.Fatal(err)
		}
		h := e.signIn(cinvVictimEmail, cinvAttackerPassword)
		list := e.get("/organization/list-user-invitations", h, nil)
		expectOK(t, list)
		found := false
		for _, i := range list.list() {
			if fmt.Sprint(i.(map[string]any)["id"]) == st.invitationID {
				found = true
			}
		}
		if !found {
			t.Fatalf("invitation not listed: %v", list.Data)
		}
		cinvExpectAccepted(t, e.post("/organization/accept-invitation", h, map[string]any{"invitationId": st.invitationID}))
		cinvExpectMemberEmail(t, st, cinvVictimEmail)
	})
}

const (
	cinvOtherUserEmail = "user-b@example.com"
	cinvInviteeEmail   = "invitee@example.com"
	cinvPassword       = "test-password-123"
)

func cinvTeamEnv(t *testing.T, hooks *OrganizationHooks) *testEnv {
	t.Helper()
	return newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}, OrganizationHooks: hooks}, envConfig{verifyUsers: true})
}

func cinvCreateOrg(t *testing.T, e *testEnv, h http.Header, name, slug string) string {
	t.Helper()
	r := e.post("/organization/create", h, map[string]any{"name": name, "slug": slug})
	expectOK(t, r)
	return s(r.m()["id"])
}

func cinvCreateTeam(t *testing.T, e *testEnv, h http.Header, orgID, name string) string {
	t.Helper()
	r := e.post("/organization/create-team", h, map[string]any{"name": name, "organizationId": orgID})
	expectOK(t, r)
	return s(r.m()["id"])
}

func cinvInvite(t *testing.T, e *testEnv, h http.Header, orgID string, teamID any) string {
	t.Helper()
	r := e.post("/organization/invite-member", h, map[string]any{"organizationId": orgID, "email": cinvInviteeEmail, "role": "member", "teamId": teamID})
	expectOK(t, r)
	return fmt.Sprint(r.m()["id"])
}

// cinvSignUpIn signs a user up and in, returning session headers and the user id.
func cinvSignUpIn(t *testing.T, e *testEnv, email, name string) (http.Header, string) {
	t.Helper()
	expectOK(t, e.post("/sign-up/email", nil, map[string]any{"email": email, "password": cinvPassword, "name": name}))
	h := e.signIn(email, cinvPassword)
	return h, s(e.session(h)["userId"])
}

func cinvTeamIDsOf(t *testing.T, e *testEnv, userID string) []string {
	t.Helper()
	rows, err := e.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "teamMember", Where: []adapter.Where{{Field: "userId", Value: userID}}})
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, r := range rows {
		out = append(out, s(r["teamId"]))
	}
	return out
}

func cinvFindInvitation(t *testing.T, e *testEnv, id string) adapter.Record {
	t.Helper()
	r, err := e.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "invitation", Where: []adapter.Where{{Field: "id", Value: id}}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCrudInvitesTeamIDBelongsToOrganization(t *testing.T) {
	bg := context.Background()

	t.Run("rejects creating an invitation with a teamId from another organization", func(t *testing.T) {
		e := cinvTeamEnv(t, nil)
		owner := e.signInTestUser()
		firstOrg := cinvCreateOrg(t, e, owner, "Org A", "org-a")
		firstTeam := cinvCreateTeam(t, e, owner, firstOrg, "Team A")
		second, _ := cinvSignUpIn(t, e, cinvOtherUserEmail, "User B")
		otherOrg := cinvCreateOrg(t, e, second, "Org B", "org-b")
		r := e.post("/organization/invite-member", second, map[string]any{"organizationId": otherOrg, "email": cinvInviteeEmail, "role": "member", "teamId": firstTeam})
		if r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
		if r.code() != "TEAM_NOT_FOUND" {
			t.Fatalf("code = %s", r.code())
		}
	})

	t.Run("rejects accepting an invitation whose teamId points at another org", func(t *testing.T) {
		e := cinvTeamEnv(t, nil)
		owner := e.signInTestUser()
		firstOrg := cinvCreateOrg(t, e, owner, "Org A", "org-a")
		firstTeam := cinvCreateTeam(t, e, owner, firstOrg, "Team A")
		second, _ := cinvSignUpIn(t, e, cinvOtherUserEmail, "User B")
		otherOrg := cinvCreateOrg(t, e, second, "Org B", "org-b")
		otherTeam := cinvCreateTeam(t, e, second, otherOrg, "Team B")
		invID := cinvInvite(t, e, second, otherOrg, otherTeam)
		if _, err := e.auth.Context().Adapter.Update(bg, "invitation", []adapter.Where{{Field: "id", Value: invID}}, adapter.Record{"teamId": firstTeam}); err != nil {
			t.Fatal(err)
		}
		invitee, _ := cinvSignUpIn(t, e, cinvInviteeEmail, "Invitee")
		r := e.post("/organization/accept-invitation", invitee, map[string]any{"invitationId": invID})
		if r.code() != "TEAM_NOT_FOUND" {
			t.Fatalf("code = %s (%v)", r.code(), r.Data)
		}
		rows, err := e.auth.Context().Adapter.FindMany(bg, adapter.FindManyInput{Model: "teamMember", Where: []adapter.Where{{Field: "teamId", Value: firstTeam}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("team members = %v", rows)
		}
	})

	t.Run("uses the accepted invitation team ids if they change after the initial read", func(t *testing.T) {
		var e *testEnv
		replacementTeamID := ""
		e = cinvTeamEnv(t, &OrganizationHooks{
			BeforeAcceptInvitation: func(ctx *Ctx, d HookData) error {
				_, err := e.auth.Context().Adapter.Update(bg, "invitation", []adapter.Where{{Field: "id", Value: d.Invitation["id"]}}, adapter.Record{"teamId": replacementTeamID})
				return err
			},
		})
		owner := e.signInTestUser()
		org := cinvCreateOrg(t, e, owner, "Org A", "org-a")
		staleTeam := cinvCreateTeam(t, e, owner, org, "Stale Team")
		currentTeam := cinvCreateTeam(t, e, owner, org, "Current Team")
		replacementTeamID = currentTeam
		const acceptedInvitee = "accepted-row-invitee@example.com"
		ir := e.post("/organization/invite-member", owner, map[string]any{"organizationId": org, "email": acceptedInvitee, "role": "member", "teamId": staleTeam})
		expectOK(t, ir)
		invID := fmt.Sprint(ir.m()["id"])
		invitee, inviteeID := cinvSignUpIn(t, e, acceptedInvitee, "Invitee")
		r := e.post("/organization/accept-invitation", invitee, map[string]any{"invitationId": invID})
		expectOK(t, r)
		if inv, _ := r.m()["invitation"].(map[string]any); s(inv["teamId"]) != currentTeam {
			t.Fatalf("invitation = %v", r.m()["invitation"])
		}
		if ids := cinvTeamIDsOf(t, e, inviteeID); len(ids) != 1 || ids[0] != currentTeam {
			t.Fatalf("team ids = %v", ids)
		}
	})

	t.Run("keeps the invitation pending when a referenced team no longer exists", func(t *testing.T) {
		e := cinvTeamEnv(t, nil)
		owner := e.signInTestUser()
		org := cinvCreateOrg(t, e, owner, "Org A", "org-a")
		invitedTeam := cinvCreateTeam(t, e, owner, org, "Team A")
		cinvCreateTeam(t, e, owner, org, "Team B")
		invID := cinvInvite(t, e, owner, org, invitedTeam)
		if err := e.auth.Context().Adapter.Delete(bg, "team", []adapter.Where{{Field: "id", Value: invitedTeam}}); err != nil {
			t.Fatal(err)
		}
		invitee, _ := cinvSignUpIn(t, e, cinvInviteeEmail, "Invitee")
		r := e.post("/organization/accept-invitation", invitee, map[string]any{"invitationId": invID})
		if r.code() != "TEAM_NOT_FOUND" {
			t.Fatalf("code = %s (%v)", r.code(), r.Data)
		}
		if st := s(cinvFindInvitation(t, e, invID)["status"]); st != "pending" {
			t.Fatalf("status = %s", st)
		}
	})

	t.Run("clears the removed team from a pending invitation so it degrades to an organization-level invitation", func(t *testing.T) {
		e := cinvTeamEnv(t, nil)
		owner := e.signInTestUser()
		org := cinvCreateOrg(t, e, owner, "Org A", "org-a")
		invitedTeam := cinvCreateTeam(t, e, owner, org, "Team A")
		cinvCreateTeam(t, e, owner, org, "Team B")
		invID := cinvInvite(t, e, owner, org, invitedTeam)
		expectOK(t, e.post("/organization/remove-team", owner, map[string]any{"teamId": invitedTeam, "organizationId": org}))
		inv := cinvFindInvitation(t, e, invID)
		if s(inv["status"]) != "pending" {
			t.Fatalf("status = %v", inv["status"])
		}
		if inv["teamId"] != nil {
			t.Fatalf("teamId = %v", inv["teamId"])
		}
		invitee, inviteeID := cinvSignUpIn(t, e, cinvInviteeEmail, "Invitee")
		r := e.post("/organization/accept-invitation", invitee, map[string]any{"invitationId": invID})
		expectOK(t, r)
		if r.m()["member"] == nil {
			t.Fatalf("member missing: %v", r.Data)
		}
		if ids := cinvTeamIDsOf(t, e, inviteeID); len(ids) != 0 {
			t.Fatalf("team members = %v", ids)
		}
	})

	t.Run("keeps the remaining teams on a multi-team invitation when one team is removed", func(t *testing.T) {
		e := cinvTeamEnv(t, nil)
		owner := e.signInTestUser()
		org := cinvCreateOrg(t, e, owner, "Org A", "org-a")
		teamA := cinvCreateTeam(t, e, owner, org, "Team A")
		teamB := cinvCreateTeam(t, e, owner, org, "Team B")
		invID := cinvInvite(t, e, owner, org, []any{teamA, teamB})
		expectOK(t, e.post("/organization/remove-team", owner, map[string]any{"teamId": teamA, "organizationId": org}))
		inv := cinvFindInvitation(t, e, invID)
		if s(inv["status"]) != "pending" || s(inv["teamId"]) != teamB {
			t.Fatalf("invitation = %v", inv)
		}
		invitee, inviteeID := cinvSignUpIn(t, e, cinvInviteeEmail, "Invitee")
		expectOK(t, e.post("/organization/accept-invitation", invitee, map[string]any{"invitationId": invID}))
		if ids := cinvTeamIDsOf(t, e, inviteeID); len(ids) != 1 || ids[0] != teamB {
			t.Fatalf("team ids = %v", ids)
		}
	})

	t.Run("does not list another organization's team members from a mismatched teamMember row", func(t *testing.T) {
		e := cinvTeamEnv(t, nil)
		owner := e.signInTestUser()
		firstOrg := cinvCreateOrg(t, e, owner, "Org A", "org-a")
		firstTeam := cinvCreateTeam(t, e, owner, firstOrg, "Team A")
		second, secondID := cinvSignUpIn(t, e, cinvOtherUserEmail, "User B")
		if _, err := e.auth.Context().Adapter.Create(bg, adapter.CreateInput{Model: "teamMember", Data: adapter.Record{"teamId": firstTeam, "userId": secondID, "createdAt": time.Now()}}); err != nil {
			t.Fatal(err)
		}
		r := e.get("/organization/list-team-members", second, url.Values{"teamId": {firstTeam}})
		if r.Err == nil {
			t.Fatalf("expected error, got %v", r.Data)
		}
		if r.code() != "USER_IS_NOT_A_MEMBER_OF_THE_TEAM" {
			t.Fatalf("code = %s", r.code())
		}
	})
}
