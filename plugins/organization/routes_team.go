package organization

import (
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func sessionUser(s *betterauth.SessionWithUser) *betterauth.User {
	if s == nil {
		return nil
	}
	return s.User
}

func (p *plugin) createTeam() *betterauth.Endpoint {
	base := []validate.Field{
		validate.F("name", validate.String()),
		validate.F("organizationId", validate.Optional(validate.String())),
	}
	fields := mergeFields(base, additionalFieldsSchema(p.o.schema().Team.AdditionalFields)...)
	return &betterauth.Endpoint{
		Key: "createTeam", Path: "/organization/create-team", Methods: []string{"POST"},
		Body: validate.Object(fields...), Metadata: openapiMeta("/organization/create-team"),
		Handler: func(ctx *Ctx) (any, error) {
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			body := ctx.BodyMap()
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if session == nil && (ctx.Request != nil || ctx.Headers != nil) {
				return nil, errStatus("UNAUTHORIZED")
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			a := newAdapter(ctx, p.o)
			if session != nil {
				member, err := a.findMemberByOrgID(session.User.ID, orgID)
				if err != nil {
					return nil, err
				}
				if member == nil {
					return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToInviteUsersToThisOrganization)
				}
				ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"team": {"create"}}, OrganizationID: orgID})
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToCreateTeamsInThisOrganization)
				}
			}
			existing, err := a.listTeams(orgID)
			if err != nil {
				return nil, err
			}
			max := 0
			if t := p.o.Teams; t.MaximumTeamsFunc != nil {
				if max, err = t.MaximumTeamsFunc(ctx, MaximumTeamsData{OrganizationID: orgID, Session: session}); err != nil {
					return nil, err
				}
			} else if t.MaximumTeams != nil {
				max = *t.MaximumTeams
			}
			if max != 0 && len(existing) >= max {
				return nil, errFrom("BAD_REQUEST", ErrYouHaveReachedTheMaximumNumberOfTeams)
			}
			name, _ := body["name"].(string)
			additional := copyRecord(body)
			delete(additional, "name")
			delete(additional, "organizationId")
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			teamData := Record{"name": name, "organizationId": orgID, "createdAt": nowTime(), "updatedAt": nowTime()}
			hookTeam := Record{"name": name, "organizationId": orgID}
			for k, v := range additional {
				teamData[k] = v
				hookTeam[k] = v
			}
			hooks := p.o.hooks()
			teamData, _, err = callBefore(ctx, hooks.BeforeCreateTeam, HookData{Team: hookTeam, User: sessionUser(session), Organization: organization}, teamData)
			if err != nil {
				return nil, err
			}
			created, err := a.createTeam(teamData)
			if err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterCreateTeam, HookData{Team: created, User: sessionUser(session), Organization: organization}); err != nil {
				return nil, err
			}
			return p.teamObj(ctx, created), nil
		},
	}
}

func (p *plugin) removeTeam() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "removeTeam", Path: "/organization/remove-team", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("teamId", validate.String()),
			validate.F("organizationId", validate.Optional(validate.String())),
		),
		Metadata: openapiMeta("/organization/remove-team"),
		Handler: func(ctx *Ctx) (any, error) {
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			body := ctx.BodyMap()
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			if session == nil && (ctx.Request != nil || ctx.Headers != nil) {
				return nil, errStatus("UNAUTHORIZED")
			}
			teamID, _ := body["teamId"].(string)
			a := newAdapter(ctx, p.o)
			if session != nil {
				member, err := a.findMemberByOrgID(session.User.ID, orgID)
				if err != nil {
					return nil, err
				}
				if member == nil || activeTeamID(session) == teamID {
					return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToDeleteThisTeam)
				}
				ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"team": {"delete"}}, OrganizationID: orgID})
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToDeleteTeamsInThisOrganization)
				}
			}
			team, _, err := a.findTeamByID(teamID, orgID, false)
			if err != nil {
				return nil, err
			}
			if team == nil || str(team["organizationId"]) != orgID {
				return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
			}
			if !p.o.Teams.AllowRemovingAllTeams {
				teams, err := a.listTeams(orgID)
				if err != nil {
					return nil, err
				}
				if len(teams) <= 1 {
					return nil, errFrom("BAD_REQUEST", ErrUnableToRemoveLastTeam)
				}
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			hooks := p.o.hooks()
			if err := callHook(ctx, hooks.BeforeDeleteTeam, HookData{Team: team, User: sessionUser(session), Organization: organization}); err != nil {
				return nil, err
			}
			tid := str(team["id"])
			err = ctx.Transaction(func() error {
				if err := a.deleteTeam(tid); err != nil {
					return err
				}
				pending, err := a.findPendingInvitations(orgID)
				if err != nil {
					return err
				}
				for _, inv := range pending {
					raw := str(inv["teamId"])
					if raw == "" {
						continue
					}
					ids := strings.Split(raw, ",")
					if !contains(ids, tid) {
						continue
					}
					var remaining []string
					for _, id := range ids {
						if id != tid {
							remaining = append(remaining, id)
						}
					}
					var v any
					if len(remaining) > 0 {
						v = strings.Join(remaining, ",")
					}
					if _, err := ctx.Auth.Adapter.Update(ctx.Context(), "invitation", []adapter.Where{eq("id", inv["id"])}, Record{"teamId": v}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterDeleteTeam, HookData{Team: team, User: sessionUser(session), Organization: organization}); err != nil {
				return nil, err
			}
			return jsonx.O("message", "Team removed successfully."), nil
		},
	}
}

func (p *plugin) updateTeam() *betterauth.Endpoint {
	base := []validate.Field{
		validate.F("name", validate.String().Min(1)),
		validate.F("organizationId", validate.String()),
	}
	data := partialFields(mergeFields(base, additionalFieldsSchema(p.o.schema().Team.AdditionalFields)...))
	return &betterauth.Endpoint{
		Key: "updateTeam", Path: "/organization/update-team", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("teamId", validate.String()),
			validate.F("data", validate.Object(data...)),
		),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/update-team"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			body := ctx.BodyMap()
			upd, _ := body["data"].(map[string]any)
			orgID, _ := upd["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			a := newAdapter(ctx, p.o)
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateThisTeam)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"team": {"update"}}, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateThisTeam)
			}
			team, _, err := a.findTeamByID(str(body["teamId"]), orgID, false)
			if err != nil {
				return nil, err
			}
			if team == nil || str(team["organizationId"]) != orgID {
				return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			updates := Record{}
			if name, ok := upd["name"]; ok {
				updates["name"] = name
			}
			for k, v := range upd {
				if k != "name" && k != "organizationId" {
					updates[k] = v
				}
			}
			hooks := p.o.hooks()
			if hooks.BeforeUpdateTeam != nil {
				data, err := hooks.BeforeUpdateTeam(ctx, HookData{Team: team, Updates: updates, User: session.User, Organization: organization})
				if err != nil {
					return nil, err
				}
				if data != nil {
					updates = data
				}
			}
			updated, err := a.updateTeam(str(team["id"]), updates)
			if err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterUpdateTeam, HookData{Team: updated, User: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			if updated == nil {
				return betterauth.Null, nil
			}
			return p.teamObj(ctx, updated), nil
		},
	}
}

func (p *plugin) listOrganizationTeams() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listOrganizationTeams", Path: "/organization/list-teams", Methods: []string{"GET"},
		Query:    validate.Optional(validate.Object(validate.F("organizationId", validate.Optional(validate.String())))),
		Metadata: openapiMeta("/organization/list-teams"), RequireHeaders: true,
		Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			orgID := ctx.QueryString("organizationId")
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			a := newAdapter(ctx, p.o)
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToAccessThisOrganization)
			}
			teams, err := a.listTeams(orgID)
			if err != nil {
				return nil, err
			}
			return p.teamList(ctx, teams), nil
		},
	}
}

func (p *plugin) teamList(ctx *Ctx, teams []Record) []any {
	out := make([]any, len(teams))
	for i, t := range teams {
		out[i] = p.teamObj(ctx, t)
	}
	return out
}

func (p *plugin) setActiveTeam() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "setActiveTeam", Path: "/organization/set-active-team", Methods: []string{"POST"},
		Body:           validate.Object(validate.F("teamId", validate.Nullish(validate.String()))),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/set-active-team"),
		Handler: func(ctx *Ctx) (any, error) {
			a := newAdapter(ctx, p.o)
			session := ctx.Session
			raw, has := ctx.BodyMap()["teamId"]
			if has && raw == nil {
				if activeTeamID(session) == "" {
					return betterauth.Null, nil
				}
				updated, err := a.setActiveTeam(session.Session.Token, nil)
				if err != nil {
					return nil, err
				}
				if err := setSessionCookie(ctx, updated, session.User); err != nil {
					return nil, err
				}
				return betterauth.Null, nil
			}
			teamID, _ := raw.(string)
			if teamID == "" {
				teamID = activeTeamID(session)
				if teamID == "" {
					return betterauth.Null, nil
				}
			}
			orgID := activeOrgID(session)
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			team, _, err := a.findTeamByID(teamID, orgID, false)
			if err != nil {
				return nil, err
			}
			if team == nil {
				return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
			}
			member, err := a.findTeamMember(teamID, session.User.ID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("FORBIDDEN", ErrUserIsNotAMemberOfTheTeam)
			}
			updated, err := a.setActiveTeam(session.Session.Token, team["id"])
			if err != nil {
				return nil, err
			}
			if err := setSessionCookie(ctx, updated, session.User); err != nil {
				return nil, err
			}
			return p.teamObj(ctx, team), nil
		},
	}
}

func (p *plugin) listUserTeams() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listUserTeams", Path: "/organization/list-user-teams", Methods: []string{"GET"},
		Query: validate.Optional(validate.Object(
			validate.F("userId", validate.Optional(validate.String())),
			validate.F("organizationId", validate.Optional(validate.String())),
		)),
		Metadata: openapiMeta("/organization/list-user-teams"), RequireHeaders: true,
		Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			a := newAdapter(ctx, p.o)
			target := ctx.QueryString("userId")
			if target == "" {
				target = session.User.ID
			}
			isSelf := target == session.User.ID
			explicit := ctx.QueryString("organizationId")
			orgID := explicit
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			filterOrg := func(teams []Record, org string) []Record {
				out := []Record{}
				for _, t := range teams {
					if str(t["organizationId"]) == org {
						out = append(out, t)
					}
				}
				return out
			}
			if !isSelf {
				if orgID == "" {
					return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
				}
				requester, err := a.findMemberByOrgID(session.User.ID, orgID)
				if err != nil {
					return nil, err
				}
				if requester == nil {
					return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
				}
				ok, err := p.hasPermission(ctx, HasPermissionInput{Role: requester.role(), Permissions: Permissions{"member": {"update"}}, OrganizationID: orgID})
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateThisMember)
				}
				targetMember, err := a.findMemberByOrgID(target, orgID)
				if err != nil {
					return nil, err
				}
				if targetMember == nil {
					return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheOrganization)
				}
				teams, err := a.listTeamsByUser(target)
				if err != nil {
					return nil, err
				}
				return p.teamList(ctx, filterOrg(teams, orgID)), nil
			}
			if explicit != "" {
				requester, err := a.findMemberByOrgID(session.User.ID, orgID)
				if err != nil {
					return nil, err
				}
				if requester == nil {
					return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
				}
				teams, err := a.listTeamsByUser(session.User.ID)
				if err != nil {
					return nil, err
				}
				return p.teamList(ctx, filterOrg(teams, orgID)), nil
			}
			teams, err := a.listTeamsByUser(session.User.ID)
			if err != nil {
				return nil, err
			}
			memberOf := map[string]bool{}
			checked := map[string]bool{}
			out := []Record{}
			for _, t := range teams {
				org := str(t["organizationId"])
				if !checked[org] {
					checked[org] = true
					m, err := a.checkMembership(session.User.ID, org)
					if err != nil {
						return nil, err
					}
					memberOf[org] = m != nil
				}
				if memberOf[org] {
					out = append(out, t)
				}
			}
			return p.teamList(ctx, out), nil
		},
	}
}

func (p *plugin) listTeamMembers() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listTeamMembers", Path: "/organization/list-team-members", Methods: []string{"GET"},
		Query:    validate.Optional(validate.Object(validate.F("teamId", validate.Optional(validate.String())))),
		Metadata: openapiMeta("/organization/list-team-members"), RequireHeaders: true,
		Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			a := newAdapter(ctx, p.o)
			teamID := ctx.QueryString("teamId")
			if teamID == "" {
				teamID = activeTeamID(session)
			}
			if teamID == "" {
				return nil, errFrom("BAD_REQUEST", ErrYouDoNotHaveAnActiveTeam)
			}
			team, _, err := a.findTeamByID(teamID, "", false)
			if err != nil {
				return nil, err
			}
			if team == nil {
				return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
			}
			isOrgMember, err := a.checkMembership(session.User.ID, str(team["organizationId"]))
			if err != nil {
				return nil, err
			}
			if isOrgMember == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheTeam)
			}
			member, err := a.findTeamMember(teamID, session.User.ID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheTeam)
			}
			members, err := a.listTeamMembers(teamID)
			if err != nil {
				return nil, err
			}
			out := make([]any, len(members))
			for i, m := range members {
				out[i] = p.teamMemberObj(ctx, m)
			}
			return out, nil
		},
	}
}

func teamMemberBody() validate.Schema {
	return validate.Object(
		validate.F("teamId", validate.String()),
		validate.F("userId", coerceString()),
		validate.F("organizationId", validate.Optional(validate.String())),
	)
}

func (p *plugin) addTeamMember() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "addTeamMember", Path: "/organization/add-team-member", Methods: []string{"POST"},
		Body: teamMemberBody(), Metadata: openapiMeta("/organization/add-team-member"),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			a := newAdapter(ctx, p.o)
			body := ctx.BodyMap()
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			current, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if current == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: current.role(), Permissions: Permissions{"member": {"update"}}, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToCreateANewTeamMember)
			}
			userID := str(body["userId"])
			teamID := str(body["teamId"])
			toAdd, err := a.findMemberByOrgID(userID, orgID)
			if err != nil {
				return nil, err
			}
			if toAdd == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheOrganization)
			}
			team, _, err := a.findTeamByID(teamID, orgID, false)
			if err != nil {
				return nil, err
			}
			if team == nil {
				return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, errMsg("BAD_REQUEST", "User not found")
			}
			hooks := p.o.hooks()
			if hooks.BeforeAddTeamMember != nil {
				// The returned data is ignored upstream.
				if _, err := hooks.BeforeAddTeamMember(ctx, HookData{TeamMember: Record{"teamId": teamID, "userId": userID}, Team: team, User: user, Organization: organization}); err != nil {
					return nil, err
				}
			}
			var teamMember Record
			if p.o.hasMaxMembersPerTeam() {
				max, err := p.o.maxMembersPerTeam(ctx, MaximumMembersPerTeamData{TeamID: teamID, Session: session, OrganizationID: orgID})
				if err != nil {
					return nil, err
				}
				m, reached, err := a.addTeamMemberWithLimit(teamID, userID, max)
				if err != nil {
					return nil, err
				}
				if reached {
					return nil, errFrom("FORBIDDEN", ErrTeamMemberLimitReached)
				}
				teamMember = m
			} else if teamMember, err = a.findOrCreateTeamMember(teamID, userID); err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterAddTeamMember, HookData{TeamMember: teamMember, Team: team, User: user, Organization: organization}); err != nil {
				return nil, err
			}
			return p.teamMemberObj(ctx, teamMember), nil
		},
	}
}

func (p *plugin) removeTeamMember() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "removeTeamMember", Path: "/organization/remove-team-member", Methods: []string{"POST"},
		Body: teamMemberBody(), Metadata: openapiMeta("/organization/remove-team-member"),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			a := newAdapter(ctx, p.o)
			body := ctx.BodyMap()
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			current, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if current == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: current.role(), Permissions: Permissions{"member": {"delete"}}, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToRemoveATeamMember)
			}
			userID := str(body["userId"])
			teamID := str(body["teamId"])
			target, err := a.findMemberByOrgID(userID, orgID)
			if err != nil {
				return nil, err
			}
			if target == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheOrganization)
			}
			team, _, err := a.findTeamByID(teamID, orgID, false)
			if err != nil {
				return nil, err
			}
			if team == nil {
				return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, errMsg("BAD_REQUEST", "User not found")
			}
			teamMember, err := a.findTeamMember(teamID, userID)
			if err != nil {
				return nil, err
			}
			if teamMember == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheTeam)
			}
			hooks := p.o.hooks()
			if err := callHook(ctx, hooks.BeforeRemoveTeamMember, HookData{TeamMember: teamMember, Team: team, User: user, Organization: organization}); err != nil {
				return nil, err
			}
			if err := a.removeTeamMember(teamID, userID); err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterRemoveTeamMember, HookData{TeamMember: teamMember, Team: team, User: user, Organization: organization}); err != nil {
				return nil, err
			}
			return jsonx.O("message", "Team member removed successfully."), nil
		},
	}
}
