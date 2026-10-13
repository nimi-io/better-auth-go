package organization

import (
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func nowTime() time.Time { return time.Now() }

func roleSchema() validate.Schema {
	return validate.Union(validate.String(), validate.Array(validate.String()))
}

// roleNotFound is `new APIError("BAD_REQUEST", { code, message: "ROLE_NOT_FOUND: a, b" })`.
func roleNotFound(roles []string) *betterauth.APIError {
	return betterauth.NewAPIError("BAD_REQUEST", jsonx.O("code", ErrRoleNotFound.Code,
		"message", ErrRoleNotFound.Code+": "+strings.Join(roles, ", ")))
}

// unknownRoles returns the roles that are neither static nor (with dynamic access control)
// stored for the organization.
func (p *plugin) invalidRoles(ctx *Ctx, orgID string, roles []string) ([]string, error) {
	static := p.o.staticRoleNames()
	var unknown []string
	for _, r := range roles {
		if !static[r] {
			unknown = append(unknown, r)
		}
	}
	if len(unknown) == 0 || !p.o.dacEnabled() {
		return unknown, nil
	}
	vals := make([]any, len(unknown))
	for i, r := range unknown {
		vals[i] = r
	}
	found, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "organizationRole", Where: []adapter.Where{
		eq("organizationId", orgID), {Field: "role", Value: vals, Operator: adapter.In},
	}})
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, f := range found {
		names[str(f["role"])] = true
	}
	var still []string
	for _, r := range unknown {
		if !names[r] {
			still = append(still, r)
		}
	}
	return still, nil
}

func (p *plugin) addMember() *betterauth.Endpoint {
	base := []validate.Field{
		validate.F("userId", coerceString()),
		validate.F("role", roleSchema()),
		validate.F("organizationId", validate.Optional(validate.String())),
		validate.F("teamId", validate.Optional(validate.String())),
	}
	fields := mergeFields(base, additionalFieldsSchema(p.o.schema().Member.AdditionalFields)...)
	return &betterauth.Endpoint{
		Key: "addMember", ServerOnly: true, Methods: []string{"POST"},
		Body: validate.Object(fields...), Metadata: openapiMeta("addMember"),
		Handler: func(ctx *Ctx) (any, error) {
			body := ctx.BodyMap()
			userID, _ := body["userId"].(string)
			var session *betterauth.SessionWithUser
			if userID != "" {
				session, _ = betterauth.GetSessionFromCtx(ctx, nil)
			}
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			teamID, _ := body["teamId"].(string)
			if teamID != "" && !p.o.teamsEnabled() {
				ctx.Auth.Logger.Error("Teams are not enabled")
				return nil, errMsg("BAD_REQUEST", "Teams are not enabled")
			}
			a := newAdapter(ctx, p.o)
			user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, errFrom("BAD_REQUEST", betterauth.ErrUserNotFound)
			}
			already, err := a.findMemberByEmail(user.Email, orgID)
			if err != nil {
				return nil, err
			}
			if already != nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsAlreadyAMemberOfThisOrganization)
			}
			if teamID != "" {
				team, _, err := a.findTeamByID(teamID, orgID, false)
				if err != nil {
					return nil, err
				}
				if team == nil || str(team["organizationId"]) != orgID {
					return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
				}
			}
			count, err := a.countMembers(orgID)
			if err != nil {
				return nil, err
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			limit, err := p.o.membershipLimit(ctx, user, organization)
			if err != nil {
				return nil, err
			}
			if count >= int64(limit) {
				return nil, errFrom("FORBIDDEN", ErrOrganizationMembershipLimitReached)
			}
			additional := copyRecord(body)
			delete(additional, "role")
			delete(additional, "userId")
			delete(additional, "organizationId")
			role := parseRoles(body["role"])
			memberData := Record{"organizationId": orgID, "userId": user.ID, "role": role, "createdAt": nowTime()}
			for k, v := range additional {
				memberData[k] = v
			}
			hookMember := Record{"userId": user.ID, "organizationId": orgID, "role": role}
			for k, v := range additional {
				hookMember[k] = v
			}
			hooks := p.o.hooks()
			memberData, _, err = callBefore(ctx, hooks.BeforeAddMember, HookData{Member: hookMember, User: user, Organization: organization}, memberData)
			if err != nil {
				return nil, err
			}
			created, err := a.createMember(memberData)
			if err != nil {
				return nil, err
			}
			if teamID != "" {
				if err := p.addToTeam(ctx, a, session, teamID, user.ID, orgID); err != nil {
					if derr := a.deleteMember(str(created["id"]), orgID, user.ID); derr != nil {
						return nil, derr
					}
					return nil, err
				}
			}
			if err := callHook(ctx, hooks.AfterAddMember, HookData{Member: created, User: user, Organization: organization}); err != nil {
				return nil, err
			}
			return p.memberObj(ctx, created, false), nil
		},
	}
}

func (p *plugin) addToTeam(ctx *Ctx, a *orgAdapter, session *betterauth.SessionWithUser, teamID, userID, orgID string) error {
	if !p.o.hasMaxMembersPerTeam() {
		_, err := a.findOrCreateTeamMember(teamID, userID)
		return err
	}
	var max int
	if p.o.Teams.MaximumMembersPerTeamFunc != nil {
		if session == nil {
			return errStatus("UNAUTHORIZED")
		}
		var err error
		if max, err = p.o.Teams.MaximumMembersPerTeamFunc(ctx, MaximumMembersPerTeamData{TeamID: teamID, Session: session, OrganizationID: orgID}); err != nil {
			return err
		}
	} else {
		max = *p.o.Teams.MaximumMembersPerTeam
	}
	_, reached, err := a.addTeamMemberWithLimit(teamID, userID, max)
	if err != nil {
		return err
	}
	if reached {
		return errFrom("FORBIDDEN", ErrTeamMemberLimitReached)
	}
	return nil
}

func (p *plugin) removeMember() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "removeMember", Path: "/organization/remove-member", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("memberIdOrEmail", validate.String()),
			validate.F("organizationId", validate.Optional(validate.String())),
		),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/remove-member"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			body := ctx.BodyMap()
			orgID, _ := body["organizationId"].(string)
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
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			idOrEmail, _ := body["memberIdOrEmail"].(string)
			var toRemove Record
			var toRemoveOut *jsonx.Object
			if strings.Contains(idOrEmail, "@") {
				m, err := a.findMemberByEmail(idOrEmail, orgID)
				if err != nil {
					return nil, err
				}
				if m != nil {
					toRemove = m.Member
					toRemoveOut = p.memberWithUserObj(ctx, m, false)
				}
			} else {
				m, err := a.findMemberByID(idOrEmail)
				if err != nil {
					return nil, err
				}
				if m != nil {
					toRemove = m.Member
					toRemoveOut = p.memberObj(ctx, m.Member, false)
				}
			}
			if toRemove == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			creatorRole := p.o.creatorRole()
			if contains(splitRoles(str(toRemove["role"])), creatorRole) {
				if !contains(trimmedRoles(member.role()), creatorRole) {
					return nil, errFrom("BAD_REQUEST", ErrYouCannotLeaveTheOrganizationAsTheOnlyOwner)
				}
				members, _, err := a.listMembers(listMembersInput{OrganizationID: orgID})
				if err != nil {
					return nil, err
				}
				owners := 0
				for _, m := range members {
					if contains(splitRoles(m.role()), creatorRole) {
						owners++
					}
				}
				if owners <= 1 {
					return nil, errFrom("BAD_REQUEST", ErrYouCannotLeaveTheOrganizationAsTheOnlyOwner)
				}
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"member": {"delete"}}, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("UNAUTHORIZED", ErrYouAreNotAllowedToDeleteThisMember)
			}
			if str(toRemove["organizationId"]) != orgID {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			removedUser, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), str(toRemove["userId"]))
			if err != nil {
				return nil, err
			}
			if removedUser == nil {
				return nil, errMsg("BAD_REQUEST", "User not found")
			}
			hooks := p.o.hooks()
			if err := callHook(ctx, hooks.BeforeRemoveMember, HookData{Member: toRemove, User: removedUser, Organization: organization}); err != nil {
				return nil, err
			}
			if err := a.deleteMember(str(toRemove["id"]), orgID, str(toRemove["userId"])); err != nil {
				return nil, err
			}
			if session.User.ID == str(toRemove["userId"]) && activeOrgID(session) == str(toRemove["organizationId"]) {
				if _, err := a.setActiveOrganization(session.Session.Token, nil); err != nil {
					return nil, err
				}
			}
			if err := callHook(ctx, hooks.AfterRemoveMember, HookData{Member: toRemove, User: removedUser, Organization: organization}); err != nil {
				return nil, err
			}
			return jsonx.O("member", toRemoveOut), nil
		},
	}
}

func (p *plugin) updateMemberRole() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "updateMemberRole", Path: "/organization/update-member-role", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("role", roleSchema()),
			validate.F("memberId", validate.String()),
			validate.F("organizationId", validate.Optional(validate.String())),
		),
		Use:            []betterauth.Middleware{orgSessionMiddleware},
		RequireHeaders: true, Metadata: openapiMeta("/organization/update-member-role"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			body := ctx.BodyMap()
			if s, isStr := body["role"].(string); isStr && s == "" {
				return nil, errStatus("BAD_REQUEST")
			}
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			a := newAdapter(ctx, p.o)
			var rawRoles []string
			switch t := body["role"].(type) {
			case string:
				rawRoles = []string{t}
			case []any:
				for _, x := range t {
					s, _ := x.(string)
					rawRoles = append(rawRoles, s)
				}
			}
			var roleToSet []string
			for _, r := range rawRoles {
				for _, part := range strings.Split(r, ",") {
					if part = strings.TrimSpace(part); part != "" {
						roleToSet = append(roleToSet, part)
					}
				}
			}
			if len(roleToSet) == 0 {
				return nil, errStatus("BAD_REQUEST")
			}
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			memberID, _ := body["memberId"].(string)
			toUpdate := member
			if member.id() != memberID {
				if toUpdate, err = a.findMemberByID(memberID); err != nil {
					return nil, err
				}
			}
			if toUpdate == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			if str(toUpdate.Member["organizationId"]) != orgID {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateThisMember)
			}
			creatorRole := p.o.creatorRole()
			isUpdatingCreator := contains(splitRoles(toUpdate.role()), creatorRole)
			updaterIsCreator := contains(splitRoles(member.role()), creatorRole)
			isSettingCreator := contains(roleToSet, creatorRole)
			updatingThemselves := member.id() == toUpdate.id()
			if (isUpdatingCreator && !updaterIsCreator) || (isSettingCreator && !updaterIsCreator) {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateThisMember)
			}
			if updaterIsCreator && updatingThemselves {
				members, err := a.findMany("member", 0, eq("organizationId", orgID))
				if err != nil {
					return nil, err
				}
				owners := 0
				for _, m := range members {
					if contains(splitRoles(str(m["role"])), creatorRole) {
						owners++
					}
				}
				if owners <= 1 && !isSettingCreator {
					return nil, errFrom("BAD_REQUEST", ErrYouCannotLeaveTheOrganizationWithoutAnOwner)
				}
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"member": {"update"}}, AllowCreatorAllPermissions: true, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateThisMember)
			}
			invalid, err := p.invalidRoles(ctx, orgID, roleToSet)
			if err != nil {
				return nil, err
			}
			if len(invalid) > 0 {
				return nil, roleNotFound(invalid)
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			updatedUser, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), str(toUpdate.Member["userId"]))
			if err != nil {
				return nil, err
			}
			if updatedUser == nil {
				return nil, errMsg("BAD_REQUEST", "User not found")
			}
			previousRole := toUpdate.role()
			newRole := strings.Join(roleToSet, ",")
			hooks := p.o.hooks()
			if hooks.BeforeUpdateMemberRole != nil {
				data, err := hooks.BeforeUpdateMemberRole(ctx, HookData{Member: withUser(toUpdate), NewRole: newRole, User: updatedUser, Organization: organization})
				if err != nil {
					return nil, err
				}
				if data != nil {
					if r, _ := data["role"].(string); r != "" {
						newRole = r
					}
				}
			}
			updated, err := a.updateMember(memberID, newRole)
			if err != nil {
				return nil, err
			}
			if updated == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			if err := callHook(ctx, hooks.AfterUpdateMemberRole, HookData{Member: updated, PreviousRole: previousRole, User: updatedUser, Organization: organization}); err != nil {
				return nil, err
			}
			return p.memberObj(ctx, updated, false), nil
		},
	}
}

func (p *plugin) getActiveMember() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getActiveMember", Path: "/organization/get-active-member", Methods: []string{"GET"},
		Use:            []betterauth.Middleware{orgSessionMiddleware},
		RequireHeaders: true, Metadata: openapiMeta("/organization/get-active-member"),
		Handler: func(ctx *Ctx) (any, error) {
			orgID := activeOrgID(ctx.Session)
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			member, err := newAdapter(ctx, p.o).findMemberByOrgID(ctx.Session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			return p.memberWithUserObj(ctx, member, false), nil
		},
	}
}

func (p *plugin) leaveOrganization() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "leaveOrganization", Path: "/organization/leave", Methods: []string{"POST"},
		Body:           validate.Object(validate.F("organizationId", validate.String())),
		RequireHeaders: true, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			orgID := ctx.BodyString("organizationId")
			a := newAdapter(ctx, p.o)
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			creatorRole := p.o.creatorRole()
			if contains(splitRoles(member.role()), creatorRole) {
				members, err := a.findMany("member", 0, eq("organizationId", orgID))
				if err != nil {
					return nil, err
				}
				owners := 0
				for _, m := range members {
					if contains(splitRoles(str(m["role"])), creatorRole) {
						owners++
					}
				}
				if owners <= 1 {
					return nil, errFrom("BAD_REQUEST", ErrYouCannotLeaveTheOrganizationAsTheOnlyOwner)
				}
			}
			if err := a.deleteMember(member.id(), orgID, session.User.ID); err != nil {
				return nil, err
			}
			if activeOrgID(session) == orgID {
				if _, err := a.setActiveOrganization(session.Session.Token, nil); err != nil {
					return nil, err
				}
			}
			return p.memberWithUserObj(ctx, member, false), nil
		},
	}
}

var whereOperators = []string{"eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "contains", "starts_with", "ends_with"}

func (p *plugin) listMembers() *betterauth.Endpoint {
	strOrNum := validate.Union(validate.String(), validate.Number())
	query := validate.Optional(validate.Object(
		validate.F("limit", validate.Optional(strOrNum)),
		validate.F("offset", validate.Optional(strOrNum)),
		validate.F("sortBy", validate.Optional(validate.String())),
		validate.F("sortDirection", validate.Optional(validate.Enum("asc", "desc"))),
		validate.F("filterField", validate.Optional(validate.String())),
		validate.F("filterValue", validate.Optional(validate.Union(validate.String(), validate.Number(), validate.Boolean(),
			validate.Array(validate.String()), validate.Array(validate.Number())))),
		validate.F("filterOperator", validate.Optional(validate.Enum(whereOperators...))),
		validate.F("organizationId", validate.Optional(validate.String())),
		validate.F("organizationSlug", validate.Optional(validate.String())),
	))
	return &betterauth.Endpoint{
		Key: "listMembers", Path: "/organization/list-members", Methods: []string{"GET"},
		Query: query, RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			q := ctx.Query
			orgID, _ := q["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			a := newAdapter(ctx, p.o)
			if slug, _ := q["organizationSlug"].(string); slug != "" {
				org, err := a.findOrganizationBySlug(slug)
				if err != nil {
					return nil, err
				}
				if org == nil {
					return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
				}
				orgID = str(org["id"])
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			isMember, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if isMember == nil {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			in := listMembersInput{OrganizationID: orgID}
			if v, ok := q["limit"]; ok && validate.Truthy(v) {
				if f := jsNumber(v); truthyNum(f) {
					in.Limit = int(f)
				}
			}
			if v, ok := q["offset"]; ok && validate.Truthy(v) {
				if f := jsNumber(v); truthyNum(f) {
					in.Offset = int(f)
				}
			}
			in.SortBy, _ = q["sortBy"].(string)
			in.SortOrder, _ = q["sortDirection"].(string)
			if field, _ := q["filterField"].(string); field != "" {
				op, _ := q["filterOperator"].(string)
				in.Filter = &adapter.Where{Field: field, Value: dateFilterValue(ctx, field, q["filterValue"]), Operator: adapter.Operator(op)}
			}
			members, total, err := a.listMembers(in)
			if err != nil {
				return nil, err
			}
			out := make([]any, len(members))
			for i, m := range members {
				out[i] = p.memberWithUserObj(ctx, m, false)
			}
			return jsonx.O("members", out, "total", total), nil
		},
	}
}

func (p *plugin) getActiveMemberRole() *betterauth.Endpoint {
	query := validate.Optional(validate.Object(
		validate.F("userId", validate.Optional(validate.String())),
		validate.F("organizationId", validate.Optional(validate.String())),
		validate.F("organizationSlug", validate.Optional(validate.String())),
	))
	return &betterauth.Endpoint{
		Key: "getActiveMemberRole", Path: "/organization/get-active-member-role", Methods: []string{"GET"},
		Query: query, RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			orgID := ctx.QueryString("organizationId")
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			a := newAdapter(ctx, p.o)
			if slug := ctx.QueryString("organizationSlug"); slug != "" {
				org, err := a.findOrganizationBySlug(slug)
				if err != nil {
					return nil, err
				}
				if org == nil {
					return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
				}
				orgID = str(org["id"])
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			isMember, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if isMember == nil {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			userID := ctx.QueryString("userId")
			if userID == "" {
				return jsonx.O("role", isMember.role()), nil
			}
			member, err := a.findMemberByOrgID(userID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			return jsonx.O("role", member.role()), nil
		},
	}
}

// dateFilterValue parses an ISO string filter value for date fields (SQL databases compare
// ISO strings natively; the Go adapters compare time.Time values).
func dateFilterValue(ctx *Ctx, field string, v any) any {
	sv, ok := v.(string)
	if !ok {
		return v
	}
	if t := ctx.Auth.Tables.Table("member"); t != nil {
		if f, ok := t.Field(field); ok && f.Type == db.TypeDate {
			if tm, ok := jsonx.ParseJSDate(sv); ok {
				return tm
			}
		}
	}
	return v
}
