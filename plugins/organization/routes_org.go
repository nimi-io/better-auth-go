package organization

import (
	"math"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// callBefore runs a BeforeHook and merges its data into base (`{...base, ...data}`).
func callBefore(ctx *Ctx, h BeforeHook, d HookData, base Record) (Record, bool, error) {
	if h == nil {
		return base, false, nil
	}
	data, err := h(ctx, d)
	if err != nil {
		return nil, false, err
	}
	if data == nil {
		return base, false, nil
	}
	out := copyRecord(base)
	for k, v := range data {
		out[k] = v
	}
	return out, true, nil
}

func callHook(ctx *Ctx, h Hook, d HookData) error {
	if h == nil {
		return nil
	}
	return h(ctx, d)
}

func withUser(m *memberWithUser) Record {
	if m == nil {
		return nil
	}
	r := copyRecord(m.Member)
	r["user"] = m.User
	return r
}

func setSessionCookie(ctx *Ctx, s *betterauth.Session, u *betterauth.User) error {
	if s == nil {
		return nil
	}
	return betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: s, User: u}, nil, nil)
}

func (p *plugin) createOrganization() *betterauth.Endpoint {
	base := []validate.Field{
		validate.F("name", validate.String().Min(1)),
		validate.F("slug", validate.String().Min(1)),
		validate.F("userId", validate.Optional(coerceString())),
		validate.F("logo", validate.Nullish(validate.String())),
		validate.F("metadata", validate.Optional(validate.Record(validate.Any()))),
		validate.F("keepCurrentActiveOrganization", validate.Optional(validate.Boolean())),
	}
	fields := mergeFields(base, additionalFieldsSchema(p.o.schema().Organization.AdditionalFields)...)
	return &betterauth.Endpoint{
		Key: "createOrganization", Path: "/organization/create", Methods: []string{"POST"},
		Body: validate.Object(fields...), Metadata: openapiMeta("/organization/create"),
		Handler: func(ctx *Ctx) (any, error) {
			body := ctx.BodyMap()
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if session == nil && (ctx.Request != nil || ctx.Headers != nil) {
				return nil, errStatus("UNAUTHORIZED")
			}
			var user *betterauth.User
			if session != nil {
				user = session.User
			}
			bodyUserID, _ := body["userId"].(string)
			if user == nil {
				if bodyUserID == "" {
					return nil, errStatus("UNAUTHORIZED")
				}
				user, err = ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), bodyUserID)
				if err != nil {
					return nil, err
				}
			}
			if user == nil {
				return nil, errStatus("UNAUTHORIZED")
			}
			o := p.o
			canCreate := true
			if o.AllowUserToCreateOrganizationFunc != nil {
				if canCreate, err = o.AllowUserToCreateOrganizationFunc(ctx, user); err != nil {
					return nil, err
				}
			} else if o.AllowUserToCreateOrganization != nil {
				canCreate = *o.AllowUserToCreateOrganization
			}
			isSystemAction := session == nil && bodyUserID != ""
			if !canCreate && !isSystemAction {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToCreateANewOrganization)
			}
			a := newAdapter(ctx, o)
			userOrgs, err := a.listOrganizations(user.ID)
			if err != nil {
				return nil, err
			}
			reached := false
			if o.OrganizationLimitFunc != nil {
				if reached, err = o.OrganizationLimitFunc(ctx, user); err != nil {
					return nil, err
				}
			} else if o.OrganizationLimit != nil {
				reached = len(userOrgs) >= *o.OrganizationLimit
			}
			if reached {
				return nil, errFrom("FORBIDDEN", ErrYouHaveReachedTheMaximumNumberOfOrganizations)
			}
			slug, _ := body["slug"].(string)
			existing, err := a.findOrganizationBySlug(slug)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationAlreadyExists)
			}
			orgData := copyRecord(body)
			delete(orgData, "keepCurrentActiveOrganization")
			delete(orgData, "userId")
			hooks := o.hooks()
			if hooks.BeforeCreateOrganization != nil {
				data, err := hooks.BeforeCreateOrganization(ctx, HookData{Organization: orgData, User: user})
				if err != nil {
					return nil, err
				}
				if data != nil {
					orgData = copyRecord(body)
					for k, v := range data {
						orgData[k] = v
					}
				}
			}
			orgData["createdAt"] = nowTime()
			organization, err := a.createOrganization(orgData)
			if err != nil {
				return nil, err
			}
			orgID := str(organization["id"])
			memberData := Record{"userId": user.ID, "organizationId": orgID, "role": o.creatorRole()}
			memberData, _, err = callBefore(ctx, hooks.BeforeAddMember, HookData{
				Member: Record{"userId": user.ID, "organizationId": orgID, "role": o.creatorRole()},
				User:   user, Organization: organization,
			}, memberData)
			if err != nil {
				return nil, err
			}
			member, err := a.createMember(memberData)
			if err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterAddMember, HookData{Member: member, User: user, Organization: organization}); err != nil {
				return nil, err
			}
			var teamMember Record
			if o.teamsEnabled() && (o.Teams.DefaultTeam == nil || o.Teams.DefaultTeam.Enabled == nil || *o.Teams.DefaultTeam.Enabled) {
				name := jsString(organization["name"])
				teamData := Record{"organizationId": orgID, "name": name, "createdAt": nowTime()}
				teamData, _, err = callBefore(ctx, hooks.BeforeCreateTeam, HookData{
					Team: Record{"organizationId": orgID, "name": name}, User: user, Organization: organization,
				}, teamData)
				if err != nil {
					return nil, err
				}
				var defaultTeam Record
				if dt := o.Teams.DefaultTeam; dt != nil && dt.CustomCreateDefaultTeam != nil {
					if defaultTeam, err = dt.CustomCreateDefaultTeam(ctx, organization); err != nil {
						return nil, err
					}
				}
				if defaultTeam == nil {
					if defaultTeam, err = a.createTeam(teamData); err != nil {
						return nil, err
					}
				}
				if teamMember, err = a.findOrCreateTeamMember(str(defaultTeam["id"]), user.ID); err != nil {
					return nil, err
				}
				if err := callHook(ctx, hooks.AfterCreateTeam, HookData{Team: defaultTeam, User: user, Organization: organization}); err != nil {
					return nil, err
				}
			}
			if err := callHook(ctx, hooks.AfterCreateOrganization, HookData{Organization: organization, User: user, Member: member}); err != nil {
				return nil, err
			}
			keep, _ := body["keepCurrentActiveOrganization"].(bool)
			if ctx.Session != nil && !keep {
				if _, err := a.setActiveOrganization(ctx.Session.Session.Token, orgID); err != nil {
					return nil, err
				}
			}
			if teamMember != nil && ctx.Session != nil && !keep {
				if _, err := a.setActiveTeam(ctx.Session.Session.Token, teamMember["teamId"]); err != nil {
					return nil, err
				}
			}
			out := p.orgObj(ctx, organization)
			out.Set("members", []any{p.memberObj(ctx, member, false)})
			return out, nil
		},
	}
}

func (p *plugin) checkOrganizationSlug() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "checkOrganizationSlug", Path: "/organization/check-slug", Methods: []string{"POST"},
		Body: validate.Object(validate.F("slug", validate.String())),
		Use:  []betterauth.Middleware{betterauth.RequestOnlySessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			org, err := newAdapter(ctx, p.o).findOrganizationBySlug(ctx.BodyString("slug"))
			if err != nil {
				return nil, err
			}
			if org == nil {
				return jsonx.O("status", true), nil
			}
			return nil, errFrom("BAD_REQUEST", ErrOrganizationSlugAlreadyTaken)
		},
	}
}

func (p *plugin) updateOrganization() *betterauth.Endpoint {
	base := []validate.Field{
		validate.F("name", validate.Optional(validate.String().Min(1))),
		validate.F("slug", validate.Optional(validate.String().Min(1))),
		validate.F("logo", validate.Nullish(validate.String())),
		validate.F("metadata", validate.Optional(validate.Record(validate.Any()))),
	}
	data := partialFields(mergeFields(additionalFieldsSchema(p.o.schema().Organization.AdditionalFields), base...))
	return &betterauth.Endpoint{
		Key: "updateOrganization", Path: "/organization/update", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("data", validate.Object(data...)),
			validate.F("organizationId", validate.Optional(validate.String())),
		),
		RequireHeaders: true, Metadata: openapiMeta("/organization/update"),
		Handler: func(ctx *Ctx) (any, error) {
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, errMsg("UNAUTHORIZED", "User not found")
			}
			body := ctx.BodyMap()
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			a := newAdapter(ctx, p.o)
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Permissions: Permissions{"organization": {"update"}}, Role: member.role(), OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateThisOrganization)
			}
			upd, _ := body["data"].(map[string]any)
			if slug, isStr := upd["slug"].(string); isStr {
				existing, err := a.findOrganizationBySlug(slug)
				if err != nil {
					return nil, err
				}
				if existing != nil && str(existing["id"]) != orgID {
					return nil, errFrom("BAD_REQUEST", ErrOrganizationSlugAlreadyTaken)
				}
			}
			hooks := p.o.hooks()
			upd, _, err = callBefore(ctx, hooks.BeforeUpdateOrganization, HookData{Organization: upd, User: session.User, Member: withUser(member)}, upd)
			if err != nil {
				return nil, err
			}
			updated, err := a.updateOrganization(orgID, upd)
			if err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterUpdateOrganization, HookData{Organization: updated, User: session.User, Member: withUser(member)}); err != nil {
				return nil, err
			}
			if updated == nil {
				return betterauth.Null, nil
			}
			return p.orgObj(ctx, updated), nil
		},
	}
}

func (p *plugin) deleteOrganization() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "deleteOrganization", Path: "/organization/delete", Methods: []string{"POST"},
		Body:           validate.Object(validate.F("organizationId", validate.String())),
		RequireHeaders: true, Metadata: openapiMeta("/organization/delete"),
		Handler: func(ctx *Ctx) (any, error) {
			if p.o.DisableOrganizationDeletion {
				return nil, errFrom("NOT_FOUND", betterauth.ErrorCode{Code: "ORGANIZATION_DELETION_DISABLED", Message: "Organization deletion is disabled"})
			}
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, errStatus("UNAUTHORIZED")
			}
			orgID := ctx.BodyString("organizationId")
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			a := newAdapter(ctx, p.o)
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsNotAMemberOfTheOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"organization": {"delete"}}, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToDeleteThisOrganization)
			}
			if orgID == activeOrgID(session) {
				if _, err := a.setActiveOrganization(session.Session.Token, nil); err != nil {
					return nil, err
				}
			}
			org, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if org == nil {
				return nil, errStatus("BAD_REQUEST")
			}
			hooks := p.o.hooks()
			if err := callHook(ctx, hooks.BeforeDeleteOrganization, HookData{Organization: org, User: session.User}); err != nil {
				return nil, err
			}
			if err := a.deleteOrganization(orgID); err != nil {
				return nil, err
			}
			if err := callHook(ctx, hooks.AfterDeleteOrganization, HookData{Organization: org, User: session.User}); err != nil {
				return nil, err
			}
			return p.orgObj(ctx, org), nil
		},
	}
}

func orgQueryFields() []validate.Field {
	return []validate.Field{
		validate.F("organizationId", validate.Optional(validate.String())),
		validate.F("organizationSlug", validate.Optional(validate.String())),
	}
}

func (p *plugin) getOrganization() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getOrganization", Path: "/organization/get-organization", Methods: []string{"GET"},
		Query:          validate.Optional(validate.Object(orgQueryFields()...)),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/get-organization"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			slug := ctx.QueryString("organizationSlug")
			orgID := slug
			if orgID == "" {
				orgID = ctx.QueryString("organizationId")
			}
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return betterauth.Null, nil
			}
			a := newAdapter(ctx, p.o)
			var org Record
			var err error
			if slug != "" {
				org, err = a.findOrganizationBySlug(orgID)
			} else {
				org, err = a.findOrganizationByID(orgID)
			}
			if err != nil {
				return nil, err
			}
			if org == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			isMember, err := a.checkMembership(session.User.ID, str(org["id"]))
			if err != nil {
				return nil, err
			}
			if isMember == nil {
				if _, err := a.setActiveOrganization(session.Session.Token, nil); err != nil {
					return nil, err
				}
				return nil, errFrom("FORBIDDEN", ErrUserIsNotAMemberOfTheOrganization)
			}
			return p.orgObj(ctx, org), nil
		},
	}
}

// membersLimitSchema is z.number().or(z.string().transform(parseInt)).
func membersLimitSchema() validate.Schema {
	return validate.Union(validate.Number(), validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		s, ok := v.(string)
		if !ok {
			return nil, []validate.Issue{validate.NewIssue(path, "invalid_type", "Invalid input: expected string, received "+jsTypeName(v))}
		}
		return parseIntJS(s), nil
	}))
}

func (p *plugin) getFullOrganization() *betterauth.Endpoint {
	fields := append(orgQueryFields(), validate.F("membersLimit", validate.Optional(membersLimitSchema())))
	return &betterauth.Endpoint{
		Key: "getFullOrganization", Path: "/organization/get-full-organization", Methods: []string{"GET"},
		Query:          validate.Optional(validate.Object(fields...)),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/get-full-organization"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			slug := ctx.QueryString("organizationSlug")
			orgID := slug
			if orgID == "" {
				orgID = ctx.QueryString("organizationId")
			}
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return betterauth.Null, nil
			}
			limit := 0
			if f, ok := ctx.Query["membersLimit"].(float64); ok && truthyNum(f) && !math.IsInf(f, 0) {
				limit = int(f)
			}
			a := newAdapter(ctx, p.o)
			full, err := a.findFullOrganization(orgID, slug != "", p.o.teamsEnabled(), limit)
			if err != nil {
				return nil, err
			}
			if full == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			isMember, err := a.checkMembership(session.User.ID, str(full.Org["id"]))
			if err != nil {
				return nil, err
			}
			if isMember == nil {
				if _, err := a.setActiveOrganization(session.Session.Token, nil); err != nil {
					return nil, err
				}
				return nil, errFrom("FORBIDDEN", ErrUserIsNotAMemberOfTheOrganization)
			}
			return p.fullOrgObj(ctx, full), nil
		},
	}
}

func (p *plugin) fullOrgObj(ctx *Ctx, full *fullOrganization) *jsonx.Object {
	out := p.orgObj(ctx, full.Org)
	invs := make([]any, len(full.Invitations))
	for i, inv := range full.Invitations {
		invs[i] = p.invitationObj(ctx, inv, true)
	}
	out.Set("invitations", invs)
	members := make([]any, len(full.Members))
	for i, m := range full.Members {
		members[i] = p.memberWithUserObj(ctx, m, true)
	}
	out.Set("members", members)
	if full.HasTeams {
		teams := make([]any, len(full.Teams))
		hidden := hiddenAdditional(p.o.schema().Team.AdditionalFields)
		for i, t := range full.Teams {
			teams[i] = objFor(ctx, "team", t, hidden)
		}
		out.Set("teams", teams)
	}
	return out
}

func (p *plugin) setActiveOrganization() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "setActiveOrganization", Path: "/organization/set-active", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("organizationId", validate.Nullish(validate.String())),
			validate.F("organizationSlug", validate.Optional(validate.String())),
		),
		Use:            []betterauth.Middleware{orgSessionMiddleware},
		RequireHeaders: true, Metadata: openapiMeta("/organization/set-active"),
		Handler: func(ctx *Ctx) (any, error) {
			a := newAdapter(ctx, p.o)
			session := ctx.Session
			body := ctx.BodyMap()
			rawID, hasID := body["organizationId"]
			orgID, _ := rawID.(string)
			slug, _ := body["organizationSlug"].(string)
			if hasID && rawID == nil {
				if activeOrgID(session) == "" {
					return betterauth.Null, nil
				}
				updated, err := a.setActiveOrganization(session.Session.Token, nil)
				if err != nil {
					return nil, err
				}
				if err := setSessionCookie(ctx, updated, session.User); err != nil {
					return nil, err
				}
				return betterauth.Null, nil
			}
			if orgID == "" && slug == "" {
				active := activeOrgID(session)
				if active == "" {
					return betterauth.Null, nil
				}
				orgID = active
			}
			if slug != "" && orgID == "" {
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
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			isMember, err := a.checkMembership(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if isMember == nil {
				if _, err := a.setActiveOrganization(session.Session.Token, nil); err != nil {
					return nil, err
				}
				return nil, errFrom("FORBIDDEN", ErrUserIsNotAMemberOfTheOrganization)
			}
			org, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if org == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			updated, err := a.setActiveOrganization(session.Session.Token, str(org["id"]))
			if err != nil {
				return nil, err
			}
			if err := setSessionCookie(ctx, updated, session.User); err != nil {
				return nil, err
			}
			return p.orgObj(ctx, org), nil
		},
	}
}

func (p *plugin) listOrganizations() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listOrganizations", Path: "/organization/list", Methods: []string{"GET"},
		Use:            []betterauth.Middleware{orgSessionMiddleware},
		RequireHeaders: true, Metadata: openapiMeta("/organization/list"),
		Handler: func(ctx *Ctx) (any, error) {
			orgs, err := newAdapter(ctx, p.o).listOrganizations(ctx.Session.User.ID)
			if err != nil {
				return nil, err
			}
			out := make([]any, len(orgs))
			for i, o := range orgs {
				out[i] = p.orgObj(ctx, o)
			}
			return out, nil
		},
	}
}
