package organization

import (
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// requireVerifiedEmailForInvitationID ports shouldRequireVerifiedEmailForInvitationIdAction:
// verification is required unless invitation ids are opaque (built-in random or uuid ids).
func (p *plugin) requireVerifiedEmailForInvitationID(ctx *Ctx) bool {
	if p.o.RequireEmailVerificationOnInvitation != nil {
		return *p.o.RequireEmailVerificationOnInvitation
	}
	adv := ctx.Auth.Options.Advanced
	if adv == nil || adv.Database == nil {
		return false
	}
	if adv.Database.GenerateIDFunc != nil {
		return true
	}
	switch adv.Database.GenerateID {
	case adapter.IDDefault, adapter.IDUUID:
		return false
	}
	return true
}

func invitationExpired(inv Record) bool {
	t, ok := adapter.ToTime(inv["expiresAt"])
	return ok && t.Before(time.Now())
}

func teamIDList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			s, _ := x.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

func (p *plugin) sendInvitationEmail(ctx *Ctx, inv Record, org Record, member *memberWithUser, user *betterauth.User) {
	send := p.o.SendInvitationEmail
	if send == nil {
		return
	}
	inviter := copyRecord(member.Member)
	inviter["user"] = user
	data := InvitationEmailData{
		ID: str(inv["id"]), Role: str(inv["role"]), Email: strings.ToLower(str(inv["email"])),
		Organization: org, Inviter: inviter, Invitation: inv,
	}
	ctx.Auth.RunInBackgroundOrAwait(func() error { return send(ctx, data, ctx.Request) })
}

func (p *plugin) createInvitation() *betterauth.Endpoint {
	base := []validate.Field{
		validate.F("email", validate.String()),
		validate.F("role", roleSchema()),
		validate.F("organizationId", validate.Optional(validate.String())),
		validate.F("resend", validate.Optional(validate.Boolean())),
		validate.F("teamId", validate.Union(validate.Optional(validate.String()), validate.Optional(validate.Array(validate.String())))),
	}
	fields := mergeFields(base, additionalFieldsSchema(p.o.schema().Invitation.AdditionalFields)...)
	return &betterauth.Endpoint{
		Key: "createInvitation", Path: "/organization/invite-member", Methods: []string{"POST"},
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Body: validate.Object(fields...), Metadata: openapiMeta("/organization/invite-member"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			body := ctx.BodyMap()
			o := p.o
			orgID, _ := body["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			email := strings.ToLower(str(body["email"]))
			if !validate.IsEmail(email) {
				return nil, errFrom("BAD_REQUEST", betterauth.ErrInvalidEmail)
			}
			a := newAdapter(ctx, o)
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"invitation": {"create"}}, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToInviteUsersToThisOrganization)
			}
			creatorRole := o.creatorRole()
			roles := parseRoles(body["role"])
			var rolesArray []string
			for _, r := range strings.Split(roles, ",") {
				if r = strings.TrimSpace(r); r != "" {
					rolesArray = append(rolesArray, r)
				}
			}
			invalid, err := p.invalidRoles(ctx, orgID, rolesArray)
			if err != nil {
				return nil, err
			}
			if len(invalid) > 0 {
				return nil, errMsg("BAD_REQUEST", ErrRoleNotFound.Code+": "+strings.Join(invalid, ", "))
			}
			if !contains(trimmedRoles(member.role()), creatorRole) && contains(splitRoles(roles), creatorRole) {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToInviteUserWithThisRole)
			}
			already, err := a.findMemberByEmail(email, orgID)
			if err != nil {
				return nil, err
			}
			if already != nil {
				return nil, errFrom("BAD_REQUEST", ErrUserIsAlreadyAMemberOfThisOrganization)
			}
			invited, err := a.findPendingInvitation(email, orgID)
			if err != nil {
				return nil, err
			}
			resend, _ := body["resend"].(bool)
			if len(invited) > 0 && !resend && !o.CancelPendingInvitationsOnReInvite {
				return nil, errFrom("BAD_REQUEST", ErrUserIsAlreadyInvitedToThisOrganization)
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			if len(invited) > 0 && resend {
				existing := invited[0]
				newExpires := time.Now().Add(o.invitationExpiresIn())
				if _, err := ctx.Auth.Adapter.Update(ctx.Context(), "invitation", []adapter.Where{eq("id", existing["id"])}, Record{"expiresAt": newExpires}); err != nil {
					return nil, err
				}
				updated := copyRecord(existing)
				updated["expiresAt"] = newExpires.UTC().Truncate(time.Millisecond)
				p.sendInvitationEmail(ctx, updated, organization, member, session.User)
				return p.invitationObj(ctx, updated, false), nil
			}
			if len(invited) > 0 && o.CancelPendingInvitationsOnReInvite {
				if _, err := a.updateInvitation(str(invited[0]["id"]), "canceled", ""); err != nil {
					return nil, err
				}
			}
			limit := 100
			if o.InvitationLimitFunc != nil {
				if limit, err = o.InvitationLimitFunc(ctx, InvitationLimitData{User: session.User, Organization: organization, Member: withUser(member)}); err != nil {
					return nil, err
				}
			} else if o.InvitationLimit != nil {
				limit = *o.InvitationLimit
			}
			pending, err := a.findPendingInvitations(orgID)
			if err != nil {
				return nil, err
			}
			if len(pending) >= limit {
				return nil, errFrom("FORBIDDEN", ErrInvitationLimitReached)
			}
			rawTeam, hasTeam := body["teamId"]
			requested := teamIDList(rawTeam)
			if o.teamsEnabled() && hasTeam && validate.Truthy(rawTeam) {
				for _, id := range requested {
					if strings.Contains(id, ",") {
						return nil, errFrom("BAD_REQUEST", ErrInvalidTeamId)
					}
				}
				for _, id := range requested {
					team, _, err := a.findTeamByID(id, orgID, false)
					if err != nil {
						return nil, err
					}
					if team == nil {
						return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
					}
				}
			}
			if o.teamsEnabled() && o.hasMaxMembersPerTeam() && hasTeam && validate.Truthy(rawTeam) {
				for _, id := range requested {
					team, members, err := a.findTeamByID(id, orgID, true)
					if err != nil {
						return nil, err
					}
					if team == nil {
						return nil, errFrom("BAD_REQUEST", ErrTeamNotFound)
					}
					max, err := o.maxMembersPerTeam(ctx, MaximumMembersPerTeamData{TeamID: id, Session: session, OrganizationID: orgID})
					if err != nil {
						return nil, err
					}
					if len(members) >= max {
						return nil, errFrom("FORBIDDEN", ErrTeamMemberLimitReached)
					}
				}
			}
			teamIDs := []string{}
			if hasTeam {
				teamIDs = append(teamIDs, requested...)
			}
			additional := copyRecord(body)
			for _, k := range []string{"email", "role", "organizationId", "resend"} {
				delete(additional, k)
			}
			invData := Record{"role": roles, "email": email, "organizationId": orgID}
			for k, v := range additional {
				invData[k] = v
			}
			hooks := o.hooks()
			if hooks.BeforeCreateInvitation != nil {
				hookInv := copyRecord(invData)
				hookInv["teamIds"] = teamIDs
				hookInv["inviterId"] = session.User.ID
				if len(teamIDs) > 0 {
					hookInv["teamId"] = teamIDs[0]
				} else {
					delete(hookInv, "teamId")
				}
				data, err := hooks.BeforeCreateInvitation(ctx, HookData{Invitation: hookInv, Inviter: session.User, Organization: organization})
				if err != nil {
					return nil, err
				}
				for k, v := range data {
					if k == "teamIds" {
						teamIDs = teamIDList(v)
						continue
					}
					invData[k] = v
				}
			}
			invitation, err := a.createInvitation(invData, teamIDs, session.User)
			if err != nil {
				return nil, err
			}
			p.sendInvitationEmail(ctx, invitation, organization, member, session.User)
			if err := callHook(ctx, hooks.AfterCreateInvitation, HookData{Invitation: invitation, Inviter: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			return p.invitationObj(ctx, invitation, false), nil
		},
	}
}

func (p *plugin) acceptInvitation() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "acceptInvitation", Path: "/organization/accept-invitation", Methods: []string{"POST"},
		Body:           validate.Object(validate.F("invitationId", validate.String())),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/accept-invitation"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			o := p.o
			a := newAdapter(ctx, o)
			invID := ctx.BodyString("invitationId")
			invitation, err := a.findInvitationByID(invID)
			if err != nil {
				return nil, err
			}
			if invitation == nil || invitationExpired(invitation) || str(invitation["status"]) != "pending" {
				return nil, errFrom("BAD_REQUEST", ErrInvitationNotFound)
			}
			if strings.ToLower(str(invitation["email"])) != strings.ToLower(session.User.Email) {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotTheRecipientOfTheInvitation)
			}
			if p.requireVerifiedEmailForInvitationID(ctx) && !session.User.EmailVerified {
				return nil, errFrom("FORBIDDEN", ErrEmailVerificationRequiredBeforeAcceptingOrRejectingInvitation)
			}
			orgID := str(invitation["organizationId"])
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
			limit, err := o.membershipLimit(ctx, session.User, organization)
			if err != nil {
				return nil, err
			}
			if count >= int64(limit) {
				return nil, errFrom("FORBIDDEN", ErrOrganizationMembershipLimitReached)
			}
			hooks := o.hooks()
			if err := callHook(ctx, hooks.BeforeAcceptInvitation, HookData{Invitation: invitation, User: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			accepted, err := a.updateInvitation(invID, "accepted", "pending")
			if err != nil {
				return nil, err
			}
			if accepted == nil {
				return nil, errFrom("BAD_REQUEST", ErrInvitationNotFound)
			}
			var member Record
			txErr := ctx.Transaction(func() error {
				if o.teamsEnabled() {
					if tid := str(accepted["teamId"]); tid != "" {
						teamIDs := strings.Split(tid, ",")
						for _, teamID := range teamIDs {
							team, _, err := a.findTeamByID(teamID, str(accepted["organizationId"]), false)
							if err != nil {
								return err
							}
							if team == nil {
								return errFrom("BAD_REQUEST", ErrTeamNotFound)
							}
							if o.hasMaxMembersPerTeam() {
								max, err := o.maxMembersPerTeam(ctx, MaximumMembersPerTeamData{TeamID: teamID, Session: session, OrganizationID: str(accepted["organizationId"])})
								if err != nil {
									return err
								}
								_, reached, err := a.addTeamMemberWithLimit(teamID, session.User.ID, max)
								if err != nil {
									return err
								}
								if reached {
									return errFrom("FORBIDDEN", ErrTeamMemberLimitReached)
								}
							} else if _, err := a.findOrCreateTeamMember(teamID, session.User.ID); err != nil {
								return err
							}
						}
						if len(teamIDs) == 1 {
							updated, err := a.setActiveTeam(session.Session.Token, teamIDs[0])
							if err != nil {
								return err
							}
							if err := setSessionCookie(ctx, updated, session.User); err != nil {
								return err
							}
						}
					}
				}
				var err error
				member, err = a.createMember(Record{"organizationId": accepted["organizationId"], "userId": session.User.ID, "role": accepted["role"]})
				if err != nil {
					return err
				}
				_, err = a.setActiveOrganization(session.Session.Token, accepted["organizationId"])
				return err
			})
			if txErr != nil {
				if _, err := a.updateInvitation(invID, "pending", "accepted"); err != nil {
					return nil, err
				}
				return nil, txErr
			}
			if err := callHook(ctx, hooks.AfterAcceptInvitation, HookData{Invitation: accepted, Member: member, User: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			return jsonx.O("invitation", p.invitationObj(ctx, accepted, false), "member", p.memberObj(ctx, member, false)), nil
		},
	}
}

func (p *plugin) rejectInvitation() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "rejectInvitation", Path: "/organization/reject-invitation", Methods: []string{"POST"},
		Body:           validate.Object(validate.F("invitationId", validate.String())),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/reject-invitation"),
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			a := newAdapter(ctx, p.o)
			invID := ctx.BodyString("invitationId")
			invitation, err := a.findInvitationByID(invID)
			if err != nil {
				return nil, err
			}
			if invitation == nil || str(invitation["status"]) != "pending" {
				return nil, errFrom("BAD_REQUEST", betterauth.ErrorCode{Code: "INVITATION_NOT_FOUND", Message: "Invitation not found!"})
			}
			if strings.ToLower(str(invitation["email"])) != strings.ToLower(session.User.Email) {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotTheRecipientOfTheInvitation)
			}
			if p.requireVerifiedEmailForInvitationID(ctx) && !session.User.EmailVerified {
				return nil, errFrom("FORBIDDEN", ErrEmailVerificationRequiredBeforeAcceptingOrRejectingInvitation)
			}
			organization, err := a.findOrganizationByID(str(invitation["organizationId"]))
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			hooks := p.o.hooks()
			if err := callHook(ctx, hooks.BeforeRejectInvitation, HookData{Invitation: invitation, User: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			rejected, err := a.updateInvitation(invID, "rejected", "")
			if err != nil {
				return nil, err
			}
			hookInv := rejected
			if hookInv == nil {
				hookInv = invitation
			}
			if err := callHook(ctx, hooks.AfterRejectInvitation, HookData{Invitation: hookInv, User: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			return jsonx.O("invitation", p.invitationObj(ctx, rejected, false), "member", nil), nil
		},
	}
}

func (p *plugin) cancelInvitation() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "cancelInvitation", Path: "/organization/cancel-invitation", Methods: []string{"POST"},
		Body:           validate.Object(validate.F("invitationId", validate.String())),
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session := ctx.Session
			a := newAdapter(ctx, p.o)
			invID := ctx.BodyString("invitationId")
			invitation, err := a.findInvitationByID(invID)
			if err != nil {
				return nil, err
			}
			if invitation == nil {
				return nil, errFrom("BAD_REQUEST", ErrInvitationNotFound)
			}
			orgID := str(invitation["organizationId"])
			member, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrMemberNotFound)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: Permissions{"invitation": {"cancel"}}, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToCancelThisInvitation)
			}
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			hooks := p.o.hooks()
			if err := callHook(ctx, hooks.BeforeCancelInvitation, HookData{Invitation: invitation, CancelledBy: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			canceled, err := a.updateInvitation(invID, "canceled", "")
			if err != nil {
				return nil, err
			}
			hookInv := canceled
			if hookInv == nil {
				hookInv = invitation
			}
			if err := callHook(ctx, hooks.AfterCancelInvitation, HookData{Invitation: hookInv, CancelledBy: session.User, Organization: organization}); err != nil {
				return nil, err
			}
			if canceled == nil {
				return betterauth.Null, nil
			}
			return p.invitationObj(ctx, canceled, false), nil
		},
	}
}

func (p *plugin) getInvitation() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getInvitation", Path: "/organization/get-invitation", Methods: []string{"GET"},
		RequireHeaders: true, Query: validate.Object(validate.F("id", validate.String())),
		Metadata: openapiMeta("/organization/get-invitation"),
		Handler: func(ctx *Ctx) (any, error) {
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, errMsg("UNAUTHORIZED", "Not authenticated")
			}
			a := newAdapter(ctx, p.o)
			invitation, err := a.findInvitationByID(ctx.QueryString("id"))
			if err != nil {
				return nil, err
			}
			if invitation == nil || str(invitation["status"]) != "pending" || invitationExpired(invitation) {
				return nil, errMsg("BAD_REQUEST", "Invitation not found!")
			}
			if strings.ToLower(str(invitation["email"])) != strings.ToLower(session.User.Email) {
				return nil, errFrom("FORBIDDEN", ErrYouAreNotTheRecipientOfTheInvitation)
			}
			if p.requireVerifiedEmailForInvitationID(ctx) && !session.User.EmailVerified {
				return nil, errFrom("FORBIDDEN", ErrEmailVerificationRequiredForInvitation)
			}
			orgID := str(invitation["organizationId"])
			organization, err := a.findOrganizationByID(orgID)
			if err != nil {
				return nil, err
			}
			if organization == nil {
				return nil, errFrom("BAD_REQUEST", ErrOrganizationNotFound)
			}
			member, err := a.findMemberByOrgID(str(invitation["inviterId"]), orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("BAD_REQUEST", ErrInviterIsNoLongerAMemberOfTheOrganization)
			}
			out := p.invitationObj(ctx, invitation, false)
			out.Set("organizationName", organization["name"])
			out.Set("organizationSlug", organization["slug"])
			email, _ := member.User.Get("email")
			out.Set("inviterEmail", email)
			return out, nil
		},
	}
}

func (p *plugin) listInvitations() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listInvitations", Path: "/organization/list-invitations", Methods: []string{"GET"},
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Query: validate.Optional(validate.Object(validate.F("organizationId", validate.Optional(validate.String())))),
		Handler: func(ctx *Ctx) (any, error) {
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, errMsg("UNAUTHORIZED", "Not authenticated")
			}
			orgID := ctx.QueryString("organizationId")
			if orgID == "" {
				orgID = activeOrgID(session)
			}
			if orgID == "" {
				return nil, errMsg("BAD_REQUEST", "Organization ID is required")
			}
			a := newAdapter(ctx, p.o)
			isMember, err := a.findMemberByOrgID(session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if isMember == nil {
				return nil, errMsg("FORBIDDEN", "You are not a member of this organization")
			}
			invs, err := a.listInvitations(orgID)
			if err != nil {
				return nil, err
			}
			out := make([]any, len(invs))
			for i, inv := range invs {
				out[i] = p.invitationObj(ctx, inv, false)
			}
			return out, nil
		},
	}
}

func (p *plugin) listUserInvitations() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listUserInvitations", Path: "/organization/list-user-invitations", Methods: []string{"GET"},
		Query:    validate.Optional(validate.Object(validate.F("email", validate.Optional(validate.String())))),
		Metadata: openapiMeta("/organization/list-user-invitations"),
		Handler: func(ctx *Ctx) (any, error) {
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			qEmail := ctx.QueryString("email")
			if ctx.Request != nil && qEmail != "" {
				return nil, errMsg("BAD_REQUEST", "User email cannot be passed for client side API calls.")
			}
			if session != nil && !session.User.EmailVerified {
				return nil, errFrom("FORBIDDEN", ErrEmailVerificationRequiredForInvitation)
			}
			email := qEmail
			if session != nil && session.User.Email != "" {
				email = session.User.Email
			}
			if email == "" {
				return nil, errMsg("BAD_REQUEST", "Missing session headers, or email query parameter.")
			}
			invs, err := newAdapter(ctx, p.o).listUserInvitations(email)
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, inv := range invs {
				if str(inv["status"]) == "pending" {
					out = append(out, p.invitationObj(ctx, inv, false))
				}
			}
			return out, nil
		},
	}
}
