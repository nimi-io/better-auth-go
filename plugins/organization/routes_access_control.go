package organization

import (
	"math"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

const dacDocs = "\nPlease refer to the documentation here: https://better-auth.com/docs/plugins/organization#dynamic-access-control"

func (p *plugin) roleAdditionalFields(partial bool) []validate.Field {
	fields := append([]db.Field(nil), p.o.schema().OrganizationRole.AdditionalFields...)
	if partial {
		for i := range fields {
			fields[i].Required = db.False
		}
	}
	return additionalFieldsSchema(fields)
}

// orgIDFrom is `value ?? session.activeOrganizationId`.
func orgIDFrom(m map[string]any, s *betterauth.SessionWithUser) string {
	if v, ok := m["organizationId"]; ok && v != nil {
		id, _ := v.(string)
		return id
	}
	return activeOrgID(s)
}

func (p *plugin) findRoleMember(ctx *Ctx, orgID, userID string) (Record, error) {
	return ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "member", Where: []adapter.Where{
		eq("organizationId", orgID), eq("userId", userID),
	}})
}

func (p *plugin) predefinedRoleNames() []string {
	if p.o.Roles != nil {
		return sortedKeys(p.o.Roles)
	}
	return []string{"owner", "admin", "member"}
}

func (p *plugin) checkRoleNameTakenByPredefined(ctx *Ctx, role string) error {
	if contains(p.predefinedRoleNames(), role) {
		ctx.Auth.Logger.Error(`[Dynamic Access Control] The role name "` + role + `" is already taken by a pre-defined role.`)
		return errFrom("BAD_REQUEST", ErrRoleNameIsAlreadyTaken)
	}
	return nil
}

func (p *plugin) checkRoleNameTakenInDB(ctx *Ctx, orgID, role string) error {
	existing, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "organizationRole", Where: []adapter.Where{
		eq("organizationId", orgID), eq("role", role),
	}})
	if err != nil {
		return err
	}
	if existing != nil {
		ctx.Auth.Logger.Error(`[Dynamic Access Control] The role name "` + role + `" is already taken by a role in the database.`)
		return errFrom("BAD_REQUEST", ErrRoleNameIsAlreadyTaken)
	}
	return nil
}

func (p *plugin) checkForInvalidResources(ctx *Ctx, perms Permissions) error {
	for r := range perms {
		if _, ok := p.o.AC.Statements[r]; !ok {
			ctx.Auth.Logger.Error("[Dynamic Access Control] The provided permission includes an invalid resource.")
			return errFrom("BAD_REQUEST", ErrInvalidResource)
		}
	}
	return nil
}

func (p *plugin) checkIfMemberHasPermission(ctx *Ctx, member Record, orgID string, perms Permissions, action string) error {
	var missing []any
	for _, resource := range sortedKeys(perms) {
		for _, perm := range perms[resource] {
			ok, err := p.hasPermission(ctx, HasPermissionInput{OrganizationID: orgID, Permissions: Permissions{resource: {perm}}, UseMemoryCache: true, Role: str(member["role"])})
			if err != nil {
				return err
			}
			if !ok {
				missing = append(missing, resource+":"+perm)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	ctx.Auth.Logger.Error("[Dynamic Access Control] The user is missing permissions necessary to " + action + " a role with those set of permissions.\n")
	var code betterauth.ErrorCode
	switch action {
	case "create":
		code = ErrYouAreNotAllowedToCreateARole
	case "update":
		code = ErrYouAreNotAllowedToUpdateARole
	case "delete":
		code = ErrYouAreNotAllowedToDeleteARole
	case "read":
		code = ErrYouAreNotAllowedToReadARole
	case "list":
		code = ErrYouAreNotAllowedToListARole
	default:
		code = ErrYouAreNotAllowedToGetARole
	}
	return betterauth.NewAPIError("FORBIDDEN", jsonx.O("message", code.Message, "code", code.Code, "missingPermissions", missing))
}

func (p *plugin) roleObj(ctx *Ctx, rec Record) *jsonx.Object {
	return objFor(ctx, "organizationRole", rec, nil)
}

func parsePermissionValue(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	parsed, err := jsonx.Parse([]byte(s))
	if err != nil {
		return nil
	}
	return parsed
}

func (p *plugin) missingAC(ctx *Ctx) error {
	ctx.Auth.Logger.Error("[Dynamic Access Control] The organization plugin is missing a pre-defined ac instance.", dacDocs)
	return errFrom("NOT_IMPLEMENTED", ErrMissingAcInstance)
}

func (p *plugin) createOrgRole() *betterauth.Endpoint {
	body := validate.Object(
		validate.F("organizationId", validate.Optional(validate.String())),
		validate.F("role", validate.String()),
		validate.F("permission", permissionsRecord()),
		validate.F("additionalFields", validate.Optional(validate.Object(p.roleAdditionalFields(false)...))),
	)
	return &betterauth.Endpoint{
		Key: "createOrgRole", Path: "/organization/create-role", Methods: []string{"POST"},
		Body: body, RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session, user := ctx.Session, ctx.Session.User
			b := ctx.BodyMap()
			perms, _ := toPermissions(b["permission"])
			additional, _ := b["additionalFields"].(map[string]any)
			if p.o.AC == nil {
				return nil, p.missingAC(ctx)
			}
			orgID := orgIDFrom(b, session)
			if orgID == "" {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The session is missing an active organization id to create a role. Either set an active org id, or pass an organizationId in the request body.")
				return nil, errFrom("BAD_REQUEST", ErrYouMustBeInAnOrganizationToCreateARole)
			}
			roleName := strings.ToLower(str(b["role"]))
			if err := p.checkRoleNameTakenByPredefined(ctx, roleName); err != nil {
				return nil, err
			}
			member, err := p.findRoleMember(ctx, orgID, user.ID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not a member of the organization to create a role.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{OrganizationID: orgID, Permissions: Permissions{"ac": {"create"}}, Role: str(member["role"])})
			if err != nil {
				return nil, err
			}
			if !ok {
				ctx.Auth.Logger.Error(`[Dynamic Access Control] The user is not permitted to create a role. If this is unexpected, please make sure the role associated to that member has the "ac" resource with the "create" permission.`)
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToCreateARole)
			}
			max := math.Inf(1)
			if dac := p.o.DynamicAccessControl; dac.MaximumRolesPerOrganizationFunc != nil {
				n, err := dac.MaximumRolesPerOrganizationFunc(ctx, orgID)
				if err != nil {
					return nil, err
				}
				max = float64(n)
			} else if dac.MaximumRolesPerOrganization != nil {
				max = float64(*dac.MaximumRolesPerOrganization)
			}
			count, err := ctx.Auth.Adapter.Count(ctx.Context(), "organizationRole", []adapter.Where{eq("organizationId", orgID)})
			if err != nil {
				return nil, err
			}
			if float64(count) >= max {
				ctx.Auth.Logger.Error("[Dynamic Access Control] Failed to create a new role, the organization has too many roles. Maximum allowed roles is " + jsonx.FormatNumber(max) + ".")
				return nil, errFrom("BAD_REQUEST", ErrTooManyRoles)
			}
			if err := p.checkForInvalidResources(ctx, perms); err != nil {
				return nil, err
			}
			if err := p.checkIfMemberHasPermission(ctx, member, orgID, perms, "create"); err != nil {
				return nil, err
			}
			if err := p.checkRoleNameTakenInDB(ctx, orgID, roleName); err != nil {
				return nil, err
			}
			permJSON, err := jsonx.Stringify(permissionsObject(perms))
			if err != nil {
				return nil, err
			}
			data := Record{"createdAt": nowTime(), "organizationId": orgID, "permission": permJSON, "role": roleName}
			for k, v := range additional {
				data[k] = v
			}
			created, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: "organizationRole", Data: data})
			if err != nil {
				return nil, err
			}
			created["permission"] = permissionsObject(perms)
			return jsonx.O("success", true, "roleData", p.roleObj(ctx, created), "statements", permissionsObject(perms)), nil
		},
	}
}

func roleNameOrID() validate.Schema {
	return validate.Union(
		validate.Object(validate.F("roleName", validate.String().NonEmpty())),
		validate.Object(validate.F("roleId", validate.String().NonEmpty())),
	)
}

// roleCondition returns the where clause selecting a role by name or id.
func roleCondition(m map[string]any) (adapter.Where, bool) {
	if s, _ := m["roleName"].(string); s != "" {
		return eq("role", s), true
	}
	if s, _ := m["roleId"].(string); s != "" {
		return eq("id", s), true
	}
	return adapter.Where{}, false
}

func (p *plugin) deleteOrgRole() *betterauth.Endpoint {
	body := validate.And(validate.Object(validate.F("organizationId", validate.Optional(validate.String()))), roleNameOrID())
	return &betterauth.Endpoint{
		Key: "deleteOrgRole", Path: "/organization/delete-role", Methods: []string{"POST"},
		Body: body, RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session, user := ctx.Session, ctx.Session.User
			b := ctx.BodyMap()
			orgID := orgIDFrom(b, session)
			if orgID == "" {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The session is missing an active organization id to delete a role. Either set an active org id, or pass an organizationId in the request body.")
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			member, err := p.findRoleMember(ctx, orgID, user.ID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not a member of the organization to delete a role.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{OrganizationID: orgID, Permissions: Permissions{"ac": {"delete"}}, Role: str(member["role"])})
			if err != nil {
				return nil, err
			}
			if !ok {
				ctx.Auth.Logger.Error(`[Dynamic Access Control] The user is not permitted to delete a role. If this is unexpected, please make sure the role associated to that member has the "ac" resource with the "delete" permission.`)
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToDeleteARole)
			}
			if name, _ := b["roleName"].(string); name != "" && contains(p.predefinedRoleNames(), name) {
				ctx.Auth.Logger.Error("[Dynamic Access Control] Cannot delete a pre-defined role.")
				return nil, errFrom("BAD_REQUEST", ErrCannotDeleteAPreDefinedRole)
			}
			cond, ok := roleCondition(b)
			if !ok {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The role name/id is not provided in the request body.")
				return nil, errFrom("BAD_REQUEST", ErrRoleNotFound)
			}
			where := []adapter.Where{eq("organizationId", orgID), cond}
			existing, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "organizationRole", Where: where})
			if err != nil {
				return nil, err
			}
			if existing == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The role name/id does not exist in the database.")
				return nil, errFrom("BAD_REQUEST", ErrRoleNotFound)
			}
			roleToDelete := str(existing["role"])
			members, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "member", Where: []adapter.Where{
				eq("organizationId", orgID), {Field: "role", Value: roleToDelete, Operator: adapter.Contains},
			}})
			if err != nil {
				return nil, err
			}
			for _, m := range members {
				if contains(trimmedRoles(str(m["role"])), roleToDelete) {
					ctx.Auth.Logger.Error("[Dynamic Access Control] Cannot delete a role that is assigned to members.")
					return nil, errFrom("BAD_REQUEST", ErrRoleIsAssignedToMembers)
				}
			}
			if err := ctx.Auth.Adapter.Delete(ctx.Context(), "organizationRole", where); err != nil {
				return nil, err
			}
			return jsonx.O("success", true), nil
		},
	}
}

func (p *plugin) listOrgRoles() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listOrgRoles", Path: "/organization/list-roles", Methods: []string{"GET"},
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Query: validate.Optional(validate.Object(validate.F("organizationId", validate.Optional(validate.String())))),
		Handler: func(ctx *Ctx) (any, error) {
			session, user := ctx.Session, ctx.Session.User
			orgID := orgIDFrom(ctx.Query, session)
			if orgID == "" {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The session is missing an active organization id to list roles. Either set an active org id, or pass an organizationId in the request query.")
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			member, err := p.findRoleMember(ctx, orgID, user.ID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not a member of the organization to list roles.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{OrganizationID: orgID, Permissions: Permissions{"ac": {"read"}}, Role: str(member["role"])})
			if err != nil {
				return nil, err
			}
			if !ok {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not permitted to list roles.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToListARole)
			}
			roles, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "organizationRole", Where: []adapter.Where{eq("organizationId", orgID)}})
			if err != nil {
				return nil, err
			}
			out := make([]any, len(roles))
			for i, r := range roles {
				r["permission"] = parsePermissionValue(r["permission"])
				out[i] = p.roleObj(ctx, r)
			}
			return out, nil
		},
	}
}

func (p *plugin) getOrgRole() *betterauth.Endpoint {
	query := validate.Optional(validate.And(validate.Object(validate.F("organizationId", validate.Optional(validate.String()))), roleNameOrID()))
	return &betterauth.Endpoint{
		Key: "getOrgRole", Path: "/organization/get-role", Methods: []string{"GET"},
		RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware}, Query: query,
		Handler: func(ctx *Ctx) (any, error) {
			session, user := ctx.Session, ctx.Session.User
			orgID := orgIDFrom(ctx.Query, session)
			if orgID == "" {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The session is missing an active organization id to read a role. Either set an active org id, or pass an organizationId in the request query.")
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			member, err := p.findRoleMember(ctx, orgID, user.ID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not a member of the organization to read a role.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{OrganizationID: orgID, Permissions: Permissions{"ac": {"read"}}, Role: str(member["role"])})
			if err != nil {
				return nil, err
			}
			if !ok {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not permitted to read a role.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToReadARole)
			}
			cond, ok := roleCondition(ctx.Query)
			if !ok {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The role name/id is not provided in the request query.")
				return nil, errFrom("BAD_REQUEST", ErrRoleNotFound)
			}
			role, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "organizationRole", Where: []adapter.Where{eq("organizationId", orgID), cond}})
			if err != nil {
				return nil, err
			}
			if role == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The role name/id does not exist in the database.")
				return nil, errFrom("BAD_REQUEST", ErrRoleNotFound)
			}
			role["permission"] = parsePermissionValue(role["permission"])
			return p.roleObj(ctx, role), nil
		},
	}
}

func (p *plugin) updateOrgRole() *betterauth.Endpoint {
	data := mergeFields([]validate.Field{
		validate.F("permission", validate.Optional(permissionsRecord())),
		validate.F("roleName", validate.Optional(validate.String())),
	}, p.roleAdditionalFields(true)...)
	body := validate.And(validate.Object(
		validate.F("organizationId", validate.Optional(validate.String())),
		validate.F("data", validate.Object(data...)),
	), roleNameOrID())
	return &betterauth.Endpoint{
		Key: "updateOrgRole", Path: "/organization/update-role", Methods: []string{"POST"},
		Body: body, RequireHeaders: true, Use: []betterauth.Middleware{orgSessionMiddleware},
		Handler: func(ctx *Ctx) (any, error) {
			session, user := ctx.Session, ctx.Session.User
			b := ctx.BodyMap()
			if p.o.AC == nil {
				return nil, p.missingAC(ctx)
			}
			orgID := orgIDFrom(b, session)
			if orgID == "" {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The session is missing an active organization id to update a role. Either set an active org id, or pass an organizationId in the request body.")
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			member, err := p.findRoleMember(ctx, orgID, user.ID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not a member of the organization to update a role.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAMemberOfThisOrganization)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{OrganizationID: orgID, Role: str(member["role"]), Permissions: Permissions{"ac": {"update"}}})
			if err != nil {
				return nil, err
			}
			if !ok {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The user is not permitted to update a role.")
				return nil, errFrom("FORBIDDEN", ErrYouAreNotAllowedToUpdateARole)
			}
			cond, ok := roleCondition(b)
			if !ok {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The role name/id is not provided in the request body.")
				return nil, errFrom("BAD_REQUEST", ErrRoleNotFound)
			}
			where := []adapter.Where{eq("organizationId", orgID), cond}
			role, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "organizationRole", Where: where})
			if err != nil {
				return nil, err
			}
			if role == nil {
				ctx.Auth.Logger.Error("[Dynamic Access Control] The role name/id does not exist in the database.")
				return nil, errFrom("BAD_REQUEST", ErrRoleNotFound)
			}
			if s, _ := role["permission"].(string); s != "" {
				role["permission"] = parsePermissionValue(s)
			} else {
				role["permission"] = jsonx.Undefined
			}
			d, _ := b["data"].(map[string]any)
			update := Record{}
			for k, v := range d {
				if k != "permission" && k != "roleName" {
					update[k] = v
				}
			}
			var newPerms Permissions
			if raw, ok := d["permission"]; ok && raw != nil {
				newPerms, _ = toPermissions(raw)
				if err := p.checkForInvalidResources(ctx, newPerms); err != nil {
					return nil, err
				}
				if err := p.checkIfMemberHasPermission(ctx, member, orgID, newPerms, "update"); err != nil {
					return nil, err
				}
			}
			if name, _ := d["roleName"].(string); name != "" {
				name = strings.ToLower(name)
				if err := p.checkRoleNameTakenByPredefined(ctx, name); err != nil {
					return nil, err
				}
				if err := p.checkRoleNameTakenInDB(ctx, orgID, name); err != nil {
					return nil, err
				}
				update["role"] = name
			}
			if newPerms != nil {
				s, err := jsonx.Stringify(permissionsObject(newPerms))
				if err != nil {
					return nil, err
				}
				update["permission"] = s
			}
			if _, err := ctx.Auth.Adapter.UpdateMany(ctx.Context(), "organizationRole", where, update); err != nil {
				return nil, err
			}
			roleData := copyRecord(role)
			for k, v := range update {
				roleData[k] = v
			}
			switch {
			case newPerms != nil:
				roleData["permission"] = permissionsObject(newPerms)
			case role["permission"] != jsonx.Undefined && role["permission"] != nil:
				roleData["permission"] = role["permission"]
			default:
				roleData["permission"] = nil
			}
			return jsonx.O("success", true, "roleData", p.roleObj(ctx, roleData)), nil
		},
	}
}
