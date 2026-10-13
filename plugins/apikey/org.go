package apikey

import (
	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// API key permission actions on organization-owned keys (API_KEY_PERMISSIONS).
const (
	actionCreate = "create"
	actionRead   = "read"
	actionUpdate = "update"
	actionDelete = "delete"
)

// OrganizationPermissionChecker may be implemented by the organization plugin's Options
// (Plugin.Options) to answer hasPermission for organization-owned API keys. When the
// options don't implement it, the plugin resolves the roles itself from exported
// `Roles`, `CreatorRole`, `AC` and `DynamicAccessControl` fields, falling back to the
// default organization roles.
type OrganizationPermissionChecker interface {
	HasPermission(ctx *betterauth.EndpointContext, role, organizationID string, permissions map[string][]string, allowCreatorAllPermissions bool) (bool, error)
}

// member is a row of the organization "member" table.
type member struct {
	ID             string
	UserID         string
	OrganizationID string
	Role           string
}

// checkOrgPermission is checkOrgApiKeyPermission.
func (p *plugin) checkOrgPermission(ctx *betterauth.EndpointContext, userID, organizationID, action string) (*member, error) {
	org := ctx.Auth.GetPlugin("organization")
	if org == nil {
		return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrOrganizationPluginRequired)
	}
	rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "member", Where: []adapter.Where{
		{Field: "userId", Value: userID}, {Field: "organizationId", Value: organizationID},
	}})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, betterauth.ErrFrom("FORBIDDEN", ErrUserNotMemberOfOrganization)
	}
	m := &member{ID: adapter.ToString(rec["id"]), UserID: adapter.ToString(rec["userId"]),
		OrganizationID: adapter.ToString(rec["organizationId"]), Role: adapter.ToString(rec["role"])}
	ok, err := hasOrgPermission(ctx, org.Options, m.Role, organizationID, action)
	if err != nil || !ok {
		return nil, betterauth.ErrFrom("FORBIDDEN", ErrInsufficientAPIKeyPermissions)
	}
	return m, nil
}

// defaultOrgRoles are the organization plugin's default roles (organization/access).
var defaultOrgRoles = map[string]access.Statements{
	"admin": {
		"organization": {"update"}, "invitation": {"create", "cancel"}, "member": {"create", "update", "delete"},
		"team": {"create", "update", "delete"}, "ac": {"create", "read", "update", "delete"},
	},
	"owner": {
		"organization": {"update", "delete"}, "member": {"create", "update", "delete"},
		"invitation": {"create", "cancel"}, "team": {"create", "update", "delete"},
		"ac": {"create", "read", "update", "delete"},
	},
	"member": {
		"organization": {}, "member": {}, "invitation": {}, "team": {}, "ac": {"read"},
	},
}

// hasOrgPermission is hasPermission({role, options, permissions: {apiKey: [action]},
// organizationId, allowCreatorAllPermissions: true}). Errors deny access.
func hasOrgPermission(ctx *betterauth.EndpointContext, orgOptions any, role, organizationID, action string) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			ok, err = false, nil
		}
	}()
	perms := map[string][]string{"apiKey": {action}}
	if c, isChecker := orgOptions.(OrganizationPermissionChecker); isChecker {
		return c.HasPermission(ctx, role, organizationID, perms, true)
	}
	// Without the organization plugin's checker (e.g. a custom plugin registered under the
	// "organization" id), fall back to the default organization roles.
	statements, known := defaultOrgRoles[role]
	if !known {
		return false, nil
	}
	res, err := access.NewRole(statements).Authorize(jsonx.O("apiKey", []string{action}), access.AND)
	if err != nil {
		return false, err
	}
	return res.Success, nil
}
