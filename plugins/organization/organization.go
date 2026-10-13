// Package organization ports Better Auth's organization plugin
// (packages/better-auth/src/plugins/organization, v1.7.7): organizations, members,
// invitations, teams, role-based access control with optional dynamic (per-organization)
// roles, and the active organization / team on the session.
package organization

import (
	"sync"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// ID is the plugin id.
const ID = "organization"

// Version is the upstream version this port follows.
const Version = "1.7.7"

type plugin struct {
	o     *Options
	cache roleCache
}

var registry sync.Map // *Options -> *plugin

func statesFor(o *Options) *plugin {
	if v, ok := registry.Load(o); ok {
		return v.(*plugin)
	}
	v, _ := registry.LoadOrStore(o, &plugin{o: o})
	return v.(*plugin)
}

// New creates the organization plugin.
func New(opts Options) *betterauth.Plugin {
	o := &opts
	p := statesFor(o)

	eps := []*betterauth.Endpoint{
		p.createOrganization(),
		p.updateOrganization(),
		p.deleteOrganization(),
		p.setActiveOrganization(),
		p.getOrganization(),
		p.getFullOrganization(),
		p.listOrganizations(),
		p.createInvitation(),
		p.cancelInvitation(),
		p.acceptInvitation(),
		p.getInvitation(),
		p.rejectInvitation(),
		p.listInvitations(),
		p.getActiveMember(),
		p.checkOrganizationSlug(),
		p.addMember(),
		p.removeMember(),
		p.updateMemberRole(),
		p.leaveOrganization(),
		p.listUserInvitations(),
		p.listMembers(),
		p.getActiveMemberRole(),
	}
	if o.teamsEnabled() {
		eps = append(eps,
			p.createTeam(),
			p.listOrganizationTeams(),
			p.removeTeam(),
			p.updateTeam(),
			p.setActiveTeam(),
			p.listUserTeams(),
			p.listTeamMembers(),
			p.addTeamMember(),
			p.removeTeamMember(),
		)
	}
	if o.dacEnabled() {
		eps = append(eps,
			p.createOrgRole(),
			p.deleteOrgRole(),
			p.listOrgRoles(),
			p.getOrgRole(),
			p.updateOrgRole(),
		)
	}
	eps = append(eps, p.hasPermissionEndpoint())

	return &betterauth.Plugin{
		ID:         ID,
		Version:    Version,
		Endpoints:  eps,
		Schema:     pluginSchema(o),
		ErrorCodes: ErrorCodes,
		Options:    o,
	}
}

// orgSessionMiddleware requires a session (orgSessionMiddleware upstream).
var orgSessionMiddleware betterauth.Middleware = betterauth.SessionMiddleware

func permissionsRecord() validate.Schema { return validate.Record(validate.Array(validate.String())) }

func (p *plugin) hasPermissionEndpoint() *betterauth.Endpoint {
	body := validate.And(
		validate.Object(validate.F("organizationId", validate.Optional(validate.String()))),
		xor(
			validate.Object(validate.F("permission", permissionsRecord())),
			validate.Object(validate.F("permissions", permissionsRecord())),
		),
	)
	return &betterauth.Endpoint{
		Key: "hasPermission", Path: "/organization/has-permission", Methods: []string{"POST"},
		RequireHeaders: true, Body: body, Use: []betterauth.Middleware{orgSessionMiddleware},
		Metadata: openapiMeta("/organization/has-permission"),
		Handler: func(ctx *Ctx) (any, error) {
			b := ctx.BodyMap()
			orgID, _ := b["organizationId"].(string)
			if orgID == "" {
				orgID = activeOrgID(ctx.Session)
			}
			if orgID == "" {
				return nil, errFrom("BAD_REQUEST", ErrNoActiveOrganization)
			}
			a := newAdapter(ctx, p.o)
			member, err := a.findMemberByOrgID(ctx.Session.User.ID, orgID)
			if err != nil {
				return nil, err
			}
			if member == nil {
				return nil, errFrom("UNAUTHORIZED", ErrUserIsNotAMemberOfTheOrganization)
			}
			var perms Permissions
			if raw, ok := b["permissions"]; ok {
				perms, _ = toPermissions(raw)
			}
			ok, err := p.hasPermission(ctx, HasPermissionInput{Role: member.role(), Permissions: perms, OrganizationID: orgID})
			if err != nil {
				return nil, err
			}
			return jsonx.O("error", nil, "success", ok), nil
		},
	}
}
