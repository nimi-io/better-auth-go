package main

import (
	"net/http"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/access"
	"github.com/nimi-io/better-auth-go/plugins/organization"
)

// Organization profile (mirrors e2e/servers/profiles/organization.mjs): teams and dynamic
// access control enabled; invitation emails are recorded as type "invitation" with the
// invitation id as token.
func init() {
	profiles["organization"] = func(cfg *betterauth.Config, env profileEnv) {
		maxTeams, invLimit := 5, 5
		cfg.Plugins = append(cfg.Plugins, organization.New(organization.Options{
			AC: access.New(organization.DefaultStatements),
			Roles: map[string]access.Role{
				"owner": organization.OwnerAC, "admin": organization.AdminAC, "member": organization.MemberAC,
			},
			Teams:                &organization.TeamsOptions{Enabled: true, MaximumTeams: &maxTeams},
			DynamicAccessControl: &organization.DynamicAccessControlOptions{Enabled: true},
			InvitationLimit:      &invLimit,
			SendInvitationEmail: func(_ *betterauth.EndpointContext, d organization.InvitationEmailData, _ *http.Request) error {
				env.Mail.Record("invitation", d.Email, "", d.ID)
				return nil
			},
		}))
	}
}
