package admin

import (
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// DefaultStatements are the admin plugin's resources and actions (admin/access/statement.ts).
var DefaultStatements = access.Statements{
	"user": {
		"create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete",
		"set-password", "set-email", "get", "update",
	},
	"session": {"list", "revoke", "delete"},
}

// DefaultAC is the default access control (defaultAc).
var DefaultAC = access.New(DefaultStatements)

// AdminAC is the default "admin" role (adminAc). It does not include impersonate-admins.
var AdminAC = DefaultAC.NewRole(access.Statements{
	"user": {
		"create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "set-email",
		"get", "update",
	},
	"session": {"list", "revoke", "delete"},
})

// UserAC is the default "user" role (userAc).
var UserAC = DefaultAC.NewRole(access.Statements{
	"user":    {},
	"session": {},
})

// DefaultRoles are the roles used when Options.Roles is nil (defaultRoles).
func DefaultRoles() map[string]access.Role {
	return map[string]access.Role{"admin": AdminAC, "user": UserAC}
}
