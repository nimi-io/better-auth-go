package organization

import "github.com/nimi-io/better-auth-go/plugins/access"

// DefaultStatements are the organization access statements (organization/access upstream).
var DefaultStatements = access.Statements{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
}

// DefaultAC is the access control built from DefaultStatements.
var DefaultAC = access.New(DefaultStatements)

// AdminAC is the default "admin" role.
var AdminAC = DefaultAC.NewRole(access.Statements{
	"organization": {"update"},
	"invitation":   {"create", "cancel"},
	"member":       {"create", "update", "delete"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
})

// OwnerAC is the default "owner" role.
var OwnerAC = DefaultAC.NewRole(access.Statements{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
	"team":         {"create", "update", "delete"},
	"ac":           {"create", "read", "update", "delete"},
})

// MemberAC is the default "member" role.
var MemberAC = DefaultAC.NewRole(access.Statements{
	"organization": {},
	"member":       {},
	"invitation":   {},
	"team":         {},
	"ac":           {"read"},
})

// DefaultRoles are the built-in roles, in upstream key order (admin, owner, member).
func DefaultRoles() map[string]access.Role {
	return map[string]access.Role{"admin": AdminAC, "owner": OwnerAC, "member": MemberAC}
}

var defaultRoleNames = []string{"admin", "owner", "member"}
