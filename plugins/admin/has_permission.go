package admin

import (
	"slices"
	"sort"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// HasPermissionInput is the input of HasPermission.
type HasPermissionInput struct {
	UserID string
	// Role is the comma-separated role list of the user ("" = Options.DefaultRole or "user").
	Role        string
	Options     *Options
	Permissions map[string][]string
}

// HasPermission reports whether a user (by adminUserIds) or role grants every requested
// permission (has-permission.ts).
func HasPermission(in HasPermissionInput) bool {
	var opts Options
	if in.Options != nil {
		opts = *in.Options
	}
	if in.UserID != "" && slices.Contains(opts.AdminUserIDs, in.UserID) {
		return true
	}
	if in.Permissions == nil {
		return false
	}
	role := in.Role
	if role == "" {
		role = opts.DefaultRole
	}
	if role == "" {
		role = "user"
	}
	acRoles := opts.Roles
	if acRoles == nil {
		acRoles = DefaultRoles()
	}
	req := permissionsObject(in.Permissions)
	for _, r := range strings.Split(role, ",") {
		ar, ok := acRoles[r]
		if !ok {
			continue
		}
		res, err := ar.Authorize(req, access.AND)
		if err == nil && res.Success {
			return true
		}
	}
	return false
}

func permissionsObject(p map[string][]string) *jsonx.Object {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	o := jsonx.NewObject()
	for _, k := range keys {
		o.Set(k, p[k])
	}
	return o
}
