package organization

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// Permissions maps resources to actions (e.g. {"member": ["update"]}).
type Permissions = map[string][]string

// roleCache is cacheAllRoles upstream (per plugin instance rather than process-global).
type roleCache struct {
	mu sync.Mutex
	m  map[string]map[string]access.Role
}

func (c *roleCache) get(org string) (map[string]access.Role, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[org]
	return r, ok
}

func (c *roleCache) set(org string, roles map[string]access.Role) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]map[string]access.Role{}
	}
	c.m[org] = roles
}

// HasPermissionInput is the input of HasPermission.
type HasPermissionInput struct {
	Role           string
	OrganizationID string
	Permissions    Permissions
	// UseMemoryCache reuses the roles loaded by the previous check for this organization.
	UseMemoryCache bool
	// AllowCreatorAllPermissions grants every permission to the creator role.
	AllowCreatorAllPermissions bool
}

// permissionRequest converts permissions to an ordered authorize request (resources sorted:
// Go maps do not keep the request order).
func permissionRequest(p Permissions) *jsonx.Object {
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

// hasPermissionFn ports permission.ts.
func hasPermissionFn(o *Options, in HasPermissionInput, roles map[string]access.Role) bool {
	if in.Permissions == nil {
		return false
	}
	rs := strings.Split(in.Role, ",")
	if slices.Contains(rs, o.creatorRole()) && in.AllowCreatorAllPermissions {
		return true
	}
	req := permissionRequest(in.Permissions)
	for _, r := range rs {
		role, ok := roles[r]
		if !ok {
			continue
		}
		res, err := role.Authorize(req, access.AND)
		if err == nil && res.Success {
			return true
		}
	}
	return false
}

func (p *plugin) baseRoles() map[string]access.Role {
	src := p.o.Roles
	if src == nil {
		src = DefaultRoles()
	}
	out := make(map[string]access.Role, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// hasPermission ports has-permission.ts.
func (p *plugin) hasPermission(ctx *Ctx, in HasPermissionInput) (bool, error) {
	roles := p.baseRoles()
	if ctx != nil && in.OrganizationID != "" && p.o.dacEnabled() && p.o.AC != nil && !in.UseMemoryCache {
		rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "organizationRole",
			Where: []adapter.Where{{Field: "organizationId", Value: in.OrganizationID}}})
		if err != nil {
			return false, err
		}
		for _, row := range rows {
			role := str(row["role"])
			perms, ok := parseRolePermissions(row["permission"])
			if !ok {
				ctx.Auth.Logger.Error("[hasPermission] Invalid permissions for role "+role, row["permission"])
				return false, betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "Invalid permissions for role "+role)
			}
			merged := access.Statements{}
			if existing, ok := roles[role]; ok {
				for k, v := range existing.Statements {
					merged[k] = append([]string(nil), v...)
				}
			}
			for _, k := range sortedKeys(perms) {
				for _, a := range perms[k] {
					if !slices.Contains(merged[k], a) {
						merged[k] = append(merged[k], a)
					}
				}
				if merged[k] == nil {
					merged[k] = []string{}
				}
			}
			roles[role] = p.o.AC.NewRole(merged)
		}
	}
	if in.UseMemoryCache {
		if cached, ok := p.cache.get(in.OrganizationID); ok {
			roles = cached
		}
	}
	p.cache.set(in.OrganizationID, roles)
	return hasPermissionFn(p.o, in, roles), nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseRolePermissions parses a stored permission string (z.record(z.string(),
// z.array(z.string()))).
func parseRolePermissions(v any) (Permissions, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	var raw any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, false
	}
	return toPermissions(raw)
}

func toPermissions(raw any) (Permissions, bool) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	out := Permissions{}
	for k, v := range m {
		arr, ok := v.([]any)
		if !ok {
			return nil, false
		}
		list := make([]string, 0, len(arr))
		for _, x := range arr {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			list = append(list, s)
		}
		out[k] = list
	}
	return out, true
}

// permissionsObject renders permissions as an ordered JSON object (keys sorted).
func permissionsObject(p Permissions) *jsonx.Object {
	if p == nil {
		return nil
	}
	return permissionRequest(p)
}

// HasPermission checks whether a member role has the given permissions in an organization
// (the hasPermission export upstream). It loads dynamic roles when enabled.
func HasPermission(ctx *Ctx, plugin *betterauth.Plugin, in HasPermissionInput) (bool, error) {
	p, ok := plugin.Options.(*Options)
	if !ok {
		return false, nil
	}
	st := statesFor(p)
	return st.hasPermission(ctx, in)
}

// HasPermission implements apikey.OrganizationPermissionChecker so organization-owned API
// keys resolve permissions through this plugin (roles, creator role, dynamic access
// control) without reflection.
func (o *Options) HasPermission(ctx *betterauth.EndpointContext, role, organizationID string, permissions map[string][]string, allowCreatorAllPermissions bool) (bool, error) {
	return statesFor(o).hasPermission(ctx, HasPermissionInput{Role: role, OrganizationID: organizationID,
		Permissions: permissions, AllowCreatorAllPermissions: allowCreatorAllPermissions})
}
