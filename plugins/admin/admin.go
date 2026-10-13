// Package admin ports Better Auth's admin plugin (packages/better-auth/src/plugins/admin):
// user management endpoints under /admin/*, role-based access control, banning and
// impersonation.
package admin

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// SchemaOverride renames a plugin table and/or its fields (mergeSchema upstream).
type SchemaOverride struct {
	ModelName string
	// Fields maps logical field names to physical column names.
	Fields map[string]string
}

// Options configures the admin plugin (AdminOptions).
type Options struct {
	// DefaultRole is the role of new users ("user" by default).
	DefaultRole string
	// AdminRoles are the roles treated as admins when impersonating ("admin" by default).
	// Every entry must be a key of Roles (or of the default roles); New panics otherwise.
	AdminRoles []string
	// DefaultBanReason is used when ban-user receives no reason ("No reason").
	DefaultBanReason string
	// DefaultBanExpiresIn is the ban duration when ban-user receives none (0 = never expires).
	DefaultBanExpiresIn time.Duration
	// ImpersonationSessionDuration is the lifetime of impersonation sessions (1 hour).
	ImpersonationSessionDuration time.Duration
	// Schema renames the plugin's tables/fields, keyed by "user" / "session".
	Schema map[string]SchemaOverride
	// AC is the access control the roles were created from (informational on the server).
	AC *access.AccessControl
	// Roles replaces the default roles ("admin", "user").
	Roles map[string]access.Role
	// AdminUserIDs are always granted every permission.
	AdminUserIDs []string
	// BannedUserMessage is the message returned to banned users.
	BannedUserMessage string
	// BannedUserMessageFunc computes the banned message (takes precedence over BannedUserMessage).
	BannedUserMessageFunc func(ctx context.Context, user *betterauth.User) (string, error)
	// AllowImpersonatingAdmins lets every impersonator impersonate admins (legacy option;
	// prefer the "impersonate-admins" permission).
	AllowImpersonatingAdmins bool
}

// DefaultBannedUserMessage is the default bannedUserMessage.
const DefaultBannedUserMessage = "You have been banned from this application. Please contact support if you believe this is an error."

//go:embed openapi.json
var openapiJSON []byte

var openapiDocs = sync.OnceValue(func() *jsonx.Object {
	v, err := jsonx.Parse(openapiJSON)
	if err != nil {
		panic(err)
	}
	return v.(*jsonx.Object)
})

// openapi returns the endpoint metadata holding its OpenAPI operation (metadata.openapi).
func openapi(key string) map[string]any {
	o, _ := openapiDocs().Get(key)
	if obj, ok := o.(*jsonx.Object); ok {
		return map[string]any{"openapi": obj}
	}
	return nil
}

// New creates the admin plugin. It panics with a descriptive error when AdminRoles
// contains a role that is not defined in Roles (BetterAuthError upstream).
func New(options Options) *betterauth.Plugin {
	given := options
	opts := options
	if opts.DefaultRole == "" {
		opts.DefaultRole = "user"
	}
	if opts.AdminRoles == nil {
		opts.AdminRoles = []string{"admin"}
	}
	if opts.BannedUserMessage == "" {
		opts.BannedUserMessage = DefaultBannedUserMessage
	}
	if given.AdminRoles != nil {
		roles := given.Roles
		if roles == nil {
			roles = DefaultRoles()
		}
		known := map[string]bool{}
		for r := range roles {
			known[strings.ToLower(r)] = true
		}
		var invalid []string
		for _, r := range given.AdminRoles {
			if !known[strings.ToLower(r)] {
				invalid = append(invalid, r)
			}
		}
		if len(invalid) > 0 {
			panic(fmt.Errorf("Invalid admin roles: %s. Admin roles must be defined in the 'roles' configuration.", strings.Join(invalid, ", ")))
		}
	}
	o := &opts
	return &betterauth.Plugin{
		ID:      "admin",
		Version: betterauth.Version,
		Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			return &betterauth.PluginInit{DatabaseHooks: databaseHooks(ac, o, given.DefaultRole)}, nil
		},
		Hooks: betterauth.PluginHooks{
			After: []betterauth.Hook{{
				Matcher: func(ctx *betterauth.EndpointContext) bool { return ctx.Path == "/list-sessions" },
				Handler: filterImpersonatedSessions,
			}},
		},
		Endpoints: []*betterauth.Endpoint{
			setRoleEndpoint(o), getUserEndpoint(o), createUserEndpoint(o), adminUpdateUserEndpoint(o),
			listUsersEndpoint(o), listUserSessionsEndpoint(o), unbanUserEndpoint(o), banUserEndpoint(o),
			impersonateUserEndpoint(o), stopImpersonatingEndpoint(), revokeUserSessionEndpoint(o),
			revokeUserSessionsEndpoint(o), removeUserEndpoint(o), setUserPasswordEndpoint(o),
			userHasPermissionEndpoint(o),
		},
		ErrorCodes: ErrorCodes,
		Schema:     schema(given.Schema),
		Options:    given,
	}
}

func schema(over map[string]SchemaOverride) []db.PluginTable {
	tables := []db.PluginTable{
		{Key: "user", Fields: []db.Field{
			{Name: "role", Type: db.TypeString, Required: db.False, Input: db.False},
			{Name: "banned", Type: db.TypeBoolean, DefaultValue: false, Required: db.False, Input: db.False},
			{Name: "banReason", Type: db.TypeString, Required: db.False, Input: db.False},
			{Name: "banExpires", Type: db.TypeDate, Required: db.False, Input: db.False},
		}},
		{Key: "session", Fields: []db.Field{
			{Name: "impersonatedBy", Type: db.TypeString, Required: db.False, Input: db.False},
		}},
	}
	for i := range tables {
		ov, ok := over[tables[i].Key]
		if !ok {
			continue
		}
		if ov.ModelName != "" {
			tables[i].ModelName = ov.ModelName
		}
		for j := range tables[i].Fields {
			if col := ov.Fields[tables[i].Fields[j].Name]; col != "" {
				tables[i].Fields[j].FieldName = col
			}
		}
	}
	return tables
}

func databaseHooks(ac *betterauth.AuthContext, opts *Options, givenDefaultRole string) *betterauth.DatabaseHooks {
	defaultRole := givenDefaultRole
	if defaultRole == "" {
		defaultRole = "user"
	}
	return &betterauth.DatabaseHooks{
		User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
			Before: func(_ context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
				// {role: defaultRole, ...user}: an explicit role wins. The optional ban columns
				// are written as null so responses match SQL-backed deployments, where unset
				// columns read back as null (the memory adapter would omit them).
				out := adapter.Record{}
				for k, v := range map[string]any{"role": defaultRole, "banReason": nil, "banExpires": nil} {
					if _, ok := data[k]; !ok {
						out[k] = v
					}
				}
				if len(out) == 0 {
					return nil, nil
				}
				return &betterauth.DBHookResult{Data: out}, nil
			},
		}},
		Session: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
			Before: func(ctx context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
				// impersonatedBy is written as null for parity with SQL-backed deployments.
				var fill *betterauth.DBHookResult
				if _, ok := data["impersonatedBy"]; !ok {
					fill = &betterauth.DBHookResult{Data: adapter.Record{"impersonatedBy": nil}}
				}
				if betterauth.EndpointContextFrom(ctx) == nil {
					return fill, nil
				}
				userID, _ := data["userId"].(string)
				if userID == "" {
					userID = adapter.ToString(data["userId"])
				}
				user, err := ac.InternalAdapter.FindUserByID(ctx, userID)
				if err != nil {
					return nil, err
				}
				if user == nil || !truthy(user.Get("banned")) {
					return fill, nil
				}
				if exp, ok := adapter.ToTime(user.Get("banExpires")); ok && exp.Before(time.Now()) {
					if _, err := ac.InternalAdapter.UpdateUser(ctx, userID, adapter.Record{
						"banned": false, "banReason": nil, "banExpires": nil,
					}); err != nil {
						return nil, err
					}
					return fill, nil
				}
				message := opts.BannedUserMessage
				if opts.BannedUserMessageFunc != nil {
					m, err := opts.BannedUserMessageFunc(ctx, user)
					if err != nil {
						return nil, err
					}
					message = m
				}
				return nil, betterauth.ErrFrom("FORBIDDEN", betterauth.ErrorCode{Code: "BANNED_USER", Message: message})
			},
		}},
	}
}

// filterImpersonatedSessions removes impersonation sessions from /list-sessions.
func filterImpersonatedSessions(ctx *betterauth.EndpointContext) (any, error) {
	list, ok := ctx.Returned.([]any)
	if !ok {
		return nil, nil
	}
	out := []any{}
	for _, s := range list {
		if truthy(fieldOf(s, "impersonatedBy")) {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func fieldOf(v any, key string) any {
	switch t := v.(type) {
	case *jsonx.Object:
		x, _ := t.Get(key)
		return x
	case map[string]any:
		return t[key]
	case *betterauth.Session:
		return t.Get(key)
	}
	return nil
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	}
	return true
}
