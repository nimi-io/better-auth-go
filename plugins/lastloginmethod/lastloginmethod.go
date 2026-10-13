// Package lastloginmethod is the last-login-method plugin
// (packages/better-auth/src/plugins/last-login-method): it remembers how a user last
// signed in, in a readable cookie and optionally in a user column.
package lastloginmethod

import (
	"context"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// DefaultCookieName is the default cookie name.
const DefaultCookieName = "better-auth.last_used_login_method"

// DefaultMaxAge is the default cookie lifetime in seconds (30 days).
const DefaultMaxAge = 60 * 60 * 24 * 30

// Options configure the plugin (LastLoginMethodOptions).
type Options struct {
	// CookieName defaults to "better-auth.last_used_login_method".
	CookieName string
	// MaxAge is the cookie lifetime in seconds (default 30 days).
	MaxAge int
	// CustomResolveMethod resolves the login method for a request. Returning ok=false
	// falls back to the default resolution; returning ("", true) means "no method".
	CustomResolveMethod func(ctx *betterauth.EndpointContext) (method string, ok bool)
	// StoreInDatabase also stores the method in the user's lastLoginMethod column.
	StoreInDatabase bool
	// BeforeStoreCookie may veto setting the cookie (e.g. for consent). An error vetoes
	// it too (and is logged).
	BeforeStoreCookie func(ctx *betterauth.EndpointContext, lastUsedLoginMethod string) (bool, error)
	// Schema renames the user column.
	Schema *SchemaOptions
}

// SchemaOptions customise column names.
type SchemaOptions struct {
	User struct {
		// LastLoginMethod is the column name of the lastLoginMethod field.
		LastLoginMethod string
	}
}

// DefaultResolveMethod is the built-in method resolution by endpoint path.
func DefaultResolveMethod(ctx *betterauth.EndpointContext) string {
	path := ctx.Path
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "/callback/") {
		if id := ctx.Params["id"]; id != "" {
			return id
		}
		parts := strings.Split(path, "/")
		return parts[len(parts)-1]
	}
	if path == "/sign-in/email" || path == "/sign-up/email" {
		return "email"
	}
	if strings.Contains(path, "siwe") {
		return "siwe"
	}
	if strings.Contains(path, "/passkey/verify-authentication") {
		return "passkey"
	}
	if strings.HasPrefix(path, "/magic-link/verify") {
		return "magic-link"
	}
	if path == "/sign-in/email-otp" {
		return "email-otp"
	}
	return ""
}

// New creates the last-login-method plugin.
func New(opts ...Options) *betterauth.Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	cookieName := o.CookieName
	if cookieName == "" {
		cookieName = DefaultCookieName
	}
	maxAge := o.MaxAge
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	resolve := func(ctx *betterauth.EndpointContext) string {
		if o.CustomResolveMethod != nil {
			if m, ok := o.CustomResolveMethod(ctx); ok {
				return m
			}
		}
		return DefaultResolveMethod(ctx)
	}
	p := &betterauth.Plugin{
		ID:      "last-login-method",
		Options: o,
		Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			return &betterauth.PluginInit{DatabaseHooks: &betterauth.DatabaseHooks{
				User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
					Before: func(c context.Context, _ adapter.Record) (*betterauth.DBHookResult, error) {
						if !o.StoreInDatabase {
							return nil, nil
						}
						ectx := betterauth.EndpointContextFrom(c)
						if ectx == nil {
							return nil, nil
						}
						if m := resolve(ectx); m != "" {
							return &betterauth.DBHookResult{Data: adapter.Record{"lastLoginMethod": m}}, nil
						}
						return nil, nil
					},
				}},
				Session: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
					After: func(c context.Context, session adapter.Record) error {
						if !o.StoreInDatabase {
							return nil
						}
						ectx := betterauth.EndpointContextFrom(c)
						if ectx == nil {
							return nil
						}
						m := resolve(ectx)
						userID, _ := session["userId"].(string)
						if m != "" && userID != "" {
							if _, err := ac.InternalAdapter.UpdateUser(c, userID, adapter.Record{"lastLoginMethod": m}); err != nil {
								ac.Logger.Error("Failed to update lastLoginMethod", err)
							}
						}
						return nil
					},
				}},
			}}, nil
		},
		Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(*betterauth.EndpointContext) bool { return true },
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				m := resolve(ctx)
				if m == "" {
					return nil, nil
				}
				name := ctx.Auth.AuthCookies.SessionToken.Name
				has := false
				for _, sc := range ctx.ResponseHeaders.Values("Set-Cookie") {
					if strings.Contains(sc, name) {
						has = true
						break
					}
				}
				if !has {
					return nil, nil
				}
				attrs := ctx.Auth.AuthCookies.SessionToken.Attributes
				attrs.MaxAge = betterauth.Int(maxAge)
				attrs.HTTPOnly = false
				permitted := true
				if o.BeforeStoreCookie != nil {
					ok, err := callBeforeStore(o.BeforeStoreCookie, ctx, m)
					if err != nil {
						ctx.Auth.Logger.Error("[LastLoginMethod] Error in beforeStoreCookie hook", err)
						permitted = false
					} else {
						permitted = ok
					}
				}
				if !permitted {
					return nil, nil
				}
				ctx.SetCookie(cookieName, m, attrs)
				return nil, nil
			},
		}}},
	}
	if o.StoreInDatabase {
		col := "lastLoginMethod"
		if o.Schema != nil && o.Schema.User.LastLoginMethod != "" {
			col = o.Schema.User.LastLoginMethod
		}
		p.Schema = []db.PluginTable{{Key: "user", Fields: []db.Field{{
			Name: "lastLoginMethod", Type: db.TypeString, Input: db.False, Required: db.False, FieldName: col,
		}}}}
	}
	return p
}

// callBeforeStore runs the hook, converting a panic into an error (a thrown error upstream).
func callBeforeStore(fn func(*betterauth.EndpointContext, string) (bool, error), ctx *betterauth.EndpointContext, m string) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			ok, err = false, panicError{r}
		}
	}()
	return fn(ctx, m)
}

type panicError struct{ v any }

func (p panicError) Error() string { return "panic in beforeStoreCookie" }
