// Package anonymous ports Better Auth's anonymous plugin
// (packages/better-auth/src/plugins/anonymous): anonymous sign-in, linking an anonymous
// user to a real account on sign-in/sign-up, and deleting anonymous users.
package anonymous

import (
	"context"
	_ "embed"
	"strings"
	"sync"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// SchemaOverride renames the plugin table and/or its fields (mergeSchema upstream).
type SchemaOverride struct {
	ModelName string
	// Fields maps logical field names to physical column names.
	Fields map[string]string
}

// LinkAccountData is passed to Options.OnLinkAccount.
type LinkAccountData struct {
	// AnonymousUser is the anonymous session being linked (user.isAnonymous is true).
	AnonymousUser *betterauth.SessionWithUser
	// NewUser is the session created by the sign-in / sign-up.
	NewUser *betterauth.SessionWithUser
	Ctx     *betterauth.EndpointContext
}

// Options configures the anonymous plugin (AnonymousOptions).
type Options struct {
	// EmailDomainName makes generated emails temp-<id>@<domain> instead of
	// <id>@anonymous.placeholder.invalid.
	EmailDomainName string
	// OnLinkAccount runs when an anonymous user signs in or signs up with a real account.
	OnLinkAccount func(data LinkAccountData) error
	// DisableDeleteAnonymousUser keeps anonymous users after linking and disables
	// /delete-anonymous-user.
	DisableDeleteAnonymousUser bool
	// GenerateName returns the name of new anonymous users ("Anonymous" when empty).
	GenerateName func(ctx *betterauth.EndpointContext) (string, error)
	// GenerateRandomEmail returns the email of new anonymous users; it must be valid.
	GenerateRandomEmail func(ctx context.Context) (string, error)
	// Schema renames the plugin's fields, keyed by "user".
	Schema map[string]SchemaOverride
}

func ec(code, message string) betterauth.ErrorCode {
	return betterauth.ErrorCode{Code: code, Message: message}
}

// Error codes (ANONYMOUS_ERROR_CODES).
var (
	ErrInvalidEmailFormat                         = ec("INVALID_EMAIL_FORMAT", "Email was not generated in a valid format")
	ErrFailedToCreateUser                         = ec("FAILED_TO_CREATE_USER", "Failed to create user")
	ErrCouldNotCreateSession                      = ec("COULD_NOT_CREATE_SESSION", "Could not create session")
	ErrAnonymousUsersCannotSignInAgainAnonymously = ec("ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY", "Anonymous users cannot sign in again anonymously")
	ErrFailedToDeleteAnonymousUser                = ec("FAILED_TO_DELETE_ANONYMOUS_USER", "Failed to delete anonymous user")
	ErrFailedToDeleteAnonymousUserSessions        = ec("FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS", "Failed to delete anonymous user sessions")
	ErrUserIsNotAnonymous                         = ec("USER_IS_NOT_ANONYMOUS", "User is not anonymous")
	ErrDeleteAnonymousUserDisabled                = ec("DELETE_ANONYMOUS_USER_DISABLED", "Deleting anonymous users is disabled")
)

// ErrorCodes lists every anonymous error code ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{
	ErrInvalidEmailFormat, ErrFailedToCreateUser, ErrCouldNotCreateSession,
	ErrAnonymousUsersCannotSignInAgainAnonymously, ErrFailedToDeleteAnonymousUser,
	ErrFailedToDeleteAnonymousUserSessions, ErrUserIsNotAnonymous, ErrDeleteAnonymousUserDisabled,
}

//go:embed openapi.json
var openapiJSON []byte

var openapiDocs = sync.OnceValue(func() *jsonx.Object {
	v, err := jsonx.Parse(openapiJSON)
	if err != nil {
		panic(err)
	}
	return v.(*jsonx.Object)
})

func openapi(key string) map[string]any {
	o, _ := openapiDocs().Get(key)
	if obj, ok := o.(*jsonx.Object); ok {
		return map[string]any{"openapi": obj}
	}
	return nil
}

// linkPaths are the path prefixes whose new sessions link (and clean up) an anonymous user.
var linkPaths = []string{
	"/sign-in", "/sign-up", "/callback", "/magic-link/verify", "/email-otp/verify-email",
	"/one-tap/callback", "/passkey/verify-authentication", "/phone-number/verify", "/verify-email",
}

// New creates the anonymous plugin.
func New(options Options) *betterauth.Plugin {
	o := &options
	return &betterauth.Plugin{
		ID:      "anonymous",
		Version: betterauth.Version,
		Endpoints: []*betterauth.Endpoint{
			signInAnonymousEndpoint(o),
			deleteAnonymousUserEndpoint(o),
		},
		Hooks: betterauth.PluginHooks{
			Before: []betterauth.Hook{{
				Matcher: func(ctx *betterauth.EndpointContext) bool { return ctx.Path == "/sign-in/social" },
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					s, err := betterauth.GetSessionFromCtx(ctx, &betterauth.GetSessionOptions{DisableRefresh: true})
					if err != nil {
						return nil, err
					}
					if s == nil || !isAnonymous(s.User) {
						return nil, nil
					}
					betterauth.AddOAuthServerContext(ctx.Context(), map[string]any{"anonymousUserId": s.User.ID})
					return nil, nil
				},
			}},
			After: []betterauth.Hook{{
				Matcher: func(ctx *betterauth.EndpointContext) bool {
					for _, p := range linkPaths {
						if strings.HasPrefix(ctx.Path, p) {
							return true
						}
					}
					return false
				},
				Handler: func(ctx *betterauth.EndpointContext) (any, error) { return linkAfterHook(ctx, o) },
			}},
		},
		Schema:     schema(options.Schema),
		ErrorCodes: ErrorCodes,
		Options:    options,
	}
}

func schema(over map[string]SchemaOverride) []db.PluginTable {
	t := db.PluginTable{Key: "user", Fields: []db.Field{
		{Name: "isAnonymous", Type: db.TypeBoolean, Required: db.False, Input: db.False, DefaultValue: false},
	}}
	if ov, ok := over["user"]; ok {
		if ov.ModelName != "" {
			t.ModelName = ov.ModelName
		}
		if col := ov.Fields["isAnonymous"]; col != "" {
			t.Fields[0].FieldName = col
		}
	}
	return []db.PluginTable{t}
}

func isAnonymous(u *betterauth.User) bool {
	if u == nil {
		return false
	}
	return adapter.ToBool(u.Get("isAnonymous"))
}

func withAnonymous(u *betterauth.User) *betterauth.User {
	c := u.Clone()
	if c.Additional == nil {
		c.Additional = map[string]any{}
	}
	c.Additional["isAnonymous"] = true
	return c
}

func anonUserEmail(ctx context.Context, o *Options) (string, error) {
	if o.GenerateRandomEmail != nil {
		custom, err := o.GenerateRandomEmail(ctx)
		if err != nil {
			return "", err
		}
		if custom != "" {
			if !validate.IsEmail(custom) {
				return "", betterauth.ErrFrom("BAD_REQUEST", ErrInvalidEmailFormat)
			}
			return custom, nil
		}
	}
	id := bacrypto.GenerateID()
	if o.EmailDomainName != "" {
		return "temp-" + id + "@" + o.EmailDomainName, nil
	}
	// createPlaceholderEmail({identifier: id, namespace: "anonymous"})
	return id + "@anonymous.placeholder.invalid", nil
}

func signInAnonymousEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "signInAnonymous", Path: "/sign-in/anonymous", Methods: []string{"POST"},
		Metadata: openapi("signInAnonymous"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			existing, err := betterauth.GetSessionFromCtx(ctx, &betterauth.GetSessionOptions{DisableRefresh: true})
			if err != nil {
				return nil, err
			}
			if existing != nil && isAnonymous(existing.User) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrAnonymousUsersCannotSignInAgainAnonymously)
			}
			email, err := anonUserEmail(ctx.Context(), o)
			if err != nil {
				return nil, err
			}
			name := ""
			if o.GenerateName != nil {
				if name, err = o.GenerateName(ctx); err != nil {
					return nil, err
				}
			}
			if name == "" {
				name = "Anonymous"
			}
			ia := ctx.Auth.InternalAdapter
			user, err := ia.CreateUser(ctx.Context(), adapter.Record{
				"email": email, "emailVerified": false, "isAnonymous": true, "name": name,
				// image is stored as null (as SQL databases return it) so responses carry
				// "image": null like the core sign-up does.
				"image": nil,
			}, betterauth.UserInfoSource{Method: "anonymous"})
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToCreateUser)
			}
			session, err := ia.CreateSession(ctx.Context(), user.ID, nil)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrCouldNotCreateSession)
			}
			if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, nil, nil); err != nil {
				return nil, err
			}
			return jsonx.O("token", session.Token, "user", ctx.Auth.UserOutput(user)), nil
		},
	}
}

func deleteAnonymousUserEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "deleteAnonymousUser", Path: "/delete-anonymous-user", Methods: []string{"POST"},
		Use:      []betterauth.Middleware{betterauth.SensitiveSessionMiddleware},
		Metadata: openapi("deleteAnonymousUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s := ctx.Session
			if o.DisableDeleteAnonymousUser {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrDeleteAnonymousUserDisabled)
			}
			if !isAnonymous(s.User) {
				return nil, betterauth.ErrFrom("FORBIDDEN", ErrUserIsNotAnonymous)
			}
			ia := ctx.Auth.InternalAdapter
			if err := ia.DeleteUserSessions(ctx.Context(), s.User.ID); err != nil {
				ctx.Auth.Logger.Error("Failed to delete anonymous user sessions", err)
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToDeleteAnonymousUserSessions)
			}
			if err := ia.DeleteUser(ctx.Context(), s.User.ID); err != nil {
				ctx.Auth.Logger.Error("Failed to delete anonymous user", err)
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToDeleteAnonymousUser)
			}
			betterauth.DeleteSessionCookie(ctx, false)
			return jsonx.O("success", true), nil
		},
	}
}

// sessionCookieFromResponse returns the token part of the last session cookie set on the
// response (parseSetCookieHeader(...).get(name).value.split(".")[0]).
func sessionCookieFromResponse(ctx *betterauth.EndpointContext) string {
	name := ctx.Auth.AuthCookies.SessionToken.Name
	value, found := "", false
	if ctx.ResponseHeaders != nil {
		for _, h := range ctx.ResponseHeaders.Values("Set-Cookie") {
			for _, sc := range betterauth.SplitSetCookieHeader(h) {
				n, v, _ := betterauth.ParseSetCookie(sc)
				if n != name {
					continue
				}
				value, found = v, true
			}
		}
	}
	if !found {
		return ""
	}
	token, _, _ := strings.Cut(value, ".")
	return token
}

// resolveAnonymousSession finds the anonymous session being linked: the request's session
// cookie, or (when the OAuth callback carries no cookie) the anonymous user recorded in the
// OAuth state's server-only context.
func resolveAnonymousSession(ctx *betterauth.EndpointContext) (*betterauth.SessionWithUser, error) {
	s, err := betterauth.GetSessionFromCtx(ctx, &betterauth.GetSessionOptions{DisableRefresh: true})
	if err != nil {
		return nil, err
	}
	if s != nil && isAnonymous(s.User) {
		return &betterauth.SessionWithUser{Session: s.Session, User: withAnonymous(s.User)}, nil
	}
	state := betterauth.GetOAuthState(ctx.Context())
	if state == nil || state.ServerContext == nil {
		return nil, nil
	}
	id, ok := state.ServerContext["anonymousUserId"].(string)
	if !ok {
		return nil, nil
	}
	ia := ctx.Auth.InternalAdapter
	user, err := ia.FindUserByID(ctx.Context(), id)
	if err != nil {
		return nil, err
	}
	if !isAnonymous(user) {
		return nil, nil
	}
	sessions, err := ia.ListSessions(ctx.Context(), user.ID, true)
	if err != nil {
		return nil, err
	}
	if len(sessions) == 0 || sessions[0] == nil {
		return nil, nil
	}
	return &betterauth.SessionWithUser{Session: sessions[0], User: withAnonymous(user)}, nil
}

func linkAfterHook(ctx *betterauth.EndpointContext, o *Options) (any, error) {
	if sessionCookieFromResponse(ctx) == "" {
		return nil, nil
	}
	anon, err := resolveAnonymousSession(ctx)
	if err != nil {
		return nil, err
	}
	if anon == nil {
		return nil, nil
	}
	newSession := ctx.NewSession()
	if ctx.Path == "/sign-in/anonymous" && newSession == nil {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrAnonymousUsersCannotSignInAgainAnonymously)
	}
	if newSession == nil {
		return nil, nil
	}
	if o.OnLinkAccount != nil {
		if err := o.OnLinkAccount(LinkAccountData{AnonymousUser: anon, NewUser: newSession, Ctx: ctx}); err != nil {
			return nil, err
		}
	}
	sameUser := newSession.User != nil && newSession.User.ID == anon.User.ID
	if o.DisableDeleteAnonymousUser || sameUser || isAnonymous(newSession.User) {
		return nil, nil
	}
	if err := ctx.Auth.InternalAdapter.DeleteUser(ctx.Context(), anon.User.ID); err != nil {
		ctx.Auth.Logger.Error("Failed to clean up anonymous user during post-link cleanup",
			map[string]any{"anonymousUserId": anon.User.ID, "error": err})
	}
	return nil, nil
}
