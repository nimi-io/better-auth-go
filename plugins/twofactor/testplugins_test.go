package twofactor

import (
	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Minimal stand-ins for plugins used by the upstream tests that are ported separately
// (anonymous, magic-link, username, phone-number). They only reproduce the parts the
// two-factor tests depend on: the endpoint path and that a session cookie is set.

func signInUser(ctx *betterauth.EndpointContext, user *betterauth.User, dontRememberMe bool) (any, error) {
	s, err := ctx.Auth.InternalAdapter.CreateSession(ctx.Context(), user.ID, &betterauth.CreateSessionOptions{DontRememberMe: dontRememberMe})
	if err != nil {
		return nil, err
	}
	drm := dontRememberMe
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: s, User: user}, &drm, nil); err != nil {
		return nil, err
	}
	return jsonx.O("token", s.Token, "user", ctx.Auth.UserOutput(user)), nil
}

// anonymousPlugin: POST /sign-in/anonymous creates a user without credentials.
func anonymousPlugin() *betterauth.Plugin {
	return &betterauth.Plugin{ID: "anonymous", Endpoints: []*betterauth.Endpoint{{
		Key: "signInAnonymous", Path: "/sign-in/anonymous", Methods: []string{"POST"},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			id := bacrypto.GenerateID()
			u, err := ctx.Auth.InternalAdapter.CreateUser(ctx.Context(), adapter.Record{
				"email": "temp-" + id + "@anon.example.com", "name": "Anonymous", "emailVerified": false,
			}, betterauth.UserInfoSource{Action: "create-user", Method: "anonymous"})
			if err != nil {
				return nil, err
			}
			return signInUser(ctx, u, false)
		},
	}}}
}

// passwordSignInPlugin registers POST <path> signing in the test user by password (stands
// in for /sign-in/username and /sign-in/phone-number).
func passwordSignInPlugin(id, key, path, identifierField, identifier string) *betterauth.Plugin {
	return &betterauth.Plugin{ID: id, Endpoints: []*betterauth.Endpoint{{
		Key: key, Path: path, Methods: []string{"POST"},
		Body: validate.Object(validate.F(identifierField, validate.String()), validate.F("password", validate.String())),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if ctx.BodyString(identifierField) != identifier {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", betterauth.ErrInvalidEmailOrPassword)
			}
			found, err := ctx.Auth.InternalAdapter.FindUserByEmail(ctx.Context(), testEmail, false)
			if err != nil || found == nil {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", betterauth.ErrInvalidEmailOrPassword)
			}
			ok, err := validatePassword(ctx, ctx.BodyString("password"), found.User.ID)
			if err != nil || !ok {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", betterauth.ErrInvalidEmailOrPassword)
			}
			return signInUser(ctx, found.User, false)
		},
	}}}
}

// magicLinkPlugin: GET /magic-link/verify?email= signs the user in without a password.
func magicLinkPlugin() *betterauth.Plugin {
	return &betterauth.Plugin{ID: "magic-link", Endpoints: []*betterauth.Endpoint{{
		Key: "magicLinkVerify", Path: "/magic-link/verify", Methods: []string{"GET"},
		Query: validate.Object(validate.F("email", validate.String())),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			found, err := ctx.Auth.InternalAdapter.FindUserByEmail(ctx.Context(), ctx.QueryString("email"), false)
			if err != nil || found == nil {
				return nil, betterauth.ErrStatus("UNAUTHORIZED")
			}
			return signInUser(ctx, found.User, false)
		},
	}}}
}

// newSessionProbe sets x-new-session-visible when a later after hook still sees newSession.
func newSessionProbe() *betterauth.Plugin {
	return &betterauth.Plugin{ID: "new-session-probe", Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
		Matcher: func(ctx *betterauth.EndpointContext) bool {
			return len(ctx.Path) >= 9 && ctx.Path[:9] == "/sign-in/"
		},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if ctx.NewSession() != nil {
				ctx.SetHeader("x-new-session-visible", "true")
			}
			return nil, nil
		},
	}}}}
}
