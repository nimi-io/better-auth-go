// Package multisession is the multi-session plugin
// (packages/better-auth/src/plugins/multi-session): a browser keeps one signed
// `<session_token>_multi-<token>` cookie per signed-in account so it can list, switch and
// revoke device sessions.
package multisession

import (
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Options configure the multi-session plugin.
type Options struct {
	// MaximumSessions is the maximum number of sessions per device (default 5).
	MaximumSessions int
}

// ErrInvalidSessionToken is MULTI_SESSION_ERROR_CODES.INVALID_SESSION_TOKEN.
var ErrInvalidSessionToken = betterauth.ErrorCode{Code: "INVALID_SESSION_TOKEN", Message: "Invalid session token"}

func isMultiSessionCookie(key string) bool { return strings.Contains(key, "_multi-") }

func cookieHeader(ctx *betterauth.EndpointContext) string { return ctx.GetHeader("Cookie") }

// signedMultiSessionTokens returns the verified tokens of all multi-session cookies, in
// cookie order.
func signedMultiSessionTokens(ctx *betterauth.EndpointContext, header string) []string {
	var tokens []string
	for _, c := range betterauth.ParseCookies(header) {
		if !isMultiSessionCookie(c.Name) {
			continue
		}
		if t, ok := ctx.GetSignedCookie(c.Name, ctx.Auth.Secret); ok {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

func sessionPayload(ctx *betterauth.EndpointContext, s *betterauth.SessionWithUser) *jsonx.Object {
	return jsonx.O("session", ctx.Auth.SessionOutput(s.Session), "user", ctx.Auth.UserOutput(s.User))
}

func multiCookieName(ctx *betterauth.EndpointContext, token string) string {
	return ctx.Auth.AuthCookies.SessionToken.Name + "_multi-" + strings.ToLower(token)
}

var sessionTokenBody = validate.Object(validate.F("sessionToken", validate.String()))

// New creates the multi-session plugin.
func New(opts ...Options) *betterauth.Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	maximum := o.MaximumSessions
	if maximum == 0 {
		maximum = 5
	}
	return &betterauth.Plugin{
		ID:         "multi-session",
		Options:    o,
		ErrorCodes: []betterauth.ErrorCode{ErrInvalidSessionToken},
		Endpoints: []*betterauth.Endpoint{
			listDeviceSessionsEndpoint(),
			setActiveSessionEndpoint(),
			revokeDeviceSessionEndpoint(),
		},
		Hooks: betterauth.PluginHooks{
			After: []betterauth.Hook{
				{
					Matcher: func(*betterauth.EndpointContext) bool { return true },
					Handler: func(ctx *betterauth.EndpointContext) (any, error) {
						return nil, afterNewSession(ctx, maximum)
					},
				},
				{
					Matcher: func(ctx *betterauth.EndpointContext) bool { return ctx.Path == "/sign-out" },
					Handler: func(ctx *betterauth.EndpointContext) (any, error) {
						return nil, afterSignOut(ctx)
					},
				},
			},
		},
	}
}

func listDeviceSessionsEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listDeviceSessions", Path: "/multi-session/list-device-sessions", Methods: []string{"GET"},
		RequireHeaders: true,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			header := cookieHeader(ctx)
			if header == "" {
				return []any{}, nil
			}
			tokens := signedMultiSessionTokens(ctx, header)
			if len(tokens) == 0 {
				return []any{}, nil
			}
			sessions, err := ctx.Auth.InternalAdapter.FindSessions(ctx.Context(), tokens, true)
			if err != nil {
				return nil, err
			}
			now := time.Now()
			out := []any{}
			seen := map[string]bool{}
			for _, s := range sessions {
				if s == nil || !s.Session.ExpiresAt.After(now) {
					continue
				}
				if seen[s.User.ID] {
					continue
				}
				seen[s.User.ID] = true
				out = append(out, sessionPayload(ctx, s))
			}
			return out, nil
		},
	}
}

func setActiveSessionEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "setActiveSession", Path: "/multi-session/set-active", Methods: []string{"POST"},
		Body: sessionTokenBody, RequireHeaders: true,
		Metadata: map[string]any{"openapi": jsonx.O(
			"description", "Set the active session",
			"responses", jsonx.O("200", jsonx.O(
				"description", "Success",
				"content", jsonx.O("application/json", jsonx.O("schema", jsonx.O(
					"type", "object",
					"properties", jsonx.O("session", jsonx.O("$ref", "#/components/schemas/Session")),
				))),
			)),
		)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			name := multiCookieName(ctx, ctx.BodyString("sessionToken"))
			token, ok := ctx.GetSignedCookie(name, ctx.Auth.Secret)
			if !ok {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidSessionToken)
			}
			s, err := ctx.Auth.InternalAdapter.FindSession(ctx.Context(), token)
			if err != nil {
				return nil, err
			}
			if s == nil || s.Session.ExpiresAt.Before(time.Now()) {
				betterauth.ExpireCookie(ctx, betterauth.AuthCookie{Name: name, Attributes: ctx.Auth.AuthCookies.SessionToken.Attributes})
				return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidSessionToken)
			}
			if err := betterauth.SetSessionCookie(ctx, s, nil, nil); err != nil {
				return nil, err
			}
			return sessionPayload(ctx, s), nil
		},
	}
}

func revokeDeviceSessionEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "revokeDeviceSession", Path: "/multi-session/revoke", Methods: []string{"POST"},
		Body: sessionTokenBody, RequireHeaders: true, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
		Metadata: map[string]any{"openapi": jsonx.O(
			"description", "Revoke a device session",
			"responses", jsonx.O("200", jsonx.O(
				"description", "Success",
				"content", jsonx.O("application/json", jsonx.O("schema", jsonx.O(
					"type", "object",
					"properties", jsonx.O("status", jsonx.O("type", "boolean")),
				))),
			)),
		)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			name := multiCookieName(ctx, ctx.BodyString("sessionToken"))
			token, ok := ctx.GetSignedCookie(name, ctx.Auth.Secret)
			if !ok {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidSessionToken)
			}
			if err := ctx.Auth.InternalAdapter.DeleteSession(ctx.Context(), token); err != nil {
				return nil, err
			}
			betterauth.ExpireCookie(ctx, betterauth.AuthCookie{Name: name, Attributes: ctx.Auth.AuthCookies.SessionToken.Attributes})
			isActive := ctx.Session != nil && ctx.Session.Session.Token == token
			if !isActive {
				return jsonx.O("status", true), nil
			}
			header := cookieHeader(ctx)
			if header == "" {
				betterauth.DeleteSessionCookie(ctx, false)
				return jsonx.O("status", true), nil
			}
			tokens := signedMultiSessionTokens(ctx, header)
			if len(tokens) == 0 {
				betterauth.DeleteSessionCookie(ctx, false)
				return jsonx.O("status", true), nil
			}
			sessions, err := ctx.Auth.InternalAdapter.FindSessions(ctx.Context(), tokens, false)
			if err != nil {
				return nil, err
			}
			now := time.Now()
			var next *betterauth.SessionWithUser
			for _, s := range sessions {
				if s != nil && s.Session.ExpiresAt.After(now) {
					next = s
					break
				}
			}
			if next != nil {
				if err := betterauth.SetSessionCookie(ctx, next, nil, nil); err != nil {
					return nil, err
				}
			} else {
				betterauth.DeleteSessionCookie(ctx, false)
			}
			return jsonx.O("status", true), nil
		},
	}
}

// afterNewSession stores a multi-session cookie for a newly created session.
func afterNewSession(ctx *betterauth.EndpointContext, maximum int) error {
	setCookies := ctx.ResponseHeaders.Values("Set-Cookie")
	if len(setCookies) == 0 {
		return nil
	}
	newSession := ctx.NewSession()
	if newSession == nil {
		return nil
	}
	cfg := ctx.Auth.AuthCookies.SessionToken
	cookieName := cfg.Name + "_multi-" + strings.ToLower(newSession.Session.Token)
	for _, sc := range setCookies {
		for _, part := range betterauth.SplitSetCookieHeader(sc) {
			if n, _, _ := betterauth.ParseSetCookie(part); n == cookieName {
				return nil
			}
		}
	}
	cookies := betterauth.ParseCookies(cookieHeader(ctx))
	for _, c := range cookies {
		if c.Name == cookieName {
			return nil
		}
	}
	var multiKeys []string
	for _, c := range cookies {
		if isMultiSessionCookie(c.Name) {
			multiKeys = append(multiKeys, c.Name)
		}
	}
	var toDelete []string
	for _, key := range multiKeys {
		token, ok := ctx.GetSignedCookie(key, ctx.Auth.Secret)
		if !ok {
			continue
		}
		s, err := ctx.Auth.InternalAdapter.FindSession(ctx.Context(), token)
		if err != nil {
			return err
		}
		if s != nil && s.User.ID == newSession.User.ID {
			toDelete = append(toDelete, token)
			attrs := cfg.Attributes
			attrs.MaxAge = betterauth.Int(0)
			ctx.SetCookie(key, "", attrs)
		}
	}
	if len(toDelete) > 0 {
		if err := ctx.Auth.InternalAdapter.DeleteSessions(ctx.Context(), toDelete); err != nil {
			return err
		}
	}
	current := len(multiKeys) - len(toDelete)
	if strings.Contains(strings.Join(setCookies, ", "), cfg.Name) {
		current++
	}
	if current > maximum {
		return nil
	}
	ctx.SetSignedCookie(cookieName, newSession.Session.Token, ctx.Auth.Secret, cfg.Attributes)
	return nil
}

// afterSignOut expires every verified multi-session cookie and deletes its session.
func afterSignOut(ctx *betterauth.EndpointContext) error {
	header := cookieHeader(ctx)
	if header == "" {
		return nil
	}
	var verified []string
	for _, c := range betterauth.ParseCookies(header) {
		if !isMultiSessionCookie(c.Name) {
			continue
		}
		token, ok := ctx.GetSignedCookie(c.Name, ctx.Auth.Secret)
		if !ok {
			continue
		}
		name := strings.Replace(strings.ToLower(c.Name), strings.ToLower(betterauth.SecureCookiePrefix), betterauth.SecureCookiePrefix, 1)
		betterauth.ExpireCookie(ctx, betterauth.AuthCookie{Name: name, Attributes: ctx.Auth.AuthCookies.SessionToken.Attributes})
		verified = append(verified, token)
	}
	if len(verified) > 0 {
		return ctx.Auth.InternalAdapter.DeleteSessions(ctx.Context(), verified)
	}
	return nil
}
