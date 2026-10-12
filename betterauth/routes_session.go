package betterauth

import (
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// SessionResult is the get-session payload: the typed session plus its JSON rendering.
type SessionResult struct {
	*SessionWithUser
	// NeedsRefresh is set when session.deferSessionRefresh is enabled.
	NeedsRefresh *bool
	json         *jsonx.Object
}

// MarshalJSON renders {"session","user"[,"needsRefresh"]} with returned=false fields hidden.
func (s *SessionResult) MarshalJSON() ([]byte, error) { return jsonx.Marshal(s.json) }

func sessionResult(a *AuthContext, sw *SessionWithUser, needsRefresh *bool) *SessionResult {
	o := jsonx.O("session", a.SessionOutput(sw.Session), "user", a.UserOutput(sw.User))
	if needsRefresh != nil {
		o.Set("needsRefresh", *needsRefresh)
	}
	return &SessionResult{SessionWithUser: sw, NeedsRefresh: needsRefresh, json: o}
}

var getSessionQuery = validate.Optional(validate.Object(
	validate.F("disableCookieCache", validate.Optional(validate.CoerceBoolean())),
	validate.F("disableRefresh", validate.Optional(validate.CoerceBoolean())),
))

func getSessionEndpoint() *Endpoint {
	return &Endpoint{
		Key: "getSession", Path: "/get-session", Methods: []string{"GET", "POST"}, OperationID: "getSession",
		Query: getSessionQuery, RequireHeaders: true, Handler: getSessionHandler,
	}
}

func getSessionHandler(ctx *EndpointContext) (any, error) {
	ctx.SetHeader("cache-control", "no-store")
	ctx.SetHeader("pragma", "no-cache")
	a := ctx.Auth
	defer_ := a.Options.Session != nil && a.Options.Session.DeferSessionRefresh
	isPost := ctx.Method == "POST"
	if isPost && !defer_ {
		return nil, ErrFrom("METHOD_NOT_ALLOWED", ErrMethodNotAllowedDeferSessionRequired)
	}
	res, err := getSessionInner(ctx, defer_, isPost)
	if err != nil {
		if _, ok := AsAPIError(err); ok {
			return nil, err
		}
		a.Logger.Error("INTERNAL_SERVER_ERROR", err)
		return nil, ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToGetSession)
	}
	return res, nil
}

func getSessionInner(ctx *EndpointContext, deferRefresh, isPost bool) (any, error) {
	a := ctx.Auth
	cc := a.cookieCacheEnabled()
	token, hasToken := ctx.GetSignedCookie(a.AuthCookies.SessionToken.Name, a.Secret)
	if !hasToken && cc {
		return Null, nil
	}
	dataCookie := GetChunkedCookie(ctx, a.AuthCookies.SessionData.Name)
	if dataCookie != "" && !cc {
		st := newCookieStore("Session", a.AuthCookies.SessionData.Name, a.AuthCookies.SessionData.Attributes, ctx)
		st.set(st.clean())
	}
	if !hasToken {
		return Null, nil
	}
	useCache := cc && !validate.Truthy(ctx.Query["disableCookieCache"])
	var payload *cookieCachePayload
	if useCache && dataCookie != "" {
		payload = decodeCookieCache(ctx, dataCookie)
		if payload == nil {
			ExpireCookie(ctx, a.AuthCookies.SessionData)
		}
	}
	_, dontRemember := ctx.GetSignedCookie(a.AuthCookies.DontRememberToken.Name, a.Secret)
	if payload != nil {
		expire := payload.Session.Token != token
		if !expire {
			expire = defaultVersion(payload.Version) != a.cookieCacheVersion(payload.Session, payload.User)
		}
		if !expire {
			now := time.Now()
			expire = payload.ExpiresAt.Before(now) || payload.Session.ExpiresAt.IsZero() || payload.Session.ExpiresAt.Before(now)
		}
		if expire {
			ExpireCookie(ctx, a.AuthCookies.SessionData)
		} else {
			sw := &SessionWithUser{Session: payload.Session, User: payload.User}
			if a.SessionConfig.CookieRefreshCache == nil {
				ctx.Session = sw
				return sessionResult(a, sw, nil), nil
			}
			untilExpiry := time.Until(payload.ExpiresAt)
			if untilExpiry < *a.SessionConfig.CookieRefreshCache && !ShouldSkipSessionRefresh(ctx.Context()) {
				if err := setCookieCache(ctx, sw, false); err != nil {
					return nil, err
				}
				opts := a.AuthCookies.SessionToken.Attributes
				if dontRemember {
					opts.MaxAge = nil
				} else {
					opts.MaxAge = Int(int(a.SessionConfig.ExpiresIn / time.Second))
				}
				ctx.SetSignedCookie(a.AuthCookies.SessionToken.Name, sw.Session.Token, a.Secret, opts)
			}
			ctx.Session = sw
			return sessionResult(a, sw, nil), nil
		}
	}
	sw, err := a.InternalAdapter.FindSession(ctx.Context(), token)
	if err != nil {
		return nil, err
	}
	ctx.Session = sw
	if sw == nil || sw.Session.ExpiresAt.Before(time.Now()) {
		DeleteSessionCookie(ctx, false)
		if sw != nil && (!deferRefresh || isPost) {
			if err := a.InternalAdapter.DeleteSession(ctx.Context(), sw.Session.Token); err != nil {
				return nil, err
			}
		}
		ctx.Session = nil
		return Null, nil
	}
	if dontRemember || validate.Truthy(ctx.Query["disableRefresh"]) {
		return sessionResult(a, sw, nil), nil
	}
	expiresIn, updateAge := a.SessionConfig.ExpiresIn, a.SessionConfig.UpdateAge
	dueAt := sw.Session.ExpiresAt.Add(-expiresIn).Add(updateAge)
	shouldUpdate := !dueAt.After(time.Now())
	disableRefresh := validate.Truthy(ctx.Query["disableRefresh"]) ||
		(a.Options.Session != nil && a.Options.Session.DisableSessionRefresh)
	needsRefresh := shouldUpdate && !disableRefresh && !ShouldSkipSessionRefresh(ctx.Context())
	if deferRefresh && !isPost {
		if err := setCookieCache(ctx, sw, dontRemember); err != nil {
			return nil, err
		}
		return sessionResult(a, sw, &needsRefresh), nil
	}
	if needsRefresh {
		updated, err := a.InternalAdapter.UpdateSession(ctx.Context(), sw.Session.Token, adapter.Record{
			"expiresAt": time.Now().Add(expiresIn), "updatedAt": time.Now(),
		})
		if err != nil {
			return nil, err
		}
		if updated == nil {
			DeleteSessionCookie(ctx, false)
			return nil, ErrFrom("UNAUTHORIZED", ErrFailedToGetSession)
		}
		nsw := &SessionWithUser{Session: updated, User: sw.User}
		if err := SetSessionCookie(ctx, nsw, Bool(false), &CookieOptions{MaxAge: Int(int(expiresIn / time.Second))}); err != nil {
			return nil, err
		}
		ctx.Session = nsw
		return sessionResult(a, nsw, nil), nil
	}
	if err := setCookieCache(ctx, sw, dontRemember); err != nil {
		return nil, err
	}
	return sessionResult(a, sw, nil), nil
}

func defaultVersion(v string) string {
	if v == "" {
		return "1"
	}
	return v
}

func listSessionsEndpoint() *Endpoint {
	return &Endpoint{
		Key: "listSessions", Path: "/list-sessions", Methods: []string{"GET"}, OperationID: "listUserSessions",
		Use: []Middleware{FreshSessionMiddleware}, RequireHeaders: true,
		Handler: func(ctx *EndpointContext) (any, error) {
			sessions, err := ctx.Auth.InternalAdapter.ListSessions(ctx.Context(), ctx.Session.User.ID, true)
			if err != nil {
				ctx.Auth.Logger.Error(err.Error())
				return nil, ErrStatus("INTERNAL_SERVER_ERROR")
			}
			out := []any{}
			now := time.Now()
			for _, s := range sessions {
				if s.ExpiresAt.After(now) {
					out = append(out, ctx.Auth.SessionOutput(s))
				}
			}
			return out, nil
		},
	}
}

func statusTrue() *jsonx.Object { return jsonx.O("status", true) }

func revokeSessionEndpoint() *Endpoint {
	return &Endpoint{
		Key: "revokeSession", Path: "/revoke-session", Methods: []string{"POST"},
		Body: validate.Object(validate.F("token", validate.String())),
		Use:  []Middleware{SensitiveSessionMiddleware}, RequireHeaders: true,
		Handler: func(ctx *EndpointContext) (any, error) {
			token := ctx.BodyString("token")
			s, err := ctx.Auth.InternalAdapter.FindSession(ctx.Context(), token)
			if err != nil {
				return nil, err
			}
			if s != nil && s.Session.UserID == ctx.Session.User.ID {
				if err := ctx.Auth.InternalAdapter.DeleteSession(ctx.Context(), token); err != nil {
					ctx.Auth.Logger.Error("", err)
					return nil, ErrFrom("INTERNAL_SERVER_ERROR", ErrorCode{Code: "INTERNAL_SERVER_ERROR", Message: "Internal Server Error"})
				}
			}
			return statusTrue(), nil
		},
	}
}

func revokeSessionsEndpoint() *Endpoint {
	return &Endpoint{
		Key: "revokeSessions", Path: "/revoke-sessions", Methods: []string{"POST"},
		Use: []Middleware{SensitiveSessionMiddleware}, RequireHeaders: true,
		Handler: func(ctx *EndpointContext) (any, error) {
			if err := ctx.Auth.InternalAdapter.DeleteUserSessions(ctx.Context(), ctx.Session.User.ID); err != nil {
				ctx.Auth.Logger.Error("", err)
				return nil, ErrFrom("INTERNAL_SERVER_ERROR", ErrorCode{Code: "INTERNAL_SERVER_ERROR", Message: "Internal Server Error"})
			}
			return statusTrue(), nil
		},
	}
}

func revokeOtherSessionsEndpoint() *Endpoint {
	return &Endpoint{
		Key: "revokeOtherSessions", Path: "/revoke-other-sessions", Methods: []string{"POST"},
		Use: []Middleware{SensitiveSessionMiddleware}, RequireHeaders: true,
		Handler: func(ctx *EndpointContext) (any, error) {
			sessions, err := ctx.Auth.InternalAdapter.ListSessions(ctx.Context(), ctx.Session.User.ID, false)
			if err != nil {
				return nil, err
			}
			now := time.Now()
			for _, s := range sessions {
				if s.ExpiresAt.After(now) && s.Token != ctx.Session.Session.Token {
					if err := ctx.Auth.InternalAdapter.DeleteSession(ctx.Context(), s.Token); err != nil {
						return nil, err
					}
				}
			}
			return statusTrue(), nil
		},
	}
}

func updateSessionEndpoint() *Endpoint {
	return &Endpoint{
		Key: "updateSession", Path: "/update-session", Methods: []string{"POST"}, OperationID: "updateSession",
		Body: validate.Record(validate.Any()), Use: []Middleware{SessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			body := ctx.BodyMap()
			if body == nil {
				return nil, ErrFrom("BAD_REQUEST", ErrBodyMustBeAnObject)
			}
			fields, err := ctx.Auth.ParseSessionInput(body, "update")
			if err != nil {
				return nil, err
			}
			if len(fields) == 0 {
				return nil, ErrMessage("BAD_REQUEST", "No fields to update")
			}
			upd := adapter.Record{}
			for k, v := range fields {
				upd[k] = v
			}
			upd["updatedAt"] = time.Now()
			updated, err := ctx.Auth.InternalAdapter.UpdateSession(ctx.Context(), ctx.Session.Session.Token, upd)
			if err != nil {
				return nil, err
			}
			if updated == nil && ctx.Auth.stateful {
				DeleteSessionCookie(ctx, false)
				return nil, ErrFrom("UNAUTHORIZED", ErrFailedToGetSession)
			}
			if updated == nil {
				rec := mergeRecord(ctx.Session.Session.Record(), upd)
				updated = SessionFromRecord(rec)
			}
			if err := SetSessionCookie(ctx, &SessionWithUser{Session: updated, User: ctx.Session.User}, nil, nil); err != nil {
				return nil, err
			}
			return jsonx.O("session", ctx.Auth.SessionOutput(updated)), nil
		},
	}
}
