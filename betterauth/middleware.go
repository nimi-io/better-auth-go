package betterauth

import (
	"context"
	"net/http"
	"strings"
)

type sessionCtxKey struct{}

// SessionFromContext returns the session attached by Auth.Middleware or
// Auth.RequireSession (nil when the request is unauthenticated).
func SessionFromContext(ctx context.Context) *SessionWithUser {
	s, _ := ctx.Value(sessionCtxKey{}).(*SessionWithUser)
	return s
}

// WithSession returns a context carrying s (useful in tests).
func WithSession(ctx context.Context, s *SessionWithUser) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, s)
}

// ResolveSession looks up the session for an incoming request. Set-Cookie headers produced
// by a session refresh are copied to w when w is non-nil.
func (a *Auth) ResolveSession(w http.ResponseWriter, r *http.Request) (*SessionWithUser, error) {
	res, err := a.API.Call(r.Context(), "getSession", CallInput{Headers: r.Header})
	if err != nil {
		return nil, err
	}
	if w != nil {
		for _, c := range res.Headers.Values("Set-Cookie") {
			w.Header().Add("Set-Cookie", c)
		}
	}
	if sr, ok := res.Data.(*SessionResult); ok && sr != nil {
		return sr.SessionWithUser, nil
	}
	return nil, nil
}

// Middleware attaches the session (if any) to the request context and always calls next.
// Read it with SessionFromContext.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := a.ResolveSession(w, r)
		if err != nil {
			a.ctx.Logger.Error("failed to resolve session", err)
		}
		if s != nil {
			r = r.WithContext(WithSession(r.Context(), s))
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSession is like Middleware but responds 401 {"message":"Unauthorized",
// "code":"UNAUTHORIZED"} when there is no valid session.
func (a *Auth) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := a.ResolveSession(w, r)
		if err != nil || s == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Unauthorized","code":"UNAUTHORIZED"}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), s)))
	})
}

// Mount returns a handler that serves Better Auth under its base path and delegates all
// other requests to next. Unlike http.ServeMux it does not clean or redirect paths, so
// requests reach the auth router exactly as sent.
func (a *Auth) Mount(next http.Handler) http.Handler {
	base := strings.TrimRight(a.ctx.Options.BasePath, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == base || strings.HasPrefix(r.URL.Path, base+"/") {
			a.ServeHTTP(w, r)
			return
		}
		if next == nil {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
