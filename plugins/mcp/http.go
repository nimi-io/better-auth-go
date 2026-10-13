package mcp

import (
	"context"
	"net/http"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Idiomatic net/http integration (Go-only; upstream works with Fetch API handlers).

// WriteResponse writes res to w.
func WriteResponse(w http.ResponseWriter, res *betterauth.Response) {
	if res == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	for k, vs := range res.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	status := res.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if len(res.Body) > 0 {
		_, _ = w.Write(res.Body)
	}
}

// HandlerFunc adapts a ProtectedHandler to net/http. Errors returned by the handler (which
// upstream would rethrow) are passed to onError; a nil onError answers 500.
func HandlerFunc(h ProtectedHandler, onError func(w http.ResponseWriter, r *http.Request, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := h(r)
		if err != nil {
			if onError != nil {
				onError(w, r, err)
				return
			}
			if e, ok := betterauth.AsAPIError(err); ok {
				body, _ := jsonx.Marshal(e.Body)
				for k, vs := range e.Headers {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(e.StatusCode)
				_, _ = w.Write(body)
				return
			}
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		WriteResponse(w, res)
	}
}

type contextKey int

const (
	claimsKey contextKey = iota
	verifierKey
)

// ClaimsFromContext returns the verified access-token claims stored by Middleware (nil
// outside a protected request).
func ClaimsFromContext(ctx context.Context) *jsonx.Object {
	c, _ := ctx.Value(claimsKey).(*jsonx.Object)
	return c
}

// Challenge answers a handler-raised insufficient-scope error (created with
// oauthcore.CreateInsufficientScopeError) with the 403 step-up challenge for the protected
// resource of the current request. It reports whether a response was written; other
// errors are left to the caller. It only works inside Middleware.
func Challenge(w http.ResponseWriter, r *http.Request, err error) bool {
	v, _ := r.Context().Value(verifierKey).(*verifier)
	if v == nil || !isInsufficientScopeError(err) {
		return false
	}
	res, cerr := toChallengeResponse(err, v.resource, v.challenge)
	if cerr != nil {
		return false
	}
	WriteResponse(w, res)
	return true
}

func middleware(resolve func(r *http.Request) (*verifier, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v, err := resolve(r)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			claims, challenge, err := v.verifyRequest(r)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if challenge != nil {
				WriteResponse(w, challenge)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			ctx = context.WithValue(ctx, verifierKey, v)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Middleware protects an http.Handler like CreateMcpProtectedRequestHandler. The verified
// claims are available through ClaimsFromContext; handlers step up scopes with Challenge.
// Verification failures that are not challengeable (e.g. an unreachable JWKS) answer 500.
func Middleware(options ProtectedRequestHandlerOptions) (func(http.Handler) http.Handler, error) {
	v, err := newVerifier(options)
	if err != nil {
		return nil, err
	}
	return middleware(func(*http.Request) (*verifier, error) { return v, nil }), nil
}

// RequireMcpAuthMiddleware protects an http.Handler like RequireMcpAuth (issuer, resource
// and JWKS default to the auth server's resolved base URL).
func RequireMcpAuthMiddleware(auth *betterauth.Auth, opts *RequireMcpAuthOptions) (func(http.Handler) http.Handler, error) {
	if opts == nil {
		opts = &RequireMcpAuthOptions{}
	}
	if opts.Resource != "" {
		if _, err := ValidateMcpResource(opts.Resource); err != nil {
			return nil, err
		}
	}
	return middleware(func(*http.Request) (*verifier, error) {
		ac := auth.Context()
		o, err := requireMcpAuthOptions(func() (string, oauthcore.DPoPReplayReservations) { return ac.BaseURL, ac.InternalAdapter }, opts)
		if err != nil {
			return nil, err
		}
		return newVerifier(o)
	}), nil
}
