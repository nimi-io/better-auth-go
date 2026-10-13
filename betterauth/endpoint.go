package betterauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// callInput describes one endpoint invocation.
type callInput struct {
	Request *http.Request
	Headers http.Header
	// Body is the parsed body; validate.Undefined when absent.
	Body   any
	Query  map[string]any
	Params map[string]string
	Method string
	Auth   *AuthContext
	// Session pre-populates ctx.Session (used for nested calls).
	Session *SessionWithUser
}

// callResult is the outcome of an invocation.
type callResult struct {
	Response any
	Status   int
	Headers  http.Header
}

func newHeader() http.Header { return http.Header{} }

func mergeHeaders(dst, src http.Header) http.Header {
	if dst == nil {
		dst = newHeader()
	}
	for k, vs := range src {
		if http.CanonicalHeaderKey(k) == "Set-Cookie" {
			for _, v := range vs {
				dst.Add(k, v)
			}
			continue
		}
		dst[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	return dst
}

func (a *Auth) newEndpointContext(ctx context.Context, ep *Endpoint, in callInput) *EndpointContext {
	method := in.Method
	if method == "" && in.Request != nil {
		method = in.Request.Method
	}
	if method == "" && len(ep.Methods) > 0 {
		method = ep.Methods[0]
		if method == "*" {
			method = "GET"
		}
	}
	body := in.Body
	if body == nil {
		body = validate.Undefined
	}
	query := in.Query
	if query == nil {
		query = map[string]any{}
	}
	ec := &EndpointContext{
		Path: ep.Path, Method: method, Request: in.Request, Headers: in.Headers, Body: body,
		Query: query, Params: in.Params, Auth: in.Auth, Endpoint: ep, Session: in.Session,
		ResponseHeaders: newHeader(), OperationID: operationID(ep),
	}
	if ec.Headers == nil && in.Request != nil {
		ec.Headers = in.Request.Header
	}
	ec.ctx = context.WithValue(withRequestState(ctx), endpointCtxKey{}, ec)
	return ec
}

func operationID(ep *Endpoint) string {
	if ep.OperationID != "" {
		return ep.OperationID
	}
	if ep.Key != "" {
		return ep.Key
	}
	if ep.Path != "" {
		return ep.Path
	}
	return "/:virtual"
}

// runEndpoint runs validation, `use` middlewares and the handler (better-call createEndpoint).
// It does not run hooks. Errors are returned as *APIError with the context headers merged.
func runEndpoint(ec *EndpointContext) (any, error) {
	ep := ec.Endpoint
	if ep.NoStore {
		ec.SetHeader("Cache-Control", "no-store")
		ec.SetHeader("Pragma", "no-cache")
	}
	// validation (body, query, required headers/request)
	if ep.Body != nil {
		out, issues := validate.Validate(ep.Body, ec.Body)
		if len(issues) > 0 {
			return nil, validationError(validate.FormatIssues(issues, "body"))
		}
		if out == nil {
			ec.Body = validate.Undefined
		} else {
			ec.Body = out
		}
	}
	if ep.Query != nil {
		var q any = ec.Query
		// better-call passes {} for HTTP requests (Object.fromEntries(searchParams)); only
		// direct API calls without a query see undefined.
		if len(ec.Query) == 0 && ec.Request == nil {
			q = validate.Undefined
		} else if ec.Query == nil {
			q = map[string]any{}
		}
		out, issues := validate.Validate(ep.Query, q)
		if len(issues) > 0 {
			return nil, validationError(validate.FormatIssues(issues, "query"))
		}
		if m, ok := out.(map[string]any); ok {
			ec.Query = m
		} else if out == nil {
			ec.Query = map[string]any{}
		}
	}
	if ep.RequireHeaders && ec.Headers == nil {
		return nil, validationError("Headers is required")
	}
	if ep.RequireRequest && ec.Request == nil {
		return nil, validationError("Request is required")
	}
	for _, mw := range ep.Use {
		if err := mw(ec); err != nil {
			return nil, attachHeaders(err, ec.ResponseHeaders)
		}
	}
	res, err := ep.Handler(ec)
	if err != nil {
		return nil, attachHeaders(err, ec.ResponseHeaders)
	}
	return res, nil
}

func validationError(msg string) *APIError {
	return NewAPIError("BAD_REQUEST", jsonx.O("message", msg, "code", "VALIDATION_ERROR"))
}

// attachHeaders merges context headers into an APIError (kAPIErrorHeaderSymbol).
func attachHeaders(err error, h http.Header) error {
	e, ok := AsAPIError(err)
	if !ok {
		return err
	}
	merged := mergeHeaders(newHeader(), h)
	for k, vs := range e.Headers {
		if http.CanonicalHeaderKey(k) == "Set-Cookie" {
			for _, v := range vs {
				merged.Add(k, v)
			}
		} else {
			merged[k] = vs
		}
	}
	c := *e
	c.Headers = merged
	return &c
}

func (a *Auth) hooks(ac *AuthContext) (before, after []Hook) {
	if h := ac.Options.Hooks; h != nil {
		if h.Before != nil {
			before = append(before, Hook{Matcher: func(*EndpointContext) bool { return true }, Handler: h.Before})
		}
		if h.After != nil {
			after = append(after, Hook{Matcher: func(*EndpointContext) bool { return true }, Handler: h.After})
		}
	}
	for _, p := range ac.plugins {
		before = append(before, p.Hooks.Before...)
		after = append(after, p.Hooks.After...)
	}
	return
}

// dispatch runs before hooks, the endpoint and after hooks (dispatchAuthEndpoint).
func (a *Auth) dispatch(ctx context.Context, ep *Endpoint, in callInput) (*callResult, error) {
	ec := a.newEndpointContext(ctx, ep, in)
	before, after := a.hooks(ec.Auth)

	beforeHeaders := newHeader()
	for _, h := range before {
		matched, err := safeMatch(h, ec)
		if err != nil {
			ec.Auth.Logger.Error("An error occurred during hook matcher execution:", err)
			return nil, ErrMessage("INTERNAL_SERVER_ERROR", "An error occurred during hook matcher execution. Check the logs for more details.")
		}
		if !matched {
			continue
		}
		ec.ResponseHeaders = newHeader()
		res, err := h.Handler(ec)
		beforeHeaders = mergeHeaders(beforeHeaders, ec.ResponseHeaders)
		if err != nil {
			return nil, attachHeaders(err, beforeHeaders)
		}
		if res != nil {
			return &callResult{Response: res, Headers: beforeHeaders}, nil
		}
	}
	// Request headers may have been changed by hooks; drop the cached cookie map.
	ec.invalidateCookies()

	ec.ResponseHeaders = newHeader()
	res, err := runEndpoint(ec)
	result := &callResult{Response: res, Status: ec.status}
	if err != nil {
		e, ok := AsAPIError(err)
		if !ok {
			return nil, err
		}
		result.Response = e
		result.Status = e.StatusCode
		result.Headers = mergeHeaders(newHeader(), e.Headers)
	} else {
		result.Headers = ec.ResponseHeaders
	}

	ec.Returned = result.Response
	ec.ReturnedStatus = result.Status
	ec.ResponseHeaders = result.Headers
	for _, h := range after {
		if !h.Matcher(ec) {
			continue
		}
		r, err := h.Handler(ec)
		if err != nil {
			e, ok := AsAPIError(err)
			if !ok {
				return nil, err
			}
			ec.ResponseHeaders = mergeHeaders(ec.ResponseHeaders, e.Headers)
			ec.Returned = e
			continue
		}
		if r != nil {
			ec.Returned = r
		}
	}
	result.Response = ec.Returned
	result.Headers = ec.ResponseHeaders
	return result, nil
}

func safeMatch(h Hook, ec *EndpointContext) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return h.Matcher(ec), nil
}

// ---- session helpers (api/routes/session.ts) ----

// GetSessionOptions are passed to GetSessionFromCtx.
type GetSessionOptions struct {
	DisableCookieCache bool
	DisableRefresh     bool
}

// GetSessionFromCtx resolves the session for the current request (getSessionFromCtx). The
// result is cached on ctx.Session and any Set-Cookie headers from a refresh are forwarded.
func GetSessionFromCtx(ctx *EndpointContext, opts *GetSessionOptions) (*SessionWithUser, error) {
	if ctx.Session != nil {
		return ctx.Session, nil
	}
	query := map[string]any{}
	for k, v := range ctx.Query {
		query[k] = v
	}
	dcc := validate.Truthy(ctx.Query["disableCookieCache"])
	dr := validate.Truthy(ctx.Query["disableRefresh"])
	if opts != nil {
		dcc = dcc || opts.DisableCookieCache
		dr = dr || opts.DisableRefresh
	}
	if dcc {
		query["disableCookieCache"] = true
	} else {
		delete(query, "disableCookieCache")
	}
	if dr {
		query["disableRefresh"] = true
	} else {
		delete(query, "disableRefresh")
	}
	// Always the core endpoint (upstream calls getSession() directly), even when a plugin
	// such as custom-session replaces the registered "getSession" route.
	ep := coreGetSessionEndpoint()
	child := &EndpointContext{
		ctx: ctx.ctx, Path: ep.Path, Method: "GET", Request: ctx.Request, Headers: ctx.Headers,
		Body: validate.Undefined, Query: query, Params: ctx.Params, Auth: ctx.Auth, Endpoint: ep,
		ResponseHeaders: newHeader(),
	}
	if child.Headers == nil {
		child.Headers = http.Header{}
	}
	res, err := runEndpoint(child)
	if err != nil {
		ctx.Session = nil
		return nil, nil //nolint:nilerr // upstream swallows getSession errors here
	}
	var sw *SessionWithUser
	if sr, ok := res.(*SessionResult); ok && sr != nil {
		sw = sr.SessionWithUser
	}
	if sw == nil {
		ctx.Session = nil
		return nil, nil
	}
	for k, vs := range child.ResponseHeaders {
		lk := strings.ToLower(k)
		if lk == "cache-control" || lk == "pragma" {
			continue
		}
		if lk == "set-cookie" {
			for _, v := range vs {
				ctx.ResponseHeaders.Add(k, v)
			}
		} else {
			ctx.ResponseHeaders[k] = vs
		}
	}
	ctx.Session = sw
	return sw, nil
}

// GetAuthoritativeSessionFromCtx bypasses the cookie cache when sessions are stored
// server-side.
func GetAuthoritativeSessionFromCtx(ctx *EndpointContext) (*SessionWithUser, error) {
	if !ctx.Auth.stateful {
		return GetSessionFromCtx(ctx, nil)
	}
	ctx.Session = nil
	return GetSessionFromCtx(ctx, &GetSessionOptions{DisableCookieCache: true})
}

func unauthorized() *APIError {
	return ErrFrom("UNAUTHORIZED", ErrorCode{Code: "UNAUTHORIZED", Message: "Unauthorized"})
}

// SessionMiddleware requires a session (sessionMiddleware).
func SessionMiddleware(ctx *EndpointContext) error {
	s, err := GetSessionFromCtx(ctx, nil)
	if err != nil {
		return err
	}
	if s == nil || s.Session == nil {
		return unauthorized()
	}
	ctx.Session = s
	return nil
}

// SensitiveSessionMiddleware requires an authoritative session (sensitiveSessionMiddleware).
func SensitiveSessionMiddleware(ctx *EndpointContext) error {
	s, err := GetAuthoritativeSessionFromCtx(ctx)
	if err != nil {
		return err
	}
	if s == nil || s.Session == nil {
		return unauthorized()
	}
	ctx.Session = s
	return nil
}

// RequestOnlySessionMiddleware requires a session only for HTTP/header-bearing calls.
func RequestOnlySessionMiddleware(ctx *EndpointContext) error {
	s, err := GetSessionFromCtx(ctx, nil)
	if err != nil {
		return err
	}
	if (s == nil || s.Session == nil) && (ctx.Request != nil || ctx.Headers != nil) {
		return unauthorized()
	}
	ctx.Session = s
	return nil
}

// FreshSessionMiddleware requires a session created within freshAge (freshSessionMiddleware).
func FreshSessionMiddleware(ctx *EndpointContext) error {
	s, err := GetSessionFromCtx(ctx, nil)
	if err != nil {
		return err
	}
	if s == nil || s.Session == nil {
		return unauthorized()
	}
	if fa := ctx.Auth.SessionConfig.FreshAge; fa != 0 {
		if timeSince(s.Session.CreatedAt) >= fa {
			return ErrFrom("FORBIDDEN", ErrSessionNotFresh)
		}
	}
	ctx.Session = s
	return nil
}

var errNotFound = errors.New("not found")

func timeSince(t time.Time) time.Duration { return time.Since(t) }

var coreGetSession struct {
	once sync.Once
	ep   *Endpoint
}

// coreGetSessionEndpoint returns the built-in get-session endpoint.
func coreGetSessionEndpoint() *Endpoint {
	coreGetSession.once.Do(func() { coreGetSession.ep = getSessionEndpoint() })
	return coreGetSession.ep
}
