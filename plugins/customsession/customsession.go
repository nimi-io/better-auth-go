// Package customsession is the custom-session plugin
// (packages/better-auth/src/plugins/custom-session): it replaces the /get-session response
// with the result of a user function (and optionally the multi-session
// list-device-sessions response).
package customsession

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Func computes the custom session. session is the get-session payload (fields with
// returned: false are not included); the result must be a JSON object (*jsonx.Object,
// map[string]any or a struct) or nil (rendered as null).
type Func func(ctx *betterauth.EndpointContext, session *betterauth.SessionWithUser) (any, error)

// Options are the plugin options (CustomSessionPluginOptions).
type Options struct {
	// ShouldMutateListDeviceSessionsEndpoint also maps every entry of the multi-session
	// /multi-session/list-device-sessions response through the function.
	ShouldMutateListDeviceSessionsEndpoint bool
}

// New creates the custom-session plugin.
func New(fn Func, opts ...Options) *betterauth.Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	return &betterauth.Plugin{
		ID:      "custom-session",
		Options: o,
		Hooks: betterauth.PluginHooks{
			After: []betterauth.Hook{{
				Matcher: func(ctx *betterauth.EndpointContext) bool {
					return ctx.Path == "/multi-session/list-device-sessions" && o.ShouldMutateListDeviceSessionsEndpoint
				},
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					return mutateDeviceSessions(ctx, fn)
				},
			}},
		},
		Endpoints: []*betterauth.Endpoint{getSessionEndpoint(fn)},
	}
}

// toObject converts a function result to an ordered JSON object.
func toObject(v any) (*jsonx.Object, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case *jsonx.Object:
		return t, nil
	}
	b, err := jsonx.Marshal(v)
	if err != nil {
		return nil, err
	}
	parsed, err := jsonx.Parse(b)
	if err != nil {
		return nil, err
	}
	o, _ := parsed.(*jsonx.Object)
	return o, nil
}

// fromPayload rebuilds a session from its JSON payload ({session, user}).
func fromPayload(v any) *betterauth.SessionWithUser {
	o, ok := v.(*jsonx.Object)
	if !ok {
		b, err := jsonx.Marshal(v)
		if err != nil {
			return nil
		}
		p, err := jsonx.Parse(b)
		if err != nil {
			return nil
		}
		if o, ok = p.(*jsonx.Object); !ok {
			return nil
		}
	}
	b, err := jsonx.Marshal(o)
	if err != nil {
		return nil
	}
	parsed, err := jsonx.Parse(b)
	if err != nil {
		return nil
	}
	po, _ := parsed.(*jsonx.Object)
	revived, _ := jsonx.ReviveDates(po).(*jsonx.Object)
	if revived == nil {
		return nil
	}
	sv, _ := revived.Get("session")
	uv, _ := revived.Get("user")
	return &betterauth.SessionWithUser{Session: betterauth.SessionFromRecord(sv), User: betterauth.UserFromRecord(uv)}
}

func mutateDeviceSessions(ctx *betterauth.EndpointContext, fn Func) (any, error) {
	var items []any
	switch t := ctx.Returned.(type) {
	case []any:
		items = t
	case []*jsonx.Object:
		for _, x := range t {
			items = append(items, x)
		}
	default:
		return nil, nil
	}
	out := make([]any, 0, len(items))
	for _, item := range items {
		r, err := fn(ctx, fromPayload(item))
		if err != nil {
			return nil, err
		}
		if r == nil {
			out = append(out, betterauth.Null)
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func getSessionEndpoint(fn Func) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getSession", Path: "/get-session", Methods: []string{"GET"},
		Query: betterauth.GetSessionQuerySchema, RequireHeaders: true,
		Metadata: map[string]any{
			"CUSTOM_SESSION": true,
			"openapi": jsonx.O(
				"description", "Get custom session data",
				"responses", jsonx.O("200", jsonx.O(
					"description", "Success",
					"content", jsonx.O("application/json", jsonx.O("schema", jsonx.O(
						"type", "array",
						"nullable", true,
						"items", jsonx.O("$ref", "#/components/schemas/Session"),
					))),
				)),
			),
		},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			// GetSessionFromCtx (session middlewares) resolves the session through the
			// endpoint registered as "getSession", i.e. this one. Upstream it calls the core
			// getSession directly, so nested lookups get the core result unchanged.
			if betterauth.EndpointContextFrom(ctx.Context()) != ctx {
				return betterauth.CoreGetSession(ctx)
			}
			return customGetSession(ctx, fn)
		},
	}
}

func customGetSession(ctx *betterauth.EndpointContext, fn Func) (any, error) {
	child := &betterauth.EndpointContext{
		Path: ctx.Path, Method: "GET", Request: ctx.Request, Headers: ctx.Headers, Body: ctx.Body,
		Query: ctx.Query, Params: ctx.Params, Auth: ctx.Auth, Endpoint: ctx.Endpoint,
		ResponseHeaders: http.Header{}, OperationID: ctx.OperationID,
	}
	child.SetContext(ctx.Context())
	res, err := betterauth.CoreGetSession(child)
	// getSession()(...).catch(() => null)
	var sr *betterauth.SessionResult
	if err == nil {
		sr, _ = res.(*betterauth.SessionResult)
	}
	ctx.Session = child.Session
	if ns := child.NewSession(); ns != nil {
		ctx.SetNewSession(ns)
	}
	if sr == nil || sr.SessionWithUser == nil {
		return betterauth.Null, nil
	}
	// fn receives the get-session payload (parsed output, returned: false fields removed)
	b, err := json.Marshal(sr)
	if err != nil {
		return nil, err
	}
	parsed, err := jsonx.Parse(b)
	if err != nil {
		return nil, err
	}
	result, err := fn(ctx, fromPayload(parsed))
	if err != nil {
		return nil, err
	}
	for _, sc := range child.ResponseHeaders.Values("Set-Cookie") {
		for _, part := range betterauth.SplitSetCookieHeader(sc) {
			name, value, attrs := betterauth.ParseSetCookie(part)
			if name == "" {
				continue
			}
			ctx.SetCookie(name, value, toCookieOptions(attrs))
		}
	}
	for k, vs := range child.ResponseHeaders {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		ctx.SetHeader(k, strings.Join(vs, ", "))
	}
	out, err := toObject(result)
	if err != nil {
		return nil, err
	}
	return betterauth.NewCustomSessionResult(sr.SessionWithUser, out), nil
}

// toCookieOptions mirrors cookie-utils toCookieOptions(parseSetCookieHeader(...)).
func toCookieOptions(attrs map[string]string) betterauth.CookieOptions {
	var o betterauth.CookieOptions
	for k, v := range attrs {
		switch k {
		case "max-age":
			if v != "" {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					o.MaxAge = betterauth.Int(n)
				}
			}
		case "expires":
			if t, err := http.ParseTime(strings.TrimSpace(v)); err == nil {
				o.Expires = &t
			}
		case "domain":
			o.Domain = v
		case "path":
			o.Path = v
		case "secure":
			o.Secure = true
		case "httponly":
			o.HTTPOnly = true
		case "samesite":
			o.SameSite = strings.ToLower(v)
		case "partitioned":
			o.Partitioned = true
		}
	}
	return o
}
