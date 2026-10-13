// Package bearer is the bearer plugin (packages/better-auth/src/plugins/bearer): it lets
// clients authenticate with `Authorization: Bearer <session token>` instead of the session
// cookie, and exposes the session token in the `set-auth-token` response header.
package bearer

import (
	"net/http"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Options configure the bearer plugin.
type Options struct {
	// RequireSignature rejects unsigned tokens (the raw session token without its
	// ".signature" suffix). Signed tokens are what set-auth-token returns.
	RequireSignature bool
}

const bearerScheme = "bearer "

func tryDecode(s string) string {
	d, err := betterauth.DecodeURIComponent(s)
	if err != nil {
		return s
	}
	return d
}

// New creates the bearer plugin.
func New(opts ...Options) *betterauth.Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	return &betterauth.Plugin{
		ID:      "bearer",
		Options: o,
		Hooks: betterauth.PluginHooks{
			Before: []betterauth.Hook{{
				Matcher: func(ctx *betterauth.EndpointContext) bool {
					return authorizationHeader(ctx) != ""
				},
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					beforeHook(ctx, o)
					return nil, nil
				},
			}},
			After: []betterauth.Hook{{
				Matcher: func(*betterauth.EndpointContext) bool { return true },
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					afterHook(ctx)
					return nil, nil
				},
			}},
		},
	}
}

// authorizationHeader reads the Authorization header from the request, then the call
// headers (request?.headers.get("authorization") || headers?.get("authorization")).
func authorizationHeader(ctx *betterauth.EndpointContext) string {
	if ctx.Request != nil {
		if v := ctx.Request.Header.Get("Authorization"); v != "" {
			return v
		}
	}
	return ctx.GetHeader("Authorization")
}

func beforeHook(ctx *betterauth.EndpointContext, o Options) {
	authHeader := authorizationHeader(ctx)
	if authHeader == "" {
		return
	}
	if len(authHeader) < len(bearerScheme) || strings.ToLower(authHeader[:len(bearerScheme)]) != bearerScheme {
		return
	}
	token := strings.TrimSpace(authHeader[len(bearerScheme):])
	if token == "" {
		return
	}
	secret := ctx.Auth.Secret
	var decoded string
	if strings.Contains(token, ".") {
		decoded = token
		if strings.Contains(token, "%") {
			decoded = tryDecode(token)
		}
	} else {
		if o.RequireSignature {
			return
		}
		// serializeSignedCookie("", token, secret) without the leading "=", decoded
		decoded = token + "." + bacrypto.MakeSignature(token, secret)
	}
	parts := strings.Split(decoded, ".")
	if len(parts) < 2 {
		return
	}
	sig, err := bacrypto.DecodeBase64Loose(parts[1])
	if err != nil {
		return
	}
	if !bacrypto.ConstantTimeEqual(bacrypto.HMACSHA256([]byte(secret), []byte(parts[0])), sig) {
		return
	}
	var base http.Header
	if ctx.Request != nil {
		base = ctx.Request.Header
	} else {
		base = ctx.Headers
	}
	headers := http.Header{}
	for k, vs := range base {
		// new Headers({...Object.fromEntries(entries())}) keeps one (comma-joined) value
		headers.Set(k, strings.Join(vs, ", "))
	}
	if c := base.Values("Cookie"); len(c) > 1 {
		headers.Set("Cookie", strings.Join(c, "; "))
	}
	betterauth.SetRequestCookie(headers, ctx.Auth.AuthCookies.SessionToken.Name, decoded)
	ctx.Headers = headers
}

func afterHook(ctx *betterauth.EndpointContext) {
	setCookies := ctx.ResponseHeaders.Values("Set-Cookie")
	if len(setCookies) == 0 {
		return
	}
	name := ctx.Auth.AuthCookies.SessionToken.Name
	var value string
	var found bool
	var maxAgeZero bool
	// parseSetCookieHeader keeps the last entry for a name
	for _, sc := range setCookies {
		for _, part := range betterauth.SplitSetCookieHeader(sc) {
			n, v, attrs := betterauth.ParseSetCookie(part)
			if n != name {
				continue
			}
			found = true
			value = v
			maxAgeZero = false
			if ma, ok := attrs["max-age"]; ok && strings.TrimSpace(ma) == "0" {
				maxAgeZero = true
			}
		}
	}
	if !found || value == "" || maxAgeZero {
		return
	}
	exposed := ctx.ResponseHeaders.Get("Access-Control-Expose-Headers")
	var list []string
	seen := map[string]bool{}
	for _, h := range strings.Split(exposed, ",") {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		list = append(list, h)
	}
	if !seen["set-auth-token"] {
		list = append(list, "set-auth-token")
	}
	ctx.SetHeader("set-auth-token", value)
	ctx.SetHeader("Access-Control-Expose-Headers", strings.Join(list, ", "))
}
