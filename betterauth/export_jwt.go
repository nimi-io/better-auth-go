package betterauth

// Exported helpers used by the jwt, bearer, multi-session, custom-session and
// last-login-method plugins (which live outside this package).

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// CookiePair is one request cookie.
type CookiePair struct {
	Name  string
	Value string
}

// ParseCookies parses a Cookie request header like better-auth's cookie-utils
// parseCookies: entries with an invalid name or value are dropped, values are
// URI-decoded, the last occurrence of a name wins and iteration keeps first-seen order.
func ParseCookies(header string) []CookiePair {
	list := parseCookieList(header)
	out := make([]CookiePair, len(list))
	for i, c := range list {
		out[i] = CookiePair{Name: c.name, Value: c.value}
	}
	return out
}

// SetRequestCookie adds or replaces a cookie in the request Cookie header
// (setRequestCookie): the header is re-serialized as `name=encodeURIComponent(value)`
// pairs joined with "; ".
func SetRequestCookie(h http.Header, name, value string) {
	list := parseCookieList(h.Get("Cookie"))
	if cookieNameRegex.MatchString(name) {
		found := false
		for i := range list {
			if list[i].name == name {
				list[i].value = value
				found = true
				break
			}
		}
		if !found {
			list = append(list, orderedCookie{name, value})
		}
	}
	parts := make([]string, len(list))
	for i, c := range list {
		parts[i] = c.name + "=" + EncodeURIComponent(c.value)
	}
	h.Set("Cookie", strings.Join(parts, "; "))
}

// CoreGetSession runs the core get-session handler on ctx (the `getSession()` endpoint
// function upstream, used by plugins that replace /get-session). The result is a
// *SessionResult, Null, or an error; ctx.Session and the response headers are updated.
func CoreGetSession(ctx *EndpointContext) (any, error) {
	return getSessionHandler(ctx)
}

// GetSessionQuerySchema is the get-session query schema (getSessionQuerySchema).
var GetSessionQuerySchema = getSessionQuery

// NewCustomSessionResult wraps a session with a replacement JSON body. Handlers that
// return it render out (null when nil) while GetSessionFromCtx and API.GetSession still
// see the underlying session (used by the custom-session plugin).
func NewCustomSessionResult(sw *SessionWithUser, out *jsonx.Object) *SessionResult {
	return &SessionResult{SessionWithUser: sw, json: out}
}

// GetCookieCacheWithVerifier is GetCookieCache for the "jwt" strategy with a custom token
// verifier (getCookieCache's `jwt.jwks` option, provided by the jwt plugin). verify returns
// the verified claims, or ok=false when the token is invalid.
func GetCookieCacheWithVerifier(h http.Header, o CookieCacheOptions, verify func(token string) (*jsonx.Object, bool)) (*SessionWithUser, error) {
	raw := h.Get("Cookie")
	if raw == "" {
		return nil, nil
	}
	if o.CookiePrefix == "" {
		o.CookiePrefix = "better-auth"
	}
	if o.CookieName == "" {
		o.CookieName = "session_data"
	}
	secure := isProduction()
	if o.IsSecure != nil {
		secure = *o.IsSecure
	}
	name := o.CookiePrefix + "." + o.CookieName
	if secure {
		name = SecureCookiePrefix + name
	}
	value := ""
	type chunk struct {
		idx int
		v   string
	}
	var chunks []chunk
	for _, c := range parseCookieList(raw) {
		if c.name == name {
			value = c.value
		} else if strings.HasPrefix(c.name, name+".") {
			parts := strings.Split(c.name, ".")
			if i, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				chunks = append(chunks, chunk{i, c.value})
			}
		}
	}
	if value == "" && len(chunks) > 0 {
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].idx < chunks[j].idx })
		var b strings.Builder
		for _, c := range chunks {
			b.WriteString(c.v)
		}
		value = b.String()
	}
	if value == "" {
		return nil, nil
	}
	if verify == nil {
		return GetCookieCache(h, o)
	}
	claims, ok := verify(value)
	if !ok || claims == nil {
		return nil, nil
	}
	p := parseCookieCachePayload(jsonx.ReviveDates(claims))
	if p == nil {
		return nil, nil
	}
	if o.Version != "" || o.VersionFunc != nil {
		want := o.Version
		if o.VersionFunc != nil {
			want = o.VersionFunc(p.Session, p.User)
		}
		if defaultVersion(p.Version) != want {
			return nil, nil
		}
	}
	if !p.Session.ExpiresAt.IsZero() && p.Session.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	return &SessionWithUser{Session: p.Session, User: p.User}, nil
}
