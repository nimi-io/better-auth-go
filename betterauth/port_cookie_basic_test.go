package betterauth

// Port of better-auth/src/cookies/cookies.test.ts (upstream v1.7.7): cookie naming and
// attributes, secure prefix rules, cross-subdomain, getSessionCookie, parseCookies,
// getChunkedCookie, parseSetCookieHeader and expireCookie.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

// ---- shared helpers ----

const (
	pkTestEmail    = "test@test.com"
	pkTestPassword = "test123456"
	pkTestName     = "test name"
)

// pkEnvWithUser mirrors getTestInstance: it builds an env and creates the default test user.
func pkEnvWithUser(t *testing.T, mutate func(c *Config)) *testEnv {
	t.Helper()
	env := newTestEnv(t, mutate)
	pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"email": pkTestEmail, "password": pkTestPassword, "name": pkTestName,
	}, "", 200)
	return env
}

// pkSignIn signs in the default test user from a fresh (cookie-less) request.
func pkSignIn(t *testing.T, env *testEnv, extra map[string]any) *testResponse {
	t.Helper()
	body := map[string]any{"email": pkTestEmail, "password": pkTestPassword}
	for k, v := range extra {
		body[k] = v
	}
	return pkDo(t, env, "POST", "/sign-in/email", body, "", 200)
}

// pkDo sends a request without a cookie jar; cookie is the raw Cookie header. When want is
// non-zero the status is asserted.
func pkDo(t *testing.T, env *testEnv, method, path string, body any, cookie string, want int) *testResponse {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, env.server.URL+"/api/auth"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", env.server.URL)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	out := &testResponse{Status: res.StatusCode, Header: res.Header, Body: b}
	if want != 0 && out.Status != want {
		t.Fatalf("%s %s: expected %d, got %d: %s", method, path, want, out.Status, b)
	}
	return out
}

// pkJoinedSetCookie mirrors response.headers.get("set-cookie") (values joined with ", ").
func pkJoinedSetCookie(res *testResponse) string {
	return strings.Join(res.Header.Values("Set-Cookie"), ", ")
}

type pkSetCookie struct {
	name, value, raw string
	attrs            map[string]string
}

// pkSetCookies parses each Set-Cookie line (last one wins per name, like a Map).
func pkSetCookies(res *testResponse) []pkSetCookie {
	var out []pkSetCookie
	idx := map[string]int{}
	for _, raw := range res.Header.Values("Set-Cookie") {
		n, v, a := ParseSetCookie(raw)
		c := pkSetCookie{name: n, value: v, raw: raw, attrs: a}
		if i, ok := idx[n]; ok {
			out[i] = c
			continue
		}
		idx[n] = len(out)
		out = append(out, c)
	}
	return out
}

func pkFindSetCookie(res *testResponse, name string) (pkSetCookie, bool) {
	for _, c := range pkSetCookies(res) {
		if c.name == name {
			return c, true
		}
	}
	return pkSetCookie{}, false
}

// pkCookieHeader mirrors cookieSetter(headers) (applySetCookies): every Set-Cookie
// name=value lands in a Cookie header, values re-encoded with encodeURIComponent.
func pkCookieHeader(res *testResponse) string {
	var parts []string
	for _, c := range pkSetCookies(res) {
		parts = append(parts, c.name+"="+EncodeURIComponent(c.value))
	}
	return strings.Join(parts, "; ")
}

func pkHeaders(cookie string) http.Header {
	h := http.Header{}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return h
}

func pkCookieMap(list []orderedCookie) map[string]string {
	m := map[string]string{}
	for _, c := range list {
		m[c.name] = c.value
	}
	return m
}

// pkLogger captures log calls.
type pkLogger struct {
	mu    sync.Mutex
	calls []pkLogCall
}

type pkLogCall struct {
	level, msg string
}

func (l *pkLogger) add(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, pkLogCall{level, msg})
}
func (l *pkLogger) Debug(msg string, _ ...any) { l.add("debug", msg) }
func (l *pkLogger) Info(msg string, _ ...any)  { l.add("info", msg) }
func (l *pkLogger) Warn(msg string, _ ...any)  { l.add("warn", msg) }
func (l *pkLogger) Error(msg string, _ ...any) { l.add("error", msg) }

func (l *pkLogger) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = nil
}

func (l *pkLogger) snapshot() []pkLogCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]pkLogCall(nil), l.calls...)
}

func (l *pkLogger) warned(substr string) bool {
	for _, c := range l.snapshot() {
		if c.level == "warn" && strings.Contains(c.msg, substr) {
			return true
		}
	}
	return false
}

// ---- describe("cookies") ----

func TestPortCookieSetsCookiesWithDefaultOptions(t *testing.T) {
	env := pkEnvWithUser(t, nil)
	setCookie := pkJoinedSetCookie(pkSignIn(t, env, nil))
	for _, want := range []string{"Path=/", "HttpOnly", "SameSite=Lax", "better-auth"} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("set-cookie %q missing %q", setCookie, want)
		}
	}
}

func TestPortCookieSetsMultipleCookies(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
	})
	res := pkSignIn(t, env, nil)
	if n := len(pkSetCookies(res)); n <= 1 {
		t.Fatalf("expected more than one cookie, got %d: %v", n, res.Header.Values("Set-Cookie"))
	}
}

func TestPortCookieUsesSecureCookies(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) { c.Advanced.UseSecureCookies = Bool(true) })
	if sc := pkJoinedSetCookie(pkSignIn(t, env, nil)); !strings.Contains(sc, "Secure") {
		t.Fatalf("expected Secure: %q", sc)
	}
}

func TestPortCookieUsesSecureCookiesWhenBaseURLIsHTTPS(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.BaseURL = "https://example.com"
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*")
	})
	if sc := pkJoinedSetCookie(pkSignIn(t, env, nil)); !strings.Contains(sc, "Secure") {
		t.Fatalf("expected Secure: %q", sc)
	}
}

func TestPortCookieProductionSecureWithoutBaseURL(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		t.Setenv("NODE_ENV", "production")
		c.BaseURL = ""
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*")
	})
	if sc := pkJoinedSetCookie(pkSignIn(t, env, nil)); !strings.Contains(sc, "Secure") {
		t.Fatalf("expected Secure: %q", sc)
	}
}

// ---- describe("crossSubdomainCookies") ----

func TestPortCookieCrossSubdomainCustomDomain(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.Advanced.CrossSubDomainCookies = &CrossSubDomainCookies{Enabled: true, Domain: "example.com"}
	})
	sc := pkJoinedSetCookie(pkSignIn(t, env, nil))
	if !strings.Contains(sc, "Domain=example.com") || !strings.Contains(sc, "SameSite=Lax") {
		t.Fatalf("unexpected set-cookie %q", sc)
	}
}

func TestPortCookieCrossSubdomainDefaultDomainFromBaseURL(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.BaseURL = "https://example.com"
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*")
		c.Advanced.CrossSubDomainCookies = &CrossSubDomainCookies{Enabled: true}
	})
	if sc := pkJoinedSetCookie(pkSignIn(t, env, nil)); !strings.Contains(sc, "Domain=example.com") {
		t.Fatalf("expected Domain=example.com: %q", sc)
	}
}

// ---- describe("cookie configuration") — getCookies(options) ----

func TestPortCookieConfigurationOptions(t *testing.T) {
	cfg := &Config{
		BaseURL: "https://example.com",
		Advanced: &AdvancedConfig{
			UseSecureCookies:      Bool(true),
			CrossSubDomainCookies: &CrossSubDomainCookies{Enabled: true, Domain: "example.com"},
			CookiePrefix:          "test-prefix",
		},
	}
	a := &Auth{}
	gen, err := newCookieGetter(cfg, a.useSecureCookies(cfg))
	if err != nil {
		t.Fatal(err)
	}
	cookies := buildAuthCookies(cfg, gen)
	if !cookies.SessionToken.Attributes.Secure {
		t.Fatal("sessionToken.secure should be true")
	}
	if !strings.Contains(cookies.SessionToken.Name, "test-prefix.session_token") {
		t.Fatalf("sessionToken name %q", cookies.SessionToken.Name)
	}
	if cookies.SessionData.Attributes.SameSite != "lax" {
		t.Fatalf("sessionData sameSite %q", cookies.SessionData.Attributes.SameSite)
	}
	if cookies.SessionData.Attributes.Domain != "example.com" {
		t.Fatalf("sessionData domain %q", cookies.SessionData.Attributes.Domain)
	}
}

// ---- describe("cookie-utils parseSetCookieHeader") ----
// Go has no comma-joined Set-Cookie splitter (net/http keeps Set-Cookie lines separate);
// single-cookie cases are ported against ParseSetCookie.

func TestPortCookieParseSetCookieHeaderSplitting(t *testing.T) {
	t.Skip("missing API: parseSetCookieHeader/splitSetCookieHeader (comma-joined Set-Cookie parsing); Go only has ParseSetCookie for a single line")
}

func TestPortCookieParseSetCookieDecodesURIValues(t *testing.T) {
	name, value, _ := ParseSetCookie("token=hello%20world%3Dfoo; Path=/")
	if name != "token" || value != "hello world=foo" {
		t.Fatalf("got %q=%q", name, value)
	}
}

func TestPortCookieParseSetCookieExpiresWithGMTValue(t *testing.T) {
	name, value, attrs := ParseSetCookie("session_data=testsessiondata; Path=/; Expires=Mon, 02 Mar 2026 05:42:16 GMT; Max-Age=300; Secure; HttpOnly; SameSite=lax")
	if name != "session_data" || value != "testsessiondata" {
		t.Fatalf("got %q=%q", name, value)
	}
	exp, err := http.ParseTime(attrs["expires"])
	if err != nil {
		t.Fatalf("expires %q: %v", attrs["expires"], err)
	}
	want, _ := http.ParseTime("Mon, 02 Mar 2026 05:42:16 GMT")
	if !exp.Equal(want) {
		t.Fatalf("expires %v want %v", exp, want)
	}
}

func TestPortCookieParseSetCookiePartitioned(t *testing.T) {
	name, value, attrs := ParseSetCookie("session=xyz; Path=/; Secure; HttpOnly; SameSite=None; Partitioned")
	if name != "session" || value != "xyz" {
		t.Fatalf("got %q=%q", name, value)
	}
	for _, k := range []string{"secure", "httponly", "partitioned"} {
		if _, ok := attrs[k]; !ok {
			t.Fatalf("missing boolean attribute %q: %v", k, attrs)
		}
	}
	if strings.ToLower(attrs["samesite"]) != "none" {
		t.Fatalf("samesite %q", attrs["samesite"])
	}
}

func TestPortCookieToCookieOptions(t *testing.T) {
	t.Skip("missing API: toCookieOptions (parsed Set-Cookie attributes -> CookieOptions)")
}

// ---- describe("cookie-utils stripSecureCookiePrefix") ----

func TestPortCookieStripSecureCookiePrefix(t *testing.T) {
	t.Skip("missing API: stripSecureCookiePrefix / HOST_COOKIE_PREFIX")
}

// ---- describe("cookie-utils setRequestCookie") ----

func TestPortCookieSetRequestCookie(t *testing.T) {
	t.Skip("missing API: setRequestCookie")
}

// ---- describe("getSessionCookie") ----

func TestPortCookieGetSessionCookieReturnsSessionCookie(t *testing.T) {
	// Covers: request, Headers object, Headers-like and cross-realm Headers variants
	// (Go takes an http.Header in all cases).
	env := pkEnvWithUser(t, nil)
	h := pkHeaders(pkCookieHeader(pkSignIn(t, env, nil)))
	if v := GetSessionCookie(h, ""); v == "" {
		t.Fatalf("expected session cookie in %q", h.Get("Cookie"))
	}
}

func TestPortCookieGetSessionCookieOnProduction(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.BaseURL = "https://example.com"
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*")
	})
	h := pkHeaders(pkCookieHeader(pkSignIn(t, env, nil)))
	if v := GetSessionCookie(h, ""); v == "" {
		t.Fatalf("expected session cookie in %q", h.Get("Cookie"))
	}
}

func TestPortCookieGetSessionCookieSeparatorsAndPrefixes(t *testing.T) {
	type cfg struct {
		cookiePrefix, cookieName string
		prefix, name             string
	}
	cases := []cfg{
		{"", "", "better-auth", "session_token"},
		{"myprefix", "", "myprefix", "session_token"},
		{"", "my_token", "better-auth", "my_token"},
		{"myprefix", "my_token", "myprefix", "my_token"},
	}
	for _, sep := range []string{".", "-"} {
		for _, secure := range []string{"", SecureCookiePrefix} {
			for _, c := range cases {
				c := c
				t.Run(sep+"/"+secure+c.prefix+"/"+c.name, func(t *testing.T) {
					if c.cookieName != "" {
						t.Skip("missing API: GetSessionCookie has no cookieName option")
					}
					h := pkHeaders(secure + c.prefix + sep + c.name + "=token-123")
					if got := GetSessionCookie(h, c.cookiePrefix); got != "token-123" {
						t.Fatalf("got %q", got)
					}
				})
			}
		}
	}
}

func TestPortCookieGetSessionCookiePrefersSecure(t *testing.T) {
	h := pkHeaders("better-auth.session_token=stale; __Secure-better-auth.session_token=current")
	if got := GetSessionCookie(h, ""); got != "current" {
		t.Fatalf("got %q", got)
	}
}

func TestPortCookieGetSessionCookieNoFallbackWhenSecureEmpty(t *testing.T) {
	h := pkHeaders("better-auth.session_token=stale; __Secure-better-auth.session_token=")
	if got := GetSessionCookie(h, ""); got != "" {
		t.Fatalf("expected null (no fallback to non-secure leftover), got %q", got)
	}
}

func TestPortCookieGetSessionCookieOverridePrefixWithSecure(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.Advanced.UseSecureCookies = Bool(true)
		c.Advanced.CookiePrefix = "test-prefix"
	})
	h := pkHeaders(pkCookieHeader(pkSignIn(t, env, nil)))
	if v := GetSessionCookie(h, "test-prefix"); v == "" {
		t.Fatalf("expected session cookie in %q", h.Get("Cookie"))
	}
}

func TestPortCookieGetSessionCookieOverrideCookieName(t *testing.T) {
	t.Skip("missing API: GetSessionCookie has no cookieName option (upstream getSessionCookie(request, {cookieName}))")
}

// ---- describe("sensitive session middleware cookie cache") ----

func TestPortCookieSensitiveEndpointIgnoresQueryCookieCache(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
	})
	signIn := pkSignIn(t, env, nil)
	cookie := pkCookieHeader(signIn)
	user, _ := signIn.JSON(t)["user"].(map[string]any)
	userID, _ := user["id"].(string)
	if userID == "" {
		t.Fatalf("no user id: %s", signIn.Body)
	}
	if err := env.auth.Context().InternalAdapter.DeleteUserSessions(context.Background(), userID); err != nil {
		t.Fatal(err)
	}
	res := pkDo(t, env, "POST", "/change-password?disableCookieCache=", map[string]any{
		"newPassword": "new-password", "currentPassword": pkTestPassword,
	}, cookie, 0)
	if res.Status != 401 {
		t.Fatalf("expected 401, got %d: %s", res.Status, res.Body)
	}
}

// ---- describe("parse cookies") / parseCookies validation ----

func TestPortCookieParseCookiesKeyValue(t *testing.T) {
	m := pkCookieMap(parseCookieList("better-auth.session_token=session-token.signature; better-auth.session_data=session-data.signature"))
	if m["better-auth.session_token"] != "session-token.signature" || m["better-auth.session_data"] != "session-data.signature" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieParseCookiesSignedWithPadding(t *testing.T) {
	m := pkCookieMap(parseCookieList("better-auth.session_token=session-token.signature=; better-auth.session_data=session-data.signature="))
	if m["better-auth.session_token"] != "session-token.signature=" || m["better-auth.session_data"] != "session-data.signature=" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieParseCookiesSemicolonOnly(t *testing.T) {
	m := pkCookieMap(parseCookieList("better-auth.session_token=session-token.signature;better-auth.session_data=session-data.signature"))
	if m["better-auth.session_token"] != "session-token.signature" || m["better-auth.session_data"] != "session-data.signature" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieParseCookiesMixedSeparators(t *testing.T) {
	m := pkCookieMap(parseCookieList("a=1; b=2;c=3;\td=4"))
	if m["a"] != "1" || m["b"] != "2" || m["c"] != "3" || m["d"] != "4" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieGetSessionCookieSemicolonOnly(t *testing.T) {
	if got := GetSessionCookie(pkHeaders("preference=dark;better-auth.session_token=token-123"), ""); got != "token-123" {
		t.Fatalf("got %q", got)
	}
}

func TestPortCookieGetChunkedCookieSemicolonOnly(t *testing.T) {
	ctx := &EndpointContext{Headers: pkHeaders("better-auth.session_data.0=chunkA;better-auth.session_data.1=chunkB")}
	if got := GetChunkedCookie(ctx, "better-auth.session_data"); got != "chunkAchunkB" {
		t.Fatalf("got %q", got)
	}
}

func TestPortCookieGetChunkedCookieIgnoresNonCanonical(t *testing.T) {
	for _, name := range []string{
		"better-auth.session_data.0junk",
		"better-auth.session_data.nested.0",
		"better-auth.session_data.01",
		"better-auth.session_data.-1",
	} {
		ctx := &EndpointContext{Headers: pkHeaders(name + "=chunk")}
		if got := GetChunkedCookie(ctx, "better-auth.session_data"); got != "" {
			t.Fatalf("%s: expected null, got %q", name, got)
		}
	}
}

func TestPortCookieParseCookiesEmpty(t *testing.T) {
	if n := len(parseCookieList("")); n != 0 {
		t.Fatalf("expected empty, got %d", n)
	}
}

func TestPortCookieParseCookiesRejectsBadNames(t *testing.T) {
	m := pkCookieMap(parseCookieList("bad name=v1; ok=v2; bad,name=v3; bad:name=v4"))
	for _, k := range []string{"bad name", "bad,name", "bad:name"} {
		if _, ok := m[k]; ok {
			t.Fatalf("should reject %q: %v", k, m)
		}
	}
	if m["ok"] != "v2" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieParseCookiesRejectsBadValues(t *testing.T) {
	m := pkCookieMap(parseCookieList("a=ok; b=has\rcr; c=has\"quote; d=has\\slash"))
	if m["a"] != "ok" {
		t.Fatalf("got %v", m)
	}
	for _, k := range []string{"b", "c", "d"} {
		if _, ok := m[k]; ok {
			t.Fatalf("should reject %q: %v", k, m)
		}
	}
}

func TestPortCookieParseCookiesAcceptsSpaceAndComma(t *testing.T) {
	m := pkCookieMap(parseCookieList("a=hello world; b=v1,v2"))
	if m["a"] != "hello world" || m["b"] != "v1,v2" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieParseCookiesSplitsOnFirstEquals(t *testing.T) {
	if m := pkCookieMap(parseCookieList("a=b=c=d")); m["a"] != "b=c=d" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieParseCookiesRejectsCRLF(t *testing.T) {
	m := pkCookieMap(parseCookieList("a=ok\r; b\r=1; c=v\nv; d=ok"))
	for _, k := range []string{"a", "b", "c"} {
		if _, ok := m[k]; ok {
			t.Fatalf("should reject %q: %v", k, m)
		}
	}
	if m["d"] != "ok" {
		t.Fatalf("got %v", m)
	}
}

func TestPortCookieParseCookiesStripsQuotes(t *testing.T) {
	m := pkCookieMap(parseCookieList(`a="hello"; b=plain; c="with space"`))
	if m["a"] != "hello" || m["b"] != "plain" || m["c"] != "with space" {
		t.Fatalf("got %v", m)
	}
}

// ---- describe("applySetCookies") ----

func TestPortCookieApplySetCookies(t *testing.T) {
	t.Skip("missing API: applySetCookies / setCookieToHeader")
}

// ---- describe("expireCookie") ----

func TestPortCookieExpireCookiePreservesAttributes(t *testing.T) {
	ctx := &EndpointContext{}
	ExpireCookie(ctx, AuthCookie{Name: "test", Attributes: CookieOptions{Path: "/custom", HTTPOnly: true}})
	got := ctx.ResponseHeaders.Values("Set-Cookie")
	want, _ := SerializeCookie("test", "", CookieOptions{Path: "/custom", HTTPOnly: true, MaxAge: Int(0)})
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v want [%s]", got, want)
	}
	// setCookie must receive exactly {path, httpOnly, maxAge: 0}.
	_, _, attrs := ParseSetCookie(got[0])
	if attrs["path"] != "/custom" || attrs["max-age"] != "0" {
		t.Fatalf("attrs %v", attrs)
	}
	if _, ok := attrs["httponly"]; !ok {
		t.Fatalf("attrs %v", attrs)
	}
	for _, k := range []string{"secure", "samesite", "domain", "expires"} {
		if _, ok := attrs[k]; ok {
			t.Fatalf("unexpected attribute %q: %v", k, attrs)
		}
	}
}

func TestPortCookieExpireCookieScrubsPendingSetCookies(t *testing.T) {
	ctx := &EndpointContext{ResponseHeaders: http.Header{}}
	ctx.ResponseHeaders.Add("Set-Cookie", "keep=1; Path=/")
	ctx.ResponseHeaders.Add("Set-Cookie", "target=valid; Path=/")
	ctx.ResponseHeaders.Add("Set-Cookie", "target.0=chunk; Path=/")
	ExpireCookie(ctx, AuthCookie{Name: "target", Attributes: CookieOptions{Path: "/"}})
	joined := strings.Join(ctx.ResponseHeaders.Values("Set-Cookie"), ", ")
	if !strings.Contains(joined, "keep=1") {
		t.Fatalf("keep removed: %q", joined)
	}
	if strings.Contains(joined, "target=valid") || strings.Contains(joined, "target.0=chunk") {
		t.Fatalf("stale target entries survived: %q", joined)
	}
	found := false
	for _, sc := range ctx.ResponseHeaders.Values("Set-Cookie") {
		n, v, a := ParseSetCookie(sc)
		if n == "target" && v == "" && a["path"] == "/" && a["max-age"] == "0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected target=; Path=/; Max-Age=0 in %q", joined)
	}
}

// ---- describe("account cookie sync on user switch") ----

func pcAccountSwitchEnv(t *testing.T) (*testEnv, *oauth2test.Server) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){pacStoreAccountCookie, poCookieCache()}, poInstanceOpts{disableTestUser: true})
	return env, m
}

// pcGoogleSignIn mocks the Google token endpoint for (email, sub) and runs sign-in/social +
// callback on c, returning the callback response.
func pcGoogleSignIn(t *testing.T, c *testClient, m *oauth2test.Server, email, sub string) *testResponse {
	t.Helper()
	poMockGoogleToken(m, poGoogleProfile(email, true, sub, "Test User", "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw"),
		map[string]any{"access_token": "access-token-" + sub, "refresh_token": "refresh-token-" + sub})
	state := poSocialState(t, c, map[string]any{"provider": "google", "callbackURL": "/callback"})
	res := poCallback(t, c, "google", state)
	if res.Status != 302 {
		t.Fatalf("callback: %d %s", res.Status, res.Body)
	}
	return res
}

// pcSetCookie returns the parsed Set-Cookie entry for name in res, if any.
func pcSetCookie(res *testResponse, name string) (value string, attrs map[string]string, ok bool) {
	for _, sc := range res.Header.Values("Set-Cookie") {
		if n, v, a := ParseSetCookie(sc); n == name {
			value, attrs, ok = v, a, true
		}
	}
	return
}

func TestPortCookieAccountCookieSyncOnUserSwitch(t *testing.T) {
	t.Run("keeps the fresh account cookie issued for the new user when the request carries another user's stale account cookie", func(t *testing.T) {
		env, m := pcAccountSwitchEnv(t)
		ac := env.auth.Context()
		name := ac.AuthCookies.AccountData.Name
		c := env.client()
		pcGoogleSignIn(t, c, m, "switch-first@test.com", "switch-first-sub")
		res := pcGoogleSignIn(t, c, m, "switch-second@test.com", "switch-second-sub")
		v, attrs, ok := pcSetCookie(res, name)
		if !ok || v == "" || attrs["max-age"] == "0" {
			t.Fatalf("expected a fresh %s cookie, got ok=%v value=%q attrs=%v", name, ok, v, attrs)
		}
		s := c.session()
		u, _ := s["user"].(map[string]any)
		if u["email"] != "switch-second@test.com" {
			t.Fatalf("session user %v", u)
		}
		dec, _ := url.QueryUnescape(v)
		data := bacrypto.SymmetricDecodeJWT(dec, ac.SecretConfig, "better-auth-account")
		if data == nil {
			t.Fatal("account cookie did not decode")
		}
		if uid, _ := data.Get("userId"); uid != u["id"] {
			t.Fatalf("account cookie userId %v, session user %v", uid, u["id"])
		}
	})
	t.Run("still expires another user's stale account cookie when the response issues no fresh one", func(t *testing.T) {
		env, m := pcAccountSwitchEnv(t)
		name := env.auth.Context().AuthCookies.AccountData.Name
		c := env.client()
		pcGoogleSignIn(t, c, m, "expire-first@test.com", "expire-first-sub")
		res := c.signUp("expire-second@test.com", "password123456", "Second User")
		if res.Status != 200 {
			t.Fatalf("sign-up %d %s", res.Status, res.Body)
		}
		v, attrs, ok := pcSetCookie(res, name)
		if !ok || v != "" || attrs["max-age"] != "0" {
			t.Fatalf("expected %s to be expired, got ok=%v value=%q attrs=%v", name, ok, v, attrs)
		}
	})
}
