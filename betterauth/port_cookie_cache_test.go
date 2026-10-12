package betterauth

// Port of better-auth/src/cookies/cookies.test.ts (upstream v1.7.7): cookie cache
// (getCookieCache, field filtering, strategies), chunking and compact-cache expiry.
//
// Go has no exported getCookieCache(request, {secret, strategy, cookiePrefix}) helper.
// pkGetCookieCache reproduces its cookie lookup (name + chunk reassembly via
// GetChunkedCookie) and delegates decoding to the internal decoders (decodeCompactCache /
// VerifyJWT + parseCookieCachePayload). Freshness checks of getCookieCache are ported
// through the get-session endpoint instead (see the expiry tests at the bottom).

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const pkCacheSecret = "better-auth.secret"

type pkCacheOpts struct {
	secret, strategy, cookiePrefix string
}

func pkGetCookieCache(t *testing.T, cookie string, o pkCacheOpts) *cookieCachePayload {
	t.Helper()
	if cookie == "" {
		return nil
	}
	prefix := o.cookiePrefix
	if prefix == "" {
		prefix = "better-auth"
	}
	name := prefix + ".session_data"
	if isProduction() {
		name = SecureCookiePrefix + name
	}
	ctx := &EndpointContext{Headers: pkHeaders(cookie)}
	value := GetChunkedCookie(ctx, name)
	if value == "" {
		return nil
	}
	switch o.strategy {
	case "jwt":
		decoded, err := bacrypto.VerifyJWT(value, o.secret)
		if err != nil {
			return nil
		}
		return parseCookieCachePayload(jsonx.ReviveDates(decoded))
	default:
		return decodeCompactCache(value, o.secret)
	}
}

// pkRawCookieHeader mirrors headers.append("cookie", `${name}=${value.value}`) for every
// parsed Set-Cookie (undici joins Cookie values with "; ").
func pkRawCookieHeader(res *testResponse) string {
	var parts []string
	for _, c := range pkSetCookies(res) {
		parts = append(parts, c.name+"="+c.value)
	}
	return strings.Join(parts, "; ")
}

func pkStringField(name string, def any, returned *bool) db.Field {
	return db.Field{Name: name, Type: db.TypeString, DefaultValue: def, Returned: returned}
}

func pkCacheEnv(t *testing.T, mutate func(c *Config)) *testEnv {
	return pkEnvWithUser(t, func(c *Config) {
		c.Secret = pkCacheSecret
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
		if mutate != nil {
			mutate(c)
		}
	})
}

func pkHasChunks(res *testResponse) bool {
	for _, c := range pkSetCookies(res) {
		if strings.Contains(c.name, "session_data.0") || strings.Contains(c.name, "session_data.1") {
			return true
		}
	}
	return false
}

// ---- describe("getSessionCookie") cookie cache cases ----

func TestPortCookieGetCookieCacheReturnsCache(t *testing.T) {
	env := pkCacheEnv(t, nil)
	cookie := pkCookieHeader(pkSignIn(t, env, nil))
	cache := pkGetCookieCache(t, cookie, pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatalf("expected cache from %q", cookie)
	}
	if cache.User.Email != pkTestEmail || cache.Session.Token == "" {
		t.Fatalf("unexpected cache %+v %+v", cache.User, cache.Session)
	}
}

func TestPortCookieCacheRespectsDontRememberMe(t *testing.T) {
	env := pkCacheEnv(t, nil)
	res := pkSignIn(t, env, map[string]any{"rememberMe": false})
	tok, ok := pkFindSetCookie(res, "better-auth.session_token")
	if !ok {
		t.Fatalf("no session_token: %v", res.Header.Values("Set-Cookie"))
	}
	if _, has := tok.attrs["max-age"]; has {
		t.Fatalf("session_token should have no max-age: %s", tok.raw)
	}
	data, ok := pkFindSetCookie(res, "better-auth.session_data")
	if !ok {
		t.Fatalf("no session_data: %v", res.Header.Values("Set-Cookie"))
	}
	if _, has := data.attrs["max-age"]; has {
		t.Fatalf("session_data should have no max-age: %s", data.raw)
	}
}

func TestPortCookieGetCookieCacheNullWhenInvalid(t *testing.T) {
	env := pkEnvWithUser(t, func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
	})
	pkSignIn(t, env, nil)
	// Upstream passes an empty Headers (the sign-in cookies are never captured).
	if cache := pkGetCookieCache(t, "", pkCacheOpts{secret: "wrong-secret"}); cache != nil {
		t.Fatalf("expected null, got %+v", cache)
	}
}

func TestPortCookieGetCookieCacheWrongSecret(t *testing.T) {
	// Companion to the case above that actually exercises the signature check.
	env := pkEnvWithUser(t, func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
	})
	cookie := pkCookieHeader(pkSignIn(t, env, nil))
	if cache := pkGetCookieCache(t, cookie, pkCacheOpts{secret: "wrong-secret"}); cache != nil {
		t.Fatalf("expected null, got %+v", cache)
	}
}

func TestPortCookieGetCookieCacheThrowsWithoutSecret(t *testing.T) {
	t.Skip("missing API: getCookieCache (secret-less call throwing BetterAuthError)")
}

func TestPortCookieChunksLargeCookiesInsteadOfError(t *testing.T) {
	env := newTestEnv(t, func(c *Config) {
		c.Secret = pkCacheSecret
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			pkStringField("customField1", "", nil), pkStringField("customField2", "", nil), pkStringField("customField3", "", nil),
		}}}
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
	})
	large := strings.Repeat("x", 2000)
	res := pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"name": "Test User", "email": "large-data-test@example.com", "password": "password123",
		"customField1": large, "customField2": large, "customField3": large,
	}, "", 200)
	if !pkHasChunks(res) {
		t.Fatalf("expected chunked session_data: %v", res.Header.Values("Set-Cookie"))
	}
}

// ---- describe("Cookie Cache Field Filtering") ----

func TestPortCookieCacheExcludesUnreturnedUserField(t *testing.T) {
	env := pkCacheEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			pkStringField("internalNote", "", Bool(false)),
		}}}
	})
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if cache.User.Email != pkTestEmail {
		t.Fatalf("email %q", cache.User.Email)
	}
	if _, ok := cache.User.Additional["internalNote"]; ok {
		t.Fatalf("internalNote should be excluded: %v", cache.User.Additional)
	}
}

func TestPortCookieCacheFiltersMultipleUserFields(t *testing.T) {
	env := pkCacheEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			pkStringField("publicBio", "default-bio", Bool(true)),
			pkStringField("internalNotes", "internal-notes", Bool(false)),
			pkStringField("preferences", "default-prefs", Bool(true)),
			pkStringField("adminFlags", "admin-flags", Bool(false)),
		}}}
	})
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	add := cache.User.Additional
	if add["publicBio"] == nil || add["preferences"] == nil {
		t.Fatalf("returned fields missing: %v", add)
	}
	for _, k := range []string{"internalNotes", "adminFlags"} {
		if _, ok := add[k]; ok {
			t.Fatalf("%s should be excluded: %v", k, add)
		}
	}
}

func TestPortCookieCacheReducesSizeWhenLargeFieldsExcluded(t *testing.T) {
	large := strings.Repeat("x", 2000)
	env := pkCacheEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			pkStringField("largeBio", large, Bool(false)),
			pkStringField("smallField", "small-value", Bool(true)),
		}}}
	})
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if _, ok := cache.User.Additional["largeBio"]; ok {
		t.Fatal("largeBio should be excluded")
	}
	if cache.User.Additional["smallField"] == nil {
		t.Fatalf("smallField missing: %v", cache.User.Additional)
	}
}

func TestPortCookieCacheSessionFieldFiltering(t *testing.T) {
	env := pkCacheEnv(t, func(c *Config) {
		c.Session.AdditionalFields = []db.Field{
			pkStringField("internalSessionData", "internal-data", Bool(false)),
			pkStringField("publicSessionData", "public-data", Bool(true)),
		}
	})
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if cache.Session.Token == "" {
		t.Fatal("session token missing")
	}
	if _, ok := cache.Session.Additional["internalSessionData"]; ok {
		t.Fatalf("internalSessionData should be excluded: %v", cache.Session.Additional)
	}
}

func TestPortCookieCacheIncludesStandardFields(t *testing.T) {
	env := pkCacheEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			pkStringField("knownField", "known-value", Bool(false)),
		}}}
	})
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if _, ok := cache.User.Additional["knownField"]; ok {
		t.Fatal("knownField should be excluded")
	}
	if cache.User.Email != pkTestEmail || cache.User.Name == "" {
		t.Fatalf("standard fields missing: %+v", cache.User)
	}
}

func TestPortCookieCacheJWTStrategy(t *testing.T) {
	env := pkCacheEnv(t, func(c *Config) { c.Session.CookieCache.Strategy = "jwt" })
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret, strategy: "jwt"})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if cache.User.Email != pkTestEmail || cache.Session.Token == "" {
		t.Fatalf("unexpected cache %+v", cache.User)
	}
}

func TestPortCookieCacheJWTStrategyJWKS(t *testing.T) {
	t.Skip("unimplemented plugin: jwt({ sessionCookieCache: true }) / getCookieCache jwt.jwks verification")
}

func TestPortCookieCacheCompactStrategy(t *testing.T) {
	env := pkCacheEnv(t, func(c *Config) { c.Session.CookieCache.Strategy = "compact" })
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret, strategy: "compact"})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if cache.User.Email != pkTestEmail || cache.Session.Token == "" {
		t.Fatalf("unexpected cache %+v", cache.User)
	}
}

// pkBuildCompactCookie mirrors setCookieCache's compact encoding.
func pkBuildCompactCookie(secret string, sessionData *jsonx.Object, outerExpiresAt float64) string {
	signed := sessionData.Clone().Set("expiresAt", outerExpiresAt)
	sig := bacrypto.Base64URLNoPad(bacrypto.HMACSHA256([]byte(secret), jsonx.MustMarshal(signed)))
	return bacrypto.Base64URLNoPad(jsonx.MustMarshal(jsonx.O("session", sessionData, "expiresAt", outerExpiresAt, "signature", sig)))
}

func pkNowMs() float64 { return float64(time.Now().UnixMilli()) }

func TestPortCookieCacheInvalidCompactCookieUsesConfiguredLogger(t *testing.T) {
	const secret = "test-secret"
	logger := &pkLogger{}
	env := newTestEnv(t, func(c *Config) {
		c.Secret = secret
		c.Logger = logger
		c.Advanced.CookiePrefix = "p"
		c.Advanced.UseSecureCookies = Bool(false)
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
	})
	bake := func(emailVerified any) string {
		now := jsonx.ISOTime(time.Now())
		data := jsonx.O(
			"session", jsonx.O("id", "s1", "token", "tok", "userId", "u1",
				"expiresAt", jsonx.ISOTime(time.Now().Add(24*time.Hour)), "createdAt", now, "updatedAt", now),
			"user", jsonx.O("id", "u1", "name", "Test", "email", "a@b.com", "emailVerified", emailVerified,
				"createdAt", now, "updatedAt", now),
			"updatedAt", pkNowMs(),
			"version", "1",
		)
		return pkBuildCompactCookie(secret, data, pkNowMs()+300_000)
	}
	decode := func(v string) *cookieCachePayload {
		ctx := &EndpointContext{Auth: env.auth.Context(), Headers: pkHeaders("p.session_data=" + v)}
		return decodeCookieCache(ctx, GetChunkedCookie(ctx, "p.session_data"))
	}
	logger.reset()
	if decode(bake(false)) == nil {
		t.Fatal("expected valid cache")
	}
	if calls := logger.snapshot(); len(calls) != 0 {
		t.Fatalf("logger should not be called: %v", calls)
	}
	if decode(bake(nil)) != nil {
		t.Fatal("expected null for emailVerified=null")
	}
	calls := logger.snapshot()
	if len(calls) != 1 || calls[0].level != "warn" {
		t.Fatalf("expected exactly one warn log for the schema failure, got %v", calls)
	}
}

func TestPortCookieCacheInvalidJWTReturnsNull(t *testing.T) {
	if cache := pkGetCookieCache(t, "better-auth.session_data=invalid.jwt.token", pkCacheOpts{secret: pkCacheSecret, strategy: "jwt"}); cache != nil {
		t.Fatalf("expected null, got %+v", cache)
	}
}

func TestPortCookieCacheRequiresSecretWithoutJWKS(t *testing.T) {
	t.Skip("missing API: getCookieCache (secret-less jwt call throwing 'getCookieCache requires a secret')")
}

func TestPortCookieCacheRejectsNonCacheJWTPluginTokens(t *testing.T) {
	t.Skip("unimplemented plugin: jwt() signJWT/getJwks + getCookieCache jwt.jwks")
}

func TestPortCookieCacheWrongJWKSReturnsNull(t *testing.T) {
	t.Skip("unimplemented plugin: jwt({ sessionCookieCache: true }) + getCookieCache jwt.jwks")
}

func TestPortCookieCacheDefaultsToCompact(t *testing.T) {
	env := pkCacheEnv(t, nil)
	if s := env.auth.Context().cookieCacheStrategy(); s != "compact" {
		t.Fatalf("default strategy %q", s)
	}
	cache := pkGetCookieCache(t, pkCookieHeader(pkSignIn(t, env, nil)), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if cache.User.Email != pkTestEmail || cache.Session.Token == "" {
		t.Fatalf("unexpected cache %+v", cache.User)
	}
}

// ---- describe("Cookie Chunking") ----

func pkChunkEnv(t *testing.T, fields []db.Field, mutate func(c *Config)) *testEnv {
	return newTestEnv(t, func(c *Config) {
		c.Secret = pkCacheSecret
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: fields}}
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
		if mutate != nil {
			mutate(c)
		}
	})
}

func TestPortCookieChunksOver4KB(t *testing.T) {
	env := pkChunkEnv(t, []db.Field{pkStringField("field1", "", nil), pkStringField("field2", "", nil)}, nil)
	large := strings.Repeat("x", 2000)
	res := pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"name": "Test User", "email": "chunk-test@example.com", "password": "password123",
		"field1": large, "field2": large,
	}, "", 200)
	if !pkHasChunks(res) {
		t.Fatalf("expected chunks: %v", res.Header.Values("Set-Cookie"))
	}
	cache := pkGetCookieCache(t, pkRawCookieHeader(res), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if cache.User.Email != "chunk-test@example.com" || cache.Session.Token == "" {
		t.Fatalf("unexpected cache %+v", cache.User)
	}
}

func TestPortCookieChunksJWKSBackedJWT(t *testing.T) {
	t.Skip("unimplemented plugin: jwt({ sessionCookieCache: true })")
}

func TestPortCookieReconstructsChunkedCookies(t *testing.T) {
	env := pkChunkEnv(t, []db.Field{pkStringField("largeField", "", nil)}, nil)
	large := strings.Repeat("y", 2500)
	res := pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"name": "Large Data User", "email": "large-chunk-test@example.com", "password": "password123",
		"largeField": large,
	}, "", 200)
	cache := pkGetCookieCache(t, pkCookieHeader(res), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil {
		t.Fatal("expected cache")
	}
	if cache.User.Email != "large-chunk-test@example.com" {
		t.Fatalf("email %q", cache.User.Email)
	}
	if got, _ := cache.User.Additional["largeField"].(string); got != large {
		t.Fatalf("largeField length %d, want %d", len(got), len(large))
	}
}

func TestPortCookieCleansUpChunksOnSignOut(t *testing.T) {
	env := pkChunkEnv(t, []db.Field{pkStringField("field1", "", nil), pkStringField("field2", "", nil)}, nil)
	large := strings.Repeat("z", 2000)
	res := pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"name": "Delete Test User", "email": "delete-chunk-test@example.com", "password": "password123",
		"field1": large, "field2": large,
	}, "", 200)
	out := pkDo(t, env, "POST", "/sign-out", map[string]any{}, pkRawCookieHeader(res), 200)
	if len(out.Header.Values("Set-Cookie")) == 0 {
		t.Fatal("expected set-cookie on sign-out")
	}
	cleaned := false
	for _, c := range pkSetCookies(out) {
		if strings.Contains(c.name, "session_data") {
			if c.attrs["max-age"] != "0" {
				t.Fatalf("%s should have Max-Age=0: %s", c.name, c.raw)
			}
			cleaned = true
		}
	}
	if !cleaned {
		t.Fatalf("no session_data cleanup cookies: %v", out.Header.Values("Set-Cookie"))
	}
}

func TestPortCookieDoesNotChunkUnder4KB(t *testing.T) {
	env := pkCacheEnv(t, nil)
	res := pkSignIn(t, env, nil)
	single := false
	for _, c := range pkSetCookies(res) {
		if strings.HasSuffix(c.name, "session_data") {
			single = true
		}
	}
	if pkHasChunks(res) || !single {
		t.Fatalf("expected a single session_data cookie: %v", res.Header.Values("Set-Cookie"))
	}
	cache := pkGetCookieCache(t, pkRawCookieHeader(res), pkCacheOpts{secret: pkCacheSecret})
	if cache == nil || cache.User.Email != pkTestEmail {
		t.Fatalf("unexpected cache %+v", cache)
	}
}

func TestPortCookieChunksWhenAttributesOverflow(t *testing.T) {
	longPrefix := "better-auth-" + strings.Repeat("x", 80)
	env := pkChunkEnv(t, []db.Field{pkStringField("entraProfile", "", nil)}, func(c *Config) {
		c.Advanced.CookiePrefix = longPrefix
	})
	res := pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"name": "Entra User", "email": "entra-chunk@example.com", "password": "password123",
		"entraProfile": strings.Repeat("x", 2400),
	}, "", 200)
	var dataCookies []pkSetCookie
	for _, c := range pkSetCookies(res) {
		if strings.Contains(c.name, "session_data") {
			dataCookies = append(dataCookies, c)
		}
	}
	chunkRe := regexp.MustCompile(`session_data\.\d+$`)
	chunked := false
	var parts []string
	for _, c := range dataCookies {
		if len(c.raw) > 4093 {
			t.Fatalf("session_data cookie %q serialized to %d bytes", c.name, len(c.raw))
		}
		if chunkRe.MatchString(c.name) {
			chunked = true
		}
		parts = append(parts, c.name+"="+c.value)
	}
	if !chunked {
		t.Fatalf("expected chunked session_data: %v", res.Header.Values("Set-Cookie"))
	}
	cache := pkGetCookieCache(t, strings.Join(parts, "; "), pkCacheOpts{secret: pkCacheSecret, cookiePrefix: longPrefix})
	if cache == nil || cache.User.Email != "entra-chunk@example.com" {
		t.Fatalf("unexpected cache %+v", cache)
	}
}

func pkAssertCacheSkipped(t *testing.T, env *testEnv, logger *pkLogger, res *testResponse, email string) {
	t.Helper()
	if string(res.Body) == "null" || len(res.Body) == 0 {
		t.Fatalf("sign-up should succeed: %s", res.Body)
	}
	hasData, hasToken := false, false
	for _, c := range pkSetCookies(res) {
		if strings.Contains(c.name, "session_data") {
			hasData = true
		}
		if strings.Contains(c.name, "session_token") {
			hasToken = true
		}
	}
	if hasData {
		t.Fatalf("session_data should be skipped: %d cookies", len(res.Header.Values("Set-Cookie")))
	}
	if !hasToken {
		t.Fatal("session_token should still be set")
	}
	if !logger.warned("too large to store even after chunking") {
		t.Fatalf("expected warn, got %v", logger.snapshot())
	}
	sw, err := env.auth.API.GetSession(context.Background(), http.Header{"Cookie": {pkCookieHeader(res)}})
	if err != nil {
		t.Fatal(err)
	}
	if sw == nil || sw.User.Email != email {
		t.Fatalf("expected session for %s, got %+v", email, sw)
	}
}

func TestPortCookieSkipsCacheWhenTooLargeToChunk(t *testing.T) {
	logger := &pkLogger{}
	env := pkChunkEnv(t, []db.Field{pkStringField("blob", "", nil)}, func(c *Config) { c.Logger = logger })
	res := pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"name": "Big", "email": "too-big@example.com", "password": "password123",
		"blob": strings.Repeat("x", 420_000),
	}, "", 200)
	pkAssertCacheSkipped(t, env, logger, res, "too-big@example.com")
}

func TestPortCookieSkipsCacheWhenPrefixOverflows(t *testing.T) {
	logger := &pkLogger{}
	longPrefix := "better-auth-" + strings.Repeat("x", 4100)
	env := pkChunkEnv(t, nil, func(c *Config) {
		c.Logger = logger
		c.Advanced.CookiePrefix = longPrefix
	})
	res := pkDo(t, env, "POST", "/sign-up/email", map[string]any{
		"name": "No Room", "email": "no-room@example.com", "password": "password123",
	}, "", 200)
	pkAssertCacheSkipped(t, env, logger, res, "no-room@example.com")
}

// ---- describe("getCookieCache expiry (compact strategy)") ----
// Ported through get-session: the request carries a valid signed session_token for a
// session that does not exist in the database, so a non-null response can only come from
// the cookie cache, and a stale cache must yield null.

func pkExpiryCookie(embeddedExpiresAt time.Time, outerExpiresAt float64) string {
	now := jsonx.ISOTime(time.Now())
	data := jsonx.O(
		"session", jsonx.O("id", "s1", "token", "session-token", "userId", "u1",
			"createdAt", now, "updatedAt", now, "expiresAt", jsonx.ISOTime(embeddedExpiresAt)),
		"user", jsonx.O("id", "u1", "email", "cache@test.com", "emailVerified", true, "name", "Cache User",
			"createdAt", now, "updatedAt", now),
		"updatedAt", pkNowMs(),
		"version", "1",
	)
	return pkBuildCompactCookie(pkCacheSecret, data, outerExpiresAt)
}

func pkExpiryGetSession(t *testing.T, cacheCookie string) *testResponse {
	t.Helper()
	env := newTestEnv(t, func(c *Config) {
		c.Secret = pkCacheSecret
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true}}
	})
	signed := "session-token." + bacrypto.MakeSignature("session-token", pkCacheSecret)
	cookie := "better-auth.session_token=" + EncodeURIComponent(signed) + "; better-auth.session_data=" + cacheCookie
	return pkDo(t, env, "GET", "/get-session", nil, cookie, 200)
}

func TestPortCookieCacheExpiryFreshSnapshot(t *testing.T) {
	res := pkExpiryGetSession(t, pkExpiryCookie(time.Now().Add(time.Hour), pkNowMs()+5*60*1000))
	if string(res.Body) == "null" {
		t.Fatal("expected session from cache")
	}
	user, _ := res.JSON(t)["user"].(map[string]any)
	if user["email"] != "cache@test.com" {
		t.Fatalf("unexpected body %s", res.Body)
	}
}

func TestPortCookieCacheExpiryEmbeddedSessionExpired(t *testing.T) {
	res := pkExpiryGetSession(t, pkExpiryCookie(time.Now().Add(-time.Minute), pkNowMs()+5*60*1000))
	if string(res.Body) != "null" {
		t.Fatalf("expected null, got %s", res.Body)
	}
}

func TestPortCookieCacheExpiryWindowElapsed(t *testing.T) {
	res := pkExpiryGetSession(t, pkExpiryCookie(time.Now().Add(time.Hour), pkNowMs()-60*1000))
	if string(res.Body) != "null" {
		t.Fatalf("expected null, got %s", res.Body)
	}
}
