package jwt_test

// Ports of the betterauth cookie-cache tests that need the jwt plugin
// (api/routes/session-api.test.ts "cookie cache with JWT strategy backed by JWKS" and
// cookies/cookies.test.ts getCookieCache jwt.jwks cases). The betterauth package cannot
// import plugins, so its skipped placeholders point here.

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// applySetCookies is cookieSetter / setCookieToHeader: merges Set-Cookie values into the
// Cookie header.
func applySetCookies(h http.Header, res *response) {
	for _, sc := range res.Header.Values("Set-Cookie") {
		n, v, attrs := betterauth.ParseSetCookie(sc)
		_ = attrs
		betterauth.SetRequestCookie(h, n, v)
	}
}

func cookieOf(h http.Header, name string) string {
	for _, c := range betterauth.ParseCookies(h.Get("Cookie")) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

type findOneSpy struct {
	adapter.Adapter
	n *atomic.Int64
}

func (s findOneSpy) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	s.n.Add(1)
	return s.Adapter.FindOne(ctx, in)
}

func jwksCacheInstance(t *testing.T, mutate func(c *betterauth.Config), o jwt.Options) (*instance, *atomic.Int64) {
	n := &atomic.Int64{}
	o.SessionCookieCache = true
	in := newInstance(t, func(c *betterauth.Config) {
		store := memory.NewDB()
		c.Database = func(opts adapter.Options) (adapter.Adapter, error) {
			a, err := memory.New(store)(opts)
			if err != nil {
				return nil, err
			}
			return findOneSpy{Adapter: a, n: n}, nil
		}
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, Strategy: "jwt"}}
		if mutate != nil {
			mutate(c)
		}
		c.Plugins = append(c.Plugins, jwt.New(o))
	})
	return in, n
}

func signInJar(t *testing.T, in *instance) http.Header {
	t.Helper()
	res := in.do("POST", "/sign-in/email", map[string]any{"email": in.email, "password": in.password}, nil)
	if res.Status != 200 {
		t.Fatalf("sign-in %d %s", res.Status, res.Body)
	}
	h := http.Header{}
	applySetCookies(h, res)
	return h
}

func getJwks(t *testing.T, in *instance) jose.JWKS {
	t.Helper()
	r, err := in.call("getJwks", betterauth.CallInput{})
	if err != nil {
		t.Fatal(err)
	}
	var set jose.JWKS
	if err := r.Decode(&set); err != nil {
		t.Fatal(err)
	}
	return set
}

func verifyCacheJWT(t *testing.T, token string, set jose.JWKS) (*jsonx.Object, *jsonx.Object) {
	t.Helper()
	h, p, err := jose.VerifyJWT(token, jose.KeySetFunc(set), jose.VerifyOptions{Audience: []string{jwt.SessionCookieJWTAudience}})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return h, p
}

func TestCookieCacheJWTStrategyBackedByJWKS(t *testing.T) {
	in, findOne := jwksCacheInstance(t, func(c *betterauth.Config) {
		c.Session.AdditionalFields = []db.Field{{Name: "sensitiveData", Type: db.TypeString, Returned: db.False, DefaultValue: "sensitive-data"}}
	}, jwt.Options{})

	t.Run("should cache cookies with JWKS-backed JWT strategy", func(t *testing.T) {
		h := signInJar(t, in)
		before := findOne.Load()
		res := in.do("GET", "/get-session", nil, h)
		session := res.json(t)
		token := cookieOf(h, "better-auth.session_data")
		if token == "" {
			t.Fatal("JWT not found")
		}
		hdr, err := jose.Header(token)
		if err != nil {
			t.Fatal(err)
		}
		if kid, _ := hdr.Get("kid"); kid == "" {
			t.Fatal("no kid")
		}
		if typ, _ := hdr.Get("typ"); typ != jwt.SessionCookieJWTType {
			t.Fatalf("typ %v", typ)
		}
		_, p := verifyCacheJWT(t, token, getJwks(t, in))
		user := session["user"].(map[string]any)
		sess := session["session"].(map[string]any)
		iss, _ := p.Get("iss")
		aud, _ := p.Get("aud")
		sub, _ := p.Get("sub")
		sid, _ := p.Get("sid")
		if _, ok := p.Get("session"); !ok {
			t.Fatal("no session claim")
		}
		if s, _ := iss.(string); s == "" || aud != jwt.SessionCookieJWTAudience || sub != user["id"] || sid != sess["token"] {
			t.Fatalf("claims iss=%v aud=%v sub=%v sid=%v", iss, aud, sub, sid)
		}
		if _, ok := sess["sensitiveData"]; ok {
			t.Fatal("sensitiveData leaked")
		}
		if after := findOne.Load(); after != before {
			t.Fatalf("get-session hit the database (%d findOne calls)", after-before)
		}
	})

	t.Run("should ignore a JWKS cookie cache from a different session token", func(t *testing.T) {
		first := signInJar(t, in)
		firstSession := in.do("GET", "/get-session", nil, first).json(t)
		second := signInJar(t, in)
		secondSession := in.do("GET", "/get-session", nil, second).json(t)
		mixed := http.Header{}
		mixed.Set("Cookie", "better-auth.session_data="+cookieOf(first, "better-auth.session_data")+"; better-auth.session_token="+betterauth.EncodeURIComponent(cookieOf(second, "better-auth.session_token")))
		m := in.do("GET", "/get-session", nil, mixed).json(t)
		tok := m["session"].(map[string]any)["token"]
		if tok != secondSession["session"].(map[string]any)["token"] || tok == firstSession["session"].(map[string]any)["token"] {
			t.Fatalf("mixed session token %v", tok)
		}
	})

	t.Run("should not allow tampering with the cookie in JWKS mode", func(t *testing.T) {
		h := signInJar(t, in)
		_, p := verifyCacheJWT(t, cookieOf(h, "better-auth.session_data"), getJwks(t, in))
		sv, _ := p.Get("session")
		uv, _ := p.Get("user")
		user := uv.(*jsonx.Object).Clone().Set("id", "tampered-id")
		tampered, err := bacrypto.SignJWT(jsonx.O("session", sv, "user", user), "tampered-secret", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		h.Set("Cookie", "better-auth.session_data="+tampered+"; better-auth.session_token="+betterauth.EncodeURIComponent(cookieOf(h, "better-auth.session_token")))
		res := in.do("GET", "/get-session", nil, h).json(t)
		u := res["user"].(map[string]any)
		if u["id"] == "tampered-id" || u["email"] != in.email {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("should reject a secret-signed cookie cache and fall back to the database", func(t *testing.T) {
		h := signInJar(t, in)
		sessionCookie := cookieOf(h, "better-auth.session_token")
		_, p := verifyCacheJWT(t, cookieOf(h, "better-auth.session_data"), getJwks(t, in))
		sv, _ := p.Get("session")
		uv, _ := p.Get("user")
		secretSigned, err := bacrypto.SignJWT(jsonx.O("session", sv, "user", uv, "updatedAt", float64(time.Now().UnixMilli()), "version", "1"), in.auth.Context().Secret, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		h.Set("Cookie", "better-auth.session_data="+secretSigned+"; better-auth.session_token="+betterauth.EncodeURIComponent(sessionCookie))
		res := in.do("GET", "/get-session", nil, h)
		body := res.json(t)
		if body["user"].(map[string]any)["email"] != in.email || body["session"].(map[string]any)["token"] != sv.(*jsonx.Object).Map()["token"] {
			t.Fatalf("body %v", body)
		}
		replaced, ok := setCookieValue(res.Header, "better-auth.session_data")
		if !ok || replaced == "" || replaced == secretSigned {
			t.Fatalf("cookie cache was not replaced (%q)", replaced)
		}
		hdr, _ := jose.Header(replaced)
		if typ, _ := hdr.Get("typ"); typ != jwt.SessionCookieJWTType {
			t.Fatalf("typ %v", typ)
		}
	})

	t.Run("should verify existing cookie-cache JWTs across JWKS rotation grace period", func(t *testing.T) {
		grace := time.Minute
		rin, _ := jwksCacheInstance(t, nil, jwt.Options{JWKS: &jwt.JWKSOptions{RotationInterval: time.Second, GracePeriod: &grace}})
		h := signInJar(t, rin)
		original := cookieOf(h, "better-auth.session_data")
		if original == "" {
			t.Fatal("JWT not found")
		}
		time.Sleep(1100 * time.Millisecond)
		if _, err := rin.call("signJWT", betterauth.CallInput{Body: map[string]any{"payload": map[string]any{"sub": "rotated-user"}}}); err != nil {
			t.Fatal(err)
		}
		set := getJwks(t, rin)
		if len(set.Keys) <= 1 {
			t.Fatalf("keys %d", len(set.Keys))
		}
		_, p := verifyCacheJWT(t, original, set)
		if _, ok := p.Get("session"); !ok {
			t.Fatal("no session claim")
		}
	})
}

func TestGetCookieCacheJWKS(t *testing.T) {
	notSecure := false
	opts := func(set *jose.JWKS) jwt.CookieCacheOptions {
		return jwt.CookieCacheOptions{CookieCacheOptions: betterauth.CookieCacheOptions{Strategy: "jwt", IsSecure: &notSecure}, JWKS: set}
	}
	t.Run("should work with JWT strategy backed by JWKS keys", func(t *testing.T) {
		in, _ := jwksCacheInstance(t, nil, jwt.Options{})
		h := signInJar(t, in)
		token := cookieOf(h, "better-auth.session_data")
		hdr, _ := jose.Header(token)
		if alg, _ := hdr.Get("alg"); alg != "EdDSA" {
			t.Fatalf("alg %v", alg)
		}
		set := getJwks(t, in)
		cache, err := jwt.GetCookieCache(h, opts(&set))
		if err != nil || cache == nil || cache.User.Email != in.email {
			t.Fatalf("cache %+v %v", cache, err)
		}
		_, p := verifyCacheJWT(t, token, set)
		sub, _ := p.Get("sub")
		sid, _ := p.Get("sid")
		if typ, _ := hdr.Get("typ"); typ != jwt.SessionCookieJWTType || sub != cache.User.ID || sid != cache.Session.Token {
			t.Fatalf("claims sub=%v sid=%v", sub, sid)
		}
	})
	t.Run("should require a secret when helper verification has no JWKS", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_SECRET", "")
		h := http.Header{}
		h.Set("Cookie", "better-auth.session_data=token")
		_, err := jwt.GetCookieCache(h, opts(nil))
		if err == nil || !strings.Contains(err.Error(), "getCookieCache requires a secret to be provided") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("should reject JWT plugin tokens that are not cookie-cache JWTs", func(t *testing.T) {
		in := newInstance(t, withJWT(jwt.Options{}))
		r, err := in.call("signJWT", betterauth.CallInput{Body: map[string]any{"payload": map[string]any{"sub": "user-id"}}})
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Token string }
		_ = r.Decode(&out)
		set := getJwks(t, in)
		h := http.Header{}
		h.Set("Cookie", "better-auth.session_data="+out.Token)
		if cache, _ := jwt.GetCookieCache(h, opts(&set)); cache != nil {
			t.Fatalf("cache %+v", cache)
		}
	})
	t.Run("should return null when JWKS verification uses the wrong key set", func(t *testing.T) {
		in, _ := jwksCacheInstance(t, nil, jwt.Options{})
		h := signInJar(t, in)
		if len(getJwks(t, in).Keys) == 0 {
			t.Fatal("no keys")
		}
		if cache, _ := jwt.GetCookieCache(h, opts(&jose.JWKS{Keys: []jose.JWK{}})); cache != nil {
			t.Fatalf("cache %+v", cache)
		}
	})
	t.Run("should chunk JWKS-backed JWT cookies when they exceed 4KB", func(t *testing.T) {
		large := strings.Repeat("j", 2000)
		in, _ := jwksCacheInstance(t, func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
				{Name: "field1", Type: db.TypeString, DefaultValue: ""},
				{Name: "field2", Type: db.TypeString, DefaultValue: ""},
			}}}
		}, jwt.Options{})
		res := in.do("POST", "/sign-up/email", map[string]any{"name": "JWKS Chunk User", "email": "jwks-chunk-test@example.com",
			"password": "password123", "field1": large, "field2": large}, nil)
		if res.Status != 200 {
			t.Fatalf("sign-up %d %s", res.Status, res.Body)
		}
		hasChunks := false
		for _, sc := range res.Header.Values("Set-Cookie") {
			if strings.Contains(sc, "session_data.0") || strings.Contains(sc, "session_data.1") {
				hasChunks = true
			}
		}
		if !hasChunks {
			t.Fatal("expected chunks")
		}
		h := http.Header{}
		applySetCookies(h, res)
		set := getJwks(t, in)
		cache, err := jwt.GetCookieCache(h, opts(&set))
		if err != nil || cache == nil || cache.User.Email != "jwks-chunk-test@example.com" || cache.Session.Token == "" {
			t.Fatalf("cache %+v %v", cache, err)
		}
	})
}

func TestSessionCookieCacheInit(t *testing.T) {
	t.Run("requires session.cookieCache.strategy jwt", func(t *testing.T) {
		t.Setenv("NODE_ENV", "test")
		_, err := betterauth.New(betterauth.Config{BaseURL: "http://localhost:3000", Secret: testSecret, Logger: betterauth.NopLogger{},
			Plugins: []*betterauth.Plugin{jwt.New(jwt.Options{SessionCookieCache: true})}})
		if err == nil || !strings.Contains(err.Error(), "requires `session.cookieCache.strategy = \"jwt\"`") {
			t.Fatalf("err %v", err)
		}
	})
}
