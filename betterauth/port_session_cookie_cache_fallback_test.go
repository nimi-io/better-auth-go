package betterauth

// Port of better-auth/src/api/routes/cookie-cache-fallback.test.ts (v1.7.7).

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const psRetiredSecret = "better-auth-retired-cookie-cache-test-secret"

func psRetiredInstance(t *testing.T, cacheEnabled bool) *psInst {
	return psNew(t, func(c *Config) {
		c.Secret = psRetiredSecret
		if c.Advanced == nil {
			c.Advanced = &AdvancedConfig{}
		}
		c.Advanced.Cookies = map[string]CookieOverride{
			"session_token": {Name: "custom.session_token"},
			"session_data":  {Name: "custom.session"},
		}
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: cacheEnabled, Strategy: "compact", MaxAge: 5 * time.Minute}
	})
}

func psRetiredCache(t *testing.T) string {
	t.Helper()
	v, err := bacrypto.SymmetricEncodeJWT(jsonx.O("retired", true), bacrypto.PlainSecret(psRetiredSecret), "better-auth-session", 0)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// @see https://github.com/better-auth/better-auth/issues/11119
func TestPortSessionDisabledCookieCacheFallback(t *testing.T) {
	const cacheMaxAge = 5 * 60
	for _, tc := range []struct {
		mode         string
		cacheEnabled bool
		query        string
		want         int
	}{
		{"in configuration", false, "", 0},
		{"for the request", true, "disableCookieCache=true", cacheMaxAge},
	} {
		t.Run("ignores retired session_data when caching is disabled "+tc.mode, func(t *testing.T) {
			p := psRetiredInstance(t, tc.cacheEnabled)
			headers := psNewJar()
			p.signIn(headers, nil)
			cookie := headers.header() + "; custom.session=" + psRetiredCache(t) + "; custom.session.0=stale; custom.session.1=chunks"
			res, s := p.getSession(cookie, tc.query)
			if s == nil || psMap(t, s["user"], "user")["email"] != psEmail {
				t.Fatalf("session = %v (%d %s)", s, res.Status, res.Body)
			}
			got, ok := psMaxAge(res.Header, "custom.session")
			if !ok || got != tc.want {
				t.Fatalf("custom.session max-age = %v (present=%v), want %d; set-cookie=%v", got, ok, tc.want, res.Header.Values("Set-Cookie"))
			}
			for _, n := range []string{"custom.session.0", "custom.session.1"} {
				if got, ok := psMaxAge(res.Header, n); !ok || got != 0 {
					t.Fatalf("%s max-age = %v (present=%v), want 0; set-cookie=%v", n, got, ok, res.Header.Values("Set-Cookie"))
				}
			}
			if _, ok := psSetCookies(res.Header)["custom.session_token"]; ok {
				t.Fatalf("unexpected custom.session_token Set-Cookie: %v", res.Header.Values("Set-Cookie"))
			}
		})
	}
	for _, tc := range []struct{ state, tokenCookie string }{
		{"missing", ""},
		{"invalid", "; custom.session_token=invalid"},
	} {
		t.Run("clears retired session_data when session_token is "+tc.state, func(t *testing.T) {
			p := psRetiredInstance(t, false)
			cookie := "custom.session=" + psRetiredCache(t) + "; custom.session.0=stale; custom.session.1=chunks" + tc.tokenCookie
			res, s := p.getSession(cookie, "")
			if s != nil {
				t.Fatalf("expected null, got %v", s)
			}
			for _, n := range []string{"custom.session", "custom.session.0", "custom.session.1"} {
				if got, ok := psMaxAge(res.Header, n); !ok || got != 0 {
					t.Fatalf("%s max-age = %v (present=%v), want 0; set-cookie=%v", n, got, ok, res.Header.Values("Set-Cookie"))
				}
			}
		})
	}
}

// btoa(JSON.stringify(v))
func psBtoaJSON(v any) string {
	raw, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(raw)
}

func psCompactInstance(t *testing.T, strategy string) (*psInst, *psJar) {
	p := psNew(t, func(c *Config) {
		psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, Strategy: strategy}
	})
	headers := psNewJar()
	p.signIn(headers, nil)
	return p, headers
}

// @see https://github.com/better-auth/better-auth/issues/9233
func TestPortSessionCookieCacheHMACFallback(t *testing.T) {
	t.Run("should fall through to session_token DB validation when session_data HMAC fails", func(t *testing.T) {
		p, headers := psCompactInstance(t, "compact")
		if _, s := p.getSession(headers.header(), ""); s == nil || psMap(t, s["user"], "user")["email"] != psEmail {
			t.Fatalf("initial session = %v", s)
		}
		token, ok := headers.get("better-auth.session_token")
		if !ok {
			t.Fatal("session_token missing")
		}
		invalid := psBtoaJSON(map[string]any{
			"session": map[string]any{
				"session":   map[string]any{"token": "fake", "userId": "fake"},
				"user":      map[string]any{"id": "fake", "email": "fake@example.com"},
				"updatedAt": time.Now().UnixMilli(),
			},
			"expiresAt": time.Now().Add(5 * time.Minute).UnixMilli(),
			"signature": "invalid-signature-that-will-fail-hmac-verification",
		})
		_, s := p.getSession("better-auth.session_data="+invalid+"; better-auth.session_token="+EncodeURIComponent(token), "")
		if s == nil || psMap(t, s["user"], "user")["email"] != psEmail {
			t.Fatalf("expected DB fallback, got %v", s)
		}
	})

	t.Run("should expire malformed compact session_data and fall through to session_token DB validation", func(t *testing.T) {
		p, headers := psCompactInstance(t, "compact")
		token, ok := headers.get("better-auth.session_token")
		if !ok {
			t.Fatal("session_token missing")
		}
		res, s := p.getSession("better-auth.session_data="+base64.StdEncoding.EncodeToString([]byte("not-json"))+"; better-auth.session_token="+EncodeURIComponent(token), "")
		if s == nil || psMap(t, s["user"], "user")["email"] != psEmail {
			t.Fatalf("expected DB fallback, got %v", s)
		}
		setCookie := strings.Join(res.Header.Values("Set-Cookie"), ", ")
		if !strings.Contains(setCookie, "better-auth.session_data=") || !strings.Contains(setCookie, "Max-Age=0") {
			t.Fatalf("set-cookie = %s", setCookie)
		}
	})

	t.Run("should still return null when both session_data and session_token are invalid", func(t *testing.T) {
		p, _ := psCompactInstance(t, "compact")
		invalid := psBtoaJSON(map[string]any{
			"session": map[string]any{
				"session":   map[string]any{"token": "fake", "userId": "fake"},
				"user":      map[string]any{"id": "fake", "email": "fake@example.com"},
				"updatedAt": time.Now().UnixMilli(),
			},
			"expiresAt": time.Now().Add(5 * time.Minute).UnixMilli(),
			"signature": "invalid-signature",
		})
		if _, s := p.getSession("better-auth.session_data="+invalid+"; better-auth.session_token=invalid-token.invalid-signature", ""); s != nil {
			t.Fatalf("expected null, got %v", s)
		}
	})

	for _, tc := range []struct{ name, strategy, data string }{
		{"should work with JWT strategy when HMAC verification fails", "jwt", "invalid.jwt.token"},
		{"should work with JWE strategy when decryption fails", "jwe", "invalid.jwe.token.here.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, headers := psCompactInstance(t, tc.strategy)
			token, _ := headers.get("better-auth.session_token")
			_, s := p.getSession("better-auth.session_data="+tc.data+"; better-auth.session_token="+EncodeURIComponent(token), "")
			if s == nil || psMap(t, s["user"], "user")["email"] != psEmail {
				t.Fatalf("expected DB fallback, got %v", s)
			}
		})
	}

	t.Run("should handle cross-subdomain cookie migration without silent logout", func(t *testing.T) {
		p := psNew(t, func(c *Config) {
			c.BaseURL = "https://www.app.example.com"
			psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, MaxAge: 10 * time.Second}
			if c.Advanced == nil {
				c.Advanced = &AdvancedConfig{}
			}
			c.Advanced.CrossSubDomainCookies = &CrossSubDomainCookies{Enabled: true, Domain: ".example.com"}
		})
		// The cookies are Secure and scoped to .example.com, so drive the API directly.
		signIn := p.apiSignIn()
		headers := psNewJar()
		for _, sc := range signIn.Headers.Values("Set-Cookie") {
			n, v, _ := ParseSetCookie(sc)
			headers.set(n, v)
		}
		token, ok := headers.get("__Secure-better-auth.session_token")
		if !ok {
			token, ok = headers.get("better-auth.session_token")
		}
		if !ok || token == "" {
			t.Fatalf("session token missing: %v", signIn.Headers.Values("Set-Cookie"))
		}
		initial, err := p.apiGetSession(headers.header(), "")
		if err != nil || psSessionResult(t, initial) == nil {
			t.Fatalf("initial session: %v %v", initial, err)
		}
		now := time.Now()
		stale := psBtoaJSON(map[string]any{
			"session": map[string]any{
				"session": map[string]any{
					"token": "old-session-token", "userId": "old-user-id",
					"expiresAt": now.Add(-time.Second).UTC().Format("2006-01-02T15:04:05.000Z"),
					"createdAt": now.UTC().Format("2006-01-02T15:04:05.000Z"),
					"updatedAt": now.UTC().Format("2006-01-02T15:04:05.000Z"),
				},
				"user": map[string]any{
					"id": "old-user-id", "email": psEmail, "name": psName, "emailVerified": false,
					"createdAt": now.UTC().Format("2006-01-02T15:04:05.000Z"),
					"updatedAt": now.UTC().Format("2006-01-02T15:04:05.000Z"),
				},
				"updatedAt": now.Add(-time.Minute).UnixMilli(),
			},
			"expiresAt": now.Add(-time.Second).UnixMilli(),
			"signature": "stale-signature-from-old-domain-cookie",
		})
		res, err := p.apiGetSession("__Secure-better-auth.session_data="+stale+"; __Secure-better-auth.session_token="+EncodeURIComponent(token), "")
		if err != nil {
			t.Fatal(err)
		}
		sr := psSessionResult(t, res)
		if sr == nil || sr.User.Email != psEmail {
			t.Fatalf("expected DB fallback, got %#v", res.Data)
		}
	})

	t.Run("should work during cookieCache window even with stale session_data", func(t *testing.T) {
		p := psNew(t, func(c *Config) {
			psSessionCfg(c).CookieCache = &CookieCacheConfig{Enabled: true, MaxAge: 60 * time.Second}
		})
		headers := psNewJar()
		p.signIn(headers, nil)
		if _, s := p.getSession(headers.header(), ""); s == nil {
			t.Fatal("expected initial session")
		}
		token, _ := headers.get("better-auth.session_token")
		stale := psBtoaJSON(map[string]any{
			"session": map[string]any{
				"session":   map[string]any{"token": "stale", "userId": "stale"},
				"user":      map[string]any{"id": "stale", "email": "stale@example.com"},
				"updatedAt": time.Now().Add(-time.Hour).UnixMilli(),
			},
			"expiresAt": time.Now().Add(-time.Second).UnixMilli(),
			"signature": "stale-signature-from-old-deployment",
		})
		_, s := p.getSession("better-auth.session_data="+stale+"; better-auth.session_token="+EncodeURIComponent(token), "")
		if s == nil || psMap(t, s["user"], "user")["email"] != psEmail {
			t.Fatalf("expected DB fallback, got %v", s)
		}
	})
}
