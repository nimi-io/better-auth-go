package betterauth

// Port of packages/better-auth/src/utils/url.test.ts (upstream v1.7.7).

import (
	"net/http"
	"strings"
	"testing"
)

// pnRequest mirrors `new Request(url, { headers })`. A "host" entry is kept as a header
// (as undici does) so getHostFromRequest sees it.
func pnRequest(t *testing.T, rawURL string, headers map[string]string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func pnMustBaseURL(t *testing.T, raw, path string, r *http.Request, loadEnv, trusted bool) string {
	t.Helper()
	v, err := getBaseURL(raw, path, r, loadEnv, trusted)
	if err != nil {
		t.Fatalf("getBaseURL error: %v", err)
	}
	return v
}

func TestPortNetURLTrimTrailingSlashes(t *testing.T) {
	t.Run("should remove trailing slashes", func(t *testing.T) {
		if got := trimTrailingSlashes("https://example.com///"); got != "https://example.com" {
			t.Fatalf("got %q", got)
		}
		if got := trimTrailingSlashes("///"); got != "" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should leave non-trailing slashes unchanged", func(t *testing.T) {
		v := "https://example.com/" + strings.Repeat("/", 10_000) + "a"
		if got := trimTrailingSlashes(v); got != v {
			t.Fatalf("value changed")
		}
	})
}

func TestPortNetURLGetBaseURL(t *testing.T) {
	t.Run("should append the auth path after trailing slashes", func(t *testing.T) {
		if got := pnMustBaseURL(t, "https://example.com////", "/auth", nil, false, false); got != "https://example.com/auth" {
			t.Fatalf("got %q", got)
		}
	})

	fallback := "http://localhost:3000/auth"
	cases := []struct {
		name    string
		headers map[string]string
		trusted bool
		want    string
	}{
		{"should reject malicious protocol in X-Forwarded-Proto", map[string]string{"x-forwarded-host": "example.com", "x-forwarded-proto": "javascript"}, true, fallback},
		{"should reject file protocol in X-Forwarded-Proto", map[string]string{"x-forwarded-host": "example.com", "x-forwarded-proto": "file"}, true, fallback},
		{"should reject path traversal in X-Forwarded-Host", map[string]string{"x-forwarded-host": "../../../etc/passwd", "x-forwarded-proto": "http"}, true, fallback},
		{"should reject HTML injection in X-Forwarded-Host", map[string]string{"x-forwarded-host": "<script>alert('xss')</script>", "x-forwarded-proto": "http"}, true, fallback},
		{"should reject empty X-Forwarded-Host", map[string]string{"x-forwarded-host": "", "x-forwarded-proto": "http"}, true, fallback},
		{"should reject whitespace-only X-Forwarded-Host", map[string]string{"x-forwarded-host": "   ", "x-forwarded-proto": "http"}, true, fallback},
		{"should accept valid hostname with port", map[string]string{"x-forwarded-host": "example.com:8080", "x-forwarded-proto": "https"}, true, "https://example.com:8080/auth"},
		{"should accept valid IPv4 address", map[string]string{"x-forwarded-host": "192.168.1.1", "x-forwarded-proto": "https"}, true, "https://192.168.1.1/auth"},
		{"should accept valid IPv4 address with port", map[string]string{"x-forwarded-host": "192.168.1.1:3000", "x-forwarded-proto": "http"}, true, "http://192.168.1.1:3000/auth"},
		{"should accept valid IPv6 address in brackets", map[string]string{"x-forwarded-host": "[2001:db8::1]", "x-forwarded-proto": "https"}, true, "https://[2001:db8::1]/auth"},
		{"should accept localhost", map[string]string{"x-forwarded-host": "localhost", "x-forwarded-proto": "http"}, true, "http://localhost/auth"},
		{"should accept localhost with port", map[string]string{"x-forwarded-host": "localhost:8080", "x-forwarded-proto": "http"}, true, "http://localhost:8080/auth"},
		{"should reject invalid port numbers", map[string]string{"x-forwarded-host": "example.com:999999", "x-forwarded-proto": "http"}, true, fallback},
		{"should not use proxy headers when trustedProxyHeaders is false", map[string]string{"x-forwarded-host": "evil.com", "x-forwarded-proto": "https"}, false, fallback},
		{"should require both headers to be present (only host)", map[string]string{"x-forwarded-host": "example.com"}, true, fallback},
		{"should require both headers to be present (only proto)", map[string]string{"x-forwarded-proto": "https"}, true, fallback},
		{"should handle subdomain correctly", map[string]string{"x-forwarded-host": "api.example.com", "x-forwarded-proto": "https"}, true, "https://api.example.com/auth"},
		{"should handle deep subdomain correctly", map[string]string{"x-forwarded-host": "api.v1.staging.example.com", "x-forwarded-proto": "https"}, true, "https://api.v1.staging.example.com/auth"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := pnRequest(t, "http://localhost:3000/test", c.headers)
			if got := pnMustBaseURL(t, "", "/auth", r, false, c.trusted); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}

	// Upstream asserts `new Request` throws for a header containing NUL; Go's http stack
	// rejects such headers on the wire too. The equivalent server-side guarantee is that the
	// proxy header validator refuses it and the base URL falls back to the request URL.
	t.Run("should reject null bytes in X-Forwarded-Host", func(t *testing.T) {
		if validateProxyHeader("evil.com\x00.example.com", "host") {
			t.Fatal("expected NUL-containing host to be rejected")
		}
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-proto": "http"})
		r.Header["X-Forwarded-Host"] = []string{"evil.com\x00.example.com"}
		if got := pnMustBaseURL(t, "", "/auth", r, false, true); got != fallback {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("should only accept http or https protocols", func(t *testing.T) {
		for _, proto := range []string{"ftp", "ws", "wss", "data", "blob", "javascript"} {
			r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-host": "example.com", "x-forwarded-proto": proto})
			if got := pnMustBaseURL(t, "", "/auth", r, false, true); got != fallback {
				t.Fatalf("proto %s: got %q", proto, got)
			}
		}
	})
}

func TestPortNetURLMatchesHostPattern(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		// exact matches
		{"myapp.com", "myapp.com", true},
		{"localhost:3000", "localhost:3000", true},
		{"MyApp.COM", "myapp.com", true},
		{"myapp.com", "MyApp.COM", true},
		{"evil.com", "myapp.com", false},
		// wildcard patterns
		{"preview-123.vercel.app", "*.vercel.app", true},
		{"my-app-abc.vercel.app", "*.vercel.app", true},
		{"vercel.app", "*.vercel.app", false},
		{"preview-123.myapp.com", "preview-*.myapp.com", true},
		{"preview-abc.myapp.com", "preview-*.myapp.com", true},
		{"staging-123.myapp.com", "preview-*.myapp.com", false},
		{"api-v1-staging.myapp.com", "api-*-staging.myapp.com", true},
		{"api-v2-staging.myapp.com", "api-*-staging.myapp.com", true},
		{"api1.myapp.com", "api?.myapp.com", true},
		{"api2.myapp.com", "api?.myapp.com", true},
		{"api12.myapp.com", "api?.myapp.com", false},
		// protocol handling
		{"https://myapp.com", "myapp.com", true},
		{"myapp.com", "https://myapp.com", true},
		{"myapp.com/api/auth", "myapp.com", true},
		// edge cases
		{"", "myapp.com", false},
		{"myapp.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := matchesHostPattern(c.host, c.pattern); got != c.want {
			t.Errorf("matchesHostPattern(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestPortNetURLGetHostFromSource(t *testing.T) {
	t.Run("should prefer x-forwarded-host over host header when trustedProxyHeaders is true", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-host": "myapp.vercel.app", "host": "localhost:3000"})
		if got := getHostFromRequest(r, nil, true); got != "myapp.vercel.app" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should ignore x-forwarded-host when trustedProxyHeaders is falsy", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-host": "myapp.vercel.app", "host": "localhost:3000"})
		if got := getHostFromRequest(r, nil, false); got != "localhost:3000" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should fall back to host header if x-forwarded-host is not set", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"host": "localhost:3000"})
		if got := getHostFromRequest(r, nil, true); got != "localhost:3000" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should fall back to request URL if no headers", func(t *testing.T) {
		r := pnRequest(t, "http://example.com:8080/test", nil)
		if got := getHostFromRequest(r, nil, false); got != "example.com:8080" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should reject malicious x-forwarded-host and fall back", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-host": "../../../etc/passwd", "host": "localhost:3000"})
		if got := getHostFromRequest(r, nil, true); got != "localhost:3000" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestPortNetURLGetProtocolFromSource(t *testing.T) {
	t.Run("should use explicit protocol config", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", nil)
		if got := getProtocolFromRequest(r, nil, "https", false); got != "https" {
			t.Fatalf("got %q", got)
		}
		if got := getProtocolFromRequest(r, nil, "http", false); got != "http" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should use x-forwarded-proto when trustedProxyHeaders is true", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-proto": "https"})
		if got := getProtocolFromRequest(r, nil, "auto", true); got != "https" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should ignore x-forwarded-proto when trustedProxyHeaders is falsy", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-proto": "https"})
		if got := getProtocolFromRequest(r, nil, "auto", false); got != "http" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should fall back to request URL protocol", func(t *testing.T) {
		r := pnRequest(t, "https://example.com/test", nil)
		if got := getProtocolFromRequest(r, nil, "auto", false); got != "https" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should use request URL protocol as fallback", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", nil)
		if got := getProtocolFromRequest(r, nil, "auto", false); got != "http" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestPortNetURLIsDynamicBaseURLConfig(t *testing.T) {
	t.Skip("isDynamicBaseURLConfig is a JS runtime type guard; Go uses the typed Config.DynamicBaseURL field instead")
}

func TestPortNetURLResolveDynamicBaseURL(t *testing.T) {
	cfg := &DynamicBaseURL{AllowedHosts: []string{"myapp.com", "*.vercel.app", "preview-*.myapp.com"}, Protocol: "https"}

	t.Run("should resolve allowed host from x-forwarded-host when trustedProxyHeaders is true", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-host": "preview-123.vercel.app", "x-forwarded-proto": "https"})
		got, err := resolveDynamicBaseURL(cfg, r, nil, "/api/auth", true)
		if err != nil || got != "https://preview-123.vercel.app/api/auth" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("should resolve allowed exact match host from host header", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"host": "myapp.com"})
		got, err := resolveDynamicBaseURL(cfg, r, nil, "/api/auth", false)
		if err != nil || got != "https://myapp.com/api/auth" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("should resolve preview wildcard pattern", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"host": "preview-abc123.myapp.com"})
		got, err := resolveDynamicBaseURL(cfg, r, nil, "/api/auth", false)
		if err != nil || got != "https://preview-abc123.myapp.com/api/auth" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("should throw for disallowed host without fallback", func(t *testing.T) {
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"host": "evil.com"})
		_, err := resolveDynamicBaseURL(cfg, r, nil, "/api/auth", false)
		if err == nil || !strings.Contains(err.Error(), `Host "evil.com" is not in the allowed hosts list`) {
			t.Fatalf("got err %v", err)
		}
	})
	t.Run("should use fallback for disallowed host", func(t *testing.T) {
		c := &DynamicBaseURL{AllowedHosts: []string{"myapp.com"}, Fallback: "https://myapp.com"}
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"host": "evil.com"})
		got, err := resolveDynamicBaseURL(c, r, nil, "/api/auth", false)
		if err != nil || got != "https://myapp.com/api/auth" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("should respect protocol config", func(t *testing.T) {
		c := &DynamicBaseURL{AllowedHosts: []string{"myapp.com"}, Protocol: "https"}
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"host": "myapp.com"})
		got, err := resolveDynamicBaseURL(c, r, nil, "/api/auth", false)
		if err != nil || got != "https://myapp.com/api/auth" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("should ignore x-forwarded-host when trustedProxyHeaders is falsy", func(t *testing.T) {
		r := pnRequest(t, "http://preview.vercel.app/test", map[string]string{"x-forwarded-host": "myapp.com", "host": "preview.vercel.app"})
		got, err := resolveDynamicBaseURL(cfg, r, nil, "/api/auth", false)
		if err != nil || got != "https://preview.vercel.app/api/auth" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

// resolveBaseURL has no single Go counterpart; each branch maps to the function the Go
// handler calls for that configuration shape.
func TestPortNetURLResolveBaseURL(t *testing.T) {
	t.Run("should handle static string config", func(t *testing.T) {
		if got := pnMustBaseURL(t, "https://myapp.com", "/api/auth", nil, false, false); got != "https://myapp.com/api/auth" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should handle dynamic config with request when trustedProxyHeaders is true", func(t *testing.T) {
		c := &DynamicBaseURL{AllowedHosts: []string{"myapp.com", "*.vercel.app"}}
		r := pnRequest(t, "http://localhost:3000/test", map[string]string{"x-forwarded-host": "preview.vercel.app", "x-forwarded-proto": "https"})
		got, err := resolveDynamicBaseURL(c, r, nil, "/api/auth", true)
		if err != nil || got != "https://preview.vercel.app/api/auth" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("should fall back to legacy behavior for undefined config", func(t *testing.T) {
		r := pnRequest(t, "http://example.com:3000/test", nil)
		if got := pnMustBaseURL(t, "", "/api/auth", r, false, false); got != "http://example.com:3000/api/auth" {
			t.Fatalf("got %q", got)
		}
	})
}
