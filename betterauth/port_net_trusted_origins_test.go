package betterauth

// Port of packages/better-auth/src/auth/trusted-origins.test.ts (upstream v1.7.7).
//
// Upstream's getTestInstance serves on http://localhost:3000; the Go harness serves on the
// httptest server URL, which plays the role of "the app's origin".

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type pnTrustedInstance struct {
	env *testEnv
	c   *testClient
}

// pnNewTrustedInstance mirrors createAuthTestInstance: it registers a test plugin exposing
// GET /test-trusted-origin?url=...&allowRelativePaths=... returning ctx.context.isTrustedOrigin.
func pnNewTrustedInstance(t *testing.T, mutate func(c *Config)) *pnTrustedInstance {
	t.Helper()
	plugin := &Plugin{ID: "test-plugin", Endpoints: []*Endpoint{{
		Key: "testTrustedOrigin", Path: "/test-trusted-origin", Methods: []string{"GET"},
		Handler: func(ctx *EndpointContext) (any, error) {
			u, _ := ctx.Query["url"].(string)
			allow := false
			if v, ok := ctx.Query["allowRelativePaths"].(string); ok {
				allow = v == "true"
			}
			return ctx.Auth.IsTrustedOrigin(u, allow), nil
		},
	}}}
	env := newTestEnv(t, func(c *Config) {
		if mutate != nil {
			mutate(c)
		}
		c.Plugins = append([]*Plugin{plugin}, c.Plugins...)
	})
	return &pnTrustedInstance{env: env, c: env.client()}
}

func (p *pnTrustedInstance) isTrusted(t *testing.T, u string, allowRelative ...bool) bool {
	t.Helper()
	q := url.Values{"url": {u}}
	if len(allowRelative) > 0 {
		q.Set("allowRelativePaths", fmt.Sprint(allowRelative[0]))
	}
	res := p.c.get("/test-trusted-origin?" + q.Encode())
	if res.Status != 200 {
		t.Fatalf("test-trusted-origin %q: %d %s", u, res.Status, res.Body)
	}
	var b bool
	if err := json.Unmarshal(res.Body, &b); err != nil {
		t.Fatalf("decode %s: %v", res.Body, err)
	}
	return b
}

func (p *pnTrustedInstance) expect(t *testing.T, u string, want bool, allowRelative ...bool) {
	t.Helper()
	if got := p.isTrusted(t, u, allowRelative...); got != want {
		t.Errorf("isTrustedOrigin(%q, %v) = %v, want %v", u, allowRelative, got, want)
	}
}

func TestPortNetTrustedOriginsList(t *testing.T) {
	t.Run("should always allow the app's origin", func(t *testing.T) {
		p := pnNewTrustedInstance(t, nil)
		app := p.env.server.URL
		p.expect(t, app, true)
		p.expect(t, app+"/some/path", true)
	})
	t.Run("should always allow the app's origin (inferred from baseURL)", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_URL", "")
		p := pnNewTrustedInstance(t, func(c *Config) { c.BaseURL = "" })
		app := p.env.server.URL
		p.expect(t, app, true)
		p.expect(t, app+"/some/path", true)
	})
	t.Run("should always allow the app's origin (even if context is updated)", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_URL", "")
		p := pnNewTrustedInstance(t, func(c *Config) {
			c.BaseURL = ""
			c.Plugins = append(c.Plugins, &Plugin{ID: "test-init-plugin", Init: func(*AuthContext) (*PluginInit, error) {
				return &PluginInit{}, nil
			}})
		})
		app := p.env.server.URL
		p.expect(t, app, true)
		p.expect(t, app+"/some/path", true)
	})
	t.Run("should reject origins that start with a trusted origin", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"https://trusted.com"} })
		p.expect(t, "https://trusted.com.malicious.com", false)
	})
	t.Run("should reject untrusted origin subdomains", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"https://trusted.com"} })
		p.expect(t, "http://sub-domain.trusted.com", false)
	})
	t.Run("should allow origins that directly match a trusted origin", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"https://trusted.com"} })
		p.expect(t, "https://trusted.com", true)
		p.expect(t, "https://trusted.com/some/path", true)
	})
}

func TestPortNetTrustedOriginsRelativePaths(t *testing.T) {
	p := pnNewTrustedInstance(t, nil)
	t.Run("should reject relative paths by default", func(t *testing.T) {
		p.expect(t, "/", false)
		p.expect(t, "/some-absolute-url", false)
	})
	t.Run("should allow relative paths", func(t *testing.T) {
		p.expect(t, "/", true, true)
		p.expect(t, "/dashboard", true, true)
	})
	t.Run("should allow relative paths with query params", func(t *testing.T) {
		p.expect(t, "/dashboard?email=123@email.com", true, true)
	})
	t.Run("should allow relative paths with plus signs", func(t *testing.T) {
		p.expect(t, "/dashboard+page?test=123+456", true, true)
	})
	t.Run("should reject relative paths with tildes when relative paths are disabled", func(t *testing.T) {
		p.expect(t, "/my-team/~settings/account", false)
		p.expect(t, "/my-team/~settings/account", false, false)
	})
	t.Run("should allow relative paths with tildes", func(t *testing.T) {
		p.expect(t, "/my-team/~settings/account", true, true)
		p.expect(t, "/~settings?next=/~account", true, true)
	})
	t.Run("should allow standards-compliant relative URLs", func(t *testing.T) {
		for _, u := range []string{
			"/docs/!$&'()*+,;=:@~",
			"/café#profile",
			"/search?next=/settings?tab=security",
			"/callback?next=%2Fdashboard",
			"/profile#section?tab=security",
			"/#%2f%2fevil.com",
		} {
			p.expect(t, u, true, true)
		}
	})
	t.Run("should reject URLs with ambiguous path prefixes", func(t *testing.T) {
		for _, u := range []string{"//evil.com", "///evil.com", `/\evil.com`} {
			p.expect(t, u, false, true)
		}
	})
	t.Run("should reject urls with encoded malicious content", func(t *testing.T) {
		for _, u := range []string{
			"/%2f/evil.com", "/%2F/evil.com", "/%5c/evil.com", "/%5C/evil.com",
			"/safe/%2f/evil.com", "/safe/%2F/evil.com", "/safe/%5c/evil.com", "/safe/%5C/evil.com",
			"/%2f/evil.com#section", `/\/\/evil.com`, "/..%2F..%2Fevil.com",
			"/\u0000evil.com", "/\u007fevil.com", "/\u0085evil.com",
			"/\t/evil.com", "/\n/evil.com", "/\r/evil.com",
			"javascript:alert('xss')", "data:text/html,<script>alert('xss')</script>",
		} {
			p.expect(t, u, false, true)
		}
	})
}

func TestPortNetTrustedOriginsWildcards(t *testing.T) {
	t.Run("should allow origins that match a wildcard trusted origin", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"*.my-site.com"} })
		p.expect(t, "https://sub-domain.my-site.com", true)
		p.expect(t, "https://sub-domain.my-site.com/callback", true)
		p.expect(t, "https://another-sub.my-site.com", true)
		p.expect(t, "https://another-sub.my-site.com/callback", true)
	})
	t.Run("should reject urls with malicious domain with wildcard trusted origins", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"*.example.com"} })
		p.expect(t, "malicious.com?.example.com", false)
	})
	t.Run("should work with protocol specific wildcard trusted origins", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"https://*.protocol-site.com"} })
		p.expect(t, "https://api.protocol-site.com", true)
		p.expect(t, "http://api.protocol-site.com", false)
	})
	t.Run("should work with custom scheme wildcards (e.g. exp:// for Expo)", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) {
			c.TrustedOrigins = []string{"exp://10.0.0.*:*/*", "exp://192.168.*.*:*/*", "exp://172.*.*.*:*/*"}
		})
		p.expect(t, "exp://10.0.0.29:8081/--/", true)
		p.expect(t, "exp://192.168.1.100:8081/--/", true)
		p.expect(t, "exp://172.16.0.1:8081/--/", true)
		p.expect(t, "exp://203.0.113.0:8081/--/", false)
	})
}

func TestPortNetTrustedOriginsCustomScheme(t *testing.T) {
	cb := func(c *Config) { c.TrustedOrigins = []string{"myapp://callback"} }
	t.Run("should reject URLs where the host extends the trusted pattern", func(t *testing.T) {
		p := pnNewTrustedInstance(t, cb)
		p.expect(t, "myapp://callback.attacker.tld", false)
		p.expect(t, "myapp://callback.attacker.tld/path", false)
	})
	t.Run("should allow exact custom-scheme origin match", func(t *testing.T) {
		p := pnNewTrustedInstance(t, cb)
		for _, u := range []string{"myapp://callback", "myapp://callback/", "myapp://callback/path", "myapp://callback?token=x", "myapp://callback#frag"} {
			p.expect(t, u, true)
		}
	})
	t.Run("should reject control characters in custom-scheme URLs", func(t *testing.T) {
		p := pnNewTrustedInstance(t, cb)
		p.expect(t, "myapp://callback?"+strings.Repeat("#", 10_000)+"\n\n", false)
	})
	t.Run("should match custom-scheme with empty host (myapp:/)", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"myapp:/"} })
		p.expect(t, "myapp:/", true)
		p.expect(t, "myapp://", true)
		p.expect(t, "myapp:/auth/callback", true)
	})
	t.Run("should reject different custom schemes", func(t *testing.T) {
		p := pnNewTrustedInstance(t, cb)
		p.expect(t, "otherapp://callback", false)
	})
	t.Run("should still support wildcard matching for custom schemes", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"exp://192.168.*.*:*/*"} })
		p.expect(t, "exp://192.168.1.100:8081/--/", true)
		p.expect(t, "exp://10.0.0.1:8081/--/", false)
	})
	t.Run("should trust any host for a host-less custom-scheme pattern", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"exp://", "myapp://"} })
		p.expect(t, "exp://192.168.1.5:8081/--/", true)
		p.expect(t, "exp://localhost:8081/--/", true)
		p.expect(t, "myapp://callback", true)
		p.expect(t, "myapp://other-host/path", true)
		p.expect(t, "evil://anything", false)
	})
	t.Run("should match custom-scheme host case-insensitively", func(t *testing.T) {
		p := pnNewTrustedInstance(t, cb)
		p.expect(t, "myapp://CALLBACK", true)
		p.expect(t, "MyApp://Callback", true)
	})
	t.Run("should pin the path when the pattern includes one", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"myapp://host/cb"} })
		p.expect(t, "myapp://host/cb", true)
		p.expect(t, "myapp://host/cb/extra", true)
		p.expect(t, "myapp://host/cbx", false)
		p.expect(t, "myapp://host/other", false)
	})
	t.Run("should not let a path-pinned pattern be bypassed with traversal", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) { c.TrustedOrigins = []string{"myapp://host/cb"} })
		p.expect(t, "myapp://host/cb/../evil", false)
		p.expect(t, "myapp://host/cb/%2e%2e/evil", false)
		p.expect(t, "myapp://host/cb%2f..%2fevil", false)
	})
}

func TestPortNetTrustedOriginsDynamic(t *testing.T) {
	t.Run("should allow dynamically computed trusted origins", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) {
			c.TrustedOriginsFunc = func(r *http.Request) ([]string, error) {
				if r == nil {
					return nil, nil
				}
				raw := r.URL.Query().Get("url")
				if raw == "" {
					raw = "unknown"
				}
				o := getOrigin(raw)
				if o == "" {
					return nil, errors.New("Invalid URL")
				}
				return []string{o}, nil
			}
		})
		p.expect(t, "http://localhost:5000/callback", true)
	})
	t.Run("should not allow dynamically computed trusted origins", func(t *testing.T) {
		p := pnNewTrustedInstance(t, func(c *Config) {
			c.TrustedOriginsFunc = func(*http.Request) ([]string, error) { return []string{}, nil }
		})
		p.expect(t, "http://localhost:5000/callback", false)
	})
}

// getTrustedOrigins(options) for a dynamic baseURL config.
func pnGetTrustedOrigins(t *testing.T, cfg Config) []string {
	t.Helper()
	t.Setenv("BETTER_AUTH_TRUSTED_ORIGINS", "")
	a := &Auth{cfg: &cfg}
	out, err := a.trustedOrigins(&cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func pnContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func pnExpectOrigins(t *testing.T, origins []string, has []string, hasNot []string) {
	t.Helper()
	for _, h := range has {
		if !pnContains(origins, h) {
			t.Errorf("expected %v to contain %q", origins, h)
		}
	}
	for _, h := range hasNot {
		if pnContains(origins, h) {
			t.Errorf("expected %v not to contain %q", origins, h)
		}
	}
}

func TestPortNetTrustedOriginsDynamicBaseURLProtocol(t *testing.T) {
	t.Run("should add http:// origins when protocol is 'http'", func(t *testing.T) {
		o := pnGetTrustedOrigins(t, Config{DynamicBaseURL: &DynamicBaseURL{
			AllowedHosts: []string{"staging.example.com", "dev.example.local"}, Protocol: "http", Fallback: "https://app.example.com"}})
		pnExpectOrigins(t, o, []string{"http://staging.example.com", "http://dev.example.local", "https://app.example.com"},
			[]string{"https://staging.example.com", "https://dev.example.local"})
	})
	t.Run("should add only https:// origins when protocol is 'https'", func(t *testing.T) {
		o := pnGetTrustedOrigins(t, Config{DynamicBaseURL: &DynamicBaseURL{
			AllowedHosts: []string{"staging.example.com", "app.example.com"}, Protocol: "https"}})
		pnExpectOrigins(t, o, []string{"https://staging.example.com", "https://app.example.com"},
			[]string{"http://staging.example.com", "http://app.example.com"})
	})
	t.Run("should add both http:// and https:// origins when protocol is 'auto'", func(t *testing.T) {
		o := pnGetTrustedOrigins(t, Config{DynamicBaseURL: &DynamicBaseURL{
			AllowedHosts: []string{"staging.example.com"}, Protocol: "auto"}})
		pnExpectOrigins(t, o, []string{"https://staging.example.com", "http://staging.example.com"}, nil)
	})
	t.Run("should default to https:// with http:// for loopback when protocol is undefined", func(t *testing.T) {
		o := pnGetTrustedOrigins(t, Config{DynamicBaseURL: &DynamicBaseURL{
			AllowedHosts: []string{"staging.example.com", "localhost:3000"}}})
		pnExpectOrigins(t, o, []string{"https://staging.example.com", "https://localhost:3000", "http://localhost:3000"},
			[]string{"http://staging.example.com"})
	})
	t.Run("should still allow hosts with explicit protocol in the host string", func(t *testing.T) {
		o := pnGetTrustedOrigins(t, Config{DynamicBaseURL: &DynamicBaseURL{
			AllowedHosts: []string{"http://already-specified.example.com", "staging.example.com"}, Protocol: "http"}})
		pnExpectOrigins(t, o, []string{"http://already-specified.example.com", "http://staging.example.com"}, nil)
	})
	t.Run("should add http:// for loopback hosts even when protocol is 'https'", func(t *testing.T) {
		o := pnGetTrustedOrigins(t, Config{DynamicBaseURL: &DynamicBaseURL{
			AllowedHosts: []string{"localhost:3000", "127.0.0.1:8080"}, Protocol: "https"}})
		pnExpectOrigins(t, o, []string{"https://localhost:3000", "http://localhost:3000", "https://127.0.0.1:8080", "http://127.0.0.1:8080"}, nil)
	})
}

func TestPortNetTrustedOriginsMergePluginInit(t *testing.T) {
	p := pnNewTrustedInstance(t, func(c *Config) {
		c.TrustedOriginsFunc = func(*http.Request) ([]string, error) { return []string{"https://user-dynamic.com"}, nil }
		c.Plugins = append(c.Plugins,
			&Plugin{ID: "plugin-a", Init: func(*AuthContext) (*PluginInit, error) {
				return &PluginInit{TrustedOrigins: []string{"https://plugin-static.com"}}, nil
			}},
			&Plugin{ID: "plugin-b", Init: func(*AuthContext) (*PluginInit, error) {
				return &PluginInit{TrustedOriginsFunc: func(*http.Request) ([]string, error) {
					return []string{"https://plugin-fn.com"}, nil
				}}, nil
			}},
		)
	})
	p.expect(t, "https://user-dynamic.com", true)
	p.expect(t, "https://plugin-static.com", true)
	p.expect(t, "https://plugin-fn.com", true)
	p.expect(t, "https://unknown.com", false)
}
