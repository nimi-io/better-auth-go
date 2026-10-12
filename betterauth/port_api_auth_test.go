package betterauth

// Port of packages/better-auth/src/auth/full.test.ts and auth/minimal.test.ts
// (upstream v1.7.7). Type-level (expectTypeOf) assertions are translated to runtime
// equivalents where one exists.

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
)

// describe("auth type")
func TestPortAPIAuthFullTypes(t *testing.T) {
	t.Run("default auth type should be okay", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf type assertion")
	})
	t.Run("$ERROR_CODES in auth", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.Plugins = []*Plugin{{ID: "custom-plugin", ErrorCodes: []ErrorCode{{Code: "CUSTOM_ERROR", Message: "Custom error message"}}}}
		})
		got, ok := env.auth.ErrorCodes["CUSTOM_ERROR"]
		if !ok || got.Code != "CUSTOM_ERROR" || got.Message != "Custom error message" {
			t.Fatalf("ErrorCodes[CUSTOM_ERROR] = %+v (%v)", got, ok)
		}
	})
	t.Run("plugin endpoints", func(t *testing.T) {
		// Runtime translation: a plugin endpoint with the getSession key replaces the core one.
		env := ppPluginEnv(t, []*Endpoint{{Key: "getSession", Path: "/get-session", Methods: []string{"GET"},
			Handler: func(*EndpointContext) (any, error) {
				return map[string]any{"data": map[string]any{"message": "Hello, World!"}}, nil
			}}}, nil)
		res := ppMustCall(t, env.auth, "getSession", CallInput{})
		if got := ppDecode(t, res.Data); !reflect.DeepEqual(got, map[string]any{"data": map[string]any{"message": "Hello, World!"}}) {
			t.Fatalf("getSession = %v", got)
		}
	})
}

func ppBaseURLCaptureEnv(t *testing.T, mutate func(c *Config), capture func(ctx *EndpointContext)) *testEnv {
	t.Helper()
	ppNoEnvBaseURL(t)
	return newTestEnv(t, func(c *Config) {
		c.BaseURL = ""
		if capture != nil {
			c.Hooks = &HooksConfig{Before: func(ctx *EndpointContext) (any, error) { capture(ctx); return nil, nil }}
		}
		if mutate != nil {
			mutate(c)
		}
	})
}

// client.$fetch("/ok", { headers }) through customFetchImpl (auth.handler) with the
// client baseURL http://localhost:3000.
func ppFetchOK(t *testing.T, a *Auth, path string, headers map[string]string) *Response {
	t.Helper()
	return ppMustServe(t, a, "GET", "http://localhost:3000/api/auth"+path, "", headers)
}

// describe("auth with trusted proxy headers")
func TestPortAPIAuthFullTrustedProxyHeaders(t *testing.T) {
	t.Run("shouldn't infer base url from proxy headers if trusted", func(t *testing.T) {
		var baseURL string
		env := ppBaseURLCaptureEnv(t, func(c *Config) { c.Advanced.TrustedProxyHeaders = true },
			func(ctx *EndpointContext) { baseURL = ctx.Auth.BaseURL })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "localhost:3001", "x-forwarded-proto": "http"})
		if baseURL != "http://localhost:3001/api/auth" {
			t.Fatalf("baseURL = %q", baseURL)
		}
	})
	t.Run("shouldn't infer base url from proxy headers if not trusted", func(t *testing.T) {
		var baseURL string
		env := ppBaseURLCaptureEnv(t, func(c *Config) { c.Advanced.TrustedProxyHeaders = false },
			func(ctx *EndpointContext) { baseURL = ctx.Auth.BaseURL })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "localhost:3001", "x-forwarded-proto": "http"})
		if baseURL != "http://localhost:3000/api/auth" {
			t.Fatalf("baseURL = %q", baseURL)
		}
	})
}

// describe("auth with dynamic baseURL (allowedHosts)") (#4151)
func TestPortAPIAuthFullDynamicBaseURL(t *testing.T) {
	t.Run("should throw error for empty allowedHosts array", func(t *testing.T) {
		ppNoEnvBaseURL(t)
		_, err := New(Config{Secret: testSecret, Database: memory.New(memory.NewDB()), Logger: NopLogger{},
			DynamicBaseURL: &DynamicBaseURL{AllowedHosts: []string{}}})
		if err == nil || !strings.Contains(err.Error(), "baseURL.allowedHosts cannot be empty") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("should resolve baseURL from allowed host", func(t *testing.T) {
		var baseURL, optionsBaseURL string
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"myapp.com", "*.vercel.app", "localhost:*"}}
			c.Advanced.TrustedProxyHeaders = true
		}, func(ctx *EndpointContext) { baseURL, optionsBaseURL = ctx.Auth.BaseURL, ctx.Auth.Options.BaseURL })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "preview-123.vercel.app", "x-forwarded-proto": "https"})
		if baseURL != "https://preview-123.vercel.app/api/auth" || optionsBaseURL != "https://preview-123.vercel.app" {
			t.Fatalf("baseURL = %q options.baseURL = %q", baseURL, optionsBaseURL)
		}
	})
	t.Run("should reject disallowed host and throw error", func(t *testing.T) {
		// Upstream auth.handler rejects; the Go handler cannot throw, so it logs the error
		// and responds 500.
		log := &ppCaptureLogger{}
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"myapp.com"}}
			c.Advanced.TrustedProxyHeaders = true
			c.Logger = log
		}, nil)
		r := ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "evil.com", "x-forwarded-proto": "https"})
		if r.Status != 500 {
			t.Fatalf("status = %d", r.Status)
		}
		if !log.contains(`Host "evil.com" is not in the allowed hosts list`) {
			t.Fatalf("logged = %v", log.lines)
		}
	})
	t.Run("should use fallback for disallowed host", func(t *testing.T) {
		var baseURL string
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"myapp.com"}, Fallback: "https://myapp.com"}
		}, func(ctx *EndpointContext) { baseURL = ctx.Auth.BaseURL })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "evil.com", "x-forwarded-proto": "https"})
		if baseURL != "https://myapp.com/api/auth" {
			t.Fatalf("baseURL = %q", baseURL)
		}
	})
	t.Run("should respect protocol config", func(t *testing.T) {
		var baseURL string
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"myapp.com"}, Protocol: "https"}
			c.Advanced.TrustedProxyHeaders = true
		}, func(ctx *EndpointContext) { baseURL = ctx.Auth.BaseURL })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "myapp.com", "x-forwarded-proto": "http"})
		if baseURL != "https://myapp.com/api/auth" {
			t.Fatalf("baseURL = %q", baseURL)
		}
	})
	t.Run("should work with wildcard patterns for Vercel deployments", func(t *testing.T) {
		var baseURL string
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"myapp.com", "www.myapp.com", "*.vercel.app", "preview-*.myapp.com"}}
			c.Advanced.TrustedProxyHeaders = true
		}, func(ctx *EndpointContext) { baseURL = ctx.Auth.BaseURL })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "my-app-abc123-team.vercel.app", "x-forwarded-proto": "https"})
		if baseURL != "https://my-app-abc123-team.vercel.app/api/auth" {
			t.Fatalf("baseURL = %q", baseURL)
		}
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "preview-feature-branch.myapp.com", "x-forwarded-proto": "https"})
		if baseURL != "https://preview-feature-branch.myapp.com/api/auth" {
			t.Fatalf("baseURL = %q", baseURL)
		}
	})
	t.Run("should isolate per-request context for concurrent requests", func(t *testing.T) {
		var resolved ppStringRecorder
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"tenant-a.example.com", "tenant-b.example.com"}}
			c.Advanced.TrustedProxyHeaders = true
		}, func(ctx *EndpointContext) {
			if ctx.Auth.BaseURL != "" {
				resolved.add(ctx.Auth.BaseURL)
			}
		})
		resolved.reset()
		var wg sync.WaitGroup
		for _, host := range []string{"tenant-a.example.com", "tenant-b.example.com"} {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				_, _ = ppServe(env.auth, "GET", "http://localhost:3000/api/auth/ok", "",
					map[string]string{"x-forwarded-host": host, "x-forwarded-proto": "https"})
			}(host)
		}
		wg.Wait()
		a, b := "https://tenant-a.example.com/api/auth", "https://tenant-b.example.com/api/auth"
		if resolved.count(a) != 1 || resolved.count(b) != 1 {
			t.Fatalf("resolved = %v", resolved.list())
		}
	})
	t.Run("should include all allowedHosts in trustedOrigins", func(t *testing.T) {
		var trusted []string
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"myapp.com", "*.vercel.app", "localhost:3000"}, Fallback: "https://fallback.example.com"}
		}, func(ctx *EndpointContext) { trusted = ctx.Auth.TrustedOrigins })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "myapp.com", "x-forwarded-proto": "https"})
		for _, want := range []string{"https://myapp.com", "https://*.vercel.app", "https://localhost:3000", "http://localhost:3000", "https://fallback.example.com"} {
			found := false
			for _, o := range trusted {
				found = found || o == want
			}
			if !found {
				t.Fatalf("trustedOrigins %v missing %q", trusted, want)
			}
		}
	})
	t.Run("should set cookie domain dynamically with crossSubDomainCookies", func(t *testing.T) {
		var domain string
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"auth.example1.com", "auth.example2.com"}, Protocol: "https"}
			c.Advanced.CrossSubDomainCookies = &CrossSubDomainCookies{Enabled: true}
			c.Advanced.TrustedProxyHeaders = true
		}, func(ctx *EndpointContext) { domain = ctx.Auth.AuthCookies.SessionToken.Attributes.Domain })
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "auth.example1.com", "x-forwarded-proto": "https"})
		if domain != "auth.example1.com" {
			t.Fatalf("domain = %q", domain)
		}
		ppFetchOK(t, env.auth, "/ok", map[string]string{"x-forwarded-host": "auth.example2.com", "x-forwarded-proto": "https"})
		if domain != "auth.example2.com" {
			t.Fatalf("domain = %q", domain)
		}
	})
	t.Run("create a auth context per request which contains the internal adapter", func(t *testing.T) {
		var baseURL, optionsBaseURL string
		var internal *InternalAdapter
		env := ppBaseURLCaptureEnv(t, func(c *Config) {
			c.DynamicBaseURL = &DynamicBaseURL{AllowedHosts: []string{"myapp.com", "*.vercel.app", "localhost:*"}}
			c.Advanced.TrustedProxyHeaders = true
			c.Plugins = []*Plugin{{ID: "custom-plugin", Endpoints: []*Endpoint{{Key: "validateContext", Path: "/validate-context",
				Methods: []string{"GET"}, Handler: func(ctx *EndpointContext) (any, error) {
					internal = ctx.Auth.InternalAdapter
					return map[string]any{"message": "Hello, World!"}, nil
				}}}}}
		}, func(ctx *EndpointContext) { baseURL, optionsBaseURL = ctx.Auth.BaseURL, ctx.Auth.Options.BaseURL })
		r := ppFetchOK(t, env.auth, "/validate-context", map[string]string{"x-forwarded-host": "preview-123.vercel.app", "x-forwarded-proto": "https"})
		if r.Status != 200 {
			t.Fatalf("status = %d %s", r.Status, r.Body)
		}
		if baseURL != "https://preview-123.vercel.app/api/auth" || optionsBaseURL != "https://preview-123.vercel.app" {
			t.Fatalf("baseURL = %q options.baseURL = %q", baseURL, optionsBaseURL)
		}
		if internal == nil {
			t.Fatal("internalAdapter is nil")
		}
	})
}

// describe("auth-minimal")
func TestPortAPIAuthMinimal(t *testing.T) {
	t.Run("default auth type should be okay", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf type assertion")
	})
	t.Run("auth.fetch should be the same reference as auth.handler", func(t *testing.T) {
		t.Skip("TS-only: auth.fetch alias; Go exposes a single http.Handler (Auth.Handler/ServeHTTP)")
	})
	t.Run("should initialize with adapter without Kysely dependencies", func(t *testing.T) {
		a, err := New(Config{BaseURL: "http://localhost:3000", Secret: testSecret, Database: memory.New(memory.NewDB()), Logger: NopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		if a == nil || a.Handler() == nil || a.API == nil || a.Options() == nil {
			t.Fatal("auth not fully initialized")
		}
		if id := a.Context().Adapter.ID(); id != "memory" {
			t.Fatalf("adapter id = %q", id)
		}
	})
	t.Run("should throw error when attempting to run migrations", func(t *testing.T) {
		t.Skip("TS-only: better-auth/minimal build entry (ctx.runMigrations); Go has no minimal variant")
	})
	t.Run("should handle requests through adapter", func(t *testing.T) {
		a, err := New(Config{BaseURL: "http://localhost:3000", Secret: testSecret, Database: memory.New(memory.NewDB()), Logger: NopLogger{}})
		if err != nil {
			t.Fatal(err)
		}
		r := ppMustServe(t, a, "GET", "http://localhost:3000/api/auth/ok", "", nil)
		if r.Status != 200 {
			t.Fatalf("status = %d", r.Status)
		}
		if got := ppBodyJSON(t, r); got["ok"] != true {
			t.Fatalf("body = %v", got)
		}
	})
	t.Run("should throw error with direct database connection (Kysely required)", func(t *testing.T) {
		t.Skip("TS-only: Kysely direct database connections")
	})
}
