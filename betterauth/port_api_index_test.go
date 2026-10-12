package betterauth

// Port of packages/better-auth/src/api/index.test.ts (upstream v1.7.7).

import (
	"net/http"
	"reflect"
	"testing"
)

// describe("getEndpoints") — upstream awaits a promise-based AuthContext before calling a
// plugin middleware. Go has no async context; the translatable behavior is that a plugin
// path middleware runs for its path with the resolved AuthContext.
func TestPortAPIIndexGetEndpointsMiddlewareContext(t *testing.T) {
	var called bool
	var baseURL string
	var hasOptions bool
	env := newTestEnv(t, func(c *Config) {
		c.Plugins = []*Plugin{{
			ID: "test-plugin",
			Middlewares: []PathMiddleware{{Path: "/test", Middleware: func(ctx *EndpointContext) error {
				called = true
				baseURL = ctx.Auth.BaseURL
				hasOptions = ctx.Auth.Options != nil
				return nil
			}}},
			Endpoints: []*Endpoint{{Key: "ppTest", Path: "/test", Methods: []string{"GET"},
				Handler: func(*EndpointContext) (any, error) { return map[string]any{"ok": true}, nil }}},
		}}
	})
	res := env.client().get("/test")
	if res.Status != 200 {
		t.Fatalf("status %d: %s", res.Status, res.Body)
	}
	if !called {
		t.Fatal("middleware was not called")
	}
	if baseURL != env.server.URL+"/api/auth" || !hasOptions {
		t.Fatalf("middleware context: baseURL=%q options=%v", baseURL, hasOptions)
	}
}

// describe("onRequest chain")
func TestPortAPIIndexOnRequestChain(t *testing.T) {
	t.Run("should execute all plugins onRequest handlers in chain", func(t *testing.T) {
		var order []string
		pluginA := &Plugin{ID: "plugin-a", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			order = append(order, "plugin-a")
			nr := r.Clone(r.Context())
			nr.Header.Set("x-plugin-a", "true")
			return nr, nil, nil
		}}
		pluginB := &Plugin{ID: "plugin-b", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			order = append(order, "plugin-b")
			nr := r.Clone(r.Context())
			nr.Header.Set("x-plugin-b", "true")
			return nr, nil, nil
		}}
		pluginC := &Plugin{ID: "plugin-c", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			order = append(order, "plugin-c")
			return nil, nil, nil
		}}
		env := newTestEnv(t, func(c *Config) { c.Plugins = []*Plugin{pluginA, pluginB, pluginC} })
		c := env.client()
		c.signUp("test@test.com", "test123456", "test user")
		order = nil
		c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"})
		if !reflect.DeepEqual(order, []string{"plugin-a", "plugin-b", "plugin-c"}) {
			t.Fatalf("order = %v", order)
		}
	})

	t.Run("should pass modified request from previous plugin to next plugin", func(t *testing.T) {
		var received string
		pluginA := &Plugin{ID: "plugin-a", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			nr := r.Clone(r.Context())
			nr.Header.Set("x-from-plugin-a", "hello")
			return nr, nil, nil
		}}
		pluginB := &Plugin{ID: "plugin-b", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			received = r.Header.Get("x-from-plugin-a")
			return nil, nil, nil
		}}
		env := newTestEnv(t, func(c *Config) { c.Plugins = []*Plugin{pluginA, pluginB} })
		c := env.client()
		c.signUp("test@test.com", "test123456", "test user")
		received = ""
		c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"})
		if received != "hello" {
			t.Fatalf("plugin-b received %q", received)
		}
	})

	t.Run("should stop chain when response is returned", func(t *testing.T) {
		var order []string
		pluginA := &Plugin{ID: "plugin-a", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			order = append(order, "plugin-a")
			return nil, &Response{Status: 403, Header: http.Header{}, Body: []byte("Blocked by plugin-a")}, nil
		}}
		pluginB := &Plugin{ID: "plugin-b", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			order = append(order, "plugin-b")
			return nil, &Response{Status: 200, Header: http.Header{}, Body: []byte("ok")}, nil
		}}
		env := newTestEnv(t, func(c *Config) { c.Plugins = []*Plugin{pluginA, pluginB} })
		// getTestInstance creates the test user before the test body runs (also blocked here).
		_ = ppSignUpTestUser(t, env.auth)
		order = nil
		res := env.client().post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"})
		if !reflect.DeepEqual(order, []string{"plugin-a"}) {
			t.Fatalf("order = %v", order)
		}
		if res.Status != 403 {
			t.Fatalf("status = %d", res.Status)
		}
	})
}

// describe("skipTrailingSlashes option")
func TestPortAPIIndexSkipTrailingSlashes(t *testing.T) {
	t.Run("should return 404 for trailing slash requests by default", func(t *testing.T) {
		env := newTestEnv(t, nil)
		res := ppMustServe(t, env.auth, "GET", "http://localhost:3000/api/auth/ok/", "", nil)
		if res.Status != 404 {
			t.Fatalf("status = %d", res.Status)
		}
	})
	t.Run("should handle trailing slash requests when skipTrailingSlashes is enabled", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.Advanced.SkipTrailingSlashes = true })
		res := ppMustServe(t, env.auth, "GET", "http://localhost:3000/api/auth/ok/", "", nil)
		if res.Status != 200 {
			t.Fatalf("status = %d", res.Status)
		}
		if body := ppBodyJSON(t, res); !reflect.DeepEqual(body, map[string]any{"ok": true}) {
			t.Fatalf("body = %v", body)
		}
	})
	t.Run("should work with POST requests with trailing slash", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.Advanced.SkipTrailingSlashes = true })
		res := ppMustServe(t, env.auth, "POST", "http://localhost:3000/api/auth/sign-up/email/",
			`{"email":"test2@example.com","password":"password123","name":"Test User 2"}`,
			map[string]string{"Content-Type": "application/json"})
		if res.Status == 404 {
			t.Fatalf("status = 404: %s", res.Body)
		}
	})
}

// describe("base path leading-prefix enforcement")
func TestPortAPIIndexBasePathLeadingPrefix(t *testing.T) {
	t.Run("rejects a path where basePath is not a leading prefix", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.BasePath = "/api/auth" })
		res := ppMustServe(t, env.auth, "GET", "http://localhost:3000/x/api/auth/ok", "", nil)
		if res.Status != 404 {
			t.Fatalf("status = %d", res.Status)
		}
	})
	t.Run("rejects a path before basePath that targets a disabled route", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.BasePath = "/api/auth"
			c.DisabledPaths = []string{"/sign-up/email"}
		})
		body := `{"email":"user@example.com","password":"password12345","name":"Test User"}`
		h := map[string]string{"content-type": "application/json"}
		blocked := ppMustServe(t, env.auth, "POST", "http://localhost:3000/api/auth/sign-up/email", body, h)
		if blocked.Status != 404 {
			t.Fatalf("blocked status = %d", blocked.Status)
		}
		confused := ppMustServe(t, env.auth, "POST", "http://localhost:3000/x/api/auth/sign-up/email", body, h)
		if confused.Status != 404 {
			t.Fatalf("confused status = %d", confused.Status)
		}
	})
}
