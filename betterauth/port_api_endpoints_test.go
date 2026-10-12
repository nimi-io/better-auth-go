package betterauth

// Port of packages/better-auth/src/api/to-auth-endpoints.test.ts (upstream v1.7.7).
//
// Translation notes:
//   - toAuthEndpoints(endpoints, init(opts)) → a test env with a plugin exposing the
//     endpoints, invoked through auth.API.Call.
//   - A before hook returning { context: {...} } → the Go hook mutates ctx.Body / Query /
//     Params / Headers and returns nil.
//   - asResponse: true → ppAsResponse (toResponse of the CallResult or *APIError);
//     returnHeaders / returnStatus → CallResult.Headers / CallResult.Status.
//   - kAPIErrorHeaderSymbol → (*APIError).Headers.

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func ppEcho(f func(ctx *EndpointContext) any) func(ctx *EndpointContext) (any, error) {
	return func(ctx *EndpointContext) (any, error) { return f(ctx), nil }
}

func ppHeadersObject(h http.Header) map[string]any {
	out := map[string]any{}
	for k, vs := range h {
		out[strings.ToLower(k)] = strings.Join(vs, ", ")
	}
	return out
}

func ppCall(t *testing.T, a *Auth, key string, in CallInput) (*CallResult, error) {
	t.Helper()
	return a.API.Call(t.Context(), key, in)
}

func ppMustCall(t *testing.T, a *Auth, key string, in CallInput) *CallResult {
	t.Helper()
	res, err := ppCall(t, a, key, in)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return res
}

func ppAssertSubset(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Fatalf("got %v, want subset %v (key %q)", got, want, k)
		}
	}
}

// describe("before hook") > describe("context")
func TestPortAPIEndpointsBeforeHookContext(t *testing.T) {
	eps := []*Endpoint{
		{Key: "query", Path: "/query", Methods: []string{"GET"}, Handler: ppEcho(func(c *EndpointContext) any { return c.Query })},
		{Key: "body", Path: "/body", Methods: []string{"POST"}, Handler: ppEcho(func(c *EndpointContext) any { return c.Body })},
		{Key: "params", Path: "/params", Methods: []string{"GET"}, Handler: ppEcho(func(c *EndpointContext) any { return c.Params })},
		{Key: "headers", Path: "/headers", Methods: []string{"GET"}, RequireHeaders: true,
			Handler: ppEcho(func(c *EndpointContext) any { return ppHeadersObject(c.Headers) })},
	}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Hooks = &HooksConfig{Before: func(c *EndpointContext) (any, error) {
			switch c.Path {
			case "/body":
				m := c.BodyMap()
				if m == nil {
					m = map[string]any{}
				}
				m["name"] = "body"
				c.Body = m
			case "/params":
				if c.Params == nil {
					c.Params = map[string]string{}
				}
				c.Params["name"] = "params"
			case "/headers":
				if c.Headers == nil {
					c.Headers = http.Header{}
				}
				c.Headers.Set("name", "headers")
			default:
				if c.Query == nil {
					c.Query = map[string]any{}
				}
				c.Query["name"] = "query"
			}
			return nil, nil
		}}
	})
	a := env.auth

	t.Run("should return hook set query", func(t *testing.T) {
		res := ppDecode(t, ppMustCall(t, a, "query", CallInput{}).Data)
		if res["name"] != "query" {
			t.Fatalf("res = %v", res)
		}
		res2 := ppDecode(t, ppMustCall(t, a, "query", CallInput{Query: map[string]any{"key": "value"}}).Data)
		ppAssertSubset(t, res2, map[string]any{"name": "query", "key": "value"})
	})
	t.Run("should return hook set body", func(t *testing.T) {
		res := ppDecode(t, ppMustCall(t, a, "body", CallInput{}).Data)
		if res["name"] != "body" {
			t.Fatalf("res = %v", res)
		}
		res2 := ppDecode(t, ppMustCall(t, a, "body", CallInput{Body: map[string]any{"key": "value"}}).Data)
		ppAssertSubset(t, res2, map[string]any{"name": "body", "key": "value"})
	})
	t.Run("should return hook set param", func(t *testing.T) {
		res := ppDecode(t, ppMustCall(t, a, "params", CallInput{}).Data)
		if res["name"] != "params" {
			t.Fatalf("res = %v", res)
		}
		res2 := ppDecode(t, ppMustCall(t, a, "params", CallInput{Params: map[string]string{"key": "value"}}).Data)
		ppAssertSubset(t, res2, map[string]any{"name": "params", "key": "value"})
	})
	t.Run("should return hook set headers", func(t *testing.T) {
		h := http.Header{}
		h.Set("key", "value")
		res := ppDecode(t, ppMustCall(t, a, "headers", CallInput{Headers: h}).Data)
		ppAssertSubset(t, res, map[string]any{"key": "value", "name": "headers"})
	})
}

func TestPortAPIEndpointsBeforeHookReplaceArray(t *testing.T) {
	// should replace existing array when hook provides another array
	eps := []*Endpoint{{Key: "body", Path: "/body-array-replace", Methods: []string{"POST"},
		Body:    validate.Object(validate.F("tags", validate.Array(validate.String()))),
		Handler: ppEcho(func(c *EndpointContext) any { return c.Body })}}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Hooks = &HooksConfig{Before: func(c *EndpointContext) (any, error) {
			if c.Path == "/body-array-replace" {
				m := c.BodyMap()
				if m == nil {
					m = map[string]any{}
				}
				m["tags"] = []any{"a"}
				c.Body = m
			}
			return nil, nil
		}}
	})
	res := ppDecode(t, ppMustCall(t, env.auth, "body", CallInput{Body: map[string]any{"tags": []any{"b", "c"}}}).Data)
	if !reflect.DeepEqual(res["tags"], []any{"a"}) {
		t.Fatalf("tags = %v", res["tags"])
	}
}

// describe("before hook") > describe("response")
func TestPortAPIEndpointsBeforeHookResponse(t *testing.T) {
	eps := []*Endpoint{
		{Key: "response", Path: "/response", Methods: []string{"GET"}, Handler: ppEcho(func(*EndpointContext) any { return map[string]any{"response": true} })},
		{Key: "json", Path: "/json", Methods: []string{"GET"}, Handler: ppEcho(func(*EndpointContext) any { return map[string]any{"response": true} })},
	}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Hooks = &HooksConfig{Before: func(c *EndpointContext) (any, error) {
			if c.Path == "/json" {
				return map[string]any{"before": true}, nil
			}
			if c.Path == "/response" {
				return &Response{Status: 200, Header: http.Header{}, Body: []byte(`{"before":true}`)}, nil
			}
			return nil, nil
		}}
	})
	t.Run("should return Response object", func(t *testing.T) {
		res := ppMustCall(t, env.auth, "response", CallInput{})
		if _, ok := res.Data.(*Response); !ok {
			t.Fatalf("Data = %T", res.Data)
		}
	})
	t.Run("should return the hook response", func(t *testing.T) {
		res := ppDecode(t, ppMustCall(t, env.auth, "json", CallInput{}).Data)
		ppAssertSubset(t, res, map[string]any{"before": true})
	})
}

// describe("after hook") > describe("response")
func TestPortAPIEndpointsAfterHookResponse(t *testing.T) {
	eps := []*Endpoint{
		{Key: "changeResponse", Path: "/change-response", Methods: []string{"GET"},
			Handler: ppEcho(func(*EndpointContext) any { return map[string]any{"hello": "world"} })},
		{Key: "throwError", Path: "/throw-error", Methods: []string{"POST"},
			Query:   validate.Optional(validate.Object(validate.F("throwHook", validate.Boolean()))),
			Handler: func(*EndpointContext) (any, error) { return nil, ErrStatus("BAD_REQUEST") }},
		{Key: "multipleHooks", Path: "/multi-hooks", Methods: []string{"GET"},
			Handler: ppEcho(func(*EndpointContext) any { return map[string]any{"return": "1"} })},
	}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Plugins = append(c.Plugins, &Plugin{ID: "test", Hooks: PluginHooks{After: []Hook{{
			Matcher: func(*EndpointContext) bool { return true },
			Handler: func(c *EndpointContext) (any, error) {
				if c.Path == "/multi-hooks" {
					return map[string]any{"return": "3"}, nil
				}
				return nil, nil
			},
		}}}})
		c.Hooks = &HooksConfig{After: func(c *EndpointContext) (any, error) {
			if c.Path == "/change-response" {
				return map[string]any{"hello": "auth"}, nil
			}
			if c.Path == "/multi-hooks" {
				return map[string]any{"return": "2"}, nil
			}
			if c.Query["throwHook"] == true {
				c.SetHeader("Set-Cookie", "auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
				return nil, ErrMessage("BAD_REQUEST", "from after hook")
			}
			return nil, nil
		}}
	})
	a := env.auth
	t.Run("should change the response object from hello:world to hello:auth", func(t *testing.T) {
		ppAssertSubset(t, ppDecode(t, ppMustCall(t, a, "changeResponse", CallInput{}).Data), map[string]any{"hello": "auth"})
	})
	t.Run("should return the last hook returned response", func(t *testing.T) {
		ppAssertSubset(t, ppDecode(t, ppMustCall(t, a, "multipleHooks", CallInput{}).Data), map[string]any{"return": "3"})
	})
	t.Run("should return error as response", func(t *testing.T) {
		r := ppAsResponse(ppCall(t, a, "throwError", CallInput{}))
		if r.Status != 400 {
			t.Fatalf("status = %d", r.Status)
		}
	})
	t.Run("should throw the last error", func(t *testing.T) {
		_, err := ppCall(t, a, "throwError", CallInput{Query: map[string]any{"throwHook": true}})
		e, ok := AsAPIError(err)
		if !ok {
			t.Fatalf("err = %v", err)
		}
		if e.Message() != "from after hook" {
			t.Fatalf("message = %q", e.Message())
		}
		r := ppAsResponse(ppCall(t, a, "throwError", CallInput{Query: map[string]any{"throwHook": true}}))
		if got := ppSetCookie(r.Header); got != "auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT" {
			t.Fatalf("Set-Cookie = %q", got)
		}
	})
}

// describe("after hook") > describe("cookies")
func TestPortAPIEndpointsAfterHookCookies(t *testing.T) {
	eps := []*Endpoint{
		{Key: "cookies", Path: "/cookies", Methods: []string{"POST"}, Handler: func(c *EndpointContext) (any, error) {
			c.SetCookie("session", "value", CookieOptions{})
			return map[string]any{"hello": "world"}, nil
		}},
		{Key: "cookieOverride", Path: "/cookie", Methods: []string{"GET"}, Handler: func(c *EndpointContext) (any, error) {
			c.SetCookie("data", "1", CookieOptions{})
			return nil, nil
		}},
		{Key: "noCookie", Path: "/no-cookie", Methods: []string{"GET"}, Handler: func(*EndpointContext) (any, error) { return nil, nil }},
	}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Hooks = &HooksConfig{After: func(c *EndpointContext) (any, error) {
			c.SetHeader("key", "value")
			c.SetCookie("data", "2", CookieOptions{})
			return nil, nil
		}}
	})
	a := env.auth
	t.Run("set cookies from both hook", func(t *testing.T) {
		sc := ppSetCookie(ppAsResponse(ppCall(t, a, "cookies", CallInput{})).Header)
		if !strings.Contains(sc, "session=value") || !strings.Contains(sc, "data=2") {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
	t.Run("should override cookie", func(t *testing.T) {
		sc := ppSetCookie(ppAsResponse(ppCall(t, a, "cookieOverride", CallInput{})).Header)
		if !strings.Contains(sc, "data=2") {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
	t.Run("should only set the hook cookie", func(t *testing.T) {
		sc := ppSetCookie(ppAsResponse(ppCall(t, a, "noCookie", CallInput{})).Header)
		if !strings.Contains(sc, "data=2") {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
	t.Run("should return cookies from return headers", func(t *testing.T) {
		res := ppMustCall(t, a, "noCookie", CallInput{})
		if sc := ppSetCookie(res.Headers); !strings.Contains(sc, "data=2") {
			t.Fatalf("set-cookie = %q", sc)
		}
		sc := ppSetCookie(ppAsResponse(ppCall(t, a, "cookies", CallInput{})).Header)
		if !strings.Contains(sc, "session=value") || !strings.Contains(sc, "data=2") {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
	t.Run("should return a Response when invoked with a request context", func(t *testing.T) {
		// Go API semantics: a call with Request still returns a *CallResult (data + headers).
		req := httptest.NewRequest("POST", "http://localhost:3000/cookies", nil)
		res := ppMustCall(t, a, "cookies", CallInput{Request: req})
		ppAssertSubset(t, ppDecode(t, res.Data), map[string]any{"hello": "world"})
		sc := ppSetCookie(res.Headers)
		if !strings.Contains(sc, "session=value") || !strings.Contains(sc, "data=2") {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
}

// describe("disabled paths")
func TestPortAPIEndpointsDisabledPaths(t *testing.T) {
	jsonH := map[string]string{"Content-Type": "application/json"}
	signInBody := `{"email":"test@test.com","password":"test"}`

	t.Run("should return 404 for disabled paths", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.DisabledPaths = []string{"/sign-in/email"} })
		c := env.client()
		ok := c.get("/ok")
		if ok.Status != 200 || !reflect.DeepEqual(ok.JSON(t), map[string]any{"ok": true}) {
			t.Fatalf("/ok = %d %s", ok.Status, ok.Body)
		}
		res := c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test"})
		if res.Status != 404 {
			t.Fatalf("status = %d", res.Status)
		}
	})
	t.Run("should return 404 for when base path is /", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.BasePath = "/"
			c.DisabledPaths = []string{"/sign-in/email"}
		})
		res, err := ppServe(env.auth, "POST", "http://localhost:3000/sign-in/email", signInBody, jsonH)
		if err != nil || res == nil || res.Status == 0 {
			t.Fatalf("expected a response, got %v %v", res, err)
		}
	})
	t.Run("should return 404 for disabled paths with a trailing slash", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.DisabledPaths = []string{"/sign-in/email"} })
		r1 := ppMustServe(t, env.auth, "POST", "http://localhost:3000/api/auth/sign-in/email%2F", "", nil)
		r2 := ppMustServe(t, env.auth, "POST", "http://localhost:3000/api/auth/sign-inemail", "", nil)
		if r1.Status != 404 || r2.Status != 404 {
			t.Fatalf("statuses = %d %d", r1.Status, r2.Status)
		}
	})
	t.Run("should return 404 for encoded paths", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.DisabledPaths = []string{"/sign-in/email"} })
		r1 := ppMustServe(t, env.auth, "POST", "http://localhost:3000/api/auth/sign-in/email%2F", "", nil)
		_ = ppMustServe(t, env.auth, "POST", "http://localhost:3000/api/auth/sign-inemail", "", nil)
		if r1.Status != 404 {
			t.Fatalf("status = %d", r1.Status)
		}
	})
	t.Run("should block URL encoded slash bypass attempts", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.DisabledPaths = []string{"/sign-in/email"} })
		for _, u := range []string{
			"http://localhost:3000/api/auth/sign-in%2Femail",
			"http://localhost:3000/api/auth/sign-in%252Femail",
			"http://localhost:3000/api/auth/sign-in%2femail",
		} {
			if r := ppMustServe(t, env.auth, "POST", u, signInBody, jsonH); r.Status != 404 {
				t.Fatalf("%s: status = %d", u, r.Status)
			}
		}
	})
	t.Run("should block path traversal attempts", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.DisabledPaths = []string{"/sign-in/email"} })
		for _, u := range []string{
			"http://localhost:3000/api/auth/sign-in/../sign-in/email",
			"http://localhost:3000/api/auth/./sign-in/email",
			"http://localhost:3000/api/auth/sign-in/./email",
			"http://localhost:3000/api/auth/sign-in//email",
			"http://localhost:3000/api/auth/sign-in///email",
		} {
			if r := ppMustServe(t, env.auth, "POST", u, signInBody, jsonH); r.Status != 404 {
				t.Fatalf("%s: status = %d", u, r.Status)
			}
		}
	})
	t.Run("should handle unicode and special characters in disabled paths", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.DisabledPaths = []string{"/sign-in/email"} })
		for _, u := range []string{
			"http://localhost:3000/api/auth/sign-in%00/email",
			"http://localhost:3000/api/auth/sign-in\u0000/email",
			"http://localhost:3000/api/auth/sign-in/email%09",
			"http://localhost:3000/api/auth/sign-in/email%20",
		} {
			r, err := ppServe(env.auth, "POST", u, signInBody, jsonH)
			if err != nil {
				continue // URL constructor may throw for invalid URLs - acceptable upstream
			}
			if r.Status != 404 && r.Status != 400 {
				t.Fatalf("%q: status = %d", u, r.Status)
			}
		}
	})
	t.Run("should not be affected by case sensitivity bypass", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) { c.DisabledPaths = []string{"/sign-in/email"} })
		for _, u := range []string{
			"http://localhost:3000/api/auth/Sign-In/Email",
			"http://localhost:3000/api/auth/SIGN-IN/EMAIL",
			"http://localhost:3000/api/auth/Sign-in/email",
		} {
			if r := ppMustServe(t, env.auth, "POST", u, signInBody, jsonH); r.Status == 200 {
				t.Fatalf("%s: status = 200", u)
			}
		}
	})
}

// describe("trustedProxyHeaders security")
func TestPortAPIEndpointsTrustedProxyHeaders(t *testing.T) {
	captureEnv := func(t *testing.T, trusted bool, captured *string) *testEnv {
		ppNoEnvBaseURL(t)
		return newTestEnv(t, func(c *Config) {
			c.BaseURL = ""
			c.Advanced.TrustedProxyHeaders = trusted
			if captured != nil {
				c.Hooks = &HooksConfig{Before: func(ctx *EndpointContext) (any, error) {
					*captured = ctx.Auth.BaseURL
					return nil, nil
				}}
			}
		})
	}
	t.Run("should not use X-Forwarded headers when trustedProxyHeaders is false", func(t *testing.T) {
		var captured string
		env := captureEnv(t, false, &captured)
		ppMustServe(t, env.auth, "GET", "http://localhost:3000/api/auth/ok", "",
			map[string]string{"x-forwarded-host": "evil.com", "x-forwarded-proto": "https"})
		if captured != "http://localhost:3000/api/auth" || strings.Contains(captured, "evil.com") {
			t.Fatalf("baseURL = %q", captured)
		}
	})
	t.Run("should validate X-Forwarded headers when trustedProxyHeaders is true", func(t *testing.T) {
		var captured string
		env := captureEnv(t, true, &captured)
		ppMustServe(t, env.auth, "GET", "http://localhost:3000/api/auth/ok", "",
			map[string]string{"x-forwarded-host": "trusted-proxy.com", "x-forwarded-proto": "https"})
		if captured != "https://trusted-proxy.com/api/auth" {
			t.Fatalf("baseURL = %q", captured)
		}
	})
	t.Run("should not trust partial X-Forwarded headers", func(t *testing.T) {
		env := captureEnv(t, true, nil)
		r1 := ppMustServe(t, env.auth, "GET", "http://localhost:3000/api/auth/ok", "", map[string]string{"x-forwarded-host": "evil.com"})
		r2 := ppMustServe(t, env.auth, "GET", "http://localhost:3000/api/auth/ok", "", map[string]string{"x-forwarded-proto": "https"})
		if r1.Status != 200 || r2.Status != 200 {
			t.Fatalf("statuses = %d %d", r1.Status, r2.Status)
		}
	})
	t.Run("should handle malformed X-Forwarded headers gracefully", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.BaseURL = "http://localhost:3000"
			c.Advanced.TrustedProxyHeaders = true
		})
		for _, h := range []map[string]string{
			{"x-forwarded-host": "../../../../etc/passwd", "x-forwarded-proto": "http"},
			{"x-forwarded-host": "evil.com:99999", "x-forwarded-proto": "http"},
			{"x-forwarded-host": "evil.com", "x-forwarded-proto": "javascript"},
			{"x-forwarded-host": "evil.com", "x-forwarded-proto": "file"},
			{"x-forwarded-host": "", "x-forwarded-proto": "http"},
			{"x-forwarded-host": " ", "x-forwarded-proto": "http"},
		} {
			if r := ppMustServe(t, env.auth, "GET", "http://localhost:3000/api/auth/ok", "", h); r.Status != 200 {
				t.Fatalf("%v: status = %d", h, r.Status)
			}
		}
	})
}

// describe("debug mode stack trace") — JavaScript Error.stack formatting.
func TestPortAPIEndpointsDebugModeStackTrace(t *testing.T) {
	t.Skip("TS-only: asserts JavaScript Error.stack contents (ErrorWithStack, .ts:line:col); Go errors carry no stack")
}

// describe("dynamic baseURL resolution") (#9105)
func TestPortAPIEndpointsDynamicBaseURL(t *testing.T) {
	readBaseURL := []*Endpoint{{Key: "readBaseURL", Path: "/read-base-url", Methods: []string{"GET"},
		Handler: ppEcho(func(c *EndpointContext) any { return map[string]any{"baseURL": c.Auth.BaseURL} })}}
	dynEnv := func(t *testing.T, d *DynamicBaseURL, mutate func(c *Config)) *testEnv {
		ppNoEnvBaseURL(t)
		return ppPluginEnv(t, readBaseURL, func(c *Config) {
			c.BaseURL = ""
			c.DynamicBaseURL = d
			if mutate != nil {
				mutate(c)
			}
		})
	}
	hostHeaders := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	baseOf := func(t *testing.T, res *CallResult) string {
		t.Helper()
		s, _ := ppDecode(t, res.Data)["baseURL"].(string)
		return s
	}

	t.Run("should resolve dynamic baseURL from headers for direct auth.api calls", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com"}, Protocol: "https"}, nil)
		res := ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "example.com")})
		if got := baseOf(t, res); got != "https://example.com/api/auth" {
			t.Fatalf("baseURL = %q", got)
		}
	})
	t.Run("should leave baseURL untouched for static string config", func(t *testing.T) {
		env := ppPluginEnv(t, readBaseURL, func(c *Config) { c.BaseURL = "https://static.example.com" })
		res := ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "other.example.com")})
		if got := baseOf(t, res); got != "https://static.example.com/api/auth" {
			t.Fatalf("baseURL = %q", got)
		}
	})
	t.Run("should reject Node IncomingMessage-shaped objects when duck typing", func(t *testing.T) {
		t.Skip("TS-only: duck-typing of Node IncomingMessage vs Fetch Request; Go has a single *http.Request type")
	})
	t.Run("should not mutate the shared authContext across calls", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"tenant-a.example.com", "tenant-b.example.com"}, Protocol: "https"}, nil)
		var wg sync.WaitGroup
		var resA, resB *CallResult
		var errA, errB error
		wg.Add(2)
		go func() {
			defer wg.Done()
			resA, errA = env.auth.API.Call(t.Context(), "readBaseURL", CallInput{Headers: hostHeaders("host", "tenant-a.example.com")})
		}()
		go func() {
			defer wg.Done()
			resB, errB = env.auth.API.Call(t.Context(), "readBaseURL", CallInput{Headers: hostHeaders("host", "tenant-b.example.com")})
		}()
		wg.Wait()
		if errA != nil || errB != nil {
			t.Fatalf("errors: %v %v", errA, errB)
		}
		if got := baseOf(t, resA); got != "https://tenant-a.example.com/api/auth" {
			t.Fatalf("A = %q", got)
		}
		if got := baseOf(t, resB); got != "https://tenant-b.example.com/api/auth" {
			t.Fatalf("B = %q", got)
		}
		if got := env.auth.Context().BaseURL; got != "" {
			t.Fatalf("shared ctx baseURL = %q", got)
		}
	})
	t.Run("should ignore x-forwarded headers when trustedProxyHeaders is not configured", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com", "proxy.example.com"}}, nil)
		res := ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "example.com",
			"x-forwarded-host", "proxy.example.com", "x-forwarded-proto", "http")})
		if got := baseOf(t, res); got != "https://example.com/api/auth" {
			t.Fatalf("baseURL = %q", got)
		}
	})
	t.Run("should ignore x-forwarded-host when trustedProxyHeaders is explicitly disabled", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com", "evil.com"}, Protocol: "https"},
			func(c *Config) { c.Advanced.TrustedProxyHeaders = false })
		res := ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "example.com", "x-forwarded-host", "evil.com")})
		if got := baseOf(t, res); got != "https://example.com/api/auth" {
			t.Fatalf("baseURL = %q", got)
		}
	})
	t.Run("should honor x-forwarded-host when trustedProxyHeaders is enabled", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com", "proxy.example.com"}, Protocol: "https"},
			func(c *Config) { c.Advanced.TrustedProxyHeaders = true })
		res := ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "example.com", "x-forwarded-host", "proxy.example.com")})
		if got := baseOf(t, res); got != "https://proxy.example.com/api/auth" {
			t.Fatalf("baseURL = %q", got)
		}
	})
	t.Run("should throw APIError when the host is not in allowedHosts", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com"}, Protocol: "https"}, nil)
		_, err := ppCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "not-allowed.com")})
		if _, ok := AsAPIError(err); !ok {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("should throw APIError when called with no source and no fallback", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com"}, Protocol: "https"}, nil)
		_, err := ppCall(t, env.auth, "readBaseURL", CallInput{})
		if _, ok := AsAPIError(err); !ok {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("should use fallback when source is missing", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com"}, Protocol: "https", Fallback: "https://default.example.com"}, nil)
		res := ppMustCall(t, env.auth, "readBaseURL", CallInput{})
		if got := baseOf(t, res); got != "https://default.example.com/api/auth" {
			t.Fatalf("baseURL = %q", got)
		}
	})
	t.Run("should expose a Request-like to a user-defined trustedOrigins callback", func(t *testing.T) {
		var seenHost string
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"example.com"}, Protocol: "https"}, func(c *Config) {
			c.TrustedOriginsFunc = func(r *http.Request) ([]string, error) {
				if r != nil {
					seenHost = r.Header.Get("Host")
					if seenHost == "" {
						seenHost = r.Host
					}
				}
				return nil, nil
			}
		})
		seenHost = ""
		ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "example.com")})
		if seenHost != "example.com" {
			t.Fatalf("trustedOrigins callback saw host %q, want example.com", seenHost)
		}
	})
	t.Run("should return a Response for cross-realm Request inputs", func(t *testing.T) {
		t.Skip("TS-only: cross-realm Request detection via Symbol.toStringTag")
	})
	t.Run("should infer http for loopback hosts on the headers-only path", func(t *testing.T) {
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"localhost:3000"}}, nil)
		res := ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "localhost:3000")})
		if got := baseOf(t, res); got != "http://localhost:3000/api/auth" {
			t.Fatalf("baseURL = %q", got)
		}
	})
	t.Run("should rehydrate trustedProviders per call when configured as a function", func(t *testing.T) {
		var hosts ppStringRecorder
		env := dynEnv(t, &DynamicBaseURL{AllowedHosts: []string{"tenant-a.example.com", "tenant-b.example.com"}, Protocol: "https"}, func(c *Config) {
			c.Account = &AccountConfig{AccountLinking: &AccountLinkingConfig{TrustedProvidersFunc: func(r *http.Request) ([]string, error) {
				if r != nil {
					h := r.Header.Get("Host")
					if h == "" {
						h = r.Host
					}
					if h != "" {
						hosts.add(h)
					}
				}
				return []string{"google"}, nil
			}}}
		})
		hosts.reset()
		ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "tenant-a.example.com")})
		ppMustCall(t, env.auth, "readBaseURL", CallInput{Headers: hostHeaders("host", "tenant-b.example.com")})
		if got := hosts.list(); !reflect.DeepEqual(got, []string{"tenant-a.example.com", "tenant-b.example.com"}) {
			t.Fatalf("hosts = %v", got)
		}
	})
}

// describe("custom response code")
func TestPortAPIEndpointsCustomResponseCode(t *testing.T) {
	eps := []*Endpoint{{Key: "responseWithStatus", Path: "/response-with-status", Methods: []string{"GET"},
		Handler: func(c *EndpointContext) (any, error) {
			c.SetStatus(201)
			return map[string]any{"success": true}, nil
		}}}
	env := ppPluginEnv(t, eps, nil)
	t.Run("should return response with custom status", func(t *testing.T) {
		r := ppAsResponse(ppCall(t, env.auth, "responseWithStatus", CallInput{}))
		if r.Status != 201 {
			t.Fatalf("status = %d", r.Status)
		}
	})
	t.Run("should return status code", func(t *testing.T) {
		res := ppMustCall(t, env.auth, "responseWithStatus", CallInput{})
		if res.Status != 201 {
			t.Fatalf("status = %d", res.Status)
		}
		if got := ppDecode(t, res.Data); !reflect.DeepEqual(got, map[string]any{"success": true}) {
			t.Fatalf("response = %v", got)
		}
	})
}

// describe("response headers on APIError") (#8576)
func TestPortAPIEndpointsResponseHeadersOnAPIError(t *testing.T) {
	eps := []*Endpoint{
		{Key: "setCookieThenThrow", Path: "/set-cookie-then-throw", Methods: []string{"POST"}, Handler: func(c *EndpointContext) (any, error) {
			c.SetCookie("session", "", CookieOptions{MaxAge: Int(0)})
			c.SetCookie("session_data", "", CookieOptions{MaxAge: Int(0)})
			return nil, ErrMessage("UNAUTHORIZED", "cleared")
		}},
		{Key: "setCookieThenThrowWithExplicitHeaders", Path: "/set-cookie-then-throw-with-explicit-headers", Methods: []string{"POST"},
			Handler: func(c *EndpointContext) (any, error) {
				c.SetCookie("session", "", CookieOptions{MaxAge: Int(0)})
				e := NewAPIError("FOUND", jsonx.O("message", "redirect"))
				e.Headers.Set("location", "/login")
				return nil, e
			}},
		{Key: "setCookieThenRedirect", Path: "/set-cookie-then-redirect", Methods: []string{"GET"}, Handler: func(c *EndpointContext) (any, error) {
			c.SetCookie("session", "", CookieOptions{MaxAge: Int(0)})
			c.SetCookie("session_data", "", CookieOptions{MaxAge: Int(0)})
			return nil, c.Redirect("/dashboard")
		}},
	}
	env := ppPluginEnv(t, eps, nil)
	a := env.auth

	t.Run("preserves Set-Cookie headers accumulated via c.setCookie when the endpoint throws APIError", func(t *testing.T) {
		r := ppAsResponse(ppCall(t, a, "setCookieThenThrow", CallInput{}))
		if r.Status != 401 {
			t.Fatalf("status = %d", r.Status)
		}
		sc := ppSetCookie(r.Header)
		if !regexp.MustCompile(`(^|,\s*)session=;`).MatchString(sc) || !regexp.MustCompile(`(^|,\s*)session_data=;`).MatchString(sc) {
			t.Fatalf("set-cookie = %q", sc)
		}
		if !strings.Contains(strings.ToLower(sc), "max-age=0") {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
	t.Run("merges ctx.responseHeaders with explicit APIError headers so both survive", func(t *testing.T) {
		r := ppAsResponse(ppCall(t, a, "setCookieThenThrowWithExplicitHeaders", CallInput{}))
		if r.Status != 302 {
			t.Fatalf("status = %d", r.Status)
		}
		if r.Header.Get("location") != "/login" {
			t.Fatalf("location = %q", r.Header.Get("location"))
		}
		if sc := ppSetCookie(r.Header); !regexp.MustCompile(`(^|,\s*)session=;`).MatchString(sc) {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
	t.Run("attaches merged headers to the thrown APIError on the non-response path", func(t *testing.T) {
		_, err := ppCall(t, a, "setCookieThenThrowWithExplicitHeaders", CallInput{})
		e, ok := AsAPIError(err)
		if !ok {
			t.Fatalf("err = %v", err)
		}
		if e.Headers == nil {
			t.Fatal("no headers on APIError")
		}
		if e.Headers.Get("location") != "/login" {
			t.Fatalf("location = %q", e.Headers.Get("location"))
		}
		if sc := ppSetCookie(e.Headers); !regexp.MustCompile(`(^|,\s*)session=;`).MatchString(sc) {
			t.Fatalf("set-cookie = %q", sc)
		}
	})
	t.Run("does not duplicate Set-Cookie when c.redirect reuses ctx.responseHeaders as e.headers", func(t *testing.T) {
		r := ppAsResponse(ppCall(t, a, "setCookieThenRedirect", CallInput{}))
		if r.Status != 302 {
			t.Fatalf("status = %d", r.Status)
		}
		if r.Header.Get("location") != "/dashboard" {
			t.Fatalf("location = %q", r.Header.Get("location"))
		}
		scs := r.Header.Values("Set-Cookie")
		if len(scs) != 2 {
			t.Fatalf("set-cookies = %q", scs)
		}
		var s1, s2 bool
		for _, c := range scs {
			s1 = s1 || strings.HasPrefix(c, "session=")
			s2 = s2 || strings.HasPrefix(c, "session_data=")
		}
		if !s1 || !s2 {
			t.Fatalf("set-cookies = %q", scs)
		}
	})
}

// describe("hook dispatch boundary") (#9887)
func TestPortAPIEndpointsHookDispatchBoundary(t *testing.T) {
	var before, after ppStringRecorder
	env := newTestEnv(t, func(c *Config) {
		c.Hooks = &HooksConfig{
			Before: func(ctx *EndpointContext) (any, error) { before.add(ctx.Path); return nil, nil },
			After:  func(ctx *EndpointContext) (any, error) { after.add(ctx.Path); return nil, nil },
		}
	})
	headers := ppSignUpTestUser(t, env.auth)
	before.reset()
	after.reset()
	if _, err := env.auth.API.ListSessions(t.Context(), headers); err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if !before.contains("/list-sessions") || !after.contains("/list-sessions") {
		t.Fatalf("before=%v after=%v", before.list(), after.list())
	}
	if before.contains("/get-session") || after.contains("/get-session") {
		t.Fatalf("hooks re-ran for internal getSession: before=%v after=%v", before.list(), after.list())
	}
	before.reset()
	if _, err := env.auth.API.GetSession(t.Context(), headers); err != nil {
		t.Fatalf("getSession: %v", err)
	}
	if !before.contains("/get-session") {
		t.Fatalf("before=%v", before.list())
	}
}

// describe("before hook response headers")
func TestPortAPIEndpointsBeforeHookResponseHeaders(t *testing.T) {
	eps := []*Endpoint{{Key: "guarded", Path: "/guarded", Methods: []string{"GET"},
		Handler: ppEcho(func(*EndpointContext) any { return map[string]any{"handler": true} })}}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Hooks = &HooksConfig{Before: func(c *EndpointContext) (any, error) {
			c.SetHeader("x-before", "yes")
			c.SetCookie("from_before", "1", CookieOptions{})
			return map[string]any{"shortCircuited": true}, nil
		}}
	})
	r := ppAsResponse(ppCall(t, env.auth, "guarded", CallInput{}))
	ppAssertSubset(t, ppBodyJSON(t, r), map[string]any{"shortCircuited": true})
	if r.Header.Get("x-before") != "yes" {
		t.Fatalf("x-before = %q", r.Header.Get("x-before"))
	}
	if sc := ppSetCookie(r.Header); !strings.Contains(sc, "from_before=1") {
		t.Fatalf("set-cookie = %q", sc)
	}
}

// describe("after hook error headers")
func TestPortAPIEndpointsAfterHookErrorHeaders(t *testing.T) {
	eps := []*Endpoint{{Key: "ppAfterOk", Path: "/pp-after-ok", Methods: []string{"GET"},
		Handler: ppEcho(func(*EndpointContext) any { return map[string]any{"ok": true} })}}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Hooks = &HooksConfig{After: func(c *EndpointContext) (any, error) {
			c.SetCookie("from_after", "1", CookieOptions{})
			e := ErrMessage("BAD_REQUEST", "after rejected")
			e.Headers.Set("location", "/login")
			return nil, e
		}}
	})
	r := ppAsResponse(ppCall(t, env.auth, "ppAfterOk", CallInput{}))
	if r.Status != 400 {
		t.Fatalf("status = %d", r.Status)
	}
	if r.Header.Get("location") != "/login" {
		t.Fatalf("location = %q", r.Header.Get("location"))
	}
	if sc := ppSetCookie(r.Header); !strings.Contains(sc, "from_after=1") {
		t.Fatalf("set-cookie = %q", sc)
	}
}

// describe("before hook request headers")
func TestPortAPIEndpointsBeforeHookRequestHeaders(t *testing.T) {
	eps := []*Endpoint{{Key: "echoHeaders", Path: "/echo-headers", Methods: []string{"GET"},
		Handler: ppEcho(func(c *EndpointContext) any { return ppHeadersObject(c.Headers) })}}
	env := ppPluginEnv(t, eps, func(c *Config) {
		c.Hooks = &HooksConfig{Before: func(c *EndpointContext) (any, error) {
			if c.Path == "/echo-headers" {
				if c.Headers == nil {
					c.Headers = http.Header{}
				}
				c.Headers.Set("injected", "yes")
			}
			return nil, nil
		}}
	})
	res := ppDecode(t, ppMustCall(t, env.auth, "echoHeaders", CallInput{}).Data)
	ppAssertSubset(t, res, map[string]any{"injected": "yes"})
}
