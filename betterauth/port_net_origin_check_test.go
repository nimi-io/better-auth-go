package betterauth

// Port of packages/better-auth/src/api/middlewares/origin-check.test.ts (upstream v1.7.7).
//
// Upstream drives requests through `customFetchImpl` / `auth.handler(new Request(...))`,
// which never persists cookies between calls. pnServe mirrors that by calling the Go
// handler directly with an explicit set of headers. Upstream's app origin
// "http://localhost:3000" maps to the httptest server URL.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	pnTestEmail    = "test@test.com"
	pnTestPassword = "test123456"
	pnCSRFMessage  = "Cross-site navigation login blocked. This request appears to be a CSRF attack."
)

// pnServe mirrors auth.handler(new Request(rawURL, {method, headers, body})).
func pnServe(t *testing.T, env *testEnv, method, rawURL string, headers map[string]string, body any) *testResponse {
	t.Helper()
	var buf *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		buf = bytes.NewReader(raw)
	} else {
		buf = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, rawURL, buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	env.auth.ServeHTTP(rec, req)
	return &testResponse{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
}

func pnURL(env *testEnv, path string) string { return env.server.URL + "/api/auth" + path }

// pnCreateTestUser mirrors getTestInstance's auth.api.signUpEmail({ body: testUser }).
func pnCreateTestUser(t *testing.T, env *testEnv) {
	t.Helper()
	if _, err := env.auth.API.SignUpEmail(context.Background(),
		SignUpEmailInput{Email: pnTestEmail, Password: pnTestPassword, Name: "test user"}, nil); err != nil {
		t.Fatalf("create test user: %v", err)
	}
}

func pnSignInBody(extra ...any) map[string]any {
	m := map[string]any{"email": pnTestEmail, "password": pnTestPassword}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i].(string)] = extra[i+1]
	}
	return m
}

func pnExpectUser(t *testing.T, res *testResponse) {
	t.Helper()
	if res.Status != 200 {
		t.Fatalf("expected user, got %d %s", res.Status, res.Body)
	}
	if m := res.JSON(t); m["user"] == nil {
		t.Fatalf("expected user in %s", res.Body)
	}
}

func pnExpectStatus(t *testing.T, res *testResponse, status int) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("expected %d, got %d: %s", status, res.Status, res.Body)
	}
}

func pnExpectNotStatus(t *testing.T, res *testResponse, status int) {
	t.Helper()
	if res.Status == status {
		t.Fatalf("expected status other than %d: %s", status, res.Body)
	}
}

func pnExpectMessage(t *testing.T, res *testResponse, msg string) {
	t.Helper()
	if m := res.JSON(t); m["message"] != msg {
		t.Fatalf("expected message %q, got %v (%s)", msg, m["message"], res.Body)
	}
}

func pnExpectNotCSRFMessage(t *testing.T, res *testResponse) {
	t.Helper()
	var m map[string]any
	if json.Unmarshal(res.Body, &m) == nil && m["message"] == pnCSRFMessage {
		t.Fatalf("unexpected CSRF block: %s", res.Body)
	}
}

func pnAdvanced(csrf, origin *bool) *AdvancedConfig {
	return &AdvancedConfig{DisableCSRFCheck: csrf, DisableOriginCheck: origin}
}

func TestPortNetOriginCheck(t *testing.T) {
	env := newTestEnv(t, func(c *Config) {
		c.TrustedOrigins = []string{"http://localhost:5000", "https://trusted.com", "*.my-site.com"}
		c.EmailAndPassword = &EmailAndPasswordConfig{Enabled: true,
			SendResetPassword: func(_ context.Context, _ EmailData, _ *http.Request) error { return nil }}
		c.Advanced = pnAdvanced(Bool(false), Bool(false))
	})
	pnCreateTestUser(t, env)
	app := env.server.URL

	t.Run("should allow trusted origins", func(t *testing.T) {
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), map[string]string{"origin": app},
			pnSignInBody("callbackURL", app+"/callback"))
		pnExpectUser(t, res)
	})
	t.Run("should not allow untrusted origins", func(t *testing.T) {
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), nil,
			map[string]any{"email": "test@test.com", "password": "password", "callbackURL": "http://malicious.com"})
		pnExpectStatus(t, res, 403)
		pnExpectMessage(t, res, "Invalid callbackURL")
	})
	t.Run("should reject untrusted origin headers", func(t *testing.T) {
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "malicious.com", "cookie": "session=123"}, pnSignInBody())
		pnExpectStatus(t, res, 403)
	})
	t.Run("should reject untrusted origin even without cookies", func(t *testing.T) {
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://sub-domain.trusted.com"}, pnSignInBody())
		pnExpectStatus(t, res, 403)
	})
	t.Run("should reject untrusted redirectTo", func(t *testing.T) {
		res := pnServe(t, env, "POST", pnURL(env, "/request-password-reset"), nil,
			map[string]any{"email": pnTestEmail, "redirectTo": "http://malicious.com"})
		pnExpectStatus(t, res, 403)
		pnExpectMessage(t, res, "Invalid redirectURL")
	})
	t.Run("should work with list of trusted origins", func(t *testing.T) {
		h := map[string]string{"origin": "https://trusted.com"}
		res := pnServe(t, env, "POST", pnURL(env, "/request-password-reset"), h,
			map[string]any{"email": pnTestEmail, "redirectTo": "http://localhost:5000/reset-password"})
		pnExpectStatus(t, res, 200)
		if m := res.JSON(t); m["status"] != true {
			t.Fatalf("expected status true: %s", res.Body)
		}
		res2 := pnServe(t, env, "POST", pnURL(env, "/sign-in/email?currentURL=http%3A%2F%2Flocalhost%3A5000"), h, pnSignInBody())
		pnExpectUser(t, res2)
	})
	t.Run("should work with wildcard trusted origins", func(t *testing.T) {
		res := pnServe(t, env, "POST", "https://sub-domain.my-site.com/api/auth/sign-in/email",
			map[string]string{"origin": "https://sub-domain.my-site.com"},
			pnSignInBody("callbackURL", "https://sub-domain.my-site.com/callback"))
		pnExpectUser(t, res)
	})
	t.Run("should work with GET requests", func(t *testing.T) {
		res := pnServe(t, env, "GET", "https://sub-domain.my-site.com/api/auth/ok",
			map[string]string{"origin": "https://google.com", "cookie": "value"}, nil)
		pnExpectStatus(t, res, 200)
		if m := res.JSON(t); m["ok"] != true {
			t.Fatalf("got %s", res.Body)
		}
	})
	t.Run("should handle POST requests with proper origin validation", func(t *testing.T) {
		valid := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://localhost:5000", "cookie": "session=123"}, pnSignInBody())
		pnExpectUser(t, valid)
		invalid := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://untrusted-domain.com", "cookie": "session=123"}, pnSignInBody())
		pnExpectStatus(t, invalid, 403)
	})
	t.Run("should filter out null values from trustedOrigins callback", func(t *testing.T) {
		env2 := newTestEnv(t, func(c *Config) {
			c.Advanced = pnAdvanced(Bool(false), Bool(false))
			c.TrustedOriginsFunc = func(r *http.Request) ([]string, error) {
				if r == nil {
					return []string{}, nil
				}
				return []string{"http://valid-origin.com", r.Header.Get("x-custom-origin"), r.Header.Get("x-another-origin")}, nil
			}
		})
		pnCreateTestUser(t, env2)
		res := pnServe(t, env2, "POST", pnURL(env2, "/sign-in/email"),
			map[string]string{"origin": "http://valid-origin.com"}, pnSignInBody())
		pnExpectUser(t, res)
	})
}

func TestPortNetOriginFetchMetadataCSRF(t *testing.T) {
	var env *testEnv
	env = newTestEnv(t, func(c *Config) {
		// "http://localhost:3000" upstream is the app origin, i.e. the server URL here.
		c.TrustedOrigins = []string{c.BaseURL, "https://app.example.com"}
		c.Advanced = pnAdvanced(Bool(false), Bool(false))
	})
	pnCreateTestUser(t, env)
	app := env.server.URL
	signIn := pnURL(env, "/sign-in/email")

	t.Run("should block cross-site navigation on first-login (no session cookie)", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{
			"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "origin": "https://evil.com",
		}, map[string]any{"email": "attacker@evil.com", "password": "password123"})
		pnExpectStatus(t, res, 403)
		pnExpectMessage(t, res, pnCSRFMessage)
	})
	t.Run("should allow same-origin navigation on first-login (no session cookie)", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "origin": app,
		}, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
		pnExpectNotCSRFMessage(t, res)
	})
	t.Run("should allow same-site navigation on first-login (no session cookie)", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{
			"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "origin": "https://app.example.com",
		}, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
		pnExpectNotCSRFMessage(t, res)
	})
	t.Run("should fallback to origin validation when Fetch Metadata is missing", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{"origin": app}, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
	})
	t.Run("should reject an untrusted origin on first-login when Fetch Metadata is missing", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{"origin": "https://evil.com"}, pnSignInBody())
		pnExpectStatus(t, res, 403)
	})
	t.Run("should reject an untrusted Referer on first-login when Fetch Metadata is missing", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{"referer": "https://evil.com"}, pnSignInBody())
		pnExpectStatus(t, res, 403)
	})
	t.Run("should allow a first-login request that sends no cookies, Fetch Metadata, or origin", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, nil, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
	})
	t.Run("should use existing origin validation when session cookie exists", func(t *testing.T) {
		signInRes := pnServe(t, env, "POST", signIn, nil, pnSignInBody())
		token, ok := signInRes.cookie("better-auth.session_token")
		if !ok {
			t.Fatalf("Failed to get session cookie: %v", signInRes.Header.Values("Set-Cookie"))
		}
		res := pnServe(t, env, "POST", signIn, map[string]string{
			"cookie": "better-auth.session_token=" + token, "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "origin": app,
		}, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
	})
	t.Run("should block cross-site navigation for sign-up endpoint", func(t *testing.T) {
		res := pnServe(t, env, "POST", pnURL(env, "/sign-up/email"), map[string]string{
			"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "origin": "https://evil.com",
		}, map[string]any{"email": "attacker@evil.com", "password": "password123", "name": "Attacker"})
		pnExpectStatus(t, res, 403)
		pnExpectMessage(t, res, pnCSRFMessage)
	})
	t.Run("should allow cors mode requests (fetch/XHR)", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "origin": app,
		}, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
		pnExpectNotCSRFMessage(t, res)
	})
	t.Run("should allow requests with expired session cookie (cookie presence check)", func(t *testing.T) {
		res := pnServe(t, env, "POST", signIn, map[string]string{
			"cookie": "better-auth.session_token=expired_or_invalid_token", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "origin": app,
		}, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
		pnExpectNotCSRFMessage(t, res)
	})
}

func pnCallbackEndpoint(key, path string) *Endpoint {
	return &Endpoint{Key: key, Path: path, Methods: []string{"GET"},
		Use: []Middleware{OriginCheck(func(c *EndpointContext) []string { return []string{c.QueryString("callbackURL")} })},
		Handler: func(c *EndpointContext) (any, error) {
			if c.QueryString("callbackURL") == "" {
				return nil, ErrMessage("BAD_REQUEST", "callbackURL is required")
			}
			return c.QueryString("callbackURL"), nil
		}}
}

// pnExpectData mirrors better-fetch's `res.data` for a string payload: JSON bodies are
// parsed, anything else is read as text.
func pnExpectData(t *testing.T, res *testResponse, want string) {
	t.Helper()
	pnExpectStatus(t, res, 200)
	s := string(res.Body)
	if strings.Contains(res.Header.Get("Content-Type"), "json") {
		if err := json.Unmarshal(res.Body, &s); err != nil {
			t.Fatalf("decode %s: %v", res.Body, err)
		}
	}
	if s != want {
		t.Fatalf("expected %q, got %q", want, s)
	}
}

func TestPortNetOriginCheckMiddleware(t *testing.T) {
	t.Run("should return invalid origin", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.TrustedOrigins = []string{"https://trusted-site.com"}
			c.Plugins = []*Plugin{{ID: "test", Endpoints: []*Endpoint{pnCallbackEndpoint("test", "/test")}}}
		})
		c := env.client()
		pnExpectStatus(t, c.get("/test?callbackURL=https://malicious-site.com"), 403)
		pnExpectData(t, c.get("/test?callbackURL=/dashboard"), "/dashboard")
		pnExpectData(t, c.get("/test?callbackURL=https://trusted-site.com/path"), "https://trusted-site.com/path")
		pnExpectStatus(t, c.get("/verify-email?callbackURL=https://malicious-site.com&token=xyz"), 403)
	})
	t.Run("should skip origin check for matched paths when skipOriginCheck is set to an array", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.TrustedOrigins = []string{"https://trusted-site.com"}
			c.Plugins = []*Plugin{{ID: "test",
				Init: func(ac *AuthContext) (*PluginInit, error) {
					ac.SkipOriginCheckPaths = []string{"/public/data"}
					return nil, nil
				},
				Endpoints: []*Endpoint{pnCallbackEndpoint("publicEndpoint", "/public/data"), pnCallbackEndpoint("protectedEndpoint", "/protected/data")}}}
		})
		c := env.client()
		pnExpectData(t, c.get("/public/data?callbackURL=https://malicious.com"), "https://malicious.com")
		pnExpectStatus(t, c.get("/protected/data?callbackURL=https://malicious.com"), 403)
	})
	t.Run("should not skip origin check for a path that only shares a prefix with a skip path", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.TrustedOrigins = []string{"https://trusted-site.com"}
			c.Plugins = []*Plugin{{ID: "test",
				Init: func(ac *AuthContext) (*PluginInit, error) {
					ac.SkipOriginCheckPaths = []string{"/public/data"}
					return nil, nil
				},
				Endpoints: []*Endpoint{pnCallbackEndpoint("siblingEndpoint", "/public/database")}}}
		})
		pnExpectStatus(t, env.client().get("/public/database?callbackURL=https://malicious.com"), 403)
	})
	t.Run("should reject a non-string redirect parameter with 400, not 500", func(t *testing.T) {
		env := newTestEnv(t, func(c *Config) {
			c.TrustedOrigins = []string{c.BaseURL}
			c.Advanced = pnAdvanced(Bool(false), Bool(false))
		})
		app := env.server.URL
		objRes := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), map[string]string{"origin": app},
			map[string]any{"email": "test@test.com", "password": "password12345", "callbackURL": map[string]any{"object": true}})
		pnExpectStatus(t, objRes, 400)
		arrRes := pnServe(t, env, "POST", pnURL(env, "/sign-in/email?callbackURL=/a&callbackURL=/b"), map[string]string{"origin": app},
			map[string]any{"email": "test@test.com", "password": "password12345"})
		pnExpectStatus(t, arrRes, 400)
	})
}

func pnInferredEnv(t *testing.T, mutate func(c *Config)) *testEnv {
	t.Helper()
	t.Setenv("BETTER_AUTH_URL", "")
	env := newTestEnv(t, func(c *Config) {
		c.BaseURL = ""
		c.Advanced = pnAdvanced(Bool(false), Bool(false))
		if mutate != nil {
			mutate(c)
		}
	})
	pnCreateTestUser(t, env)
	return env
}

func TestPortNetOriginInferredBaseURL(t *testing.T) {
	t.Run("should respect trustedOrigins array when baseURL is NOT in config", func(t *testing.T) {
		env := pnInferredEnv(t, func(c *Config) { c.TrustedOrigins = []string{"http://my-frontend.com"} })
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://my-frontend.com", "cookie": "session=test"},
			pnSignInBody("callbackURL", "http://my-frontend.com/dashboard"))
		pnExpectUser(t, res)
	})
	t.Run("should reject untrusted origins even when baseURL is inferred", func(t *testing.T) {
		env := pnInferredEnv(t, func(c *Config) { c.TrustedOrigins = []string{"http://my-frontend.com"} })
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://evil-site.com", "cookie": "session=test"}, pnSignInBody())
		pnExpectStatus(t, res, 403)
	})
	t.Run("should respect BETTER_AUTH_TRUSTED_ORIGINS env when baseURL is NOT in config", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_TRUSTED_ORIGINS", "http://env-frontend.com")
		env := pnInferredEnv(t, nil)
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://env-frontend.com", "cookie": "session=test"},
			pnSignInBody("callbackURL", "http://env-frontend.com/dashboard"))
		pnExpectUser(t, res)
	})
	t.Run("should allow requests from inferred baseURL origin", func(t *testing.T) {
		env := pnInferredEnv(t, nil)
		app := env.server.URL
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": app, "cookie": "session=test"}, pnSignInBody("callbackURL", app+"/dashboard"))
		pnExpectUser(t, res)
	})
	t.Run("should support both config array and env var together when baseURL is inferred", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_TRUSTED_ORIGINS", "http://env-origin.com")
		env := pnInferredEnv(t, func(c *Config) { c.TrustedOrigins = []string{"http://config-origin.com"} })
		res1 := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://config-origin.com", "cookie": "session=test"},
			pnSignInBody("callbackURL", "http://config-origin.com/dashboard"))
		pnExpectUser(t, res1)
		res2 := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": "http://env-origin.com", "cookie": "session=test"},
			pnSignInBody("callbackURL", "http://env-origin.com/dashboard"))
		pnExpectUser(t, res2)
	})
}

// pnCaptureLogger records log lines (stands in for vi.spyOn(console, "warn")).
type pnCaptureLogger struct {
	mu    sync.Mutex
	warns []string
}

func (l *pnCaptureLogger) Debug(string, ...any) {}
func (l *pnCaptureLogger) Info(string, ...any)  {}
func (l *pnCaptureLogger) Error(string, ...any) {}
func (l *pnCaptureLogger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(args) > 0 {
		msg += " " + strings.TrimSpace(fmt.Sprintln(args...))
	}
	l.warns = append(l.warns, msg)
}
func (l *pnCaptureLogger) count() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.warns) }

func TestPortNetOriginCSRFAndOriginSeparation(t *testing.T) {
	newEnv := func(t *testing.T, adv *AdvancedConfig) *testEnv {
		env := newTestEnv(t, func(c *Config) {
			c.TrustedOrigins = []string{c.BaseURL}
			c.Advanced = adv
		})
		pnCreateTestUser(t, env)
		return env
	}
	evil := map[string]string{"origin": "http://evil-site.com", "cookie": "session=test"}

	t.Run("disableCSRFCheck should allow untrusted origins with cookies (CSRF bypass)", func(t *testing.T) {
		env := newEnv(t, pnAdvanced(Bool(true), Bool(false)))
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), evil, pnSignInBody("callbackURL", env.server.URL+"/dashboard"))
		pnExpectUser(t, res)
	})
	t.Run("disableCSRFCheck should still validate callbackURL (origin check still active)", func(t *testing.T) {
		env := newEnv(t, pnAdvanced(Bool(true), Bool(false)))
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), evil, pnSignInBody("callbackURL", "http://malicious-site.com/steal"))
		pnExpectStatus(t, res, 403)
		pnExpectMessage(t, res, "Invalid callbackURL")
	})
	t.Run("disableOriginCheck should allow untrusted callbackURL", func(t *testing.T) {
		env := newEnv(t, pnAdvanced(Bool(false), Bool(true)))
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"),
			map[string]string{"origin": env.server.URL, "cookie": "session=test"}, pnSignInBody("callbackURL", "http://any-site.com/redirect"))
		pnExpectUser(t, res)
	})
	t.Run("disableOriginCheck also disables CSRF for backward compatibility", func(t *testing.T) {
		logger := &pnCaptureLogger{}
		env := newTestEnv(t, func(c *Config) {
			c.TrustedOrigins = []string{c.BaseURL}
			c.Advanced = pnAdvanced(nil, Bool(true))
			c.Logger = logger
		})
		pnCreateTestUser(t, env)
		if n := logger.count(); n != 0 {
			t.Fatalf("expected 0 warnings before request, got %d", n)
		}
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), evil, pnSignInBody("callbackURL", "http://any-site.com/redirect"))
		pnExpectUser(t, res)
		if n := logger.count(); n != 1 {
			t.Fatalf("expected exactly 1 deprecation warning after first request, got %d: %v", n, logger.warns)
		}
		if !strings.HasPrefix(logger.warns[0], "[Deprecation]") {
			t.Fatalf("expected warning to start with [Deprecation], got %q", logger.warns[0])
		}
		pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), evil, pnSignInBody("callbackURL", "http://any-site.com/redirect"))
		if n := logger.count(); n != 1 {
			t.Fatalf("expected warning to be logged only once, got %d", n)
		}
	})
	t.Run("disableCSRFCheck should bypass Fetch Metadata CSRF protection", func(t *testing.T) {
		env := newEnv(t, pnAdvanced(Bool(true), Bool(false)))
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), map[string]string{
			"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "origin": "https://evil.com",
		}, pnSignInBody())
		pnExpectNotStatus(t, res, 403)
	})
	t.Run("both flags disabled should bypass all checks", func(t *testing.T) {
		env := newEnv(t, pnAdvanced(Bool(true), Bool(true)))
		res := pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), evil, pnSignInBody("callbackURL", "http://malicious-site.com/steal"))
		pnExpectUser(t, res)
	})
}

func TestPortNetOriginRequestScopedIsolation(t *testing.T) {
	aReached := make(chan struct{})
	releaseA := make(chan struct{})
	env := newTestEnv(t, func(c *Config) {
		c.Advanced = pnAdvanced(Bool(false), Bool(false))
		c.TrustedOriginsFunc = func(r *http.Request) ([]string, error) {
			if r != nil && r.Header.Get("x-tenant") == "a" {
				return []string{"https://a.example"}, nil
			}
			return []string{"https://b.example"}, nil
		}
		c.Plugins = []*Plugin{{ID: "pause-tenant-a", OnRequest: func(r *http.Request, _ *AuthContext) (*http.Request, *Response, error) {
			if r.Header.Get("x-tenant") == "a" {
				close(aReached)
				<-releaseA
			}
			return nil, nil, nil
		}}}
	})
	send := func(tenant string) *testResponse {
		return pnServe(t, env, "POST", pnURL(env, "/sign-in/email"), map[string]string{
			"x-tenant": tenant, "origin": "https://b.example", "cookie": "x=1",
		}, map[string]any{"email": tenant + "@example.com", "password": "password1234"})
	}
	aDone := make(chan *testResponse, 1)
	go func() { aDone <- send("a") }()
	<-aReached
	send("b")
	close(releaseA)
	aRes := <-aDone
	pnExpectStatus(t, aRes, 403)
}

func TestPortNetOriginInferredBaseURLNotPersisted(t *testing.T) {
	var mu sync.Mutex
	var resetURLs []string
	t.Setenv("BETTER_AUTH_URL", "")
	env := newTestEnv(t, func(c *Config) {
		c.BaseURL = ""
		c.EmailAndPassword = &EmailAndPasswordConfig{Enabled: true,
			SendResetPassword: func(_ context.Context, d EmailData, _ *http.Request) error {
				mu.Lock()
				defer mu.Unlock()
				resetURLs = append(resetURLs, d.URL)
				return nil
			}}
	})
	pnCreateTestUser(t, env)
	body := map[string]any{"email": pnTestEmail, "redirectTo": "/"}
	pnServe(t, env, "POST", "https://untrusted.example/api/auth/request-password-reset", nil, body)
	pnServe(t, env, "POST", "https://app.example/api/auth/request-password-reset", nil, body)
	mu.Lock()
	defer mu.Unlock()
	if len(resetURLs) == 0 {
		t.Fatal("expected a reset URL")
	}
	legit := resetURLs[len(resetURLs)-1]
	if !strings.Contains(legit, "https://app.example") || strings.Contains(legit, "untrusted.example") {
		t.Fatalf("legit URL = %q", legit)
	}
}
