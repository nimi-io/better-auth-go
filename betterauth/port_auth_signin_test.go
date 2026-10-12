package betterauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nimi-io/better-auth-go/db"
)

// Port of better-auth/src/api/routes/sign-in.test.ts

// describe("sign-in")
func TestPortAuthSignIn(t *testing.T) {
	env := paNewEnv(t, nil)

	t.Run("should return a response with a set-cookie header", func(t *testing.T) {
		_, res := env.mustCall("signInEmail", map[string]any{"email": env.testUser.Email, "password": env.testUser.Password}, nil)
		if _, _, ok := paSetCookie(res.Headers, "better-auth.session_token"); !ok {
			t.Fatalf("expected better-auth.session_token set-cookie, got %v", res.Headers.Values("Set-Cookie"))
		}
	})

	t.Run("should read the ip address and user agent from the headers", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Forwarded-For", "127.0.0.1")
		h.Set("User-Agent", "Test")
		_, res := env.mustCall("signInEmail", map[string]any{"email": env.testUser.Email, "password": env.testUser.Password}, h)
		tok, _, ok := paSetCookie(res.Headers, "better-auth.session_token")
		if !ok {
			t.Fatalf("no session cookie")
		}
		h.Set("Cookie", "better-auth.session_token="+tok)
		s, err := env.auth.API.GetSession(context.Background(), h)
		if err != nil || s == nil {
			t.Fatalf("no session: %v", err)
		}
		if s.Session.IPAddress == nil || *s.Session.IPAddress != "127.0.0.1" {
			t.Fatalf("ipAddress = %v", s.Session.IPAddress)
		}
		if s.Session.UserAgent == nil || *s.Session.UserAgent != "Test" {
			t.Fatalf("userAgent = %v", s.Session.UserAgent)
		}
	})

	verificationCase := func(t *testing.T, sendOnSignIn bool, wantAfter int) {
		m := &paMock{}
		env := paNewEnv(t, func(c *Config) {
			c.EmailVerification = &EmailVerificationConfig{SendOnSignIn: sendOnSignIn, SendVerificationEmail: func(_ context.Context, d EmailData, r *http.Request) error {
				m.record(d, r)
				return nil
			}}
			c.EmailAndPassword.RequireEmailVerification = true
		})
		if m.count() != 1 {
			t.Fatalf("sendVerificationEmail called %d times after sign-up, want 1", m.count())
		}
		_, apiErr := env.call("signInEmail", map[string]any{"email": env.testUser.Email, "password": env.testUser.Password}, nil)
		if apiErr == nil || apiErr.StatusCode != 403 || apiErr.Code() != ErrEmailNotVerified.Code || apiErr.Message() != ErrEmailNotVerified.Message {
			t.Fatalf("expected FORBIDDEN EMAIL_NOT_VERIFIED, got %s", paFormatErr(apiErr))
		}
		if m.count() != wantAfter {
			t.Fatalf("sendVerificationEmail called %d times, want %d", m.count(), wantAfter)
		}
	}

	t.Run("verification email will be sent if sendOnSignIn is enabled", func(t *testing.T) {
		verificationCase(t, true, 2)
	})

	t.Run("verification email will not be sent if sendOnSignIn is disabled", func(t *testing.T) {
		verificationCase(t, false, 1)
	})

	t.Run("logs expected auth validation failures below error level", func(t *testing.T) {
		log := &paRecLogger{}
		env := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(context.Context, EmailData, *http.Request) error { return nil }
			c.Logger = log
		})
		expectWarnWithoutError := func(msg string) {
			t.Helper()
			found := false
			for _, e := range log.snapshot() {
				if e.level == "warn" && strings.Contains(e.msg, msg) {
					found = true
				}
				if e.level == "error" {
					t.Errorf("unexpected error-level log: %q", e.msg)
				}
			}
			if !found {
				t.Errorf("expected a warn log containing %q, got %+v", msg, log.snapshot())
			}
		}

		log.clear()
		_, apiErr := env.call("signInEmail", map[string]any{"email": env.testUser.Email, "password": "wrong-password"}, nil)
		if apiErr == nil || apiErr.StatusCode != 401 || apiErr.Code() != ErrInvalidEmailOrPassword.Code {
			t.Fatalf("expected UNAUTHORIZED INVALID_EMAIL_OR_PASSWORD, got %s", paFormatErr(apiErr))
		}
		expectWarnWithoutError("Invalid password")

		log.clear()
		_, apiErr = env.call("signInEmail", map[string]any{"email": "missing-sign-in@test.com", "password": "password"}, nil)
		if apiErr == nil || apiErr.StatusCode != 401 || apiErr.Code() != ErrInvalidEmailOrPassword.Code {
			t.Fatalf("expected UNAUTHORIZED INVALID_EMAIL_OR_PASSWORD, got %s", paFormatErr(apiErr))
		}
		expectWarnWithoutError("User not found")

		log.clear()
		_, apiErr = env.call("signUpEmail", map[string]any{"email": "short-password@test.com", "password": "short", "name": "Short Password"}, nil)
		if apiErr == nil || apiErr.StatusCode != 400 || apiErr.Code() != ErrPasswordTooShort.Code {
			t.Fatalf("expected BAD_REQUEST PASSWORD_TOO_SHORT, got %s", paFormatErr(apiErr))
		}
		expectWarnWithoutError("Password is too short")

		log.clear()
		res, _ := env.mustCall("requestPasswordReset", map[string]any{"email": "reset-missing@test.com"}, nil)
		if res["status"] != true {
			t.Fatalf("status = %v", res["status"])
		}
		expectWarnWithoutError("Reset Password: User not found")
	})
}

// describe("url checks")
func TestPortAuthSignInURLChecks(t *testing.T) {
	t.Run("should reject untrusted origins", func(t *testing.T) {
		t.Skip("phase 2: requires /sign-in/social and the google social provider")
	})
}

// describe("sign-in CSRF protection")
func TestPortAuthSignInCSRFProtection(t *testing.T) {
	env := paCSRFEnv(t, false)
	creds := map[string]any{"email": env.testUser.Email, "password": env.testUser.Password}

	t.Run("should block cross-site navigation login attempts (no cookies)", func(t *testing.T) {
		res := env.do("POST", "/sign-in/email", map[string]any{"email": "attacker@evil.com", "password": "password123"}, map[string]string{
			"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "https://evil.com",
		})
		if res.Status != 403 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if m := res.JSON(t); m["message"] != ErrCrossSiteNavigationLoginBlocked.Message {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should allow same-origin navigation login attempts", func(t *testing.T) {
		res := env.do("POST", "/sign-in/email", creds, map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "http://localhost:3000",
		})
		if res.Status == 403 {
			t.Fatalf("status = 403: %s", res.Body)
		}
	})

	t.Run("should allow fetch/XHR requests (cors mode)", func(t *testing.T) {
		res := env.do("POST", "/sign-in/email", creds, map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Origin": "http://localhost:3000",
		})
		if res.Status == 403 {
			t.Fatalf("status = 403: %s", res.Body)
		}
	})

	t.Run("should use origin validation when cookies exist", func(t *testing.T) {
		res := env.do("POST", "/sign-in/email", creds, map[string]string{
			"Cookie": "some_cookie=value", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Origin": "http://localhost:3000",
		})
		if res.Status == 403 {
			t.Fatalf("status = 403: %s", res.Body)
		}
	})
}

// describe("sign-in with additionalFields")
func TestPortAuthSignInWithAdditionalFields(t *testing.T) {
	env := paNewEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			paStrField("newField"),
			{Name: "isAdmin", Type: db.TypeBoolean, DefaultValue: true, Input: Bool(false)},
		}}}
	}, paInstanceOpts{disableTestUser: true})

	t.Run("should return additionalFields in signInEmail response", func(t *testing.T) {
		env.mustCall("signUpEmail", map[string]any{"email": "signin-additional@test.com", "password": "password", "name": "SignIn Test", "newField": "signin-value"}, nil)
		res, _ := env.mustCall("signInEmail", map[string]any{"email": "signin-additional@test.com", "password": "password"}, nil)
		u, ok := res["user"].(map[string]any)
		if !ok {
			t.Fatalf("user should be defined")
		}
		if u["newField"] != "signin-value" {
			t.Fatalf("newField = %v", u["newField"])
		}
		if u["isAdmin"] != true {
			t.Fatalf("isAdmin = %v", u["isAdmin"])
		}
	})
}

// describe("sign-in with form data")
func TestPortAuthSignInWithFormData(t *testing.T) {
	env := paNewEnv(t, func(c *Config) {
		c.TrustedOrigins = []string{"http://localhost:3000"}
		c.Advanced = &AdvancedConfig{DisableCSRFCheck: Bool(false), DisableOriginCheck: Bool(false)}
	})
	form := func(u paUser) url.Values { return url.Values{"email": {u.Email}, "password": {u.Password}} }
	// createFormRequest
	formRequest := func(e *paEnv, target string, headers map[string]string, u paUser) *paResponse {
		h := map[string]string{
			"Cookie":         "better-auth.session_token=expired",
			"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Dest": "document",
		}
		for k, v := range headers {
			h[k] = v
		}
		return e.do("POST", target, form(u), h)
	}
	expectErr := func(t *testing.T, res *paResponse, code ErrorCode) {
		t.Helper()
		if res.Status != 403 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		if m["code"] != code.Code || m["message"] != code.Message {
			t.Fatalf("expected %s %q, got %s", code.Code, code.Message, res.Body)
		}
	}

	t.Run("should accept form-urlencoded content type", func(t *testing.T) {
		res := env.do("POST", "http://localhost:3000/api/auth/sign-in/email", form(env.testUser), map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "http://localhost:3000",
		})
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		if _, ok := m["token"]; !ok {
			t.Fatalf("token should be defined")
		}
		if m["user"].(map[string]any)["email"] != env.testUser.Email {
			t.Fatalf("user = %v", m["user"])
		}
	})

	t.Run("accepts a null Origin when Fetch Metadata confirms a trusted target", func(t *testing.T) {
		res := formRequest(env, "http://localhost:3000/api/auth/sign-in/email", map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}, env.testUser)
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		if _, ok := m["token"].(string); !ok {
			t.Fatalf("token should be a string: %v", m["token"])
		}
		if m["user"].(map[string]any)["email"] != env.testUser.Email {
			t.Fatalf("user = %v", m["user"])
		}
	})

	t.Run("accepts a null Origin through a trusted reverse proxy", func(t *testing.T) {
		proxy := paNewEnv(t, func(c *Config) {
			c.TrustedOrigins = []string{"https://app.example.com"}
			c.Advanced = &AdvancedConfig{DisableCSRFCheck: Bool(false), DisableOriginCheck: Bool(false), TrustedProxyHeaders: true}
		})
		res := formRequest(proxy, "http://internal:3000/api/auth/sign-in/email", map[string]string{
			"Origin": "null", "Sec-Fetch-Site": "same-origin", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Proto": "https",
		}, proxy.testUser)
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		if _, ok := m["token"].(string); !ok {
			t.Fatalf("token should be a string: %v", m["token"])
		}
		if m["user"].(map[string]any)["email"] != proxy.testUser.Email {
			t.Fatalf("user = %v", m["user"])
		}
	})

	t.Run("ignores forwarded origins when proxy headers are not trusted", func(t *testing.T) {
		res := formRequest(env, "https://untrusted.example/api/auth/sign-in/email", map[string]string{
			"Origin": "null", "Sec-Fetch-Site": "same-origin", "X-Forwarded-Host": "localhost:3000", "X-Forwarded-Proto": "http",
		}, env.testUser)
		expectErr(t, res, ErrInvalidOrigin)
	})

	t.Run("rejects a null Origin when the same-origin target is not trusted", func(t *testing.T) {
		res := formRequest(env, "https://untrusted.example/api/auth/sign-in/email", map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}, env.testUser)
		expectErr(t, res, ErrInvalidOrigin)
	})

	for _, site := range []string{"cross-site", "same-site"} {
		t.Run("rejects a null Origin for a "+site+" form submission", func(t *testing.T) {
			res := formRequest(env, "http://localhost:3000/api/auth/sign-in/email", map[string]string{"Origin": "null", "Sec-Fetch-Site": site}, env.testUser)
			expectErr(t, res, ErrMissingOrNullOrigin)
		})
	}

	t.Run("rejects a null Origin without Fetch Metadata", func(t *testing.T) {
		res := formRequest(env, "http://localhost:3000/api/auth/sign-in/email", map[string]string{"Origin": "null"}, env.testUser)
		expectErr(t, res, ErrMissingOrNullOrigin)
	})

	t.Run("rejects a missing Origin even when Fetch Metadata says same-origin", func(t *testing.T) {
		res := formRequest(env, "http://localhost:3000/api/auth/sign-in/email", map[string]string{"Sec-Fetch-Site": "same-origin"}, env.testUser)
		expectErr(t, res, ErrMissingOrNullOrigin)
	})

	t.Run("should block cross-site form submissions", func(t *testing.T) {
		res := env.do("POST", "http://localhost:3000/api/auth/sign-in/email", url.Values{"email": {"attacker@evil.com"}, "password": {"password123"}}, map[string]string{
			"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "https://evil.com",
		})
		if res.Status != 403 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if m := res.JSON(t); m["message"] != ErrCrossSiteNavigationLoginBlocked.Message {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should allow same-site form submissions from trusted origins", func(t *testing.T) {
		res := env.do("POST", "http://localhost:3000/api/auth/sign-in/email", form(env.testUser), map[string]string{
			"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "http://localhost:3000",
		})
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
	})
}

// describe("email case insensitivity")
func TestPortAuthSignInEmailCaseInsensitivity(t *testing.T) {
	t.Run("should sign in with different email casing than sign-up", func(t *testing.T) {
		env := paNewEnv(t, nil)
		mixed := "Test.User@Example.COM"
		pw := "securePassword123"
		env.mustCall("signUpEmail", map[string]any{"email": mixed, "password": pw, "name": "Test User"}, nil)
		for _, e := range []string{strings.ToLower(mixed), strings.ToUpper(mixed), mixed} {
			res, _ := env.mustCall("signInEmail", map[string]any{"email": e, "password": pw}, nil)
			u, ok := res["user"].(map[string]any)
			if !ok || u["email"] != strings.ToLower(mixed) {
				t.Fatalf("sign-in with %q: user = %v", e, res["user"])
			}
		}
	})

	t.Run("should store email as lowercase regardless of input casing", func(t *testing.T) {
		env := paNewEnv(t, nil)
		mixed := "Another.User@DOMAIN.com"
		res, _ := env.mustCall("signUpEmail", map[string]any{"email": mixed, "password": "password123", "name": "Another User"}, nil)
		if res["user"].(map[string]any)["email"] != strings.ToLower(mixed) {
			t.Fatalf("email = %v", res["user"])
		}
	})

	t.Run("should not allow duplicate sign-ups with different email casing", func(t *testing.T) {
		env := paNewEnv(t, nil)
		email := "duplicate.test@example.com"
		env.mustCall("signUpEmail", map[string]any{"email": strings.ToLower(email), "password": "password123", "name": "First User"}, nil)
		if _, apiErr := env.call("signUpEmail", map[string]any{"email": strings.ToUpper(email), "password": "password123", "name": "Second User"}, nil); apiErr == nil {
			t.Fatalf("expected duplicate sign-up to fail")
		}
	})
}

// paCountingPassword is the hash/verify pair used by the "password length" suites.
type paCountingPassword struct {
	hashCalls, verifyCalls atomic.Int32
}

func (p *paCountingPassword) config() *PasswordConfig {
	return &PasswordConfig{
		Hash: func(pw string) (string, error) {
			p.hashCalls.Add(1)
			return "hashed:" + pw, nil
		},
		Verify: func(h, pw string) (bool, error) {
			p.verifyCalls.Add(1)
			return h == "hashed:"+pw, nil
		},
	}
}

func (p *paCountingPassword) clear() {
	p.hashCalls.Store(0)
	p.verifyCalls.Store(0)
}

// describe("sign-in password length")
func TestPortAuthSignInPasswordLength(t *testing.T) {
	pw := &paCountingPassword{}
	env := paNewEnv(t, func(c *Config) { c.EmailAndPassword.Password = pw.config() })

	for _, tc := range []struct{ name, email string }{
		{"should reject a password longer than maxPasswordLength before hashing", env.testUser.Email},
		{"should reject the same length for an unknown email", "unknown-long-password@test.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pw.clear()
			_, apiErr := env.call("signInEmail", map[string]any{"email": tc.email, "password": strings.Repeat("x", 129)}, nil)
			if apiErr == nil || apiErr.Status != "BAD_REQUEST" || apiErr.Code() != "PASSWORD_TOO_LONG" {
				t.Fatalf("expected BAD_REQUEST PASSWORD_TOO_LONG, got %s", paFormatErr(apiErr))
			}
			if pw.hashCalls.Load() != 0 || pw.verifyCalls.Load() != 0 {
				t.Fatalf("hash/verify should not be called (hash=%d verify=%d)", pw.hashCalls.Load(), pw.verifyCalls.Load())
			}
		})
	}
}
