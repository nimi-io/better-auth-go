package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Ported from packages/better-auth/src/plugins/captcha/captcha.test.ts.
//
// vi.mock(betterFetch) is replaced by a mock HTTP transport (Options.HTTPClient); the
// email-otp cases use a stand-in /sign-in/email-otp endpoint (the plugin is ported
// separately, and only the path matters to captcha); Vercel's botid SDK development
// verdicts are replaced by equivalent checkBotId stubs; fake timers are replaced by a
// shortened verifyTimeout.

type fetchCall struct {
	req      *http.Request
	body     string
	deadline time.Duration
}

type mockFetch struct {
	mu    sync.Mutex
	calls []fetchCall
	// data is returned as JSON (status 200); fail makes the request fail; status != 0
	// returns an empty error response.
	data   any
	fail   error
	status int
	hang   bool
}

func (m *mockFetch) set(data any) {
	m.mu.Lock()
	m.data, m.fail, m.status, m.hang = data, nil, 0, false
	m.mu.Unlock()
}
func (m *mockFetch) setError(err error) {
	m.mu.Lock()
	m.data, m.fail, m.status = nil, err, 0
	m.mu.Unlock()
}
func (m *mockFetch) setStatus(s int) {
	m.mu.Lock()
	m.data, m.fail, m.status = nil, nil, s
	m.mu.Unlock()
}
func (m *mockFetch) clear()     { m.mu.Lock(); m.calls = nil; m.mu.Unlock() }
func (m *mockFetch) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.calls) }
func (m *mockFetch) last() fetchCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[len(m.calls)-1]
}

type rt func(*http.Request) (*http.Response, error)

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (m *mockFetch) client() *http.Client {
	return &http.Client{Transport: rt(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		var d time.Duration
		if dl, ok := r.Context().Deadline(); ok {
			d = time.Until(dl)
		}
		m.mu.Lock()
		m.calls = append(m.calls, fetchCall{req: r, body: string(b), deadline: d})
		data, fail, status, hang := m.data, m.fail, m.status, m.hang
		m.mu.Unlock()
		if hang {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		if fail != nil {
			return nil, fail
		}
		if status != 0 {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		raw, _ := json.Marshal(data)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}
}

func withMock(o Options, m *mockFetch) Options { o.HTTPClient = m.client(); return o }

func plugins(o Options, extra ...*betterauth.Plugin) []*betterauth.Plugin {
	return append([]*betterauth.Plugin{New(o)}, extra...)
}

func token(v string) http.Header { return http.Header{"X-Captcha-Response": {v}} }

func signIn(c *client, headers ...http.Header) *response {
	c.inst.t.Helper()
	return c.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"}, headers...)
}

func raw(inst *instance, method, path, body string) *response {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://localhost:3000/api/auth"+path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	inst.auth.Handler().ServeHTTP(rec, req)
	return &response{Status: rec.Code, Header: rec.Header(), Body: rec.Body.Bytes()}
}

type logEntry struct {
	level, msg string
	details    map[string]any
}

type captureLogger struct {
	mu      sync.Mutex
	entries []logEntry
}

func (l *captureLogger) add(level, msg string, args []any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := logEntry{level: level, msg: msg}
	if len(args) > 0 {
		e.details, _ = args[0].(map[string]any)
	}
	l.entries = append(l.entries, e)
}
func (l *captureLogger) Debug(m string, a ...any) { l.add("debug", m, a) }
func (l *captureLogger) Info(m string, a ...any)  { l.add("info", m, a) }
func (l *captureLogger) Warn(m string, a ...any)  { l.add("warn", m, a) }
func (l *captureLogger) Error(m string, a ...any) { l.add("error", m, a) }

func (l *captureLogger) find(level, msg string) *logEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.entries {
		if l.entries[i].level == level && l.entries[i].msg == msg {
			return &l.entries[i]
		}
	}
	return nil
}

func jsonEq(t *testing.T, got, want any) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("got %s, want %s", g, w)
	}
}

// stand-in for the email-otp sign-in endpoint.
func emailOTPStandIn() *betterauth.Plugin {
	return &betterauth.Plugin{ID: "email-otp-stand-in", Endpoints: []*betterauth.Endpoint{{
		Path: "/sign-in/email-otp", Methods: []string{"POST"}, Body: validate.Object(validate.F("email", validate.String()), validate.F("otp", validate.String())),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			return jsonx.O("token", "stand-in", "user", jsonx.O("email", ctx.BodyString("email"))), nil
		},
	}}}
}

func TestCaptcha(t *testing.T) {
	m := &mockFetch{}

	t.Run("Should ignore non-protected endpoints", func(t *testing.T) {
		inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", Endpoints: []string{"/sign-up"}}, m)), nil)
		m.set(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
		if expectOK(t, signIn(inst.client(), token("invalid-captcha-token")))["user"] == nil {
			t.Fatal("expected user")
		}
	})

	t.Run("Should return a 500 when missing secret key", func(t *testing.T) {
		inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: ""}, m)), nil)
		eq(t, signIn(inst.client(), token("invalid-captcha-token")).Status, 500)
	})

	t.Run("Should return 400 if no captcha token is found in the request headers", func(t *testing.T) {
		inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), nil)
		eq(t, signIn(inst.client()).Status, 400)
	})

	t.Run("returns JSON content type for captcha errors", func(t *testing.T) {
		inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), nil, instanceOpts{disableTestUser: true})
		res := raw(inst, "POST", "/sign-in/email", `{"email":"test@test.com","password":"test123456"}`)
		eq(t, res.Status, 400)
		eq(t, res.Header.Get("Content-Type"), "application/json")
		eq(t, string(res.Body), `{"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"}`)
	})

	t.Run("should apply rate limits before verifying captcha tokens", func(t *testing.T) {
		m.clear()
		m.set(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
		inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), func(c *betterauth.Config) {
			c.RateLimit = &betterauth.RateLimitConfig{Enabled: betterauth.Bool(true), CustomRules: map[string]betterauth.CustomRateLimitRule{
				"/sign-in/email": {Rule: &betterauth.RateLimitRule{Window: 10 * time.Second, Max: 1}}}}
		})
		c := inst.client()
		first := signIn(c, token("invalid-captcha-token"))
		second := signIn(c, token("invalid-captcha-token"))
		eq(t, first.Status, 403)
		eq(t, second.Status, 429)
		eq(t, m.count(), 1)
	})

	t.Run("Should return 500 if an unexpected error occurs", func(t *testing.T) {
		inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), nil)
		m.setError(errors.New("Failed to fetch"))
		eq(t, signIn(inst.client(), token("captcha-token")).Status, 500)
	})

	t.Run("cloudflare-turnstile", func(t *testing.T) {
		inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), nil)
		t.Run("Should successfully sign in users if they passed the CAPTCHA challenge", func(t *testing.T) {
			m.clear()
			m.set(map[string]any{"success": true, "challenge_ts": "2022-02-28T15:14:30.096Z", "hostname": "example.com", "error-codes": []string{},
				"action": "login", "cdata": "sessionid-123456789", "metadata": map[string]any{"ephemeral_id": "x:9f78e0ed210960d7693b167e"}})
			res := signIn(inst.client(), http.Header{"X-Captcha-Response": {"captcha-token"}, "X-Forwarded-For": {"127.0.0.1"}})
			if expectOK(t, res)["user"] == nil {
				t.Fatal("expected user")
			}
			call := m.last()
			eq(t, call.req.URL.String(), SiteVerifyURLs[CloudflareTurnstile])
			eq(t, call.req.Header.Get("Content-Type"), "application/json")
			eq(t, call.body, `{"secret":"xx-secret-key","response":"captcha-token","remoteip":"127.0.0.1"}`)
		})
		t.Run("Should return 500 if the call to /siteverify fails", func(t *testing.T) {
			m.setStatus(502)
			eq(t, signIn(inst.client(), token("captcha-token")).Status, 500)
		})
		t.Run("Siteverify failures", func(t *testing.T) {
			t.Run("returns a generic 403", func(t *testing.T) {
				m.set(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
				res := signIn(inst.client(), token("captcha-token"))
				expectStatus(t, res, 403, "VERIFICATION_FAILED")
				eq(t, res.Message(), "Captcha verification failed")
			})
			t.Run("logs diagnostics without sensitive response fields", func(t *testing.T) {
				log := &captureLogger{}
				inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), func(c *betterauth.Config) { c.Logger = log })
				m.set(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}, "hostname": "example.com", "action": "login",
					"cdata": "private-custom-data", "metadata": map[string]any{"ephemeral_id": "private-device-id"}})
				signIn(inst.client(), token("captcha-token"))
				e := log.find("warn", "Cloudflare Turnstile verification failed")
				if e == nil {
					t.Fatal("no warning logged")
				}
				jsonEq(t, e.details, map[string]any{"provider": "cloudflare-turnstile", "reason": "siteverify_rejected",
					"errorCodes": []string{"invalid-input-response"}, "hostname": "example.com", "action": "login"})
			})
		})
	})

	t.Run("google-recaptcha", func(t *testing.T) {
		inst := newInstance(t, plugins(withMock(Options{Provider: GoogleRecaptcha, SecretKey: "xx-secret-key"}, m)), nil)
		t.Run("Should successfully sign in users if they passed the CAPTCHA challenge", func(t *testing.T) {
			m.clear()
			m.set(map[string]any{"success": true, "challenge_ts": "2022-02-28T15:14:30.096Z", "hostname": "example.com"})
			res := signIn(inst.client(), http.Header{"X-Captcha-Response": {"captcha-token"}, "X-Forwarded-For": {"127.0.0.1"}})
			if expectOK(t, res)["user"] == nil {
				t.Fatal("expected user")
			}
			call := m.last()
			eq(t, call.req.URL.String(), SiteVerifyURLs[GoogleRecaptcha])
			eq(t, call.body, "secret=xx-secret-key&response=captcha-token&remoteip=127.0.0.1")
			q, _ := url.ParseQuery(call.body)
			eq(t, q.Get("remoteip"), "127.0.0.1")
		})
		t.Run("Should return 500 if the call to /siteverify fails", func(t *testing.T) {
			m.setStatus(500)
			eq(t, signIn(inst.client(), token("captcha-token")).Status, 500)
		})
		t.Run("Should return 403 in case of a validation failure", func(t *testing.T) {
			m.set(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
			eq(t, signIn(inst.client(), token("invalid-captcha-token")).Status, 403)
		})
		t.Run("Should return 403 in case of a too low score (ReCAPTCHA v3)", func(t *testing.T) {
			m.set(map[string]any{"success": true, "score": 0.4, "action": "yourAction", "challenge_ts": "2022-02-28T15:14:30.096Z", "hostname": "example.com"})
			eq(t, signIn(inst.client(), token("low-score-captcha-token")).Status, 403)
		})
	})

	for _, tc := range []struct{ provider, remoteKey string }{{HCaptcha, "remoteip"}, {CaptchaFox, "remoteIp"}} {
		t.Run(tc.provider, func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: tc.provider, SecretKey: "xx-secret-key", SiteKey: "xx-site-key"}, m)), nil)
			t.Run("Should successfully sign in users if they passed the CAPTCHA challenge", func(t *testing.T) {
				m.clear()
				m.set(map[string]any{"success": true, "challenge_ts": "2022-02-28T15:14:30.096Z", "hostname": "example.com"})
				res := signIn(inst.client(), http.Header{"X-Captcha-Response": {"captcha-token"}, "X-Forwarded-For": {"127.0.0.1"}})
				if expectOK(t, res)["user"] == nil {
					t.Fatal("expected user")
				}
				call := m.last()
				eq(t, call.req.URL.String(), SiteVerifyURLs[tc.provider])
				eq(t, call.req.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
				eq(t, call.body, "secret=xx-secret-key&response=captcha-token&sitekey=xx-site-key&"+tc.remoteKey+"=127.0.0.1")
			})
			t.Run("Should return 500 if the call to /siteverify fails", func(t *testing.T) {
				m.setStatus(500)
				eq(t, signIn(inst.client(), token("captcha-token")).Status, 500)
			})
			t.Run("Should return 403 in case of a validation failure", func(t *testing.T) {
				m.set(map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}})
				eq(t, signIn(inst.client(), token("invalid-captcha-token")).Status, 403)
			})
		})
	}

	t.Run("verification timeout", func(t *testing.T) {
		configs := []Options{
			{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"},
			{Provider: GoogleRecaptcha, SecretKey: "xx-secret-key"},
			{Provider: HCaptcha, SecretKey: "xx-secret-key", SiteKey: "xx-site"},
			{Provider: CaptchaFox, SecretKey: "xx-secret-key", SiteKey: "xx-site"},
		}
		for _, cfg := range configs {
			t.Run(cfg.Provider+" bounds the verification request with the shared timeout", func(t *testing.T) {
				m.clear()
				m.set(map[string]any{"success": true, "challenge_ts": "ts", "hostname": "example.com"})
				inst := newInstance(t, plugins(withMock(cfg, m)), nil)
				signIn(inst.client(), token("captcha-token"))
				d := m.last().deadline
				if d <= VerifyTimeout-time.Second || d > VerifyTimeout {
					t.Fatalf("deadline %v", d)
				}
			})
		}
		for _, cfg := range configs {
			t.Run(cfg.Provider+" fails closed when the provider call times out", func(t *testing.T) {
				verifyTimeout = 50 * time.Millisecond
				defer func() { verifyTimeout = VerifyTimeout }()
				m.set(nil)
				m.mu.Lock()
				m.hang = true
				m.mu.Unlock()
				defer m.set(nil)
				inst := newInstance(t, plugins(withMock(cfg, m)), nil)
				res := signIn(inst.client(), token("captcha-token"))
				eq(t, res.Status, 500)
				if res.Data() != nil {
					t.Fatal("expected no data")
				}
			})
		}
	})

	t.Run("exempt paths", func(t *testing.T) {
		t.Run("should not apply captcha to /sign-in/email-otp with default endpoints", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m), emailOTPStandIn()), nil)
			d := expectOK(t, inst.client().post("/sign-in/email-otp", map[string]any{"email": "test@test.com", "otp": "123456"}))
			eq(t, d["user"].(map[string]any)["email"], "test@test.com")
		})
		t.Run("should still apply captcha when /sign-in/email-otp is explicitly opted in", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", Endpoints: []string{"/sign-in/email-otp"}}, m), emailOTPStandIn()), nil)
			expectStatus(t, inst.client().post("/sign-in/email-otp", map[string]any{"email": "test@test.com", "otp": "000000"}), 400, "MISSING_RESPONSE")
		})
		t.Run("should still apply captcha when a protected pathname contains duplicate slashes", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), nil)
			expectStatus(t, raw(inst, "POST", "/sign-in//email", `{"email":"test@test.com","password":"test123456"}`), 400, "MISSING_RESPONSE")
		})
		t.Run("should still apply captcha when a protected pathname has a trailing slash", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), nil)
			expectStatus(t, raw(inst, "POST", "/sign-in/email/", `{"email":"test@test.com","password":"test123456"}`), 400, "MISSING_RESPONSE")
		})
		t.Run("should not treat partial endpoint paths as matches", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", Endpoints: []string{"/sign-in"}}, m)), nil)
			eq(t, expectOK(t, signIn(inst.client()))["user"].(map[string]any)["email"], "test@test.com")
		})
		t.Run("should not apply captcha to sub-routes of default protected endpoints", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key"}, m)), nil)
			if raw(inst, "POST", "/sign-in/email/extra-segment", `{}`).Status == 400 {
				t.Fatal("unexpected 400")
			}
		})
	})

	t.Run("wildcard endpoints", func(t *testing.T) {
		t.Run("should apply captcha to single-segment wildcard matches", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", Endpoints: []string{"/sign-in/*"}}, m)), nil)
			expectStatus(t, raw(inst, "POST", "/sign-in/email-otp", `{}`), 400, "MISSING_RESPONSE")
		})
		t.Run("should not match nested routes with a single-segment wildcard", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", Endpoints: []string{"/sign-in/*"}}, m)), nil)
			if raw(inst, "POST", "/sign-in/social/google", `{}`).Status == 400 {
				t.Fatal("unexpected 400")
			}
		})
		t.Run("should apply captcha to nested routes with a multi-segment wildcard", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", Endpoints: []string{"/sign-in/**"}}, m)), nil)
			expectStatus(t, raw(inst, "POST", "/sign-in/social/google", `{}`), 400, "MISSING_RESPONSE")
		})
	})

	t.Run("vercel-botid", func(t *testing.T) {
		for _, path := range []string{"/sign-up/email", "/sign-in/email", "/request-password-reset"} {
			t.Run("rejects bots on "+path+" without a captcha token or secret key", func(t *testing.T) {
				calls := 0
				inst := newInstance(t, plugins(Options{Provider: VercelBotID, CheckBotID: func(context.Context) (BotIDVerification, error) {
					calls++
					return BotIDVerification{IsBot: true}, nil
				}}), nil)
				expectStatus(t, raw(inst, "POST", path, ""), 403, "VERIFICATION_FAILED")
				eq(t, calls, 1)
			})
		}
		// The botid SDK's development "BAD-BOT" / "HUMAN" bypass verdicts.
		t.Run("rejects the SDK's development BAD-BOT verdict", func(t *testing.T) {
			inst := newInstance(t, plugins(Options{Provider: VercelBotID, CheckBotID: func(context.Context) (BotIDVerification, error) {
				return BotIDVerification{IsBot: true}, nil
			}}), nil)
			expectStatus(t, raw(inst, "POST", "/sign-in/email", ""), 403, "VERIFICATION_FAILED")
		})
		t.Run("allows the SDK's development HUMAN verdict without a captcha token", func(t *testing.T) {
			calls := 0
			inst := newInstance(t, plugins(Options{Provider: VercelBotID, CheckBotID: func(context.Context) (BotIDVerification, error) {
				calls++
				return BotIDVerification{IsBot: false}, nil
			}}), nil)
			if expectOK(t, signIn(inst.client()))["user"] == nil {
				t.Fatal("expected user")
			}
			eq(t, calls, 1)
		})
		t.Run("allows a verified bot when custom validation opts in", func(t *testing.T) {
			inst := newInstance(t, plugins(Options{Provider: VercelBotID,
				CheckBotID: func(context.Context) (BotIDVerification, error) {
					return BotIDVerification{IsBot: true, IsVerifiedBot: true, VerifiedBotName: "trusted-agent"}, nil
				},
				ValidateRequest: func(_ context.Context, c ValidateRequestContext) (bool, error) {
					return c.Verification.IsVerifiedBot && c.Verification.VerifiedBotName == "trusted-agent", nil
				}}), nil)
			expectOK(t, signIn(inst.client()))
		})
		t.Run("rejects a human when custom validation rejects the request", func(t *testing.T) {
			inst := newInstance(t, plugins(Options{Provider: VercelBotID,
				CheckBotID:      func(context.Context) (BotIDVerification, error) { return BotIDVerification{}, nil },
				ValidateRequest: func(context.Context, ValidateRequestContext) (bool, error) { return false, nil }}), nil)
			eq(t, signIn(inst.client()).Status, 403)
		})
		t.Run("returns a generic 500 when the check fails", func(t *testing.T) {
			inst := newInstance(t, plugins(Options{Provider: VercelBotID, CheckBotID: func(context.Context) (BotIDVerification, error) {
				return BotIDVerification{}, errors.New("private BotID failure")
			}}), nil)
			res := signIn(inst.client())
			expectStatus(t, res, 500, "UNKNOWN_ERROR")
			eq(t, res.Message(), "Something went wrong")
		})
		t.Run("does not check routes outside the protected endpoints", func(t *testing.T) {
			calls := 0
			inst := newInstance(t, plugins(Options{Provider: VercelBotID, CheckBotID: func(context.Context) (BotIDVerification, error) {
				calls++
				return BotIDVerification{IsBot: true}, nil
			}}), nil)
			eq(t, raw(inst, "GET", "/ok", "").Status, 200)
			eq(t, calls, 0)
		})
		t.Run("fails closed when the check never resolves", func(t *testing.T) {
			verifyTimeout = 50 * time.Millisecond
			defer func() { verifyTimeout = VerifyTimeout }()
			p := &plugin{opts: Options{Provider: VercelBotID, CheckBotID: func(ctx context.Context) (BotIDVerification, error) {
				select {}
			}}}
			start := time.Now()
			_, err := p.vercelBotID(httptest.NewRequest("POST", "http://localhost/sign-in/email", nil))
			if err == nil || !strings.Contains(err.Error(), "CAPTCHA service unavailable") {
				t.Fatalf("err %v", err)
			}
			if time.Since(start) < 50*time.Millisecond {
				t.Fatal("settled before the timeout")
			}
		})
		t.Run("fails closed when custom validation never resolves", func(t *testing.T) {
			verifyTimeout = 50 * time.Millisecond
			defer func() { verifyTimeout = VerifyTimeout }()
			p := &plugin{opts: Options{Provider: VercelBotID,
				CheckBotID:      func(context.Context) (BotIDVerification, error) { return BotIDVerification{}, nil },
				ValidateRequest: func(context.Context, ValidateRequestContext) (bool, error) { select {} }}}
			start := time.Now()
			_, err := p.vercelBotID(httptest.NewRequest("POST", "http://localhost/sign-in/email", nil))
			if err == nil || !strings.Contains(err.Error(), "CAPTCHA service unavailable") {
				t.Fatalf("err %v", err)
			}
			if time.Since(start) < 50*time.Millisecond {
				t.Fatal("settled before the timeout")
			}
		})
	})

	t.Run("action and hostname binding", func(t *testing.T) {
		t.Run("rejects a Turnstile token whose action does not match expectedAction", func(t *testing.T) {
			log := &captureLogger{}
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", ExpectedAction: "login"}, m)), func(c *betterauth.Config) { c.Logger = log })
			m.set(map[string]any{"success": true, "action": "signup", "hostname": "myapp.com"})
			eq(t, signIn(inst.client(), token("token")).Status, 403)
			e := log.find("warn", "Cloudflare Turnstile verification failed")
			if e == nil {
				t.Fatal("no warning")
			}
			jsonEq(t, e.details, map[string]any{"provider": "cloudflare-turnstile", "reason": "action_mismatch", "expectedAction": "login", "actualAction": "signup"})
		})
		t.Run("rejects a Turnstile token from a hostname outside allowedHostnames", func(t *testing.T) {
			log := &captureLogger{}
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", AllowedHostnames: []string{"myapp.com"}}, m)), func(c *betterauth.Config) { c.Logger = log })
			m.set(map[string]any{"success": true, "hostname": "untrusted.example"})
			eq(t, signIn(inst.client(), token("token")).Status, 403)
			e := log.find("warn", "Cloudflare Turnstile verification failed")
			if e == nil {
				t.Fatal("no warning")
			}
			jsonEq(t, e.details, map[string]any{"provider": "cloudflare-turnstile", "reason": "hostname_mismatch", "allowedHostnames": []string{"myapp.com"}, "actualHostname": "untrusted.example"})
		})
		t.Run("rejects a reCAPTCHA v3 token whose action does not match expectedAction", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: GoogleRecaptcha, SecretKey: "xx-secret-key", ExpectedAction: "login"}, m)), nil)
			m.set(map[string]any{"success": true, "score": 0.9, "action": "signup", "hostname": "myapp.com", "challenge_ts": "2022-02-28T15:14:30.096Z"})
			eq(t, signIn(inst.client(), token("token")).Status, 403)
		})
		t.Run("accepts a token when action and hostname match", func(t *testing.T) {
			inst := newInstance(t, plugins(withMock(Options{Provider: CloudflareTurnstile, SecretKey: "xx-secret-key", ExpectedAction: "login", AllowedHostnames: []string{"myapp.com"}}, m)), nil)
			m.set(map[string]any{"success": true, "action": "login", "hostname": "myapp.com"})
			if signIn(inst.client(), token("token")).Status == 403 {
				t.Fatal("unexpected 403")
			}
		})
	})
}

func TestWildcard(t *testing.T) {
	for _, tc := range []struct {
		pattern, sample string
		want            bool
	}{
		{"/sign-in/*", "/sign-in/email", true},
		{"/sign-in/*", "/sign-in/social/google", false},
		{"/sign-in/**", "/sign-in/social/google", true},
		{"/sign-in/**", "/sign-in", true},
		{"/a/*/c", "/a/b/c", true},
		{"/a/?", "/a/bb", false},
	} {
		if got := wildcardRegexp(tc.pattern).MatchString(tc.sample); got != tc.want {
			t.Errorf("%s ~ %s = %v, want %v (%s)", tc.pattern, tc.sample, got, tc.want, transform(tc.pattern))
		}
	}
	eq(t, formEncode("a b", "x*~é"), fmt.Sprintf("a+b=x*%%7E%%C3%%A9"))
}
