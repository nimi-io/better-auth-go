package haveibeenpwned

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/phonenumber"
	"github.com/nimi-io/better-auth-go/validate"
)

// Ported from packages/better-auth/src/plugins/haveibeenpwned/haveibeenpwned.test.ts.
//
// The upstream suite calls the live API for "123456789" and spies on globalThis.fetch
// elsewhere; here every test uses a mock transport (pwnedAPI) that reports a configurable
// set of breached passwords. The email-otp and admin cases use stand-in endpoints mounted
// on the same paths (those plugins are ported separately): the check is keyed on the
// endpoint path, which is what these cases exercise.

func sha1Upper(pw string) string {
	s := sha1.Sum([]byte(pw))
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func textResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader(body))}
}

// pwnedAPI emulates api.pwnedpasswords.com for a set of breached passwords.
type pwnedAPI struct {
	mu       sync.Mutex
	breached map[string]bool
	requests []*http.Request
}

func newPwnedAPI(breached ...string) *pwnedAPI {
	p := &pwnedAPI{breached: map[string]bool{}}
	for _, b := range breached {
		p.breach(b)
	}
	return p
}

func (p *pwnedAPI) breach(pw string) { p.mu.Lock(); p.breached[sha1Upper(pw)] = true; p.mu.Unlock() }

func (p *pwnedAPI) client() *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.requests = append(p.requests, r)
		if !strings.HasPrefix(r.URL.String(), RangeURL) {
			return nil, errors.New("unexpected url " + r.URL.String())
		}
		prefix := strings.TrimPrefix(r.URL.String(), RangeURL)
		var b strings.Builder
		for h := range p.breached {
			if strings.HasPrefix(h, prefix) {
				fmt.Fprintf(&b, "%s:42\n", h[5:])
			}
		}
		b.WriteString("00000000000000000000000000000000000:0\n")
		return textResponse(200, b.String()), nil
	})}
}

func stamp() string { return fmt.Sprint(time.Now().UnixNano()) }

// passwordEndpoint is a stand-in for another plugin's endpoint that hashes a password.
func passwordEndpoint(path string) *betterauth.Plugin {
	return &betterauth.Plugin{ID: "stand-in" + path, Endpoints: []*betterauth.Endpoint{{
		Path: path, Methods: []string{"POST"}, Body: validate.Object(validate.F("password", validate.String())),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if _, err := ctx.Auth.Password.Hash(ctx.BodyString("password")); err != nil {
				return nil, err
			}
			return map[string]any{"status": true}, nil
		},
	}}}
}

func TestHaveIBeenPwned(t *testing.T) {
	api := newPwnedAPI("123456789")
	inst := newInstance(t, []*betterauth.Plugin{New(Options{HTTPClient: api.client()})}, nil, instanceOpts{disableTestUser: true})
	ia := inst.auth.Context().InternalAdapter

	t.Run("should prevent account creation with compromised password", func(t *testing.T) {
		email := "test-" + stamp() + "@example.com"
		res := inst.client().post("/sign-up/email", map[string]any{"email": email, "password": "123456789", "name": "Test User"})
		u, err := ia.FindUserByEmail(context.Background(), email, false)
		if err != nil || u != nil {
			t.Fatalf("user should not exist: %v", err)
		}
		expectStatus(t, res, 400, "PASSWORD_COMPROMISED")
		eq(t, res.Message(), ErrPasswordCompromised.Message)
		r := api.requests[len(api.requests)-1]
		eq(t, r.Header.Get("Add-Padding"), "true")
		eq(t, r.Header.Get("User-Agent"), "BetterAuth Password Checker")
		eq(t, r.URL.String(), RangeURL+sha1Upper("123456789")[:5])
	})

	t.Run("should allow account creation with strong, uncompromised password", func(t *testing.T) {
		res := inst.client().post("/sign-up/email", map[string]any{"email": "test-" + stamp() + "@example.com", "password": "Str0ng!P@ssw0rd-" + stamp(), "name": "Test User"})
		if expectOK(t, res)["user"] == nil {
			t.Fatal("expected user")
		}
	})

	t.Run("should prevent password update to compromised password", func(t *testing.T) {
		c := inst.client()
		initial := "Str0ng!P@ssw0rd-" + stamp()
		c.post("/sign-up/email", map[string]any{"email": "test-" + stamp() + "@example.com", "password": initial, "name": "Test User"})
		res := c.post("/change-password", map[string]any{"currentPassword": initial, "newPassword": "123456789"})
		eq(t, res.Status, 400)
	})

	t.Run("when enabled is false", func(t *testing.T) {
		disabled := newInstance(t, []*betterauth.Plugin{New(Options{Enabled: betterauth.Bool(false), HTTPClient: api.client()})}, nil, instanceOpts{disableTestUser: true})
		t.Run("should allow account creation with compromised password", func(t *testing.T) {
			res := disabled.client().post("/sign-up/email", map[string]any{"email": "test-" + stamp() + "@example.com", "password": "123456789", "name": "Test User"})
			if expectOK(t, res)["user"] == nil {
				t.Fatal("expected user")
			}
		})
	})

	t.Run("reset password with email OTP", func(t *testing.T) {
		api := newPwnedAPI()
		inst := newInstance(t, []*betterauth.Plugin{New(Options{HTTPClient: api.client()}), passwordEndpoint("/email-otp/reset-password")}, nil, instanceOpts{disableTestUser: true})
		t.Run("should reject a compromised password on /email-otp/reset-password", func(t *testing.T) {
			api.breach("breached-via-email-otp")
			res := inst.client().post("/email-otp/reset-password", map[string]any{"password": "breached-via-email-otp"})
			expectStatus(t, res, 400, "PASSWORD_COMPROMISED")
		})
	})

	t.Run("reset password with phone number OTP", func(t *testing.T) {
		api := newPwnedAPI()
		var mu sync.Mutex
		var signUpOTP, resetOTP string
		inst := newInstance(t, []*betterauth.Plugin{New(Options{HTTPClient: api.client()}), phonenumber.New(phonenumber.Options{
			SendOTP: func(d phonenumber.OTPData, _ *betterauth.EndpointContext) error {
				mu.Lock()
				signUpOTP = d.Code
				mu.Unlock()
				return nil
			},
			SendPasswordResetOTP: func(d phonenumber.OTPData, _ *betterauth.EndpointContext) error {
				mu.Lock()
				resetOTP = d.Code
				mu.Unlock()
				return nil
			},
			SignUpOnVerification: &phonenumber.SignUpOnVerification{GetTempEmail: func(p string) string { return "temp-" + p + "@example.com" }},
		})}, nil, instanceOpts{disableTestUser: true})
		t.Run("should reject a compromised password on /phone-number/reset-password", func(t *testing.T) {
			c := inst.client()
			phone := "+1555" + stamp()[len(stamp())-7:]
			c.post("/phone-number/send-otp", map[string]any{"phoneNumber": phone})
			c.post("/phone-number/verify", map[string]any{"phoneNumber": phone, "code": signUpOTP})
			c.post("/phone-number/request-password-reset", map[string]any{"phoneNumber": phone})
			api.breach("breached-via-phone-otp")
			res := c.post("/phone-number/reset-password", map[string]any{"phoneNumber": phone, "otp": resetOTP, "newPassword": "breached-via-phone-otp"})
			expectStatus(t, res, 400, "PASSWORD_COMPROMISED")
		})
	})

	t.Run("admin password endpoints", func(t *testing.T) {
		api := newPwnedAPI()
		inst := newInstance(t, []*betterauth.Plugin{New(Options{HTTPClient: api.client()}),
			passwordEndpoint("/admin/create-user"), passwordEndpoint("/admin/set-user-password")}, nil, instanceOpts{disableTestUser: true})
		t.Run("should reject a compromised password on /admin/create-user", func(t *testing.T) {
			api.breach("breached-via-admin-create")
			expectStatus(t, inst.client().post("/admin/create-user", map[string]any{"password": "breached-via-admin-create"}), 400, "PASSWORD_COMPROMISED")
		})
		t.Run("should reject a compromised password on /admin/set-user-password", func(t *testing.T) {
			expectOK(t, inst.client().post("/admin/create-user", map[string]any{"password": "Str0ng!P@ssw0rd-" + stamp()}))
			api.breach("breached-via-admin-set")
			expectStatus(t, inst.client().post("/admin/set-user-password", map[string]any{"password": "breached-via-admin-set"}), 400, "PASSWORD_COMPROMISED")
		})
	})

	t.Run("custom message and custom paths", func(t *testing.T) {
		api := newPwnedAPI("123456789")
		inst := newInstance(t, []*betterauth.Plugin{New(Options{HTTPClient: api.client(), Paths: []string{"/custom"},
			CustomPasswordCompromisedMessage: "pick another"}), passwordEndpoint("/custom")}, nil, instanceOpts{disableTestUser: true})
		res := inst.client().post("/custom", map[string]any{"password": "123456789"})
		expectStatus(t, res, 400, "PASSWORD_COMPROMISED")
		eq(t, res.Message(), "pick another")
		// /sign-up/email is no longer checked
		expectOK(t, inst.client().post("/sign-up/email", map[string]any{"email": "x-" + stamp() + "@example.com", "password": "123456789", "name": "X"}))
	})
}

func mockClient(f func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{Transport: roundTrip(f)}
}

func expectAPIError(t *testing.T, err error, msg string) {
	t.Helper()
	e, ok := betterauth.AsAPIError(err)
	if !ok || e.Status != "INTERNAL_SERVER_ERROR" || e.Message() != msg {
		t.Fatalf("expected INTERNAL_SERVER_ERROR %q, got %v", msg, err)
	}
}

func TestIsPasswordCompromised(t *testing.T) {
	ctx := context.Background()
	t.Run("should report a compromised password", func(t *testing.T) {
		ok, err := isPasswordCompromised(ctx, newPwnedAPI("breached-password").client(), "breached-password")
		if err != nil || !ok {
			t.Fatalf("%v %v", ok, err)
		}
	})
	t.Run("should report a safe password", func(t *testing.T) {
		c := mockClient(func(*http.Request) (*http.Response, error) {
			return textResponse(200, "00000000000000000000000000000000000:1\n"), nil
		})
		ok, err := isPasswordCompromised(ctx, c, "unique-password")
		if err != nil || ok {
			t.Fatalf("%v %v", ok, err)
		}
	})
	t.Run("should ignore padded entries with a zero count", func(t *testing.T) {
		c := mockClient(func(*http.Request) (*http.Response, error) {
			return textResponse(200, sha1Upper("padded-password")[5:]+":0\n"), nil
		})
		ok, err := isPasswordCompromised(ctx, c, "padded-password")
		if err != nil || ok {
			t.Fatalf("%v %v", ok, err)
		}
	})
	t.Run("should match lowercase hash suffixes in CRLF responses", func(t *testing.T) {
		c := mockClient(func(*http.Request) (*http.Response, error) {
			return textResponse(200, strings.ToLower(sha1Upper("compromised-password")[5:])+":1\r\n"), nil
		})
		ok, err := isPasswordCompromised(ctx, c, "compromised-password")
		if err != nil || !ok {
			t.Fatalf("%v %v", ok, err)
		}
	})
	t.Run("should check an empty password", func(t *testing.T) {
		ok, err := isPasswordCompromised(ctx, newPwnedAPI("").client(), "")
		if err != nil || !ok {
			t.Fatalf("%v %v", ok, err)
		}
	})
	t.Run("should throw an API error when the service cannot complete the check", func(t *testing.T) {
		c := mockClient(func(*http.Request) (*http.Response, error) { return textResponse(503, ""), nil })
		_, err := isPasswordCompromised(ctx, c, "password")
		expectAPIError(t, err, "Failed to check password. Status: 503")
	})
	t.Run("should hide unexpected service errors", func(t *testing.T) {
		c := mockClient(func(*http.Request) (*http.Response, error) { return nil, errors.New("network unavailable") })
		_, err := isPasswordCompromised(ctx, c, "password")
		expectAPIError(t, err, "Failed to check password. Please try again later.")
	})
	for i, count := range []string{"", "   ", "invalid"} {
		t.Run(fmt.Sprintf("should reject an invalid compromise count %d", i), func(t *testing.T) {
			c := mockClient(func(*http.Request) (*http.Response, error) {
				return textResponse(200, sha1Upper("password")[5:]+":"+count+"\n"), nil
			})
			_, err := isPasswordCompromised(ctx, c, "password")
			expectAPIError(t, err, "Failed to check password. Please try again later.")
		})
	}
}
