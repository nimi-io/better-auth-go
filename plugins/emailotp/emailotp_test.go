package emailotp_test

// Port of packages/better-auth/src/plugins/email-otp/email-otp.test.ts (v1.7.7).
//
// Upstream's instances add the bearer plugin; the Go port carries sessions in cookies
// instead (an "invalid bearer token" becomes an invalid session cookie).
// vi.advanceTimersByTime is emulated by inst.advance (shifting stored timestamps back).

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/plugins/emailotp"
)

// box records sendVerificationOTP calls (the otpFn mock and the `otp` variable upstream).
type box struct {
	mu    sync.Mutex
	calls []emailotp.SendVerificationOTPData
	ctxs  []*betterauth.EndpointContext
}

func (b *box) send(ctx *betterauth.EndpointContext, d emailotp.SendVerificationOTPData) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, d)
	b.ctxs = append(b.ctxs, ctx)
	return nil
}

func (b *box) otp() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.calls) == 0 {
		return ""
	}
	return b.calls[len(b.calls)-1].OTP
}

func (b *box) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

func (b *box) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls, b.ctxs = nil, nil
}

func (b *box) calledWith(email, otp, typ string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.calls {
		if c.Email == email && (otp == "" || c.OTP == otp) && c.Type == typ {
			return true
		}
	}
	return false
}

func withOTP(o emailotp.Options) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.Plugins = append(c.Plugins, emailotp.New(o)) }
}

func chain(fns ...func(c *betterauth.Config)) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		for _, f := range fns {
			if f != nil {
				f(c)
			}
		}
	}
}

func autoSignIn(c *betterauth.Config) {
	c.EmailVerification = &betterauth.EmailVerificationConfig{AutoSignInAfterVerification: true}
}

func send(c *client, email, typ string, h ...http.Header) *resp {
	return c.post("/email-otp/send-verification-otp", map[string]any{"email": email, "type": typ}, h...)
}

func verifyEmail(c *client, email, otp string, h ...http.Header) *resp {
	return c.post("/email-otp/verify-email", map[string]any{"email": email, "otp": otp}, h...)
}

func signInOTP(c *client, body map[string]any) *resp { return c.post("/sign-in/email-otp", body) }

func resetPassword(c *client, email, otp, password string) *resp {
	return c.post("/email-otp/reset-password", map[string]any{"email": email, "otp": otp, "password": password})
}

func hasSessionCookie(r *resp) bool {
	for _, sc := range r.Header.Values("Set-Cookie") {
		if strings.Contains(sc, "better-auth.session_token") {
			return true
		}
	}
	return false
}

func findOTP(t *testing.T, in *inst, id string) *betterauth.Verification {
	t.Helper()
	v, err := in.ctx().InternalAdapter.FindVerificationValue(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEmailOTP(t *testing.T) {
	b := &box{}
	type genCall struct {
		data emailotp.GenerateOTPData
		ctx  *betterauth.EndpointContext
	}
	var genMu sync.Mutex
	var genCalls []genCall
	in := newInst(t, chain(withOTP(emailotp.Options{
		GenerateOTP: func(d emailotp.GenerateOTPData, ctx *betterauth.EndpointContext) string {
			genMu.Lock()
			genCalls = append(genCalls, genCall{d, ctx})
			genMu.Unlock()
			return "123456"
		},
		SendVerificationOTP:      b.send,
		SendVerificationOnSignUp: true,
	}), autoSignIn))
	c := in.client(false)

	t.Run("should verify email with otp", func(t *testing.T) {
		res := send(c, testEmail, "email-verification")
		if res.val("success") != true {
			t.Fatalf("send: %s", res.Body)
		}
		if len(b.otp()) != 6 || !b.calledWith(testEmail, b.otp(), "email-verification") {
			t.Fatalf("otp %q calls %+v", b.otp(), b.calls)
		}
		if v := verifyEmail(c, testEmail, b.otp()); v.val("status") != true {
			t.Fatalf("verify: %s", v.Body)
		}
	})

	t.Run("should sign-in with otp", func(t *testing.T) {
		if send(c, testEmail, "sign-in").val("success") != true {
			t.Fatal("send failed")
		}
		if len(b.otp()) != 6 || !b.calledWith(testEmail, b.otp(), "sign-in") {
			t.Fatal("otp not sent")
		}
		res := signInOTP(c, map[string]any{"email": testEmail, "otp": b.otp()})
		if !hasSessionCookie(res) || res.str("token") == "" {
			t.Fatalf("sign-in: %d %s", res.Status, res.Body)
		}
	})

	t.Run("should clear an unverified account's password when sign-in adopts it", func(t *testing.T) {
		sb := &box{}
		scoped := newInst(t, chain(func(c *betterauth.Config) { c.EmailAndPassword.RequireEmailVerification = true },
			withOTP(emailotp.Options{SendVerificationOTP: sb.send})))
		email := "otp-unverified-pw-user@email.com"
		existing := "existing-password-123"
		created := scoped.mustAPI("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": email, "name": "Test User", "password": existing}})
		user := created["user"].(map[string]any)
		userID := user["id"].(string)
		if user["emailVerified"] != false {
			t.Fatal("expected unverified")
		}
		ia := scoped.ctx().InternalAdapter
		if _, err := ia.CreateAccount(context.Background(), adapter.Record{"userId": userID, "providerId": "google", "accountId": "attacker-google"}); err != nil {
			t.Fatal(err)
		}
		if _, err := scoped.api("signInEmail", betterauth.CallInput{Body: map[string]any{"email": email, "password": existing}}); err == nil {
			t.Fatal("sign-in should fail")
		}
		sc := scoped.client(false)
		send(sc, email, "sign-in")
		if r := signInOTP(sc, map[string]any{"email": email, "otp": sb.otp()}); r.str("token") == "" {
			t.Fatalf("sign-in: %s", r.Body)
		}
		row, _ := ia.FindUserByEmail(context.Background(), email, false)
		if !row.User.EmailVerified {
			t.Fatal("not verified")
		}
		accs, _ := ia.FindAccounts(context.Background(), userID)
		if len(accs) != 0 {
			t.Fatalf("accounts = %d", len(accs))
		}
		if _, err := scoped.api("signInEmail", betterauth.CallInput{Body: map[string]any{"email": email, "password": existing}}); err == nil {
			t.Fatal("old password should not work")
		}
	})

	t.Run("should sign-up with otp", func(t *testing.T) {
		send(c, "test-email@domain.com", "sign-in")
		res := signInOTP(c, map[string]any{"email": "test-email@domain.com", "otp": b.otp()})
		if !hasSessionCookie(res) || res.str("token") == "" {
			t.Fatalf("sign-up: %d %s", res.Status, res.Body)
		}
	})

	t.Run("should reject sign-up with otp when validateUserInfo returns error", func(t *testing.T) {
		bb := &box{}
		scoped := newInst(t, chain(func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, user map[string]any, src betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
				if src.Method != "email-otp" {
					t.Errorf("method = %q", src.Method)
				}
				if e, _ := user["email"].(string); strings.HasSuffix(e, "@blocked.com") {
					return &betterauth.ValidateUserInfoResult{Error: "email_otp_blocked", ErrorDescription: "OTP sign-up is not allowed"}, nil
				}
				return nil, nil
			}}
		}, withOTP(emailotp.Options{SendVerificationOTP: bb.send})), instOpts{disableTestUser: true})
		sc := scoped.client(false)
		send(sc, "new@blocked.com", "sign-in")
		res := signInOTP(sc, map[string]any{"email": "new@blocked.com", "otp": bb.otp()})
		if res.code() != "email_otp_blocked" || res.str("message") != "OTP sign-up is not allowed" {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})

	t.Run("should sign-up with otp and set name and image", func(t *testing.T) {
		email := "test-email-with-name@domain.com"
		send(c, email, "sign-in")
		res := signInOTP(c, map[string]any{"email": email, "otp": b.otp(), "name": "Test User", "image": "https://example.com/avatar.png"})
		if res.str("token") == "" || res.str("user", "name") != "Test User" || res.str("user", "image") != "https://example.com/avatar.png" {
			t.Fatalf("got %s", res.Body)
		}
	})

	t.Run("should sign-up with uppercase email", func(t *testing.T) {
		send(c, "TEST-EMAIL@DOMAIN.COM", "sign-in")
		if r := signInOTP(c, map[string]any{"email": "TEST-EMAIL@DOMAIN.COM", "otp": b.otp()}); r.str("token") == "" {
			t.Fatalf("got %s", r.Body)
		}
	})

	t.Run("should sign-up with varying case email", func(t *testing.T) {
		send(c, "test-email@domain.com", "sign-in")
		if r := signInOTP(c, map[string]any{"email": "TEST-EMAIL@DOMAIN.COM", "otp": b.otp()}); r.str("token") == "" {
			t.Fatalf("got %s", r.Body)
		}
	})

	t.Run("should send verification otp on sign-up", func(t *testing.T) {
		genMu.Lock()
		genCalls = nil
		genMu.Unlock()
		res := c.post("/sign-up/email", map[string]any{"email": "test8@email.com", "password": "password", "name": "test"})
		expectStatus(t, res, 200, "")
		genMu.Lock()
		found := false
		for _, g := range genCalls {
			if g.data == (emailotp.GenerateOTPData{Email: "test8@email.com", Type: "email-verification"}) && g.ctx != nil {
				found = true
			}
		}
		genMu.Unlock()
		if !found {
			t.Fatalf("generateOTP calls %+v", genCalls)
		}
		if !b.calledWith("test8@email.com", b.otp(), "email-verification") {
			t.Fatal("otp not sent")
		}
	})

	t.Run("should reset password using new emailOtp.requestPasswordReset endpoint", func(t *testing.T) {
		c.post("/email-otp/request-password-reset", map[string]any{"email": testEmail})
		resetPassword(c, testEmail, b.otp(), "changed-password")
		r := c.post("/sign-in/email", map[string]any{"email": testEmail, "password": "changed-password"})
		if r.val("user") == nil {
			t.Fatalf("sign-in: %s", r.Body)
		}
	})

	for _, tc := range []struct{ password, code string }{
		{"short", "PASSWORD_TOO_SHORT"},
		{strings.Repeat("a", 129), "PASSWORD_TOO_LONG"},
	} {
		t.Run("should preserve OTP after "+tc.code, func(t *testing.T) {
			c.post("/email-otp/request-password-reset", map[string]any{"email": testEmail})
			otp := b.otp()
			if r := resetPassword(c, testEmail, otp, tc.password); r.code() != tc.code {
				t.Fatalf("invalid reset: %s", r.Body)
			}
			if r := resetPassword(c, testEmail, otp, "valid-password"); r.val("success") != true {
				t.Fatalf("valid reset: %s", r.Body)
			}
		})
	}

	t.Run("should reset password using deprecated forgetPassword endpoint (backward compatibility)", func(t *testing.T) {
		c.post("/forget-password/email-otp", map[string]any{"email": testEmail})
		resetPassword(c, testEmail, b.otp(), "changed-password-2")
		r := c.post("/sign-in/email", map[string]any{"email": testEmail, "password": "changed-password-2"})
		if r.val("user") == nil {
			t.Fatalf("sign-in: %s", r.Body)
		}
	})

	t.Run("should call onPasswordReset callback when resetting password", func(t *testing.T) {
		bb := &box{}
		var gotUser *betterauth.User
		var gotReq *http.Request
		scoped := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: bb.send, SendVerificationOnSignUp: true}), func(c *betterauth.Config) {
			c.EmailAndPassword.OnPasswordReset = func(_ context.Context, u *betterauth.User, r *http.Request) error {
				gotUser, gotReq = u, r
				return nil
			}
		}))
		sc := scoped.client(false)
		send(sc, testEmail, "forget-password")
		resetPassword(sc, testEmail, bb.otp(), "new-password")
		if gotUser == nil || gotUser.Email != testEmail || gotReq == nil {
			t.Fatalf("onPasswordReset user=%v req=%v", gotUser, gotReq)
		}
	})

	t.Run("should reset password and create credential account", func(t *testing.T) {
		email := "test-email@domain.com"
		send(c, email, "sign-in")
		if r := signInOTP(c, map[string]any{"email": email, "otp": b.otp()}); !hasSessionCookie(r) {
			t.Fatalf("sign-in: %s", r.Body)
		}
		send(c, email, "forget-password")
		resetPassword(c, email, b.otp(), "password")
		r := c.post("/sign-in/email", map[string]any{"email": email, "password": "password"})
		if r.str("token") == "" {
			t.Fatalf("sign-in: %s", r.Body)
		}
		userID := r.str("user", "id")
		acc, err := in.ctx().InternalAdapter.FindCredentialAccount(context.Background(), userID)
		if err != nil || acc == nil || acc.UserID != userID || acc.ProviderID != "credential" || acc.AccountID != userID {
			t.Fatalf("credential account %+v %v", acc, err)
		}
	})

	t.Run("should fail on invalid email", func(t *testing.T) {
		expectStatus(t, send(c, "invalid-email", "email-verification"), 400, "INVALID_EMAIL")
	})

	t.Run("should reject change-email type", func(t *testing.T) {
		r := send(c, testEmail, "change-email")
		if r.Status != 400 || r.str("message") != "Invalid OTP type" {
			t.Fatalf("got %d %s", r.Status, r.Body)
		}
	})

	t.Run("should fail on expired otp", func(t *testing.T) {
		send(c, testEmail, "email-verification")
		in.advance(6 * time.Minute)
		expectStatus(t, verifyEmail(c, testEmail, b.otp()), 400, "OTP_EXPIRED")
	})

	t.Run("should not fail on time elapsed", func(t *testing.T) {
		send(c, testEmail, "email-verification")
		in.advance(4 * time.Minute)
		res := verifyEmail(c, testEmail, b.otp())
		if res.val("status") != true {
			t.Fatalf("verify: %s", res.Body)
		}
		s := in.getSession(cookieHeader(res.Header))
		if s == nil || s["user"].(map[string]any)["emailVerified"] != true {
			t.Fatalf("session %v", s)
		}
	})

	t.Run("should create verification otp on server", func(t *testing.T) {
		var otp string
		for range 2 {
			res, err := in.api("createVerificationOTP", betterauth.CallInput{Body: map[string]any{"type": "sign-in", "email": "test@email.com"}})
			if err != nil {
				t.Fatal(err)
			}
			otp, _ = res.Data.(string)
		}
		if len(otp) != 6 {
			t.Fatalf("otp %q", otp)
		}
	})

	t.Run("should get verification otp on server", func(t *testing.T) {
		if _, err := in.api("getVerificationOTP", betterauth.CallInput{Query: map[string]any{"email": "test@email.com", "type": "sign-in"}}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("should work with custom options", func(t *testing.T) {
		bb := &box{}
		scoped := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: bb.send, SendVerificationOnSignUp: true,
			ExpiresIn: 10 * time.Second, OTPLength: 8}), autoSignIn))
		sc := scoped.client(false)
		send(sc, testEmail, "email-verification")
		if len(bb.otp()) != 8 {
			t.Fatalf("otp %q", bb.otp())
		}
		scoped.advance(11 * time.Second)
		if r := verifyEmail(sc, testEmail, bb.otp()); r.code() != "OTP_EXPIRED" {
			t.Fatalf("got %s", r.Body)
		}
	})
}

func TestEmailOTPChangeEmail(t *testing.T) {
	b := &box{}
	in := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: b.send, SendVerificationOnSignUp: true,
		ChangeEmail: &emailotp.ChangeEmailOptions{Enabled: true}}), autoSignIn))
	c := in.client(false)
	requestChange := func(c *client, h http.Header, body map[string]any) *resp {
		return c.post("/email-otp/request-email-change", body, h)
	}
	changeEmail := func(c *client, h http.Header, body map[string]any) *resp {
		return c.post("/email-otp/change-email", body, h)
	}
	invalidSession := http.Header{"Cookie": {"better-auth.session_token=invalid-session-token"}}

	t.Run("request/should send otp for change email request", func(t *testing.T) {
		b.clear()
		res := requestChange(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": "new-email@test.com"})
		if res.val("success") != true {
			t.Fatalf("got %s", res.Body)
		}
		if !b.calledWith("new-email@test.com", "", "change-email") {
			t.Fatal("otp not sent")
		}
	})
	t.Run("request/should not send otp for change email request if session does not exist", func(t *testing.T) {
		expectStatus(t, requestChange(c, nil, map[string]any{"newEmail": "new-email@test.com"}), 401, "UNAUTHORIZED")
	})
	t.Run("request/should not send otp for change email request if session is invalid", func(t *testing.T) {
		expectStatus(t, requestChange(c, invalidSession, map[string]any{"newEmail": "new-email@test.com"}), 401, "UNAUTHORIZED")
	})
	t.Run("request/should not send otp for change email request when change email with OTP is disabled", func(t *testing.T) {
		scoped := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: (&box{}).send, SendVerificationOnSignUp: true,
			ChangeEmail: &emailotp.ChangeEmailOptions{Enabled: false}}))
		res := requestChange(scoped.client(false), scoped.signIn(testEmail, testPassword), map[string]any{"newEmail": "new@test.com"})
		if res.Status != 400 || res.str("message") != "Change email with OTP is disabled" {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})
	t.Run("request/should not send otp for change email request if email is same as old email", func(t *testing.T) {
		res := requestChange(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": testEmail})
		if res.Status != 400 || !strings.Contains(res.str("message"), "Email is the same") {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})
	t.Run("request/should not send otp for change email request if email is already used by another account", func(t *testing.T) {
		c.post("/sign-up/email", map[string]any{"email": "other-user@test.com", "password": "password123", "name": "Other User"})
		b.clear()
		res := requestChange(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": "other-user@test.com"})
		if res.val("success") != true {
			t.Fatalf("got %s", res.Body)
		}
		if b.calledWith("other-user@test.com", "", "change-email") {
			t.Fatal("otp sent to existing account")
		}
	})

	t.Run("request/when verifyCurrentEmail is enabled", func(t *testing.T) {
		vb := &box{}
		vc := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: vb.send, SendVerificationOnSignUp: true,
			ChangeEmail: &emailotp.ChangeEmailOptions{Enabled: true, VerifyCurrentEmail: true}}), autoSignIn))
		vcc := vc.client(false)
		t.Run("should require otp when requesting email change", func(t *testing.T) {
			res := requestChange(vcc, vc.signIn(testEmail, testPassword), map[string]any{"newEmail": "new@test.com"})
			if res.Status != 400 || res.str("message") != "OTP is required to verify current email" {
				t.Fatalf("got %d %s", res.Status, res.Body)
			}
		})
		t.Run("should reject invalid current email otp when requesting email change", func(t *testing.T) {
			res := requestChange(vcc, vc.signIn(testEmail, testPassword), map[string]any{"newEmail": "new@test.com", "otp": "000000"})
			expectStatus(t, res, 400, "INVALID_OTP")
		})
		t.Run("should reject when no email-verification OTP was requested for current email", func(t *testing.T) {
			res := requestChange(vcc, vc.signIn(testEmail, testPassword), map[string]any{"newEmail": "new@test.com", "otp": "123456"})
			expectStatus(t, res, 400, "INVALID_OTP")
		})
		t.Run("should reject expired current email OTP when requesting email change", func(t *testing.T) {
			eb := &box{}
			exp := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: eb.send, SendVerificationOnSignUp: true,
				ChangeEmail: &emailotp.ChangeEmailOptions{Enabled: true, VerifyCurrentEmail: true}, ExpiresIn: 60 * time.Second}), autoSignIn))
			ec := exp.client(false)
			send(ec, testEmail, "email-verification", exp.signIn(testEmail, testPassword))
			current := eb.otp()
			exp.advance(61 * time.Second)
			res := requestChange(ec, exp.signIn(testEmail, testPassword), map[string]any{"newEmail": "new@test.com", "otp": current})
			expectStatus(t, res, 400, "OTP_EXPIRED")
		})
		t.Run("should send change-email OTP when valid current email OTP is provided", func(t *testing.T) {
			newEmail := "verified-change@test.com"
			vb.clear()
			// Verification rows are ordered by createdAt (millisecond precision); make sure the
			// new OTP is strictly newer than the row re-created by the previous wrong attempt.
			time.Sleep(3 * time.Millisecond)
			send(vcc, testEmail, "email-verification", vc.signIn(testEmail, testPassword))
			current := vb.otp()
			if current == "" {
				t.Fatal("no otp")
			}
			res := requestChange(vcc, vc.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail, "otp": current})
			if res.val("success") != true {
				t.Fatalf("got %s", res.Body)
			}
			if !vb.calledWith(newEmail, "", "change-email") {
				t.Fatal("otp not sent")
			}
		})
	})

	t.Run("change/should change email with otp", func(t *testing.T) {
		c.post("/sign-up/email", map[string]any{"email": "user-to-change@test.com", "password": "password123", "name": "User To Change"})
		newEmail := "changed-email@test.com"
		h := in.signIn("user-to-change@test.com", "password123")
		if r := requestChange(c, h, map[string]any{"newEmail": newEmail}); r.val("success") != true {
			t.Fatalf("request: %s", r.Body)
		}
		if !b.calledWith(newEmail, "", "change-email") {
			t.Fatal("otp not sent")
		}
		h = in.signIn("user-to-change@test.com", "password123")
		r := changeEmail(c, h, map[string]any{"newEmail": newEmail, "otp": b.otp()})
		if r.val("success") != true {
			t.Fatalf("change: %s", r.Body)
		}
		if s := in.getSession(h); s["user"].(map[string]any)["email"] != newEmail {
			t.Fatalf("session %v", s)
		}
	})
	t.Run("change/should not change email if session does not exist", func(t *testing.T) {
		expectStatus(t, changeEmail(c, nil, map[string]any{"newEmail": "other@test.com", "otp": "123456"}), 401, "UNAUTHORIZED")
	})
	t.Run("change/should not change email if session is invalid", func(t *testing.T) {
		expectStatus(t, changeEmail(c, invalidSession, map[string]any{"newEmail": "other@test.com", "otp": "123456"}), 401, "UNAUTHORIZED")
	})
	t.Run("change/should not change email if session contains different email from otp request email", func(t *testing.T) {
		newEmail := "target-email@test.com"
		if r := requestChange(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail}); r.val("success") != true {
			t.Fatalf("request: %s", r.Body)
		}
		c.post("/sign-up/email", map[string]any{"email": "other-account@test.com", "password": "password123", "name": "Other Account"})
		r := changeEmail(c, in.signIn("other-account@test.com", "password123"), map[string]any{"newEmail": newEmail, "otp": b.otp()})
		expectStatus(t, r, 400, "INVALID_OTP")
	})
	t.Run("change/should not change email if new email is different from otp request email", func(t *testing.T) {
		if r := requestChange(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": "requested@test.com"}); r.val("success") != true {
			t.Fatalf("request: %s", r.Body)
		}
		r := changeEmail(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": "wrong@test.com", "otp": b.otp()})
		expectStatus(t, r, 400, "INVALID_OTP")
	})
	t.Run("change/should not change email if otp is invalid", func(t *testing.T) {
		if r := requestChange(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": "another-new@test.com"}); r.val("success") != true {
			t.Fatalf("request: %s", r.Body)
		}
		r := changeEmail(c, in.signIn(testEmail, testPassword), map[string]any{"newEmail": "another-new@test.com", "otp": "000000"})
		expectStatus(t, r, 400, "INVALID_OTP")
	})
	t.Run("change/should not change email if otp is expired", func(t *testing.T) {
		eb := &box{}
		exp := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: eb.send, SendVerificationOnSignUp: true,
			ExpiresIn: 60 * time.Second, ChangeEmail: &emailotp.ChangeEmailOptions{Enabled: true}}), autoSignIn))
		ec := exp.client(false)
		newEmail := "expired-otp@test.com"
		if r := requestChange(ec, exp.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail}); r.val("success") != true {
			t.Fatalf("request: %s", r.Body)
		}
		exp.advance(61 * time.Second)
		r := changeEmail(ec, exp.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail, "otp": eb.otp()})
		expectStatus(t, r, 400, "OTP_EXPIRED")
	})
	t.Run("change/should call beforeEmailVerification callback when email is updated", func(t *testing.T) {
		cb := &box{}
		var calls []*betterauth.User
		var reqs []*http.Request
		scoped := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: cb.send, SendVerificationOnSignUp: true,
			ChangeEmail: &emailotp.ChangeEmailOptions{Enabled: true}}), func(c *betterauth.Config) {
			c.EmailVerification = &betterauth.EmailVerificationConfig{AutoSignInAfterVerification: true,
				BeforeEmailVerification: func(_ context.Context, u *betterauth.User, r *http.Request) error {
					calls = append(calls, u)
					reqs = append(reqs, r)
					return nil
				}}
		}))
		sc := scoped.client(false)
		newEmail := "before-cb@test.com"
		requestChange(sc, scoped.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail})
		changeEmail(sc, scoped.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail, "otp": cb.otp()})
		if len(calls) != 1 || calls[0].Email != testEmail || reqs[0] == nil {
			t.Fatalf("calls %v", calls)
		}
	})
	t.Run("change/should call afterEmailVerification callback when email is updated", func(t *testing.T) {
		cb := &box{}
		var calls []*betterauth.User
		var reqs []*http.Request
		scoped := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: cb.send, SendVerificationOnSignUp: true,
			ChangeEmail: &emailotp.ChangeEmailOptions{Enabled: true}}), func(c *betterauth.Config) {
			c.EmailVerification = &betterauth.EmailVerificationConfig{AutoSignInAfterVerification: true,
				AfterEmailVerification: func(_ context.Context, u *betterauth.User, r *http.Request) error {
					calls = append(calls, u)
					reqs = append(reqs, r)
					return nil
				}}
		}))
		sc := scoped.client(false)
		newEmail := "after-cb@test.com"
		requestChange(sc, scoped.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail})
		changeEmail(sc, scoped.signIn(testEmail, testPassword), map[string]any{"newEmail": newEmail, "otp": cb.otp()})
		if len(calls) != 1 || calls[0].Email != newEmail || !calls[0].EmailVerified || reqs[0] == nil {
			t.Fatalf("calls %v", calls)
		}
	})
}

func TestEmailOTPVerify(t *testing.T) {
	b := &box{}
	in := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: b.send, SendVerificationOnSignUp: true, DisableSignUp: true}))
	c := in.client(false)

	t.Run("should prevent user enumeration when disableSignUp is enabled", func(t *testing.T) {
		if r := send(c, "non-existent@domain.com", "email-verification"); r.Status != 200 || r.val("success") != true {
			t.Fatalf("got %s", r.Body)
		}
		if r := send(c, testEmail, "email-verification"); r.Status != 200 || r.val("success") != true {
			t.Fatalf("got %s", r.Body)
		}
	})

	t.Run("should return INVALID_OTP regardless of email registration", func(t *testing.T) {
		scoped := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: (&box{}).send, DisableSignUp: true}))
		sc := scoped.client(false)
		for _, email := range []string{testEmail, "non-existent@domain.com"} {
			r := sc.post("/email-otp/check-verification-otp", map[string]any{"email": email, "type": "email-verification", "otp": "000000"})
			if r.Status != 400 || r.code() != "INVALID_OTP" || r.str("message") != "Invalid OTP" {
				t.Fatalf("%s: %d %s", email, r.Status, r.Body)
			}
		}
	})

	t.Run("should not send OTP email for non-existent users when disableSignUp is enabled", func(t *testing.T) {
		sb := &box{}
		scoped := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: sb.send, DisableSignUp: true}))
		sc := scoped.client(false)
		sb.clear()
		if r := send(sc, "non-existent-user@example.com", "sign-in"); r.val("success") != true || sb.count() != 0 {
			t.Fatalf("got %s calls=%d", r.Body, sb.count())
		}
		if r := send(sc, testEmail, "sign-in"); r.val("success") != true || sb.count() != 1 || !sb.calledWith(testEmail, "", "sign-in") {
			t.Fatalf("got %s calls=%d", r.Body, sb.count())
		}
	})

	t.Run("should verify email with last otp", func(t *testing.T) {
		for range 3 {
			send(c, testEmail, "email-verification")
		}
	})

	t.Run("should block after exceeding allowed attempts", func(t *testing.T) {
		send(c, testEmail, "email-verification")
		for range 3 {
			r := verifyEmail(c, testEmail, "wrong-otp")
			if r.Status != 400 || r.str("message") != "Invalid OTP" {
				t.Fatalf("got %d %s", r.Status, r.Body)
			}
		}
		r := verifyEmail(c, testEmail, "000000")
		if r.Status != 403 || r.str("message") != "Too many attempts" {
			t.Fatalf("got %d %s", r.Status, r.Body)
		}
	})

	t.Run("should block reset password after exceeding allowed attempts", func(t *testing.T) {
		send(c, testEmail, "forget-password")
		for range 3 {
			r := resetPassword(c, testEmail, "wrong-otp", "new-password")
			if r.Status != 400 || r.str("message") != "Invalid OTP" {
				t.Fatalf("got %d %s", r.Status, r.Body)
			}
		}
		r := resetPassword(c, testEmail, "000000", "new-password")
		if r.Status != 403 || r.str("message") != "Too many attempts" {
			t.Fatalf("got %d %s", r.Status, r.Body)
		}
	})
}

func TestEmailOTPCustomRateLimitingStorage(t *testing.T) {
	// Upstream uses the in-memory rate limiter and fake timers; the database storage is
	// used here so the window can be advanced by shifting stored timestamps.
	in := newInst(t, chain(func(c *betterauth.Config) {
		c.RateLimit = &betterauth.RateLimitConfig{Enabled: betterauth.Bool(true), Storage: "database"}
	}, withOTP(emailotp.Options{SendVerificationOTP: (&box{}).send})))
	c := in.client(false)
	for _, tc := range []struct {
		path string
		body map[string]any
	}{
		{"/email-otp/send-verification-otp", map[string]any{"email": "test@email.com", "type": "sign-in"}},
		{"/sign-in/email-otp", map[string]any{"email": "test@email.com", "otp": "12312"}},
		{"/email-otp/verify-email", map[string]any{"email": "test@email.com", "otp": "12312"}},
	} {
		t.Run("should rate limit send verification endpoint "+tc.path, func(t *testing.T) {
			for i := range 10 {
				r := c.post(tc.path, tc.body)
				if i >= 3 && r.Status != 429 {
					t.Fatalf("request %d: %d %s", i, r.Status, r.Body)
				}
			}
			in.advance(60 * time.Second)
			if r := c.post(tc.path, tc.body); r.Status == 429 {
				t.Fatal("still rate limited")
			}
		})
	}
}

func TestEmailOTPCustomGenerateOTP(t *testing.T) {
	in := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: (&box{}).send,
		GenerateOTP: func(emailotp.GenerateOTPData, *betterauth.EndpointContext) string { return "123456" }}))
	c := in.client(false)
	t.Run("should generate otp", func(t *testing.T) {
		if r := send(c, testEmail, "email-verification"); r.val("success") != true {
			t.Fatalf("got %s", r.Body)
		}
	})
	t.Run("should verify email with otp", func(t *testing.T) {
		if r := verifyEmail(c, testEmail, "123456"); r.val("status") != true {
			t.Fatalf("got %s", r.Body)
		}
	})
}

func TestEmailOTPCustomStoreOTP(t *testing.T) {
	cases := []struct {
		name      string
		store     emailotp.StoreOTP
		canGet    bool
		createMsg string
	}{
		{"hashed", emailotp.StoreHashed, false, "should create a hashed otp"},
		{"encrypted", emailotp.StoreEncrypted, true, "should create an encrypted otp"},
		{"custom encryptor", emailotp.StoreOTP{
			Encrypt: func(otp string) (string, error) { return otp + "encrypted", nil },
			Decrypt: func(s string) (string, error) { return strings.Replace(s, "encrypted", "", 1), nil },
		}, true, "should create a custom encryptor otp"},
		{"custom hasher", emailotp.StoreOTP{Hash: func(otp string) (string, error) { return otp + "hashed", nil }}, false, "should create a custom hasher otp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &box{}
			in := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: b.send, StoreOTP: tc.store}))
			c := in.client(false)
			email := strings.ToLower(randomEmail())
			var valid string
			t.Run(tc.createMsg, func(t *testing.T) {
				send(c, email, "sign-in")
				v := findOTP(t, in, "sign-in-otp-"+email)
				valid = b.otp()
				if v == nil || v.Value == "" {
					t.Fatal("no stored otp")
				}
				stored, _ := emailotp.SplitAtLastColon(v.Value)
				if stored == valid || !strings.HasSuffix(v.Value, ":0") {
					t.Fatalf("stored %q otp %q", v.Value, valid)
				}
			})
			getName := "should not be allowed to get otp if storeOTP is hashed"
			if tc.name == "encrypted" {
				getName = "should be allowed to get otp if storeOTP is encrypted"
			} else if tc.name != "hashed" {
				getName = "should be allowed to get otp if storeOTP is " + tc.name
			}
			t.Run(getName, func(t *testing.T) {
				res, err := in.api("getVerificationOTP", betterauth.CallInput{Query: map[string]any{"email": email, "type": "sign-in"}})
				if !tc.canGet {
					e := apiErr(t, err)
					if e.StatusCode != 400 || e.Status != "BAD_REQUEST" || e.Message() != "OTP is hashed, cannot return the plain text OTP" {
						t.Fatalf("error %+v", e)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var out struct{ OTP string }
				_ = res.Decode(&out)
				if out.OTP != valid || len(out.OTP) != 6 {
					t.Fatalf("otp %q want %q", out.OTP, valid)
				}
			})
			signName := "should be able to sign in with normal otp"
			switch tc.name {
			case "encrypted":
				signName = "should be able to sign in with encrypted otp"
			case "custom encryptor":
				signName = "should be able to sign in with custom encryptor otp"
			case "custom hasher":
				signName = "should be able to sign in with custom hasher otp"
			}
			t.Run(signName, func(t *testing.T) {
				r := signInOTP(c, map[string]any{"email": email, "otp": valid})
				if r.str("user", "email") != email || r.str("token") == "" {
					t.Fatalf("got %s", r.Body)
				}
			})
		})
	}
}

var emailCounter int

func randomEmail() string {
	emailCounter++
	return "u" + time.Now().Format("150405.000000") + "-" + string(rune('a'+emailCounter%26)) + "@email.com"
}

func TestEmailOTPOverrideDefaultEmailVerification(t *testing.T) {
	b := &box{}
	in := newInst(t, chain(func(c *betterauth.Config) {
		c.EmailVerification = &betterauth.EmailVerificationConfig{SendOnSignUp: betterauth.Bool(true)}
	}, withOTP(emailotp.Options{SendVerificationOTP: b.send, OverrideDefaultEmailVerification: true})))
	c := in.client(false)
	t.Run("should send verification email on sign up", func(t *testing.T) {
		c.post("/sign-up/email", map[string]any{"email": "test-otp-override@email.com", "password": "password", "name": "Test User"})
		if len(b.otp()) != 6 {
			t.Fatalf("otp %q", b.otp())
		}
	})
	t.Run("should verify email with otp", func(t *testing.T) {
		r := verifyEmail(c, "test-otp-override@email.com", b.otp())
		if r.val("status") != true || r.val("user", "emailVerified") != true {
			t.Fatalf("got %s", r.Body)
		}
	})
	t.Run("should by default not override default email verification", func(t *testing.T) {
		called := false
		scoped := newInst(t, chain(func(c *betterauth.Config) {
			c.EmailVerification = &betterauth.EmailVerificationConfig{SendOnSignUp: betterauth.Bool(true),
				SendVerificationEmail: func(context.Context, betterauth.EmailData, *http.Request) error {
					called = true
					return nil
				}}
		}, withOTP(emailotp.Options{SendVerificationOTP: (&box{}).send})))
		scoped.client(false).post("/sign-up/email", map[string]any{"email": "test-otp-override@email.com", "password": "password", "name": "Test User"})
		if !called {
			t.Fatal("sendVerificationEmail not called")
		}
	})
	t.Run("should send email only once when override is enabled", func(t *testing.T) {
		sb := &box{}
		scoped := newInst(t, chain(func(c *betterauth.Config) {
			c.EmailVerification = &betterauth.EmailVerificationConfig{SendOnSignUp: betterauth.Bool(true)}
		}, withOTP(emailotp.Options{SendVerificationOTP: sb.send, OverrideDefaultEmailVerification: true, SendVerificationOnSignUp: true})))
		sb.clear()
		scoped.client(false).post("/sign-up/email", map[string]any{"email": "test-no-duplicate@email.com", "password": "password", "name": "Test User"})
		if sb.count() != 1 || !sb.calledWith("test-no-duplicate@email.com", "", "email-verification") || sb.ctxs[0] == nil {
			t.Fatalf("calls %+v", sb.calls)
		}
	})
	t.Run("should call afterEmailVerification hook when override is enabled", func(t *testing.T) {
		sb := &box{}
		var calls []*betterauth.User
		scoped := newInst(t, chain(func(c *betterauth.Config) {
			c.EmailVerification = &betterauth.EmailVerificationConfig{SendOnSignUp: betterauth.Bool(true),
				AfterEmailVerification: func(_ context.Context, u *betterauth.User, r *http.Request) error {
					if r == nil {
						t.Error("request missing")
					}
					calls = append(calls, u)
					return nil
				}}
		}, withOTP(emailotp.Options{SendVerificationOTP: sb.send, OverrideDefaultEmailVerification: true})))
		sc := scoped.client(false)
		sc.post("/sign-up/email", map[string]any{"email": "test-hook@email.com", "password": "password", "name": "Test User"})
		if r := verifyEmail(sc, "test-hook@email.com", sb.otp()); r.val("status") != true {
			t.Fatalf("got %s", r.Body)
		}
		if len(calls) != 1 || calls[0].Email != "test-hook@email.com" || !calls[0].EmailVerified {
			t.Fatalf("calls %v", calls)
		}
	})
}

func TestEmailOTPSignUpAdditionalFields(t *testing.T) {
	b := &box{}
	in := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: b.send}), func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
			{Name: "lang", Type: db.TypeString, Required: db.Bool(false), Input: db.Bool(true)},
			{Name: "isAdmin", Type: db.TypeBoolean, DefaultValue: false, Input: db.Bool(false)},
		}}}
	}))
	c := in.client(false)
	t.Run("should sign-up with additional fields", func(t *testing.T) {
		email := "additional-fields@domain.com"
		send(c, email, "sign-in")
		r := signInOTP(c, map[string]any{"email": email, "otp": b.otp(), "name": "AF User", "lang": "ko"})
		if r.str("token") == "" || r.str("user", "name") != "AF User" {
			t.Fatalf("got %s", r.Body)
		}
		u := in.getSession(cookieHeader(r.Header))["user"].(map[string]any)
		if u["name"] != "AF User" || u["lang"] != "ko" || u["isAdmin"] != false {
			t.Fatalf("user %v", u)
		}
	})
	t.Run("should ignore input: false fields and use default value", func(t *testing.T) {
		email := "ignore-input-false@domain.com"
		send(c, email, "sign-in")
		r := signInOTP(c, map[string]any{"email": email, "otp": b.otp(), "isAdmin": true})
		if r.str("token") == "" {
			t.Fatalf("got %s", r.Body)
		}
		if u := in.getSession(cookieHeader(r.Header))["user"].(map[string]any); u["isAdmin"] != false {
			t.Fatalf("user %v", u)
		}
	})
}

func TestEmailOTPRaceConditionProtection(t *testing.T) {
	b := &box{}
	in := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: b.send}))
	c := in.client(false)
	concurrent := func(fn func() *resp) []*resp {
		out := make([]*resp, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out[i] = fn()
			}()
		}
		wg.Wait()
		return out
	}

	t.Run("should delete OTP after successful sign-in", func(t *testing.T) {
		email := "race-test@domain.com"
		send(c, email, "sign-in")
		otp := b.otp()
		if r := signInOTP(c, map[string]any{"email": email, "otp": otp}); r.str("token") == "" {
			t.Fatalf("got %s", r.Body)
		}
		if findOTP(t, in, "sign-in-otp-"+email) != nil {
			t.Fatal("otp not deleted")
		}
		if r := signInOTP(c, map[string]any{"email": email, "otp": otp}); r.code() != "INVALID_OTP" {
			t.Fatalf("got %s", r.Body)
		}
	})
	t.Run("should delete OTP after successful email verification", func(t *testing.T) {
		email := "race-verify@domain.com"
		send(c, email, "sign-in")
		signInOTP(c, map[string]any{"email": email, "otp": b.otp()})
		send(c, email, "email-verification")
		otp := b.otp()
		if r := verifyEmail(c, email, otp); r.val("status") != true {
			t.Fatalf("got %s", r.Body)
		}
		if findOTP(t, in, "email-verification-otp-"+email) != nil {
			t.Fatal("otp not deleted")
		}
		if r := verifyEmail(c, email, otp); r.code() != "INVALID_OTP" {
			t.Fatalf("got %s", r.Body)
		}
	})
	t.Run("should delete OTP after successful password reset", func(t *testing.T) {
		email := "race-reset@domain.com"
		send(c, email, "sign-in")
		signInOTP(c, map[string]any{"email": email, "otp": b.otp()})
		c.post("/email-otp/request-password-reset", map[string]any{"email": email})
		otp := b.otp()
		if r := resetPassword(c, email, otp, "newpass1"); r.val("success") != true {
			t.Fatalf("got %s", r.Body)
		}
		if findOTP(t, in, "forget-password-otp-"+email) != nil {
			t.Fatal("otp not deleted")
		}
		if r := resetPassword(c, email, otp, "newpass2"); r.code() != "INVALID_OTP" {
			t.Fatalf("got %s", r.Body)
		}
	})
	t.Run("should allow exactly one success when the same OTP is verified concurrently", func(t *testing.T) {
		email := "race-concurrent-signin@domain.com"
		send(c, email, "sign-in")
		otp := b.otp()
		res := concurrent(func() *resp { return signInOTP(c, map[string]any{"email": email, "otp": otp}) })
		ok, failed := 0, 0
		for _, r := range res {
			if r.str("token") != "" {
				ok++
			} else if r.code() == "INVALID_OTP" {
				failed++
			}
		}
		if ok != 1 || failed != 1 {
			t.Fatalf("ok=%d failed=%d: %s / %s", ok, failed, res[0].Body, res[1].Body)
		}
		if findOTP(t, in, "sign-in-otp-"+email) != nil {
			t.Fatal("otp not deleted")
		}
	})
	t.Run("should allow exactly one success when the same email-verification OTP is verified concurrently", func(t *testing.T) {
		email := "race-concurrent-verify@domain.com"
		send(c, email, "sign-in")
		signInOTP(c, map[string]any{"email": email, "otp": b.otp()})
		send(c, email, "email-verification")
		otp := b.otp()
		res := concurrent(func() *resp { return verifyEmail(c, email, otp) })
		ok, failed := 0, 0
		for _, r := range res {
			if r.val("status") == true {
				ok++
			} else if r.code() == "INVALID_OTP" {
				failed++
			}
		}
		if ok != 1 || failed != 1 {
			t.Fatalf("ok=%d failed=%d", ok, failed)
		}
	})
	t.Run("should increment attempts on a wrong code without burning a valid OTP, and reject replay of a consumed code", func(t *testing.T) {
		email := "race-wrong-code@domain.com"
		send(c, email, "sign-in")
		valid := b.otp()
		wrong := "000000"
		if valid == wrong {
			wrong = "111111"
		}
		if r := signInOTP(c, map[string]any{"email": email, "otp": wrong}); r.code() != "INVALID_OTP" {
			t.Fatalf("got %s", r.Body)
		}
		after := findOTP(t, in, "sign-in-otp-"+email)
		if after == nil {
			t.Fatal("otp burned")
		}
		if _, attempts := emailotp.SplitAtLastColon(after.Value); attempts != "1" {
			t.Fatalf("attempts %q", attempts)
		}
		if r := signInOTP(c, map[string]any{"email": email, "otp": valid}); r.str("token") == "" {
			t.Fatalf("got %s", r.Body)
		}
		if r := signInOTP(c, map[string]any{"email": email, "otp": valid}); r.code() != "INVALID_OTP" {
			t.Fatalf("got %s", r.Body)
		}
	})
	t.Run("should lock out after the attempt budget is exhausted and not recreate the OTP", func(t *testing.T) {
		email := "race-lockout@domain.com"
		send(c, email, "sign-in")
		valid := b.otp()
		wrong := "000000"
		if valid == wrong {
			wrong = "111111"
		}
		for range 3 {
			signInOTP(c, map[string]any{"email": email, "otp": wrong})
		}
		if r := signInOTP(c, map[string]any{"email": email, "otp": wrong}); r.code() != "TOO_MANY_ATTEMPTS" {
			t.Fatalf("got %s", r.Body)
		}
		if findOTP(t, in, "sign-in-otp-"+email) != nil {
			t.Fatal("otp recreated")
		}
		if r := signInOTP(c, map[string]any{"email": email, "otp": valid}); r.code() != "INVALID_OTP" {
			t.Fatalf("got %s", r.Body)
		}
	})
}

func TestEmailOTPResendStrategy(t *testing.T) {
	b := &box{}
	in := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: b.send, ResendStrategy: "reuse"}))
	c := in.client(false)
	otps := func(bx *box) []string {
		bx.mu.Lock()
		defer bx.mu.Unlock()
		var out []string
		for _, c := range bx.calls {
			out = append(out, c.OTP)
		}
		return out
	}
	t.Run("should reuse existing OTP when resendStrategy is reuse", func(t *testing.T) {
		b.clear()
		send(c, testEmail, "email-verification")
		send(c, testEmail, "email-verification")
		o := otps(b)
		if len(o) != 2 || o[0] != o[1] {
			t.Fatalf("otps %v", o)
		}
	})
	t.Run("should generate new OTP after previous one expires", func(t *testing.T) {
		b.clear()
		send(c, testEmail, "sign-in")
		in.advance(6 * time.Minute)
		send(c, testEmail, "sign-in")
		o := otps(b)
		if len(o) != 2 || o[0] == o[1] {
			t.Fatalf("otps %v", o)
		}
	})
	for _, tc := range []struct {
		name  string
		store emailotp.StoreOTP
	}{
		{"should generate new OTP when resendStrategy is reuse but storeOTP is hashed", emailotp.StoreHashed},
		{"should generate new OTP when resendStrategy is reuse but storeOTP is custom hash", emailotp.StoreOTP{Hash: func(o string) (string, error) { return "hashed-" + o, nil }}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hb := &box{}
			scoped := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: hb.send, ResendStrategy: "reuse", StoreOTP: tc.store}))
			sc := scoped.client(false)
			send(sc, testEmail, "email-verification")
			send(sc, testEmail, "email-verification")
			o := otps(hb)
			if len(o) != 2 || o[0] == o[1] {
				t.Fatalf("otps %v", o)
			}
		})
	}
	t.Run("should not send OTP for non-existent user on email-verification type", func(t *testing.T) {
		nb := &box{}
		scoped := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: nb.send, ResendStrategy: "reuse", DisableSignUp: true}))
		if r := send(scoped.client(false), "nonexistent@test.com", "email-verification"); r.val("success") != true || nb.count() != 0 {
			t.Fatalf("got %s calls %d", r.Body, nb.count())
		}
	})
	t.Run("should generate fresh OTP when attempts are exhausted", func(t *testing.T) {
		ab := &box{}
		scoped := newInst(t, withOTP(emailotp.Options{SendVerificationOTP: ab.send, ResendStrategy: "reuse", AllowedAttempts: 2}))
		sc := scoped.client(false)
		send(sc, testEmail, "email-verification")
		verifyEmail(sc, testEmail, "wrong1")
		verifyEmail(sc, testEmail, "wrong2")
		send(sc, testEmail, "email-verification")
		o := otps(ab)
		if len(o) != 2 || o[0] == o[1] {
			t.Fatalf("otps %v", o)
		}
	})
}

func TestEmailOTPVerifyEmailCookieCacheIsolation(t *testing.T) {
	// should not mark the current session's user as verified when a different user's email
	// is verified
	secret := "better-auth-secret-1234567890-cookie-cache"
	b := &box{}
	in := newInst(t, chain(withOTP(emailotp.Options{SendVerificationOTP: b.send}), func(c *betterauth.Config) {
		c.Secret = secret
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true}}
	}))
	c := in.client(false)
	in.mustAPI("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": "user-b@test.com", "password": "user-b-password", "name": "user-b"}})
	signed := c.post("/sign-in/email", map[string]any{"email": "user-b@test.com", "password": "user-b-password"})
	cookies := map[string]string{}
	for _, sc := range signed.Header.Values("Set-Cookie") {
		nv, _, _ := strings.Cut(sc, ";")
		k, v, _ := strings.Cut(nv, "=")
		cookies[k] = v
	}
	headers := http.Header{"Cookie": {"better-auth.session_token=" + cookies["better-auth.session_token"] + "; better-auth.session_data=" + cookies["better-auth.session_data"]}}
	in.mustAPI("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": "other@test.com", "password": "other-password", "name": "other"}})
	send(c, "other@test.com", "email-verification")
	verified := verifyEmail(c, "other@test.com", b.otp(), headers)
	if verified.val("status") != true {
		t.Fatalf("verify: %s", verified.Body)
	}
	for _, sc := range verified.Header.Values("Set-Cookie") {
		nv, _, _ := strings.Cut(sc, ";")
		if k, v, _ := strings.Cut(nv, "="); k == "better-auth.session_data" && v != "" {
			headers.Set("Cookie", "better-auth.session_token="+cookies["better-auth.session_token"]+"; better-auth.session_data="+v)
		}
	}
	cache, err := betterauth.GetCookieCache(headers, betterauth.CookieCacheOptions{Secret: secret})
	if err != nil || cache == nil {
		t.Fatalf("cookie cache %v %v", cache, err)
	}
	if cache.User.Email != "user-b@test.com" || cache.User.EmailVerified {
		t.Fatalf("cache user %+v", cache.User)
	}
	s := in.getSession(headers)
	if u := s["user"].(map[string]any); u["email"] != "user-b@test.com" || u["emailVerified"] != false {
		t.Fatalf("session user %v", u)
	}
}

func TestEmailOTPSendOriginCSRF(t *testing.T) {
	b := &box{}
	in := newInst(t, chain(func(c *betterauth.Config) {
		c.TrustedOrigins = []string{"http://localhost:3000"}
		c.Advanced = &betterauth.AdvancedConfig{DisableCSRFCheck: betterauth.Bool(false), DisableOriginCheck: betterauth.Bool(false)}
	}, withOTP(emailotp.Options{SendVerificationOTP: b.send})))
	c := in.client(false)
	t.Run("should block cross-site navigation to the send endpoint (no cookies)", func(t *testing.T) {
		b.clear()
		r := send(c, "attacker@evil.com", "sign-in", http.Header{"Sec-Fetch-Site": {"cross-site"}, "Sec-Fetch-Mode": {"navigate"},
			"Sec-Fetch-Dest": {"document"}, "Origin": {"https://evil.com"}})
		if r.Status != 403 || b.count() != 0 {
			t.Fatalf("status %d calls %d", r.Status, b.count())
		}
	})
	t.Run("should reject a cookieless cross-origin POST to the send endpoint", func(t *testing.T) {
		b.clear()
		r := send(c, "attacker@evil.com", "sign-in", http.Header{"Origin": {"https://evil.com"}})
		if r.Status != 403 || b.count() != 0 {
			t.Fatalf("status %d calls %d", r.Status, b.count())
		}
	})
	t.Run("should still allow a cookieless request with no Origin (server-to-server)", func(t *testing.T) {
		b.clear()
		r := send(c, testEmail, "email-verification")
		if r.Status != 200 || b.count() != 1 {
			t.Fatalf("status %d calls %d", r.Status, b.count())
		}
	})
}
