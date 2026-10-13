package phonenumber

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Ported from packages/better-auth/src/plugins/phone-number/phone-number.test.ts.
//
// Differences from the TypeScript suite:
//   - vi.useFakeTimers is replaced by moving the stored expiresAt into the past (expiry) or
//     by short sleeps (ordering of codes created in sequence).
//   - The bearer plugin is not used; the session cookie returned by the same response is.
//   - Monkey-patching internalAdapter.findVerificationValue (race test) is replaced by an
//     adapter wrapper that holds both concurrent lookups at the same barrier.

type otpBox struct {
	mu   sync.Mutex
	code string
}

func (b *otpBox) set(c string) { b.mu.Lock(); b.code = c; b.mu.Unlock() }
func (b *otpBox) get() string  { b.mu.Lock(); defer b.mu.Unlock(); return b.code }

func capture(b *otpBox) func(OTPData, *betterauth.EndpointContext) error {
	return func(d OTPData, _ *betterauth.EndpointContext) error { b.set(d.Code); return nil }
}

func tempEmail(phone string) string { return "temp-" + phone }

func header(c *client) http.Header { return http.Header{"Cookie": {c.cookieHeader()}} }

func sendOTP(c *client, phone string) *response {
	c.inst.t.Helper()
	return c.post("/phone-number/send-otp", map[string]any{"phoneNumber": phone})
}

func verify(c *client, body map[string]any) *response {
	c.inst.t.Helper()
	return c.post("/phone-number/verify", body)
}

func call(inst *instance, key string, body map[string]any) (*betterauth.CallResult, error) {
	return inst.auth.API.Call(context.Background(), key, betterauth.CallInput{Body: body})
}

func TestPhoneNumber(t *testing.T) {
	otp := &otpBox{}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, nil)
	signedIn := inst.client()
	const testPhoneNumber = "+251911121314"

	t.Run("should send verification code", func(t *testing.T) {
		expectOK(t, sendOTP(inst.client(), testPhoneNumber))
		eq(t, len(otp.get()), 6)
	})

	t.Run("should verify phone number", func(t *testing.T) {
		res := verify(signedIn, map[string]any{"phoneNumber": testPhoneNumber, "code": otp.get()})
		eq(t, expectOK(t, res)["status"], true)
	})

	t.Run("shouldn't verify again with the same code", func(t *testing.T) {
		eq(t, verify(inst.client(), map[string]any{"phoneNumber": testPhoneNumber, "code": otp.get()}).Status, 400)
	})

	t.Run("should update phone number", func(t *testing.T) {
		newPhone := "+0123456789"
		sendOTP(signedIn, newPhone)
		verify(signedIn, map[string]any{"phoneNumber": newPhone, "updatePhoneNumber": true, "code": otp.get()})
		u := signedIn.sessionUser()
		eq(t, u["phoneNumber"], newPhone)
		eq(t, u["phoneNumberVerified"], true)
	})

	t.Run("should not verify if code expired", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, "+25120201212")
		if _, err := inst.auth.Context().InternalAdapter.UpdateVerificationByIdentifier(context.Background(), "+25120201212",
			adapter.Record{"expiresAt": time.Now().Add(-time.Millisecond)}); err != nil {
			t.Fatal(err)
		}
		eq(t, verify(c, map[string]any{"phoneNumber": "+25120201212", "code": otp.get()}).Status, 400)
	})
}

func TestConsumePhoneNumberOTP(t *testing.T) {
	otp := &otpBox{}
	var callbacks atomic.Int32
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		CallbackOnVerification: func(VerificationData, *betterauth.EndpointContext) error { callbacks.Add(1); return nil }})}, nil,
		instanceOpts{disableTestUser: true})
	ac := inst.auth.Context()
	ctx := context.Background()

	t.Run("consumes an OTP server-side without creating a user or session", func(t *testing.T) {
		phone := "+251911121301"
		sendOTP(inst.client(), phone)
		res, err := call(inst, "consumePhoneNumberOTP", map[string]any{"phoneNumber": phone, "code": otp.get()})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := res.JSON()
		eq(t, string(b), `{"status":true}`)
		eq(t, callbacks.Load(), int32(0))
		users, err := ac.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "phoneNumber", Value: phone}}})
		if err != nil {
			t.Fatal(err)
		}
		eq(t, len(users), 0)
		v, err := ac.InternalAdapter.FindVerificationValue(ctx, phone)
		if err != nil || v != nil {
			t.Fatalf("expected no verification value: %v %v", v, err)
		}
	})

	t.Run("is exposed through the server API only", func(t *testing.T) {
		res := inst.client().post("/phone-number/consume-otp", map[string]any{"phoneNumber": "+251911121302", "code": "123456"})
		eq(t, res.Status, 404)
	})

	t.Run("keeps attempt limiting active when a stored attempt count is corrupt", func(t *testing.T) {
		phone := "+251911121303"
		c := inst.client()
		sendOTP(c, phone)
		if _, err := ac.InternalAdapter.UpdateVerificationByIdentifier(ctx, phone, adapter.Record{"value": otp.get() + ":not-a-number"}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			res := verify(c, map[string]any{"phoneNumber": phone, "code": "000000"})
			eq(t, res.Status, 400)
			eq(t, res.Message(), "Invalid OTP")
		}
		res := verify(c, map[string]any{"phoneNumber": phone, "code": "000000"})
		eq(t, res.Status, 403)
		eq(t, res.Message(), "Too many attempts")
	})

	t.Run("honors allowedAttempts set to 0", func(t *testing.T) {
		zeroOTP := &otpBox{}
		zero := 0
		inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(zeroOTP), AllowedAttempts: &zero})}, nil,
			instanceOpts{disableTestUser: true})
		phone := "+251911121304"
		sendOTP(inst.client(), phone)
		_, err := call(inst, "consumePhoneNumberOTP", map[string]any{"phoneNumber": phone, "code": zeroOTP.get()})
		e, ok := betterauth.AsAPIError(err)
		if !ok || e.Message() != "Too many attempts" {
			t.Fatalf("expected Too many attempts, got %v", err)
		}
	})
}

func TestPhoneNumberCallbackOnVerificationOnUpdatePhoneNumber(t *testing.T) {
	otp := &otpBox{}
	var mu sync.Mutex
	var calls []VerificationData
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		CallbackOnVerification: func(d VerificationData, ctx *betterauth.EndpointContext) error {
			if ctx == nil {
				return errors.New("missing ctx")
			}
			mu.Lock()
			calls = append(calls, d)
			mu.Unlock()
			return nil
		},
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, nil)
	t.Run("fires when verifying a new phone number on an authenticated session", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, "+251911121314")
		verify(c, map[string]any{"phoneNumber": "+251911121314", "code": otp.get()})
		mu.Lock()
		calls = nil
		mu.Unlock()
		sendOTP(c, "+0123456789")
		res := verify(c, map[string]any{"phoneNumber": "+0123456789", "updatePhoneNumber": true, "code": otp.get()})
		eq(t, expectOK(t, res)["status"], true)
		eq(t, len(calls), 1)
		eq(t, calls[0].PhoneNumber, "+0123456789")
		eq(t, calls[0].User.Additional["phoneNumber"], "+0123456789")
		eq(t, calls[0].User.Additional["phoneNumberVerified"], true)
	})
}

func TestPhoneNumberSendOTPErrorHandling(t *testing.T) {
	var calls atomic.Int32
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: func(OTPData, *betterauth.EndpointContext) error {
		calls.Add(1)
		return errors.New("SMS provider error")
	}})}, nil)
	t.Run("should return an error when sendOTP fails without background tasks", func(t *testing.T) {
		res := sendOTP(inst.client(), "+251922334455")
		eq(t, calls.Load(), int32(1))
		eq(t, res.Status, 500)
	})
}

func TestPhoneNumberSendOTPBackgroundTaskHandling(t *testing.T) {
	sent := make(chan struct{}, 1)
	var handlerCalls atomic.Int32
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: func(OTPData, *betterauth.EndpointContext) error {
		sent <- struct{}{}
		return errors.New("SMS provider error")
	}})}, func(c *betterauth.Config) {
		c.Advanced = &betterauth.AdvancedConfig{BackgroundTasks: func(fn func()) { handlerCalls.Add(1); go fn() }}
	})
	t.Run("should keep succeeding when sendOTP fails in a background task", func(t *testing.T) {
		res := sendOTP(inst.client(), "+251955667788")
		<-sent
		eq(t, handlerCalls.Load(), int32(1))
		eq(t, expectOK(t, res)["message"], "code sent")
	})
}

func TestPhoneNumberSendOTPBackgroundHandlerFailures(t *testing.T) {
	sent := make(chan struct{}, 1)
	var handlerCalls atomic.Int32
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: func(OTPData, *betterauth.EndpointContext) error {
		sent <- struct{}{}
		return nil
	}})}, func(c *betterauth.Config) {
		c.Advanced = &betterauth.AdvancedConfig{BackgroundTasks: func(func()) {
			handlerCalls.Add(1)
			panic("Background task handler error")
		}}
	})
	t.Run("should keep succeeding when the background task handler throws", func(t *testing.T) {
		res := sendOTP(inst.client(), "+251988776655")
		<-sent
		eq(t, handlerCalls.Load(), int32(1))
		eq(t, expectOK(t, res)["message"], "code sent")
	})
}

func TestPhoneAuthFlow(t *testing.T) {
	otp := &otpBox{}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ChangeEmail: &betterauth.ChangeEmailConfig{Enabled: true, UpdateEmailWithoutVerification: true}}
	})
	signedIn := inst.client()
	const newEmail = "new-email@email.com"

	t.Run("should send otp", func(t *testing.T) {
		expectOK(t, sendOTP(inst.client(), "+251911121314"))
		eq(t, len(otp.get()), 6)
	})

	t.Run("should verify phone number and create user & session", func(t *testing.T) {
		c := inst.client()
		res := verify(c, map[string]any{"phoneNumber": "+251911121314", "code": otp.get()})
		if tok, _ := expectOK(t, res)["token"].(string); tok == "" {
			t.Fatal("expected token")
		}
		s := c.get("/get-session").JSON()
		u := s["user"].(map[string]any)
		eq(t, u["phoneNumberVerified"], true)
		eq(t, u["email"], "temp-+251911121314")
		if s["session"].(map[string]any)["token"] == nil {
			t.Fatal("expected session token")
		}
	})

	t.Run("should go through send-verify and sign-in the user", func(t *testing.T) {
		sendOTP(signedIn, "+251911121314")
		eq(t, expectOK(t, verify(signedIn, map[string]any{"phoneNumber": "+251911121314", "code": otp.get()}))["status"], true)
	})

	t.Run("should set password and update user", func(t *testing.T) {
		if _, err := inst.auth.API.SetPassword(context.Background(), "password", header(signedIn)); err != nil {
			t.Fatal(err)
		}
		res := signedIn.post("/change-email", map[string]any{"newEmail": newEmail})
		eq(t, expectOK(t, res)["status"], true)
		userID := signedIn.sessionUser()["id"].(string)
		acc, err := inst.auth.Context().InternalAdapter.FindCredentialAccount(context.Background(), userID)
		if err != nil || acc == nil {
			t.Fatalf("credential account: %v", err)
		}
		eq(t, acc.UserID, userID)
		eq(t, acc.ProviderID, "credential")
		eq(t, acc.AccountID, userID)
		signIn := inst.client().post("/sign-in/email", map[string]any{"email": newEmail, "password": "password"})
		eq(t, expectOK(t, signIn)["user"].(map[string]any)["id"], userID)
	})

	t.Run("should sign in with phone number and password", func(t *testing.T) {
		res := inst.client().post("/sign-in/phone-number", map[string]any{"phoneNumber": "+251911121314", "password": "password"})
		if tok, _ := expectOK(t, res)["token"].(string); tok == "" {
			t.Fatal("expected token")
		}
	})

	t.Run("should sign in with new email", func(t *testing.T) {
		expectOK(t, inst.client().post("/sign-in/email", map[string]any{"email": newEmail, "password": "password"}))
	})
}

func TestVerifyPhoneNumber(t *testing.T) {
	otp := &otpBox{}
	three := 3
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp), AllowedAttempts: &three,
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, nil)
	const phone = "+251911121314"

	t.Run("should verify the last code", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, phone)
		time.Sleep(5 * time.Millisecond)
		sendOTP(c, phone)
		time.Sleep(5 * time.Millisecond)
		sendOTP(c, phone)
		eq(t, expectOK(t, verify(c, map[string]any{"phoneNumber": phone, "code": otp.get()}))["status"], true)
	})

	t.Run("should block after exceeding allowed attempts", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, phone)
		for i := 0; i < 3; i++ {
			res := verify(c, map[string]any{"phoneNumber": phone, "code": "000000"})
			eq(t, res.Status, 400)
			eq(t, res.Message(), "Invalid OTP")
		}
		res := verify(c, map[string]any{"phoneNumber": phone, "code": "000000"})
		eq(t, res.Status, 403)
		eq(t, res.Message(), "Too many attempts")
	})
}

// barrierAdapter holds the first two verification lookups for an identifier until both
// have arrived (the Promise barrier in the upstream race test).
type barrierAdapter struct {
	adapter.Adapter
	identifier string
	mu         sync.Mutex
	entered    int
	release    chan struct{}
}

func (b *barrierAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	res, err := b.Adapter.FindMany(ctx, in)
	if in.Model == "verification" && len(in.Where) == 1 && in.Where[0].Value == b.identifier && !betterauth.InTransaction(ctx) {
		b.mu.Lock()
		b.entered++
		n := b.entered
		if n == 2 {
			close(b.release)
		}
		b.mu.Unlock()
		if n <= 2 {
			<-b.release
		}
	}
	return res, err
}

func (b *barrierAdapter) PlanMigrations(ctx context.Context, s *db.Schema) (*adapter.MigrationPlan, error) {
	m, _ := adapter.AsMigrator(b.Adapter)
	return m.PlanMigrations(ctx, s)
}

func TestVerifyPhoneNumberRaceConditionProtection(t *testing.T) {
	otp := &otpBox{}
	three := 3
	barrier := &barrierAdapter{identifier: "+251900000001", release: make(chan struct{})}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp), AllowedAttempts: &three,
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, func(c *betterauth.Config) {
		orig := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := orig(o)
			barrier.Adapter = a
			return barrier, err
		}
	})
	ac := inst.auth.Context()
	ctx := context.Background()

	t.Run("should allow exactly one success when the same code is verified concurrently", func(t *testing.T) {
		phone := "+251900000001"
		sendOTP(inst.client(), phone)
		results := make([]*response, 2)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = verify(inst.client(), map[string]any{"phoneNumber": phone, "code": otp.get()})
			}(i)
		}
		wg.Wait()
		var successes, failures []*response
		for _, r := range results {
			if r.Status == 200 && r.JSON()["status"] == true {
				successes = append(successes, r)
			} else {
				failures = append(failures, r)
			}
		}
		eq(t, len(successes), 1)
		eq(t, len(failures), 1)
		eq(t, failures[0].Status, 400)
		eq(t, failures[0].Message(), "Invalid OTP")
		v, err := ac.InternalAdapter.FindVerificationValue(ctx, phone)
		if err != nil || v != nil {
			t.Fatalf("expected consumed verification: %v %v", v, err)
		}
	})

	t.Run("should increment the stored attempt counter by exactly one per wrong code", func(t *testing.T) {
		phone := "+251900000002"
		c := inst.client()
		sendOTP(c, phone)
		correct := otp.get()
		for expected := 1; expected <= 2; expected++ {
			res := verify(c, map[string]any{"phoneNumber": phone, "code": "000000"})
			eq(t, res.Status, 400)
			eq(t, res.Message(), "Invalid OTP")
			stored, err := ac.InternalAdapter.FindVerificationValue(ctx, phone)
			if err != nil || stored == nil {
				t.Fatalf("expected stored value: %v", err)
			}
			eq(t, stored.Value, correct+":"+string(rune('0'+expected)))
		}
		eq(t, expectOK(t, verify(c, map[string]any{"phoneNumber": phone, "code": correct}))["status"], true)
		v, err := ac.InternalAdapter.FindVerificationValue(ctx, phone)
		if err != nil || v != nil {
			t.Fatalf("expected consumed verification: %v %v", v, err)
		}
	})
}

func TestResetPasswordFlowAttempts(t *testing.T) {
	otp, resetOTP := &otpBox{}, &otpBox{}
	three := 3
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp), SendPasswordResetOTP: capture(resetOTP),
		AllowedAttempts: &three, SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, nil)
	const phone = "+251911121314"
	reset := func(c *client, phone, code string) *response {
		return c.post("/phone-number/reset-password", map[string]any{"phoneNumber": phone, "otp": code, "newPassword": "password"})
	}

	t.Run("should block reset password after exceeding allowed attempts", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, phone)
		verify(c, map[string]any{"phoneNumber": phone, "code": otp.get()})
		c.post("/phone-number/request-password-reset", map[string]any{"phoneNumber": phone})
		wrong := otp.get()
		if wrong == resetOTP.get() {
			wrong = "x" + wrong
		}
		for i := 0; i < 3; i++ {
			res := reset(c, phone, wrong)
			eq(t, res.Status, 400)
			eq(t, res.Message(), "Invalid OTP")
		}
		res := reset(c, phone, wrong)
		eq(t, res.Status, 403)
		eq(t, res.Message(), "Too many attempts")
	})

	t.Run("should successfully reset password with correct code", func(t *testing.T) {
		c := inst.client()
		c.post("/phone-number/request-password-reset", map[string]any{"phoneNumber": phone})
		eq(t, expectOK(t, reset(c, phone, resetOTP.get()))["status"], true)
	})

	t.Run("should reset password and create credential account", func(t *testing.T) {
		c := inst.client()
		email, phone2 := "test-user2@email.com", "+2519111213142"
		sendOTP(c, phone2)
		if _, err := inst.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "user", Data: adapter.Record{
			"name": "Test User", "email": email, "phoneNumber": phone2}}); err != nil {
			t.Fatal(err)
		}
		c.post("/phone-number/request-password-reset", map[string]any{"phoneNumber": phone2})
		reset(c, phone2, resetOTP.get())
		res := c.post("/sign-in/email", map[string]any{"email": email, "password": "password"})
		d := expectOK(t, res)
		userID := d["user"].(map[string]any)["id"].(string)
		acc, err := inst.auth.Context().InternalAdapter.FindCredentialAccount(context.Background(), userID)
		if err != nil || acc == nil {
			t.Fatalf("credential account: %v", err)
		}
		eq(t, acc.UserID, userID)
		eq(t, acc.ProviderID, "credential")
		eq(t, acc.AccountID, userID)
	})

	t.Run("shouldn't allow to re-use the same OTP code", func(t *testing.T) {
		eq(t, reset(inst.client(), phone, resetOTP.get()).Status, 400)
	})
}

func TestResetPasswordSessionRevocation(t *testing.T) {
	otp, resetOTP := &otpBox{}, &otpBox{}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp), SendPasswordResetOTP: capture(resetOTP),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, func(c *betterauth.Config) {
		c.EmailAndPassword.RevokeSessionsOnPasswordReset = true
	})
	t.Run("should revoke all sessions after password reset when configured", func(t *testing.T) {
		const phone = "+251911000000"
		c := inst.client()
		sendOTP(c, phone)
		expectOK(t, verify(c, map[string]any{"phoneNumber": phone, "code": otp.get()}))
		if c.sessionUser() == nil {
			t.Fatal("expected session")
		}
		other := inst.client()
		other.post("/phone-number/request-password-reset", map[string]any{"phoneNumber": phone})
		res := other.post("/phone-number/reset-password", map[string]any{"phoneNumber": phone, "otp": resetOTP.get(), "newPassword": "new-secure-password"})
		eq(t, expectOK(t, res)["status"], true)
		eq(t, string(c.get("/get-session").Body), "null")
	})
}

func TestResetPasswordOnPasswordResetCallback(t *testing.T) {
	otp, resetOTP := &otpBox{}, &otpBox{}
	var resetUsers []*betterauth.User
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp), SendPasswordResetOTP: capture(resetOTP),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, func(c *betterauth.Config) {
		c.EmailAndPassword.OnPasswordReset = func(_ context.Context, u *betterauth.User, r *http.Request) error {
			if r == nil {
				return errors.New("missing request")
			}
			resetUsers = append(resetUsers, u)
			return nil
		}
	})
	t.Run("should call onPasswordReset after phone number password reset", func(t *testing.T) {
		const phone = "+251911999888"
		c := inst.client()
		sendOTP(c, phone)
		verify(c, map[string]any{"phoneNumber": phone, "code": otp.get()})
		c.post("/phone-number/request-password-reset", map[string]any{"phoneNumber": phone})
		res := c.post("/phone-number/reset-password", map[string]any{"phoneNumber": phone, "otp": resetOTP.get(), "newPassword": "new-password-123"})
		eq(t, expectOK(t, res)["status"], true)
		eq(t, len(resetUsers), 1)
		eq(t, resetUsers[0].Additional["phoneNumber"], phone)
	})
}

func TestPhoneNumberVerificationRequirement(t *testing.T) {
	otp := &otpBox{}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp), RequireVerification: true,
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ChangeEmail: &betterauth.ChangeEmailConfig{Enabled: true}}
	})
	t.Run("should not allow sign in with unverified phone number and trigger OTP send", func(t *testing.T) {
		c := inst.client()
		c.post("/sign-up/email", map[string]any{"email": "test2@test.com", "password": "password123", "name": "test", "phoneNumber": "+251911121314"})
		res := c.post("/sign-in/phone-number", map[string]any{"phoneNumber": "+251911121314", "password": "password123"})
		expectStatus(t, res, 401, "PHONE_NUMBER_NOT_VERIFIED")
		eq(t, len(otp.get()), 6)
	})
}

func TestUpdateUserPhoneNumberUpdatePrevention(t *testing.T) {
	otp := &otpBox{}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, nil)
	t.Run("should prevent updating phone number via updateUser", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, "+251911121314")
		eq(t, expectOK(t, verify(c, map[string]any{"phoneNumber": "+251911121314", "code": otp.get()}))["status"], true)
		u := c.sessionUser()
		eq(t, u["phoneNumberVerified"], true)
		eq(t, u["phoneNumber"], "+251911121314")
		res := c.post("/update-user", map[string]any{"phoneNumber": "+9876543210"})
		eq(t, res.Status, 400)
		eq(t, res.Message(), "Phone number cannot be updated")
		u = c.sessionUser()
		eq(t, u["phoneNumberVerified"], true)
		eq(t, u["phoneNumber"], "+251911121314")
	})
}

func TestUpdateUserPhoneNumberDisassociation(t *testing.T) {
	otp := &otpBox{}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, nil)
	original, reclaimer := inst.client(), inst.client()
	const shared = "+251911121314"

	t.Run("should null phone number and reset verified flag atomically", func(t *testing.T) {
		sendOTP(original, shared)
		expectOK(t, verify(original, map[string]any{"phoneNumber": shared, "code": otp.get()}))
		expectOK(t, original.post("/update-user", map[string]any{"phoneNumber": nil}))
		u := original.sessionUser()
		eq(t, u["phoneNumber"], nil)
		eq(t, u["phoneNumberVerified"], false)
	})

	t.Run("should let another user claim the released number via verify", func(t *testing.T) {
		reclaimer.post("/sign-up/email", map[string]any{"email": "reclaimer@test.com", "password": "password123", "name": "reclaimer"})
		sendOTP(reclaimer, shared)
		expectOK(t, verify(reclaimer, map[string]any{"phoneNumber": shared, "code": otp.get(), "updatePhoneNumber": true}))
		u := reclaimer.sessionUser()
		eq(t, u["phoneNumber"], shared)
		eq(t, u["phoneNumberVerified"], true)
		eq(t, original.sessionUser()["phoneNumber"], nil)
	})
}

func TestSignUpOnVerificationWithAdditionalFields(t *testing.T) {
	otp := &otpBox{}
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: func(p string) string { return "temp-" + p + "@example.com" }}})},
		func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
				{Name: "lastName", Type: db.TypeString, Required: db.True},
				{Name: "dateOfBirth", Type: db.TypeDate, Required: db.False},
			}}}
		}, instanceOpts{disableTestUser: true})
	t.Run("should create user with additional fields from body", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, "+1234567890")
		d := expectOK(t, verify(c, map[string]any{"phoneNumber": "+1234567890", "code": otp.get(), "lastName": "Doe"}))
		eq(t, d["status"], true)
		eq(t, d["user"].(map[string]any)["lastName"], "Doe")
	})
}

func TestCustomVerifyOTP(t *testing.T) {
	var mu sync.Mutex
	var next []bool
	var calls []OTPData
	mock := func(d OTPData, ctx *betterauth.EndpointContext) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if ctx == nil {
			return false, errors.New("missing ctx")
		}
		calls = append(calls, d)
		if len(next) == 0 {
			return false, nil
		}
		v := next[0]
		next = next[1:]
		return v, nil
	}
	once := func(v bool) { mu.Lock(); next = append(next, v); mu.Unlock() }
	lastCall := func() OTPData { mu.Lock(); defer mu.Unlock(); return calls[len(calls)-1] }
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: func(OTPData, *betterauth.EndpointContext) error { return nil },
		VerifyOTP: mock, SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, nil)
	signedIn := inst.client()

	t.Run("should call custom verifyOTP when provided", func(t *testing.T) {
		sendOTP(signedIn, "+1234567890")
		once(true)
		eq(t, expectOK(t, verify(signedIn, map[string]any{"phoneNumber": "+1234567890", "code": "123456"}))["status"], true)
		eq(t, lastCall(), OTPData{PhoneNumber: "+1234567890", Code: "123456"})
	})

	t.Run("should reject verification when custom verifyOTP returns false", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, "+9876543210")
		once(false)
		res := verify(c, map[string]any{"phoneNumber": "+9876543210", "code": "wrong-code"})
		eq(t, res.Status, 400)
		eq(t, res.Message(), "Invalid OTP")
		eq(t, lastCall(), OTPData{PhoneNumber: "+9876543210", Code: "wrong-code"})
	})

	t.Run("should not use internal verification logic when custom verifyOTP is provided", func(t *testing.T) {
		once(true)
		eq(t, expectOK(t, verify(inst.client(), map[string]any{"phoneNumber": "+5555555555", "code": "external-code"}))["status"], true)
		eq(t, lastCall(), OTPData{PhoneNumber: "+5555555555", Code: "external-code"})
	})

	t.Run("should work with updatePhoneNumber using custom verifyOTP", func(t *testing.T) {
		once(true)
		eq(t, expectOK(t, verify(signedIn, map[string]any{"phoneNumber": "+1111111111", "code": "123456", "updatePhoneNumber": true}))["status"], true)
		u := signedIn.sessionUser()
		eq(t, u["phoneNumber"], "+1111111111")
		eq(t, u["phoneNumberVerified"], true)
	})

	t.Run("should delegate server-side consumption to custom verifyOTP without an internal record", func(t *testing.T) {
		once(true)
		res, err := call(inst, "consumePhoneNumberOTP", map[string]any{"phoneNumber": "+12223334444", "code": "external-code"})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := res.JSON()
		eq(t, string(b), `{"status":true}`)
		eq(t, lastCall(), OTPData{PhoneNumber: "+12223334444", Code: "external-code"})
	})
}

func TestPhoneNumberValidateUserInfoProvisioningGate(t *testing.T) {
	otp := &otpBox{}
	var actionErr error
	inst := newInstance(t, []*betterauth.Plugin{New(Options{SendOTP: capture(otp),
		SignUpOnVerification: &SignUpOnVerification{GetTempEmail: tempEmail}})}, func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, _ map[string]any, s betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
			if s.Method != "phone-number" {
				return nil, nil
			}
			if s.Action != "create-user" {
				actionErr = errors.New("unexpected action " + s.Action)
			}
			return &betterauth.ValidateUserInfoResult{Error: "phone_blocked", ErrorDescription: "Phone sign-up is not allowed"}, nil
		}}
	}, instanceOpts{disableTestUser: true})
	t.Run("rejects phone-number sign-up when validateUserInfo returns error", func(t *testing.T) {
		c := inst.client()
		sendOTP(c, "+251900000000")
		expectStatus(t, verify(c, map[string]any{"phoneNumber": "+251900000000", "code": otp.get()}), 403, "phone_blocked")
		if actionErr != nil {
			t.Fatal(actionErr)
		}
	})
}

func TestPhoneNumberSignInPasswordLength(t *testing.T) {
	var hashCalls, verifyCalls atomic.Int32
	inst := newInstance(t, []*betterauth.Plugin{New(Options{})}, func(c *betterauth.Config) {
		c.EmailAndPassword.Password = &betterauth.PasswordConfig{
			Hash:   func(pw string) (string, error) { hashCalls.Add(1); return "hashed:" + pw, nil },
			Verify: func(h, pw string) (bool, error) { verifyCalls.Add(1); return h == "hashed:"+pw, nil },
		}
	})
	t.Run("should reject a password longer than maxPasswordLength before hashing", func(t *testing.T) {
		ctx := context.Background()
		if _, err := inst.auth.API.SignUpEmail(ctx, betterauth.SignUpEmailInput{Email: "long-password@test.com", Password: "password",
			Name: "Long Password", Additional: map[string]any{"phoneNumber": "+251911121314"}}, nil); err != nil {
			t.Fatal(err)
		}
		hashCalls.Store(0)
		verifyCalls.Store(0)
		_, err := call(inst, "signInPhoneNumber", map[string]any{"phoneNumber": "+251911121314", "password": strings.Repeat("x", 129)})
		e, ok := betterauth.AsAPIError(err)
		if !ok || e.Status != "BAD_REQUEST" || e.Code() != "PASSWORD_TOO_LONG" {
			t.Fatalf("unexpected error %v", err)
		}
		eq(t, hashCalls.Load(), int32(0))
		eq(t, verifyCalls.Load(), int32(0))
	})
}
