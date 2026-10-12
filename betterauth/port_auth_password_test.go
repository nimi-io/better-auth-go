package betterauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

// Port of better-auth/src/api/routes/password.test.ts

// paTokenFromURL mirrors `url.split("?")[0].split("/").pop()`.
func paTokenFromURL(u string) string {
	p := strings.SplitN(u, "?", 2)[0]
	parts := strings.Split(p, "/")
	return parts[len(parts)-1]
}

func paAccountTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		tt, _ := time.Parse(time.RFC3339Nano, t)
		return tt
	}
	return time.Time{}
}

// describe("forgot password")
func TestPortAuthForgotPassword(t *testing.T) {
	var mu sync.Mutex
	token := ""
	getToken := func() string { mu.Lock(); defer mu.Unlock(); return token }
	sendEmail := &paMock{}
	onReset := &paMock{}
	env := paNewEnv(t, func(c *Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, d EmailData, _ *http.Request) error {
			mu.Lock()
			token = paTokenFromURL(d.URL)
			mu.Unlock()
			sendEmail.record()
			return nil
		}
		c.EmailAndPassword.OnPasswordReset = func(_ context.Context, u *User, _ *http.Request) error {
			onReset.record(u)
			return nil
		}
	})
	tu := env.testUser

	t.Run("should send a reset password email when enabled", func(t *testing.T) {
		env.do("POST", "/request-password-reset", map[string]any{"email": tu.Email, "redirectTo": "http://localhost:3000"}, nil)
		if len(getToken()) <= 10 {
			t.Fatalf("token %q should be longer than 10", getToken())
		}
	})

	t.Run("should reject untrusted redirectTo", func(t *testing.T) {
		inst := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(context.Context, EmailData, *http.Request) error { return nil }
			c.TrustedOrigins = []string{"http://localhost:3000"}
			c.Advanced = &AdvancedConfig{DisableOriginCheck: Bool(false)}
		})
		res := inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": "http://malicious.com"}, nil)
		if res.Status != 403 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if m := res.JSON(t); m["message"] != "Invalid redirectURL" {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should fail on invalid password", func(t *testing.T) {
		res := env.do("POST", "/reset-password?token="+url.QueryEscape(getToken()), map[string]any{"newPassword": "short"}, nil)
		if res.Status != 400 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
	})

	t.Run("should verify the token", func(t *testing.T) {
		res := env.do("POST", "/reset-password?token="+url.QueryEscape(getToken()), map[string]any{"newPassword": "new-password"}, nil)
		if res.Status != 200 || res.JSON(t)["status"] != true {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})

	t.Run("should update account's updatedAt when resetting password", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", map[string]any{"name": "Test Reset User", "email": "test-reset-updated@email.com", "password": "originalPassword123"}, nil)
		if res.Status != 200 {
			t.Fatalf("sign-up: %d %s", res.Status, res.Body)
		}
		userID, _ := res.JSON(t)["user"].(map[string]any)["id"].(string)
		if userID == "" {
			t.Fatalf("userId should be defined")
		}
		credAccounts := func() []adapter.Record {
			var out []adapter.Record
			for _, a := range env.db.Rows("account") {
				if a["userId"] == userID && a["providerId"] == "credential" {
					out = append(out, a)
				}
			}
			return out
		}
		initial := credAccounts()
		if len(initial) != 1 {
			t.Fatalf("expected 1 credential account, got %d", len(initial))
		}
		initialUpdatedAt := paAccountTime(initial[0]["updatedAt"])

		env.do("POST", "/request-password-reset", map[string]any{"email": "test-reset-updated@email.com", "redirectTo": "http://localhost:3000"}, nil)
		resetToken := getToken()
		if resetToken == "" {
			t.Fatalf("token should be defined")
		}
		time.Sleep(100 * time.Millisecond)

		rr := env.do("POST", "/reset-password", map[string]any{"newPassword": "newResetPassword123", "token": resetToken}, nil)
		if rr.Status != 200 || rr.JSON(t)["status"] != true {
			t.Fatalf("reset: %d %s", rr.Status, rr.Body)
		}
		updated := credAccounts()
		if len(updated) != 1 {
			t.Fatalf("expected 1 credential account, got %d", len(updated))
		}
		if updated[0]["providerId"] != "credential" || updated[0]["accountId"] != userID {
			t.Fatalf("account = %v", updated[0])
		}
		newUpdatedAt := paAccountTime(updated[0]["updatedAt"])
		if !newUpdatedAt.After(initialUpdatedAt) {
			t.Fatalf("updatedAt not refreshed: %v -> %v", initialUpdatedAt, newUpdatedAt)
		}
		sr := env.do("POST", "/sign-in/email", map[string]any{"email": "test-reset-updated@email.com", "password": "newResetPassword123"}, nil)
		if sr.Status != 200 || sr.JSON(t)["user"] == nil {
			t.Fatalf("sign-in: %d %s", sr.Status, sr.Body)
		}
	})

	t.Run("should sign-in with the new password", func(t *testing.T) {
		old := env.do("POST", "/sign-in/email", map[string]any{"email": tu.Email, "password": tu.Email}, nil)
		if old.Status != 401 {
			t.Fatalf("old credentials: status = %d", old.Status)
		}
		nc := env.do("POST", "/sign-in/email", map[string]any{"email": tu.Email, "password": "new-password"}, nil)
		if nc.Status != 200 || nc.JSON(t)["user"] == nil {
			t.Fatalf("new credentials: %d %s", nc.Status, nc.Body)
		}
	})

	t.Run("shouldn't allow the token to be used twice", func(t *testing.T) {
		// Note: the shared token now belongs to the last reset request (test-reset-updated),
		// which has already been consumed, exactly as upstream.
		res := env.do("POST", "/reset-password?token="+url.QueryEscape(getToken()), map[string]any{"newPassword": "new-password"}, nil)
		if res.Status != 400 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
	})

	t.Run("should reject a concurrent reset using the same token", func(t *testing.T) {
		email := "race-reset@email.com"
		env.do("POST", "/sign-up/email", map[string]any{"name": "Race Reset User", "email": email, "password": "originalPassword123"}, nil)
		env.do("POST", "/request-password-reset", map[string]any{"email": email, "redirectTo": "http://localhost:3000"}, nil)
		raceToken := getToken()
		passwords := []string{"legitimate-password-123", "attacker-password-123"}
		results := make([]*paResponse, 2)
		var wg sync.WaitGroup
		for i := range passwords {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = env.do("POST", "/reset-password?token="+url.QueryEscape(raceToken), map[string]any{"newPassword": passwords[i]}, nil)
			}(i)
		}
		wg.Wait()
		succeeded, rejected, winner := 0, 0, -1
		for i, r := range results {
			if r.Status == 200 && r.JSON(t)["status"] == true {
				succeeded++
				winner = i
			} else if r.Status == 400 {
				rejected++
			}
		}
		if succeeded != 1 || rejected != 1 {
			t.Fatalf("succeeded=%d rejected=%d (%d %s / %d %s)", succeeded, rejected, results[0].Status, results[0].Body, results[1].Status, results[1].Body)
		}
		win := env.do("POST", "/sign-in/email", map[string]any{"email": email, "password": passwords[winner]}, nil)
		if win.Status != 200 {
			t.Fatalf("winning password sign-in: %d %s", win.Status, win.Body)
		}
		lose := env.do("POST", "/sign-in/email", map[string]any{"email": email, "password": passwords[1-winner]}, nil)
		if lose.Status != 401 {
			t.Fatalf("losing password sign-in: status = %d", lose.Status)
		}
	})

	t.Run("should expire", func(t *testing.T) {
		// Upstream uses resetPasswordTokenExpiresIn: 10 (seconds) with fake timers advanced by
		// 9s / 11s. Go has no fake clock, so the same scenario runs on a 1s expiry with real
		// sleeps of 0.9s / 1.1s.
		var tmu sync.Mutex
		tok := ""
		onPasswordReset := &paMock{}
		inst := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(_ context.Context, d EmailData, _ *http.Request) error {
				tmu.Lock()
				tok = d.Token
				tmu.Unlock()
				return nil
			}
			c.EmailAndPassword.ResetPasswordTokenExpiresIn = time.Second
			c.EmailAndPassword.OnPasswordReset = func(_ context.Context, u *User, _ *http.Request) error {
				onPasswordReset.record(u)
				return nil
			}
		})
		curTok := func() string { tmu.Lock(); defer tmu.Unlock(); return tok }
		_, headers := inst.signInWithTestUser()
		inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": "/sign-in"}, paHeaderMap(headers))
		time.Sleep(900 * time.Millisecond)
		cb := inst.do("GET", "/reset-password/"+curTok()+"?callbackURL=/cb", nil, nil)
		loc := cb.Header.Get("Location")
		if strings.Contains(loc, "error") || !strings.Contains(loc, "token") {
			t.Fatalf("callback location = %q (status %d)", loc, cb.Status)
		}
		res := inst.do("POST", "/reset-password", map[string]any{"newPassword": "new-password", "token": curTok()}, nil)
		if res.Status != 200 || res.JSON(t)["status"] != true {
			t.Fatalf("reset: %d %s", res.Status, res.Body)
		}
		if onPasswordReset.count() != 1 {
			t.Fatalf("onPasswordReset called %d times", onPasswordReset.count())
		}
		inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": "/sign-in"}, paHeaderMap(headers))
		time.Sleep(1100 * time.Millisecond)
		res2 := inst.do("POST", "/reset-password", map[string]any{"newPassword": "new-password", "token": curTok()}, nil)
		if onPasswordReset.count() != 1 {
			t.Fatalf("onPasswordReset called %d times, want 1", onPasswordReset.count())
		}
		if res2.Status != 400 {
			t.Fatalf("expired token: status = %d: %s", res2.Status, res2.Body)
		}
	})

	t.Run("should allow callbackURL to have multiple query params", func(t *testing.T) {
		var u string
		inst := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(_ context.Context, d EmailData, _ *http.Request) error {
				u = d.URL
				return nil
			}
			c.EmailAndPassword.ResetPasswordTokenExpiresIn = 10 * time.Second
		})
		queryParams := "foo=bar&baz=qux"
		redirectTo := "http://localhost:3000?" + queryParams
		res := inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": redirectTo}, nil)
		if res.Status != 200 || res.JSON(t)["status"] != true {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
		if strings.Contains(u, queryParams) {
			t.Fatalf("url %q should not contain raw query params", u)
		}
		if !strings.Contains(u, "callbackURL="+EncodeURIComponent(redirectTo)) {
			t.Fatalf("url %q should contain encoded callbackURL", u)
		}
	})

	const genericMsg = "If this email exists in our system, check your email for the reset link"

	t.Run("should not reveal user existence on success", func(t *testing.T) {
		inst := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(context.Context, EmailData, *http.Request) error { sendEmail.record(); return nil }
		})
		res := inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": "http://localhost:3000"}, nil)
		if m := res.JSON(t); m["message"] != genericMsg {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should not reveal user existence on failure", func(t *testing.T) {
		inst := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(context.Context, EmailData, *http.Request) error { sendEmail.record(); return nil }
		})
		res := inst.do("POST", "/request-password-reset", map[string]any{"email": "non-existent-user@email.com", "redirectTo": "http://localhost:3000"}, nil)
		if m := res.JSON(t); m["message"] != genericMsg {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should not reveal failure of email sending", func(t *testing.T) {
		inst := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(context.Context, EmailData, *http.Request) error {
				return errors.New("Failed to send email")
			}
		})
		res := inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": "http://localhost:3000"}, nil)
		m := res.JSON(t)
		if m["status"] != true || m["message"] != genericMsg {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})
}

// describe("revoke sessions on password reset")
func TestPortAuthRevokeSessionsOnPasswordReset(t *testing.T) {
	newInst := func(t *testing.T, revoke bool) (*paEnv, func() string) {
		var mu sync.Mutex
		token := ""
		inst := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.SendResetPassword = func(_ context.Context, d EmailData, _ *http.Request) error {
				mu.Lock()
				token = paTokenFromURL(d.URL)
				mu.Unlock()
				return nil
			}
			c.EmailAndPassword.RevokeSessionsOnPasswordReset = revoke
		})
		return inst, func() string { mu.Lock(); defer mu.Unlock(); return token }
	}

	t.Run("should revoke other sessions when revokeSessionsOnPasswordReset is enabled", func(t *testing.T) {
		inst, tok := newInst(t, true)
		_, headers := inst.signInWithTestUser()
		inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": "http://localhost:3000"}, nil)
		inst.do("POST", "/reset-password?token="+url.QueryEscape(tok()), map[string]any{"newPassword": "new-password"}, nil)
		res := inst.do("GET", "/get-session", nil, paHeaderMap(headers))
		if string(res.Body) != "null" {
			t.Fatalf("session should be null, got %d %s", res.Status, res.Body)
		}
	})

	t.Run("should not revoke other sessions by default", func(t *testing.T) {
		inst, tok := newInst(t, false)
		_, headers := inst.signInWithTestUser()
		inst.do("POST", "/request-password-reset", map[string]any{"email": inst.testUser.Email, "redirectTo": "http://localhost:3000"}, nil)
		inst.do("POST", "/reset-password?token="+url.QueryEscape(tok()), map[string]any{"newPassword": "new-password"}, nil)
		res := inst.do("GET", "/get-session", nil, paHeaderMap(headers))
		if res.Status != 200 || string(res.Body) == "null" || res.JSON(t)["user"] == nil {
			t.Fatalf("session user should be defined, got %d %s", res.Status, res.Body)
		}
	})
}

// describe("verify password")
func TestPortAuthVerifyPassword(t *testing.T) {
	env := paNewEnv(t, nil)
	getSessionHeaders := func(t *testing.T) http.Header {
		_, res := env.mustCall("signInEmail", map[string]any{"email": env.testUser.Email, "password": env.testUser.Password}, nil)
		sc := res.Headers.Values("Set-Cookie")
		if len(sc) == 0 {
			t.Fatalf("no set-cookie")
		}
		h := http.Header{}
		h.Set("Cookie", sc[0])
		return h
	}

	t.Run("should verify password with correct password", func(t *testing.T) {
		res, _ := env.mustCall("verifyPassword", map[string]any{"password": env.testUser.Password}, getSessionHeaders(t))
		if res["status"] != true {
			t.Fatalf("status = %v", res["status"])
		}
	})

	t.Run("should fail to verify password with incorrect password", func(t *testing.T) {
		_, apiErr := env.call("verifyPassword", map[string]any{"password": "wrong-password"}, getSessionHeaders(t))
		if apiErr == nil || apiErr.Status != "BAD_REQUEST" || apiErr.Message() != "Invalid password" {
			t.Fatalf("expected BAD_REQUEST Invalid password, got %s", paFormatErr(apiErr))
		}
	})

	t.Run("should require a session to verify password", func(t *testing.T) {
		_, apiErr := env.call("verifyPassword", map[string]any{"password": env.testUser.Password}, http.Header{})
		if apiErr == nil || apiErr.Status != "UNAUTHORIZED" {
			t.Fatalf("expected UNAUTHORIZED, got %s", paFormatErr(apiErr))
		}
	})
}

// describe("verify password length")
func TestPortAuthVerifyPasswordLength(t *testing.T) {
	pw := &paCountingPassword{}
	env := paNewEnv(t, func(c *Config) { c.EmailAndPassword.Password = pw.config() })

	t.Run("should reject a password longer than maxPasswordLength before hashing", func(t *testing.T) {
		_, headers := env.signInWithTestUser()
		pw.clear()
		_, apiErr := env.call("verifyPassword", map[string]any{"password": strings.Repeat("x", 129)}, headers)
		if apiErr == nil || apiErr.Status != "BAD_REQUEST" || apiErr.Code() != "PASSWORD_TOO_LONG" {
			t.Fatalf("expected BAD_REQUEST PASSWORD_TOO_LONG, got %s", paFormatErr(apiErr))
		}
		if pw.hashCalls.Load() != 0 || pw.verifyCalls.Load() != 0 {
			t.Fatalf("hash/verify should not be called (hash=%d verify=%d)", pw.hashCalls.Load(), pw.verifyCalls.Load())
		}
	})
}
