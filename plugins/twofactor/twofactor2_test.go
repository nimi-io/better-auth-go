package twofactor

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Port of two-factor.test.ts (second half).

func otpStorageFlow(t *testing.T, i *instance, otp func() string) {
	t.Helper()
	headers := i.signInWithTestUser().headers
	i.api("enableTwoFactor", headers, map[string]any{"password": testPassword, "method": "otp"})
	h := i.startChallenge()
	i.api("sendTwoFactorOTP", h, map[string]any{})
	if len(otp()) != 6 {
		t.Fatalf("otp %q", otp())
	}
	expectStatus(t, i.api("verifyTwoFactorOTP", h, map[string]any{"code": otp()}), 200)
}

func TestOTPStorageModes(t *testing.T) {
	t.Run("hashed OTP storage", func(t *testing.T) {
		opts, otp := otpCapture()
		opts.StoreOTP = StoreHashed
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: opts})})
		t.Run("should verify OTP when stored as hashed", func(t *testing.T) {
			otpStorageFlow(t, i, otp)
		})
		t.Run("should reject invalid OTP when stored as hashed", func(t *testing.T) {
			h := i.startChallenge()
			i.api("sendTwoFactorOTP", h, map[string]any{})
			r := i.api("verifyTwoFactorOTP", h, map[string]any{"code": "000000"})
			expectStatus(t, r, 401)
			expectMessage(t, r, ErrInvalidCode.Message)
		})
		t.Run("stores the base64url SHA-256 of the code", func(t *testing.T) {
			h := i.startChallenge()
			i.api("sendTwoFactorOTP", h, map[string]any{})
			rows, _ := i.ad.FindMany(t.Context(), adapter.FindManyInput{Model: "verification"})
			found := false
			for _, r := range rows {
				if strings.HasPrefix(r["identifier"].(string), "2fa-otp-") && r["value"] == DefaultKeyHasher(otp())+":0" {
					found = true
				}
			}
			if !found {
				t.Fatal("hashed OTP row not found")
			}
		})
	})
	t.Run("encrypted OTP storage", func(t *testing.T) {
		opts, otp := otpCapture()
		opts.StoreOTP = StoreEncrypted
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: opts})})
		t.Run("should verify OTP when stored as encrypted", func(t *testing.T) {
			otpStorageFlow(t, i, otp)
		})
	})
	t.Run("custom hash function OTP storage", func(t *testing.T) {
		opts, otp := otpCapture()
		opts.Hash = func(token string) (string, error) {
			r := []rune(token)
			for a, b := 0, len(r)-1; a < b; a, b = a+1, b-1 {
				r[a], r[b] = r[b], r[a]
			}
			return "custom_" + string(r), nil
		}
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: opts})})
		t.Run("should verify OTP with custom hash function", func(t *testing.T) {
			otpStorageFlow(t, i, otp)
		})
	})
}

func TestPreMigrationTwoFactorRows(t *testing.T) {
	t.Run("should complete enrollment when verified is null", func(t *testing.T) {
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
		si := i.signInWithTestUser()
		i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword})
		row := i.twoFactorRow(si.userID)
		i.update("twoFactor", adapter.Record{"verified": nil}, eq("id", row["id"]))
		v := i.api("verifyTOTP", si.headers, map[string]any{"code": totpNow(t, decryptSecret(t, row["secret"]))})
		expectStatus(t, v, 200)
		if i.userRow(si.userID)["twoFactorEnabled"] != true {
			t.Fatal("not enabled")
		}
		if i.twoFactorRow(si.userID)["verified"] != true {
			t.Fatal("not verified")
		}
	})
}

func TestTOTPEnrollmentVerification(t *testing.T) {
	t.Run("should create twoFactor row with verified=false on enableTwoFactor", func(t *testing.T) {
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
		si := i.signInWithTestUser()
		expectStatus(t, i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword}), 200)
		if row := i.twoFactorRow(si.userID); row == nil || row["verified"] != false {
			t.Fatalf("row %v", row)
		}
	})
	t.Run("should mark TOTP as verified after verifyTOTP during enrollment", func(t *testing.T) {
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
		si := i.signInWithTestUser()
		i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword})
		if i.twoFactorRow(si.userID)["verified"] != false {
			t.Fatal("expected unverified")
		}
		expectStatus(t, i.api("verifyTOTP", si.headers, map[string]any{"code": i.currentTOTP(si.userID)}), 200)
		if i.twoFactorRow(si.userID)["verified"] != true {
			t.Fatal("expected verified")
		}
	})
	for _, tc := range []struct {
		state    string
		verified any
	}{{"verified", true}, {"legacy", nil}} {
		t.Run("rejects re-enrollment while a "+tc.state+" TOTP is active", func(t *testing.T) {
			i := newInstance(t, []*betterauth.Plugin{New(Options{})})
			si := i.signInWithTestUser()
			headers := si.headers
			i.api("enableTwoFactor", headers, map[string]any{"password": testPassword})
			enrollment := i.twoFactorRow(si.userID)
			if enrollment == nil {
				t.Fatal("expected TOTP enrollment")
			}
			v := i.api("verifyTOTP", headers, map[string]any{"code": totpNow(t, decryptSecret(t, enrollment["secret"]))})
			headers = v.cookieHeaders()
			expectStatus(t, v, 200)
			i.update("twoFactor", adapter.Record{"verified": tc.verified}, eq("id", enrollment["id"]))
			active := i.twoFactorRow(si.userID)
			r := i.api("enableTwoFactor", headers, map[string]any{"password": testPassword})
			expectStatus(t, r, 400)
			if r.code() != ErrTOTPAlreadyEnabled.Code {
				t.Fatalf("code %v", r.Data)
			}
			after := i.twoFactorRow(si.userID)
			if after["id"] != active["id"] || after["secret"] != active["secret"] || after["backupCodes"] != active["backupCodes"] || after["verified"] != tc.verified {
				t.Fatalf("row changed %v", after)
			}
		})
	}
	t.Run("allows restarting an unverified TOTP enrollment", func(t *testing.T) {
		i := newInstance(t, []*betterauth.Plugin{New(Options{})})
		si := i.signInWithTestUser()
		i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword})
		first := i.twoFactorRow(si.userID)
		if first == nil {
			t.Fatal("expected initial TOTP enrollment")
		}
		expectStatus(t, i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword}), 200)
		again := i.twoFactorRow(si.userID)
		if again["secret"] == first["secret"] || again["backupCodes"] == first["backupCodes"] || again["verified"] != false {
			t.Fatalf("row %v", again)
		}
	})
	t.Run("should reject unverified TOTP during sign-in and allow OTP fallback", func(t *testing.T) {
		opts, otp := otpCapture()
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: opts})})
		si := i.signInWithTestUser()
		i.api("sendTwoFactorOTP", si.headers, map[string]any{})
		enroll := i.api("verifyTwoFactorOTP", si.headers, map[string]any{"code": otp()})
		expectStatus(t, enroll, 200)
		eh := enroll.cookieHeaders()
		en := i.api("enableTwoFactor", eh, map[string]any{"password": testPassword})
		if en.str("method") != "totp" {
			t.Fatalf("expected totp %v", en.Data)
		}
		codes := anyStrings(en.Data["backupCodes"])
		if i.twoFactorRow(si.userID)["verified"] != false {
			t.Fatal("expected unverified")
		}
		h := i.startChallenge()
		expectStatus(t, i.api("verifyTOTP", h, map[string]any{"code": "000000"}), 400)
		expectStatus(t, i.api("verifyBackupCode", h, map[string]any{"code": codes[0]}), 200)
	})
}

func TestTwoFactorPasswordless(t *testing.T) {
	i := newInstance(t, []*betterauth.Plugin{anonymousPlugin(), New(Options{AllowPasswordless: true})}, instanceOpts{disableTestUser: true})
	sr := i.api("signInAnonymous", nil, nil)
	headers := applySetCookies(nil, sr.setCookies())
	userID := i.session(headers)["user"].(map[string]any)["id"].(string)
	t.Run("allows enabling without password for users without credentials", func(t *testing.T) {
		r := i.api("enableTwoFactor", headers, map[string]any{})
		headers = applySetCookies(headers, r.setCookies())
		if len(anyStrings(r.Data["backupCodes"])) != 10 || r.str("totpURI") == "" {
			t.Fatalf("data %d %v", r.Status, r.Data)
		}
		row := i.twoFactorRow(userID)
		if row == nil {
			t.Fatal("No two factor")
		}
		v := i.api("verifyTOTP", headers, map[string]any{"code": totpNow(t, decryptSecret(t, row["secret"]))})
		headers = applySetCookies(headers, v.setCookies())
	})
	t.Run("allows getting totp uri without password", func(t *testing.T) {
		r := i.api("getTOTPURI", headers, map[string]any{})
		if r.str("totpURI") == "" {
			t.Fatalf("data %d %v", r.Status, r.Data)
		}
	})
	t.Run("allows generating backup codes without password", func(t *testing.T) {
		r := i.api("generateBackupCodes", headers, map[string]any{})
		if len(anyStrings(r.Data["backupCodes"])) != 10 {
			t.Fatalf("data %d %v", r.Status, r.Data)
		}
	})
	t.Run("allows disabling without password", func(t *testing.T) {
		expectStatus(t, i.api("disableTwoFactor", headers, map[string]any{}), 200)
	})
}

func TestTwoFactorPasswordStillRequiredForCredentialAccounts(t *testing.T) {
	i := newInstance(t, []*betterauth.Plugin{New(Options{AllowPasswordless: true})})
	headers := i.signInWithTestUser().headers
	t.Run("rejects enabling without password for credential users", func(t *testing.T) {
		expectStatus(t, i.api("enableTwoFactor", headers, map[string]any{}), 400)
	})
}

func TestCheckPasswordDoesNotLeakCredentialPresence(t *testing.T) {
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
	si := i.signInWithTestUser()
	en := i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword})
	if en.str("method") != "totp" || en.str("totpURI") == "" {
		t.Fatal("expected totp")
	}
	t.Run("uses INVALID_PASSWORD for wrong password and when credential row is missing", func(t *testing.T) {
		r := i.api("getTOTPURI", si.headers, map[string]any{"password": "not-the-real-password"})
		if r.code() != betterauth.ErrInvalidPassword.Code {
			t.Fatalf("code %v", r.Data)
		}
		cred := i.findOne("account", eq("userId", si.userID), eq("providerId", "credential"))
		if cred == nil {
			t.Fatal("no credential")
		}
		if err := i.ad.Delete(t.Context(), "account", []adapter.Where{eq("id", cred["id"])}); err != nil {
			t.Fatal(err)
		}
		r = i.api("getTOTPURI", si.headers, map[string]any{"password": testPassword})
		if r.code() != betterauth.ErrInvalidPassword.Code || r.code() == betterauth.ErrCredentialAccountNotFound.Code {
			t.Fatalf("code %v", r.Data)
		}
	})
}

func enrollAndVerifyTOTP(t *testing.T, i *instance, userID string) {
	t.Helper()
	h := i.signIn().cookieHeaders()
	i.api("enableTwoFactor", h, map[string]any{"password": testPassword})
	expectStatus(t, i.api("verifyTOTP", h, map[string]any{"code": i.currentTOTP(userID)}), 200)
}

func TestTwoFactorMethodsInSignInResponse(t *testing.T) {
	t.Run("totp enabled in config, otp disabled", func(t *testing.T) {
		i := newInstance(t, []*betterauth.Plugin{New(Options{})})
		si := i.signInWithTestUser()
		t.Run("should not redirect when user has not verified totp", func(t *testing.T) {
			r := i.signIn()
			if r.Data["user"] == nil || r.Data["twoFactorRedirect"] != nil {
				t.Fatalf("data %v", r.Data)
			}
		})
		t.Run("should return twoFactorMethods: ['totp'] when user has verified totp", func(t *testing.T) {
			enrollAndVerifyTOTP(t, i, si.userID)
			r := i.signIn()
			if r.Data["twoFactorRedirect"] != true || !reflect.DeepEqual(anyStrings(r.Data["twoFactorMethods"]), []string{"totp"}) {
				t.Fatalf("data %v", r.Data)
			}
		})
	})
	t.Run("totp enabled in config, otp enabled", func(t *testing.T) {
		i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
		si := i.signInWithTestUser()
		setEnabled := func(v bool) { i.update("user", adapter.Record{"twoFactorEnabled": v}, eq("id", si.userID)) }
		t.Run("should return twoFactorMethods: ['otp'] when user has 2fa enabled but no totp row", func(t *testing.T) {
			setEnabled(true)
			r := i.signIn()
			if r.Data["twoFactorRedirect"] != true || !reflect.DeepEqual(anyStrings(r.Data["twoFactorMethods"]), []string{"otp"}) {
				t.Fatalf("data %v", r.Data)
			}
		})
		t.Run("should exclude unverified totp from twoFactorMethods", func(t *testing.T) {
			setEnabled(false)
			h := i.signIn().cookieHeaders()
			i.api("enableTwoFactor", h, map[string]any{"password": testPassword})
			setEnabled(true)
			r := i.signIn()
			if r.Data["twoFactorRedirect"] != true || !reflect.DeepEqual(anyStrings(r.Data["twoFactorMethods"]), []string{"otp"}) {
				t.Fatalf("data %v", r.Data)
			}
		})
		t.Run("should return twoFactorMethods: ['totp', 'otp'] when user has verified totp", func(t *testing.T) {
			setEnabled(false)
			enrollAndVerifyTOTP(t, i, si.userID)
			r := i.signIn()
			if r.Data["twoFactorRedirect"] != true || !reflect.DeepEqual(anyStrings(r.Data["twoFactorMethods"]), []string{"totp", "otp"}) {
				t.Fatalf("data %v", r.Data)
			}
		})
	})
	t.Run("totp disabled in config, otp enabled", func(t *testing.T) {
		i := newInstance(t, []*betterauth.Plugin{New(Options{TOTPOptions: &TOTPOptions{Disable: true}, OTPOptions: &OTPOptions{SendOTP: noopSend}})})
		i.signInWithTestUser()
		t.Run("should return twoFactorMethods: ['otp'] when totp is disabled in config", func(t *testing.T) {
			h := i.signIn().cookieHeaders()
			i.api("enableTwoFactor", h, map[string]any{"password": testPassword, "method": "otp"})
			r := i.signIn()
			if r.Data["twoFactorRedirect"] != true || !reflect.DeepEqual(anyStrings(r.Data["twoFactorMethods"]), []string{"otp"}) {
				t.Fatalf("data %v", r.Data)
			}
		})
	})
}

func Test2FAEnforcementScope(t *testing.T) {
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}, SkipVerificationOnEnable: true}), magicLinkPlugin()})
	t.Run("should not challenge 2FA on magic-link sign-in", func(t *testing.T) {
		// Adapted: the magic-link plugin is replaced by a stand-in /magic-link/verify
		// endpoint that signs the user in; what matters is that it is not a hooked path.
		headers := i.signInWithTestUser().headers
		i.api("enableTwoFactor", headers, map[string]any{"password": testPassword})
		r, err := i.auth.API.Call(t.Context(), "magicLinkVerify", betterauth.CallInput{Query: map[string]any{"email": testEmail}})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = r.Decode(&m)
		if _, has := m["twoFactorRedirect"]; has || m["token"] == nil {
			t.Fatalf("data %v", m)
		}
	})
	t.Run("should not challenge 2FA on authenticated non-sign-in endpoints", func(t *testing.T) {
		n := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}, SkipVerificationOnEnable: true})})
		headers := n.signInWithTestUser().headers
		en := n.api("enableTwoFactor", headers, map[string]any{"password": testPassword})
		headers = en.cookieHeaders()
		if n.session(headers)["user"].(map[string]any)["twoFactorEnabled"] != true {
			t.Fatal("not enabled")
		}
		u := n.api("updateUser", headers, map[string]any{"name": "updated-name"})
		expectStatus(t, u, 200)
		if _, has := u.Data["twoFactorRedirect"]; has {
			t.Fatal("unexpected redirect")
		}
	})
}

func TestBackupCodesStorageConfigurations(t *testing.T) {
	customEncrypt := func(data string) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte(data)) + ":custom", nil
	}
	customDecrypt := func(data string) (string, error) {
		enc, _, _ := strings.Cut(data, ":custom")
		b, err := base64.StdEncoding.DecodeString(enc)
		return string(b), err
	}
	parse := func(t *testing.T, raw string) []string {
		var out []string
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return out
	}
	modes := []struct {
		name         string
		opts         *BackupCodeOptions
		decodeStored func(t *testing.T, raw string) []string
		verifyFormat func(t *testing.T, raw string)
	}{
		{"plain", &BackupCodeOptions{StoreBackupCodes: StorePlain}, parse, func(*testing.T, string) {}},
		{"encrypted", &BackupCodeOptions{StoreBackupCodes: StoreEncrypted},
			func(t *testing.T, raw string) []string {
				d, err := bacrypto.SymmetricDecrypt(bacrypto.PlainSecret(betterauth.DefaultSecret), raw)
				if err != nil {
					t.Fatal(err)
				}
				return parse(t, d)
			},
			func(t *testing.T, raw string) {
				var v any
				if json.Unmarshal([]byte(raw), &v) == nil {
					t.Fatal("expected non-JSON")
				}
			}},
		{"custom", &BackupCodeOptions{Encrypt: customEncrypt, Decrypt: customDecrypt},
			func(t *testing.T, raw string) []string {
				d, _ := customDecrypt(raw)
				return parse(t, d)
			},
			func(t *testing.T, raw string) {
				if !strings.Contains(raw, ":custom") {
					t.Fatal("expected :custom")
				}
			}},
	}
	for _, mode := range modes {
		t.Run("should preserve "+mode.name+" storage format after backup code verification", func(t *testing.T) {
			i := newInstance(t, []*betterauth.Plugin{New(Options{BackupCodeOptions: mode.opts, SkipVerificationOnEnable: true})})
			si := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
			headers := applySetCookies(nil, si.setCookies())
			userID := si.Data["user"].(map[string]any)["id"].(string)
			en := post(i, "/two-factor/enable", headers, map[string]any{"password": testPassword})
			if en.str("method") != "totp" {
				t.Fatal("expected totp")
			}
			initial := anyStrings(en.Data["backupCodes"])
			if len(initial) != 10 {
				t.Fatal("expected 10 codes")
			}
			before := i.twoFactorRow(userID)["backupCodes"].(string)
			mode.verifyFormat(t, before)
			if !reflect.DeepEqual(mode.decodeStored(t, before), initial) {
				t.Fatal("stored codes mismatch")
			}
			r := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
			tf, _ := r.cookie("better-auth.two_factor")
			h := cookieHeader("better-auth.two_factor", betterauth.EncodeURIComponent(tf.Value))
			post(i, "/two-factor/verify-backup-code", h, map[string]any{"code": initial[0]})
			after := i.twoFactorRow(userID)["backupCodes"].(string)
			mode.verifyFormat(t, after)
			remaining := mode.decodeStored(t, after)
			if len(remaining) != 9 || containsStr(remaining, initial[0]) || !reflect.DeepEqual(remaining, initial[1:]) {
				t.Fatalf("remaining %v", remaining)
			}
		})
	}
}

func TestTwoFactorPasswordLength(t *testing.T) {
	var hashCalls, verifyCalls int
	i := newInstance(t, []*betterauth.Plugin{New(Options{})}, instanceOpts{mutate: func(c *betterauth.Config) {
		c.EmailAndPassword.Password = &betterauth.PasswordConfig{
			Hash:   func(pw string) (string, error) { hashCalls++; return "hashed:" + pw, nil },
			Verify: func(h, pw string) (bool, error) { verifyCalls++; return h == "hashed:"+pw, nil },
		}
	}})
	headers := i.signInWithTestUser().headers
	long := strings.Repeat("x", 129)
	t.Run("enable should ignore an overlong optional password for a passwordless user", func(t *testing.T) {
		n := newInstance(t, []*betterauth.Plugin{anonymousPlugin(), New(Options{AllowPasswordless: true})}, instanceOpts{disableTestUser: true})
		sr := n.api("signInAnonymous", nil, nil)
		expectStatus(t, n.api("enableTwoFactor", sr.cookieHeaders(), map[string]any{"password": long}), 200)
	})
	t.Run("enable should reject a password longer than maxPasswordLength before hashing", func(t *testing.T) {
		hashCalls, verifyCalls = 0, 0
		r := i.api("enableTwoFactor", headers, map[string]any{"password": long})
		expectStatus(t, r, 400)
		if r.code() != "PASSWORD_TOO_LONG" || hashCalls != 0 || verifyCalls != 0 {
			t.Fatalf("code %v hash %d verify %d", r.Data, hashCalls, verifyCalls)
		}
	})
	t.Run("get-totp-uri should reject a password longer than maxPasswordLength before hashing", func(t *testing.T) {
		i.api("enableTwoFactor", headers, map[string]any{"password": testPassword})
		hashCalls, verifyCalls = 0, 0
		r := i.api("getTOTPURI", headers, map[string]any{"password": long})
		expectStatus(t, r, 400)
		if r.code() != "PASSWORD_TOO_LONG" || hashCalls != 0 || verifyCalls != 0 {
			t.Fatalf("code %v hash %d verify %d", r.Data, hashCalls, verifyCalls)
		}
	})
}
