package twofactor

import (
	"context"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// Port of two-factor.test.ts.

func post(i *instance, path string, headers http.Header, body any) *res {
	i.t.Helper()
	return i.http("POST", path, headers, body)
}

func TestTwoFactor(t *testing.T) {
	var mu sync.Mutex
	OTP := ""
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{
		SendOTP: func(_ context.Context, d OTPData, _ *betterauth.EndpointContext) error {
			mu.Lock()
			OTP = d.OTP
			mu.Unlock()
			return nil
		},
	}})}, instanceOpts{mutate: func(c *betterauth.Config) {
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true}}
	}})
	otp := func() string { mu.Lock(); defer mu.Unlock(); return OTP }
	headers := http.Header{}
	signIn := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
	expectStatus(t, signIn, 200)
	headers = applySetCookies(headers, signIn.setCookies())
	userID := signIn.Data["user"].(map[string]any)["id"].(string)

	t.Run("should return uri and backup codes and shouldn't enable twoFactor yet", func(t *testing.T) {
		r := post(i, "/two-factor/enable", headers, map[string]any{"password": testPassword})
		expectStatus(t, r, 200)
		if r.str("method") != "totp" {
			t.Fatal("expected totp")
		}
		if len(anyStrings(r.Data["backupCodes"])) != 10 || r.str("totpURI") == "" {
			t.Fatalf("bad response %v", r.Data)
		}
		if i.userRow(userID)["twoFactorEnabled"] != false {
			t.Fatal("twoFactorEnabled should be false")
		}
		row := i.twoFactorRow(userID)
		if row["secret"] == nil || row["backupCodes"] == nil || row["verified"] != false {
			t.Fatalf("bad row %v", row)
		}
	})
	t.Run("should use custom issuer from request parameter", func(t *testing.T) {
		r := post(i, "/two-factor/enable", headers, map[string]any{"password": testPassword, "issuer": "Custom App Name"})
		uri := r.str("totpURI")
		if !strings.HasPrefix(uri, "otpauth://totp/Custom%20App%20Name:") || !strings.Contains(uri, "&issuer=Custom+App+Name&") {
			t.Fatalf("uri %q", uri)
		}
	})
	t.Run("should fallback to appName when no issuer provided", func(t *testing.T) {
		r := post(i, "/two-factor/enable", headers, map[string]any{"password": testPassword})
		uri := r.str("totpURI")
		if !regexp.MustCompile(`^otpauth://totp/Better%20Auth:`).MatchString(uri) || !strings.Contains(uri, "&issuer=Better+Auth&") {
			t.Fatalf("uri %q", uri)
		}
	})
	t.Run("should enable twoFactor", func(t *testing.T) {
		code := i.currentTOTP(userID)
		r := post(i, "/two-factor/verify-totp", headers, map[string]any{"code": code})
		expectStatus(t, r, 200)
		headers = applySetCookies(headers, r.setCookies())
		if r.str("token") == "" {
			t.Fatal("no token")
		}
	})
	t.Run("should require two factor", func(t *testing.T) {
		r := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword, "rememberMe": false})
		st, _ := r.cookie("better-auth.session_token")
		sd, _ := r.cookie("better-auth.session_data")
		tf, okTF := r.cookie("better-auth.two_factor")
		dr, okDR := r.cookie("better-auth.dont_remember")
		if st.Value != "" || sd.Value != "" || !okTF || !okDR {
			t.Fatalf("cookies %v", r.setCookies())
		}
		h := cookieHeader("better-auth.two_factor", betterauth.EncodeURIComponent(tf.Value), "better-auth.dont_remember", betterauth.EncodeURIComponent(dr.Value))
		if r.Data["twoFactorRedirect"] != true || !reflect.DeepEqual(anyStrings(r.Data["twoFactorMethods"]), []string{"totp", "otp"}) {
			t.Fatalf("data %v", r.Data)
		}
		post(i, "/two-factor/send-otp", h, nil)
		v := post(i, "/two-factor/verify-otp", h, map[string]any{"code": otp()})
		tok, ok := v.cookie("better-auth.session_token")
		if !ok || tok.Value == "" {
			t.Fatal("no session token")
		}
		if _, has := tok.Attrs["max-age"]; has {
			t.Fatal("session token should not have max-age")
		}
		if v.str("token") == "" {
			t.Fatalf("no token %v", v.Data)
		}
	})
	t.Run("should fail if two factor cookie is missing", func(t *testing.T) {
		r := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword, "rememberMe": false})
		st, _ := r.cookie("better-auth.session_token")
		_, okTF := r.cookie("better-auth.two_factor")
		dr, okDR := r.cookie("better-auth.dont_remember")
		if st.Value != "" || !okTF || !okDR {
			t.Fatalf("cookies %v", r.setCookies())
		}
		if r.Data["twoFactorRedirect"] != true {
			t.Fatal("expected redirect")
		}
		h := cookieHeader("better-auth.dont_remember", betterauth.EncodeURIComponent(dr.Value))
		post(i, "/two-factor/send-otp", h, nil)
		v := post(i, "/two-factor/verify-otp", h, map[string]any{"code": otp()})
		if _, ok := v.cookie("better-auth.session_token"); ok {
			t.Fatal("session token should not be set")
		}
		expectMessage(t, v, ErrInvalidTwoFactorCookie.Message)
	})
	t.Run("should fail when passing invalid TOTP code with expected error code", func(t *testing.T) {
		r := post(i, "/two-factor/verify-totp", headers, map[string]any{"code": "invalid-code"})
		expectMessage(t, r, ErrInvalidCode.Message)
	})
	var backupCodes []string
	t.Run("should generate backup codes", func(t *testing.T) {
		r := post(i, "/two-factor/generate-backup-codes", headers, map[string]any{"password": testPassword})
		backupCodes = anyStrings(r.Data["backupCodes"])
		if len(backupCodes) == 0 {
			t.Fatalf("no backup codes %d %v", r.Status, r.Data)
		}
	})
	t.Run("should allow sign in with backup code", func(t *testing.T) {
		r := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
		if st, _ := r.cookie("better-auth.session_token"); st.Value != "" {
			t.Fatal("session token should be empty")
		}
		tf, _ := r.cookie("better-auth.two_factor")
		h := cookieHeader("better-auth.two_factor", betterauth.EncodeURIComponent(tf.Value))
		v := post(i, "/two-factor/verify-backup-code", h, map[string]any{"code": backupCodes[0]})
		if tok, _ := v.cookie("better-auth.session_token"); tok.Value == "" {
			t.Fatalf("no session token %v", v.Data)
		}
		view := i.api("viewBackupCodes", nil, map[string]any{"userId": userID})
		codes := anyStrings(view.Data["backupCodes"])
		if len(codes) == 0 || containsStr(codes, backupCodes[0]) {
			t.Fatalf("codes %v", codes)
		}
		r2 := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
		tf2, _ := r2.cookie("better-auth.two_factor")
		h2 := cookieHeader("better-auth.two_factor", betterauth.EncodeURIComponent(tf2.Value))
		bad := post(i, "/two-factor/verify-backup-code", h2, map[string]any{"code": "invalid-code"})
		expectMessage(t, bad, "Invalid backup code")
	})
	t.Run("should trust device", func(t *testing.T) {
		r := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
		if r.Data["twoFactorRedirect"] != true {
			t.Fatal("expected redirect")
		}
		tf, _ := r.cookie("better-auth.two_factor")
		h := cookieHeader("better-auth.two_factor", betterauth.EncodeURIComponent(tf.Value))
		post(i, "/two-factor/send-otp", h, nil)
		v := post(i, "/two-factor/verify-otp", h, map[string]any{"trustDevice": true, "code": otp()})
		trust, ok := v.cookie("better-auth.trust_device")
		if !ok || trust.Value == "" {
			t.Fatalf("no trust cookie %v", v.setCookies())
		}
		newHeaders := cookieHeader("better-auth.trust_device", betterauth.EncodeURIComponent(trust.Value))
		s1 := post(i, "/sign-in/email", newHeaders, map[string]any{"email": testEmail, "password": testPassword})
		refreshed, ok := s1.cookie("better-auth.trust_device")
		if !ok || refreshed.Value == "" {
			t.Fatal("trust cookie not refreshed")
		}
		if s1.Data["user"] == nil {
			t.Fatalf("expected user %v", s1.Data)
		}
		updated := cookieHeader("better-auth.trust_device", betterauth.EncodeURIComponent(refreshed.Value))
		s2 := post(i, "/sign-in/email", newHeaders, map[string]any{"email": testEmail, "password": testPassword})
		if s2.Data["twoFactorRedirect"] != true {
			t.Fatalf("old trust cookie should be rotated %v", s2.Data)
		}
		s3 := post(i, "/sign-in/email", updated, map[string]any{"email": testEmail, "password": testPassword})
		if s3.Data["user"] == nil {
			t.Fatalf("expected user %v", s3.Data)
		}
	})
	t.Run("should limit OTP verification attempts", func(t *testing.T) {
		r := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
		tf, _ := r.cookie("better-auth.two_factor")
		h := cookieHeader("better-auth.two_factor", betterauth.EncodeURIComponent(tf.Value))
		post(i, "/two-factor/send-otp", h, nil)
		for k := 0; k < 5; k++ {
			expectMessage(t, post(i, "/two-factor/verify-otp", h, map[string]any{"code": "000000"}), "Invalid code")
		}
		expectMessage(t, post(i, "/two-factor/verify-otp", h, map[string]any{"code": otp()}), "Too many attempts. Please request a new code.")
	})
	t.Run("should disable two factor", func(t *testing.T) {
		r := post(i, "/two-factor/disable", headers, map[string]any{"password": testPassword})
		if r.Data["status"] != true {
			t.Fatalf("disable %d %v", r.Status, r.Data)
		}
		if i.userRow(userID)["twoFactorEnabled"] != false {
			t.Fatal("still enabled")
		}
		s := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
		if s.Data["user"] == nil {
			t.Fatalf("expected user %v", s.Data)
		}
	})
}

func otpCapture() (*OTPOptions, func() string) {
	var mu sync.Mutex
	v := ""
	return &OTPOptions{SendOTP: func(_ context.Context, d OTPData, _ *betterauth.EndpointContext) error {
			mu.Lock()
			v = d.OTP
			mu.Unlock()
			return nil
		}}, func() string {
			mu.Lock()
			defer mu.Unlock()
			return v
		}
}

func noopSend(context.Context, OTPData, *betterauth.EndpointContext) error { return nil }

func TestOTPOnlyEnablement(t *testing.T) {
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
	headers := i.signInWithTestUser().headers
	t.Run("should enable 2FA with OTP method", func(t *testing.T) {
		r := i.api("enableTwoFactor", headers, map[string]any{"password": testPassword, "method": "otp"})
		headers = r.cookieHeaders()
		if r.str("method") != "otp" {
			t.Fatalf("method %v", r.Data)
		}
		s := i.session(headers)
		if s["user"].(map[string]any)["twoFactorEnabled"] != true {
			t.Fatal("not enabled")
		}
	})
	t.Run("should only report OTP in twoFactorMethods at sign-in", func(t *testing.T) {
		r := i.signIn()
		if r.Data["twoFactorRedirect"] != true || !reflect.DeepEqual(anyStrings(r.Data["twoFactorMethods"]), []string{"otp"}) {
			t.Fatalf("data %v", r.Data)
		}
	})
	t.Run("should reject OTP enable when sendOTP is not configured", func(t *testing.T) {
		n := newInstance(t, []*betterauth.Plugin{New(Options{})})
		r := n.api("enableTwoFactor", n.signInWithTestUser().headers, map[string]any{"password": testPassword, "method": "otp"})
		expectStatus(t, r, 400)
		if r.code() != "OTP_NOT_CONFIGURED" {
			t.Fatalf("code %v", r.Data)
		}
	})
	t.Run("should reject TOTP enable when totpOptions.disable is set", func(t *testing.T) {
		n := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}, TOTPOptions: &TOTPOptions{Disable: true}})})
		r := n.api("enableTwoFactor", n.signInWithTestUser().headers, map[string]any{"password": testPassword, "method": "totp"})
		expectStatus(t, r, 400)
	})
	t.Run("should preserve existing TOTP row when enabling OTP", func(t *testing.T) {
		n := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
		si := n.signInWithTestUser()
		h := si.headers
		n.api("enableTwoFactor", h, map[string]any{"password": testPassword, "method": "totp"})
		v := n.api("verifyTOTP", h, map[string]any{"code": n.currentTOTP(si.userID)})
		h = v.cookieHeaders()
		o := n.api("enableTwoFactor", h, map[string]any{"password": testPassword, "method": "otp"})
		expectStatus(t, o, 200)
		row := n.twoFactorRow(si.userID)
		if row["secret"] == nil || row["verified"] != true {
			t.Fatalf("row %v", row)
		}
		s := n.signIn()
		if !reflect.DeepEqual(anyStrings(s.Data["twoFactorMethods"]), []string{"totp", "otp"}) {
			t.Fatalf("methods %v", s.Data)
		}
	})
}

func TestTwoFactorAuthAPI(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	OTP := ""
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: func(_ context.Context, d OTPData, _ *betterauth.EndpointContext) error {
		mu.Lock()
		defer mu.Unlock()
		OTP = d.OTP
		calls = append(calls, d.OTP)
		return nil
	}}})})
	headers := i.signInWithTestUser().headers
	t.Run("should enable two factor with OTP method", func(t *testing.T) {
		r := i.api("enableTwoFactor", headers, map[string]any{"password": testPassword, "method": "otp"})
		headers = r.cookieHeaders()
		if r.str("method") != "otp" {
			t.Fatal("method")
		}
		if i.session(headers)["user"].(map[string]any)["twoFactorEnabled"] != true {
			t.Fatal("not enabled")
		}
	})
	t.Run("should request second factor", func(t *testing.T) {
		r := i.signIn()
		headers = r.cookieHeaders()
		expectStatus(t, r, 200)
		if _, ok := r.cookie("better-auth.two_factor"); !ok {
			t.Fatal("no two_factor cookie")
		}
		if st, _ := r.cookie("better-auth.session_token"); st.Value != "" {
			t.Fatal("session token set")
		}
	})
	t.Run("should send otp", func(t *testing.T) {
		r := i.api("sendTwoFactorOTP", headers, map[string]any{"trustDevice": false})
		expectStatus(t, r, 200)
		mu.Lock()
		defer mu.Unlock()
		if len(OTP) != 6 || len(calls) != 1 || calls[0] != OTP {
			t.Fatalf("otp %q calls %v", OTP, calls)
		}
	})
	t.Run("should verify otp", func(t *testing.T) {
		mu.Lock()
		code := OTP
		mu.Unlock()
		r := i.api("verifyTwoFactorOTP", headers, map[string]any{"code": code})
		expectStatus(t, r, 200)
		if len(r.setCookies()) == 0 {
			t.Fatal("no set-cookie")
		}
		headers = r.cookieHeaders()
	})
	t.Run("should disable two factor", func(t *testing.T) {
		r := i.api("disableTwoFactor", headers, map[string]any{"password": testPassword})
		headers = r.cookieHeaders()
		expectStatus(t, r, 200)
		if i.session(headers)["user"].(map[string]any)["twoFactorEnabled"] != false {
			t.Fatal("still enabled")
		}
	})
}

func TestViewBackupCodes(t *testing.T) {
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
	si := i.signInWithTestUser()
	en := i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword, "method": "otp"})
	headers := en.cookieHeaders()
	userID := si.userID
	view := func() []string {
		r := i.api("viewBackupCodes", nil, map[string]any{"userId": userID})
		if r.Data["status"] != true {
			t.Fatalf("view %v", r.Data)
		}
		if _, isStr := r.Data["backupCodes"].(string); isStr {
			t.Fatal("backupCodes is a string")
		}
		return anyStrings(r.Data["backupCodes"])
	}
	generate := func() []string {
		r := i.api("generateBackupCodes", headers, map[string]any{"password": testPassword})
		if r.Data["status"] != true {
			t.Fatalf("generate %d %v", r.Status, r.Data)
		}
		c := anyStrings(r.Data["backupCodes"])
		if len(c) != 10 {
			t.Fatalf("codes %v", c)
		}
		return c
	}
	t.Run("should return parsed array of backup codes, not JSON string", func(t *testing.T) {
		r := i.api("enableTwoFactor", headers, map[string]any{"password": testPassword})
		if r.str("method") != "totp" {
			t.Fatalf("expected totp %v", r.Data)
		}
		codes := view()
		if len(codes) != 10 || !reflect.DeepEqual(codes, anyStrings(r.Data["backupCodes"])) {
			t.Fatalf("codes %v", codes)
		}
		for _, c := range codes {
			if c == "" {
				t.Fatal("empty code")
			}
		}
	})
	t.Run("should return array after generating new backup codes", func(t *testing.T) {
		g := generate()
		if !reflect.DeepEqual(view(), g) {
			t.Fatal("mismatch")
		}
	})
	t.Run("should successfully regenerate backup codes multiple times", func(t *testing.T) {
		a := generate()
		b := generate()
		if reflect.DeepEqual(a, b) {
			t.Fatal("codes not regenerated")
		}
		c := generate()
		if !reflect.DeepEqual(view(), c) {
			t.Fatal("mismatch")
		}
	})
	t.Run("should correctly update backup codes after verification", func(t *testing.T) {
		codes := generate()
		r := post(i, "/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
		tf, _ := r.cookie("better-auth.two_factor")
		h := cookieHeader("better-auth.two_factor", betterauth.EncodeURIComponent(tf.Value))
		v := post(i, "/two-factor/verify-backup-code", h, map[string]any{"code": codes[0]})
		if tok, _ := v.cookie("better-auth.session_token"); tok.Value == "" {
			t.Fatalf("no session %d %v", v.Status, v.Data)
		}
		updated := view()
		if len(updated) != 9 || containsStr(updated, codes[0]) {
			t.Fatalf("updated %v", updated)
		}
		for _, c := range codes[1:] {
			if !containsStr(updated, c) {
				t.Fatalf("missing %s", c)
			}
		}
	})
	t.Run("should not expose viewBackupCodes to client", func(t *testing.T) {
		r := post(i, "/two-factor/view-backup-codes", nil, map[string]any{"userId": userID})
		expectStatus(t, r, 404)
	})
}

// trustCookieIdentifier extracts the identifier from a signed trust_device cookie value.
func trustCookieIdentifier(t *testing.T, value string) string {
	t.Helper()
	unsigned := value[:strings.LastIndex(value, ".")]
	parts := strings.Split(unsigned, "!")
	if len(parts) < 2 || parts[1] == "" {
		t.Fatalf("bad trust cookie %q", value)
	}
	return parts[1]
}

func TestTrustDeviceServerSideValidation(t *testing.T) {
	opts, otp := otpCapture()
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: opts})})
	headers := i.signInWithTestUser().headers
	trustFlow := func(t *testing.T) (*res, string, string) {
		h := i.startChallenge()
		i.api("sendTwoFactorOTP", h, map[string]any{})
		v := i.api("verifyTwoFactorOTP", h, map[string]any{"code": otp(), "trustDevice": true})
		expectStatus(t, v, 200)
		c, ok := v.cookie("better-auth.trust_device")
		if !ok {
			t.Fatal("no trust cookie")
		}
		id := trustCookieIdentifier(t, c.Value)
		if i.findOne("verification", eq("identifier", id)) == nil {
			t.Fatal("no trust record")
		}
		return v, c.Value, id
	}
	t.Run("should force 2FA when server-side trust record is expired", func(t *testing.T) {
		en := i.api("enableTwoFactor", headers, map[string]any{"password": testPassword, "method": "otp"})
		headers = en.cookieHeaders()
		_, value, id := trustFlow(t)
		rec := i.findOne("verification", eq("identifier", id))
		i.update("verification", adapter.Record{"expiresAt": timeNowAdd(-1000)}, eq("id", rec["id"]))
		r := i.api("signInEmail", cookieHeader("better-auth.trust_device", betterauth.EncodeURIComponent(value)),
			map[string]any{"email": testEmail, "password": testPassword})
		if r.Data["twoFactorRedirect"] != true {
			t.Fatalf("expected redirect %v", r.Data)
		}
		c, ok := r.cookie("better-auth.trust_device")
		if !ok || c.Value != "" {
			t.Fatal("trust cookie should be cleared")
		}
	})
	t.Run("should preserve trust device after sign-out", func(t *testing.T) {
		v, value, id := trustFlow(t)
		out := i.api("signOut", v.cookieHeaders(), nil)
		expectStatus(t, out, 200)
		if c, ok := out.cookie("better-auth.trust_device"); ok && c.Value == "" {
			t.Fatal("trust cookie cleared on sign-out")
		}
		if i.findOne("verification", eq("identifier", id)) == nil {
			t.Fatal("trust record removed")
		}
		r := i.api("signInEmail", cookieHeader("better-auth.trust_device", betterauth.EncodeURIComponent(value)),
			map[string]any{"email": testEmail, "password": testPassword})
		if u, _ := r.Data["user"].(map[string]any); u == nil || u["email"] != testEmail {
			t.Fatalf("expected user %v", r.Data)
		}
	})
	t.Run("should revoke trust device when disabling 2FA", func(t *testing.T) {
		v, _, id := trustFlow(t)
		d := i.api("disableTwoFactor", v.cookieHeaders(), map[string]any{"password": testPassword})
		expectStatus(t, d, 200)
		c, ok := d.cookie("better-auth.trust_device")
		if !ok || c.Value != "" {
			t.Fatalf("trust cookie not cleared %v", d.setCookies())
		}
		if i.findOne("verification", eq("identifier", id)) != nil {
			t.Fatal("trust record should be deleted")
		}
	})
}

func TestTrustDeviceMaxAge(t *testing.T) {
	customMaxAge := 7 * 24 * 60 * 60
	opts, otp := otpCapture()
	i := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: opts, TrustDeviceMaxAge: customMaxAge})})
	headers := i.signInWithTestUser().headers
	t.Run("should use custom trustDeviceMaxAge for the trust device cookie", func(t *testing.T) {
		i.api("enableTwoFactor", headers, map[string]any{"password": testPassword, "method": "otp"})
		h := i.startChallenge()
		i.api("sendTwoFactorOTP", h, map[string]any{})
		v := i.api("verifyTwoFactorOTP", h, map[string]any{"code": otp(), "trustDevice": true})
		expectStatus(t, v, 200)
		c, ok := v.cookie("better-auth.trust_device")
		if !ok || c.Attrs["max-age"] != "604800" {
			t.Fatalf("cookie %v", v.setCookies())
		}
		rec := i.findOne("verification", eq("identifier", trustCookieIdentifier(t, c.Value)))
		diff := toTime(rec["expiresAt"]).Sub(timeNowAdd(int64(customMaxAge) * 1000))
		if diff < -5e9 || diff > 5e9 {
			t.Fatalf("expiresAt off by %v", diff)
		}
	})
	t.Run("should use default 30 days when trustDeviceMaxAge is not specified", func(t *testing.T) {
		o2, otp2 := otpCapture()
		n := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: o2})})
		n.api("enableTwoFactor", n.signInWithTestUser().headers, map[string]any{"password": testPassword, "method": "otp"})
		h := n.startChallenge()
		n.api("sendTwoFactorOTP", h, map[string]any{})
		v := n.api("verifyTwoFactorOTP", h, map[string]any{"code": otp2(), "trustDevice": true})
		expectStatus(t, v, 200)
		c, ok := v.cookie("better-auth.trust_device")
		if !ok || c.Attrs["max-age"] != "2592000" {
			t.Fatalf("cookie %v", v.setCookies())
		}
	})
}

func TestTwoFactorCookieMaxAge(t *testing.T) {
	i := newInstance(t, []*betterauth.Plugin{New(Options{TwoFactorCookieMaxAge: 15 * 60, OTPOptions: &OTPOptions{SendOTP: noopSend}})})
	headers := i.signInWithTestUser().headers
	t.Run("should use custom twoFactorCookieMaxAge for the two-factor cookie", func(t *testing.T) {
		expectStatus(t, i.api("enableTwoFactor", headers, map[string]any{"password": testPassword, "method": "otp"}), 200)
		c, ok := i.signIn().cookie("better-auth.two_factor")
		if !ok || c.Attrs["max-age"] != "900" {
			t.Fatalf("cookie %v", c)
		}
	})
	t.Run("should use default 10 minutes when twoFactorCookieMaxAge is not specified", func(t *testing.T) {
		n := newInstance(t, []*betterauth.Plugin{New(Options{OTPOptions: &OTPOptions{SendOTP: noopSend}})})
		expectStatus(t, n.api("enableTwoFactor", n.signInWithTestUser().headers, map[string]any{"password": testPassword, "method": "otp"}), 200)
		c, ok := n.signIn().cookie("better-auth.two_factor")
		if !ok || c.Attrs["max-age"] != "600" {
			t.Fatalf("cookie %v", c)
		}
	})
}

func TestTwoFactorTableOption(t *testing.T) {
	store := newStore()
	i := newInstance(t, []*betterauth.Plugin{New(Options{TwoFactorTable: "custom_two_factor", OTPOptions: &OTPOptions{SendOTP: noopSend}})},
		instanceOpts{mutate: func(c *betterauth.Config) { c.Database = store.factory() }})
	si := i.signInWithTestUser()
	t.Run("should use custom table name for two factor data", func(t *testing.T) {
		i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword})
		row := i.twoFactorRow(si.userID)
		if row == nil || row["secret"] == nil {
			t.Fatal("no row")
		}
		if len(store.db.Rows("custom_two_factor")) != 1 {
			t.Fatal("row not stored in custom_two_factor")
		}
	})
}
