package twofactor

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Ports of two-factor.attempt-cap.test.ts and two-factor.security.test.ts.

type challengeSetup struct {
	*instance
	userID      string
	secret      string
	backupCodes []string
}

// setupTwoFactorChallenge enrolls and verifies TOTP for the test user.
func setupTwoFactorChallenge(t *testing.T, plugins []*betterauth.Plugin, io ...instanceOpts) *challengeSetup {
	t.Helper()
	i := newInstance(t, plugins, io...)
	si := i.signInWithTestUser()
	en := i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword})
	if en.str("method") != "totp" {
		t.Fatalf("expected totp enrollment %v", en.Data)
	}
	secret := decryptSecret(t, i.twoFactorRow(si.userID)["secret"])
	expectStatus(t, i.api("verifyTOTP", si.headers, map[string]any{"code": totpNow(t, secret)}), 200)
	if i.userRow(si.userID)["twoFactorEnabled"] != true {
		t.Fatal("failed to enable 2FA for test user")
	}
	return &challengeSetup{instance: i, userID: si.userID, secret: secret, backupCodes: anyStrings(en.Data["backupCodes"])}
}

func (c *challengeSetup) verifyTotp(h http.Header, code string) *res {
	return c.api("verifyTOTP", h, map[string]any{"code": code})
}

func (c *challengeSetup) verifyBackup(h http.Header, code string) *res {
	return c.api("verifyBackupCode", h, map[string]any{"code": code})
}

func parallel(n int, fn func(k int) *res) []*res {
	out := make([]*res, n)
	var wg sync.WaitGroup
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			out[k] = fn(k)
		}(k)
	}
	wg.Wait()
	return out
}

func TestSecurityTOTPAttemptCap(t *testing.T) {
	c := setupTwoFactorChallenge(t, []*betterauth.Plugin{New(Options{})})
	t.Run("locks out after the limit and cancels the challenge", func(t *testing.T) {
		h := c.startChallenge()
		for k := 0; k < DefaultTwoFactorAllowedAttempts; k++ {
			r := c.verifyTotp(h, "000000")
			expectStatus(t, r, 401)
			expectMessage(t, r, ErrInvalidCode.Message)
		}
		locked := c.verifyTotp(h, totpNow(t, c.secret))
		expectStatus(t, locked, 400)
		expectMessage(t, locked, ErrTooManyAttemptsRequestNewCode.Message)
		after := c.verifyTotp(h, "000000")
		expectStatus(t, after, 401)
		expectMessage(t, after, ErrInvalidTwoFactorCookie.Message)
	})
	t.Run("a concurrent burst cannot exceed the attempt budget", func(t *testing.T) {
		h := c.startChallenge()
		results := parallel(DefaultTwoFactorAllowedAttempts*4, func(int) *res { return c.verifyTotp(h, "111111") })
		processed := 0
		for _, r := range results {
			if r.Status == 200 {
				t.Fatal("unexpected success")
			}
			if r.message() == ErrInvalidCode.Message {
				processed++
			}
		}
		if processed > DefaultTwoFactorAllowedAttempts {
			t.Fatalf("processed %d", processed)
		}
	})
	t.Run("a server error during verification does not spend an attempt slot", func(t *testing.T) {
		// Divergence (test only): the two cases above record up to 10 account-level failures
		// (5 sequential + up to 5 from the burst). Under Node's single-threaded scheduling the
		// burst typically processes a single guess, so the TS suite never reaches the default
		// lockout of 10; Go goroutines use the whole budget and would lock the account here.
		// Reset the counter so this case tests what it is about (attempt slot restoration).
		c.update("twoFactor", adapter.Record{"failedVerificationCount": 0, "lockedUntil": nil}, eq("userId", c.userID))
		h := c.startChallenge()
		valid := c.twoFactorRow(c.userID)["secret"]
		c.update("twoFactor", adapter.Record{"secret": "not-a-valid-encrypted-secret"}, eq("userId", c.userID))
		if r := c.verifyTotp(h, "000000"); r.GoErr == nil {
			t.Fatalf("expected a thrown error, got %d %v", r.Status, r.Data)
		}
		c.update("twoFactor", adapter.Record{"secret": valid}, eq("userId", c.userID))
		expectStatus(t, c.verifyTotp(h, totpNow(t, c.secret)), 200)
	})
}

func TestSecurityBackupCodeAttemptCap(t *testing.T) {
	c := setupTwoFactorChallenge(t, []*betterauth.Plugin{New(Options{})})
	if len(c.backupCodes) == 0 {
		t.Fatal("expected backup codes from enrollment")
	}
	t.Run("counts wrong backup codes up to the limit then locks out", func(t *testing.T) {
		h := c.startChallenge()
		for k := 0; k < DefaultTwoFactorAllowedAttempts; k++ {
			r := c.verifyBackup(h, "0000-0000")
			expectStatus(t, r, 401)
			expectMessage(t, r, ErrInvalidBackupCode.Message)
		}
		locked := c.verifyBackup(h, c.backupCodes[0])
		expectStatus(t, locked, 400)
		expectMessage(t, locked, ErrTooManyAttemptsRequestNewCode.Message)
	})
}

// ---- two-factor.security.test.ts ----

func setCookieValue(entry string) string {
	first, _, _ := strings.Cut(entry, ";")
	_, v, ok := strings.Cut(first, "=")
	if !ok {
		return ""
	}
	return v
}

// replayCookies builds a Cookie header from the non-empty Set-Cookie entries whose name is
// one of names (or starts with "<name>." when chunks is set).
func replayCookies(entries []string, chunks bool, names ...string) http.Header {
	var parts []string
	for _, e := range entries {
		match := false
		for _, n := range names {
			if strings.HasPrefix(e, n+"=") || (chunks && strings.HasPrefix(e, n+".")) {
				match = true
			}
		}
		if !match || setCookieValue(e) == "" {
			continue
		}
		first, _, _ := strings.Cut(e, ";")
		parts = append(parts, first)
	}
	h := http.Header{}
	h.Set("Cookie", strings.Join(parts, "; "))
	return h
}

func TestSecuritySignInDoesNotLeakSessionCookiesCookieCache(t *testing.T) {
	const username, phone = "security_user", "+15551230000"
	c := setupTwoFactorChallenge(t, []*betterauth.Plugin{
		New(Options{}),
		// Stand-ins for the username and phone-number plugins (ported separately).
		passwordSignInPlugin("username", "signInUsername", "/sign-in/username", "username", username),
		passwordSignInPlugin("phone-number", "signInPhoneNumber", "/sign-in/phone-number", "phoneNumber", phone),
		newSessionProbe(),
	}, instanceOpts{mutate: func(cfg *betterauth.Config) {
		cfg.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true}}
	}})
	cases := []struct {
		path string
		call func() *res
	}{
		{"/sign-in/email", func() *res { return c.signIn() }},
		{"/sign-in/username", func() *res {
			return c.api("signInUsername", nil, map[string]any{"username": username, "password": testPassword})
		}},
		{"/sign-in/phone-number", func() *res {
			return c.api("signInPhoneNumber", nil, map[string]any{"phoneNumber": phone, "password": testPassword})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.path+": response carries no valid signed session_token or session_data", func(t *testing.T) {
			r := tc.call()
			expectStatus(t, r, 200)
			if r.Header.Get("x-new-session-visible") != "" {
				t.Fatal("newSession visible to later hooks")
			}
			sc := r.setCookies()
			if len(sc) == 0 {
				t.Fatal("no cookies")
			}
			for _, e := range sc {
				if strings.HasPrefix(e, "better-auth.session_token=") || strings.HasPrefix(e, "better-auth.session_data=") || strings.HasPrefix(e, "better-auth.session_data.") {
					if setCookieValue(e) != "" {
						t.Fatalf("leaked %s", e)
					}
				}
			}
			found := false
			for _, e := range sc {
				if strings.HasPrefix(e, "better-auth.two_factor=") {
					found = true
				}
			}
			if !found {
				t.Fatal("no two_factor cookie")
			}
		})
		t.Run(tc.path+": replaying captured cookies cannot authenticate or disable 2FA", func(t *testing.T) {
			r := tc.call()
			replay := replayCookies(r.setCookies(), false, "better-auth.session_token", "better-auth.session_data")
			if c.session(replay) != nil {
				t.Fatal("replay authenticated")
			}
			expectStatus(t, c.api("disableTwoFactor", replay, map[string]any{"password": testPassword}), 401)
		})
	}
}

func TestSecuritySignInDoesNotLeakSessionCookiesNoCache(t *testing.T) {
	c := setupTwoFactorChallenge(t, []*betterauth.Plugin{New(Options{})})
	t.Run("response carries no valid signed session_token on 2FA-required sign-in", func(t *testing.T) {
		r := c.signIn()
		expectStatus(t, r, 200)
		for _, e := range r.setCookies() {
			if strings.HasPrefix(e, "better-auth.session_token=") && setCookieValue(e) != "" {
				t.Fatalf("leaked %s", e)
			}
		}
	})
	t.Run("replaying any cookies captured from the response cannot authenticate", func(t *testing.T) {
		r := c.signIn()
		if c.session(replayCookies(r.setCookies(), false, "better-auth.session_token", "better-auth.session_data")) != nil {
			t.Fatal("replay authenticated")
		}
	})
}

func TestSecurityChunkedSessionDataScrubbed(t *testing.T) {
	filler := strings.Repeat("x", 2200)
	i := newInstance(t, []*betterauth.Plugin{New(Options{})}, instanceOpts{mutate: func(cfg *betterauth.Config) {
		cfg.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: blobFields()}}
		cfg.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true}}
	}})
	si := i.signInWithTestUser()
	i.update("user", adapter.Record{"blob1": filler, "blob2": filler}, eq("id", si.userID))
	probe := i.signIn()
	chunks := 0
	for _, e := range probe.setCookies() {
		if strings.HasPrefix(e, "better-auth.session_data.") {
			chunks++
		}
	}
	i.api("enableTwoFactor", si.headers, map[string]any{"password": testPassword})
	expectStatus(t, i.api("verifyTOTP", si.headers, map[string]any{"code": i.currentTOTP(si.userID)}), 200)
	t.Run("test setup exercises chunked session_data cookies", func(t *testing.T) {
		expectStatus(t, probe, 200)
		if chunks == 0 {
			t.Fatal("no chunks")
		}
	})
	t.Run("no session_data.N chunk leaks a non-empty value and replay cannot authenticate", func(t *testing.T) {
		r := i.signIn()
		expectStatus(t, r, 200)
		for _, e := range r.setCookies() {
			if (strings.HasPrefix(e, "better-auth.session_data.") || strings.HasPrefix(e, "better-auth.session_token=")) && setCookieValue(e) != "" {
				t.Fatalf("leaked %s", e)
			}
		}
		replay := replayCookies(r.setCookies(), true, "better-auth.session_token", "better-auth.session_data")
		if i.session(replay) != nil {
			t.Fatal("replay authenticated")
		}
	})
}

func TestSecurityChallengeSingleUseAndExpiry(t *testing.T) {
	c := setupTwoFactorChallenge(t, []*betterauth.Plugin{New(Options{})})
	countSessions := func() int {
		rows, err := c.ad.FindMany(context.Background(), adapter.FindManyInput{Model: "session", Where: []adapter.Where{eq("userId", c.userID)}})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	t.Run("rejects an expired two-factor sign-in challenge even with a valid TOTP", func(t *testing.T) {
		h := c.startChallenge()
		row := c.findOne("verification", eq("value", c.userID))
		if row == nil {
			t.Fatal("no challenge row")
		}
		c.update("verification", adapter.Record{"expiresAt": time.Now().Add(-time.Minute)}, eq("id", row["id"]))
		before := countSessions()
		r := c.verifyTotp(h, totpNow(t, c.secret))
		expectStatus(t, r, 401)
		expectMessage(t, r, ErrInvalidTwoFactorCookie.Message)
		for _, e := range r.setCookies() {
			if strings.HasPrefix(e, "better-auth.session_token=") && setCookieValue(e) != "" {
				t.Fatalf("leaked %s", e)
			}
		}
		if countSessions() != before {
			t.Fatal("session created")
		}
	})
	t.Run("two concurrent verifications of the same challenge yield exactly one session", func(t *testing.T) {
		h := c.startChallenge()
		before := countSessions()
		code := totpNow(t, c.secret)
		rs := parallel(2, func(int) *res { return c.verifyTotp(h, code) })
		statuses := []int{rs[0].Status, rs[1].Status}
		sort.Ints(statuses)
		if statuses[0] != 200 || statuses[1] != 401 {
			t.Fatalf("statuses %v", statuses)
		}
		if countSessions() != before+1 {
			t.Fatal("expected exactly one new session")
		}
	})
}

// slowStorage is the delayed secondary storage of the OTP concurrency test.
type slowStorage struct {
	mu   sync.Mutex
	data map[string]slowEntry
}

type slowEntry struct {
	value     string
	expiresAt time.Time
}

func (s *slowStorage) Get(_ context.Context, key string) (string, bool, error) {
	if strings.Contains(key, "2fa-otp") {
		time.Sleep(25 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return "", false, nil
	}
	if e.expiresAt.Before(time.Now()) {
		delete(s.data, key)
		return "", false, nil
	}
	return e.value, true, nil
}

func (s *slowStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	delete(s.data, key)
	if !ok || e.expiresAt.Before(time.Now()) {
		return "", false, nil
	}
	return e.value, true, nil
}

func (s *slowStorage) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int64(0)
	if e, ok := s.data[key]; ok {
		for _, ch := range e.value {
			n = n*10 + int64(ch-'0')
		}
	}
	n++
	s.data[key] = slowEntry{value: itoa(n), expiresAt: time.Now().Add(ttl)}
	return n, nil
}

func (s *slowStorage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	s.data[key] = slowEntry{value: value, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *slowStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestSecurityOTPAttemptsAtomic(t *testing.T) {
	const allowedAttempts = 3
	opts, otp := otpCapture()
	opts.AllowedAttempts = allowedAttempts
	c := setupTwoFactorChallenge(t, []*betterauth.Plugin{New(Options{OTPOptions: opts})}, instanceOpts{mutate: func(cfg *betterauth.Config) {
		cfg.SecondaryStorage = &slowStorage{data: map[string]slowEntry{}}
	}})
	startWithOtp := func() http.Header {
		h := c.startChallenge()
		c.api("sendTwoFactorOTP", h, nil)
		return h
	}
	verifyOtp := func(h http.Header, code string) *res {
		return c.api("verifyTwoFactorOTP", h, map[string]any{"code": code})
	}
	t.Run("counts wrong guesses up to the limit then locks out", func(t *testing.T) {
		h := startWithOtp()
		for k := 0; k < allowedAttempts; k++ {
			r := verifyOtp(h, "000000")
			expectStatus(t, r, 401)
			expectMessage(t, r, ErrInvalidCode.Message)
		}
		locked := verifyOtp(h, otp())
		expectStatus(t, locked, 400)
		expectMessage(t, locked, ErrTooManyAttemptsRequestNewCode.Message)
	})
	t.Run("a concurrent burst of wrong guesses cannot exceed the attempt budget", func(t *testing.T) {
		h := startWithOtp()
		rs := parallel(allowedAttempts*4, func(int) *res { return verifyOtp(h, "111111") })
		n := 0
		for _, r := range rs {
			if r.message() == ErrInvalidCode.Message {
				n++
			}
		}
		if n > allowedAttempts {
			t.Fatalf("invalid count %d", n)
		}
	})
	t.Run("concurrent correct codes mint at most one session", func(t *testing.T) {
		h := startWithOtp()
		code := otp()
		rs := parallel(3, func(int) *res { return verifyOtp(h, code) })
		ok := 0
		for _, r := range rs {
			if r.Status == 200 {
				ok++
			}
		}
		if ok > 1 {
			t.Fatalf("%d sessions minted", ok)
		}
	})
}

func blobFields() []db.Field {
	return []db.Field{
		{Name: "blob1", Type: db.TypeString, DefaultValue: ""},
		{Name: "blob2", Type: db.TypeString, DefaultValue: ""},
	}
}
