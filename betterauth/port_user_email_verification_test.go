package betterauth

// Port of packages/better-auth/src/api/routes/email-verification.test.ts (v1.7.7).

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

type puEmailCall struct {
	Data    EmailData
	Request *http.Request
	Body    string
	BodyErr error
}

type puEmailRecorder struct {
	mu    sync.Mutex
	calls []puEmailCall
	// readBody mirrors callbacks that call request.text().
	readBody bool
	err      func(n int) error
}

func (r *puEmailRecorder) send(_ context.Context, d EmailData, req *http.Request) error {
	c := puEmailCall{Data: d, Request: req}
	if r.readBody && req != nil && req.Body != nil {
		b, err := io.ReadAll(req.Body)
		c.Body, c.BodyErr = string(b), err
	}
	r.mu.Lock()
	r.calls = append(r.calls, c)
	n := len(r.calls)
	r.mu.Unlock()
	if r.err != nil {
		return r.err(n)
	}
	return nil
}

func (r *puEmailRecorder) all() []puEmailCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]puEmailCall(nil), r.calls...)
}

func (r *puEmailRecorder) last(t *testing.T) puEmailCall {
	t.Helper()
	c := r.all()
	if len(c) == 0 {
		t.Fatal("sendVerificationEmail was not called")
	}
	return c[len(c)-1]
}

func (r *puEmailRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

func (r *puEmailRecorder) calledWithEmail(email string) bool {
	for _, c := range r.all() {
		if c.Data.User != nil && c.Data.User.Email == email {
			return true
		}
	}
	return false
}

func puRateLimitErr(msg string) func(n int) error {
	return func(n int) error {
		if n >= 2 {
			return ErrFrom("TOO_MANY_REQUESTS", ErrorCode{Code: "RATE_LIMIT_EXCEEDED", Message: msg})
		}
		return nil
	}
}

func (p *puInst) apiSendVerificationEmail(body map[string]any, headers http.Header) (*CallResult, error) {
	return p.auth.API.Call(p.ctx(), "sendVerificationEmail", CallInput{Body: body, Headers: headers})
}

// ---- describe("Email Verification - Request body consumption bug") ----

// Upstream mocks Request.prototype.clone to throw so the fallback request (without body)
// is passed to the callback, hence the expected empty body text. Go has no request cloning:
// the callback receives the incoming *http.Request whose body was buffered and restored.
// We assert the same method/URL and that reading the body does not fail.
func TestPortUserEmailVerificationSignUpCallbackRequest(t *testing.T) {
	rec := &puEmailRecorder{readBody: true}
	p := puInstance(t, func(c *Config) {
		c.EmailVerification = &EmailVerificationConfig{SendOnSignUp: Bool(true), SendVerificationEmail: rec.send}
	}, puOpts{DisableTestUser: true})
	res := p.signUp("clone-throws@example.com", "password123", "Test User")
	if res.Status != 200 {
		t.Fatalf("expected 200, got %d %s", res.Status, res.Body)
	}
	c := rec.last(t)
	if c.Data.User.Email != "clone-throws@example.com" {
		t.Fatalf("email = %q", c.Data.User.Email)
	}
	if c.Request == nil {
		t.Fatal("expected request to be passed to sendVerificationEmail")
	}
	if c.Request.Method != "POST" {
		t.Fatalf("method = %q", c.Request.Method)
	}
	if got, want := "http://"+c.Request.Host+c.Request.URL.Path, p.env.server.URL+"/api/auth/sign-up/email"; got != want {
		t.Fatalf("url = %q, want %q", got, want)
	}
	if c.BodyErr != nil {
		t.Fatalf("reading request body failed: %v", c.BodyErr)
	}
}

func TestPortUserEmailVerificationBodyNotConsumedAPI(t *testing.T) {
	rec := &puEmailRecorder{readBody: true}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: rec.send}
	}, puOpts{})
	if _, err := p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email}, nil); err != nil {
		t.Fatal(err)
	}
	c := rec.last(t)
	if c.Data.User.Email != p.testUser.Email || c.Data.URL == "" {
		t.Fatalf("unexpected call %+v", c.Data)
	}
	for _, c := range rec.all() {
		if c.BodyErr != nil {
			t.Fatalf("body read error: %v", c.BodyErr)
		}
	}
}

func TestPortUserEmailVerificationBodyNotConsumedSignUp(t *testing.T) {
	rec := &puEmailRecorder{readBody: true}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendOnSignUp: Bool(true), SendVerificationEmail: rec.send}
	}, puOpts{})
	p.signUp("newuser@example.com", "password123", "Test User")
	if !rec.calledWithEmail("newuser@example.com") || rec.last(t).Data.URL == "" {
		t.Fatal("sendVerificationEmail not called for newuser@example.com")
	}
	for _, c := range rec.all() {
		if c.BodyErr != nil {
			t.Fatalf("body read error: %v", c.BodyErr)
		}
	}
}

func TestPortUserEmailVerificationBodyNotConsumedSignIn(t *testing.T) {
	rec := &puEmailRecorder{readBody: true}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendOnSignIn: true, SendVerificationEmail: rec.send}
	}, puOpts{})
	rec.reset()
	p.signIn(p.testUser.Email, p.testUser.Password)
	if !rec.calledWithEmail(p.testUser.Email) || rec.last(t).Data.URL == "" {
		t.Fatal("sendVerificationEmail not called on sign-in")
	}
	for _, c := range rec.all() {
		if c.BodyErr != nil {
			t.Fatalf("body read error: %v", c.BodyErr)
		}
	}
}

// ---- describe("Email Verification") ----

func TestPortUserEmailVerificationSendWhenEnabled(t *testing.T) {
	rec := &puEmailRecorder{}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendOnSignUp: Bool(false), SendVerificationEmail: rec.send}
	}, puOpts{})
	if _, err := p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email}, nil); err != nil {
		t.Fatal(err)
	}
	calls := rec.all()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one call, got %d", len(calls))
	}
	if calls[0].Data.User.Email != p.testUser.Email || calls[0].Data.URL == "" {
		t.Fatalf("unexpected call %+v", calls[0].Data)
	}
	if calls[0].Request != nil {
		t.Fatalf("expected request to be undefined (nil) for a direct API call, got %v", calls[0].Request)
	}
}

// @see https://github.com/better-auth/better-auth/issues/8757
func TestPortUserEmailVerificationAPIErrorStatusFromCallback(t *testing.T) {
	rec := &puEmailRecorder{err: puRateLimitErr("Too many requests. Please try again later.")}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: rec.send}
	}, puOpts{})
	_, err := p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email}, nil)
	if err == nil {
		t.Fatal("Expected sendVerificationEmail to throw")
	}
	e, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T %v", err, err)
	}
	if e.Status != "TOO_MANY_REQUESTS" {
		t.Fatalf("status = %q", e.Status)
	}
	if e.Code() != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("code = %q", e.Code())
	}
}

func TestPortUserEmailVerificationSendOnSignInWhenUnverified(t *testing.T) {
	rec := &puEmailRecorder{}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendOnSignUp: Bool(false), SendOnSignIn: true, SendVerificationEmail: rec.send}
	}, puOpts{})
	res := p.signIn(p.testUser.Email, p.testUser.Password)
	if res.Status == 200 || res.JSON(t)["code"] != "EMAIL_NOT_VERIFIED" {
		t.Fatalf("expected EMAIL_NOT_VERIFIED, got %d %s", res.Status, res.Body)
	}
	calls := rec.all()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one call, got %d", len(calls))
	}
	if calls[0].Data.User.Email != p.testUser.Email || calls[0].Data.URL == "" || calls[0].Request == nil {
		t.Fatalf("unexpected call %+v (request %v)", calls[0].Data, calls[0].Request)
	}
}

func puTokenInstance(t *testing.T, mutate func(ev *EmailVerificationConfig)) (*puInst, *string) {
	t.Helper()
	token := new(string)
	var mu sync.Mutex
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendOnSignUp: Bool(false),
			SendVerificationEmail: func(_ context.Context, d EmailData, _ *http.Request) error {
				mu.Lock()
				*token = d.Token
				mu.Unlock()
				return nil
			}}
		if mutate != nil {
			mutate(c.EmailVerification)
		}
	}, puOpts{})
	if _, err := p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email}, nil); err != nil {
		t.Fatal(err)
	}
	return p, token
}

func TestPortUserEmailVerificationVerifyEmail(t *testing.T) {
	p, token := puTokenInstance(t, nil)
	res := p.verifyEmail(url.Values{"token": {*token}})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("expected status true, got %d %s", res.Status, res.Body)
	}
}

func TestPortUserEmailVerificationRedirectToCallback(t *testing.T) {
	p, token := puTokenInstance(t, nil)
	res := p.verifyEmail(url.Values{"token": {*token}, "callbackURL": {"/callback"}})
	if res.Status != 302 {
		t.Fatalf("expected redirect, got %d %s", res.Status, res.Body)
	}
	if loc := res.Header.Get("Location"); loc != "/callback" {
		t.Fatalf("location = %q", loc)
	}
}

func TestPortUserEmailVerificationSignInAfterVerification(t *testing.T) {
	p, token := puTokenInstance(t, func(ev *EmailVerificationConfig) { ev.AutoSignInAfterVerification = true })

	// runWithUser: sign-in fails (EMAIL_NOT_VERIFIED) so no cookie is captured.
	headers, _ := p.signInWithUser(p.testUser.Email, p.testUser.Password)
	upd := p.post("/update-user", map[string]any{"name": "New Name", "image": "https://example.com/image.jpg"}, headers)
	if upd.Status != 401 {
		t.Fatalf("expected 401, got %d %s", upd.Status, upd.Body)
	}
	if http.StatusText(upd.Status) != "Unauthorized" {
		t.Fatalf("statusText mismatch")
	}

	verifyHeaders := http.Header{}
	res := p.verifyEmail(url.Values{"token": {*token}})
	if res.Status != 200 {
		t.Fatalf("verify failed: %d %s", res.Status, res.Body)
	}
	puSessionSetter(verifyHeaders, res)
	// Upstream reads the bearer plugin's set-auth-token header (plugin not ported); the
	// session token cookie carries the same token.
	sessionToken, _ := res.cookie("better-auth.session_token")
	if len(sessionToken) <= 10 {
		t.Fatalf("expected session token, got %q", sessionToken)
	}
	s := p.getSession(verifyHeaders)
	if s == nil {
		t.Fatal("expected session")
	}
	if puGet(s, "user", "emailVerified") != true {
		t.Fatalf("emailVerified = %v", puGet(s, "user", "emailVerified"))
	}
}

func TestPortUserEmailVerificationCustomExpiresIn(t *testing.T) {
	p, token := puTokenInstance(t, func(ev *EmailVerificationConfig) { ev.ExpiresIn = 10 * time.Second })
	// vi.advanceTimersByTimeAsync(10 * 1000) — no fake clock in Go; wait for real.
	time.Sleep(10 * time.Second)
	res := p.verifyEmail(url.Values{"token": {*token}})
	if res.Status == 200 {
		t.Fatalf("expected error, got %s", res.Body)
	}
	if res.JSON(t)["code"] != "TOKEN_EXPIRED" {
		t.Fatalf("expected TOKEN_EXPIRED, got %s", res.Body)
	}
}

func puHookRecorder() (*[]*User, *[]*http.Request, func(context.Context, *User, *http.Request) error) {
	var users []*User
	var reqs []*http.Request
	return &users, &reqs, func(_ context.Context, u *User, r *http.Request) error {
		users = append(users, u.Clone())
		reqs = append(reqs, r)
		return nil
	}
}

func TestPortUserEmailVerificationAfterEmailVerificationCallback(t *testing.T) {
	users, reqs, hook := puHookRecorder()
	p, token := puTokenInstance(t, func(ev *EmailVerificationConfig) { ev.AfterEmailVerification = hook })
	res := p.verifyEmail(url.Values{"token": {*token}})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("expected status true, got %d %s", res.Status, res.Body)
	}
	if len(*users) == 0 || (*users)[0].Email != p.testUser.Email || (*reqs)[0] == nil {
		t.Fatalf("afterEmailVerification not called with user/request: %v", *users)
	}
}

func TestPortUserEmailVerificationBeforeEmailVerificationCallback(t *testing.T) {
	users, reqs, hook := puHookRecorder()
	p, token := puTokenInstance(t, func(ev *EmailVerificationConfig) { ev.BeforeEmailVerification = hook })
	res := p.verifyEmail(url.Values{"token": {*token}})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("expected status true, got %d %s", res.Status, res.Body)
	}
	if len(*users) == 0 || (*users)[0].Email != p.testUser.Email || (*reqs)[0] == nil {
		t.Fatalf("beforeEmailVerification not called with user/request: %v", *users)
	}
}

func TestPortUserEmailVerificationAfterEmailVerificationVerifiedUser(t *testing.T) {
	users, reqs, hook := puHookRecorder()
	p, token := puTokenInstance(t, func(ev *EmailVerificationConfig) { ev.AfterEmailVerification = hook })
	res := p.verifyEmail(url.Values{"token": {*token}})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("expected status true, got %d %s", res.Status, res.Body)
	}
	if len(*users) == 0 || (*users)[0].Email != p.testUser.Email || !(*users)[0].EmailVerified || (*reqs)[0] == nil {
		t.Fatalf("afterEmailVerification not called with verified user: %+v", *users)
	}
}

func TestPortUserEmailVerificationPreserveEncodedCallbackURL(t *testing.T) {
	testEmail := "test+user@example.com"
	encodedEmail := EncodeURIComponent(testEmail)
	callbackURL := "/sign-in?verifiedEmail=" + encodedEmail
	p, token := puTokenInstance(t, nil)
	res := p.verifyEmail(url.Values{"token": {*token}, "callbackURL": {callbackURL}})
	if res.Status != 302 {
		t.Fatalf("expected redirect, got %d %s", res.Status, res.Body)
	}
	loc := res.Header.Get("Location")
	if loc != "/sign-in?verifiedEmail="+encodedEmail {
		t.Fatalf("location = %q", loc)
	}
	u, err := url.Parse("http://localhost:3000" + loc)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("verifiedEmail"); got != testEmail {
		t.Fatalf("verifiedEmail = %q", got)
	}
}

func TestPortUserEmailVerificationEncodeCallbackURLInEmail(t *testing.T) {
	rec := &puEmailRecorder{}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: rec.send}
	}, puOpts{})
	callbackURL := "https://example.com/app?redirect=/dashboard&tab=settings"
	if _, err := p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email, "callbackURL": callbackURL}, nil); err != nil {
		t.Fatal(err)
	}
	captured := rec.last(t).Data.URL
	u, err := url.Parse(captured)
	if err != nil {
		t.Fatal(err)
	}
	got := u.Query().Get("callbackURL")
	if got != callbackURL {
		t.Fatalf("callbackURL = %q (url %q)", got, captured)
	}
}

func TestPortUserEmailVerificationNoSendForVerifiedThirdParty(t *testing.T) {
	rec := &puEmailRecorder{}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: rec.send}
	}, puOpts{})
	p.post("/send-verification-email", map[string]any{"email": p.testUser.Email})
	p.verifyEmail(url.Values{"token": {rec.last(t).Data.Token}})
	rec.reset()
	res := p.post("/send-verification-email", map[string]any{"email": p.testUser.Email})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("expected status true, got %d %s", res.Status, res.Body)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("expected no email to be sent, got %d", n)
	}
}

// ---- describe("Email Verification - Timing-safe unauthenticated path") ----

func TestPortUserEmailVerificationConstantTimeFloor(t *testing.T) {
	rec := &puEmailRecorder{}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: rec.send}
	}, puOpts{})
	start := time.Now()
	_, _ = p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email}, nil)
	elapsedExisting := time.Since(start)
	start = time.Now()
	_, _ = p.apiSendVerificationEmail(map[string]any{"email": "nonexistent@example.com"}, nil)
	elapsedMissing := time.Since(start)
	if elapsedExisting < 450*time.Millisecond || elapsedMissing < 450*time.Millisecond {
		t.Fatalf("elapsed existing=%v missing=%v", elapsedExisting, elapsedMissing)
	}
	if !rec.calledWithEmail(p.testUser.Email) {
		t.Fatal("expected email to be sent to test user")
	}
	if rec.calledWithEmail("nonexistent@example.com") {
		t.Fatal("email sent to nonexistent user")
	}
}

func TestPortUserEmailVerificationErrorsAfterMinimumDelay(t *testing.T) {
	rec := &puEmailRecorder{err: puRateLimitErr("Too many requests.")}
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{RequireEmailVerification: true}
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: rec.send}
	}, puOpts{})
	start := time.Now()
	_, err := p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email}, nil)
	if err == nil {
		t.Fatal("Expected to throw")
	}
	e, ok := AsAPIError(err)
	if !ok || e.Status != "TOO_MANY_REQUESTS" {
		t.Fatalf("expected TOO_MANY_REQUESTS APIError, got %v", err)
	}
	if el := time.Since(start); el < 450*time.Millisecond {
		t.Fatalf("elapsed %v", el)
	}
}

// ---- describe("Email Verification Secondary Storage") (shared instance) ----

func TestPortUserEmailVerificationSecondaryStorage(t *testing.T) {
	store := newPuStore()
	var mu sync.Mutex
	var token string
	setToken := func(s string) { mu.Lock(); token = s; mu.Unlock() }
	getToken := func() string { mu.Lock(); defer mu.Unlock(); return token }
	p := puInstance(t, func(c *Config) {
		c.SecondaryStorage = store
		c.EmailVerification = &EmailVerificationConfig{
			SendVerificationEmail: func(_ context.Context, d EmailData, _ *http.Request) error {
				setToken(d.Token)
				return nil
			},
			AutoSignInAfterVerification: true,
		}
		c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true,
			SendChangeEmailConfirmation: func(_ context.Context, d ChangeEmailData, _ *http.Request) error {
				setToken(d.Token)
				return nil
			}}}
	}, puOpts{})

	t.Run("should verify email", func(t *testing.T) {
		if _, err := p.apiSendVerificationEmail(map[string]any{"email": p.testUser.Email}, nil); err != nil {
			t.Fatal(err)
		}
		headers := http.Header{}
		res := p.verifyEmail(url.Values{"token": {getToken()}})
		if res.Status == 200 {
			puCookieSetter(headers, res)
		}
		s := p.getSession(headers)
		if puGet(s, "user", "email") != p.testUser.Email {
			t.Fatalf("email = %v (%v)", puGet(s, "user", "email"), s)
		}
		if puGet(s, "user", "emailVerified") != true {
			t.Fatalf("emailVerified = %v", puGet(s, "user", "emailVerified"))
		}
	})

	t.Run("should change email", func(t *testing.T) {
		headers, _ := p.signInWithTestUser()
		// runWithUser(headers): every request carries headers unless overridden.
		if _, err := p.auth.API.Call(p.ctx(), "changeEmail", CallInput{Body: map[string]any{"newEmail": "new@email.com"}, Headers: headers}); err != nil {
			t.Fatal(err)
		}
		confirmationHeaders := http.Header{}
		res := p.verifyEmail(url.Values{"token": {getToken()}}, headers, headers)
		if res.Status == 200 {
			puCookieSetter(confirmationHeaders, res)
		}
		s := p.getSession(headers, confirmationHeaders)
		if puGet(s, "user", "email") != p.testUser.Email {
			t.Fatalf("email after confirmation = %v", puGet(s, "user", "email"))
		}
		verificationHeaders := http.Header{}
		res = p.verifyEmail(url.Values{"token": {getToken()}}, headers, confirmationHeaders)
		if res.Status == 200 {
			puCookieSetter(verificationHeaders, res)
		}
		s = p.getSession(headers, verificationHeaders)
		if puGet(s, "user", "email") != "new@email.com" {
			t.Fatalf("email after verification = %v (%s)", puGet(s, "user", "email"), res.Body)
		}
		if puGet(s, "user", "emailVerified") != true {
			t.Fatalf("emailVerified = %v", puGet(s, "user", "emailVerified"))
		}
	})

	for _, sample := range []puUser{{Name: "sampler", Email: "sample@sample.com", Password: "sample-password"},
		{Name: "sampler2", Email: "sample2@sample.com", Password: "sample-password"}} {
		t.Run("should set emailVerified on all sessions/"+sample.Name, func(t *testing.T) {
			p.signUp(sample.Email, sample.Password, sample.Name)
			secondSignInHeaders := http.Header{}
			res := p.signIn(sample.Email, sample.Password)
			if res.Status == 200 {
				puCookieSetter(secondSignInHeaders, res)
			}
			if _, err := p.apiSendVerificationEmail(map[string]any{"email": sample.Email}, nil); err != nil {
				t.Fatal(err)
			}
			headers := http.Header{}
			res = p.verifyEmail(url.Values{"token": {getToken()}})
			if res.Status == 200 {
				puCookieSetter(headers, res)
			}
			s := p.getSession(headers)
			if puGet(s, "user", "email") != sample.Email || puGet(s, "user", "emailVerified") != true {
				t.Fatalf("verify session: %v", s)
			}
			s2 := p.getSession(secondSignInHeaders)
			if puGet(s2, "user", "email") != sample.Email {
				t.Fatalf("second session email: %v", s2)
			}
			if puGet(s2, "user", "emailVerified") != true {
				t.Fatalf("second session emailVerified = %v", puGet(s2, "user", "emailVerified"))
			}
		})
	}

	t.Run("should call hooks when verifying email change (change-email-verification)", func(t *testing.T) {
		users, _, hook := puHookRecorder()
		var captured string
		var cmu sync.Mutex
		set := func(s string) { cmu.Lock(); captured = s; cmu.Unlock() }
		q := puInstance(t, func(c *Config) {
			c.EmailVerification = &EmailVerificationConfig{
				SendVerificationEmail:  func(_ context.Context, d EmailData, _ *http.Request) error { set(d.Token); return nil },
				AfterEmailVerification: hook,
			}
			c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true,
				SendChangeEmailConfirmation: func(_ context.Context, d ChangeEmailData, _ *http.Request) error { set(d.Token); return nil }}}
		}, puOpts{})
		headers, _ := q.signInWithTestUser()
		if _, err := q.auth.API.Call(q.ctx(), "changeEmail", CallInput{Body: map[string]any{"newEmail": "newemail@example.com"}, Headers: headers}); err != nil {
			t.Fatal(err)
		}
		cmu.Lock()
		tok := captured
		cmu.Unlock()
		q.verifyEmail(url.Values{"token": {tok}}, headers, headers)
		found := false
		for _, u := range *users {
			if u.Email == "newemail@example.com" && u.EmailVerified {
				found = true
			}
		}
		if !found {
			t.Fatalf("afterEmailVerification not called with new verified email: %+v", *users)
		}
	})

	t.Run("should handle email case insensitivity when sending verification email while signed in", func(t *testing.T) {
		rec := &puEmailRecorder{}
		q := puInstance(t, func(c *Config) {
			c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: rec.send}
		}, puOpts{})
		mixed := "Test.Email.Case@Example.COM"
		lower := "test.email.case@example.com"
		res, err := q.auth.API.SignUpEmail(q.ctx(), SignUpEmailInput{Email: mixed, Password: "password123", Name: "Test User"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var su map[string]any
		if err := res.Decode(&su); err != nil {
			t.Fatal(err)
		}
		if puGet(su, "user", "email") != lower || puGet(su, "user", "emailVerified") != false {
			t.Fatalf("sign-up user: %v", su)
		}
		headers, _ := q.signInWithUser(lower, "password123")
		s, err := q.auth.API.GetSession(q.ctx(), headers)
		if err != nil || s == nil {
			t.Fatalf("session: %v %v", s, err)
		}
		if s.User.Email != lower || s.User.EmailVerified {
			t.Fatalf("session user: %+v", s.User)
		}
		out, err := q.apiSendVerificationEmail(map[string]any{"email": "TEST.EMAIL.CASE@EXAMPLE.COM"}, headers)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = out.Decode(&m)
		if m["status"] != true {
			t.Fatalf("status = %v", m)
		}
	})
}
