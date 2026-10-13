package magiclink_test

// Port of packages/better-auth/src/plugins/magic-link/magic-link.test.ts (v1.7.7).
// vi.advanceTimersByTime is emulated by inst.advance (shifting stored timestamps back).

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/plugins/magiclink"
)

type mailbox struct {
	mu   sync.Mutex
	last magiclink.SendMagicLinkData
	all  []magiclink.SendMagicLinkData
}

func (m *mailbox) send(_ *betterauth.EndpointContext, d magiclink.SendMagicLinkData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = d
	m.all = append(m.all, d)
	return nil
}

func (m *mailbox) get() magiclink.SendMagicLinkData {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

func withMagicLink(mb *mailbox, o magiclink.Options) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		if o.SendMagicLink == nil {
			o.SendMagicLink = mb.send
		}
		c.Plugins = append(c.Plugins, magiclink.New(o))
	}
}

func verifyPath(token string, extra ...string) string {
	q := url.Values{"token": {token}}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return "/magic-link/verify?" + q.Encode()
}

func expectErrorRedirect(t *testing.T, r *resp, contains string) {
	t.Helper()
	if r.Status != 302 {
		t.Fatalf("expected 302, got %d: %s", r.Status, r.Body)
	}
	if loc := r.Header.Get("Location"); !strings.Contains(loc, contains) {
		t.Fatalf("location %q does not contain %q", loc, contains)
	}
}

func TestMagicLink(t *testing.T) {
	mb := &mailbox{}
	in := newInst(t, withMagicLink(mb, magiclink.Options{}))
	c := in.client(false)

	t.Run("should send magic link", func(t *testing.T) {
		expectStatus(t, c.post("/sign-in/magic-link", map[string]any{"email": testEmail}), 200, "")
		got := mb.get()
		if got.Email != testEmail || !strings.Contains(got.URL, "http://localhost:3000/api/auth/magic-link/verify") {
			t.Fatalf("unexpected email %+v", got)
		}
		if got.Metadata != nil {
			t.Fatalf("metadata = %v", got.Metadata)
		}
	})

	t.Run("should forward metadata to sendMagicLink", func(t *testing.T) {
		expectStatus(t, c.post("/sign-in/magic-link", map[string]any{"email": testEmail, "metadata": map[string]any{"inviteId": "123"}}), 200, "")
		got := mb.get()
		if got.Email != testEmail || got.Metadata["inviteId"] != "123" {
			t.Fatalf("unexpected email %+v", got)
		}
	})

	t.Run("should verify magic link", func(t *testing.T) {
		res := c.get(verifyPath(tokenFromURL(t, mb.get().URL)))
		expectStatus(t, res, 200, "")
		if res.str("token") == "" {
			t.Fatalf("no token: %s", res.Body)
		}
		if len(res.Header.Values("Set-Cookie")) == 0 {
			t.Fatal("no cookie")
		}
	})

	t.Run("shouldn't verify magic link with the same token", func(t *testing.T) {
		expectErrorRedirect(t, c.get(verifyPath(tokenFromURL(t, mb.get().URL))), "?error=INVALID_TOKEN")
	})

	t.Run("shouldn't verify magic link with an expired token", func(t *testing.T) {
		expectStatus(t, c.post("/sign-in/magic-link", map[string]any{"email": testEmail}), 200, "")
		token := mb.get().Token
		in.advance(5*time.Minute + time.Millisecond)
		expectErrorRedirect(t, c.get(verifyPath(token, "callbackURL", "/callback")), "?error=INVALID_TOKEN")
	})

	t.Run("should redirect to errorCallbackURL in case of error", func(t *testing.T) {
		res := c.get(verifyPath("invalid-token", "errorCallbackURL", "http://localhost:3000/error-page?foo=bar&baz=qux"))
		if res.Status != 302 {
			t.Fatalf("status %d", res.Status)
		}
		u, err := url.Parse(res.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if u.Scheme+"://"+u.Host != "http://localhost:3000" || u.Path != "/error-page" ||
			u.Query().Get("foo") != "bar" || u.Query().Get("baz") != "qux" || u.Query().Get("error") != "INVALID_TOKEN" {
			t.Fatalf("location %s", u)
		}
	})

	t.Run("should sign up with magic link", func(t *testing.T) {
		email := "new-email@email.com"
		expectStatus(t, c.post("/sign-in/magic-link", map[string]any{"email": email, "name": "test"}), 200, "")
		got := mb.get()
		if got.Email != email || !strings.Contains(got.URL, "http://localhost:3000/api/auth/magic-link/verify") {
			t.Fatalf("unexpected email %+v", got)
		}
		res := c.get(verifyPath(tokenFromURL(t, got.URL)))
		s := in.getSession(cookieHeader(res.Header))
		u := s["user"].(map[string]any)
		if u["name"] != "test" || u["email"] != email || u["emailVerified"] != true {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("should use custom generateToken function", func(t *testing.T) {
		called := false
		mb2 := &mailbox{}
		in2 := newInst(t, withMagicLink(mb2, magiclink.Options{GenerateToken: func(string) (string, error) {
			called = true
			return "custom_token", nil
		}}))
		in2.client(false).post("/sign-in/magic-link", map[string]any{"email": testEmail})
		if !called || mb2.get().Token != "custom_token" {
			t.Fatalf("called=%v token=%q", called, mb2.get().Token)
		}
	})
}

func TestMagicLinkValidateUserInfo(t *testing.T) {
	// should reject new-user magic link verify when validateUserInfo returns error
	mb := &mailbox{}
	in := newInst(t, func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, _ map[string]any, src betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
			if src.Method != "magic-link" {
				t.Errorf("source method = %q", src.Method)
			}
			return &betterauth.ValidateUserInfoResult{Error: "magic_link_blocked", ErrorDescription: "Magic link sign-up is not allowed"}, nil
		}}
		withMagicLink(mb, magiclink.Options{})(c)
	}, instOpts{disableTestUser: true})
	c := in.client(false)
	c.post("/sign-in/magic-link", map[string]any{"email": "new-magic-link@example.com"})
	res := c.get(verifyPath(tokenFromURL(t, mb.get().URL)))
	expectErrorRedirect(t, res, "error=magic_link_blocked")
	expectErrorRedirect(t, res, "error_description=Magic+link+sign-up+is+not+allowed")
}

func TestMagicLinkExistingUnverifiedUser(t *testing.T) {
	t.Run("should verify email and return emailVerified true in session for existing unverified user", func(t *testing.T) {
		mb := &mailbox{}
		in := newInst(t, withMagicLink(mb, magiclink.Options{}))
		email := "unverified-user@email.com"
		created := in.mustAPI("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": email, "name": "Unverified User", "password": "password123"}})
		if created["user"].(map[string]any)["emailVerified"] != false {
			t.Fatal("expected unverified")
		}
		c := in.client(false)
		c.post("/sign-in/magic-link", map[string]any{"email": email})
		res := c.get(verifyPath(tokenFromURL(t, mb.get().URL)))
		if res.val("user", "emailVerified") != true {
			t.Fatalf("response %s", res.Body)
		}
		s := in.getSession(cookieHeader(res.Header))
		if s["user"].(map[string]any)["emailVerified"] != true {
			t.Fatalf("session %v", s)
		}
		u, _ := in.ctx().InternalAdapter.FindUserByEmail(context.Background(), email, false)
		if !u.User.EmailVerified {
			t.Fatal("db user not verified")
		}
	})

	t.Run("should clear an unverified account's password when verify adopts it", func(t *testing.T) {
		mb := &mailbox{}
		in := newInst(t, func(c *betterauth.Config) {
			c.EmailAndPassword.RequireEmailVerification = true
			withMagicLink(mb, magiclink.Options{})(c)
		})
		email := "unverified-pw-user@email.com"
		existing := "existing-password-123"
		created := in.mustAPI("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": email, "name": "Test User", "password": existing}})
		user := created["user"].(map[string]any)
		userID := user["id"].(string)
		if user["emailVerified"] != false {
			t.Fatal("expected unverified")
		}
		ia := in.ctx().InternalAdapter
		if _, err := ia.CreateAccount(context.Background(), adapter.Record{"userId": userID, "providerId": "google", "accountId": "attacker-google"}); err != nil {
			t.Fatal(err)
		}
		if _, err := in.api("signInEmail", betterauth.CallInput{Body: map[string]any{"email": email, "password": existing}}); err == nil {
			t.Fatal("sign-in should fail before verification")
		}
		c := in.client(false)
		c.post("/sign-in/magic-link", map[string]any{"email": email})
		res := c.get(verifyPath(tokenFromURL(t, mb.get().URL)))
		if res.val("user", "emailVerified") != true {
			t.Fatalf("response %s", res.Body)
		}
		s := in.getSession(cookieHeader(res.Header))
		if s["user"].(map[string]any)["emailVerified"] != true {
			t.Fatalf("session %v", s)
		}
		accs, _ := ia.FindAccounts(context.Background(), userID)
		if len(accs) != 0 {
			t.Fatalf("accounts = %d", len(accs))
		}
		if _, err := in.api("signInEmail", betterauth.CallInput{Body: map[string]any{"email": email, "password": existing}}); err == nil {
			t.Fatal("old password should no longer work")
		}
	})
}

func TestMagicLinkAdditionalFields(t *testing.T) {
	// should return additional fields
	mb := &mailbox{}
	in := newInst(t, func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
			{Name: "foo", Type: db.TypeString, Required: db.Bool(false)},
		}}}
		withMagicLink(mb, magiclink.Options{})(c)
	})
	c := in.client(false)
	email := "test-email@test.com"
	c.post("/sign-in/magic-link", map[string]any{"email": email})
	res := c.get(verifyPath(tokenFromURL(t, mb.get().URL)))
	user, _ := res.val("user").(map[string]any)
	if user == nil {
		t.Fatalf("no user: %s", res.Body)
	}
	// toBeNull upstream (SQLite returns NULL for the unset column); the memory adapter
	// omits never-written columns, so absent is accepted as null here.
	if v := user["foo"]; v != nil {
		t.Fatalf("foo = %v", v)
	}
	h := cookieHeader(res.Header)
	if _, err := in.api("updateUser", betterauth.CallInput{Body: map[string]any{"foo": "bar"}, Headers: h}); err != nil {
		t.Fatal(err)
	}
	c.post("/sign-in/magic-link", map[string]any{"email": email})
	res = c.get(verifyPath(tokenFromURL(t, mb.get().URL)))
	if res.val("user", "foo") != "bar" {
		t.Fatalf("response %s", res.Body)
	}
}

func TestMagicLinkVerify(t *testing.T) {
	// should verify last magic link
	mb := &mailbox{}
	in := newInst(t, withMagicLink(mb, magiclink.Options{}))
	c := in.client(false)
	for range 3 {
		c.post("/sign-in/magic-link", map[string]any{"email": testEmail})
	}
	res := c.get(verifyPath(tokenFromURL(t, mb.get().URL)))
	if res.str("token") == "" || len(res.Header.Values("Set-Cookie")) == 0 {
		t.Fatalf("response %d %s", res.Status, res.Body)
	}
}

func TestMagicLinkVerifyOriginValidation(t *testing.T) {
	// should reject untrusted callbackURL on verify
	mb := &mailbox{}
	in := newInst(t, func(c *betterauth.Config) {
		c.TrustedOrigins = []string{"http://localhost:3000"}
		c.Advanced = &betterauth.AdvancedConfig{DisableOriginCheck: betterauth.Bool(false)}
		withMagicLink(mb, magiclink.Options{})(c)
	})
	c := in.client(false)
	c.post("/sign-in/magic-link", map[string]any{"email": testEmail})
	res := c.get(verifyPath(tokenFromURL(t, mb.get().URL), "callbackURL", "http://malicious.com"))
	if res.Status != 403 || res.str("message") != "Invalid callbackURL" {
		t.Fatalf("got %d %s", res.Status, res.Body)
	}
}

func TestMagicLinkStoreToken(t *testing.T) {
	run := func(t *testing.T, store magiclink.StoreToken, stored func(string) string) {
		mb := &mailbox{}
		in := newInst(t, withMagicLink(mb, magiclink.Options{StoreToken: store}))
		h := in.signIn(testEmail, testPassword)
		in.mustAPI("signInMagicLink", betterauth.CallInput{Body: map[string]any{"email": testEmail}, Headers: h})
		v, err := in.ctx().InternalAdapter.FindVerificationValue(context.Background(), "magic-link:"+stored(mb.get().Token))
		if err != nil || v == nil {
			t.Fatalf("stored token not found: %v", err)
		}
		res := in.mustAPI("signInMagicLink", betterauth.CallInput{Body: map[string]any{"email": testEmail}, Headers: h})
		if res["status"] != true {
			t.Fatalf("response %v", res)
		}
	}
	t.Run("should store token in hashed", func(t *testing.T) {
		run(t, magiclink.StoreToken{Mode: "hashed"}, magiclink.DefaultKeyHasher)
	})
	t.Run("should store token with custom hasher", func(t *testing.T) {
		run(t, magiclink.StoreToken{Hash: func(token string) (string, error) { return token + "hashed", nil }},
			func(tok string) string { return tok + "hashed" })
	})
}

func TestMagicLinkSingleUseSemantics(t *testing.T) {
	setup := func(t *testing.T, allowedAttempts int) (*inst, *client, *mailbox) {
		mb := &mailbox{}
		in := newInst(t, withMagicLink(mb, magiclink.Options{AllowedAttempts: allowedAttempts}))
		c := in.client(false)
		c.post("/sign-in/magic-link", map[string]any{"email": testEmail})
		return in, c, mb
	}
	secondFails := func(t *testing.T, allowed int) {
		_, c, mb := setup(t, allowed)
		token := tokenFromURL(t, mb.get().URL)
		res := c.get(verifyPath(token))
		if res.str("token") == "" || len(res.Header.Values("Set-Cookie")) == 0 {
			t.Fatalf("first verify: %d %s", res.Status, res.Body)
		}
		expectErrorRedirect(t, c.get(verifyPath(token)), "?error=INVALID_TOKEN")
	}
	t.Run("rejects the second verification with the default allowedAttempts (1)", func(t *testing.T) { secondFails(t, 0) })
	t.Run("rejects the second verification even when allowedAttempts is set to 3", func(t *testing.T) { secondFails(t, 3) })
	t.Run("rejects the second verification even when allowedAttempts is Infinity", func(t *testing.T) { secondFails(t, int(^uint(0)>>1)) })
	t.Run("mints at most one session under concurrent verification of the same token", func(t *testing.T) {
		_, c, mb := setup(t, 0)
		token := tokenFromURL(t, mb.get().URL)
		var wg sync.WaitGroup
		out := make([]*resp, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out[i] = c.get(verifyPath(token))
			}()
		}
		wg.Wait()
		n := 0
		for _, r := range out {
			if r.str("token") != "" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("sessions minted = %d", n)
		}
	})
}

func TestMagicLinkSendOriginCSRF(t *testing.T) {
	calls := 0
	var mu sync.Mutex
	in := newInst(t, func(c *betterauth.Config) {
		c.TrustedOrigins = []string{"http://localhost:3000"}
		c.Advanced = &betterauth.AdvancedConfig{DisableCSRFCheck: betterauth.Bool(false), DisableOriginCheck: betterauth.Bool(false)}
		c.Plugins = append(c.Plugins, magiclink.New(magiclink.Options{SendMagicLink: func(*betterauth.EndpointContext, magiclink.SendMagicLinkData) error {
			mu.Lock()
			calls++
			mu.Unlock()
			return nil
		}}))
	})
	c := in.client(false)
	t.Run("should block cross-site navigation to the send endpoint (no cookies)", func(t *testing.T) {
		calls = 0
		res := c.post("/sign-in/magic-link", map[string]any{"email": "attacker@evil.com"}, http.Header{
			"Sec-Fetch-Site": {"cross-site"}, "Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}, "Origin": {"https://evil.com"}})
		if res.Status != 403 || calls != 0 {
			t.Fatalf("status %d calls %d", res.Status, calls)
		}
	})
	t.Run("should reject a cookieless cross-origin POST to the send endpoint", func(t *testing.T) {
		calls = 0
		res := c.post("/sign-in/magic-link", map[string]any{"email": "attacker@evil.com"}, http.Header{"Origin": {"https://evil.com"}})
		if res.Status != 403 || calls != 0 {
			t.Fatalf("status %d calls %d", res.Status, calls)
		}
	})
	t.Run("should still allow a cookieless request with no Origin (server-to-server)", func(t *testing.T) {
		calls = 0
		res := c.post("/sign-in/magic-link", map[string]any{"email": testEmail})
		if res.Status != 200 || calls != 1 {
			t.Fatalf("status %d calls %d", res.Status, calls)
		}
	})
}
