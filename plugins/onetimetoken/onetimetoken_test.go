package onetimetoken_test

// Port of packages/better-auth/src/plugins/one-time-token/one-time-token.test.ts (v1.7.7).
// vi.advanceTimersByTime is emulated by inst.advance (shifting stored timestamps back).

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/onetimetoken"
)

func withPlugin(o onetimetoken.Options) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.Plugins = append(c.Plugins, onetimetoken.New(o)) }
}

func (in *inst) generate() string {
	in.t.Helper()
	m := in.mustAPI("generateOneTimeToken", betterauth.CallInput{Headers: in.signIn(testEmail, testPassword)})
	tok, _ := m["token"].(string)
	if tok == "" {
		in.t.Fatalf("no token: %v", m)
	}
	return tok
}

func (in *inst) verify(token string) (*betterauth.CallResult, error) {
	return in.api("verifyOneTimeToken", betterauth.CallInput{Body: map[string]any{"token": token}})
}

func TestOneTimeToken(t *testing.T) {
	in := newInst(t, withPlugin(onetimetoken.Options{}))

	t.Run("should work", func(t *testing.T) {
		tok := in.generate()
		res, err := in.verify(tok)
		if err != nil || res.Data == nil {
			t.Fatalf("verify: %v", err)
		}
		if _, err := in.verify(tok); err == nil {
			t.Fatal("second verify should fail")
		} else {
			apiErr(t, err)
		}
	})

	t.Run("should expire", func(t *testing.T) {
		tok := in.generate()
		in.advance(5 * time.Minute)
		_, err := in.verify(tok)
		apiErr(t, err)
	})

	t.Run("should only redeem a token once under concurrent verification", func(t *testing.T) {
		tok := in.generate()
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = in.auth.API.Call(context.Background(), "verifyOneTimeToken", betterauth.CallInput{Body: map[string]any{"token": tok}})
			}()
		}
		wg.Wait()
		ok, failed := 0, 0
		for _, e := range errs {
			if e == nil {
				ok++
			} else {
				apiErr(t, e)
				failed++
			}
		}
		if ok != 1 || failed != 1 {
			t.Fatalf("fulfilled=%d rejected=%d", ok, failed)
		}
	})

	t.Run("should work with client", func(t *testing.T) {
		h := in.signIn(testEmail, testPassword)
		c := in.client(false)
		res := c.get("/one-time-token/generate", h)
		expectStatus(t, res, 200, "")
		tok := res.str("token")
		if tok == "" {
			t.Fatal("no token")
		}
		v := c.post("/one-time-token/verify", map[string]any{"token": tok})
		expectStatus(t, v, 200, "")
		if v.val("session") == nil {
			t.Fatalf("no session: %s", v.Body)
		}
	})
}

func TestOneTimeTokenSessionExpired(t *testing.T) {
	// should reject token when underlying session has expired
	in := newInst(t, func(c *betterauth.Config) {
		c.Session = &betterauth.SessionConfig{ExpiresIn: 60 * time.Second, UpdateAge: betterauth.Duration(0)}
		c.Plugins = append(c.Plugins, onetimetoken.New(onetimetoken.Options{ExpiresIn: 10 * time.Minute}))
	})
	tok := in.generate()
	in.advance(2 * time.Minute)
	_, err := in.verify(tok)
	if e := apiErr(t, err); e.Message() != "Session expired" {
		t.Fatalf("message = %q", e.Message())
	}
}

func TestOneTimeTokenStoreToken(t *testing.T) {
	t.Run("hashed/should work with hashed", func(t *testing.T) {
		in := newInst(t, withPlugin(onetimetoken.Options{
			StoreToken: onetimetoken.StoreToken{Mode: "hashed"},
			GenerateToken: func(*betterauth.SessionWithUser, *betterauth.EndpointContext) (string, error) {
				return "123456", nil
			},
		}))
		tok := in.generate()
		if tok != "123456" {
			t.Fatalf("token = %q", tok)
		}
		v, err := in.ctx().InternalAdapter.FindVerificationValue(context.Background(), "one-time-token:"+onetimetoken.DefaultKeyHasher(tok))
		if err != nil || v == nil {
			t.Fatalf("stored token not found: %v", err)
		}
		res, err := in.verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			User struct{ Email string } `json:"user"`
		}
		_ = res.Decode(&out)
		if out.User.Email == "" {
			t.Fatal("missing user email")
		}
	})

	t.Run("custom hasher/should work with custom hasher", func(t *testing.T) {
		in := newInst(t, withPlugin(onetimetoken.Options{
			StoreToken: onetimetoken.StoreToken{Hash: func(token string) (string, error) { return token + "hashed", nil }},
			GenerateToken: func(*betterauth.SessionWithUser, *betterauth.EndpointContext) (string, error) {
				return "123456", nil
			},
		}))
		tok := in.generate()
		if tok != "123456" {
			t.Fatalf("token = %q", tok)
		}
		v, err := in.ctx().InternalAdapter.FindVerificationValue(context.Background(), "one-time-token:"+tok+"hashed")
		if err != nil || v == nil {
			t.Fatalf("stored token not found: %v", err)
		}
		if _, err := in.verify(tok); err != nil {
			t.Fatal(err)
		}
	})
}

func TestOneTimeTokenDisableClientRequest(t *testing.T) {
	in := newInst(t, withPlugin(onetimetoken.Options{DisableClientRequest: true}))
	t.Run("should allow server-side requests", func(t *testing.T) {
		in.generate()
	})
	t.Run("should reject client requests when disableClientRequest is true", func(t *testing.T) {
		res := in.client(false).get("/one-time-token/generate", in.signIn(testEmail, testPassword))
		if res.str("message") != "Client requests are disabled" {
			t.Fatalf("got %d %s", res.Status, res.Body)
		}
	})
}

func TestOneTimeTokenDisableSetSessionCookie(t *testing.T) {
	t.Run("should not set session cookie when disableSetSessionCookie is true", func(t *testing.T) {
		in := newInst(t, withPlugin(onetimetoken.Options{DisableSetSessionCookie: true}))
		tok := in.generate()
		res, err := in.verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		if sc := res.Headers.Values("Set-Cookie"); len(sc) != 0 {
			t.Fatalf("unexpected Set-Cookie: %v", sc)
		}
	})
	t.Run("should set session cookie by default", func(t *testing.T) {
		in := newInst(t, withPlugin(onetimetoken.Options{}))
		tok := in.generate()
		res, err := in.verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, sc := range res.Headers.Values("Set-Cookie") {
			if strings.Contains(sc, "better-auth.session_token") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no session cookie: %v", res.Headers.Values("Set-Cookie"))
		}
	})
}

func TestOneTimeTokenSetOttHeaderOnNewSession(t *testing.T) {
	t.Run("should set OTT header on new session when enabled", func(t *testing.T) {
		in := newInst(t, withPlugin(onetimetoken.Options{SetOttHeaderOnNewSession: true}))
		res, err := in.api("signUpEmail", betterauth.CallInput{Body: map[string]any{
			"email": "ott-header-test@test.com", "password": "password123", "name": "OTT Header Test"}})
		if err != nil {
			t.Fatal(err)
		}
		if ott := res.Headers.Get("set-ott"); len(ott) != 32 {
			t.Fatalf("set-ott = %q", ott)
		}
		if exp := res.Headers.Get("access-control-expose-headers"); !strings.Contains(exp, "set-ott") {
			t.Fatalf("expose headers = %q", exp)
		}
	})
	t.Run("should not set OTT header on new session by default", func(t *testing.T) {
		in := newInst(t, withPlugin(onetimetoken.Options{}))
		res, err := in.api("signUpEmail", betterauth.CallInput{Body: map[string]any{
			"email": "ott-header-test-default@test.com", "password": "password123", "name": "OTT Header Test Default"}})
		if err != nil {
			t.Fatal(err)
		}
		if ott := res.Headers.Get("set-ott"); ott != "" {
			t.Fatalf("set-ott = %q", ott)
		}
	})
	t.Run("should set OTT header on sign in when enabled", func(t *testing.T) {
		in := newInst(t, withPlugin(onetimetoken.Options{SetOttHeaderOnNewSession: true}))
		if _, err := in.api("signUpEmail", betterauth.CallInput{Body: map[string]any{
			"email": "ott-signin-test@test.com", "password": "password123", "name": "OTT SignIn Test"}}); err != nil {
			t.Fatal(err)
		}
		res, err := in.api("signInEmail", betterauth.CallInput{Body: map[string]any{
			"email": "ott-signin-test@test.com", "password": "password123"}})
		if err != nil {
			t.Fatal(err)
		}
		if ott := res.Headers.Get("set-ott"); len(ott) != 32 {
			t.Fatalf("set-ott = %q", ott)
		}
	})
}
