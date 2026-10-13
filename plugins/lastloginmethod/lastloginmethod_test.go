package lastloginmethod_test

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
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/plugins/lastloginmethod"
)

const cookieName = "better-auth.last_used_login_method"

// applySetCookies is cookieSetter (setCookieToHeader).
func applySetCookies(h http.Header, res *response) {
	for _, sc := range res.Header.Values("Set-Cookie") {
		n, v, _ := betterauth.ParseSetCookie(sc)
		betterauth.SetRequestCookie(h, n, v)
	}
}

func cookieOf(h http.Header, name string) (string, bool) {
	for _, c := range betterauth.ParseCookies(h.Get("Cookie")) {
		if c.Name == name {
			return c.Value, true
		}
	}
	return "", false
}

func withPlugins(ps ...*betterauth.Plugin) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.Plugins = append(c.Plugins, ps...) }
}

// signInCookies signs the test user in and returns the cookies merged from the response.
func signInCookies(t *testing.T, in *instance, email, password string) (http.Header, *response) {
	t.Helper()
	res := in.do("POST", "/sign-in/email", map[string]any{"email": email, "password": password}, nil)
	h := http.Header{}
	if res.Status == 200 {
		applySetCookies(h, res)
	}
	return h, res
}

func expectMethod(t *testing.T, h http.Header, name, want string) {
	t.Helper()
	v, ok := cookieOf(h, name)
	if want == "" {
		if ok {
			t.Fatalf("cookie %s should not be set (got %q)", name, v)
		}
		return
	}
	if v != want {
		t.Fatalf("cookie %s = %q, want %q (%s)", name, v, want, h.Get("Cookie"))
	}
}

// dbMethod reads user.lastLoginMethod through get-session with a bearer token.
func dbMethod(t *testing.T, in *instance, token string) any {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	r, err := in.auth.API.Call(context.Background(), "getSession", betterauth.CallInput{Headers: h})
	if err != nil {
		t.Fatal(err)
	}
	var s struct{ User map[string]any }
	if err := r.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s.User["lastLoginMethod"]
}

// ---- stand-ins for the email-otp, siwe and magic-link plugins ----
// The method resolution only depends on the endpoint path, so these endpoints sign the
// user in (creating them when needed) at the same paths as the real plugins.

func signInUser(ctx *betterauth.EndpointContext, email string) (*betterauth.SessionWithUser, error) {
	ia := ctx.Auth.InternalAdapter
	u, err := ia.FindUserByEmail(ctx.Context(), email, false)
	if err != nil {
		return nil, err
	}
	var user *betterauth.User
	if u != nil {
		user = u.User
	} else {
		user, err = ia.CreateUser(ctx.Context(), adapter.Record{"email": email, "name": "", "emailVerified": true},
			betterauth.UserInfoSource{Action: "create-user", Method: "email-password"})
		if err != nil {
			return nil, err
		}
	}
	s, err := ia.CreateSession(ctx.Context(), user.ID, nil)
	if err != nil {
		return nil, err
	}
	sw := &betterauth.SessionWithUser{Session: s, User: user}
	return sw, betterauth.SetSessionCookie(ctx, sw, nil, nil)
}

func fakeMethodsPlugin() *betterauth.Plugin {
	respond := func(ctx *betterauth.EndpointContext, email string) (any, error) {
		sw, err := signInUser(ctx, email)
		if err != nil {
			return nil, err
		}
		return map[string]any{"token": sw.Session.Token, "success": true}, nil
	}
	return &betterauth.Plugin{ID: "fake-methods", Endpoints: []*betterauth.Endpoint{
		{Key: "signInEmailOTP", Path: "/sign-in/email-otp", Methods: []string{"POST"}, Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			return respond(ctx, ctx.BodyString("email"))
		}},
		{Key: "verifySiweMessage", Path: "/siwe/verify", Methods: []string{"POST"}, Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			return respond(ctx, ctx.BodyString("email"))
		}},
		{Key: "magicLinkVerify", Path: "/magic-link/verify", Methods: []string{"GET"}, Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if _, err := signInUser(ctx, ctx.QueryString("email")); err != nil {
				return nil, err
			}
			return nil, ctx.Redirect(ctx.QueryString("callbackURL"))
		}},
		// an endpoint without a path (server-only), creating a user and a session
		{Key: "createWithoutPath", ServerOnly: true, Methods: []string{"POST"}, Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			return respond(ctx, ctx.BodyString("email"))
		}},
	}}
}

// fakeGoogle is an OAuth provider standing in for the msw-mocked Google endpoints.
type fakeGoogle struct {
	id    string
	email string
}

func (p *fakeGoogle) ID() string   { return p.id }
func (p *fakeGoogle) Name() string { return p.id }
func (p *fakeGoogle) CreateAuthorizationURL(_ context.Context, a oauth2.AuthorizationURLParams) (*url.URL, error) {
	return url.Parse("https://accounts.google.com/o/oauth2/auth?state=" + url.QueryEscape(a.State))
}
func (p *fakeGoogle) ValidateAuthorizationCode(_ context.Context, c oauth2.CodeParams) (*oauth2.Tokens, error) {
	if c.Code != "test" {
		return nil, errors.New("invalid code")
	}
	return &oauth2.Tokens{AccessToken: "test-access-token", RefreshToken: "test-refresh-token"}, nil
}
func (p *fakeGoogle) GetUserInfo(context.Context, oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
	return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "OAuth Test User", Email: p.email, EmailVerified: true},
		Data: map[string]any{"sub": "1234567890", "email": p.email}}, nil
}
func (p *fakeGoogle) AccountSubject(context.Context, *oauth2.Tokens, map[string]any) (string, error) {
	return "1234567890", nil
}

func withGoogle(id, email string) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		c.SocialProviders = append(c.SocialProviders, &fakeGoogle{id: id, email: email})
	}
}

// oauthSignIn runs /sign-in/social + /callback/<id> and returns the callback response.
func oauthSignIn(t *testing.T, in *instance, provider string) *response {
	t.Helper()
	start := in.do("POST", "/sign-in/social", map[string]any{"provider": provider, "callbackURL": "/callback"}, nil)
	if start.Status != 200 {
		t.Fatalf("sign-in/social %d %s", start.Status, start.Body)
	}
	oauth := http.Header{}
	applySetCookies(oauth, start)
	u, _ := url.Parse(start.json(t)["url"].(string))
	cb := in.do("GET", "/callback/"+provider+"?state="+url.QueryEscape(u.Query().Get("state"))+"&code=test", nil, oauth)
	if cb.Status != 302 || cb.Header.Get("Location") == "" {
		t.Fatalf("callback %d %s", cb.Status, cb.Body)
	}
	return cb
}

func TestLastLoginMethod(t *testing.T) {
	in := newInstance(t, withPlugins(lastloginmethod.New(), fakeMethodsPlugin()))

	t.Run("should set the last login method cookie", func(t *testing.T) {
		h, _ := signInCookies(t, in, in.email, in.password)
		expectMethod(t, h, cookieName, "email")
	})
	t.Run("should set the last login method cookie for email OTP", func(t *testing.T) {
		h := http.Header{}
		applySetCookies(h, in.do("POST", "/sign-in/email-otp", map[string]any{"email": in.email, "otp": "123456"}, nil))
		expectMethod(t, h, cookieName, "email-otp")
	})
	t.Run("should set the last login method cookie for siwe", func(t *testing.T) {
		h := http.Header{}
		applySetCookies(h, in.do("POST", "/siwe/verify", map[string]any{"message": "m", "signature": "valid_signature", "email": "user@example.com"}, nil))
		expectMethod(t, h, cookieName, "siwe")
	})
	t.Run("should set the last login method cookie for magic-link", func(t *testing.T) {
		res := in.do("GET", "/magic-link/verify?email="+url.QueryEscape(in.email)+"&callbackURL=%2Fcallback", nil, nil)
		if res.Status != 302 {
			t.Fatalf("status %d", res.Status)
		}
		h := http.Header{}
		applySetCookies(h, res)
		expectMethod(t, h, cookieName, "magic-link")
	})
	t.Run("should NOT set the last login method cookie on failed authentication", func(t *testing.T) {
		res := in.do("POST", "/sign-in/email", map[string]any{"email": in.email, "password": "wrong-password"}, nil)
		if res.Status == 200 {
			t.Fatal("expected an error")
		}
		h := http.Header{}
		applySetCookies(h, res)
		expectMethod(t, h, cookieName, "")
	})
	t.Run("should NOT set the last login method cookie on failed OAuth callback", func(t *testing.T) {
		res := in.do("GET", "/callback/google?code=invalid-code&state=invalid-state", nil, nil)
		if res.Status == 200 {
			t.Fatal("expected an error")
		}
		h := http.Header{}
		applySetCookies(h, res)
		expectMethod(t, h, cookieName, "")
	})
	t.Run("should ignore missing path in after hooks", func(t *testing.T) {
		p := lastloginmethod.New()
		r, err := p.Hooks.After[0].Handler(&betterauth.EndpointContext{Path: ""})
		if r != nil || err != nil {
			t.Fatalf("%v %v", r, err)
		}
	})
}

func TestLastLoginMethodDatabase(t *testing.T) {
	t.Run("should set the last login method for magic-link in the database", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true}), fakeMethodsPlugin()))
		res := in.do("GET", "/magic-link/verify?email="+url.QueryEscape(in.email)+"&callbackURL=%2F", nil, nil)
		tok, _ := setCookie(res, "better-auth.session_token")
		if tok == "" {
			t.Fatal("no session token")
		}
		if m := dbMethod(t, in, tok); m != "magic-link" {
			t.Fatalf("lastLoginMethod %v", m)
		}
	})
	t.Run("should set the last login method in the database", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true})))
		_, res := signInCookies(t, in, in.email, in.password)
		if m := dbMethod(t, in, res.json(t)["token"].(string)); m != "email" {
			t.Fatalf("lastLoginMethod %v", m)
		}
	})
	t.Run("should set the last login method for siwe in the database", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true}), fakeMethodsPlugin()))
		res := in.do("POST", "/siwe/verify", map[string]any{"message": "m", "signature": "valid_signature", "email": "user@example.com"}, nil)
		if m := dbMethod(t, in, res.json(t)["token"].(string)); m != "siwe" {
			t.Fatalf("lastLoginMethod %v", m)
		}
	})
	t.Run("should ignore missing path in database hooks", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true}), fakeMethodsPlugin()))
		r, err := in.auth.API.Call(context.Background(), "createWithoutPath", betterauth.CallInput{Body: map[string]any{"email": "nopath@example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Token string }
		_ = r.Decode(&out)
		if m := dbMethod(t, in, out.Token); m != nil {
			t.Fatalf("lastLoginMethod %v", m)
		}
	})
	t.Run("should normalize missing path for custom resolver in database hooks", func(t *testing.T) {
		var mu sync.Mutex
		var paths []string
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true,
			CustomResolveMethod: func(ctx *betterauth.EndpointContext) (string, bool) {
				mu.Lock()
				paths = append(paths, ctx.Path)
				mu.Unlock()
				if strings.HasPrefix(ctx.Path, "/magic-link") {
					return "magic-link", true
				}
				return "", false
			}}), fakeMethodsPlugin()))
		mu.Lock()
		paths = nil
		mu.Unlock()
		r, err := in.auth.API.Call(context.Background(), "createWithoutPath", betterauth.CallInput{Body: map[string]any{"email": "nopath2@example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Token string }
		_ = r.Decode(&out)
		mu.Lock()
		got := append([]string(nil), paths...)
		mu.Unlock()
		if len(got) < 2 || got[0] != "" || got[1] != "" {
			t.Fatalf("resolver paths %q", got)
		}
		if m := dbMethod(t, in, out.Token); m != nil {
			t.Fatalf("lastLoginMethod %v", m)
		}
	})
	t.Run("should update the last login method in the database on subsequent logins", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true})))
		in.do("POST", "/sign-up/email", map[string]any{"email": "test@example.com", "password": "password123", "name": "Test User"}, nil)
		h, res := signInCookies(t, in, "test@example.com", "password123")
		if m := dbMethod(t, in, res.json(t)["token"].(string)); m != "email" {
			t.Fatalf("lastLoginMethod %v", m)
		}
		in.do("POST", "/sign-out", nil, h)
		_, res = signInCookies(t, in, "test@example.com", "password123")
		if m := dbMethod(t, in, res.json(t)["token"].(string)); m != "email" {
			t.Fatalf("lastLoginMethod %v", m)
		}
	})
	t.Run("should update the last login method in the database on subsequent logins with email and OAuth", func(t *testing.T) {
		const email = "github-issue-demo@example.com"
		in := newInstance(t, func(c *betterauth.Config) {
			withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true}))(c)
			withGoogle("google", email)(c)
			c.Account = &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{Enabled: betterauth.Bool(true), TrustedProviders: []string{"google"}}}
			c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				Before: func(context.Context, adapter.Record) (*betterauth.DBHookResult, error) {
					return &betterauth.DBHookResult{Data: adapter.Record{"emailVerified": true}}, nil
				},
			}}}
		})
		in.do("POST", "/sign-up/email", map[string]any{"email": email, "password": "password123", "name": "GitHub Issue Demo User"}, nil)
		h, res := signInCookies(t, in, email, "password123")
		if m := dbMethod(t, in, res.json(t)["token"].(string)); m != "email" {
			t.Fatalf("lastLoginMethod %v", m)
		}
		in.do("POST", "/sign-out", nil, h)
		cb := oauthSignIn(t, in, "google")
		if v, ok := setCookie(cb, cookieName); ok && v != "google" {
			t.Fatalf("cookie %q", v)
		}
		oh := http.Header{}
		applySetCookies(oh, cb)
		s := in.do("GET", "/get-session", nil, oh).json(t)
		if s["user"].(map[string]any)["lastLoginMethod"] != "google" {
			t.Fatalf("session %v", s)
		}
	})
	t.Run("should set the last login method for generic OAuth provider with /callback/:providerId", func(t *testing.T) {
		in := newInstance(t, func(c *betterauth.Config) {
			withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true}))(c)
			withGoogle("my-provider-id", "generic@example.com")(c)
		})
		cb := oauthSignIn(t, in, "my-provider-id")
		if v, ok := setCookie(cb, cookieName); ok && v != "my-provider-id" {
			t.Fatalf("cookie %q", v)
		}
		oh := http.Header{}
		applySetCookies(oh, cb)
		s := in.do("GET", "/get-session", nil, oh).json(t)
		if s["user"].(map[string]any)["lastLoginMethod"] != "my-provider-id" {
			t.Fatalf("session %v", s)
		}
	})
}

func setCookie(res *response, name string) (string, bool) {
	val, found := "", false
	for _, sc := range res.Header.Values("Set-Cookie") {
		n, v, _ := betterauth.ParseSetCookie(sc)
		if n == name {
			val, found = v, true
		}
	}
	return val, found
}

func before(fn func(*betterauth.EndpointContext, string) (bool, error)) func(c *betterauth.Config) {
	return withPlugins(lastloginmethod.New(lastloginmethod.Options{BeforeStoreCookie: fn}))
}

func TestBeforeStoreCookieHook(t *testing.T) {
	signIn := func(t *testing.T, in *instance) http.Header {
		h, _ := signInCookies(t, in, in.email, in.password)
		return h
	}
	t.Run("should set cookie when beforeStoreCookie returns true", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) { return true, nil }))
		expectMethod(t, signIn(t, in), cookieName, "email")
	})
	t.Run("should NOT set cookie when beforeStoreCookie returns false", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) { return false, nil }))
		expectMethod(t, signIn(t, in), cookieName, "")
	})
	t.Run("should set cookie when beforeStoreCookie returns Promise<true>", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) {
			time.Sleep(10 * time.Millisecond)
			return true, nil
		}))
		expectMethod(t, signIn(t, in), cookieName, "email")
	})
	t.Run("should NOT set cookie when beforeStoreCookie returns Promise<false>", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) {
			time.Sleep(10 * time.Millisecond)
			return false, nil
		}))
		expectMethod(t, signIn(t, in), cookieName, "")
	})
	t.Run("should set cookie when beforeStoreCookie is undefined (default behavior)", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New()))
		expectMethod(t, signIn(t, in), cookieName, "email")
	})
	t.Run("should conditionally set cookie based on login method", func(t *testing.T) {
		in := newInstance(t, func(c *betterauth.Config) {
			before(func(_ *betterauth.EndpointContext, m string) (bool, error) { return m == "email", nil })(c)
			withGoogle("google", "oauth@example.com")(c)
		})
		expectMethod(t, signIn(t, in), cookieName, "email")
		oh := http.Header{}
		applySetCookies(oh, oauthSignIn(t, in, "google"))
		expectMethod(t, oh, cookieName, "")
	})
	t.Run("should conditionally set cookie based on context properties", func(t *testing.T) {
		in := newInstance(t, before(func(ctx *betterauth.EndpointContext, _ string) (bool, error) {
			return strings.Contains(ctx.Path, "sign-in"), nil
		}))
		expectMethod(t, signIn(t, in), cookieName, "email")
	})
	t.Run("should allow different behavior for different login methods", func(t *testing.T) {
		allowed := map[string]bool{"email": true, "google": true}
		in := newInstance(t, func(c *betterauth.Config) {
			before(func(_ *betterauth.EndpointContext, m string) (bool, error) { return allowed[m], nil })(c)
			withGoogle("google", "oauth@example.com")(c)
		})
		expectMethod(t, signIn(t, in), cookieName, "email")
		oh := http.Header{}
		applySetCookies(oh, oauthSignIn(t, in, "google"))
		expectMethod(t, oh, cookieName, "google")
	})
	t.Run("should handle dynamic consent changes between logins", func(t *testing.T) {
		var consent bool
		var mu sync.Mutex
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			return consent, nil
		}))
		h1 := signIn(t, in)
		expectMethod(t, h1, cookieName, "")
		mu.Lock()
		consent = true
		mu.Unlock()
		in.do("POST", "/sign-out", nil, h1)
		expectMethod(t, signIn(t, in), cookieName, "email")
	})
	t.Run("should handle falsy return values correctly", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) { return false, nil }))
		expectMethod(t, signIn(t, in), cookieName, "")
	})
	t.Run("should handle truthy return values correctly", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) { return true, nil }))
		expectMethod(t, signIn(t, in), cookieName, "email")
	})
	t.Run("should receive correct context and lastUsedLoginMethod parameters", func(t *testing.T) {
		var path, method string
		in := newInstance(t, before(func(ctx *betterauth.EndpointContext, m string) (bool, error) {
			path, method = ctx.Path, m
			return true, nil
		}))
		signIn(t, in)
		if path != "/sign-in/email" || method != "email" {
			t.Fatalf("path %q method %q", path, method)
		}
	})
	t.Run("should work correctly with sign-up flow", func(t *testing.T) {
		in := newInstance(t, before(func(_ *betterauth.EndpointContext, m string) (bool, error) { return m == "email", nil }))
		h := http.Header{}
		applySetCookies(h, in.do("POST", "/sign-up/email", map[string]any{"email": "newuser@example.com", "password": "password123", "name": "New User"}, nil))
		expectMethod(t, h, cookieName, "email")
	})
	t.Run("should handle async operations in beforeStoreCookie", func(t *testing.T) {
		in := newInstance(t, before(func(_ *betterauth.EndpointContext, m string) (bool, error) {
			time.Sleep(50 * time.Millisecond)
			return m == "email", nil
		}))
		expectMethod(t, signIn(t, in), cookieName, "email")
	})
	t.Run("should NOT set cookie when beforeStoreCookie throws an error", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) { panic("GDPR check failed") }))
		h, res := signInCookies(t, in, in.email, in.password)
		if res.Status != 200 {
			t.Fatalf("sign-in should succeed: %d", res.Status)
		}
		expectMethod(t, h, cookieName, "")
		if _, ok := setCookie(res, cookieName); ok {
			t.Fatal("set-cookie present")
		}
	})
	t.Run("should NOT set cookie when beforeStoreCookie returns a rejected promise", func(t *testing.T) {
		in := newInstance(t, before(func(*betterauth.EndpointContext, string) (bool, error) {
			time.Sleep(10 * time.Millisecond)
			return false, errors.New("GDPR check failed")
		}))
		h, res := signInCookies(t, in, in.email, in.password)
		if res.Status != 200 {
			t.Fatalf("sign-in should succeed: %d", res.Status)
		}
		expectMethod(t, h, cookieName, "")
		if _, ok := setCookie(res, cookieName); ok {
			t.Fatal("set-cookie present")
		}
	})
	t.Run("should handle complex GDPR consent logic", func(t *testing.T) {
		in := newInstance(t, before(func(_ *betterauth.EndpointContext, m string) (bool, error) { return m == "email", nil }))
		in.do("POST", "/sign-up/email", map[string]any{"email": "test-gdpr@example.com", "password": "password123", "name": "Test GDPR User"}, nil)
		h, _ := signInCookies(t, in, "test-gdpr@example.com", "password123")
		expectMethod(t, h, cookieName, "email")
	})
	t.Run("should work correctly with custom cookie name", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{CookieName: "custom.last_login_method",
			BeforeStoreCookie: func(*betterauth.EndpointContext, string) (bool, error) { return true, nil }})))
		h := signIn(t, in)
		expectMethod(t, h, "custom.last_login_method", "email")
		expectMethod(t, h, cookieName, "")
	})
	t.Run("should combine beforeStoreCookie with storeInDatabase correctly", func(t *testing.T) {
		in := newInstance(t, withPlugins(lastloginmethod.New(lastloginmethod.Options{StoreInDatabase: true,
			BeforeStoreCookie: func(_ *betterauth.EndpointContext, m string) (bool, error) { return m == "email", nil }})))
		_, res := signInCookies(t, in, in.email, in.password)
		if m := dbMethod(t, in, res.json(t)["token"].(string)); m != "email" {
			t.Fatalf("lastLoginMethod %v", m)
		}
	})
}

func TestLastLoginMethodCookies(t *testing.T) {
	t.Run("should clear cross-subdomain cookies by including the domain attribute", func(t *testing.T) {
		in := newInstance(t, func(c *betterauth.Config) {
			c.BaseURL = "https://auth.example.com"
			c.Advanced = &betterauth.AdvancedConfig{CrossSubDomainCookies: &betterauth.CrossSubDomainCookies{Enabled: true, Domain: "example.com"}}
			c.Plugins = append(c.Plugins, lastloginmethod.New())
		})
		_, res := signInCookies(t, in, in.email, in.password)
		joined := strings.Join(res.Header.Values("Set-Cookie"), ", ")
		if !strings.Contains(joined, cookieName+"=email") || !strings.Contains(joined, "Domain=example.com") {
			t.Fatalf("set-cookie %s", joined)
		}
		// The second half (lastLoginMethodClient().clearLastUsedLoginMethod writing
		// document.cookie with the domain) is client-only; covered by the e2e suite.
	})
	t.Run("should handle multiple set-cookie headers correctly", func(t *testing.T) {
		extra := &betterauth.Plugin{ID: "multi-cookie-test", Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(*betterauth.EndpointContext) bool { return true },
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				for _, c := range ctx.ResponseHeaders.Values("Set-Cookie") {
					if strings.Contains(c, ctx.Auth.AuthCookies.SessionToken.Name) {
						ctx.SetCookie("additional-test-cookie", "test-value", betterauth.CookieOptions{MaxAge: betterauth.Int(60 * 60 * 24 * 30)})
						break
					}
				}
				return nil, nil
			},
		}}}}
		in := newInstance(t, withPlugins(extra, lastloginmethod.New()))
		h, res := signInCookies(t, in, in.email, in.password)
		sc := res.Header.Values("Set-Cookie")
		joined := strings.Join(sc, ";")
		if len(sc) <= 1 || !strings.Contains(joined, "additional-test-cookie=test-value") || !strings.Contains(joined, cookieName+"=email") {
			t.Fatalf("set-cookie %v", sc)
		}
		expectMethod(t, h, cookieName, "email")
		expectMethod(t, h, "additional-test-cookie", "test-value")
	})
}

// ---- custom-prefix.test.ts ----

func TestLastLoginMethodCustomCookiePrefix(t *testing.T) {
	prefix := func(p string, o lastloginmethod.Options) func(c *betterauth.Config) {
		return func(c *betterauth.Config) {
			c.Advanced = &betterauth.AdvancedConfig{CookiePrefix: p}
			c.Plugins = append(c.Plugins, lastloginmethod.New(o))
		}
	}
	signInAs := func(t *testing.T, in *instance) http.Header {
		res := in.do("POST", "/sign-in/email", map[string]any{"email": in.email, "password": in.password}, nil)
		h := http.Header{}
		applySetCookies(h, res)
		return h
	}
	t.Run("should work with default cookie name regardless of custom prefix", func(t *testing.T) {
		in := newInstance(t, prefix("custom-auth", lastloginmethod.Options{}))
		expectMethod(t, signInAs(t, in), cookieName, "email")
	})
	t.Run("should work with custom cookie name and prefix", func(t *testing.T) {
		in := newInstance(t, prefix("my-app", lastloginmethod.Options{CookieName: "my-app.last_method"}))
		expectMethod(t, signInAs(t, in), "my-app.last_method", "email")
	})
	t.Run("should work with custom cookie name regardless of prefix", func(t *testing.T) {
		in := newInstance(t, prefix("my-app", lastloginmethod.Options{CookieName: "last_login_method"}))
		expectMethod(t, signInAs(t, in), "last_login_method", "email")
	})
	t.Run("should work with cross-subdomain and custom prefix", func(t *testing.T) {
		in := newInstance(t, func(c *betterauth.Config) {
			c.BaseURL = "https://auth.example.com"
			c.Advanced = &betterauth.AdvancedConfig{CookiePrefix: "custom-auth",
				CrossSubDomainCookies: &betterauth.CrossSubDomainCookies{Enabled: true, Domain: "example.com"}}
			c.Plugins = append(c.Plugins, lastloginmethod.New())
		})
		res := in.do("POST", "/sign-in/email", map[string]any{"email": in.email, "password": in.password}, nil)
		joined := strings.Join(res.Header.Values("Set-Cookie"), ", ")
		for _, want := range []string{"Domain=example.com", "SameSite=Lax", cookieName + "=email"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("missing %q in %s", want, joined)
			}
		}
	})
	t.Run("should work with cross-origin cookies", func(t *testing.T) {
		in := newInstance(t, func(c *betterauth.Config) {
			c.BaseURL = "https://api.example.com"
			c.Advanced = &betterauth.AdvancedConfig{DefaultCookieAttributes: &betterauth.CookieAttributes{SameSite: betterauth.StrPtr("none"), Secure: betterauth.Bool(true)}}
			c.Plugins = append(c.Plugins, lastloginmethod.New())
		})
		res := in.do("POST", "/sign-in/email", map[string]any{"email": in.email, "password": in.password}, nil)
		joined := strings.Join(res.Header.Values("Set-Cookie"), ", ")
		if !strings.Contains(joined, "SameSite=None") || !strings.Contains(joined, "Secure") || strings.Contains(joined, "Domain=") || !strings.Contains(joined, cookieName+"=email") {
			t.Fatalf("set-cookie %s", joined)
		}
	})
	t.Run("should handle cross-origin on localhost for development", func(t *testing.T) {
		in := newInstance(t, func(c *betterauth.Config) {
			c.Advanced = &betterauth.AdvancedConfig{DefaultCookieAttributes: &betterauth.CookieAttributes{SameSite: betterauth.StrPtr("none"), Secure: betterauth.Bool(false)}}
			c.Plugins = append(c.Plugins, lastloginmethod.New())
		})
		res := in.do("POST", "/sign-in/email", map[string]any{"email": in.email, "password": in.password}, nil)
		joined := strings.Join(res.Header.Values("Set-Cookie"), ", ")
		if !strings.Contains(joined, "SameSite=None") || strings.Contains(joined, "Secure") || !strings.Contains(joined, cookieName+"=email") {
			t.Fatalf("set-cookie %s", joined)
		}
	})
}
