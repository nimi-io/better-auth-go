package anonymous

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

// linkRecorder is the vi.fn() passed as onLinkAccount.
type linkRecorder struct {
	mu    sync.Mutex
	calls []LinkAccountData
}

func (r *linkRecorder) fn(d LinkAccountData) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, d)
	return nil
}

func (r *linkRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *linkRecorder) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

// stripSessionCookie drops the session token cookie (an Expo callback carries no cookie).
func stripSessionCookie(j *jar) *jar {
	c := j.clone()
	for name := range c.cookies {
		if strings.HasPrefix(name, "better-auth.session_token") {
			delete(c.cookies, name)
		}
	}
	return c
}

func googleMock(t *testing.T) *oauth2test.Server {
	mock := oauth2test.New(t)
	mock.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{
		"access_token": "test", "refresh_token": "test",
		"id_token": mock.IDToken(map[string]any{
			"email": "user@email.com", "email_verified": true, "name": "First Last",
			"picture": "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw", "sub": "1234567890",
			"aud": "test", "azp": "test", "iss": "test", "locale": "en", "given_name": "First", "family_name": "Last",
		}),
	})
	return mock
}

func signInAnonymous(t *testing.T, e *env, j *jar) *response {
	t.Helper()
	return e.post("/sign-in/anonymous", nil, j)
}

// Port of plugins/anonymous/anon.test.ts — describe("anonymous").
func TestAnonymous(t *testing.T) {
	googleMock(t)
	link := &linkRecorder{}
	e := newEnv(t, func(c *betterauth.Config) {
		c.Plugins = []*betterauth.Plugin{New(Options{
			OnLinkAccount: link.fn,
			Schema:        map[string]SchemaOverride{"user": {Fields: map[string]string{"isAnonymous": "is_anon"}}},
		})}
	}, instanceOpts{})
	headers := newJar()

	t.Run("should sign in anonymously", func(t *testing.T) {
		signInAnonymous(t, e, headers).data(t)
		s := e.get("/get-session", nil, headers).data(t)
		if s["session"] == nil || s["user"].(map[string]any)["isAnonymous"] != true {
			t.Fatalf("%v", s)
		}
		// the renamed column is used in storage
		rec, _ := e.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user",
			Where: []adapter.Where{{Field: "id", Value: s["user"].(map[string]any)["id"]}}})
		if rec["isAnonymous"] != true {
			t.Fatalf("record %v", rec)
		}
	})
	t.Run("uses a namespaced placeholder email by default", func(t *testing.T) {
		res := signInAnonymous(t, e, nil).data(t)
		email := res["user"].(map[string]any)["email"].(string)
		if !regexp.MustCompile(`^[^@]+@anonymous\.placeholder\.invalid$`).MatchString(email) {
			t.Fatalf("email %q", email)
		}
	})
	t.Run("should reject anonymous sign-in when validateUserInfo returns error", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, _ map[string]any, source betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
				if source.Method != "anonymous" {
					return nil, nil
				}
				if source.Action != "create-user" {
					t.Errorf("action = %q", source.Action)
				}
				return &betterauth.ValidateUserInfoResult{Error: "anonymous_blocked", ErrorDescription: "Anonymous users are not allowed"}, nil
			}}
			c.Plugins = []*betterauth.Plugin{New(Options{})}
		}, instanceOpts{disableTestUser: true})
		res := signInAnonymous(t, e2, nil)
		if res.code(t) != "anonymous_blocked" || res.message() != "Anonymous users are not allowed" {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("link anonymous user account", func(t *testing.T) {
		if link.count() != 0 {
			t.Fatalf("calls = %d", link.count())
		}
		anonID := e.get("/get-session", nil, headers).data(t)["user"].(map[string]any)["id"].(string)
		e.post("/sign-in/email", map[string]any{"email": e.testUser.Email, "password": e.testUser.Password}, headers).data(t)
		if link.count() != 1 {
			t.Fatalf("calls = %d", link.count())
		}
		d := link.calls[0]
		if d.AnonymousUser.User.ID != anonID || !isAnonymous(d.AnonymousUser.User) || d.NewUser.User.Email != e.testUser.Email || d.Ctx == nil {
			t.Fatalf("link data %+v", d)
		}
		if e.findUser(anonID) != nil {
			t.Fatal("anonymous user should be deleted after linking")
		}
		link.clear()
	})
	socialSignIn := func(t *testing.T, j *jar, body map[string]any) url.Values {
		t.Helper()
		res := e.post("/sign-in/social", body, j)
		u, err := url.Parse(res.data(t)["url"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return u.Query()
	}
	t.Run("should link in social sign on", func(t *testing.T) {
		h := newJar()
		signInAnonymous(t, e, h).data(t)
		e.get("/get-session", nil, h).data(t)
		params := socialSignIn(t, h, map[string]any{"provider": "google", "callbackURL": "/dashboard"})
		res := e.get("/callback/google", q("state", params.Get("state"), "code", "test"), h)
		if res.Status != 302 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
		if link.count() == 0 {
			t.Fatal("onLinkAccount not called")
		}
	})
	t.Run("should link the anonymous account on social sign-in when the callback has no session cookie (Expo)", func(t *testing.T) {
		link.clear()
		h := newJar()
		signInAnonymous(t, e, h).data(t)
		s := e.get("/get-session", nil, h).data(t)
		if s["user"].(map[string]any)["isAnonymous"] != true {
			t.Fatalf("%v", s)
		}
		params := socialSignIn(t, h, map[string]any{"provider": "google", "callbackURL": "/dashboard"})
		res := e.get("/callback/google", q("state", params.Get("state"), "code", "test"), stripSessionCookie(h))
		if res.Status != 302 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
		if link.count() == 0 {
			t.Fatal("onLinkAccount not called")
		}
	})
	t.Run("should ignore a client-supplied anonymousUserId on the OAuth callback", func(t *testing.T) {
		link.clear()
		victimHeaders := newJar()
		victim := signInAnonymous(t, e, victimHeaders).data(t)
		victimID := victim["user"].(map[string]any)["id"].(string)
		if victimID == "" {
			t.Fatal("no victim id")
		}
		attacker := newJar()
		params := socialSignIn(t, attacker, map[string]any{"provider": "google", "callbackURL": "/dashboard",
			"additionalData": map[string]any{"anonymousUserId": victimID}})
		e.get("/callback/google", q("state", params.Get("state"), "code", "test"), attacker)
		if link.count() != 0 {
			t.Fatal("onLinkAccount must not be called")
		}
		if u := e.findUser(victimID); u == nil || u.ID != victimID {
			t.Fatal("victim was deleted")
		}
	})
	t.Run("should call onLinkAccount when anonymous user verifies email", func(t *testing.T) {
		rec := &linkRecorder{}
		var mu sync.Mutex
		token := ""
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{OnLinkAccount: rec.fn})}
			c.EmailAndPassword = &betterauth.EmailAndPasswordConfig{Enabled: true, RequireEmailVerification: true}
			c.EmailVerification = &betterauth.EmailVerificationConfig{AutoSignInAfterVerification: true,
				SendVerificationEmail: func(_ context.Context, d betterauth.EmailData, _ *http.Request) error {
					u, _ := url.Parse(d.URL)
					mu.Lock()
					token = u.Query().Get("token")
					mu.Unlock()
					return nil
				}}
		}, instanceOpts{disableTestUser: true})
		anonHeaders := newJar()
		signInAnonymous(t, e2, anonHeaders).data(t)
		e2.mustCall("signUpEmail", map[string]any{"email": "newuser@example.com", "password": "password123", "name": "New User"}, nil, anonHeaders.header())
		mu.Lock()
		tok := token
		mu.Unlock()
		if _, err := e2.auth.API.Call(context.Background(), "verifyEmail", betterauth.CallInput{Query: map[string]any{"token": tok}, Headers: anonHeaders.header()}); err != nil && !betterauth.IsRedirect(err) {
			t.Fatal(err)
		}
		if rec.count() != 1 {
			t.Fatalf("calls = %d", rec.count())
		}
	})
	t.Run("should work with generateName", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{GenerateName: func(*betterauth.EndpointContext) (string, error) { return "i-am-anonymous", nil }})}
		}, instanceOpts{})
		res := signInAnonymous(t, e2, newJar()).data(t)
		if res["user"].(map[string]any)["name"] != "i-am-anonymous" {
			t.Fatalf("%v", res)
		}
	})
	uuidEmail := func(prefix string) func(context.Context) (string, error) {
		return func(context.Context) (string, error) {
			return prefix + "-" + bacrypto.RandomUUID() + "@example.com", nil
		}
	}
	t.Run("should work with generateRandomEmail", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{GenerateRandomEmail: uuidEmail("custom")})}
		}, instanceOpts{})
		email := signInAnonymous(t, e2, newJar()).data(t)["user"].(map[string]any)["email"].(string)
		if !regexp.MustCompile(`^custom-[a-f0-9-]+@example\.com$`).MatchString(email) {
			t.Fatalf("email %q", email)
		}
	})
	t.Run("should work with async generateRandomEmail", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{GenerateRandomEmail: uuidEmail("async")})}
		}, instanceOpts{})
		email := signInAnonymous(t, e2, newJar()).data(t)["user"].(map[string]any)["email"].(string)
		if !regexp.MustCompile(`^async-[a-f0-9-]+@example\.com$`).MatchString(email) {
			t.Fatalf("email %q", email)
		}
	})
	invalidEmail := func(t *testing.T, email string) {
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{GenerateRandomEmail: func(context.Context) (string, error) { return email, nil }})}
		}, instanceOpts{})
		res := signInAnonymous(t, e2, newJar())
		if res.Status == 200 || res.message() != "Email was not generated in a valid format" {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	}
	t.Run("should throw error if generateRandomEmail returns invalid email", func(t *testing.T) { invalidEmail(t, "not-an-email") })
	t.Run("should throw error if async generateRandomEmail returns invalid email", func(t *testing.T) { invalidEmail(t, "still-not-an-email") })
	t.Run("should not reject first-time anonymous sign-in", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) { c.Plugins = []*betterauth.Plugin{New(Options{})} }, instanceOpts{})
		fresh := newJar()
		if signInAnonymous(t, e2, fresh).data(t)["user"] == nil {
			t.Fatal("no user")
		}
		s := e2.get("/get-session", nil, fresh).data(t)
		if s["session"] == nil || s["user"].(map[string]any)["isAnonymous"] != true {
			t.Fatalf("%v", s)
		}
	})
	t.Run("should reject subsequent anonymous sign-in attempts once signed in", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) { c.Plugins = []*betterauth.Plugin{New(Options{})} }, instanceOpts{})
		persistent := newJar()
		signInAnonymous(t, e2, persistent).data(t)
		s := e2.get("/get-session", nil, persistent).data(t)
		if s["session"] == nil || s["user"].(map[string]any)["isAnonymous"] != true {
			t.Fatalf("%v", s)
		}
		second := signInAnonymous(t, e2, persistent)
		if second.Status == 200 || second.message() != "Anonymous users cannot sign in again anonymously" {
			t.Fatalf("%d %s", second.Status, second.Body)
		}
	})

	// describe("anonymous cleanup safeguards"): upstream calls the after hook with a mocked
	// context and a mocked getSessionFromCtx; here ctx.Session plays the mocked session and
	// a real anonymous user plays the deleteUser target.
	t.Run("anonymous cleanup safeguards", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) { c.Plugins = []*betterauth.Plugin{New(Options{})} }, instanceOpts{disableTestUser: true})
		hookCtx := func(t *testing.T, anonID string, newUser *betterauth.User) *betterauth.EndpointContext {
			t.Helper()
			ctx := &betterauth.EndpointContext{
				Path: "/sign-in/anonymous", Auth: e2.auth.Context(), Headers: http.Header{}, Query: map[string]any{},
				ResponseHeaders: http.Header{"Set-Cookie": {"better-auth.session_token=new-token.value; Path=/; HttpOnly"}},
				Session: &betterauth.SessionWithUser{
					User:    &betterauth.User{ID: anonID, Additional: map[string]any{"isAnonymous": true}},
					Session: &betterauth.Session{Token: "old-token"},
				},
			}
			ctx.SetNewSession(&betterauth.SessionWithUser{User: newUser, Session: &betterauth.Session{Token: "new-token"}})
			return ctx
		}
		handler := New(Options{}).Hooks.After[0].Handler
		t.Run("does not delete when the new session is still anonymous", func(t *testing.T) {
			id := signInAnonymous(t, e2, nil).data(t)["user"].(map[string]any)["id"].(string)
			ctx := hookCtx(t, id, &betterauth.User{ID: id, Additional: map[string]any{"isAnonymous": true}})
			if _, err := handler(ctx); err != nil {
				t.Fatal(err)
			}
			if e2.findUser(id) == nil {
				t.Fatal("anonymous user was deleted")
			}
		})
		t.Run("deletes the previous anonymous user when linking a new account", func(t *testing.T) {
			id := signInAnonymous(t, e2, nil).data(t)["user"].(map[string]any)["id"].(string)
			ctx := hookCtx(t, id, &betterauth.User{ID: "linked-user", Additional: map[string]any{"isAnonymous": false}})
			if _, err := handler(ctx); err != nil {
				t.Fatal(err)
			}
			if e2.findUser(id) != nil {
				t.Fatal("anonymous user was not deleted")
			}
		})
	})
}

// Port of anon.test.ts — describe("anonymous linking through generic oauth (Expo)").
func TestAnonymousLinkingThroughGenericOAuth(t *testing.T) {
	t.Run("links the anonymous account when the callback lacks the session cookie", func(t *testing.T) {
		t.Skip("needs the generic-oauth plugin and an OIDC mock server; the same server-context linking path is covered by the Google Expo case in TestAnonymous")
	})
}
