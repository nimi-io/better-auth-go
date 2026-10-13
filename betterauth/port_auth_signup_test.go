package betterauth

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
)

// Port of better-auth/src/api/routes/sign-up.test.ts

func paStrField(name string) db.Field {
	return db.Field{Name: name, Type: db.TypeString, Required: db.False}
}

// describe("sign-up with custom fields")
func TestPortAuthSignUpWithCustomFields(t *testing.T) {
	mock := &paMock{}
	env := paNewEnv(t, func(c *Config) {
		c.Account = &AccountConfig{ModelConfig: ModelConfig{Fields: map[string]string{"providerId": "provider_id", "accountId": "account_id"}}}
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			paStrField("newField"),
			paStrField("newField2"),
			{Name: "isAdmin", Type: db.TypeBoolean, DefaultValue: true, Input: Bool(false)},
			{Name: "role", Type: db.TypeString, Required: db.False, Input: Bool(false)},
		}}}
		c.EmailVerification = &EmailVerificationConfig{
			SendOnSignUp: Bool(true),
			SendVerificationEmail: func(_ context.Context, d EmailData, r *http.Request) error {
				mock.record(d, r)
				return nil
			},
		}
	}, paInstanceOpts{disableTestUser: true})

	t.Run("should work with custom fields on account table", func(t *testing.T) {
		defer mock.reset()
		res, _ := env.mustCall("signUpEmail", map[string]any{
			"email": "email@test.com", "password": "password", "name": "Test Name", "image": "https://picsum.photos/200",
		}, nil)
		if res["token"] == nil {
			t.Fatalf("token should be defined: %v", res)
		}
		users := env.db.Rows("user")
		accounts := env.db.Rows("account")
		if len(accounts) != 1 {
			t.Fatalf("expected 1 account, got %d", len(accounts))
		}
		if _, ok := users[0]["isAdmin"]; !ok {
			t.Fatalf("isAdmin should be in user row: %v", users[0])
		}
		if users[0]["isAdmin"] != true {
			t.Fatalf("isAdmin = %v, want true", users[0]["isAdmin"])
		}
		if mock.count() != 1 {
			t.Fatalf("sendVerificationEmail called %d times, want 1", mock.count())
		}
		args := mock.last()
		d := args[0].(EmailData)
		if d.Token == "" || d.URL == "" || d.User == nil {
			t.Fatalf("expected token/url/user in email data: %+v", d)
		}
		if r := args[1].(*http.Request); r != nil {
			t.Fatalf("expected request to be undefined for a direct API call")
		}
	})

	t.Run("should succeed when passing empty name", func(t *testing.T) {
		// Upstream reads the session with the bearer plugin (`authorization: Bearer <token>`);
		// the bearer plugin is not ported yet so the session cookie returned by the same
		// sign-up call is used instead.
		res, cr := env.mustCall("signUpEmail", map[string]any{"email": "noname@test.com", "password": "password", "name": ""}, nil)
		if res["token"] == nil {
			t.Fatalf("token missing")
		}
		tok, _, ok := paSetCookie(cr.Headers, "better-auth.session_token")
		if !ok {
			t.Fatalf("no session cookie")
		}
		h := http.Header{}
		h.Set("Cookie", "better-auth.session_token="+tok)
		s, err := env.auth.API.GetSession(context.Background(), h)
		if err != nil || s == nil {
			t.Fatalf("session should be defined: %v", err)
		}
		if s.User.Name != "" {
			t.Fatalf("name = %q, want empty", s.User.Name)
		}
	})

	t.Run("should get the ipAddress and userAgent from headers", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Forwarded-For", "127.0.0.1")
		h.Set("User-Agent", "test-user-agent")
		_, cr := env.mustCall("signUpEmail", map[string]any{"email": "email2@test.com", "password": "password", "name": "Test Name"}, h)
		tok, _, ok := paSetCookie(cr.Headers, "better-auth.session_token")
		if !ok {
			t.Fatalf("no session cookie")
		}
		sh := http.Header{}
		sh.Set("Cookie", "better-auth.session_token="+tok)
		s, err := env.auth.API.GetSession(context.Background(), sh)
		if err != nil || s == nil {
			t.Fatalf("session should be defined: %v", err)
		}
		if s.Session.UserAgent == nil || *s.Session.UserAgent != "test-user-agent" {
			t.Fatalf("userAgent = %v", s.Session.UserAgent)
		}
		if s.Session.IPAddress == nil || *s.Session.IPAddress != "127.0.0.1" {
			t.Fatalf("ipAddress = %v", s.Session.IPAddress)
		}
	})

	t.Run("should rollback when session creation fails", func(t *testing.T) {
		// Upstream replaces internalAdapter.createSession with a rejecting mock; here the
		// session create is made to fail through a session.create.before database hook on a
		// dedicated instance (the memory adapter supports transactions).
		env2 := paNewEnv(t, func(c *Config) {
			c.DatabaseHooks = &DatabaseHooks{Session: DBModelHooks{Create: DBOperationHooks{
				Before: func(ctx context.Context, data adapter.Record) (*DBHookResult, error) {
					return nil, errPaDatabaseUnavailable
				},
			}}}
		}, paInstanceOpts{disableTestUser: true})
		_, apiErr := env2.auth.API.Call(context.Background(), "signUpEmail", CallInput{Body: map[string]any{
			"email": "rollback@test.com", "password": "password", "name": "Rollback Test",
		}})
		if apiErr == nil {
			t.Fatalf("expected sign-up to fail")
		}
		for _, u := range env2.db.Rows("user") {
			if u["email"] == "rollback@test.com" {
				t.Fatalf("user should have been rolled back: %v", u)
			}
		}
	})

	t.Run("should not allow user to set the field that is set to input: false", func(t *testing.T) {
		_, apiErr := env.call("signUpEmail", map[string]any{
			"email": "input-false@test.com", "password": "password", "name": "Input False Test", "role": "admin",
		}, nil)
		if apiErr == nil {
			t.Fatalf("expected error")
		}
		if !strings.Contains(apiErr.Error(), "role is not allowed to be set") {
			t.Fatalf("error = %s, want to contain %q", paFormatErr(apiErr), "role is not allowed to be set")
		}
	})

	t.Run("should return additionalFields in signUpEmail response", func(t *testing.T) {
		res, _ := env.mustCall("signUpEmail", map[string]any{
			"email": "additional-fields@test.com", "password": "password", "name": "Additional Fields Test", "newField": "custom-value",
		}, nil)
		user, ok := res["user"].(map[string]any)
		if !ok {
			t.Fatalf("user should be defined: %v", res)
		}
		if user["newField"] != "custom-value" {
			t.Fatalf("newField = %v", user["newField"])
		}
		if user["isAdmin"] != true {
			t.Fatalf("isAdmin = %v, want true", user["isAdmin"])
		}
	})

	t.Run("should throw status code 400 when passing invalid body", func(t *testing.T) {
		_, apiErr := env.call("signUpEmail", map[string]any{"name": "Test", "email": "body-validation@test.com"}, nil)
		if apiErr == nil || apiErr.StatusCode != 400 {
			t.Fatalf("expected 400, got %s", paFormatErr(apiErr))
		}
	})
}

// describe("validateUserInfo sign-up")
func TestPortAuthSignUpValidateUserInfo(t *testing.T) {
	t.Run("should allow email/password sign-up when validateUserInfo returns void", func(t *testing.T) {
		var capturedMethod, capturedEmail, capturedAction string
		env := paNewEnv(t, func(c *Config) {
			c.User = &UserConfig{ValidateUserInfo: func(_ *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
				capturedAction = source.Action
				capturedMethod = source.Method
				capturedEmail, _ = user["email"].(string)
				return nil, nil
			}}
		}, paInstanceOpts{disableTestUser: true})
		res, _ := env.mustCall("signUpEmail", map[string]any{"email": "allowed@test.com", "password": "password", "name": "Allowed User"}, nil)
		if res["user"].(map[string]any)["email"] != "allowed@test.com" {
			t.Fatalf("unexpected user %v", res["user"])
		}
		if capturedAction != "create-user" {
			t.Fatalf("source.action = %q, want create-user", capturedAction)
		}
		if capturedMethod != "email-password" {
			t.Fatalf("source.method = %q", capturedMethod)
		}
		if capturedEmail != "allowed@test.com" {
			t.Fatalf("email = %q", capturedEmail)
		}
	})

	t.Run("should reject email/password sign-up when validateUserInfo returns error", func(t *testing.T) {
		env := paNewEnv(t, func(c *Config) {
			c.User = &UserConfig{ValidateUserInfo: func(_ *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
				if source.Method != "email-password" {
					t.Errorf("source.method = %q", source.Method)
				}
				if e, _ := user["email"].(string); strings.HasSuffix(e, "@blocked.com") {
					return &ValidateUserInfoResult{Error: "email_not_allowed", ErrorDescription: "Only company emails are allowed"}, nil
				}
				return nil, nil
			}}
		}, paInstanceOpts{disableTestUser: true})
		_, apiErr := env.call("signUpEmail", map[string]any{"email": "new@blocked.com", "password": "password", "name": "Blocked User"}, nil)
		if apiErr == nil || apiErr.StatusCode != 403 || apiErr.Code() != "email_not_allowed" || apiErr.Message() != "Only company emails are allowed" {
			t.Fatalf("expected 403 email_not_allowed, got %s", paFormatErr(apiErr))
		}
		for _, u := range env.db.Rows("user") {
			if u["email"] == "new@blocked.com" {
				t.Fatalf("blocked user should not exist")
			}
		}
	})

	t.Run("hides gate rejections behind the generic-duplicate response", func(t *testing.T) {
		env := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.AutoSignIn = Bool(false)
			c.User = &UserConfig{ValidateUserInfo: func(_ *EndpointContext, user map[string]any, _ UserInfoSource) (*ValidateUserInfoResult, error) {
				if e, _ := user["email"].(string); strings.HasSuffix(e, "@blocked.com") {
					return &ValidateUserInfoResult{Error: "email_not_allowed"}, nil
				}
				return nil, nil
			}}
		}, paInstanceOpts{disableTestUser: true})
		res, _ := env.mustCall("signUpEmail", map[string]any{"email": "ghost@blocked.com", "password": "password", "name": "Ghost User"}, nil)
		if v, ok := res["token"]; !ok || v != nil {
			t.Fatalf("token should be null: %v", res)
		}
		if res["user"].(map[string]any)["email"] != "ghost@blocked.com" {
			t.Fatalf("user.email = %v", res["user"])
		}
		for _, u := range env.db.Rows("user") {
			if u["email"] == "ghost@blocked.com" {
				t.Fatalf("ghost user should not exist")
			}
		}
	})
}

// describe("sign-up user enumeration protection")
func TestPortAuthSignUpEnumerationProtection(t *testing.T) {
	body := func(email, name string) map[string]any {
		return map[string]any{"email": email, "password": "password123", "name": name}
	}
	onExisting := func(m *paMock) func(context.Context, *User, *http.Request) error {
		return func(_ context.Context, u *User, r *http.Request) error {
			m.record(u, r)
			return nil
		}
	}

	t.Run("should return success for existing email when email verification is required", func(t *testing.T) {
		env := paNewEnv(t, func(c *Config) { c.EmailAndPassword.RequireEmailVerification = true }, paInstanceOpts{disableTestUser: true})
		b := body("existing-email@test.com", "Existing User")
		env.mustCall("signUpEmail", b, nil)
		dup, _ := env.mustCall("signUpEmail", b, nil)
		if v, ok := dup["token"]; !ok || v != nil {
			t.Fatalf("token should be null: %v", dup)
		}
		if dup["user"].(map[string]any)["email"] != b["email"] {
			t.Fatalf("user.email = %v", dup["user"])
		}
	})

	t.Run("should call onExistingUserSignUp when requireEmailVerification is true", func(t *testing.T) {
		m := &paMock{}
		env := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.RequireEmailVerification = true
			c.EmailAndPassword.OnExistingUserSignUp = onExisting(m)
		}, paInstanceOpts{disableTestUser: true})
		b := body("callback-rev@test.com", "Callback User")
		env.mustCall("signUpEmail", b, nil)
		if m.count() != 0 {
			t.Fatalf("should not have been called")
		}
		env.mustCall("signUpEmail", b, nil)
		if m.count() != 1 {
			t.Fatalf("called %d times, want 1", m.count())
		}
		args := m.last()
		if u := args[0].(*User); u == nil || u.Email != b["email"] {
			t.Fatalf("user = %+v", args[0])
		}
		if r := args[1].(*http.Request); r != nil {
			t.Fatalf("expected request to be undefined for a direct API call")
		}
	})

	t.Run("should call onExistingUserSignUp when autoSignIn is false and requireEmailVerification is true", func(t *testing.T) {
		m := &paMock{}
		env := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.AutoSignIn = Bool(false)
			c.EmailAndPassword.RequireEmailVerification = true
			c.EmailAndPassword.OnExistingUserSignUp = onExisting(m)
		}, paInstanceOpts{disableTestUser: true})
		b := body("callback-autosignin@test.com", "Callback AutoSignIn")
		env.mustCall("signUpEmail", b, nil)
		env.mustCall("signUpEmail", b, nil)
		if m.count() != 1 {
			t.Fatalf("called %d times, want 1", m.count())
		}
	})

	t.Run("should call onExistingUserSignUp when autoSignIn is false without requireEmailVerification", func(t *testing.T) {
		m := &paMock{}
		env := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.AutoSignIn = Bool(false)
			c.EmailAndPassword.OnExistingUserSignUp = onExisting(m)
		}, paInstanceOpts{disableTestUser: true})
		b := body("callback-autosignin-no-verify@test.com", "Callback AutoSignIn No Verify")
		env.mustCall("signUpEmail", b, nil)
		res, _ := env.mustCall("signUpEmail", b, nil)
		if v, ok := res["token"]; !ok || v != nil {
			t.Fatalf("token should be null: %v", res)
		}
		if res["user"] == nil {
			t.Fatalf("user should be defined")
		}
		if m.count() != 1 {
			t.Fatalf("called %d times, want 1", m.count())
		}
	})

	t.Run("should not call onExistingUserSignUp when enumeration protection is inactive", func(t *testing.T) {
		m := &paMock{}
		env := paNewEnv(t, func(c *Config) { c.EmailAndPassword.OnExistingUserSignUp = onExisting(m) }, paInstanceOpts{disableTestUser: true})
		b := body("callback-noenum@test.com", "No Enum")
		env.mustCall("signUpEmail", b, nil)
		if _, apiErr := env.call("signUpEmail", b, nil); apiErr == nil {
			t.Fatalf("expected duplicate sign-up to fail")
		}
		if m.count() != 0 {
			t.Fatalf("should not have been called")
		}
	})

	t.Run("should not call onExistingUserSignUp for new user sign-ups", func(t *testing.T) {
		m := &paMock{}
		env := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.RequireEmailVerification = true
			c.EmailAndPassword.OnExistingUserSignUp = onExisting(m)
		}, paInstanceOpts{disableTestUser: true})
		env.mustCall("signUpEmail", body("brand-new-user@test.com", "Brand New"), nil)
		if m.count() != 0 {
			t.Fatalf("should not have been called")
		}
	})

	t.Run("should return synthetic user for existing email when autoSignIn is disabled without requireEmailVerification", func(t *testing.T) {
		env := paNewEnv(t, func(c *Config) { c.EmailAndPassword.AutoSignIn = Bool(false) }, paInstanceOpts{disableTestUser: true})
		b := body("existing-auto-signin@test.com", "Existing User")
		env.mustCall("signUpEmail", b, nil)
		res, _ := env.mustCall("signUpEmail", b, nil)
		if v, ok := res["token"]; !ok || v != nil {
			t.Fatalf("token should be null: %v", res)
		}
		u, _ := res["user"].(map[string]any)
		if u == nil || u["email"] != "existing-auto-signin@test.com" {
			t.Fatalf("user = %v", res["user"])
		}
	})

	t.Run("should return token: null for new sign-up when autoSignIn is disabled", func(t *testing.T) {
		env := paNewEnv(t, func(c *Config) { c.EmailAndPassword.AutoSignIn = Bool(false) }, paInstanceOpts{disableTestUser: true})
		res, _ := env.mustCall("signUpEmail", body("new-auto-signin@test.com", "New User"), nil)
		if v, ok := res["token"]; !ok || v != nil {
			t.Fatalf("token should be null: %v", res)
		}
		if res["user"].(map[string]any)["email"] != "new-auto-signin@test.com" {
			t.Fatalf("user = %v", res["user"])
		}
	})
}

func paCSRFEnv(t *testing.T, disableTestUser bool) *paEnv {
	return paNewEnv(t, func(c *Config) {
		c.TrustedOrigins = []string{"http://localhost:3000"}
		c.Advanced = &AdvancedConfig{DisableCSRFCheck: Bool(false)}
	}, paInstanceOpts{disableTestUser: disableTestUser})
}

// describe("sign-up CSRF protection")
func TestPortAuthSignUpCSRFProtection(t *testing.T) {
	env := paCSRFEnv(t, true)

	t.Run("should block cross-site navigation sign-up attempts (no cookies)", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", map[string]any{"email": "victim@example.com", "password": "password123", "name": "Victim"}, map[string]string{
			"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "https://evil.com",
		})
		if res.Status != 403 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if m := res.JSON(t); m["message"] != ErrCrossSiteNavigationLoginBlocked.Message {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should allow same-origin navigation sign-up attempts", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", map[string]any{"email": "newuser@example.com", "password": "password123", "name": "New User"}, map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "http://localhost:3000",
		})
		if res.Status == 403 {
			t.Fatalf("status = 403: %s", res.Body)
		}
	})

	t.Run("should allow fetch/XHR sign-up requests (cors mode)", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", map[string]any{"email": "fetchuser@example.com", "password": "password123", "name": "Fetch User"}, map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Origin": "http://localhost:3000",
		})
		if res.Status == 403 {
			t.Fatalf("status = 403: %s", res.Body)
		}
	})

	t.Run("should use origin validation when cookies exist", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", map[string]any{"email": "cookieuser@example.com", "password": "password123", "name": "Cookie User"}, map[string]string{
			"Cookie": "some_cookie=value", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Origin": "http://localhost:3000",
		})
		if res.Status == 403 {
			t.Fatalf("status = 403: %s", res.Body)
		}
	})
}

// describe("sign-up with form data")
func TestPortAuthSignUpWithFormData(t *testing.T) {
	env := paCSRFEnv(t, true)

	t.Run("should accept form-urlencoded content type", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", url.Values{"email": {"formuser@example.com"}, "password": {"password123"}, "name": {"Form User"}}, map[string]string{
			"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "http://localhost:3000",
		})
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		if _, ok := m["token"]; !ok {
			t.Fatalf("token should be defined: %v", m)
		}
		if m["user"].(map[string]any)["email"] != "formuser@example.com" {
			t.Fatalf("user = %v", m["user"])
		}
	})

	t.Run("should block cross-site form submissions", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", url.Values{"email": {"victim@example.com"}, "password": {"password123"}, "name": {"Victim"}}, map[string]string{
			"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "https://evil.com",
		})
		if res.Status != 403 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
		if m := res.JSON(t); m["message"] != ErrCrossSiteNavigationLoginBlocked.Message {
			t.Fatalf("message = %v", m["message"])
		}
	})

	t.Run("should allow same-site form submissions from trusted origins", func(t *testing.T) {
		res := env.do("POST", "/sign-up/email", url.Values{"email": {"samesiteuser@example.com"}, "password": {"password123"}, "name": {"Same Site User"}}, map[string]string{
			"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Origin": "http://localhost:3000",
		})
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.Body)
		}
	})
}

// describe("sign-up sendOnSignUp option behavior")
func TestPortAuthSignUpSendOnSignUp(t *testing.T) {
	cases := []struct {
		name   string
		send   *bool
		emails int
		email  string
	}{
		{"should not send verification email when sendOnSignUp is false, even with requireEmailVerification", Bool(false), 0, "no-verification@test.com"},
		{"should send verification email when sendOnSignUp is true", Bool(true), 1, "with-verification@test.com"},
		{"should send verification email when sendOnSignUp is not set but requireEmailVerification is true (default)", nil, 1, "default-verification@test.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &paMock{}
			env := paNewEnv(t, func(c *Config) {
				c.EmailVerification = &EmailVerificationConfig{SendOnSignUp: tc.send, SendVerificationEmail: func(_ context.Context, d EmailData, r *http.Request) error {
					m.record(d, r)
					return nil
				}}
				c.EmailAndPassword.RequireEmailVerification = true
			}, paInstanceOpts{disableTestUser: true})
			env.mustCall("signUpEmail", map[string]any{"email": tc.email, "password": "password123", "name": "X"}, nil)
			if m.count() != tc.emails {
				t.Fatalf("sendVerificationEmail called %d times, want %d", m.count(), tc.emails)
			}
		})
	}
}

// describe("sign-up enumeration protection — indistinguishable response")
func TestPortAuthSignUpIndistinguishableResponse(t *testing.T) {
	env := paNewEnv(t, func(c *Config) {
		c.EmailAndPassword.RequireEmailVerification = true
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: func(context.Context, EmailData, *http.Request) error { return nil }}
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
			paStrField("displayName"),
			{Name: "isAdmin", Type: db.TypeBoolean, DefaultValue: false, Input: Bool(false)},
		}}}
	}, paInstanceOpts{disableTestUser: true})

	t.Run("should have identical image key presence for real and synthetic user when image is omitted", func(t *testing.T) {
		b := map[string]any{"email": "image-enum-test@test.com", "password": "password123", "name": "Image Enum Test"}
		first, _ := env.mustCall("signUpEmail", b, nil)
		second, _ := env.mustCall("signUpEmail", b, nil)
		fu, su := first["user"].(map[string]any), second["user"].(map[string]any)
		_, fi := fu["image"]
		_, si := su["image"]
		if fi != si {
			t.Fatalf("image key presence differs: real=%v synthetic=%v", fi, si)
		}
		if !reflect.DeepEqual(fu["image"], su["image"]) {
			t.Fatalf("image differs: %v vs %v", fu["image"], su["image"])
		}
	})

	t.Run("should have identical image key presence in raw JSON response when image is omitted", func(t *testing.T) {
		env2 := paNewEnv(t, func(c *Config) {
			c.EmailAndPassword.RequireEmailVerification = true
			c.EmailAndPassword.AutoSignIn = Bool(false)
		}, paInstanceOpts{disableTestUser: true})
		b := map[string]any{"name": "A", "email": "image-raw-test@example.com", "password": "correct horse battery staple"}
		r1 := env2.do("POST", "http://localhost/api/auth/sign-up/email", b, nil)
		r2 := env2.do("POST", "http://localhost/api/auth/sign-up/email", b, nil)
		if r1.Status != 200 || r2.Status != 200 {
			t.Fatalf("status %d/%d: %s / %s", r1.Status, r2.Status, r1.Body, r2.Body)
		}
		fu, su := r1.JSON(t)["user"].(map[string]any), r2.JSON(t)["user"].(map[string]any)
		_, fi := fu["image"]
		_, si := su["image"]
		if fi != si {
			t.Fatalf("image key presence differs: real=%v synthetic=%v (%s vs %s)", fi, si, r1.Body, r2.Body)
		}
		if !reflect.DeepEqual(fu["image"], su["image"]) {
			t.Fatalf("image differs: %v vs %v", fu["image"], su["image"])
		}
	})

	t.Run("should return same keys in same order for real and synthetic user", func(t *testing.T) {
		_, c1 := env.mustCall("signUpEmail", map[string]any{"email": "indistinguishable@test.com", "password": "password123", "name": "First User", "displayName": "FirstDisplay"}, nil)
		_, c2 := env.mustCall("signUpEmail", map[string]any{"email": "indistinguishable@test.com", "password": "password456", "name": "Second Attempt", "displayName": "SecondDisplay"}, nil)
		raw1, raw2 := paRaw(t, c1), paRaw(t, c2)
		if k1, k2 := paKeys(t, raw1), paKeys(t, raw2); !reflect.DeepEqual(k1, k2) {
			t.Fatalf("top-level keys differ: %v vs %v", k1, k2)
		}
		if k1, k2 := paKeys(t, raw1, "user"), paKeys(t, raw2, "user"); !reflect.DeepEqual(k1, k2) {
			t.Fatalf("user keys differ:\nreal:      %v\nsynthetic: %v", k1, k2)
		}
		first, second := paDecode(t, c1), paDecode(t, c2)
		if v, ok := second["token"]; !ok || v != nil {
			t.Fatalf("token should be null")
		}
		su, fu := second["user"].(map[string]any), first["user"].(map[string]any)
		if su["name"] != "Second Attempt" {
			t.Fatalf("name = %v", su["name"])
		}
		if su["id"] == fu["id"] {
			t.Fatalf("synthetic id should differ from real id")
		}
		if su["isAdmin"] != false {
			t.Fatalf("isAdmin = %v", su["isAdmin"])
		}
		if su["displayName"] != "SecondDisplay" {
			t.Fatalf("displayName = %v", su["displayName"])
		}
	})
}

// describe("sign-up enumeration protection — customSyntheticUser with admin plugin")
func TestPortAuthSignUpCustomSyntheticUserAdmin(t *testing.T) {
	t.Run("should return indistinguishable response with admin plugin fields", func(t *testing.T) {
		t.Skip("requires the admin plugin (not ported yet): role/banned/banReason/banExpires schema fields")
	})
}
