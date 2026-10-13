package username

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// Ported from packages/better-auth/src/plugins/username/username.test.ts.

func signUp(c *client, body map[string]any) *response {
	c.inst.t.Helper()
	return c.post("/sign-up/email", body)
}

func user(res *response) map[string]any {
	u, _ := res.JSON()["user"].(map[string]any)
	return u
}

func TestUsername(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{MinUsernameLength: 4})}, nil)
	signedIn := inst.client()

	t.Run("should sign up with username", func(t *testing.T) {
		c := inst.client()
		expectOK(t, signUp(c, map[string]any{"email": "new-email@gamil.com", "username": "new_username", "password": "new-password", "name": "new-name"}))
		eq(t, c.sessionUser()["username"], "new_username")
	})

	t.Run("should sign-in with username", func(t *testing.T) {
		res := signedIn.post("/sign-in/username", map[string]any{"username": "new_username", "password": "new-password"})
		if tok, _ := expectOK(t, res)["token"].(string); tok == "" {
			t.Fatal("expected token")
		}
	})

	t.Run("uses only the canonical credential account during username sign-in", func(t *testing.T) {
		inst := newInstance(t, []*betterauth.Plugin{New(Options{})}, nil)
		c := inst.client()
		res := signUp(c, map[string]any{"email": "canonical-username@example.com", "username": "canonical_username", "password": "canonical-password", "name": "Canonical Username"})
		userID := user(res)["id"].(string)
		ac := inst.auth.Context()
		ctx := context.Background()
		canonical, err := ac.InternalAdapter.FindCredentialAccount(ctx, userID)
		if err != nil || canonical == nil || canonical.Password == nil {
			t.Fatal("canonical credential account is required")
		}
		if err := ac.InternalAdapter.DeleteAccount(ctx, canonical.ID); err != nil {
			t.Fatal(err)
		}
		decoyHash, _ := ac.Password.Hash("decoy-password")
		if _, err := ac.InternalAdapter.CreateAccount(ctx, adapter.Record{"userId": userID, "providerId": "credential", "accountId": "decoy-subject", "password": decoyHash}); err != nil {
			t.Fatal(err)
		}
		if _, err := ac.InternalAdapter.CreateAccount(ctx, adapter.Record{"userId": userID, "providerId": "credential", "accountId": userID, "password": *canonical.Password}); err != nil {
			t.Fatal(err)
		}
		ok := c.post("/sign-in/username", map[string]any{"username": "canonical_username", "password": "canonical-password"})
		eq(t, user(ok)["id"], userID)
		decoy := c.post("/sign-in/username", map[string]any{"username": "canonical_username", "password": "decoy-password"})
		if decoy.Data() != nil {
			t.Fatal("expected no data")
		}
		eq(t, decoy.Status, 401)
	})

	t.Run("should redirect to callbackURL on sign-in (parity with sign-in/email)", func(t *testing.T) {
		res := inst.client().post("/sign-in/username", map[string]any{"username": "new_username", "password": "new-password", "callbackURL": "/dashboard"})
		d := expectOK(t, res)
		eq(t, d["redirect"], true)
		eq(t, d["url"], "/dashboard")
		if d["token"] == nil {
			t.Fatal("expected token")
		}
		eq(t, res.Header.Get("Location"), "/dashboard")
	})

	t.Run("should not set redirect when callbackURL is omitted", func(t *testing.T) {
		d := expectOK(t, inst.client().post("/sign-in/username", map[string]any{"username": "new_username", "password": "new-password"}))
		eq(t, d["redirect"], false)
		if _, ok := d["url"]; ok {
			t.Fatal("url should be undefined")
		}
	})

	t.Run("should update username", func(t *testing.T) {
		signedIn.post("/update-user", map[string]any{"username": "new_username_2.1"})
		eq(t, signedIn.sessionUser()["username"], "new_username_2.1")
	})

	t.Run("should fail on duplicate username in sign-up", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "new-email-2@gamil.com", "username": "New_username_2.1", "password": "new_password", "name": "new-name"})
		eq(t, res.Status, 400)
	})

	t.Run("should fail on duplicate username in update-user if user is different", func(t *testing.T) {
		signUp(inst.client(), map[string]any{"email": "duplicate_user@gmail.com", "username": "duplicate_user", "password": "new_password", "name": "duplicate-user"})
		res := inst.signInWithTestUser().post("/update-user", map[string]any{"username": "duplicate_user"})
		eq(t, res.Status, 400)
	})

	t.Run("should fail on duplicate username in update-user with different casing", func(t *testing.T) {
		signUp(inst.client(), map[string]any{"email": "case-test@gmail.com", "username": "casetestuser", "password": "new_password", "name": "case-test"})
		res := inst.signInWithTestUser().post("/update-user", map[string]any{"username": "CaseTestUser"})
		eq(t, res.Status, 400)
	})

	t.Run("should succeed on duplicate username in update-user if user is the same", func(t *testing.T) {
		signedIn.post("/update-user", map[string]any{"username": "New_username_2.1"})
		eq(t, signedIn.sessionUser()["username"], "new_username_2.1")
	})

	t.Run("should preserve both username and displayUsername when updating both", func(t *testing.T) {
		expectOK(t, signedIn.post("/update-user", map[string]any{"username": "priority_user", "displayUsername": "Priority Display Name"}))
		u := signedIn.sessionUser()
		eq(t, u["username"], "priority_user")
		eq(t, u["displayUsername"], "Priority Display Name")
	})

	t.Run("should fail on invalid username", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "email-4@email.com", "username": "new username", "password": "new_password", "name": "new-name"})
		expectStatus(t, res, 400, ErrInvalidUsername.Code)
	})

	t.Run("should fail on too short username", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "email-4@email.com", "username": "new", "password": "new_password", "name": "new-name"})
		expectStatus(t, res, 400, "USERNAME_TOO_SHORT")
	})

	t.Run("should fail on empty username", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "email-4@email.com", "username": "", "password": "new_password", "name": "new-name"})
		eq(t, res.Status, 400)
	})

	t.Run("should check if username is unavailable", func(t *testing.T) {
		eq(t, expectOK(t, inst.client().post("/is-username-available", map[string]any{"username": "priority_user"}))["available"], false)
	})

	t.Run("should check if username is unavailable with different case (normalization)", func(t *testing.T) {
		eq(t, expectOK(t, inst.client().post("/is-username-available", map[string]any{"username": "PRIORITY_USER"}))["available"], false)
	})

	t.Run("should check if username is available", func(t *testing.T) {
		eq(t, expectOK(t, inst.client().post("/is-username-available", map[string]any{"username": "new_username_2.2"}))["available"], true)
	})

	t.Run("should reject invalid username format in isUsernameAvailable", func(t *testing.T) {
		expectStatus(t, inst.client().post("/is-username-available", map[string]any{"username": "invalid username!"}), 422, ErrInvalidUsername.Code)
	})

	t.Run("should reject too short username in isUsernameAvailable", func(t *testing.T) {
		expectStatus(t, inst.client().post("/is-username-available", map[string]any{"username": "abc"}), 422, "USERNAME_TOO_SHORT")
	})

	t.Run("should reject too long username in isUsernameAvailable", func(t *testing.T) {
		expectStatus(t, inst.client().post("/is-username-available", map[string]any{"username": strings.Repeat("a", 31)}), 422, ErrUsernameTooLong.Code)
	})

	t.Run("should not normalize displayUsername", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "display-test@email.com", "displayUsername": "Test_Username", "password": "test-password", "name": "test-name"})
		u := c.sessionUser()
		eq(t, u["username"], "test_username")
		eq(t, u["displayUsername"], "Test_Username")
	})

	t.Run("should not store an invalid displayUsername-only value as username", func(t *testing.T) {
		c := inst.client()
		expectOK(t, signUp(c, map[string]any{"email": "invalid-display-username@email.com", "displayUsername": "Invalid Username", "password": "test-password", "name": "test-name"}))
		u := c.sessionUser()
		if v, ok := u["username"]; !ok || v != nil {
			t.Fatalf("expected username null, got %#v", u)
		}
		eq(t, u["displayUsername"], "Invalid Username")
	})

	t.Run("should not replace an explicit empty username with displayUsername", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "empty-username@email.com", "username": "", "displayUsername": "valid_username", "password": "test-password", "name": "test-name"})
		expectStatus(t, res, 400, ErrUsernameTooShort.Code)
	})

	t.Run("should preserve both username and displayUsername when both are provided", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "both-fields@email.com", "username": "custom_user", "displayUsername": "Fancy Display Name", "password": "test-password", "name": "test-name"})
		u := c.sessionUser()
		eq(t, u["username"], "custom_user")
		eq(t, u["displayUsername"], "Fancy Display Name")
	})

	t.Run("should sign in with normalized username", func(t *testing.T) {
		inst := newInstance(t, []*betterauth.Plugin{New(Options{})}, nil)
		c := inst.client()
		signUp(c, map[string]any{"email": "normalized-username@email.com", "username": "Custom_User", "password": "test-password", "name": "test-name"})
		res := c.post("/sign-in/username", map[string]any{"username": "Custom_User", "password": "test-password"})
		eq(t, user(res)["username"], "custom_user")
		eq(t, user(res)["displayUsername"], "Custom_User")
	})
}

func TestUsernameCustomNormalization(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{MinUsernameLength: 4, UsernameNormalization: func(u string) string {
		return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(u, "0", "o"), "4", "a"))
	}})}, nil)

	t.Run("should sign up with username", func(t *testing.T) {
		expectOK(t, signUp(inst.client(), map[string]any{"email": "new-email@gamil.com", "username": "H4XX0R", "password": "new-password", "name": "new-name"}))
	})

	t.Run("should fail on duplicate username", func(t *testing.T) {
		eq(t, signUp(inst.client(), map[string]any{"email": "new-email-2@gamil.com", "username": "haxxor", "password": "new-password", "name": "new-name"}).Status, 400)
	})

	t.Run("should normalize displayUsername", func(t *testing.T) {
		inst := newInstance(t, []*betterauth.Plugin{New(Options{DisplayUsernameNormalization: strings.ToLower})}, nil)
		ctx := context.Background()
		res, err := inst.auth.API.SignUpEmail(ctx, betterauth.SignUpEmailInput{Email: "new-email-3@gmail.com", Password: "new-password", Name: "new-name",
			Additional: map[string]any{"username": "test_username", "displayUsername": "Test Username"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := inst.client()
		c.apply(res.Headers)
		u := c.sessionUser()
		eq(t, u["username"], "test_username")
		eq(t, u["displayUsername"], "test username")
	})
}

var displayRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func TestUsernameWithDisplayUsernameValidation(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{DisplayUsernameValidator: displayRe.MatchString})}, nil)

	t.Run("should accept valid displayUsername", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "display-valid@email.com", "displayUsername": "Valid_Display-123", "password": "test-password", "name": "test-name"})
		expectOK(t, res)
		if v, ok := user(res)["username"]; !ok || v != nil {
			t.Fatalf("expected username null: %s", res.Body)
		}
		eq(t, user(res)["displayUsername"], "Valid_Display-123")
	})

	t.Run("should reject invalid displayUsername", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "display-invalid@email.com", "username": "invalid_display", "displayUsername": "Invalid Display!", "password": "test-password", "name": "test-name"})
		expectStatus(t, res, 400, ErrInvalidDisplayUsername.Code)
	})

	t.Run("should not validate inferred displayUsername during sign-up", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "inferred-display@email.com", "username": "valid.username", "password": "test-password", "name": "test-name"})
		expectOK(t, res)
		eq(t, user(res)["username"], "valid.username")
		eq(t, user(res)["displayUsername"], "valid.username")
	})

	t.Run("should update displayUsername with valid value", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "update-display@email.com", "displayUsername": "Initial_Name", "username": "initial_name", "password": "test-password", "name": "test-name"})
		before := c.sessionUser()
		eq(t, before["displayUsername"], "Initial_Name")
		eq(t, before["username"], "initial_name")
		expectOK(t, c.post("/update-user", map[string]any{"displayUsername": "Updated_Name-123"}))
		after := c.sessionUser()
		eq(t, after["displayUsername"], "Updated_Name-123")
		eq(t, after["username"], "initial_name")
	})

	t.Run("should reject invalid displayUsername on update", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "update-invalid@email.com", "username": "valid_name", "displayUsername": "Valid_Name", "password": "test-password", "name": "test-name"})
		expectStatus(t, c.post("/update-user", map[string]any{"displayUsername": "Invalid Display!"}), 400, ErrInvalidDisplayUsername.Code)
	})
}

func TestIsUsernameAvailableWithCustomValidator(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{UsernameValidator: func(u string) bool { return strings.HasPrefix(u, "user_") }})}, nil)

	t.Run("should accept username with custom validator", func(t *testing.T) {
		eq(t, expectOK(t, inst.client().post("/is-username-available", map[string]any{"username": "user_valid123"}))["available"], true)
	})

	t.Run("should reject username that doesn't match custom validator", func(t *testing.T) {
		expectStatus(t, inst.client().post("/is-username-available", map[string]any{"username": "invalid_user"}), 422, ErrInvalidUsername.Code)
	})

	t.Run("should reject username that doesn't match custom validator during sign-up/sign-in", func(t *testing.T) {
		c := inst.client()
		res := signUp(c, map[string]any{"email": "test-user@test.com", "password": "password1234", "name": "Test user", "username": "invalid_user"})
		eq(t, res.Code(), ErrInvalidUsername.Code)
		res = c.post("/sign-in/username", map[string]any{"username": "invalid_user", "password": "password1234"})
		eq(t, res.Code(), ErrInvalidUsername.Code)
	})
}

func TestPostNormalizationFlow(t *testing.T) {
	t.Run("should set displayUsername to username if only username is provided", func(t *testing.T) {
		inst := newInstance(t, []*betterauth.Plugin{New(Options{
			ValidationOrder:       ValidationOrder{Username: PostNormalization, DisplayUsername: PostNormalization},
			UsernameNormalization: func(u string) string { return strings.ToLower(strings.Join(strings.Split(u, " "), "_")) },
		})}, nil)
		res, err := inst.auth.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: "test-username@email.com", Password: "test-password", Name: "test-name",
			Additional: map[string]any{"username": "Test Username"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := inst.client()
		c.apply(res.Headers)
		u := c.sessionUser()
		eq(t, u["username"], "test_username")
		eq(t, u["displayUsername"], "Test Username")
	})
}

func TestUsernameEmailVerificationFlowNoInfoLeak(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{})}, func(c *betterauth.Config) {
		c.EmailAndPassword.RequireEmailVerification = true
	})

	t.Run("returns INVALID_USERNAME_OR_PASSWORD for wrong password even if email is unverified", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "unverified-user@example.com", "username": "unverified_user", "password": "correct-password", "name": "Unverified User"})
		expectStatus(t, c.post("/sign-in/username", map[string]any{"username": "unverified_user", "password": "wrong-password"}), 401, "INVALID_USERNAME_OR_PASSWORD")
	})

	t.Run("returns EMAIL_NOT_VERIFIED only after a correct password for an unverified user", func(t *testing.T) {
		expectStatus(t, inst.client().post("/sign-in/username", map[string]any{"username": "unverified_user", "password": "correct-password"}), 403, "EMAIL_NOT_VERIFIED")
	})
}

func TestImmutableUsername(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{ImmutableUsername: true})}, nil)

	t.Run("should sign up with username when immutable username is enabled", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "immutable-test@example.com", "username": "immutable_user", "password": "password123", "name": "Immutable Test"})
		eq(t, c.sessionUser()["username"], "immutable_user")
	})

	t.Run("should fail when trying to update username to a different value", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "immutable-update-test@example.com", "username": "immutable_update_user", "password": "password123", "name": "Immutable Update Test"})
		expectStatus(t, c.post("/update-user", map[string]any{"username": "new_username_attempt"}), 400, ErrUsernameIsImmutable.Code)
	})

	t.Run("should succeed setting username if previously unset", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "immutable-update-unset-test@example.com", "password": "password123", "name": "Immutable Update Test"})
		expectOK(t, c.post("/update-user", map[string]any{"username": "new_username_previously_unset"}))
		eq(t, c.sessionUser()["username"], "new_username_previously_unset")
	})

	t.Run("should succeed when updating username to the same value", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "immutable-same-value@example.com", "username": "immutable_same_user", "password": "password123", "name": "Immutable Same Value Test"})
		expectOK(t, c.post("/update-user", map[string]any{"username": "immutable_same_user"}))
		eq(t, c.sessionUser()["username"], "immutable_same_user")
	})

	t.Run("should succeed when updating displayUsername even with immutable username", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "immutable-display-update@example.com", "username": "immutable_display_user", "displayUsername": "Original Display", "password": "password123", "name": "Immutable Display Update Test"})
		expectOK(t, c.post("/update-user", map[string]any{"displayUsername": "Updated Display Name"}))
		u := c.sessionUser()
		eq(t, u["username"], "immutable_display_user")
		eq(t, u["displayUsername"], "Updated Display Name")
	})
}

func TestUsernameSignInVerifyEmailCallbackURL(t *testing.T) {
	t.Run("encodes callbackURL in the verify-email link on username sign-in", func(t *testing.T) {
		captured := ""
		inst := newInstance(t, []*betterauth.Plugin{New(Options{})}, func(c *betterauth.Config) {
			c.EmailAndPassword.RequireEmailVerification = true
			c.EmailVerification = &betterauth.EmailVerificationConfig{SendOnSignIn: true,
				SendVerificationEmail: func(_ context.Context, d betterauth.EmailData, _ *http.Request) error {
					captured = d.URL
					return nil
				}}
		})
		c := inst.client()
		signUp(c, map[string]any{"email": "encode-username@example.com", "username": "encode_username", "password": "correct-password", "name": "Encode Username"})
		cb := "/welcome?ref=username&plan=pro"
		c.post("/sign-in/username", map[string]any{"username": "encode_username", "password": "correct-password", "callbackURL": cb})
		if captured == "" {
			t.Fatal("no url captured")
		}
		u, err := url.Parse(captured)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, u.Query().Get("callbackURL"), cb)
	})
}

func TestUsernameWithDisplayUsernameDisabled(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{DisplayUsername: betterauth.Bool(false)})}, nil)

	t.Run("should sign up and normalize username without writing displayUsername", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "no-display@example.com", "username": "No_Display_User", "password": "new-password", "name": "No Display"})
		u := c.sessionUser()
		eq(t, u["username"], "no_display_user")
		if _, ok := u["displayUsername"]; ok {
			t.Fatal("displayUsername should not be present")
		}
	})

	t.Run("should update username without writing displayUsername", func(t *testing.T) {
		c := inst.client()
		signUp(c, map[string]any{"email": "no-display-update@example.com", "username": "update_no_display", "password": "new-password", "name": "Update No Display"})
		expectOK(t, c.post("/update-user", map[string]any{"username": "Updated_No_Display"}))
		u := c.sessionUser()
		eq(t, u["username"], "updated_no_display")
		if _, ok := u["displayUsername"]; ok {
			t.Fatal("displayUsername should not be present")
		}
	})
}

func TestUsernameWithDisplayUsernameDisabledAndAValidator(t *testing.T) {
	inst := newInstance(t, []*betterauth.Plugin{New(Options{DisplayUsername: betterauth.Bool(false), DisplayUsernameValidator: displayRe.MatchString})}, nil)
	t.Run("should not validate displayUsername from the body when the field is disabled", func(t *testing.T) {
		res := signUp(inst.client(), map[string]any{"email": "disabled-validator@example.com", "username": "disabled_validator_user", "password": "new-password", "name": "Disabled Validator", "displayUsername": "Invalid Display!"})
		expectOK(t, res)
		eq(t, user(res)["username"], "disabled_validator_user")
		if _, ok := user(res)["displayUsername"]; ok {
			t.Fatal("displayUsername should not be present")
		}
	})
}

func TestUsernameSignInPasswordLength(t *testing.T) {
	var hashCalls, verifyCalls atomic.Int32
	hash := func(pw string) (string, error) { hashCalls.Add(1); return "hashed:" + pw, nil }
	verify := func(h, pw string) (bool, error) { verifyCalls.Add(1); return h == "hashed:"+pw, nil }
	inst := newInstance(t, []*betterauth.Plugin{New(Options{})}, func(c *betterauth.Config) {
		c.EmailAndPassword.Password = &betterauth.PasswordConfig{Hash: hash, Verify: verify}
	})
	t.Run("should reject a password longer than maxPasswordLength before hashing", func(t *testing.T) {
		ctx := context.Background()
		if _, err := inst.auth.API.SignUpEmail(ctx, betterauth.SignUpEmailInput{Email: "long-password@test.com", Password: "password", Name: "Long Password",
			Additional: map[string]any{"username": "long_password"}}, nil); err != nil {
			t.Fatal(err)
		}
		hashCalls.Store(0)
		verifyCalls.Store(0)
		_, err := inst.auth.API.Call(ctx, "signInUsername", betterauth.CallInput{Body: map[string]any{"username": "long_password", "password": strings.Repeat("x", 129)}})
		e, ok := betterauth.AsAPIError(err)
		if !ok || e.Status != "BAD_REQUEST" || e.Code() != "PASSWORD_TOO_LONG" {
			t.Fatalf("unexpected error %v", err)
		}
		eq(t, hashCalls.Load(), int32(0))
		eq(t, verifyCalls.Load(), int32(0))
	})
}
