package passkey

// Ports packages/passkey/src/passkey.test.ts. The upstream suite mocks
// @simplewebauthn/server's verifyRegistrationResponse / verifyAuthenticationResponse;
// mockVerifiers swaps the package verifiers the same way.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func TestPasskey(t *testing.T) {
	ti := newInstance(t, Options{})
	mocks := mockVerifiers(t)

	t.Run("should reject registration without a response", func(t *testing.T) {
		defer mocks.reset()
		headers, _ := ti.signInWithTestUser()
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		res := ti.fetch("POST", "/passkey/verify-registration", headers, nil, map[string]any{}, false)
		if res.Status != 400 {
			t.Fatalf("status %d %s", res.Status, res.Body)
		}
		if mocks.regCalls.Load() != 0 {
			t.Fatal("verifyRegistrationResponse was called")
		}
	})

	t.Run("should generate register options", func(t *testing.T) {
		headers, _ := ti.signInWithTestUser()
		options, _, err := ti.call("generatePasskeyRegistrationOptions", headers, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"challenge", "rp", "user", "pubKeyCredParams"} {
			if _, ok := options[k]; !ok {
				t.Fatalf("missing %s in %v", k, options)
			}
		}
		res := ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, false)
		if sc := strings.Join(res.Header.Values("Set-Cookie"), "\n"); !strings.Contains(sc, "better-auth-passkey") {
			t.Fatalf("set-cookie %q", sc)
		}
	})

	t.Run("should generate authenticate options", func(t *testing.T) {
		headers, _ := ti.signInWithTestUser()
		options, _, err := ti.call("generatePasskeyAuthenticationOptions", headers, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// allowCredentials is undefined (omitted from JSON) while the user has no passkeys;
		// the TS assertion sees the key with an undefined value.
		for _, k := range []string{"challenge", "rpId", "userVerification"} {
			if _, ok := options[k]; !ok {
				t.Fatalf("missing %s in %v", k, options)
			}
		}
	})

	t.Run("should generate authenticate options without session (discoverable credentials)", func(t *testing.T) {
		options, _, err := ti.call("generatePasskeyAuthenticationOptions", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"challenge", "rpId", "userVerification"} {
			if _, ok := options[k]; !ok {
				t.Fatalf("missing %s", k)
			}
		}
		if _, ok := options["allowCredentials"]; ok {
			t.Fatal("allowCredentials must be omitted without a session")
		}
	})

	t.Run("should list user passkeys", func(t *testing.T) {
		headers, user := ti.signInWithTestUser()
		ti.createPasskey(mockPasskey(user["id"].(string), "mockCredentialID", "mockName", "mockTransports"))
		passkeys := ti.callList("listPasskeys", headers)
		if len(passkeys) == 0 {
			t.Fatal("no passkeys")
		}
		for _, k := range []string{"id", "userId", "publicKey", "credentialID", "aaguid"} {
			if _, ok := passkeys[0][k]; !ok {
				t.Fatalf("missing %s", k)
			}
		}
	})

	t.Run("should update a passkey", func(t *testing.T) {
		headers, _ := ti.signInWithTestUser()
		passkeys := ti.callList("listPasskeys", headers)
		res, _, err := ti.call("updatePasskey", headers, map[string]any{"id": passkeys[0]["id"], "name": "newName"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res["passkey"].(map[string]any)["name"] != "newName" {
			t.Fatalf("%v", res)
		}
	})

	t.Run("rejects a whitespace-only passkey name on update", func(t *testing.T) {
		headers, user := ti.signInWithTestUser()
		pk := ti.createPasskey(mockPasskey(user["id"].(string), "update-reject-cred", "original", "internal"))
		_, _, err := ti.call("updatePasskey", headers, map[string]any{"id": pk["id"], "name": "   "}, nil)
		if apiErr(t, err).StatusCode != 400 {
			t.Fatalf("%v", err)
		}
	})

	t.Run("should not delete a passkey that doesn't exist", func(t *testing.T) {
		headers, _ := ti.signInWithTestUser()
		_, _, err := ti.call("deletePasskey", headers, map[string]any{"id": "mockPasskeyId"}, nil)
		apiErr(t, err)
	})

	t.Run("should delete a passkey", func(t *testing.T) {
		headers, user := ti.signInWithTestUser()
		pk := ti.createPasskey(mockPasskey(user["id"].(string), "mockCredentialID", "mockName", "mockTransports"))
		res, _, err := ti.call("deletePasskey", headers, map[string]any{"id": pk["id"]}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res["status"] != true {
			t.Fatalf("%v", res)
		}
	})

	t.Run("should not allow deleting another user's passkey", func(t *testing.T) {
		_, userA := ti.signInWithTestUser()
		pk := ti.createPasskey(mockPasskey(userA["id"].(string), "cross-user-delete-test", "userA-passkey", "mockTransports"))
		headersB, _ := ti.signUpAndIn("attacker-delete@test.com", "password123", "Attacker")
		_, _, err := ti.call("deletePasskey", headersB, map[string]any{"id": pk["id"]}, nil)
		apiErr(t, err)
		if rows := ti.findPasskeys(adapter.Where{Field: "id", Value: pk["id"]}); len(rows) != 1 {
			t.Fatal("passkey was deleted")
		}
	})

	t.Run("should not allow updating another user's passkey", func(t *testing.T) {
		_, userA := ti.signInWithTestUser()
		pk := ti.createPasskey(mockPasskey(userA["id"].(string), "cross-user-update-test", "original-name", "mockTransports"))
		headersB, _ := ti.signUpAndIn("attacker-update@test.com", "password123", "Attacker")
		_, _, err := ti.call("updatePasskey", headersB, map[string]any{"id": pk["id"], "name": "hacked"}, nil)
		apiErr(t, err)
		rows := ti.findPasskeys(adapter.Where{Field: "id", Value: pk["id"]})
		if rows[0]["name"] != "original-name" {
			t.Fatalf("%v", rows[0])
		}
	})

	t.Run("should verify passkey authentication and return user", func(t *testing.T) {
		defer mocks.reset()
		headers, user := ti.signInWithTestUser()
		ti.createPasskey(mockPasskey(user["id"].(string), "mockCredentialID", "mockName", "mockTransports"))
		res := ti.fetch("GET", "/passkey/generate-authenticate-options", headers, nil, nil, false)
		passkeyCookie := strings.SplitN(res.Header.Get("Set-Cookie"), ";", 2)[0]
		mocks.setAuth(&VerifiedAuthenticationResponse{Verified: true, AuthenticationInfo: AuthenticationInfo{NewCounter: 1}})
		headers.Set("Cookie", headers.Get("Cookie")+"; "+passkeyCookie)
		headers.Set("origin", testOrigin)
		out, _, err := ti.call("verifyPasskeyAuthentication", headers, mockAuthenticationBody("mockCredentialID"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if out["session"] == nil || out["user"] == nil {
			t.Fatalf("%v", out)
		}
		u := out["user"].(map[string]any)
		if u["id"] != user["id"] || u["email"] != user["email"] {
			t.Fatalf("%v", u)
		}
	})

	t.Run("should propagate inner APIError status when registration verification fails", func(t *testing.T) {
		defer mocks.reset()
		headers, _ := ti.signInWithTestUser()
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		mocks.setReg(&VerifiedRegistrationResponse{Verified: false})
		_, _, err := ti.call("verifyPasskeyRegistration", headers, map[string]any{"response": mockRegistrationResponse}, nil)
		expectAPIError(t, err, "BAD_REQUEST", "FAILED_TO_VERIFY_REGISTRATION")
	})

	t.Run("should propagate inner APIError status when authentication verification fails", func(t *testing.T) {
		defer mocks.reset()
		headers, user := ti.signInWithTestUser()
		ti.createPasskey(mockPasskey(user["id"].(string), "mockCredentialID", "mockName", "mockTransports"))
		res := ti.fetch("GET", "/passkey/generate-authenticate-options", headers, nil, nil, false)
		headers.Set("Cookie", headers.Get("Cookie")+"; "+strings.SplitN(res.Header.Get("Set-Cookie"), ";", 2)[0])
		headers.Set("origin", testOrigin)
		mocks.setAuth(&VerifiedAuthenticationResponse{Verified: false})
		_, _, err := ti.call("verifyPasskeyAuthentication", headers, mockAuthenticationBody("mockCredentialID"), nil)
		expectAPIError(t, err, "UNAUTHORIZED", "AUTHENTICATION_FAILED")
	})

	t.Run("should mint at most one session under concurrent verification of the same challenge", func(t *testing.T) {
		defer mocks.reset()
		headers, user := ti.signInWithTestUser()
		ti.createPasskey(mockPasskey(user["id"].(string), "race-credential-id", "race-passkey", "internal"))
		res := ti.fetch("GET", "/passkey/generate-authenticate-options", headers, nil, nil, false)
		headers.Set("Cookie", headers.Get("Cookie")+"; "+strings.SplitN(res.Header.Get("Set-Cookie"), ";", 2)[0])
		headers.Set("origin", testOrigin)
		mocks.setAuth(&VerifiedAuthenticationResponse{Verified: true, AuthenticationInfo: AuthenticationInfo{NewCounter: 1}})
		var wg sync.WaitGroup
		var mu sync.Mutex
		fulfilled := 0
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := ti.auth.API.Call(context.Background(), "verifyPasskeyAuthentication", betterauth.CallInput{Headers: headers.Clone(), Body: mockAuthenticationBody("race-credential-id")})
				if err == nil {
					mu.Lock()
					fulfilled++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if fulfilled != 1 {
			t.Fatalf("fulfilled %d", fulfilled)
		}
	})

	t.Run("should reject when the WebAuthn challenge is not consumable", func(t *testing.T) {
		defer mocks.reset()
		headers := http.Header{}
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-authenticate-options", headers, nil, nil, true)
		// consumeVerificationValue resolving null: the challenge row is gone.
		if _, err := ti.ctx().Adapter.DeleteMany(context.Background(), "verification", nil); err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"response": map[string]any{"id": "", "rawId": "",
			"response":               map[string]any{"clientDataJSON": "", "authenticatorData": "", "signature": ""},
			"clientExtensionResults": map[string]any{}, "type": "public-key"}}
		_, _, err := ti.call("verifyPasskeyAuthentication", headers, body, nil)
		expectAPIError(t, err, "BAD_REQUEST", "CHALLENGE_NOT_FOUND")
	})
}

func TestPasskeyPreAuth(t *testing.T) {
	t.Run("should generate register options without session when resolveUser is provided", func(t *testing.T) {
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			RequireSession: betterauth.Bool(false),
			ResolveUser: func(*betterauth.EndpointContext, *string) (*RegistrationUser, error) {
				return &RegistrationUser{ID: "pre-auth-user", Name: "pre-auth@example.com"}, nil
			},
		}})
		options, _, err := ti.call("generatePasskeyRegistrationOptions", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"challenge", "rp", "user", "pubKeyCredParams"} {
			if _, ok := options[k]; !ok {
				t.Fatalf("missing %s", k)
			}
		}
	})

	t.Run("should create a session after pre-auth passkey registration", func(t *testing.T) {
		mocks := mockVerifiers(t)
		userID := ""
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			RequireSession: betterauth.Bool(false),
			ResolveUser: func(*betterauth.EndpointContext, *string) (*RegistrationUser, error) {
				return &RegistrationUser{ID: "pending-passkey-registration", Name: "passkey-first@example.com"}, nil
			},
			AfterVerification: func(a AfterRegistrationArgs) (*AfterRegistrationResult, error) {
				u, err := a.Ctx.Auth.InternalAdapter.CreateUser(a.Ctx.Context(), adapter.Record{"name": "Passkey First", "email": "passkey-first@example.com"}, betterauth.UserInfoSource{Method: "test"})
				if err != nil {
					return nil, err
				}
				userID = u.ID
				return &AfterRegistrationResult{UserID: userID}, nil
			},
		}})
		headers := http.Header{}
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		mocks.setReg(mockRegistrationVerification)
		out, res, err := ti.call("verifyPasskeyRegistration", headers, map[string]any{"response": mockRegistrationResponse, "createSession": true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out["credentialID"] != "credential-id" || out["session"].(map[string]any)["userId"] != userID || out["user"].(map[string]any)["id"] != userID {
			t.Fatalf("%v", out)
		}
		if sc := strings.Join(res.Headers.Values("Set-Cookie"), "\n"); !strings.Contains(sc, "better-auth.session_token=") {
			t.Fatalf("set-cookie %q", sc)
		}
	})

	t.Run("should roll back passkey persistence when session creation fails", func(t *testing.T) {
		mocks := mockVerifiers(t)
		userID := ""
		failSession := false
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			RequireSession: betterauth.Bool(false),
			ResolveUser: func(*betterauth.EndpointContext, *string) (*RegistrationUser, error) {
				return &RegistrationUser{ID: "pending-failed-registration", Name: "failed-session@example.com"}, nil
			},
			AfterVerification: func(a AfterRegistrationArgs) (*AfterRegistrationResult, error) {
				u, err := a.Ctx.Auth.InternalAdapter.CreateUser(a.Ctx.Context(), adapter.Record{"name": "Failed Session", "email": "failed-session@example.com"}, betterauth.UserInfoSource{Method: "test"})
				if err != nil {
					return nil, err
				}
				userID = u.ID
				return &AfterRegistrationResult{UserID: userID}, nil
			},
		}}, func(c *betterauth.Config) {
			// internalAdapter.createSession resolving null (vi.spyOn(...).mockResolvedValueOnce(null)).
			c.DatabaseHooks = &betterauth.DatabaseHooks{Session: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				Before: func(context.Context, adapter.Record) (*betterauth.DBHookResult, error) {
					if failSession {
						return &betterauth.DBHookResult{Abort: true}, nil
					}
					return nil, nil
				},
			}}}
		})
		headers := http.Header{}
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		mocks.setReg(mockRegistrationVerification)
		failSession = true
		_, _, err := ti.call("verifyPasskeyRegistration", headers, map[string]any{"response": mockRegistrationResponse, "createSession": true}, nil)
		expectAPIError(t, err, "INTERNAL_SERVER_ERROR", "UNABLE_TO_CREATE_SESSION")
		failSession = false
		if rows := ti.findPasskeys(adapter.Where{Field: "credentialID", Value: "credential-id"}); len(rows) != 0 {
			t.Fatalf("passkey persisted: %v", rows)
		}
		if u, _ := ti.ctx().InternalAdapter.FindUserByID(context.Background(), userID); u != nil {
			t.Fatal("user creation was not rolled back")
		}
	})

	t.Run("should require resolveUser when session is not available", func(t *testing.T) {
		ti := newInstance(t, Options{Registration: &RegistrationOptions{RequireSession: betterauth.Bool(false)}})
		_, _, err := ti.call("generatePasskeyRegistrationOptions", nil, nil, nil)
		expectAPIError(t, err, "BAD_REQUEST", "RESOLVE_USER_REQUIRED")
	})

	t.Run("should call afterVerification and allow userId override", func(t *testing.T) {
		mocks := mockVerifiers(t)
		linkedUserID := ""
		var gotContext *string
		called := false
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			RequireSession: betterauth.Bool(false),
			ResolveUser: func(*betterauth.EndpointContext, *string) (*RegistrationUser, error) {
				return &RegistrationUser{ID: "pre-auth-user-id", Name: "pre-auth@example.com", DisplayName: "Pre-auth user"}, nil
			},
			AfterVerification: func(a AfterRegistrationArgs) (*AfterRegistrationResult, error) {
				called = true
				gotContext = a.Context
				return &AfterRegistrationResult{UserID: linkedUserID}, nil
			},
		}})
		res, err := ti.auth.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: "linked-user@example.com", Password: "test123456", Name: "Linked User"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var su map[string]any
		_ = res.Decode(&su)
		linkedUserID = su["user"].(map[string]any)["id"].(string)
		mocks.setReg(mockRegistrationVerification)
		headers := http.Header{}
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, url.Values{"context": {"link-token"}}, nil, true)
		out, _, err := ti.call("verifyPasskeyRegistration", headers, map[string]any{"response": mockRegistrationResponse}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if mocks.regCalls.Load() == 0 || !called || gotContext == nil || *gotContext != "link-token" {
			t.Fatalf("calls=%d called=%v context=%v", mocks.regCalls.Load(), called, gotContext)
		}
		if out["userId"] != linkedUserID {
			t.Fatalf("%v", out)
		}
	})

	t.Run("should reject invalid userId returned from afterVerification", func(t *testing.T) {
		t.Skip("TS-only: the hook returns userId: 123 (a non-string); AfterRegistrationResult.UserID is a Go string, so the case cannot be expressed")
	})

	t.Run("should reject afterVerification override that mismatches session user", func(t *testing.T) {
		mocks := mockVerifiers(t)
		called := false
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			AfterVerification: func(AfterRegistrationArgs) (*AfterRegistrationResult, error) {
				called = true
				return &AfterRegistrationResult{UserID: "different-user-id"}, nil
			},
		}})
		mocks.setReg(mockRegistrationVerification)
		headers, _ := ti.signInWithTestUser()
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		_, _, err := ti.call("verifyPasskeyRegistration", headers, map[string]any{"response": mockRegistrationResponse}, nil)
		expectAPIError(t, err, "UNAUTHORIZED", "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")
		if !called {
			t.Fatal("afterVerification not called")
		}
	})

	t.Run("should register at most one passkey under concurrent verification of the same challenge", func(t *testing.T) {
		mocks := mockVerifiers(t)
		raceUserID := ""
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			RequireSession: betterauth.Bool(false),
			ResolveUser: func(*betterauth.EndpointContext, *string) (*RegistrationUser, error) {
				return &RegistrationUser{ID: raceUserID, Name: "race@example.com"}, nil
			},
		}})
		res, err := ti.auth.API.SignUpEmail(context.Background(), betterauth.SignUpEmailInput{Email: "race@example.com", Password: "password1234", Name: "Race User"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var su map[string]any
		_ = res.Decode(&su)
		raceUserID = su["user"].(map[string]any)["id"].(string)
		headers := http.Header{}
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		gate := make(chan struct{})
		mocks.mu.Lock()
		mocks.reg = func(VerifyRegistrationInput) (*VerifiedRegistrationResponse, error) {
			<-gate
			return buildRegistrationVerification("race-aaguid", "race-reg-credential-id"), nil
		}
		mocks.mu.Unlock()
		body := map[string]any{"response": map[string]any{"id": "race-reg-credential-id", "response": map[string]any{"transports": []any{"internal"}}}}
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = ti.auth.API.Call(context.Background(), "verifyPasskeyRegistration", betterauth.CallInput{Headers: headers.Clone(), Body: body})
			}()
		}
		time.Sleep(50 * time.Millisecond)
		close(gate)
		wg.Wait()
		if rows := ti.findPasskeys(adapter.Where{Field: "credentialID", Value: "race-reg-credential-id"}); len(rows) != 1 {
			t.Fatalf("rows %d", len(rows))
		}
	})
}

func TestPasskeyCeremonyAndIdentityGating(t *testing.T) {
	t.Run("rejects a registration that reuses an authentication challenge in pre-auth mode", func(t *testing.T) {
		mocks := mockVerifiers(t)
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			RequireSession: betterauth.Bool(false),
			ResolveUser: func(*betterauth.EndpointContext, *string) (*RegistrationUser, error) {
				return &RegistrationUser{ID: "resolved-user-id", Name: "resolved@example.com"}, nil
			},
		}})
		headers := http.Header{}
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-authenticate-options", headers, nil, nil, true)
		mocks.setReg(mockRegistrationVerification)
		_, _, err := ti.call("verifyPasskeyRegistration", headers, map[string]any{"response": mockRegistrationResponse}, nil)
		expectAPIError(t, err, "BAD_REQUEST", "CHALLENGE_NOT_FOUND")
		if mocks.regCalls.Load() != 0 {
			t.Fatal("verifier called")
		}
		if rows := ti.findPasskeys(adapter.Where{Field: "credentialID", Value: "credential-id"}); len(rows) != 0 {
			t.Fatal("passkey created")
		}
	})

	t.Run("rejects an authentication that reuses a registration challenge", func(t *testing.T) {
		mocks := mockVerifiers(t)
		ti := newInstance(t, Options{})
		headers, user := ti.signInWithTestUser()
		headers.Set("origin", testOrigin)
		ti.createPasskey(mockPasskey(user["id"].(string), "cross-ceremony-credential-id", "cross-ceremony-passkey", "internal"))
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		mocks.setAuth(&VerifiedAuthenticationResponse{Verified: true, AuthenticationInfo: AuthenticationInfo{NewCounter: 1}})
		_, _, err := ti.call("verifyPasskeyAuthentication", headers, mockAuthenticationBody("cross-ceremony-credential-id"), nil)
		expectAPIError(t, err, "BAD_REQUEST", "CHALLENGE_NOT_FOUND")
		if mocks.authCalls.Load() != 0 {
			t.Fatal("verifier called")
		}
	})

	t.Run("rejects registration when the resolved target user id is empty", func(t *testing.T) {
		mocks := mockVerifiers(t)
		ti := newInstance(t, Options{Registration: &RegistrationOptions{
			RequireSession: betterauth.Bool(false),
			ResolveUser: func(*betterauth.EndpointContext, *string) (*RegistrationUser, error) {
				return &RegistrationUser{ID: "seed-user-id", Name: "seed@example.com"}, nil
			},
		}})
		headers := http.Header{}
		headers.Set("origin", testOrigin)
		ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
		ctx := context.Background()
		rows, err := ti.ctx().Adapter.FindMany(ctx, adapter.FindManyInput{Model: "verification"})
		if err != nil || len(rows) == 0 {
			t.Fatalf("%v %v", rows, err)
		}
		challenge := rows[len(rows)-1]
		var parsed map[string]any
		_ = json.Unmarshal([]byte(challenge["value"].(string)), &parsed)
		parsed["userData"].(map[string]any)["id"] = ""
		b, _ := json.Marshal(parsed)
		if _, err := ti.ctx().Adapter.Update(ctx, "verification", []adapter.Where{{Field: "id", Value: challenge["id"]}}, adapter.Record{"value": string(b)}); err != nil {
			t.Fatal(err)
		}
		mocks.setReg(mockRegistrationVerification)
		_, _, err = ti.call("verifyPasskeyRegistration", headers, map[string]any{"response": mockRegistrationResponse}, nil)
		expectAPIError(t, err, "BAD_REQUEST", "RESOLVED_USER_INVALID")
		if rows := ti.findPasskeys(adapter.Where{Field: "credentialID", Value: "credential-id"}); len(rows) != 0 {
			t.Fatal("passkey created")
		}
	})
}

const googleAAGUID = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"

func registerNamed(t *testing.T, ti *instance, mocks *verifierMocks, aaguid, credentialID string, name *string) (map[string]any, error) {
	t.Helper()
	headers, _ := ti.signInWithTestUser()
	headers.Set("origin", testOrigin)
	mocks.setReg(buildRegistrationVerification(aaguid, credentialID))
	ti.fetch("GET", "/passkey/generate-register-options", headers, nil, nil, true)
	body := map[string]any{"response": mockRegistrationResponse}
	if name != nil {
		body["name"] = *name
	}
	out, _, err := ti.call("verifyPasskeyRegistration", headers, body, nil)
	return out, err
}

func strp(s string) *string { return &s }

func TestPasskeyRegistrationNamingDefaultOptions(t *testing.T) {
	ti := newInstance(t, Options{})
	mocks := mockVerifiers(t)

	t.Run("stores the trimmed client-provided name", func(t *testing.T) {
		rec, err := registerNamed(t, ti, mocks, googleAAGUID, "cred-explicit", strp("  My Work Key  "))
		if err != nil || rec["name"] != "My Work Key" {
			t.Fatalf("%v %v", rec, err)
		}
	})
	t.Run("stores no label for a whitespace-only name", func(t *testing.T) {
		rec, err := registerNamed(t, ti, mocks, googleAAGUID, "cred-whitespace", strp("   "))
		if err != nil || rec["name"] != nil {
			t.Fatalf("%v %v", rec, err)
		}
	})
	t.Run("does not infer a label from the AAGUID, but persists the raw AAGUID", func(t *testing.T) {
		rec, err := registerNamed(t, ti, mocks, googleAAGUID, "cred-no-name", nil)
		if err != nil || rec["name"] != nil || rec["aaguid"] != googleAAGUID {
			t.Fatalf("%v %v", rec, err)
		}
	})
}

func TestPasskeyRegistrationNamingAfterVerificationFallback(t *testing.T) {
	calls := 0
	ti := newInstance(t, Options{Registration: &RegistrationOptions{
		AfterVerification: func(AfterRegistrationArgs) (*AfterRegistrationResult, error) {
			calls++
			return &AfterRegistrationResult{Name: "My Provider"}, nil
		},
	}})
	mocks := mockVerifiers(t)

	t.Run("uses the returned name when the client provides none", func(t *testing.T) {
		rec, err := registerNamed(t, ti, mocks, googleAAGUID, "cred-fallback", nil)
		if err != nil || rec["name"] != "My Provider" {
			t.Fatalf("%v %v", rec, err)
		}
	})
	t.Run("falls back to the returned name when the client sends only whitespace", func(t *testing.T) {
		rec, err := registerNamed(t, ti, mocks, googleAAGUID, "cred-whitespace-fallback", strp("   "))
		if err != nil || rec["name"] != "My Provider" {
			t.Fatalf("%v %v", rec, err)
		}
	})
	t.Run("keeps the client-provided name over the returned one, but still runs the hook", func(t *testing.T) {
		before := calls
		rec, err := registerNamed(t, ti, mocks, googleAAGUID, "cred-precedence", strp("Explicit Name"))
		if err != nil || rec["name"] != "Explicit Name" || calls == before {
			t.Fatalf("%v %v", rec, err)
		}
	})
}

// "passkey expirationTime per-request": upstream advances fake timers past the challenge
// lifetime between init and the request; here the expiry must be relative to the request.
func TestPasskeyExpirationTimePerRequest(t *testing.T) {
	latestVerification := func(t *testing.T, ti *instance) time.Time {
		rows, err := ti.ctx().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "verification"})
		if err != nil || len(rows) == 0 {
			t.Fatalf("%v %v", rows, err)
		}
		exp, _ := adapter.ToTime(rows[len(rows)-1]["expiresAt"])
		return exp
	}
	t.Run("should compute expirationTime per-request, not at init time", func(t *testing.T) {
		ti := newInstance(t, Options{})
		headers, _ := ti.signInWithTestUser()
		if _, _, err := ti.call("generatePasskeyRegistrationOptions", headers, nil, nil); err != nil {
			t.Fatal(err)
		}
		if exp := latestVerification(t, ti); !exp.After(time.Now()) || exp.After(time.Now().Add(5*time.Minute+time.Second)) {
			t.Fatalf("expiresAt %v", exp)
		}
	})
	t.Run("should compute expirationTime per-request for authentication options", func(t *testing.T) {
		ti := newInstance(t, Options{})
		if _, _, err := ti.call("generatePasskeyAuthenticationOptions", nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if exp := latestVerification(t, ti); !exp.After(time.Now()) {
			t.Fatalf("expiresAt %v", exp)
		}
	})
}
