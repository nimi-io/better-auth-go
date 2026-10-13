package deviceauthorization

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Port of packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts.

func gen(values ...string) func(context.Context) (string, error) {
	var mu sync.Mutex
	return func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(values) == 0 {
			return "unused", nil
		}
		v := values[0]
		values = values[1:]
		return v, nil
	}
}

func constGen(v string, calls *int) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		if calls != nil {
			*calls++
		}
		return v, nil
	}
}

func TestDeviceAuthorizationPluginInputValidation(t *testing.T) {
	t.Run("basic validation", func(t *testing.T) {
		o, err := ParseOptions(Options{})
		if err != nil {
			t.Fatal(err)
		}
		if o.DeviceCodeLength != 40 || o.ExpiresIn != "30m" || o.Interval != "5s" || o.UserCodeLength != 8 {
			t.Fatalf("unexpected defaults %+v", o)
		}
	})
	t.Run("should validate custom options", func(t *testing.T) {
		o, err := ParseOptions(Options{ExpiresIn: "1m", Interval: "2s", DeviceCodeLength: 50, UserCodeLength: 10})
		if err != nil {
			t.Fatal(err)
		}
		if o.DeviceCodeLength != 50 || o.ExpiresIn != "1m" || o.Interval != "2s" || o.UserCodeLength != 10 {
			t.Fatalf("unexpected options %+v", o)
		}
	})
	t.Run("should reject generated code lengths that exceed indexed columns", func(t *testing.T) {
		if _, err := ParseOptions(Options{DeviceCodeLength: 192}); err == nil {
			t.Fatal("expected deviceCodeLength 192 to be rejected")
		}
		if _, err := ParseOptions(Options{UserCodeLength: 192}); err == nil {
			t.Fatal("expected userCodeLength 192 to be rejected")
		}
	})
}

func TestUserCodeVerificationRateLimiting(t *testing.T) {
	env := newEnv(t, Options{}, envOptions{disableTestUser: true, mutate: func(c *betterauth.Config) {
		c.RateLimit = &betterauth.RateLimitConfig{Enabled: betterauth.Bool(true)}
	}})
	t.Run("returns 429 after five verification guesses", func(t *testing.T) {
		var statuses []int
		for attempt := 0; attempt < 6; attempt++ {
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:3000/api/auth/device?user_code=INVALID%d", attempt), nil)
			req.Header.Set("X-Forwarded-For", "192.0.2.42")
			statuses = append(statuses, env.handler(req).Code)
		}
		for i := 0; i < 5; i++ {
			if statuses[i] != 400 {
				t.Fatalf("statuses %v", statuses)
			}
		}
		if statuses[5] != 429 {
			t.Fatalf("statuses %v", statuses)
		}
	})
	t.Run("does not apply the verification limit to token polling", func(t *testing.T) {
		const ip = "192.0.2.43"
		req, _ := http.NewRequest("POST", "http://localhost:3000/api/auth/device/code", strings.NewReader(`{"client_id":"test-client"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		res := env.handler(req)
		if res.Code != 200 {
			t.Fatalf("device code: %d %s", res.Code, res.Body)
		}
		v, _ := jsonx.Parse(res.Body.Bytes())
		dc, _ := v.(*jsonx.Object).Get("device_code")
		for attempt := 0; attempt < 5; attempt++ {
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:3000/api/auth/device?user_code=INVALID%d", attempt), nil)
			req.Header.Set("X-Forwarded-For", ip)
			if c := env.handler(req).Code; c != 400 {
				t.Fatalf("verify status %d", c)
			}
		}
		for poll := 0; poll < 6; poll++ {
			body := fmt.Sprintf(`{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":%q,"client_id":"test-client"}`, dc)
			req, _ := http.NewRequest("POST", "http://localhost:3000/api/auth/device/token", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", ip)
			if c := env.handler(req).Code; c == 429 {
				t.Fatal("token polling was rate limited")
			}
		}
	})
}

func TestClientValidation(t *testing.T) {
	valid := map[string]bool{"valid-client-1": true, "valid-client-2": true}
	env := newEnv(t, Options{ValidateClient: func(_ context.Context, id string) (bool, error) { return valid[id], nil }})
	t.Run("should reject invalid client in device code request", func(t *testing.T) {
		_, err := env.call("deviceCode", betterauth.CallInput{Body: map[string]any{"client_id": "invalid-client"}})
		expectOAuthError(t, err, "invalid_client", "Invalid client ID")
	})
	t.Run("should accept valid client in device code request", func(t *testing.T) {
		if env.deviceCode(map[string]any{"client_id": "valid-client-1"})["device_code"] == nil {
			t.Fatal("missing device_code")
		}
	})
	t.Run("should reject invalid client in token request", func(t *testing.T) {
		dc := env.deviceCode(map[string]any{"client_id": "valid-client-1"})["device_code"].(string)
		_, err := env.call("deviceToken", betterauth.CallInput{Body: tokenBody(dc, "invalid-client")})
		expectOAuthError(t, err, "invalid_grant", "Invalid client ID")
	})
	t.Run("should reject mismatched client_id in token request", func(t *testing.T) {
		dc := env.deviceCode(map[string]any{"client_id": "valid-client-1"})["device_code"].(string)
		_, err := env.call("deviceToken", betterauth.CallInput{Body: tokenBody(dc, "valid-client-2")})
		expectOAuthError(t, err, "invalid_grant", "Client ID mismatch")
	})
}

func TestGrantRequestValidation(t *testing.T) {
	t.Run("delegates grant-field validation errors to the configured grant", func(t *testing.T) {
		grant := &Grant{
			RequestSchemaFields: []validate.Field{validate.F("grant_value", validate.String())},
			RequestErrorCodes:   []string{"grant_invalid"},
			OnRequestValidationError: func(issues []validate.Issue) error {
				for _, is := range issues {
					if len(is.Path) == 0 || is.Path[0] != "grant_value" {
						return nil
					}
				}
				return betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "grant_invalid", "error_description", "Invalid grant request"))
			},
		}
		env := newEnv(t, Options{Grant: grant})
		req, _ := http.NewRequest("POST", "http://localhost:3000/api/auth/device/code", strings.NewReader(`{"client_id":"client","grant_value":42}`))
		req.Header.Set("Content-Type", "application/json")
		res := env.handler(req)
		if res.Code != 400 {
			t.Fatalf("status %d", res.Code)
		}
		if !strings.Contains(res.Body.String(), `"error":"grant_invalid"`) || !strings.Contains(res.Body.String(), `"error_description":"Invalid grant request"`) {
			t.Fatalf("body %s", res.Body)
		}
	})
	t.Run("runs before the application callback", func(t *testing.T) {
		authorizeCalls, callbackCalls := 0, 0
		grant := &Grant{AuthorizeRequest: func(*betterauth.EndpointContext, map[string]any) (*GrantAuthorization, error) {
			authorizeCalls++
			return nil, errors.New("rejected")
		}}
		env := newEnv(t, Options{Grant: grant, OnDeviceAuthRequest: func(context.Context, string, *string) error {
			callbackCalls++
			return nil
		}})
		_, err := env.auth.API.Call(context.Background(), "deviceCode", betterauth.CallInput{Body: map[string]any{"client_id": "client"}})
		if err == nil || !strings.Contains(err.Error(), "rejected") {
			t.Fatalf("expected rejection, got %v", err)
		}
		if authorizeCalls != 1 || callbackCalls != 0 {
			t.Fatalf("authorize %d callback %d", authorizeCalls, callbackCalls)
		}
	})
}

func TestGrantVerificationContext(t *testing.T) {
	t.Run("does not let grant context overwrite host-owned response fields", func(t *testing.T) {
		grant := &Grant{GetVerificationContext: func(adapter.Record) map[string]any {
			return map[string]any{"user_code": "grant-user-code", "status": "grant-status", "client_id": "grant-client",
				"scope": "grant-scope", "grant_field": "grant-value"}
		}}
		env := newEnv(t, Options{Grant: grant, ValidateClient: func(context.Context, string) (bool, error) { return true, nil }})
		headers, _ := env.signInWithTestUser()
		code := env.deviceCode(map[string]any{"client_id": "client", "scope": "read"})
		res := env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": code["user_code"]}, Headers: headers})
		want := map[string]any{"user_code": code["user_code"], "status": "pending", "client_id": "client", "scope": "read", "grant_field": "grant-value"}
		for k, v := range want {
			if res[k] != v {
				t.Fatalf("%s = %v, want %v (%v)", k, res[k], v, res)
			}
		}
	})
}

func TestDeviceAuthorizationFlow(t *testing.T) {
	env := newEnv(t, Options{ExpiresIn: "5min", Interval: "2s"})
	approve := func(userCode string, headers http.Header) (map[string]any, *betterauth.APIError) {
		return env.call("deviceApprove", betterauth.CallInput{Body: map[string]any{"userCode": userCode}, Headers: headers})
	}
	deny := func(userCode string, headers http.Header) (map[string]any, *betterauth.APIError) {
		return env.call("deviceDeny", betterauth.CallInput{Body: map[string]any{"userCode": userCode}, Headers: headers})
	}
	verify := func(userCode string, headers http.Header) map[string]any {
		return env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": userCode}, Headers: headers})
	}
	token := func(dc string) (map[string]any, *betterauth.APIError) {
		return env.call("deviceToken", betterauth.CallInput{Body: tokenBody(dc, "test-client")})
	}
	newCode := func(body map[string]any) (string, string) {
		if body == nil {
			body = map[string]any{"client_id": "test-client"}
		}
		r := env.deviceCode(body)
		return r["device_code"].(string), r["user_code"].(string)
	}

	t.Run("device code request", func(t *testing.T) {
		t.Run("should generate device and user codes", func(t *testing.T) {
			r := env.deviceCode(map[string]any{"client_id": "test-client"})
			uc, _ := r["user_code"].(string)
			if r["device_code"] == nil || uc == "" {
				t.Fatalf("missing codes %v", r)
			}
			vu, _ := r["verification_uri"].(string)
			vc, _ := r["verification_uri_complete"].(string)
			if !strings.Contains(vu, "/device") || !strings.Contains(vc, "/device") || !strings.Contains(vc, "user_code="+uc) {
				t.Fatalf("unexpected URIs %v", r)
			}
			if r["expires_in"] != 300.0 || r["interval"] != 2.0 {
				t.Fatalf("expires_in %v interval %v", r["expires_in"], r["interval"])
			}
			if !regexp.MustCompile(`^[A-Z0-9]{8}$`).MatchString(uc) {
				t.Fatalf("user code %q", uc)
			}
		})
		t.Run("should support custom client ID and scope", func(t *testing.T) {
			r := env.deviceCode(map[string]any{"client_id": "test-client", "scope": "read write"})
			if r["device_code"] == nil || r["user_code"] == nil {
				t.Fatal("missing codes")
			}
		})
	})

	t.Run("device token polling", func(t *testing.T) {
		t.Run("should return authorization_pending when not approved", func(t *testing.T) {
			dc, _ := newCode(nil)
			_, err := token(dc)
			expectOAuthError(t, err, "authorization_pending", "Authorization pending")
		})
		t.Run("should return expired_token for expired device codes", func(t *testing.T) {
			// Upstream advances fake timers by 301s; Go moves the stored expiry instead.
			dc, _ := newCode(nil)
			env.updateDeviceCode(dc, adapter.Record{"expiresAt": time.Now().Add(-time.Second)})
			_, err := token(dc)
			expectOAuthError(t, err, "expired_token", "Device code has expired")
		})
		t.Run("should return error for invalid device code", func(t *testing.T) {
			_, err := token("invalid-code")
			expectOAuthError(t, err, "invalid_grant", "Invalid device code")
		})
	})

	t.Run("device verification", func(t *testing.T) {
		t.Run("accepts lowercase user codes for verification, approval, and denial", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			lower := func() string { _, uc := newCode(nil); return strings.ToLower(uc) }
			if verify(lower(), headers)["status"] != "pending" {
				t.Fatal("expected pending")
			}
			uc := lower()
			verify(uc, headers)
			if r, err := approve(uc, headers); err != nil || r["success"] != true {
				t.Fatalf("approve: %v %v", r, errBody(err))
			}
			uc = lower()
			verify(uc, headers)
			if r, err := deny(uc, headers); err != nil || r["success"] != true {
				t.Fatalf("deny: %v %v", r, errBody(err))
			}
		})
		t.Run("ignores readability punctuation and whitespace for default user codes", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			formatted := func() string {
				_, uc := newCode(nil)
				return " \t" + uc[:2] + "-" + uc[2:4] + "." + uc[4:] + " \n"
			}
			if verify(formatted(), headers)["status"] != "pending" {
				t.Fatal("expected pending")
			}
			uc := formatted()
			verify(uc, headers)
			if r, err := approve(uc, headers); err != nil || r["success"] != true {
				t.Fatalf("approve: %v %v", r, errBody(err))
			}
			uc = formatted()
			verify(uc, headers)
			if r, err := deny(uc, headers); err != nil || r["success"] != true {
				t.Fatalf("deny: %v %v", r, errBody(err))
			}
		})
		t.Run("only returns authorization context to the authenticated owner", func(t *testing.T) {
			_, uc := newCode(map[string]any{"client_id": "test-client", "scope": "read write"})
			anon := verify(uc, nil)
			if anon["user_code"] != uc || anon["status"] != "pending" {
				t.Fatalf("anonymous %v", anon)
			}
			for _, k := range []string{"client_id", "scope", "resource"} {
				if _, ok := anon[k]; ok {
					t.Fatalf("anonymous response exposes %s", k)
				}
			}
			headers, _ := env.signInWithTestUser()
			r := verify(uc, headers)
			if _, ok := r["error"]; ok {
				t.Fatal("unexpected error")
			}
			if r["user_code"] != uc || r["status"] != "pending" || r["client_id"] != "test-client" || r["scope"] != "read write" {
				t.Fatalf("owner response %v", r)
			}
		})
		t.Run("should handle invalid user code", func(t *testing.T) {
			_, err := env.call("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": "INVALID"}})
			expectOAuthError(t, err, "invalid_request", "Invalid user code")
		})
	})

	t.Run("device approval flow", func(t *testing.T) {
		t.Run("sends no-store on the device code response", func(t *testing.T) {
			res, err := env.auth.API.Call(context.Background(), "deviceCode", betterauth.CallInput{Body: map[string]any{"client_id": "test-client"}})
			if err != nil {
				t.Fatal(err)
			}
			if res.Headers.Get("Cache-Control") != "no-store" || res.Headers.Get("Pragma") != "no-cache" {
				t.Fatalf("headers %v", res.Headers)
			}
		})
		t.Run("sends no-store on the device token response", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			dc, uc := newCode(nil)
			verify(uc, headers)
			if _, err := approve(uc, headers); err != nil {
				t.Fatal(errBody(err))
			}
			res, err := env.auth.API.Call(context.Background(), "deviceToken", betterauth.CallInput{Body: tokenBody(dc, "test-client")})
			if err != nil {
				t.Fatal(err)
			}
			if res.Headers.Get("Cache-Control") != "no-store" || res.Headers.Get("Pragma") != "no-cache" {
				t.Fatalf("headers %v", res.Headers)
			}
		})
		t.Run("should approve device and create session", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			dc, uc := newCode(nil)
			verify(uc, headers)
			if r, err := approve(uc, headers); err != nil || r["success"] != true {
				t.Fatalf("approve %v %v", r, errBody(err))
			}
			r, err := token(dc)
			if err != nil {
				t.Fatal(errBody(err))
			}
			if r["access_token"] == nil || r["token_type"] != "Bearer" || r["expires_in"].(float64) <= 0 {
				t.Fatalf("token response %v", r)
			}
			if _, ok := r["scope"]; !ok {
				t.Fatal("scope missing")
			}
		})
		t.Run("should deny device authorization", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			dc, uc := newCode(nil)
			verify(uc, headers)
			if r, err := deny(uc, headers); err != nil || r["success"] != true {
				t.Fatalf("deny %v %v", r, errBody(err))
			}
			_, err := token(dc)
			expectOAuthError(t, err, "access_denied", "Access denied")
		})
		t.Run("should require authentication for approval", func(t *testing.T) {
			_, uc := newCode(nil)
			_, err := approve(uc, http.Header{})
			expectOAuthError(t, err, "unauthorized", "Authentication required")
		})
		t.Run("should enforce rate limiting with slow_down error", func(t *testing.T) {
			dc, _ := newCode(nil)
			_, _ = token(dc)
			_, err := token(dc)
			expectOAuthError(t, err, "slow_down", "Polling too frequently")
		})
	})

	t.Run("edge cases", func(t *testing.T) {
		t.Run("should not allow approving already processed device code", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			_, uc := newCode(nil)
			verify(uc, headers)
			if _, err := approve(uc, headers); err != nil {
				t.Fatal(errBody(err))
			}
			_, err := approve(uc, headers)
			expectOAuthError(t, err, "invalid_request", "Device code already processed")
		})
		t.Run("should handle user code without dashes", func(t *testing.T) {
			_, uc := newCode(nil)
			if verify(strings.ReplaceAll(uc, "-", ""), nil)["status"] != "pending" {
				t.Fatal("expected pending")
			}
		})
		t.Run("should store and use scope from device code request", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			dc, uc := newCode(map[string]any{"client_id": "test-client", "scope": "read write profile"})
			verify(uc, headers)
			if _, err := approve(uc, headers); err != nil {
				t.Fatal(errBody(err))
			}
			r, err := token(dc)
			if err != nil {
				t.Fatal(errBody(err))
			}
			if r["scope"] != "read write profile" {
				t.Fatalf("scope %v", r["scope"])
			}
		})
		t.Run("should require authentication for deny", func(t *testing.T) {
			_, uc := newCode(nil)
			_, err := deny(uc, http.Header{})
			expectOAuthError(t, err, "unauthorized", "Authentication required")
		})
		t.Run("should allow first user to approve but prevent re-approval", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			_, uc := newCode(nil)
			verify(uc, headers)
			if r, err := approve(uc, headers); err != nil || r["success"] != true {
				t.Fatalf("approve %v %v", r, errBody(err))
			}
			rec := env.findDeviceCode("userCode", strings.ReplaceAll(uc, "-", ""))
			if rec["status"] != "approved" || rec["userId"] == nil {
				t.Fatalf("record %v", rec)
			}
			_, err := approve(uc, headers)
			expectOAuthError(t, err, "invalid_request", "Device code already processed")
		})
	})

	t.Run("concurrent token redemption", func(t *testing.T) {
		t.Run("should redeem an approved device code at most once under concurrent polling", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			dc, uc := newCode(nil)
			verify(uc, headers)
			if _, err := approve(uc, headers); err != nil {
				t.Fatal(errBody(err))
			}
			var wg sync.WaitGroup
			results := make([]map[string]any, 2)
			for i := range results {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					res, err := env.auth.API.Call(context.Background(), "deviceToken", betterauth.CallInput{Body: tokenBody(dc, "test-client")})
					if err == nil {
						var m map[string]any
						_ = res.Decode(&m)
						results[i] = m
					}
				}(i)
			}
			wg.Wait()
			successes := 0
			for _, r := range results {
				if r != nil && r["access_token"] != nil {
					successes++
				}
			}
			if successes != 1 {
				t.Fatalf("successes %d", successes)
			}
			if rec := env.findDeviceCode("deviceCode", dc); rec != nil {
				t.Fatalf("row still present %v", rec)
			}
			_, err := token(dc)
			expectOAuthError(t, err, "invalid_grant", "")
		})
		t.Run("should preserve an approved code when user lookup fails before session issuance", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			dc, uc := newCode(nil)
			verify(uc, headers)
			if _, err := approve(uc, headers); err != nil {
				t.Fatal(errBody(err))
			}
			env.updateDeviceCode(dc, adapter.Record{"userId": "missing-user"})
			_, err := token(dc)
			expectOAuthError(t, err, "server_error", "")
			if rec := env.findDeviceCode("deviceCode", dc); rec == nil || rec["status"] != "approved" {
				t.Fatalf("record %v", rec)
			}
		})
		t.Run("should burn an expired approved device code instead of issuing a token", func(t *testing.T) {
			headers, _ := env.signInWithTestUser()
			dc, uc := newCode(nil)
			verify(uc, headers)
			if _, err := approve(uc, headers); err != nil {
				t.Fatal(errBody(err))
			}
			env.updateDeviceCode(dc, adapter.Record{"expiresAt": time.Now().Add(-time.Second)})
			_, err := token(dc)
			expectOAuthError(t, err, "expired_token", "")
			if rec := env.findDeviceCode("deviceCode", dc); rec != nil {
				t.Fatalf("row still present %v", rec)
			}
		})
	})
}

const (
	attackerEmail    = "attacker@example.test"
	attackerPassword = "attacker-password-123"
)

func TestDeviceAuthorizationOwnershipGate(t *testing.T) {
	opts := Options{ExpiresIn: "5min", Interval: "2s"}
	withAttacker := func(t *testing.T, o Options) (*testEnv, http.Header, map[string]any) {
		env := newEnv(t, o)
		env.signUp(attackerEmail, attackerPassword, "attacker")
		h, u := env.signIn(attackerEmail, attackerPassword)
		return env, h, u
	}
	t.Run("rejects approve from a session that did not claim the pending code", func(t *testing.T) {
		env, attackerHeaders, attacker := withAttacker(t, opts)
		r := env.deviceCode(map[string]any{"client_id": "test-client"})
		dc, uc := r["device_code"].(string), r["user_code"].(string)
		if dc == "" || uc == "" {
			t.Fatal("missing codes")
		}
		_, err := env.call("deviceApprove", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: attackerHeaders})
		expectOAuthError(t, err, "invalid_request", "")
		rec := env.findDeviceCode("userCode", uc)
		if rec["userId"] == attacker["id"] || rec["status"] != "pending" {
			t.Fatalf("record %v", rec)
		}
		_, err = env.call("deviceToken", betterauth.CallInput{Body: tokenBody(dc, "test-client")})
		expectOAuthError(t, err, "authorization_pending", "")
	})
	t.Run("rejects deny from a session that did not claim the pending code", func(t *testing.T) {
		env, attackerHeaders, attacker := withAttacker(t, opts)
		uc := env.deviceCode(map[string]any{"client_id": "test-client"})["user_code"].(string)
		_, err := env.call("deviceDeny", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: attackerHeaders})
		expectOAuthError(t, err, "invalid_request", "")
		rec := env.findDeviceCode("userCode", uc)
		if rec["userId"] == attacker["id"] || rec["status"] != "pending" {
			t.Fatalf("record %v", rec)
		}
	})
	t.Run("allows approve when the same session called verify first", func(t *testing.T) {
		env := newEnv(t, opts)
		headers, _ := env.signInWithTestUser()
		uc := env.deviceCode(map[string]any{"client_id": "test-client"})["user_code"].(string)
		env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: headers})
		if r := env.mustCall("deviceApprove", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: headers}); r["success"] != true {
			t.Fatalf("approve %v", r)
		}
	})
	t.Run("does not expose or authorize a code claimed by a different user", func(t *testing.T) {
		env, attackerHeaders, _ := withAttacker(t, opts)
		claimerHeaders, _ := env.signInWithTestUser()
		uc := env.deviceCode(map[string]any{"client_id": "test-client", "scope": "read write"})["user_code"].(string)
		env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: claimerHeaders})
		v := env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: attackerHeaders})
		for _, k := range []string{"client_id", "scope", "resource"} {
			if _, ok := v[k]; ok {
				t.Fatalf("attacker sees %s", k)
			}
		}
		for _, key := range []string{"deviceApprove", "deviceDeny"} {
			_, err := env.call(key, betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: attackerHeaders})
			expectOAuthError(t, err, "access_denied", "")
			if err.Status != "FORBIDDEN" {
				t.Fatalf("status %s", err.Status)
			}
		}
	})
	t.Run("rejects approve from a different user if the code was generated for a different user_id", func(t *testing.T) {
		env, attackerHeaders, _ := withAttacker(t, opts)
		_, user := env.signInWithTestUser()
		uc := env.deviceCode(map[string]any{"client_id": "test-client", "user_id": user["id"]})["user_code"].(string)
		for _, key := range []string{"deviceApprove", "deviceDeny"} {
			_, err := env.call(key, betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: attackerHeaders})
			expectOAuthError(t, err, "access_denied", "")
			if err.Status != "FORBIDDEN" {
				t.Fatalf("status %s", err.Status)
			}
		}
	})
	t.Run("omits empty form base parameters regardless of order", func(t *testing.T) {
		env, attackerHeaders, _ := withAttacker(t, Options{})
		ownerHeaders, user := env.signInWithTestUser()
		for _, emptyFirst := range []bool{true, false} {
			form := url.Values{}
			var parts []string
			for _, kv := range [][2]string{{"client_id", "test-client"}, {"scope", "read write"}, {"user_id", user["id"].(string)}} {
				values := []string{kv[1], ""}
				if emptyFirst {
					values = []string{"", kv[1]}
				}
				for _, v := range values {
					form.Add(kv[0], v)
					parts = append(parts, url.QueryEscape(kv[0])+"="+url.QueryEscape(v))
				}
			}
			req, _ := http.NewRequest("POST", "http://localhost:3000/api/auth/device/code", strings.NewReader(strings.Join(parts, "&")))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res := env.handler(req)
			if res.Code != 200 {
				t.Fatalf("status %d %s", res.Code, res.Body)
			}
			v, _ := jsonx.Parse(res.Body.Bytes())
			uc, _ := v.(*jsonx.Object).Get("user_code")
			ver := env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: ownerHeaders})
			if ver["client_id"] != "test-client" || ver["scope"] != "read write" {
				t.Fatalf("verification %v", ver)
			}
			_, err := env.call("deviceApprove", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: attackerHeaders})
			expectOAuthError(t, err, "access_denied", "")
			if err.Status != "FORBIDDEN" {
				t.Fatalf("status %s", err.Status)
			}
		}
	})
	t.Run("allows approve when the pre-bound user matches the current user", func(t *testing.T) {
		env := newEnv(t, opts)
		headers, user := env.signInWithTestUser()
		uc := env.deviceCode(map[string]any{"client_id": "test-client", "user_id": user["id"]})["user_code"].(string)
		if r := env.mustCall("deviceApprove", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: headers}); r["success"] != true {
			t.Fatalf("approve %v", r)
		}
	})
	t.Run("allows deny when the pre-bound user matches the current user", func(t *testing.T) {
		env := newEnv(t, opts)
		headers, user := env.signInWithTestUser()
		uc := env.deviceCode(map[string]any{"client_id": "test-client", "user_id": user["id"]})["user_code"].(string)
		if r := env.mustCall("deviceDeny", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: headers}); r["success"] != true {
			t.Fatalf("deny %v", r)
		}
	})
	t.Run("treats an empty user_id as omitted and leaves the code unbound", func(t *testing.T) {
		env := newEnv(t, opts)
		headers, _ := env.signInWithTestUser()
		uc := env.deviceCode(map[string]any{"client_id": "test-client", "user_id": ""})["user_code"].(string)
		env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: headers})
		if r := env.mustCall("deviceApprove", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: headers}); r["success"] != true {
			t.Fatalf("approve %v", r)
		}
	})
	t.Run("does not overwrite a device code claimed after verify reads it", func(t *testing.T) {
		env := newEnv(t, opts)
		env.signUp("concurrent-owner@example.test", "concurrent-owner-password-123", "concurrent owner")
		_, owner := env.signIn("concurrent-owner@example.test", "concurrent-owner-password-123")
		env.signUp("racer@example.test", "racer-password-123", "racer")
		racerHeaders, racer := env.signIn("racer@example.test", "racer-password-123")
		uc := env.deviceCode(map[string]any{"client_id": "test-client"})["user_code"].(string)
		simulate := true
		env.db.incrementOne = func(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
			if simulate && in.Model == "deviceCode" && in.Set["userId"] != nil {
				simulate = false
				for _, w := range in.Where {
					if w.Field == "id" {
						if _, err := env.base.Update(ctx, "deviceCode", []adapter.Where{{Field: "id", Value: w.Value}}, adapter.Record{"userId": owner["id"]}); err != nil {
							return nil, err
						}
					}
				}
			}
			return env.base.IncrementOne(ctx, in)
		}
		env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: racerHeaders})
		rec := env.findDeviceCode("userCode", uc)
		if rec["userId"] != owner["id"] || rec["userId"] == racer["id"] || rec["status"] != "pending" {
			t.Fatalf("record %v", rec)
		}
	})
}

type sqlServerError struct {
	Code   string
	Number int
}

func (e *sqlServerError) Error() string { return "SQL Server request failed" }

type prismaError struct{ Code string }

func (e *prismaError) Error() string { return "Prisma collision" }

func TestDeviceAuthorizationWithCustomOptions(t *testing.T) {
	t.Run("should correctly store interval as milliseconds in database", func(t *testing.T) {
		env := newEnv(t, Options{Interval: "5s"})
		r := env.deviceCode(map[string]any{"client_id": "test-client"})
		if r["interval"] != 5.0 {
			t.Fatalf("interval %v", r["interval"])
		}
		rec := env.findDeviceCode("deviceCode", r["device_code"].(string))
		if n, ok := toFloat(rec["pollingInterval"]); !ok || n != 5000 {
			t.Fatalf("pollingInterval %v (%T)", rec["pollingInterval"], rec["pollingInterval"])
		}
	})
	t.Run("should use custom code generators", func(t *testing.T) {
		env := newEnv(t, Options{GenerateDeviceCode: constGen("custom-device-code-12345", nil), GenerateUserCode: constGen("CUSTOM12", nil)})
		r := env.deviceCode(map[string]any{"client_id": "test-client"})
		if r["device_code"] != "custom-device-code-12345" || r["user_code"] != "CUSTOM12" {
			t.Fatalf("codes %v", r)
		}
	})
	t.Run("should regenerate codes when custom generators collide with active values", func(t *testing.T) {
		env := newEnv(t, Options{
			GenerateDeviceCode: gen("device-code-1", "device-code-1", "device-code-2", "device-code-3", "device-code-4"),
			GenerateUserCode:   gen("USERCODE1", "USERCODE2", "USERCODE3", "USERCODE3", "USERCODE4"),
		})
		first := env.deviceCode(map[string]any{"client_id": "test-client"})
		second := env.deviceCode(map[string]any{"client_id": "test-client"})
		third := env.deviceCode(map[string]any{"client_id": "test-client"})
		if second["device_code"] != "device-code-2" || second["user_code"] != "USERCODE3" ||
			third["device_code"] != "device-code-4" || third["user_code"] != "USERCODE4" {
			t.Fatalf("second %v third %v", second, third)
		}
		if second["device_code"] == first["device_code"] || second["user_code"] == first["user_code"] ||
			third["device_code"] == first["device_code"] || third["user_code"] == first["user_code"] ||
			third["device_code"] == second["device_code"] || third["user_code"] == second["user_code"] {
			t.Fatal("codes collide")
		}
	})
	collisionCase := func(t *testing.T, collision error) {
		env := newEnv(t, Options{GenerateDeviceCode: gen("device-code-1", "device-code-2"), GenerateUserCode: gen("USERCODE1", "USERCODE2")})
		failed := false
		env.db.create = func(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
			if in.Model == "deviceCode" && !failed {
				failed = true
				return nil, collision
			}
			return env.base.Create(ctx, in)
		}
		r := env.deviceCode(map[string]any{"client_id": "test-client"})
		if r["device_code"] != "device-code-2" || r["user_code"] != "USERCODE2" {
			t.Fatalf("codes %v", r)
		}
	}
	t.Run("should retry Prisma-style unique constraint errors during issuance", func(t *testing.T) {
		collisionCase(t, &prismaError{Code: "P2002"})
	})
	t.Run("should inspect every database error identifier for unique violations", func(t *testing.T) {
		collisionCase(t, &sqlServerError{Code: "EREQUEST", Number: 2601})
	})
	t.Run("should return a controlled server error when generators cannot produce unique codes", func(t *testing.T) {
		deviceCalls, userCalls := 0, 0
		env := newEnv(t, Options{GenerateDeviceCode: constGen("device-code", &deviceCalls), GenerateUserCode: constGen("USERCODE", &userCalls)})
		env.deviceCode(map[string]any{"client_id": "test-client"})
		_, err := env.call("deviceCode", betterauth.CallInput{Body: map[string]any{"client_id": "test-client"}})
		expectOAuthError(t, err, "server_error", "Failed to generate a unique device code")
		if deviceCalls != 4 || userCalls != 4 {
			t.Fatalf("calls %d %d", deviceCalls, userCalls)
		}
	})
	t.Run("preserves exact matching for custom user codes outside the default alphabet", func(t *testing.T) {
		env := newEnv(t, Options{GenerateUserCode: gen("custom/user-code_01", "custom:user-code_02", "custom.user-code_03")})
		headers, _ := env.signInWithTestUser()
		uc := env.deviceCode(map[string]any{"client_id": "test-client"})["user_code"]
		if r := env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: headers}); r["status"] != "pending" {
			t.Fatalf("verify %v", r)
		}
		for _, key := range []string{"deviceApprove", "deviceDeny"} {
			uc := env.deviceCode(map[string]any{"client_id": "test-client"})["user_code"]
			env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": uc}, Headers: headers})
			if r := env.mustCall(key, betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: headers}); r["success"] != true {
				t.Fatalf("%s %v", key, r)
			}
		}
	})
	t.Run("preserves custom user-code casing with case-insensitive adapters", func(t *testing.T) {
		const custom = "Custom/User-Code"
		env := newEnv(t, Options{GenerateUserCode: constGen(custom, nil)})
		headers, _ := env.signInWithTestUser()
		env.deviceCode(map[string]any{"client_id": "test-client"})
		stored := env.findDeviceCode("userCode", custom)
		if stored == nil {
			t.Fatal("device code was not stored")
		}
		env.db.findOne = func(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
			if in.Model == "deviceCode" {
				c := adapter.Record{}
				for k, v := range stored {
					c[k] = v
				}
				return c, nil
			}
			return env.base.FindOne(ctx, in)
		}
		_, err := env.call("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": strings.ToLower(custom)}, Headers: headers})
		expectOAuthError(t, err, "invalid_request", "")
	})
	for _, c := range []struct {
		label string
		opts  Options
	}{
		{"device", Options{GenerateDeviceCode: constGen(strings.Repeat("d", 192), nil), GenerateUserCode: constGen("USERCODE", nil)}},
		{"user", Options{GenerateDeviceCode: constGen("device-code", nil), GenerateUserCode: constGen(strings.Repeat("u", 192), nil)}},
	} {
		t.Run("should reject an oversized custom "+c.label+" code", func(t *testing.T) {
			env := newEnv(t, c.opts)
			_, err := env.call("deviceCode", betterauth.CallInput{Body: map[string]any{"client_id": "test-client"}})
			expectOAuthError(t, err, "invalid_request", "Generated "+c.label+" code must be at most 191 characters")
		})
	}
	// "should reject a non-string custom %s code" is not ported: Go generators return a
	// string, so a non-string code cannot be produced.
	t.Run("should count Unicode code points when validating custom codes", func(t *testing.T) {
		code := strings.Repeat("🦋", 191)
		env := newEnv(t, Options{GenerateDeviceCode: constGen(code, nil)})
		if r := env.deviceCode(map[string]any{"client_id": "test-client"}); r["device_code"] != code {
			t.Fatal("unexpected device code")
		}
	})
	t.Run("should respect custom expiration time", func(t *testing.T) {
		env := newEnv(t, Options{ExpiresIn: "1min"})
		if r := env.deviceCode(map[string]any{"client_id": "test-client"}); r["expires_in"] != 60.0 {
			t.Fatalf("expires_in %v", r["expires_in"])
		}
	})
}

func TestVerificationURIOption(t *testing.T) {
	t.Run("should validate verificationUri option at plugin initialization", func(t *testing.T) {
		// Upstream rejects a non-string verificationUri; in Go the option is typed. Invalid
		// options still fail at initialization:
		if _, err := betterauth.New(betterauth.Config{Secret: "test-secret-that-is-long-enough-for-tests-1234567890",
			Logger: betterauth.NopLogger{}, Plugins: []*betterauth.Plugin{New(Options{ExpiresIn: "soon"})}}); err == nil {
			t.Fatal("expected invalid options to fail")
		}
	})
	code := func(t *testing.T, o Options) map[string]any {
		return newEnv(t, o).deviceCode(map[string]any{"client_id": "test-client"})
	}
	t.Run("should return default /device verification URIs when not configured", func(t *testing.T) {
		r := code(t, Options{})
		vu, vc := r["verification_uri"].(string), r["verification_uri_complete"].(string)
		if vu != "http://localhost:3000/device" || !strings.Contains(vc, "/device") || !strings.Contains(vc, "user_code="+r["user_code"].(string)) {
			t.Fatalf("URIs %v", r)
		}
	})
	t.Run("should use custom relative path for verificationUri", func(t *testing.T) {
		r := code(t, Options{VerificationURI: "/auth/device-verify"})
		vu, vc := r["verification_uri"].(string), r["verification_uri_complete"].(string)
		if !strings.Contains(vu, "/auth/device-verify") || !strings.Contains(vc, "/auth/device-verify") || !strings.Contains(vc, "user_code="+r["user_code"].(string)) {
			t.Fatalf("URIs %v", r)
		}
	})
	t.Run("should use absolute URL for verificationUri", func(t *testing.T) {
		r := code(t, Options{VerificationURI: "https://myapp.com/device"})
		if r["verification_uri"] != "https://myapp.com/device" || r["verification_uri_complete"] != "https://myapp.com/device?user_code="+r["user_code"].(string) {
			t.Fatalf("URIs %v", r)
		}
	})
	t.Run("should properly encode user_code in verification_uri_complete", func(t *testing.T) {
		r := code(t, Options{VerificationURI: "/device", GenerateUserCode: constGen("ABC-123", nil)})
		if !strings.Contains(r["verification_uri_complete"].(string), "user_code=ABC-123") {
			t.Fatalf("URIs %v", r)
		}
	})
	t.Run("should support verificationUri with existing query parameters", func(t *testing.T) {
		r := code(t, Options{VerificationURI: "/device?lang=en"})
		vu, vc := r["verification_uri"].(string), r["verification_uri_complete"].(string)
		if !strings.Contains(vu, "lang=en") || !strings.Contains(vc, "lang=en") || !strings.Contains(vc, "user_code="+r["user_code"].(string)) {
			t.Fatalf("URIs %v", r)
		}
	})
}
