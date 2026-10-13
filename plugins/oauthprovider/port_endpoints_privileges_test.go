package oauthprovider

import (
	"net/http"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

// rgPrivSpy mimics vi.fn for clientPrivileges.
type rgPrivSpy struct {
	mu      sync.Mutex
	actions []string
	allowed string
}

func (s *rgPrivSpy) fn(c PrivilegeContext) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actions = append(s.actions, c.Action)
	return c.User != nil && c.User.Email == s.allowed, nil
}

func (s *rgPrivSpy) clear() { s.mu.Lock(); s.actions = nil; s.mu.Unlock() }

func (s *rgPrivSpy) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.actions...)
}

func (s *rgPrivSpy) expectCalls(t *testing.T, n int) {
	t.Helper()
	if got := s.calls(); len(got) != n {
		t.Fatalf("expected clientPrivileges called %d times, got %d (%v)", n, len(got), got)
	}
}

func (s *rgPrivSpy) expectCalledWith(t *testing.T, action string) {
	t.Helper()
	for _, a := range s.calls() {
		if a == action {
			return
		}
	}
	t.Fatalf("expected clientPrivileges called with action %q, got %v", action, s.calls())
}

// ---- endpoints-privileges.test.ts ----

func TestRg_OauthClientPrivileges(t *testing.T) {
	providerID := "test"
	redirectURI := "https://rp.example.com/api/auth/oauth2/callback/" + providerID
	allowedEmail, forbiddenEmail, pw := "allowed@test.com", "forbidden@test.com", "test123456"
	spy := &rgPrivSpy{allowed: allowedEmail}
	env := newEnv(t, Options{
		Scopes:           []string{"openid", "profile", "email", "offline_access", "m2m:read"},
		ClientReference:  func(UserSessionContext) (string, error) { return "oauth-client-test", nil },
		ClientPrivileges: spy.fn,
	})
	env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": allowedEmail, "password": pw, "name": "allowed user"}})
	env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": forbiddenEmail, "password": pw, "name": "forbidden user"}})
	allowedHeaders := env.signIn(allowedEmail, pw)
	forbiddenHeaders := env.signIn(forbiddenEmail, pw)
	unauthed := rgClient{env, http.Header{}}
	allowed := rgClient{env, allowedHeaders}
	forbidden := rgClient{env, forbiddenHeaders}
	var oauthClient map[string]any

	run := func(name string, f func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			spy.clear()
			f(t)
		})
	}

	run("should not create client with unauthenticated session", func(t *testing.T) {
		r := unauthed.createClient(rgMerge(rgUiClientInput, map[string]any{"redirect_uris": []any{redirectURI}}))
		rgErr(t, r, 401)
	})

	run("should not create client with forbidden user", func(t *testing.T) {
		r := forbidden.createClient(rgMerge(rgUiClientInput, map[string]any{"redirect_uris": []any{redirectURI}}))
		rgErr(t, r, 401)
		spy.expectCalls(t, 1)
	})

	run("should create client with allowed user", func(t *testing.T) {
		r := allowed.createClient(rgMerge(rgUiClientInput, map[string]any{"redirect_uris": []any{redirectURI}}))
		rgExpectDefined(t, r.m(), "client_id", "reference_id", "client_secret", "client_id_issued_at")
		rgExpectUndefined(t, r.m(), "user_id")
		spy.expectCalls(t, 1)
	})

	run("should not create client with forbidden user via admin api", func(t *testing.T) {
		_, err := rgCall(env, "adminCreateOAuthClient", betterauth.CallInput{Headers: forbiddenHeaders,
			Body: rgMerge(rgUiClientInput, map[string]any{"redirect_uris": []any{redirectURI}, "skip_consent": true})})
		rgExpectStatus(t, err, "UNAUTHORIZED", 401)
		spy.expectCalls(t, 1)
	})

	run("should create client with allowed user via admin api", func(t *testing.T) {
		admin := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: allowedHeaders,
			Body: rgMerge(rgUiClientInput, map[string]any{"redirect_uris": []any{redirectURI}})})
		rgExpectDefined(t, admin, "client_id", "reference_id", "client_secret", "client_id_issued_at")
		rgExpectUndefined(t, admin, "user_id")
		c := allowed.getClient(admin["client_id"].(string))
		rgExpectDefined(t, c.m(), "client_id", "reference_id", "client_id_issued_at")
		rgExpectUndefined(t, c.m(), "user_id", "client_secret")
		oauthClient = c.m()
		oauthClient["client_secret"] = admin["client_secret"]
		spy.expectCalls(t, 2)
	})

	run("requires a distinct privilege action to configure client_credentials scopes", func(t *testing.T) {
		admin := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: allowedHeaders, Body: map[string]any{
			"grant_types":               []any{"client_credentials"},
			"client_credentials_scopes": []any{"m2m:read", "m2m:read"},
		}})
		rgEqual(t, admin["client_credentials_scopes"], []any{"m2m:read"})
		calls := spy.calls()
		if len(calls) != 2 || calls[0] != "create" || calls[1] != "configure-client-credentials-scopes" {
			t.Fatalf("calls: %v", calls)
		}
		allowed.deleteClient(admin["client_id"].(string))
	})

	run("clears client_credentials authority when the grant is removed and does not restore it", func(t *testing.T) {
		admin := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: allowedHeaders, Body: map[string]any{
			"grant_types":               []any{"authorization_code", "client_credentials"},
			"redirect_uris":             []any{redirectURI},
			"client_credentials_scopes": []any{"m2m:read"},
		}})
		id := admin["client_id"]
		spy.clear()
		removed := rgMustCall(t, env, "adminUpdateOAuthClient", betterauth.CallInput{Headers: allowedHeaders, Body: map[string]any{
			"client_id": id, "update": map[string]any{"grant_types": []any{"authorization_code"}},
		}})
		rgEqual(t, removed["client_credentials_scopes"], []any{})
		spy.expectCalls(t, 1)
		spy.expectCalledWith(t, "update")
		spy.clear()
		restored := rgMustCall(t, env, "adminUpdateOAuthClient", betterauth.CallInput{Headers: allowedHeaders, Body: map[string]any{
			"client_id": id, "update": map[string]any{"grant_types": []any{"authorization_code", "client_credentials"}},
		}})
		rgEqual(t, restored["client_credentials_scopes"], []any{})
		spy.expectCalls(t, 1)
		spy.clear()
		cleared := rgMustCall(t, env, "adminUpdateOAuthClient", betterauth.CallInput{Headers: allowedHeaders, Body: map[string]any{
			"client_id": id, "update": map[string]any{"client_credentials_scopes": []any{}},
		}})
		rgEqual(t, cleared["client_credentials_scopes"], []any{})
		spy.expectCalls(t, 1)
		spy.expectCalledWith(t, "update")
		allowed.deleteClient(id.(string))
	})

	run("should not get a client with forbidden user", func(t *testing.T) {
		r := forbidden.getClient(oauthClient["client_id"].(string))
		rgErr(t, r, 401)
		spy.expectCalls(t, 1)
	})

	run("should get a client with allowed user", func(t *testing.T) {
		r := allowed.getClient(oauthClient["client_id"].(string))
		rgExpectUndefined(t, r.m(), "client_secret")
		rgMatch(t, r.m(), rgWithout(oauthClient, "client_secret"))
		spy.expectCalls(t, 1)
	})

	run("should get public-only information about a client with any user", func(t *testing.T) {
		want := rgMerge(map[string]any{"client_id": oauthClient["client_id"]}, rgUiClientInput)
		rgMatch(t, allowed.publicClient(oauthClient["client_id"].(string)).m(), want)
		rgMatch(t, forbidden.publicClient(oauthClient["client_id"].(string)).m(), want)
		spy.expectCalls(t, 0)
	})

	run("should not get clients with forbidden user", func(t *testing.T) {
		r := forbidden.getClients()
		rgErr(t, r, 401)
		spy.expectCalls(t, 1)
	})

	run("should get clients with allowed user", func(t *testing.T) {
		r := allowed.getClients()
		list, _ := r.data.([]any)
		if len(list) != 2 {
			t.Fatalf("expected 2 clients, got %s", r.raw)
		}
		c, _ := list[1].(map[string]any)
		rgExpectUndefined(t, c, "client_secret")
		rgMatch(t, c, rgWithout(oauthClient, "client_secret"))
		spy.expectCalls(t, 1)
	})

	newRedirectURI := "https://example.com/api/auth/oauth2/callback/" + providerID

	run("should not update the client with forbidden user", func(t *testing.T) {
		r := forbidden.updateClient(oauthClient["client_id"].(string), map[string]any{"redirect_uris": []any{redirectURI, newRedirectURI}})
		rgErr(t, r, 401)
		spy.expectCalls(t, 1)
	})

	run("should update the client with allowed user", func(t *testing.T) {
		r := allowed.updateClient(oauthClient["client_id"].(string), map[string]any{"redirect_uris": []any{redirectURI, newRedirectURI}})
		rgExpectUndefined(t, r.m(), "client_secret")
		rgMatch(t, r.m(), rgMerge(rgWithout(oauthClient, "client_secret"), map[string]any{"redirect_uris": []any{redirectURI, newRedirectURI}}))
		oauthClient = r.m()
		spy.expectCalls(t, 1)
	})

	run("should not rotate the client secret with forbidden user", func(t *testing.T) {
		r := forbidden.rotateSecret(oauthClient["client_id"].(string))
		rgErr(t, r, 401)
		spy.expectCalls(t, 1)
	})

	run("should rotate the client secret with allowed user", func(t *testing.T) {
		r := allowed.rotateSecret(oauthClient["client_id"].(string))
		rgExpectDefined(t, r.m(), "client_secret")
		if r.m()["client_secret"] == oauthClient["client_secret"] {
			t.Fatal("secret not rotated")
		}
		rgMatch(t, rgWithout(r.m(), "client_secret"), rgWithout(oauthClient, "client_secret"))
		oauthClient = r.m()
		spy.expectCalls(t, 1)
	})

	run("should not delete the client with forbidden user", func(t *testing.T) {
		r := forbidden.deleteClient(oauthClient["client_id"].(string))
		rgErr(t, r, 401)
		spy.expectCalls(t, 1)
	})

	run("should delete the client with allowed user", func(t *testing.T) {
		r := allowed.deleteClient(oauthClient["client_id"].(string))
		if !r.ok() || r.data != nil {
			t.Fatalf("delete: %d %s", r.status, r.raw)
		}
		spy.expectCalls(t, 1)
	})

	run("should not create client via admin api without a session", func(t *testing.T) {
		_, err := rgCall(env, "adminCreateOAuthClient", betterauth.CallInput{
			Body: rgMerge(rgUiClientInput, map[string]any{"redirect_uris": []any{redirectURI}})})
		rgExpectStatus(t, err, "UNAUTHORIZED", 401)
	})
}

func TestRg_OauthClientDynamicRegistrationPrivileges(t *testing.T) {
	redirectURI := "https://rp.example.com/callback"
	allowedEmail, forbiddenEmail, pw := "dcr-allowed@test.com", "dcr-forbidden@test.com", "test123456"
	spy := &rgPrivSpy{allowed: allowedEmail}
	env := newEnv(t, Options{
		AllowDynamicClientRegistration:         true,
		AllowUnauthenticatedClientRegistration: true,
		ClientPrivileges:                       spy.fn,
	})
	env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": allowedEmail, "password": pw, "name": "dcr allowed user"}})
	env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": forbiddenEmail, "password": pw, "name": "dcr forbidden user"}})
	allowed := rgClient{env, env.signIn(allowedEmail, pw)}
	forbidden := rgClient{env, env.signIn(forbiddenEmail, pw)}
	unauthed := rgClient{env, http.Header{}}

	run := func(name string, f func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			spy.clear()
			f(t)
		})
	}

	run("should not register a client for a forbidden user", func(t *testing.T) {
		r := forbidden.register(map[string]any{"redirect_uris": []any{redirectURI}})
		rgErr(t, r, 401)
		if r.m() != nil {
			rgExpectUndefined(t, r.m(), "client_secret")
		}
		spy.expectCalledWith(t, "create")
	})

	run("should register a client for an allowed user", func(t *testing.T) {
		r := allowed.register(map[string]any{"redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		spy.expectCalledWith(t, "create")
	})

	run("should allow unauthenticated public registration without invoking the gate", func(t *testing.T) {
		r := unauthed.register(map[string]any{"token_endpoint_auth_method": "none", "redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id")
		rgExpectUndefined(t, r.m(), "client_secret", "public")
		if r.m()["token_endpoint_auth_method"] != "none" {
			t.Fatalf("register: %s", r.raw)
		}
		spy.expectCalls(t, 0)
	})

	run("should allow unauthenticated confidential registration without invoking the gate", func(t *testing.T) {
		r := unauthed.register(map[string]any{"redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		rgExpectUndefined(t, r.m(), "public")
		if r.m()["token_endpoint_auth_method"] != "client_secret_basic" {
			t.Fatalf("register: %s", r.raw)
		}
		spy.expectCalls(t, 0)
	})
}
