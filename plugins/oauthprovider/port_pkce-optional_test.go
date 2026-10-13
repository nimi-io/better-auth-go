package oauthprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Port of pkce-optional.test.ts.

const azPkceRedirectURI = "https://rp.example.com/api/auth/callback/test"

// azLocation runs a GET against path with headers and returns the Location header.
func azLocation(env *testEnv, path string, h http.Header) string {
	env.t.Helper()
	return env.do("GET", path, nil, h).location()
}

// azAuthorizeNoPKCE builds the manual authorize URL used throughout the file.
func azAuthorizeNoPKCE(clientID, redirectURI, scope, state string) string {
	return authorizeURL("client_id", clientID, "redirect_uri", redirectURI, "response_type", "code",
		"scope", scope, "state", state)
}

// azCreateAuthorizationURL mirrors createAuthorizationURL from better-auth/oauth2 and returns
// the path relative to /api/auth.
func azCreateAuthorizationURL(t *testing.T, clientID, redirectURI, state string, scopes []string, verifier, nonce string) string {
	t.Helper()
	u, err := oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{ID: "test", ClientID: clientID,
		AuthorizationEndpoint: testAuthBase + "/oauth2/authorize", RedirectURI: redirectURI, State: state,
		Scopes: scopes, ResponseType: "code", CodeVerifier: verifier, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	return u.String()
}

func azCodeFrom(t *testing.T, loc string) string {
	t.Helper()
	base, _ := url.Parse(testBaseURL)
	u, err := base.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code")
}

// azPostTokenRequest mirrors authorizationCodeRequest with client_secret_post credentials.
func azPostTokenRequest(env *testEnv, clientID, secret, code, redirectURI, verifier string) *response {
	env.t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	form.Set("client_id", clientID)
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return env.token(form, nil)
}

func azMustContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Fatalf("expected %q to contain %q", s, sub)
		}
	}
}

func azMustNotContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			t.Fatalf("expected %q not to contain %q", s, sub)
		}
	}
}

func azStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func TestAz_PKCEOptionalDefaultBehavior(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	conf := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native",
		"token_endpoint_auth_method": "client_secret_post", "skip_consent": true})
	pub := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native",
		"skip_consent": true, "token_endpoint_auth_method": "none"})
	t.Run("public client without PKCE should fail", func(t *testing.T) {
		loc := azLocation(env, azAuthorizeNoPKCE(azStr(pub, "client_id"), azPkceRedirectURI, "openid", "123"), h)
		azMustContain(t, loc, "error=invalid_request", "pkce+is+required+for+public+clients")
	})
	t.Run("confidential client without PKCE should fail with default settings", func(t *testing.T) {
		loc := azLocation(env, azAuthorizeNoPKCE(azStr(conf, "client_id"), azPkceRedirectURI, "openid", "123"), h)
		azMustContain(t, loc, "error=invalid_request", "pkce+is+required+for+this+client")
	})
	t.Run("confidential client with PKCE should succeed", func(t *testing.T) {
		verifier := crypto.RandomString(64)
		loc := azLocation(env, azCreateAuthorizationURL(t, azStr(conf, "client_id"), azPkceRedirectURI, "123", []string{"openid"}, verifier, ""), h)
		azMustContain(t, loc, azPkceRedirectURI, "code=", "state=123")
		azMustNotContain(t, loc, "error=")
	})
}

func TestAz_PKCEOptionalPerClientOptOut(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	conf := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native",
		"token_endpoint_auth_method": "client_secret_post", "skip_consent": true, "require_pkce": false})
	pub := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native",
		"skip_consent": true, "token_endpoint_auth_method": "none"})
	t.Run("public client without PKCE should always fail", func(t *testing.T) {
		loc := azLocation(env, azAuthorizeNoPKCE(azStr(pub, "client_id"), azPkceRedirectURI, "openid", "123"), h)
		azMustContain(t, loc, "error=invalid_request", "pkce+is+required+for+public+clients")
	})
	t.Run("confidential client without PKCE should succeed", func(t *testing.T) {
		loc := azLocation(env, azAuthorizeNoPKCE(azStr(conf, "client_id"), azPkceRedirectURI, "openid", "123"), h)
		azMustContain(t, loc, azPkceRedirectURI, "state=123")
		azMustNotContain(t, loc, "code_challenge=", "error=")
		code := azCodeFrom(t, loc)
		if code == "" {
			t.Fatal("missing code")
		}
		res := azPostTokenRequest(env, azStr(conf, "client_id"), azStr(conf, "client_secret"), code, azPkceRedirectURI, "")
		m := res.json()
		if m["access_token"] == nil || m["id_token"] == nil {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
	})
}

func TestAz_PKCEOptionalDynamicClientRegistrationPolicy(t *testing.T) {
	env := newEnv(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true,
		ClientRegistrationRequirePKCE: betterauth.Bool(false)})
	h := env.signInWithTestUser()
	t.Run("confidential DCR client without PKCE should succeed when registration policy disables PKCE", func(t *testing.T) {
		reg := env.do("POST", "/oauth2/register", map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native"}, nil)
		rm := reg.json()
		if azStr(rm, "client_id") == "" || azStr(rm, "client_secret") == "" || rm["token_endpoint_auth_method"] != "client_secret_basic" || rm["require_pkce"] != false {
			t.Fatalf("registration: %d %s", reg.status, reg.body)
		}
		clientID, secret := azStr(rm, "client_id"), azStr(rm, "client_secret")
		state := "dcr-no-pkce"
		loc := azLocation(env, azAuthorizeNoPKCE(clientID, azPkceRedirectURI, "openid", state), h)
		azMustContain(t, loc, "/consent")
		azMustNotContain(t, loc, "error=")
		base, _ := url.Parse(testBaseURL)
		cu, _ := base.Parse(loc)
		cres := env.do("POST", "/oauth2/consent", map[string]any{"accept": true, "oauth_query": cu.RawQuery}, h)
		cURL := azStr(cres.json(), "url")
		if cres.status != 200 {
			t.Fatalf("consent: %d %s", cres.status, cres.body)
		}
		azMustContain(t, cURL, "code=", "state="+state)
		code := azCodeFrom(t, cURL)
		tres := env.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {azPkceRedirectURI}},
			basicAuth(clientID, secret))
		tm := tres.json()
		if tres.status != 200 || tm["access_token"] == nil || tm["id_token"] == nil {
			t.Fatalf("token: %d %s", tres.status, tres.body)
		}
	})
	t.Run("public DCR client without PKCE should still fail", func(t *testing.T) {
		reg := env.do("POST", "/oauth2/register", map[string]any{"token_endpoint_auth_method": "none",
			"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native"}, nil)
		rm := reg.json()
		if azStr(rm, "client_id") == "" || rm["token_endpoint_auth_method"] != "none" {
			t.Fatalf("registration: %d %s", reg.status, reg.body)
		}
		if _, ok := rm["public"]; ok {
			t.Fatalf("unexpected public property: %s", reg.body)
		}
		loc := azLocation(env, azAuthorizeNoPKCE(azStr(rm, "client_id"), azPkceRedirectURI, "openid", "public-dcr-no-pkce"), h)
		azMustContain(t, loc, "error=invalid_request", "pkce+is+required+for+public+clients")
	})
}

func TestAz_PKCEOptionalOfflineAccessScope(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	conf := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native",
		"token_endpoint_auth_method": "client_secret_post", "skip_consent": true, "require_pkce": false})
	clientID, secret := azStr(conf, "client_id"), azStr(conf, "client_secret")
	const offlineErr = "pkce+or+OIDC+nonce+is+required+when+requesting+offline_access+scope"
	t.Run("offline_access without PKCE or OIDC nonce should fail even with requirePKCE: false", func(t *testing.T) {
		loc := azLocation(env, azAuthorizeNoPKCE(clientID, azPkceRedirectURI, "openid offline_access", "123"), h)
		azMustContain(t, loc, "error=invalid_request", offlineErr)
	})
	t.Run("offline_access without PKCE should succeed for confidential OIDC requests with nonce", func(t *testing.T) {
		nonce := "offline-access-nonce"
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azPkceRedirectURI, "123", []string{"openid", "offline_access"}, "", nonce), h)
		azMustContain(t, loc, azPkceRedirectURI, "code=")
		azMustNotContain(t, loc, "error=")
		res := azPostTokenRequest(env, clientID, secret, azCodeFrom(t, loc), azPkceRedirectURI, "")
		m := res.json()
		if m["access_token"] == nil || m["id_token"] == nil || m["refresh_token"] == nil {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
		if decodeJWTPayload(t, m["id_token"].(string))["nonce"] != nonce {
			t.Fatalf("nonce mismatch")
		}
	})
	t.Run("offline_access without PKCE should fail for non-OIDC requests with nonce", func(t *testing.T) {
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azPkceRedirectURI, "123", []string{"offline_access"}, "", "unused-without-openid"), h)
		azMustContain(t, loc, "error=invalid_request", offlineErr)
		azMustNotContain(t, loc, "code=")
	})
	t.Run("offline_access with PKCE should succeed", func(t *testing.T) {
		verifier := crypto.RandomString(64)
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azPkceRedirectURI, "123", []string{"openid", "offline_access"}, verifier, ""), h)
		azMustContain(t, loc, azPkceRedirectURI, "code=")
		azMustNotContain(t, loc, "error=")
		res := azPostTokenRequest(env, clientID, secret, azCodeFrom(t, loc), azPkceRedirectURI, verifier)
		m := res.json()
		if m["access_token"] == nil || m["refresh_token"] == nil {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
	})
}

func TestAz_PKCEOptionalConsistencyChecks(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	conf := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native",
		"token_endpoint_auth_method": "client_secret_post", "skip_consent": true, "require_pkce": false})
	clientID, secret := azStr(conf, "client_id"), azStr(conf, "client_secret")
	expect401 := func(t *testing.T, res *response, desc string) {
		t.Helper()
		if res.status != 401 {
			t.Fatalf("expected 401, got %d %s", res.status, res.body)
		}
		azMustContain(t, azStr(res.json(), "error_description"), desc)
	}
	t.Run("PKCE in auth but not in token should fail", func(t *testing.T) {
		verifier := crypto.RandomString(64)
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azPkceRedirectURI, "123", []string{"openid"}, verifier, ""), h)
		res := azPostTokenRequest(env, clientID, secret, azCodeFrom(t, loc), azPkceRedirectURI, "")
		expect401(t, res, "code_verifier required because PKCE was used in authorization")
	})
	t.Run("PKCE not in auth but in token should fail", func(t *testing.T) {
		loc := azLocation(env, azAuthorizeNoPKCE(clientID, azPkceRedirectURI, "openid", "123"), h)
		res := azPostTokenRequest(env, clientID, secret, azCodeFrom(t, loc), azPkceRedirectURI, crypto.RandomString(64))
		expect401(t, res, "code_verifier provided but PKCE was not used in authorization")
	})
	t.Run("mismatched PKCE challenge should fail", func(t *testing.T) {
		verifier := crypto.RandomString(64)
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azPkceRedirectURI, "123", []string{"openid"}, verifier, ""), h)
		res := azPostTokenRequest(env, clientID, secret, azCodeFrom(t, loc), azPkceRedirectURI, crypto.RandomString(64))
		expect401(t, res, "code verification failed")
	})
}

func TestAz_PKCEOptionalRegistrationRestrictions(t *testing.T) {
	env := newEnv(t, Options{AllowDynamicClientRegistration: true})
	h := env.signInWithTestUser()
	t.Run("admin create endpoint should persist require_pkce", func(t *testing.T) {
		disabled := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native", "require_pkce": false})
		if disabled["require_pkce"] != false {
			t.Fatalf("require_pkce: %v", disabled)
		}
		required := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native", "require_pkce": true})
		if required["require_pkce"] != true {
			t.Fatalf("require_pkce: %v", required)
		}
	})
	for _, tc := range [][2]string{{"dynamic registration", "/oauth2/register"}, {"non-admin create-client", "/oauth2/create-client"}} {
		t.Run("should ignore require_pkce false ("+tc[0]+")", func(t *testing.T) {
			res := env.do("POST", tc[1], map[string]any{"redirect_uris": []any{azPkceRedirectURI}, "application_type": "native", "require_pkce": false}, h)
			m := res.json()
			if azStr(m, "client_id") == "" || m["require_pkce"] == true {
				t.Fatalf("response: %d %s", res.status, res.body)
			}
			loc := azLocation(env, azAuthorizeNoPKCE(azStr(m, "client_id"), azPkceRedirectURI, "openid", "123"), h)
			azMustContain(t, loc, "error=invalid_request", "pkce+is+required+for+this+client")
		})
	}
}
