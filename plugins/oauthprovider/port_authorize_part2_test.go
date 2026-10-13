package oauthprovider

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
)

// Port of authorize.test.ts (part 2).

func TestAz_OAuthAuthorizeAuthenticated(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	body := func(skip bool) map[string]any {
		return map[string]any{"redirect_uris": []any{azRPRedirectURI}, "application_type": "native", "skip_consent": skip}
	}
	client := azAdminClient(t, env, h, body(true))
	needsConsent := azAdminClient(t, env, h, body(false))
	for _, c := range []map[string]any{client, needsConsent} {
		if azStr(c, "user_id") == "" || azStr(c, "client_secret") == "" || !reflect.DeepEqual(c["redirect_uris"], []any{azRPRedirectURI}) {
			t.Fatalf("client: %v", c)
		}
	}
	clientID := azStr(client, "client_id")
	t.Run("should authorize and include iss parameter", func(t *testing.T) {
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azRPRedirectURI, "123", []string{"openid"}, crypto.RandomString(64), ""), h)
		azMustContain(t, loc, azRPRedirectURI, "code=", "state=123", azIssEncoded)
	})
	t.Run("should include iss parameter in error responses", func(t *testing.T) {
		loc := azLocation(env, authorizeURL("client_id", clientID, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "error-test-state"), h)
		azMustContain(t, loc, azRPRedirectURI, "error=invalid_request", "pkce", "iss=", azIssEncoded)
	})
	t.Run("should return invalid_target for invalid resource with explicit description", func(t *testing.T) {
		loc := azLocation(env, azAuthzPKCE("client_id", clientID, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "invalid-resource-state", "resource", "https://resource.example.com"), h)
		azMustContain(t, loc, azRPRedirectURI, "error=invalid_target", "state=invalid-resource-state", azIssEncoded)
	})
	t.Run("should have metadata issuer match iss parameter (RFC 9207)", func(t *testing.T) {
		md := env.mustCall("getOpenIdConfig", betterauth.CallInput{})
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azRPRedirectURI, "issuer-match-test", []string{"openid"}, crypto.RandomString(64), ""), h)
		u, err := url.Parse(loc)
		if err != nil || u.Query().Get("iss") != md["issuer"] {
			t.Fatalf("iss %q != issuer %v", loc, md["issuer"])
		}
	})
	t.Run("should return consent_required when prompt=none and consent is needed", func(t *testing.T) {
		loc := azLocation(env, azAuthzPKCE("client_id", azStr(needsConsent, "client_id"), "redirect_uri", azRPRedirectURI,
			"response_type", "code", "scope", "openid", "state", "prompt-none-consent-required", "prompt", "none"), h)
		azMustContain(t, loc, azRPRedirectURI, "error=consent_required", "state=prompt-none-consent-required", azIssEncoded)
		azMustNotContain(t, loc, "/consent")
	})
}

func TestAz_OAuthAuthorizeConsentedResources(t *testing.T) {
	const (
		validResource       = "https://api.example.com"
		secondValidResource = "https://api.secondary.example.com"
	)
	env := newEnv(t, Options{Resources: []ResourceInput{{Identifier: validResource}, {Identifier: secondValidResource}},
		EnforcePerClientResources: betterauth.Bool(false)})
	h := env.signInWithTestUser()
	userID := azStr(env.findOne("user", eq("email", testUserEmail)), "id")
	// testerCreateConsent: a legacy consent row created directly through the adapter.
	createConsent := func(clientID string, scopes []string) {
		now := time.Unix(time.Now().Unix(), 0)
		if _, err := env.db.Create(env.ctx(), adapter.CreateInput{Model: "oauthConsent", Data: adapter.Record{
			"createdAt": now, "updatedAt": now, "clientId": clientID, "userId": userID, "scopes": scopes}}); err != nil {
			t.Fatal(err)
		}
	}
	newClient := func() string {
		return azStr(azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{azRPRedirectURI}, "application_type": "native", "skip_consent": false}), "client_id")
	}
	consentAccept := func(t *testing.T, consentLoc string, extra map[string]any) string {
		t.Helper()
		b := map[string]any{"accept": true, "oauth_query": BuildSignedOAuthQuery(azResolve(t, consentLoc).RawQuery)}
		for k, v := range extra {
			b[k] = v
		}
		res := env.do("POST", "/oauth2/consent", b, h)
		if res.status != 200 {
			t.Fatalf("consent: %d %s", res.status, res.body)
		}
		return azStr(res.json(), "url")
	}
	needsConsent := newClient()
	createConsent(needsConsent, []string{"openid"})
	t.Run("should re-prompt for consent when stored consent has no resources and a resource is requested", func(t *testing.T) {
		loc := azLocation(env, azAuthzPKCE("client_id", needsConsent, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "legacy-consent-no-resource", "resource", validResource), h)
		azMustContain(t, loc, "/consent")
		azMustNotContain(t, loc, azRPRedirectURI+"?code=")
	})
	t.Run("should re-prompt for consent when stored consent has no requested UserInfo claim", func(t *testing.T) {
		dedicated := newClient()
		createConsent(dedicated, []string{"openid"})
		loc := azLocation(env, azAuthzPKCE("client_id", dedicated, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "userinfo-claim-consent", "claims", `{"userinfo":{"email":null}}`), h)
		azMustContain(t, loc, "/consent")
		azMustNotContain(t, loc, azRPRedirectURI+"?code=")
		if got := azResolve(t, loc).Query().Get("claims"); got != `{"userinfo":{"email":null}}` {
			t.Fatalf("claims: %q", got)
		}
	})
	t.Run("should persist multiple resource values onto OAuthConsent.resources", func(t *testing.T) {
		loc := azLocation(env, azAuthzPKCE("client_id", needsConsent, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "multiple-resources-persist", "resource", validResource, "resource", secondValidResource), h)
		azMustContain(t, loc, "/consent")
		azMustContain(t, consentAccept(t, loc, nil), azRPRedirectURI+"?code=")
		saved := env.findOne("oauthConsent", eq("clientId", needsConsent), eq("userId", userID))
		if got := recStrings(saved, "resources"); !reflect.DeepEqual(got, []string{validResource, secondValidResource}) {
			t.Fatalf("resources: %v", got)
		}
	})
	t.Run("should persist only accepted UserInfo claims onto OAuthConsent", func(t *testing.T) {
		dedicated := newClient()
		loc := azLocation(env, azAuthzPKCE("client_id", dedicated, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "persist-userinfo-claims", "claims", `{"userinfo":{"name":null,"email":null}}`), h)
		azMustContain(t, loc, "/consent")
		cu := consentAccept(t, loc, map[string]any{"claims": map[string]any{"userinfo": map[string]any{"name": nil}}})
		azMustContain(t, cu, azRPRedirectURI+"?code=")
		saved := env.findOne("oauthConsent", eq("clientId", dedicated), eq("userId", userID))
		if got := recStrings(saved, "requestedUserInfoClaims"); !reflect.DeepEqual(got, []string{"name"}) {
			t.Fatalf("requestedUserInfoClaims: %v", got)
		}
	})
	t.Run("should return consent_required for prompt=none when requested resource is not covered by prior consent", func(t *testing.T) {
		dedicated := newClient()
		createConsent(dedicated, []string{"openid"})
		loc := azLocation(env, azAuthzPKCE("client_id", dedicated, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "prompt-none-resource-consent", "prompt", "none", "resource", validResource), h)
		azMustContain(t, loc, azRPRedirectURI, "error=consent_required", "state=prompt-none-resource-consent", azIssEncoded)
		azMustNotContain(t, loc, "/consent")
	})
}

func azAllowLocalhostSubdomain(uri string, registered []string, defaultResult bool) (bool, error) {
	if defaultResult {
		return true, nil
	}
	u, err := parseURL(uri)
	if err != nil {
		return false, nil
	}
	if strings.HasSuffix(u.Hostname(), ".localhost") {
		for _, r := range registered {
			ru, err := parseURL(r)
			if err != nil {
				return false, nil
			}
			if ru.Hostname() == "localhost" && ru.Port() == u.Port() && ru.Path == u.Path {
				return true, nil
			}
		}
	}
	return false, nil
}

func azAllowPreviewRedirectURI(uri string, _ []string, defaultResult bool) (bool, error) {
	if defaultResult {
		return true, nil
	}
	if strings.Contains(uri, "#") {
		return false, nil
	}
	u, err := parseURL(uri)
	if err != nil {
		return false, nil
	}
	return u.Scheme == "https" && u.User == nil && strings.HasSuffix(u.Hostname(), ".preview.example.com") &&
		u.Port() == "" && u.Path == "/api/auth/callback" && u.RawQuery == "" && !u.ForceQuery, nil
}

func TestAz_OAuthAuthorizeCustomValidateRedirectUri(t *testing.T) {
	const (
		registeredURI = "https://app.example.com/api/auth/callback"
		previewURI    = "https://pr-123.preview.example.com/api/auth/callback"
	)
	env := newEnv(t, Options{ValidateRedirectURI: azAllowPreviewRedirectURI})
	h := env.signInWithTestUser()
	clientID := azStr(azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{registeredURI}, "skip_consent": true}), "client_id")
	t.Run("should accept redirect_uri matching custom validation logic", func(t *testing.T) {
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, previewURI, "custom-validator-test", []string{"openid"}, crypto.RandomString(64), ""), h)
		azMustContain(t, loc, previewURI, "code=", "state=custom-validator-test")
	})
	for _, c := range [][2]string{
		{"a different callback path", "https://pr-123.preview.example.com/other-callback"},
		{"a query parameter", "https://pr-123.preview.example.com/api/auth/callback?next=/evil"},
		{"an unexpected port", "https://pr-123.preview.example.com:8443/api/auth/callback"},
		{"a lookalike host", "https://pr-123.preview.example.com.evil.test/api/auth/callback"},
	} {
		t.Run("should reject "+c[0]+" in a preview redirect URI", func(t *testing.T) {
			loc := azLocation(env, azAuthzPKCE("client_id", clientID, "redirect_uri", c[1], "response_type", "code",
				"scope", "openid", "state", "unauthorized-test"), h)
			azMustContain(t, loc, "error=invalid_redirect")
			azMustNotContain(t, loc, c[1])
		})
	}
	t.Run("should preserve a registered redirect URI", func(t *testing.T) {
		loc := azLocation(env, authorizeURL("client_id", clientID, "redirect_uri", registeredURI, "response_type", "code", "scope", "unknown-scope"), h)
		azMustContain(t, loc, registeredURI, "error=invalid_scope")
	})
	t.Run("should forward early protocol errors to a custom-validated redirect_uri", func(t *testing.T) {
		loc := azLocation(env, authorizeURL("client_id", clientID, "redirect_uri", previewURI, "response_type", "code",
			"scope", "openid", "state", "early-error-forwarding-test", "request", "some-request-object"), h)
		azMustContain(t, loc, previewURI, "error=request_not_supported", "state=early-error-forwarding-test")
	})
}

func TestAz_OAuthAuthorizeValidateRedirectUriErrorHandling(t *testing.T) {
	const rpBase = "http://localhost:5000"
	unregisteredThrowingURI := rpBase + "/throw-error-callback"
	throwing := func(uri string, _ []string, _ bool) (bool, error) {
		if strings.Contains(uri, "throw-error") {
			return false, errors.New("Validator intentionally threw")
		}
		return uri == rpBase+"/callback", nil
	}
	env := newEnv(t, Options{ValidateRedirectURI: throwing})
	h := env.signInWithTestUser()
	clientID := azStr(azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{rpBase + "/callback"}, "application_type": "native", "skip_consent": true}), "client_id")
	t.Run("should fail closed when validator throws an exception", func(t *testing.T) {
		loc := azLocation(env, azAuthzPKCE("client_id", clientID, "redirect_uri", unregisteredThrowingURI, "response_type", "code",
			"scope", "openid", "state", "validator-throws-test"), h)
		azMustContain(t, loc, "error=invalid_redirect")
		azMustNotContain(t, loc, "throw-error")
	})
	t.Run("should fail closed in the error-forwarding path when validator throws", func(t *testing.T) {
		loc := azLocation(env, authorizeURL("client_id", clientID, "redirect_uri", unregisteredThrowingURI, "response_type", "code",
			"scope", "openid", "state", "error-path-throw-test", "request", "some-request-object"), h)
		azMustContain(t, loc, "error=request_not_supported")
		azMustNotContain(t, loc, "throw-error")
	})
}

func TestAz_OAuthAuthorizeAsyncValidateRedirectUri(t *testing.T) {
	asyncValidator := func(uri string, registered []string, def bool) (bool, error) {
		time.Sleep(10 * time.Millisecond)
		return azAllowLocalhostSubdomain(uri, registered, def)
	}
	env := newEnv(t, Options{ValidateRedirectURI: asyncValidator})
	h := env.signInWithTestUser()
	const registeredURI = "http://localhost:5000/callback"
	const subdomainURI = "http://async-test.localhost:5000/callback"
	clientID := azStr(azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{registeredURI}, "application_type": "native", "skip_consent": true}), "client_id")
	t.Run("should support async validator returning a Promise", func(t *testing.T) {
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, subdomainURI, "async-validator-test", []string{"openid"}, crypto.RandomString(64), ""), h)
		azMustContain(t, loc, "async-test.localhost", "code=", "state=async-validator-test")
	})
}

func TestAz_OAuthAuthorizeCustomRedirectURISafety(t *testing.T) {
	const registeredURI = "https://app.example.com/api/auth/callback"
	env := newEnv(t, Options{ValidateRedirectURI: func(string, []string, bool) (bool, error) { return true, nil }})
	h := env.signInWithTestUser()
	clientID := azStr(azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{registeredURI}, "skip_consent": true}), "client_id")
	for _, c := range [][2]string{
		{"a fragment", "https://pr-123.preview.example.com/api/auth/callback#fragment"},
		{"userinfo", "https://user@pr-123.preview.example.com/api/auth/callback"},
		{"an unsafe scheme", "javascript:alert(1)"},
		{"HTTP on a public host", "http://pr-123.preview.example.com/api/auth/callback"},
	} {
		t.Run("does not forward early errors to a URI with "+c[0], func(t *testing.T) {
			loc := azLocation(env, authorizeURL("client_id", clientID, "redirect_uri", c[1], "response_type", "code",
				"request", "unsupported-request-object"), h)
			azMustContain(t, loc, testAuthBase+"/error", "error=request_not_supported")
		})
	}
	t.Run("rejects userinfo in a parsed authorization request", func(t *testing.T) {
		loc := azLocation(env, azAuthzPKCE("client_id", clientID, "redirect_uri", "https://user@pr-123.preview.example.com/api/auth/callback",
			"response_type", "code", "scope", "openid"), h)
		azMustContain(t, loc, testAuthBase+"/error", "error=invalid_redirect")
	})
}
