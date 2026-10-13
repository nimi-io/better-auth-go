package sso

// Port of oidc.test.ts and oidc/id-token.test.ts (@better-auth/sso 1.7.7).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/organization"
)

// ---- helpers ----

// o1AnyString matches any non-empty string in o1Match (expect.any(String)).
type o1AnyString struct{}

// o1Match checks that got contains want (toMatchObject semantics).
func o1Match(t *testing.T, label string, got, want any) {
	t.Helper()
	if err := o1MatchErr(got, want, label); err != "" {
		t.Errorf("%s", err)
	}
}

func o1MatchErr(got, want any, path string) string {
	switch w := want.(type) {
	case o1AnyString:
		if s, ok := got.(string); !ok || s == "" {
			return fmt.Sprintf("%s: expected any string, got %#v", path, got)
		}
		return ""
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: expected object, got %#v", path, got)
		}
		for k, v := range w {
			if e := o1MatchErr(g[k], v, path+"."+k); e != "" {
				return e
			}
		}
		return ""
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Sprintf("%s: got %#v, want %#v", path, got, want)
	}
	return ""
}

func o1Contains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("expected %q to contain %q", s, sub)
	}
}

func o1NotContains(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("expected %q not to contain %q", s, sub)
	}
}

func o1Eq(t *testing.T, label string, got, want any) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%s: got %#v, want %#v", label, got, want)
	}
}

// o1RedirectParam is the encoded redirect_uri query fragment for a callback path.
func o1RedirectParam(env *testEnv, path string) string {
	return "redirect_uri=" + url.QueryEscape(env.baseURL+path)
}

// o1SignInSSO is authClient.signIn.sso({ ..., fetchOptions: { throw: true, onSuccess:
// cookieSetter(headers) } }): it returns the authorization URL and the cookie headers.
func o1SignInSSO(t *testing.T, env *testEnv, body map[string]any) (string, http.Header) {
	t.Helper()
	res := env.do("POST", "/sign-in/sso", nil, body)
	if res.Err != nil {
		t.Fatalf("sign-in/sso: %d %s", res.Status, res.Raw)
	}
	u, _ := res.m()["url"].(string)
	return u, cookieHeaders(res.Headers)
}

// o1OIDCBody is the common registerSSOProvider body with explicit endpoints.
func o1OIDCBody(idp *mockOIDC, domain, providerID, clientID, secret string, mapping bool) map[string]any {
	cfg := map[string]any{
		"clientId":              clientID,
		"clientSecret":          secret,
		"authorizationEndpoint": idp.URL + "/authorize",
		"tokenEndpoint":         idp.URL + "/token",
		"jwksEndpoint":          idp.URL + "/jwks",
		"discoveryEndpoint":     idp.URL + "/.well-known/openid-configuration",
	}
	if mapping {
		cfg["mapping"] = map[string]any{"email": "email", "emailVerified": "email_verified", "name": "name", "image": "picture"}
	}
	return map[string]any{"issuer": idp.URL, "domain": domain, "providerId": providerID, "oidcConfig": cfg}
}

func o1SetClaims(idp *mockOIDC, claims map[string]any) {
	idp.BeforeTokenSigning = func(p map[string]any, _ *http.Request) {
		for k, v := range claims {
			p[k] = v
		}
	}
}

func o1SetUserinfo(idp *mockOIDC, body map[string]any) {
	idp.BeforeUserinfo = func(r *mockResponse, _ *http.Request) {
		r.Body = body
		r.StatusCode = 200
	}
}

func o1TrustIdP(origins ...string) envConfig {
	return envConfig{mutate: func(c *betterauth.Config) { c.TrustedOrigins = origins }}
}

func o1WithOrg(ec envConfig) envConfig {
	ec.extraPlugins = append(ec.extraPlugins, organization.New(organization.Options{}))
	return ec
}

func o1SessionEmail(t *testing.T, env *testEnv, h http.Header) string {
	t.Helper()
	s := env.session(h)
	if s == nil || s.User == nil {
		t.Errorf("expected a session")
		return ""
	}
	return s.User.Email
}

// ---- describe("SSO") ----

func TestOIDCSSO(t *testing.T) {
	t.Run("SSO", func(t *testing.T) {
		idp := newMockOIDC(t)
		env := newEnv(t, Options{}, o1WithOrg(o1TrustIdP(idp.URL)))
		defaultUserinfo := map[string]any{"email": "oauth2@test.com", "name": "OAuth2 Test", "sub": "oauth2",
			"picture": "https://test.com/picture.png", "email_verified": true}
		defaultClaims := map[string]any{"sub": "oauth2", "email": "sso-user@localhost:8000.com", "email_verified": true,
			"name": "Test User", "picture": "https://test.com/picture.png"}
		o1SetUserinfo(idp, defaultUserinfo)
		o1SetClaims(idp, defaultClaims)
		restore := func() {
			o1SetUserinfo(idp, defaultUserinfo)
			o1SetClaims(idp, defaultClaims)
		}

		t.Run("should register a new SSO provider", func(t *testing.T) {
			h := env.signInTestUser()
			r := env.api("registerSSOProvider", h, o1OIDCBody(idp, "localhost.com", "test", "test", "test", true), nil)
			if r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.Raw)
			}
			o1Match(t, "provider", r.Data, map[string]any{
				"id":     o1AnyString{},
				"issuer": idp.URL,
				"oidcConfig": map[string]any{
					"issuer":                idp.URL,
					"clientId":              "test",
					"clientSecret":          "test",
					"authorizationEndpoint": idp.URL + "/authorize",
					"tokenEndpoint":         idp.URL + "/token",
					"jwksEndpoint":          idp.URL + "/jwks",
					"discoveryEndpoint":     idp.URL + "/.well-known/openid-configuration",
					"mapping":               map[string]any{"email": "email", "emailVerified": "email_verified", "name": "name", "image": "picture"},
				},
				"userId": o1AnyString{},
			})
		})

		t.Run("rejects OIDC profile mappings that attempt to replace the subject", func(t *testing.T) {
			h := env.signInTestUser()
			r := env.api("registerSSOProvider", h, map[string]any{
				"issuer": idp.URL, "domain": "subject-mapping.example.com", "providerId": "subject-mapping",
				"oidcConfig": map[string]any{
					"clientId": "test", "clientSecret": "test", "skipDiscovery": true,
					"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/jwks",
					"mapping": map[string]any{"id": "employee_id", "email": "email", "name": "name"},
				},
			}, nil)
			if r.Err == nil || r.Status != 400 {
				t.Fatalf("expected 400, got %d %s", r.Status, r.Raw)
			}
		})

		t.Run("should fail to register a new SSO provider with invalid issuer", func(t *testing.T) {
			h := env.signInTestUser()
			r := env.api("registerSSOProvider", h, map[string]any{
				"issuer": "invalid", "domain": "localhost", "providerId": "test",
				"oidcConfig": map[string]any{"clientId": "test", "clientSecret": "test"},
			}, nil)
			if r.Err != nil {
				o1Eq(t, "status", r.Status, 400)
				o1Eq(t, "message", r.message(), "[body.issuer] Invalid URL")
			}
		})

		t.Run("should not allow creating a provider with duplicate providerId", func(t *testing.T) {
			h := env.signInTestUser()
			env.mustAPI("registerSSOProvider", h, map[string]any{
				"issuer": idp.URL, "domain": "duplicate.com", "providerId": "duplicate-oidc-provider",
				"oidcConfig": map[string]any{"clientId": "test", "clientSecret": "test"},
			}, nil)
			r := env.api("registerSSOProvider", h, map[string]any{
				"issuer": idp.URL, "domain": "another-duplicate.com", "providerId": "duplicate-oidc-provider",
				"oidcConfig": map[string]any{"clientId": "test2", "clientSecret": "test2"},
			}, nil)
			if r.Err == nil {
				t.Fatalf("expected error, got %s", r.Raw)
			}
			o1Eq(t, "status", r.Status, 422)
			o1Eq(t, "message", r.message(), "SSO provider with this providerId already exists")
		})

		t.Run("should sign in with SSO provider with email matching", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"email": "my-email@localhost.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/test"))
			o1Contains(t, u, "login_hint=my-email%40localhost.com")
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
		})

		t.Run("should sign in with SSO provider with domain", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"email": "my-email@test.com", "domain": "localhost.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/test"))
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
		})

		t.Run("should sign in with SSO provider with providerId", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"providerId": "test", "loginHint": "user@example.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/test"))
			o1Contains(t, u, "login_hint=user%40example.com")
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
		})

		t.Run("should redirect with the token endpoint error description when code exchange fails", func(t *testing.T) {
			h := env.signInTestUser()
			env.mustAPI("registerSSOProvider", h, o1OIDCBody(idp, "token-error.com", "token-error-provider", "test", "test", false), nil)
			var once sync.Once
			idp.BeforeResponse = func(resp *mockResponse, _ *http.Request) {
				once.Do(func() {
					resp.Body = map[string]any{"error": "invalid_client", "error_description": "client rejected by issuer"}
					resp.StatusCode = 401
				})
			}
			defer func() { idp.BeforeResponse = nil }()
			u, sh := o1SignInSSO(t, env, map[string]any{"providerId": "token-error-provider", "callbackURL": "/dashboard"})
			flow := env.simulateOAuthFlow(u, sh)
			ru, _ := url.Parse(flow.CallbackURL)
			o1Eq(t, "error", ru.Query().Get("error"), "invalid_provider")
			o1Eq(t, "error_description", ru.Query().Get("error_description"), "client rejected by issuer")
		})

		t.Run("should redirect with an encoded invalid request when callback has no code", func(t *testing.T) {
			h := env.signInTestUser()
			env.mustAPI("registerSSOProvider", h, o1OIDCBody(idp, "missing-code.com", "missing-code-provider", "test", "test", false), nil)
			u, sh := o1SignInSSO(t, env, map[string]any{"providerId": "missing-code-provider", "callbackURL": "/dashboard"})
			res, err := noRedirectClient.Get(u)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			loc := res.Header.Get("Location")
			if loc == "" {
				t.Fatal("No callback location found")
			}
			cb, _ := url.Parse(loc)
			q := cb.Query()
			q.Del("code")
			cb.RawQuery = q.Encode()
			r := env.do("GET", cb.String(), sh, nil)
			ru, _ := url.Parse(r.location())
			o1Eq(t, "error", ru.Query().Get("error"), "invalid_request")
			o1Eq(t, "error_description", ru.Query().Get("error_description"), "authorization_code_not_found")
		})

		t.Run("should forward additionalParams to the SSO authorization URL", func(t *testing.T) {
			u, _ := o1SignInSSO(t, env, map[string]any{"providerId": "test", "callbackURL": "/dashboard",
				"additionalParams": map[string]any{"domain_hint": "contoso.com"}})
			pu, _ := url.Parse(u)
			o1Eq(t, "domain_hint", pu.Query().Get("domain_hint"), "contoso.com")
		})

		t.Run("should reject SSO additionalParams that collide with reserved OAuth params", func(t *testing.T) {
			res := env.do("POST", "/sign-in/sso", nil, map[string]any{"providerId": "test", "callbackURL": "/dashboard",
				"additionalParams": map[string]any{"redirect_uri": "https://attacker.example/callback"}})
			o1Eq(t, "status", res.Status, 400)
		})

		t.Run("should hydrate authorizationEndpoint via discovery when missing from stored config", func(t *testing.T) {
			h := env.signInTestUser()
			env.mustAPI("registerSSOProvider", h, map[string]any{
				"issuer": idp.URL, "domain": "no-auth-endpoint.com", "providerId": "no-auth-endpoint",
				"oidcConfig": map[string]any{
					"clientId": "test", "clientSecret": "test", "skipDiscovery": true,
					"tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/jwks",
					"discoveryEndpoint": idp.URL + "/.well-known/openid-configuration",
					"mapping":           map[string]any{"email": "email", "emailVerified": "email_verified", "name": "name", "image": "picture"},
				},
			}, nil)
			o1SetUserinfo(idp, map[string]any{"email": "no-auth-endpoint-user@no-auth-endpoint.com", "name": "No Auth Endpoint User",
				"sub": "no-auth-endpoint-user", "email_verified": true})
			o1SetClaims(idp, map[string]any{"email": "no-auth-endpoint-user@no-auth-endpoint.com", "email_verified": true,
				"name": "No Auth Endpoint User", "sub": "no-auth-endpoint-user"})
			defer restore()
			u, sh := o1SignInSSO(t, env, map[string]any{"providerId": "no-auth-endpoint", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			flow := env.simulateOAuthFlow(u, sh)
			o1Contains(t, flow.CallbackURL, "/dashboard")
		})

		t.Run("should normalize email to lowercase in OIDC authentication", func(t *testing.T) {
			h := env.signInTestUser()
			env.mustAPI("registerSSOProvider", h, map[string]any{
				"providerId": "email-case-oidc-provider", "issuer": idp.URL, "domain": "email-case-test.com",
				"oidcConfig": map[string]any{
					"clientId": "email-case-test-client", "clientSecret": "test-client-secret",
					"discoveryEndpoint": idp.URL + "/.well-known/openid-configuration", "pkce": false,
				},
			}, nil)
			mixed := "OIDCUser@Example.COM"
			o1SetUserinfo(idp, map[string]any{"email": mixed, "name": "OIDC Test User", "sub": "oidc-email-case-test-user",
				"picture": "https://test.com/picture.png", "email_verified": true})
			o1SetClaims(idp, map[string]any{"email": mixed, "email_verified": true, "name": "OIDC Test User", "sub": "oidc-email-case-test-user"})
			defer restore()

			u1, h1 := o1SignInSSO(t, env, map[string]any{"email": "user@email-case-test.com", "callbackURL": "/dashboard"})
			f1 := env.simulateOAuthFlow(u1, h1)
			o1Contains(t, f1.CallbackURL, "/dashboard")
			s1 := env.session(f1.Headers)
			if s1 == nil {
				t.Fatal("expected session 1")
			}
			o1Eq(t, "email", s1.User.Email, "oidcuser@example.com")
			firstID := s1.User.ID
			if firstID == "" {
				t.Fatal("expected user id")
			}
			u2, h2 := o1SignInSSO(t, env, map[string]any{"email": "user@email-case-test.com", "callbackURL": "/dashboard"})
			f2 := env.simulateOAuthFlow(u2, h2)
			o1Contains(t, f2.CallbackURL, "/dashboard")
			s2 := env.session(f2.Headers)
			if s2 == nil {
				t.Fatal("expected session 2")
			}
			o1Eq(t, "user id", s2.User.ID, firstID)
			o1Eq(t, "email", s2.User.Email, "oidcuser@example.com")
		})
	})
}

// ---- describe("SSO disable implicit sign in") ----

func TestOIDCDisableImplicitSignIn(t *testing.T) {
	t.Run("SSO disable implicit sign in", func(t *testing.T) {
		idp := newMockOIDC(t)
		env := newEnv(t, Options{DisableImplicitSignUp: true}, o1WithOrg(o1TrustIdP(idp.URL)))
		o1SetUserinfo(idp, map[string]any{"email": "oauth2@test.com", "name": "OAuth2 Test", "sub": "oauth2",
			"picture": "https://test.com/picture.png", "email_verified": true})
		// Upstream shares one oauth2-mock-server across describes and registers listeners in
		// describe bodies, so the "SSO" describe's beforeTokenSigning (sub = "oauth2") is
		// still active here; without it the id_token sub ("johndoe") would not match UserInfo.
		o1SetClaims(idp, map[string]any{"sub": "oauth2", "email": "sso-user@localhost:8000.com", "email_verified": true, "name": "Test User",
			"picture": "https://test.com/picture.png"})

		t.Run("should register a new SSO provider", func(t *testing.T) {
			h := env.signInTestUser()
			r := env.api("registerSSOProvider", h, o1OIDCBody(idp, "localhost.com", "test", "test", "test", true), nil)
			if r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.Raw)
			}
			o1Match(t, "provider", r.Data, map[string]any{
				"id":     o1AnyString{},
				"issuer": idp.URL,
				"oidcConfig": map[string]any{
					"issuer":                idp.URL,
					"clientId":              "test",
					"clientSecret":          "test",
					"authorizationEndpoint": idp.URL + "/authorize",
					"tokenEndpoint":         idp.URL + "/token",
					"jwksEndpoint":          idp.URL + "/jwks",
					"discoveryEndpoint":     idp.URL + "/.well-known/openid-configuration",
					"mapping":               map[string]any{"email": "email", "emailVerified": "email_verified", "name": "name", "image": "picture"},
				},
				"userId": o1AnyString{},
			})
		})

		t.Run("should not create user with SSO provider when sign ups are disabled", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"email": "my-email@localhost.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/test"))
			flow := env.simulateOAuthFlow(u, h)
			o1NotContains(t, flow.CallbackURL, "error=signup disabled")
			cu, err := url.Parse(flow.CallbackURL)
			if err != nil {
				t.Fatal(err)
			}
			o1Eq(t, "pathname", cu.Path, "/api/auth/error")
			o1Eq(t, "error", cu.Query().Get("error"), "signup disabled")
		})

		t.Run("should create user with SSO provider when sign ups are disabled but sign up is requested", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"email": "my-email@localhost.com", "callbackURL": "/dashboard", "requestSignUp": true})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/test"))
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
		})
	})
}

// ---- describe("provisioning") ----

func TestOIDCProvisioning(t *testing.T) {
	t.Run("provisioning", func(t *testing.T) {
		idp := newMockOIDC(t)
		env := newEnv(t, Options{}, o1WithOrg(o1TrustIdP(idp.URL)))
		o1SetUserinfo(idp, map[string]any{"email": "test@localhost.com", "name": "OAuth2 Test", "sub": "oauth2",
			"picture": "https://test.com/picture.png", "email_verified": true})
		// Upstream shares one oauth2-mock-server across describes and registers listeners in
		// describe bodies, so the "SSO" describe's beforeTokenSigning (sub = "oauth2") is
		// still active here; without it the id_token sub ("johndoe") would not match UserInfo.
		o1SetClaims(idp, map[string]any{"sub": "oauth2", "email": "sso-user@localhost:8000.com", "email_verified": true, "name": "Test User",
			"picture": "https://test.com/picture.png"})

		t.Run("should provision user", func(t *testing.T) {
			h := env.signInTestUser()
			org := env.mustAPI("createOrganization", h, map[string]any{"name": "Localhost", "slug": "localhost"}, nil)
			orgID, _ := org.m()["id"].(string)
			body := o1OIDCBody(idp, "localhost.com", "test2", "test", "test", true)
			body["organizationId"] = orgID
			provider := env.mustAPI("registerSSOProvider", h, body, nil)
			o1Match(t, "provider", provider.Data, map[string]any{"organizationId": orgID})

			u, nh := o1SignInSSO(t, env, map[string]any{"email": "my-email@localhost.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/test"))
			flow := env.simulateOAuthFlow(u, nh)
			o1Contains(t, flow.CallbackURL, "/dashboard")

			full := env.mustAPI("getFullOrganization", h, nil, map[string]any{"organizationId": orgID})
			members, _ := full.m()["members"].([]any)
			var member map[string]any
			for _, m := range members {
				mm, _ := m.(map[string]any)
				if u, _ := mm["user"].(map[string]any); u != nil && u["email"] == "test@localhost.com" {
					member = mm
				}
			}
			if member == nil {
				t.Fatalf("member not found: %s", full.Raw)
			}
			o1Match(t, "member", member, map[string]any{
				"role": "member",
				"user": map[string]any{"id": o1AnyString{}, "name": "OAuth2 Test", "email": "test@localhost.com", "image": "https://test.com/picture.png"},
			})
		})

		t.Run("should sign in with SSO provide with org slug", func(t *testing.T) {
			r := env.mustAPI("signInSSO", nil, map[string]any{"organizationSlug": "localhost", "callbackURL": "/dashboard"}, nil)
			u, _ := r.m()["url"].(string)
			o1Contains(t, u, idp.URL+"/authorize")
		})
	})
}

// ---- describe("provisionUser should only be called for new users") ----

func TestOIDCProvisionUserOnlyForNewUsers(t *testing.T) {
	t.Run("provisionUser should only be called for new users", func(t *testing.T) {
		idp := newMockOIDC(t)
		var mu sync.Mutex
		provisionCalls := 0
		var validateSources []betterauth.UserInfoSource
		ec := o1WithOrg(envConfig{mutate: func(c *betterauth.Config) {
			c.TrustedOrigins = []string{idp.URL}
			c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, _ map[string]any, src betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
				if src.Method == "sso-oidc" {
					mu.Lock()
					validateSources = append(validateSources, src)
					mu.Unlock()
				}
				return nil, nil
			}}
		}})
		env := newEnv(t, Options{ProvisionUser: func(context.Context, ProvisionUserData) error {
			mu.Lock()
			provisionCalls++
			mu.Unlock()
			return nil
		}}, ec)
		o1SetUserinfo(idp, map[string]any{"email": "provision-test@localhost.com", "name": "Provision Test", "sub": "provision-test-sub",
			"picture": "https://test.com/picture.png", "email_verified": true})
		o1SetClaims(idp, map[string]any{"sub": "provision-test-sub", "email": "provision-test@localhost.com", "email_verified": true,
			"name": "Provision Test", "picture": "https://test.com/picture.png"})

		t.Run("should call provisionUser only on first sign-in (new user), not on subsequent sign-ins", func(t *testing.T) {
			h := env.signInTestUser()
			env.mustAPI("registerSSOProvider", h, o1OIDCBody(idp, "localhost.com", "provision-test", "test", "test", true), nil)
			provisionCalls = 0
			validateSources = nil

			u1, h1 := o1SignInSSO(t, env, map[string]any{"email": "user@localhost.com", "callbackURL": "/dashboard"})
			env.simulateOAuthFlow(u1, h1)
			o1Eq(t, "provisionUser calls", provisionCalls, 1)
			if len(validateSources) != 1 {
				t.Fatalf("validateUserInfo calls: %d", len(validateSources))
			}
			s := validateSources[0]
			o1Eq(t, "action", s.Action, "create-user")
			o1Eq(t, "method", s.Method, "sso-oidc")
			o1Eq(t, "providerId", s.ProviderID, "provision-test")
			o1Eq(t, "profile.sub", s.Profile["sub"], "provision-test-sub")

			provisionCalls = 0
			u2, h2 := o1SignInSSO(t, env, map[string]any{"email": "user@localhost.com", "callbackURL": "/dashboard"})
			env.simulateOAuthFlow(u2, h2)
			o1Eq(t, "provisionUser calls", provisionCalls, 0)
			if len(validateSources) != 2 {
				t.Fatalf("validateUserInfo calls: %d", len(validateSources))
			}
			s = validateSources[1]
			o1Eq(t, "action", s.Action, "sign-in")
			o1Eq(t, "method", s.Method, "sso-oidc")
			o1Eq(t, "providerId", s.ProviderID, "provision-test")
			o1Eq(t, "profile.sub", s.Profile["sub"], "provision-test-sub")
		})
	})
}

// ---- describe("provisionUserOnEveryLogin should call provisionUser on every sign-in") ----

func TestOIDCProvisionUserOnEveryLogin(t *testing.T) {
	t.Run("provisionUserOnEveryLogin should call provisionUser on every sign-in", func(t *testing.T) {
		idp := newMockOIDC(t)
		calls := 0
		env := newEnv(t, Options{ProvisionUserOnEveryLogin: true, ProvisionUser: func(context.Context, ProvisionUserData) error {
			calls++
			return nil
		}}, o1WithOrg(o1TrustIdP(idp.URL)))
		o1SetUserinfo(idp, map[string]any{"email": "provision-every-login@localhost.com", "name": "Provision Every Login",
			"sub": "provision-every-login-sub", "picture": "https://test.com/picture.png", "email_verified": true})
		o1SetClaims(idp, map[string]any{"sub": "provision-every-login-sub", "email": "provision-every-login@localhost.com",
			"email_verified": true, "name": "Provision Every Login", "picture": "https://test.com/picture.png"})

		t.Run("should call provisionUser on both first and subsequent sign-ins", func(t *testing.T) {
			h := env.signInTestUser()
			env.mustAPI("registerSSOProvider", h, o1OIDCBody(idp, "localhost.com", "provision-every-login-test", "test", "test", true), nil)
			calls = 0
			u1, h1 := o1SignInSSO(t, env, map[string]any{"email": "user@localhost.com", "callbackURL": "/dashboard"})
			env.simulateOAuthFlow(u1, h1)
			o1Eq(t, "calls", calls, 1)
			calls = 0
			u2, h2 := o1SignInSSO(t, env, map[string]any{"email": "user@localhost.com", "callbackURL": "/dashboard"})
			env.simulateOAuthFlow(u2, h2)
			o1Eq(t, "calls", calls, 1)
		})
	})
}

// ---- describe("SSO shared redirectURI") ----

func TestOIDCSharedRedirectURI(t *testing.T) {
	t.Run("SSO shared redirectURI", func(t *testing.T) {
		idp := newMockOIDC(t)
		env := newEnv(t, Options{RedirectURI: "/sso/callback"}, o1WithOrg(o1TrustIdP(idp.URL)))
		o1SetUserinfo(idp, map[string]any{"email": "shared-redirect@test.com", "name": "Shared Redirect User", "sub": "shared-redirect-user",
			"picture": "https://test.com/shared.png", "email_verified": true})
		o1SetClaims(idp, map[string]any{"sub": "shared-redirect-user", "email": "shared-redirect@test.com", "email_verified": true,
			"name": "Shared Redirect User", "picture": "https://test.com/shared.png"})

		t.Run("should return shared redirectURI when registering provider", func(t *testing.T) {
			h := env.signInTestUser()
			r := env.mustAPI("registerSSOProvider", h, o1OIDCBody(idp, "shared-redirect.com", "shared-test", "shared-test", "shared-test-secret", true), nil)
			ru, _ := r.m()["redirectURI"].(string)
			o1Eq(t, "redirectURI", ru, env.baseURL+"/sso/callback")
			o1NotContains(t, ru, "shared-test")
		})

		t.Run("should use shared redirect URI in authorization URL", func(t *testing.T) {
			u, _ := o1SignInSSO(t, env, map[string]any{"email": "user@shared-redirect.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback"))
			o1NotContains(t, u, o1RedirectParam(env, "/sso/callback/shared-test"))
		})

		t.Run("should complete OIDC flow using shared callback endpoint", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"email": "user@shared-redirect.com", "callbackURL": "/dashboard"})
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
			o1Eq(t, "email", o1SessionEmail(t, env, flow.Headers), "shared-redirect@test.com")
		})
	})
}

// ---- describe("OIDC SSO with defaultSSO array") ----

func TestOIDCDefaultSSOArray(t *testing.T) {
	t.Run("OIDC SSO with defaultSSO array", func(t *testing.T) {
		idp := newMockOIDC(t)
		env := newEnv(t, Options{DefaultSSO: []DefaultSSOProvider{
			{Domain: "default-oidc.com", ProviderID: "default-oidc-provider", OIDCConfig: &OIDCConfig{
				Issuer: idp.URL, ClientID: "default-client", ClientSecret: "default-secret", PKCE: false,
				DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration",
			}},
			{Domain: "default-oidc-explicit.com", ProviderID: "default-oidc-provider-explicit", OIDCConfig: &OIDCConfig{
				Issuer: idp.URL, ClientID: "explicit-client", ClientSecret: "explicit-secret", PKCE: false,
				AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JwksEndpoint: idp.URL + "/jwks",
				DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration",
			}},
			{Domain: "https://default-oidc-normalized.com/path,default-oidc-secondary.com", ProviderID: "default-oidc-provider-normalized", OIDCConfig: &OIDCConfig{
				Issuer: idp.URL, ClientID: "normalized-client", ClientSecret: "normalized-secret", PKCE: false,
				AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JwksEndpoint: idp.URL + "/jwks",
				DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration",
			}},
		}}, o1WithOrg(o1TrustIdP(idp.URL)))

		var mu sync.Mutex
		currentEmail := "default-sso-user@default-oidc.com"
		currentSub := "default-sso-sub"
		idp.BeforeUserinfo = func(r *mockResponse, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			r.Body = map[string]any{"email": currentEmail, "name": "Default SSO User", "sub": currentSub,
				"picture": "https://test.com/default.png", "email_verified": true}
			r.StatusCode = 200
		}
		idp.BeforeTokenSigning = func(p map[string]any, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			isExplicit := p["aud"] == "explicit-client"
			isNormalized := p["aud"] == "normalized-client"
			switch {
			case isNormalized:
				currentEmail, currentSub = "default-sso-user@default-oidc-secondary.com", "normalized-sso-sub"
			case isExplicit:
				currentEmail, currentSub = "default-sso-user@default-oidc-explicit.com", "explicit-sso-sub"
			default:
				currentEmail, currentSub = "default-sso-user@default-oidc.com", "default-sso-sub"
			}
			p["email"] = currentEmail
			p["email_verified"] = true
			p["name"] = "Default SSO User"
			p["picture"] = "https://test.com/default.png"
			p["sub"] = currentSub
		}

		t.Run("should sign in via defaultSSO OIDC using providerId (discovery resolves endpoints)", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"providerId": "default-oidc-provider", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/default-oidc-provider"))
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
			o1Eq(t, "email", o1SessionEmail(t, env, flow.Headers), "default-sso-user@default-oidc.com")
		})

		t.Run("should sign in via defaultSSO OIDC using email domain matching", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"email": "someone@default-oidc.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
		})

		t.Run("should sign in via defaultSSO OIDC using normalized domain matching", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"email": "someone@default-oidc-secondary.com", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/default-oidc-provider-normalized"))
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
			o1Eq(t, "email", o1SessionEmail(t, env, flow.Headers), "default-sso-user@default-oidc-secondary.com")
		})

		t.Run("should sign in via defaultSSO OIDC with all endpoints explicit (no discovery needed)", func(t *testing.T) {
			u, h := o1SignInSSO(t, env, map[string]any{"providerId": "default-oidc-provider-explicit", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			o1Contains(t, u, o1RedirectParam(env, "/sso/callback/default-oidc-provider-explicit"))
			flow := env.simulateOAuthFlow(u, h)
			o1Contains(t, flow.CallbackURL, "/dashboard")
			o1Eq(t, "email", o1SessionEmail(t, env, flow.Headers), "default-sso-user@default-oidc-explicit.com")
		})
	})
}

// ---- describe("OIDC SSO with private_key_jwt") ----

func TestOIDCPrivateKeyJWT(t *testing.T) {
	t.Run("OIDC SSO with private_key_jwt", func(t *testing.T) {
		idp := newMockOIDC(t)
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		privJWK, _ := jose.JWKFromPrivateKey(key)
		var privateJwk map[string]any
		raw, _ := json.Marshal(privJWK)
		_ = json.Unmarshal(raw, &privateJwk)

		var mu sync.Mutex
		var resolveCalls []ResolvePrivateKeyParams
		var nextEmpty bool
		env := newEnv(t, Options{ResolvePrivateKey: func(_ context.Context, p ResolvePrivateKeyParams) (*PrivateKey, error) {
			mu.Lock()
			defer mu.Unlock()
			resolveCalls = append(resolveCalls, p)
			if nextEmpty {
				nextEmpty = false
				return &PrivateKey{}, nil
			}
			return &PrivateKey{PrivateKeyJWK: privateJwk, Kid: p.KeyID, Algorithm: "RS256"}, nil
		}}, o1WithOrg(o1TrustIdP(idp.URL)))
		o1SetUserinfo(idp, map[string]any{"email": "jwt-auth-user@private-key-jwt.com", "name": "Private Key JWT User",
			"sub": "private-key-jwt-sub", "picture": "https://test.com/private-key-jwt.png", "email_verified": true})
		o1SetClaims(idp, map[string]any{"email": "jwt-auth-user@private-key-jwt.com", "email_verified": true,
			"name": "Private Key JWT User", "picture": "https://test.com/private-key-jwt.png", "sub": "private-key-jwt-sub"})

		h := env.signInTestUser()
		body := o1OIDCBody(idp, "private-key-jwt.com", "private-key-jwt-provider", "private-key-jwt-client", "", true)
		cfg := body["oidcConfig"].(map[string]any)
		delete(cfg, "clientSecret")
		cfg["tokenEndpointAuthentication"] = "private_key_jwt"
		cfg["privateKeyId"] = "private-key-jwt-key"
		cfg["privateKeyAlgorithm"] = "RS256"
		env.mustAPI("registerSSOProvider", h, body, nil)

		t.Run("should sign in using private_key_jwt and resolvePrivateKey", func(t *testing.T) {
			mu.Lock()
			resolveCalls = nil
			mu.Unlock()
			idp.mu.Lock()
			idp.TokenRequests = nil
			idp.mu.Unlock()
			u, sh := o1SignInSSO(t, env, map[string]any{"providerId": "private-key-jwt-provider", "callbackURL": "/dashboard"})
			o1Contains(t, u, idp.URL+"/authorize")
			flow := env.simulateOAuthFlow(u, sh)
			o1Contains(t, flow.CallbackURL, "/dashboard")

			want := ResolvePrivateKeyParams{ProviderID: "private-key-jwt-provider", KeyID: "private-key-jwt-key", Issuer: idp.URL}
			found := false
			for _, c := range resolveCalls {
				if c == want {
					found = true
				}
			}
			if !found {
				t.Errorf("resolvePrivateKey calls %+v, want %+v", resolveCalls, want)
			}
			idp.mu.Lock()
			reqs := idp.TokenRequests
			idp.mu.Unlock()
			if len(reqs) == 0 {
				t.Fatal("no token request captured")
			}
			tokenReq := reqs[len(reqs)-1]
			if tokenReq.Get("client_assertion") == "" {
				t.Fatal("client_assertion missing")
			}
			o1Eq(t, "client_assertion_type", tokenReq.Get("client_assertion_type"), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			o1Eq(t, "client_id", tokenReq.Get("client_id"), "private-key-jwt-client")
			if _, ok := tokenReq["client_secret"]; ok {
				t.Errorf("client_secret should be undefined")
			}
			pub, _ := jose.JWKFromPublicKey(&key.PublicKey)
			pub.Kid, pub.Alg, pub.Use = "private-key-jwt-key", "RS256", "sig"
			_, payload, err := jose.VerifyJWT(tokenReq.Get("client_assertion"), jose.KeySetFunc(jose.JWKS{Keys: []jose.JWK{pub}}),
				jose.VerifyOptions{Algorithms: []string{"RS256"}, Audience: []string{idp.URL + "/token"}})
			if err != nil {
				t.Fatalf("jwtVerify: %v", err)
			}
			iss, _ := payload.Get("iss")
			sub, _ := payload.Get("sub")
			o1Eq(t, "iss", iss, "private-key-jwt-client")
			o1Eq(t, "sub", sub, "private-key-jwt-client")
			o1Eq(t, "email", o1SessionEmail(t, env, flow.Headers), "jwt-auth-user@private-key-jwt.com")
		})

		t.Run("should redirect with no_private_key_available when resolvePrivateKey returns no key material", func(t *testing.T) {
			mu.Lock()
			nextEmpty = true
			mu.Unlock()
			u, sh := o1SignInSSO(t, env, map[string]any{"providerId": "private-key-jwt-provider", "callbackURL": "/dashboard"})
			flow := env.simulateOAuthFlow(u, sh)
			o1Contains(t, flow.CallbackURL, "error_description=no_private_key_available")
		})
	})
}

// ---- describe("SSO OIDC UserInfo endpoint sub claim mapping") ----

func TestOIDCUserInfoSubClaimMapping(t *testing.T) {
	t.Run("SSO OIDC UserInfo endpoint sub claim mapping", func(t *testing.T) {
		idp := newMockOIDC(t)
		env := newEnv(t, Options{}, o1WithOrg(o1TrustIdP(idp.URL)))
		o1SetUserinfo(idp, map[string]any{"sub": "userinfo-only-sub-id", "email": "userinfo-only@test.com", "name": "UserInfo Only User",
			"picture": "https://test.com/picture.png", "email_verified": true})
		idp.BeforeResponse = func(resp *mockResponse, _ *http.Request) {
			if m, ok := resp.Body.(map[string]any); ok {
				delete(m, "id_token")
			}
		}
		idp.BeforeTokenSigning = func(map[string]any, *http.Request) {}

		t.Run("should sign in successfully using sub claim from UserInfo endpoint when no ID token is returned", func(t *testing.T) {
			h := env.signInTestUser()
			body := o1OIDCBody(idp, "test.com", "userinfo-sub-test", "test", "test", false)
			body["oidcConfig"].(map[string]any)["userInfoEndpoint"] = idp.URL + "/userinfo"
			env.mustAPI("registerSSOProvider", h, body, nil)
			u, sh := o1SignInSSO(t, env, map[string]any{"email": "user@test.com", "callbackURL": "/dashboard"})
			flow := env.simulateOAuthFlow(u, sh)
			o1Contains(t, flow.CallbackURL, "/dashboard")
			o1NotContains(t, flow.CallbackURL, "error=invalid_provider")
			o1NotContains(t, flow.CallbackURL, "missing_user_info")
			o1Eq(t, "email", o1SessionEmail(t, env, flow.Headers), "userinfo-only@test.com")
		})

		expectErr := func(t *testing.T, r *result, status int, code string) {
			t.Helper()
			if r.Err == nil {
				t.Fatalf("expected rejection, got %d %s", r.Status, r.Raw)
			}
			if status != 0 {
				o1Eq(t, "status", r.Status, status)
			}
			o1Eq(t, "code", r.code(), code)
		}
		skipDisc := func(domain, pid string, extra map[string]any) map[string]any {
			cfg := map[string]any{"clientId": "test", "clientSecret": "test", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/jwks"}
			for k, v := range extra {
				cfg[k] = v
			}
			return map[string]any{"issuer": idp.URL, "domain": domain, "providerId": pid, "oidcConfig": cfg}
		}

		t.Run("skipDiscovery SSRF protection (registerSSOProvider)", func(t *testing.T) {
			t.Run("should reject registration when tokenEndpoint points to a non-publicly-routable host", func(t *testing.T) {
				h := env.signInTestUser()
				r := env.api("registerSSOProvider", h, skipDisc("ssrf-token.com", "ssrf-token-endpoint",
					map[string]any{"tokenEndpoint": "http://169.254.169.254/latest/meta-data/"}), nil)
				expectErr(t, r, 400, "discovery_private_host")
			})

			t.Run("should reject registration when userInfoEndpoint points to a cloud metadata host", func(t *testing.T) {
				h := env.signInTestUser()
				r := env.api("registerSSOProvider", h, skipDisc("ssrf-userinfo.com", "ssrf-userinfo-endpoint",
					map[string]any{"userInfoEndpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}), nil)
				expectErr(t, r, 400, "discovery_private_host")
			})

			t.Run("should reject registration when jwksEndpoint points to a loopback port not in trustedOrigins", func(t *testing.T) {
				h := env.signInTestUser()
				r := env.api("registerSSOProvider", h, skipDisc("ssrf-jwks.com", "ssrf-jwks-endpoint",
					map[string]any{"jwksEndpoint": "http://localhost:6379/"}), nil)
				expectErr(t, r, 400, "discovery_private_host")
			})

			t.Run("should reject registration when an endpoint is not a valid URL", func(t *testing.T) {
				h := env.signInTestUser()
				r := env.api("registerSSOProvider", h, skipDisc("ssrf-invalid.com", "ssrf-invalid-url",
					map[string]any{"tokenEndpoint": "not-a-url"}), nil)
				expectErr(t, r, 0, "VALIDATION_ERROR")
			})

			t.Run("should reject registration when an endpoint uses a non-http(s) protocol", func(t *testing.T) {
				h := env.signInTestUser()
				r := env.api("registerSSOProvider", h, skipDisc("ssrf-protocol.com", "ssrf-bad-protocol",
					map[string]any{"tokenEndpoint": "file:///etc/passwd"}), nil)
				expectErr(t, r, 400, "discovery_invalid_url")
			})

			t.Run("should accept registration when endpoints match a trustedOrigins entry", func(t *testing.T) {
				h := env.signInTestUser()
				r := env.api("registerSSOProvider", h, skipDisc("ssrf-trusted.com", "ssrf-trusted-endpoints",
					map[string]any{"userInfoEndpoint": idp.URL + "/userinfo"}), nil)
				if r.Err != nil {
					t.Fatalf("register: %d %s", r.Status, r.Raw)
				}
				o1Eq(t, "providerId", r.m()["providerId"], "ssrf-trusted-endpoints")
			})

			t.Run("should reject registration when oidcConfig endpoints point to a private host even without skipDiscovery", func(t *testing.T) {
				h := env.signInTestUser()
				r := env.api("registerSSOProvider", h, map[string]any{
					"issuer": idp.URL, "domain": "ssrf-override.com", "providerId": "ssrf-override-endpoint",
					"oidcConfig": map[string]any{"clientId": "test", "clientSecret": "test", "tokenEndpoint": "http://169.254.169.254/token"},
				}, nil)
				expectErr(t, r, 400, "discovery_private_host")
			})
		})

		t.Run("OIDC endpoint SSRF protection (updateSSOProvider)", func(t *testing.T) {
			t.Run("should reject update when oidcConfig contains a link-local endpoint", func(t *testing.T) {
				h := env.signInTestUser()
				p := env.mustAPI("registerSSOProvider", h, skipDisc("ssrf-update-target.com", "ssrf-update-target", nil), nil)
				r := env.api("updateSSOProvider", h, map[string]any{"providerId": p.m()["providerId"],
					"oidcConfig": map[string]any{"userInfoEndpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}, nil)
				expectErr(t, r, 400, "discovery_private_host")
			})

			t.Run("should reject update when oidcConfig contains an invalid URL", func(t *testing.T) {
				h := env.signInTestUser()
				p := env.mustAPI("registerSSOProvider", h, skipDisc("ssrf-update-invalid.com", "ssrf-update-invalid", nil), nil)
				r := env.api("updateSSOProvider", h, map[string]any{"providerId": p.m()["providerId"],
					"oidcConfig": map[string]any{"tokenEndpoint": "not-a-url"}}, nil)
				expectErr(t, r, 0, "VALIDATION_ERROR")
			})

			t.Run("should accept update when oidcConfig endpoints are trusted", func(t *testing.T) {
				h := env.signInTestUser()
				p := env.mustAPI("registerSSOProvider", h, skipDisc("ssrf-update-trusted.com", "ssrf-update-trusted", nil), nil)
				r := env.api("updateSSOProvider", h, map[string]any{"providerId": p.m()["providerId"],
					"oidcConfig": map[string]any{"userInfoEndpoint": idp.URL + "/userinfo"}}, nil)
				if r.Err != nil {
					t.Fatalf("update: %d %s", r.Status, r.Raw)
				}
				o1Eq(t, "providerId", r.m()["providerId"], "ssrf-update-trusted")
			})
		})
	})
}

// ---- describe("SSO OIDC hook rejection redirect") ----

func TestOIDCHookRejectionRedirect(t *testing.T) {
	t.Run("SSO OIDC hook rejection redirect", func(t *testing.T) {
		hookServer := newMockOIDC(t)
		o1SetUserinfo(hookServer, map[string]any{"email": "rejected@test.com", "name": "Rejected User", "sub": "rejected-sub", "email_verified": true})
		o1SetClaims(hookServer, map[string]any{"sub": "rejected-sub", "email": "rejected@test.com", "email_verified": true})
		env := newEnv(t, Options{}, envConfig{mutate: func(c *betterauth.Config) {
			c.TrustedOrigins = []string{hookServer.URL, "https://frontend.example.com"}
			c.DatabaseHooks = &betterauth.DatabaseHooks{Session: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				Before: func(ctx context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
					ec := betterauth.EndpointContextFrom(ctx)
					if ec == nil {
						return nil, nil
					}
					uid, _ := data["userId"].(string)
					user, _ := ec.Auth.InternalAdapter.FindUserByID(ctx, uid)
					if user != nil && user.Email == "rejected@test.com" {
						return nil, betterauth.NewAPIError("FORBIDDEN", jsonx.O("code", "HOOK_REJECTED", "message", "SSO hook rejected this user"))
					}
					return nil, nil
				},
			}}}
		}})

		t.Run("should preserve the errorCallbackURL query and fragment when a session hook throws", func(t *testing.T) {
			admin := env.signInTestUser()
			body := o1OIDCBody(hookServer, "hook-reject.com", "hook-reject", "test", "test", false)
			body["oidcConfig"].(map[string]any)["mapping"] = map[string]any{"email": "email", "emailVerified": "email_verified", "name": "name"}
			env.mustAPI("registerSSOProvider", admin, body, nil)
			u, sh := o1SignInSSO(t, env, map[string]any{"providerId": "hook-reject", "callbackURL": "https://frontend.example.com/dashboard",
				"errorCallbackURL": "https://frontend.example.com/auth-error?source=sso#retry"})
			flow := env.simulateOAuthFlow(u, sh)
			cu, err := url.Parse(flow.CallbackURL)
			if err != nil {
				t.Fatal(err)
			}
			o1Eq(t, "origin", cu.Scheme+"://"+cu.Host, "https://frontend.example.com")
			o1Eq(t, "pathname", cu.Path, "/auth-error")
			o1Eq(t, "source", cu.Query().Get("source"), "sso")
			o1Eq(t, "error", cu.Query().Get("error"), "HOOK_REJECTED")
			o1Eq(t, "error_description", cu.Query().Get("error_description"), "SSO hook rejected this user")
			o1Eq(t, "hash", "#"+cu.Fragment, "#retry")
		})
	})
}

// ---- describe("SSO OIDC IDP-initiated bounce") ----

func TestOIDCIdpInitiatedBounce(t *testing.T) {
	t.Run("SSO OIDC IDP-initiated bounce", func(t *testing.T) {
		idp := newMockOIDC(t)
		env := newEnv(t, Options{DefaultSSO: []DefaultSSOProvider{
			{Domain: "idp-initiated.com", ProviderID: "idp-initiated", OIDCConfig: &OIDCConfig{
				Issuer: idp.URL, ClientID: "idp-initiated-client", ClientSecret: "idp-initiated-secret", PKCE: true,
				DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration", AllowIdpInitiated: true,
			}},
			{Domain: "strict-oidc.com", ProviderID: "strict-oidc", OIDCConfig: &OIDCConfig{
				Issuer: idp.URL, ClientID: "strict-client", ClientSecret: "strict-secret", PKCE: true,
				DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration",
			}},
		}}, o1TrustIdP(idp.URL))

		t.Run("should bounce a stateless OIDC callback to the provider's authorize endpoint when allowIdpInitiated is true", func(t *testing.T) {
			r := env.do("GET", "/sso/callback/idp-initiated?code=idp-issued-code", nil, nil)
			o1Eq(t, "status", r.Status, 302)
			loc := r.location()
			o1Contains(t, loc, idp.URL+"/authorize")
			lu, _ := url.Parse(loc)
			if lu.Query().Get("state") == "" {
				t.Errorf("expected state")
			}
			o1Eq(t, "client_id", lu.Query().Get("client_id"), "idp-initiated-client")
			if lu.Query().Has("code") {
				t.Errorf("code should be null")
			}
		})

		t.Run("should not bounce when the `code` parameter is empty", func(t *testing.T) {
			r := env.do("GET", "/sso/callback/idp-initiated?code=", nil, nil)
			o1Eq(t, "status", r.Status, 302)
			o1NotContains(t, r.location(), idp.URL+"/authorize")
		})

		t.Run("should not bounce on an empty `state=` parameter, only on truly stateless callbacks", func(t *testing.T) {
			r := env.do("GET", "/sso/callback/idp-initiated?code=idp-issued-code&state=", nil, nil)
			o1Eq(t, "status", r.Status, 302)
			o1NotContains(t, r.location(), idp.URL+"/authorize")
			o1Contains(t, r.location(), "state_not_found")
		})

		t.Run("should carry ssoProviderId in the bounced state when options.redirectURI is configured", func(t *testing.T) {
			shared := newEnv(t, Options{RedirectURI: "/sso/callback", DefaultSSO: []DefaultSSOProvider{
				{Domain: "idp-initiated-shared.com", ProviderID: "idp-initiated-shared", OIDCConfig: &OIDCConfig{
					Issuer: idp.URL, ClientID: "idp-initiated-shared-client", ClientSecret: "idp-initiated-shared-secret", PKCE: true,
					DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration", AllowIdpInitiated: true,
				}},
			}}, o1TrustIdP(idp.URL))
			r := shared.do("GET", "/sso/callback/idp-initiated-shared?code=idp-issued-code", nil, nil)
			o1Eq(t, "status", r.Status, 302)
			loc := r.location()
			o1Contains(t, loc, idp.URL+"/authorize")
			lu, _ := url.Parse(loc)
			o1Eq(t, "redirect_uri", lu.Query().Get("redirect_uri"), shared.baseURL+"/sso/callback")
			state := lu.Query().Get("state")
			if state == "" {
				t.Fatal("expected state")
			}
			v, err := shared.auth.Context().InternalAdapter.FindVerificationValue(context.Background(), "auth-state:"+state)
			if err != nil || v == nil {
				t.Fatalf("verification: %v %v", v, err)
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v.Value), &parsed); err != nil {
				t.Fatal(err)
			}
			sc, _ := parsed["serverContext"].(map[string]any)
			ref, _ := sc["ssoProviderReference"].(map[string]any)
			o1Eq(t, "serverContext.ssoProviderReference.providerId", ref["providerId"], "idp-initiated-shared")
			if _, ok := parsed["ssoProviderId"]; ok {
				t.Errorf("ssoProviderId should be undefined")
			}
		})

		t.Run("should redirect to the error page for providers without the flag", func(t *testing.T) {
			r := env.do("GET", "/sso/callback/strict-oidc?code=idp-issued-code", nil, nil)
			o1Eq(t, "status", r.Status, 302)
			o1Contains(t, r.location(), "state_not_found")
		})
	})
}

// ---- oidc/id-token.test.ts: describe("OIDC authorized party validation") ----

func TestOIDCAuthorizedPartyValidation(t *testing.T) {
	t.Run("OIDC authorized party validation", func(t *testing.T) {
		t.Run("accepts the configured client as azp for a multi-audience token", func(t *testing.T) {
			err := assertOIDCAuthorizedParty(map[string]any{"aud": []any{"workforce-client", "api"}, "azp": "workforce-client"}, "workforce-client")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})

		cases := []struct {
			name    string
			payload map[string]any
		}{
			{"rejects { aud: [ 'workforce-client', 'api' ] } (missing azp)", map[string]any{"aud": []any{"workforce-client", "api"}}},
			{"rejects { aud: [ 'workforce-client', 'api' ], azp: 'another-client' } (incorrect azp)",
				map[string]any{"aud": []any{"workforce-client", "api"}, "azp": "another-client"}},
			{"rejects { aud: 'workforce-client', azp: 'another-client' } (incorrect azp)",
				map[string]any{"aud": "workforce-client", "azp": "another-client"}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				err := assertOIDCAuthorizedParty(c.payload, "workforce-client")
				if err == nil || !strings.Contains(err.Error(), "OIDC ID token authorized party does not match the client") {
					t.Fatalf("expected authorized party error, got %v", err)
				}
			})
		}
	})
}
