package sso

// Port of saml.test.ts (better-auth 1.7.7) lines 5638-end: "SAML Single Logout (SLO)"
// through "SAML SSO Hardening".

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"

	_ "modernc.org/sqlite"
)

// ---- shared helpers ----

const s3MockIdPEntityLiteral = "http://localhost:8081/api/sso/saml2/idp/metadata"

// s3MockIdentityProviderMetadata is mockIdentityProviderMetadata.
func s3MockIdentityProviderMetadata() map[string]any {
	return map[string]any{"entityID": s3MockIdPEntityLiteral}
}

// s3SLOIdPMetadata is sloIdpMetadata (http://localhost:8081 kept: no request reaches it).
var s3SLOIdPMetadata = `
		<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8081/api/sso/saml2/idp/metadata">
		<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
			<md:KeyDescriptor use="signing">
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<ds:X509Data>
				<ds:X509Certificate>` + certificate + `</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
			</md:KeyDescriptor>
			<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/api/sso/saml2/idp/slo"/>
			<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8081/api/sso/saml2/idp/slo"/>
			<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
			<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/api/sso/saml2/idp/post"/>
		</md:IDPSSODescriptor>
		</md:EntityDescriptor>
	`

var s3CertRe = regexp.MustCompile(`<ds:X509Certificate>([^<]+)</ds:X509Certificate>`)

// s3ExtractSigningCert is extractSigningCertificateFromMetadata.
func s3ExtractSigningCert(t *testing.T, metadata string) string {
	t.Helper()
	m := s3CertRe.FindStringSubmatch(metadata)
	if m == nil || strings.TrimSpace(m[1]) == "" {
		t.Fatal("IdP metadata does not contain a signing certificate")
	}
	return "-----BEGIN CERTIFICATE-----\n" + strings.TrimSpace(m[1]) + "\n-----END CERTIFICATE-----"
}

func s3Bool(b bool) *bool { return &b }

func s3MustRegister(t *testing.T, env *testEnv, headers http.Header, body map[string]any) {
	t.Helper()
	r := env.api("registerSSOProvider", headers, body, nil)
	if r.Err != nil {
		t.Fatalf("registerSSOProvider: %d %s %s", r.Status, r.code(), r.message())
	}
}

// s3Form posts form values through the handler without an Origin header.
func s3Form(env *testEnv, path string, headers http.Header, form url.Values) *result {
	env.t.Helper()
	return env.postForm(path, headers, form)
}

// s3SignIn calls auth.api.signInSSO (returnHeaders) and returns the IdP URL and cookies.
func s3SignIn(t *testing.T, env *testEnv, body map[string]any) (string, http.Header, *result) {
	t.Helper()
	r := env.api("signInSSO", nil, body, nil)
	if r.Err != nil {
		t.Fatalf("signInSSO: %d %s %s", r.Status, r.code(), r.message())
	}
	u, _ := r.m()["url"].(string)
	return u, cookieHeaders(r.Headers), r
}

// s3ACS calls auth.api.acsEndpoint (asResponse).
func s3ACS(env *testEnv, providerID string, headers http.Header, body map[string]any) *result {
	env.t.Helper()
	return env.apiIn("acsEndpoint", betterauth.CallInput{Method: "POST", Headers: headers, Body: body, Params: map[string]string{"providerId": providerID}})
}

func s3RelayState(t *testing.T, signInURL string) string {
	t.Helper()
	u, err := url.Parse(signInURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("RelayState")
}

func s3SetCookies(h http.Header) string { return strings.Join(h.Values("Set-Cookie"), ";") }

// s3ResolveLocation is new URL(location, base).
func s3ResolveLocation(t *testing.T, location, base string) *url.URL {
	t.Helper()
	b, _ := url.Parse(base)
	u, err := b.Parse(location)
	if err != nil {
		t.Fatalf("bad location %q", location)
	}
	return u
}

func s3Origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

// ---- SAML Single Logout (SLO) ----

func TestSAML3SingleLogout(t *testing.T) {
	sloRegister := func(t *testing.T, env *testEnv, h http.Header, providerID, domain string, samlCfg map[string]any) {
		t.Helper()
		s3MustRegister(t, env, h, map[string]any{"providerId": providerID, "issuer": "http://localhost:8081", "domain": domain, "samlConfig": samlCfg})
	}
	logoutReq := func(t *testing.T, env *testEnv, path string) *result {
		t.Helper()
		return s3Form(env, path, nil, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte("<LogoutRequest/>"))}})
	}
	sloEnabled := Options{SAML: &SAMLOptions{EnableSingleLogout: true}}

	t.Run("SLO disabled", func(t *testing.T) {
		t.Run("should return error when enableSingleLogout is not enabled", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			sloRegister(t, env, h, "slo-disabled-test", "slo-disabled.com", map[string]any{
				"entryPoint": "http://localhost:8081/sso", "cert": certificate,
				"idpMetadata": s3MockIdentityProviderMetadata(), "spMetadata": map[string]any{"metadata": spMetadata},
			})
			res := logoutReq(t, env, "/sso/saml2/sp/slo/slo-disabled-test")
			if res.Status != 400 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if !strings.Contains(res.message(), "Single Logout is not enabled") {
				t.Fatalf("message %q", res.message())
			}
		})
	})

	t.Run("SLO enabled - error cases", func(t *testing.T) {
		t.Run("should return error when provider not found", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			res := logoutReq(t, env, "/sso/saml2/sp/slo/nonexistent-provider")
			if res.Status != 404 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if !strings.Contains(res.message(), "SAML provider not found") {
				t.Fatalf("message %q", res.message())
			}
		})

		t.Run("should allow SLO POST from external IdP origin (CSRF bypass)", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			h := env.signInTestUser()
			sloRegister(t, env, h, "slo-origin-bypass", "slo-origin.com", map[string]any{
				"entryPoint": "http://localhost:8081/sso", "cert": certificate,
				"idpMetadata": s3MockIdentityProviderMetadata(), "spMetadata": map[string]any{"metadata": spMetadata},
			})
			hh := http.Header{"Origin": {"http://external-idp.example.com"}, "Cookie": {h.Get("Cookie")}}
			res := s3Form(env, "/sso/saml2/sp/slo/slo-origin-bypass", hh, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte("<LogoutRequest/>"))}})
			if res.Status == 403 {
				t.Fatalf("status 403 %s", res.Raw)
			}
		})
	})

	t.Run("SP Metadata - SingleLogoutService", func(t *testing.T) {
		t.Run("should include SingleLogoutService when SLO is enabled", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			h := env.signInTestUser()
			sloRegister(t, env, h, "slo-metadata-test", "slo-metadata.com", map[string]any{
				"entryPoint": "http://localhost:8081/sso", "cert": certificate,
				"idpMetadata": s3MockIdentityProviderMetadata(), "spMetadata": map[string]any{"entityID": "http://localhost:8081/sp"},
			})
			r := env.api("spMetadata", nil, nil, map[string]any{"providerId": "slo-metadata-test"})
			xml := string(r.Raw)
			for _, want := range []string{"SingleLogoutService", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "/sso/saml2/sp/slo/slo-metadata-test"} {
				if !strings.Contains(xml, want) {
					t.Fatalf("metadata missing %q:\n%s", want, xml)
				}
			}
		})

		t.Run("should NOT include SingleLogoutService when SLO is disabled", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			sloRegister(t, env, h, "slo-metadata-disabled", "slo-metadata-disabled.com", map[string]any{
				"entryPoint": "http://localhost:8081/sso", "cert": certificate,
				"idpMetadata": s3MockIdentityProviderMetadata(), "spMetadata": map[string]any{"entityID": "http://localhost:8081/sp"},
			})
			r := env.api("spMetadata", nil, nil, map[string]any{"providerId": "slo-metadata-disabled"})
			if strings.Contains(string(r.Raw), "SingleLogoutService") {
				t.Fatalf("metadata contains SingleLogoutService:\n%s", r.Raw)
			}
		})
	})

	t.Run("SP-initiated SLO (initiateSLO)", func(t *testing.T) {
		t.Run("should return error when IdP has no SLO service configured", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			h := env.signInTestUser()
			sloRegister(t, env, h, "sp-slo-no-idp-slo", "sp-slo-no-idp.com", map[string]any{
				"entryPoint": "http://localhost:8081/sso", "cert": certificate,
				"idpMetadata": s3MockIdentityProviderMetadata(), "spMetadata": map[string]any{"metadata": spMetadata},
			})
			res := env.do("POST", "/sso/saml2/logout/sp-slo-no-idp-slo", http.Header{"Cookie": {h.Get("Cookie")}},
				map[string]any{"callbackURL": "http://localhost:8081/logged-out"})
			if res.Status != 400 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if !strings.Contains(res.message(), "IdP does not support Single Logout Service") {
				t.Fatalf("message %q", res.message())
			}
		})

		t.Run("should generate LogoutRequest and redirect to IdP", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			h := env.signInTestUser()
			sloRegister(t, env, h, "sp-slo-initiate", "sp-slo-initiate.com", map[string]any{
				"entryPoint": "http://localhost:8081/sso", "cert": certificate,
				"spMetadata": map[string]any{"metadata": spMetadata}, "idpMetadata": map[string]any{"metadata": s3SLOIdPMetadata},
			})
			res := env.do("POST", "/sso/saml2/logout/sp-slo-initiate", http.Header{"Cookie": {h.Get("Cookie")}},
				map[string]any{"callbackURL": "http://localhost:8081/logged-out"})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			loc := res.location()
			if !strings.Contains(loc, "http://localhost:8081/api/sso/saml2/idp/slo") || !strings.Contains(loc, "SAMLRequest=") {
				t.Fatalf("location %q", loc)
			}
			if s := env.session(h); s != nil {
				t.Fatalf("session still active: %+v", s)
			}
		})
	})

	idpAndSP := func(t *testing.T, sloLocation string) (*samlify.Entity, *samlify.Entity) {
		t.Helper()
		idp, err := samlify.IdentityProvider(samlify.Setting{Metadata: s3SLOIdPMetadata, PrivateKey: idPk, PrivateKeyPass: "jXmKf9By6ruLnUdRo90G"})
		if err != nil {
			t.Fatal(err)
		}
		sp, err := samlify.ServiceProvider(samlify.Setting{
			EntityID:                 "http://localhost:8081",
			AssertionConsumerService: []samlify.Service{{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "http://localhost:8081/callback"}},
			SingleLogoutService:      []samlify.Service{{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: sloLocation}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return idp, sp
	}
	registerIdPSLO := func(t *testing.T, env *testEnv, h http.Header, providerID, domain string) {
		t.Helper()
		s3MustRegister(t, env, h, map[string]any{
			"providerId": providerID, "issuer": s3MockIdPEntityLiteral, "domain": domain,
			"samlConfig": map[string]any{
				"entryPoint": "http://localhost:8081/api/sso/saml2/idp/post", "cert": certificate,
				"spMetadata": map[string]any{"metadata": spMetadata}, "idpMetadata": map[string]any{"metadata": s3SLOIdPMetadata},
			},
		})
	}

	t.Run("IdP-initiated SLO (LogoutRequest)", func(t *testing.T) {
		t.Run("should process valid LogoutRequest and return LogoutResponse", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			h := env.signInTestUser()
			sloLocation := env.baseURL + "/sso/saml2/sp/slo/idp-slo-test"
			registerIdPSLO(t, env, h, "idp-slo-test", "idp-slo.com")
			idp, sp := idpAndSP(t, sloLocation)
			lr, err := idp.CreateLogoutRequest(sp, samlify.BindingRedirect, samlify.LogoutUser{LogoutNameID: "test@email.com"}, "http://localhost:8081/after-logout")
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(lr.Context)
			target := sloLocation + "?SAMLRequest=" + url.QueryEscape(u.Query().Get("SAMLRequest")) + "&RelayState=" + url.QueryEscape(u.Query().Get("RelayState"))
			res := env.send(s3NewRequest(t, "GET", target, nil, ""))
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if !strings.Contains(res.location(), "SAMLResponse=") {
				t.Fatalf("location %q", res.location())
			}
		})
	})

	t.Run("LogoutResponse handling (SP-initiated flow completion)", func(t *testing.T) {
		t.Run("should process LogoutResponse and redirect to relayState", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			h := env.signInTestUser()
			sloLocation := env.baseURL + "/sso/saml2/sp/slo/logout-response-test"
			callbackURL := env.server.URL + "/logged-out"
			registerIdPSLO(t, env, h, "logout-response-test", "logout-response-test.com")
			idp, sp := idpAndSP(t, sloLocation)
			lr, err := idp.CreateLogoutResponse(sp, "", samlify.BindingRedirect, callbackURL)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(lr.Context)
			target := sloLocation + "?SAMLResponse=" + url.QueryEscape(u.Query().Get("SAMLResponse")) + "&RelayState=" + url.QueryEscape(u.Query().Get("RelayState"))
			res := env.send(s3NewRequest(t, "GET", target, nil, ""))
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if res.location() != callbackURL {
				t.Fatalf("location %q want %q", res.location(), callbackURL)
			}
			if sc := s3SetCookies(res.Headers); !strings.Contains(sc, "better-auth.session_token=;") {
				t.Fatalf("set-cookie %q", sc)
			}
		})

		t.Run("should redirect to baseURL when relayState is missing", func(t *testing.T) {
			env := newEnv(t, sloEnabled)
			h := env.signInTestUser()
			sloLocation := env.baseURL + "/sso/saml2/sp/slo/logout-no-relay"
			registerIdPSLO(t, env, h, "logout-no-relay", "logout-no-relay.com")
			idp, sp := idpAndSP(t, sloLocation)
			lr, err := idp.CreateLogoutResponse(sp, "", samlify.BindingRedirect, "")
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(lr.Context)
			target := sloLocation + "?SAMLResponse=" + url.QueryEscape(u.Query().Get("SAMLResponse"))
			res := env.send(s3NewRequest(t, "GET", target, nil, ""))
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if res.location() != env.server.URL {
				t.Fatalf("location %q want %q", res.location(), env.server.URL)
			}
		})
	})
}

func s3NewRequest(t *testing.T, method, target string, headers http.Header, body string) *http.Request {
	t.Helper()
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, target, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, target, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req
}

// ---- provisionUser ----

func s3ProvisionRegisterBody(idp *mockSAMLIdP, providerID string) map[string]any {
	return map[string]any{
		"providerId": providerID, "issuer": idp.URL, "domain": idp.URL,
		"samlConfig": map[string]any{
			"entryPoint": idp.URL + "/api/sso/saml2/idp/post", "cert": certificate,
			"wantAssertionsSigned": false, "signatureAlgorithm": "sha256", "digestAlgorithm": "sha256",
			"idpMetadata": map[string]any{"metadata": idp.MetadataXML}, "spMetadata": map[string]any{"metadata": spMetadata},
			"identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		},
	}
}

// s3SAMLSignInRoundTrip runs signInSSO -> mock IdP -> acsEndpoint.
func s3SAMLSignInRoundTrip(t *testing.T, env *testEnv, providerID, callbackURL string) *result {
	t.Helper()
	signInURL, cookies, _ := s3SignIn(t, env, map[string]any{"providerId": providerID, "callbackURL": callbackURL})
	resp, status, body := fetchSAMLResponse(t, signInURL)
	if status != 200 {
		t.Fatalf("idp: %d %v", status, body)
	}
	return s3ACS(env, providerID, cookies, map[string]any{"SAMLResponse": resp, "RelayState": s3RelayState(t, signInURL)})
}

func TestSAML3ProvisionUserOnlyForNewUsers(t *testing.T) {
	t.Run("SAML provisionUser should only be called for new users", func(t *testing.T) {
		var mu sync.Mutex
		provisionCalls := 0
		var validateCalls []betterauth.UserInfoSource
		idp := newMockSAMLIdP(t, mockSAMLOptions{})
		env := newEnv(t, Options{
			ProvisionUser: func(ctx context.Context, data ProvisionUserData) error {
				mu.Lock()
				provisionCalls++
				mu.Unlock()
				return nil
			},
			SAML: &SAMLOptions{EnableInResponseToValidation: s3Bool(false)},
		}, envConfig{mutate: func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ValidateUserInfo: func(ctx *betterauth.EndpointContext, user map[string]any, source betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
				if source.Method == "sso-saml" {
					mu.Lock()
					validateCalls = append(validateCalls, source)
					mu.Unlock()
				}
				return nil, nil
			}}
		}})
		t.Run("should call provisionUser only on first sign-in (new user), not on subsequent sign-ins", func(t *testing.T) {
			h := env.signInTestUser()
			env.api("registerSSOProvider", h, s3ProvisionRegisterBody(idp, "saml-provision-test"), nil)
			provisionCalls, validateCalls = 0, nil

			s3SAMLSignInRoundTrip(t, env, "saml-provision-test", "http://localhost:3000/dashboard")
			if provisionCalls != 1 {
				t.Fatalf("provisionUser calls = %d, want 1", provisionCalls)
			}
			if len(validateCalls) != 1 {
				t.Fatalf("validateUserInfo calls = %d, want 1", len(validateCalls))
			}
			v := validateCalls[0]
			if v.Action != "create-user" || v.Method != "sso-saml" || v.ProviderID != "saml-provision-test" {
				t.Fatalf("validate source[0] = %+v", v)
			}
			if v.Profile == nil {
				t.Fatalf("validate source[0].sso.profile undefined")
			}

			provisionCalls = 0
			s3SAMLSignInRoundTrip(t, env, "saml-provision-test", "http://localhost:3000/dashboard")
			if provisionCalls != 0 {
				t.Fatalf("provisionUser calls = %d, want 0", provisionCalls)
			}
			if len(validateCalls) != 2 {
				t.Fatalf("validateUserInfo calls = %d, want 2", len(validateCalls))
			}
			v = validateCalls[1]
			if v.Action != "sign-in" || v.Method != "sso-saml" || v.ProviderID != "saml-provision-test" {
				t.Fatalf("validate source[1] = %+v", v)
			}
			if v.Profile == nil {
				t.Fatalf("validate source[1].sso.profile undefined")
			}
		})
	})
}

func TestSAML3ProvisionUserOnEveryLogin(t *testing.T) {
	t.Run("SAML provisionUserOnEveryLogin should call provisionUser on every sign-in", func(t *testing.T) {
		var mu sync.Mutex
		calls := 0
		idp := newMockSAMLIdP(t, mockSAMLOptions{})
		env := newEnv(t, Options{
			ProvisionUser: func(ctx context.Context, data ProvisionUserData) error {
				mu.Lock()
				calls++
				mu.Unlock()
				return nil
			},
			ProvisionUserOnEveryLogin: true,
			SAML:                      &SAMLOptions{EnableInResponseToValidation: s3Bool(false)},
		})
		t.Run("should call provisionUser on both first and subsequent sign-ins", func(t *testing.T) {
			h := env.signInTestUser()
			env.api("registerSSOProvider", h, s3ProvisionRegisterBody(idp, "saml-provision-every-login"), nil)
			calls = 0
			s3SAMLSignInRoundTrip(t, env, "saml-provision-every-login", "http://localhost:3000/dashboard")
			if calls != 1 {
				t.Fatalf("first: provisionUser calls = %d, want 1", calls)
			}
			calls = 0
			s3SAMLSignInRoundTrip(t, env, "saml-provision-every-login", "http://localhost:3000/dashboard")
			if calls != 1 {
				t.Fatalf("second: provisionUser calls = %d, want 1", calls)
			}
		})
	})
}

// ---- E2E ----

func TestSAML3E2E(t *testing.T) {
	t.Run("SAML E2E: SP-initiated flow", func(t *testing.T) {
		t.Run("should complete the full flow: register, sign-in, ACS, user + session created", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			// Upstream passes a top-level `trustedProviders` option, which is not a Better
			// Auth option and has no effect.
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: s3Bool(false)}})
			h := env.signInTestUser()
			s3MustRegister(t, env, h, map[string]any{
				"providerId": "e2e-saml", "issuer": "https://sp.example.com/saml/e2e", "domain": "e2e.example.com",
				"samlConfig": map[string]any{
					"entryPoint": idp.URL + "/api/sso/saml2/idp/post", "cert": s3ExtractSigningCert(t, idp.MetadataXML),
					"idpMetadata":      map[string]any{"entityID": idp.URL + "/api/sso/saml2/idp/metadata"},
					"spMetadata":       map[string]any{"metadata": spMetadata},
					"identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				},
			})
			signInURL, cookies, r := s3SignIn(t, env, map[string]any{"providerId": "e2e-saml", "callbackURL": "/dashboard"})
			if !strings.Contains(signInURL, idp.URL) {
				t.Fatalf("url %q", signInURL)
			}
			if r.m()["redirect"] != true {
				t.Fatalf("redirect = %v", r.m()["redirect"])
			}
			resp, status, body := fetchSAMLResponse(t, signInURL)
			if status != 200 || resp == "" {
				t.Fatalf("idp: %d %v", status, body)
			}
			acs := s3ACS(env, "e2e-saml", cookies, map[string]any{"SAMLResponse": resp, "RelayState": s3RelayState(t, signInURL)})
			if acs.Status != 302 {
				t.Fatalf("acs status %d %s", acs.Status, acs.Raw)
			}
			loc := acs.location()
			if strings.Contains(loc, "error=") || !strings.Contains(loc, "/dashboard") {
				t.Fatalf("location %q", loc)
			}
			var ssoAccount map[string]any
			for _, a := range env.rows("account") {
				if a["providerId"] == "e2e-saml" {
					ssoAccount = a
				}
			}
			if ssoAccount == nil {
				t.Fatal("no sso account")
			}
			if ssoAccount["accountId"] != "test@email.com" {
				t.Fatalf("accountId %v", ssoAccount["accountId"])
			}
			var ssoUser map[string]any
			for _, u := range env.rows("user") {
				if u["id"] == ssoAccount["userId"] {
					ssoUser = u
				}
			}
			if ssoUser == nil || ssoUser["email"] != "test@email.com" {
				t.Fatalf("sso user %v", ssoUser)
			}
			var ssoSession map[string]any
			for _, s := range env.rows("session") {
				if s["userId"] == ssoUser["id"] {
					ssoSession = s
				}
			}
			if ssoSession == nil || ssoSession["expiresAt"] == nil {
				t.Fatalf("sso session %v", ssoSession)
			}
		})
	})
}

// ---- SAML user resolution HTTP ----

type s3URInstance struct {
	env              *testEnv
	idp              *mockSAMLIdP
	conn             *sql.DB
	providerOwnerID  string
	providerRecordID string
}

func s3PersistedSAMLConfiguration(t *testing.T, idp *mockSAMLIdP) map[string]any {
	return map[string]any{
		"issuer":           "https://service.example.com/saml",
		"entryPoint":       idp.URL + "/api/sso/saml2/idp/redirect",
		"cert":             s3ExtractSigningCert(t, idp.MetadataXML),
		"idpMetadata":      map[string]any{"entityID": idp.URL + "/api/sso/saml2/idp/metadata"},
		"spMetadata":       map[string]any{"metadata": spMetadata},
		"identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	}
}

func s3EncryptionCertBody() string {
	s := strings.NewReplacer("-----BEGIN CERTIFICATE-----", "", "-----END CERTIFICATE-----", "").Replace(certificate)
	return strings.Join(strings.Fields(s), "")
}

func s3StrictAssertionSigningConfiguration(t *testing.T, idp *mockSAMLIdP, encrypted bool) map[string]any {
	md := spMetadata
	if encrypted {
		md = s3CertRe.ReplaceAllLiteralString(md, "<ds:X509Certificate>"+s3EncryptionCertBody()+"</ds:X509Certificate>")
	}
	md = strings.Replace(md, `WantAssertionsSigned="false"`, `WantAssertionsSigned="true"`, 1)
	cfg := s3PersistedSAMLConfiguration(t, idp)
	cfg["idpMetadata"] = map[string]any{"entityID": idp.URL + "/api/sso/saml2/idp/metadata", "isAssertionEncrypted": encrypted}
	spm := map[string]any{"metadata": md, "isAssertionEncrypted": encrypted}
	if encrypted {
		spm["encPrivateKey"] = idpPrivateKey
		spm["encPrivateKeyPass"] = "q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW"
	}
	cfg["spMetadata"] = spm
	cfg["wantAssertionsSigned"] = true
	return cfg
}

func s3MetadataRequiredAssertionSigningConfiguration(t *testing.T, idp *mockSAMLIdP) map[string]any {
	cfg := s3StrictAssertionSigningConfiguration(t, idp, false)
	cfg["wantAssertionsSigned"] = false
	return cfg
}

func s3NumericAssertionSigningConfiguration(t *testing.T, idp *mockSAMLIdP, value string) map[string]any {
	cfg := s3PersistedSAMLConfiguration(t, idp)
	cfg["spMetadata"] = map[string]any{"metadata": strings.Replace(spMetadata, `WantAssertionsSigned="false"`, `WantAssertionsSigned="`+value+`"`, 1)}
	cfg["wantAssertionsSigned"] = false
	return cfg
}

// s3NewURInstance is createSAMLUserResolutionInstance (sqlite database, no test user).
func s3NewURInstance(t *testing.T, opts Options, mutate func(c *betterauth.Config), samlCfg func(idp *mockSAMLIdP) map[string]any) *s3URInstance {
	t.Helper()
	idp := newMockSAMLIdP(t, mockSAMLOptions{})
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
	env := newEnv(t, opts, envConfig{noTestUser: true, mutate: func(c *betterauth.Config) {
		c.Database = sqladapter.New(conn, sqladapter.Config{Dialect: sqladapter.SQLite, Transaction: betterauth.Bool(true)})
		if mutate != nil {
			mutate(c)
		}
		c.TrustedOrigins = []string{idp.URL}
	}})
	ctx := context.Background()
	if err := env.auth.RunMigrations(ctx); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	a := env.auth.Context().Adapter
	now := time.Now()
	owner, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{
		"email": "provider-owner-" + bacrypto.RandomUUID() + "@example.com", "emailVerified": true, "name": "Provider Owner",
		"image": nil, "createdAt": now, "updatedAt": now,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if samlCfg != nil {
		cfg = samlCfg(idp)
	} else {
		cfg = s3PersistedSAMLConfiguration(t, idp)
	}
	raw, _ := json.Marshal(cfg)
	rec, err := a.Create(ctx, adapter.CreateInput{Model: "ssoProvider", Data: adapter.Record{
		"issuer": "https://service.example.com/saml", "domain": "example.com", "oidcConfig": nil, "samlConfig": string(raw),
		"userId": owner["id"], "providerId": "workforce-saml", "organizationId": nil,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return &s3URInstance{env: env, idp: idp, conn: conn, providerOwnerID: fmt.Sprint(owner["id"]), providerRecordID: fmt.Sprint(rec["id"])}
}

func (in *s3URInstance) replaceConfig(t *testing.T, cfg map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	if _, err := in.env.auth.Context().Adapter.Update(context.Background(), "ssoProvider",
		[]adapter.Where{{Field: "id", Value: in.providerRecordID}}, adapter.Record{"samlConfig": string(raw)}); err != nil {
		t.Fatal(err)
	}
}

func (in *s3URInstance) count(t *testing.T, model string) int {
	t.Helper()
	n, err := in.env.auth.Context().Adapter.Count(context.Background(), model, nil)
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

func (in *s3URInstance) expectNoAuthenticationWrites(t *testing.T) {
	t.Helper()
	if n := in.count(t, "account"); n != 0 {
		t.Errorf("account count = %d, want 0", n)
	}
	if n := in.count(t, "session"); n != 0 {
		t.Errorf("session count = %d, want 0", n)
	}
}

func (in *s3URInstance) expectOneAccountAndSession(t *testing.T) {
	t.Helper()
	if n := in.count(t, "account"); n != 1 {
		t.Errorf("account count = %d, want 1", n)
	}
	if n := in.count(t, "session"); n != 1 {
		t.Errorf("session count = %d, want 1", n)
	}
}

type s3SignInState struct {
	cookies      http.Header
	samlResponse string
	relayState   string
}

func (in *s3URInstance) initiate(t *testing.T) *s3SignInState {
	t.Helper()
	base := in.env.server.URL
	r := in.env.do("POST", base+"/api/auth/sign-in/sso", http.Header{"Origin": {base}},
		map[string]any{"providerId": "workforce-saml", "callbackURL": base + "/employee"})
	if r.Status != 200 {
		t.Fatalf("sign-in status %d %s", r.Status, r.Raw)
	}
	u, _ := r.m()["url"].(string)
	resp, status, body := fetchSAMLResponse(t, u)
	if status != 200 {
		t.Fatalf("idp status %d %v", status, body)
	}
	return &s3SignInState{cookies: cookieHeaders(r.Headers), samlResponse: resp, relayState: s3RelayState(t, u)}
}

// submit is submitSAMLResponse; relayState nil uses the sign-in RelayState, a pointer to
// "\x00" omits it.
func (in *s3URInstance) submit(t *testing.T, s *s3SignInState, relayState *string) *result {
	t.Helper()
	form := url.Values{"SAMLResponse": {s.samlResponse}}
	if relayState == nil {
		form.Set("RelayState", s.relayState)
	} else if *relayState != "\x00" {
		form.Set("RelayState", *relayState)
	}
	h := http.Header{}
	if c := s.cookies.Get("Cookie"); c != "" {
		h.Set("Cookie", c)
	}
	res := in.env.postForm(in.env.server.URL+"/api/auth/sso/saml2/sp/acs/workforce-saml", h, form)
	s.cookies = mergeCookies(s.cookies, res.Headers)
	return res
}

func s3Decode(t *testing.T, b64 string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var s3SignatureRe = regexp.MustCompile(`(?s)<ds:Signature\b.*?</ds:Signature>`)

func s3RemoveResponseSignature(xml string) string {
	loc := s3SignatureRe.FindStringIndex(xml)
	if loc == nil {
		return xml
	}
	return xml[:loc[0]] + xml[loc[1]:]
}

func s3SignSAMLContent(t *testing.T, idp *mockSAMLIdP, xml string, assertion bool) string {
	t.Helper()
	o := samlify.SignatureOptions{
		PrivateKey: idPk, PrivateKeyPass: "jXmKf9By6ruLnUdRo90G",
		SignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		SigningCert:        samlify.NormalizeCerString(s3ExtractSigningCert(t, idp.MetadataXML)),
		AfterLocalName:     "Issuer",
	}
	if assertion {
		o.ReferenceLocalPath = []string{"Response", "Assertion"}
	}
	signed, err := samlify.ConstructSAMLSignature(xml, o)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(signed))
}

func s3EncryptSAMLContent(t *testing.T, idp *mockSAMLIdP, xml string) string {
	t.Helper()
	encSP := s3CertRe.ReplaceAllLiteralString(spMetadata, "<ds:X509Certificate>"+s3EncryptionCertBody()+"</ds:X509Certificate>")
	ip, err := samlify.IdentityProvider(samlify.Setting{Metadata: idp.MetadataXML, PrivateKey: idPk, PrivateKeyPass: "jXmKf9By6ruLnUdRo90G", IsAssertionEncrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := samlify.ServiceProvider(samlify.Setting{Metadata: encSP})
	if err != nil {
		t.Fatal(err)
	}
	out, err := samlify.EncryptAssertion(ip, sp, xml)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func s3ExpectLocation(t *testing.T, res *result, want string) {
	t.Helper()
	if res.Status != 302 {
		t.Fatalf("status %d %s", res.Status, res.Raw)
	}
	if res.location() != want {
		t.Fatalf("location %q want %q", res.location(), want)
	}
}

func s3ExpectLocationContains(t *testing.T, res *result, want string) {
	t.Helper()
	if res.Status != 302 {
		t.Fatalf("status %d %s", res.Status, res.Raw)
	}
	if !strings.Contains(res.location(), want) {
		t.Fatalf("location %q does not contain %q", res.location(), want)
	}
}

func s3CookieNames(h http.Header) []string {
	var names []string
	for _, part := range strings.Split(h.Get("Cookie"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, _, _ := strings.Cut(part, "=")
		names = append(names, k)
	}
	return names
}

func s3NoAuthCookies(t *testing.T, res *result, jar http.Header) {
	t.Helper()
	sc := s3SetCookies(res.Headers)
	if strings.Contains(sc, "account_data=") {
		t.Errorf("set-cookie contains account_data=: %q", sc)
	}
	if strings.Contains(sc, "session_token=") {
		t.Errorf("set-cookie contains session_token=: %q", sc)
	}
	if jar != nil {
		for _, n := range s3CookieNames(jar) {
			if strings.Contains(n, "account_data") || strings.Contains(n, "session_token") {
				t.Errorf("cookie jar contains %q", n)
			}
		}
	}
}

func TestSAML3UserResolutionHTTP(t *testing.T) {
	t.Run("accepts a response-only signature when the effective SP policy is false", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, nil)
		s := in.initiate(t)
		xml := s3Decode(t, s.samlResponse)
		ai := strings.Index(xml, "<saml:Assertion")
		si := strings.Index(xml, "<ds:Signature")
		if !(si < ai) {
			t.Fatalf("signature index %d not before assertion index %d", si, ai)
		}
		if strings.Contains(xml[ai:], "<ds:Signature") {
			t.Fatal("assertion contains a signature")
		}
		res := in.submit(t, s, nil)
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		in.expectOneAccountAndSession(t)
	})

	rejects := []struct {
		name string
		cfg  func(t *testing.T) func(idp *mockSAMLIdP) map[string]any
	}{
		{"rejects a response-only signature when the effective SP policy requires signed assertions", func(t *testing.T) func(*mockSAMLIdP) map[string]any {
			return func(idp *mockSAMLIdP) map[string]any { return s3StrictAssertionSigningConfiguration(t, idp, false) }
		}},
		{"rejects a response-only signature when custom metadata requires signed assertions", func(t *testing.T) func(*mockSAMLIdP) map[string]any {
			return func(idp *mockSAMLIdP) map[string]any { return s3MetadataRequiredAssertionSigningConfiguration(t, idp) }
		}},
		{"rejects a response-only signature when custom metadata uses XML Schema numeric true", func(t *testing.T) func(*mockSAMLIdP) map[string]any {
			return func(idp *mockSAMLIdP) map[string]any { return s3NumericAssertionSigningConfiguration(t, idp, "1") }
		}},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			in := s3NewURInstance(t, Options{}, nil, tc.cfg(t))
			s := in.initiate(t)
			res := in.submit(t, s, nil)
			s3ExpectLocationContains(t, res, "error=invalid_saml_response")
			in.expectNoAuthenticationWrites(t)
		})
	}

	t.Run("accepts a response-only signature when custom metadata uses XML Schema numeric false", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, func(idp *mockSAMLIdP) map[string]any { return s3NumericAssertionSigningConfiguration(t, idp, "0") })
		s := in.initiate(t)
		res := in.submit(t, s, nil)
		s3ExpectLocation(t, res, in.env.server.URL+"/employee")
		in.expectOneAccountAndSession(t)
	})

	metadataChanges := []struct {
		desc    string
		replace func(string) string
	}{
		{"an invalid WantAssertionsSigned lexical value", func(m string) string {
			return strings.Replace(m, `WantAssertionsSigned="false"`, `WantAssertionsSigned="TRUE"`, 1)
		}},
		{"an unqualified metadata tree", func(string) string {
			return `
				<EntityDescriptor entityID="https://service.example.com/saml">
					<SPSSODescriptor WantAssertionsSigned="false">
						<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</SPSSODescriptor>
				</EntityDescriptor>
			`
		}},
		{"a foreign root around a metadata namespace decoy", func(string) string {
			return `
				<foreign:EntityDescriptor xmlns:foreign="urn:example:foreign" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
					<md:EntityDescriptor entityID="https://service.example.com/saml">
						<md:SPSSODescriptor WantAssertionsSigned="false">
							<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
						</md:SPSSODescriptor>
					</md:EntityDescriptor>
				</foreign:EntityDescriptor>
			`
		}},
		{"a foreign service-provider descriptor", func(string) string {
			return `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
					<foreign:SPSSODescriptor WantAssertionsSigned="false">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</foreign:SPSSODescriptor>
				</md:EntityDescriptor>
			`
		}},
		{"a foreign POST endpoint namespace decoy", func(string) string {
			return `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<foreign:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			`
		}},
		{"a valid descriptor followed by a foreign descriptor", func(string) string {
			return `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</md:SPSSODescriptor>
					<foreign:SPSSODescriptor WantAssertionsSigned="true">
						<foreign:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attacker.example.com/saml/acs" />
					</foreign:SPSSODescriptor>
				</md:EntityDescriptor>
			`
		}},
		{"a foreign POST endpoint before a valid endpoint", func(string) string {
			return `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<foreign:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attacker.example.com/saml/acs" />
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			`
		}},
		{"a foreign NameID format before a valid format", func(string) string {
			return `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<foreign:NameIDFormat>urn:example:attacker</foreign:NameIDFormat>
						<md:NameIDFormat>urn:example:valid</md:NameIDFormat>
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			`
		}},
	}
	for _, tc := range metadataChanges {
		t.Run("rejects an ACS request after persisted SP metadata changes to "+tc.desc, func(t *testing.T) {
			in := s3NewURInstance(t, Options{}, nil, nil)
			s := in.initiate(t)
			cfg := s3PersistedSAMLConfiguration(t, in.idp)
			cfg["spMetadata"] = map[string]any{"metadata": tc.replace(spMetadata)}
			in.replaceConfig(t, cfg)
			res := in.submit(t, s, nil)
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			loc, err := url.Parse(res.location())
			if err != nil {
				t.Fatal(err)
			}
			if s3Origin(loc) != in.env.server.URL {
				t.Errorf("origin %q", s3Origin(loc))
			}
			// WHATWG URL reports an empty path as "/".
			if pathname := or(loc.Path, "/"); pathname != "/" {
				t.Errorf("pathname %q (location %q)", pathname, res.location())
			}
			if got := loc.Query().Get("error"); got != "saml_invalid_sp_metadata" {
				t.Errorf("error %q (location %q)", got, res.location())
			}
			if got := loc.Query().Get("error_description"); got != "Invalid SAML service provider metadata" {
				t.Errorf("error_description %q", got)
			}
			in.expectNoAuthenticationWrites(t)
		})
	}

	t.Run("accepts a cryptographically signed assertion through the HTTP ACS", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, func(idp *mockSAMLIdP) map[string]any { return s3StrictAssertionSigningConfiguration(t, idp, false) })
		s := in.initiate(t)
		unsigned := s3RemoveResponseSignature(s3Decode(t, s.samlResponse))
		s.samlResponse = s3SignSAMLContent(t, in.idp, unsigned, true)
		res := in.submit(t, s, nil)
		s3ExpectLocation(t, res, in.env.server.URL+"/employee")
		in.expectOneAccountAndSession(t)
	})

	t.Run("accepts a signed assertion when custom metadata supplies the effective policy", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, func(idp *mockSAMLIdP) map[string]any { return s3MetadataRequiredAssertionSigningConfiguration(t, idp) })
		s := in.initiate(t)
		unsigned := s3RemoveResponseSignature(s3Decode(t, s.samlResponse))
		s.samlResponse = s3SignSAMLContent(t, in.idp, unsigned, true)
		res := in.submit(t, s, nil)
		s3ExpectLocation(t, res, in.env.server.URL+"/employee")
		in.expectOneAccountAndSession(t)
	})

	t.Run("accepts valid response and assertion signatures through the strict HTTP ACS", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, func(idp *mockSAMLIdP) map[string]any { return s3StrictAssertionSigningConfiguration(t, idp, false) })
		s := in.initiate(t)
		unsigned := s3RemoveResponseSignature(s3Decode(t, s.samlResponse))
		assertionSigned := s3Decode(t, s3SignSAMLContent(t, in.idp, unsigned, true))
		both := s3SignSAMLContent(t, in.idp, assertionSigned, false)
		if n := len(regexp.MustCompile(`<ds:Signature\b`).FindAllString(s3Decode(t, both), -1)); n != 2 {
			t.Fatalf("signature count %d, want 2", n)
		}
		s.samlResponse = both
		res := in.submit(t, s, nil)
		s3ExpectLocation(t, res, in.env.server.URL+"/employee")
		in.expectOneAccountAndSession(t)
	})

	t.Run("rejects a valid response signature with a bogus assertion signature", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, func(idp *mockSAMLIdP) map[string]any { return s3StrictAssertionSigningConfiguration(t, idp, false) })
		s := in.initiate(t)
		// String.replace with a non-global regex replaces only the first match.
		orig := s3RemoveResponseSignature(s3Decode(t, s.samlResponse))
		m := regexp.MustCompile(`<saml:Assertion\b([^>]*)>`).FindStringSubmatchIndex(orig)
		if m == nil {
			t.Fatal("no assertion")
		}
		unsigned := orig[:m[0]] + "<saml:Assertion" + orig[m[2]:m[3]] + `><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" />` + orig[m[1]:]
		s.samlResponse = s3SignSAMLContent(t, in.idp, unsigned, false)
		res := in.submit(t, s, nil)
		s3ExpectLocationContains(t, res, "error=invalid_saml_response")
		in.expectNoAuthenticationWrites(t)
	})

	t.Run("rejects an encrypted unsigned assertion protected only by a response signature", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, func(idp *mockSAMLIdP) map[string]any { return s3StrictAssertionSigningConfiguration(t, idp, true) })
		s := in.initiate(t)
		unsigned := s3RemoveResponseSignature(s3Decode(t, s.samlResponse))
		encrypted := s3Decode(t, s3EncryptSAMLContent(t, in.idp, unsigned))
		s.samlResponse = s3SignSAMLContent(t, in.idp, encrypted, false)
		res := in.submit(t, s, nil)
		s3ExpectLocationContains(t, res, "error=invalid_saml_response")
		in.expectNoAuthenticationWrites(t)
	})

	t.Run("accepts a signed and encrypted assertion through the HTTP ACS", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, func(idp *mockSAMLIdP) map[string]any { return s3StrictAssertionSigningConfiguration(t, idp, true) })
		s := in.initiate(t)
		unsigned := s3RemoveResponseSignature(s3Decode(t, s.samlResponse))
		assertionSigned := s3Decode(t, s3SignSAMLContent(t, in.idp, unsigned, true))
		s.samlResponse = s3EncryptSAMLContent(t, in.idp, assertionSigned)
		res := in.submit(t, s, nil)
		s3ExpectLocation(t, res, in.env.server.URL+"/employee")
		in.expectOneAccountAndSession(t)
	})

	t.Run("links the signed NameID to the exact selected user without email fallback", func(t *testing.T) {
		var mu sync.Mutex
		selectedUserID := ""
		var inputs []UserResolutionInput
		var databases []adapter.Adapter
		in := s3NewURInstance(t, Options{
			DisableImplicitSignUp: true,
			ResolveUser: func(ctx context.Context, input UserResolutionInput, rc UserResolutionContext) (UserResolution, error) {
				mu.Lock()
				defer mu.Unlock()
				inputs = append(inputs, input)
				databases = append(databases, rc.Adapter)
				return UserResolution{Action: "link", UserID: selectedUserID, Profile: "preserve"}, nil
			},
		}, func(c *betterauth.Config) {
			c.Account = &betterauth.AccountConfig{StoreAccountCookie: betterauth.Bool(true)}
		}, nil)
		now := time.Now()
		selected, err := in.env.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "user", Data: adapter.Record{
			"email": "directory-user@example.com", "emailVerified": false, "name": "Directory User",
			"image": "https://directory.example.com/avatar.png", "createdAt": now, "updatedAt": now,
		}})
		if err != nil {
			t.Fatal(err)
		}
		selectedUserID = fmt.Sprint(selected["id"])

		s := in.initiate(t)
		if !regexp.MustCompile(`InResponseTo="_[^"]+"`).MatchString(s3Decode(t, s.samlResponse)) {
			t.Fatal("SAMLResponse has no InResponseTo")
		}
		res := in.submit(t, s, nil)
		s3ExpectLocation(t, res, in.env.server.URL+"/employee")
		sc := s3SetCookies(res.Headers)
		if !strings.Contains(sc, "account_data=") || !strings.Contains(sc, "session_token=") {
			t.Fatalf("set-cookie %q", sc)
		}
		if len(inputs) != 1 {
			t.Fatalf("resolver inputs %d, want 1", len(inputs))
		}
		i := inputs[0]
		if i.Protocol != "saml" || i.ProviderID != "workforce-saml" {
			t.Errorf("protocol/providerId %q %q", i.Protocol, i.ProviderID)
		}
		if i.AccountKey.Issuer != in.idp.URL+"/api/sso/saml2/idp/metadata" || i.AccountKey.AccountID != "test@email.com" {
			t.Errorf("accountKey %+v", i.AccountKey)
		}
		if i.ProviderUser.Email != "test@email.com" {
			t.Errorf("providerUser.email %q", i.ProviderUser.Email)
		}
		for k, v := range map[string]string{"firstName": "Test", "lastName": "User", "email": "test@email.com"} {
			if i.ProviderAttributes[k] != v {
				t.Errorf("providerAttributes[%s] = %#v, want %q", k, i.ProviderAttributes[k], v)
			}
		}
		pr := i.ProviderReference
		if pr.ProviderID != "workforce-saml" || pr.Source.Type != "persisted" || pr.Source.RecordID != in.providerRecordID || pr.AuthenticationConfigurationFingerprint == "" {
			t.Errorf("providerReference %+v (record %s)", pr, in.providerRecordID)
		}
		if len(databases) != 1 || databases[0] == nil {
			t.Errorf("databases %d", len(databases))
		}
		users := in.env.rows("user")
		if len(users) != 2 {
			t.Fatalf("users %d, want 2", len(users))
		}
		foundSelected := false
		for _, u := range users {
			if u["email"] == "test@email.com" {
				t.Errorf("unexpected user test@email.com")
			}
			if fmt.Sprint(u["id"]) == selectedUserID && u["email"] == "directory-user@example.com" && u["name"] == "Directory User" {
				foundSelected = true
			}
		}
		if !foundSelected {
			t.Errorf("selected user not preserved: %v", users)
		}
		accounts := in.env.rows("account")
		if len(accounts) != 1 || accounts[0]["accountId"] != "test@email.com" || accounts[0]["providerId"] != "workforce-saml" || fmt.Sprint(accounts[0]["userId"]) != selectedUserID {
			t.Errorf("accounts %v", accounts)
		}
		n := 0
		for _, sess := range in.env.rows("session") {
			if fmt.Sprint(sess["userId"]) == selectedUserID {
				n++
			}
		}
		if n != 1 {
			t.Errorf("sessions for selected user %d, want 1", n)
		}
	})

	for _, failure := range []string{"reject", "throw", "account"} {
		t.Run("rolls back resolver and authentication writes on "+failure+" failure", func(t *testing.T) {
			markerUserID := ""
			in := s3NewURInstance(t, Options{
				ResolveUser: func(ctx context.Context, input UserResolutionInput, rc UserResolutionContext) (UserResolution, error) {
					if _, err := rc.Adapter.Update(ctx, "user", []adapter.Where{{Field: "id", Value: markerUserID}}, adapter.Record{"name": "must roll back"}); err != nil {
						return UserResolution{}, err
					}
					switch failure {
					case "reject":
						msg := "Directory access denied"
						return UserResolution{Action: "reject", Code: "directory_access_denied", Message: &msg}, nil
					case "throw":
						return UserResolution{}, errors.New("resolver unavailable")
					}
					return UserResolution{Action: "continue"}, nil
				},
			}, func(c *betterauth.Config) {
				c.Account = &betterauth.AccountConfig{StoreAccountCookie: betterauth.Bool(true)}
				if failure == "account" {
					c.DatabaseHooks = &betterauth.DatabaseHooks{Account: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
						Before: func(ctx context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
							return &betterauth.DBHookResult{Abort: true}, nil
						},
					}}}
				}
			}, nil)
			now := time.Now()
			marker, err := in.env.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "user", Data: adapter.Record{
				"email": "marker-" + failure + "@example.com", "emailVerified": true, "name": "marker", "image": nil, "createdAt": now, "updatedAt": now,
			}})
			if err != nil {
				t.Fatal(err)
			}
			markerUserID = fmt.Sprint(marker["id"])

			s := in.initiate(t)
			res := in.submit(t, s, nil)
			redirect := s3ResolveLocation(t, res.location(), in.env.server.URL)
			want := map[string]string{"reject": "directory_access_denied", "throw": "SSO_USER_RESOLUTION_FAILED", "account": "unable_to_create_user"}[failure]
			if got := redirect.Query().Get("error"); got != want {
				t.Errorf("error %q want %q (status %d location %q body %s)", got, want, res.Status, res.location(), res.Raw)
			}
			s3NoAuthCookies(t, res, nil)
			in.expectNoAuthenticationWrites(t)
			m, err := in.env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: markerUserID}}})
			if err != nil || m == nil || m["name"] != "marker" {
				t.Errorf("marker user %v %v", m, err)
			}
			if n := in.count(t, "user"); n != 2 {
				t.Errorf("user count %d, want 2", n)
			}
		})
	}

	for _, change := range []string{"record", "configuration"} {
		t.Run("rejects a persisted provider "+change+" change between sign-in and ACS", func(t *testing.T) {
			var mu sync.Mutex
			resolverCalls := 0
			in := s3NewURInstance(t, Options{ResolveUser: func(ctx context.Context, input UserResolutionInput, rc UserResolutionContext) (UserResolution, error) {
				mu.Lock()
				resolverCalls++
				mu.Unlock()
				return UserResolution{Action: "continue"}, nil
			}}, nil, nil)
			s := in.initiate(t)
			if change == "record" {
				if _, err := in.conn.Exec(`UPDATE "ssoProvider" SET "id" = ? WHERE "providerId" = ?`, "replacement-provider-row", "workforce-saml"); err != nil {
					t.Fatal(err)
				}
			} else {
				cfg := s3PersistedSAMLConfiguration(t, in.idp)
				cfg["callbackUrl"] = in.env.server.URL + "/changed-callback"
				raw, _ := json.Marshal(cfg)
				if _, err := in.conn.Exec(`UPDATE "ssoProvider" SET "samlConfig" = ? WHERE "providerId" = ?`, string(raw), "workforce-saml"); err != nil {
					t.Fatal(err)
				}
			}
			res := in.submit(t, s, nil)
			redirect := s3ResolveLocation(t, res.location(), in.env.server.URL)
			if got := redirect.Query().Get("error"); got != "invalid_state" {
				t.Errorf("error %q (status %d location %q)", got, res.Status, res.location())
			}
			if resolverCalls != 0 {
				t.Errorf("resolver calls %d", resolverCalls)
			}
			in.expectNoAuthenticationWrites(t)
		})
	}

	t.Run("preserves the signed SAML sign-in behavior when no resolver is configured", func(t *testing.T) {
		in := s3NewURInstance(t, Options{}, nil, nil)
		s := in.initiate(t)
		res := in.submit(t, s, nil)
		s3ExpectLocation(t, res, in.env.server.URL+"/employee")
		accounts := in.env.rows("account")
		if len(accounts) != 1 || accounts[0]["accountId"] != "test@email.com" || accounts[0]["providerId"] != "workforce-saml" {
			t.Fatalf("accounts %v", accounts)
		}
		u, err := in.env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: accounts[0]["userId"]}}})
		if err != nil || u == nil || u["email"] != "test@email.com" {
			t.Fatalf("user %v %v", u, err)
		}
		if n := in.count(t, "session"); n != 1 {
			t.Fatalf("session count %d", n)
		}
	})

	for _, rsCase := range []string{"missing", "corrupted", "legacy"} {
		t.Run("rejects an SP-initiated response with "+rsCase+" RelayState after the provider configuration changes", func(t *testing.T) {
			var mu sync.Mutex
			resolverCalls := 0
			in := s3NewURInstance(t, Options{ResolveUser: func(ctx context.Context, input UserResolutionInput, rc UserResolutionContext) (UserResolution, error) {
				mu.Lock()
				resolverCalls++
				mu.Unlock()
				return UserResolution{Action: "continue"}, nil
			}}, nil, nil)
			s := in.initiate(t)
			ctx := context.Background()
			if rsCase == "legacy" {
				v, err := in.env.auth.Context().InternalAdapter.FindVerificationValue(ctx, "auth-state:"+s.relayState)
				if err != nil || v == nil {
					t.Fatalf("verification %v %v", v, err)
				}
				var stored map[string]any
				if err := json.Unmarshal([]byte(v.Value), &stored); err != nil {
					t.Fatal(err)
				}
				delete(stored, "serverContext")
				raw, _ := json.Marshal(stored)
				if _, err := in.env.auth.Context().Adapter.Update(ctx, "verification", []adapter.Where{{Field: "id", Value: v.ID}}, adapter.Record{"value": string(raw)}); err != nil {
					t.Fatal(err)
				}
			}
			cfg := s3PersistedSAMLConfiguration(t, in.idp)
			cfg["callbackUrl"] = in.env.server.URL + "/changed-callback"
			raw, _ := json.Marshal(cfg)
			if _, err := in.conn.Exec(`UPDATE "ssoProvider" SET "samlConfig" = ? WHERE "providerId" = ?`, string(raw), "workforce-saml"); err != nil {
				t.Fatal(err)
			}
			var rs *string
			switch rsCase {
			case "missing":
				omit := "\x00"
				rs = &omit
			case "corrupted":
				c := "corrupted-relay-state"
				rs = &c
			}
			res := in.submit(t, s, rs)
			redirect := s3ResolveLocation(t, res.location(), in.env.server.URL)
			if got := redirect.Query().Get("error"); got != "invalid_state" {
				t.Errorf("error %q (status %d location %q)", got, res.Status, res.location())
			}
			if resolverCalls != 0 {
				t.Errorf("resolver calls %d", resolverCalls)
			}
			s3NoAuthCookies(t, res, s.cookies)
			in.expectNoAuthenticationWrites(t)
		})
	}

	idpInitiated := func(t *testing.T, relayState string) (*s3URInstance, *result, http.Header, *int) {
		t.Helper()
		var mu sync.Mutex
		calls := 0
		in := s3NewURInstance(t, Options{
			ResolveUser: func(ctx context.Context, input UserResolutionInput, rc UserResolutionContext) (UserResolution, error) {
				mu.Lock()
				calls++
				mu.Unlock()
				return UserResolution{Action: "continue"}, nil
			},
			SAML: &SAMLOptions{AllowIdpInitiated: true, IdpInitiatedCallbackURL: "/employee"},
		}, nil, nil)
		resp, status, body := fetchSAMLResponse(t, in.idp.URL+"/api/sso/saml2/idp/post?idpInitiated=true")
		if status != 200 {
			t.Fatalf("idp %d %v", status, body)
		}
		form := url.Values{"SAMLResponse": {resp}}
		if relayState != "" {
			form.Set("RelayState", relayState)
		}
		res := in.env.postForm(in.env.server.URL+"/api/auth/sso/saml2/sp/acs/workforce-saml", nil, form)
		jar := mergeCookies(http.Header{}, res.Headers)
		return in, res, jar, &calls
	}

	t.Run("accepts a true explicitly allowed IdP-initiated response without RelayState or InResponseTo", func(t *testing.T) {
		in, res, _, calls := idpInitiated(t, "")
		s3ExpectLocation(t, res, "/employee")
		if *calls != 1 {
			t.Errorf("resolver calls %d, want 1", *calls)
		}
		if sc := s3SetCookies(res.Headers); !strings.Contains(sc, "session_token=") {
			t.Errorf("set-cookie %q", sc)
		}
		in.expectOneAccountAndSession(t)
	})

	t.Run("rejects an explicitly allowed IdP-initiated response with malformed RelayState", func(t *testing.T) {
		in, res, jar, calls := idpInitiated(t, "malformed-relay-state")
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		redirect := s3ResolveLocation(t, res.location(), in.env.server.URL)
		if got := redirect.Query().Get("error"); got != "invalid_state" {
			t.Errorf("error %q (location %q)", got, res.location())
		}
		if *calls != 0 {
			t.Errorf("resolver calls %d", *calls)
		}
		s3NoAuthCookies(t, res, jar)
		in.expectNoAuthenticationWrites(t)
	})
}

// ---- PEM normalization ----

func TestSAML3PEMNormalization(t *testing.T) {
	t.Run("PEM normalization", func(t *testing.T) {
		t.Run("should complete full SAML flow with whitespace-indented keys", func(t *testing.T) {
			indent := func(pem string) string {
				lines := strings.Split(pem, "\n")
				for i, l := range lines {
					lines[i] = "    " + l
				}
				return strings.Join(lines, "\n")
			}
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			s3MustRegister(t, env, h, map[string]any{
				"providerId": "indent-test", "issuer": idp.URL, "domain": "indent.example.com",
				"samlConfig": map[string]any{
					"entryPoint": idp.URL + "/api/sso/saml2/idp/post", "cert": indent(certificate),
					"idpMetadata":      map[string]any{"metadata": idp.MetadataXML, "privateKey": indent(idpPrivateKey), "privateKeyPass": "q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW"},
					"spMetadata":       map[string]any{"metadata": spMetadata, "privateKey": indent(spPrivateKey), "privateKeyPass": "VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px"},
					"identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				},
			})
			signInURL, _, _ := s3SignIn(t, env, map[string]any{"providerId": "indent-test", "callbackURL": "/dashboard"})
			if !strings.Contains(signInURL, idp.URL) {
				t.Fatalf("url %q", signInURL)
			}
			resp, status, body := fetchSAMLResponse(t, signInURL)
			if status != 200 || resp == "" {
				t.Fatalf("idp %d %v", status, body)
			}
			acs := s3ACS(env, "indent-test", nil, map[string]any{"SAMLResponse": resp})
			if acs.Status != 302 {
				t.Fatalf("acs status %d %s", acs.Status, acs.Raw)
			}
		})
	})
}

// ---- SAML SSO Hardening ----

// s3FailingAdapter makes ssoProvider lookups fail on demand.
type s3FailingAdapter struct {
	adapter.Adapter
	fail *bool
}

func (a *s3FailingAdapter) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	if *a.fail && in.Model == "ssoProvider" {
		return nil, errors.New("provider lookup unavailable")
	}
	return a.Adapter.FindOne(ctx, in)
}

func TestSAML3Hardening(t *testing.T) {
	t.Run("ACS URL consistency (provider.id vs providerId)", func(t *testing.T) {
		t.Run("should use providerId (not internal row ID) in SP metadata ACS URL", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			s3MustRegister(t, env, h, map[string]any{
				"providerId": "acs-consistency-test", "issuer": "http://localhost:8081", "domain": "acs-test.example.com",
				"samlConfig": map[string]any{
					"entryPoint": "http://localhost:8081/api/sso/saml2/idp/post", "cert": certificate,
					"idpMetadata": s3MockIdentityProviderMetadata(), "spMetadata": map[string]any{},
				},
			})
			r := env.api("spMetadata", nil, nil, map[string]any{"providerId": "acs-consistency-test"})
			if !strings.Contains(string(r.Raw), "acs-consistency-test") {
				t.Fatalf("metadata:\n%s", r.Raw)
			}
		})

		t.Run("should produce matching ACS URLs in SP metadata and AuthnRequest", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			s3MustRegister(t, env, h, map[string]any{
				"providerId": "acs-match-test", "issuer": "http://localhost:8081", "domain": "acs-match.example.com",
				"samlConfig": map[string]any{
					"entryPoint": "http://localhost:8081/api/sso/saml2/idp/post", "cert": certificate,
					"idpMetadata": map[string]any{"metadata": idpMetadata}, "spMetadata": map[string]any{},
				},
			})
			r := env.api("spMetadata", nil, nil, map[string]any{"providerId": "acs-match-test"})
			m := regexp.MustCompile(`Location="([^"]*/sso/saml2/sp/acs[^"]*)"`).FindStringSubmatch(string(r.Raw))
			if m == nil {
				t.Fatalf("no ACS location in metadata:\n%s", r.Raw)
			}
			signInURL, _, _ := s3SignIn(t, env, map[string]any{"providerId": "acs-match-test", "callbackURL": "/dashboard"})
			if !strings.Contains(m[1], "acs-match-test") {
				t.Fatalf("metadata ACS %q", m[1])
			}
			if signInURL == "" {
				t.Fatal("signIn url undefined")
			}
		})
	})

	defaultSSO := []DefaultSSOProvider{{
		ProviderID: "default-provider", Domain: "default.example.com",
		SAMLConfig: &SAMLConfig{
			Issuer: "http://localhost:8081", EntryPoint: "http://localhost:8081/api/sso/saml2/idp/post", Cert: Cert(certificate),
			IdpMetadata: &SAMLIdentityProviderMetadata{EntityID: s3MockIdPEntityLiteral},
			SpMetadata:  &SAMLServiceProviderMetadata{Metadata: spMetadata},
		},
	}}

	t.Run("Provider lookup fallback", func(t *testing.T) {
		t.Run("should find DB provider even when defaultSSO is configured with different providers", func(t *testing.T) {
			env := newEnv(t, Options{DefaultSSO: defaultSSO})
			h := env.signInTestUser()
			s3MustRegister(t, env, h, map[string]any{
				"providerId": "db-provider", "issuer": "http://localhost:8081", "domain": "db.example.com",
				"samlConfig": map[string]any{
					"entryPoint": "http://localhost:8081/api/sso/saml2/idp/post", "cert": certificate,
					"spMetadata": map[string]any{"metadata": spMetadata}, "idpMetadata": map[string]any{"metadata": idpMetadata},
				},
			})
			res := s3Form(env, "/sso/saml2/sp/acs/db-provider", nil, url.Values{"SAMLResponse": {"invalid-but-tests-provider-lookup"}})
			if res.Status == 404 {
				t.Fatalf("status 404 %s", res.Raw)
			}
		})

		t.Run("should return 404 for nonexistent providerId even when defaultSSO is configured", func(t *testing.T) {
			env := newEnv(t, Options{DefaultSSO: defaultSSO})
			res := s3Form(env, "/sso/saml2/sp/acs/nonexistent-provider", nil, url.Values{"SAMLResponse": {"irrelevant"}})
			if res.Status != 404 {
				t.Fatalf("status %d %s (location %q)", res.Status, res.Raw, res.location())
			}
		})
	})

	t.Run("Registration-time config validation", func(t *testing.T) {
		t.Run("should reject SAML mappings that attempt to replace the NameID identity", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			res := env.do("POST", "/sso/register", h, map[string]any{
				"providerId": "mapped-saml-identity", "issuer": "https://sp.example.com/saml", "domain": "example.com",
				"samlConfig": map[string]any{
					"entryPoint": "https://idp.example.com/sso", "cert": "placeholder",
					"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
					"mapping":     map[string]any{"id": "employee_id", "email": "email", "name": "displayName"},
				},
			})
			if res.Status != 400 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
		})

		t.Run("should reject manual IdP configuration without an explicit entity ID", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			res := env.do("POST", "/sso/register", h, map[string]any{
				"providerId": "ambiguous-idp-authority", "issuer": "https://sp.example.com/saml", "domain": "example.com",
				"samlConfig": map[string]any{"entryPoint": "https://idp.example.com/sso", "cert": "placeholder", "spMetadata": map[string]any{}},
			})
			if res.Status != 400 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if !strings.Contains(res.message(), "idpMetadata.entityID") {
				t.Fatalf("message %q", res.message())
			}
		})

		t.Run("should reject registration with empty entryPoint and no idpMetadata.metadata", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			r := env.api("registerSSOProvider", h, map[string]any{
				"providerId": "broken-config", "issuer": "http://localhost:8081", "domain": "broken.example.com",
				"samlConfig": map[string]any{"entryPoint": "not-a-url", "cert": "placeholder", "spMetadata": map[string]any{}},
			}, nil)
			if r.Err == nil {
				t.Fatalf("registration succeeded: %s", r.Raw)
			}
			if !strings.Contains(r.message(), "entryPoint") {
				t.Fatalf("message %q", r.message())
			}
		})
	})

	t.Run("RelayState controls post-auth redirect", func(t *testing.T) {
		t.Run("should redirect to RelayState callbackURL after authentication", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: s3Bool(false)}})
			h := env.signInTestUser()
			s3MustRegister(t, env, h, map[string]any{
				"providerId": "relay-priority-test", "issuer": idp.URL, "domain": "relay.example.com",
				"samlConfig": map[string]any{
					"entryPoint": idp.URL + "/api/sso/saml2/idp/post", "cert": certificate,
					"idpMetadata": map[string]any{"metadata": idp.MetadataXML}, "spMetadata": map[string]any{"metadata": spMetadata},
				},
			})
			signInURL, _, _ := s3SignIn(t, env, map[string]any{"providerId": "relay-priority-test", "callbackURL": "/from-relay-state"})
			resp, _, _ := fetchSAMLResponse(t, signInURL)
			res := s3ACS(env, "relay-priority-test", nil, map[string]any{"SAMLResponse": resp, "RelayState": s3RelayState(t, signInURL)})
			loc := res.location()
			if !strings.Contains(loc, "/from-relay-state") || strings.Contains(loc, "/from-config") {
				t.Fatalf("location %q (status %d %s)", loc, res.Status, res.Raw)
			}
		})
	})

	t.Run("IdP-initiated SAML login with split origin redirect", func(t *testing.T) {
		const frontendOrigin = "https://frontend.example.com"
		trustedAll := func(string, bool) bool { return true }

		t.Run("should allow a trusted cross-origin redirect with the ACS pathname", func(t *testing.T) {
			appOrigin := "http://localhost:3000"
			callbackPath := appOrigin + "/api/auth/sso/saml2/sp/acs/shared-path-provider"
			frontendCallback := frontendOrigin + "/api/auth/sso/saml2/sp/acs/shared-path-provider"
			if got := GetSafeRedirectURL([]string{frontendCallback}, callbackPath, appOrigin, trustedAll); got != frontendCallback {
				t.Fatalf("got %q", got)
			}
		})

		for _, candidate := range []string{`/\evil.example.com`, "/%2fevil.example.com", "/%5cevil.example.com"} {
			t.Run("should skip unsafe relative redirect candidate "+candidate, func(t *testing.T) {
				appOrigin := "http://localhost:3000"
				callbackPath := appOrigin + "/api/auth/sso/saml2/sp/acs/provider"
				if got := GetSafeRedirectURL([]string{candidate, "/dashboard"}, callbackPath, appOrigin, trustedAll); got != "/dashboard" {
					t.Fatalf("got %q", got)
				}
			})
		}

		idpInitiatedResponse := func(t *testing.T, idp *mockSAMLIdP) string {
			t.Helper()
			resp, status, body := fetchSAMLResponse(t, idp.URL+"/api/sso/saml2/idp/post")
			if status != 200 || resp == "" {
				t.Fatalf("Mock IdP did not return a SAML response: %d %v", status, body)
			}
			return resp
		}
		withFrontend := envConfig{mutate: func(c *betterauth.Config) { c.TrustedOrigins = []string{frontendOrigin} }}
		register := func(t *testing.T, env *testEnv, idp *mockSAMLIdP, h http.Header, providerID, domain string, extra map[string]any) {
			t.Helper()
			cfg := map[string]any{
				"entryPoint": idp.URL + "/api/sso/saml2/idp/post", "cert": certificate,
				"idpMetadata": map[string]any{"metadata": idp.MetadataXML}, "spMetadata": map[string]any{"metadata": spMetadata},
			}
			for k, v := range extra {
				cfg[k] = v
			}
			s3MustRegister(t, env, h, map[string]any{"providerId": providerID, "issuer": idp.URL, "domain": domain, "samlConfig": cfg})
		}

		t.Run("should redirect to provider-level idpInitiatedCallbackUrl when RelayState is missing (IdP-initiated)", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, EnableInResponseToValidation: s3Bool(false)}}, withFrontend)
			h := env.signInTestUser()
			register(t, env, idp, h, "split-origin-provider", "split.example.com", map[string]any{
				"callbackUrl":             env.server.URL + "/api/auth/sso/saml2/callback/split-origin-provider",
				"idpInitiatedCallbackUrl": frontendOrigin + "/provider-idp-redirect",
			})
			res := s3ACS(env, "split-origin-provider", nil, map[string]any{"SAMLResponse": idpInitiatedResponse(t, idp)})
			s3ExpectLocation(t, res, frontendOrigin+"/provider-idp-redirect")
		})

		t.Run("should redirect to global idpInitiatedCallbackUrl when RelayState is missing (IdP-initiated fallback)", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, EnableInResponseToValidation: s3Bool(false),
				IdpInitiatedCallbackURL: frontendOrigin + "/global-idp-redirect"}}, withFrontend)
			h := env.signInTestUser()
			register(t, env, idp, h, "global-fallback-provider", "fallback.example.com", map[string]any{
				"callbackUrl": env.server.URL + "/api/auth/sso/saml2/callback/global-fallback-provider",
			})
			res := s3ACS(env, "global-fallback-provider", nil, map[string]any{"SAMLResponse": idpInitiatedResponse(t, idp)})
			s3ExpectLocation(t, res, frontendOrigin+"/global-idp-redirect")
		})

		t.Run("should prioritize SP-initiated RelayState over idpInitiatedCallbackUrl", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, EnableInResponseToValidation: s3Bool(false),
				IdpInitiatedCallbackURL: frontendOrigin + "/global-idp-redirect"}}, withFrontend)
			h := env.signInTestUser()
			register(t, env, idp, h, "priority-test-provider", "priority.example.com", map[string]any{
				"callbackUrl":             env.server.URL + "/api/auth/sso/saml2/callback/priority-test-provider",
				"idpInitiatedCallbackUrl": frontendOrigin + "/provider-idp-redirect",
			})
			signInURL, _, _ := s3SignIn(t, env, map[string]any{"providerId": "priority-test-provider", "callbackURL": "/from-relay-state"})
			resp, status, body := fetchSAMLResponse(t, signInURL)
			if status != 200 || resp == "" {
				t.Fatalf("Mock IdP did not return a SAML response: %d %v", status, body)
			}
			res := s3ACS(env, "priority-test-provider", nil, map[string]any{"SAMLResponse": resp, "RelayState": s3RelayState(t, signInURL)})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			loc := res.location()
			if !strings.Contains(loc, "/from-relay-state") || strings.Contains(loc, "/provider-idp-redirect") || strings.Contains(loc, "/global-idp-redirect") {
				t.Fatalf("location %q", loc)
			}
		})

		t.Run("should preserve the signed RelayState error callback on validation errors", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, IdpInitiatedCallbackURL: frontendOrigin + "/global-idp-redirect"}}, withFrontend)
			h := env.signInTestUser()
			register(t, env, idp, h, "error-relay-state-provider", "error-relay-state.example.com", map[string]any{
				"callbackUrl":             env.server.URL + "/api/auth/sso/saml2/callback/error-relay-state-provider",
				"idpInitiatedCallbackUrl": frontendOrigin + "/provider-idp-redirect",
			})
			signInURL, _, _ := s3SignIn(t, env, map[string]any{"providerId": "error-relay-state-provider",
				"callbackURL": frontendOrigin + "/success", "errorCallbackURL": frontendOrigin + "/saml-error#details"})
			res := s3Form(env, "/sso/saml2/sp/acs/error-relay-state-provider", nil,
				url.Values{"SAMLResponse": {"invalid-saml-response-garbage"}, "RelayState": {s3RelayState(t, signInURL)}})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			u, err := url.Parse(res.location())
			if err != nil {
				t.Fatal(err)
			}
			if s3Origin(u) != frontendOrigin || u.Path != "/saml-error" || u.Query().Get("error") != "saml_invalid_encoding" || u.Fragment != "details" {
				t.Fatalf("location %q", res.location())
			}
		})

		t.Run("should preserve the signed error callback on binding validation errors", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, IdpInitiatedCallbackURL: frontendOrigin + "/global-idp-redirect"}}, withFrontend)
			h := env.signInTestUser()
			register(t, env, idp, h, "binding-error-relay-state-provider", "binding-error.example.com", map[string]any{
				"callbackUrl":             env.server.URL + "/api/auth/sso/saml2/sp/acs/binding-error-relay-state-provider",
				"idpInitiatedCallbackUrl": frontendOrigin + "/provider-idp-redirect",
			})
			signInURL, _, _ := s3SignIn(t, env, map[string]any{"providerId": "binding-error-relay-state-provider",
				"callbackURL": frontendOrigin + "/success", "errorCallbackURL": frontendOrigin + "/binding-error#details"})
			idpURL, _ := url.Parse(signInURL)
			q := idpURL.Query()
			q.Set("audience", "https://unexpected.example.com/saml/metadata")
			idpURL.RawQuery = q.Encode()
			resp, status, body := fetchSAMLResponse(t, idpURL.String())
			if status != 200 || resp == "" {
				t.Fatalf("Mock IdP did not return a SAML response: %d %v", status, body)
			}
			res := s3Form(env, "/sso/saml2/sp/acs/binding-error-relay-state-provider", nil,
				url.Values{"SAMLResponse": {resp}, "RelayState": {q.Get("RelayState")}})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			u, err := url.Parse(res.location())
			if err != nil {
				t.Fatal(err)
			}
			if s3Origin(u) != frontendOrigin || u.Path != "/binding-error" || u.Query().Get("error") != "invalid_saml_response" || u.Fragment != "details" {
				t.Fatalf("location %q", res.location())
			}
		})

		t.Run("should prevent open redirect attacks on idpInitiatedCallbackUrl", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, EnableInResponseToValidation: s3Bool(false),
				IdpInitiatedCallbackURL: "http://attacker.com/malicious"}})
			h := env.signInTestUser()
			register(t, env, idp, h, "unsafe-provider", "unsafe.example.com", nil)
			res := s3ACS(env, "unsafe-provider", nil, map[string]any{"SAMLResponse": idpInitiatedResponse(t, idp)})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			loc := res.location()
			if strings.Contains(loc, "attacker.com") {
				t.Fatalf("location %q", loc)
			}
			if loc != env.server.URL {
				t.Fatalf("location %q want %q", loc, env.server.URL)
			}
		})

		t.Run("should redirect to idpInitiatedCallbackUrl on SAML validation error", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, IdpInitiatedCallbackURL: frontendOrigin + "/global-idp-redirect"}}, withFrontend)
			h := env.signInTestUser()
			register(t, env, idp, h, "error-provider", "error.example.com", map[string]any{
				"callbackUrl":             env.server.URL + "/api/auth/sso/saml2/callback/error-provider",
				"idpInitiatedCallbackUrl": frontendOrigin + "/provider-idp-redirect#saml",
			})
			res := s3Form(env, "/sso/saml2/sp/acs/error-provider", nil, url.Values{
				"SAMLResponse": {"invalid-saml-response-garbage"},
				"RelayState":   {env.baseURL + "/sso/saml2/sp/acs/error-provider"},
			})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			u, err := url.Parse(res.location())
			if err != nil {
				t.Fatal(err)
			}
			if s3Origin(u) != frontendOrigin || u.Path != "/provider-idp-redirect" || u.Query().Get("error") != "saml_invalid_encoding" || u.Fragment != "saml" {
				t.Fatalf("location %q", res.location())
			}
		})

		t.Run("should use the global fallback when provider lookup fails before error redirect resolution", func(t *testing.T) {
			idp := newMockSAMLIdP(t, mockSAMLOptions{})
			fail := false
			mem := memory.New(memory.NewDB())
			env := newEnv(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: true, IdpInitiatedCallbackURL: frontendOrigin + "/global-idp-redirect", MaxResponseSize: 16}},
				envConfig{mutate: func(c *betterauth.Config) {
					c.TrustedOrigins = []string{frontendOrigin}
					c.Database = func(opts adapter.Options) (adapter.Adapter, error) {
						a, err := mem(opts)
						if err != nil {
							return nil, err
						}
						return &s3FailingAdapter{Adapter: a, fail: &fail}, nil
					}
				}})
			h := env.signInTestUser()
			register(t, env, idp, h, "error-lookup-provider", "error-lookup.example.com", map[string]any{
				"callbackUrl":             env.server.URL + "/api/auth/sso/saml2/callback/error-lookup-provider",
				"idpInitiatedCallbackUrl": frontendOrigin + "/provider-idp-redirect",
			})
			fail = true
			res := s3Form(env, "/sso/saml2/sp/acs/error-lookup-provider", nil, url.Values{"SAMLResponse": {"response-exceeds-size-limit"}})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			u, err := url.Parse(res.location())
			if err != nil {
				t.Fatal(err)
			}
			if s3Origin(u) != frontendOrigin || u.Path != "/global-idp-redirect" || u.Query().Get("error") != "saml_error" {
				t.Fatalf("location %q", res.location())
			}
		})
	})
}
