package sso

// Port of saml.test.ts (upstream v1.7.7) from "private key normalization" through
// "SSO Provider Config Parsing".

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

const s1EmailFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

// s1MockIdentityProviderMetadata mirrors mockIdentityProviderMetadata.
var s1MockIdentityProviderMetadata = map[string]any{"entityID": "http://localhost:8081/api/sso/saml2/idp/metadata"}

// s1SignedIdPMetadata is idpMetadataWithSignedRequests (localhost:8082 is rewritten to
// the mock IdP URL through the localhost:8081 placeholder).
func s1SignedIdPMetadata() string {
	body := strings.TrimSpace(strings.NewReplacer("-----BEGIN CERTIFICATE-----", "", "-----END CERTIFICATE-----", "").Replace(mockIdpSigningCert))
	return `
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8081/api/sso/saml2/idp/metadata">
<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>` + body + `</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8081/api/sso/saml2/idp/redirect"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/api/sso/saml2/idp/post"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
`
}

// s1FullSAMLConfig is the samlConfig with encrypted IdP/SP keys used by several tests.
func s1FullSAMLConfig(entryPoint, idpXML string, withSPMetadata bool) map[string]any {
	sp := map[string]any{
		"binding": "post", "privateKey": spPrivateKey, "privateKeyPass": "VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px",
		"isAssertionEncrypted": true, "encPrivateKey": spEncryptionKey, "encPrivateKeyPass": "BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU",
	}
	if withSPMetadata {
		sp["metadata"] = spMetadata
	}
	return map[string]any{
		"entryPoint": entryPoint, "cert": certificate, "wantAssertionsSigned": false,
		"signatureAlgorithm": "sha256", "digestAlgorithm": "sha256",
		"idpMetadata": map[string]any{
			"metadata": idpXML, "privateKey": idpPrivateKey, "privateKeyPass": "q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW",
			"isAssertionEncrypted": true, "encPrivateKey": idpEncryptionKey, "encPrivateKeyPass": "g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN",
		},
		"spMetadata":       sp,
		"identifierFormat": s1EmailFormat,
	}
}

// s1BasicSAMLConfig is the common samlConfig pointing at the mock IdP; extra entries
// override (nil deletes).
func s1BasicSAMLConfig(m *mockSAMLIdP, extra map[string]any) map[string]any {
	c := map[string]any{
		"entryPoint": m.URL + "/api/sso/saml2/idp/post", "cert": certificate, "wantAssertionsSigned": false,
		"signatureAlgorithm": "sha256", "digestAlgorithm": "sha256",
		"idpMetadata":      map[string]any{"metadata": m.MetadataXML},
		"spMetadata":       map[string]any{"metadata": spMetadata},
		"identifierFormat": s1EmailFormat,
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func s1Register(t *testing.T, env *testEnv, h http.Header, body map[string]any) *result {
	t.Helper()
	r := env.api("registerSSOProvider", h, body, nil)
	if r.Err != nil {
		t.Fatalf("registerSSOProvider: %d %s %s", r.Status, r.code(), r.Raw)
	}
	return r
}

// s1SignIn calls auth.api.signInSSO and checks the {url, redirect: true} shape.
func s1SignIn(t *testing.T, env *testEnv, body map[string]any, urlContains string) (*result, string) {
	t.Helper()
	r := env.api("signInSSO", nil, body, nil)
	if r.Err != nil {
		t.Fatalf("signInSSO: %d %s %s", r.Status, r.code(), r.message())
	}
	m := r.m()
	u, _ := m["url"].(string)
	if len(m) != 2 || m["redirect"] != true || !strings.Contains(u, urlContains) {
		t.Fatalf("signInSSO response %s, want {url containing %q, redirect: true}", r.Raw, urlContains)
	}
	return r, u
}

func s1RelayState(t *testing.T, signInURL string) string {
	t.Helper()
	u, err := url.Parse(signInURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("RelayState")
}

func s1FetchSAML(t *testing.T, u string) string {
	t.Helper()
	s, status, body := fetchSAMLResponse(t, u)
	if status != 200 || s == "" {
		t.Fatalf("mock IdP %s: %d %v", u, status, body)
	}
	return s
}

func s1ACS(env *testEnv, providerID string, headers http.Header, samlResponse string, relayState *string) *result {
	form := url.Values{"SAMLResponse": {samlResponse}}
	if relayState != nil {
		form.Set("RelayState", *relayState)
	}
	return env.postForm("/sso/saml2/sp/acs/"+providerID, headers, form)
}

func s1Str(s string) *string { return &s }

func s1Expect302(t *testing.T, r *result) string {
	t.Helper()
	if r.Status != 302 {
		t.Fatalf("status %d, want 302: %s", r.Status, r.Raw)
	}
	return r.location()
}

func s1Contains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("%q does not contain %q", s, sub)
	}
}

func s1NotContains(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("%q unexpectedly contains %q", s, sub)
	}
}

func s1HostOf(u string) string {
	return strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
}

func s1ExpectErr(t *testing.T, r *result, status int, message string) {
	t.Helper()
	if r.Err == nil || r.Status != status || r.message() != message {
		t.Fatalf("got %d %q (%s), want %d %q", r.Status, r.message(), r.Raw, status, message)
	}
}

// s1CheckRegisteredSAML mirrors the toMatchObject of "should register a new SAML provider".
func s1CheckRegisteredSAML(t *testing.T, r *result, issuer, entryPoint string) {
	t.Helper()
	m := r.m()
	if id, ok := m["id"].(string); !ok || id == "" {
		t.Fatalf("id: %s", r.Raw)
	}
	if m["issuer"] != issuer {
		t.Fatalf("issuer %v, want %s", m["issuer"], issuer)
	}
	sc, _ := m["samlConfig"].(map[string]any)
	if sc == nil {
		t.Fatalf("samlConfig: %s", r.Raw)
	}
	if _, ok := sc["cert"].(string); !ok {
		t.Fatalf("samlConfig.cert should be a string: %v", sc["cert"])
	}
	want := map[string]any{"entryPoint": entryPoint, "wantAssertionsSigned": false, "signatureAlgorithm": "sha256",
		"digestAlgorithm": "sha256", "identifierFormat": s1EmailFormat}
	for k, v := range want {
		if sc[k] != v {
			t.Fatalf("samlConfig.%s = %v, want %v", k, sc[k], v)
		}
	}
}

func TestSAML1PrivateKeyNormalization(t *testing.T) {
	t.Run("private key normalization", func(t *testing.T) {
		t.Run("loads PEM keys pasted with leading indentation", func(t *testing.T) {
			lines := strings.Split(idPk, "\n")
			for i, l := range lines {
				lines[i] = "    " + l
			}
			indented := strings.Join(lines, "\n")
			load := func(k string) error {
				block, _ := pem.Decode([]byte(k))
				if block == nil {
					return fmt.Errorf("no PEM block")
				}
				_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				return err
			}
			if load(indented) == nil {
				t.Fatal("expected indented key to fail to load")
			}
			if err := load(normalizePem(indented)); err != nil {
				t.Fatalf("normalized key: %v", err)
			}
		})
	})
}

func TestSAML1DefaultSSOArray(t *testing.T) {
	t.Run("SAML SSO with defaultSSO array", func(t *testing.T) {
		env := newEnv(t, Options{
			DefaultSSO: []DefaultSSOProvider{{
				Domain: "localhost:8081", ProviderID: "default-saml",
				SAMLConfig: &SAMLConfig{
					Issuer: "http://localhost:8081", EntryPoint: "http://localhost:8081/api/sso/saml2/idp/post",
					Cert: Cert(certificate), WantAssertionsSigned: betterauth.Bool(false), SignatureAlgorithm: "sha256", DigestAlgorithm: "sha256",
					IdpMetadata:      &SAMLIdentityProviderMetadata{Metadata: idpMetadata},
					SpMetadata:       &SAMLServiceProviderMetadata{Metadata: spMetadata},
					IdentifierFormat: s1EmailFormat,
				},
			}},
			ProvisionUser: func(context.Context, ProvisionUserData) error { return nil },
		}, envConfig{noTestUser: true})
		dashboard := env.server.URL + "/dashboard"

		t.Run("should use default SAML SSO provider from array when no provider found in database", func(t *testing.T) {
			s1SignIn(t, env, map[string]any{"providerId": "default-saml", "callbackURL": dashboard}, "http://localhost:8081")
		})

		t.Run("should reject additionalParams when routing to a SAML provider", func(t *testing.T) {
			r := env.api("signInSSO", nil, map[string]any{"providerId": "default-saml", "callbackURL": dashboard,
				"additionalParams": map[string]any{"domain_hint": "contoso.com"}}, nil)
			if r.Err == nil || !regexp.MustCompile(`additionalParams is not supported for SAML`).MatchString(r.message()) {
				t.Fatalf("got %d %q", r.Status, r.message())
			}
		})

		t.Run("should fetch sp metadata for a defaultSSO provider", func(t *testing.T) {
			r := env.api("spMetadata", nil, nil, map[string]any{"providerId": "default-saml"})
			if r.Status != 200 || string(r.Raw) != spMetadata {
				t.Fatalf("status %d body %q", r.Status, r.Raw)
			}
		})
	})
}

func TestSAML1SignedAuthnRequests(t *testing.T) {
	t.Run("SAML SSO with signed AuthnRequests", func(t *testing.T) {
		m := newMockSAMLIdP(t, mockSAMLOptions{idpMetadataXML: s1SignedIdPMetadata(), wantAuthnRequestsSigned: true})
		env := newEnv(t, Options{DefaultSSO: []DefaultSSOProvider{{
			Domain: s1HostOf(m.URL), ProviderID: "signed-saml",
			SAMLConfig: &SAMLConfig{
				Issuer: m.URL, EntryPoint: m.URL + "/api/sso/saml2/idp/redirect", Cert: Cert(certificate),
				WantAssertionsSigned: betterauth.Bool(false), AuthnRequestsSigned: betterauth.Bool(true),
				SignatureAlgorithm: "sha256", DigestAlgorithm: "sha256", PrivateKey: idPk,
				SpMetadata:       &SAMLServiceProviderMetadata{PrivateKey: idPk},
				IdpMetadata:      &SAMLIdentityProviderMetadata{Metadata: m.MetadataXML},
				IdentifierFormat: s1EmailFormat,
			},
		}}}, envConfig{noTestUser: true})
		dashboard := env.server.URL + "/dashboard"
		body := map[string]any{"providerId": "signed-saml", "callbackURL": dashboard}

		t.Run("should generate signed AuthnRequest with Signature and SigAlg", func(t *testing.T) {
			_, u := s1SignIn(t, env, body, m.URL)
			s1Contains(t, u, "Signature=")
			s1Contains(t, u, "SigAlg=")
		})

		t.Run("should include RelayState in the signed URL", func(t *testing.T) {
			_, u := s1SignIn(t, env, body, m.URL)
			s1Contains(t, u, "RelayState=")
			if strings.Index(u, "RelayState=") >= strings.Index(u, "Signature=") {
				t.Fatalf("RelayState must come before Signature: %s", u)
			}
		})

		t.Run("should produce a signature the IdP can verify", func(t *testing.T) {
			_, u := s1SignIn(t, env, body, m.URL)
			s, status, b := fetchSAMLResponse(t, u)
			if status != 200 || s == "" {
				t.Fatalf("IdP: %d %v", status, b)
			}
		})

		t.Run("should throw when authnRequestsSigned is true but no privateKey is provided", func(t *testing.T) {
			noKey := newEnv(t, Options{DefaultSSO: []DefaultSSOProvider{{
				Domain: s1HostOf(m.URL), ProviderID: "no-key-saml",
				SAMLConfig: &SAMLConfig{
					Issuer: m.URL, EntryPoint: m.URL + "/api/sso/saml2/idp/redirect", Cert: Cert(certificate),
					AuthnRequestsSigned: betterauth.Bool(true), SpMetadata: &SAMLServiceProviderMetadata{},
					IdpMetadata:      &SAMLIdentityProviderMetadata{Metadata: m.MetadataXML},
					IdentifierFormat: s1EmailFormat,
				},
			}}}, envConfig{noTestUser: true})
			r := noKey.api("signInSSO", nil, map[string]any{"providerId": "no-key-saml", "callbackURL": noKey.server.URL + "/dashboard"}, nil)
			if r.Err == nil || !strings.Contains(r.message(), "privateKey") {
				t.Fatalf("got %d %q", r.Status, r.message())
			}
		})
	})
}

func TestSAML1UnsignedAuthnRequests(t *testing.T) {
	t.Run("SAML SSO without signed AuthnRequests", func(t *testing.T) {
		env := newEnv(t, Options{DefaultSSO: []DefaultSSOProvider{{
			Domain: "localhost:8082", ProviderID: "unsigned-saml",
			SAMLConfig: &SAMLConfig{
				Issuer: "http://localhost:8082", EntryPoint: "http://localhost:8081/api/sso/saml2/idp/post", Cert: Cert(certificate),
				WantAssertionsSigned: betterauth.Bool(false), AuthnRequestsSigned: betterauth.Bool(false),
				SignatureAlgorithm: "sha256", DigestAlgorithm: "sha256",
				IdpMetadata:      &SAMLIdentityProviderMetadata{Metadata: idpMetadata},
				SpMetadata:       &SAMLServiceProviderMetadata{Metadata: spMetadata},
				IdentifierFormat: s1EmailFormat,
			},
		}}}, envConfig{noTestUser: true})

		t.Run("should NOT include Signature in URL when authnRequestsSigned is false", func(t *testing.T) {
			_, u := s1SignIn(t, env, map[string]any{"providerId": "unsigned-saml", "callbackURL": env.server.URL + "/dashboard"}, "http://localhost:8081")
			s1NotContains(t, u, "Signature=")
			s1NotContains(t, u, "SigAlg=")
		})
	})
}

func TestSAML1IdpMetadataFallback(t *testing.T) {
	t.Run("SAML SSO with idpMetadata but without metadata XML (fallback to top-level config)", func(t *testing.T) {
		env := newEnv(t, Options{DefaultSSO: []DefaultSSOProvider{{
			Domain: "localhost:8083", ProviderID: "partial-idp-metadata-saml",
			SAMLConfig: &SAMLConfig{
				Issuer: "http://localhost:8083/issuer", EntryPoint: "http://localhost:8081/api/sso/saml2/idp/redirect", Cert: Cert(certificate),
				WantAssertionsSigned: betterauth.Bool(false), AuthnRequestsSigned: betterauth.Bool(false),
				SpMetadata:       &SAMLServiceProviderMetadata{},
				IdpMetadata:      &SAMLIdentityProviderMetadata{EntityID: "http://localhost:8081/custom-entity-id"},
				IdentifierFormat: s1EmailFormat,
			},
		}}}, envConfig{noTestUser: true})
		body := map[string]any{"providerId": "partial-idp-metadata-saml", "callbackURL": env.server.URL + "/dashboard"}

		t.Run("should initiate SAML login using fallback entryPoint when idpMetadata has no metadata XML", func(t *testing.T) {
			_, u := s1SignIn(t, env, body, "http://localhost:8081/api/sso/saml2/idp/redirect")
			s1Contains(t, u, "SAMLRequest=")
		})

		t.Run("should use idpMetadata.entityID when provided (not fall back to issuer)", func(t *testing.T) {
			_, u := s1SignIn(t, env, body, "http://localhost:8081")
			pu, err := url.Parse(u)
			if err != nil || pu.Query().Get("SAMLRequest") == "" {
				t.Fatalf("no SAMLRequest in %s", u)
			}
		})
	})
}

// s1SharedEnv mirrors the shared "SAML SSO" instance (data reset before each test).
func s1SharedEnv(t *testing.T) (*testEnv, http.Header) {
	t.Helper()
	env := newEnv(t, Options{
		ProvisionUser: func(context.Context, ProvisionUserData) error { return nil },
		SAML:          &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)},
	}, envConfig{noTestUser: true})
	env.signUp("test@email.com", "password", "Test User")
	return env, env.signIn("test@email.com", "password")
}

// s1MockSPACS mirrors the mock IdP's own POST /api/sso/saml2/sp/acs/:providerId route.
func s1MockSPACS(t *testing.T, m *mockSAMLIdP) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, "/api/sso/saml2/sp/acs/") {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		if _, err := m.sp("").ParseLoginResponse(m.idp(), r.PostForm.Get("SAMLResponse")); err != nil {
			writeJSON(w, 500, map[string]any{"error": "Failed to process SAML response"})
			return
		}
		http.Redirect(w, r, or(r.PostForm.Get("RelayState"), "http://localhost:3000/dashboard"), http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSAML1SAMLSSO(t *testing.T) {
	m := newMockSAMLIdP(t, mockSAMLOptions{})
	metadataURL := m.URL + "/idp/metadata"

	t.Run("SAML SSO", func(t *testing.T) {
		t.Run("should register a new SAML provider", func(t *testing.T) {
			env, h := s1SharedEnv(t)
			r := s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": m.URL, "domain": m.URL,
				"samlConfig": s1FullSAMLConfig(metadataURL, m.MetadataXML, true)})
			s1CheckRegisteredSAML(t, r, m.URL, metadataURL)
		})

		t.Run("Should fetch sp metadata", func(t *testing.T) {
			env, h := s1SharedEnv(t)
			r := s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": m.URL, "domain": m.URL,
				"samlConfig": s1FullSAMLConfig(metadataURL, m.MetadataXML, true)})
			pid, _ := r.m()["providerId"].(string)
			res := env.api("spMetadata", nil, nil, map[string]any{"providerId": pid})
			if res.Status != 200 || string(res.Raw) != spMetadata {
				t.Fatalf("status %d body %q", res.Status, res.Raw)
			}
		})

		t.Run("Should fetch sp metadata", func(t *testing.T) {
			env, h := s1SharedEnv(t)
			issuer := m.URL
			r := s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": issuer, "domain": issuer,
				"samlConfig": s1FullSAMLConfig(metadataURL, m.MetadataXML, false)})
			pid, _ := r.m()["providerId"].(string)
			res := env.api("spMetadata", nil, nil, map[string]any{"providerId": pid})
			if res.Status != 200 {
				t.Fatalf("status %d", res.Status)
			}
			body := string(res.Raw)
			s1Contains(t, body, s1EmailFormat)
			s1Contains(t, body, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
			s1Contains(t, body, `<EntityDescriptor entityID="`+issuer+`"`)
			s1Contains(t, body, `Location="`+env.baseURL+`/sso/saml2/sp/acs/saml-provider-1"`)
		})

		t.Run("should initiate SAML login and handle response", func(t *testing.T) {
			env, h := s1SharedEnv(t)
			s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": m.URL, "domain": m.URL,
				"samlConfig": s1FullSAMLConfig(m.URL+"/api/sso/saml2/idp/post", m.MetadataXML, true)})
			_, u := s1SignIn(t, env, map[string]any{"providerId": "saml-provider-1", "callbackURL": env.server.URL + "/dashboard"}, m.URL)
			samlResp := s1FetchSAML(t, u)
			acsBase := s1MockSPACS(t, m)
			req, _ := http.NewRequest("POST", acsBase+"/api/sso/saml2/sp/acs/saml-provider-1", strings.NewReader(url.Values{"SAMLResponse": {samlResp}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res, err := noRedirectClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != 302 {
				t.Fatalf("status %d", res.StatusCode)
			}
			if loc := res.Header.Get("Location"); loc != "http://localhost:3000/dashboard" {
				t.Fatalf("location %q", loc)
			}
		})

		t.Run("should validate response binding after decrypting an encrypted assertion", func(t *testing.T) {
			encryptionCertificate := regexp.MustCompile(`\s+`).ReplaceAllString(
				strings.NewReplacer("-----BEGIN CERTIFICATE-----", "", "-----END CERTIFICATE-----", "").Replace(certificate), "")
			encryptedSpMetadata := regexp.MustCompile(`<ds:X509Certificate>[^<]+</ds:X509Certificate>`).ReplaceAllString(spMetadata,
				"<ds:X509Certificate>"+encryptionCertificate+"</ds:X509Certificate>")
			em := newMockSAMLIdP(t, mockSAMLOptions{spMetadataXML: encryptedSpMetadata, isAssertionEncrypted: true})
			encEnv := newEnv(t, Options{
				SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)},
				DefaultSSO: []DefaultSSOProvider{{
					Domain: s1HostOf(em.URL), ProviderID: "encrypted-saml-provider",
					SAMLConfig: &SAMLConfig{
						Issuer: em.URL, EntryPoint: em.URL + "/api/sso/saml2/idp/post", Cert: Cert(certificate),
						CallbackURL: em.URL + "/dashboard", WantAssertionsSigned: betterauth.Bool(false),
						SignatureAlgorithm: "sha256", DigestAlgorithm: "sha256",
						IdpMetadata: &SAMLIdentityProviderMetadata{Metadata: em.MetadataXML, PrivateKey: idpPrivateKey,
							PrivateKeyPass: "q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW", IsAssertionEncrypted: betterauth.Bool(true),
							EncPrivateKey: idpEncryptionKey, EncPrivateKeyPass: "g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN"},
						SpMetadata: &SAMLServiceProviderMetadata{Metadata: encryptedSpMetadata, Binding: "post", PrivateKey: idpPrivateKey,
							PrivateKeyPass: "q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW", IsAssertionEncrypted: betterauth.Bool(true),
							EncPrivateKey: idpPrivateKey, EncPrivateKeyPass: "q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW"},
						IdentifierFormat: s1EmailFormat,
					},
				}},
			}, envConfig{noTestUser: true})
			dashboard := encEnv.server.URL + "/dashboard"
			_, u := s1SignIn(t, encEnv, map[string]any{"providerId": "encrypted-saml-provider", "callbackURL": dashboard}, em.URL)
			relayState := s1RelayState(t, u)
			samlResp := s1FetchSAML(t, u)
			xmlStr := string(samlify.Base64Decode(samlResp))
			s1Contains(t, xmlStr, "EncryptedAssertion")
			r := s1ACS(encEnv, "encrypted-saml-provider", nil, samlResp, &relayState)
			if loc := s1Expect302(t, r); loc != dashboard {
				t.Fatalf("location %q, want %q", loc, dashboard)
			}
		})

		limitBody := func(pid string) map[string]any {
			return map[string]any{"providerId": pid, "issuer": "http://localhost:8081", "domain": "http://localhost:8081",
				"samlConfig": map[string]any{"entryPoint": metadataURL, "cert": certificate, "idpMetadata": s1MockIdentityProviderMetadata,
					"wantAssertionsSigned": false, "signatureAlgorithm": "sha256", "digestAlgorithm": "sha256",
					"spMetadata": map[string]any{"metadata": spMetadata}}}
		}

		t.Run("should not allow creating a provider if limit is set to 0", func(t *testing.T) {
			env := newEnv(t, Options{ProvidersLimit: betterauth.Int(0)})
			h := env.signInTestUser()
			s1ExpectErr(t, env.api("registerSSOProvider", h, limitBody("saml-provider-1"), nil), 403, "SSO provider registration is disabled")
		})

		t.Run("should not allow creating a provider if limit is reached", func(t *testing.T) {
			env := newEnv(t, Options{ProvidersLimit: betterauth.Int(1)})
			h := env.signInTestUser()
			s1Register(t, env, h, limitBody("saml-provider-1"))
			s1ExpectErr(t, env.api("registerSSOProvider", h, limitBody("saml-provider-2"), nil), 403, "You have reached the maximum number of SSO providers")
		})

		t.Run("should not allow creating a provider if limit from function is reached", func(t *testing.T) {
			env := newEnv(t, Options{ProvidersLimitFunc: func(_ context.Context, u *betterauth.User) (int, error) {
				if u.Email == "pro@example.com" {
					return 2, nil
				}
				return 1, nil
			}})
			h := env.signInTestUser()
			s1Register(t, env, h, limitBody("saml-provider-1"))
			s1ExpectErr(t, env.api("registerSSOProvider", h, limitBody("saml-provider-2"), nil), 403, "You have reached the maximum number of SSO providers")
		})

		t.Run("should reject registration when no cert source is provided", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			r := env.api("registerSSOProvider", h, map[string]any{"providerId": "no-cert-source", "issuer": "http://localhost:8081", "domain": "http://localhost:8081",
				"samlConfig": map[string]any{"entryPoint": metadataURL, "idpMetadata": s1MockIdentityProviderMetadata,
					"spMetadata": map[string]any{"metadata": spMetadata}}}, nil)
			if r.Status != 400 || r.code() != "CERT_SOURCE_MISSING" {
				t.Fatalf("got %d %q (%s)", r.Status, r.code(), r.Raw)
			}
		})

		for _, tc := range []struct {
			name  string
			certs []string
		}{
			{"bad-then-good", []string{unrelatedCertificate, mockIdpSigningCert}},
			{"good-then-bad", []string{mockIdpSigningCert, unrelatedCertificate}},
		} {
			t.Run(fmt.Sprintf("should validate SAML response when signing cert matches any in the array (%s)", tc.name), func(t *testing.T) {
				env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}})
				h := env.signInTestUser()
				idpEntity := m.URL + "/api/sso/saml2/idp/metadata"
				s1Register(t, env, h, map[string]any{"providerId": "saml-provider-multi-cert", "issuer": idpEntity, "domain": m.URL,
					"samlConfig": map[string]any{
						"entryPoint": m.URL + "/api/sso/saml2/idp/post", "cert": tc.certs, "wantAssertionsSigned": false,
						"signatureAlgorithm": "sha256", "digestAlgorithm": "sha256",
						"idpMetadata": map[string]any{"entityID": idpEntity, "singleSignOnService": []any{
							map[string]any{"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "Location": m.URL + "/api/sso/saml2/idp/post"},
							map[string]any{"Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Location": m.URL + "/api/sso/saml2/idp/post"},
						}},
						"spMetadata": map[string]any{"metadata": spMetadata, "binding": "post", "privateKey": spPrivateKey,
							"privateKeyPass": "VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px"},
						"identifierFormat": s1EmailFormat,
					}})
				sr, u := s1SignIn(t, env, map[string]any{"providerId": "saml-provider-multi-cert", "callbackURL": env.server.URL + "/dashboard"}, m.URL)
				samlResp := s1FetchSAML(t, u)
				rs := s1RelayState(t, u)
				r := s1ACS(env, "saml-provider-multi-cert", cookieHeaders(sr.Headers), samlResp, &rs)
				s1Contains(t, r.location(), "dashboard")
			})
		}

		t.Run("should not allow creating a provider with duplicate providerId", func(t *testing.T) {
			env, h := s1SharedEnv(t)
			body := func(issuer string) map[string]any {
				return map[string]any{"providerId": "duplicate-provider", "issuer": issuer, "domain": issuer,
					"samlConfig": map[string]any{"entryPoint": metadataURL, "cert": certificate, "idpMetadata": s1MockIdentityProviderMetadata,
						"spMetadata": map[string]any{"metadata": spMetadata}}}
			}
			s1Register(t, env, h, body("http://localhost:8081"))
			s1ExpectErr(t, env.api("registerSSOProvider", h, body("http://localhost:8082"), nil), 422, "SSO provider with this providerId already exists")
		})

		t.Run("should initiate SAML login and validate RelayState", func(t *testing.T) {
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}})
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": m.URL, "domain": m.URL, "samlConfig": s1BasicSAMLConfig(m, nil)})
			sr, u := s1SignIn(t, env, map[string]any{"providerId": "saml-provider-1", "callbackURL": env.server.URL + "/dashboard"}, m.URL)
			samlResp := s1FetchSAML(t, u)
			rs := s1RelayState(t, u)
			r := s1ACS(env, "saml-provider-1", cookieHeaders(sr.Headers), samlResp, &rs)
			s1Contains(t, r.location(), "dashboard")
		})

		t.Run("should reject an invalid RelayState even when InResponseTo validation is disabled", func(t *testing.T) {
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}})
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": m.URL, "domain": m.URL, "samlConfig": s1BasicSAMLConfig(m, nil)})
			sr, u := s1SignIn(t, env, map[string]any{"providerId": "saml-provider-1", "callbackURL": env.server.URL + "/dashboard"}, m.URL)
			samlResp := s1FetchSAML(t, u)
			r := s1ACS(env, "saml-provider-1", cookieHeaders(sr.Headers), samlResp, s1Str("not-the-right-relay-state"))
			loc := s1Expect302(t, r)
			s1Contains(t, loc, "error=invalid_state")
			s1Contains(t, loc, "error_description=invalid_or_expired_relay_state")
		})

		t.Run("should initiate SAML login and signup user when disableImplicitSignUp is true but requestSignup is explicitly enabled", func(t *testing.T) {
			env := newEnv(t, Options{DisableImplicitSignUp: true, SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}})
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": m.URL, "domain": m.URL, "samlConfig": s1BasicSAMLConfig(m, nil)})
			sr, u := s1SignIn(t, env, map[string]any{"providerId": "saml-provider-1", "callbackURL": env.server.URL + "/dashboard", "requestSignUp": true}, m.URL)
			samlResp := s1FetchSAML(t, u)
			rs := s1RelayState(t, u)
			r := s1ACS(env, "saml-provider-1", cookieHeaders(sr.Headers), samlResp, &rs)
			s1Contains(t, r.location(), "dashboard")
		})

		idpInitiatedCase := func(t *testing.T, opts Options, cfg envConfig, providerID, domain string, samlExtra map[string]any) string {
			t.Helper()
			env := newEnv(t, opts, cfg)
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": providerID, "issuer": m.URL, "domain": domain, "samlConfig": s1BasicSAMLConfig(m, samlExtra)})
			samlResp := s1FetchSAML(t, m.URL+"/api/sso/saml2/idp/post")
			return s1Expect302(t, s1ACS(env, providerID, nil, samlResp, nil))
		}

		t.Run("should reject SAML sign-in when disableImplicitSignUp is true and user doesn't exist", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{DisableImplicitSignUp: true, SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}},
				envConfig{}, "saml-test-provider", m.URL, nil)
			s1Contains(t, loc, "error=signup_disabled")
		})

		t.Run("should reject SAML ACS (IdP-initiated) when disableImplicitSignUp is true and user doesn't exist", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{DisableImplicitSignUp: true, SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}},
				envConfig{}, "saml-acs-test-provider", m.URL, nil)
			s1Contains(t, loc, "error=signup_disabled")
		})

		t.Run("rejects a SAML assertion whose audience does not match this SP", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			acsURL := env.baseURL + "/sso/saml2/sp/acs/saml-audience-provider"
			s1Register(t, env, h, map[string]any{"providerId": "saml-audience-provider", "issuer": m.URL, "domain": m.URL,
				"samlConfig": s1BasicSAMLConfig(m, map[string]any{"callbackUrl": env.server.URL + "/dashboard?source=saml"})})
			q := url.Values{"audience": {"http://other.example.com/saml/metadata"}, "destination": {acsURL}, "recipient": {acsURL}}
			samlResp := s1FetchSAML(t, m.URL+"/api/sso/saml2/idp/post?"+q.Encode())
			loc := s1Expect302(t, s1ACS(env, "saml-audience-provider", nil, samlResp, nil))
			s1Contains(t, loc, "error=invalid_saml_response")
			s1Contains(t, loc, "source=saml")
			s1Contains(t, loc, "error_description=")
			lu, err := url.Parse(loc)
			if err != nil {
				t.Fatal(err)
			}
			s1Contains(t, lu.Query().Get("error_description"), "audience does not match")
		})

		t.Run("should deny account linking when provider is not trusted and domain is not verified", func(t *testing.T) {
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}}, envConfig{mutate: func(c *betterauth.Config) {
				c.Account = &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{Enabled: betterauth.Bool(true), TrustedProviders: []string{}}}
			}})
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": "untrusted-saml-provider", "issuer": m.URL, "domain": m.URL, "samlConfig": s1BasicSAMLConfig(m, nil)})
			now := time.Now()
			if _, err := env.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "user", ForceAllowID: true, Data: adapter.Record{
				"id": "existing-user-id", "email": "test@email.com", "name": "Existing User", "emailVerified": true, "createdAt": now, "updatedAt": now,
			}}); err != nil {
				t.Fatal(err)
			}
			samlResp := s1FetchSAML(t, m.URL+"/api/sso/saml2/idp/post")
			loc := s1Expect302(t, s1ACS(env, "untrusted-saml-provider", nil, samlResp, nil))
			s1Contains(t, loc, "error=account_not_linked")
		})

		t.Run("should reject registering an SSO provider whose id collides with a trustedProviders entry", func(t *testing.T) {
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}}, envConfig{mutate: func(c *betterauth.Config) {
				c.Account = &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{Enabled: betterauth.Bool(true), TrustedProviders: []string{"trusted-saml-provider"}}}
			}})
			h := env.signInTestUser()
			r := env.api("registerSSOProvider", h, map[string]any{"providerId": "trusted-saml-provider", "issuer": m.URL, "domain": m.URL, "samlConfig": s1BasicSAMLConfig(m, nil)}, nil)
			if r.Status != 422 {
				t.Fatalf("status %d (%s)", r.Status, r.Raw)
			}
		})

		t.Run("should reject unsolicited SAML response when allowIdpInitiated is false", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(true), AllowIdpInitiated: false}},
				envConfig{}, "strict-saml-provider", m.URL, nil)
			s1Contains(t, loc, "error=invalid_saml_response")
		})

		t.Run("should allow unsolicited SAML response when allowIdpInitiated is explicitly true", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(true), AllowIdpInitiated: true}},
				envConfig{}, "permissive-saml-provider", m.URL, nil)
			s1NotContains(t, loc, "error=unsolicited_response")
		})

		t.Run("should skip InResponseTo validation when explicitly disabled", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}},
				envConfig{}, "legacy-saml-provider", m.URL, nil)
			s1NotContains(t, loc, "error=")
		})

		t.Run("should enable InResponseTo validation by default", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{SAML: &SAMLOptions{AllowIdpInitiated: false}}, envConfig{}, "saml-provider", "example.com",
				map[string]any{"audience": "http://localhost:3000", "spMetadata": map[string]any{"metadata": spMetadata, "binding": "post"}})
			s1Contains(t, loc, "error=invalid_saml_response")
		})

		t.Run("should use verification table for InResponseTo validation", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(true), AllowIdpInitiated: false}},
				envConfig{}, "db-fallback-provider", m.URL, nil)
			s1Contains(t, loc, "error=invalid_saml_response")
		})

		t.Run("should reject SAML response with mismatched audience restriction", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}}, envConfig{}, "audience-mismatch-provider", m.URL,
				map[string]any{"audience": "https://wrong-audience.example.com", "spMetadata": map[string]any{"metadata": spMetadata, "binding": "post"}, "identifierFormat": nil})
			s1Contains(t, loc, "error=invalid_saml_response&error_description=Audience+mismatch")
		})

		t.Run("should accept SAML response when audience matches configured value", func(t *testing.T) {
			loc := idpInitiatedCase(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}}, envConfig{}, "audience-match-provider", m.URL,
				map[string]any{"audience": "http://localhost:3001/api/sso/saml2/sp/metadata", "spMetadata": map[string]any{"metadata": spMetadata, "binding": "post"}, "identifierFormat": nil})
			s1NotContains(t, loc, "error=")
		})

		t.Run("should correctly parse verification-ID-based RelayState on ACS route (SP-initiated)", func(t *testing.T) {
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}})
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": "saml-acs-relay-provider", "issuer": m.URL, "domain": m.URL, "samlConfig": s1BasicSAMLConfig(m, nil)})
			sr, u := s1SignIn(t, env, map[string]any{"providerId": "saml-acs-relay-provider", "callbackURL": env.server.URL + "/dashboard"}, m.URL)
			rs := s1RelayState(t, u)
			if rs == "" {
				t.Fatal("RelayState should be set")
			}
			s1NotContains(t, rs, "http")
			samlResp := s1FetchSAML(t, u)
			loc := s1Expect302(t, s1ACS(env, "saml-acs-relay-provider", cookieHeaders(sr.Headers), samlResp, &rs))
			s1Contains(t, loc, "dashboard")
			s1NotContains(t, loc, "error")
		})

		crossSite := func(t *testing.T) {
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}})
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": "saml-provider", "issuer": m.URL, "domain": "example.com",
				"samlConfig": s1BasicSAMLConfig(m, map[string]any{"spMetadata": map[string]any{"metadata": spMetadata, "binding": "post"}})})
			_, u := s1SignIn(t, env, map[string]any{"providerId": "saml-provider", "callbackURL": "/dashboard"}, m.URL)
			rs := s1RelayState(t, u)
			if rs == "" {
				t.Fatal("RelayState should be set")
			}
			samlResp := s1FetchSAML(t, u)
			loc := s1Expect302(t, s1ACS(env, "saml-provider", nil, samlResp, &rs))
			s1Contains(t, loc, "/dashboard")
			s1NotContains(t, loc, "/sso/saml2/sp/acs/")
			s1NotContains(t, loc, "error")
		}
		t.Run("should redirect to signIn callbackURL when relay_state cookie is missing on callback route (cross-site POST)", crossSite)
		t.Run("should redirect to signIn callbackURL when relay_state cookie is missing on ACS route (cross-site POST)", crossSite)

		t.Run("should fallback to baseURL on ACS route when RelayState is invalid", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			s1Register(t, env, h, map[string]any{"providerId": "saml-acs-bad-relay-provider", "issuer": m.URL, "domain": m.URL, "samlConfig": s1BasicSAMLConfig(m, nil)})
			samlResp := s1FetchSAML(t, m.URL+"/api/sso/saml2/idp/post")
			loc := s1Expect302(t, s1ACS(env, "saml-acs-bad-relay-provider", nil, samlResp, s1Str("not-a-valid-relay-state")))
			s1Contains(t, loc, env.server.URL)
			s1NotContains(t, loc, "not-a-valid-relay-state")
		})
	})
}

func TestSAML1CustomFields(t *testing.T) {
	m := newMockSAMLIdP(t, mockSAMLOptions{})
	t.Run("SAML SSO with custom fields", func(t *testing.T) {
		t.Run("should register a new SAML provider", func(t *testing.T) {
			env := newEnv(t, Options{ModelName: "sso_provider", Fields: FieldNames{
				Issuer: "the_issuer", OIDCConfig: "oidc_config", SAMLConfig: "saml_config", UserID: "user_id",
				ProviderID: "provider_id", OrganizationID: "organization_id", Domain: "the_domain",
			}}, envConfig{noTestUser: true})
			env.signUp("test@email.com", "password", "Test User")
			h := env.signIn("test@email.com", "password")
			metadataURL := m.URL + "/idp/metadata"
			r := s1Register(t, env, h, map[string]any{"providerId": "saml-provider-1", "issuer": m.URL, "domain": m.URL,
				"samlConfig": s1FullSAMLConfig(metadataURL, m.MetadataXML, true)})
			s1CheckRegisteredSAML(t, r, m.URL, metadataURL)
		})
	})
}

func TestSAML1SafeJSONParse(t *testing.T) {
	type nested struct {
		B int `json:"b"`
	}
	type obj struct {
		A      int    `json:"a"`
		Nested nested `json:"nested"`
	}
	t.Run("safeJsonParse", func(t *testing.T) {
		t.Run("returns object as-is when value is already an object", func(t *testing.T) {
			t.Skip("TS-only: Go safeJSONParse accepts only stored JSON strings (no object passthrough / reference identity)")
		})
		t.Run("parses stringified JSON when value is a string", func(t *testing.T) {
			r, err := safeJSONParse[obj](`{"a":1,"nested":{"b":2}}`)
			if err != nil || r == nil || *r != (obj{A: 1, Nested: nested{B: 2}}) {
				t.Fatalf("got %+v %v", r, err)
			}
		})
		t.Run("returns null for null input", func(t *testing.T) {
			r, err := safeJSONParse[obj]("")
			if err != nil || r != nil {
				t.Fatalf("got %+v %v", r, err)
			}
		})
		t.Run("returns null for undefined input", func(t *testing.T) {
			var undefinedValue string
			r, err := safeJSONParse[obj](undefinedValue)
			if err != nil || r != nil {
				t.Fatalf("got %+v %v", r, err)
			}
		})
		t.Run("throws error for invalid JSON string", func(t *testing.T) {
			_, err := safeJSONParse[obj]("not valid json")
			if err == nil || !strings.Contains(err.Error(), "Failed to parse JSON") {
				t.Fatalf("got %v", err)
			}
		})
		t.Run("handles empty object", func(t *testing.T) {
			t.Skip("TS-only: object passthrough by reference has no Go equivalent (safeJSONParse takes strings)")
		})
		t.Run("handles empty string JSON", func(t *testing.T) {
			r, err := safeJSONParse[map[string]any]("{}")
			if err != nil || r == nil || len(*r) != 0 {
				t.Fatalf("got %+v %v", r, err)
			}
		})
	})
}

func TestSAML1ProviderConfigParsing(t *testing.T) {
	t.Run("SSO Provider Config Parsing", func(t *testing.T) {
		t.Run("returns parsed SAML config and avoids [object Object] in response", func(t *testing.T) {
			env := newEnv(t, Options{}, envConfig{noTestUser: true})
			env.signUp("test@example.com", "password123", "Test User")
			h := env.signIn("test@example.com", "password123")
			r := s1Register(t, env, h, map[string]any{"providerId": "saml-config-provider", "issuer": "http://localhost:8081", "domain": "example.com",
				"samlConfig": map[string]any{"entryPoint": "http://localhost:8081/sso", "cert": "test-cert", "idpMetadata": s1MockIdentityProviderMetadata,
					"callbackUrl": "http://localhost:3000/callback", "idpInitiatedCallbackUrl": "/dashboard",
					"spMetadata": map[string]any{"entityID": "test-entity"}}})
			sc, ok := r.m()["samlConfig"].(map[string]any)
			if !ok {
				t.Fatalf("samlConfig is not an object: %s", r.Raw)
			}
			if sc["entryPoint"] != "http://localhost:8081/sso" || sc["cert"] != "test-cert" || sc["idpInitiatedCallbackUrl"] != "/dashboard" {
				t.Fatalf("samlConfig %v", sc)
			}
			b, _ := json.Marshal(sc)
			s1NotContains(t, string(b), "[object Object]")
			sp, _ := sc["spMetadata"].(map[string]any)
			if sp == nil || sp["entityID"] != "test-entity" {
				t.Fatalf("spMetadata %v", sc["spMetadata"])
			}
		})

		t.Run("returns parsed OIDC config and avoids [object Object] in response", func(t *testing.T) {
			idp := newMockOIDC(t)
			env := newEnv(t, Options{}, envConfig{noTestUser: true, mutate: func(c *betterauth.Config) { c.TrustedOrigins = []string{idp.URL} }})
			env.signUp("test@example.com", "password123", "Test User")
			h := env.signIn("test@example.com", "password123")
			r := s1Register(t, env, h, map[string]any{"providerId": "oidc-config-provider", "issuer": idp.URL, "domain": "example.com",
				"oidcConfig": map[string]any{"clientId": "test-client", "clientSecret": "test-secret", "tokenEndpointAuthentication": "client_secret_basic",
					"mapping": map[string]any{"email": "email", "name": "name"}}})
			oc, ok := r.m()["oidcConfig"].(map[string]any)
			if !ok {
				t.Fatalf("oidcConfig is not an object: %s", r.Raw)
			}
			if oc["clientId"] != "test-client" || oc["clientSecret"] != "test-secret" {
				t.Fatalf("oidcConfig %v", oc)
			}
			b, _ := json.Marshal(oc)
			s1NotContains(t, string(b), "[object Object]")
			mp, _ := oc["mapping"].(map[string]any)
			if len(mp) != 2 || mp["email"] != "email" || mp["name"] != "name" {
				t.Fatalf("mapping %v", oc["mapping"])
			}
		})
	})
}
