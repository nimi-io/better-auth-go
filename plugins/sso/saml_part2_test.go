package sso

// Port of saml.test.ts lines 3537-5637: "SAML SSO - IdP Initiated Flow" through
// "SAML SSO - Single Assertion Validation".

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

// ---- helpers ----

// s2RegisterFull registers a SAML provider with the full mock IdP metadata config used
// by most upstream cases (issuer/domain http://localhost:8081 -> idp.URL).
func s2RegisterFull(t *testing.T, env *testEnv, h http.Header, idp *mockSAMLIdP, providerID, domain, entryPoint string, extra map[string]any) {
	t.Helper()
	cfg := map[string]any{
		"entryPoint":           entryPoint,
		"cert":                 certificate,
		"wantAssertionsSigned": false,
		"signatureAlgorithm":   "sha256",
		"digestAlgorithm":      "sha256",
		"idpMetadata":          map[string]any{"metadata": idp.MetadataXML},
		"spMetadata":           map[string]any{"metadata": spMetadata},
		"identifierFormat":     "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	env.mustAPI("registerSSOProvider", h, map[string]any{
		"providerId": providerID, "issuer": idp.URL, "domain": domain, "samlConfig": cfg,
	}, nil)
}

// s2RegisterEntityID registers a provider whose idpMetadata is mockIdentityProviderMetadata
// ({entityID}).
func s2RegisterEntityID(t *testing.T, env *testEnv, h http.Header, idp *mockSAMLIdP, providerID, domain string) {
	t.Helper()
	env.mustAPI("registerSSOProvider", h, map[string]any{
		"providerId": providerID, "issuer": idp.URL, "domain": domain,
		"samlConfig": map[string]any{
			"entryPoint":           idp.URL + "/idp/metadata",
			"cert":                 certificate,
			"idpMetadata":          map[string]any{"entityID": idp.URL + "/api/sso/saml2/idp/metadata"},
			"wantAssertionsSigned": false,
			"signatureAlgorithm":   "sha256",
			"digestAlgorithm":      "sha256",
			"spMetadata":           map[string]any{"metadata": spMetadata},
		},
	}, nil)
}

// s2FetchSAML fetches a SAMLResponse from the mock IdP post endpoint.
func s2FetchSAML(t *testing.T, idp *mockSAMLIdP, query string) string {
	t.Helper()
	u := idp.URL + "/api/sso/saml2/idp/post"
	if query != "" {
		u += "?" + query
	}
	s, status, body := fetchSAMLResponse(t, u)
	if status != 200 || s == "" {
		t.Fatalf("Failed to get SAML response from mock IdP: %d %v", status, body)
	}
	return s
}

// s2ACS calls auth.api.acsEndpoint directly.
func s2ACS(env *testEnv, method, providerID string, headers http.Header, body map[string]any, query map[string]any) *result {
	env.t.Helper()
	in := betterauth.CallInput{Method: method, Headers: headers, Params: map[string]string{"providerId": providerID}, Query: query}
	if body != nil {
		in.Body = body
	}
	return env.apiIn("acsEndpoint", in)
}

func s2b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// s2PostRaw posts a form without touching testing.T (safe from goroutines).
func s2PostRaw(u string, form url.Values) (int, string, error) {
	req, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := noRedirectClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode, res.Header.Get("Location"), nil
}

func s2ExpectThrow(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q, got nil", msg)
	}
	got := err.Error()
	if ae, ok := betterauth.AsAPIError(err); ok {
		got = ae.Message()
	}
	if !strings.Contains(got, msg) {
		t.Fatalf("expected error containing %q, got %q", msg, got)
	}
}

func s2ExpectNoThrow(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func s2Skew(ms int64) TimestampValidationOptions { return TimestampValidationOptions{ClockSkew: &ms} }

func s2ISO(d time.Duration) string { return samlify.ISOTime(time.Now().Add(d)) }

func s2SAMLEnv(t *testing.T, disableIRT bool) (*testEnv, http.Header) {
	t.Helper()
	o := Options{}
	if disableIRT {
		o.SAML = &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}
	}
	env := newEnv(t, o)
	return env, env.signInTestUser()
}

// ---- SAML SSO - IdP Initiated Flow ----

func TestSAML2IdPInitiatedFlow(t *testing.T) {
	idp := newMockSAMLIdP(t, mockSAMLOptions{})
	entry := idp.URL + "/idp/post"

	t.Run("should handle IdP-initiated flow with GET after POST redirect", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "idp-initiated-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "idp-initiated-provider", nil, map[string]any{"SAMLResponse": sr}, nil)
		if post.Status != 302 {
			t.Fatalf("post status %d %s", post.Status, post.Raw)
		}
		if post.location() != env.server.URL {
			t.Fatalf("post location %q want %q", post.location(), env.server.URL)
		}
		get := s2ACS(env, "GET", "idp-initiated-provider", cookieHeaders(post.Headers), nil,
			map[string]any{"RelayState": env.server.URL + "/dashboard"})
		if get.Status != 302 {
			t.Fatalf("get status %d %s", get.Status, get.Raw)
		}
		if get.location() != env.server.URL+"/dashboard" {
			t.Fatalf("get location %q", get.location())
		}
	})

	t.Run("should reject direct GET request without session", func(t *testing.T) {
		env := newEnv(t, Options{})
		get := s2ACS(env, "GET", "test-provider", nil, nil, nil)
		if get.Status != 302 {
			t.Fatalf("status %d %s", get.Status, get.Raw)
		}
		loc := get.location()
		if !strings.Contains(loc, "/error") || !strings.Contains(loc, "error=invalid_request") {
			t.Fatalf("location %q", loc)
		}
	})

	t.Run("should redirect to baseURL after ACS, not back to the ACS route", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		callbackRouteURL := env.baseURL + "/sso/saml2/sp/acs/loop-test-provider"
		s2RegisterFull(t, env, h, idp, "loop-test-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "loop-test-provider", nil, map[string]any{"SAMLResponse": sr}, nil)
		if post.Status != 302 {
			t.Fatalf("status %d %s", post.Status, post.Raw)
		}
		if post.location() == callbackRouteURL {
			t.Fatalf("redirected back to ACS route")
		}
		if post.location() != env.server.URL {
			t.Fatalf("location %q want %q", post.location(), env.server.URL)
		}
	})

	t.Run("should handle GET request with RelayState in query", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "relaystate-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "relaystate-provider", nil, map[string]any{"SAMLResponse": sr}, nil)
		get := s2ACS(env, "GET", "relaystate-provider", cookieHeaders(post.Headers), nil,
			map[string]any{"RelayState": env.server.URL + "/custom-path"})
		if get.Status != 302 {
			t.Fatalf("status %d %s", get.Status, get.Raw)
		}
		if get.location() != env.server.URL+"/custom-path" {
			t.Fatalf("location %q", get.location())
		}
	})

	t.Run("should handle GET request when POST redirects to callback URL (original issue scenario)", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		callbackRouteURL := env.baseURL + "/sso/saml2/sp/acs/issue-6615-provider"
		s2RegisterFull(t, env, h, idp, "issue-6615-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "issue-6615-provider", nil, map[string]any{"SAMLResponse": sr}, nil)
		if post.Status != 302 {
			t.Fatalf("status %d %s", post.Status, post.Raw)
		}
		if post.location() == callbackRouteURL || post.location() != env.server.URL {
			t.Fatalf("post location %q", post.location())
		}
		get := s2ACS(env, "GET", "issue-6615-provider", cookieHeaders(post.Headers), nil, nil)
		if get.Status != 302 {
			t.Fatalf("get status %d %s", get.Status, get.Raw)
		}
		if get.location() != env.server.URL {
			t.Fatalf("get location %q", get.location())
		}
	})

	t.Run("should prevent open redirect with malicious RelayState URL", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "open-redirect-test-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "open-redirect-test-provider", nil,
			map[string]any{"SAMLResponse": sr, "RelayState": "https://evil.com/phishing"}, nil)
		if post.Status != 302 {
			t.Fatalf("status %d %s", post.Status, post.Raw)
		}
		loc := post.location()
		if strings.Contains(loc, "evil.com") || !strings.Contains(loc, "error=invalid_state") {
			t.Fatalf("location %q", loc)
		}
	})

	t.Run("should prevent open redirect via GET with malicious RelayState", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "open-redirect-get-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "open-redirect-get-provider", nil, map[string]any{"SAMLResponse": sr}, nil)
		get := s2ACS(env, "GET", "open-redirect-get-provider", cookieHeaders(post.Headers), nil,
			map[string]any{"RelayState": "https://evil.com/steal-cookies"})
		if get.Status != 302 {
			t.Fatalf("status %d %s", get.Status, get.Raw)
		}
		loc := get.location()
		if strings.Contains(loc, "evil.com") || loc != env.server.URL {
			t.Fatalf("location %q", loc)
		}
	})

	t.Run("should reject a raw relative-path RelayState instead of trusting it", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "relative-path-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "relative-path-provider", nil,
			map[string]any{"SAMLResponse": sr, "RelayState": "/dashboard/settings"}, nil)
		if post.Status != 302 {
			t.Fatalf("status %d %s", post.Status, post.Raw)
		}
		if !strings.Contains(post.location(), "error=invalid_state") {
			t.Fatalf("location %q", post.location())
		}
	})

	t.Run("should block protocol-relative URL attacks (//evil.com)", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "protocol-relative-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		post := s2ACS(env, "POST", "protocol-relative-provider", nil,
			map[string]any{"SAMLResponse": sr, "RelayState": "//evil.com/phishing"}, nil)
		if post.Status != 302 {
			t.Fatalf("status %d %s", post.Status, post.Raw)
		}
		loc := post.location()
		if strings.Contains(loc, "evil.com") || !strings.Contains(loc, "error=invalid_state") {
			t.Fatalf("location %q", loc)
		}
	})
}

// ---- SAML SSO - Timestamp Validation ----

func TestSAML2TimestampValidation(t *testing.T) {
	v := ValidateSAMLTimestamp
	none := TimestampValidationOptions{}

	t.Run("Valid assertions within time window", func(t *testing.T) {
		t.Run("should accept assertion with current NotBefore and future NotOnOrAfter", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotBefore: s2ISO(0), NotOnOrAfter: s2ISO(5 * time.Minute)}, none))
		})
		t.Run("should accept assertion within clock skew tolerance (expired 2 min ago with 5 min skew)", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotOnOrAfter: s2ISO(-2 * time.Minute)}, none))
		})
		t.Run("should accept assertion with NotBefore slightly in future (within clock skew)", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotBefore: s2ISO(2 * time.Minute)}, none))
		})
	})

	t.Run("NotBefore validation (future-dated assertions)", func(t *testing.T) {
		t.Run("should reject assertion with NotBefore too far in future (beyond clock skew)", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{NotBefore: s2ISO(10 * time.Minute)}, none), "SAML assertion is not yet valid")
		})
		t.Run("should reject with custom strict clock skew (1 second)", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{NotBefore: s2ISO(3 * time.Second)}, s2Skew(1000)), "SAML assertion is not yet valid")
		})
	})

	t.Run("NotOnOrAfter validation (expired assertions)", func(t *testing.T) {
		t.Run("should reject expired assertion (NotOnOrAfter in past beyond clock skew)", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{NotOnOrAfter: s2ISO(-10 * time.Minute)}, none), "SAML assertion has expired")
		})
		t.Run("should reject with custom strict clock skew (1 second)", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{NotOnOrAfter: s2ISO(-3 * time.Second)}, s2Skew(1000)), "SAML assertion has expired")
		})
	})

	t.Run("Boundary conditions (exactly at window edges)", func(t *testing.T) {
		// vi.useFakeTimers equivalent: inside a synctest bubble time.Now() is frozen.
		skew := time.Duration(DefaultClockSkewMS) * time.Millisecond
		frozen := func(t *testing.T, f func(t *testing.T, fixed time.Time)) {
			synctest.Test(t, func(t *testing.T) { f(t, time.Now()) })
		}
		t.Run("should accept assertion expiring exactly at clock skew boundary", func(t *testing.T) {
			frozen(t, func(t *testing.T, fixed time.Time) {
				s2ExpectNoThrow(t, v(&SAMLConditions{NotOnOrAfter: samlify.ISOTime(fixed.Add(-skew))}, none))
			})
		})
		t.Run("should reject assertion expiring 1ms beyond clock skew boundary", func(t *testing.T) {
			frozen(t, func(t *testing.T, fixed time.Time) {
				s2ExpectThrow(t, v(&SAMLConditions{NotOnOrAfter: samlify.ISOTime(fixed.Add(-skew - time.Millisecond))}, none), "SAML assertion has expired")
			})
		})
		t.Run("should accept assertion with NotBefore exactly at clock skew boundary", func(t *testing.T) {
			frozen(t, func(t *testing.T, fixed time.Time) {
				s2ExpectNoThrow(t, v(&SAMLConditions{NotBefore: samlify.ISOTime(fixed.Add(skew))}, none))
			})
		})
		t.Run("should reject assertion with NotBefore 1ms beyond clock skew boundary", func(t *testing.T) {
			frozen(t, func(t *testing.T, fixed time.Time) {
				s2ExpectThrow(t, v(&SAMLConditions{NotBefore: samlify.ISOTime(fixed.Add(skew + time.Millisecond))}, none), "SAML assertion is not yet valid")
			})
		})
	})

	t.Run("Missing timestamps behavior", func(t *testing.T) {
		t.Run("should accept missing timestamps when requireTimestamps is false (default)", func(t *testing.T) {
			s2ExpectNoThrow(t, v(nil, TimestampValidationOptions{RequireTimestamps: false}))
		})
		t.Run("should accept empty conditions when requireTimestamps is false", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{}, TimestampValidationOptions{RequireTimestamps: false}))
		})
		t.Run("should reject missing timestamps when requireTimestamps is true", func(t *testing.T) {
			s2ExpectThrow(t, v(nil, TimestampValidationOptions{RequireTimestamps: true}), "SAML assertion missing required timestamp conditions")
		})
		t.Run("should reject empty conditions when requireTimestamps is true", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{}, TimestampValidationOptions{RequireTimestamps: true}), "SAML assertion missing required timestamp conditions")
		})
		t.Run("should accept assertions with only NotBefore (valid)", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotBefore: s2ISO(0)}, none))
		})
		t.Run("should accept assertions with only NotOnOrAfter (valid, in future)", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotOnOrAfter: s2ISO(10 * time.Minute)}, none))
		})
	})

	t.Run("Custom clock skew configuration", func(t *testing.T) {
		t.Run("should use custom clockSkew when provided", func(t *testing.T) {
			twoSecondsAgo := s2ISO(-2 * time.Second)
			s2ExpectThrow(t, v(&SAMLConditions{NotOnOrAfter: twoSecondsAgo}, s2Skew(1000)), "SAML assertion has expired")
			s2ExpectNoThrow(t, v(&SAMLConditions{NotOnOrAfter: twoSecondsAgo}, s2Skew(5*60*1000)))
		})
		t.Run("should use default 5 minute clock skew when not specified", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotOnOrAfter: s2ISO(-4 * time.Minute)}, none))
			s2ExpectThrow(t, v(&SAMLConditions{NotOnOrAfter: s2ISO(-6 * time.Minute)}, none), "SAML assertion has expired")
		})
	})

	t.Run("Malformed timestamp handling", func(t *testing.T) {
		t.Run("should reject malformed NotBefore timestamp", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{NotBefore: "not-a-valid-date"}, none), "SAML assertion has invalid NotBefore timestamp")
		})
		t.Run("should reject malformed NotOnOrAfter timestamp", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{NotOnOrAfter: "invalid-timestamp"}, none), "SAML assertion has invalid NotOnOrAfter timestamp")
		})
		t.Run("should treat empty string timestamps as missing (falsy values)", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotBefore: ""}, none))
			s2ExpectNoThrow(t, v(&SAMLConditions{NotOnOrAfter: ""}, none))
		})
		t.Run("should reject garbage data in timestamps", func(t *testing.T) {
			s2ExpectThrow(t, v(&SAMLConditions{NotBefore: "abc123xyz", NotOnOrAfter: "!@#$%^&*()"}, none), "SAML assertion has invalid NotBefore timestamp")
		})
		t.Run("should accept valid ISO 8601 timestamps", func(t *testing.T) {
			s2ExpectNoThrow(t, v(&SAMLConditions{NotBefore: s2ISO(0), NotOnOrAfter: s2ISO(10 * time.Minute)}, none))
		})
	})
}

// ---- SAML ACS Origin Check Bypass ----

func TestSAML2ACSOriginCheckBypass(t *testing.T) {
	idp := newMockSAMLIdP(t, mockSAMLOptions{})
	fake := s2b64("<fake-saml-response/>")

	t.Run("Positive: SAML endpoints allow external IdP origins", func(t *testing.T) {
		t.Run("should allow SAML callback POST from external IdP origin", func(t *testing.T) {
			env, h := s2SAMLEnv(t, true)
			s2RegisterEntityID(t, env, h, idp, "origin-bypass-callback", "origin-bypass.com")
			hd := http.Header{"Origin": {"http://external-idp.example.com"}, "Cookie": {h.Get("Cookie")}}
			res := env.postForm("/sso/saml2/sp/acs/origin-bypass-callback", hd, url.Values{"SAMLResponse": {fake}, "RelayState": {""}})
			if res.Status == 403 {
				t.Fatalf("origin check not bypassed: %s", res.Raw)
			}
		})
		t.Run("should allow ACS endpoint POST from external IdP origin", func(t *testing.T) {
			env, h := s2SAMLEnv(t, true)
			s2RegisterEntityID(t, env, h, idp, "origin-bypass-acs", "origin-bypass-acs.com")
			hd := http.Header{"Origin": {"http://idp.external.com"}, "Cookie": {h.Get("Cookie")}}
			res := env.postForm("/sso/saml2/sp/acs/origin-bypass-acs", hd, url.Values{"SAMLResponse": {fake}})
			if res.Status == 403 {
				t.Fatalf("origin check not bypassed: %s", res.Raw)
			}
		})
	})

	t.Run("Negative: Non-SAML endpoints remain protected", func(t *testing.T) {
		t.Run("should block POST to sign-up with untrusted origin when origin check is enabled", func(t *testing.T) {
			env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}}, envConfig{
				mutate: func(c *betterauth.Config) {
					c.Advanced = &betterauth.AdvancedConfig{DisableCSRFCheck: betterauth.Bool(false), DisableOriginCheck: betterauth.Bool(false)}
				},
			})
			res := env.do("POST", "/sign-up/email", http.Header{
				"Origin": {"http://attacker.com"},
				"Cookie": {"better-auth.session_token=fake-session"},
			}, map[string]any{"email": "victim@example.com", "password": "password123", "name": "Victim"})
			if res.Status != 403 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
		})
	})

	t.Run("Edge cases", func(t *testing.T) {
		t.Run("should allow GET requests to SAML metadata regardless of origin", func(t *testing.T) {
			env := newEnv(t, Options{})
			res := env.do("GET", "/sso/saml2/sp/metadata", http.Header{"Origin": {"http://any-origin.com"}}, nil)
			if res.Status == 403 {
				t.Fatalf("status 403 %s", res.Raw)
			}
		})
		t.Run("should not redirect to malicious RelayState URLs", func(t *testing.T) {
			env := newEnv(t, Options{})
			h := env.signInTestUser()
			s2RegisterEntityID(t, env, h, idp, "relay-security-test", "relay-security.com")
			res := env.postForm("/sso/saml2/sp/acs/relay-security-test", http.Header{"Origin": {"http://idp.example.com"}},
				url.Values{"SAMLResponse": {fake}, "RelayState": {"http://malicious-site.com/steal-token"}})
			if res.Status == 302 && strings.Contains(res.location(), "malicious-site.com") {
				t.Fatalf("redirected to malicious url: %s", res.location())
			}
		})
	})
}

// ---- SAML Response Security ----

func TestSAML2ResponseSecurity(t *testing.T) {
	idp := newMockSAMLIdP(t, mockSAMLOptions{})

	t.Run("should reject forged/unsigned SAML responses", func(t *testing.T) {
		env := newEnv(t, Options{})
		h := env.signInTestUser()
		s2RegisterEntityID(t, env, h, idp, "security-test-provider", "security-test.com")
		forged := `
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion>
					<saml:Subject>
						<saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">attacker@evil.com</saml2:NameID>
					</saml:Subject>
				</saml:Assertion>
			</samlp:Response>
		`
		res := env.postForm("/sso/saml2/sp/acs/security-test-provider", nil, url.Values{"SAMLResponse": {s2b64(forged)}, "RelayState": {""}})
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		if !strings.Contains(res.location(), "error=") {
			t.Fatalf("location %q", res.location())
		}
	})

	t.Run("should reject SAML response with tampered nameID", func(t *testing.T) {
		env := newEnv(t, Options{})
		h := env.signInTestUser()
		s2RegisterEntityID(t, env, h, idp, "tamper-test-provider", "tamper-test.com")
		tampered := `<?xml version="1.0"?>
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
				<saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">admin@victim.com</saml2:NameID>
			</samlp:Response>`
		res := env.postForm("/sso/saml2/sp/acs/tamper-test-provider", nil, url.Values{"SAMLResponse": {s2b64(tampered)}, "RelayState": {""}})
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		if !strings.Contains(res.location(), "error=") {
			t.Fatalf("location %q", res.location())
		}
	})
}

// ---- SAML SSO - Size Limit Validation ----

func TestSAML2SizeLimitValidation(t *testing.T) {
	t.Run("should export default size limit constants", func(t *testing.T) {
		if DefaultMaxSAMLResponseSize != 256*1024 {
			t.Fatalf("DefaultMaxSAMLResponseSize = %d", DefaultMaxSAMLResponseSize)
		}
		if DefaultMaxSAMLMetadataSize != 100*1024 {
			t.Fatalf("DefaultMaxSAMLMetadataSize = %d", DefaultMaxSAMLMetadataSize)
		}
	})
}

// ---- SAML SSO - Assertion Replay Protection ----

func TestSAML2AssertionReplayProtection(t *testing.T) {
	idp := newMockSAMLIdP(t, mockSAMLOptions{})
	entry := idp.URL + "/api/sso/saml2/idp/post"

	replay := func(t *testing.T, providerID string) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, providerID, idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		first := env.postForm("/sso/saml2/sp/acs/"+providerID, nil, url.Values{"SAMLResponse": {sr}})
		if first.Status != 302 {
			t.Fatalf("first status %d %s", first.Status, first.Raw)
		}
		if strings.Contains(first.location(), "error") {
			t.Fatalf("first location %q", first.location())
		}
		second := env.postForm("/sso/saml2/sp/acs/"+providerID, nil, url.Values{"SAMLResponse": {sr}})
		if second.Status != 302 {
			t.Fatalf("replay status %d %s", second.Status, second.Raw)
		}
		if !strings.Contains(second.location(), "error=replay_detected") {
			t.Fatalf("replay location %q", second.location())
		}
	}

	t.Run("should reject replayed SAML assertion (same assertion submitted twice)", func(t *testing.T) {
		replay(t, "replay-test-provider")
	})
	t.Run("should reject replayed SAML assertion on ACS endpoint", func(t *testing.T) {
		replay(t, "acs-replay-test-provider")
	})
	t.Run("should reject cross-endpoint replay (callback → ACS)", func(t *testing.T) {
		replay(t, "cross-endpoint-provider")
	})

	concurrent := func(env *testEnv, providerID, sr string) []string {
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		locs := make([]string, 2)
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				statuses[i], locs[i], errs[i] = s2PostRaw(env.baseURL+"/sso/saml2/sp/acs/"+providerID, url.Values{"SAMLResponse": {sr}})
			}(i)
		}
		wg.Wait()
		for i := range 2 {
			if errs[i] != nil {
				env.t.Fatal(errs[i])
			}
			if statuses[i] != 302 {
				env.t.Fatalf("submission %d status %d", i, statuses[i])
			}
		}
		return locs
	}

	t.Run("should issue only one session when the same SP-initiated assertion is submitted concurrently", func(t *testing.T) {
		env := newEnv(t, Options{})
		h := env.signInTestUser()
		s2RegisterFull(t, env, h, idp, "concurrent-replay-provider", idp.URL, entry, nil)
		ctx := env.auth.Context()
		provider, err := findSAMLProvider(context.Background(), "concurrent-replay-provider", &Options{}, ctx.Adapter)
		if err != nil || provider == nil {
			t.Fatalf("provider not found: %v", err)
		}
		ref := computeProviderReference(provider)
		inResponseTo := "null"
		now := time.Now()
		value := jsonx.O("id", inResponseTo, "providerId", "concurrent-replay-provider", "providerReference", ref.jsonObject(),
			"createdAt", float64(now.UnixMilli()), "expiresAt", float64(now.Add(5*time.Minute).UnixMilli()))
		if _, err := ctx.InternalAdapter.CreateVerificationValue(context.Background(), AuthnRequestKeyPrefix+inResponseTo,
			string(jsonx.MustMarshal(value)), now.Add(5*time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		sr := s2FetchSAML(t, idp, "")
		locs := concurrent(env, "concurrent-replay-provider", sr)
		succeeded, failed := 0, 0
		for _, l := range locs {
			if strings.Contains(l, "error") {
				failed++
			} else {
				succeeded++
			}
		}
		if succeeded != 1 || failed != 1 {
			t.Fatalf("succeeded=%d failed=%d locations=%v", succeeded, failed, locs)
		}
	})

	t.Run("should issue only one session when the same assertion is submitted concurrently without InResponseTo validation", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "concurrent-assertion-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		locs := concurrent(env, "concurrent-assertion-provider", sr)
		succeeded, replayed := 0, 0
		for _, l := range locs {
			if l != "" && !strings.Contains(l, "error") {
				succeeded++
			}
			if strings.Contains(l, "error=replay_detected") {
				replayed++
			}
		}
		if succeeded != 1 || replayed != 1 {
			t.Fatalf("succeeded=%d replayed=%d locations=%v", succeeded, replayed, locs)
		}
	})
}

// ---- SAML SSO - Single Assertion Validation ----

const s2MultiAssertionResponse = `
			<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml2:Issuer>http://localhost:8081</saml2:Issuer>
				<saml2p:Status>
					<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
				</saml2p:Status>
				<saml2:Assertion ID="assertion-1">
					<saml2:Issuer>http://localhost:8081</saml2:Issuer>
					<saml2:Subject>
						<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">legitimate@example.com</saml2:NameID>
					</saml2:Subject>
				</saml2:Assertion>
				<saml2:Assertion ID="assertion-2">
					<saml2:Issuer>http://localhost:8081</saml2:Issuer>
					<saml2:Subject>
						<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">attacker@evil.com</saml2:NameID>
					</saml2:Subject>
				</saml2:Assertion>
			</saml2p:Response>
		`

func TestSAML2SingleAssertionValidation(t *testing.T) {
	idp := newMockSAMLIdP(t, mockSAMLOptions{})
	entry := idp.URL + "/api/sso/saml2/idp/post"
	issuerXML := func(xml string) string { return samlFixtureFor(xml, idp.URL) }

	t.Run("should reject SAML response with multiple assertions on callback endpoint", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "multi-assertion-callback-provider", idp.URL, entry, nil)
		res := s2ACS(env, "", "multi-assertion-callback-provider", nil, map[string]any{
			"SAMLResponse": s2b64(issuerXML(s2MultiAssertionResponse)), "RelayState": env.server.URL + "/dashboard",
		}, nil)
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		if !strings.Contains(res.location(), "error=saml_multiple_assertions") {
			t.Fatalf("location %q", res.location())
		}
	})

	t.Run("should reject SAML response with multiple assertions on ACS endpoint", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "multi-assertion-acs-provider", idp.URL, entry, nil)
		res := env.postForm("/sso/saml2/sp/acs/multi-assertion-acs-provider", nil, url.Values{
			"SAMLResponse": {s2b64(issuerXML(s2MultiAssertionResponse))}, "RelayState": {env.server.URL + "/dashboard"},
		})
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		if !strings.Contains(res.location(), "error=saml_multiple_assertions") {
			t.Fatalf("location %q", res.location())
		}
	})

	t.Run("should reject SAML response with no assertions", func(t *testing.T) {
		env, h := s2SAMLEnv(t, false)
		s2RegisterFull(t, env, h, idp, "no-assertion-provider", idp.URL, entry, nil)
		xml := `
			<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml2:Issuer>http://localhost:8081</saml2:Issuer>
				<saml2p:Status>
					<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
				</saml2p:Status>
			</saml2p:Response>
		`
		res := s2ACS(env, "", "no-assertion-provider", nil, map[string]any{
			"SAMLResponse": s2b64(issuerXML(xml)), "RelayState": env.server.URL + "/dashboard",
		}, nil)
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		if !strings.Contains(res.location(), "error=saml_no_assertion") {
			t.Fatalf("location %q", res.location())
		}
	})

	t.Run("should reject SAML response with XSW-style assertion injection in Extensions", func(t *testing.T) {
		env, h := s2SAMLEnv(t, false)
		s2RegisterFull(t, env, h, idp, "xsw-injection-provider", idp.URL, entry, nil)
		xml := `
			<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml2:Issuer>http://localhost:8081</saml2:Issuer>
				<saml2p:Status>
					<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
				</saml2p:Status>
				<saml2p:Extensions>
					<saml2:Assertion ID="injected-assertion">
						<saml2:Issuer>http://localhost:8081</saml2:Issuer>
						<saml2:Subject>
							<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">attacker@evil.com</saml2:NameID>
						</saml2:Subject>
					</saml2:Assertion>
				</saml2p:Extensions>
				<saml2:Assertion ID="legitimate-assertion">
					<saml2:Issuer>http://localhost:8081</saml2:Issuer>
					<saml2:Subject>
						<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml2:NameID>
					</saml2:Subject>
				</saml2:Assertion>
			</saml2p:Response>
		`
		res := s2ACS(env, "", "xsw-injection-provider", nil, map[string]any{
			"SAMLResponse": s2b64(issuerXML(xml)), "RelayState": env.server.URL + "/dashboard",
		}, nil)
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		if !strings.Contains(res.location(), "error=saml_multiple_assertions") {
			t.Fatalf("location %q", res.location())
		}
	})

	t.Run("should accept valid SAML response with exactly one assertion", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "single-assertion-provider", idp.URL, entry, nil)
		sr := s2FetchSAML(t, idp, "")
		res := env.postForm("/sso/saml2/sp/acs/single-assertion-provider", nil, url.Values{"SAMLResponse": {sr}})
		if res.Status != 302 {
			t.Fatalf("status %d %s", res.Status, res.Raw)
		}
		if strings.Contains(res.location(), "error") {
			t.Fatalf("location %q", res.location())
		}
	})

	t.Run("should normalize email to lowercase in SAML authentication to prevent duplicate creation", func(t *testing.T) {
		env, h := s2SAMLEnv(t, true)
		s2RegisterFull(t, env, h, idp, "email-case-provider", "example.com", entry, map[string]any{
			"mapping": map[string]any{"email": "nameID", "name": "displayName"},
		})
		submit := func() *betterauth.SessionWithUser {
			sr := s2FetchSAML(t, idp, "emailCase=mixed")
			res := env.postForm("/sso/saml2/sp/acs/email-case-provider", nil, url.Values{"SAMLResponse": {sr}})
			if res.Status != 302 {
				t.Fatalf("status %d %s", res.Status, res.Raw)
			}
			if strings.Contains(res.location(), "error") {
				t.Fatalf("location %q", res.location())
			}
			var token string
			for _, sc := range res.Headers.Values("Set-Cookie") {
				if n, v, _ := betterauth.ParseSetCookie(sc); n == "better-auth.session_token" {
					token = v
				}
			}
			if token == "" {
				t.Fatalf("no session token cookie: %v", res.Headers.Values("Set-Cookie"))
			}
			return env.session(http.Header{"Cookie": {"better-auth.session_token=" + token}})
		}
		first := submit()
		if first == nil || first.User.Email != "testuser@example.com" {
			t.Fatalf("first session %+v", first)
		}
		firstUserID := first.User.ID
		if firstUserID == "" {
			t.Fatal("missing first user id")
		}
		second := submit()
		if second == nil || second.User.ID != firstUserID || second.User.Email != "testuser@example.com" {
			t.Fatalf("second session %+v", second)
		}
		n := 0
		for _, u := range env.rows("user") {
			if u["email"] == "testuser@example.com" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("saml users = %d", n)
		}
	})
}
