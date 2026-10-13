package sso

// Port of packages/sso/src/oidc/discovery.test.ts. betterFetch / fetch mocks are replaced by
// a custom transport on oauth2.HTTPClient and node:dns lookups by the lookupHost package var.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// ---- helpers ----

type u1undefT struct{}

// u1undef deletes a key in u1Doc overrides (TS `undefined`).
var u1undef = u1undefT{}

// u1Doc is createMockDiscoveryDocument (JSON-shaped values).
func u1Doc(overrides map[string]any) map[string]any {
	d := map[string]any{
		"issuer":                                "https://idp.example.com",
		"authorization_endpoint":                "https://idp.example.com/oauth2/authorize",
		"token_endpoint":                        "https://idp.example.com/oauth2/token",
		"jwks_uri":                              "https://idp.example.com/.well-known/jwks.json",
		"userinfo_endpoint":                     "https://idp.example.com/userinfo",
		"token_endpoint_auth_methods_supported": []any{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []any{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []any{"code", "token", "id_token"},
		"subject_types_supported":               []any{"public"},
		"id_token_signing_alg_values_supported": []any{"RS256"},
		"claims_supported":                      []any{"sub", "name", "email", "email_verified"},
	}
	for k, v := range overrides {
		if _, ok := v.(u1undefT); ok {
			delete(d, k)
			continue
		}
		d[k] = v
	}
	return d
}

// u1Fetch is a mock transport installed on oauth2.HTTPClient.
type u1Fetch struct {
	mu      sync.Mutex
	calls   []*http.Request
	handler func(*http.Request) (*http.Response, error)
}

func (f *u1Fetch) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	h := f.handler
	f.mu.Unlock()
	if h == nil {
		return nil, errors.New("u1Fetch: unexpected request " + r.URL.String())
	}
	res, err := h(r)
	if res != nil {
		res.Request = r
	}
	return res, err
}

func (f *u1Fetch) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *u1Fetch) set(h func(*http.Request) (*http.Response, error)) {
	f.mu.Lock()
	f.handler = h
	f.mu.Unlock()
}

// u1MockFetch swaps oauth2.HTTPClient for a client using a mock transport (keeping the
// production redirect policy).
func u1MockFetch(t *testing.T) *u1Fetch {
	t.Helper()
	f := &u1Fetch{}
	orig := oauth2.HTTPClient
	oauth2.HTTPClient = &http.Client{Transport: f, Timeout: orig.Timeout, CheckRedirect: orig.CheckRedirect}
	t.Cleanup(func() { oauth2.HTTPClient = orig })
	return f
}

func u1Resp(status int, contentType string, body []byte, hdr ...string) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

func u1JSONResp(v any) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return u1Resp(200, "application/json", b), nil
	}
}

func u1StatusResp(status int) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) {
		return u1Resp(status, "application/json", []byte(`{"message":"`+http.StatusText(status)+`"}`)), nil
	}
}

// u1DNS replaces lookupHost (node:dns lookup mock).
type u1DNS struct {
	calls atomic.Int32
	mu    sync.Mutex
	addrs []string
	err   error
}

func (d *u1DNS) resolve(addrs ...string) {
	d.mu.Lock()
	d.addrs, d.err = addrs, nil
	d.mu.Unlock()
}

func (d *u1DNS) fail(err error) {
	d.mu.Lock()
	d.addrs, d.err = nil, err
	d.mu.Unlock()
}

func u1MockDNS(t *testing.T) *u1DNS {
	t.Helper()
	d := &u1DNS{addrs: []string{"93.184.216.34"}}
	orig := lookupHost
	lookupHost = func(_ context.Context, _ string) ([]string, error) {
		d.calls.Add(1)
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.addrs, d.err
	}
	t.Cleanup(func() { lookupHost = orig })
	return d
}

// u1Setup is the shared beforeEach: reset fetch mock and resolve DNS to a public address.
func u1Setup(t *testing.T) (*u1Fetch, *u1DNS) {
	t.Helper()
	return u1MockFetch(t), u1MockDNS(t)
}

func u1DErr(t *testing.T, err error) *DiscoveryError {
	t.Helper()
	if err == nil {
		t.Fatal("expected DiscoveryError, got nil")
	}
	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatalf("expected *DiscoveryError, got %T: %v", err, err)
	}
	return de
}

func u1ExpectCode(t *testing.T, err error, code string) *DiscoveryError {
	t.Helper()
	de := u1DErr(t, err)
	if de.Code != code {
		t.Fatalf("code = %q, want %q (message %q)", de.Code, code, de.Message)
	}
	return de
}

func u1ExpectContains(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("error %v does not contain %q", err, sub)
	}
}

func u1Eq(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func u1MissingContains(t *testing.T, de *DiscoveryError, fields ...string) {
	t.Helper()
	missing, _ := de.Details["missingFields"].([]string)
	for _, f := range fields {
		found := false
		for _, m := range missing {
			if m == f {
				found = true
			}
		}
		if !found {
			t.Fatalf("missingFields %v does not contain %q", missing, f)
		}
	}
}

func u1True(string) bool  { return true }
func u1False(string) bool { return false }

var u1ctx = context.Background()

// ---- tests ----

func TestUnitOIDCDiscovery(t *testing.T) {
	t.Run("computeDiscoveryUrl", func(t *testing.T) {
		t.Run("should compute discovery URL from issuer without trailing slash", func(t *testing.T) {
			u1Eq(t, computeDiscoveryURL("https://idp.example.com"), "https://idp.example.com/.well-known/openid-configuration")
		})
		t.Run("should compute discovery URL from issuer with trailing slash", func(t *testing.T) {
			u1Eq(t, computeDiscoveryURL("https://idp.example.com/"), "https://idp.example.com/.well-known/openid-configuration")
		})
		t.Run("should handle issuer with path", func(t *testing.T) {
			u1Eq(t, computeDiscoveryURL("https://idp.example.com/tenant/v1"), "https://idp.example.com/tenant/v1/.well-known/openid-configuration")
		})
		t.Run("should handle issuer with path and trailing slash", func(t *testing.T) {
			u1Eq(t, computeDiscoveryURL("https://idp.example.com/tenant/v1/"), "https://idp.example.com/tenant/v1/.well-known/openid-configuration")
		})
	})

	t.Run("validateDiscoveryUrl", func(t *testing.T) {
		trusted := true
		isTrustedOrigin := func(string) bool { return trusted }

		t.Run("should accept valid HTTPS URL", func(t *testing.T) {
			if err := validateDiscoveryURL("https://idp.example.com/.well-known/openid-configuration", isTrustedOrigin); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("should accept valid HTTP URL", func(t *testing.T) {
			if err := validateDiscoveryURL("http://localhost:8080/.well-known/openid-configuration", isTrustedOrigin); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("should reject invalid URL", func(t *testing.T) {
			err := validateDiscoveryURL("not-a-url", isTrustedOrigin)
			u1DErr(t, err)
			u1ExpectContains(t, err, `The url "discoveryEndpoint" must be valid`)
		})
		t.Run("should reject non-HTTP protocols", func(t *testing.T) {
			err := validateDiscoveryURL("ftp://example.com/config", isTrustedOrigin)
			u1DErr(t, err)
			u1ExpectContains(t, err, "must use the http or https supported protocols")
		})
		t.Run("should throw DiscoveryError with discovery_invalid_url code for invalid URL", func(t *testing.T) {
			de := u1ExpectCode(t, validateDiscoveryURL("not-a-url", isTrustedOrigin), "discovery_invalid_url")
			u1Eq(t, de.Details["url"], "not-a-url")
		})
		t.Run("should throw DiscoveryError with discovery_invalid_url code for non-HTTP protocol", func(t *testing.T) {
			de := u1ExpectCode(t, validateDiscoveryURL("ftp://example.com/config", isTrustedOrigin), "discovery_invalid_url")
			u1Eq(t, de.Details["protocol"], "ftp:")
		})
		t.Run("should throw DiscoveryError with discovery_untrusted_origin code for untrusted origins", func(t *testing.T) {
			trusted = false
			de := u1ExpectCode(t, validateDiscoveryURL("https://untrusted.com/.well-known/openid-configuration", isTrustedOrigin), "discovery_untrusted_origin")
			u1Eq(t, de.Message, `The main discovery endpoint "https://untrusted.com/.well-known/openid-configuration" is not trusted by your trusted origins configuration.`)
		})
	})

	t.Run("validateDiscoveryDocument", func(t *testing.T) {
		issuer := "https://idp.example.com"

		t.Run("should accept valid discovery document", func(t *testing.T) {
			if err := validateDiscoveryDocument(u1Doc(nil), issuer); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("should accept discovery document with only required fields", func(t *testing.T) {
			doc := map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/authorize",
				"token_endpoint":         issuer + "/token",
				"jwks_uri":               issuer + "/jwks",
			}
			if err := validateDiscoveryDocument(doc, issuer); err != nil {
				t.Fatal(err)
			}
		})
		for _, f := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
			t.Run("should throw discovery_incomplete for missing "+f, func(t *testing.T) {
				de := u1ExpectCode(t, validateDiscoveryDocument(u1Doc(map[string]any{f: ""}), issuer), "discovery_incomplete")
				u1MissingContains(t, de, f)
			})
		}
		t.Run("should list all missing fields", func(t *testing.T) {
			doc := map[string]any{"issuer": "", "authorization_endpoint": "", "token_endpoint": "", "jwks_uri": ""}
			de := u1ExpectCode(t, validateDiscoveryDocument(doc, issuer), "discovery_incomplete")
			u1MissingContains(t, de, "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
		})
		t.Run("should throw issuer_mismatch when issuer doesn't match", func(t *testing.T) {
			de := u1ExpectCode(t, validateDiscoveryDocument(u1Doc(map[string]any{"issuer": "https://evil.example.com"}), issuer), "issuer_mismatch")
			u1Eq(t, de.Details["discovered"], "https://evil.example.com")
			u1Eq(t, de.Details["configured"], issuer)
		})
		t.Run("should handle trailing slash normalization in issuer comparison", func(t *testing.T) {
			if err := validateDiscoveryDocument(u1Doc(map[string]any{"issuer": "https://idp.example.com/"}), "https://idp.example.com"); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("should handle trailing slash in configured issuer", func(t *testing.T) {
			if err := validateDiscoveryDocument(u1Doc(map[string]any{"issuer": "https://idp.example.com"}), "https://idp.example.com/"); err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("selectTokenEndpointAuthMethod", func(t *testing.T) {
		methods := func(m ...any) map[string]any {
			return u1Doc(map[string]any{"token_endpoint_auth_methods_supported": m})
		}
		t.Run("should return existing config value if provided", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(u1Doc(nil), "client_secret_post"), "client_secret_post")
		})
		t.Run("should prefer client_secret_basic when both are supported", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(methods("client_secret_post", "client_secret_basic"), ""), "client_secret_basic")
		})
		t.Run("should use client_secret_post if only that is supported", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(methods("client_secret_post"), ""), "client_secret_post")
		})
		t.Run("should select private_key_jwt when it is the only supported method", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(methods("private_key_jwt"), ""), "private_key_jwt")
		})
		t.Run("should select private_key_jwt when only tls_client_auth and private_key_jwt are supported", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(methods("tls_client_auth", "private_key_jwt"), ""), "private_key_jwt")
		})
		t.Run("should default to client_secret_basic if not specified in discovery", func(t *testing.T) {
			doc := u1Doc(map[string]any{"token_endpoint_auth_methods_supported": u1undef})
			u1Eq(t, selectTokenEndpointAuthMethod(doc, ""), "client_secret_basic")
		})
		t.Run("should default to client_secret_basic for empty array", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(methods(), ""), "client_secret_basic")
		})
		t.Run("should preserve explicit private_key_jwt when passed as existing", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(methods("private_key_jwt", "client_secret_basic"), "private_key_jwt"), "private_key_jwt")
		})
		t.Run("should prefer client_secret_basic over private_key_jwt when both are supported", func(t *testing.T) {
			u1Eq(t, selectTokenEndpointAuthMethod(methods("private_key_jwt", "client_secret_basic"), ""), "client_secret_basic")
		})
	})

	t.Run("normalizeDiscoveryUrls", func(t *testing.T) {
		t.Run("should return the document unchanged if all urls are already absolute", func(t *testing.T) {
			doc := u1Doc(nil)
			res, err := normalizeDiscoveryURLs(doc, "https://idp.example.com", u1True)
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res, doc)
		})
		t.Run("should resolve all required discovery urls relative to the issuer", func(t *testing.T) {
			expected := u1Doc(map[string]any{
				"issuer":                 "https://idp.example.com",
				"authorization_endpoint": "https://idp.example.com/oauth2/authorize",
				"token_endpoint":         "https://idp.example.com/oauth2/token",
				"jwks_uri":               "https://idp.example.com/.well-known/jwks.json",
			})
			doc := u1Doc(map[string]any{
				"issuer":                 "https://idp.example.com",
				"authorization_endpoint": "/oauth2/authorize",
				"token_endpoint":         "/oauth2/token",
				"jwks_uri":               "/.well-known/jwks.json",
			})
			res, err := normalizeDiscoveryURLs(doc, "https://idp.example.com", u1True)
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res, expected)
		})
		t.Run("should resolve all discovery urls relative to the issuer", func(t *testing.T) {
			expected := u1Doc(map[string]any{
				"issuer":                 "https://idp.example.com",
				"authorization_endpoint": "https://idp.example.com/oauth2/authorize",
				"token_endpoint":         "https://idp.example.com/oauth2/token",
				"jwks_uri":               "https://idp.example.com/.well-known/jwks.json",
				"userinfo_endpoint":      "https://idp.example.com/userinfo",
				"revocation_endpoint":    "https://idp.example.com/revoke",
			})
			doc := u1Doc(map[string]any{
				"issuer":                 "https://idp.example.com",
				"authorization_endpoint": "/oauth2/authorize",
				"token_endpoint":         "/oauth2/token",
				"jwks_uri":               "/.well-known/jwks.json",
				"userinfo_endpoint":      "/userinfo",
				"revocation_endpoint":    "/revoke",
			})
			res, err := normalizeDiscoveryURLs(doc, "https://idp.example.com", u1True)
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res, expected)
		})
		t.Run("should reject on invalid discovery urls", func(t *testing.T) {
			doc := u1Doc(map[string]any{"authorization_endpoint": "/oauth2/authorize"})
			_, err := normalizeDiscoveryURLs(doc, "not-url", u1True)
			u1ExpectContains(t, err, `The url "authorization_endpoint" must be valid`)
		})
		t.Run("should reject with discovery_untrusted_origin code on untrusted discovery urls", func(t *testing.T) {
			doc := u1Doc(map[string]any{
				"authorization_endpoint": "/oauth2/authorize",
				"token_endpoint":         "/oauth2/token",
				"jwks_uri":               "/.well-known/jwks.json",
				"userinfo_endpoint":      "/userinfo",
				"revocation_endpoint":    "/revoke",
				"end_session_endpoint":   "/endsession",
				"introspection_endpoint": "/introspection",
			})
			for _, c := range [][3]string{
				{"/oauth2/token", "token_endpoint", "https://idp.example.com/oauth2/token"},
				{"/oauth2/authorize", "authorization_endpoint", "https://idp.example.com/oauth2/authorize"},
				{"/.well-known/jwks.json", "jwks_uri", "https://idp.example.com/.well-known/jwks.json"},
				{"/userinfo", "userinfo_endpoint", "https://idp.example.com/userinfo"},
				{"/revoke", "revocation_endpoint", "https://idp.example.com/revoke"},
				{"/endsession", "end_session_endpoint", "https://idp.example.com/endsession"},
				{"/introspection", "introspection_endpoint", "https://idp.example.com/introspection"},
			} {
				suffix := c[0]
				_, err := normalizeDiscoveryURLs(doc, "https://idp.example.com", func(u string) bool { return !strings.HasSuffix(u, suffix) })
				de := u1ExpectCode(t, err, "discovery_untrusted_origin")
				u1Eq(t, de.Message, fmt.Sprintf("The %s %q is not trusted by your trusted origins configuration.", c[1], c[2]))
				u1Eq(t, de.Details, map[string]any{"endpoint": c[1], "url": c[2]})
			}
		})
	})

	t.Run("normalizeUrl", func(t *testing.T) {
		t.Run("should return endpoint unchanged if already absolute", func(t *testing.T) {
			endpoint := "https://idp.example.com/oauth2/token"
			got, err := normalizeURL("url", endpoint, "https://idp.example.com")
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, got, endpoint)
		})
		t.Run("should return endpoint as an absolute url", func(t *testing.T) {
			got, err := normalizeURL("url", "/oauth2/token", "https://idp.example.com")
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, got, "https://idp.example.com/oauth2/token")
		})
		for _, c := range [][3]string{
			{"/oauth2/token", "https://idp.example.com/base", "endpoint with leading slash"},
			{"oauth2/token", "https://idp.example.com/base", "endpoint without leading slash"},
			{"/oauth2/token", "https://idp.example.com/base/", "issuer with trailing slash"},
			{"//oauth2/token", "https://idp.example.com/base//", "multiple slashes"},
		} {
			c := c
			t.Run(fmt.Sprintf("should resolve relative endpoint preserving issuer base path (%s, %s) - %s", c[0], c[1], c[2]), func(t *testing.T) {
				got, err := normalizeURL("url", c[0], c[1])
				if err != nil {
					t.Fatal(err)
				}
				u1Eq(t, got, "https://idp.example.com/base/oauth2/token")
			})
		}
		t.Run("should reject invalid endpoint urls", func(t *testing.T) {
			_, err := normalizeURL("url", "oauth2/token", "not-a-url")
			u1ExpectContains(t, err, `The url "url" must be valid`)
		})
		t.Run("should reject urls with unsupported protocols", func(t *testing.T) {
			_, err := normalizeURL("url", "not-a-url", "ftp://idp.example.com")
			u1ExpectContains(t, err, `The url "url" must use the http or https supported protocols`)
		})
	})

	t.Run("needsRuntimeDiscovery", func(t *testing.T) {
		t.Run("should return true for undefined config", func(t *testing.T) {
			u1Eq(t, needsRuntimeDiscovery(nil), true)
		})
		t.Run("should return true for empty config", func(t *testing.T) {
			u1Eq(t, needsRuntimeDiscovery(&OIDCConfig{}), true)
		})
		t.Run("should return true if tokenEndpoint is missing", func(t *testing.T) {
			u1Eq(t, needsRuntimeDiscovery(&OIDCConfig{JwksEndpoint: "https://idp.example.com/.well-known/jwks.json"}), true)
		})
		t.Run("should return true if jwksEndpoint is missing", func(t *testing.T) {
			u1Eq(t, needsRuntimeDiscovery(&OIDCConfig{TokenEndpoint: "https://idp.example.com/oauth2/token"}), true)
		})
		t.Run("should return false if tokenEndpoint, jwksEndpoint and authorizationEndpoint are all present", func(t *testing.T) {
			u1Eq(t, needsRuntimeDiscovery(&OIDCConfig{
				TokenEndpoint:         "https://idp.example.com/oauth2/token",
				JwksEndpoint:          "https://idp.example.com/.well-known/jwks.json",
				AuthorizationEndpoint: "https://idp.example.com/oauth2/authorize",
			}), false)
		})
		t.Run("should return true if authorizationEndpoint is missing", func(t *testing.T) {
			u1Eq(t, needsRuntimeDiscovery(&OIDCConfig{
				TokenEndpoint: "https://idp.example.com/oauth2/token",
				JwksEndpoint:  "https://idp.example.com/.well-known/jwks.json",
			}), true)
		})
	})

	t.Run("fetchDiscoveryDocument", func(t *testing.T) {
		const discURL = "https://idp.example.com/.well-known/openid-configuration"

		t.Run("should fetch and parse valid discovery document", func(t *testing.T) {
			f, _ := u1Setup(t)
			expected := u1Doc(nil)
			f.set(u1JSONResp(expected))
			res, err := fetchDiscoveryDocument(u1ctx, discURL, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
				u1Eq(t, res[k], expected[k])
			}
			if f.count() != 1 {
				t.Fatalf("fetch calls = %d", f.count())
			}
			u1Eq(t, f.calls[0].URL.String(), discURL)
			u1Eq(t, f.calls[0].Method, "GET")
		})
		t.Run("should throw discovery_not_found for 404 response", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1StatusResp(404))
			_, err := fetchDiscoveryDocument(u1ctx, discURL, 0, nil)
			u1ExpectCode(t, err, "discovery_not_found")
		})
		t.Run("should throw discovery_timeout on AbortError (betterFetch throws on timeout)", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(func(r *http.Request) (*http.Response, error) {
				<-r.Context().Done()
				return nil, r.Context().Err()
			})
			_, err := fetchDiscoveryDocument(u1ctx, discURL, 100*time.Millisecond, nil)
			u1ExpectCode(t, err, "discovery_timeout")
		})
		t.Run("should throw discovery_timeout on HTTP 408 response", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1StatusResp(408))
			_, err := fetchDiscoveryDocument(u1ctx, discURL, 100*time.Millisecond, nil)
			u1ExpectCode(t, err, "discovery_timeout")
		})
		t.Run("should throw discovery_unexpected_error for server errors", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1StatusResp(500))
			_, err := fetchDiscoveryDocument(u1ctx, discURL, 0, nil)
			u1ExpectCode(t, err, "discovery_unexpected_error")
		})
		t.Run("should throw discovery_invalid_json for empty response", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(func(*http.Request) (*http.Response, error) { return u1Resp(200, "application/json", nil), nil })
			_, err := fetchDiscoveryDocument(u1ctx, discURL, 0, nil)
			u1ExpectCode(t, err, "discovery_invalid_json")
		})
		t.Run("should throw discovery_invalid_json for JSON parse errors", func(t *testing.T) {
			f, _ := u1Setup(t)
			body := "<!DOCTYPE html><html>Not JSON</html>"
			f.set(func(*http.Request) (*http.Response, error) { return u1Resp(200, "text/html", []byte(body)), nil })
			_, err := fetchDiscoveryDocument(u1ctx, discURL, 0, nil)
			de := u1ExpectCode(t, err, "discovery_invalid_json")
			u1Eq(t, de.Details["bodyPreview"], body)
		})
		t.Run("should throw discovery_unexpected_error for unknown errors", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(func(*http.Request) (*http.Response, error) { return nil, errors.New("Network failure") })
			_, err := fetchDiscoveryDocument(u1ctx, discURL, 0, nil)
			u1ExpectCode(t, err, "discovery_unexpected_error")
		})
	})

	t.Run("discoverOIDCConfig (integration)", func(t *testing.T) {
		issuer := "https://idp.example.com"
		trust := func(string) bool { return true }
		isTrustedOrigin := func(u string) bool { return trust(u) }

		t.Run("should return hydrated config from valid discovery", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(u1Doc(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/oauth2/authorize",
				"token_endpoint":         issuer + "/oauth2/token",
				"jwks_uri":               issuer + "/.well-known/jwks.json",
				"userinfo_endpoint":      issuer + "/userinfo",
			})))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.Issuer, issuer)
			u1Eq(t, res.AuthorizationEndpoint, issuer+"/oauth2/authorize")
			u1Eq(t, res.TokenEndpoint, issuer+"/oauth2/token")
			u1Eq(t, res.JwksEndpoint, issuer+"/.well-known/jwks.json")
			u1Eq(t, res.UserInfoEndpoint, issuer+"/userinfo")
			u1Eq(t, res.DiscoveryEndpoint, issuer+"/.well-known/openid-configuration")
			u1Eq(t, res.TokenEndpointAuthentication, "client_secret_basic")
		})
		t.Run("should merge existing config with discovered values (existing takes precedence)", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(u1Doc(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/oauth2/authorize",
				"token_endpoint":         issuer + "/oauth2/token",
				"jwks_uri":               issuer + "/.well-known/jwks.json",
			})))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin,
				ExistingConfig: &HydratedOIDCConfig{TokenEndpoint: "https://custom.example.com/token", TokenEndpointAuthentication: "client_secret_post"}})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.TokenEndpoint, "https://custom.example.com/token")
			u1Eq(t, res.TokenEndpointAuthentication, "client_secret_post")
			u1Eq(t, res.AuthorizationEndpoint, issuer+"/oauth2/authorize")
			u1Eq(t, res.JwksEndpoint, issuer+"/.well-known/jwks.json")
		})
		t.Run("should use custom discovery endpoint if provided", func(t *testing.T) {
			f, _ := u1Setup(t)
			custom := issuer + "/custom/.well-known/openid-configuration"
			f.set(u1JSONResp(u1Doc(map[string]any{"issuer": issuer})))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, DiscoveryEndpoint: custom, IsTrustedOrigin: isTrustedOrigin})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.DiscoveryEndpoint, custom)
			u1Eq(t, f.calls[0].URL.String(), custom)
		})
		t.Run("should use discovery endpoint from existing config", func(t *testing.T) {
			f, _ := u1Setup(t)
			existing := issuer + "/tenant/.well-known/openid-configuration"
			f.set(u1JSONResp(u1Doc(map[string]any{"issuer": issuer})))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin,
				ExistingConfig: &HydratedOIDCConfig{DiscoveryEndpoint: existing}})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.DiscoveryEndpoint, existing)
			u1Eq(t, f.calls[0].URL.String(), existing)
		})
		t.Run("should throw on issuer mismatch", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(u1Doc(map[string]any{"issuer": "https://evil.example.com"})))
			_, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			u1ExpectCode(t, err, "issuer_mismatch")
		})
		t.Run("should throw on missing required fields", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize"}))
			_, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			u1ExpectCode(t, err, "discovery_incomplete")
		})
		t.Run("should throw discovery_not_found when endpoint doesn't exist", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1StatusResp(404))
			_, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			u1ExpectCode(t, err, "discovery_not_found")
		})
		t.Run("should include scopes_supported in hydrated config", func(t *testing.T) {
			f, _ := u1Setup(t)
			scopes := []any{"openid", "profile", "email", "offline_access", "custom"}
			f.set(u1JSONResp(u1Doc(map[string]any{"issuer": issuer, "scopes_supported": scopes})))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.ScopesSupported, []string{"openid", "profile", "email", "offline_access", "custom"})
		})
		t.Run("should handle discovery document without optional fields", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/authorize",
				"token_endpoint":         issuer + "/token",
				"jwks_uri":               issuer + "/jwks",
			}))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.Issuer, issuer)
			u1Eq(t, res.AuthorizationEndpoint, issuer+"/authorize")
			u1Eq(t, res.TokenEndpoint, issuer+"/token")
			u1Eq(t, res.JwksEndpoint, issuer+"/jwks")
			u1Eq(t, res.UserInfoEndpoint, "")
			if res.ScopesSupported != nil {
				t.Fatalf("scopesSupported = %v, want undefined", res.ScopesSupported)
			}
			u1Eq(t, res.TokenEndpointAuthentication, "client_secret_basic")
		})
		t.Run("should keep all existing config fields and only fill missing ones from discovery", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(u1Doc(map[string]any{"issuer": issuer})))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin,
				ExistingConfig: &HydratedOIDCConfig{
					Issuer:                      issuer,
					DiscoveryEndpoint:           "https://custom.example.com/.well-known/openid-configuration",
					AuthorizationEndpoint:       "https://custom.example.com/auth",
					TokenEndpoint:               "https://custom.example.com/token",
					JwksEndpoint:                "https://custom.example.com/jwks",
					UserInfoEndpoint:            "https://custom.example.com/userinfo",
					TokenEndpointAuthentication: "client_secret_post",
					ScopesSupported:             []string{"openid", "profile"},
				}})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.Issuer, issuer)
			u1Eq(t, res.DiscoveryEndpoint, "https://custom.example.com/.well-known/openid-configuration")
			u1Eq(t, res.AuthorizationEndpoint, "https://custom.example.com/auth")
			u1Eq(t, res.TokenEndpoint, "https://custom.example.com/token")
			u1Eq(t, res.JwksEndpoint, "https://custom.example.com/jwks")
			u1Eq(t, res.UserInfoEndpoint, "https://custom.example.com/userinfo")
			u1Eq(t, res.TokenEndpointAuthentication, "client_secret_post")
			u1Eq(t, res.ScopesSupported, []string{"openid", "profile"})
		})
		t.Run("should default to client_secret_basic when IdP only supports methods we don't support", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/jwks",
				"token_endpoint_auth_methods_supported": []any{"tls_client_auth"},
			}))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.TokenEndpointAuthentication, "client_secret_basic")
		})
		t.Run("should select private_key_jwt from discovery when it is the only supported method", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/jwks",
				"token_endpoint_auth_methods_supported": []any{"private_key_jwt"},
			}))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.TokenEndpointAuthentication, "private_key_jwt")
		})
		t.Run("should fill missing fields from discovery when existing config is partial", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(u1Doc(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/oauth2/authorize",
				"token_endpoint":         issuer + "/oauth2/token",
				"jwks_uri":               issuer + "/.well-known/jwks.json",
				"userinfo_endpoint":      issuer + "/userinfo",
			})))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin,
				ExistingConfig: &HydratedOIDCConfig{JwksEndpoint: "https://custom.example.com/jwks"}})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.JwksEndpoint, "https://custom.example.com/jwks")
			u1Eq(t, res.Issuer, issuer)
			u1Eq(t, res.AuthorizationEndpoint, issuer+"/oauth2/authorize")
			u1Eq(t, res.TokenEndpoint, issuer+"/oauth2/token")
			u1Eq(t, res.UserInfoEndpoint, issuer+"/userinfo")
			u1Eq(t, res.TokenEndpointAuthentication, "client_secret_basic")
		})
		t.Run("should handle discovery document with extra unknown fields and missing optional fields", func(t *testing.T) {
			f, _ := u1Setup(t)
			f.set(u1JSONResp(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/authorize",
				"token_endpoint":         issuer + "/token",
				"jwks_uri":               issuer + "/jwks",
				"x-vendor-feature":       true,
				"custom_logout_endpoint": issuer + "/logout",
				"experimental_flags":     map[string]any{"feature_a": true, "feature_b": false},
			}))
			res, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, res.Issuer, issuer)
			u1Eq(t, res.AuthorizationEndpoint, issuer+"/authorize")
			u1Eq(t, res.TokenEndpoint, issuer+"/token")
			u1Eq(t, res.JwksEndpoint, issuer+"/jwks")
			u1Eq(t, res.UserInfoEndpoint, "")
			if res.ScopesSupported != nil {
				t.Fatalf("scopesSupported = %v, want undefined", res.ScopesSupported)
			}
			u1Eq(t, res.TokenEndpointAuthentication, "client_secret_basic")
		})
		t.Run("should throw an error with discovery_untrusted_origin code when the main discovery url is untrusted", func(t *testing.T) {
			u1Setup(t)
			trust = func(string) bool { return false }
			_, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			de := u1ExpectCode(t, err, "discovery_untrusted_origin")
			u1Eq(t, de.Message, `The main discovery endpoint "https://idp.example.com/.well-known/openid-configuration" is not trusted by your trusted origins configuration.`)
			u1Eq(t, de.Details, map[string]any{"url": "https://idp.example.com/.well-known/openid-configuration"})
		})
		t.Run("should throw an error with discovery_untrusted_origin code when discovered urls are untrusted", func(t *testing.T) {
			f, _ := u1Setup(t)
			trust = func(u string) bool { return strings.HasSuffix(u, ".well-known/openid-configuration") }
			f.set(u1JSONResp(u1Doc(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/oauth2/authorize",
				"token_endpoint":         issuer + "/oauth2/token",
				"jwks_uri":               issuer + "/.well-known/jwks.json",
				"userinfo_endpoint":      issuer + "/userinfo",
			})))
			_, err := discoverOIDCConfig(u1ctx, DiscoverOIDCConfigParams{Issuer: issuer, IsTrustedOrigin: isTrustedOrigin})
			de := u1ExpectCode(t, err, "discovery_untrusted_origin")
			u1Eq(t, de.Message, `The token_endpoint "https://idp.example.com/oauth2/token" is not trusted by your trusted origins configuration.`)
			u1Eq(t, de.Details, map[string]any{"endpoint": "token_endpoint", "url": "https://idp.example.com/oauth2/token"})
		})
	})
}

func TestUnitEnsureRuntimeDiscovery(t *testing.T) {
	issuer := "https://idp.example.com"
	baseConfig := func() *OIDCConfig {
		return &OIDCConfig{
			Issuer:            issuer,
			ClientID:          "client-id",
			ClientSecret:      "client-secret",
			PKCE:              true,
			DiscoveryEndpoint: issuer + "/.well-known/openid-configuration",
		}
	}
	mockDiscoveryDoc := u1Doc(nil)
	setup := func(t *testing.T) (*u1Fetch, *u1DNS) {
		f, d := u1Setup(t)
		f.set(u1JSONResp(mockDiscoveryDoc))
		return f, d
	}

	t.Run("returns config unchanged when discovery is not needed", func(t *testing.T) {
		f, _ := setup(t)
		complete := baseConfig()
		complete.AuthorizationEndpoint = issuer + "/oauth2/authorize"
		complete.TokenEndpoint = issuer + "/oauth2/token"
		complete.JwksEndpoint = issuer + "/.well-known/jwks.json"
		res, err := ensureRuntimeDiscovery(u1ctx, complete, issuer, u1True)
		if err != nil {
			t.Fatal(err)
		}
		// Go returns a copy; TS returns the same object (toBe). Compare by value.
		u1Eq(t, *res, *complete)
		if f.count() != 0 {
			t.Fatalf("fetch called %d times", f.count())
		}
	})
	t.Run("hydrates missing endpoints when discovery is needed", func(t *testing.T) {
		setup(t)
		res, err := ensureRuntimeDiscovery(u1ctx, baseConfig(), issuer, u1True)
		if err != nil {
			t.Fatal(err)
		}
		u1Eq(t, res.AuthorizationEndpoint, mockDiscoveryDoc["authorization_endpoint"])
		u1Eq(t, res.TokenEndpoint, mockDiscoveryDoc["token_endpoint"])
		u1Eq(t, res.JwksEndpoint, mockDiscoveryDoc["jwks_uri"])
		u1Eq(t, res.UserInfoEndpoint, mockDiscoveryDoc["userinfo_endpoint"])
	})
	t.Run("preserves existing config fields not returned by discovery", func(t *testing.T) {
		setup(t)
		base := baseConfig()
		res, err := ensureRuntimeDiscovery(u1ctx, base, issuer, u1True)
		if err != nil {
			t.Fatal(err)
		}
		u1Eq(t, res.ClientID, base.ClientID)
		u1Eq(t, res.ClientSecret, base.ClientSecret)
		u1Eq(t, res.PKCE, base.PKCE)
	})
	t.Run("throws when discovery fails", func(t *testing.T) {
		f, _ := setup(t)
		f.set(u1StatusResp(500))
		_, err := ensureRuntimeDiscovery(u1ctx, baseConfig(), issuer, u1True)
		u1DErr(t, err)
	})
	t.Run("throws DiscoveryError for untrusted origin", func(t *testing.T) {
		setup(t)
		_, err := ensureRuntimeDiscovery(u1ctx, baseConfig(), issuer, u1False)
		u1ExpectCode(t, err, "discovery_untrusted_origin")
	})
	t.Run("rejects a stored endpoint whose DNS resolves to an internal address", func(t *testing.T) {
		f, d := setup(t)
		complete := baseConfig()
		complete.AuthorizationEndpoint = "https://idp.internal.example/oauth2/authorize"
		complete.TokenEndpoint = "https://idp.internal.example/oauth2/token"
		complete.JwksEndpoint = "https://idp.internal.example/.well-known/jwks.json"
		d.resolve("169.254.169.254")
		_, err := ensureRuntimeDiscovery(u1ctx, complete, issuer, u1False)
		u1ExpectCode(t, err, "discovery_private_host")
		if f.count() != 0 {
			t.Fatalf("fetch called %d times", f.count())
		}
	})
}

func TestUnitResolvedAddressGuard(t *testing.T) {
	notTrusted := u1False

	t.Run("assertEndpointResolvesPublic", func(t *testing.T) {
		for _, c := range [][2]string{
			{"loopback", "127.0.0.1"},
			{"link-local / cloud metadata", "169.254.169.254"},
			{"private RFC 1918", "10.0.0.5"},
			{"IPv6 loopback", "::1"},
		} {
			c := c
			t.Run(fmt.Sprintf("rejects an FQDN that resolves to %s (%s)", c[0], c[1]), func(t *testing.T) {
				d := u1MockDNS(t)
				d.resolve(c[1])
				err := assertEndpointResolvesPublic(u1ctx, "tokenEndpoint", "https://idp.internal.example/token", notTrusted)
				u1ExpectCode(t, err, "discovery_private_host")
			})
		}
		t.Run("allows an FQDN that resolves to a public address", func(t *testing.T) {
			d := u1MockDNS(t)
			d.resolve("93.184.216.34")
			if err := assertEndpointResolvesPublic(u1ctx, "tokenEndpoint", "https://idp.example.com/token", notTrusted); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("rejects if ANY resolved address is internal (mixed result)", func(t *testing.T) {
			d := u1MockDNS(t)
			d.resolve("93.184.216.34", "127.0.0.1")
			err := assertEndpointResolvesPublic(u1ctx, "jwksEndpoint", "https://idp.internal.example/jwks", notTrusted)
			u1ExpectCode(t, err, "discovery_private_host")
		})
		t.Run("skips DNS resolution for operator-allowlisted origins (internal IdP escape hatch)", func(t *testing.T) {
			d := u1MockDNS(t)
			if err := assertEndpointResolvesPublic(u1ctx, "tokenEndpoint", "https://internal-idp.corp/token", u1True); err != nil {
				t.Fatal(err)
			}
			if n := d.calls.Load(); n != 0 {
				t.Fatalf("lookup called %d times", n)
			}
		})
		t.Run("does not resolve IP-literal hosts (already covered by the sync check)", func(t *testing.T) {
			d := u1MockDNS(t)
			if err := assertEndpointResolvesPublic(u1ctx, "tokenEndpoint", "https://93.184.216.34/token", notTrusted); err != nil {
				t.Fatal(err)
			}
			if n := d.calls.Load(); n != 0 {
				t.Fatalf("lookup called %d times", n)
			}
		})
		t.Run("does not throw when resolution itself fails (lets the fetch surface it)", func(t *testing.T) {
			d := u1MockDNS(t)
			d.fail(errors.New("ENOTFOUND"))
			if err := assertEndpointResolvesPublic(u1ctx, "tokenEndpoint", "https://idp.example.com/token", notTrusted); err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("assertServerFetchedOIDCEndpointsAllowed", func(t *testing.T) {
		t.Run("checks token, userinfo, and jwks endpoints", func(t *testing.T) {
			d := u1MockDNS(t)
			d.resolve("93.184.216.34")
			if err := assertServerFetchedOIDCEndpointsAllowed(u1ctx, "https://idp.example.com/token", "https://idp.example.com/userinfo", "https://idp.example.com/jwks", notTrusted); err != nil {
				t.Fatal(err)
			}
			if n := d.calls.Load(); n != 3 {
				t.Fatalf("lookup called %d times, want 3", n)
			}
		})
		t.Run("rejects when the userinfo endpoint resolves internally", func(t *testing.T) {
			d := u1MockDNS(t)
			d.resolve("10.1.2.3")
			err := assertServerFetchedOIDCEndpointsAllowed(u1ctx, "", "https://idp.internal.example/userinfo", "", notTrusted)
			u1ExpectCode(t, err, "discovery_private_host")
		})
		t.Run("rejects a syntactically-private endpoint before any DNS lookup", func(t *testing.T) {
			d := u1MockDNS(t)
			err := assertServerFetchedOIDCEndpointsAllowed(u1ctx, "https://169.254.169.254/token", "", "", notTrusted)
			u1ExpectCode(t, err, "discovery_private_host")
			if n := d.calls.Load(); n != 0 {
				t.Fatalf("lookup called %d times", n)
			}
		})
	})
}

func TestUnitFetchDiscoveryDocumentRedirectHandling(t *testing.T) {
	const discURL = "https://idp.example.com/.well-known/openid-configuration"

	t.Run("disables automatic redirect following", func(t *testing.T) {
		f, _ := u1Setup(t)
		f.set(u1JSONResp(u1Doc(nil)))
		if _, err := fetchDiscoveryDocument(u1ctx, discURL, 0, u1True); err != nil {
			t.Fatal(err)
		}
		if f.count() != 1 || f.calls[0].URL.String() != discURL {
			t.Fatalf("unexpected fetch calls: %d", f.count())
		}
		// redirect: "manual" equivalent: the client used for OIDC fetches never follows redirects.
		if oauth2.HTTPClient.CheckRedirect == nil {
			t.Fatal("HTTPClient follows redirects")
		}
		req, _ := http.NewRequest("GET", "https://idp.example.com/final", nil)
		if err := oauth2.HTTPClient.CheckRedirect(req, []*http.Request{f.calls[0]}); !errors.Is(err, http.ErrUseLastResponse) {
			t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
		}
	})

	/** @see https://github.com/better-auth/better-auth/issues/10052 */
	t.Run("rejects redirect responses after using manual redirect mode", func(t *testing.T) {
		f, _ := u1Setup(t)
		f.set(func(*http.Request) (*http.Response, error) {
			return u1Resp(302, "", nil, "Location", "https://idp.example.com/final"), nil
		})
		_, err := fetchDiscoveryDocument(u1ctx, discURL, 0, u1True)
		u1ExpectCode(t, err, "oidc_endpoint_redirect")
		if f.count() != 1 {
			t.Fatalf("redirect was followed: %d requests", f.count())
		}
	})
}

func TestUnitFetchOIDCEndpointResponseRedirectHandling(t *testing.T) {
	t.Run("uses manual redirect mode and rejects redirect responses", func(t *testing.T) {
		f, _ := u1Setup(t)
		f.set(func(*http.Request) (*http.Response, error) {
			return u1Resp(302, "", nil, "Location", "https://idp.example.com/final-jwks"), nil
		})
		_, err := fetchOIDCEndpoint(u1ctx, "jwksEndpoint", "https://idp.example.com/jwks", "GET", "", nil, 0, u1True)
		u1ExpectCode(t, err, "oidc_endpoint_redirect")
		if f.count() != 1 {
			t.Fatalf("fetch calls = %d, want 1 (redirect must not be followed)", f.count())
		}
		u1Eq(t, f.calls[0].URL.String(), "https://idp.example.com/jwks")
	})
}
