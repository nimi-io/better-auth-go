package cimd

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

// Port of packages/cimd/src/validate-metadata-document.test.ts.

func validMetadata(fetchURL string, overrides map[string]any) map[string]any {
	u, _ := url.Parse(fetchURL)
	origin := u.Scheme + "://" + u.Host
	m := map[string]any{"client_id": fetchURL, "client_name": "Example Client", "redirect_uris": []any{origin + "/callback"}}
	for k, v := range overrides {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	return m
}

func expectInvalid(t *testing.T, r MetadataValidationResult, contains string) {
	t.Helper()
	if r.Valid || !strings.Contains(r.Error, contains) {
		t.Fatalf("expected invalid containing %q, got %+v", contains, r)
	}
}

func expectValid(t *testing.T, r MetadataValidationResult) {
	t.Helper()
	if !r.Valid || r.Error != "" {
		t.Fatalf("expected valid, got %q", r.Error)
	}
}

func TestIsCimdClientIDURLCandidate(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
		want bool
	}{
		{"accepts https:// URLs", []string{"https://example.com/meta"}, true},
		{"matches mixed-case URL schemes (schemes are case-insensitive)", []string{"HTTPS://example.com/meta", "HtTpS://example.com/meta"}, true},
		{"routes https:// loopback-shaped IDs to validation", []string{"https://127.0.0.1/meta", "https://localhost/meta"}, true},
		{"does not match http:// loopback", []string{"http://localhost/meta", "http://127.0.0.1:8080/meta", "http://[::1]/meta", "http://app.localhost/meta"}, false},
		{"rejects http:// non-loopback", []string{"http://example.com/meta"}, false},
		{"rejects non-URL strings", []string{"my-client-id", "ftp://example.com/meta"}, false},
		{"rejects empty string", []string{""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, id := range c.ids {
				if got := IsCimdClientIDURLCandidate(id); got != c.want {
					t.Fatalf("%s: %v", id, got)
				}
			}
		})
	}
}

func TestValidateClientIDURL(t *testing.T) {
	contains := func(t *testing.T, raw, want string) {
		t.Helper()
		if got := ValidateClientIDURL(raw); !strings.Contains(got, want) || got == "" {
			t.Fatalf("%s: %q (want %q)", raw, got, want)
		}
	}
	rejected := func(t *testing.T, raws ...string) {
		t.Helper()
		for _, raw := range raws {
			if ValidateClientIDURL(raw) == "" {
				t.Fatalf("%s accepted", raw)
			}
		}
	}
	accepted := func(t *testing.T, raws ...string) {
		t.Helper()
		for _, raw := range raws {
			if got := ValidateClientIDURL(raw); got != "" {
				t.Fatalf("%s: %s", raw, got)
			}
		}
	}
	t.Run("accepts valid https URL with path", func(t *testing.T) { accepted(t, "https://example.com/client-metadata.json") })
	t.Run("requires an explicit root path for draft-02 validation", func(t *testing.T) {
		contains(t, "https://example.com", "explicit path")
		accepted(t, "https://example.com/")
	})
	for _, raw := range []string{"https:example.com/client.json", "https:/example.com/client.json", "https:///example.com/client.json",
		"https:////example.com/client.json", `https:\\example.com\client.json`, `https://example.com\client.json`} {
		t.Run("rejects malformed raw HTTPS authority form: "+raw, func(t *testing.T) { contains(t, raw, "explicit HTTPS authority form") })
	}
	t.Run("accepts case-insensitive HTTPS scheme syntax", func(t *testing.T) { accepted(t, "HTTPS://example.com/client.json") })
	t.Run("rejects URL with fragment", func(t *testing.T) { contains(t, "https://example.com/meta#frag", "fragment") })
	t.Run("rejects URL with dot segments", func(t *testing.T) {
		contains(t, "https://example.com/../meta.json", "dot segments")
		contains(t, "https://example.com/./meta.json", "dot segments")
	})
	t.Run("rejects URL with credentials", func(t *testing.T) { contains(t, "https://user:pass@example.com/meta", "credentials") })
	t.Run("rejects non-https non-loopback", func(t *testing.T) { contains(t, "http://example.com/meta", "HTTPS") })
	t.Run("rejects http://localhost", func(t *testing.T) { rejected(t, "http://localhost/meta", "http://localhost:8080/meta") })
	t.Run("rejects private IP 10.0.0.1", func(t *testing.T) { contains(t, "https://10.0.0.1/meta", "private") })
	t.Run("rejects private IP 172.16.0.1", func(t *testing.T) { contains(t, "https://172.16.0.1/meta", "private") })
	t.Run("rejects private IP 192.168.1.1", func(t *testing.T) { contains(t, "https://192.168.1.1/meta", "private") })
	t.Run("rejects link-local 169.254.169.254 (AWS metadata)", func(t *testing.T) { contains(t, "https://169.254.169.254/meta", "private") })
	t.Run("rejects loopback IP 127.0.0.1 via https", func(t *testing.T) { rejected(t, "https://127.0.0.1/meta", "https://127.0.0.1:8080/meta") })
	t.Run("accepts public IP like 8.8.8.8", func(t *testing.T) { accepted(t, "https://8.8.8.8/meta") })
	t.Run("rejects 6to4 anycast relay 192.88.99.1 (RFC 7526 deprecated)", func(t *testing.T) { contains(t, "https://192.88.99.1/meta", "private") })
	t.Run("rejects multicast addresses (RFC 5771, 224.0.0.0/4)", func(t *testing.T) {
		contains(t, "https://224.0.0.1/meta", "private")
		contains(t, "https://239.255.255.250/meta", "private")
	})
	t.Run("rejects reserved/future-use and broadcast addresses (240.0.0.0/4)", func(t *testing.T) {
		contains(t, "https://240.0.0.1/meta", "private")
		contains(t, "https://255.255.255.255/meta", "private")
	})
	t.Run("rejects IPv4-mapped IPv6 targeting private/link-local IPs", func(t *testing.T) {
		contains(t, "https://[::ffff:169.254.169.254]/meta", "private")
		contains(t, "https://[::ffff:10.0.0.1]/meta", "private")
		rejected(t, "https://[::ffff:127.0.0.1]/meta")
	})
	t.Run("rejects cloud metadata hostname", func(t *testing.T) { contains(t, "https://metadata.google.internal/meta", "private") })
	t.Run("rejects subdomain of localhost", func(t *testing.T) { rejected(t, "http://app.localhost/meta", "https://app.localhost/meta") })
	t.Run("rejects IPv6 unspecified [::] (0.0.0.0-day class)", func(t *testing.T) { rejected(t, "https://[::]/meta") })
	t.Run("rejects trailing-dot cloud-metadata FQDN", func(t *testing.T) { rejected(t, "https://metadata.google.internal./meta") })
	t.Run("rejects additional cloud-metadata FQDNs", func(t *testing.T) {
		rejected(t, "https://metadata.goog/meta", "https://metadata/meta", "https://instance-data/meta", "https://instance-data.ec2.internal/meta")
	})
	t.Run("rejects IPv6 tunnel forms embedding private/IMDS IPv4 (6to4, NAT64, Teredo)", func(t *testing.T) {
		rejected(t, "https://[2002:7f00:1::]/meta", "https://[64:ff9b::7f00:1]/meta", "https://[2001:0:0:0:0:0:7f00:1]/meta")
	})
	t.Run("rejects deprecated IPv4-compatible IPv6 embedding loopback/IMDS/private", func(t *testing.T) {
		rejected(t, "https://[::127.0.0.1]/meta", "https://[::169.254.169.254]/meta", "https://[::10.0.0.1]/meta")
	})
	t.Run("rejects percent-encoded dot segments", func(t *testing.T) {
		contains(t, "https://example.com/%2e%2e/meta", "dot segments")
		contains(t, "https://example.com/%2e/meta", "dot segments")
	})
}

var ecJWK = map[string]any{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF4BM-Y5uP1oahSjXdY9tAe3hoTb3QuA7qM",
	"y": "x_FEzRu9wNL7LMBTlSTd4vP7qB27FjGCFZB-RcIEpV0"}

func TestValidateCimdMetadata(t *testing.T) {
	const fetchURL = "https://example.com/client-metadata.json"
	mcpProfile := MetadataValidationOptions{MetadataProfile: MetadataProfileMCP20260728}
	none := MetadataValidationOptions{}
	v := func(overrides map[string]any) MetadataValidationResult {
		return ValidateCimdMetadata(fetchURL, validMetadata(fetchURL, overrides), none)
	}

	t.Run("requires a non-empty client_name", func(t *testing.T) {
		for _, name := range []any{nil, "", "   "} {
			m := validMetadata(fetchURL, nil)
			if name == nil {
				delete(m, "client_name")
			} else {
				m["client_name"] = name
			}
			expectInvalid(t, ValidateCimdMetadata(fetchURL, m, mcpProfile), "client_name")
		}
	})
	t.Run("preserves surrounding client_name whitespace after validation", func(t *testing.T) {
		r := v(map[string]any{"client_name": "  Display Name  "})
		expectValid(t, r)
		if n, _ := r.Metadata.Get("client_name"); n != "  Display Name  " {
			t.Fatal(n)
		}
	})
	t.Run("rejects malformed shared client metadata before CIMD policy checks", func(t *testing.T) {
		for _, m := range []map[string]any{{"application_type": "desktop"}, {"contacts": "security@example.com"},
			{"scope": []any{"openid"}}, {"dpop_bound_access_tokens": "true"}} {
			if r := v(m); r.Valid {
				t.Fatal(m)
			}
		}
	})
	t.Run("accepts valid metadata where client_id == fetchUrl", func(t *testing.T) { expectValid(t, v(nil)) })
	t.Run("accepts generic metadata without display or redirect fields for a supported non-redirect grant", func(t *testing.T) {
		r := ValidateCimdMetadata(fetchURL, map[string]any{"client_id": fetchURL, "grant_types": []any{"client_credentials"},
			"token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{ecJWK}}}, none)
		expectValid(t, r)
		if r.Metadata.Has("client_name") || r.Metadata.Has("redirect_uris") {
			t.Fatal(r.Metadata)
		}
	})
	for _, c := range []struct {
		name string
		doc  map[string]any
	}{
		{"client_name", map[string]any{"client_id": fetchURL, "redirect_uris": []any{"https://example.com/callback"}}},
		{"redirect_uris", map[string]any{"client_id": fetchURL, "client_name": "MCP Client"}},
	} {
		t.Run("requires "+c.name+" for the MCP 2026-07-28 metadata profile", func(t *testing.T) {
			expectInvalid(t, ValidateCimdMetadata(fetchURL, c.doc, mcpProfile), c.name)
		})
	}
	t.Run("rejects when client_id != fetchUrl", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"client_id": "https://evil.com/client-metadata.json"}), "does not match")
	})
	t.Run("compares client_id to the fetched URL without trimming", func(t *testing.T) {
		for _, id := range []string{" " + fetchURL, fetchURL + " "} {
			expectInvalid(t, v(map[string]any{"client_id": id}), "does not match")
		}
	})
	t.Run("uses simple-string comparison when one client_id has an explicit default port", func(t *testing.T) {
		explicit := "https://example.com:443/client-metadata.json"
		expectInvalid(t, ValidateCimdMetadata(explicit, validMetadata(explicit, map[string]any{"client_id": fetchURL}), none), "does not match")
	})
	t.Run("rejects when client_secret is present", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"client_secret": "test-secret"}), "client_secret")
	})
	t.Run("rejects when client_secret_expires_at is present", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"client_secret_expires_at": 0}), "client_secret_expires_at")
	})
	t.Run("rejects recognized credential, privilege, and server-control fields", func(t *testing.T) {
		for _, field := range []string{"disabled", "skip_consent", "enable_end_session", "require_pkce", "reference_id", "user_id",
			"client_id_issued_at", "resources", "skipConsent", "enableEndSession", "requirePKCE", "clientSecret", "referenceId",
			"userId", "clientId", "applicationType", "tokenEndpointAuthMethod", "redirectUris", "postLogoutRedirectUris",
			"grantTypes", "responseTypes", "scopes", "expiresAt", "createdAt", "updatedAt", "softwareId", "softwareVersion",
			"softwareStatement", "backchannelLogoutUri", "backchannelLogoutSessionRequired", "jwksUri", "dpopBoundAccessTokens",
			"subjectType"} {
			expectInvalid(t, v(map[string]any{field: true}), field)
		}
	})
	t.Run("ignores unknown members and generic internal storage aliases", func(t *testing.T) {
		unknown := map[string]any{"name": "Internal alias", "uri": "https://ignored.example.com", "icon": "https://ignored.example.com/icon.png",
			"tos": "https://ignored.example.com/tos", "policy": "https://ignored.example.com/policy", "metadata": map[string]any{"privileged": true},
			"clientCredentialsScopes": []any{"admin"}, "client_credentials_scopes": []any{"admin"}, "public": true, "type": "web",
			"https://example.com/oauth/custom": map[string]any{"display_mode": "compact"}}
		r := v(unknown)
		expectValid(t, r)
		for k := range unknown {
			if r.Metadata.Has(k) {
				t.Fatal(k)
			}
		}
	})
	for _, m := range []string{"client_secret_post", "client_secret_basic", "client_secret_jwt"} {
		t.Run("rejects symmetric auth method "+m, func(t *testing.T) {
			expectInvalid(t, v(map[string]any{"token_endpoint_auth_method": m}), "symmetric")
		})
	}
	t.Run(`accepts token_endpoint_auth_method: "none"`, func(t *testing.T) {
		expectValid(t, v(map[string]any{"token_endpoint_auth_method": "none"}))
	})
	t.Run(`accepts token_endpoint_auth_method: "private_key_jwt" with jwks`, func(t *testing.T) {
		expectValid(t, v(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{ecJWK}}}))
	})
	t.Run("rejects a bare JWK array in generic CIMD metadata", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"token_endpoint_auth_method": "private_key_jwt",
			"jwks": []any{map[string]any{"kty": "RSA", "n": "modulus", "e": "AQAB"}}}), "jwks")
	})
	t.Run("rejects private or malformed public key metadata", func(t *testing.T) {
		for _, jwks := range []map[string]any{
			{"keys": []any{}},
			{"keys": []any{map[string]any{"kty": "oct", "k": "secret"}}},
			{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "private"}}},
			{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "x", "d": "private"}}},
			{"keys": []any{map[string]any{"kty": "EC"}}},
			{"keys": []any{map[string]any{"kty": "RSA", "n": "n", "e": "AQAB", "alg": "HS256"}}},
			{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "RS256"}}},
			{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES384"}}},
			{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed448", "x": "x", "alg": "EdDSA"}}},
		} {
			expectInvalid(t, v(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks}), "jwks")
		}
	})
	t.Run(`accepts token_endpoint_auth_method: "private_key_jwt" with jwks_uri`, func(t *testing.T) {
		expectValid(t, v(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://example.com/.well-known/jwks.json"}))
	})
	for _, uri := range []string{"https://user:password@example.com/.well-known/jwks.json", "https://example.com/.well-known/jwks.json#keys"} {
		t.Run("rejects an unsafe jwks_uri before persistence: "+uri, func(t *testing.T) {
			expectInvalid(t, v(map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": uri}), "jwks_uri")
		})
	}
	t.Run("rejects private_key_jwt without jwks or jwks_uri", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"token_endpoint_auth_method": "private_key_jwt"}), "jwks")
	})
	t.Run("rejects unknown auth method", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"token_endpoint_auth_method": "custom_method"}), "private_key_jwt")
	})
	t.Run("rejects missing redirect_uris", func(t *testing.T) {
		expectInvalid(t, ValidateCimdMetadata(fetchURL, map[string]any{"client_id": fetchURL, "client_name": "Missing Redirect Client"}, mcpProfile), "redirect_uris")
	})
	t.Run("rejects empty redirect_uris", func(t *testing.T) {
		expectInvalid(t, ValidateCimdMetadata(fetchURL, map[string]any{"client_id": fetchURL, "redirect_uris": []any{}}, none), "redirect_uris")
	})
	redirectDoc := func(name string, uris ...any) map[string]any {
		return map[string]any{"client_id": fetchURL, "client_name": name, "redirect_uris": uris}
	}
	t.Run("rejects redirect_uris outside HTTP(S) and private-use forms", func(t *testing.T) {
		expectInvalid(t, ValidateCimdMetadata(fetchURL, redirectDoc("Invalid Redirect Client", "ftp://example.com/callback"), none), "redirect_uris")
	})
	t.Run("accepts an authority-free private-use redirect URI", func(t *testing.T) {
		expectValid(t, ValidateCimdMetadata(fetchURL, redirectDoc("Private-use Client", "com.example.app:/callback"), none))
	})
	t.Run("rejects a private-use redirect URI with a naming authority", func(t *testing.T) {
		expectInvalid(t, ValidateCimdMetadata(fetchURL, redirectDoc("Invalid Private-use Client", "com.example.app://host/callback"), none), "redirect_uris")
	})
	for _, uri := range []string{"com.example.app:callback", "com.example.app:///callback"} {
		t.Run("rejects a private-use redirect URI without the single-slash form: "+uri, func(t *testing.T) {
			expectInvalid(t, ValidateCimdMetadata(fetchURL, redirectDoc("Invalid Private-use Client", uri), none), "redirect_uris")
		})
	}
	t.Run("rejects malformed reverse-domain private-use redirect schemes", func(t *testing.T) {
		for _, uri := range []string{"com..example:/callback", "com.-example:/callback", "com.example-:/callback"} {
			expectInvalid(t, ValidateCimdMetadata(fetchURL, redirectDoc("Invalid Private-use Client", uri), none), "redirect_uris")
		}
	})
	t.Run("accepts client_credentials as a generic CIMD grant", func(t *testing.T) {
		expectValid(t, v(map[string]any{"grant_types": []any{"client_credentials"}, "token_endpoint_auth_method": "private_key_jwt",
			"jwks": map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}}}}))
	})
	t.Run("accepts allowed grant_types", func(t *testing.T) {
		expectValid(t, v(map[string]any{"grant_types": []any{"authorization_code", "refresh_token"}}))
	})
	t.Run("accepts authorization_code alone", func(t *testing.T) {
		expectValid(t, v(map[string]any{"grant_types": []any{"authorization_code"}}))
	})
	t.Run("rejects disallowed response_types", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"response_types": []any{"token"}}), "response_types")
	})
	t.Run(`accepts response_types: ["code"]`, func(t *testing.T) {
		expectValid(t, v(map[string]any{"response_types": []any{"code"}}))
	})
	t.Run("allows localhost redirect_uris for local/native app flows", func(t *testing.T) {
		expectValid(t, ValidateCimdMetadata(fetchURL, redirectDoc("Loopback Client", "http://localhost:3000/callback", "http://127.0.0.1:3000/callback"), none))
	})
	t.Run("does not origin-bind redirect_uris by default", func(t *testing.T) {
		expectValid(t, ValidateCimdMetadata(fetchURL, redirectDoc("Cross-origin Redirect Client", "https://other-domain.com/callback"), none))
	})
	t.Run("respects custom originBoundFields parameter", func(t *testing.T) {
		d := redirectDoc("Custom Origin Client", "https://example.com/callback")
		d["logo_uri"] = "https://evil.com/logo.png"
		expectInvalid(t, ValidateCimdMetadata(fetchURL, d, MetadataValidationOptions{OriginBoundFields: []string{"logo_uri"}}), "same origin")
	})
	t.Run("does not enforce origin on fields outside originBoundFields", func(t *testing.T) {
		d := redirectDoc("External Home Page Client", "https://example.com/callback")
		d["client_uri"] = "https://other.com/about"
		expectValid(t, ValidateCimdMetadata(fetchURL, d, MetadataValidationOptions{OriginBoundFields: []string{"redirect_uris"}}))
	})
	t.Run("rejects loopback URL on a non-redirect field (client_uri)", func(t *testing.T) {
		d := redirectDoc("Unsafe Home Page Client", "https://example.com/callback")
		d["client_uri"] = "http://localhost:3000/about"
		expectInvalid(t, ValidateCimdMetadata(fetchURL, d, none), "private")
	})
	t.Run("accepts localhost URL on post_logout_redirect_uris", func(t *testing.T) {
		d := redirectDoc("Loopback Logout Client", "https://example.com/callback")
		d["post_logout_redirect_uris"] = []any{"http://localhost:3000/logout"}
		expectValid(t, ValidateCimdMetadata(fetchURL, d, none))
	})
	t.Run("validates client_uri for SSRF (private address)", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"client_uri": "http://169.254.169.254/latest/meta-data/"}), "private")
	})
	t.Run("validates logo_uri for SSRF (private address)", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"logo_uri": "http://10.0.0.1/internal-logo.png"}), "private")
	})
	t.Run("rejects IPv4-compatible IPv6 in logo_uri (SSRF)", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"logo_uri": "https://[::169.254.169.254]/logo.png"}), "private")
	})
	t.Run("accepts public client_uri and logo_uri", func(t *testing.T) {
		expectValid(t, v(map[string]any{"client_uri": "https://example.com/about", "logo_uri": "https://cdn.example.com/logo.png"}))
	})
	for _, field := range []string{"client_uri", "logo_uri", "tos_uri", "policy_uri"} {
		t.Run("rejects credentials in "+field, func(t *testing.T) {
			expectInvalid(t, v(map[string]any{field: "https://user:password@example.com/resource"}), field)
		})
	}
	for _, field := range []string{"tos_uri", "policy_uri"} {
		t.Run("rejects javascript and private targets in "+field, func(t *testing.T) {
			for _, value := range []string{"javascript:alert(1)", "https://127.0.0.1/resource"} {
				expectInvalid(t, v(map[string]any{field: value}), field)
			}
		})
	}
	for _, field := range []string{"backchannel_logout_uri", "backchannel_logout_session_required"} {
		t.Run("rejects CIMD back-channel metadata: "+field, func(t *testing.T) {
			var value any = true
			if field == "backchannel_logout_uri" {
				value = "https://client.example.com/backchannel"
			}
			expectInvalid(t, v(map[string]any{field: value}), field)
		})
	}
	t.Run("returns warning for query string in fetchUrl", func(t *testing.T) {
		withQuery := "https://example.com/client-metadata.json?v=1"
		r := ValidateCimdMetadata(withQuery, validMetadata(withQuery, nil), none)
		expectValid(t, r)
		if len(r.Warnings) == 0 || !strings.Contains(r.Warnings[0], "query string") {
			t.Fatal(r.Warnings)
		}
	})
	t.Run("accepts a root Client Identifier URL with a NOT RECOMMENDED warning", func(t *testing.T) {
		root := "https://example.com/"
		if ValidateClientIDURL(root) != "" {
			t.Fatal(ValidateClientIDURL(root))
		}
		r := ValidateCimdMetadata(root, validMetadata(root, nil), none)
		expectValid(t, r)
		if !slices.Contains(r.Warnings, "client_id URL path / is NOT RECOMMENDED (§3)") {
			t.Fatal(r.Warnings)
		}
	})
	for _, id := range []string{"https://example.com", "https://example.com?version=1"} {
		t.Run("rejects an authority-only Client Identifier URL: "+id, func(t *testing.T) {
			if !strings.Contains(ValidateClientIDURL(id), "path") {
				t.Fatal(ValidateClientIDURL(id))
			}
		})
	}
	t.Run("rejects non-object metadata", func(t *testing.T) {
		for _, raw := range []any{nil, "string", 42.0} {
			if ValidateCimdMetadata(fetchURL, raw, none).Valid {
				t.Fatal(raw)
			}
		}
	})
	t.Run("rejects client_uri with non-HTTP scheme", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"client_uri": "ftp://example.com/about"}), "client_uri")
	})
	t.Run("rejects logo_uri that is not a valid URL", func(t *testing.T) {
		expectInvalid(t, v(map[string]any{"logo_uri": "not a url"}), "logo_uri")
	})

	// Go-only: exact messages and the defaulted auth method.
	t.Run("formats schema issues as path: message and defaults the auth method", func(t *testing.T) {
		r := v(map[string]any{"application_type": "desktop"})
		if !strings.HasPrefix(r.Error, "application_type: ") {
			t.Fatal(r.Error)
		}
		ok := v(nil)
		if m, _ := ok.Metadata.Get("token_endpoint_auth_method"); m != "none" {
			t.Fatal(m)
		}
	})
}
