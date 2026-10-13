package oauthprovider

import (
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of authorize.test.ts (part 1).

const (
	azRPRedirectURI = "http://localhost:5000/api/auth/callback/test"
	azIssEncoded    = "iss=http%3A%2F%2Flocalhost%3A3000"
)

// azResolve resolves a Location header against the auth server base URL.
func azResolve(t *testing.T, loc string) *url.URL {
	t.Helper()
	base, _ := url.Parse(testBaseURL)
	u, err := base.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// azAuthz builds an /oauth2/authorize path with code_challenge params appended.
func azAuthzPKCE(kv ...string) string {
	return authorizeURL(append(kv, "code_challenge", crypto.RandomString(43), "code_challenge_method", "S256")...)
}

func TestAz_ValidateIssuerUrlRFC9207(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"should allow HTTPS URLs unchanged", "https://auth.example.com", "https://auth.example.com"},
		{"should convert HTTP to HTTPS for non-localhost", "http://auth.example.com", "https://auth.example.com"},
		{"should allow HTTP for localhost", "http://localhost:3000", "http://localhost:3000"},
		{"should allow HTTP for 127.0.0.1", "http://127.0.0.1:3000", "http://127.0.0.1:3000"},
		{"should strip query parameters", "https://auth.example.com?foo=bar", "https://auth.example.com"},
		{"should strip fragment", "https://auth.example.com#section", "https://auth.example.com"},
		{"should strip both query and fragment", "https://auth.example.com?foo=bar#section", "https://auth.example.com"},
		{"should remove trailing slash", "https://auth.example.com/", "https://auth.example.com"},
		{"should preserve path", "https://auth.example.com/api/auth", "https://auth.example.com/api/auth"},
		{"should handle complex invalid URL and sanitize", "http://auth.example.com:8080/path?query=1#hash", "https://auth.example.com:8080/path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validateIssuerURL(c.in); got != c.want {
				t.Fatalf("validateIssuerUrl(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestAz_FormatErrorURL(t *testing.T) {
	t.Run("should append query errors before the URL fragment", func(t *testing.T) {
		got := formatErrorURL("/error?source=oauth#retry", "invalid_request", "Missing parameter", "", "", "query")
		want := "/error?source=oauth&error=invalid_request&error_description=Missing+parameter#retry"
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	})
}

func azCreateSignedParams(secret string, configure func(p *searchParams)) *searchParams {
	p := newSearchParams()
	p.set("client_id", "client-a")
	p.set("redirect_uri", "https://rp.example.com/callback")
	p.set("response_type", "code")
	p.set("scope", "openid profile")
	p.set("state", "state-a")
	if configure != nil {
		configure(p)
	}
	p.set("exp", strconv.FormatInt(time.Now().Unix()+600, 10))
	p.set(signedQueryIssuedAtParam, strconv.FormatInt(time.Now().UnixMilli(), 10))
	setSignedOAuthQueryParameterNames(p)
	p.set("sig", crypto.MakeSignature(canonicalizeOAuthQueryParams(p).String(), secret))
	return p
}

func azReversed(p *searchParams) *searchParams {
	out := newSearchParams()
	for i := len(p.list) - 1; i >= 0; i-- {
		out.append(p.list[i].k, p.list[i].v)
	}
	return out
}

func TestAz_OAuthSignedQuerySignatures(t *testing.T) {
	t.Run("should verify signed params when query params are reordered", func(t *testing.T) {
		if !VerifyOAuthQueryParams(azReversed(azCreateSignedParams("test-secret", nil)).String(), "test-secret") {
			t.Fatal("expected valid")
		}
	})
	t.Run("should verify signed params when repeated values are reordered", func(t *testing.T) {
		p := azCreateSignedParams("test-secret", func(p *searchParams) {
			p.append("resource", "https://b.example.com")
			p.append("resource", "https://a.example.com")
		})
		if !VerifyOAuthQueryParams(azReversed(p).String(), "test-secret") {
			t.Fatal("expected valid")
		}
	})
	t.Run("should reject tampered signed params", func(t *testing.T) {
		p := azCreateSignedParams("test-secret", nil)
		p.set("client_id", "client-b")
		if VerifyOAuthQueryParams(p.String(), "test-secret") {
			t.Fatal("expected invalid")
		}
	})
	t.Run("should reject duplicate signature params", func(t *testing.T) {
		p := azCreateSignedParams("test-secret", nil)
		p.append("sig", "extra-sig")
		if VerifyOAuthQueryParams(p.String(), "test-secret") {
			t.Fatal("expected invalid")
		}
	})
	t.Run("should preserve custom signed params when the client copies reordered signed queries", func(t *testing.T) {
		p := azCreateSignedParams("test-secret", func(p *searchParams) {
			p.set("custom_authorization_context", "tenant-a")
			p.append("resource", "https://api.example.com")
		})
		re := azReversed(p)
		re.append("utm_email", "user@example.com")
		// The client plugin's onRequest forwards buildSignedOAuthQuery(window.location.search).
		oauthQuery := BuildSignedOAuthQuery("?" + re.String())
		fwd := parseSearchParams(oauthQuery)
		if !VerifyOAuthQueryParams(oauthQuery, "test-secret") {
			t.Fatal("expected valid forwarded query")
		}
		if fwd.getString("custom_authorization_context") != "tenant-a" || fwd.getString("resource") != "https://api.example.com" || fwd.has("utm_email") {
			t.Fatalf("forwarded: %s", oauthQuery)
		}
		if !contains(fwd.getAll(signedQueryParameterNameParam), "custom_authorization_context") {
			t.Fatalf("missing ba_param: %s", oauthQuery)
		}
	})
}

func azAdminClient(t *testing.T, env *testEnv, h http.Header, body map[string]any) map[string]any {
	t.Helper()
	c := env.adminCreateClient(h, body)
	if azStr(c, "client_id") == "" {
		t.Fatalf("client: %v", c)
	}
	return c
}

func TestAz_OAuthAuthorizeUnauthenticated(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	client := azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{azRPRedirectURI}, "application_type": "native", "skip_consent": true})
	if azStr(client, "user_id") == "" || azStr(client, "client_secret") == "" || !reflect.DeepEqual(client["redirect_uris"], []any{azRPRedirectURI}) {
		t.Fatalf("client: %v", client)
	}
	clientID := azStr(client, "client_id")
	t.Run("should always redirect to /login because user is not logged in", func(t *testing.T) {
		loc := azLocation(env, azCreateAuthorizationURL(t, clientID, azRPRedirectURI, "123", []string{"openid"}, crypto.RandomString(64), ""), nil)
		azMustContain(t, loc, "/login", "response_type=code", "client_id="+clientID, "scope=openid", "redirect_uri="+url.QueryEscape(azRPRedirectURI))
	})
	t.Run("should replace incoming sig when signing the login redirect", func(t *testing.T) {
		raw := azCreateAuthorizationURL(t, clientID, azRPRedirectURI, "incoming-sig", []string{"openid"}, crypto.RandomString(64), "")
		raw += "&sig=attacker-sig"
		loc := azResolve(t, azLocation(env, raw, nil))
		q := parseSearchParams(loc.RawQuery)
		if len(q.getAll("sig")) != 1 || q.getString("sig") == "attacker-sig" {
			t.Fatalf("sig: %s", loc)
		}
		secret := "better-auth.secret-for-tests-1234567890abcdef"
		if !VerifyOAuthQueryParams(loc.RawQuery, secret) || !VerifyOAuthQueryParams(azReversed(q).String(), secret) {
			t.Fatalf("signature invalid: %s", loc)
		}
	})
	t.Run("should return login_required when prompt=none and user is not logged in", func(t *testing.T) {
		loc := azLocation(env, azAuthzPKCE("client_id", clientID, "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", "openid", "state", "prompt-none-login-required", "prompt", "none"), nil)
		azMustContain(t, loc, azRPRedirectURI, "error=login_required", "state=prompt-none-login-required", azIssEncoded)
		azMustNotContain(t, loc, "/login")
	})
}

func TestAz_OAuthAuthorizeMaxAge(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	client := azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{azRPRedirectURI}, "application_type": "native", "skip_consent": true})
	needsConsent := azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{azRPRedirectURI}, "application_type": "native", "skip_consent": false})
	redirectFor := func(maxAge, prompt, clientID string) string {
		if clientID == "" {
			clientID = azStr(client, "client_id")
		}
		kv := []string{"client_id", clientID, "redirect_uri", azRPRedirectURI, "response_type", "code", "scope", "openid",
			"state", "123", "code_challenge", crypto.RandomString(43), "code_challenge_method", "S256", "max_age", maxAge}
		if prompt != "" {
			kv = append(kv, "prompt", prompt)
		}
		return azLocation(env, authorizeURL(kv...), h)
	}
	t.Run("treats max_age=0 as an explicit re-authentication request", func(t *testing.T) {
		azMustContain(t, redirectFor("0", "", ""), "/login")
	})
	t.Run("does not re-authenticate when the session is within max_age", func(t *testing.T) {
		loc := redirectFor("10000", "", "")
		azMustContain(t, loc, azRPRedirectURI, "code=")
		azMustNotContain(t, loc, "/login")
	})
	t.Run("removes satisfied max_age before redirecting to consent", func(t *testing.T) {
		u := azResolve(t, redirectFor("10000", "", azStr(needsConsent, "client_id")))
		if u.Path != "/consent" || u.Query().Has("max_age") || u.Query().Get("client_id") != azStr(needsConsent, "client_id") {
			t.Fatalf("consent redirect: %s", u)
		}
	})
	t.Run("returns login_required for prompt=none when the session is older than max_age", func(t *testing.T) {
		loc := redirectFor("0", "none", "")
		azMustContain(t, loc, "error=login_required")
		azMustNotContain(t, loc, "/login")
	})
	t.Run("returns invalid_request for invalid max_age values", func(t *testing.T) {
		loc := redirectFor("-1", "", "")
		azMustContain(t, loc, azRPRedirectURI, "error=invalid_request")
		azMustNotContain(t, loc, "/login")
	})
	t.Run("returns invalid_request for empty max_age values", func(t *testing.T) {
		for _, maxAge := range []string{"", "   "} {
			loc := redirectFor(maxAge, "", "")
			azMustContain(t, loc, azRPRedirectURI, "error=invalid_request")
			azMustNotContain(t, loc, "/login")
		}
	})
}

func TestAz_OAuthAuthorizeACRRequests(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	client := azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{azRPRedirectURI}, "application_type": "native", "skip_consent": true})
	// acrClaim is the JSON of the acr claim request ("" for none).
	redirectFor := func(acrClaim, scope string) *url.URL {
		if scope == "" {
			scope = "openid"
		}
		kv := []string{"client_id", azStr(client, "client_id"), "redirect_uri", azRPRedirectURI, "response_type", "code",
			"scope", scope, "state", "acr-state", "code_challenge", crypto.RandomString(43), "code_challenge_method", "S256"}
		if acrClaim != "" {
			kv = append(kv, "claims", `{"id_token":{"acr":`+acrClaim+`}}`)
		}
		return azResolve(t, azLocation(env, authorizeURL(kv...), h))
	}
	expectCode := func(t *testing.T, u *url.URL) {
		t.Helper()
		if u.Query().Has("error") || u.Query().Get("code") == "" {
			t.Fatalf("expected code: %s", u)
		}
	}
	t.Run("claims.id_token.acr (OIDC Core 1.0 §5.5.1.1)", func(t *testing.T) {
		t.Run("accepts an unsupported voluntary claim", func(t *testing.T) {
			expectCode(t, redirectFor(`{"values":["1"]}`, ""))
		})
		for _, c := range [][2]string{{"value", `{"essential":true,"value":"1"}`}, {"values", `{"essential":true,"values":["1"]}`}} {
			t.Run("rejects an unsupported essential "+c[0], func(t *testing.T) {
				u := redirectFor(c[1], "")
				if u.Scheme+"://"+u.Host+u.Path != azRPRedirectURI || u.Query().Get("error") != "access_denied" ||
					u.Query().Get("state") != "acr-state" || u.Query().Has("code") {
					t.Fatalf("redirect: %s", u)
				}
			})
		}
		for _, c := range [][2]string{{"value", `{"essential":true,"value":1}`}, {"values", `{"essential":true,"values":"1"}`}} {
			t.Run("rejects a malformed essential "+c[0], func(t *testing.T) {
				u := redirectFor(c[1], "")
				if u.Query().Get("error") != "invalid_request" || u.Query().Get("state") != "acr-state" || u.Query().Has("code") {
					t.Fatalf("redirect: %s", u)
				}
			})
		}
		for _, c := range []string{`{"essential":true,"value":"1"}`, `{"essential":true,"value":1}`} {
			t.Run("rejects claims in OAuth-only requests", func(t *testing.T) {
				u := redirectFor(c, "profile")
				if u.Query().Get("error") != "invalid_request" ||
					u.Query().Get("error_description") != "openid scope must be requested when using the claims parameter" || u.Query().Has("code") {
					t.Fatalf("redirect: %s", u)
				}
			})
		}
		t.Run("accepts the current ACR in an essential values request", func(t *testing.T) {
			expectCode(t, redirectFor(`{"essential":true,"values":["1","0"]}`, ""))
		})
		t.Run("accepts matching value and values selectors", func(t *testing.T) {
			expectCode(t, redirectFor(`{"essential":true,"value":"0","values":["0"]}`, ""))
		})
		t.Run("rejects conflicting value and values selectors", func(t *testing.T) {
			u := redirectFor(`{"essential":true,"value":"0","values":["1"]}`, "")
			if u.Query().Get("error") != "access_denied" || u.Query().Has("code") {
				t.Fatalf("redirect: %s", u)
			}
		})
	})
}

func TestAz_OAuthAuthorizeRequestURIResolution(t *testing.T) {
	const (
		requestURI                    = "urn:better-auth:par:test"
		requestURIWithPostLoginMarker = "urn:better-auth:par:post-login"
		requestURIWithInvalidMaxAge   = "urn:better-auth:par:invalid-max-age"
		requestURIWithReorderedPrompt = "urn:better-auth:par:reordered-prompt"
	)
	calls := 0
	resolver := func(in RequestURIInput) (*jsonx.Object, error) {
		calls++
		p := jsonx.O("response_type", "code", "redirect_uri", azRPRedirectURI, "scope", "openid", "state", "par-state",
			"code_challenge", strings.Repeat("a", 43), "code_challenge_method", "S256")
		switch in.RequestURI {
		case requestURI:
			return p, nil
		case requestURIWithPostLoginMarker:
			p.Set(postLoginClearedParam, "attacker-session")
			return p, nil
		case requestURIWithInvalidMaxAge:
			p.Set("max_age", "-1")
			return p, nil
		case requestURIWithReorderedPrompt:
			p.Set("prompt", "consent login")
			return p, nil
		}
		return nil, nil
	}
	env := newEnv(t, Options{RequestURIResolver: resolver})
	h := env.signInWithTestUser()
	clientID := azStr(azAdminClient(t, env, h, map[string]any{"redirect_uris": []any{azRPRedirectURI}, "application_type": "native", "skip_consent": true}), "client_id")
	t.Run("should reject request_uri without client_id before resolver lookup", func(t *testing.T) {
		calls = 0
		u := azResolve(t, azLocation(env, authorizeURL("request_uri", requestURI), nil))
		if calls != 0 {
			t.Fatal("resolver should not have been called")
		}
		if u.Query().Get("error") != "invalid_request" || !regexp.MustCompile(`client_id`).MatchString(u.Query().Get("error_description")) {
			t.Fatalf("redirect: %s", u)
		}
	})
	t.Run("should sign the resolved PAR parameters for the login redirect", func(t *testing.T) {
		loc := azLocation(env, authorizeURL("client_id", clientID, "request_uri", requestURI), nil)
		azMustContain(t, loc, "/login", "response_type=code", "client_id="+clientID, "scope=openid",
			"redirect_uri="+url.QueryEscape(azRPRedirectURI), "state=par-state")
		azMustNotContain(t, loc, "request_uri=")
	})
	t.Run("should drop reserved post-login markers from resolved PAR parameters", func(t *testing.T) {
		u := azResolve(t, azLocation(env, authorizeURL("client_id", clientID, "request_uri", requestURIWithPostLoginMarker), nil))
		if u.Path != "/login" || u.Query().Has(postLoginClearedParam) {
			t.Fatalf("redirect: %s", u)
		}
	})
	t.Run("should discard front-channel params not in the stored PAR request", func(t *testing.T) {
		loc := azLocation(env, authorizeURL("client_id", clientID, "request_uri", requestURI, "prompt", "none", "scope", "openid profile admin"), nil)
		azMustContain(t, loc, "/login", "scope=openid")
		azMustNotContain(t, loc, "admin", "prompt=none")
	})
	t.Run("should validate resolved PAR parameters through the authorization query schema", func(t *testing.T) {
		loc := azLocation(env, authorizeURL("client_id", clientID, "request_uri", requestURIWithInvalidMaxAge), nil)
		azMustContain(t, loc, azRPRedirectURI, "error=invalid_request")
		azMustNotContain(t, loc, "/login")
	})
	t.Run("should accept valid PAR prompt values in any order", func(t *testing.T) {
		u := azResolve(t, azLocation(env, authorizeURL("client_id", clientID, "request_uri", requestURIWithReorderedPrompt), nil))
		if u.Path != "/login" || u.Query().Get("prompt") != "consent login" {
			t.Fatalf("redirect: %s", u)
		}
	})
}
