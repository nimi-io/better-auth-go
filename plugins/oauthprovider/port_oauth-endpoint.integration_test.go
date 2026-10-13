package oauthprovider

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of oauth-endpoint.integration.test.ts.

func mxAbsURL(t *testing.T, loc string) *url.URL {
	t.Helper()
	if loc == "" {
		t.Fatal("missing redirect location")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return (&url.URL{Scheme: "http", Host: "localhost:3000"}).ResolveReference(u)
}

func mxExpectRedirectStatus(t *testing.T, res *response) {
	t.Helper()
	if res.status < 300 || res.status >= 400 {
		t.Fatalf("expected redirect, got %d %s", res.status, res.body)
	}
}

func TestMx_RFCEnvelopeComplianceAcrossOAuthEndpoints(t *testing.T) {
	env := newEnv(t, Options{}, envOptions{jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}}})
	h := env.signInWithTestUser()
	redirectURI := "http://localhost:5000/api/auth/oauth2/callback/test"
	oc := env.adminCreateClient(h, map[string]any{
		"redirect_uris": []any{redirectURI}, "application_type": "native", "skip_consent": true,
	})
	clientID, _ := oc["client_id"].(string)
	clientSecret, _ := oc["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		t.Fatalf("OAuth client was not created: %v", oc)
	}
	withJSON := func(extra http.Header) http.Header {
		out := h.Clone()
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	postForm := func(path string, form url.Values) *response {
		return env.do("POST", path, form, withJSON(nil))
	}
	postJSON := func(path string, body map[string]any) *response {
		return env.do("POST", path, body, withJSON(nil))
	}
	redirect := func(path string) *response { return env.do("GET", path, nil, h) }

	for _, path := range []string{"/oauth2/introspect", "/oauth2/revoke"} {
		t.Run(path+" rejects repeated form client authentication fields", func(t *testing.T) {
			body := "client_id=" + url.QueryEscape(clientID) + "&client_secret=" + url.QueryEscape(clientSecret) +
				"&client_secret=duplicate-secret&token=opaque-token"
			res := env.do("POST", path, body, withJSON(nil))
			if res.status != 400 || res.json()["error"] != "invalid_request" {
				t.Fatalf("got %d %s", res.status, res.body)
			}
		})
	}

	t.Run("oauth2Token (JSON delivery)", func(t *testing.T) {
		t.Run("missing grant_type → invalid_request", func(t *testing.T) {
			res := postForm("/oauth2/token", url.Values{})
			if res.status != 400 {
				t.Fatalf("status %d %s", res.status, res.body)
			}
			mxExpectJSON(t, res.json(), map[string]any{"error": "invalid_request", "error_description": "grant_type is required"})
		})
		t.Run("unsupported grant_type → unsupported_grant_type", func(t *testing.T) {
			res := postForm("/oauth2/token", url.Values{"grant_type": {"password"}})
			if res.status != 400 || res.json()["error"] != "unsupported_grant_type" {
				t.Fatalf("got %d %s", res.status, res.body)
			}
		})
	})

	t.Run("oauth2Revoke (JSON delivery)", func(t *testing.T) {
		t.Run("unknown token_type_hint is ignored at schema level (RFC 7009 §2.2.1)", func(t *testing.T) {
			res := postForm("/oauth2/revoke", url.Values{"token": {"placeholder"}, "token_type_hint": {"id_token"}})
			if res.json()["error"] == "unsupported_token_type" {
				t.Fatalf("got %s", res.body)
			}
		})
		t.Run("missing token → invalid_request with envelope", func(t *testing.T) {
			res := postForm("/oauth2/revoke", url.Values{})
			if res.status != 400 {
				t.Fatalf("status %d %s", res.status, res.body)
			}
			mxExpectJSON(t, res.json(), map[string]any{"error": "invalid_request", "error_description": "token is required"})
		})
	})

	t.Run("registerOAuthClient (JSON delivery)", func(t *testing.T) {
		t.Run("disabled registration rejects before metadata validation", func(t *testing.T) {
			res := postJSON("/oauth2/register", map[string]any{})
			if res.status != 403 || res.json()["error"] != "access_denied" {
				t.Fatalf("got %d %s", res.status, res.body)
			}
		})
		t.Run("disabled registration does not leak supported auth methods", func(t *testing.T) {
			res := postJSON("/oauth2/register", map[string]any{"redirect_uris": []any{redirectURI},
				"application_type": "native", "token_endpoint_auth_method": "not_a_real_method"})
			if res.status != 403 || res.json()["error"] != "access_denied" {
				t.Fatalf("got %d %s", res.status, res.body)
			}
		})
	})

	t.Run("oauth2Authorize (redirect delivery)", func(t *testing.T) {
		t.Run("unsupported response_type=token → error in fragment (OIDC §5)", func(t *testing.T) {
			state := "opaque-state-abc"
			res := redirect(authorizeURL("client_id", clientID, "redirect_uri", redirectURI, "response_type", "token", "state", state))
			mxExpectRedirectStatus(t, res)
			loc := res.location()
			u := mxAbsURL(t, loc)
			if !strings.HasPrefix(loc, redirectURI) || u.Fragment == "" {
				t.Fatalf("location %q", loc)
			}
			p := parseSearchParams(u.Fragment)
			if p.getString("error") != "unsupported_response_type" || p.getString("error_description") == "" ||
				p.getString("state") != state || p.getString("iss") == "" {
				t.Fatalf("fragment %q", u.Fragment)
			}
		})
		t.Run("response_mode=query overrides implicit default", func(t *testing.T) {
			res := redirect(authorizeURL("client_id", clientID, "redirect_uri", redirectURI, "response_type", "token",
				"response_mode", "query", "state", "s"))
			u := mxAbsURL(t, res.location())
			if u.Fragment != "" || strings.Contains(res.location(), "#") || u.Query().Get("error") != "unsupported_response_type" {
				t.Fatalf("location %q", res.location())
			}
		})
		t.Run("duplicated response_type → invalid_request (RFC 6749 §3.1)", func(t *testing.T) {
			res := redirect(authorizeURL("client_id", clientID, "redirect_uri", redirectURI, "response_type", "code",
				"response_type", "token", "state", "s"))
			mxExpectRedirectStatus(t, res)
			u := mxAbsURL(t, res.location())
			if u.Query().Get("error") != "invalid_request" || !regexp.MustCompile(`response_type`).MatchString(u.Query().Get("error_description")) {
				t.Fatalf("location %q", res.location())
			}
		})
		t.Run("missing response_type with trusted redirect_uri → invalid_request", func(t *testing.T) {
			state := "missing-response-type"
			res := redirect(authorizeURL("client_id", clientID, "redirect_uri", redirectURI, "state", state))
			mxExpectRedirectStatus(t, res)
			loc := res.location()
			u := mxAbsURL(t, loc)
			if !strings.HasPrefix(loc, redirectURI) || u.Query().Get("error") != "invalid_request" ||
				!strings.Contains(u.Query().Get("error_description"), "response_type") ||
				u.Query().Get("state") != state || u.Query().Get("iss") == "" {
				t.Fatalf("location %q", loc)
			}
		})
		t.Run("missing response_type with unregistered redirect_uri → server error page", func(t *testing.T) {
			res := redirect(authorizeURL("client_id", clientID, "redirect_uri", "https://evil.example.com/callback", "state", "s"))
			mxExpectRedirectStatus(t, res)
			loc := res.location()
			u := mxAbsURL(t, loc)
			if strings.HasPrefix(loc, redirectURI) || strings.Contains(loc, "evil.example.com") ||
				u.Query().Get("error") != "invalid_request" || !strings.Contains(u.Query().Get("error_description"), "response_type") {
				t.Fatalf("location %q", loc)
			}
		})
		t.Run("form POST authorization request → code redirect", func(t *testing.T) {
			state := "post-authorization-state"
			form := url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
				"scope": {"openid"}, "state": {state}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}}
			res := env.do("POST", "/oauth2/authorize", form, h)
			mxExpectRedirectStatus(t, res)
			loc := res.location()
			u := mxAbsURL(t, loc)
			if !strings.HasPrefix(loc, redirectURI) || u.Query().Get("code") == "" || u.Query().Get("state") != state || u.Query().Get("iss") == "" {
				t.Fatalf("location %q", loc)
			}
		})
		requestErr := func(t *testing.T, key, value, code string) {
			t.Helper()
			res := redirect(authorizeURL("client_id", clientID, "redirect_uri", redirectURI, "response_type", "code",
				"scope", "openid", key, value))
			mxExpectRedirectStatus(t, res)
			loc := res.location()
			u := mxAbsURL(t, loc)
			if !strings.HasPrefix(loc, redirectURI) || u.Query().Get("error") != code || u.Query().Has("code") {
				t.Fatalf("location %q", loc)
			}
		}
		t.Run("unsupported request object → request_not_supported", func(t *testing.T) {
			requestErr(t, "request", "eyJhbGciOiJub25lIn0.eyJzdGF0ZSI6Imp3dC1zdGF0ZSJ9.", "request_not_supported")
		})
		t.Run("empty request object parameter → request_not_supported", func(t *testing.T) {
			requestErr(t, "request", "", "request_not_supported")
		})
		t.Run("unsupported request_uri without resolver → request_uri_not_supported", func(t *testing.T) {
			requestErr(t, "request_uri", "https://rp.example.com/request.jwt", "request_uri_not_supported")
		})
		t.Run("empty request_uri parameter without resolver → request_uri_not_supported", func(t *testing.T) {
			requestErr(t, "request_uri", "", "request_uri_not_supported")
		})
		t.Run("missing client_id → server error page with invalid_request (no RP to trust)", func(t *testing.T) {
			res := redirect(authorizeURL("redirect_uri", redirectURI, "response_type", "code", "state", "s"))
			mxExpectRedirectStatus(t, res)
			loc := res.location()
			u := mxAbsURL(t, loc)
			if strings.HasPrefix(loc, redirectURI) || u.Query().Get("error") != "invalid_request" || u.Query().Get("error_description") == "" {
				t.Fatalf("location %q", loc)
			}
		})
		t.Run("invalid response_type with unregistered redirect_uri → server error page", func(t *testing.T) {
			res := redirect(authorizeURL("client_id", clientID, "redirect_uri", "http://evil.example.com/callback",
				"response_type", "token", "state", "s"))
			mxExpectRedirectStatus(t, res)
			if loc := res.location(); loc == "" || strings.HasPrefix(loc, "http://evil.example.com") {
				t.Fatalf("location %q", loc)
			}
		})
	})

	t.Run("oauth2Introspect (JSON delivery)", func(t *testing.T) {
		t.Run("missing token → invalid_request with envelope", func(t *testing.T) {
			res := postForm("/oauth2/introspect", url.Values{})
			if res.status != 400 {
				t.Fatalf("status %d %s", res.status, res.body)
			}
			mxExpectJSON(t, res.json(), map[string]any{"error": "invalid_request", "error_description": "token is required"})
		})
	})

	t.Run("oauth2EndSession (JSON delivery)", func(t *testing.T) {
		t.Run("missing id_token_hint → controlled invalid_request with envelope", func(t *testing.T) {
			res := env.do("GET", "/oauth2/end-session", nil, h)
			if res.status != 400 {
				t.Fatalf("status %d %s", res.status, res.body)
			}
			mxExpectJSON(t, res.json(), map[string]any{"error": "invalid_request",
				"error_description": "User confirmation is required to complete logout"})
		})
	})
}
