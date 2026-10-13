package oauthprovider

import (
	"net/url"
	"testing"

	"github.com/nimi-io/better-auth-go/crypto"
)

// Port of authorize-loopback.test.ts.

const (
	azRegisteredLocalhostRedirect        = "http://localhost/callback?source=cli"
	azRegisteredPortfulLocalhostRedirect = "http://localhost:8080/portful-callback"
	azRegisteredIPv4Redirect             = "http://127.0.0.1/callback"
)

var azRejectedRedirects = []struct{ component, redirectURI, err string }{
	{"path", "http://localhost:51234/other?source=cli", "invalid_redirect"},
	{"query", "http://localhost:51234/callback?source=other", "invalid_redirect"},
	{"protocol", "https://localhost:51234/callback?source=cli", "invalid_redirect"},
	{"localhost subdomain", "http://tenant.localhost:51234/callback?source=cli", "invalid_redirect"},
	{"fragment", "http://localhost:51234/callback?source=cli#fragment", "invalid_request"},
	{"empty fragment", "http://localhost:51234/callback?source=cli#", "invalid_request"},
	{"userinfo", "http://user:password@localhost:51234/callback?source=cli", "invalid_redirect"},
	{"scheme casing", "HTTP://localhost:51234/callback?source=cli", "invalid_redirect"},
	{"hostname casing", "http://LOCALHOST:51234/callback?source=cli", "invalid_redirect"},
	{"dot path segment", "http://localhost:51234/path/../callback?source=cli", "invalid_redirect"},
	{"empty query marker", "http://127.0.0.1:51234/callback?", "invalid_redirect"},
	{"IPv4 shorthand", "http://127.1:51234/callback", "invalid_redirect"},
}

func azExpectAuthorizationCodeRedirect(t *testing.T, loc *url.URL, expected string) {
	t.Helper()
	exp, _ := url.Parse(expected)
	if loc.Scheme+"://"+loc.Host != exp.Scheme+"://"+exp.Host || loc.Path != exp.Path {
		t.Fatalf("unexpected redirect %s (want %s)", loc, expected)
	}
	q := loc.Query()
	if q.Get("source") != exp.Query().Get("source") || q.Get("code") == "" || q.Get("state") != "state" || q.Has("error") {
		t.Fatalf("unexpected redirect params %s", loc)
	}
}

func azExpectRejectedRedirect(t *testing.T, loc *url.URL, expectedErr string) {
	t.Helper()
	if loc.Scheme+"://"+loc.Host != testBaseURL || loc.Path != "/api/auth/error" ||
		loc.Query().Get("error") != expectedErr || loc.Query().Has("code") {
		t.Fatalf("expected rejection %s, got %s", expectedErr, loc)
	}
}

func TestAz_AuthorizeLoopbackPortVariance(t *testing.T) {
	env := newEnv(t, Options{})
	h := env.signInWithTestUser()
	client := env.adminCreateClient(h, map[string]any{
		"redirect_uris":    []any{azRegisteredLocalhostRedirect, azRegisteredPortfulLocalhostRedirect, azRegisteredIPv4Redirect},
		"application_type": "native",
		"skip_consent":     true,
	})
	clientID := client["client_id"].(string)
	authorizeRedirect := func(t *testing.T, redirectURI string) *url.URL {
		t.Helper()
		res := env.do("GET", authorizeURL("client_id", clientID, "redirect_uri", redirectURI, "response_type", "code",
			"scope", "openid", "state", "state", "code_challenge", crypto.RandomString(43),
			"code_challenge_method", "S256"), nil, h)
		loc := res.location()
		if loc == "" {
			t.Fatalf("Expected the authorize endpoint to redirect: %d %s", res.status, res.body)
		}
		base, _ := url.Parse(testBaseURL)
		u, err := base.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	t.Run("accepts an ephemeral port for localhost", func(t *testing.T) {
		r := "http://localhost:51234/callback?source=cli"
		azExpectAuthorizationCodeRedirect(t, authorizeRedirect(t, r), r)
	})
	t.Run("accepts a different port for a portful localhost registration", func(t *testing.T) {
		r := "http://localhost:51234/portful-callback"
		azExpectAuthorizationCodeRedirect(t, authorizeRedirect(t, r), r)
	})
	t.Run("preserves loopback IPv4 port variance", func(t *testing.T) {
		r := "http://127.0.0.1:51234/callback"
		azExpectAuthorizationCodeRedirect(t, authorizeRedirect(t, r), r)
	})
	for _, tc := range azRejectedRedirects {
		t.Run("rejects a changed "+tc.component, func(t *testing.T) {
			azExpectRejectedRedirect(t, authorizeRedirect(t, tc.redirectURI), tc.err)
		})
	}
}
