package betterauth

// Port of better-auth/src/oauth2/state.test.ts — describe("parseState error mapping").
//
// Upstream mocks parseGenericState to throw each StateError code and calls parseState
// directly. Go inlines parseState in the /callback/:id handler (routes_social.go) and the
// state parser cannot be mocked, so each case drives the real callback into the condition
// that makes ParseGenericState fail with the same error:
//   - state_not_found:           callback without a state parameter
//   - state_invalid:             cookie strategy with an undecryptable oauth_state cookie
//   - state_mismatch:            database strategy with an unknown state
//   - state_security_mismatch:   database strategy, state cookie missing (other browser)
//   - non-StateError failure:    a stored state row whose value is not valid state JSON

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func poStateEnv(t *testing.T, mutate func(c *Config)) *testEnv {
	t.Helper()
	return socialEnv(t, mutate)
}

func poStateCookieStrategy(errorURL string) func(c *Config) {
	return func(c *Config) {
		c.Account = &AccountConfig{StoreStateStrategy: "cookie"}
		if errorURL != "" {
			c.OnAPIError = &OnAPIErrorConfig{ErrorURL: errorURL}
		}
	}
}

// poStateInvalidRedirect runs a cookie-strategy callback whose oauth_state cookie cannot
// be decrypted (StateError state_invalid) and returns the redirect location.
func poStateInvalidRedirect(t *testing.T, env *testEnv) string {
	t.Helper()
	c := env.client()
	state, _ := startSocial(t, c, map[string]any{"provider": "github", "callbackURL": "/d"})
	name := env.auth.Context().CreateAuthCookie("oauth_state", nil).Name
	if c.cookieValue(name) == "" {
		t.Fatalf("expected the %s cookie after sign-in", name)
	}
	pacSetCookies(c, &http.Cookie{Name: name, Value: "not-a-valid-encrypted-state"})
	res := c.get("/callback/github?code=x&state=" + url.QueryEscape(state))
	if res.Status != 302 {
		t.Fatalf("expected 302, got %d %s", res.Status, res.Body)
	}
	return res.Header.Get("Location")
}

func TestPortOAuthStateErrorMapping(t *testing.T) {
	cases := []struct {
		code, expected string
		redirect       func(t *testing.T) string
	}{
		{"state_not_found", "state_not_found", func(t *testing.T) string {
			env := poStateEnv(t, nil)
			return env.client().get("/callback/github").Header.Get("Location")
		}},
		{"state_invalid", "state_invalid", func(t *testing.T) string {
			return poStateInvalidRedirect(t, poStateEnv(t, poStateCookieStrategy("")))
		}},
		{"state_mismatch", "state_mismatch", func(t *testing.T) string {
			env := poStateEnv(t, nil)
			return env.client().get("/callback/github?code=x&state=unknown-state").Header.Get("Location")
		}},
		{"state_security_mismatch", "state_mismatch", func(t *testing.T) string {
			env := poStateEnv(t, nil)
			state, _ := startSocial(t, env.client(), map[string]any{"provider": "github", "callbackURL": "/d"})
			return env.client().get("/callback/github?code=x&state=" + url.QueryEscape(state)).Header.Get("Location")
		}},
	}
	for _, tc := range cases {
		t.Run("maps StateError "+tc.code+" to error="+tc.expected, func(t *testing.T) {
			loc := tc.redirect(t)
			if !strings.Contains(loc, "error="+tc.expected) {
				t.Fatalf("redirect %q does not contain error=%s", loc, tc.expected)
			}
			if strings.Contains(loc, "please_restart_the_process") {
				t.Fatalf("redirect %q must not contain please_restart_the_process", loc)
			}
		})
	}
}

func TestPortOAuthStateUnexpectedFailure(t *testing.T) {
	env := poStateEnv(t, nil)
	ia := env.auth.Context().InternalAdapter
	if _, err := ia.CreateVerificationValue(context.Background(), "auth-state:broken-state", "{not valid state json",
		time.Now().Add(10*time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	loc := env.client().get("/callback/github?code=x&state=broken-state").Header.Get("Location")
	if !strings.Contains(loc, "error=internal_server_error") {
		t.Fatalf("redirect %q does not contain error=internal_server_error", loc)
	}
}

func TestPortOAuthStateErrorURLWithQuery(t *testing.T) {
	env := poStateEnv(t, poStateCookieStrategy("https://example.com/error?foo=bar"))
	if loc := poStateInvalidRedirect(t, env); loc != "https://example.com/error?foo=bar&error=state_invalid" {
		t.Fatalf("redirect = %q", loc)
	}
}

// @see https://github.com/better-auth/better-auth/issues/10022
func TestPortOAuthStateErrorURLWithFragment(t *testing.T) {
	env := poStateEnv(t, poStateCookieStrategy("https://example.com/error?source=oauth#retry"))
	if loc := poStateInvalidRedirect(t, env); loc != "https://example.com/error?source=oauth&error=state_invalid#retry" {
		t.Fatalf("redirect = %q", loc)
	}
}

// @see https://github.com/better-auth/better-auth/issues/5467
func TestPortOAuthStatePrefersRecoveredErrorURL(t *testing.T) {
	env := poStateEnv(t, nil)
	state, _ := startSocial(t, env.client(), map[string]any{"provider": "github", "callbackURL": "/d",
		"errorCallbackURL": "/oauth-error?source=expo"})
	// a different browser (no state cookie) -> state_security_mismatch carrying the errorURL
	loc := env.client().get("/callback/github?code=x&state=" + url.QueryEscape(state)).Header.Get("Location")
	if loc != "/oauth-error?source=expo&error=state_mismatch" {
		t.Fatalf("redirect = %q", loc)
	}
}

func TestPortOAuthStateEmptyRecoveredErrorURL(t *testing.T) {
	env := poStateEnv(t, nil)
	state, _ := startSocial(t, env.client(), map[string]any{"provider": "github", "callbackURL": "/d"})
	loc := env.client().get("/callback/github?code=x&state=" + url.QueryEscape(state)).Header.Get("Location")
	if want := env.server.URL + "/api/auth/error?error=state_mismatch"; loc != want {
		t.Fatalf("redirect = %q, want %q", loc, want)
	}
}
