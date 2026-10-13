package oauthprovider

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/genericoauth"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of packages/oauth-provider/src/oauth.test.ts.

type oaNullStorage struct{}

func (oaNullStorage) Get(context.Context, string) (string, bool, error) { return "", false, nil }
func (oaNullStorage) Set(context.Context, string, string, time.Duration) error {
	return nil
}
func (oaNullStorage) Delete(context.Context, string) error { return nil }
func (oaNullStorage) GetAndDelete(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (oaNullStorage) Increment(context.Context, string, time.Duration) (int64, error) {
	return 1, nil
}

func oaExpectInitErr(t *testing.T, env *testEnv, msg string) {
	t.Helper()
	if env.initErr == nil || !strings.Contains(env.initErr.Error(), msg) {
		t.Fatalf("expected init error containing %q, got %v", msg, env.initErr)
	}
}

func TestOa_OAuthInit(t *testing.T) {
	t.Run("should fail without the jwt plugin", func(t *testing.T) {
		env := newEnv(t, Options{}, envOptions{noJwt: true, expectInitError: true})
		oaExpectInitErr(t, env, "jwt_config")
	})
	t.Run("should pass without the jwt plugin and disableJwtPlugin set", func(t *testing.T) {
		newEnv(t, Options{DisableJwtPlugin: true}, envOptions{noJwt: true})
	})
	t.Run("should pass with correct plugins", func(t *testing.T) {
		newEnv(t, Options{})
	})
	const ssMsg = "OAuth Provider requires `session.storeSessionInDatabase: true` when using secondaryStorage"
	t.Run("should fail with secondaryStorage when session config is omitted", func(t *testing.T) {
		env := newEnv(t, Options{}, envOptions{expectInitError: true, mutate: func(c *betterauth.Config) {
			c.SecondaryStorage = oaNullStorage{}
		}})
		oaExpectInitErr(t, env, ssMsg)
	})
	t.Run("should fail with secondaryStorage when storeSessionInDatabase is false", func(t *testing.T) {
		env := newEnv(t, Options{}, envOptions{expectInitError: true, mutate: func(c *betterauth.Config) {
			c.SecondaryStorage = oaNullStorage{}
			c.Session = &betterauth.SessionConfig{StoreSessionInDatabase: false}
		}})
		oaExpectInitErr(t, env, ssMsg)
	})
	t.Run("should pass with secondaryStorage when storeSessionInDatabase is true", func(t *testing.T) {
		newEnv(t, Options{}, envOptions{mutate: func(c *betterauth.Config) {
			c.SecondaryStorage = oaNullStorage{}
			c.Session = &betterauth.SessionConfig{StoreSessionInDatabase: true}
		}})
	})
	t.Run("should pass with dynamic baseURL config when ctx.baseURL is unresolved during init", func(t *testing.T) {
		newEnv(t, Options{}, envOptions{disableTestUser: true, mutate: func(c *betterauth.Config) {
			c.BaseURL = ""
			c.DynamicBaseURL = &betterauth.DynamicBaseURL{AllowedHosts: []string{"localhost:3000"}, Protocol: "http"}
		}})
	})
	t.Run("should still fail for an invalid configured jwt issuer", func(t *testing.T) {
		env := newEnv(t, Options{}, envOptions{expectInitError: true, jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: "not-a-valid-url"}}})
		oaExpectInitErr(t, env, "Invalid URL")
	})
}

// oaSignInEmail is authClient.signIn.email with window.location.search = search.
func oaSignInEmail(t *testing.T, env *testEnv, search string, jar *oaJar, extra http.Header) *response {
	t.Helper()
	body := oaWithQuery(map[string]any{"email": testUserEmail, "password": testUserPassword}, search)
	return oaFetch(t, env, "POST", "/sign-in/email", body, jar, extra)
}

func TestOa_OAuth(t *testing.T) {
	env := newEnv(t, Options{})
	oaRouteOAuth2(t, env)
	oaServeDiscovery(env)
	admin := env.signInWithTestUser()
	oauthClient := env.adminCreateClient(admin, map[string]any{
		"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
		"redirect_uris":              []any{oaRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
	})
	clientID, secret := oaStr(oauthClient, "client_id"), oaStr(oauthClient, "client_secret")
	if clientID == "" || secret == "" || oauthClient["user_id"] == nil {
		t.Fatalf("client: %v", oauthClient)
	}
	if ru, _ := oauthClient["redirect_uris"].([]any); len(ru) != 1 || ru[0] != oaRedirectURI {
		t.Fatalf("redirect_uris: %v", oauthClient["redirect_uris"])
	}
	encRedirect := "redirect_uri=" + url.QueryEscape(oaRedirectURI)

	// startLogin runs sign-in/social at the RP and authorize at the AS (no session),
	// returning the RP jar and the login redirect.
	startLogin := func(t *testing.T, rp *oaRP, cid string) (*oaJar, string) {
		t.Helper()
		rpJar := oaNewJar()
		authURL := rp.signInSocial(t, env, rpJar)
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+cid)
		loc, _ := oaAuthorize(t, env, authURL, nil)
		oaContains(t, loc, "/login")
		return rpJar, loc
	}

	t.Run("should sign in using generic oauth plugin", func(t *testing.T) {
		rp := oaNewRP(t, env, clientID, secret, genericoauth.Config{})
		rpJar, login := startLogin(t, rp, clientID)
		oaContains(t, login, "client_id="+clientID)
		oaContains(t, login, encRedirect)
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, nil)
		redirect, signInURL := oaRedirectResult(t, res)
		if !redirect {
			t.Fatalf("redirect: %s", res.body)
		}
		oaContains(t, signInURL, oaRPBase)
		cb := oaFetch(t, env, "GET", signInURL, nil, rpJar, nil)
		oaContains(t, cb.location(), "/success")
	})

	t.Run("should return a JSON redirect after email sign-in in a fetch-based oauth flow", func(t *testing.T) {
		rp := oaNewRP(t, env, clientID, secret, genericoauth.Config{})
		_, login := startLogin(t, rp, clientID)
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, http.Header{"Sec-Fetch-Mode": {"cors"}})
		if res.location() != "" {
			t.Fatalf("unexpected Location %q", res.location())
		}
		redirect, u := oaRedirectResult(t, res)
		if !redirect {
			t.Fatalf("redirect: %s", res.body)
		}
		oaContains(t, u, oaRPBase+"/api/auth/callback/"+oaProviderID)
		oaNotContains(t, u, testBaseURL+"/login")
	})

	t.Run("should return JSON redirect after sign-in without Sec-Fetch-Mode header", func(t *testing.T) {
		rp := oaNewRP(t, env, clientID, secret, genericoauth.Config{})
		_, login := startLogin(t, rp, clientID)
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, nil)
		if res.location() != "" {
			t.Fatalf("unexpected Location %q", res.location())
		}
		redirect, u := oaRedirectResult(t, res)
		if !redirect {
			t.Fatalf("redirect: %s", res.body)
		}
		oaContains(t, u, oaRPBase+"/api/auth/callback/"+oaProviderID)
	})

	t.Run("should still return 302 redirect for navigate-mode requests (form submissions)", func(t *testing.T) {
		rp := oaNewRP(t, env, clientID, secret, genericoauth.Config{})
		_, login := startLogin(t, rp, clientID)
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, http.Header{"Sec-Fetch-Mode": {"navigate"}})
		oaContains(t, res.location(), oaRPBase)
	})

	t.Run("should still return 302 redirect for html accept requests without Sec-Fetch-Mode", func(t *testing.T) {
		rp := oaNewRP(t, env, clientID, secret, genericoauth.Config{})
		_, login := startLogin(t, rp, clientID)
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, http.Header{"Accept": {"text/html,application/xhtml+xml"}})
		oaContains(t, res.location(), oaRPBase)
	})

	newTempClient := func(t *testing.T) map[string]any {
		t.Helper()
		adminHeaders := env.signInWithTestUser()
		c := env.adminCreateClient(adminHeaders, map[string]any{
			"grant_types":      []any{"authorization_code", "client_credentials", "refresh_token"},
			"redirect_uris":    []any{oaRedirectURI},
			"application_type": "native",
			"skip_consent":     true,
		})
		if oaStr(c, "client_id") == "" {
			t.Fatalf("temp client: %v", c)
		}
		return c
	}

	t.Run("should return JSON error redirect when client is deleted during OAuth flow", func(t *testing.T) {
		adminHeaders := env.signInWithTestUser()
		temp := newTempClient(t)
		rp := oaNewRP(t, env, oaStr(temp, "client_id"), oaStr(temp, "client_secret"), genericoauth.Config{})
		_, login := startLogin(t, rp, oaStr(temp, "client_id"))
		env.mustCall("deleteOAuthClient", betterauth.CallInput{Headers: adminHeaders, Body: map[string]any{"client_id": oaStr(temp, "client_id")}})
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, nil)
		redirect, u := oaRedirectResult(t, res)
		if !redirect {
			t.Fatalf("redirect: %s", res.body)
		}
		oaContains(t, u, "error=invalid_client")
	})

	t.Run("should return JSON error redirect when client is disabled during OAuth flow", func(t *testing.T) {
		temp := newTempClient(t)
		rp := oaNewRP(t, env, oaStr(temp, "client_id"), oaStr(temp, "client_secret"), genericoauth.Config{})
		_, login := startLogin(t, rp, oaStr(temp, "client_id"))
		env.update("oauthClient", map[string]any{"disabled": true}, eq("clientId", oaStr(temp, "client_id")))
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, nil)
		redirect, u := oaRedirectResult(t, res)
		if !redirect {
			t.Fatalf("redirect: %s", res.body)
		}
		oaContains(t, u, "error=client_disabled")
	})

	t.Run("should sign in using generic oauth discovery", func(t *testing.T) {
		rp := oaNewRP(t, env, clientID, secret, genericoauth.Config{DiscoveryURL: testBaseURL + "/.well-known/openid-configuration"})
		rpJar := oaNewJar()
		authURL := rp.signInSocial(t, env, rpJar)
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		login, _ := oaAuthorize(t, env, authURL, rpJar)
		oaContains(t, login, "/login")
		oaContains(t, login, "client_id="+clientID)
		oaContains(t, login, encRedirect)
		res := oaSignInEmail(t, env, oaSearch(t, login), nil, nil)
		redirect, signInURL := oaRedirectResult(t, res)
		if !redirect {
			t.Fatalf("redirect: %s", res.body)
		}
		oaContains(t, signInURL, oaRPBase)
		cb := oaFetch(t, env, "GET", signInURL, nil, rpJar, nil)
		oaContains(t, cb.location(), "/success")
	})
}
