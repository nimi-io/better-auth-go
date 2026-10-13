package oauthprovider

import (
	"net/url"
	"testing"
)

// Port of packages/oauth-provider/src/no-store.test.ts.

func irExpectNoStore(t *testing.T, res *response) {
	t.Helper()
	if v := res.header.Get("Cache-Control"); v != "no-store" {
		t.Fatalf("Cache-Control = %q (%d %s)", v, res.status, res.body)
	}
	if v := res.header.Get("Pragma"); v != "no-cache" {
		t.Fatalf("Pragma = %q (%d %s)", v, res.status, res.body)
	}
}

func TestIr_OAuthCredentialResponsesCarryNoStore(t *testing.T) {
	env := newEnv(t, Options{
		Scopes: []string{"m2m:read"},
		ClientPrivileges: func(c PrivilegeContext) (bool, error) {
			return c.Action == "create" || c.Action == "configure-client-credentials-scopes", nil
		},
		AllowDynamicClientRegistration: true,
	})
	headers := env.signInWithTestUser()
	c := irClientFrom(t, env.adminCreateClient(headers, map[string]any{
		"grant_types":                []any{"client_credentials"},
		"redirect_uris":              []any{irRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
		"client_credentials_scopes":  []any{"m2m:read"},
	}))
	if c.secret == "" {
		t.Fatalf("client_secret missing: %v", c.raw)
	}
	// clientCredentialsTokenRequest without scopes: grant_type + client_secret_post credentials.
	ccForm := func(id, secret string) url.Values {
		return url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}
	}

	t.Run("sets no-store on a successful token response", func(t *testing.T) {
		res := irPostForm(env, headers, "/oauth2/token", ccForm(c.id, c.secret))
		if res.json()["access_token"] == nil {
			t.Fatalf("token: %d %s", res.status, res.body)
		}
		irExpectNoStore(t, res)
	})

	t.Run("sets no-store on a token error response", func(t *testing.T) {
		res := irPostForm(env, headers, "/oauth2/token", ccForm("client-that-does-not-exist", "wrong"))
		if res.status < 400 {
			t.Fatalf("expected error, got %d %s", res.status, res.body)
		}
		irExpectNoStore(t, res)
	})

	t.Run("sets 201 and no-store on a registration response", func(t *testing.T) {
		res := env.do("POST", "/oauth2/register", map[string]any{
			"redirect_uris":    []any{irRedirectURI},
			"application_type": "native",
		}, headers)
		if res.json()["client_id"] == nil {
			t.Fatalf("register: %d %s", res.status, res.body)
		}
		if res.status != 201 {
			t.Fatalf("expected 201, got %d", res.status)
		}
		irExpectNoStore(t, res)
	})

	t.Run("sets no-store on the introspection response", func(t *testing.T) {
		tok := irPostForm(env, headers, "/oauth2/token", ccForm(c.id, c.secret))
		at, _ := tok.json()["access_token"].(string)
		res := irIntrospect(env, headers, &c, at, "")
		irExpectNoStore(t, res)
	})
}
