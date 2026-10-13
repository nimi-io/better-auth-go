package oauthprovider

import (
	"strings"
	"testing"
)

// Port of packages/oauth-provider/src/revoke.test.ts.

// irExpectRevoked mirrors revocation.data === null && revocation.error === null.
func irExpectRevoked(t *testing.T, res *response) {
	t.Helper()
	if res.status != 200 {
		t.Fatalf("expected successful revocation, got %d %s", res.status, res.body)
	}
	if b := strings.TrimSpace(string(res.body)); b != "" && b != "null" {
		t.Fatalf("expected null body, got %s", b)
	}
}

func irExpectRevokeError(t *testing.T, res *response, status int, code string) {
	t.Helper()
	if res.status != status {
		t.Fatalf("expected %d, got %d %s", status, res.status, res.body)
	}
	if code != "" && res.json()["error"] != code {
		t.Fatalf("expected error %q, got %s", code, res.body)
	}
}

func TestIr_OAuthRevoke(t *testing.T) {
	env := irMainEnv(t)
	headers := env.signInWithTestUser()
	c := irClientFrom(t, env.adminCreateClient(headers, map[string]any{
		"redirect_uris":              []any{irRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
	}))
	if c.raw["user_id"] == nil || c.secret == "" {
		t.Fatalf("client: %v", c.raw)
	}
	if ru, _ := c.raw["redirect_uris"].([]any); len(ru) != 1 || ru[0] != irRedirectURI {
		t.Fatalf("redirect_uris: %v", c.raw["redirect_uris"])
	}
	getTokens := func(resource string) map[string]any {
		return irGetTokens(env, headers, c, nil, resource)
	}

	t.Run("should fail unauthenticated request", func(t *testing.T) {
		tokens := getTokens("")
		irExpectRevokeError(t, irRevoke(env, headers, nil, tokens["access_token"].(string), ""), 401, "")
	})

	t.Run("reports unsupported_token_type for a jwt access_token with token_type_hint access_token", func(t *testing.T) {
		tokens := getTokens(irValidResource)
		irExpectRevokeError(t, irRevoke(env, headers, &c, tokens["access_token"].(string), "access_token"), 400, "unsupported_token_type")
	})

	t.Run("should pass verification with token_type_hint access_token and sent opaque access_token", func(t *testing.T) {
		tokens := getTokens("")
		irExpectRevoked(t, irRevoke(env, headers, &c, tokens["access_token"].(string), "access_token"))
	})

	t.Run("should fail with token_type_hint access_token and sent refresh_token", func(t *testing.T) {
		tokens := getTokens("")
		irExpectRevokeError(t, irRevoke(env, headers, &c, tokens["refresh_token"].(string), "access_token"), 400, "")
	})

	t.Run("should pass verification with token_type_hint refresh_token and sent refresh_token", func(t *testing.T) {
		tokens := getTokens("")
		irExpectRevoked(t, irRevoke(env, headers, &c, tokens["refresh_token"].(string), "refresh_token"))
	})

	t.Run("should fail verification with token_type_hint refresh_token and sent access_token", func(t *testing.T) {
		tokens := getTokens("")
		irExpectRevokeError(t, irRevoke(env, headers, &c, tokens["access_token"].(string), "refresh_token"), 400, "")
	})

	t.Run("reports unsupported_token_type for a jwt access_token without token_type_hint", func(t *testing.T) {
		tokens := getTokens(irValidResource)
		irExpectRevokeError(t, irRevoke(env, headers, &c, tokens["access_token"].(string), ""), 400, "unsupported_token_type")
	})

	t.Run("should pass verification without token_type_hint and sent opaque access_token", func(t *testing.T) {
		tokens := getTokens("")
		irExpectRevoked(t, irRevoke(env, headers, &c, tokens["access_token"].(string), ""))
	})

	t.Run("should pass verification without token_type_hint and sent refresh_token", func(t *testing.T) {
		tokens := getTokens("")
		irExpectRevoked(t, irRevoke(env, headers, &c, tokens["refresh_token"].(string), ""))
	})
}

func TestIr_OAuthRevokeConfig(t *testing.T) {
	t.Run("should pass with the correct opaqueAccessTokenPrefix", func(t *testing.T) {
		prefix := "hello_"
		testScopes := []string{"read:profile"}
		env, h, c := irConfigEnv(t, func(o *Options) {
			o.Prefix = &PrefixOptions{OpaqueAccessToken: prefix}
			o.Scopes = testScopes
		})
		tok := irClientCredentials(env, h, c, strings.Join(testScopes, " "))
		at, _ := tok.json()["access_token"].(string)
		if !strings.HasPrefix(at, prefix) {
			t.Fatalf("access token %q lacks prefix (%d %s)", at, tok.status, tok.body)
		}
		irExpectRevoked(t, irRevoke(env, h, &c, at, "access_token"))
	})

	t.Run("should pass with the correct refreshTokenPrefix", func(t *testing.T) {
		rtPrefix := "hello_rt_"
		testScopes := []string{"openid", "offline_access"}
		env, h, c := irConfigEnv(t, func(o *Options) {
			o.Prefix = &PrefixOptions{RefreshToken: rtPrefix}
			o.Scopes = testScopes
		})
		tokens := irCodeTokens(env, h, c, testScopes, "")
		rt, ok := tokens["refresh_token"].(string)
		if !ok {
			t.Fatalf("no refresh_token: %v", tokens)
		}
		if !strings.HasPrefix(rt, rtPrefix) {
			t.Fatalf("refresh token %q lacks prefix", rt)
		}
		irExpectRevoked(t, irRevoke(env, h, &c, rt, "refresh_token"))
	})
}
