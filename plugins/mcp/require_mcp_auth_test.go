package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/mcp/src/require-mcp-auth.test.ts.

// These tests mock verifyAccessTokenRequest, so the replay store is never exercised; the
// stub only needs to satisfy the context type.
type reservationStub struct{}

func (reservationStub) ReserveVerificationValue(context.Context, string, string, time.Time) (bool, error) {
	return true, nil
}

func authWith(resolvedBaseURL string) authState {
	return func() (string, oauthcore.DPoPReplayReservations) { return resolvedBaseURL, reservationStub{} }
}

func mustRequire(t *testing.T, state authState, h RequestHandler, o *RequireMcpAuthOptions) ProtectedHandler {
	t.Helper()
	p, err := requireMcpAuth(state, h, o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRequireMcpAuth(t *testing.T) {
	const resolved = "https://app.example.com/api/auth"
	unauthorized := func() error {
		return betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "missing authorization header"))
	}

	t.Run("verifies against the provider's resolved base URL, not the bare origin", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-1")
		var verifiedSub any
		res, err := mustRequire(t, authWith(resolved), func(_ *http.Request, c *jsonx.Object) (*betterauth.Response, error) {
			verifiedSub, _ = c.Get("sub")
			return &betterauth.Response{Status: 200, Body: []byte(`{"ok":true}`)}, nil
		}, nil)(bearerRequest("https://app.example.com/mcp"))
		if err != nil || res.Status != 200 || verifiedSub != "user-1" {
			t.Fatal(err, res, verifiedSub)
		}
		c := m.calls[0]
		if c.in.AuthorizationHeader != "Bearer access-token" || c.in.DPoPProofJWT != "" || c.in.Method != "GET" || c.in.URL != "https://app.example.com/mcp" {
			t.Fatalf("%+v", c.in)
		}
		if strings.Join(c.opts.VerifyOptions.Issuer, ",") != resolved || strings.Join(c.opts.VerifyOptions.Audience, ",") != resolved ||
			c.opts.JWKSURL != resolved+"/jwks" {
			t.Fatalf("%+v", c.opts)
		}
		if c.opts.DPoP == nil || c.opts.DPoP.ReplayStore == nil {
			t.Fatal("expected the database-backed replay store")
		}
	})

	t.Run("challenges with the served resource_metadata URL when no token is present", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = unauthorized()
		res, err := mustRequire(t, authWith(resolved), unreachable, nil)(httptest.NewRequest("GET", "https://app.example.com/mcp", nil))
		if err != nil || res.Status != 401 {
			t.Fatal(err, res)
		}
		if got := res.Header.Get("WWW-Authenticate"); got != `Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/api/auth"` {
			t.Fatal(got)
		}
		if string(res.Body) != `{"jsonrpc":"2.0","error":{"code":-32000,"message":"missing authorization header"},"id":null}` {
			t.Fatal(string(res.Body))
		}
		if res.Header.Get("Content-Type") != "application/json" {
			t.Fatal(res.Header)
		}
	})

	dpopRequired := func() error {
		return betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "DPoP proof header is required",
			"error", "invalid_dpop_proof", "error_description", "DPoP proof header is required"))
	}
	dpopRequest := func() *http.Request {
		r := httptest.NewRequest("GET", "https://app.example.com/mcp", nil)
		r.Header.Set("Authorization", "DPoP access-token")
		return r
	}

	t.Run("answers a DPoP-bound failure with an RFC 9449 DPoP challenge", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = dpopRequired()
		res, err := mustRequire(t, authWith(resolved), unreachable, nil)(dpopRequest())
		if err != nil || res.Status != 401 || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "DPoP ") {
			t.Fatal(err, res)
		}
	})

	t.Run("advertises the configured DPoP signing algorithms in the challenge", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = dpopRequired()
		res, err := mustRequire(t, authWith(resolved), unreachable, &RequireMcpAuthOptions{DPoP: &DPoPOptions{SigningAlgorithms: []string{"ES256"}}})(dpopRequest())
		if err != nil || res.Status != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), `algs="ES256"`) {
			t.Fatal(err, res)
		}
	})

	t.Run("verifies against an explicit resource override", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-2")
		_, err := mustRequire(t, authWith(resolved), unreachable, &RequireMcpAuthOptions{Resource: "https://mcp.example.com/mcp"})(bearerRequest("https://mcp.example.com/mcp"))
		if err != nil {
			t.Fatal(err)
		}
		c := m.calls[0]
		if c.in.AuthorizationHeader != "Bearer access-token" || strings.Join(c.opts.VerifyOptions.Audience, ",") != "https://mcp.example.com/mcp" {
			t.Fatalf("%+v", c)
		}
	})

	t.Run("advertises a scope hint in the challenge when configured", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = unauthorized()
		res, _ := mustRequire(t, authWith(resolved), unreachable, &RequireMcpAuthOptions{ChallengeScopes: []string{"openid", "profile"}})(httptest.NewRequest("GET", "https://app.example.com/mcp", nil))
		if res.Status != 401 || res.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/api/auth", scope="openid profile"` {
			t.Fatal(res.Status, res.Header.Get("WWW-Authenticate"))
		}
	})

	t.Run("enforces required scopes against the token's scope claim", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-3", "scope", "mcp:read mcp:write")
		res, err := mustRequire(t, authWith(resolved), func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return &betterauth.Response{Status: 200}, nil
		}, &RequireMcpAuthOptions{RequiredScopes: []string{"mcp:read"}})(bearerRequest("https://app.example.com/mcp"))
		if err != nil || res.Status != 200 {
			t.Fatal(err, res)
		}
		c := m.calls[0]
		if c.in.AuthorizationHeader != "Bearer access-token" || strings.Join(c.opts.RequiredScopes, ",") != "mcp:read" {
			t.Fatalf("%+v", c)
		}
	})

	t.Run("answers a scope failure with a 403 insufficient_scope challenge", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = oauthcore.CreateInsufficientScopeError([]string{"mcp:write"}, "")
		res, _ := mustRequire(t, authWith(resolved), unreachable, &RequireMcpAuthOptions{RequiredScopes: []string{"mcp:write"}})(bearerRequest("https://app.example.com/mcp"))
		if res.Status != 403 || res.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="mcp:write", resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/api/auth", error_description="access token is missing required scope: mcp:write"` {
			t.Fatal(res.Status, res.Header.Get("WWW-Authenticate"))
		}
	})

	t.Run("lets a handler challenge for the scopes its tool needs", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-4", "scope", "mcp:read")
		res, err := mustRequire(t, authWith(resolved), func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, oauthcore.CreateInsufficientScopeError([]string{"mcp:admin"}, "tool requires mcp:admin")
		}, &RequireMcpAuthOptions{ChallengeScopes: []string{"mcp:read"}})(bearerRequest("https://app.example.com/mcp"))
		if err != nil || res.Status != 403 || res.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="mcp:admin", resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/api/auth", error_description="tool requires mcp:admin"` {
			t.Fatal(err, res)
		}
	})

	t.Run("propagates a handler-thrown permission denial unchanged", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-5", "scope", "mcp:read")
		denial := betterauth.NewAPIError("FORBIDDEN", jsonx.O("message", "user is not a member of this organization"))
		_, err := mustRequire(t, authWith(resolved), func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, denial
		}, &RequireMcpAuthOptions{RequiredScopes: []string{"mcp:read"}})(bearerRequest("https://app.example.com/mcp"))
		if err != denial {
			t.Fatal(err)
		}
	})

	t.Run("propagates a handler error with its type and stack intact", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-6")
		failure := errors.New("database connection lost")
		_, err := mustRequire(t, authWith(resolved), func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, failure
		}, nil)(bearerRequest("https://app.example.com/mcp"))
		if err != failure {
			t.Fatal(err)
		}
	})

	t.Run("propagates a primitive handler failure unchanged", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-7")
		primitive := errors.New("primitive failure")
		_, err := mustRequire(t, authWith(resolved), func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, primitive
		}, nil)(bearerRequest("https://app.example.com/mcp"))
		if err != primitive {
			t.Fatal(err)
		}
	})

	t.Run("rejects an opaque resource at wrapper construction", func(t *testing.T) {
		_, err := requireMcpAuth(authWith(resolved), unreachable, &RequireMcpAuthOptions{Resource: "urn:example:mcp"})
		if err == nil || !strings.Contains(err.Error(), "MCP resource") {
			t.Fatal(err)
		}
	})

	t.Run("rejects unsafe configured challenge scopes instead of serializing them", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = unauthorized()
		_, err := mustRequire(t, authWith(resolved), unreachable, &RequireMcpAuthOptions{ChallengeScopes: []string{"mcp:read\r\nX-Test: injected"}})(httptest.NewRequest("GET", "https://app.example.com/mcp", nil))
		if err == nil || !strings.Contains(err.Error(), "invalid challenge scope") {
			t.Fatal(err)
		}
	})

	t.Run("derives the challenge scope hint from enforced scopes when no hint is set", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = unauthorized()
		res, _ := mustRequire(t, authWith(resolved), unreachable, &RequireMcpAuthOptions{RequiredScopes: []string{"mcp:read", "mcp:write"}})(httptest.NewRequest("GET", "https://app.example.com/mcp", nil))
		if res.Status != 401 || res.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/api/auth", scope="mcp:read mcp:write"` {
			t.Fatal(res.Status, res.Header.Get("WWW-Authenticate"))
		}
	})

	t.Run("rejects a resource query at wrapper construction", func(t *testing.T) {
		_, err := requireMcpAuth(authWith(resolved), unreachable, &RequireMcpAuthOptions{Resource: "https://mcp.example.com/mcp?tenant=a"})
		if err == nil || !strings.Contains(err.Error(), "MCP resource") {
			t.Fatal(err)
		}
	})

	// Go-only: the dynamic base URL guard.
	t.Run("requires a resolvable base URL", func(t *testing.T) {
		installMockVerify(t)
		_, err := mustRequire(t, authWith(""), unreachable, nil)(bearerRequest("https://app.example.com/mcp"))
		if err == nil || !strings.Contains(err.Error(), "requires a resolvable base URL") {
			t.Fatal(err)
		}
	})
}
