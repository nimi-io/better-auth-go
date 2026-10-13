package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/mcp/src/handler.test.ts.

// mockVerify replaces verifyAccessTokenRequest (vi.mock of better-auth/oauth2).
type mockVerify struct {
	claims *jsonx.Object
	err    error
	calls  []mockVerifyCall
}

type mockVerifyCall struct {
	in   oauthcore.ResourceRequestInput
	opts oauthcore.VerifyAccessTokenRequestOptions
}

func installMockVerify(t *testing.T) *mockVerify {
	t.Helper()
	m := &mockVerify{}
	prev := verifyAccessTokenRequest
	verifyAccessTokenRequest = func(_ context.Context, in oauthcore.ResourceRequestInput, o oauthcore.VerifyAccessTokenRequestOptions) (*jsonx.Object, error) {
		m.calls = append(m.calls, mockVerifyCall{in, o})
		return m.claims, m.err
	}
	t.Cleanup(func() { verifyAccessTokenRequest = prev })
	return m
}

var protectedRequestOptions = ProtectedRequestHandlerOptions{
	Issuer:   "https://app.example.com",
	Audience: "https://app.example.com/mcp",
}

func bearerRequest(target string) *http.Request {
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("Authorization", "Bearer access-token")
	return r
}

func unreachable(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
	return &betterauth.Response{Status: 200, Body: []byte("unreachable")}, nil
}

func mustHandler(t *testing.T, o ProtectedRequestHandlerOptions, h RequestHandler) ProtectedHandler {
	t.Helper()
	p, err := CreateMcpProtectedRequestHandler(o, h)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCreateMcpProtectedRequestHandler(t *testing.T) {
	t.Run("answers a scope failure with a 403 insufficient_scope challenge", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = oauthcore.CreateInsufficientScopeError([]string{"mcp:write"}, "")
		o := protectedRequestOptions
		o.RequiredScopes = []string{"mcp:write"}
		res, err := mustHandler(t, o, unreachable)(bearerRequest("https://app.example.com/mcp"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != 403 {
			t.Fatal(res.Status)
		}
		if got := res.Header.Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", scope="mcp:write", resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/mcp", error_description="access token is missing required scope: mcp:write"` {
			t.Fatal(got)
		}
	})

	t.Run("forwards flat JWT verification and challenge options", func(t *testing.T) {
		m := installMockVerify(t)
		m.err = betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("error", "invalid_token", "message", "invalid access token"))
		o := protectedRequestOptions
		o.JWTVerifyOptions = oauthcore.VerifyOptions{Algorithms: []string{"ES256"}}
		o.ChallengeScopes = []string{"mcp:read"}
		res, err := mustHandler(t, o, unreachable)(bearerRequest("https://app.example.com/mcp"))
		if err != nil {
			t.Fatal(err)
		}
		if len(m.calls) != 1 {
			t.Fatal(len(m.calls))
		}
		vo := m.calls[0].opts.VerifyOptions
		if strings.Join(vo.Algorithms, ",") != "ES256" || strings.Join(vo.Issuer, ",") != protectedRequestOptions.Issuer ||
			strings.Join(vo.Audience, ",") != protectedRequestOptions.Audience {
			t.Fatalf("%+v", vo)
		}
		if got := res.Header.Get("WWW-Authenticate"); !strings.Contains(got, `scope="mcp:read"`) {
			t.Fatal(got)
		}
	})

	t.Run("propagates a handler error with its type and stack intact", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-1")
		failure := errors.New("database connection lost")
		_, err := mustHandler(t, protectedRequestOptions, func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, failure
		})(bearerRequest("https://app.example.com/mcp"))
		if err != failure {
			t.Fatal(err)
		}
	})

	t.Run("propagates a handler-thrown permission denial unchanged", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-2")
		denial := betterauth.NewAPIError("FORBIDDEN", jsonx.O("message", "user is not a member of this organization"))
		_, err := mustHandler(t, protectedRequestOptions, func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, denial
		})(bearerRequest("https://app.example.com/mcp"))
		if err != denial {
			t.Fatal(err)
		}
	})

	for _, status := range []string{"UNAUTHORIZED", "FORBIDDEN"} {
		t.Run("propagates a handler-thrown "+status+" API error unchanged", func(t *testing.T) {
			m := installMockVerify(t)
			m.claims = jsonx.O("sub", "user-3")
			denial := betterauth.NewAPIError(status, jsonx.O("message", "handler denial"))
			_, err := mustHandler(t, protectedRequestOptions, func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
				return nil, denial
			})(bearerRequest("https://app.example.com/mcp"))
			if err != denial {
				t.Fatal(err)
			}
		})
	}

	// "propagates a primitive handler failure unchanged": Go handlers return error values;
	// the closest analogue is a plain string error, which must come back unchanged.
	t.Run("propagates a primitive handler failure unchanged", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-4")
		primitive := errors.New("primitive failure")
		_, err := mustHandler(t, protectedRequestOptions, func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, primitive
		})(bearerRequest("https://app.example.com/mcp"))
		if err != primitive {
			t.Fatal(err)
		}
	})

	t.Run("turns a typed handler insufficient-scope error into a 403 challenge", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-5")
		res, err := mustHandler(t, protectedRequestOptions, func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, oauthcore.CreateInsufficientScopeError([]string{"mcp:admin"}, "")
		})(bearerRequest("https://app.example.com/mcp"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != 403 || !strings.Contains(res.Header.Get("WWW-Authenticate"), `scope="mcp:admin"`) {
			t.Fatal(res.Status, res.Header)
		}
	})

	t.Run("propagates an unbranded structural insufficient-scope error unchanged", func(t *testing.T) {
		m := installMockVerify(t)
		m.claims = jsonx.O("sub", "user-6")
		spoofed := betterauth.NewAPIError("FORBIDDEN", jsonx.O("error", "insufficient_scope", "scope", "mcp:admin"))
		_, err := mustHandler(t, protectedRequestOptions, func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return nil, spoofed
		})(bearerRequest("https://app.example.com/mcp"))
		if err != spoofed {
			t.Fatal(err)
		}
	})

	// The "audience array" case is TS-only: Audience is a Go string.
	for _, c := range []struct{ name, resource string }{
		{"opaque URI", "urn:example:mcp"},
		{"non-loopback HTTP URL", "http://api.example.com/mcp"},
		{"private HTTP hostname", "http://mcp.internal/mcp"},
		{"loopback-lookalike hostname", "http://127.example.com/mcp"},
		{"credentials", "https://user:pass@api.example.com/mcp"},
		{"fragment", "https://api.example.com/mcp#tools"},
		{"query", "https://api.example.com/mcp?tenant=a"},
	} {
		t.Run("rejects an invalid canonical MCP resource: "+c.name, func(t *testing.T) {
			o := protectedRequestOptions
			o.Audience = c.resource
			_, err := CreateMcpProtectedRequestHandler(o, unreachable)
			if err == nil || !strings.Contains(err.Error(), "MCP resource") {
				t.Fatal(err)
			}
		})
	}

	for _, resource := range []string{
		"https://api.example.com/mcp",
		"http://localhost:3000/mcp",
		"http://127.0.0.1:3000/mcp",
		"http://127.42.0.1/mcp",
		"http://[::1]:3000/mcp",
	} {
		t.Run("accepts a canonical MCP resource: "+resource, func(t *testing.T) {
			o := protectedRequestOptions
			o.Audience = resource
			if _, err := CreateMcpProtectedRequestHandler(o, unreachable); err != nil {
				t.Fatal(err)
			}
		})
	}
}
