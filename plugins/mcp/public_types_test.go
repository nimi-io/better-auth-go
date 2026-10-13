package mcp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/mcp/src/public-types.test.ts (the type-level assertions become
// compile-time checks).

func TestPublicMcpSurface(t *testing.T) {
	t.Run("exports the protected-request vocabulary from the package root", func(t *testing.T) {
		var _ func(ProtectedRequestHandlerOptions, RequestHandler) (ProtectedHandler, error) = CreateMcpProtectedRequestHandler
		var _ func(*betterauth.Auth, RequestHandler, *RequireMcpAuthOptions) (ProtectedHandler, error) = RequireMcpAuth
		var o ProtectedRequestHandlerOptions
		var _ string = o.Issuer
		var _ string = o.Audience
		var _ oauthcore.VerifyOptions = o.JWTVerifyOptions
		var _ []string = o.ChallengeScopes
		var r RequireMcpAuthOptions
		var _ []string = r.RequiredScopes
	})

	t.Run("publishes no Better Auth MCP client or adapter subpath", func(t *testing.T) {
		for _, dir := range []string{"client", "client/adapters"} {
			if _, err := os.Stat(dir); err == nil {
				t.Fatalf("unexpected subpackage %s", dir)
			}
		}
	})
}

// Go-only: the net/http middleware variants.
func TestMiddleware(t *testing.T) {
	m := installMockVerify(t)
	mw, err := Middleware(ProtectedRequestHandlerOptions{Issuer: "https://app.example.com", Audience: "https://app.example.com/mcp",
		RequiredScopes: []string{"mcp:read"}})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("admin") == "1" && Challenge(w, r, oauthcore.CreateInsufficientScopeError([]string{"mcp:admin"}, "")) {
			return
		}
		sub, _ := ClaimsFromContext(r.Context()).Get("sub")
		_, _ = w.Write([]byte(sub.(string)))
	}))

	m.err = betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "missing authorization header"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "https://app.example.com/mcp", nil))
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != `Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp:read"` {
		t.Fatal(rec.Code, rec.Header())
	}

	m.err, m.claims = nil, jsonx.O("sub", "user-1", "scope", "mcp:read")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bearerRequest("https://app.example.com/mcp"))
	if rec.Code != 200 || rec.Body.String() != "user-1" {
		t.Fatal(rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bearerRequest("https://app.example.com/mcp?admin=1"))
	if rec.Code != 403 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `scope="mcp:admin"`) {
		t.Fatal(rec.Code, rec.Header())
	}

	if _, err := Middleware(ProtectedRequestHandlerOptions{Audience: "urn:x"}); err == nil {
		t.Fatal("expected invalid resource error")
	}

	// HandlerFunc adapts the request-handler API.
	ph, _ := CreateMcpProtectedRequestHandler(ProtectedRequestHandlerOptions{Issuer: "https://app.example.com", Audience: "https://app.example.com/mcp"},
		func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			return &betterauth.Response{Status: 201, Body: []byte("ok")}, nil
		})
	rec = httptest.NewRecorder()
	HandlerFunc(ph, nil)(rec, bearerRequest("https://app.example.com/mcp"))
	if rec.Code != 201 || rec.Body.String() != "ok" {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

// Go-only: RequireMcpAuthMiddleware reads the auth server's base URL like RequireMcpAuth.
func TestRequireMcpAuthMiddleware(t *testing.T) {
	env, _ := mcpEnv(t, pAuthServerBaseURL, Options{Resource: pBaseURL})
	mw, err := RequireMcpAuthMiddleware(env.auth, &RequireMcpAuthOptions{RequiredScopes: []string{"mcp:read"}})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Fatal("handler must not run") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", pAuthServerBaseURL+"/mcp", nil))
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != `Bearer resource_metadata="`+pAuthServerBaseURL+`/.well-known/oauth-protected-resource/api/auth", scope="mcp:read"` {
		t.Fatal(rec.Code, rec.Header())
	}
	if _, err := RequireMcpAuthMiddleware(env.auth, &RequireMcpAuthOptions{Resource: "urn:x"}); err == nil {
		t.Fatal("expected invalid resource error")
	}
}
