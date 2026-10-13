package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/mcp"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// MCP profile (mirrors e2e/servers/profiles/mcp.mjs): the MCP authorization server with
// resource <base>/mcp, dynamic registration, and a protected JSON-RPC endpoint at /mcp
// (requireMcpAuth requiring mcp:read; tools/call steps up to mcp:write). The RFC 9728
// protected resource metadata lives outside /api/auth, so its paths are forwarded to the
// auth handler.

func mcpResource(baseURL string) string { return baseURL + "/mcp" }

func init() {
	profiles["mcp"] = func(cfg *betterauth.Config, env profileEnv) {
		o := mcp.Options{Resource: mcpResource(env.BaseURL)}
		o.LoginPage = "/login"
		o.ConsentPage = "/consent"
		o.AllowDynamicClientRegistration = true
		o.AllowUnauthenticatedClientRegistration = true
		o.Scopes = []string{"openid", "profile", "email", "offline_access", "mcp:read", "mcp:write"}
		cfg.Plugins = append(cfg.Plugins, jwt.New(), mcp.MustNew(o))
	}
	forward := func(w http.ResponseWriter, r *http.Request, auth *betterauth.Auth) {
		if os.Getenv("PROFILE") != "mcp" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("null"))
			return
		}
		auth.Handler().ServeHTTP(w, r)
	}
	testHandlers["/.well-known/oauth-protected-resource"] = forward
	testHandlers["/.well-known/oauth-protected-resource/mcp"] = forward
	testHandlers["/mcp"] = func(w http.ResponseWriter, r *http.Request, auth *betterauth.Auth) {
		if os.Getenv("PROFILE") != "mcp" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("null"))
			return
		}
		baseURL := "http://" + r.Host
		h, err := mcp.RequireMcpAuth(auth, mcpToolHandler, &mcp.RequireMcpAuthOptions{
			Resource:       mcpResource(baseURL),
			RequiredScopes: []string{"mcp:read"},
		})
		if err != nil {
			log.Print(err)
			w.WriteHeader(500)
			return
		}
		mcp.HandlerFunc(h, func(w http.ResponseWriter, _ *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":` + jsonString(err.Error()) + `}`))
		})(w, r)
	}
}

// mcpToolHandler is a minimal JSON-RPC endpoint: it echoes the verified claims; tools/call
// requires mcp:write and raises an insufficient-scope challenge otherwise.
func mcpToolHandler(r *http.Request, claims *jsonx.Object) (*betterauth.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	var body struct {
		ID     any    `json:"id"`
		Method string `json:"method"`
	}
	_ = json.Unmarshal(raw, &body)
	scope, _ := claims.Get("scope")
	s, _ := scope.(string)
	if body.Method == "tools/call" && !strings.Contains(" "+s+" ", " mcp:write ") {
		return nil, oauthcore.CreateInsufficientScopeError([]string{"mcp:write"}, "tool requires mcp:write")
	}
	result := jsonx.O("method", body.Method)
	for _, k := range []string{"sub", "client_id", "scope", "aud"} {
		if v, ok := claims.Get(k); ok {
			result.Set(k, v)
		}
	}
	out, _ := jsonx.Marshal(jsonx.O("jsonrpc", "2.0", "id", body.ID, "result", result))
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &betterauth.Response{Status: 200, Header: h, Body: out}, nil
}
