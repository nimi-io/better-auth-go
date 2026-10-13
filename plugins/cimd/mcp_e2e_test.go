package cimd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/mcp"
)

// Port of packages/cimd/src/mcp-e2e.test.ts. The official MCP SDK v2 is TypeScript-only:
// its "official SDK AuthInfo mapping" cases test test-local helpers that are ported (and
// tested) in plugins/mcp/mcp_test.go, and the SDK flow is reproduced step by step here.

const (
	e2eAuthorizationServer = "https://auth.cimd.example.test"
	e2eClientID            = "https://client.example.test/oauth/client.json"
	e2eRedirectURI         = "https://callback.example.test/oauth/callback"
	e2eMCPResource         = "https://resource.cimd.example.test/mcp"
	e2eProtocolVersion     = "2026-07-28"
)

var e2eResourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

type cimdSdkFlow struct {
	t             *testing.T
	env           *testEnv
	headers       http.Header
	tokenRequests []url.Values
	verifier      string
	accessToken   string
	refreshToken  string
	authorizeURL  *url.URL
	consentURL    *url.URL
}

func (f *cimdSdkFlow) mcpRequest(method, token string) *betterauth.Response {
	f.t.Helper()
	r := httptest.NewRequest("POST", e2eMCPResource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`))
	r.Header.Set("Mcp-Method", method)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	required := []string{"mcp:base"}
	if method == "tools/call" {
		required = []string{"greeting"}
	}
	h, err := mcp.CreateMcpProtectedRequestHandler(mcp.ProtectedRequestHandlerOptions{Issuer: e2eAuthorizationServer,
		Audience: e2eMCPResource, JWKSURL: e2eAuthorizationServer + "/api/auth/jwks", RequiredScopes: required},
		func(_ *http.Request, claims *jsonx.Object) (*betterauth.Response, error) {
			if cid, _ := claims.Get("client_id"); cid != e2eClientID {
				f.t.Errorf("client_id claim %v", cid)
			}
			var result *jsonx.Object
			if method == "tools/call" {
				result = jsonx.O("content", []any{jsonx.O("type", "text", "text", "hello from CIMD")})
			} else {
				result = jsonx.O("protocolVersion", e2eProtocolVersion)
			}
			b, _ := jsonx.Marshal(jsonx.O("jsonrpc", "2.0", "id", 1, "result", result))
			return &betterauth.Response{Status: 200, Body: b}, nil
		})
	if err != nil {
		f.t.Fatal(err)
	}
	res, err := h(r)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func (f *cimdSdkFlow) token(form url.Values) map[string]any {
	f.t.Helper()
	f.tokenRequests = append(f.tokenRequests, form)
	res := f.env.do("POST", e2eAuthorizationServer+"/api/auth/oauth2/token", form, nil)
	if res.status != 200 {
		f.t.Fatalf("token: %d %s", res.status, res.body)
	}
	return res.json()
}

func (f *cimdSdkFlow) startAuthorization(endpoint, scope string) {
	f.verifier = "cimd-sdk-verifier-" + strings.Repeat("v", 40)
	q := url.Values{"response_type": {"code"}, "client_id": {e2eClientID}, "code_challenge": {pkceChallenge(f.verifier)},
		"code_challenge_method": {"S256"}, "redirect_uri": {e2eRedirectURI}, "state": {"cimd-sdk-v2-state"},
		"scope": {scope}, "resource": {e2eMCPResource}}
	// The MCP SDK requests prompt=consent whenever it asks for offline_access.
	if strings.Contains(scope, "offline_access") {
		q.Set("prompt", "consent")
	}
	f.authorizeURL, _ = url.Parse(endpoint + "?" + q.Encode())
}

func (f *cimdSdkFlow) completeAuthorization() *url.URL {
	f.t.Helper()
	location := f.env.do("GET", f.authorizeURL.String(), nil, f.headers).location()
	if !strings.Contains(location, "/consent") {
		f.t.Fatalf("authorization did not reach consent: %s", location)
	}
	f.consentURL, _ = url.Parse(location)
	if f.consentURL.Query().Get("client_id") != e2eClientID || f.consentURL.Query().Get("redirect_uri") != e2eRedirectURI {
		f.t.Fatal(location)
	}
	cb, _ := url.Parse(f.env.consent(f.headers, location))
	return cb
}

func (f *cimdSdkFlow) finishAuth(cb *url.URL) map[string]any {
	f.t.Helper()
	tokens := f.token(url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"code_verifier": {f.verifier}, "redirect_uri": {e2eRedirectURI}, "client_id": {e2eClientID}, "resource": {e2eMCPResource}})
	f.accessToken, _ = tokens["access_token"].(string)
	f.refreshToken, _ = tokens["refresh_token"].(string)
	return tokens
}

func TestCimdFirstMcpAuthorizationWithOfficialSdkV2(t *testing.T) {
	var mu sync.Mutex
	metadataFetchCount := 0
	var conditional []string
	fetch := func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		metadataFetchCount++
		if metadataFetchCount > 1 {
			conditional = append(conditional, r.Header.Get("If-None-Match"))
			return emptyResponse(304, "Cache-Control", "no-cache"), nil
		}
		return jsonResponse(200, map[string]any{"client_id": e2eClientID, "client_name": "CIMD SDK v2 client",
			"redirect_uris": []any{e2eRedirectURI}, "application_type": "native", "token_endpoint_auth_method": "none",
			"grant_types": []any{"authorization_code", "refresh_token"}, "response_types": []any{"code"}},
			"Cache-Control", "no-cache", "Etag", `"client-metadata-v1"`), nil
	}
	fetchCount := func() int { mu.Lock(); defer mu.Unlock(); return metadataFetchCount }
	mo := mcp.Options{Resource: e2eMCPResource}
	mo.LoginPage, mo.ConsentPage = "/login", "/consent"
	mo.EnforcePerClientResources = betterauth.Bool(true)
	mo.Scopes = []string{"openid", "offline_access", "mcp:base", "greeting"}
	mp, err := mcp.New(mo)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := New(Options{FetchClientMetadataResource: fetch, MetadataFetchPolicy: &MetadataFetchPolicy{MinimumFetchInterval: 0},
		MetadataProfile: MetadataProfileMCP20260728})
	if err != nil {
		t.Fatal(err)
	}
	env := newEnv(t, envOptions{baseURL: e2eAuthorizationServer, plugins: []*betterauth.Plugin{
		jwt.New(jwt.Options{JWT: &jwt.JWTOptions{Issuer: e2eAuthorizationServer}}), mp, cp},
		mutate: func(c *betterauth.Config) {
			c.Advanced = &betterauth.AdvancedConfig{UseSecureCookies: betterauth.Bool(false)}
		}})
	f := &cimdSdkFlow{t: t, env: env, headers: env.signInWithTestUser()}
	dcrRequests := func() int { return 0 } // the flow below never calls /oauth2/register

	t.Run("discovers, caches, binds, steps up, invokes, and refreshes without DCR", func(t *testing.T) {
		discovery := env.mustCall("getOAuthServerConfig", betterauth.CallInput{})
		if _, ok := discovery["registration_endpoint"]; ok || discovery["client_id_metadata_document_supported"] != true {
			t.Fatal(discovery)
		}
		prm := env.do("GET", "https://resource.cimd.example.test/.well-known/oauth-protected-resource/mcp", nil, nil).json()
		if !reflect.DeepEqual(prm["scopes_supported"], []any{"mcp:base", "greeting"}) {
			t.Fatal(prm)
		}

		// connect -> 401 -> discovery
		res := f.mcpRequest("initialize", "")
		m := e2eResourceMetadataRe.FindStringSubmatch(res.Header.Get("WWW-Authenticate"))
		if res.Status != 401 || m == nil {
			t.Fatal(res.Status, res.Header)
		}
		prm = env.do("GET", m[1], nil, nil).json()
		if prm["resource"] != e2eMCPResource || !reflect.DeepEqual(prm["authorization_servers"], []any{e2eAuthorizationServer}) {
			t.Fatal(prm)
		}
		asm := env.do("GET", e2eAuthorizationServer+"/.well-known/oauth-authorization-server", nil, nil).json()
		if asm["issuer"] != e2eAuthorizationServer || asm["client_id_metadata_document_supported"] != true ||
			asm["authorization_response_iss_parameter_supported"] != true {
			t.Fatal(asm)
		}
		endpoint := asm["authorization_endpoint"].(string)
		f.startAuthorization(endpoint, "mcp:base offline_access")
		if dcrRequests() != 0 || f.authorizeURL.Query().Get("resource") != e2eMCPResource {
			t.Fatal(f.authorizeURL)
		}

		cb := f.completeAuthorization()
		if cb.Query().Get("iss") != e2eAuthorizationServer {
			t.Fatal(cb)
		}
		tokens := f.finishAuth(cb)
		if f.tokenRequests[len(f.tokenRequests)-1].Get("resource") != e2eMCPResource || f.refreshToken == "" ||
			tokens["scope"] != "mcp:base offline_access" {
			t.Fatal(tokens)
		}

		if init := f.mcpRequest("initialize", f.accessToken); init.Status != 200 ||
			!strings.Contains(string(init.Body), e2eProtocolVersion) {
			t.Fatal(init.Status, string(init.Body))
		}
		if call := f.mcpRequest("tools/call", f.accessToken); call.Status != 403 {
			t.Fatal(call.Status)
		}
		f.startAuthorization(endpoint, "mcp:base offline_access greeting")
		if f.authorizeURL.Query().Get("scope") != "mcp:base offline_access greeting" {
			t.Fatal(f.authorizeURL)
		}
		f.finishAuth(f.completeAuthorization())
		if f.tokenRequests[len(f.tokenRequests)-1].Get("resource") != e2eMCPResource {
			t.Fatal("token request without resource")
		}
		if result := f.mcpRequest("tools/call", f.accessToken); result.Status != 200 ||
			!strings.Contains(string(result.Body), `"content":[{"type":"text","text":"hello from CIMD"}]`) {
			t.Fatal(result.Status, string(result.Body))
		}

		links, err := env.db.FindMany(context.Background(), adapter.FindManyInput{Model: "oauthClientResource",
			Where: []adapter.Where{{Field: "clientId", Value: e2eClientID}}})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, l := range links {
			ids = append(ids, recordResourceIdentifier(t, env, l))
		}
		if !reflect.DeepEqual(ids, []string{e2eMCPResource}) {
			t.Fatal(ids)
		}

		// A second client storage re-authorizes; each authorize/consent revalidates the
		// no-cache document with its ETag.
		re := &cimdSdkFlow{t: t, env: env, headers: f.headers}
		if r := re.mcpRequest("initialize", ""); r.Status != 401 {
			t.Fatal(r.Status)
		}
		before := fetchCount()
		re.startAuthorization(endpoint, "mcp:base offline_access")
		cb = re.completeAuthorization()
		if fetchCount() != before+2 {
			t.Fatal(fetchCount(), before)
		}
		reTokens := re.finishAuth(cb)
		if reTokens["access_token"] == nil || reTokens["refresh_token"] == nil {
			t.Fatal(reTokens)
		}
		for _, c := range conditional {
			if c != `"client-metadata-v1"` {
				t.Fatal(conditional)
			}
		}

		refreshed := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {f.refreshToken},
			"client_id": {e2eClientID}, "resource": {e2eMCPResource}})
		at, _ := refreshed["access_token"].(string)
		if at == "" || at == f.accessToken || refreshed["refresh_token"] == nil ||
			f.tokenRequests[len(f.tokenRequests)-1].Get("resource") != e2eMCPResource {
			t.Fatal(refreshed)
		}
		if r := f.mcpRequest("tools/call", at); r.Status != 200 || !strings.Contains(string(r.Body), "hello from CIMD") {
			t.Fatal(r.Status, string(r.Body))
		}
		if dcrRequests() != 0 {
			t.Fatal("DCR used")
		}
	})
}

// recordResourceIdentifier maps an oauthClientResource link to the resource identifier.
func recordResourceIdentifier(t *testing.T, env *testEnv, link adapter.Record) string {
	t.Helper()
	rid, _ := link["resourceId"].(string)
	if rid == e2eMCPResource {
		return rid
	}
	r, err := env.db.FindOne(context.Background(), adapter.FindOneInput{Model: "oauthResource",
		Where: []adapter.Where{{Field: "id", Value: rid}}})
	if err != nil || r == nil {
		return rid
	}
	id, _ := r["identifier"].(string)
	return id
}
