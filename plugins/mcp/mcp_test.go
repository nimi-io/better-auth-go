package mcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/mcp/src/mcp.test.ts. The official MCP SDK v2 (client and server) is
// TypeScript-only; the SDK flow is reproduced step by step against the same server
// configuration: protected-resource discovery, authorization-server metadata, dynamic
// registration, authorization + consent with the resource indicator, token exchange,
// a protected JSON-RPC endpoint with per-method scopes, step-up and refresh.

const (
	authorizationServer = "https://auth.example.test"
	mcpResource         = "https://resource.example.test/mcp"
	sdkRedirectURI      = "https://client.example.test/oauth/callback"
	protocolVersion     = "2026-07-28"
)

// ---- official SDK AuthInfo mapping (test-local helpers upstream) ----

type sdkAuthInfo struct {
	Token     string
	ClientID  string
	Scopes    []string
	ExpiresAt any
	Resource  string
	Extra     map[string]any
}

var errClientID = errors.New("MCP access token client_id must be a non-empty string")
var errPresentation = errors.New("verified MCP request is missing a valid Bearer or DPoP access token")

func requireAccessTokenClientID(claims *jsonx.Object) (string, error) {
	v, _ := claims.Get("client_id")
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", errClientID
	}
	return s, nil
}

var presentedTokenRe = regexp.MustCompile(`(?i)^(?:Bearer|DPoP)[ \t]+(\S+)$`)

func extractPresentedAccessToken(r *http.Request) (string, error) {
	m := presentedTokenRe.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil || m[1] == "" {
		return "", errPresentation
	}
	return m[1], nil
}

func parseGrantedScopes(scope any) []string {
	s, ok := scope.(string)
	if !ok {
		return []string{}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, p := range strings.Split(s, " ") {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func createOfficialSdkAuthInfo(r *http.Request, claims *jsonx.Object, resource string) (*sdkAuthInfo, error) {
	token, err := extractPresentedAccessToken(r)
	if err != nil {
		return nil, err
	}
	clientID, err := requireAccessTokenClientID(claims)
	if err != nil {
		return nil, err
	}
	scope, _ := claims.Get("scope")
	exp, _ := claims.Get("exp")
	return &sdkAuthInfo{Token: token, ClientID: clientID, Scopes: parseGrantedScopes(scope), ExpiresAt: exp,
		Resource: resource, Extra: map[string]any{"accessTokenClaims": claims}}, nil
}

func TestOfficialSdkAuthInfoMapping(t *testing.T) {
	for _, claims := range []*jsonx.Object{jsonx.O(), jsonx.O("client_id", ""), jsonx.O("client_id", "   "), jsonx.O("client_id", 42)} {
		b, _ := jsonx.Marshal(claims)
		t.Run("rejects a missing or malformed client_id claim: "+string(b), func(t *testing.T) {
			if _, err := requireAccessTokenClientID(claims); err != errClientID {
				t.Fatal(err)
			}
		})
	}
	for _, authorization := range []string{"", "Basic access-token", "Bearer", "Bearer ", "Bearer access-token trailing", "DPoP "} {
		t.Run("rejects a malformed authorization presentation: "+authorization, func(t *testing.T) {
			r := httptest.NewRequest("GET", mcpResource, nil)
			if authorization != "" {
				r.Header.Set("Authorization", authorization)
			}
			if _, err := extractPresentedAccessToken(r); err != errPresentation {
				t.Fatal(err)
			}
		})
	}
	for _, scheme := range []string{"Bearer", "DPoP"} {
		t.Run("extracts the actual "+scheme+" access token", func(t *testing.T) {
			r := httptest.NewRequest("GET", mcpResource, nil)
			r.Header.Set("Authorization", scheme+" presented-token")
			if tok, err := extractPresentedAccessToken(r); err != nil || tok != "presented-token" {
				t.Fatal(tok, err)
			}
		})
	}
	t.Run("deduplicates string scopes and treats other claim types as empty", func(t *testing.T) {
		if got := parseGrantedScopes("mcp:base greeting mcp:base"); !reflect.DeepEqual(got, []string{"mcp:base", "greeting"}) {
			t.Fatal(got)
		}
		if got := parseGrantedScopes(nil); len(got) != 0 {
			t.Fatal(got)
		}
		if got := parseGrantedScopes([]any{"mcp:base"}); len(got) != 0 {
			t.Fatal(got)
		}
	})
	t.Run("maps verified claims and the presented token into SDK AuthInfo", func(t *testing.T) {
		r := httptest.NewRequest("GET", mcpResource, nil)
		r.Header.Set("Authorization", "DPoP actual-token")
		info, err := createOfficialSdkAuthInfo(r, jsonx.O("client_id", "mcp-client", "scope", "mcp:base mcp:base", "exp", 1_800_000_000), mcpResource)
		if err != nil {
			t.Fatal(err)
		}
		if info.Token != "actual-token" || info.ClientID != "mcp-client" || !reflect.DeepEqual(info.Scopes, []string{"mcp:base"}) ||
			info.ExpiresAt != 1_800_000_000 || info.Resource != mcpResource {
			t.Fatalf("%+v", info)
		}
	})
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in tests")
}

func TestMcp(t *testing.T) {
	const apiServerBaseURL = "http://localhost:5000"
	prev := oauthcore.HTTPClient
	oauthcore.HTTPClient = &http.Client{Transport: failingTransport{}}
	t.Cleanup(func() { oauthcore.HTTPClient = prev })
	apiClient := oauthprovider.NewResourceClient(nil)

	for _, c := range []struct{ resource, expected string }{
		{apiServerBaseURL, `Bearer resource_metadata="` + apiServerBaseURL + `/.well-known/oauth-protected-resource"`},
		{apiServerBaseURL + "/resource1", `Bearer resource_metadata="` + apiServerBaseURL + `/.well-known/oauth-protected-resource/resource1"`},
	} {
		t.Run("provides the OAuth resource challenge for "+c.resource, func(t *testing.T) {
			_, err := apiClient.VerifyBearerToken(context.Background(), "bad_access_token", oauthprovider.ResourceVerifyOptions{
				Issuer: []string{authorizationServer}, Audience: []string{c.resource}, JWKSURL: authorizationServer + "/api/auth/jwks"})
			if err == nil {
				t.Fatal("expected an error")
			}
			ch, cerr := oauthprovider.CreateResourceServerChallenge(err, []string{c.resource}, nil)
			if cerr != nil || ch == nil || ch.StatusCode != 401 || ch.Headers.Get("WWW-Authenticate") != c.expected {
				t.Fatal(cerr, ch)
			}
		})
	}

	t.Run("preserves the MCP challenge boundary", func(t *testing.T) {
		h, err := CreateMcpProtectedRequestHandler(ProtectedRequestHandlerOptions{Issuer: authorizationServer, Audience: mcpResource},
			func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
				return &betterauth.Response{Status: 200, Body: []byte("unused")}, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		res, err := h(httptest.NewRequest("GET", mcpResource, nil))
		if err != nil || res.Status != 401 || res.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="https://resource.example.test/.well-known/oauth-protected-resource/mcp"` {
			t.Fatal(err, res)
		}
	})
}

// sdkFlow drives the MCP authorization flow the official SDK performs.
type sdkFlow struct {
	t                *testing.T
	env              *testEnv
	headers          http.Header
	tokenRequests    []url.Values
	registrations    []map[string]any
	scopeChallenges  []string
	verifier         string
	clientID         string
	accessToken      string
	refreshToken     string
	lastAuthorizeURL *url.URL
}

// mcpRequest sends a JSON-RPC request to the protected MCP endpoint.
func (f *sdkFlow) mcpRequest(method string, token string) *betterauth.Response {
	f.t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{}}`
	r := httptest.NewRequest("POST", mcpResource, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Mcp-Method", method)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	required := []string{"mcp:base"}
	if method == "tools/call" {
		required = []string{"greeting"}
	}
	h, err := CreateMcpProtectedRequestHandler(ProtectedRequestHandlerOptions{
		Issuer: authorizationServer, Audience: mcpResource, JWKSURL: authorizationServer + "/api/auth/jwks", RequiredScopes: required,
	}, func(vr *http.Request, claims *jsonx.Object) (*betterauth.Response, error) {
		info, err := createOfficialSdkAuthInfo(vr, claims, mcpResource)
		if err != nil {
			return nil, err
		}
		_ = info
		raw, _ := io.ReadAll(vr.Body)
		var result *jsonx.Object
		switch {
		case strings.Contains(string(raw), `"initialize"`):
			result = jsonx.O("protocolVersion", protocolVersion, "capabilities", jsonx.O("tools", jsonx.O()),
				"serverInfo", jsonx.O("name", "better-auth-mcp-acceptance", "version", "1.0.0"))
		case strings.Contains(string(raw), `"tools/call"`):
			result = jsonx.O("content", []any{jsonx.O("type", "text", "text", "hello from protected MCP")})
		default:
			result = jsonx.O()
		}
		b, _ := jsonx.Marshal(jsonx.O("jsonrpc", "2.0", "id", 1, "result", result))
		hd := http.Header{}
		hd.Set("Content-Type", "application/json")
		return &betterauth.Response{Status: 200, Header: hd, Body: b}, nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	res, err := h(r)
	if err != nil {
		f.t.Fatal(err)
	}
	if res.Status == 403 {
		if c := res.Header.Get("WWW-Authenticate"); c != "" {
			f.scopeChallenges = append(f.scopeChallenges, c)
		}
	}
	return res
}

func (f *sdkFlow) token(form url.Values) map[string]any {
	f.t.Helper()
	f.tokenRequests = append(f.tokenRequests, form)
	res := f.env.do("POST", authorizationServer+"/api/auth/oauth2/token", form, nil)
	if res.status != 200 {
		f.t.Fatalf("token: %d %s", res.status, res.body)
	}
	return res.json()
}

// authorize builds the authorization URL like the SDK, completes consent and returns the
// callback URL.
func (f *sdkFlow) authorize(endpoint, scope string) *url.URL {
	f.t.Helper()
	f.verifier = "sdk-verifier-" + strings.Repeat("x", 40) + scope[:3]
	q := url.Values{"response_type": {"code"}, "client_id": {f.clientID}, "code_challenge": {pkceChallenge(f.verifier)},
		"code_challenge_method": {"S256"}, "redirect_uri": {sdkRedirectURI}, "state": {"mcp-sdk-v2-state"},
		"scope": {scope}, "resource": {mcpResource}}
	// The MCP SDK requests prompt=consent whenever it asks for offline_access.
	if strings.Contains(scope, "offline_access") {
		q.Set("prompt", "consent")
	}
	u, _ := url.Parse(endpoint + "?" + q.Encode())
	f.lastAuthorizeURL = u
	location := f.env.do("GET", u.String(), nil, f.headers).location()
	if !strings.Contains(location, "/consent") {
		f.t.Fatalf("authorization did not reach consent: %s", location)
	}
	cb, err := url.Parse(f.env.consent(f.headers, location))
	if err != nil {
		f.t.Fatal(err)
	}
	return cb
}

func (f *sdkFlow) finishAuth(cb *url.URL) map[string]any {
	f.t.Helper()
	tokens := f.token(url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"code_verifier": {f.verifier}, "redirect_uri": {sdkRedirectURI}, "client_id": {f.clientID}, "resource": {mcpResource}})
	f.accessToken, _ = tokens["access_token"].(string)
	f.refreshToken, _ = tokens["refresh_token"].(string)
	return tokens
}

var resourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

func TestMcpSdkV2ExplicitDCRFlow(t *testing.T) {
	o := Options{Resource: mcpResource}
	o.EnforcePerClientResources = betterauth.Bool(true)
	o.AllowDynamicClientRegistration = true
	o.AllowUnauthenticatedClientRegistration = true
	o.Scopes = []string{"openid", "offline_access", "mcp:base", "greeting"}
	env := newEnv(t, envOptions{baseURL: authorizationServer, plugins: []*betterauth.Plugin{
		jwt.New(jwt.Options{JWT: &jwt.JWTOptions{Issuer: authorizationServer}}), mustPlugin(t, o)},
		mutate: func(c *betterauth.Config) {
			c.Advanced = &betterauth.AdvancedConfig{UseSecureCookies: betterauth.Bool(false)}
		}})
	f := &sdkFlow{t: t, env: env, headers: env.signInWithTestUser()}

	t.Run("registers, binds, negotiates 2026-07-28, steps up, invokes a tool, and refreshes", func(t *testing.T) {
		// connect: unauthenticated initialize -> 401 + resource_metadata.
		res := f.mcpRequest("initialize", "")
		if res.Status != 401 {
			t.Fatal(res.Status)
		}
		m := resourceMetadataRe.FindStringSubmatch(res.Header.Get("WWW-Authenticate"))
		if m == nil || m[1] != "https://resource.example.test/.well-known/oauth-protected-resource/mcp" {
			t.Fatal(res.Header.Get("WWW-Authenticate"))
		}
		prm := env.do("GET", m[1], nil, nil).json()
		if prm["resource"] != mcpResource || !reflect.DeepEqual(prm["authorization_servers"], []any{authorizationServer}) ||
			!reflect.DeepEqual(prm["scopes_supported"], []any{"mcp:base", "greeting"}) {
			t.Fatal(prm)
		}
		asm := env.do("GET", authorizationServer+"/.well-known/oauth-authorization-server", nil, nil).json()
		if asm["issuer"] != authorizationServer || asm["authorization_response_iss_parameter_supported"] != true {
			t.Fatal(asm)
		}
		// Dynamic client registration without resources.
		doc := map[string]any{"client_name": "Better Auth MCP SDK v2 client", "redirect_uris": []any{sdkRedirectURI},
			"application_type": "native", "token_endpoint_auth_method": "none",
			"grant_types": []any{"authorization_code", "refresh_token"}, "response_types": []any{"code"}}
		f.registrations = append(f.registrations, doc)
		reg := env.do("POST", asm["registration_endpoint"].(string), doc, nil).json()
		f.clientID, _ = reg["client_id"].(string)
		if f.clientID == "" || reg["scope"] != "openid offline_access mcp:base greeting" {
			t.Fatal(reg)
		}
		if _, ok := f.registrations[0]["resources"]; ok || len(f.registrations) != 1 {
			t.Fatal(f.registrations)
		}
		if f.lastAuthorizeURL != nil {
			t.Fatal("unexpected authorization")
		}
		cb := f.authorize(asm["authorization_endpoint"].(string), "mcp:base offline_access")
		if f.lastAuthorizeURL.Query().Get("resource") != mcpResource {
			t.Fatal(f.lastAuthorizeURL)
		}
		if cb.Query().Get("iss") != authorizationServer {
			t.Fatal(cb)
		}
		tokens := f.finishAuth(cb)
		if f.tokenRequests[len(f.tokenRequests)-1].Get("resource") != mcpResource {
			t.Fatal("token request without resource")
		}
		if f.accessToken == "" || f.refreshToken == "" || tokens["scope"] != "mcp:base offline_access" {
			t.Fatal(tokens)
		}

		// Reconnect with the token: initialize negotiates the pinned protocol version.
		init := f.mcpRequest("initialize", f.accessToken)
		if init.Status != 200 || !strings.Contains(string(init.Body), `"protocolVersion":"`+protocolVersion+`"`) {
			t.Fatal(init.Status, string(init.Body))
		}
		// The tool needs "greeting": step-up challenge.
		if call := f.mcpRequest("tools/call", f.accessToken); call.Status != 403 {
			t.Fatal(call.Status)
		}
		if len(f.scopeChallenges) != 1 {
			t.Fatal(f.scopeChallenges)
		}
		ch := f.scopeChallenges[0]
		if !strings.Contains(ch, `error="insufficient_scope"`) || !strings.Contains(ch, `scope="greeting"`) ||
			strings.Contains(ch, "mcp:base") || strings.Contains(ch, "offline_access") {
			t.Fatal(ch)
		}
		stepUp := f.authorize(asm["authorization_endpoint"].(string), "mcp:base offline_access greeting")
		if f.lastAuthorizeURL.Query().Get("scope") != "mcp:base offline_access greeting" || f.lastAuthorizeURL.Query().Get("resource") != mcpResource {
			t.Fatal(f.lastAuthorizeURL)
		}
		if stepUp.Query().Get("iss") != authorizationServer {
			t.Fatal(stepUp)
		}
		f.finishAuth(stepUp)
		if f.tokenRequests[len(f.tokenRequests)-1].Get("resource") != mcpResource {
			t.Fatal("token request without resource")
		}
		result := f.mcpRequest("tools/call", f.accessToken)
		if result.Status != 200 || !strings.Contains(string(result.Body), `"content":[{"type":"text","text":"hello from protected MCP"}]`) {
			t.Fatal(result.Status, string(result.Body))
		}
		before := f.accessToken
		refreshed := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {f.refreshToken},
			"client_id": {f.clientID}, "resource": {mcpResource}})
		at, _ := refreshed["access_token"].(string)
		if at == "" || at == before || refreshed["refresh_token"] == nil {
			t.Fatal(refreshed)
		}
		if f.tokenRequests[len(f.tokenRequests)-1].Get("resource") != mcpResource {
			t.Fatal("refresh without resource")
		}
		if aud := decodeJWTPayload(t, at)["aud"]; aud != mcpResource {
			t.Fatal(aud)
		}
	})

	// "discards client credentials stamped for another issuer" exercises the official MCP
	// SDK client's credential storage (OAuthClientProvider), not server behaviour; it has no
	// Go counterpart.
	t.Run("discards client credentials stamped for another issuer", func(t *testing.T) {
		t.Skip("TS-only: MCP SDK client credential storage")
	})
}
