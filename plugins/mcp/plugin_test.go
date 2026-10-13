package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/deviceauthorization"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/mcp/src/plugin.test.ts.

const (
	pAuthServerBaseURL = "http://localhost:3000"
	pRPBaseURL         = "http://localhost:5000"
	pBaseURL           = pAuthServerBaseURL + "/api/auth"
	pProviderID        = "test"
	pRedirectURI       = pRPBaseURL + "/api/auth/callback/" + pProviderID
)

func mcpEnv(t *testing.T, baseURL string, o Options, extra ...*betterauth.Plugin) (*testEnv, *betterauth.Plugin) {
	t.Helper()
	p := mustPlugin(t, o)
	plugins := append([]*betterauth.Plugin{jwt.New(), p}, extra...)
	return newEnv(t, envOptions{baseURL: baseURL, plugins: plugins}), p
}

// pluginOption reads a resolved oauth-provider option by field name (upstream reads
// mcpPlugin.options.<name>).
func pluginOption(p *betterauth.Plugin, name string) any {
	return reflect.ValueOf(p.Options).Elem().FieldByName(name).Interface()
}

func TestMcpPlugin(t *testing.T) {
	env, plugin := mcpEnv(t, pAuthServerBaseURL, Options{Resource: pBaseURL})
	headers := env.signInWithTestUser()

	t.Run("dynamic client registration", func(t *testing.T) {
		t.Run("configures the MCP resource as a registration default", func(t *testing.T) {
			got := pluginOption(plugin, "ClientRegistrationDefaultResources").([]string)
			if !reflect.DeepEqual(got, []string{pBaseURL}) {
				t.Fatal(got)
			}
		})

		t.Run("does not enable unauthenticated DCR by default", func(t *testing.T) {
			res := env.do("POST", "/oauth2/register", map[string]any{"client_name": "test-public-client",
				"redirect_uris": []any{pRedirectURI}, "token_endpoint_auth_method": "none", "application_type": "native"}, nil)
			if res.status != 403 {
				t.Fatal(res.status, string(res.body))
			}
		})

		t.Run("advertises and accepts DCR only when explicitly enabled", func(t *testing.T) {
			explicitBaseURL := "http://localhost:3020"
			explicitResource := explicitBaseURL + "/api/auth"
			o := Options{Resource: explicitResource}
			o.AllowDynamicClientRegistration = true
			o.AllowUnauthenticatedClientRegistration = true
			explicit, _ := mcpEnv(t, explicitBaseURL, o)
			md := explicit.mustCall("getOAuthServerConfig", betterauth.CallInput{})
			if md["registration_endpoint"] != explicitResource+"/oauth2/register" {
				t.Fatal(md["registration_endpoint"])
			}
			if _, ok := md["client_id_metadata_document_supported"]; ok {
				t.Fatal("unexpected client_id_metadata_document_supported")
			}
			res := explicit.do("POST", "/oauth2/register", map[string]any{"client_name": "explicit DCR client",
				"redirect_uris": []any{"https://client.example.com/callback"}, "token_endpoint_auth_method": "none"}, nil)
			m := res.json()
			if res.status != 200 && res.status != 201 {
				t.Fatal(res.status, string(res.body))
			}
			if !reflect.DeepEqual(m["resources"], []any{explicitResource}) || m["token_endpoint_auth_method"] != "none" {
				t.Fatal(m)
			}
		})
	})

	t.Run("discovery metadata", func(t *testing.T) {
		t.Run("advertises the /oauth2/* endpoints and never alg=none", func(t *testing.T) {
			res := env.do("GET", pBaseURL+"/.well-known/oauth-authorization-server", nil, nil)
			if res.status != 200 {
				t.Fatal(res.status)
			}
			m := res.json()
			for k, v := range map[string]string{"issuer": pBaseURL, "authorization_endpoint": pBaseURL + "/oauth2/authorize",
				"token_endpoint": pBaseURL + "/oauth2/token", "userinfo_endpoint": pBaseURL + "/oauth2/userinfo"} {
				if m[k] != v {
					t.Fatalf("%s = %v", k, m[k])
				}
			}
			if _, ok := m["registration_endpoint"]; ok {
				t.Fatal("registration_endpoint advertised")
			}
			if _, ok := m["client_id_metadata_document_supported"]; ok {
				t.Fatal("client_id_metadata_document_supported advertised")
			}
			if !slices.Contains(m["scopes_supported"].([]any), any("offline_access")) {
				t.Fatal(m["scopes_supported"])
			}
			if slices.Contains(m["id_token_signing_alg_values_supported"].([]any), any("none")) {
				t.Fatal(m["id_token_signing_alg_values_supported"])
			}
		})

		t.Run("composes with device authorization and advertises the device-code grant", func(t *testing.T) {
			deviceBaseURL := "http://localhost:3011"
			device, _ := mcpEnv(t, deviceBaseURL, Options{Resource: deviceBaseURL + "/api/auth"},
				oauthprovider.OAuthDeviceAuthorization(deviceauthorization.Options{}))
			md := device.mustCall("getOAuthServerConfig", betterauth.CallInput{})
			if md["device_authorization_endpoint"] != deviceBaseURL+"/api/auth/device/code" {
				t.Fatal(md["device_authorization_endpoint"])
			}
			if !slices.Contains(md["grant_types_supported"].([]any), any(oauthprovider.DeviceCodeGrantType)) {
				t.Fatal(md["grant_types_supported"])
			}
		})
	})

	t.Run("protected resource metadata", func(t *testing.T) {
		algs := make([]any, len(oauthcore.DPoPSigningAlgorithms))
		for i, a := range oauthcore.DPoPSigningAlgorithms {
			algs[i] = a
		}
		t.Run("returns RFC 9728 protected resource metadata", func(t *testing.T) {
			res := env.do("GET", pAuthServerBaseURL+"/.well-known/oauth-protected-resource", nil, nil)
			if res.status != 200 {
				t.Fatal(res.status)
			}
			m := res.json()
			want := map[string]any{"resource": pBaseURL, "authorization_servers": []any{pBaseURL},
				"bearer_methods_supported": []any{"header"}, "dpop_signing_alg_values_supported": algs}
			if !reflect.DeepEqual(m, want) {
				t.Fatal(m)
			}
			// Go-only: key order and caching headers of the document.
			if string(res.body) != `{"resource":"http://localhost:3000/api/auth","authorization_servers":["http://localhost:3000/api/auth"],"bearer_methods_supported":["header"],"dpop_signing_alg_values_supported":["EdDSA","ES256","ES512","PS256","RS256"]}` {
				t.Fatal(string(res.body))
			}
			if res.header.Get("Cache-Control") == "" {
				t.Fatal("missing Cache-Control")
			}
			// The resource-path-inserted alias serves the same document.
			alias := env.do("GET", pAuthServerBaseURL+"/.well-known/oauth-protected-resource/api/auth", nil, nil)
			if alias.status != 200 || string(alias.body) != string(res.body) {
				t.Fatal(alias.status, string(alias.body))
			}
		})

		t.Run("advertises resource scopes without authorization-server-only scopes", func(t *testing.T) {
			resourceServerBaseURL := "http://localhost:3010"
			resourceBaseURL := resourceServerBaseURL + "/api/auth"
			o := Options{Resource: resourceBaseURL}
			o.Scopes = []string{"openid", "offline_access", "mcp:read"}
			rs, _ := mcpEnv(t, resourceServerBaseURL, o)
			res := rs.do("GET", resourceServerBaseURL+"/.well-known/oauth-protected-resource", nil, nil)
			if res.status != 200 {
				t.Fatal(res.status)
			}
			want := map[string]any{"resource": resourceBaseURL, "authorization_servers": []any{resourceBaseURL},
				"scopes_supported": []any{"mcp:read"}, "bearer_methods_supported": []any{"header"},
				"dpop_signing_alg_values_supported": algs}
			if m := res.json(); !reflect.DeepEqual(m, want) {
				t.Fatal(m)
			}
		})

		t.Run("answers HEAD with metadata headers and an empty body", func(t *testing.T) {
			res := env.do("HEAD", pAuthServerBaseURL+"/.well-known/oauth-protected-resource", nil, nil)
			if res.status != 200 || !strings.Contains(res.header.Get("Content-Type"), "application/json") || len(res.body) != 0 {
				t.Fatal(res.status, res.header, string(res.body))
			}
		})

		t.Run("rejects non-GET/HEAD methods with 405", func(t *testing.T) {
			res := env.do("POST", pAuthServerBaseURL+"/.well-known/oauth-protected-resource", nil, nil)
			if res.status != 405 || res.header.Get("Allow") != "GET, HEAD" {
				t.Fatal(res.status, res.header)
			}
		})

		// The "array" case is TS-only: Resource is a Go string.
		for _, c := range []struct{ name, resource string }{
			{"opaque URI", "urn:example:mcp"},
			{"non-loopback HTTP", "http://api.example.com/mcp"},
			{"private HTTP hostname", "http://mcp.internal/mcp"},
			{"loopback-lookalike hostname", "http://127.example.com/mcp"},
			{"credentials", "https://user:pass@api.example.com/mcp"},
			{"fragment", "https://api.example.com/mcp#fragment"},
			{"query", "https://api.example.com/mcp?tenant=a"},
		} {
			t.Run("rejects an invalid canonical MCP resource: "+c.name, func(t *testing.T) {
				o := Options{Resource: c.resource}
				o.LoginPage, o.ConsentPage = "/login", "/consent"
				if _, err := New(o); err == nil || !strings.Contains(err.Error(), "MCP resource") {
					t.Fatal(err)
				}
			})
		}
		for _, resource := range []string{"https://api.example.com/mcp", "http://localhost:3000/mcp", "http://127.0.0.1:3000/mcp",
			"http://127.42.0.1/mcp", "http://[::1]:3000/mcp"} {
			t.Run("accepts a canonical MCP resource: "+resource, func(t *testing.T) {
				o := Options{Resource: resource}
				o.LoginPage, o.ConsentPage = "/login", "/consent"
				if _, err := New(o); err != nil {
					t.Fatal(err)
				}
			})
		}
	})

	t.Run("requireMcpAuth", func(t *testing.T) {
		never := func(*http.Request, *jsonx.Object) (*betterauth.Response, error) {
			t.Fatal("handler must not run")
			return nil, nil
		}
		t.Run("returns 401 with the resource_metadata header when unauthenticated", func(t *testing.T) {
			h, err := RequireMcpAuth(env.auth, never, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := h(httptest.NewRequest("GET", pAuthServerBaseURL+"/mcp", nil))
			if err != nil || res.Status != 401 || res.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="`+pAuthServerBaseURL+`/.well-known/oauth-protected-resource/api/auth"` {
				t.Fatal(err, res)
			}
		})

		t.Run("returns 401 for an invalid bearer token", func(t *testing.T) {
			h, _ := RequireMcpAuth(env.auth, never, nil)
			r := httptest.NewRequest("GET", pAuthServerBaseURL+"/mcp", nil)
			r.Header.Set("Authorization", "Bearer invalid-token")
			res, err := h(r)
			if err != nil || res.Status != 401 || res.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="`+pAuthServerBaseURL+`/.well-known/oauth-protected-resource/api/auth"` {
				t.Fatal(err, res)
			}
		})

		t.Run("challenges for a missing scope and accepts a union-scope retry", func(t *testing.T) {
			pub, priv, err := jose.GenerateKeyPair("RS256", jose.GenerateKeyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			jwk, _ := jose.JWKFromPublicKey(pub)
			jwk.Kid, jwk.Alg = "mcp-real-verifier", "RS256"
			jwks, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
			env.serveHost("localhost:3000", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(jwks)
			}))
			t.Cleanup(func() {
				env.mu.Lock()
				delete(env.hosts, "localhost:3000")
				env.mu.Unlock()
				oauthcore.ResetJWKSCache()
			})
			oauthcore.ResetJWKSCache()
			sign := func(scope string) string {
				now := time.Now().Unix()
				tok, err := jose.SignJWT(jsonx.O("alg", "RS256", "kid", jwk.Kid),
					jsonx.O("sub", "user-real", "scope", scope, "iss", pBaseURL, "aud", pBaseURL, "iat", now, "exp", now+3600), priv)
				if err != nil {
					t.Fatal(err)
				}
				return tok
			}
			calls := 0
			protect, err := CreateMcpProtectedRequestHandler(ProtectedRequestHandlerOptions{
				Issuer: pBaseURL, Audience: pBaseURL, JWKSURL: pBaseURL + "/jwks", RequiredScopes: []string{"mcp:write"},
			}, func(_ *http.Request, c *jsonx.Object) (*betterauth.Response, error) {
				calls++
				sub, _ := c.Get("sub")
				b, _ := jsonx.Marshal(jsonx.O("sub", sub))
				return &betterauth.Response{Status: 200, Body: b}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", pAuthServerBaseURL+"/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+sign("mcp:read"))
			challenge, err := protect(r)
			if err != nil || challenge.Status != 403 {
				t.Fatal(err, challenge)
			}
			wa := challenge.Header.Get("WWW-Authenticate")
			if !strings.Contains(wa, `scope="mcp:write"`) || strings.Contains(wa, `scope="mcp:read`) || calls != 0 {
				t.Fatal(wa, calls)
			}
			r = httptest.NewRequest("GET", pAuthServerBaseURL+"/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+sign("mcp:read mcp:write"))
			res, err := protect(r)
			if err != nil || res.Status != 200 || string(res.Body) != `{"sub":"user-real"}` || calls != 1 {
				t.Fatal(err, res, calls)
			}
		})
	})

	t.Run("authorization code + PKCE flow", func(t *testing.T) {
		reg := env.mustCall("adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"client_name": "test-pkce-client", "redirect_uris": []any{pRedirectURI},
			"token_endpoint_auth_method": "none", "application_type": "native"}})
		publicClientID, _ := reg["client_id"].(string)
		if publicClientID == "" {
			t.Fatal("client creation failed")
		}
		state := "mcp-pkce-state"

		t.Run("mints an access token through authorize + consent + token exchange", func(t *testing.T) {
			verifier := "mcp-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJ"
			q := url.Values{"response_type": {"code"}, "client_id": {publicClientID}, "state": {state},
				"scope": {"openid offline_access"}, "redirect_uri": {pRedirectURI},
				"code_challenge_method": {"S256"}, "code_challenge": {pkceChallenge(verifier)}}
			az := env.do("GET", pBaseURL+"/oauth2/authorize?"+q.Encode(), nil, headers)
			consentRedirect := az.location()
			// Untrusted self-registered clients must pass through consent.
			if !strings.Contains(consentRedirect, "/consent") {
				t.Fatal(az.status, consentRedirect)
			}
			cb := env.consent(headers, consentRedirect)
			if !strings.Contains(cb, "code=") || !strings.Contains(cb, "state="+state) {
				t.Fatal(cb)
			}
			cu, _ := url.Parse(cb)
			tok := env.do("POST", pBaseURL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"},
				"code": {cu.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {pRedirectURI},
				"client_id": {publicClientID}}, nil)
			tokens := tok.json()
			for _, k := range []string{"access_token", "id_token", "refresh_token"} {
				if tokens[k] == nil {
					t.Fatalf("missing %s: %s", k, tok.body)
				}
			}
			if strings.ToLower(tokens["token_type"].(string)) != "bearer" || tokens["scope"] != "openid offline_access" {
				t.Fatal(tokens)
			}
			refresh := func() map[string]any {
				return env.do("POST", pBaseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"},
					"refresh_token": {tokens["refresh_token"].(string)}, "client_id": {publicClientID}}, nil).json()
			}
			first := refresh()
			if first["access_token"] == nil || first["refresh_token"] == nil {
				t.Fatal(first)
			}
			replay := refresh()
			for _, k := range []string{"access_token", "expires_at", "refresh_token", "token_type", "scope", "id_token"} {
				if !reflect.DeepEqual(replay[k], first[k]) {
					t.Fatalf("%s: %v != %v", k, replay[k], first[k])
				}
			}
			if replay["expires_in"].(float64) > first["expires_in"].(float64) {
				t.Fatal(replay["expires_in"], first["expires_in"])
			}
		})
	})
}

// The refresh_token grant on a confidential MCP client must authenticate the client.
// See GHSA-pw9m-5jxm-xr6h.
func TestMcpRefreshTokenGrantClientAuthentication(t *testing.T) {
	o := Options{Resource: pAuthServerBaseURL + "/api/auth"}
	o.AllowDynamicClientRegistration = true
	o.AllowUnauthenticatedClientRegistration = true
	env, _ := mcpEnv(t, pAuthServerBaseURL, o)
	headers := env.signInWithTestUser()
	created := env.do("POST", "/oauth2/register", map[string]any{"client_name": "test-refresh-confidential-client",
		"redirect_uris": []any{pRedirectURI}, "token_endpoint_auth_method": "client_secret_basic", "application_type": "native"}, headers).json()
	clientID, _ := created["client_id"].(string)
	clientSecret, _ := created["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		t.Fatal("client registration failed", created)
	}
	basic := func(secret string) http.Header {
		h := http.Header{}
		h.Set("Authorization", basicAuth(clientID, secret))
		return h
	}
	mintRefreshToken := func() string {
		t.Helper()
		verifier := "mcp-refresh-verifier-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFG"
		q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "state": {"mcp-refresh-state"},
			"scope": {"openid offline_access"}, "redirect_uri": {pRedirectURI},
			"code_challenge_method": {"S256"}, "code_challenge": {pkceChallenge(verifier)}}
		redirect := env.do("GET", "/oauth2/authorize?"+q.Encode(), nil, headers).location()
		// A prior grant may let authorize skip consent and return the code directly.
		codeRedirect := redirect
		if strings.Contains(redirect, "/consent") {
			codeRedirect = env.consent(headers, redirect)
		}
		u, _ := url.Parse(codeRedirect)
		code := u.Query().Get("code")
		if code == "" {
			t.Fatal("missing authorization code", redirect)
		}
		tokens := env.do("POST", "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"code_verifier": {verifier}, "redirect_uri": {pRedirectURI}}, basic(clientSecret)).json()
		rt, _ := tokens["refresh_token"].(string)
		if rt == "" {
			t.Fatal("token exchange did not return a refresh token", tokens)
		}
		return rt
	}

	t.Run("rejects refresh_token grant on a confidential client without client_secret", func(t *testing.T) {
		rt := mintRefreshToken()
		res := env.do("POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}}, nil)
		m := res.json()
		if res.status != 400 || m["error"] != "invalid_client" || m["access_token"] != nil {
			t.Fatal(res.status, m)
		}
	})

	t.Run("rejects refresh_token grant on a confidential client with the wrong client_secret", func(t *testing.T) {
		rt := mintRefreshToken()
		res := env.do("POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, basic("wrong-secret"))
		m := res.json()
		if res.status != 401 || m["error"] != "invalid_client" || m["access_token"] != nil {
			t.Fatal(res.status, m)
		}
	})

	t.Run("accepts refresh_token grant when client_secret comes via Authorization: Basic", func(t *testing.T) {
		rt := mintRefreshToken()
		res := env.do("POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, basic(clientSecret))
		m := res.json()
		if res.status != 200 || m["access_token"] == nil || m["refresh_token"] == nil {
			t.Fatal(res.status, m)
		}
	})

	t.Run("rejects refresh_token grant when the confidential client is disabled", func(t *testing.T) {
		rt := mintRefreshToken()
		where := []adapter.Where{{Field: "clientId", Value: clientID}}
		if _, err := env.db.Update(context.Background(), "oauthClient", where, adapter.Record{"disabled": true}); err != nil {
			t.Fatal(err)
		}
		res := env.do("POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, basic(clientSecret))
		if _, err := env.db.Update(context.Background(), "oauthClient", where, adapter.Record{"disabled": false}); err != nil {
			t.Fatal(err)
		}
		m := res.json()
		// Failed HTTP Basic authentication returns its registered challenge.
		if res.status != 401 || res.header.Get("WWW-Authenticate") != "Basic" || m["error"] != "invalid_client" || m["access_token"] != nil {
			t.Fatal(res.status, res.header, m)
		}
	})

	t.Run("rotates the refresh token on a successful confidential refresh", func(t *testing.T) {
		rt := mintRefreshToken()
		m := env.do("POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, basic(clientSecret)).json()
		if m["access_token"] == nil || m["refresh_token"] == nil || m["refresh_token"] == rt {
			t.Fatal(m)
		}
	})
}
