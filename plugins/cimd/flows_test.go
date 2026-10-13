package cimd

import (
	"encoding/json"
	"errors"
	"fmt"

	"crypto/rand"
	"encoding/hex"
	"github.com/nimi-io/better-auth-go/adapter"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/cimd/src/flows.test.ts.

type rsaClientKey struct {
	priv      any
	publicJWK *jsonx.Object
}

func newRSAClientKey(t *testing.T) rsaClientKey {
	t.Helper()
	pub, priv, err := jose.GenerateKeyPair("RS256", jose.GenerateKeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pj, _ := jose.JWKFromPublicKey(pub)
	return rsaClientKey{priv: priv, publicJWK: jose.ExportJWK(pj)}
}

func (k rsaClientKey) jwks(kid string) map[string]any {
	j := k.publicJWK.Clone()
	j.Set("kid", kid)
	j.Set("alg", "RS256")
	j.Set("use", "sig")
	b, _ := jsonx.Marshal(jsonx.O("keys", []any{j}))
	return map[string]any{"raw": string(b)}
}

// signPrivateKeyJwtClientAssertion signs an RFC 7523 client assertion.
func signPrivateKeyJwtClientAssertion(t *testing.T, clientID, tokenEndpoint string, key any, kid string) string {
	t.Helper()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	now := time.Now().Unix()
	s, err := jose.SignJWT(jsonx.O("alg", "RS256", "kid", kid, "typ", "JWT"),
		jsonx.O("iss", clientID, "sub", clientID, "aud", tokenEndpoint, "jti", hex.EncodeToString(b), "iat", now, "exp", now+60), key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jwksResponse(k rsaClientKey, kid string) *http.Response {
	return jsonResponse(200, k.jwks(kid)["raw"])
}

func TestCimdTokenExchangeFlow(t *testing.T) {
	const (
		authServerBaseURL = "http://localhost:3102"
		clientMetadataURL = "https://mcp-client-token.example.com/client-metadata.json"
		redirectURI       = "http://localhost:5102/callback"
		tokenEndpoint     = authServerBaseURL + "/api/auth/oauth2/token"
	)
	metadataDocument := map[string]any{"client_id": clientMetadataURL, "client_name": "Token Exchange Test Client",
		"redirect_uris": []any{redirectURI}, "token_endpoint_auth_method": "none", "application_type": "native",
		"grant_types": []any{"authorization_code"}, "response_types": []any{"code"}}
	ms := newMetadataServer()
	env := cimdEnv(t, authServerBaseURL, oauthprovider.Options{Scopes: []string{"openid", "profile", "email", "offline_access"}},
		Options{FetchClientMetadataResource: ms.fetch}, func(c *betterauth.Config) {
			c.TrustedOrigins = append(c.TrustedOrigins, "https://kms.example.com")
		})
	run := func(name string, fn func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(ms.clear)
			fn(t)
		})
	}
	exchange := func(form url.Values) *response {
		return env.do("POST", tokenEndpoint, form, nil)
	}

	exchangeWithUnsafeJwksResponse := func(t *testing.T, kind string) (*response, string) {
		clientID := "https://" + kind + "-key-client.example.com/client-metadata.json"
		jwksURI := "https://" + kind + "-key-client.example.com/.well-known/jwks.json"
		redirect := fmt.Sprintf("http://localhost:%d/callback", 5200+len(kind))
		kid := kind + "-key"
		key := newRSAClientKey(t)
		ms.setJSON(clientID, map[string]any{"client_id": clientID, "client_name": kind + " JWKS Client",
			"redirect_uris": []any{redirect}, "token_endpoint_auth_method": "private_key_jwt", "application_type": "native",
			"grant_types": []any{"authorization_code"}, "response_types": []any{"code"}, "jwks_uri": jwksURI})
		ms.set(jwksURI, func(*http.Request) (*http.Response, error) {
			switch kind {
			case "redirected":
				// Go responses carry no `redirected` flag; an unfollowed redirect is the
				// transport-level equivalent.
				return emptyResponse(302, "Location", "https://elsewhere.example.com/jwks.json"), nil
			case "wrong-mime":
				return jsonResponse(200, key.jwks(kid)["raw"], "Content-Type", "text/plain"), nil
			}
			var m map[string]any
			_ = json.Unmarshal([]byte(key.jwks(kid)["raw"].(string)), &m)
			m["padding"] = strings.Repeat("x", 70*1024)
			return jsonResponse(200, m), nil
		})
		code := env.extractAuthorizationCode(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientID, redirect, ""))
		res := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
			"client_id": {clientID}, "client_assertion_type": {oauthcore.ClientAssertionType},
			"client_assertion": {signPrivateKeyJwtClientAssertion(t, clientID, tokenEndpoint, key.priv, kid)},
			"code_verifier":    {pkceVerifier}})
		return res, jwksURI
	}

	run("exchanges an authorization code for an access token", func(t *testing.T) {
		ms.setJSON(clientMetadataURL, metadataDocument)
		code := env.extractAuthorizationCode(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientMetadataURL, redirectURI, ""))
		res := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			"client_id": {clientMetadataURL}, "code_verifier": {pkceVerifier}})
		m := res.json()
		if res.status != 200 || m["access_token"] == nil || m["token_type"] != "Bearer" {
			t.Fatal(res.status, m)
		}
		if _, ok := m["expires_in"].(float64); !ok {
			t.Fatal(m)
		}
	})

	run("exchanges a private-key JWT code when metadata cannot be cached", func(t *testing.T) {
		clientID := "https://connect.example.com/connectors/scl_test"
		jwksURI := "https://kms.example.com/.well-known/jwks.json"
		redirect := "http://localhost:5110/callback"
		kid := "vercel-connect-key"
		key := newRSAClientKey(t)
		ms.setJSON(clientID, map[string]any{"client_id": clientID, "client_name": "Vercel Connect Client",
			"redirect_uris": []any{redirect}, "token_endpoint_auth_method": "private_key_jwt", "application_type": "native",
			"grant_types": []any{"authorization_code"}, "response_types": []any{"code"}, "jwks_uri": jwksURI},
			"Cache-Control", "private, max-age=0, must-revalidate")
		ms.set(jwksURI, func(*http.Request) (*http.Response, error) { return jwksResponse(key, kid), nil })
		code := env.extractAuthorizationCode(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientID, redirect, ""))
		res := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
			"client_id": {clientID}, "client_assertion_type": {oauthcore.ClientAssertionType},
			"client_assertion": {signPrivateKeyJwtClientAssertion(t, clientID, tokenEndpoint, key.priv, kid)},
			"code_verifier":    {pkceVerifier}})
		if res.status != 200 || res.json()["access_token"] == nil {
			t.Fatal(res.status, string(res.body))
		}
		if ms.countURL(clientID) <= 1 || ms.countURL(jwksURI) == 0 {
			t.Fatal(ms.calledURLs())
		}
	})

	run("authenticates an uppercase URL client_id with a same-origin jwks_uri", func(t *testing.T) {
		clientID := "HTTPS://key-client.example.com/client-metadata.json"
		jwksURI := "https://key-client.example.com/.well-known/jwks.json"
		kid := "uppercase-url-client-key"
		redirect := "http://localhost:5106/callback"
		key := newRSAClientKey(t)
		ms.setJSON(clientID, map[string]any{"client_id": clientID, "client_name": "Uppercase URL Client",
			"redirect_uris": []any{redirect}, "token_endpoint_auth_method": "private_key_jwt", "application_type": "native",
			"grant_types": []any{"authorization_code"}, "response_types": []any{"code"}, "jwks_uri": jwksURI})
		ms.set(jwksURI, func(*http.Request) (*http.Response, error) { return jwksResponse(key, kid), nil })
		code := env.extractAuthorizationCode(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientID, redirect, ""))
		res := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
			"client_id": {clientID}, "client_assertion_type": {oauthcore.ClientAssertionType},
			"client_assertion": {signPrivateKeyJwtClientAssertion(t, clientID, tokenEndpoint, key.priv, kid)},
			"code_verifier":    {pkceVerifier}})
		if res.status != 200 || res.json()["access_token"] == nil {
			t.Fatal(res.status, string(res.body))
		}
		// The Go request URL normalises the scheme; the document was requested for the
		// uppercase client_id.
		if ms.countURL(clientID) == 0 || ms.countURL(jwksURI) == 0 {
			t.Fatal(ms.calledURLs())
		}
	})

	for _, kind := range []string{"redirected", "wrong-mime", "oversized"} {
		run("rejects a "+kind+" discovery-owned JWKS response", func(t *testing.T) {
			res, jwksURI := exchangeWithUnsafeJwksResponse(t, kind)
			if ms.countURL(jwksURI) == 0 {
				t.Fatal(ms.calledURLs())
			}
			if res.status < 400 {
				t.Fatal(res.status, string(res.body))
			}
		})
	}

	run("returns user claims from /oauth2/userinfo with a CIMD-issued access token", func(t *testing.T) {
		ms.setJSON(clientMetadataURL, metadataDocument)
		code := env.extractAuthorizationCode(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientMetadataURL, redirectURI, "openid email profile"))
		token := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			"client_id": {clientMetadataURL}, "code_verifier": {pkceVerifier}}).json()
		at, _ := token["access_token"].(string)
		if at == "" {
			t.Fatal(token)
		}
		h := http.Header{}
		h.Set("Authorization", "Bearer "+at)
		res := env.do("GET", "/oauth2/userinfo", nil, h)
		claims := res.json()
		if res.status != 200 || claims["sub"] == nil || claims["email"] != testUserEmail {
			t.Fatal(res.status, claims)
		}
	})

	run("refresh token grant mints a new access token for a CIMD client", func(t *testing.T) {
		ms.setJSON(clientMetadataURL, metadataDocument)
		code := env.extractAuthorizationCode(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientMetadataURL, redirectURI, "openid offline_access"))
		initial := exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			"client_id": {clientMetadataURL}, "code_verifier": {pkceVerifier}}).json()
		rt, _ := initial["refresh_token"].(string)
		if initial["access_token"] == nil || rt == "" {
			t.Fatal(initial)
		}
		res := exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientMetadataURL}})
		m := res.json()
		if res.status != 200 || m["access_token"] == nil || m["access_token"] == initial["access_token"] {
			t.Fatal(res.status, m)
		}
	})
}

func TestCimdRefreshPreservesAdminSetFlags(t *testing.T) {
	const (
		authServerBaseURL = "http://localhost:3103"
		clientMetadataURL = "https://mcp-client-refresh.example.com/client-metadata.json"
		redirectURI       = "http://localhost:5103/callback"
	)
	var mu sync.Mutex
	var refreshed []ClientRefreshedEvent
	ms := newMetadataServer()
	env := cimdEnv(t, authServerBaseURL, oauthprovider.Options{
		Scopes: []string{"openid", "profile", "email", "offline_access", "service:read"},
		ClientPrivileges: func(c oauthprovider.PrivilegeContext) (bool, error) {
			return c.Action == "update" || c.Action == "configure-client-credentials-scopes", nil
		},
	}, Options{
		// 0 makes every request stale, so the refresh path fires on the second authorize.
		MetadataRevalidationInterval: 0,
		MetadataFetchPolicy:          &MetadataFetchPolicy{MinimumFetchInterval: 0},
		FetchClientMetadataResource:  ms.fetch,
		OnClientRefreshed: func(ev ClientRefreshedEvent) error {
			mu.Lock()
			refreshed = append(refreshed, ev)
			mu.Unlock()
			return errNotificationSink
		},
	})

	t.Run("preserves server-owned flags and client_credentials scope authority across a stale refresh", func(t *testing.T) {
		pub, _, err := jose.GenerateKeyPair("ES256", jose.GenerateKeyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pj, _ := jose.JWKFromPublicKey(pub)
		jwk := jose.ExportJWK(pj)
		jwk.Set("kid", "refresh-preserve-key")
		jwk.Set("alg", "ES256")
		jwk.Set("use", "sig")
		ms.setJSON(clientMetadataURL, map[string]any{"client_id": clientMetadataURL, "client_name": "Refresh Preserve Test Client",
			"redirect_uris": []any{redirectURI}, "application_type": "native",
			"grant_types": []any{"authorization_code", "client_credentials"}, "response_types": []any{"code"},
			"clientCredentialsScopes": []any{"admin"}, "client_credentials_scopes": []any{"admin"}, "name": "Ignored internal alias",
			"token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{jwk}}})
		headers := env.signInWithTestUser()
		target := authorizeURL(authServerBaseURL, clientMetadataURL, redirectURI, "")
		if _, loc := env.authorizeStatus(headers, target); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
		// A discovered declaration never grants machine-to-machine scopes.
		if d := oauthprovider.ClientFromRecord(env.findClient(clientMetadataURL)); len(d.ClientCredentialsScopes) != 0 {
			t.Fatal(d.ClientCredentialsScopes)
		}
		// The administrative route is the only supported way to assign the server-owned
		// M2M ceiling on this unowned discovered client.
		upd := env.mustCall("adminUpdateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"client_id": clientMetadataURL, "update": map[string]any{"client_credentials_scopes": []any{"service:read"}}}})
		if !reflect.DeepEqual(upd["client_credentials_scopes"], []any{"service:read"}) {
			t.Fatal(upd)
		}
		// Admin-set lifecycle flags remain protected from metadata refresh.
		if _, err := env.db.Update(t.Context(), "oauthClient", eqClient(clientMetadataURL),
			adapter.Record{"disabled": true, "skipConsent": true, "enableEndSession": true}); err != nil {
			t.Fatal(err)
		}
		check := func(c *oauthprovider.SchemaClient) {
			t.Helper()
			if c == nil || !isSet(c.Disabled) || !isSet(c.SkipConsent) || !isSet(c.EnableEndSession) ||
				!reflect.DeepEqual(c.ClientCredentialsScopes, []string{"service:read"}) {
				t.Fatalf("%+v", c)
			}
		}
		check(oauthprovider.ClientFromRecord(env.findClient(clientMetadataURL)))
		// Second authorize triggers a stale refresh; the document carries none of the flags.
		env.authorizeStatus(headers, target)
		check(oauthprovider.ClientFromRecord(env.findClient(clientMetadataURL)))
		mu.Lock()
		defer mu.Unlock()
		// toHaveBeenCalledWith: some refresh notification carries the admin-set state.
		matched := false
		for _, ev := range refreshed {
			p := ev.PreviousClient
			if p != nil && isSet(p.Disabled) && isSet(p.SkipConsent) && isSet(p.EnableEndSession) &&
				reflect.DeepEqual(p.ClientCredentialsScopes, []string{"service:read"}) && ev.Client.ClientID == clientMetadataURL &&
				ev.Context != nil {
				if id, _ := ev.ClientMetadataDocument.Get("client_id"); id == clientMetadataURL {
					matched = true
				}
			}
		}
		if !matched {
			t.Fatal(len(refreshed))
		}
	})
}

func TestCimdMetadataDocumentURLPolicy(t *testing.T) {
	const (
		authServerBaseURL  = "http://localhost:3104"
		blockedClientURL   = "https://blocked.example.com/client-metadata.json"
		allowedClientURL   = "https://allowed.example.com/client-metadata.json"
		redirectURIBlocked = "http://localhost:5104/callback"
		redirectURIAllowed = "http://localhost:5105/callback"
	)
	ms := newMetadataServer()
	env := cimdEnv(t, authServerBaseURL, oauthprovider.Options{Scopes: []string{"openid", "profile", "email", "offline_access"}},
		Options{FetchClientMetadataResource: ms.fetch, IsMetadataDocumentURLAllowed: func(raw string, _ *betterauth.EndpointContext) (bool, error) {
			u, err := url.Parse(raw)
			return err == nil && u.Hostname() == "allowed.example.com", nil
		}})

	t.Run("rejects a URL blocked by isMetadataDocumentUrlAllowed before the fetch runs", func(t *testing.T) {
		ms.clear()
		status, _ := env.authorizeStatus(env.signInWithTestUser(), authorizeURL(authServerBaseURL, blockedClientURL, redirectURIBlocked, ""))
		if status < 400 || ms.countURL(blockedClientURL) != 0 {
			t.Fatal(status, ms.calledURLs())
		}
	})

	t.Run("allows a URL permitted by isMetadataDocumentUrlAllowed", func(t *testing.T) {
		ms.clear()
		ms.setJSON(allowedClientURL, map[string]any{"client_id": allowedClientURL, "client_name": "Allowed Fetch Client",
			"redirect_uris": []any{redirectURIAllowed}, "token_endpoint_auth_method": "none", "application_type": "native"})
		if _, loc := env.authorizeStatus(env.signInWithTestUser(), authorizeURL(authServerBaseURL, allowedClientURL, redirectURIAllowed, "")); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
	})
}

var errNotificationSink = errors.New("notification sink unavailable")

func eqClient(clientID string) []adapter.Where {
	return []adapter.Where{{Field: "clientId", Value: clientID}}
}

func isSet(b *bool) bool { return b != nil && *b }
