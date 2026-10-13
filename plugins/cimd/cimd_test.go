package cimd

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/cimd.test.ts. The stubbed global fetch becomes the plugin's
// metadata transport (metadataServer); the listhen server that only re-exposed the auth
// handler is not needed.

func createClientRecord(t *testing.T, env *testEnv, c *oauthprovider.SchemaClient) *oauthprovider.SchemaClient {
	t.Helper()
	now := time.Now()
	c.CreatedAt, c.UpdatedAt = &now, &now
	rec := c.ToRecord()
	if c.ClientDiscoveryID == "" {
		rec["clientDiscoveryId"] = nil
	}
	out, err := env.db.Create(context.Background(), adapter.CreateInput{Model: "oauthClient", Data: rec})
	if err != nil {
		t.Fatal(err)
	}
	return oauthprovider.ClientFromRecord(out)
}

func TestCimdIntegration(t *testing.T) {
	const (
		authServerBaseURL = "http://localhost:3002"
		redirectURI       = "http://localhost:5002/api/auth/oauth2/callback/cimd-test"
		clientMetadataURL = "https://mcp-client.example.com/client-metadata.json"
	)
	metadataDocument := map[string]any{"client_id": clientMetadataURL, "client_name": "Test MCP Client",
		"redirect_uris": []any{redirectURI}, "token_endpoint_auth_method": "none", "application_type": "native",
		"grant_types": []any{"authorization_code"}, "response_types": []any{"code"}}
	ms := newMetadataServer()
	po := oauthprovider.Options{Scopes: []string{"openid", "profile", "email", "offline_access"}}
	env := cimdEnv(t, authServerBaseURL, po, Options{FetchClientMetadataResource: ms.fetch})
	t.Cleanup(ms.clear)

	t.Run("should auto-create a public client from a URL client_id on authorize", func(t *testing.T) {
		ms.clear()
		ms.setJSON(clientMetadataURL, metadataDocument)
		headers := env.signInWithTestUser()
		_, loc := env.authorizeStatus(headers, authorizeURL(authServerBaseURL, clientMetadataURL, redirectURI, ""))
		if !strings.Contains(loc, "/consent") || !strings.Contains(loc, "client_id="+url.QueryEscape(clientMetadataURL)) {
			t.Fatal(loc)
		}
		stored := env.findClient(clientMetadataURL)
		if stored["applicationType"] != "native" || stored["clientDiscoveryId"] != "cimd" {
			t.Fatal(stored)
		}
	})

	t.Run("does not fetch or take over an existing managed HTTPS client", func(t *testing.T) {
		ms.clear()
		managed := "https://managed-client.example.com/client-metadata.json"
		createClientRecord(t, env, &oauthprovider.SchemaClient{ClientID: managed, Name: "Managed HTTPS Client",
			RedirectURIs: []string{redirectURI}, TokenEndpointAuthMethod: "none", ApplicationType: "native",
			GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}})
		ms.set(managed, func(*http.Request) (*http.Response, error) {
			return nil, errors.New("managed client must not use CIMD transport")
		})
		headers := env.signInWithTestUser()
		_, loc := env.authorizeStatus(headers, authorizeURL(authServerBaseURL, managed, redirectURI, ""))
		if !strings.Contains(loc, "/consent") || ms.callCount() != 0 {
			t.Fatal(loc, ms.callCount())
		}
	})

	t.Run("refreshes a discovered client with a fresh resolver after cache restart", func(t *testing.T) {
		restarted := "https://restarted-client.example.com/client-metadata.json"
		existing := createClientRecord(t, env, &oauthprovider.SchemaClient{ClientID: restarted, ClientDiscoveryID: "cimd",
			Name: "Before Restart", RedirectURIs: []string{redirectURI}, TokenEndpointAuthMethod: "none", ApplicationType: "native",
			GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}})
		transport := newMetadataServer()
		transport.setJSON(restarted, map[string]any{"client_id": restarted, "client_name": "After Restart",
			"redirect_uris": []any{redirectURI}, "token_endpoint_auth_method": "none", "application_type": "native",
			"grant_types": []any{"authorization_code"}, "response_types": []any{"code"}})
		d, err := CreateCimdClientDiscovery(Options{FetchClientMetadataResource: transport.fetch})
		if err != nil {
			t.Fatal(err)
		}
		refreshed, err := d.Resolve(&betterauth.EndpointContext{Auth: env.auth.Context()}, restarted, existing)
		if err != nil {
			t.Fatal(err)
		}
		if transport.callCount() != 1 || refreshed.Name != "After Restart" || refreshed.ClientDiscoveryID != "cimd" {
			t.Fatal(transport.callCount(), refreshed)
		}
	})

	t.Run("persists an omitted application_type as null", func(t *testing.T) {
		omitted := "https://web-client.example.com/client-metadata.json"
		redirect := "http://localhost:5199/callback"
		ms.clear()
		ms.setJSON(omitted, map[string]any{"client_id": omitted, "client_name": "Application Type Omission Client",
			"redirect_uris": []any{redirect}, "token_endpoint_auth_method": "none"})
		env.authorizeStatus(env.signInWithTestUser(), authorizeURL(authServerBaseURL, omitted, redirect, ""))
		stored := env.findClient(omitted)
		if stored == nil {
			t.Fatal("client not stored")
		}
		if v, ok := stored["applicationType"]; ok && v != nil {
			t.Fatal(v)
		}
	})

	t.Run("should complete authorize and consent flow with a CIMD client", func(t *testing.T) {
		ms.clear()
		ms.setJSON(clientMetadataURL, metadataDocument)
		headers := env.signInWithTestUser()
		_, loc := env.authorizeStatus(headers, authorizeURL(authServerBaseURL, clientMetadataURL, redirectURI, ""))
		if !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
		u, _ := url.Parse(loc)
		res := env.do("POST", "/oauth2/consent", map[string]any{"accept": true,
			"oauth_query": oauthprovider.BuildSignedOAuthQuery("?" + u.RawQuery)}, headers)
		m := res.json()
		cb, _ := m["url"].(string)
		if m["redirect"] != true || !strings.Contains(cb, redirectURI) || !strings.Contains(cb, "code=") {
			t.Fatal(res.status, m)
		}
	})

	t.Run("should advertise client_id_metadata_document_supported in discovery", func(t *testing.T) {
		cfg := env.mustCall("getOAuthServerConfig", betterauth.CallInput{})
		if cfg["client_id_metadata_document_supported"] != true {
			t.Fatal(cfg)
		}
		if _, ok := cfg["registration_endpoint"]; ok {
			t.Fatal(cfg["registration_endpoint"])
		}
	})

	t.Run("should reject metadata document where client_id does not match URL", func(t *testing.T) {
		mismatched := "https://mismatch.example.com/client-metadata.json"
		ms.clear()
		ms.setJSON(mismatched, map[string]any{"client_id": "https://wrong.example.com/other.json", "client_name": "Mismatched Client",
			"redirect_uris": []any{"https://mismatch.example.com/callback"}, "token_endpoint_auth_method": "none"})
		status, _ := env.authorizeStatus(env.signInWithTestUser(), authorizeURL(authServerBaseURL, mismatched, "https://mismatch.example.com/callback", ""))
		if status < 400 {
			t.Fatal(status)
		}
	})

	t.Run("enforces application_type redirect URI constraints from the metadata document", func(t *testing.T) {
		native := "https://native.example.com/client-metadata.json"
		loopback := "http://127.0.0.1:5099/callback"
		ms.clear()
		// A loopback interception redirect belongs to a native client; declaring web
		// contradicts it.
		ms.setJSON(native, map[string]any{"client_id": native, "client_name": "Mislabelled Native Client",
			"application_type": "web", "redirect_uris": []any{loopback}, "token_endpoint_auth_method": "none"})
		status, _ := env.authorizeStatus(env.signInWithTestUser(), authorizeURL(authServerBaseURL, native, loopback, ""))
		if status < 400 {
			t.Fatal(status)
		}
	})

	t.Run("allows a cross-origin registered redirect but rejects a different authorization redirect", func(t *testing.T) {
		clientID := "https://distributed-client.example/client.json"
		registered := "https://callback.example/callback"
		requested := "https://callback.example/other"
		ms.clear()
		ms.setJSON(clientID, map[string]any{"client_id": clientID, "client_name": "Distributed Client",
			"redirect_uris": []any{registered}, "application_type": "web", "token_endpoint_auth_method": "none"})
		status, loc := env.authorizeStatus(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientID, requested, ""))
		if status != 302 || !strings.Contains(loc, "error=") || strings.Contains(loc, "/consent") || strings.Contains(loc, "code=") {
			t.Fatal(status, loc)
		}
		stored := oauthprovider.ClientFromRecord(env.findClient(clientID))
		if stored == nil || !reflect.DeepEqual(stored.RedirectURIs, []string{registered}) {
			t.Fatal(stored)
		}
	})

	t.Run("accepts same-origin private_key_jwt key discovery without unrelated trustedOrigins", func(t *testing.T) {
		clientID := "https://key-client.example.com/client-metadata.json"
		redirect := "https://key-client.example.com/callback"
		ms.clear()
		ms.setJSON(clientID, map[string]any{"client_id": clientID, "client_name": "Key-authenticated Client",
			"redirect_uris": []any{redirect}, "application_type": "web", "token_endpoint_auth_method": "private_key_jwt",
			"jwks_uri": "https://key-client.example.com/.well-known/jwks.json", "grant_types": []any{"authorization_code"},
			"response_types": []any{"code"}})
		_, loc := env.authorizeStatus(env.signInWithTestUser(), authorizeURL(authServerBaseURL, clientID, redirect, ""))
		if !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
		stored := env.findClient(clientID)
		if stored["tokenEndpointAuthMethod"] != "private_key_jwt" || stored["jwksUri"] != "https://key-client.example.com/.well-known/jwks.json" {
			t.Fatal(stored)
		}
	})
}
