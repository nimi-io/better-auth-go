package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/cimd"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// CIMD profile (mirrors e2e/servers/profiles/cimd.mjs): the OAuth provider with Client ID
// Metadata Documents. The metadata transport is an in-memory fake (cimdE2EDocuments, the
// same table as the TS profile): documents are served with Cache-Control: no-cache and an
// ETag, and conditional requests are answered with 304.

const cimdE2EETag = `"v1"`

var cimdE2EDocuments = map[string]map[string]any{
	"https://client.e2e.example/client.json": {
		"client_id": "https://client.e2e.example/client.json", "client_name": "E2E CIMD Client",
		"client_uri": "https://client.e2e.example/", "redirect_uris": []any{"https://client.e2e.example/callback"},
		"token_endpoint_auth_method": "none", "application_type": "web",
		"grant_types": []any{"authorization_code", "refresh_token"}, "response_types": []any{"code"},
	},
	"https://native.e2e.example/client.json": {
		"client_id": "https://native.e2e.example/client.json", "client_name": "E2E Native Client",
		"redirect_uris": []any{"http://127.0.0.1:7777/callback"}, "application_type": "native",
	},
	"https://mismatch.e2e.example/client.json": {
		"client_id": "https://other.e2e.example/client.json", "client_name": "Mismatch",
		"redirect_uris": []any{"https://mismatch.e2e.example/callback"},
	},
	"https://secret.e2e.example/client.json": {
		"client_id": "https://secret.e2e.example/client.json", "client_name": "Secret",
		"redirect_uris": []any{"https://secret.e2e.example/callback"}, "token_endpoint_auth_method": "client_secret_basic",
	},
	"https://forbidden.e2e.example/client.json": {
		"client_id": "https://forbidden.e2e.example/client.json", "client_name": "Forbidden",
		"redirect_uris": []any{"https://forbidden.e2e.example/callback"}, "skip_consent": true,
	},
	"https://plain.e2e.example/client.json": {
		"client_id": "https://plain.e2e.example/client.json", "client_name": "Plain",
		"redirect_uris": []any{"https://plain.e2e.example/callback"},
	},
}

func cimdE2EFetch(req *http.Request) (*http.Response, error) {
	doc, ok := cimdE2EDocuments[req.URL.String()]
	if !ok {
		return nil, errors.New("network error")
	}
	h := http.Header{}
	h.Set("Cache-Control", "no-cache")
	if req.Header.Get("If-None-Match") == cimdE2EETag {
		return &http.Response{StatusCode: 304, Header: h, Body: http.NoBody}, nil
	}
	b, _ := json.Marshal(doc)
	if req.URL.Host == "plain.e2e.example" {
		h = http.Header{}
		h.Set("Content-Type", "text/plain")
	} else {
		h.Set("Content-Type", "application/json")
		h.Set("Etag", cimdE2EETag)
	}
	return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func init() {
	profiles["cimd"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, jwt.New(), oauthprovider.New(oauthprovider.Options{
			LoginPage:   "/login",
			ConsentPage: "/consent",
		}), cimd.MustNew(cimd.Options{
			FetchClientMetadataResource: cimdE2EFetch,
			MetadataFetchPolicy:         &cimd.MetadataFetchPolicy{MinimumFetchInterval: 0},
		}))
	}
}
