package oauthprovider

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/internal/testdb"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/plugins/genericoauth"
)

// Port of private-key-jwt-e2e.test.ts: a relying party (generic-oauth with
// tokenEndpointAuth private_key_jwt) signs in against the provider. The RP reaches the
// provider through oauth2.HTTPClient routed to the test env.

// pkPrivateKeyJwtAssertionGetter mirrors createPrivateKeyJwtClientAssertionGetter.
func pkPrivateKeyJwtAssertionGetter(priv any, kid, alg string) func(clientID, tokenEndpoint, grantType string) (string, error) {
	return func(clientID, tokenEndpoint, _ string) (string, error) {
		now := time.Now().Unix()
		return jose.SignJWT(jsonx.O("alg", alg, "kid", kid),
			jsonx.O("iss", clientID, "sub", clientID, "aud", tokenEndpoint, "iat", now, "exp", now+120, "jti", pkUUID()), priv)
	}
}

type pkRP struct {
	t    *testing.T
	auth *betterauth.Auth
	base string
}

// pkNewRP builds the relying party instance (getTestInstance with genericOAuth).
func pkNewRP(t *testing.T, base string, cfg genericoauth.Config, providerID string) *pkRP {
	t.Helper()
	conn := testdb.SQLite(t)
	f := false
	a, err := betterauth.New(betterauth.Config{
		BaseURL:        base,
		Secret:         "better-auth.secret-for-tests-1234567890abcdef",
		Database:       sqladapter.New(conn, sqladapter.Config{}),
		Logger:         betterauth.NopLogger{},
		RateLimit:      &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		TrustedOrigins: []string{base},
		Account: &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{
			TrustedProviders: []string{providerID}, RequireLocalEmailVerified: &f}},
		Plugins: []*betterauth.Plugin{genericoauth.New(genericoauth.Options{Config: []genericoauth.Config{cfg}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RunMigrations(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &pkRP{t: t, auth: a, base: base}
}

func (rp *pkRP) do(method, target string, body any, headers http.Header) *response {
	rp.t.Helper()
	if !strings.HasPrefix(target, "http") {
		target = rp.base + "/api/auth" + target
	}
	var rd *bytes.Reader
	if body != nil {
		b, _ := jsonx.Marshal(body)
		rd = bytes.NewReader(b)
	}
	var req *http.Request
	if rd != nil {
		req = httptest.NewRequest(method, target, rd)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if method != http.MethodGet && req.Header.Get("Origin") == "" {
		req.Header.Set("Origin", rp.base)
	}
	rec := httptest.NewRecorder()
	rp.auth.Handler().ServeHTTP(rec, req)
	return &response{status: rec.Code, header: rec.Header(), body: rec.Body.Bytes()}
}

func TestPk_PrivateKeyJwtE2E(t *testing.T) {
	rpBaseURL := "http://localhost:5002"
	providerID := "jwt-assertion-provider"
	key := pkGenRSA(t)
	authServerBaseURL := testBaseURL
	env := newEnv(t, Options{AssertionMaxLifetime: 300}, envOptions{mutate: func(c *betterauth.Config) {
		c.TrustedOrigins = append(c.TrustedOrigins, "https://trusted.example.com")
	}})
	// handler: rewrite the root OpenID configuration path to the auth handler.
	asHandler := env.auth.Handler()
	env.serveHost("localhost:3000", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			r.URL.Path = "/api/auth/.well-known/openid-configuration"
			r.RequestURI = r.URL.RequestURI()
		}
		asHandler.ServeHTTP(w, r)
	}))
	prevOAuth2 := oauth2.HTTPClient
	oauth2.HTTPClient = &http.Client{Transport: env, CheckRedirect: prevOAuth2.CheckRedirect}
	t.Cleanup(func() { oauth2.HTTPClient = prevOAuth2 })

	redirectURI := rpBaseURL + "/api/auth/callback/" + providerID
	headers := env.signInWithTestUser()
	oauthClient := env.adminCreateClient(headers, map[string]any{
		"redirect_uris": []any{redirectURI}, "application_type": "native", "skip_consent": true,
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks":                       map[string]any{"keys": []any{pkJwkWith(key.publicJwk, "kid", "e2e-key-1", "alg", "RS256", "use", "sig")}},
	})
	if oauthClient["client_id"] == nil || oauthClient["client_secret"] != nil {
		t.Fatalf("client: %v", oauthClient)
	}
	oauthJwksURIClient := env.adminCreateClient(headers, map[string]any{
		"redirect_uris": []any{redirectURI}, "application_type": "native", "skip_consent": true,
		"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://trusted.example.com/.well-known/jwks.json",
	})
	if oauthJwksURIClient["client_id"] == nil || oauthJwksURIClient["client_secret"] != nil {
		t.Fatalf("jwks_uri client: %v", oauthJwksURIClient)
	}

	pkce := true
	rpConfig := func(clientID string) genericoauth.Config {
		return genericoauth.Config{
			ProviderID: providerID, ClientID: clientID, RedirectURI: redirectURI,
			DiscoveryURL: authServerBaseURL + "/.well-known/openid-configuration",
			Scopes:       []string{"openid", "profile", "email"}, PKCE: &pkce,
			TokenEndpointAuth: &oauth2.TokenEndpointAuth{Method: oauth2.AuthPrivateKeyJWT,
				GetClientAssertion: pkPrivateKeyJwtAssertionGetter(key.priv, "e2e-key-1", "RS256")},
		}
	}

	// runFlow performs the full sign-in and returns the RP callback Location.
	runFlow := func(t *testing.T, rp *pkRP, clientID string) string {
		t.Helper()
		signIn := rp.do("POST", "/sign-in/social", map[string]any{"provider": providerID, "callbackURL": "/success"}, nil)
		if signIn.status != 200 {
			t.Fatalf("sign-in/social: %d %s", signIn.status, signIn.body)
		}
		rpHeaders := cookieHeader(signIn.header)
		signInURL, _ := signIn.json()["url"].(string)
		if !strings.Contains(signInURL, authServerBaseURL+"/api/auth/oauth2/authorize") ||
			!strings.Contains(signInURL, "client_id="+clientID) {
			t.Fatalf("sign-in url: %s", signInURL)
		}
		authz := env.do("GET", signInURL, nil, nil)
		loginRedirect := authz.location()
		if !strings.Contains(loginRedirect, "/login") {
			t.Fatalf("authorize: %d %q %s", authz.status, loginRedirect, authz.body)
		}
		lu, err := url.Parse(loginRedirect)
		if err != nil {
			t.Fatal(err)
		}
		// oauthProviderClient adds window.location.search as oauth_query.
		signInRes := env.do("POST", "/sign-in/email", map[string]any{"email": testUserEmail, "password": testUserPassword,
			"oauth_query": BuildSignedOAuthQuery("?" + lu.RawQuery)}, nil)
		m := signInRes.json()
		u, _ := m["url"].(string)
		if m["redirect"] != true || !strings.Contains(u, rpBaseURL) {
			t.Fatalf("sign-in/email: %d %s", signInRes.status, signInRes.body)
		}
		cb := rp.do("GET", u, nil, rpHeaders)
		return cb.location()
	}

	t.Run("should complete full sign-in flow using private_key_jwt across RP and provider", func(t *testing.T) {
		clientID := oauthClient["client_id"].(string)
		rp := pkNewRP(t, rpBaseURL, rpConfig(clientID), providerID)
		if cb := runFlow(t, rp, clientID); !strings.Contains(cb, "/success") || strings.Contains(cb, "error=") {
			t.Fatalf("callback: %q", cb)
		}
	})

	t.Run("should complete full sign-in flow using a trusted jwks_uri client", func(t *testing.T) {
		var mu sync.Mutex
		var fetched, accepts []string
		env.serveHost("trusted.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			fetched = append(fetched, "https://"+r.Host+r.URL.Path)
			accepts = append(accepts, r.Header.Get("Accept"))
			mu.Unlock()
			w.Header().Set("content-type", "application/json")
			b, _ := jsonx.Marshal(jsonx.O("keys", []any{pkJwkWith(key.publicJwk, "kid", "e2e-key-1", "alg", "RS256", "use", "sig")}))
			_, _ = w.Write(b)
		}))
		clientID := oauthJwksURIClient["client_id"].(string)
		rp := pkNewRP(t, rpBaseURL, rpConfig(clientID), providerID)
		cb := runFlow(t, rp, clientID)
		mu.Lock()
		if len(fetched) == 0 || fetched[0] != "https://trusted.example.com/.well-known/jwks.json" || accepts[0] != "application/json" {
			t.Fatalf("jwks fetches: %v %v", fetched, accepts)
		}
		mu.Unlock()
		if !strings.Contains(cb, "/success") || strings.Contains(cb, "error=") {
			t.Fatalf("callback: %q", cb)
		}
	})
}
