package oauthprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
)

// ---- register.test.ts (part 2) ----

// rgIATSpy records ValidateInitialAccessToken calls (vi.fn).
type rgIATSpy struct {
	mu    sync.Mutex
	calls []InitialAccessTokenContext
	impl  func(c InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error)
}

func (s *rgIATSpy) fn(c InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error) {
	s.mu.Lock()
	s.calls = append(s.calls, c)
	s.mu.Unlock()
	return s.impl(c)
}

func (s *rgIATSpy) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.calls) }

// rgPostJSON posts a JSON body with an optional Authorization header.
func rgPostJSON(env *testEnv, path, authorization string, body map[string]any) rgRes {
	env.t.Helper()
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	if authorization != "" {
		h.Set("Authorization", authorization)
	}
	res := env.do("POST", path, body, h)
	var data any
	_ = json.Unmarshal(res.body, &data)
	return rgRes{status: res.status, header: res.header, data: data, raw: res.body}
}

func TestRg_OauthRegisterProtectedDynamicRegistration(t *testing.T) {
	validIAT := "valid-initial-registration-token"
	redirectURI := "https://rp.example.com/api/auth/callback/test"
	spy := &rgIATSpy{impl: func(c InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error) {
		if c.InitialAccessToken == validIAT && c.ClientMetadata["client_name"] == "Machine Client" {
			return &InitialAccessTokenAuthorization{ReferenceID: "infra-provisioner"}, nil
		}
		return nil, nil
	}}
	env := newEnv(t, Options{AllowDynamicClientRegistration: true, ValidateInitialAccessToken: spy.fn})

	t.Run("should create confidential clients with a valid initial access token", func(t *testing.T) {
		r := rgPostJSON(env, "/oauth2/register", "Bearer "+validIAT, map[string]any{
			"client_name":               "Machine Client",
			"redirect_uris":             []any{redirectURI},
			"grant_types":               []any{"client_credentials"},
			"client_credentials_scopes": []any{"admin"},
			"clientCredentialsScopes":   []any{"admin"},
		})
		if r.status != 201 || r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("register: %d %v %s", r.status, r.header, r.raw)
		}
		b := r.m()
		rgExpectDefined(t, b, "client_id", "client_secret")
		rgEqual(t, b["grant_types"], []any{"client_credentials"})
		if b["reference_id"] != "infra-provisioner" || b["token_endpoint_auth_method"] != "client_secret_basic" {
			t.Fatalf("register: %s", r.raw)
		}
		rgExpectUndefined(t, b, "user_id", "client_credentials_scopes", "clientCredentialsScopes")
		stored := env.findOne("oauthClient", eq("clientId", b["client_id"]))
		rgEqual(t, rgJSONList(stored["clientCredentialsScopes"]), []any{})
		tok := env.token(url.Values{"grant_type": {"client_credentials"}}, basicAuth(b["client_id"].(string), b["client_secret"].(string)))
		if tok.status != 400 || tok.json()["error"] != "unauthorized_client" {
			t.Fatalf("token: %d %s", tok.status, tok.body)
		}
		found := false
		spy.mu.Lock()
		for _, c := range spy.calls {
			if c.InitialAccessToken == validIAT && c.ClientMetadata["client_name"] == "Machine Client" &&
				rgMatches(rgNorm(c.ClientMetadata["grant_types"]), []any{"client_credentials"}) {
				found = true
			}
		}
		spy.mu.Unlock()
		if !found {
			t.Fatalf("validator not called with expected args: %+v", spy.calls)
		}
	})

	t.Run("should reject invalid initial access tokens", func(t *testing.T) {
		r := rgPostJSON(env, "/oauth2/register", "Bearer invalid-initial-registration-token", map[string]any{
			"client_name": "Machine Client", "redirect_uris": []any{redirectURI}})
		if r.status != 401 || r.header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` ||
			r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" || r.m()["error"] != "invalid_token" {
			t.Fatalf("register: %d %v %s", r.status, r.header, r.raw)
		}
	})

	t.Run("should reject malformed initial access token headers", func(t *testing.T) {
		r := rgPostJSON(env, "/oauth2/register", "Bearer", map[string]any{
			"client_name": "Machine Client", "redirect_uris": []any{redirectURI}})
		if r.status != 400 || r.header.Get("WWW-Authenticate") != `Bearer error="invalid_request"` ||
			r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" || r.m()["error"] != "invalid_request" {
			t.Fatalf("register: %d %v %s", r.status, r.header, r.raw)
		}
	})

	t.Run("should reject initial access tokens when validation is not configured", func(t *testing.T) {
		nenv := newEnv(t, Options{AllowDynamicClientRegistration: true})
		r := rgPostJSON(nenv, "/oauth2/register", "Bearer "+validIAT, map[string]any{
			"client_name": "Machine Client", "redirect_uris": []any{redirectURI}})
		if r.status != 401 || r.header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` ||
			r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" || r.m()["error"] != "invalid_token" {
			t.Fatalf("register: %d %v %s", r.status, r.header, r.raw)
		}
	})

	t.Run("should register a confidential client_credentials client without redirect_uris", func(t *testing.T) {
		r := rgPostJSON(env, "/oauth2/register", "Bearer "+validIAT, map[string]any{
			"client_name": "Machine Client", "grant_types": []any{"client_credentials"}})
		if r.status != 201 {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		rgEqual(t, r.m()["grant_types"], []any{"client_credentials"})
	})

	t.Run("should reject an authorization_code registration without redirect_uris", func(t *testing.T) {
		r := rgPostJSON(env, "/oauth2/register", "Bearer "+validIAT, map[string]any{
			"client_name": "Machine Client", "grant_types": []any{"authorization_code"}})
		if r.status != 400 || r.m()["error"] != "invalid_redirect_uri" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("should answer a no-credentials request with a bare Bearer challenge", func(t *testing.T) {
		r := rgPostJSON(env, "/oauth2/register", "", map[string]any{
			"client_name": "Machine Client", "redirect_uris": []any{redirectURI}})
		if r.status != 401 || r.header.Get("WWW-Authenticate") != "Bearer" || r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("register: %d %v %s", r.status, r.header, r.raw)
		}
		if m := r.m(); m != nil && m["error"] != nil {
			t.Fatalf("expected no error field: %s", r.raw)
		}
	})

	t.Run("should create an unowned client when the validator returns no referenceId", func(t *testing.T) {
		oenv := newEnv(t, Options{AllowDynamicClientRegistration: true,
			ValidateInitialAccessToken: func(InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error) {
				return &InitialAccessTokenAuthorization{}, nil
			}})
		r := rgPostJSON(oenv, "/oauth2/register", "Bearer "+validIAT, map[string]any{
			"client_name": "Machine Client", "grant_types": []any{"client_credentials"}})
		if r.status != 201 {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
		rgExpectDefined(t, r.m(), "client_id")
		rgExpectUndefined(t, r.m(), "reference_id", "user_id")
	})

	t.Run("should fail closed when the validator throws", func(t *testing.T) {
		tenv := newEnv(t, Options{AllowDynamicClientRegistration: true,
			ValidateInitialAccessToken: func(InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error) {
				return nil, errors.New("validator failure")
			}})
		r := rgPostJSON(tenv, "/oauth2/register", "Bearer "+validIAT, map[string]any{
			"client_name": "Machine Client", "redirect_uris": []any{redirectURI}})
		desc, _ := r.m()["error_description"].(string)
		if r.status != 500 || r.m()["error"] != "server_error" || strings.Contains(desc, "validator failure") {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("passes through an APIError the validator throws", func(t *testing.T) {
		aenv := newEnv(t, Options{AllowDynamicClientRegistration: true,
			ValidateInitialAccessToken: func(InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error) {
				return nil, betterauth.NewAPIError("FORBIDDEN", jsonx.O("error", "access_denied", "error_description", "tenant suspended"))
			}})
		r := rgPostJSON(aenv, "/oauth2/register", "Bearer "+validIAT, map[string]any{
			"client_name": "Machine Client", "redirect_uris": []any{redirectURI}})
		if r.status != 403 || r.m()["error"] != "access_denied" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("should not consult the validator for session-backed registration", func(t *testing.T) {
		sspy := &rgIATSpy{impl: func(InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error) {
			return &InitialAccessTokenAuthorization{ReferenceID: "from-token"}, nil
		}}
		senv := newEnv(t, Options{AllowDynamicClientRegistration: true, ValidateInitialAccessToken: sspy.fn})
		c := rgClient{senv, senv.signInWithTestUser()}
		r := c.register(map[string]any{"client_name": "Session Client", "redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id", "user_id")
		if sspy.count() != 0 {
			t.Fatalf("validator called %d times", sspy.count())
		}
		rgExpectUndefined(t, r.m(), "reference_id")
	})

	t.Run("with the bearer plugin: a session bearer is the session, a non-session bearer is an initial access token", func(t *testing.T) {
		bearerIAT := "bearer-precedence-initial-access-token"
		bspy := &rgIATSpy{impl: func(c InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error) {
			if c.InitialAccessToken == bearerIAT {
				return &InitialAccessTokenAuthorization{ReferenceID: "infra-provisioner"}, nil
			}
			return nil, nil
		}}
		benv := newEnv(t, Options{AllowDynamicClientRegistration: true, ValidateInitialAccessToken: bspy.fn},
			envOptions{before: []*betterauth.Plugin{bearer.New()}})
		si := benv.do("POST", "/sign-in/email", map[string]any{"email": testUserEmail, "password": testUserPassword}, nil)
		sessionBearer := si.header.Get("set-auth-token")
		if sessionBearer == "" {
			t.Fatalf("no set-auth-token: %d %v %s", si.status, si.header, si.body)
		}
		sr := rgPostJSON(benv, "/oauth2/register", "Bearer "+sessionBearer, map[string]any{
			"client_name": "Session Bearer Client", "redirect_uris": []any{redirectURI}})
		if sr.status != 201 {
			t.Fatalf("session register: %d %s", sr.status, sr.raw)
		}
		if bspy.count() != 0 {
			t.Fatalf("validator called %d times", bspy.count())
		}
		rgExpectDefined(t, sr.m(), "user_id")
		rgExpectUndefined(t, sr.m(), "reference_id")
		tr := rgPostJSON(benv, "/oauth2/register", "Bearer "+bearerIAT, map[string]any{
			"client_name": "Machine Client", "grant_types": []any{"client_credentials"}})
		if tr.status != 201 {
			t.Fatalf("token register: %d %s", tr.status, tr.raw)
		}
		found := false
		bspy.mu.Lock()
		for _, c := range bspy.calls {
			if c.InitialAccessToken == bearerIAT {
				found = true
			}
		}
		bspy.mu.Unlock()
		if !found {
			t.Fatal("validator not called with the bearer IAT")
		}
		if tr.m()["reference_id"] != "infra-provisioner" {
			t.Fatalf("token register: %s", tr.raw)
		}
		rgExpectUndefined(t, tr.m(), "user_id")
	})
}

func TestRg_OauthRegisterApplicationType(t *testing.T) {
	env := newEnv(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true})
	register := func(body map[string]any) rgRes { return rgPostJSON(env, "/oauth2/register", "", body) }

	t.Run("maps applicationType as a first-class field without hiding it in metadata", func(t *testing.T) {
		stored := oauthToSchema(toObject(map[string]any{
			"client_id":        "mapping-client",
			"redirect_uris":    []any{"com.example.app:/callback"},
			"application_type": "native",
			"metadata":         map[string]any{"custom": "value"},
		}))
		if stored.ApplicationType != "native" {
			t.Fatalf("applicationType: %q", stored.ApplicationType)
		}
		if stored.Metadata != `{"custom":"value"}` {
			t.Fatalf("metadata: %q", stored.Metadata)
		}
		wire := rgNorm(SchemaToOAuth(stored)).(map[string]any)
		if wire["application_type"] != "native" || wire["custom"] != "value" {
			t.Fatalf("wire: %v", wire)
		}
		rgExpectUndefined(t, wire, "applicationType")
	})

	t.Run("keeps reserved client fields out of opaque metadata responses", func(t *testing.T) {
		reserved := map[string]any{
			"skipConsent":                      true,
			"enableEndSession":                 true,
			"requirePKCE":                      true,
			"clientSecret":                     "injected-secret",
			"referenceId":                      "injected-reference",
			"userId":                           "injected-user",
			"clientId":                         "injected-client",
			"applicationType":                  "native",
			"tokenEndpointAuthMethod":          "none",
			"redirectUris":                     []any{"https://evil.example.com/callback"},
			"postLogoutRedirectUris":           []any{"https://evil.example.com/logout"},
			"grantTypes":                       []any{"client_credentials"},
			"responseTypes":                    []any{"token"},
			"scopes":                           []any{"admin"},
			"clientCredentialsScopes":          []any{"admin"},
			"expiresAt":                        "2099-01-01T00:00:00.000Z",
			"createdAt":                        "2099-01-01T00:00:00.000Z",
			"updatedAt":                        "2099-01-01T00:00:00.000Z",
			"disabled":                         true,
			"name":                             "Injected name",
			"uri":                              "https://evil.example.com",
			"icon":                             "https://evil.example.com/icon.png",
			"contacts":                         []any{"attacker@example.com"},
			"tos":                              "https://evil.example.com/tos",
			"policy":                           "https://evil.example.com/policy",
			"softwareId":                       "injected-software",
			"softwareVersion":                  "99",
			"softwareStatement":                "injected-statement",
			"backchannelLogoutUri":             "https://evil.example.com/logout",
			"backchannelLogoutSessionRequired": true,
			"jwks":                             "injected-jwks",
			"jwksUri":                          "https://evil.example.com/jwks",
			"dpopBoundAccessTokens":            true,
			"subjectType":                      "pairwise",
			"public":                           true,
			"type":                             "native",
			"metadata":                         map[string]any{"nested": "injected"},
			"resources":                        []any{"https://api.example.com/stale"},
			"client_credentials_scopes":        []any{"admin"},
		}
		stored := oauthToSchema(toObject(map[string]any{
			"client_id":     "reserved-metadata-client",
			"redirect_uris": []any{"https://app.example.com/callback"},
			"metadata":      rgMerge(map[string]any{"custom": "preserved"}, reserved),
		}))
		var md any
		rawMd, _ := stored.Metadata.(string)
		_ = json.Unmarshal([]byte(rawMd), &md)
		rgEqual(t, md, map[string]any{"custom": "preserved"})
		wire := rgNorm(SchemaToOAuth(stored)).(map[string]any)
		if wire["custom"] != "preserved" {
			t.Fatalf("wire: %v", wire)
		}
		for field, injected := range reserved {
			if v, ok := wire[field]; ok && rgMatches(v, rgNorm(injected)) && rgMatches(rgNorm(injected), v) {
				t.Fatalf("reserved field %s leaked: %v", field, v)
			}
		}
	})

	t.Run("registers a native client with exact loopback hosts and custom-scheme redirect URIs", func(t *testing.T) {
		r := register(map[string]any{"application_type": "native", "token_endpoint_auth_method": "none",
			"redirect_uris": []any{"http://localhost:3005/callback", "http://127.0.0.1:3005/callback", "com.example.app:/callback"}})
		if r.status != 201 || r.m()["application_type"] != "native" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("rejects a native client with an http redirect URI on a routable host", func(t *testing.T) {
		r := register(map[string]any{"application_type": "native", "token_endpoint_auth_method": "none",
			"redirect_uris": []any{"http://example.com/callback"}})
		if r.status != 400 || r.m()["error"] != "invalid_redirect_uri" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("rejects alternate numeric spellings of the IPv4 loopback host", func(t *testing.T) {
		r := register(map[string]any{"application_type": "native", "token_endpoint_auth_method": "none",
			"redirect_uris": []any{"http://127.1/callback"}})
		if r.status != 400 || r.m()["error"] != "invalid_redirect_uri" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("rejects loopback back-channel logout targets", func(t *testing.T) {
		r := register(map[string]any{"application_type": "native", "token_endpoint_auth_method": "none",
			"redirect_uris": []any{"http://127.0.0.1/callback"}, "backchannel_logout_uri": "https://127.0.0.1/backchannel"})
		desc, _ := r.m()["error_description"].(string)
		if r.status != 400 || r.m()["error"] != "invalid_client_metadata" || !strings.Contains(desc, "private or reserved") {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("rejects a web client with an http redirect URI", func(t *testing.T) {
		r := register(map[string]any{"application_type": "web", "redirect_uris": []any{"http://example.com/callback"}})
		if r.status != 400 || r.m()["error"] != "invalid_redirect_uri" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("rejects a web client with a loopback redirect URI", func(t *testing.T) {
		for _, uri := range []string{"https://localhost:3005/callback", "https://localhost./callback", "https://localhost../callback"} {
			r := register(map[string]any{"application_type": "web", "redirect_uris": []any{uri}})
			if r.status != 400 || r.m()["error"] != "invalid_redirect_uri" {
				t.Fatalf("%s: %d %s", uri, r.status, r.raw)
			}
		}
	})

	t.Run("registers a web client with an https redirect URI", func(t *testing.T) {
		r := register(map[string]any{"application_type": "web", "redirect_uris": []any{"https://rp.example.com/callback"}})
		if r.status != 201 || r.m()["application_type"] != "web" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})

	t.Run("keeps application type and client authentication as orthogonal axes", func(t *testing.T) {
		r := register(map[string]any{"application_type": "native", "token_endpoint_auth_method": "client_secret_post",
			"redirect_uris": []any{"com.example.app:/callback"}})
		if r.status != 201 || r.m()["application_type"] != "native" || r.m()["token_endpoint_auth_method"] != "client_secret_post" {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
		rgExpectDefined(t, r.m(), "client_secret")
	})

	for _, uri := range []string{
		"file:///callback",
		"ftp://example.com/callback",
		"mailto:oauth@example.com",
		"myapp:/callback",
		"com.example.app:callback",
		"com.example.app:///callback",
		"com..example.app:/callback",
		"com.example..app:/callback",
		"com.example.-app:/callback",
		"com.example.app-:/callback",
		"com.example.app://host/callback",
		"https://localhost/callback",
		"https://localhost./callback",
		"https://localhost../callback",
		"http://localhost./callback",
		"http://localhost../callback",
		"https://127.0.0.1/callback",
		"http://example.com/callback",
		"http://192.168.1.2/callback",
		"http://tenant.localhost/callback",
		"http://127.42.7.9:49152/callback",
		"https://user:password@example.com/callback",
		"https://example.com/callback#fragment",
	} {
		t.Run("rejects invalid native redirect URI "+uri, func(t *testing.T) {
			r := register(map[string]any{"application_type": "native", "token_endpoint_auth_method": "none", "redirect_uris": []any{uri}})
			if r.status != 400 {
				t.Fatalf("register: %d %s", r.status, r.raw)
			}
		})
	}

	for _, uri := range []string{
		"http://localhost:54921/callback",
		"http://127.0.0.1:54921/callback",
		"http://[::1]:61234/callback",
		"com.example.app:/callback",
		"https://app.example.com/callback",
	} {
		t.Run("accepts valid native redirect URI "+uri, func(t *testing.T) {
			r := register(map[string]any{"application_type": "native", "token_endpoint_auth_method": "none", "redirect_uris": []any{uri}})
			if r.status != 201 {
				t.Fatalf("register: %d %s", r.status, r.raw)
			}
		})
	}

	t.Run("defaults omitted application_type to web and applies web redirect policy", func(t *testing.T) {
		rej := register(map[string]any{"redirect_uris": []any{"http://localhost:5000/api/auth/callback/test"}})
		if rej.status != 400 {
			t.Fatalf("rejected: %d %s", rej.status, rej.raw)
		}
		acc := register(map[string]any{"redirect_uris": []any{"https://rp.example.com/callback"}})
		if acc.status != 201 || acc.m()["application_type"] != "web" {
			t.Fatalf("accepted: %d %s", acc.status, acc.raw)
		}
	})
}
