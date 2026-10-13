package oauthprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of metadata.test.ts.

// pkNorm JSON round-trips v so values compare like JSON.
func pkNorm(t *testing.T, v any) any {
	t.Helper()
	b, err := jsonx.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// pkMatchObject is expect(actual).toMatchObject(expected) for flat JSON objects.
func pkMatchObject(t *testing.T, actual, expected any) {
	t.Helper()
	a, _ := pkNorm(t, actual).(map[string]any)
	e, _ := pkNorm(t, expected).(map[string]any)
	if a == nil {
		t.Fatalf("actual is not an object: %v", actual)
	}
	for k, ev := range e {
		if !reflect.DeepEqual(a[k], ev) {
			t.Errorf("%s: got %v, want %v", k, a[k], ev)
		}
	}
}

func pkStrs(v ...string) []any { return stringsToAny(v) }

type pkMetaOpts struct {
	opts     *Options
	jwt      *jwt.Options
	advanced *betterauth.AdvancedConfig
}

func pkMetaEnv(t *testing.T, mo pkMetaOpts) *testEnv {
	t.Helper()
	o := Options{AllowDynamicClientRegistration: true}
	if mo.opts != nil {
		o = *mo.opts
	}
	eo := envOptions{jwt: mo.jwt, noJwt: o.DisableJwtPlugin}
	if mo.advanced != nil {
		eo.mutate = func(c *betterauth.Config) { c.Advanced = mo.advanced }
	}
	return newEnv(t, o, eo)
}

func pkGetMeta(t *testing.T, env *testEnv, key string) map[string]any {
	t.Helper()
	return env.mustCall(key, betterauth.CallInput{})
}

func TestPk_OAuthMetadata(t *testing.T) {
	baseURL := testAuthBase
	authServerBaseURL := testBaseURL
	baseClaims := []string{"sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp", "name", "picture",
		"given_name", "family_name", "email", "email_verified"}
	authMethods := pkStrs("client_secret_basic", "client_secret_post", "private_key_jwt")

	t.Run("should get openid, equivalent auth server", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		pkMatchObject(t, metadata, map[string]any{
			"scopes_supported":                               pkStrs("openid", "profile", "email", "offline_access"),
			"issuer":                                         baseURL,
			"authorization_endpoint":                         baseURL + "/oauth2/authorize",
			"token_endpoint":                                 baseURL + "/oauth2/token",
			"jwks_uri":                                       baseURL + "/jwks",
			"registration_endpoint":                          baseURL + "/oauth2/register",
			"introspection_endpoint":                         baseURL + "/oauth2/introspect",
			"revocation_endpoint":                            baseURL + "/oauth2/revoke",
			"response_types_supported":                       pkStrs("code"),
			"response_modes_supported":                       pkStrs("query"),
			"grant_types_supported":                          pkStrs("authorization_code", "client_credentials", "refresh_token"),
			"token_endpoint_auth_methods_supported":          authMethods,
			"introspection_endpoint_auth_methods_supported":  authMethods,
			"revocation_endpoint_auth_methods_supported":     authMethods,
			"code_challenge_methods_supported":               pkStrs("S256"),
			"authorization_response_iss_parameter_supported": true,
			"dpop_signing_alg_values_supported":              pkStrs(oauthcore.DPoPSigningAlgorithms...),
			"backchannel_logout_supported":                   true,
			"backchannel_logout_session_supported":           true,
			"claims_supported":                               pkStrs(baseClaims...),
			"claims_parameter_supported":                     true,
			"userinfo_endpoint":                              baseURL + "/oauth2/userinfo",
			"subject_types_supported":                        pkStrs("public"),
			"acr_values_supported":                           pkStrs("0"),
			"id_token_signing_alg_values_supported":          pkStrs("EdDSA"),
			"end_session_endpoint":                           baseURL + "/oauth2/end-session",
			"prompt_values_supported":                        pkStrs("login", "consent", "create", "select_account", "none"),
		})
		oauthMetadata := pkGetMeta(t, env, "getOAuthServerConfig")
		pkMatchObject(t, oauthMetadata, metadata)
	})

	t.Run("should serve authorization server metadata at the issuer-appended well-known URL", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{})
		res := env.do("GET", baseURL+"/.well-known/oauth-authorization-server", nil, nil)
		if res.status != 200 || res.json()["issuer"] != baseURL {
			t.Fatalf("got %d %s", res.status, res.body)
		}
	})

	t.Run("should serve authorization server metadata at the RFC 8414 path-insertion URL", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{})
		res := env.do("GET", authServerBaseURL+"/.well-known/oauth-authorization-server/api/auth", nil, nil)
		if res.status != 200 || res.json()["issuer"] != baseURL {
			t.Fatalf("got %d %s", res.status, res.body)
		}
	})

	t.Run("should advertise dynamic client registration from direct OAuth metadata when enabled", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{Scopes: []string{"create:test"}, AllowDynamicClientRegistration: true}})
		res := env.do("GET", baseURL+"/.well-known/oauth-authorization-server", nil, nil)
		if res.status != 200 {
			t.Fatalf("got %d %s", res.status, res.body)
		}
		if res.json()["registration_endpoint"] != baseURL+"/oauth2/register" {
			t.Fatalf("registration_endpoint: %s", res.body)
		}
	})

	t.Run("should serve OIDC metadata at the direct issuer well-known URL", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{})
		res := env.do("GET", baseURL+"/.well-known/openid-configuration", nil, nil)
		if res.status != 200 || res.json()["issuer"] != baseURL {
			t.Fatalf("got %d %s", res.status, res.body)
		}
	})

	t.Run("should restrict direct metadata requests to GET and HEAD", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{})
		issuerAppended := baseURL + "/.well-known/oauth-authorization-server"
		pathInsertion := authServerBaseURL + "/.well-known/oauth-authorization-server/api/auth"
		openIDConfig := baseURL + "/.well-known/openid-configuration"
		for _, u := range []string{issuerAppended, pathInsertion} {
			res := env.do("HEAD", u, nil, nil)
			if res.status != 200 {
				t.Fatalf("HEAD %s: %d", u, res.status)
			}
			if len(res.body) != 0 {
				t.Fatalf("HEAD %s body: %q", u, res.body)
			}
		}
		for _, u := range []string{issuerAppended, pathInsertion, openIDConfig} {
			res := env.do("POST", u, nil, nil)
			if res.status != 405 {
				t.Fatalf("POST %s: %d", u, res.status)
			}
			if res.header.Get("Allow") != "GET, HEAD" {
				t.Fatalf("Allow: %q", res.header.Get("Allow"))
			}
		}
	})

	t.Run("should only skip trailing slashes when configured", func(t *testing.T) {
		u := authServerBaseURL + "/.well-known/oauth-authorization-server/api/auth/"
		env := pkMetaEnv(t, pkMetaOpts{})
		if res := env.do("GET", u, nil, nil); res.status != 404 {
			t.Fatalf("expected 404, got %d %s", res.status, res.body)
		}
		env2 := pkMetaEnv(t, pkMetaOpts{advanced: &betterauth.AdvancedConfig{SkipTrailingSlashes: true}})
		res := env2.do("GET", u, nil, nil)
		if res.status != 200 || res.json()["issuer"] != baseURL {
			t.Fatalf("got %d %s", res.status, res.body)
		}
	})

	t.Run("should not have an openid-configuration, has auth server configuration", func(t *testing.T) {
		scopes := []string{"create:test"}
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{Scopes: scopes, AllowDynamicClientRegistration: true}})
		if _, err := env.call("getOpenIdConfig", betterauth.CallInput{}); err == nil {
			t.Fatal("expected APIError")
		}
		oauthMetadata := pkGetMeta(t, env, "getOAuthServerConfig")
		pkMatchObject(t, oauthMetadata, map[string]any{
			"scopes_supported":                               pkStrs(scopes...),
			"issuer":                                         baseURL,
			"authorization_endpoint":                         baseURL + "/oauth2/authorize",
			"token_endpoint":                                 baseURL + "/oauth2/token",
			"jwks_uri":                                       baseURL + "/jwks",
			"registration_endpoint":                          baseURL + "/oauth2/register",
			"introspection_endpoint":                         baseURL + "/oauth2/introspect",
			"revocation_endpoint":                            baseURL + "/oauth2/revoke",
			"response_types_supported":                       pkStrs("code"),
			"response_modes_supported":                       pkStrs("query"),
			"grant_types_supported":                          pkStrs("authorization_code", "client_credentials", "refresh_token"),
			"token_endpoint_auth_methods_supported":          authMethods,
			"introspection_endpoint_auth_methods_supported":  authMethods,
			"revocation_endpoint_auth_methods_supported":     authMethods,
			"code_challenge_methods_supported":               pkStrs("S256"),
			"authorization_response_iss_parameter_supported": true,
			"backchannel_logout_supported":                   true,
			"backchannel_logout_session_supported":           true,
		})
	})

	t.Run("advertises back-channel logout as unsupported when the jwt plugin is disabled", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{AllowDynamicClientRegistration: true, DisableJwtPlugin: true}})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		if metadata["backchannel_logout_supported"] != false || metadata["backchannel_logout_session_supported"] != false {
			t.Fatalf("metadata: %v", metadata)
		}
	})

	t.Run("should not provide dynamic client registration endpoint when disabled", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{AllowDynamicClientRegistration: false}})
		if _, ok := pkGetMeta(t, env, "getOpenIdConfig")["registration_endpoint"]; ok {
			t.Fatal("openid registration_endpoint defined")
		}
		if _, ok := pkGetMeta(t, env, "getOAuthServerConfig")["registration_endpoint"]; ok {
			t.Fatal("oauth registration_endpoint defined")
		}
	})

	t.Run("should not provide dynamic client registration endpoint when undefined", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{}})
		if _, ok := pkGetMeta(t, env, "getOpenIdConfig")["registration_endpoint"]; ok {
			t.Fatal("openid registration_endpoint defined")
		}
		if _, ok := pkGetMeta(t, env, "getOAuthServerConfig")["registration_endpoint"]; ok {
			t.Fatal("oauth registration_endpoint defined")
		}
	})

	t.Run("should utilize advertised metadata fields", func(t *testing.T) {
		advertisedScopes := []string{"email"}
		advertisedClaims := []string{"sub", "iss", "aud", "exp", "iat", "scope"}
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{AllowDynamicClientRegistration: true,
			AdvertisedMetadata: &AdvertisedMetadata{ScopesSupported: advertisedScopes, ClaimsSupported: advertisedClaims}}})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		pkMatchObject(t, metadata, map[string]any{"scopes_supported": pkStrs(advertisedScopes...),
			"claims_supported": pkStrs(advertisedClaims...)})
		pkMatchObject(t, pkGetMeta(t, env, "getOAuthServerConfig"), metadata)
	})

	t.Run("should explicitly advertise unsupported request object parameters", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		if metadata["request_parameter_supported"] != false || metadata["request_uri_parameter_supported"] != false ||
			metadata["claims_parameter_supported"] != true {
			t.Fatalf("metadata: %v", metadata)
		}
	})

	t.Run("should advertise the unspecified ACR value by default", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		if !reflect.DeepEqual(metadata["acr_values_supported"], []any{"0"}) {
			t.Fatalf("acr_values_supported: %v", metadata["acr_values_supported"])
		}
	})

	t.Run("should fail if advertised scope invalid", func(t *testing.T) {
		env := newEnv(t, Options{AdvertisedMetadata: &AdvertisedMetadata{ScopesSupported: []string{"create:test"}}},
			envOptions{expectInitError: true})
		if env.initErr == nil || !strings.Contains(env.initErr.Error(), "advertisedMetadata.scopes_supported create:test not found in scopes") {
			t.Fatalf("init error: %v", env.initErr)
		}
	})

	t.Run("should advertise custom claims", func(t *testing.T) {
		claims := append(append([]string{}, baseClaims...), "http://example.com/roles")
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{AllowDynamicClientRegistration: true,
			AdvertisedMetadata: &AdvertisedMetadata{ClaimsSupported: claims}}})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		pkMatchObject(t, metadata, map[string]any{"claims_supported": pkStrs(claims...)})
		pkMatchObject(t, pkGetMeta(t, env, "getOAuthServerConfig"), metadata)
	})

	t.Run("should use the remoteJwks url", func(t *testing.T) {
		remoteURL := "http://example.com/.well-known/openid-configuration"
		alg := "ES256"
		env := pkMetaEnv(t, pkMetaOpts{jwt: &jwt.Options{JWKS: &jwt.JWKSOptions{RemoteURL: remoteURL,
			KeyPairConfig: &jwt.JWKOptions{Alg: alg}}}})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		pkMatchObject(t, metadata, map[string]any{"jwks_uri": remoteURL, "id_token_signing_alg_values_supported": pkStrs(alg)})
		pkMatchObject(t, pkGetMeta(t, env, "getOAuthServerConfig"), metadata)
	})

	t.Run("should support disableJwtPlugin", func(t *testing.T) {
		env := pkMetaEnv(t, pkMetaOpts{opts: &Options{AllowDynamicClientRegistration: true, DisableJwtPlugin: true}})
		metadata := pkGetMeta(t, env, "getOpenIdConfig")
		pkMatchObject(t, metadata, map[string]any{"id_token_signing_alg_values_supported": pkStrs("HS256")})
		pkMatchObject(t, pkGetMeta(t, env, "getOAuthServerConfig"), metadata)
	})
}

func TestPk_DynamicBaseURLMetadataWrappers(t *testing.T) {
	host := "tenant.example.com"
	expectedBaseURL := "https://" + host + "/api/auth"
	env := newEnv(t, Options{}, envOptions{mutate: func(c *betterauth.Config) {
		c.BaseURL = ""
		c.DynamicBaseURL = &betterauth.DynamicBaseURL{AllowedHosts: []string{host}, Protocol: "https",
			Fallback: "https://fallback.example.com"}
	}})
	check := func(t *testing.T, res *betterauth.Response, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != 200 {
			t.Fatalf("status %d", res.Status)
		}
		var body map[string]any
		_ = json.Unmarshal(res.Body, &body)
		if body["issuer"] != expectedBaseURL {
			t.Fatalf("issuer: %v", body["issuer"])
		}
	}
	t.Run("oauthProviderAuthServerMetadata resolves baseURL from the incoming request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://"+host+"/.well-known/oauth-authorization-server", nil)
		res, err := OAuthProviderAuthServerMetadata(env.auth, nil)(req)
		check(t, res, err)
	})
	t.Run("oauthProviderOpenIdConfigMetadata resolves baseURL from the incoming request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://"+host+"/.well-known/openid-configuration", nil)
		res, err := OAuthProviderOpenIDConfigMetadata(env.auth, nil)(req)
		check(t, res, err)
	})
}

func TestPk_OAuthResourceMetadata(t *testing.T) {
	authServerBaseURL := testBaseURL
	validResource := "https://myapi.example.com"
	f := false
	env := newEnv(t, Options{Resources: []ResourceInput{{Identifier: validResource}}, EnforcePerClientResources: &f,
		Scopes: []string{"openid", "profile", "email", "offline_access", "read:posts"}},
		envOptions{jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: authServerBaseURL}}})
	rc := NewResourceClient(env.auth)

	t.Run("should provide resource discovery configuration", func(t *testing.T) {
		md, err := rc.GetProtectedResourceMetadata(jsonx.O("resource", validResource), nil)
		if err != nil {
			t.Fatal(err)
		}
		pkMatchObject(t, md, map[string]any{"resource": validResource, "authorization_servers": pkStrs(authServerBaseURL),
			"dpop_signing_alg_values_supported": pkStrs(oauthcore.DPoPSigningAlgorithms...)})
	})
	t.Run("should allow overwriting any field", func(t *testing.T) {
		anotherIssuer := "https://admin.example.com"
		anotherResource := "https://another-api.example.com"
		md, err := rc.GetProtectedResourceMetadata(jsonx.O("resource", anotherResource,
			"authorization_servers", pkStrs(anotherIssuer)), nil)
		if err != nil {
			t.Fatal(err)
		}
		pkMatchObject(t, md, map[string]any{"resource": anotherResource, "authorization_servers": pkStrs(anotherIssuer)})
	})
	t.Run("should not support 'openid' scope", func(t *testing.T) {
		if _, err := rc.GetProtectedResourceMetadata(jsonx.O("resource", validResource,
			"scopes_supported", pkStrs("openid")), nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("should pass with supported scopes", func(t *testing.T) {
		md, err := rc.GetProtectedResourceMetadata(jsonx.O("resource", validResource,
			"scopes_supported", pkStrs("read:posts")), nil)
		if err != nil {
			t.Fatal(err)
		}
		pkMatchObject(t, md, map[string]any{"resource": validResource, "authorization_servers": pkStrs(authServerBaseURL),
			"scopes_supported": pkStrs("read:posts")})
	})
	t.Run("should fail unsupported scope", func(t *testing.T) {
		if _, err := rc.GetProtectedResourceMetadata(jsonx.O("resource", validResource,
			"scopes_supported", pkStrs("write:posts")), nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("should pass with externally available scopes", func(t *testing.T) {
		another := "https://auth.example.com"
		md, err := rc.GetProtectedResourceMetadata(jsonx.O("resource", validResource,
			"authorization_servers", pkStrs(authServerBaseURL, another),
			"scopes_supported", pkStrs("read:posts", "write:posts")), []string{"write:posts"})
		if err != nil {
			t.Fatal(err)
		}
		pkMatchObject(t, md, map[string]any{"resource": validResource,
			"authorization_servers": pkStrs(authServerBaseURL, another),
			"scopes_supported":      pkStrs("read:posts", "write:posts")})
	})
}
