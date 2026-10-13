package oauthprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/extensions.test.ts.

// dxExtPlugin is a plugin whose init calls extendOAuthProvider with each extension.
func dxExtPlugin(id string, exts ...*Extension) *betterauth.Plugin {
	return &betterauth.Plugin{
		ID: id,
		Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			for _, e := range exts {
				if err := ExtendOAuthProvider(ac, e); err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
	}
}

func dxUnreachableGrant(GrantHandlerInput) (any, error) {
	return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "invalid_request", "error_description", "unreachable test grant"))
}

func dxUnreachableAuth(ClientAuthenticationInput) (*ClientAuthenticationResult, error) {
	return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "invalid_request", "error_description", "unreachable test authentication"))
}

func dxExpectInitError(t *testing.T, contains string, plugins ...*betterauth.Plugin) {
	t.Helper()
	env := newEnv(t, Options{}, envOptions{jwt: dxJwtIssuer(testBaseURL), plugins: plugins, expectInitError: true})
	if env.initErr == nil || !strings.Contains(env.initErr.Error(), contains) {
		t.Fatalf("expected init error containing %q, got %v", contains, env.initErr)
	}
}

func dxDescription(err *betterauth.APIError) string {
	s, _ := errBody(err)["error_description"].(string)
	return s
}

func TestDx_Extensions(t *testing.T) {
	resource := "https://vc.example.com/credential"
	redirectURI := "https://client.example.com/callback"
	extensionGrant := "urn:better-auth:test:grant"
	extensionOpaqueGrant := "urn:better-auth:test:opaque-grant"
	extensionOpaqueBoundGrant := "urn:better-auth:test:opaque-bound-grant"
	extensionDriftGrant := "urn:better-auth:test:drift-grant"
	extensionAuthMethod := "test_attestation_jwt"
	extensionAssertionType := "urn:better-auth:test:client-assertion-type:test-attestation"
	vcScopes := []string{"openid", "email", "vc"}

	var grantUserID string
	var observedCustomParam string
	grantUser := func(in GrantHandlerInput) (*betterauth.User, error) {
		if grantUserID == "" {
			return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "invalid_request", "error_description", "test user is not ready"))
		}
		return in.Ctx.Auth.InternalAdapter.FindUserByID(in.Ctx.Context(), grantUserID)
	}

	ext := &Extension{
		Grants: []ExtensionGrant{
			{GrantType: extensionGrant, Handler: func(in GrantHandlerInput) (any, error) {
				observedCustomParam, _ = bodyMap(in.Ctx)["custom_param"].(string)
				user, err := grantUser(in)
				if err != nil {
					return nil, err
				}
				a, err := in.Provider.AuthenticateClient(&ClientAuthenticationRequest{Scopes: vcScopes})
				if err != nil {
					return nil, err
				}
				return in.Provider.IssueTokens(TokenIssueParams{
					Client: a.Client, Scopes: vcScopes, User: user, Resources: []string{resource}, Confirmation: a.Confirmation,
					AccessTokenClaims: jsonx.O("grant_claim", "grant-access", "client_id", "malicious-client"),
					IDTokenClaims: jsonx.O("grant_id_claim", "grant-id", "sub", "malicious-sub", "auth_time", 0,
						"amr", []any{"malicious-grant"}, "azp", "malicious-authorized-party", "nbf", 0, "jti", "malicious-jti",
						"c_hash", "malicious-code-hash", "s_hash", "malicious-state-hash", "order_probe", "grant"),
					TokenResponse: jsonx.O("issued_token_type", "urn:better-auth:test:access_token"),
				})
			}},
			{GrantType: extensionOpaqueGrant, Handler: func(in GrantHandlerInput) (any, error) {
				user, err := grantUser(in)
				if err != nil {
					return nil, err
				}
				a, err := in.Provider.AuthenticateClient(&ClientAuthenticationRequest{Scopes: vcScopes})
				if err != nil {
					return nil, err
				}
				return in.Provider.IssueTokens(TokenIssueParams{Client: a.Client, Scopes: vcScopes, User: user,
					AccessTokenClaims: jsonx.O("opaque_per_issuance", "jwt-only")})
			}},
			{GrantType: extensionOpaqueBoundGrant, Handler: func(in GrantHandlerInput) (any, error) {
				user, err := grantUser(in)
				if err != nil {
					return nil, err
				}
				a, err := in.Provider.AuthenticateClient(&ClientAuthenticationRequest{Scopes: vcScopes})
				if err != nil {
					return nil, err
				}
				return in.Provider.IssueTokens(TokenIssueParams{Client: a.Client, Scopes: vcScopes, User: user,
					Confirmation: jsonx.O("jkt", "opaque-bound-jkt")})
			}},
			{GrantType: extensionDriftGrant, Handler: func(in GrantHandlerInput) (any, error) {
				user, err := grantUser(in)
				if err != nil {
					return nil, err
				}
				// Upstream passes a stale grantType at runtime; the Go request type has no such
				// field, so authentication is always gated on the dispatched grant.
				a, err := in.Provider.AuthenticateClient(&ClientAuthenticationRequest{Scopes: vcScopes})
				if err != nil {
					return nil, err
				}
				return in.Provider.IssueTokens(TokenIssueParams{Client: a.Client, Scopes: vcScopes, User: user})
			}},
		},
		ClientAuthentication: []ClientAuthenticationStrategy{{
			Method:         extensionAuthMethod,
			AssertionTypes: []string{extensionAssertionType},
			Authenticate: func(in ClientAuthenticationInput) (*ClientAuthenticationResult, error) {
				if in.ClientID == "" || in.Assertion != "assertion:"+in.ClientID {
					return nil, betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("error", "invalid_client", "error_description", "invalid test assertion"))
				}
				return &ClientAuthenticationResult{ClientID: in.ClientID, Confirmation: jsonx.O("x5t#S256", "wallet-attested-cert")}, nil
			},
		}},
		Metadata: func(MetadataExtensionInput) *jsonx.Object {
			return jsonx.O("issuer", "https://malicious.example.com", "credential_issuer", "https://vc.example.com")
		},
		Claims: &ExtensionClaims{
			AccessToken: func(ClaimExtensionInput) (*jsonx.Object, error) {
				return jsonx.O("extension_access_claim", "extension-access", "client_id", "malicious-extension-client",
					"cnf", jsonx.O("jkt", "forged-by-extension")), nil
			},
			IDToken: func(ClaimExtensionInput) (*jsonx.Object, error) {
				return jsonx.O("extension_id_claim", "extension-id", "sub", "malicious-extension-sub", "email", "evil@malicious.example",
					"azp", "malicious-extension-authorized-party", "jti", "malicious-extension-jti", "order_probe", "extension"), nil
			},
			UserInfo: func(UserInfoExtensionInput) (*jsonx.Object, error) {
				return jsonx.O("extension_userinfo_claim", "extension-userinfo", "email", jsonx.Undefined, "sub", "malicious-extension-sub"), nil
			},
		},
		ClientDiscovery: []*ClientDiscovery{{
			ID:      "test-client-discovery",
			Matches: func(string) bool { return false },
			Resolve: func(*betterauth.EndpointContext, string, *SchemaClient) (*SchemaClient, error) { return nil, nil },
			DiscoveryMetadata: jsonx.O("issuer", "https://malicious-discovery.example.com",
				"token_endpoint", "https://malicious-discovery.example.com/token",
				"client_id_metadata_document_supported", true),
		}},
	}

	env := newEnv(t, Options{
		Resources:                      []ResourceInput{{Identifier: resource}},
		EnforcePerClientResources:      betterauth.Bool(false),
		AllowDynamicClientRegistration: true,
		Scopes:                         []string{"openid", "profile", "email", "offline_access", "vc"},
		CustomUserInfoClaims: func(UserInfoClaimsInput) (*jsonx.Object, error) {
			return jsonx.O("custom_userinfo_claim", "custom-userinfo", "sub", "malicious-custom-sub", "email_verified", true), nil
		},
	}, envOptions{jwt: dxJwtIssuer(testBaseURL), plugins: []*betterauth.Plugin{dxExtPlugin("test-oauth-extension", ext)}})
	headers := env.signInWithTestUser()
	userRec := env.findOne("user", eq("email", testUserEmail))
	grantUserID, _ = userRec["id"].(string)

	run := func(name string, f func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			defer dxBind(env, t)()
			f(t)
		})
	}
	createExtClient := func(grant string, extra map[string]any) string {
		body := map[string]any{
			"token_endpoint_auth_method": extensionAuthMethod,
			"grant_types":                []any{grant},
			"scope":                      "openid email vc",
			"application_type":           "web",
		}
		for k, v := range extra {
			body[k] = v
		}
		return dxStr(env.adminCreateClient(headers, body), "client_id")
	}
	assertionForm := func(clientID string, kv ...string) url.Values {
		v := url.Values{"client_id": {clientID}, "client_assertion_type": {extensionAssertionType}, "client_assertion": {"assertion:" + clientID}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Add(kv[i], kv[i+1])
		}
		return v
	}

	run("advertises extension metadata without overriding core metadata", func(t *testing.T) {
		md := env.mustCall("getOpenIdConfig", betterauth.CallInput{})
		if md["issuer"] != testBaseURL {
			t.Fatalf("issuer: %v", md["issuer"])
		}
		if md["token_endpoint"] == "https://malicious-discovery.example.com/token" {
			t.Fatal("token_endpoint overridden")
		}
		if md["credential_issuer"] != "https://vc.example.com" || md["client_id_metadata_document_supported"] != true {
			t.Fatalf("metadata: %v", md)
		}
		if !dxContainsAny(md["grant_types_supported"], extensionGrant) {
			t.Fatalf("grant types: %v", md["grant_types_supported"])
		}
		for _, k := range []string{"token_endpoint_auth_methods_supported", "introspection_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported"} {
			if !dxContainsAny(md[k], extensionAuthMethod) {
				t.Fatalf("%s: %v", k, md[k])
			}
		}
	})

	run("registers extension grants and auth methods through normal client creation", func(t *testing.T) {
		body := map[string]any{
			"token_endpoint_auth_method": extensionAuthMethod,
			"grant_types":                []any{extensionGrant},
			"scope":                      "openid email vc",
			"application_type":           "web",
		}
		check := func(name string, c map[string]any, checkGrants bool) {
			if dxStr(c, "client_id") == "" {
				t.Fatalf("%s: no client_id: %v", name, c)
			}
			if _, ok := c["client_secret"]; ok {
				t.Fatalf("%s: client_secret present", name)
			}
			if c["token_endpoint_auth_method"] != extensionAuthMethod {
				t.Fatalf("%s: method %v", name, c["token_endpoint_auth_method"])
			}
			if checkGrants {
				if g, _ := c["grant_types"].([]any); len(g) != 1 || g[0] != extensionGrant {
					t.Fatalf("%s: grant_types %v", name, c["grant_types"])
				}
			}
			if r, ok := c["redirect_uris"].([]any); !ok || len(r) != 0 {
				t.Fatalf("%s: redirect_uris %v", name, c["redirect_uris"])
			}
			if _, ok := c["response_types"]; ok {
				t.Fatalf("%s: response_types %v", name, c["response_types"])
			}
		}
		check("admin", env.adminCreateClient(headers, body), true)
		check("register", env.mustCall("registerOAuthClient", betterauth.CallInput{Headers: headers, Body: body}), false)
	})

	run("rejects code response type without authorization code grant", func(t *testing.T) {
		_, err := env.call("adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"token_endpoint_auth_method": extensionAuthMethod,
			"grant_types":                []any{extensionGrant},
			"response_types":             []any{"code"},
			"scope":                      "openid email vc",
			"application_type":           "web",
		}})
		if err == nil || err.StatusCode != 400 || !strings.Contains(dxDescription(err), "authorization_code") {
			t.Fatalf("err = %v %v", err, errBody(err))
		}
	})

	run("validates jwks_uri for extension auth-method clients", func(t *testing.T) {
		_, err := env.call("adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"token_endpoint_auth_method": extensionAuthMethod,
			"grant_types":                []any{extensionGrant},
			"jwks_uri":                   "https://127.0.0.1/jwks",
			"scope":                      "openid email vc",
			"application_type":           "web",
		}})
		if err == nil || err.StatusCode != 400 || !strings.Contains(dxDescription(err), "private or reserved address") {
			t.Fatalf("err = %v %v", err, errBody(err))
		}
	})

	run("rejects extension auth-method clients carrying both jwks and jwks_uri", func(t *testing.T) {
		_, err := env.call("adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"token_endpoint_auth_method": extensionAuthMethod,
			"grant_types":                []any{extensionGrant},
			"jwks":                       map[string]any{"keys": []any{map[string]any{"kty": "RSA", "n": "test", "e": "test-exponent"}}},
			"jwks_uri":                   "https://client.example.com/jwks",
			"scope":                      "openid email vc",
			"application_type":           "web",
		}})
		if err == nil || err.StatusCode != 400 || !strings.Contains(dxDescription(err), "mutually exclusive") {
			t.Fatalf("err = %v %v", err, errBody(err))
		}
	})

	run("rejects empty grant type registration", func(t *testing.T) {
		r := env.do("POST", "/oauth2/register", map[string]any{"grant_types": []any{}, "redirect_uris": []any{redirectURI}}, headers)
		if r.status != 400 {
			t.Fatalf("status %d %s", r.status, r.body)
		}
	})

	run("rejects assertion auth for clients with omitted (default) auth method", func(t *testing.T) {
		legacy := env.adminCreateClient(headers, map[string]any{
			"grant_types": []any{extensionGrant}, "scope": "openid email vc", "application_type": "web",
		})
		id := dxStr(legacy, "client_id")
		r := env.token(assertionForm(id, "grant_type", extensionGrant), nil)
		if r.status != 400 || !strings.Contains(dxStr(r.json(), "error_description"), "client registered for client_secret_basic cannot use") {
			t.Fatalf("response %d %s", r.status, r.body)
		}
	})

	run("returns invalid_client when an extension grant omits required credentials", func(t *testing.T) {
		c := env.adminCreateClient(headers, map[string]any{
			"grant_types": []any{extensionGrant}, "scope": "openid email vc", "application_type": "web",
		})
		r := env.token(url.Values{"grant_type": {extensionGrant}, "client_id": {dxStr(c, "client_id")}}, nil)
		dxExpectStatusErr(t, r, 400, "invalid_client")
	})

	run("challenges Basic authentication with an empty secret", func(t *testing.T) {
		c := env.adminCreateClient(headers, map[string]any{
			"grant_types": []any{extensionGrant}, "scope": "openid email vc", "application_type": "web",
		})
		id := dxStr(c, "client_id")
		if id == "" {
			t.Fatal("confidential OAuth client was not created")
		}
		r := env.token(url.Values{"grant_type": {extensionGrant}}, basicAuth(id, ""))
		dxExpectStatusErr(t, r, 401, "invalid_client")
		if got := r.header.Get("WWW-Authenticate"); got != "Basic" {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	})

	run("authorizes against the resolved record, not the strategy", func(t *testing.T) {
		r := env.token(assertionForm("unregistered-but-proven", "grant_type", extensionGrant), nil)
		dxExpectStatusErr(t, r, 400, "invalid_client")
	})

	run("rejects invalid direct extension options during provider setup", func(t *testing.T) {
		// oauthProvider() throws synchronously upstream; the Go constructor defers option
		// errors to betterauth.New.
		renv := newEnv(t, Options{Extensions: []*Extension{{Grants: []ExtensionGrant{{GrantType: "password", Handler: dxUnreachableGrant}}}}},
			envOptions{expectInitError: true})
		if renv.initErr == nil || !strings.Contains(renv.initErr.Error(), "grant type must be an absolute URI") {
			t.Fatalf("err = %v", renv.initErr)
		}
	})

	run("registers an extension at most once per extension object", func(t *testing.T) {
		once := &Extension{Grants: []ExtensionGrant{{GrantType: extensionGrant, Handler: dxUnreachableGrant}}}
		oenv := newEnv(t, Options{}, envOptions{plugins: []*betterauth.Plugin{dxExtPlugin("twice", once, once)}})
		if n := len(oenv.plugin.Options.(*resolved).Extensions); n != 1 {
			t.Fatalf("extensions = %d", n)
		}
	})

	run("dispatches extension grants through shared token issuance", func(t *testing.T) {
		id := createExtClient(extensionGrant, map[string]any{"redirect_uris": []any{redirectURI + "/token"}})
		if id == "" {
			t.Fatal("no client id")
		}
		r := env.token(assertionForm(id, "grant_type", extensionGrant, "custom_param", "preserved", "resource", resource), nil)
		m := dxExpectOK(t, r)
		if m["issued_token_type"] != "urn:better-auth:test:access_token" || m["scope"] != "openid email vc" {
			t.Fatalf("token: %s", r.body)
		}
		if observedCustomParam != "preserved" {
			t.Fatalf("custom_param = %q", observedCustomParam)
		}
		at := decodeJWTPayload(t, dxStr(m, "access_token"))
		if at["extension_access_claim"] != "extension-access" || at["grant_claim"] != "grant-access" || at["client_id"] != id {
			t.Fatalf("access token: %v", at)
		}
		if !dxAudContains(at["aud"], resource) {
			t.Fatalf("aud: %v", at["aud"])
		}
		if cnf, _ := json.Marshal(at["cnf"]); string(cnf) != `{"x5t#S256":"wallet-attested-cert"}` {
			t.Fatalf("cnf: %s", cnf)
		}
		if m["token_type"] != "Bearer" {
			t.Fatalf("token_type: %v", m["token_type"])
		}
		idt := decodeJWTPayload(t, dxStr(m, "id_token"))
		if idt["extension_id_claim"] != "extension-id" || idt["grant_id_claim"] != "grant-id" || idt["sub"] != grantUserID || idt["order_probe"] != "grant" {
			t.Fatalf("id token: %v", idt)
		}
		for _, k := range []string{"auth_time", "amr", "azp", "nbf", "jti", "c_hash", "s_hash", "email"} {
			if _, ok := idt[k]; ok {
				t.Fatalf("id token has %s: %v", k, idt[k])
			}
		}
		ui := env.do("GET", "/oauth2/userinfo", nil, http.Header{"Authorization": {"Bearer " + dxStr(m, "access_token")}})
		um := dxExpectOK(t, ui)
		if um["sub"] != grantUserID || um["email"] != testUserEmail || um["extension_userinfo_claim"] != "extension-userinfo" ||
			um["custom_userinfo_claim"] != "custom-userinfo" || um["email_verified"] != true {
			t.Fatalf("userinfo: %s", ui.body)
		}
		in := env.do("POST", "/oauth2/introspect", assertionForm(id, "token", dxStr(m, "access_token")), nil)
		im := dxExpectOK(t, in)
		if im["active"] != true || im["extension_access_claim"] != "extension-access" {
			t.Fatalf("introspection: %s", in.body)
		}
	})

	run("ignores a runtime grantType argument and gates on the dispatched grant", func(t *testing.T) {
		id := createExtClient(extensionOpaqueGrant, nil)
		r := env.token(assertionForm(id, "grant_type", extensionDriftGrant), nil)
		dxExpectStatusErr(t, r, 400, "unauthorized_client")
	})

	run("rejects unsupported extension grant types before credential handling", func(t *testing.T) {
		r := env.token(url.Values{"grant_type": {"urn:better-auth:test:missing-grant"}}, nil)
		dxExpectStatusErr(t, r, 400, "unsupported_grant_type")
	})

	run("rejects extension grant keys that are not absolute URIs", func(t *testing.T) {
		dxExpectInitError(t, "grant type must be an absolute URI", dxExtPlugin("invalid-oauth-extension",
			&Extension{Grants: []ExtensionGrant{{GrantType: "custom", Handler: dxUnreachableGrant}}}))
	})

	run("rejects extension auth method keys reserved by built-in client authentication", func(t *testing.T) {
		dxExpectInitError(t, "token_endpoint_auth_method is reserved: private_key_jwt", dxExtPlugin("invalid-oauth-auth-method-extension",
			&Extension{ClientAuthentication: []ClientAuthenticationStrategy{{Method: "private_key_jwt", AssertionTypes: []string{extensionAssertionType}, Authenticate: dxUnreachableAuth}}}))
	})

	run("rejects extension assertion types reserved by private_key_jwt", func(t *testing.T) {
		dxExpectInitError(t, "client_assertion_type is reserved: "+oauthcore.ClientAssertionType, dxExtPlugin("invalid-oauth-assertion-type-extension",
			&Extension{ClientAuthentication: []ClientAuthenticationStrategy{{Method: extensionAuthMethod, AssertionTypes: []string{oauthcore.ClientAssertionType}, Authenticate: dxUnreachableAuth}}}))
	})

	run("rejects extension auth methods without assertion types", func(t *testing.T) {
		dxExpectInitError(t, "client_assertion_type list cannot be empty", dxExtPlugin("invalid-oauth-empty-assertion-types-extension",
			&Extension{ClientAuthentication: []ClientAuthenticationStrategy{{Method: extensionAuthMethod, AssertionTypes: []string{}, Authenticate: dxUnreachableAuth}}}))
	})

	run("rejects two extensions registering the same grant type", func(t *testing.T) {
		shared := "urn:better-auth:test:shared-grant"
		mk := func(id string) *betterauth.Plugin {
			return dxExtPlugin(id, &Extension{Grants: []ExtensionGrant{{GrantType: shared, Handler: dxUnreachableGrant}}})
		}
		dxExpectInitError(t, "register grant type", mk("ext-a"), mk("ext-b"))
	})

	run("rejects two extensions registering the same auth method", func(t *testing.T) {
		mk := func(id, assertionType string) *betterauth.Plugin {
			return dxExtPlugin(id, &Extension{ClientAuthentication: []ClientAuthenticationStrategy{{
				Method: "shared_attestation_jwt", AssertionTypes: []string{assertionType}, Authenticate: dxUnreachableAuth}}})
		}
		dxExpectInitError(t, "register token_endpoint_auth_method", mk("auth-ext-a", "urn:better-auth:test:a"), mk("auth-ext-b", "urn:better-auth:test:b"))
	})

	run("rejects two extensions registering the same assertion type", func(t *testing.T) {
		mk := func(id, method string) *betterauth.Plugin {
			return dxExtPlugin(id, &Extension{ClientAuthentication: []ClientAuthenticationStrategy{{
				Method: method, AssertionTypes: []string{"urn:better-auth:test:shared-assertion"}, Authenticate: dxUnreachableAuth}}})
		}
		dxExpectInitError(t, "register client_assertion_type", mk("assert-ext-a", "method_a_jwt"), mk("assert-ext-b", "method_b_jwt"))
	})

	run("rejects duplicate client discovery identifiers", func(t *testing.T) {
		mk := func(id string) *betterauth.Plugin {
			return dxExtPlugin(id, &Extension{ClientDiscovery: []*ClientDiscovery{{
				ID: "shared-client-discovery", Matches: func(string) bool { return false },
				Resolve: func(*betterauth.EndpointContext, string, *SchemaClient) (*SchemaClient, error) { return nil, nil },
			}}})
		}
		dxExpectInitError(t, "register client discovery id", mk("discovery-ext-a"), mk("discovery-ext-b"))
	})

	run("resolves a metadata key collision to the first-registered extension", func(t *testing.T) {
		mk := func(id, value string) *betterauth.Plugin {
			return dxExtPlugin(id, &Extension{Metadata: func(MetadataExtensionInput) *jsonx.Object {
				return jsonx.O("shared_metadata_field", value)
			}})
		}
		menv := newEnv(t, Options{}, envOptions{jwt: dxJwtIssuer(testBaseURL), plugins: []*betterauth.Plugin{mk("meta-ext-a", "first"), mk("meta-ext-b", "second")}})
		if md := menv.mustCall("getOpenIdConfig", betterauth.CallInput{}); md["shared_metadata_field"] != "first" {
			t.Fatalf("shared_metadata_field = %v", md["shared_metadata_field"])
		}
	})

	run("re-derives extension access-token claims on opaque-token introspection", func(t *testing.T) {
		id := createExtClient(extensionOpaqueGrant, nil)
		r := env.token(assertionForm(id, "grant_type", extensionOpaqueGrant), nil)
		at := dxStr(dxExpectOK(t, r), "access_token")
		if strings.Contains(at, ".") {
			t.Fatalf("access token is a JWT: %s", at)
		}
		in := env.do("POST", "/oauth2/introspect", assertionForm(id, "token", at), nil)
		im := dxExpectOK(t, in)
		if im["active"] != true || im["extension_access_claim"] != "extension-access" || im["client_id"] != id {
			t.Fatalf("introspection: %s", in.body)
		}
		if _, ok := im["opaque_per_issuance"]; ok {
			t.Fatalf("opaque_per_issuance present: %s", in.body)
		}
	})

	run("surfaces an extension assertion rejection as invalid_client", func(t *testing.T) {
		id := createExtClient(extensionGrant, nil)
		form := url.Values{"grant_type": {extensionGrant}, "client_id": {id}, "client_assertion_type": {extensionAssertionType},
			"client_assertion": {"assertion:wrong"}, "resource": {resource}}
		r := env.token(form, nil)
		dxExpectStatusErr(t, r, 401, "invalid_client")
	})

	run("authenticates an extension assertion on the revoke endpoint", func(t *testing.T) {
		id := createExtClient(extensionOpaqueGrant, nil)
		r := env.token(assertionForm(id, "grant_type", extensionOpaqueGrant), nil)
		at := dxStr(dxExpectOK(t, r), "access_token")
		rv := env.do("POST", "/oauth2/revoke", assertionForm(id, "token", at), nil)
		dxExpectOK(t, rv)
		in := env.do("POST", "/oauth2/introspect", assertionForm(id, "token", at), nil)
		if in.json()["active"] == true {
			t.Fatalf("introspection after revoke: %s", in.body)
		}
	})

	run("consumeClientAssertion rejects an already-expired assertion", func(t *testing.T) {
		now := float64(time.Now().Unix())
		audience := testBaseURL + "/oauth2/token"
		ctx := &betterauth.EndpointContext{Auth: &betterauth.AuthContext{BaseURL: testBaseURL}}
		err := consumeClientAssertion(ctx, &resolved{}, "test:expired",
			ClientAssertionPayload{Aud: audience, Exp: now - 10, Jti: "expired-jti"}, audience)
		apiErr, ok := betterauth.AsAPIError(err)
		if !ok || apiErr.StatusCode != 400 {
			t.Fatalf("err = %v", err)
		}
		expectOAuthError(t, apiErr, "invalid_client", "client assertion has expired")
	})

	run("binds an opaque access token to its confirmation and surfaces it at introspection", func(t *testing.T) {
		id := createExtClient(extensionOpaqueBoundGrant, nil)
		r := env.token(assertionForm(id, "grant_type", extensionOpaqueBoundGrant), nil)
		m := dxExpectOK(t, r)
		if m["token_type"] != "DPoP" {
			t.Fatalf("token_type: %s", r.body)
		}
		in := env.do("POST", "/oauth2/introspect", assertionForm(id, "token", dxStr(m, "access_token"), "token_type_hint", "access_token"), nil)
		im := in.json()
		cnf, _ := json.Marshal(im["cnf"])
		if im["active"] != true || im["token_type"] != "DPoP" || string(cnf) != `{"jkt":"opaque-bound-jkt"}` {
			t.Fatalf("introspection: %s", in.body)
		}
	})

	run("authenticateClient binds the assertion audience to the served endpoint", func(t *testing.T) {
		var observed string
		o := &resolved{Options: Options{Extensions: []*Extension{{ClientAuthentication: []ClientAuthenticationStrategy{{
			Method:         "audience_probe_method",
			AssertionTypes: []string{"urn:better-auth:test:audience-probe"},
			Authenticate: func(in ClientAuthenticationInput) (*ClientAuthenticationResult, error) {
				observed = in.ExpectedAudience
				return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "invalid_client", "error_description", "audience recorded"))
			},
		}}}}}}
		ctx := &betterauth.EndpointContext{
			Path: "/oauth2/bc-authorize",
			Auth: &betterauth.AuthContext{BaseURL: testBaseURL},
			Body: map[string]any{
				"client_id":             "probe-client",
				"client_assertion":      "probe-assertion",
				"client_assertion_type": "urn:better-auth:test:audience-probe",
			},
			Request: httptest.NewRequest("POST", testBaseURL+"/oauth2/bc-authorize", nil),
		}
		ctx.SetContext(context.Background())
		if _, err := newProviderAPI(ctx, o, "urn:better-auth:test:grant").AuthenticateClient(nil); err == nil {
			t.Fatal("expected rejection")
		}
		if observed != testBaseURL+"/oauth2/bc-authorize" {
			t.Fatalf("observed audience %q", observed)
		}
	})

	run("getOAuthProviderApi.issueTokens requires a bound grant type", func(t *testing.T) {
		api := newProviderAPI(&betterauth.EndpointContext{Auth: &betterauth.AuthContext{BaseURL: testBaseURL}}, &resolved{}, "")
		_, err := api.IssueTokens(TokenIssueParams{Client: &SchemaClient{ClientID: "x"}, Scopes: []string{}})
		apiErr, ok := betterauth.AsAPIError(err)
		if !ok || !strings.Contains(dxDescription(apiErr), "grant type") {
			t.Fatalf("err = %v", err)
		}
	})
}
