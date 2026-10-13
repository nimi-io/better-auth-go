package oauthprovider

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/organization"
)

// ---- register.test.ts (part 1) ----

// rgCheck runs checkOAuthClient against options resolved like oauthProvider(opts).
func rgCheck(t *testing.T, md map[string]any, opts Options, source string) error {
	t.Helper()
	if opts.LoginPage == "" {
		opts.LoginPage = "/login"
	}
	if opts.ConsentPage == "" {
		opts.ConsentPage = "/consent"
	}
	o, err := resolveOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	return checkOAuthClient(toObject(md), o, checkSettings{source: source})
}

func rgExpectDescContains(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", sub)
	}
	apiErr, ok := betterauth.AsAPIError(err)
	if !ok {
		t.Fatalf("expected API error, got %v", err)
	}
	desc, _ := errBody(apiErr)["error_description"].(string)
	if !strings.Contains(desc, sub) {
		t.Fatalf("expected error_description containing %q, got %v", sub, errBody(apiErr))
	}
}

func rgScopeList(r rgRes) []any {
	s, _ := r.m()["scope"].(string)
	var out []any
	for _, p := range strings.Split(s, " ") {
		out = append(out, p)
	}
	return out
}

func TestRg_OauthRegister(t *testing.T) {
	rpBaseURL := "http://localhost:5000"
	env := newEnv(t, Options{
		AllowDynamicClientRegistration:     true,
		Resources:                          []ResourceInput{{Identifier: "https://api.example.com/dcr-dedupe"}},
		ClientRegistrationAllowedResources: []string{"https://api.example.com/dcr-dedupe"},
		Scopes:                             []string{"openid", "profile", "email", "offline_access", "create:test", "delete:test"},
	})
	headers := env.signInWithTestUser()
	serverClient := rgClient{env, headers}
	unauth := rgClient{env, http.Header{}}
	redirectURI := "https://rp.example.com/api/auth/callback/test"
	allScopes := []any{"openid", "profile", "email", "offline_access", "create:test", "delete:test"}

	t.Run("should fail without body", func(t *testing.T) {
		rgErr(t, serverClient.req("POST", "/oauth2/register", nil), 400)
	})

	t.Run("should fail without authentication", func(t *testing.T) {
		rgErr(t, unauth.register(map[string]any{"redirect_uris": []any{redirectURI}}), 401)
	})

	t.Run("should reject unauthenticated registration before metadata validation", func(t *testing.T) {
		rgErr(t, unauth.register(map[string]any{"redirect_uris": []any{redirectURI}, "token_endpoint_auth_method": "not_a_real_method"}), 401)
	})

	t.Run("should register private client with minimum requirements", func(t *testing.T) {
		r := serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id", "user_id", "client_secret")
	})

	t.Run("persists operator-approved scopes so a DCR client can step up later", func(t *testing.T) {
		r := serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "scope": "openid"})
		if !r.ok() {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
		rgEqual(t, rgScopeList(r), allScopes)
		stored := env.findOne("oauthClient", eq("clientId", r.m()["client_id"]))
		rgEqual(t, rgJSONList(stored["scopes"]), rgScopeList(r))
	})

	t.Run("resolves registration scope policy as a deterministic default and allowed union", func(t *testing.T) {
		penv := newEnv(t, Options{
			AllowDynamicClientRegistration:         true,
			AllowUnauthenticatedClientRegistration: true,
			Scopes:                                 []string{"openid", "read", "write", "admin"},
			ClientRegistrationDefaultScopes:        []string{"openid", "read", "read"},
			ClientRegistrationAllowedScopes:        []string{"write", "read"},
		})
		pc := rgClient{penv, http.Header{}}
		accepted := pc.register(map[string]any{"redirect_uris": []any{redirectURI}, "token_endpoint_auth_method": "none", "scope": "read"})
		if !accepted.ok() || accepted.m()["scope"] != "openid read write" {
			t.Fatalf("accepted: %d %s", accepted.status, accepted.raw)
		}
		rejected := pc.register(map[string]any{"redirect_uris": []any{redirectURI}, "token_endpoint_auth_method": "none", "scope": "admin"})
		rgErr(t, rejected, 400)
	})

	t.Run("defaults omitted application_type to web independently of public client authentication", func(t *testing.T) {
		r := serverClient.register(map[string]any{"redirect_uris": []any{"https://client.example.com/callback"}, "token_endpoint_auth_method": "none"})
		if !r.ok() {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
		rgMatch(t, r.m(), map[string]any{"application_type": "web", "token_endpoint_auth_method": "none"})
		rgExpectUndefined(t, r.m(), "client_secret", "public", "type")
		stored := env.findOne("oauthClient", eq("clientId", r.m()["client_id"]))
		if stored["applicationType"] != "web" || stored["tokenEndpointAuthMethod"] != "none" {
			t.Fatalf("stored: %v", stored)
		}
		if _, ok := stored["public"]; ok {
			t.Fatalf("stored has public: %v", stored)
		}
		if _, ok := stored["type"]; ok {
			t.Fatalf("stored has type: %v", stored)
		}
	})

	t.Run("should fail authorization_code without response type code", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{"response_types": []any{"token"}, "redirect_uris": []any{redirectURI}}), 400)
	})

	t.Run("should register confidential client and check that certain fields are overwritten", func(t *testing.T) {
		req := map[string]any{
			"client_id":                  "bad-actor",
			"client_secret":              "bad-actor",
			"client_secret_expires_at":   0,
			"scope":                      "create:test delete:test",
			"user_id":                    "bad-actor",
			"client_id_issued_at":        time.Now().Unix(),
			"client_name":                "accept name",
			"client_uri":                 "https://example.com/ok",
			"logo_uri":                   "https://example.com/logo.png",
			"contacts":                   []any{"test@example.com"},
			"tos_uri":                    "https://example.com/terms",
			"policy_uri":                 "https://example.com/policy",
			"software_id":                "custom-software-id",
			"software_version":           "custom-v1",
			"software_statement":         "custom software statement",
			"redirect_uris":              []any{"https://example.com/callback"},
			"token_endpoint_auth_method": "client_secret_post",
			"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
			"response_types":             []any{"code"},
			"application_type":           "web",
			"disabled":                   false,
		}
		r := serverClient.register(req)
		d := r.m()
		rgExpectDefined(t, d, "client_id", "client_secret", "user_id", "client_id_issued_at")
		if d["client_id"] == "bad-actor" || d["client_secret"] == "bad-actor" || d["user_id"] == "bad-actor" {
			t.Fatalf("fields not overwritten: %v", d)
		}
		rgEqual(t, d["client_secret_expires_at"], 0)
		rgEqual(t, rgScopeList(r), allScopes)
		pick := func(keys ...string) map[string]any {
			out := map[string]any{}
			for _, k := range keys {
				out[k] = req[k]
			}
			return out
		}
		rgMatch(t, d, pick("client_name", "client_uri", "logo_uri", "contacts", "tos_uri", "policy_uri"))
		rgExpectUndefined(t, d, "jwks", "jwks_uri")
		rgMatch(t, d, pick("software_id", "software_version", "software_statement", "redirect_uris",
			"token_endpoint_auth_method", "grant_types", "response_types"))
		rgExpectUndefined(t, d, "public", "type")
		if d["disabled"] != nil && d["disabled"] != false {
			t.Fatalf("disabled: %v", d["disabled"])
		}
	})

	t.Run("preserves surrounding client_name whitespace through registration", func(t *testing.T) {
		name := "  Deliberately Spaced Client  "
		r := serverClient.register(map[string]any{"client_name": name, "redirect_uris": []any{"https://example.com/callback"}})
		if !r.ok() || r.m()["client_name"] != name {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
		stored := env.findOne("oauthClient", eq("clientId", r.m()["client_id"]))
		if stored["name"] != name {
			t.Fatalf("stored name: %q", stored["name"])
		}
	})

	t.Run("should preserve confidential method and application type for authenticated registration", func(t *testing.T) {
		r := serverClient.register(map[string]any{
			"token_endpoint_auth_method": "client_secret_post",
			"application_type":           "web",
			"redirect_uris":              []any{redirectURI},
		})
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		if r.m()["token_endpoint_auth_method"] != "client_secret_post" || r.m()["application_type"] != "web" {
			t.Fatalf("register: %s", r.raw)
		}
		rgExpectUndefined(t, r.m(), "public", "type")
	})

	t.Run("dedupes repeated DCR resources to a single client/resource link row", func(t *testing.T) {
		id := "https://api.example.com/dcr-dedupe"
		r := serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "resources": []any{id, id}})
		rgExpectDefined(t, r.m(), "client_id")
		links := env.findMany("oauthClientResource", eq("clientId", r.m()["client_id"]))
		if len(links) != 1 {
			t.Fatalf("expected 1 link, got %d", len(links))
		}
	})

	t.Run("rejects a registration resource that is not a valid RFC 8707 URI", func(t *testing.T) {
		r := serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "resources": []any{"not-a-uri"}})
		rgErr(t, r, 400)
		if r.m()["error"] != "invalid_target" {
			t.Fatalf("error: %s", r.raw)
		}
	})

	t.Run("lazy-seeds configured resources before DCR validation", func(t *testing.T) {
		id := "https://api.example.com/dcr-lazy-seed"
		lenv := newEnv(t, Options{
			AllowDynamicClientRegistration:     true,
			Resources:                          []ResourceInput{{Identifier: id}},
			ClientRegistrationAllowedResources: []string{id},
		})
		if err := lenv.db.Delete(lenv.ctx(), "oauthResource", rgWhere("identifier", id)); err != nil {
			t.Fatal(err)
		}
		ResetSeedStateForTests(lenv.plugin)
		c := rgClient{lenv, lenv.signInWithTestUser()}
		r := c.register(map[string]any{"redirect_uris": []any{redirectURI}, "resources": []any{id}})
		if !r.ok() {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
		rgEqual(t, r.m()["resources"], []any{id})
	})

	t.Run("should register client with metadata field", func(t *testing.T) {
		res := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"redirect_uris": []any{redirectURI},
			"metadata":      map[string]any{"foo": "bar", "nested": map[string]any{"key": "value"}},
		}})
		rgExpectDefined(t, res, "client_id", "client_secret")
		if res["foo"] != "bar" {
			t.Fatalf("foo: %v", res)
		}
		rgEqual(t, res["nested"], map[string]any{"key": "value"})
	})

	t.Run("rejects a bare JWK array through dynamic registration", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{
			"redirect_uris":              []any{redirectURI},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       []any{map[string]any{"kty": "RSA", "n": "modulus", "e": "AQAB"}},
		}), 400)
	})

	t.Run("should reject registration with an empty jwks.keys array", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{
			"redirect_uris":              []any{redirectURI},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       map[string]any{"keys": []any{}},
		}), 400)
	})

	for _, key := range []map[string]any{
		{"kty": "oct", "k": "secret-key"},
		{"kty": "RSA", "n": "test", "e": "test-exponent", "d": "private-exponent"},
	} {
		t.Run("should reject private or symmetric jwks material", func(t *testing.T) {
			rgErr(t, serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "jwks": map[string]any{"keys": []any{key}}}), 400)
		})
	}

	for _, key := range []map[string]any{
		{},
		{"use": "sig"},
		{"kty": "RSA", "n": "test"},
		{"kty": "EC", "crv": "P-256", "x": "test"},
		{"kty": "OKP", "crv": "Ed25519"},
		{"kty": "unsupported", "n": "test", "e": "test-exponent"},
		{"kty": "RSA", "n": "test", "e": "AQAB", "alg": "HS256"},
		{"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "RS256"},
		{"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES384"},
		{"kty": "OKP", "crv": "Ed448", "x": "x", "alg": "EdDSA"},
	} {
		t.Run("should reject malformed jwks public keys", func(t *testing.T) {
			rgErr(t, serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "jwks": map[string]any{"keys": []any{key}}}), 400)
		})
	}

	for _, tc := range []struct{ jwksURI, err string }{
		{"https://user:password@example.com/.well-known/jwks.json", "credentials"},
		{"https://example.com/.well-known/jwks.json#keys", "fragment"},
	} {
		t.Run("rejects jwks_uri containing "+tc.err, func(t *testing.T) {
			err := rgCheck(t, map[string]any{"client_id": "jwks-uri-client", "redirect_uris": []any{redirectURI}, "jwks_uri": tc.jwksURI}, Options{}, "")
			rgExpectDescContains(t, err, tc.err)
		})
	}

	t.Run("client metadata document grant intersection", func(t *testing.T) {
		t.Run("keeps a client metadata document whose grants intersect the supported set", func(t *testing.T) {
			err := rgCheck(t, map[string]any{
				"client_id":                  "https://client.example.com/oauth/client-metadata",
				"client_name":                "Claude",
				"redirect_uris":              []any{"https://client.example.com/api/auth_callback"},
				"grant_types":                []any{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
				"response_types":             []any{"code"},
				"token_endpoint_auth_method": "none",
			}, Options{}, "clientMetadataDocument")
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
		})
		t.Run("rejects a client metadata document sharing no grant with the server", func(t *testing.T) {
			err := rgCheck(t, map[string]any{
				"client_id":                  "https://client.example.com/oauth/client-metadata",
				"client_name":                "Assertion Only",
				"redirect_uris":              []any{},
				"grant_types":                []any{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				"response_types":             []any{},
				"token_endpoint_auth_method": "none",
			}, Options{}, "clientMetadataDocument")
			rgExpectDescContains(t, err, "no mutually supported")
		})
		t.Run("still rejects a dynamic registration declaring an unsupported grant", func(t *testing.T) {
			err := rgCheck(t, map[string]any{
				"client_id":      "dcr-client",
				"redirect_uris":  []any{redirectURI},
				"grant_types":    []any{"authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
				"response_types": []any{"code"},
			}, Options{}, "dynamic")
			rgExpectDescContains(t, err, "unsupported grant_type")
		})
	})

	t.Run("rejects a bare JWK array through managed registration", func(t *testing.T) {
		_, err := rgCall(env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"redirect_uris":              []any{redirectURI},
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks":                       []any{map[string]any{"kty": "RSA", "n": "modulus", "e": "AQAB"}},
		}})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("should register client with metadata and strip extra fields not in schema", func(t *testing.T) {
		res := rgMustCall(t, env, "adminCreateOAuthClient", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"redirect_uris": []any{redirectURI},
			"metadata":      map[string]any{"fromMetadata": "value1"},
			"customField":   "value2",
		}})
		rgExpectDefined(t, res, "client_id")
		if res["fromMetadata"] != "value1" {
			t.Fatalf("fromMetadata: %v", res)
		}
		rgExpectUndefined(t, res, "customField")
	})

	t.Run("round-trips backchannel_logout_uri and backchannel_logout_session_required", func(t *testing.T) {
		uri := "https://rp.example.com/logout/backchannel"
		r := serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "backchannel_logout_uri": uri, "backchannel_logout_session_required": true})
		rgExpectDefined(t, r.m(), "client_id")
		if r.m()["backchannel_logout_uri"] != uri || r.m()["backchannel_logout_session_required"] != true {
			t.Fatalf("register: %s", r.raw)
		}
	})

	t.Run("rejects backchannel_logout_uri with a fragment", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "backchannel_logout_uri": "https://rp.example.com/logout/backchannel#section"}), 400)
	})

	t.Run("rejects backchannel_logout_uri ending with a bare fragment delimiter", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "backchannel_logout_uri": "https://rp.example.com/logout/backchannel#"}), 400)
	})

	t.Run("rejects http backchannel_logout_uri on confidential clients", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "backchannel_logout_uri": "http://rp.example.com/logout/backchannel"}), 400)
	})

	t.Run("rejects http backchannel_logout_uri on public clients", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "token_endpoint_auth_method": "none",
			"backchannel_logout_uri": rpBaseURL + "/logout/backchannel"}), 400)
	})

	t.Run("rejects credentials in backchannel_logout_uri", func(t *testing.T) {
		rgErr(t, serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "backchannel_logout_uri": "https://user:password@rp.example.com/logout/backchannel"}), 400)
	})

	t.Run("rejects backchannel_logout_uri pointing at private, tunneled, or metadata targets", func(t *testing.T) {
		for _, target := range []string{
			"https://10.0.0.1/logout",
			"https://169.254.169.254/logout",
			"https://[::ffff:169.254.169.254]/logout",
			"https://[64:ff9b::a9fe:a9fe]/logout",
			"https://100.64.0.1/logout",
			"https://metadata.google.internal/logout",
		} {
			r := serverClient.register(map[string]any{"redirect_uris": []any{redirectURI}, "backchannel_logout_uri": target})
			if r.status != 400 {
				t.Fatalf("%s: expected 400, got %d %s", target, r.status, r.raw)
			}
		}
	})
}

func TestRg_OauthRegisterDisableJwtPlugin(t *testing.T) {
	rpBaseURL := "http://localhost:5000"
	env := newEnv(t, Options{AllowDynamicClientRegistration: true, DisableJwtPlugin: true}, envOptions{noJwt: true})
	c := rgClient{env, env.signInWithTestUser()}
	t.Run("rejects backchannel_logout_uri when jwt plugin is disabled", func(t *testing.T) {
		rgErr(t, c.register(map[string]any{"redirect_uris": []any{rpBaseURL + "/callback"}, "backchannel_logout_uri": rpBaseURL + "/logout/backchannel"}), 400)
	})
}

func TestRg_OauthRegisterUnauthenticated(t *testing.T) {
	env := newEnv(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true})
	c := rgClient{env, http.Header{}}
	redirectURI := "https://rp.example.com/api/auth/callback/test"

	t.Run("should create public clients without authentication", func(t *testing.T) {
		r := c.register(map[string]any{"token_endpoint_auth_method": "none", "redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id")
		rgExpectUndefined(t, r.m(), "user_id", "client_secret")
	})

	t.Run("should apply the client_secret_basic default without authentication", func(t *testing.T) {
		r := c.register(map[string]any{"redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		if r.m()["token_endpoint_auth_method"] != "client_secret_basic" {
			t.Fatalf("register: %s", r.raw)
		}
		rgExpectUndefined(t, r.m(), "public")
	})

	t.Run("should preserve client_secret_post for unauthenticated DCR", func(t *testing.T) {
		r := c.register(map[string]any{"token_endpoint_auth_method": "client_secret_post", "redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		if r.m()["token_endpoint_auth_method"] != "client_secret_post" {
			t.Fatalf("register: %s", r.raw)
		}
		rgExpectUndefined(t, r.m(), "public")
	})

	t.Run("should accept client_secret_basic with inline jwks for unauthenticated DCR", func(t *testing.T) {
		jwks := map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "client-key", "n": "test", "e": "test-exponent"}}}
		r := c.register(map[string]any{"token_endpoint_auth_method": "client_secret_basic", "redirect_uris": []any{redirectURI}, "jwks": jwks})
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		if r.m()["token_endpoint_auth_method"] != "client_secret_basic" {
			t.Fatalf("register: %s", r.raw)
		}
		rgEqual(t, r.m()["jwks"], jwks)
	})

	t.Run("should preserve application_type 'web' for unauthenticated confidential DCR", func(t *testing.T) {
		r := c.register(map[string]any{"token_endpoint_auth_method": "client_secret_post", "application_type": "web", "redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, r.m(), "client_id", "client_secret")
		if r.m()["token_endpoint_auth_method"] != "client_secret_post" || r.m()["application_type"] != "web" {
			t.Fatalf("register: %s", r.raw)
		}
	})

	t.Run("should reject client_credentials grant for unauthenticated DCR", func(t *testing.T) {
		rgErr(t, c.register(map[string]any{"grant_types": []any{"client_credentials"}, "redirect_uris": []any{redirectURI}}), 400)
	})
}

func TestRg_OauthRegisterUnauthenticatedDCRFullFlow(t *testing.T) {
	env := newEnv(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true})
	headers := env.signInWithTestUser()
	unauth := rgClient{env, http.Header{}}
	redirectURI := "https://rp.example.com/api/auth/oauth2/callback/test"
	state := "e2e-test-state"

	t.Run("should complete authorize + PKCE token exchange for client_secret_post", func(t *testing.T) {
		reg := unauth.register(map[string]any{"token_endpoint_auth_method": "client_secret_post", "redirect_uris": []any{redirectURI}})
		rgExpectDefined(t, reg.m(), "client_id", "client_secret")
		if reg.m()["token_endpoint_auth_method"] != "client_secret_post" {
			t.Fatalf("register: %s", reg.raw)
		}
		clientID := reg.m()["client_id"].(string)
		clientSecret := reg.m()["client_secret"].(string)
		verifier := "rg-code-verifier-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"
		// createAuthorizationURL parameter order.
		res := env.do("GET", authorizeURL("response_type", "code", "client_id", clientID, "state", state, "scope", "openid",
			"redirect_uri", redirectURI, "code_challenge", challengeFor(verifier), "code_challenge_method", "S256"), nil, headers)
		consentRedirect := res.location()
		if !strings.Contains(consentRedirect, "/consent") {
			t.Fatalf("authorize: %d %q %s", res.status, consentRedirect, res.body)
		}
		u, _ := url.Parse(consentRedirect)
		cr := env.do("POST", "/oauth2/consent", map[string]any{"accept": true, "oauth_query": u.RawQuery}, headers)
		curl, _ := cr.json()["url"].(string)
		if !strings.Contains(curl, "code=") {
			t.Fatalf("consent: %d %s", cr.status, cr.body)
		}
		cu, _ := url.Parse(curl)
		code := cu.Query().Get("code")
		tok := env.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
			"redirect_uri": {redirectURI}, "client_id": {clientID}, "client_secret": {clientSecret}}, nil)
		tm := tok.json()
		if tm["access_token"] == nil || tm["id_token"] == nil {
			t.Fatalf("token: %d %s", tok.status, tok.body)
		}
		if tt, _ := tm["token_type"].(string); strings.ToLower(tt) != "bearer" || tm["scope"] != "openid" {
			t.Fatalf("token: %s", tok.body)
		}
	})
}

func TestRg_OauthRegisterOrganization(t *testing.T) {
	redirectURI := "https://rp.example.com/api/auth/callback/test"
	env := newEnv(t, Options{
		AllowDynamicClientRegistration: true,
		ClientReference: func(c UserSessionContext) (string, error) {
			if c.Session == nil {
				return "", nil
			}
			s, _ := c.Session.Additional["activeOrganizationId"].(string)
			return s, nil
		},
	}, envOptions{before: []*betterauth.Plugin{organization.New(organization.Options{})}})
	headers := env.signInWithTestUser()
	c := rgClient{env, headers}
	org := c.req("POST", "/organization/create", map[string]any{"name": "my-org", "slug": "my-org"})
	if !org.ok() {
		t.Fatalf("create org: %d %s", org.status, org.raw)
	}
	orgID := org.m()["id"].(string)
	sa := c.req("POST", "/organization/set-active", map[string]any{"organizationId": orgID, "organizationSlug": "my-org"})
	if !sa.ok() {
		t.Fatalf("set-active: %d %s", sa.status, sa.raw)
	}
	sess := c.req("GET", "/get-session", nil)
	if s, _ := sess.m()["session"].(map[string]any); s == nil || s["activeOrganizationId"] != orgID {
		t.Fatalf("session: %s", sess.raw)
	}

	t.Run("should create organizational oauthClient", func(t *testing.T) {
		r := c.register(map[string]any{"redirect_uris": []any{redirectURI}})
		rgExpectUndefined(t, r.m(), "user_id")
		if r.m()["reference_id"] != orgID {
			t.Fatalf("register: %d %s", r.status, r.raw)
		}
	})
}

func TestRg_OauthRegisterSkipConsentBlocked(t *testing.T) {
	env := newEnv(t, Options{AllowDynamicClientRegistration: true})
	c := rgClient{env, env.signInWithTestUser()}
	t.Run("should reject skip_consent during dynamic registration", func(t *testing.T) {
		rgErr(t, c.register(map[string]any{"redirect_uris": []any{"https://rp.example.com/callback"}, "skip_consent": true}), 400)
	})
	t.Run("should allow registration without skip_consent", func(t *testing.T) {
		r := c.register(map[string]any{"redirect_uris": []any{"https://rp.example.com/callback"}})
		rgExpectDefined(t, r.m(), "client_id")
	})
}

// rgJSONList normalises a stored string[] column (array or JSON string).
func rgJSONList(v any) any {
	if s, ok := v.(string); ok {
		var out any
		if json.Unmarshal([]byte(s), &out) == nil {
			return out
		}
	}
	return rgNorm(v)
}
