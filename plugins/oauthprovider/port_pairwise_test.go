package oauthprovider

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of pairwise.test.ts.

// pkTokensForClient runs the authorization code flow (client_secret_post) and returns the
// token response.
func pkTokensForClient(t *testing.T, env *testEnv, headers http.Header, client map[string]any, redirectURI, resource string) map[string]any {
	t.Helper()
	clientID, _ := client["client_id"].(string)
	secret, _ := client["client_secret"].(string)
	verifier := "pk-" + crypto.RandomString(32)
	code := env.authorizeCode(headers, "response_type", "code", "client_id", clientID, "state", "test-state",
		"scope", "openid profile email offline_access", "redirect_uri", redirectURI,
		"code_challenge", challengeFor(verifier), "code_challenge_method", "S256")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {redirectURI}, "client_id": {clientID}, "client_secret": {secret}}
	if resource != "" {
		form.Set("resource", resource)
	}
	res := env.token(form, nil)
	if res.status != 200 {
		t.Fatalf("token: %d %s", res.status, res.body)
	}
	return res.json()
}

func pkSub(t *testing.T, token any) any {
	t.Helper()
	s, _ := token.(string)
	if s == "" {
		t.Fatalf("missing token")
	}
	return decodeJWTPayload(t, s)["sub"]
}

func TestPk_PairwiseSubjectIdentifiers(t *testing.T) {
	rpBaseURL := "http://localhost:5000"
	rpBaseURL2 := "http://localhost:6000"
	validResource := "https://myapi.example.com"
	f := false
	env := newEnv(t, Options{PairwiseSecret: "test-pairwise-secret-key-32chars!!", Resources: []ResourceInput{{Identifier: validResource}},
		EnforcePerClientResources: &f, AllowDynamicClientRegistration: true},
		envOptions{jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}}})
	headers := env.signInWithTestUser()
	redirectURIA := rpBaseURL + "/api/auth/callback/test-a"
	redirectURIB := rpBaseURL2 + "/api/auth/callback/test-b"
	redirectURISameHost := rpBaseURL + "/api/auth/callback/test-same"
	redirectURIPublic := rpBaseURL + "/api/auth/callback/test-public"
	mk := func(redirect string, pairwise bool) map[string]any {
		body := map[string]any{"redirect_uris": []any{redirect}, "application_type": "native",
			"token_endpoint_auth_method": "client_secret_post", "scope": "openid profile email offline_access",
			"skip_consent": true}
		if pairwise {
			body["subject_type"] = "pairwise"
		}
		c := env.adminCreateClient(headers, body)
		if c["client_id"] == nil {
			t.Fatalf("client: %v", c)
		}
		return c
	}
	pairwiseClientA := mk(redirectURIA, true)
	pairwiseClientB := mk(redirectURIB, true)
	publicClient := mk(redirectURIPublic, false)
	sameHostClientA := mk(redirectURISameHost, true)

	t.Run("should produce different sub across pairwise clients (cross-RP unlinkability)", func(t *testing.T) {
		a := pkSub(t, pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")["id_token"])
		b := pkSub(t, pkTokensForClient(t, env, headers, pairwiseClientB, redirectURIB, "")["id_token"])
		if a == nil || b == nil || a == b {
			t.Fatalf("subs: %v %v", a, b)
		}
	})
	t.Run("should produce same sub for same pairwise client (determinism)", func(t *testing.T) {
		a := pkSub(t, pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")["id_token"])
		b := pkSub(t, pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")["id_token"])
		if a != b {
			t.Fatalf("subs: %v %v", a, b)
		}
	})
	t.Run("should return user.id as sub for public client (fallback)", func(t *testing.T) {
		pub := pkSub(t, pkTokensForClient(t, env, headers, publicClient, redirectURIPublic, "")["id_token"])
		pw := pkSub(t, pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")["id_token"])
		if pub == nil || pub == pw {
			t.Fatalf("subs: %v %v", pub, pw)
		}
	})
	t.Run("should produce same pairwise sub for clients on same host (sector isolation)", func(t *testing.T) {
		a := pkSub(t, pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")["id_token"])
		b := pkSub(t, pkTokensForClient(t, env, headers, sameHostClientA, redirectURISameHost, "")["id_token"])
		if a != b {
			t.Fatalf("subs: %v %v", a, b)
		}
	})
	t.Run("should have consistent sub between id_token and userinfo", func(t *testing.T) {
		tokens := pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")
		sub := pkSub(t, tokens["id_token"])
		ui := env.do("GET", "/oauth2/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
		if ui.status != 200 || ui.json()["sub"] != sub {
			t.Fatalf("userinfo %d %s (want sub %v)", ui.status, ui.body, sub)
		}
	})
	t.Run("should return pairwise sub in opaque access token introspection", func(t *testing.T) {
		tokens := pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")
		res := env.do("POST", "/oauth2/introspect", url.Values{"client_id": {pairwiseClientA["client_id"].(string)},
			"client_secret": {pairwiseClientA["client_secret"].(string)}, "token": {tokens["access_token"].(string)},
			"token_type_hint": {"access_token"}}, http.Header{"Accept": {"application/json"}})
		sub := pkSub(t, tokens["id_token"])
		m := res.json()
		if m["active"] != true || m["sub"] != sub {
			t.Fatalf("introspection: %d %s (want sub %v)", res.status, res.body, sub)
		}
	})
	t.Run("should preserve pairwise sub after token refresh", func(t *testing.T) {
		tokens := pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, "")
		orig := pkSub(t, tokens["id_token"])
		res := env.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {pairwiseClientA["client_id"].(string)},
			"client_secret": {pairwiseClientA["client_secret"].(string)}, "refresh_token": {tokens["refresh_token"].(string)}}, nil)
		m := res.json()
		if m["id_token"] == nil {
			t.Fatalf("refresh: %d %s", res.status, res.body)
		}
		if pkSub(t, m["id_token"]) != orig {
			t.Fatalf("sub changed")
		}
	})
	t.Run("should keep user.id in JWT access token sub (not pairwise)", func(t *testing.T) {
		tokens := pkTokensForClient(t, env, headers, pairwiseClientA, redirectURIA, validResource)
		at := pkSub(t, tokens["access_token"])
		id := pkSub(t, tokens["id_token"])
		if at == nil || at == id {
			t.Fatalf("subs: %v %v", at, id)
		}
	})
}

func TestPk_PairwiseDCRValidation(t *testing.T) {
	redirectURI := "http://localhost:5000/api/auth/callback/test"
	secret := "test-secret-for-dcr-test-32chars!"

	t.Run("should reject pairwise subject_type when pairwiseSecret not configured", func(t *testing.T) {
		env := newEnv(t, Options{})
		h := env.signInWithTestUser()
		_, err := env.call("adminCreateOAuthClient", betterauth.CallInput{Headers: h, Body: map[string]any{
			"redirect_uris": []any{redirectURI}, "application_type": "native", "subject_type": "pairwise"}})
		if err == nil {
			t.Fatal("expected APIError")
		}
	})
	t.Run("should accept pairwise subject_type when pairwiseSecret is configured", func(t *testing.T) {
		env := newEnv(t, Options{PairwiseSecret: secret})
		h := env.signInWithTestUser()
		res := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{redirectURI}, "application_type": "native",
			"subject_type": "pairwise", "skip_consent": true})
		if res["client_id"] == nil || res["subject_type"] != "pairwise" {
			t.Fatalf("client: %v", res)
		}
	})
	t.Run("should default to public when no subject_type specified", func(t *testing.T) {
		env := newEnv(t, Options{PairwiseSecret: secret})
		h := env.signInWithTestUser()
		res := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{redirectURI}, "application_type": "native",
			"skip_consent": true})
		if res["client_id"] == nil {
			t.Fatalf("client: %v", res)
		}
		if _, ok := res["subject_type"]; ok {
			t.Fatalf("subject_type defined: %v", res["subject_type"])
		}
	})
	t.Run("should reject pairwise client with redirect_uris on different hosts", func(t *testing.T) {
		env := newEnv(t, Options{PairwiseSecret: secret})
		h := env.signInWithTestUser()
		_, err := env.call("adminCreateOAuthClient", betterauth.CallInput{Headers: h, Body: map[string]any{
			"redirect_uris": []any{"https://app-a.example.com/callback", "https://app-b.example.com/callback"},
			"subject_type":  "pairwise"}})
		if err == nil {
			t.Fatal("expected APIError")
		}
	})
	t.Run("should accept pairwise client with redirect_uris on the same host", func(t *testing.T) {
		env := newEnv(t, Options{PairwiseSecret: secret})
		h := env.signInWithTestUser()
		res := env.adminCreateClient(h, map[string]any{
			"redirect_uris": []any{"https://app.example.com/callback-a", "https://app.example.com/callback-b"},
			"subject_type":  "pairwise", "skip_consent": true})
		if res["client_id"] == nil || res["subject_type"] != "pairwise" {
			t.Fatalf("client: %v", res)
		}
	})
	t.Run("should round-trip subject_type through DCR", func(t *testing.T) {
		env := newEnv(t, Options{PairwiseSecret: secret, AllowDynamicClientRegistration: true})
		h := env.signInWithTestUser()
		res := env.do("POST", "/oauth2/register", map[string]any{"redirect_uris": []any{redirectURI},
			"application_type": "native", "subject_type": "pairwise", "token_endpoint_auth_method": "none"}, h)
		if res.json()["subject_type"] != "pairwise" {
			t.Fatalf("register: %d %s", res.status, res.body)
		}
	})
}

func TestPk_PairwiseConfigurationValidation(t *testing.T) {
	t.Run("should reject pairwiseSecret shorter than 32 characters", func(t *testing.T) {
		_, err := resolveOptions(Options{LoginPage: "/login", ConsentPage: "/consent", PairwiseSecret: "too-short"})
		if err == nil || !strings.Contains(err.Error(), "pairwiseSecret must be at least 32 characters") {
			t.Fatalf("err: %v", err)
		}
		// betterauth.New surfaces the same error.
		env := newEnv(t, Options{PairwiseSecret: "too-short"}, envOptions{expectInitError: true})
		if !strings.Contains(env.initErr.Error(), "pairwiseSecret must be at least 32 characters") {
			t.Fatalf("init err: %v", env.initErr)
		}
	})
	t.Run("should accept pairwiseSecret of 32+ characters", func(t *testing.T) {
		if _, err := resolveOptions(Options{LoginPage: "/login", ConsentPage: "/consent",
			PairwiseSecret: "a-valid-secret-that-is-32-chars!"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPk_PairwiseMetadata(t *testing.T) {
	t.Run("should include pairwise in subject_types_supported when secret configured", func(t *testing.T) {
		env := newEnv(t, Options{PairwiseSecret: "test-pairwise-metadata-secret!!!"})
		md := env.mustCall("getOpenIdConfig", betterauth.CallInput{})
		if !reflect.DeepEqual(md["subject_types_supported"], []any{"public", "pairwise"}) {
			t.Fatalf("subject_types_supported: %v", md["subject_types_supported"])
		}
	})
	t.Run("should only include public when no pairwise secret", func(t *testing.T) {
		env := newEnv(t, Options{})
		md := env.mustCall("getOpenIdConfig", betterauth.CallInput{})
		if !reflect.DeepEqual(md["subject_types_supported"], []any{"public"}) {
			t.Fatalf("subject_types_supported: %v", md["subject_types_supported"])
		}
	})
}
