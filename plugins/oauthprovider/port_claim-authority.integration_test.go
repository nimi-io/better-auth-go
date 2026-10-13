package oauthprovider

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of claim-authority.integration.test.ts.

const (
	mxRPBaseURL   = "http://localhost:5000"
	mxProviderID  = "test"
	mxRedirectURI = mxRPBaseURL + "/api/auth/callback/" + mxProviderID
	mxState       = "123"
)

type mxHarness struct {
	t       *testing.T
	env     *testEnv
	headers http.Header
	userID  string
	scopes  []string
}

// mxBootHarness mirrors bootHarness: oauth-provider (enforcePerClientResources=false)
// followed by the jwt plugin (issuer = base URL) unless disableJwtPlugin.
func mxBootHarness(t *testing.T, opts Options, scopes ...string) *mxHarness {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if opts.EnforcePerClientResources == nil {
		opts.EnforcePerClientResources = mxBoolPtr(false)
	}
	opts.Scopes = scopes
	eo := envOptions{noJwt: true}
	if !opts.DisableJwtPlugin {
		eo.plugins = []*betterauth.Plugin{jwt.New(jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}})}
	}
	env := newEnv(t, opts, eo)
	ResetSeedStateForTests(env.plugin)
	if err := seedResourcesOnce(context.Background(), env.auth.Context(), env.plugin.Options.(*resolved)); err != nil {
		t.Fatal(err)
	}
	h := env.signInWithTestUser()
	user := env.findOne("user", eq("email", testUserEmail))
	return &mxHarness{t: t, env: env, headers: h, userID: recStr(user, "id"), scopes: scopes}
}

type mxClient struct{ id, secret string }

func (hn *mxHarness) registerClient(overrides map[string]any) mxClient {
	hn.t.Helper()
	body := map[string]any{
		"redirect_uris":              []any{mxRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      strings.Join(hn.scopes, " "),
		"skip_consent":               true,
	}
	for k, v := range overrides {
		body[k] = v
	}
	created := hn.env.adminCreateClient(hn.headers, body)
	id, _ := created["client_id"].(string)
	secret, _ := created["client_secret"].(string)
	if id == "" || secret == "" {
		hn.t.Fatalf("admin client creation failed: %v", created)
	}
	return mxClient{id, secret}
}

// mxAuthorizationURL mirrors better-auth's createAuthorizationURL parameter order.
func mxAuthorizationURL(clientID, redirectURI, state string, scopes []string, codeVerifier string, extra ...string) string {
	kv := []string{"response_type", "code", "client_id", clientID, "state", state, "scope", strings.Join(scopes, " "),
		"redirect_uri", redirectURI, "code_challenge_method", "S256", "code_challenge", challengeFor(codeVerifier)}
	return authorizeURL(append(kv, extra...)...)
}

func (hn *mxHarness) mintToken(c mxClient, resources ...string) string {
	hn.t.Helper()
	verifier := crypto.RandomString(32)
	var extra []string
	for _, r := range resources {
		extra = append(extra, "resource", r)
	}
	res := hn.env.do("GET", mxAuthorizationURL(c.id, mxRedirectURI, mxState, hn.scopes, verifier, extra...), nil, hn.headers)
	u, err := url.Parse(res.location())
	if err != nil || u.Query().Get("code") == "" {
		hn.t.Fatalf("authorization code not issued: %d %q %s", res.status, res.location(), res.body)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {mxRedirectURI}, "client_id": {c.id}, "client_secret": {c.secret}, "scope": {strings.Join(hn.scopes, " ")},
	}
	if len(resources) > 0 {
		form["resource"] = resources
	}
	tok := hn.env.do("POST", "/oauth2/token", form, http.Header{"Accept": {"application/json"}})
	at, _ := tok.json()["access_token"].(string)
	if at == "" {
		hn.t.Fatalf("access token not issued: %d %s", tok.status, tok.body)
	}
	return at
}

func (hn *mxHarness) introspect(token string, c mxClient) map[string]any {
	hn.t.Helper()
	res := hn.env.do("POST", "/oauth2/introspect", url.Values{"client_id": {c.id}, "client_secret": {c.secret},
		"token": {token}, "token_type_hint": {"access_token"}}, http.Header{"Accept": {"application/json"}})
	if res.status != 200 {
		hn.t.Fatalf("introspect: %d %s", res.status, res.body)
	}
	return res.json()
}

func (hn *mxHarness) linkClientToResource(clientID, resourceID string) {
	hn.t.Helper()
	if _, err := hn.env.db.Create(context.Background(), adapter.CreateInput{Model: "oauthClientResource",
		Data: adapter.Record{"clientId": clientID, "resourceId": resourceID, "createdAt": time.Now()}}); err != nil {
		hn.t.Fatal(err)
	}
}

func TestMx_OpaqueIntrospectionReservedClaimStripping(t *testing.T) {
	hn := mxBootHarness(t, Options{DisableJwtPlugin: true,
		CustomAccessTokenClaims: func(AccessTokenClaimsInput) (*jsonx.Object, error) {
			return jsonx.O("role", "admin", "iss", "https://evil.example", "scope", "evil", "auth_time", 999, "amr", []any{"evil"}), nil
		}})
	c := hn.registerClient(nil)
	t.Run("keeps enriched claims and strips reserved RFC 9068 names the AS owns", func(t *testing.T) {
		data := hn.introspect(hn.mintToken(c), c)
		if data["active"] != true || data["role"] != "admin" || data["iss"] != testAuthBase ||
			data["scope"] != "openid profile email offline_access" {
			t.Fatalf("introspection: %v", data)
		}
		if _, ok := data["auth_time"]; ok {
			t.Fatalf("auth_time present: %v", data)
		}
		if _, ok := data["amr"]; ok {
			t.Fatalf("amr present: %v", data)
		}
	})
}

func TestMx_OpaqueIntrospectionPerResourceCustomClaimsParity(t *testing.T) {
	resource := "https://api.example.com/claims-parity"
	hn := mxBootHarness(t, Options{DisableJwtPlugin: true,
		Resources: []ResourceInput{{Identifier: resource, CustomClaims: jsonx.O("dept", "ops")}}})
	c := hn.registerClient(nil)
	t.Run("includes per-resource customClaims for a resource-bound opaque token", func(t *testing.T) {
		data := hn.introspect(hn.mintToken(c, resource), c)
		if data["active"] != true || data["dept"] != "ops" {
			t.Fatalf("introspection: %v", data)
		}
	})
}

func mxIntrospectionAuthorization(t *testing.T, opaque bool, resource string) (*mxHarness, mxClient, mxClient, mxClient) {
	hn := mxBootHarness(t, Options{DisableJwtPlugin: opaque, Resources: mxResources(resource)})
	a, b, c := hn.registerClient(nil), hn.registerClient(nil), hn.registerClient(nil)
	hn.linkClientToResource(b.id, resource)
	return hn, a, b, c
}

func TestMx_IntrospectionAuthorization8267(t *testing.T) {
	resource := "https://api.example.com/rs-8267"
	hn, issuerA, rsB, unrelatedC := mxIntrospectionAuthorization(t, false, resource)
	t.Run("lets the issuer introspect its own resource-bound token", func(t *testing.T) {
		if d := hn.introspect(hn.mintToken(issuerA, resource), issuerA); d["active"] != true {
			t.Fatalf("introspection: %v", d)
		}
	})
	t.Run("lets a resource server linked to the audience introspect the token", func(t *testing.T) {
		if d := hn.introspect(hn.mintToken(issuerA, resource), rsB); d["active"] != true {
			t.Fatalf("introspection: %v", d)
		}
	})
	t.Run("reports inactive to an unlinked client", func(t *testing.T) {
		if d := hn.introspect(hn.mintToken(issuerA, resource), unrelatedC); d["active"] != false {
			t.Fatalf("introspection: %v", d)
		}
	})
	t.Run("keeps a token with no resource audience issuer-only", func(t *testing.T) {
		token := hn.mintToken(issuerA)
		if d := hn.introspect(token, issuerA); d["active"] != true {
			t.Fatalf("issuer view: %v", d)
		}
		if d := hn.introspect(token, rsB); d["active"] != false {
			t.Fatalf("non-issuer view: %v", d)
		}
	})
}

func TestMx_OpaqueIntrospectionResourceLifecycle(t *testing.T) {
	deleted := "https://api.example.com/lifecycle-deleted"
	disabled := "https://api.example.com/lifecycle-disabled"
	hn := mxBootHarness(t, Options{DisableJwtPlugin: true, Resources: []ResourceInput{
		{Identifier: deleted, CustomClaims: jsonx.O("dept", "ops")},
		{Identifier: disabled, CustomClaims: jsonx.O("dept", "sec")},
	}})
	c := hn.registerClient(nil)
	t.Run("reports inactive once the bound resource row is deleted", func(t *testing.T) {
		token := hn.mintToken(c, deleted)
		before := hn.introspect(token, c)
		if before["active"] != true || before["dept"] != "ops" {
			t.Fatalf("before: %v", before)
		}
		if err := hn.env.db.Delete(context.Background(), "oauthResource", []adapter.Where{eq("identifier", deleted)}); err != nil {
			t.Fatal(err)
		}
		if after := hn.introspect(token, c); after["active"] != false {
			t.Fatalf("after: %v", after)
		}
	})
	t.Run("stays active and keeps its claims after the bound resource is disabled", func(t *testing.T) {
		token := hn.mintToken(c, disabled)
		hn.env.update("oauthResource", adapter.Record{"disabled": true}, eq("identifier", disabled))
		if d := hn.introspect(token, c); d["active"] != true || d["dept"] != "sec" {
			t.Fatalf("introspection: %v", d)
		}
	})
}

func TestMx_IntrospectionAuthorization8267OpaqueTokens(t *testing.T) {
	resource := "https://api.example.com/rs-8267-opaque"
	hn, issuerA, rsB, unrelatedC := mxIntrospectionAuthorization(t, true, resource)
	t.Run("lets a linked resource server introspect an opaque resource-bound token", func(t *testing.T) {
		if d := hn.introspect(hn.mintToken(issuerA, resource), rsB); d["active"] != true {
			t.Fatalf("introspection: %v", d)
		}
	})
	t.Run("reports inactive to an unlinked client for an opaque token", func(t *testing.T) {
		if d := hn.introspect(hn.mintToken(issuerA, resource), unrelatedC); d["active"] != false {
			t.Fatalf("introspection: %v", d)
		}
	})
}

func TestMx_IntrospectionPairwiseSubAcrossClients(t *testing.T) {
	resource := "https://api.example.com/rs-pairwise"
	hn := mxBootHarness(t, Options{PairwiseSecret: "pairwise-secret-at-least-32-chars-long", Resources: mxResources(resource)})
	issuer := hn.registerClient(map[string]any{"subject_type": "pairwise"})
	rs := hn.registerClient(nil)
	hn.linkClientToResource(rs.id, resource)
	t.Run("returns the issuing client's pairwise sub to a linked resource server", func(t *testing.T) {
		token := hn.mintToken(issuer, resource)
		iv := hn.introspect(token, issuer)
		rv := hn.introspect(token, rs)
		if iv["active"] != true || rv["active"] != true {
			t.Fatalf("views: %v %v", iv, rv)
		}
		if iv["sub"] == hn.userID || rv["sub"] != iv["sub"] {
			t.Fatalf("subs: issuer %v rs %v user %s", iv["sub"], rv["sub"], hn.userID)
		}
	})
}

func TestMx_IDTokenClaimInputSessionID(t *testing.T) {
	var captured *ClaimExtensionInput
	hn := mxBootHarness(t, Options{Extensions: []*Extension{{Claims: &ExtensionClaims{
		IDToken: func(in ClaimExtensionInput) (*jsonx.Object, error) {
			captured = &in
			return jsonx.O("session_probe", "captured"), nil
		},
	}}}})
	c := hn.registerClient(nil)
	t.Run("passes the issuing session id to a claims.idToken contributor on authorization_code", func(t *testing.T) {
		captured = nil
		hn.mintToken(c)
		if captured == nil {
			t.Fatal("idToken contributor not called")
		}
		if captured.GrantType != "authorization_code" || captured.SessionID == "" {
			t.Fatalf("input: %+v", captured)
		}
	})
}
