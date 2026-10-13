package oauthprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of oidc-rs256-profile.test.ts.

func TestMx_OpenIDConnectRS256ProviderProfile(t *testing.T) {
	issuer := testAuthBase
	providerID := "oidc-conformance"
	redirectURI := "http://localhost:5000/api/auth/callback/" + providerID
	state := "oidc-conformance-state"
	nonce := "oidc-conformance-nonce"
	scopes := []string{"openid", "profile", "email"}
	env := newEnv(t, Options{}, envOptions{jwt: &jwt.Options{JWKS: &jwt.JWKSOptions{
		KeyPairConfig: &jwt.JWKOptions{Alg: "RS256", ModulusLength: 2048}}}})
	h := env.signInWithTestUser()
	oc := env.adminCreateClient(h, map[string]any{
		"redirect_uris": []any{redirectURI}, "application_type": "native",
		"token_endpoint_auth_method": "client_secret_post", "skip_consent": true,
	})
	clientID, _ := oc["client_id"].(string)
	clientSecret, _ := oc["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		t.Fatalf("client: %v", oc)
	}
	fetchJWKS := func(t *testing.T) map[string]any {
		t.Helper()
		res := env.do("GET", "/jwks", nil, h)
		if res.status != 200 {
			t.Fatalf("jwks: %d %s", res.status, res.body)
		}
		return res.json()
	}

	t.Run("advertises the RS256 OpenID provider signing contract", func(t *testing.T) {
		md := env.mustCall("getOpenIdConfig", betterauth.CallInput{})
		want := map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/oauth2/authorize",
			"token_endpoint":                        issuer + "/oauth2/token",
			"userinfo_endpoint":                     issuer + "/oauth2/userinfo",
			"jwks_uri":                              issuer + "/jwks",
			"response_types_supported":              []any{"code"},
			"response_modes_supported":              []any{"query"},
			"grant_types_supported":                 []any{"authorization_code", "client_credentials", "refresh_token"},
			"code_challenge_methods_supported":      []any{"S256"},
			"subject_types_supported":               []any{"public"},
			"acr_values_supported":                  []any{"0"},
			"id_token_signing_alg_values_supported": []any{"RS256"},
		}
		for k, v := range want {
			mxExpectJSON(t, map[string]any{k: md[k]}, map[string]any{k: v})
		}
		found := false
		keys, _ := fetchJWKS(t)["keys"].([]any)
		for _, k := range keys {
			if m, _ := k.(map[string]any); m["alg"] == "RS256" && m["kty"] == "RSA" {
				found = true
			}
		}
		if !found {
			t.Fatalf("no RS256 RSA key in %v", keys)
		}
	})

	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"acr_values", []string{"acr_values", "1"}},
		{"voluntary ACR claim", []string{"claims", `{"id_token":{"acr":{"values":["1"]}}}`}},
	} {
		t.Run("issues an RS256 ID token with the current ACR for unsupported "+tc.name, func(t *testing.T) {
			verifier := crypto.RandomString(32)
			extra := append([]string{"nonce", nonce}, tc.extra...)
			res := env.do("GET", mxAuthorizationURL(clientID, redirectURI, state, scopes, verifier, extra...), nil, h)
			loc := res.location()
			if !strings.Contains(loc, redirectURI) || !strings.Contains(loc, "code=") {
				t.Fatalf("callback: %d %q %s", res.status, loc, res.body)
			}
			cb, _ := url.Parse(loc)
			code := cb.Query().Get("code")
			if cb.Scheme+"://"+cb.Host+cb.Path != redirectURI || cb.Query().Get("state") != state || code == "" {
				t.Fatalf("callback: %q", loc)
			}
			tok := env.do("POST", "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
				"code_verifier": {verifier}, "redirect_uri": {redirectURI}, "client_id": {clientID}, "client_secret": {clientSecret}},
				http.Header{"Accept": {"application/json"}})
			tm := tok.json()
			at, _ := tm["access_token"].(string)
			idt, _ := tm["id_token"].(string)
			if at == "" || idt == "" || tm["scope"] != strings.Join(scopes, " ") || tm["token_type"] != "Bearer" {
				t.Fatalf("token: %d %s", tok.status, tok.body)
			}
			if tok.header.Get("Cache-Control") != "no-store" || tok.header.Get("Pragma") != "no-cache" {
				t.Fatalf("headers: %v", tok.header)
			}
			keys, err := oauthcore.LocalJWKSet(fetchJWKS(t))
			if err != nil {
				t.Fatal(err)
			}
			v, err := oauthcore.JWTVerify(idt, keys, oauthcore.VerifyOptions{Issuer: []string{issuer}, Audience: []string{clientID}})
			if err != nil {
				t.Fatalf("verify id token: %v", err)
			}
			if alg, _ := v.Header.Get("alg"); alg != "RS256" {
				t.Fatalf("alg: %v", alg)
			}
			p, _ := mxJSON(t, v.Payload).(map[string]any)
			if p["iss"] != issuer || p["aud"] != clientID || p["nonce"] != nonce || p["acr"] != "0" {
				t.Fatalf("payload: %v", p)
			}
			if _, ok := p["sub"].(string); !ok {
				t.Fatalf("sub: %v", p)
			}
			if _, ok := p["auth_time"].(float64); !ok {
				t.Fatalf("auth_time: %v", p)
			}
			if _, ok := p["at_hash"].(string); !ok {
				t.Fatalf("at_hash: %v", p)
			}
			for _, k := range []string{"name", "email", "email_verified"} {
				if _, ok := p[k]; ok {
					t.Fatalf("%s present in id token: %v", k, p)
				}
			}
			ui := env.do("GET", "/oauth2/userinfo", nil, http.Header{"Authorization": {"Bearer " + at}})
			um := ui.json()
			if um["sub"] != p["sub"] || um["name"] != testUserName || um["email"] != testUserEmail {
				t.Fatalf("userinfo: %d %s", ui.status, ui.body)
			}
			if _, ok := um["email_verified"].(bool); !ok {
				t.Fatalf("email_verified: %v", um)
			}
		})
	}
}
