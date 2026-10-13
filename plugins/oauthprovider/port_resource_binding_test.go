package oauthprovider

import (
	"net/url"
	"testing"

	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of resource-binding.test.ts.

func rsAudValues(aud any) []string {
	switch v := aud.(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			s, _ := x.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

func rsContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestRs_ResourceIndicatorBinding(t *testing.T) {
	const (
		rpBase    = "http://localhost:5000"
		resourceA = "https://api-a.example.com"
		resourceB = "https://api-b.example.com"
	)
	env := newEnv(t, Options{
		Resources:                 []ResourceInput{{Identifier: resourceA}, {Identifier: resourceB}},
		EnforcePerClientResources: rsBool(false),
	}, envOptions{jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}}})
	h := env.signInWithTestUser()
	redirectURI := rpBase + "/api/auth/oauth2/callback/test"
	client := env.adminCreateClient(h, map[string]any{
		"redirect_uris":              []any{redirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
	})
	clientID, _ := client["client_id"].(string)
	secret, _ := client["client_secret"].(string)
	if clientID == "" || secret == "" {
		t.Fatalf("client: %v", client)
	}
	authorize := func(t *testing.T, resources ...string) (string, string) {
		verifier, challenge := pkcePair()
		kv := []string{"response_type", "code", "client_id", clientID, "state", "rfc8707", "scope", "openid offline_access",
			"redirect_uri", redirectURI, "code_challenge", challenge, "code_challenge_method", "S256"}
		for _, r := range resources {
			kv = append(kv, "resource", r)
		}
		return env.authorizeCode(h, kv...), verifier
	}
	exchange := func(code, verifier string, resources ...string) *response {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
			"redirect_uri": {redirectURI}, "client_id": {clientID}, "client_secret": {secret}}
		for _, r := range resources {
			f.Add("resource", r)
		}
		return env.token(f, h)
	}
	refresh := func(rt string, resources ...string) *response {
		f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID},
			"client_secret": {secret}, "scope": {"openid offline_access"}}
		for _, r := range resources {
			f.Add("resource", r)
		}
		return env.token(f, h)
	}

	t.Run("rejects a token for a resource the authorization did not cover", func(t *testing.T) {
		code, v := authorize(t, resourceA)
		res := exchange(code, v, resourceB)
		if res.status < 400 || res.json()["access_token"] != nil {
			t.Fatalf("expected error: %d %s", res.status, res.body)
		}
	})
	t.Run("narrows the JWT access-token audience to the requested resource subset", func(t *testing.T) {
		code, v := authorize(t, resourceA, resourceB)
		res := exchange(code, v, resourceA)
		if res.status != 200 {
			t.Fatalf("%d %s", res.status, res.body)
		}
		aud := rsAudValues(decodeJWTPayload(t, res.json()["access_token"].(string))["aud"])
		if !rsContains(aud, resourceA) || rsContains(aud, resourceB) {
			t.Fatal(aud)
		}
	})
	t.Run("inherits the authorized resource when the token request omits it", func(t *testing.T) {
		code, v := authorize(t, resourceA)
		res := exchange(code, v)
		if res.status != 200 {
			t.Fatalf("%d %s", res.status, res.body)
		}
		aud := rsAudValues(decodeJWTPayload(t, res.json()["access_token"].(string))["aud"])
		if !rsContains(aud, resourceA) {
			t.Fatal(aud)
		}
	})
	t.Run("keeps the full authorized set on the refresh token across narrowing", func(t *testing.T) {
		code, v := authorize(t, resourceA, resourceB)
		initial := exchange(code, v, resourceA)
		rt, _ := initial.json()["refresh_token"].(string)
		if rt == "" {
			t.Fatalf("%d %s", initial.status, initial.body)
		}
		res := refresh(rt)
		if res.status != 200 {
			t.Fatalf("%d %s", res.status, res.body)
		}
		aud := rsAudValues(decodeJWTPayload(t, res.json()["access_token"].(string))["aud"])
		if !rsContains(aud, resourceA) || !rsContains(aud, resourceB) {
			t.Fatal(aud)
		}
	})
	t.Run("rejects a refresh that widens beyond the authorized resources", func(t *testing.T) {
		code, v := authorize(t, resourceA)
		initial := exchange(code, v, resourceA)
		rt, _ := initial.json()["refresh_token"].(string)
		if rt == "" {
			t.Fatalf("%d %s", initial.status, initial.body)
		}
		res := refresh(rt, resourceB)
		if res.status < 400 {
			t.Fatalf("expected error: %d %s", res.status, res.body)
		}
	})
}

func rsBool(b bool) *bool { return &b }
