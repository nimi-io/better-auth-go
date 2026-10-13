package oauthprovider

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Port of client-jwks.test.ts.
func TestRg_ValidatePublicClientJwks(t *testing.T) {
	m := func(kv ...any) map[string]any {
		out := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	expectValid := func(t *testing.T, key map[string]any) {
		t.Helper()
		r := ValidatePublicClientJwks(map[string]any{"keys": []any{key}})
		if !r.Valid || r.JWKS == nil {
			t.Fatalf("expected valid, got %+v", r)
		}
		raw, _ := json.Marshal(r.JWKS)
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		want := map[string]any{"keys": []any{key}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("jwks mismatch: %v vs %v", got, want)
		}
	}
	for _, key := range []map[string]any{
		m("kty", "RSA", "n", "public-modulus", "e", "AQAB"),
		m("kty", "EC", "crv", "P-256", "x", "public-x", "y", "public-y"),
		m("kty", "EC", "crv", "P-384", "x", "public-x", "y", "public-y"),
		m("kty", "EC", "crv", "P-521", "x", "public-x", "y", "public-y"),
		m("kty", "OKP", "crv", "Ed25519", "x", "public-x"),
	} {
		t.Run("accepts a supported public "+key["kty"].(string)+" key", func(t *testing.T) { expectValid(t, key) })
	}
	for _, key := range []map[string]any{
		m("kty", "RSA", "n", "public-modulus", "e", "AQAB", "alg", "RS256"),
		m("kty", "RSA", "n", "public-modulus", "e", "AQAB", "alg", "PS512"),
		m("kty", "EC", "crv", "P-256", "x", "public-x", "y", "public-y", "alg", "ES256"),
		m("kty", "EC", "crv", "P-384", "x", "public-x", "y", "public-y", "alg", "ES384"),
		m("kty", "EC", "crv", "P-521", "x", "public-x", "y", "public-y", "alg", "ES512"),
		m("kty", "OKP", "crv", "Ed25519", "x", "public-x", "alg", "EdDSA"),
	} {
		t.Run("accepts "+key["alg"].(string)+" for a compatible public "+key["kty"].(string)+" key", func(t *testing.T) { expectValid(t, key) })
	}
	rejects := []struct {
		name string
		jwks any
	}{
		{"missing set", nil},
		{"bare key array", []any{m("kty", "RSA", "n", "public-modulus", "e", "AQAB")}},
		{"empty set", m("keys", []any{})},
		{"non-object key", m("keys", []any{"key"})},
		{"symmetric key", m("keys", []any{m("kty", "oct", "k", "secret")})},
		{"private RSA key", m("keys", []any{m("kty", "RSA", "n", "n", "e", "AQAB", "d", "private")})},
		{"private EC key", m("keys", []any{m("kty", "EC", "crv", "P-256", "x", "x", "y", "y", "d", "private")})},
		{"private OKP key", m("keys", []any{m("kty", "OKP", "crv", "Ed25519", "x", "x", "d", "private")})},
		{"incomplete RSA key", m("keys", []any{m("kty", "RSA", "n", "n")})},
		{"unsupported key type", m("keys", []any{m("kty", "AKP", "alg", "ML-DSA-65", "pub", "public")})},
		{"symmetric RSA algorithm", m("keys", []any{m("kty", "RSA", "n", "public-modulus", "e", "AQAB", "alg", "HS256")})},
		{"RSA key with an EC algorithm", m("keys", []any{m("kty", "RSA", "n", "public-modulus", "e", "AQAB", "alg", "ES256")})},
		{"EC key with an RSA algorithm", m("keys", []any{m("kty", "EC", "crv", "P-256", "x", "public-x", "y", "public-y", "alg", "RS256")})},
		{"OKP key with an EC algorithm", m("keys", []any{m("kty", "OKP", "crv", "Ed25519", "x", "public-x", "alg", "ES256")})},
		{"EC key with a mismatched signing curve", m("keys", []any{m("kty", "EC", "crv", "P-256", "x", "public-x", "y", "public-y", "alg", "ES384")})},
		{"EC key with an unsupported signing curve", m("keys", []any{m("kty", "EC", "crv", "secp256k1", "x", "public-x", "y", "public-y")})},
		{"OKP key with an X25519 encryption curve", m("keys", []any{m("kty", "OKP", "crv", "X25519", "x", "public-x")})},
		{"OKP key with an X448 encryption curve", m("keys", []any{m("kty", "OKP", "crv", "X448", "x", "public-x")})},
		{"OKP key with unsupported Ed448 signing curve", m("keys", []any{m("kty", "OKP", "crv", "Ed448", "x", "public-x", "alg", "EdDSA")})},
		{"OKP key with an unknown curve", m("keys", []any{m("kty", "OKP", "crv", "unknown", "x", "public-x")})},
	}
	for _, tc := range rejects {
		t.Run("rejects a "+tc.name, func(t *testing.T) {
			if r := ValidatePublicClientJwks(tc.jwks); r.Valid {
				t.Fatalf("expected invalid, got %+v", r)
			}
		})
	}
}
