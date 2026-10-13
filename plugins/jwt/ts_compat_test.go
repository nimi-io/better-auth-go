package jwt_test

// Cross-compatibility with better-auth@1.7.7 (fixtures from e2e/scripts/gen-jwt-fixtures.mjs):
// JWKS rows written by TypeScript (private keys encrypted with symmetricEncrypt) are used by
// Go to sign, TypeScript tokens verify in Go, and Go renders the identical /jwks document.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

type tsFixtures struct {
	Secret  string `json:"secret"`
	BaseURL string `json:"baseURL"`
	Cases   []struct {
		Alg       string           `json:"alg"`
		Encrypted bool             `json:"encrypted"`
		Rows      []map[string]any `json:"rows"`
		JWKS      json.RawMessage  `json:"jwks"`
		Token     string           `json:"token"`
	} `json:"cases"`
}

func TestTSCompatibility(t *testing.T) {
	raw, err := os.ReadFile("testdata/ts-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx tsFixtures
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	for _, c := range fx.Cases {
		name := c.Alg
		if !c.Encrypted {
			name += " (plain private key)"
		}
		t.Run(name, func(t *testing.T) {
			opts := jwt.Options{JWKS: &jwt.JWKSOptions{KeyPairConfig: &jwt.JWKOptions{Alg: c.Alg}, DisablePrivateKeyEncryption: !c.Encrypted}}
			in := newInstance(t, func(cfg *betterauth.Config) {
				cfg.Secret = fx.Secret
				cfg.BaseURL = fx.BaseURL
				cfg.Plugins = append(cfg.Plugins, jwt.New(opts))
			}, instanceOpts{disableTestUser: true})
			for _, r := range c.Rows {
				rec := adapter.Record{}
				for k, v := range r {
					if v == nil {
						continue
					}
					if k == "createdAt" || k == "expiresAt" {
						tm, _ := time.Parse(time.RFC3339Nano, v.(string))
						v = tm
					}
					rec[k] = v
				}
				if _, err := in.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "jwks", Data: rec, ForceAllowID: true}); err != nil {
					t.Fatal(err)
				}
			}
			kid := c.Rows[0]["id"].(string)

			// TypeScript token verifies with the Go verifyJWT (stored keys + issuer/audience)
			p := jwt.VerifyJWT(in.ctx(), c.Token, &opts)
			if p == nil {
				t.Fatal("TS token rejected by VerifyJWT")
			}
			if v, _ := p.Get("custom"); v != "value" {
				t.Fatalf("payload %v", p)
			}
			r, err := in.call("verifyJWT", betterauth.CallInput{Body: map[string]any{"token": c.Token}})
			if err != nil {
				t.Fatal(err)
			}
			var vr struct{ Payload map[string]any }
			_ = r.Decode(&vr)
			if vr.Payload["sub"] != "user-1" {
				t.Fatalf("verifyJWT endpoint %v", vr)
			}

			// identical /jwks document
			res := in.do("GET", "/jwks", nil, nil)
			var goDoc, tsDoc any
			_ = json.Unmarshal(res.Body, &goDoc)
			_ = json.Unmarshal(c.JWKS, &tsDoc)
			gb, _ := json.Marshal(goDoc)
			tb, _ := json.Marshal(tsDoc)
			if string(gb) != string(tb) || string(res.Body) != compact(t, c.JWKS) {
				t.Fatalf("jwks differ:\n go %s\n ts %s", res.Body, compact(t, c.JWKS))
			}

			// Go signs with the TypeScript key (decrypting the TS-encrypted private key)
			// (jwt.SignJWT with an ordered payload; the server-only signJWT endpoint receives a
			// Go map body whose key order is not preserved)
			tok, err := jwt.SignJWT(in.ctx(), jwt.SignConfig{Options: &opts,
				Payload: jsonx.O("sub", "user-1", "custom", "value", "exp", float64(4102444800))})
			if err != nil {
				t.Fatal(err)
			}
			out := struct{ Token string }{tok}
			set, err := jose.ParseJWKS(c.JWKS)
			if err != nil {
				t.Fatal(err)
			}
			h, payload, err := jose.VerifyJWT(out.Token, jose.KeySetFunc(set), jose.VerifyOptions{Issuer: []string{fx.BaseURL}, Audience: []string{fx.BaseURL}})
			if err != nil {
				t.Fatalf("Go token does not verify with the TS JWKS: %v", err)
			}
			if k, _ := h.Get("kid"); k != kid {
				t.Fatalf("kid %v want %v", k, kid)
			}
			// same claims (and claim order) as the TypeScript token for the same input
			_, tsPayload, _ := jose.Decode(c.Token)
			if string(mustJSON(payload)) != string(mustJSON(tsPayload)) {
				t.Fatalf("claims differ:\n go %s\n ts %s", mustJSON(payload), mustJSON(tsPayload))
			}
		})
	}
	t.Run("wrong secret cannot decrypt a TypeScript key", func(t *testing.T) {
		c := fx.Cases[0]
		opts := jwt.Options{}
		in := newInstance(t, func(cfg *betterauth.Config) { cfg.Plugins = append(cfg.Plugins, jwt.New(opts)) }, instanceOpts{disableTestUser: true})
		rec := adapter.Record{}
		for k, v := range c.Rows[0] {
			if k == "createdAt" {
				v = time.Now()
			}
			if v != nil {
				rec[k] = v
			}
		}
		if _, err := in.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "jwks", Data: rec, ForceAllowID: true}); err != nil {
			t.Fatal(err)
		}
		_, err := jwt.SignJWT(in.ctx(), jwt.SignConfig{Options: &opts, Payload: nowPayload("x")})
		if err == nil || err.Error() != jwt.ErrDecryptPrivateKey.Error() {
			t.Fatalf("err %v", err)
		}
	})
}

func compact(t *testing.T, raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// re-encode preserving key order via the jose/jsonx-compatible path
	return string(mustOrdered(raw))
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// mustOrdered compacts JSON without reordering keys.
func mustOrdered(raw []byte) []byte {
	var buf = make([]byte, 0, len(raw))
	inStr, esc := false, false
	for _, ch := range raw {
		if inStr {
			buf = append(buf, ch)
			if esc {
				esc = false
			} else if ch == '\\' {
				esc = true
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case ' ', '\n', '\t', '\r':
			continue
		case '"':
			inStr = true
		}
		buf = append(buf, ch)
	}
	return buf
}
