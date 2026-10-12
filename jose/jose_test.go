package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// testdata/fixtures.json is produced by e2e/scripts/gen-jose-fixtures.mjs using the jose
// npm library (the library better-auth itself uses).
type fixtures struct {
	Keys []struct {
		Alg        string `json:"alg"`
		Public     JWK    `json:"public"`
		Private    JWK    `json:"private"`
		Thumbprint string `json:"thumbprint"`
	} `json:"keys"`
	Tokens []struct {
		Alg   string `json:"alg"`
		Token string `json:"token"`
	} `json:"tokens"`
}

func load(t *testing.T) fixtures {
	b, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestVerifyTokensSignedByJoseJS(t *testing.T) {
	f := load(t)
	set := JWKS{}
	for _, k := range f.Keys {
		set.Keys = append(set.Keys, k.Public)
		if got := k.Public.Thumbprint(); got != k.Thumbprint {
			t.Errorf("%s thumbprint %s want %s", k.Alg, got, k.Thumbprint)
		}
	}
	for _, tok := range f.Tokens {
		_, p, err := VerifyJWT(tok.Token, KeySetFunc(set), VerifyOptions{
			Issuer: []string{"https://issuer.example.com"}, Audience: []string{"client-1"},
		})
		if err != nil {
			t.Fatalf("%s: %v", tok.Alg, err)
		}
		if sub, _ := p.Get("sub"); sub != "user-1" {
			t.Fatalf("%s payload %s", tok.Alg, jsonx.MustMarshal(p))
		}
		if _, _, err := VerifyJWT(tok.Token, KeySetFunc(set), VerifyOptions{Audience: []string{"other"}}); err == nil {
			t.Fatalf("%s: wrong audience accepted", tok.Alg)
		}
		if _, _, err := VerifyJWT(tok.Token, KeySetFunc(set), VerifyOptions{Algorithms: []string{"HS256"}}); err != ErrAlgorithm {
			t.Fatalf("%s: algorithm restriction not enforced: %v", tok.Alg, err)
		}
	}
}

func TestSignWithJSPrivateKeysRoundTrip(t *testing.T) {
	f := load(t)
	for _, k := range f.Keys {
		priv, err := k.Private.PrivateKey()
		if err != nil {
			t.Fatalf("%s private: %v", k.Alg, err)
		}
		tok, err := SignJWT(jsonx.O("alg", k.Alg, "kid", k.Public.Kid), jsonx.O("sub", "x", "exp", float64(time.Now().Add(time.Hour).Unix())), priv)
		if err != nil {
			t.Fatalf("%s sign: %v", k.Alg, err)
		}
		pub, _ := k.Public.PublicKey()
		if _, _, err := VerifyJWT(tok, StaticKey(pub), VerifyOptions{}); err != nil {
			t.Fatalf("%s verify: %v", k.Alg, err)
		}
	}
}

func TestJWKRoundTripAndClaims(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	for alg, priv := range map[string]any{"RS256": rk, "ES256": ek, "EdDSA": edk} {
		j, err := JWKFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		back, err := j.PrivateKey()
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		tok, _ := SignJWT(jsonx.O("alg", alg), jsonx.O("iat", float64(time.Now().Unix())), back)
		pub, _ := j.Public().PublicKey()
		if _, _, err := VerifyJWT(tok, StaticKey(pub), VerifyOptions{MaxTokenAge: time.Minute}); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
	key := []byte("secret")
	expired, _ := SignJWT(jsonx.O("alg", "HS256"), jsonx.O("exp", float64(time.Now().Add(-time.Minute).Unix())), key)
	if _, _, err := VerifyJWT(expired, StaticKey(key), VerifyOptions{}); err != ErrExpired {
		t.Fatalf("expected expired, got %v", err)
	}
	if _, _, err := VerifyJWT(expired, StaticKey(key), VerifyOptions{ClockTolerance: 2 * time.Minute}); err != nil {
		t.Fatalf("clock tolerance: %v", err)
	}
	nbf, _ := SignJWT(jsonx.O("alg", "HS256"), jsonx.O("nbf", float64(time.Now().Add(time.Hour).Unix())), key)
	if _, _, err := VerifyJWT(nbf, StaticKey(key), VerifyOptions{}); err != ErrNotYetValid {
		t.Fatalf("expected nbf error, got %v", err)
	}
	none := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
	if _, _, err := VerifyJWT(none, StaticKey(key), VerifyOptions{}); err == nil {
		t.Fatal("alg none accepted")
	}
}
