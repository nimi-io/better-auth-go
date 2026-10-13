package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// GenerateKeyOptions configure GenerateKeyPair (the options of jose's generateKeyPair).
type GenerateKeyOptions struct {
	// Crv selects the curve for "EdDSA" (only "Ed25519" is supported; the default).
	Crv string
	// ModulusLength is the RSA key size in bits (default 2048).
	ModulusLength int
}

// GenerateKeyPair generates a signing key pair for a JWS algorithm, like jose's
// generateKeyPair: EdDSA/Ed25519 (Ed25519), ES256 (P-256), ES384 (P-384), ES512 (P-521),
// RS256/384/512 and PS256/384/512 (RSA, default 2048 bits). It returns crypto keys.
func GenerateKeyPair(alg string, o GenerateKeyOptions) (pub, priv any, err error) {
	switch alg {
	case "EdDSA", "Ed25519":
		if o.Crv != "" && o.Crv != "Ed25519" {
			return nil, nil, fmt.Errorf("jose: unsupported or invalid EdDSA curve %q", o.Crv)
		}
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return p, k, nil
	case "ES256", "ES384", "ES512":
		var c elliptic.Curve
		switch alg {
		case "ES256":
			c = elliptic.P256()
		case "ES384":
			c = elliptic.P384()
		default:
			c = elliptic.P521()
		}
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return &k.PublicKey, k, nil
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		bits := o.ModulusLength
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, fmt.Errorf("jose: invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used")
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return &k.PublicKey, k, nil
	}
	return nil, nil, fmt.Errorf("jose: invalid or unsupported JWK \"alg\" (Algorithm) Parameter value %q", alg)
}

// ExportJWK renders a JWK with the member order of jose's exportJWK (Node.js WebCrypto):
// OKP {crv,[d],x,kty}, EC {kty,x,y,crv,[d]}, RSA {kty,n,e,[d,p,q,dp,dq,qi]}. Members other
// than the key material (kid, alg, use) are not included.
func ExportJWK(k JWK) *jsonx.Object {
	o := jsonx.NewObject()
	set := func(name, v string) {
		if v != "" {
			o.Set(name, v)
		}
	}
	switch k.Kty {
	case "OKP":
		set("crv", k.Crv)
		set("d", k.D)
		set("x", k.X)
		o.Set("kty", k.Kty)
	case "EC":
		o.Set("kty", k.Kty)
		set("x", k.X)
		set("y", k.Y)
		set("crv", k.Crv)
		set("d", k.D)
	case "RSA":
		o.Set("kty", k.Kty)
		set("n", k.N)
		set("e", k.E)
		set("d", k.D)
		set("p", k.P)
		set("q", k.Q)
		set("dp", k.DP)
		set("dq", k.DQ)
		set("qi", k.QI)
	default:
		o.Set("kty", k.Kty)
		set("k", k.K)
	}
	return o
}

// KeyMatchesAlg reports whether a JWK can be used with alg (importJWK's key type check).
func KeyMatchesAlg(k JWK, alg string) bool {
	if alg == "Ed25519" {
		return k.Kty == "OKP" && k.Crv == "Ed25519"
	}
	if !ktyMatches(k.Kty, alg) {
		return false
	}
	if k.Kty == "EC" {
		switch alg {
		case "ES256":
			return k.Crv == "P-256"
		case "ES384":
			return k.Crv == "P-384"
		case "ES512":
			return k.Crv == "P-521"
		}
		return false
	}
	if k.Kty == "OKP" {
		return k.Crv == "Ed25519"
	}
	return true
}
