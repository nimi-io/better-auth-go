// Package jose implements the subset of JOSE (JWK, JWS, JWT) used by Better Auth: verifying
// provider id tokens against a JWKS, signing and verifying JWTs for the jwt / OIDC provider
// plugins, and RFC 7638 thumbprints. It uses only the standard library.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Errors returned by verification.
var (
	ErrInvalid       = errors.New("jose: invalid token")
	ErrSignature     = errors.New("jose: signature verification failed")
	ErrExpired       = errors.New("jose: token expired")
	ErrNotYetValid   = errors.New("jose: token not yet valid")
	ErrClaim         = errors.New("jose: claim validation failed")
	ErrNoMatchingKey = errors.New("jose: no matching key")
	ErrAlgorithm     = errors.New("jose: algorithm not allowed")
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// JWK is a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC / OKP
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
	// private parts (RSA d,p,q,dp,dq,qi; EC/OKP d; oct k)
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	DP string `json:"dp,omitempty"`
	DQ string `json:"dq,omitempty"`
	QI string `json:"qi,omitempty"`
	K  string `json:"k,omitempty"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Public returns the key without private material.
func (k JWK) Public() JWK {
	k.D, k.P, k.Q, k.DP, k.DQ, k.QI, k.K = "", "", "", "", "", "", ""
	return k
}

func bigFrom(s string) (*big.Int, error) {
	b, err := unb64(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func curve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("jose: unsupported curve %q", crv)
}

// PublicKey returns the crypto public key (or []byte for oct keys).
func (k JWK) PublicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := bigFrom(k.N)
		if err != nil {
			return nil, err
		}
		e, err := bigFrom(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		c, err := curve(k.Crv)
		if err != nil {
			return nil, err
		}
		size := (c.Params().BitSize + 7) / 8
		x, err := unb64(k.X)
		if err != nil {
			return nil, err
		}
		y, err := unb64(k.Y)
		if err != nil {
			return nil, err
		}
		raw := append([]byte{4}, append(padBytes(x, size), padBytes(y, size)...)...)
		return ecdsa.ParseUncompressedPublicKey(c, raw)
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("jose: unsupported OKP curve %q", k.Crv)
		}
		x, err := unb64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		return ed25519.PublicKey(x), nil
	case "oct":
		return unb64(k.K)
	}
	return nil, fmt.Errorf("jose: unsupported kty %q", k.Kty)
}

// PrivateKey returns the crypto private key.
func (k JWK) PrivateKey() (any, error) {
	switch k.Kty {
	case "RSA":
		pub, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		d, err := bigFrom(k.D)
		if err != nil {
			return nil, err
		}
		p, err := bigFrom(k.P)
		if err != nil {
			return nil, err
		}
		q, err := bigFrom(k.Q)
		if err != nil {
			return nil, err
		}
		priv := &rsa.PrivateKey{PublicKey: *pub.(*rsa.PublicKey), D: d, Primes: []*big.Int{p, q}}
		priv.Precompute()
		return priv, nil
	case "EC":
		c, err := curve(k.Crv)
		if err != nil {
			return nil, err
		}
		d, err := unb64(k.D)
		if err != nil {
			return nil, err
		}
		return ecdsa.ParseRawPrivateKey(c, padBytes(d, (c.Params().BitSize+7)/8))
	case "OKP":
		d, err := unb64(k.D)
		if err != nil || len(d) != ed25519.SeedSize {
			return nil, ErrInvalid
		}
		return ed25519.NewKeyFromSeed(d), nil
	case "oct":
		return unb64(k.K)
	}
	return nil, fmt.Errorf("jose: unsupported kty %q", k.Kty)
}

func padBytes(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// JWKFromPublicKey builds a public JWK.
func JWKFromPublicKey(pub any) (JWK, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return JWK{Kty: "RSA", N: b64(k.N.Bytes()), E: b64(big.NewInt(int64(k.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		raw, err := k.Bytes()
		if err != nil {
			return JWK{}, err
		}
		return JWK{Kty: "EC", Crv: k.Curve.Params().Name, X: b64(raw[1 : 1+size]), Y: b64(raw[1+size:])}, nil
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64(k)}, nil
	}
	return JWK{}, fmt.Errorf("jose: unsupported public key %T", pub)
}

// JWKFromPrivateKey builds a private JWK.
func JWKFromPrivateKey(priv any) (JWK, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		j, _ := JWKFromPublicKey(&k.PublicKey)
		k.Precompute()
		j.D = b64(k.D.Bytes())
		j.P = b64(k.Primes[0].Bytes())
		j.Q = b64(k.Primes[1].Bytes())
		j.DP = b64(k.Precomputed.Dp.Bytes())
		j.DQ = b64(k.Precomputed.Dq.Bytes())
		j.QI = b64(k.Precomputed.Qinv.Bytes())
		return j, nil
	case *ecdsa.PrivateKey:
		j, err := JWKFromPublicKey(&k.PublicKey)
		if err != nil {
			return JWK{}, err
		}
		d, err := k.Bytes()
		if err != nil {
			return JWK{}, err
		}
		j.D = b64(d)
		return j, nil
	case ed25519.PrivateKey:
		j, _ := JWKFromPublicKey(k.Public())
		j.D = b64(k.Seed())
		return j, nil
	}
	return JWK{}, fmt.Errorf("jose: unsupported private key %T", priv)
}

// Thumbprint computes the RFC 7638 SHA-256 thumbprint (base64url).
func (k JWK) Thumbprint() string {
	var canon string
	switch k.Kty {
	case "RSA":
		canon = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	case "EC":
		canon = `{"crv":"` + k.Crv + `","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	case "OKP":
		canon = `{"crv":"` + k.Crv + `","kty":"OKP","x":"` + k.X + `"}`
	case "oct":
		canon = `{"k":"` + k.K + `","kty":"oct"}`
	}
	h := sha256.Sum256([]byte(canon))
	return b64(h[:])
}

// ---- signing algorithms ----

func hashFor(alg string) (crypto.Hash, func() hash.Hash, error) {
	switch alg[len(alg)-3:] {
	case "256":
		return crypto.SHA256, sha256.New, nil
	case "384":
		return crypto.SHA384, sha512.New384, nil
	case "512":
		return crypto.SHA512, sha512.New, nil
	}
	return 0, nil, ErrAlgorithm
}

// Sign signs signingInput with alg using key (a crypto private key or []byte for HS*).
func Sign(alg string, key any, signingInput []byte) ([]byte, error) {
	if alg == "EdDSA" || alg == "Ed25519" {
		k, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrAlgorithm
		}
		return ed25519.Sign(k, signingInput), nil
	}
	if len(alg) < 5 {
		return nil, ErrAlgorithm
	}
	ch, hf, err := hashFor(alg)
	if err != nil {
		return nil, err
	}
	switch alg[:2] {
	case "HS":
		k, ok := key.([]byte)
		if !ok {
			return nil, ErrAlgorithm
		}
		m := hmac.New(hf, k)
		m.Write(signingInput)
		return m.Sum(nil), nil
	case "RS", "PS":
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrAlgorithm
		}
		h := hf()
		h.Write(signingInput)
		if alg[:2] == "RS" {
			return rsa.SignPKCS1v15(rand.Reader, k, ch, h.Sum(nil))
		}
		return rsa.SignPSS(rand.Reader, k, ch, h.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES":
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrAlgorithm
		}
		h := hf()
		h.Write(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, k, h.Sum(nil))
		if err != nil {
			return nil, err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		return append(padBytes(r.Bytes(), size), padBytes(s.Bytes(), size)...), nil
	}
	return nil, ErrAlgorithm
}

// Verify checks a signature.
func Verify(alg string, key any, signingInput, sig []byte) error {
	if alg == "EdDSA" || alg == "Ed25519" {
		k, ok := key.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, signingInput, sig) {
			return ErrSignature
		}
		return nil
	}
	if len(alg) < 5 {
		return ErrAlgorithm
	}
	ch, hf, err := hashFor(alg)
	if err != nil {
		return err
	}
	switch alg[:2] {
	case "HS":
		k, ok := key.([]byte)
		if !ok {
			return ErrAlgorithm
		}
		m := hmac.New(hf, k)
		m.Write(signingInput)
		if !hmac.Equal(m.Sum(nil), sig) {
			return ErrSignature
		}
		return nil
	case "RS", "PS":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrAlgorithm
		}
		h := hf()
		h.Write(signingInput)
		if alg[:2] == "RS" {
			if rsa.VerifyPKCS1v15(k, ch, h.Sum(nil), sig) != nil {
				return ErrSignature
			}
			return nil
		}
		if rsa.VerifyPSS(k, ch, h.Sum(nil), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}) != nil {
			return ErrSignature
		}
		return nil
	case "ES":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return ErrAlgorithm
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return ErrSignature
		}
		h := hf()
		h.Write(signingInput)
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, h.Sum(nil), r, s) {
			return ErrSignature
		}
		return nil
	}
	return ErrAlgorithm
}

// ---- JWT ----

// Header returns the decoded protected header of a compact JWS/JWE.
func Header(token string) (*jsonx.Object, error) {
	i := strings.IndexByte(token, '.')
	if i < 0 {
		return nil, ErrInvalid
	}
	raw, err := unb64(token[:i])
	if err != nil {
		return nil, ErrInvalid
	}
	v, err := jsonx.Parse(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		return nil, ErrInvalid
	}
	return o, nil
}

// Decode returns header and payload without verifying the signature.
func Decode(token string) (header, payload *jsonx.Object, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, ErrInvalid
	}
	header, err = Header(token)
	if err != nil {
		return nil, nil, err
	}
	raw, err := unb64(parts[1])
	if err != nil {
		return nil, nil, ErrInvalid
	}
	v, err := jsonx.Parse(raw)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		return nil, nil, ErrInvalid
	}
	return header, o, nil
}

// SignJWT signs payload as a compact JWS. header must include "alg".
func SignJWT(header, payload *jsonx.Object, key any) (string, error) {
	algV, _ := header.Get("alg")
	alg, _ := algV.(string)
	hb, err := jsonx.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := jsonx.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := b64(hb) + "." + b64(pb)
	sig, err := Sign(alg, key, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// VerifyOptions control JWT verification.
type VerifyOptions struct {
	Algorithms []string
	// Issuer / Audience: any of the listed values is accepted.
	Issuer   []string
	Audience []string
	// MaxTokenAge rejects tokens whose iat is older than this.
	MaxTokenAge    time.Duration
	ClockTolerance time.Duration
	// Typ, when set, must match the header typ.
	Typ string
	Now func() time.Time
}

// KeyFunc returns the verification key for a token header.
type KeyFunc func(header *jsonx.Object) (any, error)

// StaticKey returns a KeyFunc for a single key.
func StaticKey(k any) KeyFunc { return func(*jsonx.Object) (any, error) { return k, nil } }

// KeySetFunc selects a key from a JWKS by kid (and alg/kty compatibility).
func KeySetFunc(set JWKS) KeyFunc {
	return func(h *jsonx.Object) (any, error) {
		kidV, _ := h.Get("kid")
		kid, _ := kidV.(string)
		algV, _ := h.Get("alg")
		alg, _ := algV.(string)
		var candidates []JWK
		for _, k := range set.Keys {
			if kid != "" && k.Kid != kid {
				continue
			}
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			if k.Alg != "" && alg != "" && k.Alg != alg {
				continue
			}
			if !ktyMatches(k.Kty, alg) {
				continue
			}
			candidates = append(candidates, k)
		}
		if len(candidates) != 1 {
			return nil, ErrNoMatchingKey
		}
		return candidates[0].PublicKey()
	}
}

func ktyMatches(kty, alg string) bool {
	switch {
	case alg == "EdDSA":
		return kty == "OKP"
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return kty == "RSA"
	case strings.HasPrefix(alg, "ES"):
		return kty == "EC"
	case strings.HasPrefix(alg, "HS"):
		return kty == "oct"
	}
	return true
}

func audienceList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// VerifyJWT verifies a compact JWS and validates standard claims.
func VerifyJWT(token string, keyFn KeyFunc, o VerifyOptions) (*jsonx.Object, *jsonx.Object, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, ErrInvalid
	}
	header, payload, err := Decode(token)
	if err != nil {
		return nil, nil, err
	}
	algV, _ := header.Get("alg")
	alg, _ := algV.(string)
	if alg == "" || alg == "none" {
		return nil, nil, ErrAlgorithm
	}
	if len(o.Algorithms) > 0 {
		ok := false
		for _, a := range o.Algorithms {
			if a == alg {
				ok = true
			}
		}
		if !ok {
			return nil, nil, ErrAlgorithm
		}
	}
	if o.Typ != "" {
		typV, _ := header.Get("typ")
		if typ, _ := typV.(string); !strings.EqualFold(typ, o.Typ) {
			return nil, nil, ErrClaim
		}
	}
	key, err := keyFn(header)
	if err != nil {
		return nil, nil, err
	}
	sig, err := unb64(parts[2])
	if err != nil {
		return nil, nil, ErrInvalid
	}
	if err := Verify(alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, nil, err
	}
	if err := ValidateClaims(payload, o); err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

// ValidateClaims checks exp, nbf, iat, iss and aud.
func ValidateClaims(p *jsonx.Object, o VerifyOptions) error {
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	ts := float64(now.Unix())
	tol := o.ClockTolerance.Seconds()
	num := func(k string) (float64, bool, error) {
		v, ok := p.Get(k)
		if !ok {
			return 0, false, nil
		}
		f, isNum := v.(float64)
		if !isNum {
			return 0, true, ErrClaim
		}
		return f, true, nil
	}
	if exp, ok, err := num("exp"); err != nil {
		return err
	} else if ok && exp <= ts-tol {
		return ErrExpired
	}
	if nbf, ok, err := num("nbf"); err != nil {
		return err
	} else if ok && nbf > ts+tol {
		return ErrNotYetValid
	}
	iat, hasIat, err := num("iat")
	if err != nil {
		return err
	}
	if o.MaxTokenAge > 0 {
		if !hasIat || ts-iat-tol > o.MaxTokenAge.Seconds() {
			return ErrExpired
		}
	}
	if len(o.Issuer) > 0 {
		v, _ := p.Get("iss")
		iss, _ := v.(string)
		ok := false
		for _, i := range o.Issuer {
			if i == iss {
				ok = true
			}
		}
		if !ok {
			return ErrClaim
		}
	}
	if len(o.Audience) > 0 {
		v, _ := p.Get("aud")
		auds := audienceList(v)
		ok := false
		for _, want := range o.Audience {
			for _, a := range auds {
				if a == want {
					ok = true
				}
			}
		}
		if !ok {
			return ErrClaim
		}
	}
	return nil
}

// ParseJWKS decodes a JWKS document.
func ParseJWKS(b []byte) (JWKS, error) {
	var s JWKS
	err := json.Unmarshal(b, &s)
	return s, err
}
