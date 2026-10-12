package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"strings"
	"time"

	"crypto/hkdf"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// JWT errors.
var (
	ErrJWTInvalid = errors.New("invalid jwt")
	ErrJWTExpired = errors.New("jwt expired")
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// withClaims returns payload extended with iat/exp (and optional jti), in jose order.
func withClaims(payload *jsonx.Object, expiresIn time.Duration, jti bool) *jsonx.Object {
	p := jsonx.NewObject()
	if payload != nil {
		p = payload.Clone()
	}
	now := time.Now().Unix()
	p.Set("iat", float64(now))
	p.Set("exp", float64(now+int64(expiresIn/time.Second)))
	if jti {
		p.Set("jti", RandomUUID())
	}
	return p
}

// SignJWT signs payload with HS256 using secret and sets iat/exp
// (better-auth/src/crypto/jwt.ts signJWT). expiresIn defaults to one hour when zero.
func SignJWT(payload *jsonx.Object, secret string, expiresIn time.Duration) (string, error) {
	if expiresIn == 0 {
		expiresIn = time.Hour
	}
	header := jsonx.MustMarshal(jsonx.O("alg", "HS256"))
	body, err := jsonx.Marshal(withClaims(payload, expiresIn, false))
	if err != nil {
		return "", err
	}
	signingInput := b64url(header) + "." + b64url(body)
	sig := HMACSHA256([]byte(secret), []byte(signingInput))
	return signingInput + "." + b64url(sig), nil
}

// VerifyJWTOptions controls VerifyJWT.
type VerifyJWTOptions struct {
	// Algorithms restricts accepted algorithms; default HS256, HS384, HS512.
	Algorithms []string
	// ClockTolerance is applied to exp/nbf checks.
	ClockTolerance time.Duration
}

// VerifyJWT verifies an HMAC-signed JWT and returns its payload. It returns ErrJWTExpired
// for expired tokens and ErrJWTInvalid for any other failure.
func VerifyJWT(token, secret string, opts ...VerifyJWTOptions) (*jsonx.Object, error) {
	var o VerifyJWTOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	algs := o.Algorithms
	if len(algs) == 0 {
		algs = []string{"HS256", "HS384", "HS512"}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrJWTInvalid
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, ErrJWTInvalid
	}
	hv, err := jsonx.Parse(hb)
	if err != nil {
		return nil, ErrJWTInvalid
	}
	header, ok := hv.(*jsonx.Object)
	if !ok {
		return nil, ErrJWTInvalid
	}
	algV, _ := header.Get("alg")
	alg, _ := algV.(string)
	allowed := false
	for _, a := range algs {
		if a == alg {
			allowed = true
		}
	}
	if !allowed {
		return nil, ErrJWTInvalid
	}
	var h func() hash.Hash
	switch alg {
	case "HS256":
		h = sha256.New
	case "HS384":
		h = sha512.New384
	case "HS512":
		h = sha512.New
	default:
		return nil, ErrJWTInvalid
	}
	m := hmac.New(h, []byte(secret))
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := b64urlDecode(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return nil, ErrJWTInvalid
	}
	pb, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, ErrJWTInvalid
	}
	return validateClaims(pb, o.ClockTolerance)
}

func validateClaims(pb []byte, tolerance time.Duration) (*jsonx.Object, error) {
	pv, err := jsonx.Parse(pb)
	if err != nil {
		return nil, ErrJWTInvalid
	}
	payload, ok := pv.(*jsonx.Object)
	if !ok {
		return nil, ErrJWTInvalid
	}
	now := float64(time.Now().Unix())
	tol := tolerance.Seconds()
	if v, ok := payload.Get("iat"); ok {
		if _, isNum := v.(float64); !isNum {
			return nil, ErrJWTInvalid
		}
	}
	if v, ok := payload.Get("nbf"); ok {
		n, isNum := v.(float64)
		if !isNum || n > now+tol {
			return nil, ErrJWTInvalid
		}
	}
	if v, ok := payload.Get("exp"); ok {
		n, isNum := v.(float64)
		if !isNum {
			return nil, ErrJWTInvalid
		}
		if n <= now-tol {
			return nil, ErrJWTExpired
		}
	}
	return payload, nil
}

// --- JWE (dir + A256CBC-HS512) -------------------------------------------------------

var jweInfo = "BetterAuth.js Generated Encryption Key"

// DeriveEncryptionSecret derives the 64-byte JWE key: HKDF-SHA256(secret, salt, info).
func DeriveEncryptionSecret(secret, salt string) []byte {
	k, err := hkdf.Key(sha256.New, []byte(secret), []byte(salt), jweInfo, 64)
	if err != nil {
		panic(err)
	}
	return k
}

// OctThumbprint computes the RFC 7638 SHA-256 thumbprint of a symmetric ("oct") JWK.
func OctThumbprint(key []byte) string {
	canonical := `{"k":"` + b64url(key) + `","kty":"oct"}`
	return b64url(SHA256([]byte(canonical)))
}

func pkcs7Pad(b []byte, bs int) []byte {
	n := bs - len(b)%bs
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func pkcs7Unpad(b []byte, bs int) ([]byte, error) {
	if len(b) == 0 || len(b)%bs != 0 {
		return nil, ErrJWTInvalid
	}
	n := int(b[len(b)-1])
	if n == 0 || n > bs || n > len(b) {
		return nil, ErrJWTInvalid
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, ErrJWTInvalid
		}
	}
	return b[:len(b)-n], nil
}

func cbcHSTag(macKey, aad, iv, ct []byte) []byte {
	al := make([]byte, 8)
	bits := uint64(len(aad)) * 8
	for i := 7; i >= 0; i-- {
		al[i] = byte(bits)
		bits >>= 8
	}
	m := hmac.New(sha512.New, macKey)
	m.Write(aad)
	m.Write(iv)
	m.Write(ct)
	m.Write(al)
	return m.Sum(nil)[:32]
}

// EncryptJWE encrypts payload (with iat/exp/jti claims added) as a compact JWE using
// alg "dir" and enc "A256CBC-HS512" with the given 64-byte key and kid header.
func EncryptJWE(payload *jsonx.Object, key []byte, kid string, expiresIn time.Duration) (string, error) {
	if len(key) != 64 {
		return "", errors.New("A256CBC-HS512 requires a 64 byte key")
	}
	header := jsonx.O("alg", "dir", "enc", "A256CBC-HS512")
	if kid != "" {
		header.Set("kid", kid)
	}
	hb := b64url(jsonx.MustMarshal(header))
	pt, err := jsonx.Marshal(withClaims(payload, expiresIn, true))
	if err != nil {
		return "", err
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key[32:])
	if err != nil {
		return "", err
	}
	ct := pkcs7Pad(pt, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, ct)
	tag := cbcHSTag(key[:32], []byte(hb), iv, ct)
	return hb + ".." + b64url(iv) + "." + b64url(ct) + "." + b64url(tag), nil
}

// JWEHeader decodes the protected header of a compact JWE.
func JWEHeader(token string) (*jsonx.Object, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, ErrJWTInvalid
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, ErrJWTInvalid
	}
	v, err := jsonx.Parse(hb)
	if err != nil {
		return nil, ErrJWTInvalid
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		return nil, ErrJWTInvalid
	}
	return o, nil
}

// DecryptJWE decrypts a compact dir/A256CBC-HS512 (or dir/A256GCM with a 32-byte key)
// JWE and validates exp/nbf with the given clock tolerance.
func DecryptJWE(token string, key []byte, tolerance time.Duration) (*jsonx.Object, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[1] != "" {
		return nil, ErrJWTInvalid
	}
	header, err := JWEHeader(token)
	if err != nil {
		return nil, err
	}
	if a, _ := header.Get("alg"); a != "dir" {
		return nil, ErrJWTInvalid
	}
	iv, err1 := b64urlDecode(parts[2])
	ct, err2 := b64urlDecode(parts[3])
	tag, err3 := b64urlDecode(parts[4])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, ErrJWTInvalid
	}
	aad := []byte(parts[0])
	var pt []byte
	switch enc, _ := header.Get("enc"); enc {
	case "A256CBC-HS512":
		if len(key) != 64 || len(iv) != 16 {
			return nil, ErrJWTInvalid
		}
		if !hmac.Equal(tag, cbcHSTag(key[:32], aad, iv, ct)) {
			return nil, ErrJWTInvalid
		}
		block, err := aes.NewCipher(key[32:])
		if err != nil || len(ct)%aes.BlockSize != 0 || len(ct) == 0 {
			return nil, ErrJWTInvalid
		}
		buf := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(buf, ct)
		pt, err = pkcs7Unpad(buf, aes.BlockSize)
		if err != nil {
			return nil, err
		}
	case "A256GCM":
		if len(key) != 32 {
			return nil, ErrJWTInvalid
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrJWTInvalid
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil || len(iv) != gcm.NonceSize() {
			return nil, ErrJWTInvalid
		}
		pt, err = gcm.Open(nil, iv, append(append([]byte{}, ct...), tag...), aad)
		if err != nil {
			return nil, ErrJWTInvalid
		}
	default:
		return nil, ErrJWTInvalid
	}
	return validateClaims(pt, tolerance)
}

// SymmetricEncodeJWT encrypts payload for the cookie cache / account cookie
// (symmetricEncodeJWT in crypto/jwt.ts) using the current secret.
func SymmetricEncodeJWT(payload *jsonx.Object, secret Secret, salt string, expiresIn time.Duration) (string, error) {
	cur, err := secret.Current()
	if err != nil {
		return "", err
	}
	key := DeriveEncryptionSecret(cur, salt)
	if expiresIn == 0 {
		expiresIn = time.Hour
	}
	return EncryptJWE(payload, key, OctThumbprint(key), expiresIn)
}

func allSecrets(secret Secret) []string {
	if secret.Config == nil {
		return []string{secret.Plain}
	}
	var out []string
	for _, s := range secret.Config.Ordered() {
		out = append(out, s.Value)
	}
	if ls := secret.Config.LegacySecret; ls != "" {
		dup := false
		for _, s := range out {
			if s == ls {
				dup = true
			}
		}
		if !dup {
			out = append(out, ls)
		}
	}
	return out
}

// SymmetricDecodeJWT decrypts a token produced by SymmetricEncodeJWT, trying every
// configured secret (by kid thumbprint when present). Returns nil on any failure.
func SymmetricDecodeJWT(token string, secret Secret, salt string) *jsonx.Object {
	if token == "" {
		return nil
	}
	header, err := JWEHeader(token)
	if err != nil {
		return nil
	}
	secrets := allSecrets(secret)
	const tol = 15 * time.Second
	if kidV, ok := header.Get("kid"); ok {
		kid, _ := kidV.(string)
		for _, s := range secrets {
			k := DeriveEncryptionSecret(s, salt)
			if OctThumbprint(k) == kid {
				p, err := DecryptJWE(token, k, tol)
				if err != nil {
					return nil
				}
				return p
			}
		}
		return nil
	}
	for _, s := range secrets {
		if p, err := DecryptJWE(token, DeriveEncryptionSecret(s, salt), tol); err == nil {
			return p
		}
	}
	return nil
}
