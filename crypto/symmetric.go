package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// SecretConfig is a versioned set of secrets used for secret rotation
// (BetterAuthOptions.secrets / BETTER_AUTH_SECRETS).
type SecretConfig struct {
	// Keys maps version → secret.
	Keys map[int]string
	// CurrentVersion is the version used for new ciphertexts (the first entry of `secrets`).
	CurrentVersion int
	// LegacySecret decrypts bare-hex payloads produced before rotation was configured.
	LegacySecret string
	// order preserves the configured order of versions.
	order []int
}

// NewSecretConfig builds a SecretConfig from ordered (version, value) pairs; the first pair
// is the current secret.
func NewSecretConfig(secrets []VersionedSecret, legacySecret string) *SecretConfig {
	sc := &SecretConfig{Keys: map[int]string{}, LegacySecret: legacySecret}
	for i, s := range secrets {
		if i == 0 {
			sc.CurrentVersion = s.Version
		}
		if _, ok := sc.Keys[s.Version]; !ok {
			sc.order = append(sc.order, s.Version)
		}
		sc.Keys[s.Version] = s.Value
	}
	return sc
}

// VersionedSecret is one entry of the `secrets` option.
type VersionedSecret struct {
	Version int
	Value   string
}

// Ordered returns the secrets in configured order. For configs built as struct literals
// (no recorded order) the current version comes first, then the others by descending
// version.
func (s *SecretConfig) Ordered() []VersionedSecret {
	seen := map[int]bool{}
	out := make([]VersionedSecret, 0, len(s.Keys))
	for _, v := range s.order {
		if val, ok := s.Keys[v]; ok && !seen[v] {
			seen[v] = true
			out = append(out, VersionedSecret{Version: v, Value: val})
		}
	}
	if len(out) == len(s.Keys) {
		return out
	}
	if val, ok := s.Keys[s.CurrentVersion]; ok && !seen[s.CurrentVersion] {
		seen[s.CurrentVersion] = true
		out = append(out, VersionedSecret{Version: s.CurrentVersion, Value: val})
	}
	var rest []int
	for v := range s.Keys {
		if !seen[v] {
			rest = append(rest, v)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(rest)))
	for _, v := range rest {
		out = append(out, VersionedSecret{Version: v, Value: s.Keys[v]})
	}
	return out
}

// Secret is either a plain secret string or a rotating SecretConfig.
type Secret struct {
	Plain  string
	Config *SecretConfig
}

// PlainSecret wraps a single secret.
func PlainSecret(s string) Secret { return Secret{Plain: s} }

// IsRotating reports whether this is a SecretConfig.
func (s Secret) IsRotating() bool { return s.Config != nil }

// Current returns the secret used for new signatures/ciphertexts.
func (s Secret) Current() (string, error) {
	if s.Config == nil {
		return s.Plain, nil
	}
	v, ok := s.Config.Keys[s.Config.CurrentVersion]
	if !ok {
		return "", fmt.Errorf("Secret version %d not found in keys", s.Config.CurrentVersion)
	}
	return v, nil
}

const envelopePrefix = "$ba$"

// ParseEnvelope splits a "$ba$<version>$<ciphertext>" envelope.
func ParseEnvelope(data string) (version int, ciphertext string, ok bool) {
	if !strings.HasPrefix(data, envelopePrefix) {
		return 0, "", false
	}
	rest := data[len(envelopePrefix):]
	sep := strings.IndexByte(rest, '$')
	if sep == -1 {
		return 0, "", false
	}
	v, err := parseJSInt(rest[:sep])
	if err != nil || v < 0 {
		return 0, "", false
	}
	return v, rest[sep+1:], true
}

// parseJSInt mimics parseInt(str, 10): leading whitespace, optional sign, then digits.
func parseJSInt(s string) (int, error) {
	s = strings.TrimLeft(s, " \t\n\r")
	end := 0
	if end < len(s) && (s[end] == '-' || s[end] == '+') {
		end++
	}
	start := end
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == start {
		return 0, errors.New("NaN")
	}
	return strconv.Atoi(s[:end])
}

// FormatEnvelope builds "$ba$<version>$<ciphertext>".
func FormatEnvelope(version int, ciphertext string) string {
	return fmt.Sprintf("%s%d$%s", envelopePrefix, version, ciphertext)
}

func rawEncrypt(secret, data string) (string, error) {
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	// @noble/ciphers managedNonce prepends the nonce to the ciphertext.
	out := aead.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(out), nil
}

func rawDecrypt(secret, hexData string) (string, error) {
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(hexData)
	if err != nil {
		return "", err
	}
	if len(raw) < chacha20poly1305.NonceSizeX+aead.Overhead() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:chacha20poly1305.NonceSizeX], raw[chacha20poly1305.NonceSizeX:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// SymmetricEncrypt encrypts data with XChaCha20-Poly1305 (key = SHA-256(secret), random
// 24-byte nonce prepended, hex output). With a rotating secret the result is wrapped in a
// "$ba$<version>$" envelope.
func SymmetricEncrypt(key Secret, data string) (string, error) {
	if key.Config == nil {
		return rawEncrypt(key.Plain, data)
	}
	secret, err := key.Current()
	if err != nil {
		return "", err
	}
	ct, err := rawEncrypt(secret, data)
	if err != nil {
		return "", err
	}
	return FormatEnvelope(key.Config.CurrentVersion, ct), nil
}

// SymmetricDecrypt reverses SymmetricEncrypt, selecting the secret by envelope version and
// falling back to the legacy secret for bare-hex payloads.
func SymmetricDecrypt(key Secret, data string) (string, error) {
	if key.Config == nil {
		return rawDecrypt(key.Plain, data)
	}
	if version, ct, ok := ParseEnvelope(data); ok {
		secret, found := key.Config.Keys[version]
		if !found {
			return "", fmt.Errorf("Secret version %d not found in keys (key may have been retired)", version)
		}
		return rawDecrypt(secret, ct)
	}
	if key.Config.LegacySecret != "" {
		return rawDecrypt(key.Config.LegacySecret, data)
	}
	return "", errors.New("Cannot decrypt legacy bare-hex payload: no legacy secret available. Set BETTER_AUTH_SECRET for backwards compatibility.")
}

// EncryptionPurpose names the purpose of a derived key.
type EncryptionPurpose string

// Purposes defined upstream in crypto/purpose.ts.
const (
	PurposeOAuthStateCookie  EncryptionPurpose = "oauth-state-cookie"
	PurposeOAuthProxyState   EncryptionPurpose = "oauth-proxy-state"
	PurposeOAuthProxyPackage EncryptionPurpose = "oauth-proxy-package"
	PurposeOAuthProxyProfile EncryptionPurpose = "oauth-proxy-profile"
)

func derivePurposeSecret(secret string, purpose EncryptionPurpose) string {
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte("better-auth:oauth-encryption:v1"),
		"better-auth:"+string(purpose)+":v1", 32)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(key)
}

// DerivePurposeKey derives a per-purpose secret (HKDF-SHA256, salt
// "better-auth:oauth-encryption:v1", info "better-auth:<purpose>:v1", hex output).
func DerivePurposeKey(secret Secret, purpose EncryptionPurpose) Secret {
	if secret.Config == nil {
		return PlainSecret(derivePurposeSecret(secret.Plain, purpose))
	}
	cfg := &SecretConfig{Keys: map[int]string{}, CurrentVersion: secret.Config.CurrentVersion}
	for _, vs := range secret.Config.Ordered() {
		cfg.Keys[vs.Version] = derivePurposeSecret(vs.Value, purpose)
		cfg.order = append(cfg.order, vs.Version)
	}
	if secret.Config.LegacySecret != "" {
		cfg.LegacySecret = derivePurposeSecret(secret.Config.LegacySecret, purpose)
	}
	return Secret{Config: cfg}
}

// MakeSignature returns base64 (standard, padded) HMAC-SHA256 of value — the signature used
// by better-call signed cookies and makeSignature.
func MakeSignature(value, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// VerifySignature verifies a base64 HMAC-SHA256 signature in constant time.
func VerifySignature(signatureB64, value, secret string) bool {
	sig, err := DecodeBase64Loose(signatureB64)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(value))
	return hmac.Equal(sig, m.Sum(nil))
}

// HMACSHA256 returns the raw HMAC-SHA256.
func HMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// Base64URLNoPad encodes without padding using the URL alphabet.
func Base64URLNoPad(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodeBase64Loose decodes base64 the way @better-auth/utils base64.decode does: the URL
// alphabet is used when '-' or '_' appear, decoding stops at the first '=', and partial
// trailing bits are discarded.
func DecodeBase64Loose(s string) ([]byte, error) {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if strings.ContainsAny(s, "-_") {
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	}
	var lut [256]int
	for i := range lut {
		lut[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		lut[alphabet[i]] = i
	}
	out := make([]byte, 0, len(s)*3/4)
	buffer, bits := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		v := lut[c]
		if v < 0 {
			return nil, fmt.Errorf("Invalid Base64 character: %c", c)
		}
		buffer = (buffer<<6 | v) & 0xFFFFFF
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buffer>>bits))
		}
	}
	return out, nil
}

// SHA256 returns the SHA-256 digest of s.
func SHA256(s []byte) []byte {
	h := sha256.Sum256(s)
	return h[:]
}
