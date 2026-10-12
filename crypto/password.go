// Package crypto contains the cryptographic primitives Better Auth uses, implemented to be
// byte-compatible with the TypeScript implementation (packages/better-auth/src/crypto and
// @better-auth/utils).
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// Scrypt parameters used by @better-auth/utils/password.
const (
	scryptN      = 16384
	scryptR      = 16
	scryptP      = 1
	scryptKeyLen = 64
)

// ErrInvalidPasswordHash is returned when a stored hash is not in "<salt>:<key>" form.
var ErrInvalidPasswordHash = errors.New("Invalid password hash")

func generateKey(password, salt string) ([]byte, error) {
	// The salt is the hex *string* (its UTF-8 bytes), not the decoded bytes.
	return scrypt.Key([]byte(norm.NFKC.String(password)), []byte(salt), scryptN, scryptR, scryptP, scryptKeyLen)
}

// HashPassword hashes a password as "<saltHex>:<keyHex>" using scrypt
// (N=16384, r=16, p=1, dkLen=64) over the NFKC-normalised password.
func HashPassword(password string) (string, error) {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	salt := hex.EncodeToString(saltBytes)
	key, err := generateKey(password, salt)
	if err != nil {
		return "", err
	}
	return salt + ":" + hex.EncodeToString(key), nil
}

// VerifyPassword checks a password against a hash produced by HashPassword (or by the
// TypeScript implementation). The comparison is constant time.
func VerifyPassword(hash, password string) (bool, error) {
	parts := strings.Split(hash, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return false, ErrInvalidPasswordHash
	}
	salt, key := parts[0], parts[1]
	target, err := generateKey(password, salt)
	if err != nil {
		return false, err
	}
	targetHex := hex.EncodeToString(target)
	return subtle.ConstantTimeCompare([]byte(targetHex), []byte(key)) == 1, nil
}

// ConstantTimeEqual compares two byte strings in constant time (with respect to content).
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
