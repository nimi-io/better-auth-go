package crypto

import (
	"crypto/rand"
	"fmt"
)

// Alphabet names accepted by RandomString, matching @better-auth/utils/random.
const (
	AlphaLower = "a-z"
	AlphaUpper = "A-Z"
	Digits     = "0-9"
	DashUnder  = "-_"
)

func expandAlphabet(name string) string {
	switch name {
	case AlphaLower:
		return "abcdefghijklmnopqrstuvwxyz"
	case AlphaUpper:
		return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case Digits:
		return "0123456789"
	case DashUnder:
		return "-_"
	}
	panic(fmt.Sprintf("Unsupported alphabet: %s", name))
}

// RandomStringFrom generates a cryptographically random string of the given length using
// the union of the named alphabets, with rejection sampling to avoid modulo bias
// (createRandomStringGenerator in @better-auth/utils).
func RandomStringFrom(length int, alphabets ...string) string {
	if length <= 0 {
		panic("Length must be a positive integer.")
	}
	charSet := ""
	for _, a := range alphabets {
		charSet += expandAlphabet(a)
	}
	if charSet == "" {
		panic("No valid characters provided for random string generation.")
	}
	n := len(charSet)
	maxValid := (256 / n) * n
	buf := make([]byte, length*2)
	out := make([]byte, 0, length)
	idx := len(buf)
	for len(out) < length {
		if idx >= len(buf) {
			if _, err := rand.Read(buf); err != nil {
				panic(err)
			}
			idx = 0
		}
		r := int(buf[idx])
		idx++
		if r < maxValid {
			out = append(out, charSet[r%n])
		}
	}
	return string(out)
}

// RandomString is generateRandomString from better-auth/src/crypto/random.ts:
// alphabet a-z, 0-9, A-Z, -_ unless other alphabets are given.
func RandomString(length int, alphabets ...string) string {
	if len(alphabets) == 0 {
		alphabets = []string{AlphaLower, Digits, AlphaUpper, DashUnder}
	}
	return RandomStringFrom(length, alphabets...)
}

// GenerateID is generateId from @better-auth/core/utils/id: a-z, A-Z, 0-9, default length 32.
func GenerateID(size ...int) string {
	n := 32
	if len(size) > 0 && size[0] > 0 {
		n = size[0]
	}
	return RandomStringFrom(n, AlphaLower, AlphaUpper, Digits)
}

// RandomUUID returns a random RFC 4122 version 4 UUID (crypto.randomUUID()).
func RandomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
