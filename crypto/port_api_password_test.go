package crypto

// Port of packages/better-auth/src/crypto/password.test.ts (upstream v1.7.7).

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

func ppHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func ppVerify(t *testing.T, hash, password string) bool {
	t.Helper()
	ok, err := VerifyPassword(hash, password)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestPortAPIPasswordHashing(t *testing.T) {
	t.Run("should hash a password", func(t *testing.T) {
		h := ppHash(t, "mySecurePassword123!")
		if h == "" || len(strings.Split(h, ":")) != 2 {
			t.Fatalf("hash = %q", h)
		}
	})
	t.Run("should verify a correct password", func(t *testing.T) {
		p := "correctPassword123!"
		if !ppVerify(t, ppHash(t, p), p) {
			t.Fatal("expected valid")
		}
	})
	t.Run("should reject an incorrect password", func(t *testing.T) {
		if ppVerify(t, ppHash(t, "correctPassword123!"), "wrongPassword456!") {
			t.Fatal("expected invalid")
		}
	})
	t.Run("should generate different hashes for the same password", func(t *testing.T) {
		if ppHash(t, "samePassword123!") == ppHash(t, "samePassword123!") {
			t.Fatal("hashes equal")
		}
	})
	t.Run("should handle long passwords", func(t *testing.T) {
		p := strings.Repeat("a", 1000)
		if !ppVerify(t, ppHash(t, p), p) {
			t.Fatal("expected valid")
		}
	})
	t.Run("should be case-sensitive", func(t *testing.T) {
		p := "CaseSensitivePassword123!"
		h := ppHash(t, p)
		if ppVerify(t, h, strings.ToLower(p)) || ppVerify(t, h, strings.ToUpper(p)) {
			t.Fatal("expected case-sensitive rejection")
		}
	})
	t.Run("should handle Unicode characters", func(t *testing.T) {
		p := "пароль123!"
		if !ppVerify(t, ppHash(t, p), p) {
			t.Fatal("expected valid")
		}
	})
}

// legacyHashPassword simulates the old @noble/hashes scryptAsync implementation
// (N=16384, r=16, p=1, dkLen=64, NFKC password, hex-string salt).
func ppLegacyHashPassword(t *testing.T, password string) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	salt := hex.EncodeToString(b)
	key, err := scrypt.Key([]byte(norm.NFKC.String(password)), []byte(salt), 16384, 16, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	return salt + ":" + hex.EncodeToString(key)
}

func TestPortAPIPasswordBackwardCompatNoble(t *testing.T) {
	t.Run("should verify a hash created by the old @noble/hashes implementation", func(t *testing.T) {
		p := "ExistingUser123!"
		if !ppVerify(t, ppLegacyHashPassword(t, p), p) {
			t.Fatal("expected valid")
		}
	})
	t.Run("should reject wrong password against old hash", func(t *testing.T) {
		if ppVerify(t, ppLegacyHashPassword(t, "ExistingUser123!"), "WrongPassword!") {
			t.Fatal("expected invalid")
		}
	})
	t.Run("should verify old hash with Unicode password", func(t *testing.T) {
		p := "비밀번호🔑密码🔒パスワード"
		if !ppVerify(t, ppLegacyHashPassword(t, p), p) {
			t.Fatal("expected valid")
		}
	})
	t.Run("should verify old hash with empty password", func(t *testing.T) {
		if !ppVerify(t, ppLegacyHashPassword(t, ""), "") {
			t.Fatal("expected valid")
		}
	})
	t.Run("should verify old hash with very long password", func(t *testing.T) {
		p := strings.Repeat("x", 10000)
		if !ppVerify(t, ppLegacyHashPassword(t, p), p) {
			t.Fatal("expected valid")
		}
	})
}
