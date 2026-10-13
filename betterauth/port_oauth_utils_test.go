package betterauth

// Port of better-auth/src/oauth2/utils.test.ts (decryptOAuthToken / setTokenUtil).

import (
	"regexp"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

const poUtilsSecret = "test-secret-key-for-encryption"

// poUtilsContext mirrors createMockContext(encryptOAuthTokens).
func poUtilsContext(t *testing.T, encrypt bool) *AuthContext {
	t.Helper()
	a, err := New(Config{
		BaseURL:  "http://localhost:3000",
		Secret:   poUtilsSecret,
		Database: memory.New(memory.NewDB()),
		Account:  &AccountConfig{EncryptOAuthTokens: encrypt},
		Logger:   NopLogger{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a.Context()
}

func poDecrypt(t *testing.T, a *AuthContext, token string) string {
	t.Helper()
	got, err := a.DecryptOAuthToken(token)
	if err != nil {
		t.Fatalf("decryptOAuthToken(%q) threw: %v", token, err)
	}
	return got
}

func poSetToken(t *testing.T, a *AuthContext, token string) any {
	t.Helper()
	got, err := a.SetTokenUtil(token)
	if err != nil {
		t.Fatalf("setTokenUtil(%q) threw: %v", token, err)
	}
	return got
}

// describe("decryptOAuthToken")

func TestPortOAuthUtilsDecryptEmptyToken(t *testing.T) {
	if got := poDecrypt(t, poUtilsContext(t, true), ""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestPortOAuthUtilsDecryptDisabled(t *testing.T) {
	const plain = "ya29.a0ARW5m7hQ_some_oauth_token"
	if got := poDecrypt(t, poUtilsContext(t, false), plain); got != plain {
		t.Fatalf("got %q", got)
	}
}

func TestPortOAuthUtilsDecryptEncrypted(t *testing.T) {
	a := poUtilsContext(t, true)
	const original = "test-access-token"
	enc, err := bacrypto.SymmetricEncrypt(bacrypto.PlainSecret(a.Secret), original)
	if err != nil {
		t.Fatal(err)
	}
	if got := poDecrypt(t, a, enc); got != original {
		t.Fatalf("got %q", got)
	}
}

func TestPortOAuthUtilsDecryptMigrationPlainToken(t *testing.T) {
	const plain = "ya29.a0ARW5m7hQ_some_oauth_token_with-dashes"
	if got := poDecrypt(t, poUtilsContext(t, true), plain); got != plain {
		t.Fatalf("got %q", got)
	}
}

func TestPortOAuthUtilsDecryptMigrationJWT(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	if got := poDecrypt(t, poUtilsContext(t, true), jwt); got != jwt {
		t.Fatalf("got %q", got)
	}
}

func TestPortOAuthUtilsDecryptMigrationOddLength(t *testing.T) {
	if got := poDecrypt(t, poUtilsContext(t, true), "abc"); got != "abc" {
		t.Fatalf("got %q", got)
	}
}

// describe("migration scenario - issue #6018")

func TestPortOAuthUtilsMigrationGoogleAccessToken(t *testing.T) {
	const tok = "ya29.a0ARW5m7hQ_test-token_with.dots-and_underscores"
	if got := poDecrypt(t, poUtilsContext(t, true), tok); got != tok {
		t.Fatalf("got %q", got)
	}
}

func TestPortOAuthUtilsMigrationRefreshToken(t *testing.T) {
	const tok = "1//0gxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	if got := poDecrypt(t, poUtilsContext(t, true), tok); got != tok {
		t.Fatalf("got %q", got)
	}
}

func TestPortOAuthUtilsMigrationStillDecrypts(t *testing.T) {
	a := poUtilsContext(t, true)
	const original = "ya29.newToken_after_encryption_enabled"
	enc, _ := poSetToken(t, a, original).(string)
	if got := poDecrypt(t, a, enc); got != original {
		t.Fatalf("got %q", got)
	}
}

// describe("setTokenUtil")

func TestPortOAuthUtilsSetTokenNil(t *testing.T) {
	// setTokenUtil(null|undefined) returns the value as-is; Go's absent token is "".
	if got := poSetToken(t, poUtilsContext(t, true), ""); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
}

func TestPortOAuthUtilsSetTokenDisabled(t *testing.T) {
	if got := poSetToken(t, poUtilsContext(t, false), "test-token"); got != "test-token" {
		t.Fatalf("got %#v", got)
	}
}

func TestPortOAuthUtilsSetTokenEncrypts(t *testing.T) {
	got := poSetToken(t, poUtilsContext(t, true), "test-token")
	s, ok := got.(string)
	if !ok || s == "test-token" {
		t.Fatalf("expected an encrypted token, got %#v", got)
	}
	if !regexp.MustCompile(`(?i)^[0-9a-f]+$`).MatchString(s) {
		t.Fatalf("expected hex-encoded data, got %q", s)
	}
	if len(s)%2 != 0 {
		t.Fatalf("expected even length, got %d", len(s))
	}
}

func TestPortOAuthUtilsSetTokenRoundTrip(t *testing.T) {
	a := poUtilsContext(t, true)
	const original = "my-secret-access-token"
	enc, _ := poSetToken(t, a, original).(string)
	if got := poDecrypt(t, a, enc); got != original {
		t.Fatalf("got %q", got)
	}
}
