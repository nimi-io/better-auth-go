package crypto

// Port of packages/better-auth/src/crypto/secret-rotation.test.ts (upstream v1.7.7):
// envelope format, symmetricEncrypt/Decrypt and JWE multi-secret blocks. The "context
// secret helpers" block lives in betterauth/port_api_secrets_test.go.
//
// SecretConfig values are built with both the struct literal (direct translation of the
// upstream object literal) and NewSecretConfig; see ppSecretModes.

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
)

const (
	ppSecretA = "secret-a-at-least-32-chars-long!!"
	ppSecretB = "secret-b-at-least-32-chars-long!!"
)

func TestPortAPISecretRotationEnvelope(t *testing.T) {
	t.Run("parseEnvelope returns null for bare hex", func(t *testing.T) {
		if _, _, ok := ParseEnvelope("abcdef1234567890"); ok {
			t.Fatal("parsed bare hex")
		}
	})
	t.Run("parseEnvelope parses valid envelope", func(t *testing.T) {
		v, ct, ok := ParseEnvelope("$ba$2$abcdef1234567890")
		if !ok || v != 2 || ct != "abcdef1234567890" {
			t.Fatalf("got %d %q %v", v, ct, ok)
		}
	})
	t.Run("parseEnvelope rejects negative version", func(t *testing.T) {
		if _, _, ok := ParseEnvelope("$ba$-1$abcdef"); ok {
			t.Fatal("accepted negative version")
		}
	})
	t.Run("parseEnvelope rejects non-integer version", func(t *testing.T) {
		if _, _, ok := ParseEnvelope("$ba$abc$abcdef"); ok {
			t.Fatal("accepted non-integer version")
		}
	})
	t.Run("formatEnvelope produces correct format", func(t *testing.T) {
		if got := FormatEnvelope(3, "deadbeef"); got != "$ba$3$deadbeef" {
			t.Fatalf("got %q", got)
		}
	})
}

func ppEncrypt(t *testing.T, key Secret, data string) string {
	t.Helper()
	ct, err := SymmetricEncrypt(key, data)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestPortAPISecretRotationSymmetric(t *testing.T) {
	t.Run("single secret string - bare hex, no envelope", func(t *testing.T) {
		ct := ppEncrypt(t, PlainSecret(ppSecretA), "hello world")
		if strings.Contains(ct, "$ba$") {
			t.Fatalf("ct = %q", ct)
		}
		if pt, err := SymmetricDecrypt(PlainSecret(ppSecretA), ct); err != nil || pt != "hello world" {
			t.Fatalf("decrypt = %q %v", pt, err)
		}
	})
	for _, mode := range ppSecretModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Run("SecretConfig with one key - produces envelope", func(t *testing.T) {
				cfg := mode.build([]ppKV{{1, ppSecretA}}, 1, "")
				ct := ppEncrypt(t, cfg, "hello world")
				if !regexp.MustCompile(`^\$ba\$1\$`).MatchString(ct) {
					t.Fatalf("ct = %q", ct)
				}
				if pt, err := SymmetricDecrypt(cfg, ct); err != nil || pt != "hello world" {
					t.Fatalf("decrypt = %q %v", pt, err)
				}
			})
			t.Run("rotation - encrypt with version 2, decrypt with both keys", func(t *testing.T) {
				cfg := mode.build([]ppKV{{2, ppSecretB}, {1, ppSecretA}}, 2, "")
				ct := ppEncrypt(t, cfg, "rotated data")
				if !regexp.MustCompile(`^\$ba\$2\$`).MatchString(ct) {
					t.Fatalf("ct = %q", ct)
				}
				if pt, err := SymmetricDecrypt(cfg, ct); err != nil || pt != "rotated data" {
					t.Fatalf("decrypt = %q %v", pt, err)
				}
			})
			t.Run("decrypt old key - data encrypted with v1, config now on v2", func(t *testing.T) {
				ct := ppEncrypt(t, mode.build([]ppKV{{1, ppSecretA}}, 1, ""), "old data")
				newCfg := mode.build([]ppKV{{2, ppSecretB}, {1, ppSecretA}}, 2, "")
				if pt, err := SymmetricDecrypt(newCfg, ct); err != nil || pt != "old data" {
					t.Fatalf("decrypt = %q %v", pt, err)
				}
			})
			t.Run("legacy bare hex + SecretConfig with legacySecret", func(t *testing.T) {
				bare := ppEncrypt(t, PlainSecret(ppSecretA), "legacy data")
				cfg := mode.build([]ppKV{{2, ppSecretB}}, 2, ppSecretA)
				if pt, err := SymmetricDecrypt(cfg, bare); err != nil || pt != "legacy data" {
					t.Fatalf("decrypt = %q %v", pt, err)
				}
			})
			t.Run("legacy bare hex without legacySecret - throws", func(t *testing.T) {
				bare := ppEncrypt(t, PlainSecret(ppSecretA), "legacy data")
				_, err := SymmetricDecrypt(mode.build([]ppKV{{2, ppSecretB}}, 2, ""), bare)
				if err == nil || !strings.Contains(err.Error(), "no legacy secret available") {
					t.Fatalf("err = %v", err)
				}
			})
			t.Run("unknown version in envelope - throws", func(t *testing.T) {
				ct := ppEncrypt(t, mode.build([]ppKV{{1, ppSecretA}}, 1, ""), "test")
				_, err := SymmetricDecrypt(mode.build([]ppKV{{2, ppSecretB}}, 2, ""), ct)
				if err == nil || !strings.Contains(err.Error(), "key may have been retired") {
					t.Fatalf("err = %v", err)
				}
			})
			t.Run("version gaps work fine", func(t *testing.T) {
				cfg := mode.build([]ppKV{{3, ppSecretB}, {1, ppSecretA}}, 3, "")
				ct := ppEncrypt(t, cfg, "gapped")
				if !regexp.MustCompile(`^\$ba\$3\$`).MatchString(ct) {
					t.Fatalf("ct = %q", ct)
				}
				if pt, err := SymmetricDecrypt(cfg, ct); err != nil || pt != "gapped" {
					t.Fatalf("decrypt = %q %v", pt, err)
				}
			})
		})
	}
}

func ppEncodeJWT(t *testing.T, secret Secret) string {
	t.Helper()
	tok, err := SymmetricEncodeJWT(jsonx.O("foo", "bar"), secret, "test-salt", 3600*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func ppFoo(p *jsonx.Object) any {
	if p == nil {
		return nil
	}
	v, _ := p.Get("foo")
	return v
}

func TestPortAPISecretRotationJWE(t *testing.T) {
	t.Run("encode and decode with single secret string", func(t *testing.T) {
		tok := ppEncodeJWT(t, PlainSecret(ppSecretA))
		if got := ppFoo(SymmetricDecodeJWT(tok, PlainSecret(ppSecretA), "test-salt")); got != "bar" {
			t.Fatalf("foo = %v", got)
		}
	})
	for _, mode := range ppSecretModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Run("encode with SecretConfig, decode with same config", func(t *testing.T) {
				cfg := mode.build([]ppKV{{1, ppSecretA}}, 1, "")
				tok := ppEncodeJWT(t, cfg)
				if got := ppFoo(SymmetricDecodeJWT(tok, cfg, "test-salt")); got != "bar" {
					t.Fatalf("foo = %v", got)
				}
			})
			t.Run("decode with rotated config containing old key", func(t *testing.T) {
				tok := ppEncodeJWT(t, mode.build([]ppKV{{1, ppSecretA}}, 1, ""))
				newCfg := mode.build([]ppKV{{2, ppSecretB}, {1, ppSecretA}}, 2, "")
				if got := ppFoo(SymmetricDecodeJWT(tok, newCfg, "test-salt")); got != "bar" {
					t.Fatalf("foo = %v", got)
				}
			})
			t.Run("decode kid-less JWT tries all secrets (fallback)", func(t *testing.T) {
				tok := ppEncodeJWT(t, PlainSecret(ppSecretA))
				cfg := mode.build([]ppKV{{2, ppSecretB}, {1, ppSecretA}}, 2, ppSecretA)
				if got := ppFoo(SymmetricDecodeJWT(tok, cfg, "test-salt")); got != "bar" {
					t.Fatalf("foo = %v", got)
				}
			})
			t.Run("decode legacy string-encoded JWT with SecretConfig legacySecret", func(t *testing.T) {
				tok := ppEncodeJWT(t, PlainSecret(ppSecretA))
				cfg := mode.build([]ppKV{{2, ppSecretB}}, 2, ppSecretA)
				if got := ppFoo(SymmetricDecodeJWT(tok, cfg, "test-salt")); got != "bar" {
					t.Fatalf("foo = %v", got)
				}
			})
			t.Run("rejects token with mismatched kid (no fallback)", func(t *testing.T) {
				tok := ppEncodeJWT(t, mode.build([]ppKV{{1, ppSecretA}}, 1, ""))
				if got := SymmetricDecodeJWT(tok, mode.build([]ppKV{{2, ppSecretB}}, 2, ""), "test-salt"); got != nil {
					t.Fatalf("decoded = %v", got)
				}
			})
		})
	}
}
