package crypto

// Port of packages/better-auth/src/crypto/purpose.test.ts (upstream v1.7.7)
// (GHSA-r4xp-prcw-77qf).
//
// Upstream builds SecretConfig as a plain object literal ({ keys: Map, currentVersion,
// legacySecret }). The direct Go translation is a *SecretConfig struct literal; each case
// also runs with NewSecretConfig so a divergence between the two is visible.

import (
	"regexp"
	"testing"
)

var ppPurposes = []EncryptionPurpose{
	PurposeOAuthStateCookie,
	PurposeOAuthProxyState,
	PurposeOAuthProxyPackage,
	PurposeOAuthProxyProfile,
}

// ppKV is one (version, secret) entry in configured order.
type ppKV struct {
	v int
	s string
}

// ppSecretModes builds a rotating Secret either as a struct literal (faithful translation
// of the upstream object literal) or through NewSecretConfig.
var ppSecretModes = []struct {
	name  string
	build func(keys []ppKV, current int, legacy string) Secret
}{
	{"literal", func(keys []ppKV, current int, legacy string) Secret {
		m := map[int]string{}
		for _, k := range keys {
			m[k.v] = k.s
		}
		return Secret{Config: &SecretConfig{Keys: m, CurrentVersion: current, LegacySecret: legacy}}
	}},
	{"NewSecretConfig", func(keys []ppKV, current int, legacy string) Secret {
		var vs []VersionedSecret
		for _, k := range keys {
			vs = append(vs, VersionedSecret{Version: k.v, Value: k.s})
		}
		sc := NewSecretConfig(vs, legacy)
		sc.CurrentVersion = current
		return Secret{Config: sc}
	}},
}

func ppOtherPurpose(p EncryptionPurpose) EncryptionPurpose {
	if p == PurposeOAuthProxyPackage {
		return PurposeOAuthStateCookie
	}
	return PurposeOAuthProxyPackage
}

func TestPortAPIPurposeDecryptsOnlyOwnPurpose(t *testing.T) {
	for _, purpose := range ppPurposes {
		t.Run(string(purpose), func(t *testing.T) {
			secret := PlainSecret("shared-secret-at-least-32-characters")
			ct, err := SymmetricEncrypt(DerivePurposeKey(secret, purpose), "synthetic payload")
			if err != nil {
				t.Fatal(err)
			}
			pt, err := SymmetricDecrypt(DerivePurposeKey(secret, purpose), ct)
			if err != nil || pt != "synthetic payload" {
				t.Fatalf("decrypt = %q %v", pt, err)
			}
			for _, other := range ppPurposes {
				if other == purpose {
					continue
				}
				if _, err := SymmetricDecrypt(DerivePurposeKey(secret, other), ct); err == nil {
					t.Fatalf("decrypted with purpose %s", other)
				}
			}
			if _, err := SymmetricDecrypt(secret, ct); err == nil {
				t.Fatal("decrypted with the shared secret")
			}
		})
	}
}

func TestPortAPIPurposeBareCiphertextLegacyKey(t *testing.T) {
	oldSecret := "old-secret-at-least-32-characters!!"
	for _, mode := range ppSecretModes {
		for _, purpose := range ppPurposes {
			t.Run(mode.name+"/"+string(purpose), func(t *testing.T) {
				rotated := mode.build([]ppKV{{2, "new-secret-at-least-32-characters!!"}}, 2, oldSecret)
				ct, err := SymmetricEncrypt(DerivePurposeKey(PlainSecret(oldSecret), purpose), "in-flight derived profile")
				if err != nil {
					t.Fatal(err)
				}
				if regexp.MustCompile(`^\$ba\$`).MatchString(ct) {
					t.Fatalf("ciphertext has envelope: %q", ct)
				}
				pt, err := SymmetricDecrypt(DerivePurposeKey(rotated, purpose), ct)
				if err != nil || pt != "in-flight derived profile" {
					t.Fatalf("decrypt = %q %v", pt, err)
				}
				if _, err := SymmetricDecrypt(DerivePurposeKey(rotated, ppOtherPurpose(purpose)), ct); err == nil {
					t.Fatal("decrypted with another purpose")
				}
			})
		}
	}
}

func TestPortAPIPurposePreservesRotation(t *testing.T) {
	oldSecret := "old-secret-at-least-32-characters!!"
	newSecret := "new-secret-at-least-32-characters!!"
	for _, mode := range ppSecretModes {
		for _, purpose := range ppPurposes {
			t.Run(mode.name+"/"+string(purpose), func(t *testing.T) {
				oldCfg := mode.build([]ppKV{{1, oldSecret}}, 1, "")
				rotated := mode.build([]ppKV{{2, newSecret}, {1, oldSecret}}, 2, oldSecret)
				oldCT, err := SymmetricEncrypt(DerivePurposeKey(oldCfg, purpose), "old profile")
				if err != nil {
					t.Fatalf("encrypt with derived old config: %v", err)
				}
				if !regexp.MustCompile(`^\$ba\$1\$`).MatchString(oldCT) {
					t.Fatalf("ciphertext = %q", oldCT)
				}
				pt, err := SymmetricDecrypt(DerivePurposeKey(rotated, purpose), oldCT)
				if err != nil || pt != "old profile" {
					t.Fatalf("decrypt = %q %v", pt, err)
				}
				if _, err := SymmetricDecrypt(DerivePurposeKey(rotated, ppOtherPurpose(purpose)), oldCT); err == nil {
					t.Fatal("decrypted with another purpose")
				}
				legacyCT, err := SymmetricEncrypt(PlainSecret(oldSecret), "pre-upgrade profile")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := SymmetricDecrypt(DerivePurposeKey(rotated, purpose), legacyCT); err == nil {
					t.Fatal("derived key accepted ciphertext made with the shared key")
				}
			})
		}
	}
}
