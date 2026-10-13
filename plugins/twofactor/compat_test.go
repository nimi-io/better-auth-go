package twofactor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Cross-compatibility with the TypeScript implementation. testdata/ts_fixtures.json is
// produced by e2e/scripts/gen-twofactor-fixtures.mjs (TS -> Go); TestCompatGoValuesAcceptedByTS
// runs the same script in verify mode on values produced here (Go -> TS).

type tsFixtures struct {
	Secret   string `json:"secret"`
	Rotating struct {
		Keys           [][2]any `json:"keys"`
		CurrentVersion int      `json:"currentVersion"`
		LegacySecret   string   `json:"legacySecret"`
	} `json:"rotating"`
	TOTP []struct {
		Secret string `json:"secret"`
		Digits int    `json:"digits"`
		Period int    `json:"period"`
		Time   int64  `json:"time"`
		Code   string `json:"code"`
	} `json:"totp"`
	HOTP []struct {
		Secret  string `json:"secret"`
		Counter uint64 `json:"counter"`
		Code    string `json:"code"`
	} `json:"hotp"`
	URIs             []uriFixture       `json:"uris"`
	EncryptedSecrets []encryptedFixture `json:"encryptedSecrets"`
	BackupCodes      []backupFixture    `json:"backupCodes"`
	HashedOTP        []struct {
		OTP  string `json:"otp"`
		Hash string `json:"hash"`
	} `json:"hashedOTP"`
}

type uriFixture struct {
	Secret  string `json:"secret"`
	Digits  int    `json:"digits"`
	Period  int    `json:"period"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
	URI     string `json:"uri"`
}

type encryptedFixture struct {
	Key       string `json:"key"`
	Secret    string `json:"secret"`
	Encrypted string `json:"encrypted"`
}

type backupFixture struct {
	Key     string   `json:"key"`
	Storage string   `json:"storage"`
	Codes   []string `json:"codes"`
	Stored  string   `json:"stored"`
}

type totpFixture struct {
	Secret string `json:"secret"`
	Digits int    `json:"digits"`
	Period int    `json:"period"`
	Time   int64  `json:"time"`
	Code   string `json:"code"`
}

func loadFixtures(t *testing.T) (*tsFixtures, map[string]bacrypto.Secret) {
	t.Helper()
	b, err := os.ReadFile("testdata/ts_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f tsFixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	var vs []bacrypto.VersionedSecret
	for _, kv := range f.Rotating.Keys {
		vs = append(vs, bacrypto.VersionedSecret{Version: int(kv[0].(float64)), Value: kv[1].(string)})
	}
	return &f, map[string]bacrypto.Secret{
		"plain":    bacrypto.PlainSecret(f.Secret),
		"rotating": {Config: bacrypto.NewSecretConfig(vs, f.Rotating.LegacySecret)},
	}
}

func otpAt(secret string, digits, period int, ms int64) *OTP {
	o := CreateOTP(secret, digits, period)
	o.now = func() time.Time { return time.UnixMilli(ms) }
	return o
}

func TestCompatTSFixturesVerifiedByGo(t *testing.T) {
	f, keys := loadFixtures(t)
	t.Run("totp codes", func(t *testing.T) {
		for _, c := range f.TOTP {
			o := otpAt(c.Secret, c.Digits, c.Period, c.Time)
			got, err := o.TOTP()
			if err != nil || got != c.Code {
				t.Fatalf("%+v: got %q %v", c, got, err)
			}
			if ok, _ := o.Verify(c.Code); !ok {
				t.Fatalf("%+v not verified", c)
			}
		}
	})
	t.Run("hotp codes", func(t *testing.T) {
		for _, c := range f.HOTP {
			if got, _ := GenerateHOTP(c.Secret, c.Counter, 6); got != c.Code {
				t.Fatalf("%+v: got %q", c, got)
			}
		}
	})
	t.Run("otpauth uris", func(t *testing.T) {
		for _, u := range f.URIs {
			if got := CreateOTP(u.Secret, u.Digits, u.Period).URL(u.Issuer, u.Account); got != u.URI {
				t.Fatalf("got  %s\nwant %s", got, u.URI)
			}
		}
	})
	t.Run("encrypted totp secrets", func(t *testing.T) {
		for _, e := range f.EncryptedSecrets {
			got, err := bacrypto.SymmetricDecrypt(keys[e.Key], e.Encrypted)
			if err != nil || got != e.Secret {
				t.Fatalf("%s: %q %v", e.Key, got, err)
			}
		}
	})
	t.Run("backup code blobs", func(t *testing.T) {
		for _, b := range f.BackupCodes {
			got, err := DecodeBackupCodes(b.Stored, keys[b.Key], &BackupCodeOptions{StoreBackupCodes: b.Storage})
			if err != nil || !reflect.DeepEqual(got, b.Codes) {
				t.Fatalf("%s/%s: %v %v", b.Key, b.Storage, got, err)
			}
			if b.Storage == StorePlain {
				enc, _ := EncodeBackupCodes(b.Codes, keys[b.Key], &BackupCodeOptions{StoreBackupCodes: StorePlain})
				if enc != b.Stored {
					t.Fatalf("plain encoding %q != %q", enc, b.Stored)
				}
			}
		}
	})
	t.Run("hashed otp", func(t *testing.T) {
		for _, h := range f.HashedOTP {
			if DefaultKeyHasher(h.OTP) != h.Hash {
				t.Fatalf("hash %s", h.OTP)
			}
		}
	})
}

func TestCompatGoValuesAcceptedByTS(t *testing.T) {
	script, _ := filepath.Abs("../../e2e/scripts/gen-twofactor-fixtures.mjs")
	if _, err := os.Stat("../../e2e/node_modules/better-auth"); err != nil {
		t.Skip("e2e/node_modules not installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available")
	}
	f, keys := loadFixtures(t)
	out := map[string]any{}
	var secrets []encryptedFixture
	for _, k := range []string{"plain", "rotating"} {
		for _, s := range []string{RandomTOTPSecret(), "Zx-_9QwErTyUiOpAsDfGhJkLzXcVbNm1"} {
			enc, err := bacrypto.SymmetricEncrypt(keys[k], s)
			if err != nil {
				t.Fatal(err)
			}
			secrets = append(secrets, encryptedFixture{Key: k, Secret: s, Encrypted: enc})
		}
	}
	out["encryptedSecrets"] = secrets
	var backups []backupFixture
	for _, k := range []string{"plain", "rotating"} {
		g, err := generateBackupCodes(keys[k], nil)
		if err != nil {
			t.Fatal(err)
		}
		backups = append(backups, backupFixture{Key: k, Storage: StoreEncrypted, Codes: g.codes, Stored: g.encoded})
	}
	odd := []string{"a<b>& c", "ünï-cödé"}
	enc, _ := EncodeBackupCodes(odd, keys["plain"], nil)
	backups = append(backups, backupFixture{Key: "plain", Storage: StoreEncrypted, Codes: odd, Stored: enc})
	out["backupCodes"] = backups
	var totps []totpFixture
	now := time.Now().UnixMilli()
	for _, digits := range []int{6, 8} {
		s := RandomTOTPSecret()
		code, _ := otpAt(s, digits, 30, now).TOTP()
		totps = append(totps, totpFixture{Secret: s, Digits: digits, Period: 30, Time: now, Code: code})
	}
	out["totp"] = totps
	var uris []uriFixture
	for _, u := range f.URIs {
		u.Secret = RandomTOTPSecret()
		u.URI = CreateOTP(u.Secret, u.Digits, u.Period).URL(u.Issuer, u.Account)
		uris = append(uris, u)
	}
	out["uris"] = uris
	out["hashedOTP"] = []map[string]string{{"otp": "424242", "hash": DefaultKeyHasher("424242")}}
	b, _ := json.Marshal(out)
	path := filepath.Join(t.TempDir(), "go_values.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := exec.Command(node, script, "verify", path).CombinedOutput()
	if err != nil || !strings.Contains(string(res), `"ok":true`) {
		t.Fatalf("TS rejected Go values: %v\n%s", err, res)
	}
}
