package crypto

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Fixtures in testdata/ts_fixtures.json are produced by the official TypeScript
// implementation (e2e/scripts/gen-crypto-fixtures.mjs, better-auth@1.7.7).
type tsFixtures struct {
	Secret   string `json:"secret"`
	Rotating struct {
		Keys           [][2]any `json:"keys"`
		CurrentVersion int      `json:"currentVersion"`
		LegacySecret   string   `json:"legacySecret"`
	} `json:"rotating"`
	Passwords []struct {
		Password string `json:"password"`
		Hash     string `json:"hash"`
	} `json:"passwords"`
	Symmetric struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	} `json:"symmetric"`
	SymmetricRotating struct {
		Plaintext        string `json:"plaintext"`
		Ciphertext       string `json:"ciphertext"`
		LegacyCiphertext string `json:"legacyCiphertext"`
	} `json:"symmetricRotating"`
	JWE struct {
		Payload       json.RawMessage `json:"payload"`
		Token         string          `json:"token"`
		RotatingToken string          `json:"rotatingToken"`
	} `json:"jwe"`
	JWT struct {
		Token string `json:"token"`
	} `json:"jwt"`
	Signature struct {
		Value     string `json:"value"`
		Signature string `json:"signature"`
	} `json:"signature"`
}

func loadFixtures(t *testing.T) tsFixtures {
	t.Helper()
	b, err := os.ReadFile("testdata/ts_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f tsFixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f tsFixtures) rotatingSecret() Secret {
	var vs []VersionedSecret
	for _, kv := range f.Rotating.Keys {
		vs = append(vs, VersionedSecret{Version: int(kv[0].(float64)), Value: kv[1].(string)})
	}
	return Secret{Config: NewSecretConfig(vs, f.Rotating.LegacySecret)}
}

func TestTSPasswordHashesVerifyInGo(t *testing.T) {
	f := loadFixtures(t)
	for _, p := range f.Passwords {
		ok, err := VerifyPassword(p.Hash, p.Password)
		if err != nil || !ok {
			t.Fatalf("password %q did not verify: %v", p.Password, err)
		}
		bad, _ := VerifyPassword(p.Hash, p.Password+"x")
		if bad {
			t.Fatalf("wrong password verified for %q", p.Password)
		}
	}
}

func TestGoPasswordHashFormat(t *testing.T) {
	h, err := HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(h, ":")
	if len(parts) != 2 || len(parts[0]) != 32 || len(parts[1]) != 128 {
		t.Fatalf("unexpected hash format %q", h)
	}
	ok, _ := VerifyPassword(h, "password123")
	if !ok {
		t.Fatal("roundtrip failed")
	}
	// NFKC: the ligature "ﬁ" normalises to "fi".
	h2, _ := HashPassword("ﬁ")
	if ok, _ := VerifyPassword(h2, "fi"); !ok {
		t.Fatal("NFKC normalisation not applied")
	}
	if _, err := VerifyPassword("nocolon", "x"); err == nil {
		t.Fatal("expected invalid hash error")
	}
}

func TestTSSymmetricDecryptsInGo(t *testing.T) {
	f := loadFixtures(t)
	pt, err := SymmetricDecrypt(PlainSecret(f.Secret), f.Symmetric.Ciphertext)
	if err != nil || pt != f.Symmetric.Plaintext {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	rs := f.rotatingSecret()
	pt, err = SymmetricDecrypt(rs, f.SymmetricRotating.Ciphertext)
	if err != nil || pt != f.SymmetricRotating.Plaintext {
		t.Fatalf("rotating decrypt: %q %v", pt, err)
	}
	if !strings.HasPrefix(f.SymmetricRotating.Ciphertext, "$ba$2$") {
		t.Fatalf("unexpected envelope %q", f.SymmetricRotating.Ciphertext[:8])
	}
	pt, err = SymmetricDecrypt(rs, f.SymmetricRotating.LegacyCiphertext)
	if err != nil || pt != "legacy" {
		t.Fatalf("legacy decrypt: %q %v", pt, err)
	}
}

func TestSymmetricRoundTripAndEnvelope(t *testing.T) {
	rs := Secret{Config: NewSecretConfig([]VersionedSecret{{3, "s3"}, {1, "s1"}}, "")}
	ct, err := SymmetricEncrypt(rs, "data")
	if err != nil || !strings.HasPrefix(ct, "$ba$3$") {
		t.Fatalf("encrypt %q %v", ct, err)
	}
	pt, err := SymmetricDecrypt(rs, ct)
	if err != nil || pt != "data" {
		t.Fatalf("decrypt %q %v", pt, err)
	}
	if _, err := SymmetricDecrypt(rs, "abcd"); err == nil {
		t.Fatal("expected legacy error without legacy secret")
	}
	v, c, ok := ParseEnvelope("$ba$12$cafe")
	if !ok || v != 12 || c != "cafe" {
		t.Fatal("parse envelope")
	}
	if _, _, ok := ParseEnvelope("$ba$x$cafe"); ok {
		t.Fatal("invalid version accepted")
	}
}

func TestTSJWEDecodesInGo(t *testing.T) {
	f := loadFixtures(t)
	p := SymmetricDecodeJWT(f.JWE.Token, PlainSecret(f.Secret), "better-auth-session")
	if p == nil {
		t.Fatal("could not decode TS JWE")
	}
	user, _ := p.Get("user")
	if name, _ := user.(*jsonx.Object).Get("name"); name != "Ann" {
		t.Fatalf("payload mismatch: %v", jsonx.MustMarshal(p))
	}
	if SymmetricDecodeJWT(f.JWE.Token, PlainSecret("wrong-secret"), "better-auth-session") != nil {
		t.Fatal("decoded with wrong secret")
	}
	if SymmetricDecodeJWT(f.JWE.Token, PlainSecret(f.Secret), "other-salt") != nil {
		t.Fatal("decoded with wrong salt")
	}
	rp := SymmetricDecodeJWT(f.JWE.RotatingToken, f.rotatingSecret(), "better-auth-session")
	if rp == nil {
		t.Fatal("could not decode rotating JWE")
	}
}

func TestJWEGoRoundTrip(t *testing.T) {
	tok, err := SymmetricEncodeJWT(jsonx.O("a", 1.0), PlainSecret("s"), "salt", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := JWEHeader(tok)
	if string(jsonx.MustMarshal(h))[:40] != `{"alg":"dir","enc":"A256CBC-HS512","kid"` {
		t.Fatalf("header %s", jsonx.MustMarshal(h))
	}
	p := SymmetricDecodeJWT(tok, PlainSecret("s"), "salt")
	if p == nil {
		t.Fatal("roundtrip failed")
	}
	expired, _ := SymmetricEncodeJWT(jsonx.O("a", 1.0), PlainSecret("s"), "salt", -time.Minute)
	if SymmetricDecodeJWT(expired, PlainSecret("s"), "salt") != nil {
		t.Fatal("expired token accepted")
	}
}

func TestTSJWTVerifiesInGo(t *testing.T) {
	f := loadFixtures(t)
	p, err := VerifyJWT(f.JWT.Token, f.Secret, VerifyJWTOptions{Algorithms: []string{"HS256"}})
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := p.Get("email"); e != "a@b.co" {
		t.Fatalf("payload %s", jsonx.MustMarshal(p))
	}
	if p.Has("updateTo") {
		t.Fatal("undefined claim should be omitted")
	}
	if _, err := VerifyJWT(f.JWT.Token, "nope"); err != ErrJWTInvalid {
		t.Fatalf("expected invalid, got %v", err)
	}
	exp, _ := SignJWT(jsonx.O("x", 1.0), "s", -time.Second)
	if _, err := VerifyJWT(exp, "s"); err != ErrJWTExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestTSSignatureMatches(t *testing.T) {
	f := loadFixtures(t)
	if got := MakeSignature(f.Signature.Value, f.Secret); got != f.Signature.Signature {
		t.Fatalf("signature mismatch %s vs %s", got, f.Signature.Signature)
	}
	if !VerifySignature(f.Signature.Signature, f.Signature.Value, f.Secret) {
		t.Fatal("verify failed")
	}
}

func TestPurposeKeyAndRandom(t *testing.T) {
	k := DerivePurposeKey(PlainSecret("secret"), PurposeOAuthStateCookie)
	if len(k.Plain) != 64 {
		t.Fatalf("purpose key %q", k.Plain)
	}
	s := RandomString(64)
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_", c) {
			t.Fatalf("bad char %q", c)
		}
	}
	id := GenerateID()
	if len(id) != 32 || strings.ContainsAny(id, "-_") {
		t.Fatalf("bad id %q", id)
	}
	if u := RandomUUID(); len(u) != 36 || u[14] != '4' {
		t.Fatalf("bad uuid %q", u)
	}
}
