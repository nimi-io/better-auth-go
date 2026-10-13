package twofactor

import (
	"testing"

	"github.com/nimi-io/better-auth-go/jsonx"
)

func TestPluginShape(t *testing.T) {
	p := New(Options{})
	want := []struct{ key, path string }{
		{"generateTOTP", ""}, {"getTOTPURI", "/two-factor/get-totp-uri"}, {"verifyTOTP", "/two-factor/verify-totp"},
		{"sendTwoFactorOTP", "/two-factor/send-otp"}, {"verifyTwoFactorOTP", "/two-factor/verify-otp"},
		{"verifyBackupCode", "/two-factor/verify-backup-code"}, {"generateBackupCodes", "/two-factor/generate-backup-codes"},
		{"viewBackupCodes", ""}, {"enableTwoFactor", "/two-factor/enable"}, {"disableTwoFactor", "/two-factor/disable"},
	}
	if len(p.Endpoints) != len(want) {
		t.Fatalf("endpoints %d", len(p.Endpoints))
	}
	for k, w := range want {
		e := p.Endpoints[k]
		if e.Key != w.key || e.Path != w.path || e.ServerOnly != (w.path == "") || e.Methods[0] != "POST" {
			t.Fatalf("endpoint %d: %+v", k, e)
		}
		if e.Key != "viewBackupCodes" {
			if _, ok := e.Metadata["openapi"].(*jsonx.Object); !ok {
				t.Fatalf("%s: no openapi metadata", e.Key)
			}
		}
	}
	if len(p.Schema) != 2 || p.Schema[1].Key != "twoFactor" || len(p.Schema[1].Fields) != 6 {
		t.Fatalf("schema %+v", p.Schema)
	}
	if len(p.ErrorCodes) != 13 || p.RateLimit[0].Max != 3 || !p.RateLimit[0].PathMatcher("/two-factor/enable") {
		t.Fatal("error codes / rate limit")
	}
	if New(Options{TwoFactorTable: "tf"}).Schema[1].ModelName != "tf" {
		t.Fatal("modelName")
	}
}
