package betterauth

// Port of the "context secret helpers" block of
// packages/better-auth/src/crypto/secret-rotation.test.ts (upstream v1.7.7):
// parseSecretsEnv, validateSecretsArray and buildSecretConfig live in context/secret-utils
// upstream and in auth.go (package betterauth) in the Go port.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
)

func ppExpectErrContains(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("err = %v, want containing %q", err, sub)
	}
}

func TestPortAPISecretsParseSecretsEnv(t *testing.T) {
	t.Run("returns null for undefined/empty", func(t *testing.T) {
		got, err := parseSecretsEnv("")
		if err != nil || got != nil {
			t.Fatalf("got %v %v", got, err)
		}
	})
	t.Run("trims whitespace around entries and values", func(t *testing.T) {
		got, err := parseSecretsEnv("1: foo , 2:bar ")
		if err != nil {
			t.Fatal(err)
		}
		if want := []SecretEntry{{1, "foo"}, {2, "bar"}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("rejects entry without colon", func(t *testing.T) {
		_, err := parseSecretsEnv("noseparator")
		ppExpectErrContains(t, err, "Expected format")
	})
	t.Run("rejects negative version", func(t *testing.T) {
		_, err := parseSecretsEnv("-1:secret")
		ppExpectErrContains(t, err, "non-negative integer")
	})
	t.Run("rejects non-integer version", func(t *testing.T) {
		_, err := parseSecretsEnv("abc:secret")
		ppExpectErrContains(t, err, "non-negative integer")
	})
	t.Run("rejects empty value", func(t *testing.T) {
		_, err := parseSecretsEnv("1:")
		ppExpectErrContains(t, err, "Empty secret value")
	})
}

func TestPortAPISecretsValidateSecretsArray(t *testing.T) {
	log := NopLogger{}
	t.Run("throws on empty array", func(t *testing.T) {
		ppExpectErrContains(t, validateSecretsArray(nil, log), "at least one entry")
	})
	t.Run("throws on duplicate versions", func(t *testing.T) {
		ppExpectErrContains(t, validateSecretsArray([]SecretEntry{
			{1, "secret-a-at-least-32-chars-long!!"}, {1, "secret-b-at-least-32-chars-long!!"}}, log), "Duplicate version")
	})
	t.Run("throws on negative version", func(t *testing.T) {
		ppExpectErrContains(t, validateSecretsArray([]SecretEntry{{-1, "secret-a-at-least-32-chars-long!!"}}, log), "non-negative integer")
	})
	t.Run("throws on empty value", func(t *testing.T) {
		ppExpectErrContains(t, validateSecretsArray([]SecretEntry{{1, ""}}, log), "Empty secret value")
	})
	t.Run("accepts valid config", func(t *testing.T) {
		if err := validateSecretsArray([]SecretEntry{
			{2, "secret-b-at-least-32-chars-long!!"}, {1, "secret-a-at-least-32-chars-long!!"}}, log); err != nil {
			t.Fatal(err)
		}
	})
	for _, name := range []string{
		"accepts string versions that are valid integers",
		"rejects hex string versions",
		"rejects scientific notation versions",
		"detects duplicates after coercion",
	} {
		t.Run(name, func(t *testing.T) {
			t.Skip("TS-only: string-typed versions coerced at runtime; SecretEntry.Version is an int in Go")
		})
	}
}

// buildSecretConfig is performed by New in the Go port (SecretConfig on the AuthContext).
func ppBuildSecretConfig(t *testing.T, secrets []SecretEntry, legacy string) *AuthContext {
	t.Helper()
	t.Setenv("BETTER_AUTH_SECRET", "")
	t.Setenv("AUTH_SECRET", "")
	t.Setenv("BETTER_AUTH_SECRETS", "")
	t.Setenv("NODE_ENV", "test")
	a, err := New(Config{BaseURL: "http://localhost:3000", Secrets: secrets, Secret: legacy,
		Database: memory.New(memory.NewDB()), Logger: NopLogger{}})
	if err != nil {
		t.Fatal(err)
	}
	return a.Context()
}

func TestPortAPISecretsBuildSecretConfig(t *testing.T) {
	t.Run("builds config with keys map", func(t *testing.T) {
		ctx := ppBuildSecretConfig(t, []SecretEntry{
			{2, "secret-b-at-least-32-chars-long!!"}, {1, "secret-a-at-least-32-chars-long!!"}}, "")
		cfg := ctx.SecretConfig.Config
		if cfg == nil {
			t.Fatal("SecretConfig not built")
		}
		if cfg.CurrentVersion != 2 {
			t.Fatalf("currentVersion = %d", cfg.CurrentVersion)
		}
		if cfg.Keys[1] != "secret-a-at-least-32-chars-long!!" || cfg.Keys[2] != "secret-b-at-least-32-chars-long!!" {
			t.Fatalf("keys = %v", cfg.Keys)
		}
		if cfg.LegacySecret != "" {
			t.Fatalf("legacySecret = %q", cfg.LegacySecret)
		}
	})
	t.Run("includes legacySecret when provided", func(t *testing.T) {
		ctx := ppBuildSecretConfig(t, []SecretEntry{{1, "secret-a-at-least-32-chars-long!!"}}, "legacy-secret-at-least-32-chars!!")
		if got := ctx.SecretConfig.Config.LegacySecret; got != "legacy-secret-at-least-32-chars!!" {
			t.Fatalf("legacySecret = %q", got)
		}
	})
	t.Run("normalizes string versions to numbers in output", func(t *testing.T) {
		t.Skip("TS-only: string-typed versions; SecretEntry.Version is an int in Go")
	})
	t.Run("excludes DEFAULT_SECRET as legacySecret", func(t *testing.T) {
		ctx := ppBuildSecretConfig(t, []SecretEntry{{1, "secret-a-at-least-32-chars-long!!"}}, "better-auth-secret-12345678901234567890")
		if got := ctx.SecretConfig.Config.LegacySecret; got != "" {
			t.Fatalf("legacySecret = %q", got)
		}
	})
}
