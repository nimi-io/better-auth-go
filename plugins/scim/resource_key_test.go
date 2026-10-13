package scim

// Port of upstream resource-key.test.ts ("SCIM persisted keys").

import (
	"strings"
	"testing"
)

func TestResourceKey_SCIMPersistedKeys(t *testing.T) {
	t.Run("remain fixed-size for provider-controlled identifiers", func(t *testing.T) {
		key := CreateUserExternalIDKey("connection-a", strings.Repeat("external-id", 1000))
		if len(key) != 43 {
			t.Fatalf("len = %d, want 43", len(key))
		}
	})

	t.Run("scope User externalIds by exact connection and value", func(t *testing.T) {
		if CreateUserExternalIDKey("connection-a", "external-id") != CreateUserExternalIDKey("connection-a", "external-id") {
			t.Fatal("same input should give same key")
		}
		if CreateUserExternalIDKey("connection-a", "external-id") == CreateUserExternalIDKey("connection-b", "external-id") {
			t.Fatal("connection must scope key")
		}
		if CreateUserExternalIDKey("connection-a", "external-id") == CreateUserExternalIDKey("connection-a", "EXTERNAL-ID") {
			t.Fatal("key must be case sensitive")
		}
	})

	t.Run("preserve tuple boundaries and connection scope", func(t *testing.T) {
		if createScopedKey("ab", "c") == createScopedKey("a", "bc") {
			t.Fatal("tuple boundaries not preserved")
		}
		if createScopedKey("connection-a", "resource") == createScopedKey("connection-b", "resource") {
			t.Fatal("connection scope not preserved")
		}
	})
}
