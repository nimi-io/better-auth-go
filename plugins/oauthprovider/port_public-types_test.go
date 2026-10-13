package oauthprovider

import "testing"

// Port of public-types.test.ts.

func TestMx_PublicOAuthProviderTypes(t *testing.T) {
	t.Run("exports the signed-query verifier with a server-side secret", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf type-level test of the package exports")
	})
	t.Run("exports option helper types from the package entrypoint", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf type-level test of the package exports")
	})
}
