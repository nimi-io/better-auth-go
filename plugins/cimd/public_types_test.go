package cimd

import (
	"os"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/public-types.test.ts (type-level assertions become
// compile-time checks).

func TestPublicCimdSurface(t *testing.T) {
	t.Run("exports the canonical discovery and validation vocabulary", func(t *testing.T) {
		var _ func(Options) (*oauthprovider.ClientDiscovery, error) = CreateCimdClientDiscovery
		var _ func(string) bool = IsCimdClientIDURLCandidate
		var _ func(string) string = ValidateClientIDURL
		var _ func(string, any, MetadataValidationOptions) MetadataValidationResult = ValidateCimdMetadata
		var vo MetadataValidationOptions
		var _ []string = vo.OriginBoundFields
		var o Options
		var _ any = o.MetadataRevalidationInterval
		// validation result narrowing: Metadata on success, Error on failure.
		r := ValidateCimdMetadata("https://example.com/c.json", map[string]any{}, vo)
		if r.Valid || r.Error == "" || r.Metadata != nil {
			t.Fatal(r)
		}
	})

	t.Run("exports named callback event contracts", func(t *testing.T) {
		var created ClientCreatedEvent
		var _ *oauthprovider.SchemaClient = created.Client
		var _ *jsonx.Object = created.ClientMetadataDocument
		var _ *betterauth.EndpointContext = created.Context
		var refreshed ClientRefreshedEvent
		var _ *oauthprovider.SchemaClient = refreshed.PreviousClient
		var _ *oauthprovider.SchemaClient = refreshed.Client
	})

	// Go-only: the node.ts transport is a plain package-level fetch.
	t.Run("exports the SSRF-safe transport", func(t *testing.T) {
		var _ oauthprovider.ClientMetadataResourceFetch = FetchClientMetadataResource
		if _, err := os.Stat("node"); err == nil {
			t.Fatal("unexpected subpackage")
		}
	})

	// Go-only: plugin construction.
	t.Run("validates options at construction", func(t *testing.T) {
		if _, err := New(Options{}); err == nil {
			t.Fatal("expected missing transport error")
		}
		if _, err := New(Options{FetchClientMetadataResource: FetchClientMetadataResource, MaxCacheEntries: intp(0)}); err == nil {
			t.Fatal("expected maxCacheEntries error")
		}
		p, err := New(Options{FetchClientMetadataResource: FetchClientMetadataResource})
		if err != nil || p.ID != "cimd" || p.Version != "1.7.7" {
			t.Fatal(p, err)
		}
	})
}
