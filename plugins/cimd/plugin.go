// Package cimd is a port of Better Auth's @better-auth/cimd package (v1.7.7): Client ID
// Metadata Documents (draft-ietf-oauth-client-id-metadata-document-02) for the OAuth
// provider (plugins/oauthprovider, or plugins/mcp).
//
// Clients identify themselves with an HTTPS URL as their client_id; the plugin fetches and
// validates the document at that URL (through the application-provided, SSRF-safe
// FetchClientMetadataResource transport), caches it per HTTP freshness rules with
// conditional revalidation, governs fetch amplification, and creates or refreshes the
// discovery-owned client record. Discovery documents advertise
// client_id_metadata_document_supported.
package cimd

import (
	"errors"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Version is the upstream package version.
const Version = "1.7.7"

// ClientCreatedEvent is CimdClientCreatedEvent.
type ClientCreatedEvent struct {
	// Client is the newly persisted discovery-owned OAuth client.
	Client *oauthprovider.SchemaClient
	// ClientMetadataDocument is the validated document that produced the client.
	ClientMetadataDocument *jsonx.Object
	// Context is the endpoint context of the discovery request.
	Context *betterauth.EndpointContext
}

// ClientRefreshedEvent is CimdClientRefreshedEvent.
type ClientRefreshedEvent struct {
	// Client is the discovery-owned client after metadata reconciliation.
	Client *oauthprovider.SchemaClient
	// PreviousClient is the client state captured before reconciliation.
	PreviousClient *oauthprovider.SchemaClient
	// ClientMetadataDocument is the validated document used for reconciliation.
	ClientMetadataDocument *jsonx.Object
	// Context is the endpoint context of the discovery request.
	Context *betterauth.EndpointContext
}

// MetadataFetchPolicy is CimdMetadataFetchPolicy: a bounded request-amplification policy
// for metadata document fetches. nil fields use the defaults. Limits reject immediately
// (429 temporarily_unavailable) rather than queueing.
type MetadataFetchPolicy struct {
	// MinimumFetchInterval is the minimum time before retrying a failed fetch for one
	// client ID: seconds (int / float64), a duration string ("10s") or a time.Duration.
	// 0 disables failed-fetch pacing. Default 1 second.
	MinimumFetchInterval any
	// MaximumConcurrentFetches across the plugin instance (default 16).
	MaximumConcurrentFetches *int
	// MaximumConcurrentFetchesPerOrigin for one URL origin (default 4).
	MaximumConcurrentFetchesPerOrigin *int
	// MaximumFetchesPerMinute in a rolling 60-second window (default 120).
	MaximumFetchesPerMinute *int
	// MaximumFetchesPerOriginPerMinute in a rolling 60-second window per origin (default 30).
	MaximumFetchesPerOriginPerMinute *int
}

// Options are CimdOptions.
type Options struct {
	// FetchClientMetadataResource is the transport for metadata documents and
	// discovery-owned metadata resources such as jwks_uri. It MUST resolve the hostname
	// once, reject special-use addresses, pin the approved address for the connection and
	// refuse redirects; FetchClientMetadataResource (this package) is such a transport.
	// Required.
	FetchClientMetadataResource oauthprovider.ClientMetadataResourceFetch
	// MetadataProfile applies an additional protocol profile ("mcp-2026-07-28" requires
	// client_name and redirect_uris).
	MetadataProfile string
	// MetadataRevalidationInterval is the maximum and fallback cache freshness lifetime:
	// seconds (int / float64), a duration string ("60m", "1d") or a time.Duration.
	// Default "60m".
	MetadataRevalidationInterval any
	// MetadataFetchPolicy bounds metadata fetches.
	MetadataFetchPolicy *MetadataFetchPolicy
	// MaxCacheEntries bounds the validated documents retained (LRU, default 1000).
	MaxCacheEntries *int
	// OriginBoundFields lists metadata fields whose URL values must share the client_id
	// origin. nil = ["post_logout_redirect_uris", "client_uri"]; an empty non-nil slice
	// disables origin binding.
	OriginBoundFields []string
	// IsMetadataDocumentURLAllowed is a pre-fetch gate; returning false rejects the
	// client_id URL.
	IsMetadataDocumentURLAllowed func(clientIDURL string, ctx *betterauth.EndpointContext) (bool, error)
	// OnClientCreated is a best-effort notification after a client is created from a
	// metadata document (errors are logged, never rolled back).
	OnClientCreated func(ev ClientCreatedEvent) error
	// OnClientRefreshed is a best-effort notification after a client is refreshed.
	OnClientRefreshed func(ev ClientRefreshedEvent) error
}

// CreateCimdClientDiscovery builds the ClientDiscovery for Client ID Metadata Documents
// (createCimdClientDiscovery). Contribute it explicitly through
// oauthprovider.Options.Extensions, or install the plugin returned by New.
func CreateCimdClientDiscovery(options Options) (*oauthprovider.ClientDiscovery, error) {
	if options.FetchClientMetadataResource == nil {
		return nil, errors.New("cimd fetchClientMetadataResource is required")
	}
	o := options
	r, err := newResolver(&o)
	if err != nil {
		return nil, err
	}
	return &oauthprovider.ClientDiscovery{
		ID:                          ClientDiscoveryID,
		Matches:                     IsCimdClientIDURLCandidate,
		Resolve:                     r.resolve,
		FetchClientMetadataResource: options.FetchClientMetadataResource,
		DiscoveryMetadata:           jsonx.O("client_id_metadata_document_supported", true),
	}, nil
}

// New creates the Client ID Metadata Document plugin (cimd()). It extends the
// oauth-provider plugin (plugins/oauthprovider or plugins/mcp), which must also be
// installed. The error reports invalid options.
func New(options Options) (*betterauth.Plugin, error) {
	discovery, err := CreateCimdClientDiscovery(options)
	if err != nil {
		return nil, err
	}
	ext := &oauthprovider.Extension{ClientDiscovery: []*oauthprovider.ClientDiscovery{discovery}}
	return &betterauth.Plugin{
		ID:      "cimd",
		Version: Version,
		Options: &options,
		Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			return nil, oauthprovider.ExtendOAuthProvider(ac, ext)
		},
	}, nil
}

// MustNew is New that panics on invalid options.
func MustNew(options Options) *betterauth.Plugin {
	p, err := New(options)
	if err != nil {
		panic(err)
	}
	return p
}
