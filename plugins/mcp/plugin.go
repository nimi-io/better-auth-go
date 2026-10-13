// Package mcp is a port of Better Auth's @better-auth/mcp package (v1.7.7): the Model
// Context Protocol authorization server and resource-server helpers.
//
// New returns the OAuth 2.1 / OIDC provider (plugins/oauthprovider) configured for MCP: it
// binds issued tokens to the MCP resource (RFC 8707), links that resource to newly
// registered clients, defaults refreshTokenReuseInterval to 30 seconds and serves the RFC
// 9728 protected resource metadata (/.well-known/oauth-protected-resource and the
// resource-path-inserted alias) so MCP clients discover the authorization server through
// standard OAuth discovery. Client registration is opt-in: compose with plugins/cimd for
// Client ID Metadata Documents, or enable the provider's dynamic-registration options.
//
// MCP servers protect their routes with RequireMcpAuth (same-process authorization
// server) or CreateMcpProtectedRequestHandler (explicit verification options), or with
// the net/http middleware variants Middleware / RequireMcpAuthMiddleware.
package mcp

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Version is the upstream package version.
const Version = "1.7.7"

const protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

var authorizationServerOnlyScopes = map[string]bool{
	"openid": true, "profile": true, "email": true, "phone": true, "address": true, "offline_access": true,
}

// Options are McpOptions: the full OAuth provider configuration plus the MCP resource.
type Options struct {
	oauthprovider.Options
	// RefreshTokenReuseInterval is the number of seconds a rotated refresh token can be
	// reused to receive the same token response. nil defaults to 30 for MCP; 0 disables the
	// overlap window (strict replay handling). It shadows
	// oauthprovider.Options.RefreshTokenReuseInterval.
	RefreshTokenReuseInterval *int
	// Resource is the canonical protected resource identifier (RFC 8707 / RFC 9728) for
	// this MCP server. It must be an HTTPS URL without query, fragment or credentials
	// (HTTP only on loopback hosts).
	Resource string
}

func appendProtectedResource(resources []oauthprovider.ResourceInput, resource string) []oauthprovider.ResourceInput {
	for _, r := range resources {
		if r.Identifier == resource {
			return resources
		}
	}
	return append(append([]oauthprovider.ResourceInput(nil), resources...), oauthprovider.ResourceInput{Identifier: resource})
}

func appendResourceIdentifier(resources []string, resource string) []string {
	for _, r := range resources {
		if r == resource {
			return resources
		}
	}
	return append(append([]string(nil), resources...), resource)
}

// buildResourceServerMetadata builds the RFC 9728 Protected Resource Metadata document.
// Resource metadata only advertises scopes that apply to the protected resource itself;
// OIDC identity scopes and offline_access stay authorization-server metadata.
func buildResourceServerMetadata(ctx *betterauth.EndpointContext, providerOptions oauthprovider.Options, resource string) *jsonx.Object {
	var scopes []string
	switch {
	case providerOptions.AdvertisedMetadata != nil && providerOptions.AdvertisedMetadata.ScopesSupported != nil:
		scopes = providerOptions.AdvertisedMetadata.ScopesSupported
	case providerOptions.Scopes != nil:
		scopes = providerOptions.Scopes
	}
	var resourceScopes []any
	for _, s := range scopes {
		if !authorizationServerOnlyScopes[s] {
			resourceScopes = append(resourceScopes, s)
		}
	}
	dpopRequired := false
	for _, r := range providerOptions.Resources {
		if r.Identifier == resource {
			dpopRequired = r.DPoPBoundAccessTokensRequired != nil && *r.DPoPBoundAccessTokensRequired
			break
		}
	}
	algs := oauthcore.DPoPSigningAlgorithms
	if providerOptions.DPoP != nil && providerOptions.DPoP.SigningAlgorithms != nil {
		algs = providerOptions.DPoP.SigningAlgorithms
	}
	algList := make([]any, len(algs))
	for i, a := range algs {
		algList[i] = a
	}
	m := jsonx.O(
		"resource", resource,
		"authorization_servers", []any{oauthprovider.GetIssuer(ctx)},
		"bearer_methods_supported", []any{"header"},
		"dpop_signing_alg_values_supported", algList,
	)
	if dpopRequired {
		m.Set("dpop_bound_access_tokens_required", true)
	}
	if len(resourceScopes) > 0 {
		m.Set("scopes_supported", resourceScopes)
	}
	return m
}

// New creates the MCP authorization server plugin (mcp()). It is the oauth-provider
// plugin (ID "oauth-provider") and therefore cannot be combined with a separate
// oauthprovider.New. The error is non-nil when options.Resource is not a valid canonical
// MCP resource; other option errors surface from betterauth.New like oauthprovider's.
func New(options Options) (*betterauth.Plugin, error) {
	resource, err := ValidateMcpResource(options.Resource)
	if err != nil {
		return nil, err
	}
	oauthOptions := options.Options
	providerOptions := oauthOptions
	providerOptions.RefreshTokenReuseInterval = 30
	if options.RefreshTokenReuseInterval != nil {
		providerOptions.RefreshTokenReuseInterval = *options.RefreshTokenReuseInterval
	}
	// RFC 8707: bind issued tokens to the MCP resource so the resource server can verify
	// the token audience against its protected resource identifier.
	providerOptions.Resources = appendProtectedResource(oauthOptions.Resources, resource)
	providerOptions.ClientRegistrationDefaultResources = appendResourceIdentifier(oauthOptions.ClientRegistrationDefaultResources, resource)
	provider := oauthprovider.New(providerOptions)

	resourcePath := ""
	if u, err := url.Parse(resource); err == nil {
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		resourcePath = strings.TrimSuffix(p, "/")
	}
	servedPaths := map[string]bool{
		protectedResourceMetadataPath:                true,
		protectedResourceMetadataPath + resourcePath: true,
	}

	// The MCP server is the OAuth resource server, so it serves the RFC 9728 protected
	// resource metadata. The provider's discovery hook runs first (authorization-server and
	// OpenID metadata); this serves the protected resource document at the well-known root
	// and the resource-path-inserted alias, on the paths the provider leaves unhandled.
	serveProviderDiscovery := provider.OnRequest
	provider.OnRequest = func(r *http.Request, ac *betterauth.AuthContext) (*http.Request, *betterauth.Response, error) {
		if serveProviderDiscovery != nil {
			nr, res, err := serveProviderDiscovery(r, ac)
			if err != nil || res != nil {
				return nr, res, err
			}
		}
		requestPath := r.URL.EscapedPath()
		if ac.Options.Advanced != nil && ac.Options.Advanced.SkipTrailingSlashes {
			requestPath = strings.TrimRight(requestPath, "/")
			if requestPath == "" {
				requestPath = "/"
			}
		}
		if !servedPaths[requestPath] {
			return nil, nil, nil
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h := http.Header{}
			h.Set("Allow", "GET, HEAD")
			return nil, &betterauth.Response{Status: 405, Header: h}, nil
		}
		ctx := &betterauth.EndpointContext{Auth: ac, Request: r, Headers: r.Header}
		res := oauthprovider.MetadataResponse(buildResourceServerMetadata(ctx, oauthOptions, resource), nil)
		if r.Method == http.MethodHead {
			res.Body = nil
		}
		return nil, res, nil
	}
	return provider, nil
}

// MustNew is New that panics on an invalid resource.
func MustNew(options Options) *betterauth.Plugin {
	p, err := New(options)
	if err != nil {
		panic(err)
	}
	return p
}
