package mcp

import (
	"errors"
	"net/http"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/mcp/src/require-mcp-auth.ts.

// RequireMcpAuthOptions are RequireMcpAuthOptions.
type RequireMcpAuthOptions struct {
	// Resource is the protected resource identifier the access token must be bound to.
	// Defaults to the server's resolved base URL.
	Resource string
	// Issuer is the expected token issuer. Defaults to the server's resolved base URL.
	// Override when the JWT plugin is configured with a custom issuer.
	Issuer string
	// JWKSURL defaults to /jwks under the server's resolved base URL.
	JWKSURL string
	// ChallengeScopes are advertised in the WWW-Authenticate challenge (RFC 6750).
	// Defaults to RequiredScopes.
	ChallengeScopes []string
	// RequiredScopes must all be present in the token's scope claim; a token missing any
	// of them is rejected with a 403 insufficient_scope challenge naming every missing
	// scope.
	RequiredScopes []string
	// IsScopeSatisfied is a custom required-scope matcher (default exact membership).
	IsScopeSatisfied func(requiredScope string, grantedScopes map[string]bool) bool
	// DPoP configures proof validation. By default the replay store is backed by the auth
	// instance's database (anti-replay across server instances).
	DPoP *DPoPOptions
}

// authState is the part of auth.$context requireMcpAuth reads.
type authState func() (baseURL string, reservations oauthcore.DPoPReplayReservations)

// RequireMcpAuth protects an MCP server route handler (requireMcpAuth). It verifies the
// bearer access token against the authorization server's JWKS (signature, issuer,
// audience and expiry) and forwards the verified payload to handler. Unauthenticated
// requests receive a JSON-RPC 401 with the RFC 9728 WWW-Authenticate header; tokens
// missing a required scope receive a 403 insufficient_scope challenge. A handler can raise
// the same challenge for scopes only it knows about by returning
// oauthcore.CreateInsufficientScopeError(...).
//
// For a resource server running separately from the authorization server, or a server
// using a dynamic base URL, use CreateMcpProtectedRequestHandler with explicit options.
func RequireMcpAuth(auth *betterauth.Auth, handler RequestHandler, opts *RequireMcpAuthOptions) (ProtectedHandler, error) {
	return requireMcpAuth(func() (string, oauthcore.DPoPReplayReservations) {
		ac := auth.Context()
		return ac.BaseURL, ac.InternalAdapter
	}, handler, opts)
}

func requireMcpAuth(state authState, handler RequestHandler, opts *RequireMcpAuthOptions) (ProtectedHandler, error) {
	if opts == nil {
		opts = &RequireMcpAuthOptions{}
	}
	if opts.Resource != "" {
		if _, err := ValidateMcpResource(opts.Resource); err != nil {
			return nil, err
		}
	}
	return func(r *http.Request) (*betterauth.Response, error) {
		protected, err := requireMcpAuthHandler(state, handler, opts)
		if err != nil {
			return nil, err
		}
		return protected(r)
	}, nil
}

// requireMcpAuthOptions resolves the protected-request options from the auth context.
func requireMcpAuthOptions(state authState, opts *RequireMcpAuthOptions) (ProtectedRequestHandlerOptions, error) {
	// The provider stamps tokens with its resolved base URL (which includes the base path)
	// as both issuer and default resource.
	baseURL, reservations := state()
	if baseURL == "" {
		return ProtectedRequestHandlerOptions{}, errors.New("requireMcpAuth requires a resolvable base URL. For dynamic base URLs use `createMcpProtectedRequestHandler` with explicit verification options.")
	}
	issuer := opts.Issuer
	if issuer == "" {
		issuer = baseURL
	}
	resource := opts.Resource
	if resource == "" {
		resource = baseURL
	}
	jwksURL := opts.JWKSURL
	if jwksURL == "" {
		jwksURL = baseURL + "/jwks"
	}
	dpop := &DPoPOptions{}
	if opts.DPoP != nil {
		*dpop = *opts.DPoP
	}
	if dpop.ReplayStore == nil && reservations != nil {
		// Default to the database-backed store so proof replay is rejected across
		// instances, not just within one process.
		dpop.ReplayStore = oauthcore.NewDPoPReplayStore(reservations)
	}
	return ProtectedRequestHandlerOptions{
		Issuer:           issuer,
		Audience:         resource,
		RequiredScopes:   opts.RequiredScopes,
		ChallengeScopes:  opts.ChallengeScopes,
		IsScopeSatisfied: opts.IsScopeSatisfied,
		JWKSURL:          jwksURL,
		DPoP:             dpop,
	}, nil
}

func requireMcpAuthHandler(state authState, handler RequestHandler, opts *RequireMcpAuthOptions) (ProtectedHandler, error) {
	o, err := requireMcpAuthOptions(state, opts)
	if err != nil {
		return nil, err
	}
	return CreateMcpProtectedRequestHandler(o, handler)
}
