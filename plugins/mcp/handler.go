package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/mcp/src/handler.ts: the protected-request wrapper an MCP server uses
// to verify access tokens and answer with RFC 9728 / RFC 6750 / RFC 9449 challenges.

// RequestHandler handles a verified MCP request. claims is the verified access token
// payload (JWTPayload upstream). Returned errors propagate unchanged to the caller of the
// protected handler, except insufficient-scope errors created with
// oauthcore.CreateInsufficientScopeError, which become 403 step-up challenges.
type RequestHandler func(r *http.Request, claims *jsonx.Object) (*betterauth.Response, error)

// ProtectedHandler is a protected request handler (the function returned by
// createMcpProtectedRequestHandler / requireMcpAuth). Use HandlerFunc to mount it on a
// net/http mux.
type ProtectedHandler func(r *http.Request) (*betterauth.Response, error)

// RemoteVerifyOptions configure remote introspection for opaque or remotely checked
// tokens.
type RemoteVerifyOptions struct {
	IntrospectURL        string
	ClientID             string
	ClientSecret         string
	Force                bool
	AllowMissingAudience bool
}

// DPoPOptions configure DPoP proof validation and replay protection.
type DPoPOptions struct {
	ProofMaxAgeSeconds int
	SigningAlgorithms  []string
	ReplayStore        oauthcore.DPoPReplayStore
}

// ProtectedRequestHandlerOptions are McpProtectedRequestHandlerOptions.
type ProtectedRequestHandlerOptions struct {
	// Issuer is the expected authorization-server issuer for the access token.
	Issuer string
	// Audience is the canonical MCP protected-resource URL expected in the token audience.
	Audience string
	// JWTVerifyOptions are additional JOSE verification constraints. Issuer and Audience
	// remain authoritative from the top-level fields.
	JWTVerifyOptions oauthcore.VerifyOptions
	// JWKSURL is the URL of the authorization server's JSON Web Key Set.
	JWKSURL string
	// RemoteVerify enables remote introspection.
	RemoteVerify *RemoteVerifyOptions
	// RequiredScopes are the scopes every accepted access token must satisfy.
	RequiredScopes []string
	// ChallengeScopes are advertised in unauthenticated WWW-Authenticate challenges.
	// Defaults to RequiredScopes.
	ChallengeScopes []string
	// IsScopeSatisfied is a custom required-scope matcher (default exact membership).
	IsScopeSatisfied func(requiredScope string, grantedScopes map[string]bool) bool
	// DPoP configures proof validation and replay protection.
	DPoP *DPoPOptions
}

// verifyAccessTokenRequest is oauthcore.VerifyAccessTokenRequest (replaced in tests, like
// the upstream vi.mock of better-auth/oauth2).
var verifyAccessTokenRequest = oauthcore.VerifyAccessTokenRequest

var allDigits = regexp.MustCompile(`^\d+$`)

func isLoopbackHost(hostname string) bool {
	octets := strings.Split(hostname, ".")
	ipv4Loopback := len(octets) == 4 && octets[0] == "127"
	if ipv4Loopback {
		for _, o := range octets {
			n, err := strconv.Atoi(o)
			if !allDigits.MatchString(o) || err != nil || n > 255 {
				ipv4Loopback = false
				break
			}
		}
	}
	return hostname == "localhost" || hostname == "[::1]" || ipv4Loopback
}

// whatwgHostname returns the hostname as WHATWG URL reports it (IPv6 literals keep their
// brackets).
func whatwgHostname(u *url.URL) string {
	h := strings.ToLower(u.Hostname())
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// ValidateMcpResource validates the canonical protected-resource identifier accepted by
// MCP (validateMcpResource). The error messages match upstream's TypeErrors.
func ValidateMcpResource(resource string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(resource))
	if err != nil || u.Scheme == "" {
		return "", errors.New("MCP resource must be an absolute URL")
	}
	if u.User != nil {
		if pw, _ := u.User.Password(); u.User.Username() != "" || pw != "" {
			return "", errors.New("MCP resource URL must not contain credentials")
		}
	}
	if strings.Contains(resource, "#") {
		return "", errors.New("MCP resource URL must not contain a fragment")
	}
	if strings.Contains(resource, "?") {
		return "", errors.New("MCP resource URL must not contain a query; to protect a query-carrying resource, verify tokens with verifyAccessTokenRequest and build challenges with createResourceServerChallenge")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopbackHost(whatwgHostname(u))) {
		return "", errors.New("MCP resource URL must use HTTPS, except for localhost or loopback IP development URLs")
	}
	return resource, nil
}

type challengeOptions struct {
	challengeScopes       []string
	dpopSigningAlgorithms []string
}

// challengeFor converts err into the challenge APIError, or returns err when it is not
// challengeable (upstream rethrows).
func challengeFor(err error, resource string, o challengeOptions) (*betterauth.APIError, error) {
	ch, cerr := oauthprovider.CreateResourceServerChallenge(err, []string{resource}, &oauthprovider.ResourceChallengeOptions{
		ChallengeScopes:       o.challengeScopes,
		DPoPSigningAlgorithms: o.dpopSigningAlgorithms,
	})
	if cerr != nil {
		return nil, cerr
	}
	if ch == nil {
		return nil, err
	}
	return ch, nil
}

// toChallengeResponse renders the challenge as a JSON-RPC error response.
func toChallengeResponse(err error, resource string, o challengeOptions) (*betterauth.Response, error) {
	ch, err := challengeFor(err, resource, o)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, vs := range ch.Headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	h.Set("Content-Type", "application/json")
	body, _ := jsonx.Marshal(jsonx.O(
		"jsonrpc", "2.0",
		"error", jsonx.O("code", -32000, "message", ch.Message()),
		"id", nil,
	))
	return &betterauth.Response{Status: ch.StatusCode, Header: h, Body: body}, nil
}

// isInsufficientScopeError mirrors upstream's branded isInsufficientScopeError: Go cannot
// brand error values, so besides the RFC 6750 shape it requires the message and
// error_description that createInsufficientScopeError always sets. A bare
// APIError("FORBIDDEN", {error: "insufficient_scope", scope}) is therefore not treated as
// a step-up challenge.
func isInsufficientScopeError(err error) bool {
	e, ok := oauthcore.IsInsufficientScopeError(err)
	if !ok {
		return false
	}
	desc, _ := e.Body.Get("error_description")
	msg, _ := e.Body.Get("message")
	ds, ok1 := desc.(string)
	ms, ok2 := msg.(string)
	return ok1 && ok2 && ds != "" && ms != ""
}

type verifier struct {
	resource  string
	challenge challengeOptions
	verify    oauthcore.VerifyAccessTokenRequestOptions
}

func newVerifier(options ProtectedRequestHandlerOptions) (*verifier, error) {
	resource, err := ValidateMcpResource(options.Audience)
	if err != nil {
		return nil, err
	}
	v := &verifier{resource: resource}
	v.challenge.challengeScopes = options.ChallengeScopes
	if v.challenge.challengeScopes == nil {
		v.challenge.challengeScopes = options.RequiredScopes
	}
	if options.DPoP != nil {
		v.challenge.dpopSigningAlgorithms = options.DPoP.SigningAlgorithms
	}
	vo := options.JWTVerifyOptions
	vo.Issuer = []string{options.Issuer}
	vo.Audience = []string{options.Audience}
	v.verify = oauthcore.VerifyAccessTokenRequestOptions{VerifyAccessTokenOptions: oauthcore.VerifyAccessTokenOptions{
		VerifyOptions:    vo,
		JWKSURL:          options.JWKSURL,
		RequiredScopes:   options.RequiredScopes,
		IsScopeSatisfied: options.IsScopeSatisfied,
	}}
	if rv := options.RemoteVerify; rv != nil {
		v.verify.RemoteVerify = &oauthcore.RemoteVerify{IntrospectURL: rv.IntrospectURL, ClientID: rv.ClientID,
			ClientSecret: rv.ClientSecret, Force: rv.Force, AllowMissingAudience: rv.AllowMissingAudience}
	}
	if d := options.DPoP; d != nil {
		v.verify.DPoP = &oauthcore.DPoPVerifyOptions{ProofMaxAgeSeconds: d.ProofMaxAgeSeconds,
			SigningAlgorithms: d.SigningAlgorithms, ReplayStore: d.ReplayStore}
	}
	return v, nil
}

// verifyRequest verifies r. On failure it returns the challenge response, or an error for
// failures that are not challengeable.
func (v *verifier) verifyRequest(r *http.Request) (*jsonx.Object, *betterauth.Response, error) {
	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	claims, err := verifyAccessTokenRequest(ctx, oauthcore.RequestToResourceInput(r), v.verify)
	if err != nil {
		res, cerr := toChallengeResponse(err, v.resource, v.challenge)
		return nil, res, cerr
	}
	return claims, nil, nil
}

// CreateMcpProtectedRequestHandler wraps handler with MCP access-token verification
// (createMcpProtectedRequestHandler). Unauthenticated requests receive a JSON-RPC 401 with
// the RFC 9728 WWW-Authenticate header; tokens missing a required scope receive a 403
// insufficient_scope challenge. The returned error is non-nil when options.Audience is not
// a valid canonical MCP resource.
func CreateMcpProtectedRequestHandler(options ProtectedRequestHandlerOptions, handler RequestHandler) (ProtectedHandler, error) {
	v, err := newVerifier(options)
	if err != nil {
		return nil, err
	}
	return func(r *http.Request) (*betterauth.Response, error) {
		claims, challenge, err := v.verifyRequest(r)
		if err != nil {
			return nil, err
		}
		if challenge != nil {
			return challenge, nil
		}
		res, herr := handler(r, claims)
		if herr != nil {
			if isInsufficientScopeError(herr) {
				return toChallengeResponse(herr, v.resource, v.challenge)
			}
			return nil, herr
		}
		return res, nil
	}, nil
}
