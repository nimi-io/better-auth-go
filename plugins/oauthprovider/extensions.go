package oauthprovider

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/extensions.ts and the extension types of
// types/index.ts.

// ClientMetadataResourceFetch performs a fetch for client metadata resources (CIMD
// documents, client JWKS). Redirects must not be followed.
type ClientMetadataResourceFetch func(req *http.Request) (*http.Response, error)

// ClientDiscovery resolves clients that are not registered in the database (for example
// Client ID Metadata Documents).
type ClientDiscovery struct {
	ID      string
	Matches func(clientID string) bool
	// Resolve returns the client for clientID (existing is the stored row when one exists).
	Resolve                     func(ctx *betterauth.EndpointContext, clientID string, existing *SchemaClient) (*SchemaClient, error)
	FetchClientMetadataResource ClientMetadataResourceFetch
	// DiscoveryMetadata is merged into the discovery documents.
	DiscoveryMetadata *jsonx.Object
}

// AuthenticatedClient is the result of ProviderAPI.AuthenticateClient.
type AuthenticatedClient struct {
	ClientID     string
	Client       *SchemaClient
	Method       string
	Confirmation *jsonx.Object
}

// ClientAuthenticationRequest configures ProviderAPI.AuthenticateClient.
type ClientAuthenticationRequest struct {
	Scopes []string
	// RequireCredentials defaults to true.
	RequireCredentials *bool
}

// TokenIssueParams are ProviderAPI.IssueTokens parameters (OAuthTokenIssueParams).
type TokenIssueParams struct {
	Client                  *SchemaClient
	Scopes                  []string
	User                    *betterauth.User
	ReferenceID             string
	SessionID               string
	Nonce                   string
	RefreshToken            *TokenRecord
	AuthTime                *time.Time
	VerificationValue       *VerificationValue
	Resources               []string
	OriginalResources       []string
	RequestedUserInfoClaims []string
	AccessTokenClaims       *jsonx.Object
	IDTokenClaims           *jsonx.Object
	TokenResponse           *jsonx.Object
	Confirmation            *jsonx.Object
}

// GrantHandlerInput is passed to extension grant handlers.
type GrantHandlerInput struct {
	Ctx       *betterauth.EndpointContext
	GrantType string
	Provider  *ProviderAPI
	opts      *resolved
}

// GrantHandler handles an extension grant type; it returns the token response.
type GrantHandler func(in GrantHandlerInput) (any, error)

// ExtensionGrant registers a grant handler.
type ExtensionGrant struct {
	GrantType string
	Handler   GrantHandler
}

// ClientAuthenticationInput is passed to client authentication strategies.
type ClientAuthenticationInput struct {
	Ctx              *betterauth.EndpointContext
	Assertion        string
	AssertionType    string
	ClientID         string
	ExpectedAudience string
}

// ClientAuthenticationResult is returned by a strategy.
type ClientAuthenticationResult struct {
	ClientID     string
	Confirmation *jsonx.Object
}

// ClientAuthenticationStrategy authenticates clients with custom assertion types.
type ClientAuthenticationStrategy struct {
	// Method is the token_endpoint_auth_method name.
	Method string
	// AssertionTypes default to [Method].
	AssertionTypes []string
	Authenticate   func(in ClientAuthenticationInput) (*ClientAuthenticationResult, error)
}

// MetadataExtensionInput is passed to Extension.Metadata.
type MetadataExtensionInput struct {
	Ctx *betterauth.EndpointContext
	// Type is "oauth-authorization-server" or "openid-configuration".
	Type     string
	Document *jsonx.Object
}

// ClaimExtensionInput is passed to claim extensions.
type ClaimExtensionInput struct {
	Ctx         *betterauth.EndpointContext
	User        *betterauth.User
	Client      *SchemaClient
	Scopes      []string
	GrantType   string
	ReferenceID string
	SessionID   string
	Resources   []string
	Metadata    *jsonx.Object
}

// UserInfoExtensionInput is passed to userinfo claim extensions.
type UserInfoExtensionInput struct {
	Ctx             *betterauth.EndpointContext
	User            *betterauth.User
	Scopes          []string
	JWT             *jsonx.Object
	Client          *SchemaClient
	RequestedClaims []string
}

// ExtensionClaims contribute claims.
type ExtensionClaims struct {
	AccessToken func(in ClaimExtensionInput) (*jsonx.Object, error)
	IDToken     func(in ClaimExtensionInput) (*jsonx.Object, error)
	UserInfo    func(in UserInfoExtensionInput) (*jsonx.Object, error)
}

// Extension extends the provider (OAuthProviderExtension).
type Extension struct {
	Grants               []ExtensionGrant
	ClientAuthentication []ClientAuthenticationStrategy
	Metadata             func(in MetadataExtensionInput) *jsonx.Object
	Claims               *ExtensionClaims
	ClientDiscovery      []*ClientDiscovery
}

var builtInConfidentialAuthMethods = []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}

func assertNonEmpty(name, value string) error {
	if strings.TrimSpace(value) != "" {
		return nil
	}
	return fmt.Errorf("OAuth Provider extension %s cannot be empty", name)
}

func assertAbsoluteURI(name, value string) error {
	if err := assertNonEmpty(name, value); err != nil {
		return err
	}
	if u, err := parseURL(value); err == nil && u.Scheme != "" {
		return nil
	}
	return fmt.Errorf("OAuth Provider extension %s must be an absolute URI: %s", name, value)
}

type extensionKeys struct{ grantTypes, authMethods, assertionTypes, discoveryIDs []string }

func collectExtensionKeys(e *Extension) (extensionKeys, error) {
	var k extensionKeys
	for _, g := range e.Grants {
		if err := assertAbsoluteURI("grant type", g.GrantType); err != nil {
			return k, err
		}
		k.grantTypes = append(k.grantTypes, g.GrantType)
	}
	for _, s := range e.ClientAuthentication {
		if err := assertNonEmpty("token_endpoint_auth_method", s.Method); err != nil {
			return k, err
		}
		if s.Method == "none" || contains(builtInConfidentialAuthMethods, s.Method) {
			return k, fmt.Errorf("OAuth Provider extension token_endpoint_auth_method is reserved: %s", s.Method)
		}
		k.authMethods = append(k.authMethods, s.Method)
		types := s.AssertionTypes
		if types == nil {
			types = []string{s.Method}
		}
		if len(types) == 0 {
			return k, fmt.Errorf("OAuth Provider extension client_assertion_type list cannot be empty for %s", s.Method)
		}
		for _, t := range types {
			if err := assertAbsoluteURI("client_assertion_type", t); err != nil {
				return k, err
			}
			if t == oauthcore.ClientAssertionType {
				return k, fmt.Errorf("OAuth Provider extension client_assertion_type is reserved: %s", t)
			}
			k.assertionTypes = append(k.assertionTypes, t)
		}
	}
	for _, d := range e.ClientDiscovery {
		if err := assertNonEmpty("client discovery id", d.ID); err != nil {
			return k, err
		}
		k.discoveryIDs = append(k.discoveryIDs, d.ID)
	}
	return k, nil
}

func assertDisjoint(label string, values []string) error {
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			return fmt.Errorf("OAuth Provider extensions register %s \"%s\" more than once. Extension contributions must be disjoint.", label, v)
		}
		seen[v] = true
	}
	return nil
}

// validateExtensions is validateOAuthProviderExtensions.
func validateExtensions(exts []*Extension) error {
	var all extensionKeys
	for _, e := range exts {
		k, err := collectExtensionKeys(e)
		if err != nil {
			return err
		}
		all.grantTypes = append(all.grantTypes, k.grantTypes...)
		all.authMethods = append(all.authMethods, k.authMethods...)
		all.assertionTypes = append(all.assertionTypes, k.assertionTypes...)
		all.discoveryIDs = append(all.discoveryIDs, k.discoveryIDs...)
	}
	if err := assertDisjoint("grant type", all.grantTypes); err != nil {
		return err
	}
	if err := assertDisjoint("token_endpoint_auth_method", all.authMethods); err != nil {
		return err
	}
	if err := assertDisjoint("client_assertion_type", all.assertionTypes); err != nil {
		return err
	}
	return assertDisjoint("client discovery id", all.discoveryIDs)
}

var extMu sync.RWMutex

func (o *resolved) extensions() []*Extension {
	extMu.RLock()
	defer extMu.RUnlock()
	return o.Extensions
}

func (o *resolved) clientDiscoveries() []*ClientDiscovery {
	var out []*ClientDiscovery
	for _, e := range o.extensions() {
		out = append(out, e.ClientDiscovery...)
	}
	return out
}

// ExtendOAuthProvider adds an extension to the oauth-provider plugin registered on ctx
// (extendOAuthProvider). It is used by companion plugins (device authorization, CIMD)
// from their Init.
func ExtendOAuthProvider(ctx *betterauth.AuthContext, ext *Extension) error {
	p := ctx.GetPlugin("oauth-provider")
	if p == nil {
		return errors.New("extendOAuthProvider requires the oauth-provider plugin.")
	}
	o, ok := p.Options.(*resolved)
	if !ok {
		return errors.New("extendOAuthProvider requires the oauth-provider plugin.")
	}
	extMu.Lock()
	defer extMu.Unlock()
	for _, e := range o.Extensions {
		if e == ext {
			return nil
		}
	}
	next := append(append([]*Extension(nil), o.Extensions...), ext)
	if err := validateExtensions(next); err != nil {
		return err
	}
	o.Extensions = next
	return nil
}

func (o *resolved) supportedGrantTypes() []string {
	out := append([]string(nil), o.GrantTypes...)
	for _, e := range o.extensions() {
		for _, g := range e.Grants {
			out = append(out, g.GrantType)
		}
	}
	return uniqueStrings(out)
}

func (o *resolved) extensionGrantHandler(grantType string) GrantHandler {
	for _, e := range o.extensions() {
		for _, g := range e.Grants {
			if g.GrantType == grantType {
				return g.Handler
			}
		}
	}
	return nil
}

func (o *resolved) extensionAuthMethods() []string {
	var out []string
	for _, e := range o.extensions() {
		for _, s := range e.ClientAuthentication {
			out = append(out, s.Method)
		}
	}
	return out
}

func (o *resolved) supportedAuthMethods(includeNone bool) []string {
	var out []string
	if includeNone {
		out = append(out, "none")
	}
	out = append(out, builtInConfidentialAuthMethods...)
	out = append(out, o.extensionAuthMethods()...)
	return uniqueStrings(out)
}

func (o *resolved) isExtensionAuthMethod(method string) bool {
	return method != "" && contains(o.extensionAuthMethods(), method)
}

func (o *resolved) extensionClientAuthStrategy(assertionType string) *ClientAuthenticationStrategy {
	if assertionType == oauthcore.ClientAssertionType {
		return nil
	}
	for _, e := range o.extensions() {
		for i := range e.ClientAuthentication {
			s := &e.ClientAuthentication[i]
			types := s.AssertionTypes
			if types == nil {
				types = []string{s.Method}
			}
			if contains(types, assertionType) {
				return s
			}
		}
	}
	return nil
}

// applyMetadataExtensions adds extension metadata keys that are not already present.
func (o *resolved) applyMetadataExtensions(ctx *betterauth.EndpointContext, typ string, doc *jsonx.Object) *jsonx.Object {
	next := doc.Clone()
	for _, e := range o.extensions() {
		if e.Metadata == nil {
			continue
		}
		c := e.Metadata(MetadataExtensionInput{Ctx: ctx, Type: typ, Document: doc})
		if c == nil {
			continue
		}
		for _, k := range c.Keys() {
			if !next.Has(k) {
				v, _ := c.Get(k)
				next.Set(k, v)
			}
		}
	}
	return next
}

func collectClaims(ctx *betterauth.EndpointContext, o *resolved, run func(e *Extension) (*jsonx.Object, error)) (*jsonx.Object, error) {
	claims := jsonx.NewObject()
	for _, e := range o.extensions() {
		c, err := run(e)
		if err != nil {
			return nil, err
		}
		if c == nil {
			continue
		}
		for _, k := range c.Keys() {
			if claims.Has(k) {
				if ctx != nil {
					ctx.Auth.Logger.Warn(fmt.Sprintf("oauth-provider: two extensions contributed the claim \"%s\"; keeping the first-registered value.", k))
				}
				continue
			}
			v, _ := c.Get(k)
			claims.Set(k, v)
		}
	}
	return claims, nil
}

func collectExtensionAccessTokenClaims(o *resolved, in ClaimExtensionInput) (*jsonx.Object, error) {
	return collectClaims(in.Ctx, o, func(e *Extension) (*jsonx.Object, error) {
		if e.Claims == nil || e.Claims.AccessToken == nil {
			return nil, nil
		}
		return e.Claims.AccessToken(in)
	})
}

func collectExtensionIDTokenClaims(o *resolved, in ClaimExtensionInput) (*jsonx.Object, error) {
	return collectClaims(in.Ctx, o, func(e *Extension) (*jsonx.Object, error) {
		if e.Claims == nil || e.Claims.IDToken == nil {
			return nil, nil
		}
		return e.Claims.IDToken(in)
	})
}

func collectExtensionUserInfoClaims(o *resolved, in UserInfoExtensionInput) (*jsonx.Object, error) {
	return collectClaims(in.Ctx, o, func(e *Extension) (*jsonx.Object, error) {
		if e.Claims == nil || e.Claims.UserInfo == nil {
			return nil, nil
		}
		return e.Claims.UserInfo(in)
	})
}

func (o *resolved) hasUserInfoClaimExtension() bool {
	for _, e := range o.extensions() {
		if e.Claims != nil && e.Claims.UserInfo != nil {
			return true
		}
	}
	return false
}
