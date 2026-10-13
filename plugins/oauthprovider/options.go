package oauthprovider

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of packages/oauth-provider/src/types/index.ts (OAuthOptions) and the option
// defaults / validation of oauth.ts.

// DefaultOAuthScopes are the scopes used when Options.Scopes is nil (DEFAULT_OAUTH_SCOPES).
var DefaultOAuthScopes = []string{"openid", "profile", "email", "offline_access"}

// Store token types (StoreTokenType).
const (
	TokenTypeAccessToken       = "access_token"
	TokenTypeRefreshToken      = "refresh_token"
	TokenTypeAuthorizationCode = "authorization_code"
)

// ResourceInput declares a protected resource (OAuthResourceInput). Pointer fields are
// optional; nil means "not set".
type ResourceInput struct {
	Identifier                    string
	Name                          *string
	AccessTokenTTL                *int
	RefreshTokenTTL               *int
	SigningAlgorithm              *string
	SigningKeyID                  *string
	AllowedScopes                 []string
	CustomClaims                  *jsonx.Object
	DPoPBoundAccessTokensRequired *bool
	Disabled                      *bool
	Metadata                      *jsonx.Object
}

// PrivilegeContext is passed to ClientPrivileges / ResourcePrivileges.
type PrivilegeContext struct {
	Ctx     *betterauth.EndpointContext
	Headers http.Header
	// Action is the attempted action ("create", "read", "update", "delete", "list",
	// "rotate", "configure-client-credentials-scopes", "link", "unlink").
	Action  string
	User    *betterauth.User
	Session *betterauth.Session
	// ResourceID is set for resource actions.
	ResourceID string
}

// UserSessionContext is passed to clientReference and the redirect callbacks.
type UserSessionContext struct {
	Ctx     *betterauth.EndpointContext
	Headers http.Header
	User    *betterauth.User
	Session *betterauth.Session
	Scopes  []string
}

// InitialAccessTokenContext is passed to ValidateInitialAccessToken.
type InitialAccessTokenContext struct {
	Ctx                *betterauth.EndpointContext
	InitialAccessToken string
	Headers            http.Header
	// ClientMetadata is the validated registration request body.
	ClientMetadata map[string]any
}

// InitialAccessTokenAuthorization is returned by ValidateInitialAccessToken.
type InitialAccessTokenAuthorization struct {
	ReferenceID string
}

// SignupOptions configures the account creation page (signup).
type SignupOptions struct {
	Page string
	// ShouldRedirect returns true to redirect to Page, or a non-empty page to redirect there.
	ShouldRedirect func(c UserSessionContext) (redirect bool, page string, err error)
}

// SelectAccountOptions configures account selection (selectAccount).
type SelectAccountOptions struct {
	Page           string
	ShouldRedirect func(c UserSessionContext) (bool, error)
}

// PostLoginOptions configures the post-login step (postLogin).
type PostLoginOptions struct {
	Page               string
	ConsentReferenceID func(c UserSessionContext) (string, error)
	ShouldRedirect     func(c UserSessionContext) (bool, error)
}

// DecodedRefreshToken is returned by FormatRefreshToken.Decrypt.
type DecodedRefreshToken struct {
	SessionID string
	Token     string
}

// FormatRefreshTokenOptions customise the refresh token format.
type FormatRefreshTokenOptions struct {
	Encrypt func(token, sessionID string) (string, error)
	Decrypt func(token string) (DecodedRefreshToken, error)
}

// StoreClientSecretOptions selects how client secrets are stored. Mode is "hashed"
// (SHA-256, base64url), "encrypted" (symmetricEncrypt with the auth secret), or "" with
// custom functions: Hash (+ optional Verify) or Encrypt + Decrypt.
type StoreClientSecretOptions struct {
	Mode    string
	Hash    func(secret string) (string, error)
	Verify  func(secret, stored string) (bool, error)
	Encrypt func(secret string) (string, error)
	Decrypt func(stored string) (string, error)
}

// StoreTokensOptions selects how tokens are stored: nil Hash means "hashed".
type StoreTokensOptions struct {
	Hash func(token, tokenType string) (string, error)
}

// UserInfoClaimsInput is passed to CustomUserInfoClaims.
type UserInfoClaimsInput struct {
	Ctx             *betterauth.EndpointContext
	User            *betterauth.User
	Scopes          []string
	JWT             *jsonx.Object
	RequestedClaims []string
}

// IDTokenClaimsInput is passed to CustomIDTokenClaims.
type IDTokenClaimsInput struct {
	Ctx      *betterauth.EndpointContext
	User     *betterauth.User
	Scopes   []string
	Metadata *jsonx.Object
}

// AccessTokenClaimsInput is passed to CustomAccessTokenClaims.
type AccessTokenClaimsInput struct {
	Ctx         *betterauth.EndpointContext
	User        *betterauth.User
	ReferenceID string
	Scopes      []string
	Resources   []string
	Metadata    *jsonx.Object
}

// TokenResponseFieldsInput is passed to CustomTokenResponseFields.
type TokenResponseFieldsInput struct {
	Ctx               *betterauth.EndpointContext
	GrantType         string
	User              *betterauth.User
	Scopes            []string
	Metadata          *jsonx.Object
	VerificationValue *VerificationValue
}

// AdvertisedMetadata overrides discovery values.
type AdvertisedMetadata struct {
	ScopesSupported []string
	ClaimsSupported []string
}

// PrefixOptions add prefixes to issued credentials.
type PrefixOptions struct {
	OpaqueAccessToken string
	RefreshToken      string
	ClientSecret      string
}

// RateLimitRule is a rate limit rule; Disabled turns the rule off (false upstream).
type RateLimitRule struct {
	Window   int
	Max      int
	Disabled bool
}

// RateLimitOptions configure endpoint rate limits (nil rule = default).
type RateLimitOptions struct {
	Token      *RateLimitRule
	Authorize  *RateLimitRule
	Introspect *RateLimitRule
	Revoke     *RateLimitRule
	Register   *RateLimitRule
	UserInfo   *RateLimitRule
}

// RequestURIInput is passed to RequestURIResolver.
type RequestURIInput struct {
	RequestURI string
	ClientID   string
	Ctx        *betterauth.EndpointContext
}

// DPoPOptions configure DPoP proof checks.
type DPoPOptions struct {
	ProofMaxAgeSeconds int
	SigningAlgorithms  []string
}

// SchemaOptions rename the plugin models and fields (schema option). Keys are model keys:
// oauthClient, oauthResource, oauthClientResource, oauthRefreshToken, oauthAccessToken,
// oauthConsent, oauthClientAssertion.
type SchemaOptions map[string]db.ModelOptions

// Options configures the OAuth 2.1 / OpenID Connect provider (OAuthOptions).
type Options struct {
	Schema SchemaOptions
	// Scopes supported by the server (default DefaultOAuthScopes).
	Scopes []string
	// ValidateRedirectURI overrides redirect URI matching.
	ValidateRedirectURI func(redirectURI string, registered []string, defaultResult bool) (bool, error)
	// Resources seeds protected resources (strings become {Identifier}).
	Resources []ResourceInput
	// ResourceSeedMode is "insertOnly" (default), "merge" or "overwrite".
	ResourceSeedMode string
	// CachedResources lists resource identifiers cached in memory.
	CachedResources []string
	// EnforcePerClientResources defaults to true.
	EnforcePerClientResources          *bool
	ClientRegistrationDefaultResources []string
	ClientRegistrationAllowedResources []string
	IdentifierValidator                func(identifier string) (bool, error)
	ResourcePrivileges                 func(c PrivilegeContext) (bool, error)
	// CachedTrustedClients lists client ids cached in memory.
	CachedTrustedClients []string
	// Token lifetimes in seconds (0 = default).
	AccessTokenExpiresIn    int
	M2MAccessTokenExpiresIn int
	IDTokenExpiresIn        int
	RefreshTokenExpiresIn   int
	// RefreshTokenReuseInterval in seconds (default 0 = strict rotation).
	RefreshTokenReuseInterval int
	CodeExpiresIn             int
	// ScopeExpirations maps scopes to lifetimes (seconds as int/float, time strings, or
	// time.Time).
	ScopeExpirations                       map[string]any
	AssertionMaxLifetime                   int
	AllowPublicClientPrelogin              bool
	AllowUnauthenticatedClientRegistration bool
	AllowDynamicClientRegistration         bool
	// ValidateInitialAccessToken authorizes registration bearer tokens; returning nil
	// rejects the token.
	ValidateInitialAccessToken      func(c InitialAccessTokenContext) (*InitialAccessTokenAuthorization, error)
	Extensions                      []*Extension
	ClientRegistrationDefaultScopes []string
	ClientRegistrationAllowedScopes []string
	ClientRegistrationRequirePKCE   *bool
	// ClientRegistrationClientSecretExpiration: seconds, time string or time.Time.
	ClientRegistrationClientSecretExpiration any
	ClientReference                          func(c UserSessionContext) (string, error)
	ClientPrivileges                         func(c PrivilegeContext) (bool, error)
	// GrantTypes defaults to authorization_code, client_credentials, refresh_token.
	GrantTypes    []string
	LoginPage     string
	ConsentPage   string
	Signup        *SignupOptions
	SelectAccount *SelectAccountOptions
	PostLogin     *PostLoginOptions
	// FormatRefreshToken customises the refresh token string.
	FormatRefreshToken *FormatRefreshTokenOptions
	// StoreClientSecret defaults to "hashed" ("encrypted" with DisableJwtPlugin).
	StoreClientSecret *StoreClientSecretOptions
	// StoreTokens defaults to "hashed".
	StoreTokens               *StoreTokensOptions
	CustomUserInfoClaims      func(in UserInfoClaimsInput) (*jsonx.Object, error)
	CustomIDTokenClaims       func(in IDTokenClaimsInput) (*jsonx.Object, error)
	CustomAccessTokenClaims   func(in AccessTokenClaimsInput) (*jsonx.Object, error)
	CustomTokenResponseFields func(in TokenResponseFieldsInput) (*jsonx.Object, error)
	AdvertisedMetadata        *AdvertisedMetadata
	Prefix                    *PrefixOptions
	GenerateClientID          func() string
	GenerateClientSecret      func() string
	GenerateOpaqueAccessToken func() (string, error)
	GenerateRefreshToken      func() (string, error)
	DisableJwtPlugin          bool
	RateLimit                 *RateLimitOptions
	PairwiseSecret            string
	// RequestURIResolver resolves request_uri parameters (nil result = invalid).
	RequestURIResolver func(in RequestURIInput) (*jsonx.Object, error)
	DPoP               *DPoPOptions
}

// resolved holds the options with defaults applied (opts upstream).
type resolved struct {
	Options
	// Claims are the supported claims derived from scopes.
	Claims []string
	// extensions may be extended at init (extendOAuthProvider).
	cachedTrusted   map[string]bool
	cachedResources map[string]bool
	trustedCache    trustedClientCache
	jwksCache       clientJwksCache
	resourceCache   resourceCache
	seed            seedState
}

func (o *resolved) storeClientSecretMode() *StoreClientSecretOptions {
	if o.StoreClientSecret != nil {
		return o.StoreClientSecret
	}
	if o.DisableJwtPlugin {
		return &StoreClientSecretOptions{Mode: "encrypted"}
	}
	return &StoreClientSecretOptions{Mode: "hashed"}
}

func (o *resolved) prefix() PrefixOptions {
	if o.Prefix == nil {
		return PrefixOptions{}
	}
	return *o.Prefix
}

func intOr(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func (o *resolved) codeExpiresIn() int        { return intOr(o.CodeExpiresIn, 600) }
func (o *resolved) accessTokenExpiresIn() int { return intOr(o.AccessTokenExpiresIn, 3600) }
func (o *resolved) m2mAccessTokenExpiresIn() int {
	return intOr(o.M2MAccessTokenExpiresIn, 3600)
}
func (o *resolved) idTokenExpiresIn() int      { return intOr(o.IDTokenExpiresIn, 36000) }
func (o *resolved) refreshTokenExpiresIn() int { return intOr(o.RefreshTokenExpiresIn, 2592000) }
func (o *resolved) assertionMaxLifetime() int  { return intOr(o.AssertionMaxLifetime, 300) }

func (o *resolved) hasScope(s string) bool {
	for _, x := range o.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

func (o *resolved) modelName(key string) string {
	if m, ok := o.Schema[key]; ok && m.ModelName != "" {
		return m.ModelName
	}
	return key
}

// standard claims in declaration order with their scope.
var standardClaimNames = []string{"name", "picture", "given_name", "family_name", "email", "email_verified"}

var standardClaimScope = map[string]string{
	"name": "profile", "picture": "profile", "given_name": "profile", "family_name": "profile",
	"email": "email", "email_verified": "email",
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// resolveOptions applies defaults and validates options (the oauthProvider() body).
func resolveOptions(options Options) (*resolved, error) {
	allowed := options.ClientRegistrationAllowedScopes
	if options.ClientRegistrationDefaultScopes != nil {
		allowed = uniqueStrings(append(append([]string(nil), allowed...), options.ClientRegistrationDefaultScopes...))
	}
	base := options.Scopes
	if base == nil {
		base = DefaultOAuthScopes
	}
	var scopes []string
	for _, s := range uniqueStrings(base) {
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	if scopes == nil {
		scopes = []string{}
	}
	scopeSet := map[string]bool{}
	for _, s := range scopes {
		scopeSet[s] = true
	}
	for _, s := range allowed {
		if !scopeSet[s] {
			return nil, fmt.Errorf("clientRegistrationAllowedScope %s not found in scopes", s)
		}
	}
	if options.AdvertisedMetadata != nil {
		for _, s := range options.AdvertisedMetadata.ScopesSupported {
			if !scopeSet[s] {
				return nil, fmt.Errorf("advertisedMetadata.scopes_supported %s not found in scopes", s)
			}
		}
	}
	configured := map[string]bool{}
	for _, r := range options.Resources {
		configured[r.Identifier] = true
	}
	for _, pair := range []struct {
		name string
		ids  []string
	}{{"clientRegistrationDefaultResources", options.ClientRegistrationDefaultResources},
		{"clientRegistrationAllowedResources", options.ClientRegistrationAllowedResources}} {
		for _, id := range pair.ids {
			if !configured[id] {
				return nil, fmt.Errorf("%s resource %s not found in resources", pair.name, id)
			}
		}
	}
	claims := []string{"sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp"}
	for _, name := range standardClaimNames {
		if scopeSet[standardClaimScope[name]] {
			claims = append(claims, name)
		}
	}
	o := &resolved{Options: options}
	o.Scopes = scopes
	o.Claims = uniqueStrings(claims)
	o.ClientRegistrationAllowedScopes = allowed
	if o.GrantTypes == nil {
		o.GrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	o.cachedTrusted = map[string]bool{}
	for _, c := range o.CachedTrustedClients {
		o.cachedTrusted[c] = true
	}
	o.cachedResources = map[string]bool{}
	for _, c := range o.CachedResources {
		o.cachedResources[c] = true
	}
	if err := validateExtensions(o.Extensions); err != nil {
		return nil, err
	}
	if o.PairwiseSecret != "" && len([]rune(o.PairwiseSecret)) < 32 {
		return nil, fmt.Errorf("pairwiseSecret must be at least 32 characters long for adequate HMAC-SHA256 security")
	}
	if contains(o.GrantTypes, "refresh_token") && !contains(o.GrantTypes, "authorization_code") {
		return nil, fmt.Errorf("refresh_token grant requires authorization_code grant")
	}
	sc := o.StoreClientSecret
	if o.DisableJwtPlugin && sc != nil && (sc.Mode == "hashed" || sc.Hash != nil) {
		return nil, fmt.Errorf("unable to store hashed secrets because id tokens will be signed with secret")
	}
	if !o.DisableJwtPlugin && sc != nil && (sc.Mode == "encrypted" || sc.Encrypt != nil || sc.Decrypt != nil) {
		return nil, fmt.Errorf("encryption method not recommended, please use 'hashed' or the 'hash' function")
	}
	return o, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func trimSpaces(s string) string { return strings.TrimSpace(s) }
