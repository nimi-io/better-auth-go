package sso

import (
	"context"
	"encoding/json"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// OIDCMapping maps provider claims to user fields (OIDCMapping).
type OIDCMapping struct {
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	Image         string            `json:"image,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}

// SAMLMapping maps SAML attributes to user fields (SAMLMapping).
type SAMLMapping struct {
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	FirstName     string            `json:"firstName,omitempty"`
	LastName      string            `json:"lastName,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}

// OIDCConfig is a provider's OpenID Connect configuration as stored in the oidcConfig
// column (JSON, same keys as upstream).
type OIDCConfig struct {
	Issuer                string `json:"issuer"`
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret,omitempty"`
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
	// TokenEndpointAuthentication is client_secret_basic, client_secret_post or
	// private_key_jwt.
	TokenEndpointAuthentication string       `json:"tokenEndpointAuthentication,omitempty"`
	PrivateKeyID                string       `json:"privateKeyId,omitempty"`
	PrivateKeyAlgorithm         string       `json:"privateKeyAlgorithm,omitempty"`
	JwksEndpoint                string       `json:"jwksEndpoint,omitempty"`
	PKCE                        bool         `json:"pkce"`
	DiscoveryEndpoint           string       `json:"discoveryEndpoint"`
	Mapping                     *OIDCMapping `json:"mapping,omitempty"`
	Scopes                      []string     `json:"scopes,omitempty"`
	UserInfoEndpoint            string       `json:"userInfoEndpoint,omitempty"`
	OverrideUserInfo            bool         `json:"overrideUserInfo"`
	SkipDiscovery               *bool        `json:"skipDiscovery,omitempty"`
	AllowIdpInitiated           bool         `json:"allowIdpInitiated,omitempty"`
}

// StringList is a value that is either a single string or a list of strings (cert).
type StringList struct {
	Values []string
	// IsList reports that the JSON value was an array.
	IsList bool
}

// Cert returns a single-certificate StringList.
func Cert(pem string) *StringList { return &StringList{Values: []string{pem}} }

// Certs returns a certificate-list StringList.
func Certs(pems ...string) *StringList { return &StringList{Values: pems, IsList: true} }

// MarshalJSON implements json.Marshaler.
func (s StringList) MarshalJSON() ([]byte, error) {
	if s.IsList {
		v := s.Values
		if v == nil {
			v = []string{}
		}
		return json.Marshal(v)
	}
	if len(s.Values) == 0 {
		return []byte(`""`), nil
	}
	return json.Marshal(s.Values[0])
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = StringList{Values: []string{one}}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = StringList{Values: many, IsList: true}
	return nil
}

// SAMLService is a metadata endpoint ({ Binding, Location }).
type SAMLService struct {
	Binding  string `json:"Binding"`
	Location string `json:"Location"`
}

// SAMLIdentityProviderMetadata configures the identity provider (idpMetadata). Either
// Metadata (IdP metadata XML) or EntityID must be set.
type SAMLIdentityProviderMetadata struct {
	Cert                 *StringList   `json:"cert,omitempty"`
	PrivateKey           string        `json:"privateKey,omitempty"`
	PrivateKeyPass       string        `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted *bool         `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string        `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string        `json:"encPrivateKeyPass,omitempty"`
	SingleSignOnService  []SAMLService `json:"singleSignOnService,omitempty"`
	SingleLogoutService  []SAMLService `json:"singleLogoutService,omitempty"`
	Metadata             string        `json:"metadata,omitempty"`
	EntityID             string        `json:"entityID,omitempty"`
}

// SAMLServiceProviderMetadata configures the service provider (spMetadata).
type SAMLServiceProviderMetadata struct {
	Metadata             string `json:"metadata,omitempty"`
	EntityID             string `json:"entityID,omitempty"`
	Binding              string `json:"binding,omitempty"`
	PrivateKey           string `json:"privateKey,omitempty"`
	PrivateKeyPass       string `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted *bool  `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string `json:"encPrivateKeyPass,omitempty"`
}

// SAMLConfig is a provider's SAML configuration as stored in the samlConfig column.
type SAMLConfig struct {
	Issuer                  string                        `json:"issuer"`
	EntryPoint              string                        `json:"entryPoint,omitempty"`
	Cert                    *StringList                   `json:"cert,omitempty"`
	Audience                string                        `json:"audience,omitempty"`
	CallbackURL             string                        `json:"callbackUrl,omitempty"`
	IdpInitiatedCallbackURL string                        `json:"idpInitiatedCallbackUrl,omitempty"`
	IdpMetadata             *SAMLIdentityProviderMetadata `json:"idpMetadata,omitempty"`
	SpMetadata              *SAMLServiceProviderMetadata  `json:"spMetadata,omitempty"`
	WantAssertionsSigned    *bool                         `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned     *bool                         `json:"authnRequestsSigned,omitempty"`
	SignatureAlgorithm      string                        `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm         string                        `json:"digestAlgorithm,omitempty"`
	IdentifierFormat        string                        `json:"identifierFormat,omitempty"`
	PrivateKey              string                        `json:"privateKey,omitempty"`
	Mapping                 *SAMLMapping                  `json:"mapping,omitempty"`
}

func (c *SAMLConfig) idp() *SAMLIdentityProviderMetadata {
	if c.IdpMetadata == nil {
		return &SAMLIdentityProviderMetadata{}
	}
	return c.IdpMetadata
}

func (c *SAMLConfig) sp() *SAMLServiceProviderMetadata {
	if c.SpMetadata == nil {
		return &SAMLServiceProviderMetadata{}
	}
	return c.SpMetadata
}

func isTrue(b *bool) bool { return b != nil && *b }

// SSOProvider is a resolved provider (a database row or a DefaultSSO entry).
type SSOProvider struct {
	// ID is the database id ("" for configured DefaultSSO providers).
	ID             string
	Issuer         string
	OIDCConfig     *OIDCConfig
	SAMLConfig     *SAMLConfig
	UserID         string
	ProviderID     string
	OrganizationID string
	Domain         string
	// DomainVerified is set when domain verification is enabled.
	DomainVerified *bool
	// Record is the raw database row (additional fields included).
	Record adapter.Record

	oidcRawValue          any
	samlRawValue          any
	orgPresent            bool
	orgNull               bool
	domainVerifiedPresent bool
}

// ProviderReference pins an authentication to the provider configuration it started with
// (SSOProviderReference).
type ProviderReference struct {
	ProviderID string `json:"providerId"`
	Source     struct {
		Type     string `json:"type"`
		RecordID string `json:"recordId,omitempty"`
	} `json:"source"`
	AuthenticationConfigurationFingerprint string `json:"authenticationConfigurationFingerprint"`
}

// ProviderUserProfile is the normalized provider user (SSOProviderUserProfile).
type ProviderUserProfile struct {
	Email         string
	EmailVerified bool
	Name          string
	Image         string
	// Extra holds additional mapped attributes.
	Extra map[string]any
}

// AccountKey identifies the provider account.
type AccountKey struct {
	Issuer    string
	AccountID string
}

// UserResolutionInput is passed to Options.ResolveUser (SSOUserResolutionInput). Protocol
// is "oidc" or "saml".
type UserResolutionInput struct {
	Protocol          string
	ProviderID        string
	AccountKey        AccountKey
	ProviderUser      ProviderUserProfile
	ProviderReference ProviderReference
	// ProviderClaims / VerifiedIDTokenClaims are set for OIDC.
	ProviderClaims        map[string]any
	VerifiedIDTokenClaims map[string]any
	// ProviderAttributes are set for SAML (string or []string values).
	ProviderAttributes map[string]any
}

// UserResolutionContext gives ResolveUser access to the active database transaction:
// use Adapter with the passed context.
type UserResolutionContext struct {
	Adapter adapter.Adapter
}

// UserResolution is the decision of ResolveUser (SSOUserResolution). Action is "continue",
// "link" (UserID, Profile "preserve" | "update") or "reject" (Code, Message).
type UserResolution struct {
	Action  string
	UserID  string
	Profile string
	Code    string
	Message *string
}

// ProviderMutationGuardInput is passed to Options.GuardProviderMutation. Action is
// "update" or "delete".
type ProviderMutationGuardInput struct {
	Action                         string
	IsAuthenticationBoundaryChange bool
	Provider                       struct {
		ID             string
		ProviderID     string
		OrganizationID *string
	}
	ProviderReference ProviderReference
}

// ProviderMutationGuardContext gives the guard access to the active transaction.
type ProviderMutationGuardContext struct {
	Adapter adapter.Adapter
}

// ProvisionUserData is passed to ProvisionUser and OrganizationProvisioning.GetRole.
type ProvisionUserData struct {
	User     *betterauth.User
	UserInfo map[string]any
	Token    *oauth2.Tokens
	Provider *SSOProvider
}

// OrganizationProvisioning configures automatic organization membership.
type OrganizationProvisioning struct {
	Disabled bool
	// DefaultRole defaults to "member".
	DefaultRole string
	GetRole     func(ctx context.Context, data ProvisionUserData) (string, error)
}

// PrivateKey is a private_key_jwt signing key (JWK JSON or PKCS#8 PEM).
type PrivateKey struct {
	PrivateKeyJWK map[string]any
	PrivateKeyPEM string
	Kid           string
	Algorithm     string
}

// DefaultSSOProvider is a provider configured in code (defaultSSO).
type DefaultSSOProvider struct {
	Domain     string
	ProviderID string
	SAMLConfig *SAMLConfig
	OIDCConfig *OIDCConfig
	PrivateKey *PrivateKey
}

// ResolvePrivateKeyParams are passed to ResolvePrivateKey.
type ResolvePrivateKeyParams struct {
	ProviderID string
	KeyID      string
	Issuer     string
}

// FieldNames rename the ssoProvider columns.
type FieldNames struct {
	Issuer         string
	OIDCConfig     string
	SAMLConfig     string
	UserID         string
	ProviderID     string
	OrganizationID string
	Domain         string
	DomainVerified string
}

// SchemaOptions customise the ssoProvider table.
type SchemaOptions struct {
	ModelName        string
	Fields           FieldNames
	AdditionalFields []db.Field
}

// DomainVerificationOptions enable DNS TXT domain verification.
type DomainVerificationOptions struct {
	Enabled bool
	// TokenPrefix defaults to "better-auth-token".
	TokenPrefix string
}

// DeprecatedAlgorithmBehavior is "reject", "warn" (default) or "allow".
type DeprecatedAlgorithmBehavior = string

// AlgorithmValidationOptions restrict SAML algorithms (AlgorithmValidationOptions).
type AlgorithmValidationOptions struct {
	OnDeprecated                    DeprecatedAlgorithmBehavior
	AllowedSignatureAlgorithms      []string
	AllowedDigestAlgorithms         []string
	AllowedKeyEncryptionAlgorithms  []string
	AllowedDataEncryptionAlgorithms []string
}

// SAMLOptions configure SAML handling.
type SAMLOptions struct {
	// EnableInResponseToValidation defaults to true.
	EnableInResponseToValidation *bool
	AllowIdpInitiated            bool
	// RequestTTL defaults to 5 minutes (milliseconds).
	RequestTTL int64
	// ClockSkew in milliseconds (default 5 minutes for timestamp validation).
	ClockSkew                *int64
	RequireTimestamps        bool
	Algorithms               *AlgorithmValidationOptions
	MaxResponseSize          int
	MaxMetadataSize          int
	EnableSingleLogout       bool
	LogoutRequestTTL         int64
	WantLogoutRequestSigned  bool
	WantLogoutResponseSigned bool
	IdpInitiatedCallbackURL  string
}

// Options configure the sso plugin (SSOOptions).
type Options struct {
	// ResolveUser decides how an authenticated SSO identity maps to a user. It runs inside
	// the account-linking transaction; use rc.Adapter with ctx.
	ResolveUser func(ctx context.Context, in UserResolutionInput, rc UserResolutionContext) (UserResolution, error)
	// GuardProviderMutation may veto provider updates and deletions by returning an error.
	GuardProviderMutation func(ctx context.Context, in ProviderMutationGuardInput, gc ProviderMutationGuardContext) error
	// ProvisionUser runs after sign-up (or every sign-in with ProvisionUserOnEveryLogin).
	ProvisionUser             func(ctx context.Context, data ProvisionUserData) error
	ProvisionUserOnEveryLogin bool
	OrganizationProvisioning  *OrganizationProvisioning
	DefaultSSO                []DefaultSSOProvider
	DefaultOverrideUserInfo   bool
	DisableImplicitSignUp     bool
	ModelName                 string
	Fields                    FieldNames
	Schema                    *SchemaOptions
	// ProvidersLimit caps providers per user (default 10; 0 disables registration).
	ProvidersLimit *int
	// ProvidersLimitFunc computes the limit per user (wins over ProvidersLimit).
	ProvidersLimitFunc func(ctx context.Context, user *betterauth.User) (int, error)
	TrustEmailVerified bool
	DomainVerification *DomainVerificationOptions
	// RedirectURI overrides the OIDC callback URL (absolute, or a path under the base URL).
	RedirectURI       string
	ResolvePrivateKey func(ctx context.Context, p ResolvePrivateKeyParams) (*PrivateKey, error)
	SAML              *SAMLOptions
}

func (o *Options) saml() *SAMLOptions {
	if o == nil || o.SAML == nil {
		return &SAMLOptions{}
	}
	return o.SAML
}

func (o *Options) domainVerificationEnabled() bool {
	return o != nil && o.DomainVerification != nil && o.DomainVerification.Enabled
}

func (o *Options) additionalFields() []db.Field {
	if o == nil || o.Schema == nil {
		return nil
	}
	return o.Schema.AdditionalFields
}
