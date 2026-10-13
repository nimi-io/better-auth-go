package scim

import (
	"context"
	"net/http"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Scope is a SCIM credential scope (SCIMScope).
type Scope string

// Supported scopes.
const (
	ScopeUsersRead   Scope = "scim.users.read"
	ScopeUsersWrite  Scope = "scim.users.write"
	ScopeGroupsRead  Scope = "scim.groups.read"
	ScopeGroupsWrite Scope = "scim.groups.write"
)

// AllScopes lists every scope (SCIM_SCOPES).
var AllScopes = []Scope{ScopeUsersRead, ScopeUsersWrite, ScopeGroupsRead, ScopeGroupsWrite}

// BearerCredential is SCIMBearerCredentialOptions: a static bearer token.
type BearerCredential struct {
	// Type is "bearer".
	Type  string
	ID    string
	Token string
	// Scopes defaults to every scope when nil.
	Scopes []Scope
	// ExpiresAt is optional; a non-nil zero time is an invalid Date.
	ExpiresAt *time.Time
}

// ConnectionOptions is SCIMConnectionOptions: a statically configured connection.
type ConnectionOptions struct {
	ID          string
	Credentials []BearerCredential
	// ProvisioningDomainID defaults to ID when empty.
	ProvisioningDomainID string
}

// Connection is SCIMConnection.
type Connection struct {
	ID                   string
	ProvisioningDomainID string
}

// Principal types.
const (
	PrincipalStaticBearer  = "static-bearer"
	PrincipalOAuthBearer   = "oauth-bearer"
	PrincipalManagedBearer = "managed-bearer"
)

// Principal is SCIMPrincipal: the authenticated SCIM caller.
type Principal struct {
	Type                 string
	ConnectionID         string
	ProvisioningDomainID string
	CredentialID         string
	Scopes               []Scope
	ExpiresAt            *time.Time
}

// BearerTokenVerificationInput is SCIMBearerTokenVerificationInput.
type BearerTokenVerificationInput struct {
	Token   string
	Method  string
	Path    string
	Headers http.Header
}

// VerifiedConnection is the `connection` of a resolved verification result. Empty fields
// are treated as missing.
type VerifiedConnection struct {
	ID                   string
	ProvisioningDomainID string
}

// BearerTokenVerification is SCIMBearerTokenVerification. Exactly one of ConnectionID (a
// configured connection) or Connection (an application-resolved connection) must be set.
type BearerTokenVerification struct {
	ConnectionID *string
	Connection   *VerifiedConnection
	CredentialID string
	Scopes       []Scope
	// ExpiresAt is optional; a non-nil zero time is treated as an invalid Date.
	ExpiresAt *time.Time
}

// FindOneUpdater is the database capability passed to bearer token verifiers.
type FindOneUpdater interface {
	FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error)
	Update(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (adapter.Record, error)
}

// BearerTokenVerificationContext is SCIMBearerTokenVerificationContext.
type BearerTokenVerificationContext struct {
	Context  context.Context
	Database FindOneUpdater
}

// AuthenticationOptions is SCIMAuthenticationOptions.
type AuthenticationOptions struct {
	// VerifyBearerToken resolves application-owned bearer tokens. Returning nil rejects the
	// token; returning an error produces a server error.
	VerifyBearerToken func(input BearerTokenVerificationInput, ctx BearerTokenVerificationContext) (*BearerTokenVerification, error)
}

// ManagedConnectionOptions is SCIMManagedConnectionOptions.
type ManagedConnectionOptions struct {
	CredentialHashSecret string
	// MaxActiveCredentials defaults to 5 (1..100).
	MaxActiveCredentials *int
	// LastUsedWriteIntervalSeconds defaults to 300.
	LastUsedWriteIntervalSeconds *int
}

// IdentitySource is SCIMIdentitySource.
type IdentitySource struct {
	ID                   string
	ConnectionID         string
	ProvisioningDomainID string
	Active               bool
}

// IdentityResolution is SCIMIdentityResolution: Action "create" or "link" (with UserID
// and Profile "manage" | "preserve").
type IdentityResolution struct {
	Action  string
	UserID  string
	Profile string
}

// CanonicalUser is SCIMCanonicalUser (the normalized resource given to resolvers).
type CanonicalUser struct {
	ExternalID   string
	UserName     string
	PrimaryEmail string
	DisplayName  string
	Active       bool
	// Resource is the complete canonical resource in upstream key order: the canonical
	// attributes (schemas, name, emails, ...), then externalId, userName, primaryEmail,
	// displayName and active.
	Resource *jsonx.Object
}

// IdentityResolutionInput is SCIMIdentityResolutionInput.
type IdentityResolutionInput struct {
	ConnectionID         string
	ProvisioningDomainID string
	Resource             CanonicalUser
}

// DatabaseContext carries the (possibly transactional) database for callbacks.
type DatabaseContext struct {
	// Context carries the active transaction; pass it to Database calls.
	Context  context.Context
	Database adapter.Adapter
}

// IdentityState is SCIMIdentityState.
type IdentityState struct {
	UserID          string
	Active          bool
	ProfileSourceID string
	Sources         []IdentitySource
}

// Identity is SCIMIdentity.
type Identity struct {
	ResolveUser   func(input IdentityResolutionInput, ctx DatabaseContext) (*IdentityResolution, error)
	ReconcileUser func(state IdentityState, ctx DatabaseContext) error
}

// AuthorizationSource is SCIMGroupAuthorizationSource.
type AuthorizationSource struct {
	Type        string // "group"
	ID          string
	ExternalID  string
	DisplayName string
}

// ProjectedRoleGrant is SCIMProjectedRoleGrant.
type ProjectedRoleGrant struct {
	Source AuthorizationSource
	Role   string
}

// ProjectedUserState is SCIMProjectedUserState.
type ProjectedUserState struct {
	ProvisioningDomainID string
	UserID               string
	Active               bool
	Sources              []IdentitySource
	Grants               []ProjectedRoleGrant
}

// RoleMappingInput is SCIMRoleMappingInput.
type RoleMappingInput struct {
	ConnectionID         string
	ProvisioningDomainID string
	SCIMUserID           string
	UserID               string
	Source               AuthorizationSource
}

// RoleExistenceInput is SCIMRoleExistenceInput.
type RoleExistenceInput struct {
	ConnectionID         string
	ProvisioningDomainID string
	Role                 string
}

// RoleProjection is SCIMRoleProjection.
type RoleProjection struct {
	Map    func(input RoleMappingInput, ctx DatabaseContext) ([]string, error)
	Exists func(input RoleExistenceInput, ctx DatabaseContext) (bool, error)
}

// Projection is SCIMProjection.
type Projection struct {
	Roles         *RoleProjection
	ReconcileUser func(state ProjectedUserState, ctx DatabaseContext) error
}

// CompatibilityOptions is SCIMCompatibilityOptions.
type CompatibilityOptions struct {
	MicrosoftEntra *MicrosoftEntraCompatibilityOptions
}

// MicrosoftEntraCompatibilityOptions is SCIMMicrosoftEntraCompatibilityOptions.
type MicrosoftEntraCompatibilityOptions struct {
	AcceptLegacyGroupSchema bool
}

// Options are the SCIM plugin options (SCIMOptions).
type Options struct {
	Connections        []ConnectionOptions
	Authentication     *AuthenticationOptions
	ManagedConnections *ManagedConnectionOptions
	Identity           *Identity
	Projection         *Projection
	Compatibility      *CompatibilityOptions
}
