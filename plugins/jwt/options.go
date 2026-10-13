package jwt

import (
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Options configure the jwt plugin (JwtOptions).
type Options struct {
	// SessionCookieCache signs the session cookie cache (session.cookieCache.strategy
	// "jwt") with the plugin's JWKS keys instead of the secret.
	SessionCookieCache bool
	JWKS               *JWKSOptions
	JWT                *JWTOptions
	// DisableSettingJwtHeader disables the set-auth-jwt header on /get-session.
	DisableSettingJwtHeader bool
	// Schema renames the jwks table and its columns.
	Schema *SchemaOptions
	// Adapter overrides how keys are stored.
	Adapter *AdapterOptions
}

// JWKSOptions configure key management.
type JWKSOptions struct {
	// RemoteURL disables the local /jwks endpoint (keys are served elsewhere).
	RemoteURL string
	// KeyPairConfig is the primary key type (default EdDSA / Ed25519).
	KeyPairConfig *JWKOptions
	// KeyPairConfigs are additional algorithms minted lazily when a signing call pins
	// them with SigningAlgorithm.
	KeyPairConfigs []JWKOptions
	// DisablePrivateKeyEncryption stores private keys in plain text.
	DisablePrivateKeyEncryption bool
	// RotationInterval sets expiresAt on new keys; expired keys are replaced on the
	// next signing call.
	RotationInterval time.Duration
	// GracePeriod keeps expired keys in /jwks (default 30 days).
	GracePeriod *time.Duration
	// JWKSPath is the JWKS endpoint path (default "/jwks").
	JWKSPath string
}

// JWKOptions select a key algorithm (JWKOptions).
type JWKOptions struct {
	// Alg is "EdDSA", "ES256", "ES512", "PS256" or "RS256".
	Alg string
	// Crv is the EdDSA curve ("Ed25519").
	Crv string
	// ModulusLength is the RSA key size (default 2048).
	ModulusLength int
}

// JWTOptions configure issued tokens.
type JWTOptions struct {
	// Issuer defaults to the base URL origin.
	Issuer string
	// Audience is a string or []string (default: the base URL origin).
	Audience any
	// ExpirationTime is a time string ("15m", "1 hour", the default "15m"), an absolute
	// NumericDate (int, int64, float64), a time.Time, or a time.Duration (relative).
	ExpirationTime any
	// DefinePayload returns the token claims for a session (default: the user object).
	// Returning nil yields only iat and sub.
	DefinePayload func(ctx *betterauth.EndpointContext, session *betterauth.SessionWithUser) (*jsonx.Object, error)
	// GetSubject returns the sub claim (default: the user id); "" falls back to the default.
	GetSubject func(ctx *betterauth.EndpointContext, session *betterauth.SessionWithUser) (string, error)
	// Sign replaces local signing (e.g. a KMS). It requires JWKS.RemoteURL.
	Sign func(ctx *betterauth.EndpointContext, payload *jsonx.Object, header *Header, cfg SigningConfig) (string, error)
}

// Header holds the optional protected header members a caller may set.
type Header struct {
	Typ string
	Cty string
}

// SigningConfig is passed to a custom Sign function.
type SigningConfig struct {
	SigningKeyID     string
	SigningAlgorithm string
}

// SchemaOptions rename the jwks model and fields.
type SchemaOptions struct {
	ModelName string
	// Fields maps logical field names (publicKey, privateKey, createdAt, expiresAt, alg,
	// crv) to column names.
	Fields map[string]string
}

// AdapterOptions replace the database storage of keys.
type AdapterOptions struct {
	GetJwks   func(ctx *betterauth.EndpointContext) ([]*Jwk, error)
	CreateJwk func(ctx *betterauth.EndpointContext, data Jwk) (*Jwk, error)
}

// Jwk is a stored key (a jwks row).
type Jwk struct {
	ID         string
	PublicKey  string
	PrivateKey string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	// Alg and Crv are empty for legacy rows.
	Alg string
	Crv string
}

// ResolvedSigningKey is a decrypted signing key.
type ResolvedSigningKey struct {
	Alg        string
	Kid        string
	PrivateKey any
}

func (o *Options) primaryAlg() string {
	if o != nil && o.JWKS != nil && o.JWKS.KeyPairConfig != nil && o.JWKS.KeyPairConfig.Alg != "" {
		return o.JWKS.KeyPairConfig.Alg
	}
	return "EdDSA"
}

func (o *Options) keyPairConfig() *JWKOptions {
	if o == nil || o.JWKS == nil {
		return nil
	}
	return o.JWKS.KeyPairConfig
}

func (o *Options) jwks() JWKSOptions {
	if o == nil || o.JWKS == nil {
		return JWKSOptions{}
	}
	return *o.JWKS
}

func (o *Options) jwt() JWTOptions {
	if o == nil || o.JWT == nil {
		return JWTOptions{}
	}
	return *o.JWT
}

func (o *Options) customSign() bool { return o != nil && o.JWT != nil && o.JWT.Sign != nil }
