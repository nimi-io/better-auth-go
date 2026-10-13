// Package apikey is the Better Auth API key plugin (packages/api-key, @better-auth/api-key
// 1.7.7): create, verify, get, update, delete and list API keys, with hashing compatible
// with the TypeScript implementation, prefixes, expiration, refills, usage limits, per-key
// rate limiting, permissions, metadata, secondary storage, organization-owned keys and
// sessions from API keys.
package apikey

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// TableName is the logical model name of the API key table (API_KEY_TABLE_NAME).
const TableName = "apikey"

// Storage modes.
const (
	StorageDatabase  = "database"
	StorageSecondary = "secondary-storage"
)

// Reference types.
const (
	ReferencesUser         = "user"
	ReferencesOrganization = "organization"
)

// Statements are permissions: resource -> actions.
type Statements = map[string][]string

// StartingCharactersConfig controls the stored starting characters of a key.
type StartingCharactersConfig struct {
	// ShouldStore stores the first characters of the key (default true).
	ShouldStore *bool
	// CharactersLength is the number of characters to store (default 6).
	CharactersLength *int
}

// KeyExpiration configures key expiration.
type KeyExpiration struct {
	// DefaultExpiresIn is the default lifetime in seconds (nil: keys don't expire).
	DefaultExpiresIn *float64
	// DisableCustomExpiresTime rejects a custom expiresIn.
	DisableCustomExpiresTime bool
	// MinExpiresIn is the minimum custom expiresIn in days (default 1).
	MinExpiresIn *float64
	// MaxExpiresIn is the maximum custom expiresIn in days (default 365).
	MaxExpiresIn *float64
}

// RateLimit configures the per-key rate limit defaults.
type RateLimit struct {
	// Enabled defaults to true.
	Enabled *bool
	// TimeWindow in milliseconds (default 86400000, one day).
	TimeWindow *float64
	// MaxRequests per window (default 10).
	MaxRequests *float64
}

// Permissions configures key permissions.
type Permissions struct {
	// DefaultPermissions are applied to keys created without permissions.
	DefaultPermissions Statements
	// DefaultPermissionsFunc computes default permissions (takes precedence).
	DefaultPermissionsFunc func(referenceID string, ctx *betterauth.EndpointContext) (Statements, error)
}

// Configuration is one API key configuration (ApiKeyConfigurationOptions).
type Configuration struct {
	// ConfigID identifies the configuration; required when several are given.
	ConfigID string
	// APIKeyHeaders are the headers read for sessions from API keys (default ["x-api-key"]).
	APIKeyHeaders []string
	// DisableKeyHashing stores keys in plain text (not recommended).
	DisableKeyHashing bool
	// CustomAPIKeyGetter reads the key from the request ("" for none).
	CustomAPIKeyGetter func(ctx *betterauth.EndpointContext) string
	// CustomAPIKeyValidator performs additional validation of a key.
	CustomAPIKeyValidator func(ctx *betterauth.EndpointContext, key string) (bool, error)
	// CustomKeyGenerator generates keys (default: prefix + 64 random letters).
	CustomKeyGenerator func(length int, prefix string) (string, error)
	// StartingCharactersConfig controls the stored "start" value.
	StartingCharactersConfig *StartingCharactersConfig
	// DefaultKeyLength is the generated key length without prefix (default 64).
	DefaultKeyLength int
	// DefaultPrefix is prepended to generated keys.
	DefaultPrefix string
	// MaximumPrefixLength defaults to 32, MinimumPrefixLength to 1.
	MaximumPrefixLength *int
	MinimumPrefixLength *int
	// RequireName requires a name on creation.
	RequireName bool
	// MaximumNameLength defaults to 32, MinimumNameLength to 1.
	MaximumNameLength *int
	MinimumNameLength *int
	// EnableMetadata allows metadata on keys.
	EnableMetadata bool
	KeyExpiration  *KeyExpiration
	RateLimit      *RateLimit
	// EnableSessionForAPIKeys turns a valid API key header into a session.
	EnableSessionForAPIKeys bool
	Permissions             *Permissions
	// Storage is "database" (default) or "secondary-storage".
	Storage string
	// FallbackToDatabase reads/writes through to the database in secondary-storage mode.
	FallbackToDatabase bool
	// CustomStorage overrides the global secondary storage for this configuration.
	CustomStorage betterauth.SecondaryStorage
	// DeferUpdates runs non-critical writes with advanced.backgroundTasks.
	DeferUpdates bool
	// References is "user" (default) or "organization".
	References string
}

// SchemaOptions customizes the apikey table (options.schema).
type SchemaOptions struct {
	// ModelName renames the table.
	ModelName string
	// Fields renames columns: logical field name -> column name.
	Fields map[string]string
}

// Options configures the plugin. Either the embedded single Configuration or a list of
// Configurations (each with a unique ConfigID) is used.
type Options struct {
	Configuration
	// Configurations, when non-empty, replaces the embedded configuration.
	Configurations []Configuration
	Schema         *SchemaOptions
}

// Int returns a pointer to n (for the optional numeric options).
func Int(n int) *int { return &n }

// Float returns a pointer to f (for the optional numeric options).
func Float(f float64) *float64 { return &f }

// Bool returns a pointer to b.
func Bool(b bool) *bool { return &b }

// config is a resolved configuration (PredefinedApiKeyOptions).
type config struct {
	Configuration
	apiKeyHeaders          []string
	defaultKeyLength       int
	maximumPrefixLength    int
	minimumPrefixLength    int
	maximumNameLength      int
	minimumNameLength      int
	storage                string
	rateLimitEnabled       bool
	rateLimitTimeWindow    float64
	rateLimitMaxRequests   float64
	defaultExpiresIn       *float64
	disableCustomExpiresIn bool
	maxExpiresIn           float64
	minExpiresIn           float64
	startShouldStore       bool
	startLength            int
	references             string
}

func intOr(p *int, d int) int {
	if p != nil {
		return *p
	}
	return d
}

func floatOr(p *float64, d float64) float64 {
	if p != nil {
		return *p
	}
	return d
}

func resolveConfig(c Configuration) *config {
	r := &config{Configuration: c}
	r.apiKeyHeaders = c.APIKeyHeaders
	if len(r.apiKeyHeaders) == 0 {
		r.apiKeyHeaders = []string{"x-api-key"}
	}
	r.defaultKeyLength = c.DefaultKeyLength
	if r.defaultKeyLength == 0 {
		r.defaultKeyLength = 64
	}
	r.maximumPrefixLength = intOr(c.MaximumPrefixLength, 32)
	r.minimumPrefixLength = intOr(c.MinimumPrefixLength, 1)
	r.maximumNameLength = intOr(c.MaximumNameLength, 32)
	r.minimumNameLength = intOr(c.MinimumNameLength, 1)
	r.storage = c.Storage
	if r.storage == "" {
		r.storage = StorageDatabase
	}
	r.rateLimitEnabled = true
	r.rateLimitTimeWindow = 1000 * 60 * 60 * 24
	r.rateLimitMaxRequests = 10
	if rl := c.RateLimit; rl != nil {
		if rl.Enabled != nil {
			r.rateLimitEnabled = *rl.Enabled
		}
		r.rateLimitTimeWindow = floatOr(rl.TimeWindow, r.rateLimitTimeWindow)
		r.rateLimitMaxRequests = floatOr(rl.MaxRequests, r.rateLimitMaxRequests)
	}
	r.maxExpiresIn, r.minExpiresIn = 365, 1
	if ke := c.KeyExpiration; ke != nil {
		r.defaultExpiresIn = ke.DefaultExpiresIn
		r.disableCustomExpiresIn = ke.DisableCustomExpiresTime
		r.maxExpiresIn = floatOr(ke.MaxExpiresIn, 365)
		r.minExpiresIn = floatOr(ke.MinExpiresIn, 1)
	}
	r.startShouldStore, r.startLength = true, 6
	if sc := c.StartingCharactersConfig; sc != nil {
		if sc.ShouldStore != nil {
			r.startShouldStore = *sc.ShouldStore
		}
		r.startLength = intOr(sc.CharactersLength, 6)
	}
	r.references = c.References
	if r.references == "" {
		r.references = ReferencesUser
	}
	return r
}

// DefaultKeyHasher hashes a key: base64url(SHA-256(key)) without padding. It produces the
// same value as defaultKeyHasher in the TypeScript plugin.
func DefaultKeyHasher(key string) string {
	sum := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DefaultKeyGenerator returns prefix followed by length random letters (a-z, A-Z).
func DefaultKeyGenerator(length int, prefix string) (string, error) {
	return prefix + bacrypto.RandomStringFrom(length, bacrypto.AlphaLower, bacrypto.AlphaUpper), nil
}

// plugin holds the runtime state of one plugin instance.
type plugin struct {
	configs []*config
	schema  *SchemaOptions
	// now is the clock (tests replace it).
	now func() time.Time

	cleanupMu   sync.Mutex
	lastChecked time.Time
}

// validateOptions checks the configuration list (BetterAuthError upstream).
func validateOptions(o Options) error {
	if len(o.Configurations) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, c := range o.Configurations {
		if c.ConfigID == "" {
			return errors.New("configId is required for each API key configuration in the api-key plugin.")
		}
	}
	for _, c := range o.Configurations {
		if seen[c.ConfigID] {
			return errors.New("configId must be unique for each API key configuration in the api-key plugin.")
		}
		seen[c.ConfigID] = true
	}
	return nil
}

func newPlugin(o Options) (*plugin, error) {
	if err := validateOptions(o); err != nil {
		return nil, err
	}
	p := &plugin{schema: o.Schema, now: time.Now}
	list := o.Configurations
	if len(list) == 0 {
		list = []Configuration{o.Configuration}
	}
	for _, c := range list {
		p.configs = append(p.configs, resolveConfig(c))
	}
	return p, nil
}

// NewE creates the plugin, returning an error for an invalid configuration list.
func NewE(o Options) (*betterauth.Plugin, error) {
	p, err := newPlugin(o)
	if err != nil {
		return nil, err
	}
	return p.build(), nil
}

// New creates the api-key plugin. It panics when the configuration list is invalid
// (missing or duplicate ConfigID), like the TypeScript constructor throws.
func New(o Options) *betterauth.Plugin {
	pl, err := NewE(o)
	if err != nil {
		panic(err)
	}
	return pl
}

func (p *plugin) build() *betterauth.Plugin {
	return &betterauth.Plugin{
		ID:         "api-key",
		Version:    "1.7.7",
		ErrorCodes: ErrorCodes,
		Schema:     p.tables(),
		Hooks: betterauth.PluginHooks{Before: []betterauth.Hook{
			{Matcher: func(ctx *betterauth.EndpointContext) bool { return p.findKeyAndConfig(ctx) != nil }, Handler: p.sessionHook},
		}},
		Endpoints: []*betterauth.Endpoint{
			p.createEndpoint(),
			p.verifyEndpoint(),
			p.getEndpoint(),
			p.updateEndpoint(),
			p.deleteEndpoint(),
			p.listEndpoint(),
			p.deleteAllExpiredEndpoint(),
		},
		Options: p,
	}
}

// Configurations returns the resolved configuration list (for other plugins).
func (p *plugin) Configurations() []Configuration {
	out := make([]Configuration, len(p.configs))
	for i, c := range p.configs {
		out[i] = c.Configuration
	}
	return out
}
