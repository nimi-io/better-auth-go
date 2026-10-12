package betterauth

import (
	"context"
	"net/http"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Config configures Better Auth (BetterAuthOptions). Zero values select the upstream
// defaults; pointer fields distinguish "unset" from an explicit zero/false.
type Config struct {
	// AppName defaults to "Better Auth".
	AppName string
	// BaseURL is the public origin (optionally with a path), e.g. "https://example.com".
	// Falls back to BETTER_AUTH_URL and then to the incoming request.
	BaseURL string
	// DynamicBaseURL resolves the base URL per request from an allow-list of hosts.
	DynamicBaseURL *DynamicBaseURL
	// BasePath defaults to "/api/auth".
	BasePath string
	// Secret signs cookies and tokens. Falls back to BETTER_AUTH_SECRET / AUTH_SECRET.
	Secret string
	// Secrets enables secret rotation; the first entry is current. Falls back to
	// BETTER_AUTH_SECRETS ("2:secret2,1:secret1").
	Secrets []SecretEntry

	// Database is the adapter factory (e.g. memory.New(), sql.New(...)).
	Database adapter.Factory
	// SecondaryStorage stores sessions, verification values and rate limits (e.g. Redis).
	SecondaryStorage SecondaryStorage

	EmailVerification *EmailVerificationConfig
	EmailAndPassword  *EmailAndPasswordConfig
	SocialProviders   []oauth2.Provider
	Plugins           []*Plugin

	User         *UserConfig
	Session      *SessionConfig
	Account      *AccountConfig
	Verification *VerificationConfig

	// TrustedOrigins are additional trusted origins; supports wildcards and custom schemes.
	TrustedOrigins []string
	// TrustedOriginsFunc returns origins per request (request may be nil).
	TrustedOriginsFunc func(r *http.Request) ([]string, error)

	RateLimit *RateLimitConfig
	Advanced  *AdvancedConfig
	// Logger receives logs; defaults to a slog-based logger at level "warn".
	Logger        Logger
	DatabaseHooks *DatabaseHooks
	OnAPIError    *OnAPIErrorConfig
	Hooks         *HooksConfig
	// DisabledPaths are endpoint paths that respond 404.
	DisabledPaths []string
}

// SecretEntry is one versioned secret.
type SecretEntry struct {
	Version int
	Value   string
}

// DynamicBaseURL is the dynamic baseURL configuration.
type DynamicBaseURL struct {
	AllowedHosts []string
	Fallback     string
	// Protocol is "http", "https" or "auto".
	Protocol string
}

// EmailData is passed to email callbacks.
type EmailData struct {
	User  *User
	URL   string
	Token string
}

// EmailVerificationConfig is emailVerification.
type EmailVerificationConfig struct {
	SendVerificationEmail func(ctx context.Context, data EmailData, r *http.Request) error
	SendOnSignUp          *bool
	SendOnSignIn          bool
	// AutoSignInAfterVerification signs the user in after verifying.
	AutoSignInAfterVerification bool
	// ExpiresIn is the token lifetime (default 1h).
	ExpiresIn               time.Duration
	BeforeEmailVerification func(ctx context.Context, user *User, r *http.Request) error
	AfterEmailVerification  func(ctx context.Context, user *User, r *http.Request) error
}

// SyntheticUserParams are passed to CustomSyntheticUser.
type SyntheticUserParams struct {
	CoreFields       map[string]any
	AdditionalFields map[string]any
	ID               string
}

// EmailAndPasswordConfig is emailAndPassword.
type EmailAndPasswordConfig struct {
	Enabled                  bool
	DisableSignUp            bool
	RequireEmailVerification bool
	// MinPasswordLength defaults to 8, MaxPasswordLength to 128.
	MinPasswordLength int
	MaxPasswordLength int
	SendResetPassword func(ctx context.Context, data EmailData, r *http.Request) error
	// ResetPasswordTokenExpiresIn defaults to 1h.
	ResetPasswordTokenExpiresIn time.Duration
	OnPasswordReset             func(ctx context.Context, user *User, r *http.Request) error
	Password                    *PasswordConfig
	// AutoSignIn defaults to true.
	AutoSignIn                    *bool
	RevokeSessionsOnPasswordReset bool
	OnExistingUserSignUp          func(ctx context.Context, user *User, r *http.Request) error
	CustomSyntheticUser           func(p SyntheticUserParams) map[string]any
}

// PasswordConfig overrides hashing.
type PasswordConfig struct {
	Hash   func(password string) (string, error)
	Verify func(hash, password string) (bool, error)
}

// ModelConfig holds modelName / fields / additionalFields for a core model.
type ModelConfig struct {
	ModelName        string
	Fields           map[string]string
	AdditionalFields []db.Field
}

// UserInfoSource describes where a user is being provisioned from (ValidateUserInfoSource).
type UserInfoSource struct {
	// Action is "create-user", "link-account" or "sign-in".
	Action string
	// Method is "oauth", "email-password", "magic-link", ...
	Method string
	// ProviderID is set for oauth / sso methods.
	ProviderID string
	Profile    map[string]any
}

// ValidateUserInfoResult rejects provisioning when Error is non-empty.
type ValidateUserInfoResult struct {
	Error            string
	ErrorDescription string
}

// UserConfig is user.
type UserConfig struct {
	ModelConfig
	ValidateUserInfo func(ctx *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error)
	ChangeEmail      *ChangeEmailConfig
	DeleteUser       *DeleteUserConfig
}

// ChangeEmailData is passed to SendChangeEmailConfirmation.
type ChangeEmailData struct {
	User     *User
	NewEmail string
	URL      string
	Token    string
}

// ChangeEmailConfig is user.changeEmail.
type ChangeEmailConfig struct {
	Enabled                        bool
	SendChangeEmailConfirmation    func(ctx context.Context, data ChangeEmailData, r *http.Request) error
	UpdateEmailWithoutVerification bool
}

// DeleteUserConfig is user.deleteUser.
type DeleteUserConfig struct {
	Enabled                       bool
	SendDeleteAccountVerification func(ctx context.Context, data EmailData, r *http.Request) error
	BeforeDelete                  func(ctx context.Context, user *User, r *http.Request) error
	AfterDelete                   func(ctx context.Context, user *User, r *http.Request) error
	// DeleteTokenExpiresIn defaults to 24h.
	DeleteTokenExpiresIn time.Duration
}

// SessionConfig is session.
type SessionConfig struct {
	ModelConfig
	// ExpiresIn defaults to 7 days.
	ExpiresIn time.Duration
	// UpdateAge defaults to 1 day; set to a pointer to 0 to refresh on every request.
	UpdateAge                 *time.Duration
	DisableSessionRefresh     bool
	DeferSessionRefresh       bool
	StoreSessionInDatabase    bool
	PreserveSessionInDatabase bool
	CookieCache               *CookieCacheConfig
	// FreshAge defaults to 1 day; a pointer to 0 disables the freshness check.
	FreshAge *time.Duration
}

// CookieCacheConfig is session.cookieCache.
type CookieCacheConfig struct {
	Enabled bool
	// MaxAge defaults to 5 minutes.
	MaxAge time.Duration
	// Strategy is "compact" (default), "jwt" or "jwe".
	Strategy string
	// RefreshCache enables refreshing the cache before expiry (stateless setups only).
	RefreshCache *RefreshCacheConfig
	// Version invalidates caches when changed.
	Version     string
	VersionFunc func(session *Session, user *User) string
}

// RefreshCacheConfig is cookieCache.refreshCache. UpdateAge defaults to 20% of MaxAge.
type RefreshCacheConfig struct {
	Enabled   bool
	UpdateAge *time.Duration
}

// AccountLinkingConfig is account.accountLinking.
type AccountLinkingConfig struct {
	// Enabled defaults to true.
	Enabled                   *bool
	DisableImplicitLinking    bool
	RequireLocalEmailVerified bool
	TrustedProviders          []string
	TrustedProvidersFunc      func(r *http.Request) ([]string, error)
	AllowDifferentEmails      bool
	AllowUnlinkingAll         bool
	UpdateUserInfoOnLink      bool
}

// AccountConfig is account.
type AccountConfig struct {
	ModelConfig
	// UpdateAccountOnSignIn defaults to true.
	UpdateAccountOnSignIn *bool
	AccountLinking        *AccountLinkingConfig
	EncryptOAuthTokens    bool
	SkipStateCookieCheck  bool
	// StoreStateStrategy is "database" or "cookie" (default depends on the setup).
	StoreStateStrategy string
	StoreAccountCookie *bool
}

// StoreIdentifier selects how verification identifiers are stored.
type StoreIdentifier struct {
	// Mode is "plain" (default) or "hashed".
	Mode string
	// Hash is a custom hasher.
	Hash func(identifier string) (string, error)
}

// VerificationConfig is verification.
type VerificationConfig struct {
	ModelConfig
	DisableCleanup  bool
	StoreIdentifier *StoreIdentifier
	// StoreIdentifierOverrides applies per identifier prefix.
	StoreIdentifierOverrides map[string]StoreIdentifier
	StoreInDatabase          bool
}

// RateLimitRule is a window/max pair.
type RateLimitRule struct {
	Window time.Duration
	Max    int
}

// CustomRateLimitRule is a per-path rule; Disabled turns limiting off for the path, and
// Func computes a rule dynamically (return nil to disable).
type CustomRateLimitRule struct {
	Rule     *RateLimitRule
	Disabled bool
	Func     func(r *http.Request, current RateLimitRule) (*RateLimitRule, error)
}

// RateLimitStorage is a custom rate limit store.
type RateLimitStorage interface {
	Consume(ctx context.Context, key string, rule RateLimitRule) (allowed bool, retryAfter time.Duration, err error)
}

// RateLimitConfig is rateLimit.
type RateLimitConfig struct {
	// Enabled defaults to true in production (GO_ENV/NODE_ENV=production).
	Enabled *bool
	// Window defaults to 10s, Max to 100.
	Window time.Duration
	Max    int
	// CustomRules are keyed by path (wildcards allowed).
	CustomRules map[string]CustomRateLimitRule
	// Storage is "memory", "database" or "secondary-storage".
	Storage       string
	CustomStorage RateLimitStorage
	ModelName     string
	Fields        map[string]string
}

// IPAddressConfig is advanced.ipAddress.
type IPAddressConfig struct {
	IPAddressHeaders  []string
	DisableIPTracking bool
	// IPv6Subnet is the prefix length IPv6 addresses are masked to (nil = /64).
	IPv6Subnet     *int
	TrustedProxies []string
}

// CrossSubDomainCookies is advanced.crossSubDomainCookies.
type CrossSubDomainCookies struct {
	Enabled           bool
	AdditionalCookies []string
	Domain            string
}

// CookieOverride customises a single cookie.
type CookieOverride struct {
	Name       string
	Attributes *CookieAttributes
}

// CookieAttributes override cookie attributes; nil fields keep the default.
type CookieAttributes struct {
	MaxAge      *int
	Domain      *string
	Path        *string
	Secure      *bool
	HTTPOnly    *bool
	SameSite    *string
	Partitioned *bool
}

func (a *CookieAttributes) applyTo(o CookieOptions) CookieOptions {
	if a == nil {
		return o
	}
	if a.MaxAge != nil {
		o.MaxAge = a.MaxAge
	}
	if a.Domain != nil {
		o.Domain = *a.Domain
	}
	if a.Path != nil {
		o.Path = *a.Path
	}
	if a.Secure != nil {
		o.Secure = *a.Secure
	}
	if a.HTTPOnly != nil {
		o.HTTPOnly = *a.HTTPOnly
	}
	if a.SameSite != nil {
		o.SameSite = *a.SameSite
	}
	if a.Partitioned != nil {
		o.Partitioned = *a.Partitioned
	}
	return o
}

// DatabaseAdvancedConfig is advanced.database.
type DatabaseAdvancedConfig struct {
	DefaultFindManyLimit int
	// GenerateID: "" (default), "uuid", "serial" or "none" (database generated).
	GenerateID adapter.IDMode
	// GenerateIDFunc overrides id generation (return ok=false for database generated ids).
	GenerateIDFunc func(model string, size int) (string, bool)
	Joins          bool
}

// AdvancedConfig is advanced.
type AdvancedConfig struct {
	IPAddress               *IPAddressConfig
	UseSecureCookies        *bool
	DisableCSRFCheck        *bool
	DisableOriginCheck      *bool
	CrossSubDomainCookies   *CrossSubDomainCookies
	Cookies                 map[string]CookieOverride
	DefaultCookieAttributes *CookieAttributes
	CookiePrefix            string
	Database                *DatabaseAdvancedConfig
	TrustedProxyHeaders     bool
	// BackgroundTasks runs fire-and-forget work (e.g. sending email) when set.
	BackgroundTasks     func(task func())
	SkipTrailingSlashes bool
}

// OnAPIErrorConfig is onAPIError.
type OnAPIErrorConfig struct {
	OnError  func(err error, ctx *AuthContext)
	ErrorURL string
	// CustomizeDefaultErrorPage customises the HTML error page.
	CustomizeDefaultErrorPage *ErrorPageCustomization
}

// ErrorPageCustomization customises the default /error page.
type ErrorPageCustomization struct {
	Colors                   map[string]string
	Size                     map[string]string
	Font                     map[string]string
	DisableTitleBorder       bool
	DisableCornerDecorations bool
	DisableBackgroundGrid    bool
}

// HooksConfig holds global before/after hooks (hooks.before / hooks.after).
type HooksConfig struct {
	Before HookHandler
	After  HookHandler
}

// Bool returns a pointer to b.
func Bool(b bool) *bool { return &b }

// Duration returns a pointer to d.
func Duration(d time.Duration) *time.Duration { return &d }
