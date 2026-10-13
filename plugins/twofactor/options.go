package twofactor

import (
	"context"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Constants (constant.ts).
const (
	TwoFactorCookieName                    = "two_factor"
	TrustDeviceCookieName                  = "trust_device"
	TrustDeviceCookieMaxAge                = 30 * 24 * 60 * 60 // seconds
	DefaultTwoFactorAllowedAttempts        = 5
	DefaultAccountLockoutMaxFailedAttempts = 10
	DefaultAccountLockoutDurationSeconds   = 15 * 60
	defaultTwoFactorCookieMaxAge           = 10 * 60
	twoFactorModel                         = "twoFactor"
)

// Options configures the two-factor plugin (TwoFactorOptions).
type Options struct {
	// Issuer is the otpauth issuer used by /two-factor/enable (defaults to the app name).
	Issuer string
	// TwoFactorTable renames the physical twoFactor table (modelName).
	TwoFactorTable    string
	TOTPOptions       *TOTPOptions
	OTPOptions        *OTPOptions
	BackupCodeOptions *BackupCodeOptions
	// SkipVerificationOnEnable enables 2FA immediately on /two-factor/enable.
	SkipVerificationOnEnable bool
	// AllowPasswordless lets users without a credential password manage 2FA.
	AllowPasswordless bool
	Schema            *SchemaOptions
	// TwoFactorCookieMaxAge is the two_factor cookie lifetime in seconds (default 600).
	TwoFactorCookieMaxAge int
	// TrustDeviceMaxAge is the trust_device cookie lifetime in seconds (default 30 days).
	TrustDeviceMaxAge int
	AccountLockout    *AccountLockoutOptions
}

// AccountLockoutOptions configures account-level lockout across challenges.
type AccountLockoutOptions struct {
	// Enabled defaults to true.
	Enabled *bool
	// MaxFailedAttempts defaults to 10.
	MaxFailedAttempts int
	// DurationSeconds defaults to 900.
	DurationSeconds int
}

// TOTPOptions configures TOTP (totpOptions; the issuer comes from Options.Issuer).
type TOTPOptions struct {
	// Digits is 6 (default) or 8.
	Digits int
	// Period is the time step in seconds (default 30).
	Period int
	// AllowPasswordless overrides Options.AllowPasswordless for /two-factor/get-totp-uri.
	AllowPasswordless *bool
	// Disable turns TOTP off.
	Disable bool
}

// OTPData is passed to OTPOptions.SendOTP.
type OTPData struct {
	User *betterauth.User
	OTP  string
}

// OTP storage modes (storeOTP).
const (
	StorePlain     = "plain"
	StoreEncrypted = "encrypted"
	StoreHashed    = "hashed"
)

// OTPOptions configures email/SMS one-time codes (otpOptions).
type OTPOptions struct {
	// Period is the code lifetime in minutes (default 3).
	Period int
	// Digits defaults to 6.
	Digits int
	// SendOTP delivers the code. Errors are logged, never returned to the client (the
	// upstream promise rejection handling).
	SendOTP func(ctx context.Context, data OTPData, ec *betterauth.EndpointContext) error
	// AllowedAttempts per code (default 5).
	AllowedAttempts int
	// StoreOTP is "plain" (default), "encrypted" or "hashed"; Hash or Encrypt/Decrypt
	// select a custom storage.
	StoreOTP string
	Hash     func(token string) (string, error)
	Encrypt  func(token string) (string, error)
	Decrypt  func(token string) (string, error)
}

// BackupCodeOptions configures backup codes (backupCodeOptions).
type BackupCodeOptions struct {
	// Amount of codes (default 10).
	Amount int
	// Length of each code before the dash is inserted (default 10).
	Length int
	// CustomBackupCodesGenerate replaces the generator.
	CustomBackupCodesGenerate func() []string
	// StoreBackupCodes is "encrypted" (default) or "plain"; Encrypt/Decrypt select a
	// custom storage.
	StoreBackupCodes string
	Encrypt          func(token string) (string, error)
	Decrypt          func(token string) (string, error)
	// AllowPasswordless overrides Options.AllowPasswordless for backup code generation.
	AllowPasswordless *bool
}

// TableOptions renames a table and its fields.
type TableOptions struct {
	ModelName string
	// Fields maps logical field names to physical column names.
	Fields map[string]string
}

// SchemaOptions customises the plugin schema (schema option).
type SchemaOptions struct {
	User      TableOptions
	TwoFactor TableOptions
}

func (o *Options) trustDeviceMaxAge() int {
	if o.TrustDeviceMaxAge != 0 {
		return o.TrustDeviceMaxAge
	}
	return TrustDeviceCookieMaxAge
}

func (o *Options) twoFactorCookieMaxAge() int {
	if o.TwoFactorCookieMaxAge != 0 {
		return o.TwoFactorCookieMaxAge
	}
	return defaultTwoFactorCookieMaxAge
}

func (o *Options) totpDisabled() bool { return o.TOTPOptions != nil && o.TOTPOptions.Disable }

func (o *Options) sendOTPConfigured() bool { return o.OTPOptions != nil && o.OTPOptions.SendOTP != nil }

type lockoutConfig struct {
	enabled     bool
	maxFailed   int
	duration    time.Duration
	durationSec int
}

func (o *Options) lockout() lockoutConfig {
	c := lockoutConfig{enabled: true, maxFailed: DefaultAccountLockoutMaxFailedAttempts, durationSec: DefaultAccountLockoutDurationSeconds}
	if l := o.AccountLockout; l != nil {
		if l.Enabled != nil {
			c.enabled = *l.Enabled
		}
		if l.MaxFailedAttempts != 0 {
			c.maxFailed = l.MaxFailedAttempts
		}
		if l.DurationSeconds != 0 {
			c.durationSec = l.DurationSeconds
		}
	}
	c.duration = time.Duration(c.durationSec) * time.Second
	return c
}

// schema returns the plugin tables (schema.ts merged with the schema options).
func (o *Options) schema() []db.PluginTable {
	user := db.PluginTable{Key: "user", Fields: []db.Field{
		{Name: "twoFactorEnabled", Type: db.TypeBoolean, Required: db.False, DefaultValue: false, Input: db.False},
	}}
	tf := db.PluginTable{Key: twoFactorModel, Fields: []db.Field{
		{Name: "secret", Type: db.TypeString, Required: db.True, Returned: db.False, Index: true},
		{Name: "backupCodes", Type: db.TypeString, Required: db.True, Returned: db.False},
		{Name: "userId", Type: db.TypeString, Required: db.True, Returned: db.False,
			References: &db.Reference{Model: "user", Field: "id"}, Index: true},
		{Name: "verified", Type: db.TypeBoolean, Required: db.False, DefaultValue: true, Input: db.False},
		{Name: "failedVerificationCount", Type: db.TypeNumber, Required: db.False, DefaultValue: 0, Input: db.False, Returned: db.False},
		{Name: "lockedUntil", Type: db.TypeDate, Required: db.False, Input: db.False, Returned: db.False},
	}}
	if s := o.Schema; s != nil {
		applyTableOptions(&user, s.User)
		applyTableOptions(&tf, s.TwoFactor)
	}
	if o.TwoFactorTable != "" {
		tf.ModelName = o.TwoFactorTable
	}
	return []db.PluginTable{user, tf}
}

func applyTableOptions(t *db.PluginTable, opts TableOptions) {
	if opts.ModelName != "" {
		t.ModelName = opts.ModelName
	}
	for i := range t.Fields {
		if col, ok := opts.Fields[t.Fields[i].Name]; ok {
			t.Fields[i].FieldName = col
		}
	}
}
