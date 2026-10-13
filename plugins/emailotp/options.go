// Package emailotp is the email OTP plugin (packages/better-auth/src/plugins/email-otp):
// one-time codes sent by email for sign-in, email verification, password reset and email
// change.
package emailotp

import (
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
)

// OTP types.
const (
	TypeEmailVerification = "email-verification"
	TypeSignIn            = "sign-in"
	TypeForgetPassword    = "forget-password"
	TypeChangeEmail       = "change-email"
)

var otpTypes = []string{TypeEmailVerification, TypeSignIn, TypeForgetPassword, TypeChangeEmail}

// SendVerificationOTPData is passed to Options.SendVerificationOTP.
type SendVerificationOTPData struct {
	Email string
	OTP   string
	// Type is one of the Type* constants.
	Type string
}

// GenerateOTPData is passed to Options.GenerateOTP.
type GenerateOTPData struct {
	Email string
	Type  string
}

// StoreOTP selects how OTPs are stored in the verification table (storeOTP upstream).
// The zero value stores the plain OTP.
type StoreOTP struct {
	// Mode is "plain" (default), "hashed" (SHA-256, base64url) or "encrypted"
	// (symmetricEncrypt with the auth secret). Ignored when Hash or Encrypt is set.
	Mode string
	// Hash is a custom one-way hasher ({ hash } upstream).
	Hash func(otp string) (string, error)
	// Encrypt/Decrypt is a custom reversible encryptor ({ encrypt, decrypt } upstream).
	Encrypt func(otp string) (string, error)
	Decrypt func(stored string) (string, error)
}

// StorePlain, StoreHashed and StoreEncrypted are the built-in storage modes.
var (
	StorePlain     = StoreOTP{Mode: "plain"}
	StoreHashed    = StoreOTP{Mode: "hashed"}
	StoreEncrypted = StoreOTP{Mode: "encrypted"}
)

// ChangeEmailOptions configures changing the email with an OTP.
type ChangeEmailOptions struct {
	Enabled bool
	// VerifyCurrentEmail requires an email-verification OTP for the current email.
	VerifyCurrentEmail bool
}

// RateLimit overrides the plugin rate limit (default 3 requests per 60 seconds).
type RateLimit struct {
	Window time.Duration
	Max    int
}

// Options configures the plugin (EmailOTPOptions).
type Options struct {
	// SendVerificationOTP delivers the OTP (required). ctx is the current endpoint context.
	SendVerificationOTP func(ctx *betterauth.EndpointContext, data SendVerificationOTPData) error
	// OTPLength is the length of generated OTPs (default 6).
	OTPLength int
	// ExpiresIn is the OTP lifetime (default 5 minutes).
	ExpiresIn time.Duration
	// GenerateOTP overrides OTP generation; an empty result falls back to the default.
	GenerateOTP func(data GenerateOTPData, ctx *betterauth.EndpointContext) string
	// SendVerificationOnSignUp sends an email-verification OTP after sign-up.
	SendVerificationOnSignUp bool
	// DisableSignUp prevents creating users when signing in with an OTP.
	DisableSignUp bool
	// AllowedAttempts is the number of wrong attempts before the OTP is invalidated
	// (default 3).
	AllowedAttempts int
	// StoreOTP selects how OTPs are stored (default plain).
	StoreOTP StoreOTP
	// ResendStrategy is "rotate" (default) or "reuse" (resend the still-valid OTP).
	ResendStrategy string
	ChangeEmail    *ChangeEmailOptions
	// OverrideDefaultEmailVerification sends an OTP instead of a verification link from
	// the core email verification flow.
	OverrideDefaultEmailVerification bool
	RateLimit                        *RateLimit
}

func (o *Options) otpLength() int {
	if o.OTPLength != 0 {
		return o.OTPLength
	}
	return 6
}

func (o *Options) expiresIn() time.Duration {
	if o.ExpiresIn != 0 {
		return o.ExpiresIn
	}
	return 5 * time.Minute
}

func (o *Options) allowedAttempts() int {
	if o.AllowedAttempts != 0 {
		return o.AllowedAttempts
	}
	return 3
}

// Error codes (EMAIL_OTP_ERROR_CODES).
var (
	ErrOTPExpired      = betterauth.ErrorCode{Code: "OTP_EXPIRED", Message: "OTP expired"}
	ErrInvalidOTP      = betterauth.ErrorCode{Code: "INVALID_OTP", Message: "Invalid OTP"}
	ErrTooManyAttempts = betterauth.ErrorCode{Code: "TOO_MANY_ATTEMPTS", Message: "Too many attempts"}
)

// ErrorCodes lists the plugin error codes.
var ErrorCodes = []betterauth.ErrorCode{ErrOTPExpired, ErrInvalidOTP, ErrTooManyAttempts}
