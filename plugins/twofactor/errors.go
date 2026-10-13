package twofactor

import "github.com/nimi-io/better-auth-go/betterauth"

func ec(code, message string) betterauth.ErrorCode {
	return betterauth.ErrorCode{Code: code, Message: message}
}

// Error codes (TWO_FACTOR_ERROR_CODES).
var (
	ErrOTPNotEnabled                 = ec("OTP_NOT_ENABLED", "OTP not enabled")
	ErrOTPNotConfigured              = ec("OTP_NOT_CONFIGURED", "OTP is not available")
	ErrOTPHasExpired                 = ec("OTP_HAS_EXPIRED", "OTP has expired")
	ErrTOTPNotEnabled                = ec("TOTP_NOT_ENABLED", "TOTP not enabled")
	ErrTOTPAlreadyEnabled            = ec("TOTP_ALREADY_ENABLED", "TOTP is already enabled")
	ErrTOTPNotConfigured             = ec("TOTP_NOT_CONFIGURED", "TOTP is not available")
	ErrTwoFactorNotEnabled           = ec("TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled")
	ErrBackupCodesNotEnabled         = ec("BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled")
	ErrInvalidBackupCode             = ec("INVALID_BACKUP_CODE", "Invalid backup code")
	ErrInvalidCode                   = ec("INVALID_CODE", "Invalid code")
	ErrTooManyAttemptsRequestNewCode = ec("TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE", "Too many attempts. Please request a new code.")
	ErrAccountTemporarilyLocked      = ec("ACCOUNT_TEMPORARILY_LOCKED", "Too many failed verification attempts. Your account is temporarily locked. Please try again later.")
	ErrInvalidTwoFactorCookie        = ec("INVALID_TWO_FACTOR_COOKIE", "Invalid two factor cookie")
)

// ErrorCodes lists the plugin error codes in declaration order ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{
	ErrOTPNotEnabled, ErrOTPNotConfigured, ErrOTPHasExpired, ErrTOTPNotEnabled, ErrTOTPAlreadyEnabled,
	ErrTOTPNotConfigured, ErrTwoFactorNotEnabled, ErrBackupCodesNotEnabled, ErrInvalidBackupCode,
	ErrInvalidCode, ErrTooManyAttemptsRequestNewCode, ErrAccountTemporarilyLocked, ErrInvalidTwoFactorCookie,
}
