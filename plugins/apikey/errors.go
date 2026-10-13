package apikey

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

func ec(code, message string) betterauth.ErrorCode {
	return betterauth.ErrorCode{Code: code, Message: message}
}

// Error codes (API_KEY_ERROR_CODES in packages/api-key/src/error-codes.ts).
var (
	ErrInvalidMetadataType               = ec("INVALID_METADATA_TYPE", "metadata must be an object or undefined")
	ErrRefillAmountAndIntervalRequired   = ec("REFILL_AMOUNT_AND_INTERVAL_REQUIRED", "refillAmount is required when refillInterval is provided")
	ErrRefillIntervalAndAmountRequired   = ec("REFILL_INTERVAL_AND_AMOUNT_REQUIRED", "refillInterval is required when refillAmount is provided")
	ErrUserBanned                        = ec("USER_BANNED", "User is banned")
	ErrUnauthorizedSession               = ec("UNAUTHORIZED_SESSION", "Unauthorized or invalid session")
	ErrKeyNotFound                       = ec("KEY_NOT_FOUND", "API Key not found")
	ErrKeyDisabled                       = ec("KEY_DISABLED", "API Key is disabled")
	ErrKeyExpired                        = ec("KEY_EXPIRED", "API Key has expired")
	ErrUsageExceeded                     = ec("USAGE_EXCEEDED", "API Key has reached its usage limit")
	ErrKeyNotRecoverable                 = ec("KEY_NOT_RECOVERABLE", "API Key is not recoverable")
	ErrExpiresInIsTooSmall               = ec("EXPIRES_IN_IS_TOO_SMALL", "The expiresIn is smaller than the predefined minimum value.")
	ErrExpiresInIsTooLarge               = ec("EXPIRES_IN_IS_TOO_LARGE", "The expiresIn is larger than the predefined maximum value.")
	ErrInvalidRemaining                  = ec("INVALID_REMAINING", "The remaining count is either too large or too small.")
	ErrInvalidPrefixLength               = ec("INVALID_PREFIX_LENGTH", "The prefix length is either too large or too small.")
	ErrInvalidNameLength                 = ec("INVALID_NAME_LENGTH", "The name length is either too large or too small.")
	ErrMetadataDisabled                  = ec("METADATA_DISABLED", "Metadata is disabled.")
	ErrRateLimitExceeded                 = ec("RATE_LIMIT_EXCEEDED", "Rate limit exceeded.")
	ErrNoValuesToUpdate                  = ec("NO_VALUES_TO_UPDATE", "No values to update.")
	ErrKeyDisabledExpiration             = ec("KEY_DISABLED_EXPIRATION", "Custom key expiration values are disabled.")
	ErrInvalidAPIKey                     = ec("INVALID_API_KEY", "Invalid API key.")
	ErrInvalidUserIDFromAPIKey           = ec("INVALID_USER_ID_FROM_API_KEY", "The user id from the API key is invalid.")
	ErrInvalidReferenceIDFromAPIKey      = ec("INVALID_REFERENCE_ID_FROM_API_KEY", "The reference id from the API key is invalid.")
	ErrInvalidAPIKeyGetterReturnType     = ec("INVALID_API_KEY_GETTER_RETURN_TYPE", "API Key getter returned an invalid key type. Expected string.")
	ErrServerOnlyProperty                = ec("SERVER_ONLY_PROPERTY", "The property you're trying to set can only be set from the server auth instance only.")
	ErrFailedToUpdateAPIKey              = ec("FAILED_TO_UPDATE_API_KEY", "Failed to update API key")
	ErrNameRequired                      = ec("NAME_REQUIRED", "API Key name is required.")
	ErrOrganizationIDRequired            = ec("ORGANIZATION_ID_REQUIRED", "Organization ID is required for organization-owned API keys.")
	ErrUserNotMemberOfOrganization       = ec("USER_NOT_MEMBER_OF_ORGANIZATION", "You are not a member of the organization that owns this API key.")
	ErrInsufficientAPIKeyPermissions     = ec("INSUFFICIENT_API_KEY_PERMISSIONS", "You do not have permission to perform this action on organization API keys.")
	ErrNoDefaultAPIKeyConfigurationFound = ec("NO_DEFAULT_API_KEY_CONFIGURATION_FOUND", "No default api-key configuration found.")
	ErrOrganizationPluginRequired        = ec("ORGANIZATION_PLUGIN_REQUIRED", "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.")
)

// ErrorCodes lists the plugin error codes in declaration order ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{
	ErrInvalidMetadataType, ErrRefillAmountAndIntervalRequired, ErrRefillIntervalAndAmountRequired,
	ErrUserBanned, ErrUnauthorizedSession, ErrKeyNotFound, ErrKeyDisabled, ErrKeyExpired,
	ErrUsageExceeded, ErrKeyNotRecoverable, ErrExpiresInIsTooSmall, ErrExpiresInIsTooLarge,
	ErrInvalidRemaining, ErrInvalidPrefixLength, ErrInvalidNameLength, ErrMetadataDisabled,
	ErrRateLimitExceeded, ErrNoValuesToUpdate, ErrKeyDisabledExpiration, ErrInvalidAPIKey,
	ErrInvalidUserIDFromAPIKey, ErrInvalidReferenceIDFromAPIKey, ErrInvalidAPIKeyGetterReturnType,
	ErrServerOnlyProperty, ErrFailedToUpdateAPIKey, ErrNameRequired, ErrOrganizationIDRequired,
	ErrUserNotMemberOfOrganization, ErrInsufficientAPIKeyPermissions,
	ErrNoDefaultAPIKeyConfigurationFound, ErrOrganizationPluginRequired,
}

// errorCodeObject renders an error code the way JSON.stringify renders a RawError
// ({code, message}); used where upstream puts the whole error code object in a field.
func errorCodeObject(c betterauth.ErrorCode) *jsonx.Object {
	return jsonx.O("code", c.Code, "message", c.Message)
}
