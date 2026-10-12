package betterauth

import (
	"errors"
	"net/http"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// StatusCodes maps better-call status names to HTTP status codes.
var StatusCodes = map[string]int{
	"OK": 200, "CREATED": 201, "ACCEPTED": 202, "NO_CONTENT": 204, "MULTIPLE_CHOICES": 300,
	"MOVED_PERMANENTLY": 301, "FOUND": 302, "SEE_OTHER": 303, "NOT_MODIFIED": 304,
	"TEMPORARY_REDIRECT": 307, "BAD_REQUEST": 400, "UNAUTHORIZED": 401, "PAYMENT_REQUIRED": 402,
	"FORBIDDEN": 403, "NOT_FOUND": 404, "METHOD_NOT_ALLOWED": 405, "NOT_ACCEPTABLE": 406,
	"PROXY_AUTHENTICATION_REQUIRED": 407, "REQUEST_TIMEOUT": 408, "CONFLICT": 409, "GONE": 410,
	"LENGTH_REQUIRED": 411, "PRECONDITION_FAILED": 412, "PAYLOAD_TOO_LARGE": 413,
	"URI_TOO_LONG": 414, "UNSUPPORTED_MEDIA_TYPE": 415, "RANGE_NOT_SATISFIABLE": 416,
	"EXPECTATION_FAILED": 417, "I'M_A_TEAPOT": 418, "MISDIRECTED_REQUEST": 421,
	"UNPROCESSABLE_ENTITY": 422, "LOCKED": 423, "FAILED_DEPENDENCY": 424, "TOO_EARLY": 425,
	"UPGRADE_REQUIRED": 426, "PRECONDITION_REQUIRED": 428, "TOO_MANY_REQUESTS": 429,
	"REQUEST_HEADER_FIELDS_TOO_LARGE": 431, "UNAVAILABLE_FOR_LEGAL_REASONS": 451,
	"INTERNAL_SERVER_ERROR": 500, "NOT_IMPLEMENTED": 501, "BAD_GATEWAY": 502,
	"SERVICE_UNAVAILABLE": 503, "GATEWAY_TIMEOUT": 504, "HTTP_VERSION_NOT_SUPPORTED": 505,
	"VARIANT_ALSO_NEGOTIATES": 506, "INSUFFICIENT_STORAGE": 507, "LOOP_DETECTED": 508,
	"NOT_EXTENDED": 510, "NETWORK_AUTHENTICATION_REQUIRED": 511,
}

// APIError is an error returned by an endpoint. It is rendered as an HTTP response with
// StatusCode, Headers and a JSON Body (typically {"message","code"}); a nil Body produces
// an empty response body.
type APIError struct {
	// Status is the better-call status name, e.g. "BAD_REQUEST".
	Status     string
	StatusCode int
	Body       *jsonx.Object
	Headers    http.Header
	// Cause is an optional wrapped error (not serialised).
	Cause error
}

func (e *APIError) Error() string {
	if m := e.Message(); m != "" {
		return m
	}
	return e.Status
}

func (e *APIError) Unwrap() error { return e.Cause }

// Message returns body.message.
func (e *APIError) Message() string {
	if e.Body == nil {
		return ""
	}
	v, _ := e.Body.Get("message")
	s, _ := v.(string)
	return s
}

// Code returns body.code.
func (e *APIError) Code() string {
	if e.Body == nil {
		return ""
	}
	v, _ := e.Body.Get("code")
	s, _ := v.(string)
	return s
}

// NewAPIError creates an APIError with a status name and an optional body.
func NewAPIError(status string, body *jsonx.Object) *APIError {
	code, ok := StatusCodes[status]
	if !ok {
		code = 500
	}
	return &APIError{Status: status, StatusCode: code, Body: body, Headers: http.Header{}}
}

// NewAPIErrorCode creates an APIError for a numeric status.
func NewAPIErrorCode(statusCode int, body *jsonx.Object) *APIError {
	name := ""
	for k, v := range StatusCodes {
		if v == statusCode {
			name = k
			break
		}
	}
	return &APIError{Status: name, StatusCode: statusCode, Body: body, Headers: http.Header{}}
}

// ErrorCode is a machine-readable error code with its default message (RawError).
type ErrorCode struct {
	Code    string
	Message string
}

func (c ErrorCode) String() string { return c.Code }

// ErrFrom is APIError.from(status, {message, code}).
func ErrFrom(status string, code ErrorCode) *APIError {
	return NewAPIError(status, jsonx.O("message", code.Message, "code", code.Code))
}

// ErrMessage is APIError.fromStatus(status, {message}).
func ErrMessage(status, message string) *APIError {
	return NewAPIError(status, jsonx.O("message", message))
}

// ErrStatus is an APIError without a body.
func ErrStatus(status string) *APIError { return NewAPIError(status, nil) }

// AsAPIError extracts an *APIError from err.
func AsAPIError(err error) (*APIError, bool) {
	var e *APIError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// IsRedirect reports whether err is a redirect (status FOUND).
func IsRedirect(err error) bool {
	e, ok := AsAPIError(err)
	return ok && e.Status == "FOUND"
}

// Redirect returns an APIError that renders a 302 redirect to url.
func Redirect(url string) *APIError {
	e := NewAPIError("FOUND", nil)
	e.Headers.Set("Location", url)
	return e
}

func ec(code, message string) ErrorCode { return ErrorCode{Code: code, Message: message} }

// Base error codes (BASE_ERROR_CODES in packages/core/src/error/codes.ts).
var (
	ErrUserNotFound                         = ec("USER_NOT_FOUND", "User not found")
	ErrFailedToCreateUser                   = ec("FAILED_TO_CREATE_USER", "Failed to create user")
	ErrFailedToCreateSession                = ec("FAILED_TO_CREATE_SESSION", "Failed to create session")
	ErrFailedToUpdateUser                   = ec("FAILED_TO_UPDATE_USER", "Failed to update user")
	ErrFailedToGetSession                   = ec("FAILED_TO_GET_SESSION", "Failed to get session")
	ErrInvalidPassword                      = ec("INVALID_PASSWORD", "Invalid password")
	ErrInvalidEmail                         = ec("INVALID_EMAIL", "Invalid email")
	ErrInvalidEmailOrPassword               = ec("INVALID_EMAIL_OR_PASSWORD", "Invalid email or password")
	ErrInvalidUser                          = ec("INVALID_USER", "Invalid user")
	ErrSocialAccountAlreadyLinked           = ec("SOCIAL_ACCOUNT_ALREADY_LINKED", "Social account already linked")
	ErrProviderNotFound                     = ec("PROVIDER_NOT_FOUND", "Provider not found")
	ErrInvalidToken                         = ec("INVALID_TOKEN", "Invalid token")
	ErrTokenExpired                         = ec("TOKEN_EXPIRED", "Token expired")
	ErrIDTokenNotSupported                  = ec("ID_TOKEN_NOT_SUPPORTED", "id_token not supported")
	ErrFailedToGetUserInfo                  = ec("FAILED_TO_GET_USER_INFO", "Failed to get user info")
	ErrUserEmailNotFound                    = ec("USER_EMAIL_NOT_FOUND", "User email not found")
	ErrEmailNotVerified                     = ec("EMAIL_NOT_VERIFIED", "Email not verified")
	ErrPasswordTooShort                     = ec("PASSWORD_TOO_SHORT", "Password too short")
	ErrPasswordTooLong                      = ec("PASSWORD_TOO_LONG", "Password too long")
	ErrUserAlreadyExists                    = ec("USER_ALREADY_EXISTS", "User already exists.")
	ErrUserAlreadyExistsUseAnotherEmail     = ec("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email.")
	ErrEmailCanNotBeUpdated                 = ec("EMAIL_CAN_NOT_BE_UPDATED", "Email can not be updated")
	ErrChangeEmailDisabled                  = ec("CHANGE_EMAIL_DISABLED", "Change email is disabled")
	ErrCredentialAccountNotFound            = ec("CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found")
	ErrSessionExpired                       = ec("SESSION_EXPIRED", "Session expired. Re-authenticate to perform this action.")
	ErrFailedToUnlinkLastAccount            = ec("FAILED_TO_UNLINK_LAST_ACCOUNT", "You can't unlink your last account")
	ErrAccountNotFound                      = ec("ACCOUNT_NOT_FOUND", "Account not found")
	ErrUserAlreadyHasPassword               = ec("USER_ALREADY_HAS_PASSWORD", "User already has a password. Provide that to delete the account.")
	ErrCrossSiteNavigationLoginBlocked      = ec("CROSS_SITE_NAVIGATION_LOGIN_BLOCKED", "Cross-site navigation login blocked. This request appears to be a CSRF attack.")
	ErrVerificationEmailNotEnabled          = ec("VERIFICATION_EMAIL_NOT_ENABLED", "Verification email isn't enabled")
	ErrEmailAlreadyVerified                 = ec("EMAIL_ALREADY_VERIFIED", "Email is already verified")
	ErrEmailMismatch                        = ec("EMAIL_MISMATCH", "Email mismatch")
	ErrSessionNotFresh                      = ec("SESSION_NOT_FRESH", "Session is not fresh")
	ErrLinkedAccountAlreadyExists           = ec("LINKED_ACCOUNT_ALREADY_EXISTS", "Linked account already exists")
	ErrInvalidOrigin                        = ec("INVALID_ORIGIN", "Invalid origin")
	ErrInvalidCallbackURL                   = ec("INVALID_CALLBACK_URL", "Invalid callbackURL")
	ErrInvalidRedirectURL                   = ec("INVALID_REDIRECT_URL", "Invalid redirectURL")
	ErrInvalidErrorCallbackURL              = ec("INVALID_ERROR_CALLBACK_URL", "Invalid errorCallbackURL")
	ErrInvalidNewUserCallbackURL            = ec("INVALID_NEW_USER_CALLBACK_URL", "Invalid newUserCallbackURL")
	ErrMissingOrNullOrigin                  = ec("MISSING_OR_NULL_ORIGIN", "Missing or null Origin")
	ErrCallbackURLRequired                  = ec("CALLBACK_URL_REQUIRED", "callbackURL is required")
	ErrFailedToCreateVerification           = ec("FAILED_TO_CREATE_VERIFICATION", "Unable to create verification")
	ErrFieldNotAllowed                      = ec("FIELD_NOT_ALLOWED", "Field not allowed to be set")
	ErrAsyncValidationNotSupported          = ec("ASYNC_VALIDATION_NOT_SUPPORTED", "Async validation is not supported")
	ErrValidationError                      = ec("VALIDATION_ERROR", "Validation Error")
	ErrMissingField                         = ec("MISSING_FIELD", "Field is required")
	ErrMethodNotAllowedDeferSessionRequired = ec("METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED", "POST method requires deferSessionRefresh to be enabled in session config")
	ErrBodyMustBeAnObject                   = ec("BODY_MUST_BE_AN_OBJECT", "Body must be an object")
	ErrPasswordAlreadySet                   = ec("PASSWORD_ALREADY_SET", "User already has a password set")
)

// BaseErrorCodes lists all base error codes keyed by code ($ERROR_CODES).
var BaseErrorCodes = map[string]ErrorCode{}

func init() {
	for _, c := range []ErrorCode{ErrUserNotFound, ErrFailedToCreateUser, ErrFailedToCreateSession,
		ErrFailedToUpdateUser, ErrFailedToGetSession, ErrInvalidPassword, ErrInvalidEmail,
		ErrInvalidEmailOrPassword, ErrInvalidUser, ErrSocialAccountAlreadyLinked, ErrProviderNotFound,
		ErrInvalidToken, ErrTokenExpired, ErrIDTokenNotSupported, ErrFailedToGetUserInfo,
		ErrUserEmailNotFound, ErrEmailNotVerified, ErrPasswordTooShort, ErrPasswordTooLong,
		ErrUserAlreadyExists, ErrUserAlreadyExistsUseAnotherEmail, ErrEmailCanNotBeUpdated,
		ErrChangeEmailDisabled, ErrCredentialAccountNotFound, ErrSessionExpired,
		ErrFailedToUnlinkLastAccount, ErrAccountNotFound, ErrUserAlreadyHasPassword,
		ErrCrossSiteNavigationLoginBlocked, ErrVerificationEmailNotEnabled, ErrEmailAlreadyVerified,
		ErrEmailMismatch, ErrSessionNotFresh, ErrLinkedAccountAlreadyExists, ErrInvalidOrigin,
		ErrInvalidCallbackURL, ErrInvalidRedirectURL, ErrInvalidErrorCallbackURL,
		ErrInvalidNewUserCallbackURL, ErrMissingOrNullOrigin, ErrCallbackURLRequired,
		ErrFailedToCreateVerification, ErrFieldNotAllowed, ErrAsyncValidationNotSupported,
		ErrValidationError, ErrMissingField, ErrMethodNotAllowedDeferSessionRequired,
		ErrBodyMustBeAnObject, ErrPasswordAlreadySet} {
		BaseErrorCodes[c.Code] = c
	}
}
