// Package deviceauthorization is a port of Better Auth's device-authorization plugin
// (packages/better-auth/src/plugins/device-authorization): the OAuth 2.0 Device
// Authorization Grant (RFC 8628).
//
// A device requests a device code and a user code (POST /device/code), shows the user code
// and polls POST /device/token. The user signs in on another device, looks the code up
// (GET /device?user_code=...), which claims the request for their session, and approves
// or denies it (POST /device/approve, /device/deny). Polling returns RFC 8628 errors
// (authorization_pending, slow_down, expired_token, access_denied) until a session is
// issued.
package deviceauthorization

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/validate"
)

// CodeMaxLength is the maximum device / user code length (DEVICE_AUTHORIZATION_CODE_MAX_LENGTH),
// bounded by the indexed column size.
const CodeMaxLength = 191

// Error codes (DEVICE_AUTHORIZATION_ERROR_CODES).
var (
	ErrInvalidDeviceCode          = betterauth.ErrorCode{Code: "INVALID_DEVICE_CODE", Message: "Invalid device code"}
	ErrExpiredDeviceCode          = betterauth.ErrorCode{Code: "EXPIRED_DEVICE_CODE", Message: "Device code has expired"}
	ErrExpiredUserCode            = betterauth.ErrorCode{Code: "EXPIRED_USER_CODE", Message: "User code has expired"}
	ErrAuthorizationPending       = betterauth.ErrorCode{Code: "AUTHORIZATION_PENDING", Message: "Authorization pending"}
	ErrAccessDenied               = betterauth.ErrorCode{Code: "ACCESS_DENIED", Message: "Access denied"}
	ErrInvalidUserCode            = betterauth.ErrorCode{Code: "INVALID_USER_CODE", Message: "Invalid user code"}
	ErrDeviceCodeAlreadyProcessed = betterauth.ErrorCode{Code: "DEVICE_CODE_ALREADY_PROCESSED", Message: "Device code already processed"}
	ErrDeviceCodeNotClaimed       = betterauth.ErrorCode{Code: "DEVICE_CODE_NOT_CLAIMED",
		Message: "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying"}
	ErrPollingTooFrequently    = betterauth.ErrorCode{Code: "POLLING_TOO_FREQUENTLY", Message: "Polling too frequently"}
	ErrUserNotFound            = betterauth.ErrorCode{Code: "USER_NOT_FOUND", Message: "User not found"}
	ErrFailedToCreateSession   = betterauth.ErrorCode{Code: "FAILED_TO_CREATE_SESSION", Message: "Failed to create session"}
	ErrInvalidDeviceCodeStatus = betterauth.ErrorCode{Code: "INVALID_DEVICE_CODE_STATUS", Message: "Invalid device code status"}
	ErrAuthenticationRequired  = betterauth.ErrorCode{Code: "AUTHENTICATION_REQUIRED", Message: "Authentication required"}
)

// ErrorCodes lists the plugin error codes in upstream order.
var ErrorCodes = []betterauth.ErrorCode{
	ErrInvalidDeviceCode, ErrExpiredDeviceCode, ErrExpiredUserCode, ErrAuthorizationPending,
	ErrAccessDenied, ErrInvalidUserCode, ErrDeviceCodeAlreadyProcessed, ErrDeviceCodeNotClaimed,
	ErrPollingTooFrequently, ErrUserNotFound, ErrFailedToCreateSession, ErrInvalidDeviceCodeStatus,
	ErrAuthenticationRequired,
}

// ModelOptions renames the deviceCode model and its fields (the schema option upstream).
type ModelOptions struct {
	ModelName string
	// Fields maps logical field names to column names.
	Fields map[string]string
}

// SchemaOptions customises the plugin schema.
type SchemaOptions struct {
	DeviceCode ModelOptions
}

// Options configures the plugin (DeviceAuthorizationOptions).
type Options struct {
	// ExpiresIn is how long device codes stay valid, as a time string ("30m", "5s", "1h").
	// Default "30m".
	ExpiresIn string
	// Interval is the minimum polling interval, as a time string. Default "5s".
	Interval string
	// DeviceCodeLength is the generated device code length (default 40, at most 191).
	DeviceCodeLength int
	// UserCodeLength is the generated user code length (default 8, at most 191).
	UserCodeLength int
	// GenerateDeviceCode replaces the default random device code generator.
	GenerateDeviceCode func(ctx context.Context) (string, error)
	// GenerateUserCode replaces the default random user code generator.
	GenerateUserCode func(ctx context.Context) (string, error)
	// ValidateClient validates client IDs on /device/code and /device/token.
	ValidateClient func(ctx context.Context, clientID string) (bool, error)
	// OnDeviceAuthRequest is called for every accepted device authorization request.
	OnDeviceAuthRequest func(ctx context.Context, clientID string, scope *string) error
	// VerificationURI is returned as verification_uri: an absolute URL or a path resolved
	// against the base URL. Default "/device".
	VerificationURI string
	// Schema renames the deviceCode model / fields.
	Schema *SchemaOptions
	// Grant extends the flow (used by OAuth integrations); see Grant.
	Grant *Grant
}

// GrantAuthorization is returned by Grant.AuthorizeRequest to accept a request on the
// grant's terms (DeviceAuthorizationGrantAuthorization).
type GrantAuthorization struct {
	ClientID string
	// DeviceCodeFields are stored on the deviceCode row (grant schema fields).
	DeviceCodeFields map[string]any
}

// Grant customises request validation, storage and redemption (DeviceAuthorizationGrant).
type Grant struct {
	// RequestSchemaFields are extra /device/code body fields.
	RequestSchemaFields []validate.Field
	// RequestErrorCodes are extra OAuth error codes /device/code may return.
	RequestErrorCodes []string
	// RequestOpenAPIResponses are extra documented /device/code responses keyed by status.
	RequestOpenAPIResponses map[string]any
	// OnRequestValidationError may return an error to replace the default invalid_request
	// response when /device/code body validation fails.
	OnRequestValidationError func(issues []validate.Issue) error
	// DeviceCodeSchemaFields are extra deviceCode columns.
	DeviceCodeSchemaFields []db.Field
	// AuthorizeRequest authorizes a /device/code request; returning nil falls back to the
	// client_id / ValidateClient checks.
	AuthorizeRequest func(ctx *betterauth.EndpointContext, request map[string]any) (*GrantAuthorization, error)
	// AssertSessionRedemption may reject a /device/token redemption.
	AssertSessionRedemption func(ctx *betterauth.EndpointContext, deviceCode adapter.Record) error
	// GetVerificationContext returns extra GET /device response fields for the owner.
	GetVerificationContext func(deviceCode adapter.Record) map[string]any
	// VerificationOpenAPIProperties are extra documented GET /device response properties.
	VerificationOpenAPIProperties map[string]any
}

const defaultExpiresIn, defaultInterval = "30m", "5s"

// ParseOptions applies defaults and validates options (deviceAuthorizationOptionsSchema).
func ParseOptions(o Options) (Options, error) {
	if o.ExpiresIn == "" {
		o.ExpiresIn = defaultExpiresIn
	}
	if o.Interval == "" {
		o.Interval = defaultInterval
	}
	const timeMsg = "Invalid time string format. Use formats like '30m', '5s', '1h', etc."
	if _, err := ParseTimeString(o.ExpiresIn); err != nil {
		return o, fmt.Errorf("[expiresIn] %s", timeMsg)
	}
	if _, err := ParseTimeString(o.Interval); err != nil {
		return o, fmt.Errorf("[interval] %s", timeMsg)
	}
	if o.DeviceCodeLength == 0 {
		o.DeviceCodeLength = 40
	}
	if o.UserCodeLength == 0 {
		o.UserCodeLength = 8
	}
	for _, l := range []struct {
		name string
		n    int
	}{{"deviceCodeLength", o.DeviceCodeLength}, {"userCodeLength", o.UserCodeLength}} {
		name, n := l.name, l.n
		if n <= 0 {
			return o, fmt.Errorf("[%s] Too small: expected number to be >0", name)
		}
		if n > CodeMaxLength {
			return o, fmt.Errorf("[%s] Too big: expected number to be <=%d", name, CodeMaxLength)
		}
	}
	return o, assertGrantFieldsAreAdditional(o.Grant)
}

var baseDeviceCodeFields = []string{"deviceCode", "userCode", "userId", "expiresAt", "status",
	"lastPolledAt", "pollingInterval", "clientId", "scope"}

func assertGrantFieldsAreAdditional(g *Grant) error {
	if g == nil {
		return nil
	}
	base := map[string]bool{}
	for _, f := range baseDeviceCodeFields {
		base[f] = true
	}
	var conflicts []string
	for _, f := range g.DeviceCodeSchemaFields {
		if base[f.Name] {
			conflicts = append(conflicts, f.Name)
		}
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("Device authorization grant fields must be additional and cannot redefine deviceCode fields: %s", strings.Join(conflicts, ", "))
	}
	request := map[string]bool{"client_id": true, "user_id": true, "scope": true}
	for _, f := range g.RequestSchemaFields {
		if request[f.Name] {
			conflicts = append(conflicts, f.Name)
		}
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("Device authorization grant request fields must be additional and cannot redefine request fields: %s", strings.Join(conflicts, ", "))
	}
	verification := map[string]bool{"user_code": true, "status": true, "client_id": true, "scope": true}
	keys := make([]string, 0, len(g.VerificationOpenAPIProperties))
	for k := range g.VerificationOpenAPIProperties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if verification[k] {
			conflicts = append(conflicts, k)
		}
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("Device authorization grant verification fields must be additional and cannot redefine response fields: %s", strings.Join(conflicts, ", "))
	}
	return nil
}

// Schema returns the plugin schema (the deviceCode table plus grant fields, with the
// schema option applied).
func Schema(o Options) []db.PluginTable {
	var mo ModelOptions
	if o.Schema != nil {
		mo = o.Schema.DeviceCode
	}
	col := func(name string) string { return mo.Fields[name] }
	fields := []db.Field{
		{Name: "deviceCode", Type: db.TypeString, Required: db.True},
		{Name: "userCode", Type: db.TypeString, Required: db.True},
		{Name: "userId", Type: db.TypeString, Required: db.False},
		{Name: "expiresAt", Type: db.TypeDate, Required: db.True},
		{Name: "status", Type: db.TypeString, Required: db.True},
		{Name: "lastPolledAt", Type: db.TypeDate, Required: db.False},
		{Name: "pollingInterval", Type: db.TypeNumber, Required: db.False},
		{Name: "clientId", Type: db.TypeString, Required: db.False},
		{Name: "scope", Type: db.TypeString, Required: db.False},
	}
	if o.Grant != nil {
		fields = append(fields, o.Grant.DeviceCodeSchemaFields...)
	}
	for i := range fields {
		if c := col(fields[i].Name); c != "" {
			fields[i].FieldName = c
		}
	}
	return []db.PluginTable{{
		Key: "deviceCode", ModelName: mo.ModelName, Fields: fields,
		Indexes: []db.Index{{Fields: []string{"deviceCode"}, Unique: true}, {Fields: []string{"userCode"}, Unique: true}},
	}}
}

// New creates the device-authorization plugin. Invalid options make betterauth.New fail.
func New(options Options) *betterauth.Plugin {
	opts, optErr := ParseOptions(options)
	if optErr != nil {
		// keep the plugin constructible; the error surfaces from betterauth.New
		opts.ExpiresIn, opts.Interval = defaultExpiresIn, defaultInterval
	}
	expiresMs, _ := ParseTimeString(opts.ExpiresIn)
	p := &betterauth.Plugin{
		ID:      "device-authorization",
		Version: betterauth.Version,
		Schema:  Schema(opts),
		Endpoints: []*betterauth.Endpoint{
			deviceCodeEndpoint(opts),
			deviceTokenEndpoint(opts),
			deviceVerifyEndpoint(opts),
			deviceApproveEndpoint(),
			deviceDenyEndpoint(),
		},
		RateLimit: []betterauth.PluginRateLimit{{
			Window:      msDuration(expiresMs),
			Max:         5,
			PathMatcher: func(path string) bool { return path == "/device" },
		}},
		ErrorCodes: ErrorCodes,
		Options:    opts,
	}
	if optErr != nil {
		p.Init = func(*betterauth.AuthContext) (*betterauth.PluginInit, error) { return nil, optErr }
	}
	return p
}
