package deviceauthorization

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Port of packages/better-auth/src/plugins/device-authorization/routes.ts.

const defaultCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

const maxDeviceCodeGenerationAttempts = 3

// openAPIBodySchemaKey documents a body validated inside the handler (see
// plugins/openapi BodySchemaMetadataKey).
const openAPIBodySchemaKey = "openapiBodySchema"

func oauthError(status, code, description string) *betterauth.APIError {
	return betterauth.NewAPIError(status, jsonx.O("error", code, "error_description", description))
}

var uniqueIdentifiers = map[string]bool{
	"11000": true, "1062": true, "2067": true, "23505": true, "2601": true, "2627": true,
	"ER_DUP_ENTRY": true, "P2002": true, "SQLITE_CONSTRAINT_UNIQUE": true,
}

var uniqueMessageRe = regexp.MustCompile(`(?i)unique(?: key)? constraint|duplicate (?:entry|key)|e11000`)

// isUniqueConstraintError inspects the error chain for database unique-violation
// identifiers (code / errcode / errno / number fields, SQLSTATE) or messages.
func isUniqueConstraintError(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := e.(interface{ SQLState() string }); ok && uniqueIdentifiers[s.SQLState()] {
			return true
		}
		v := reflect.ValueOf(e)
		for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			if v.IsNil() {
				break
			}
			v = v.Elem()
		}
		if v.Kind() == reflect.Struct {
			t := v.Type()
			for i := 0; i < t.NumField(); i++ {
				switch strings.ToLower(t.Field(i).Name) {
				case "code", "errcode", "errno", "number":
					f := v.Field(i)
					if f.CanInterface() && uniqueIdentifiers[fmt.Sprint(f.Interface())] {
						return true
					}
				}
			}
		}
		if uniqueMessageRe.MatchString(e.Error()) {
			return true
		}
	}
	return false
}

var defaultUserCodePattern = regexp.MustCompile(`(?i)^[` + defaultCharset + `]+$`)
var nonAlnum = regexp.MustCompile(`[^a-zA-Z0-9]`)

func validateGeneratedCode(code, label string) error {
	if utf8.RuneCountInString(code) > CodeMaxLength {
		return oauthError("BAD_REQUEST", "invalid_request",
			fmt.Sprintf("Generated %s code must be at most %d characters", label, CodeMaxLength))
	}
	return nil
}

func normalizeUserCode(code string) string {
	return strings.ToUpper(nonAlnum.ReplaceAllString(code, ""))
}

func str(v any) string { s, _ := v.(string); return s }

func findDeviceCodeByUserCode(ctx *betterauth.EndpointContext, userCode string) (adapter.Record, error) {
	find := func(value string) (adapter.Record, error) {
		rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{
			Model: "deviceCode", Where: []adapter.Where{{Field: "userCode", Value: value}}})
		if err != nil || rec == nil {
			return nil, err
		}
		if str(rec["userCode"]) != value {
			return nil, nil
		}
		return rec, nil
	}
	exact, err := find(userCode)
	if err != nil || exact != nil {
		return exact, err
	}
	normalized := normalizeUserCode(userCode)
	if normalized == userCode || !defaultUserCodePattern.MatchString(normalized) {
		return nil, nil
	}
	return find(normalized)
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case int32:
		return float64(t), true
	}
	return 0, false
}

func expired(rec adapter.Record) bool {
	t, ok := adapter.ToTime(rec["expiresAt"])
	return ok && t.Before(time.Now())
}

// ---- schemas & OpenAPI documentation ----

func describedString(desc string) validate.Schema { return validate.Describe(validate.String(), desc) }

func errorResponse(description string, codes []string) *jsonx.Object {
	enum := make([]any, len(codes))
	for i, c := range codes {
		enum[i] = c
	}
	return jsonx.O("description", description, "content", jsonx.O("application/json", jsonx.O("schema",
		jsonx.O("type", "object", "properties", jsonx.O(
			"error", jsonx.O("type", "string", "enum", enum),
			"error_description", jsonx.O("type", "string"),
		)))))
}

func successResponse() *jsonx.Object {
	return jsonx.O("200", jsonx.O("description", "Success", "content", jsonx.O("application/json", jsonx.O("schema",
		jsonx.O("type", "object", "properties", jsonx.O("success", jsonx.O("type", "boolean")))))))
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var deviceCodeBaseErrorCodes = []string{"invalid_request", "invalid_client", "unauthorized_client", "invalid_scope"}

func deviceCodeBodySchema(g *Grant) validate.Schema {
	clientID := describedString("The client ID of the application")
	if g != nil {
		clientID = validate.Optional(validate.String())
	}
	fields := []validate.Field{
		validate.F("client_id", clientID),
		validate.F("user_id", validate.Optional(describedString("The user ID to which the device code should be pre-bound."))),
		validate.F("scope", validate.Optional(describedString("Space-separated list of scopes"))),
	}
	if g != nil {
		fields = append(fields, g.RequestSchemaFields...)
	}
	return validate.Object(fields...)
}

// ---- verification URIs (buildVerificationUris) ----

// formEncode is the application/x-www-form-urlencoded serializer (URLSearchParams).
func formEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '*', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

func formDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

func buildVerificationURIs(verificationURI, baseURL, userCode string) (string, string, error) {
	uri := verificationURI
	if uri == "" {
		uri = "/device"
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" {
		base, berr := url.Parse(baseURL)
		if berr != nil {
			return "", "", berr
		}
		ref, rerr := url.Parse(uri)
		if rerr != nil {
			return "", "", rerr
		}
		u = base.ResolveReference(ref)
	}
	if u.Path == "" && (u.Scheme == "http" || u.Scheme == "https") {
		u.Path = "/"
	}
	verification := u.String()
	type pair struct{ k, v string }
	var pairs []pair
	for _, part := range strings.Split(u.RawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		pairs = append(pairs, pair{formDecode(k), formDecode(v)})
	}
	var out []pair
	set := false
	for _, p := range pairs {
		if p.k == "user_code" {
			if !set {
				out = append(out, pair{"user_code", userCode})
				set = true
			}
			continue
		}
		out = append(out, p)
	}
	if !set {
		out = append(out, pair{"user_code", userCode})
	}
	parts := make([]string, len(out))
	for i, p := range out {
		parts[i] = formEncode(p.k) + "=" + formEncode(p.v)
	}
	c := *u
	c.RawQuery = strings.Join(parts, "&")
	c.ForceQuery = false
	return verification, c.String(), nil
}

func defaultGenerateUserCode(length int) string {
	buf := make([]byte, length)
	_, _ = rand.Read(buf)
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = defaultCharset[int(b)%len(defaultCharset)]
	}
	return string(out)
}

// normalizeBaseRequestParameters treats empty base parameters as omitted and, for form
// bodies, rejects repeated non-empty values.
func normalizeBaseRequestParameters(ctx *betterauth.EndpointContext, body map[string]any) error {
	fields := []string{"client_id", "user_id", "scope"}
	for _, f := range fields {
		if s, ok := body[f].(string); ok && s == "" {
			delete(body, f)
		}
	}
	r := ctx.Request
	if r == nil || !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") || r.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	values := map[string][]string{}
	for _, part := range strings.Split(string(raw), "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k = formDecode(k)
		values[k] = append(values[k], formDecode(v))
	}
	for _, f := range fields {
		var effective []string
		for _, v := range values[f] {
			if v != "" {
				effective = append(effective, v)
			}
		}
		switch len(effective) {
		case 0:
			delete(body, f)
		case 1:
			body[f] = effective[0]
		default:
			return oauthError("BAD_REQUEST", "invalid_request", f+" must not be repeated")
		}
	}
	return nil
}

// ---- POST /device/code ----

func deviceCodeEndpoint(opts Options) *betterauth.Endpoint {
	g := opts.Grant
	body := deviceCodeBodySchema(g)
	requestErrorCodes := append([]string(nil), deviceCodeBaseErrorCodes...)
	responses := jsonx.NewObject()
	if g != nil {
		requestErrorCodes = append(requestErrorCodes, g.RequestErrorCodes...)
		for _, k := range sortedKeys(g.RequestOpenAPIResponses) {
			responses.Set(k, g.RequestOpenAPIResponses[k])
		}
	}
	responses.Set("200", jsonx.O("description", "Success", "content", jsonx.O("application/json", jsonx.O("schema",
		jsonx.O("type", "object", "properties", jsonx.O(
			"device_code", jsonx.O("type", "string", "description", "The device verification code"),
			"user_code", jsonx.O("type", "string", "description", "The user code to display"),
			"verification_uri", jsonx.O("type", "string", "format", "uri", "description", "The URL for user verification. Defaults to /device if not configured."),
			"verification_uri_complete", jsonx.O("type", "string", "format", "uri", "description", "The complete URL with user code as query parameter."),
			"expires_in", jsonx.O("type", "number", "description", "Lifetime in seconds of the device code"),
			"interval", jsonx.O("type", "number", "description", "Minimum polling interval in seconds"),
		))))))
	responses.Set("400", errorResponse("Error response", requestErrorCodes))
	responses.Set("500", errorResponse("Server error", []string{"server_error"}))

	expiresMs, _ := ParseTimeString(opts.ExpiresIn)
	intervalMs, _ := ParseTimeString(opts.Interval)

	generateDeviceCode := func(c context.Context) (string, error) {
		var code string
		if opts.GenerateDeviceCode != nil {
			var err error
			if code, err = opts.GenerateDeviceCode(c); err != nil {
				return "", err
			}
		} else {
			code = bacrypto.RandomStringFrom(opts.DeviceCodeLength, bacrypto.AlphaLower, bacrypto.AlphaUpper, bacrypto.Digits)
		}
		return code, validateGeneratedCode(code, "device")
	}
	generateUserCode := func(c context.Context) (string, error) {
		var code string
		if opts.GenerateUserCode != nil {
			var err error
			if code, err = opts.GenerateUserCode(c); err != nil {
				return "", err
			}
		} else {
			code = defaultGenerateUserCode(opts.UserCodeLength)
		}
		return code, validateGeneratedCode(code, "user")
	}

	return &betterauth.Endpoint{
		Key: "deviceCode", Path: "/device/code", Methods: []string{"POST"},
		NoStore:           true,
		AllowedMediaTypes: []string{"application/json", "application/x-www-form-urlencoded"},
		Metadata: map[string]any{
			openAPIBodySchemaKey: body,
			"openapi": jsonx.O(
				"description", "Request a device and user code\n\nFollow [rfc8628#section-3.2](https://datatracker.ietf.org/doc/html/rfc8628#section-3.2)",
				"responses", responses,
			),
		},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			// The body is validated here so validation errors use the OAuth error format
			// (onValidationError upstream).
			out, issues := validate.Validate(body, ctx.Body)
			if len(issues) > 0 {
				if g != nil && g.OnRequestValidationError != nil {
					if err := g.OnRequestValidationError(issues); err != nil {
						return nil, err
					}
				}
				return nil, oauthError("BAD_REQUEST", "invalid_request", validate.FormatIssues(issues, "body"))
			}
			request, _ := out.(map[string]any)
			if request == nil {
				request = map[string]any{}
			}
			ctx.Body = request
			if err := normalizeBaseRequestParameters(ctx, request); err != nil {
				return nil, err
			}
			var grantAuth *GrantAuthorization
			if g != nil && g.AuthorizeRequest != nil {
				a, err := g.AuthorizeRequest(ctx, request)
				if err != nil {
					return nil, err
				}
				grantAuth = a
			}
			clientID := str(request["client_id"])
			if grantAuth != nil {
				clientID = grantAuth.ClientID
			}
			if grantAuth == nil {
				if str(request["client_id"]) == "" {
					return nil, oauthError("BAD_REQUEST", "invalid_request", "client_id is required")
				}
				if opts.ValidateClient == nil {
					if g != nil {
						return nil, oauthError("BAD_REQUEST", "invalid_client", "Invalid client ID")
					}
				} else {
					ok, err := opts.ValidateClient(ctx.Context(), str(request["client_id"]))
					if err != nil {
						return nil, err
					}
					if !ok {
						return nil, oauthError("BAD_REQUEST", "invalid_client", "Invalid client ID")
					}
				}
			}
			if clientID == "" {
				return nil, oauthError("BAD_REQUEST", "invalid_request", "client_id is required")
			}
			var scope *string
			if s, ok := request["scope"].(string); ok {
				scope = &s
			}
			if opts.OnDeviceAuthRequest != nil {
				if err := opts.OnDeviceAuthRequest(ctx.Context(), clientID, scope); err != nil {
					return nil, err
				}
			}
			expiresAt := time.Now().Add(msDuration(expiresMs))
			for attempt := 0; attempt < maxDeviceCodeGenerationAttempts; attempt++ {
				deviceCode, err := generateDeviceCode(ctx.Context())
				if err != nil {
					return nil, err
				}
				userCode, err := generateUserCode(ctx.Context())
				if err != nil {
					return nil, err
				}
				data := adapter.Record{}
				if grantAuth != nil {
					for k, v := range grantAuth.DeviceCodeFields {
						data[k] = v
					}
				}
				var userID any
				if s := str(request["user_id"]); s != "" {
					userID = s // an empty user_id is treated as omitted (RFC 8628 section 3.1)
				}
				data["deviceCode"] = deviceCode
				data["userCode"] = userCode
				data["userId"] = userID
				data["expiresAt"] = expiresAt
				data["status"] = "pending"
				data["pollingInterval"] = intervalMs
				data["clientId"] = clientID
				if scope != nil {
					data["scope"] = *scope
				}
				if _, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: "deviceCode", Data: data}); err != nil {
					if !isUniqueConstraintError(err) {
						return nil, err
					}
					continue
				}
				vURI, vURIComplete, err := buildVerificationURIs(opts.VerificationURI, ctx.Auth.BaseURL, userCode)
				if err != nil {
					return nil, err
				}
				ctx.SetHeader("Cache-Control", "no-store")
				ctx.SetHeader("Pragma", "no-cache")
				return jsonx.O(
					"device_code", deviceCode,
					"user_code", userCode,
					"verification_uri", vURI,
					"verification_uri_complete", vURIComplete,
					"expires_in", int64(math.Floor(expiresMs/1000)),
					"interval", int64(math.Floor(intervalMs/1000)),
				), nil
			}
			return nil, oauthError("INTERNAL_SERVER_ERROR", "server_error", "Failed to generate a unique device code")
		},
	}
}

// ---- POST /device/token ----

// RedemptionAuthorization scopes a redemption (DeviceCodeRedemptionAuthorization).
type RedemptionAuthorization struct {
	// OwnershipWhere is added to the atomic claim of the approved code.
	OwnershipWhere adapter.Where
	Context        any
}

// RedeemInput is the input of RedeemDeviceCode.
type RedeemInput struct {
	DeviceCode          string
	AuthorizeRedemption func(deviceCode adapter.Record) (*RedemptionAuthorization, error)
	PrepareRedemption   func(deviceCode adapter.Record, authorizationContext any) (any, error)
}

// RedemptionResult is the result of RedeemDeviceCode (DeviceCodeRedemptionResult).
type RedemptionResult struct {
	ClaimedDeviceCode    adapter.Record
	AuthorizationContext any
	RedemptionContext    any
	User                 *betterauth.User
}

// RedeemDeviceCode runs the RFC 8628 polling checks for a device code and atomically
// claims it once approved (redeemDeviceCode upstream).
func RedeemDeviceCode(ctx *betterauth.EndpointContext, in RedeemInput) (*RedemptionResult, error) {
	ad := ctx.Auth.Adapter
	c := ctx.Context()
	rec, err := ad.FindOne(c, adapter.FindOneInput{Model: "deviceCode", Where: []adapter.Where{{Field: "deviceCode", Value: in.DeviceCode}}})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, oauthError("BAD_REQUEST", "invalid_grant", ErrInvalidDeviceCode.Message)
	}
	auth, err := in.AuthorizeRedemption(rec)
	if err != nil {
		return nil, err
	}
	if last, ok := adapter.ToTime(rec["lastPolledAt"]); ok && rec["lastPolledAt"] != nil {
		if interval, ok := toFloat(rec["pollingInterval"]); ok && interval != 0 {
			if float64(time.Since(last).Milliseconds()) < interval {
				return nil, oauthError("BAD_REQUEST", "slow_down", ErrPollingTooFrequently.Message)
			}
		}
	}
	id := rec["id"]
	byID := []adapter.Where{{Field: "id", Value: id}}
	if _, err := ad.Update(c, "deviceCode", byID, adapter.Record{"lastPolledAt": time.Now()}); err != nil {
		return nil, err
	}
	if expired(rec) {
		if err := ad.Delete(c, "deviceCode", byID); err != nil {
			return nil, err
		}
		return nil, oauthError("BAD_REQUEST", "expired_token", ErrExpiredDeviceCode.Message)
	}
	switch str(rec["status"]) {
	case "pending":
		return nil, oauthError("BAD_REQUEST", "authorization_pending", ErrAuthorizationPending.Message)
	case "denied":
		if err := ad.Delete(c, "deviceCode", byID); err != nil {
			return nil, err
		}
		return nil, oauthError("BAD_REQUEST", "access_denied", ErrAccessDenied.Message)
	}
	userID := str(rec["userId"])
	if str(rec["status"]) != "approved" || userID == "" {
		return nil, oauthError("INTERNAL_SERVER_ERROR", "server_error", ErrInvalidDeviceCodeStatus.Message)
	}
	var redemptionCtx any
	if in.PrepareRedemption != nil {
		if redemptionCtx, err = in.PrepareRedemption(rec, auth.Context); err != nil {
			return nil, err
		}
	}
	user, err := ctx.Auth.InternalAdapter.FindUserByID(c, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, oauthError("INTERNAL_SERVER_ERROR", "server_error", ErrUserNotFound.Message)
	}
	claimed, err := ad.ConsumeOne(c, "deviceCode", []adapter.Where{
		{Field: "id", Value: id}, auth.OwnershipWhere, {Field: "status", Value: "approved"},
	})
	if err != nil {
		return nil, err
	}
	if claimed == nil || str(claimed["userId"]) == "" {
		return nil, oauthError("BAD_REQUEST", "invalid_grant", ErrInvalidDeviceCode.Message)
	}
	return &RedemptionResult{ClaimedDeviceCode: claimed, AuthorizationContext: auth.Context, RedemptionContext: redemptionCtx, User: user}, nil
}

func deviceTokenEndpoint(opts Options) *betterauth.Endpoint {
	g := opts.Grant
	return &betterauth.Endpoint{
		Key: "deviceToken", Path: "/device/token", Methods: []string{"POST"},
		NoStore: true,
		Body: validate.Object(
			validate.F("grant_type", validate.Describe(validate.Literal("urn:ietf:params:oauth:grant-type:device_code"), "The grant type for device flow")),
			validate.F("device_code", describedString("The device verification code")),
			validate.F("client_id", describedString("The client ID of the application")),
		),
		Metadata: map[string]any{"openapi": jsonx.O(
			"description", "Exchange device code for access token\n\nFollow [rfc8628#section-3.4](https://datatracker.ietf.org/doc/html/rfc8628#section-3.4)",
			"responses", jsonx.O(
				"200", jsonx.O("description", "Success", "content", jsonx.O("application/json", jsonx.O("schema",
					jsonx.O("type", "object", "properties", jsonx.O(
						"session", jsonx.O("$ref", "#/components/schemas/Session"),
						"user", jsonx.O("$ref", "#/components/schemas/User"),
					))))),
				"400", errorResponse("Error response", []string{"authorization_pending", "slow_down", "expired_token", "access_denied", "invalid_request", "invalid_grant"}),
			),
		)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			deviceCode, clientID := ctx.BodyString("device_code"), ctx.BodyString("client_id")
			if opts.ValidateClient != nil {
				ok, err := opts.ValidateClient(ctx.Context(), clientID)
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, oauthError("BAD_REQUEST", "invalid_grant", "Invalid client ID")
				}
			}
			res, err := RedeemDeviceCode(ctx, RedeemInput{
				DeviceCode: deviceCode,
				AuthorizeRedemption: func(rec adapter.Record) (*RedemptionAuthorization, error) {
					if cid := str(rec["clientId"]); cid != "" && cid != clientID {
						return nil, oauthError("BAD_REQUEST", "invalid_grant", "Client ID mismatch")
					}
					if g != nil && g.AssertSessionRedemption != nil {
						if err := g.AssertSessionRedemption(ctx, rec); err != nil {
							return nil, err
						}
					}
					return &RedemptionAuthorization{OwnershipWhere: adapter.Where{Field: "clientId", Value: clientID}}, nil
				},
			})
			if err != nil {
				return nil, err
			}
			session, err := ctx.Auth.InternalAdapter.CreateSession(ctx.Context(), res.User.ID, nil)
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, oauthError("INTERNAL_SERVER_ERROR", "server_error", ErrFailedToCreateSession.Message)
			}
			ctx.SetNewSession(&betterauth.SessionWithUser{Session: session, User: res.User})
			if ctx.Auth.Options.SecondaryStorage != nil && ctx.Auth.SecondaryStorage != nil {
				payload, err := jsonx.Marshal(jsonx.O("user", res.User, "session", session))
				if err != nil {
					return nil, err
				}
				ttl := time.Duration(math.Floor(time.Until(session.ExpiresAt).Seconds())) * time.Second
				if err := ctx.Auth.SecondaryStorage.Set(ctx.Context(), session.Token, string(payload), ttl); err != nil {
					return nil, err
				}
			}
			ctx.SetHeader("Cache-Control", "no-store")
			ctx.SetHeader("Pragma", "no-cache")
			scope := str(res.ClaimedDeviceCode["scope"])
			return jsonx.O(
				"access_token", session.Token,
				"token_type", "Bearer",
				"expires_in", int64(math.Floor(time.Until(session.ExpiresAt).Seconds())),
				"scope", scope,
			), nil
		},
	}
}

// ---- GET /device ----

func deviceVerifyEndpoint(opts Options) *betterauth.Endpoint {
	g := opts.Grant
	props := jsonx.O(
		"user_code", jsonx.O("type", "string", "description", "The user code to verify"),
		"status", jsonx.O("type", "string", "enum", []any{"pending", "approved", "denied"}, "description", "Current status of the device authorization"),
		"client_id", jsonx.O("type", "string", "description", "The client requesting authorization, returned only to the authenticated user who owns this request"),
		"scope", jsonx.O("type", "string", "description", "The requested scopes, returned only to the authenticated user who owns this request"),
	)
	if g != nil {
		for _, k := range sortedKeys(g.VerificationOpenAPIProperties) {
			props.Set(k, g.VerificationOpenAPIProperties[k])
		}
	}
	return &betterauth.Endpoint{
		Key: "deviceVerify", Path: "/device", Methods: []string{"GET"},
		Query: validate.Object(validate.F("user_code", describedString("The user code to verify"))),
		Metadata: map[string]any{"openapi": jsonx.O(
			"description", "Verify user code and get device authorization status",
			"responses", jsonx.O("200", jsonx.O("description", "Device authorization status", "content",
				jsonx.O("application/json", jsonx.O("schema", jsonx.O("type", "object", "properties", props))))),
		)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			userCode := ctx.QueryString("user_code")
			rec, err := findDeviceCodeByUserCode(ctx, userCode)
			if err != nil {
				return nil, err
			}
			if rec == nil {
				return nil, oauthError("BAD_REQUEST", "invalid_request", ErrInvalidUserCode.Message)
			}
			if expired(rec) {
				return nil, oauthError("BAD_REQUEST", "expired_token", ErrExpiredUserCode.Message)
			}
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			var sessionUserID string
			if session != nil && session.User != nil {
				sessionUserID = session.User.ID
			}
			if sessionUserID != "" && str(rec["userId"]) == "" && str(rec["status"]) == "pending" {
				claimed, err := ctx.Auth.Adapter.IncrementOne(ctx.Context(), adapter.IncrementInput{
					Model: "deviceCode",
					Where: []adapter.Where{
						{Field: "id", Value: rec["id"]},
						{Field: "status", Value: "pending"},
						{Field: "userId", Operator: adapter.Eq, Value: nil},
					},
					Increment: map[string]float64{},
					Set:       adapter.Record{"userId": sessionUserID},
				})
				if err != nil {
					return nil, err
				}
				if claimed != nil {
					rec["userId"] = sessionUserID
				}
			}
			canReview := session != nil && session.User != nil && str(rec["userId"]) == sessionUserID
			res := jsonx.NewObject()
			if canReview && g != nil && g.GetVerificationContext != nil {
				extra := g.GetVerificationContext(rec)
				for _, k := range sortedKeys(extra) {
					res.Set(k, extra[k])
				}
			}
			res.Set("user_code", userCode)
			res.Set("status", rec["status"])
			if canReview {
				res.Set("client_id", rec["clientId"])
				res.Set("scope", rec["scope"])
			}
			return res, nil
		},
	}
}

// ---- POST /device/approve, /device/deny ----

func decisionEndpoint(key, path, verb, status string) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: key, Path: path, Methods: []string{"POST"},
		RequireHeaders: true,
		Body:           validate.Object(validate.F("userCode", describedString("The user code to "+verb))),
		Metadata: map[string]any{"openapi": jsonx.O(
			"description", strings.ToUpper(verb[:1])+verb[1:]+" device authorization",
			"responses", successResponse(),
		)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			session, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if session == nil || session.User == nil {
				return nil, oauthError("UNAUTHORIZED", "unauthorized", ErrAuthenticationRequired.Message)
			}
			rec, err := findDeviceCodeByUserCode(ctx, ctx.BodyString("userCode"))
			if err != nil {
				return nil, err
			}
			if rec == nil {
				return nil, oauthError("BAD_REQUEST", "invalid_request", ErrInvalidUserCode.Message)
			}
			if expired(rec) {
				return nil, oauthError("BAD_REQUEST", "expired_token", ErrExpiredUserCode.Message)
			}
			if str(rec["status"]) != "pending" {
				return nil, oauthError("BAD_REQUEST", "invalid_request", ErrDeviceCodeAlreadyProcessed.Message)
			}
			if str(rec["userId"]) == "" {
				return nil, oauthError("BAD_REQUEST", "invalid_request", ErrDeviceCodeNotClaimed.Message)
			}
			if str(rec["userId"]) != session.User.ID {
				return nil, oauthError("FORBIDDEN", "access_denied", "You are not authorized to "+verb+" this device authorization")
			}
			if _, err := ctx.Auth.Adapter.Update(ctx.Context(), "deviceCode", []adapter.Where{{Field: "id", Value: rec["id"]}},
				adapter.Record{"status": status, "userId": session.User.ID}); err != nil {
				return nil, err
			}
			return jsonx.O("success", true), nil
		},
	}
}

func deviceApproveEndpoint() *betterauth.Endpoint {
	return decisionEndpoint("deviceApprove", "/device/approve", "approve", "approved")
}

func deviceDenyEndpoint() *betterauth.Endpoint {
	return decisionEndpoint("deviceDeny", "/device/deny", "deny", "denied")
}
