package oauthprovider

import (
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Port of packages/oauth-provider/src/oauth-endpoint.ts: OAuth endpoints report request
// validation failures as RFC 6749 errors ({error, error_description}) instead of
// better-call VALIDATION_ERROR bodies.

// fieldErrorCodes maps a body field to the OAuth error code used when it is missing or
// invalid (OAuthFieldErrorCodeMap); All applies to every issue of the field.
type fieldErrorCodes struct {
	All     string
	Missing string
	Invalid string
}

// oauthErr builds the RFC 6749 error APIError: {error, error_description}.
func oauthErr(status, code, description string) *betterauth.APIError {
	return betterauth.NewAPIError(status, jsonx.O("error", code, "error_description", description))
}

// apiErr is new APIError(status) without a body.
func apiErr(status string) *betterauth.APIError { return betterauth.ErrStatus(status) }

// errorBodyString reads a string field of an APIError body.
func errorBodyString(e *betterauth.APIError, key string) string {
	if e == nil || e.Body == nil {
		return ""
	}
	v, _ := e.Body.Get(key)
	s, _ := v.(string)
	return s
}

func isMissingValueIssue(is zIssue) bool {
	return is.Code == "invalid_type" && strings.HasSuffix(is.Message, "received undefined")
}

// mapIssuesToOAuthError is mapIssuesToOAuthError.
func mapIssuesToOAuthError(issues []zIssue, byField map[string]fieldErrorCodes, defaultError string) (string, string) {
	if defaultError == "" {
		defaultError = "invalid_request"
	}
	if len(issues) == 0 {
		return defaultError, "Invalid request."
	}
	is := issues[0]
	var mapping *fieldErrorCodes
	if len(is.Path) > 0 {
		if k, ok := is.Path[0].(string); ok {
			if m, ok := byField[k]; ok {
				mapping = &m
			}
		}
	}
	field := ""
	if len(is.Path) > 0 {
		field = toDotPath(is.Path)
	}
	code := defaultError
	switch {
	case mapping != nil && mapping.All != "":
		code = mapping.All
	case isMissingValueIssue(is):
		if mapping != nil && mapping.Missing != "" {
			code = mapping.Missing
		}
	case is.Code == "invalid_value":
		if mapping != nil && mapping.Invalid != "" {
			code = mapping.Invalid
		}
	}
	return code, describeIssue(is, field)
}

func describeIssue(is zIssue, field string) string {
	if field == "" {
		return is.Message
	}
	if is.Code == "invalid_type" {
		if strings.HasSuffix(is.Message, "received undefined") {
			return field + " is required"
		}
		if strings.HasSuffix(is.Message, "received array") {
			return field + " must not appear more than once"
		}
		expected := is.Expected
		if expected == "" {
			expected = "valid value"
		}
		return field + " must be a " + expected
	}
	if is.Code == "invalid_value" && len(is.Values) > 0 {
		return field + " must be one of: " + strings.Join(is.Values, ", ")
	}
	return field + ": " + is.Message
}

// bodyValue returns the endpoint body as a value for validation (undefined when absent).
func bodyValue(ctx *betterauth.EndpointContext) any {
	if ctx.Body == nil || isUndef(ctx.Body) {
		// better-call parses an empty urlencoded request body as {} on fetch runtimes (a
		// Request with a non-null body stream), which upstream's tests pin. The Node adapter
		// (toNodeHandler) passes no body instead; see COMPATIBILITY.md.
		if r := ctx.Request; r != nil && r.Body != nil && r.Method != "GET" && r.Method != "HEAD" &&
			strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
			return map[string]any{}
		}
		return validate.Undefined
	}
	return ctx.Body
}

// validateOAuthBody validates the body with s; failures become BAD_REQUEST OAuth errors
// (createOAuthEndpoint without redirectOnError). On success ctx.Body is replaced by the
// parsed value (a map) and the ordered object is returned.
func validateOAuthBody(ctx *betterauth.EndpointContext, s zSchema, byField map[string]fieldErrorCodes, defaultError string) (*jsonx.Object, error) {
	out, issues := zParse(s, bodyValue(ctx))
	if len(issues) > 0 {
		code, desc := mapIssuesToOAuthError(issues, byField, defaultError)
		return nil, oauthErr("BAD_REQUEST", code, desc)
	}
	o, _ := out.(*jsonx.Object)
	if o != nil {
		ctx.Body = objectToMap(o)
	} else if isUndef(out) {
		ctx.Body = validate.Undefined
	}
	return o, nil
}

// validateOAuthQuery is validateOAuthBody for the query.
func validateOAuthQuery(ctx *betterauth.EndpointContext, s zSchema, byField map[string]fieldErrorCodes, defaultError string) (*jsonx.Object, error) {
	var q any = validate.Undefined
	if len(ctx.Query) > 0 || ctx.Request != nil {
		q = ctx.Query
	}
	out, issues := zParse(s, q)
	if len(issues) > 0 {
		code, desc := mapIssuesToOAuthError(issues, byField, defaultError)
		return nil, oauthErr("BAD_REQUEST", code, desc)
	}
	o, _ := out.(*jsonx.Object)
	if o != nil {
		ctx.Query = objectToMap(o)
	}
	return o, nil
}

// bodyMap returns the body as a map (empty when absent).
func bodyMap(ctx *betterauth.EndpointContext) map[string]any {
	if m, ok := ctx.Body.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func bodyStr(ctx *betterauth.EndpointContext, key string) string {
	s, _ := bodyMap(ctx)[key].(string)
	return s
}
