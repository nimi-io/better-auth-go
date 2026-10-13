package oauthprovider

import (
	"errors"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Exported validation helpers for companion packages (cimd, mcp).

// ValidationIssue is one schema validation issue (zod issue).
type ValidationIssue struct {
	Path    []any
	Code    string
	Message string
}

// ValidationError is returned by the Validate* helpers.
type ValidationError struct{ Issues []ValidationIssue }

func (e *ValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "invalid input"
	}
	return e.Issues[0].Message
}

func toValidationError(issues []zIssue) error {
	out := make([]ValidationIssue, len(issues))
	for i, is := range issues {
		out[i] = ValidationIssue{Path: is.Path, Code: is.Code, Message: is.Message}
	}
	return &ValidationError{Issues: out}
}

// ValidateClientMetadata parses a client metadata document (oauthClientMetadataSchema):
// RFC 7591 metadata plus client_id, unknown keys preserved.
func ValidateClientMetadata(v any) (*jsonx.Object, error) {
	out, issues := zParse(oauthClientMetadataSchema, v)
	if len(issues) > 0 {
		return nil, toValidationError(issues)
	}
	o, ok := out.(*jsonx.Object)
	if !ok {
		return nil, errors.New("invalid client metadata")
	}
	return o, nil
}

// ValidateResourceURI checks an RFC 8707 resource indicator (ResourceUriSchema).
func ValidateResourceURI(v string) error {
	if _, issues := zParse(resourceURI(), v); len(issues) > 0 {
		return toValidationError(issues)
	}
	return nil
}

// ValidateSafeURL checks a redirect URL (SafeUrlSchema).
func ValidateSafeURL(v string) error {
	if _, issues := zParse(safeURL(), v); len(issues) > 0 {
		return toValidationError(issues)
	}
	return nil
}
