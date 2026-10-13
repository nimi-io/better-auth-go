package scim

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// SCIM error types (RFC 7644 scimType).
const (
	errInvalidFilter = "invalidFilter"
	errTooMany       = "tooMany"
	errUniqueness    = "uniqueness"
	errMutability    = "mutability"
	errInvalidSyntax = "invalidSyntax"
	errInvalidPath   = "invalidPath"
	errNoTarget      = "noTarget"
	errInvalidValue  = "invalidValue"
)

// NewError is createSCIMError: an APIError whose body is a SCIM Error message. status is
// a better-call status name ("BAD_REQUEST"); scimType may be empty.
func NewError(status, detail, scimType string) *betterauth.APIError {
	return newSCIMError(status, &detail, scimType)
}

func newSCIMError(status string, detail *string, scimType string) *betterauth.APIError {
	code, ok := betterauth.StatusCodes[status]
	if !ok {
		code = 500
	}
	body := jsonx.O("schemas", []any{SchemaError}, "status", strconv.Itoa(code))
	if detail != nil {
		body.Set("detail", *detail)
	}
	if scimType != "" {
		body.Set("scimType", scimType)
	}
	return betterauth.NewAPIError(status, body)
}

func scimErr(status, detail string, scimType ...string) *betterauth.APIError {
	t := ""
	if len(scimType) > 0 {
		t = scimType[0]
	}
	return NewError(status, detail, t)
}

// isSCIMErrorBody reports whether body.schemas contains the SCIM Error schema.
func isSCIMErrorBody(body *jsonx.Object) bool {
	if body == nil {
		return false
	}
	return containsAny(getArr(body, "schemas"), SchemaError)
}

// isUniquenessError is isSCIMUniquenessError.
func isUniquenessError(err error) bool {
	e, ok := betterauth.AsAPIError(err)
	if !ok || e.Body == nil {
		return false
	}
	return getStr(e.Body, "status") == "409" && getStr(e.Body, "scimType") == errUniqueness
}

// betterAuthError is a BetterAuthError (rendered as a 500 by the router).
type betterAuthError struct {
	msg  string
	kind conflictKind
}

func (e *betterAuthError) Error() string { return e.msg }

type conflictKind int

const (
	conflictNone conflictKind = iota
	conflictGroupMutation
	conflictProjectionSubject
)

func newBetterAuthError(msg string) error { return &betterAuthError{msg: msg} }

// identityConflict is an APIError tagged as an identity mutation conflict.
type identityConflict struct{ *betterauth.APIError }

func (e *identityConflict) Unwrap() error { return e.APIError }

func isIdentityConflict(err error) bool {
	var ic *identityConflict
	return errors.As(err, &ic)
}

func isConflictKind(err error, k conflictKind) bool {
	var be *betterAuthError
	return errors.As(err, &be) && be.kind == k
}

// applicationError wraps a non-API callback error (runSCIMApplicationCallback).
func runApplicationCallback(detail string, fn func() error) error {
	err := safeCall(fn)
	if err == nil {
		return nil
	}
	if _, ok := betterauth.AsAPIError(err); ok {
		return err
	}
	e := scimErr("INTERNAL_SERVER_ERROR", detail)
	e.Cause = err
	return e
}

// safeCall converts panics in application callbacks into errors.
func safeCall(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				return
			}
			err = errors.New(toString(r))
		}
	}()
	return fn()
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := jsonx.Marshal(v)
	return string(b)
}

func mustStringify(v any) string {
	s, err := jsonx.Stringify(v)
	if err != nil {
		panic(err)
	}
	return s
}

// parseJSON is JSON.parse: jsonx.Parse plus a strict check that nothing but whitespace
// follows the value (jsonx.Parse tolerates trailing non-JSON text).
func parseJSON(data []byte) (any, error) {
	v, err := jsonx.Parse(data)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var discard json.RawMessage
	if err := dec.Decode(&discard); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after JSON value")
	}
	return v, nil
}
