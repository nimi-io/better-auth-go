package oauthprovider

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// A small zod v4 subset with the exact issue codes, messages and abort semantics the
// OAuth endpoints rely on (types/zod.ts, claims-request.ts, oauth-endpoint.ts map these
// issues to OAuth errors, so issue details matter beyond the message text).

type zIssue struct {
	Path     []any
	Code     string
	Message  string
	Expected string
	Values   []string
	// Continue is false for aborting issues (zod's `continue !== true`).
	Continue bool
}

type zSchema func(v any, path []any) (any, []zIssue)

var undef = validate.Undefined

func isUndef(v any) bool { return validate.IsUndefined(v) }

func zPath(path []any, seg any) []any {
	out := make([]any, len(path)+1)
	copy(out, path)
	out[len(path)] = seg
	return out
}

func zTypeName(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		if math.IsNaN(t) {
			return "NaN"
		}
		return "number"
	case int, int64:
		return "number"
	case []any, []string:
		return "array"
	case map[string]any, *jsonx.Object:
		return "object"
	}
	if isUndef(v) {
		return "undefined"
	}
	return "object"
}

func typeIssue(path []any, expected string, v any) []zIssue {
	return []zIssue{{Path: path, Code: "invalid_type", Expected: expected,
		Message: "Invalid input: expected " + expected + ", received " + zTypeName(v)}}
}

func aborted(issues []zIssue) bool {
	for _, is := range issues {
		if !is.Continue {
			return true
		}
	}
	return false
}

// ---- strings ----

type strCheck func(s string, path []any) []zIssue

func zString(checks ...strCheck) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		s, ok := v.(string)
		if !ok {
			return nil, typeIssue(path, "string", v)
		}
		var issues []zIssue
		for _, c := range checks {
			if aborted(issues) {
				break
			}
			is := c(s, path)
			if len(is) == 1 && is[0].Code == "__transform" {
				s = is[0].Message
				continue
			}
			issues = append(issues, is...)
		}
		if len(issues) > 0 {
			return nil, issues
		}
		return s, nil
	}
}

func jsLength(s string) int { return len(utf16Units(s)) }

func minLen(n int, msg string) strCheck {
	return func(s string, path []any) []zIssue {
		if jsLength(s) >= n {
			return nil
		}
		if msg == "" {
			msg = fmt.Sprintf("Too small: expected string to have >=%d characters", n)
		}
		return []zIssue{{Path: path, Code: "too_small", Message: msg, Continue: true}}
	}
}

// trimCheck is .trim() (a transform applied before later checks).
func trimCheck() strCheck {
	return func(s string, _ []any) []zIssue {
		return []zIssue{{Code: "__transform", Message: strings.TrimSpace(s)}}
	}
}

func regexCheck(re *regexp.Regexp, msg string) strCheck {
	return func(s string, path []any) []zIssue {
		if re.MatchString(s) {
			return nil
		}
		return []zIssue{{Path: path, Code: "invalid_format", Message: msg, Continue: true}}
	}
}

func refineCheck(fn func(string) bool, msg string) strCheck {
	return func(s string, path []any) []zIssue {
		if fn(s) {
			return nil
		}
		return []zIssue{{Path: path, Code: "custom", Message: msg, Continue: true}}
	}
}

// urlCheck is z.url(): the trimmed value must parse (tabs/newlines are stripped).
func urlCheck() strCheck {
	return func(s string, path []any) []zIssue {
		t := strings.TrimSpace(s)
		if !canParseURL(t) {
			return []zIssue{{Path: path, Code: "invalid_format", Message: "Invalid URL", Continue: true}}
		}
		t = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(t)
		return []zIssue{{Code: "__transform", Message: t}}
	}
}

var dangerousSchemes = []string{"javascript:", "data:", "vbscript:"}

// safeURL is SafeUrlSchema (core/utils/redirect-uri.ts).
func safeURL() zSchema {
	return zString(urlCheck(), func(s string, path []any) []zIssue {
		u, err := parseURL(s)
		if err != nil {
			return []zIssue{{Path: path, Code: "custom", Message: "URL must be parseable"}}
		}
		if contains(dangerousSchemes, u.Scheme+":") {
			return []zIssue{{Path: path, Code: "custom", Message: "URL cannot use javascript:, data:, or vbscript: scheme", Continue: true}}
		}
		var issues []zIssue
		if strings.Contains(s, "#") {
			issues = append(issues, zIssue{Path: path, Code: "custom", Message: "Redirect URI must not contain a fragment component", Continue: true})
		}
		if u.Scheme == "http" && !isLoopbackHost(u.Host) {
			issues = append(issues, zIssue{Path: path, Code: "custom", Message: "Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)", Continue: true})
		}
		return issues
	})
}

// resourceURI is ResourceUriSchema.
func resourceURI() zSchema {
	return zString(func(s string, path []any) []zIssue {
		if !canParseURL(s) {
			return []zIssue{{Path: path, Code: "custom", Message: "resource must be an absolute URI"}}
		}
		if strings.Contains(s, "#") {
			return []zIssue{{Path: path, Code: "custom", Message: "resource must not contain a fragment", Continue: true}}
		}
		u, _ := parseURL(s)
		if contains(dangerousSchemes, u.Scheme+":") {
			return []zIssue{{Path: path, Code: "custom", Message: "resource cannot use javascript:, data:, or vbscript: scheme", Continue: true}}
		}
		return nil
	})
}

// ---- other primitives ----

func zBool() zSchema {
	return func(v any, path []any) (any, []zIssue) {
		b, ok := v.(bool)
		if !ok {
			return nil, typeIssue(path, "boolean", v)
		}
		return b, nil
	}
}

func zUnknown() zSchema { return func(v any, _ []any) (any, []zIssue) { return v, nil } }

func toNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, !math.IsNaN(t)
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}

// zNumber is z.number() with optional .int(), .positive() and .nonnegative().
func zNumber(integer, positive, nonnegative bool) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		f, ok := toNumber(v)
		if !ok {
			return nil, typeIssue(path, "number", v)
		}
		if integer && (f != math.Trunc(f) || math.IsInf(f, 0) || math.Abs(f) > 9007199254740991) {
			return nil, []zIssue{{Path: path, Code: "invalid_type", Expected: "int", Message: "Invalid input: expected int, received number"}}
		}
		if positive && f <= 0 {
			return nil, []zIssue{{Path: path, Code: "too_small", Message: "Too small: expected number to be >0", Continue: true}}
		}
		if nonnegative && f < 0 {
			return nil, []zIssue{{Path: path, Code: "too_small", Message: "Too small: expected number to be >=0", Continue: true}}
		}
		return f, nil
	}
}

func zEnum(values ...string) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		if s, ok := v.(string); ok && contains(values, s) {
			return s, nil
		}
		return nil, []zIssue{enumIssue(path, values)}
	}
}

func enumIssue(path []any, values []string) zIssue {
	quoted := make([]string, len(values))
	for i, x := range values {
		quoted[i] = `"` + x + `"`
	}
	msg := "Invalid option: expected one of " + strings.Join(quoted, "|")
	if len(values) == 1 {
		msg = "Invalid input: expected " + quoted[0]
	}
	return zIssue{Path: path, Code: "invalid_value", Values: values, Message: msg}
}

// zLiteral is z.literal(value) for strings.
func zLiteral(value string) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		if s, ok := v.(string); ok && s == value {
			return s, nil
		}
		return nil, []zIssue{{Path: path, Code: "invalid_value", Values: []string{value}, Message: `Invalid input: expected "` + value + `"`}}
	}
}

// zStringEnum is z.string().pipe(z.enum(values)).
func zStringEnum(values ...string) zSchema {
	return zPipe(zString(), zEnum(values...))
}

func zPipe(a, b zSchema) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		out, issues := a(v, path)
		if len(issues) > 0 {
			return nil, issues
		}
		return b(out, path)
	}
}

func zNever(msg string) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		if msg == "" {
			msg = "Invalid input: expected never, received " + zTypeName(v)
		}
		return nil, []zIssue{{Path: path, Code: "invalid_type", Expected: "never", Message: msg}}
	}
}

func zOptional(s zSchema) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		if isUndef(v) {
			return undef, nil
		}
		return s(v, path)
	}
}

func zNullable(s zSchema) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		if v == nil {
			return nil, nil
		}
		return s(v, path)
	}
}

func zDefault(s zSchema, def any) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		if isUndef(v) {
			return def, nil
		}
		return s(v, path)
	}
}

func asArray(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

func zArray(item zSchema, minItems int) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		arr, ok := asArray(v)
		if !ok {
			return nil, typeIssue(path, "array", v)
		}
		out := make([]any, len(arr))
		var issues []zIssue
		for i, x := range arr {
			o, is := item(x, zPath(path, i))
			issues = append(issues, is...)
			out[i] = o
		}
		if !aborted(issues) && minItems > 0 && len(arr) < minItems {
			issues = append(issues, zIssue{Path: path, Code: "too_small", Continue: true,
				Message: fmt.Sprintf("Too small: expected array to have >=%d items", minItems)})
		}
		if len(issues) > 0 {
			return nil, issues
		}
		return out, nil
	}
}

func zRecord(value zSchema) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		o := asObject(v)
		if o == nil {
			return nil, typeIssue(path, "record", v)
		}
		out := jsonx.NewObject()
		var issues []zIssue
		for _, k := range o.Keys() {
			x, _ := o.Get(k)
			r, is := value(x, zPath(path, k))
			issues = append(issues, is...)
			out.Set(k, r)
		}
		if len(issues) > 0 {
			return nil, issues
		}
		return out, nil
	}
}

// asObject returns v as an ordered object (nil for non-objects). Go maps are ordered by
// key.
func asObject(v any) *jsonx.Object {
	switch t := v.(type) {
	case *jsonx.Object:
		return t
	case map[string]any:
		return toObject(t)
	}
	return nil
}

type zField struct {
	name   string
	schema zSchema
}

func zf(name string, s zSchema) zField { return zField{name, s} }

// zObject is z.object(...) (mode "strip") or .passthrough() / z.looseObject ("loose").
// Catchall validates unknown keys when set.
func zObject(mode string, catchall zSchema, fields ...zField) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		o := asObject(v)
		if o == nil {
			return nil, typeIssue(path, "object", v)
		}
		out := jsonx.NewObject()
		var issues []zIssue
		known := map[string]bool{}
		for _, fl := range fields {
			known[fl.name] = true
			val, present := o.Get(fl.name)
			if !present {
				val = undef
			}
			r, is := fl.schema(val, zPath(path, fl.name))
			issues = append(issues, is...)
			if len(is) == 0 && !isUndef(r) {
				out.Set(fl.name, r)
			}
		}
		for _, k := range o.Keys() {
			if known[k] {
				continue
			}
			val, _ := o.Get(k)
			switch {
			case catchall != nil:
				r, is := catchall(val, zPath(path, k))
				issues = append(issues, is...)
				if len(is) == 0 {
					out.Set(k, r)
				}
			case mode == "loose":
				out.Set(k, val)
			}
		}
		if len(issues) > 0 {
			return nil, issues
		}
		return out, nil
	}
}

func zUnion(options ...zSchema) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		var nonAborted [][]zIssue
		for _, o := range options {
			out, issues := o(v, path)
			if len(issues) == 0 {
				return out, nil
			}
			if !aborted(issues) {
				nonAborted = append(nonAborted, issues)
			}
		}
		if len(nonAborted) == 1 {
			return nil, nonAborted[0]
		}
		return nil, []zIssue{{Path: path, Code: "invalid_union", Message: "Invalid input"}}
	}
}

// zRefine adds a refinement (non-aborting custom issue) after s succeeds.
func zRefine(s zSchema, fn func(any) bool, msg string) zSchema {
	return func(v any, path []any) (any, []zIssue) {
		out, issues := s(v, path)
		if len(issues) > 0 {
			return nil, issues
		}
		if !fn(out) {
			return nil, []zIssue{{Path: path, Code: "custom", Message: msg, Continue: true}}
		}
		return out, nil
	}
}

// zParse runs a schema at the root.
func zParse(s zSchema, v any) (any, []zIssue) { return s(v, nil) }

// toValidate wraps a zSchema as a validate.Schema (for better-call VALIDATION_ERROR
// bodies).
func toValidate(s zSchema) validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		out, issues := s(v, path)
		if len(issues) == 0 {
			if o, ok := out.(*jsonx.Object); ok {
				return objectToMap(o), nil
			}
			return out, nil
		}
		vi := make([]validate.Issue, len(issues))
		for i, is := range issues {
			vi[i] = validate.NewIssue(is.Path, is.Code, is.Message)
		}
		return nil, vi
	})
}

// objectToMap converts an ordered object into a map (nested objects stay ordered).
func objectToMap(o *jsonx.Object) map[string]any {
	if o == nil {
		return nil
	}
	m := map[string]any{}
	for _, k := range o.Keys() {
		v, _ := o.Get(k)
		m[k] = v
	}
	return m
}

// ---- schemas from types/zod.ts ----

var promptTokens = []string{"none", "consent", "login", "create", "select_account"}

// authorizationPrompt is authorizationPromptSchema.
func authorizationPrompt() zSchema {
	return zString(func(s string, path []any) []zIssue {
		var tokens []string
		for _, t := range strings.Split(s, " ") {
			if t = strings.TrimSpace(t); t != "" {
				tokens = append(tokens, t)
			}
		}
		if len(tokens) == 0 {
			return []zIssue{{Path: path, Code: "custom", Message: "prompt must include at least one value", Continue: true}}
		}
		set := map[string]bool{}
		var issues []zIssue
		for _, t := range tokens {
			if !contains(promptTokens, t) {
				issues = append(issues, zIssue{Path: path, Code: "custom", Message: "unsupported prompt value: " + t, Continue: true})
				continue
			}
			set[t] = true
		}
		if set["none"] && len(set) > 1 {
			issues = append(issues, zIssue{Path: path, Code: "custom", Message: "prompt=none cannot be combined with other prompt values", Continue: true})
		}
		return issues
	})
}

func clientJwksSchema() zSchema {
	return zObject("strip", nil, zf("keys", zArray(zRecord(zUnknown()), 1)))
}

// maxAge is maxAgeSchema: a non-negative integer (numbers or numeric strings).
func maxAgeSchema() zSchema {
	inner := zUnion(zNumber(false, false, false), zString(trimCheck(), minLen(1, "")))
	return func(v any, path []any) (any, []zIssue) {
		out, issues := inner(v, path)
		if len(issues) > 0 {
			return nil, issues
		}
		var n float64
		switch t := out.(type) {
		case float64:
			n = t
		case string:
			n = jsNumber(t)
		}
		if math.IsNaN(n) || n != math.Trunc(n) || n < 0 || math.IsInf(n, 0) {
			return nil, []zIssue{{Path: path, Code: "custom", Message: "max_age must be a non-negative integer", Continue: true}}
		}
		return n, nil
	}
}

var dpopJktRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func resourceParam() zSchema {
	return zUnion(resourceURI(), zArray(resourceURI(), 1))
}

// claimsRequestInput is claimsRequestInputSchema (string | record).
func claimsRequestInput() zSchema { return zUnion(zString(), zRecord(zUnknown())) }

// claimsRequestParameter is claimsRequestParameterSchema.
func claimsRequestParameter() zSchema {
	return zRefine(claimsRequestInput(), func(v any) bool { return parseOIDCClaimsRequest(v) != nil },
		"claims must be a valid Claims request object")
}

func authorizationQueryFields(stored bool) []zField {
	claims := claimsRequestInput()
	if stored {
		claims = claimsRequestParameter()
	}
	return []zField{
		zf("response_type", zOptional(zStringEnum("code"))),
		zf("request", zOptional(zString())),
		zf("request_uri", zOptional(zString())),
		zf("redirect_uri", zOptional(safeURL())),
		zf("scope", zOptional(zString())),
		zf("state", zOptional(zString())),
		zf("client_id", zString(minLen(1, "client_id is required"))),
		zf("prompt", zOptional(authorizationPrompt())),
		zf("display", zOptional(zString())),
		zf("ui_locales", zOptional(zString())),
		zf("max_age", zOptional(maxAgeSchema())),
		zf("acr_values", zOptional(zString())),
		zf("login_hint", zOptional(zString())),
		zf("id_token_hint", zOptional(zString())),
		zf("code_challenge", zOptional(zString())),
		zf("code_challenge_method", zOptional(zStringEnum("S256"))),
		zf("nonce", zOptional(zString())),
		zf("claims", zOptional(claims)),
		zf("dpop_jkt", zOptional(zString(regexCheck(dpopJktRe, "dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint")))),
		zf("resource", zOptional(resourceParam())),
	}
}

// authorizationQuerySchema is authorizationQuerySchema (passthrough).
var authorizationQuerySchema = zObject("loose", nil, authorizationQueryFields(false)...)

var storedAuthorizationQuerySchema = zObject("loose", nil, authorizationQueryFields(true)...)

// verificationValueSchema is verificationValueSchema (passthrough).
var verificationValueSchema = zObject("loose", nil,
	zf("type", zLiteral("authorization_code")),
	zf("query", storedAuthorizationQuerySchema),
	zf("sessionId", zString()),
	zf("userId", zString()),
	zf("referenceId", zOptional(zString())),
	zf("authTime", zOptional(zNumber(false, false, false))),
	zf("resource", zOptional(zArray(zString(), 0))),
)

func nonBlank(s string) bool { return strings.TrimSpace(s) != "" }

func registrationFields() []zField {
	return []zField{
		zf("redirect_uris", zOptional(zArray(safeURL(), 1))),
		zf("scope", zOptional(zString())),
		zf("client_name", zOptional(zString(refineCheck(nonBlank, "client_name cannot be empty")))),
		zf("client_uri", zOptional(zString())),
		zf("logo_uri", zOptional(zString())),
		zf("contacts", zOptional(zArray(zString(minLen(1, "")), 1))),
		zf("tos_uri", zOptional(zString())),
		zf("policy_uri", zOptional(zString())),
		zf("software_id", zOptional(zString())),
		zf("software_version", zOptional(zString())),
		zf("software_statement", zOptional(zString())),
		zf("post_logout_redirect_uris", zOptional(zArray(safeURL(), 1))),
		zf("backchannel_logout_uri", zOptional(safeURL())),
		zf("backchannel_logout_session_required", zOptional(zBool())),
		zf("token_endpoint_auth_method", zOptional(zString(trimCheck(), minLen(1, "")))),
		zf("jwks", zOptional(clientJwksSchema())),
		zf("jwks_uri", zOptional(zString())),
		zf("grant_types", zOptional(zArray(zString(trimCheck(), minLen(1, "")), 1))),
		zf("response_types", zOptional(zArray(zEnum("code"), 0))),
		zf("application_type", zOptional(zEnum("web", "native"))),
		zf("subject_type", zOptional(zEnum("public", "pairwise"))),
		zf("dpop_bound_access_tokens", zOptional(zBool())),
		zf("resources", zOptional(zArray(resourceURI(), 0))),
	}
}

// clientRegistrationRequestSchema is clientRegistrationRequestSchema.
var clientRegistrationRequestSchema = zObject("strip", nil, append(registrationFields(),
	zf("skip_consent", zOptional(zNever("skip_consent cannot be set during dynamic client registration"))))...)

// OAuthClientMetadataSchema validates a client metadata document
// (oauthClientMetadataSchema): the registration fields plus client_id / client_secret /
// timestamps, unknown keys kept.
var oauthClientMetadataSchema = zObject("loose", nil, append(registrationFields(),
	zf("client_id", zString(refineCheck(nonBlank, "client_id cannot be empty"))),
	zf("client_secret", zOptional(zString())),
	zf("client_secret_expires_at", zOptional(zNumber(true, false, true))),
	zf("client_id_issued_at", zOptional(zNumber(true, false, true))),
)...)

// ---- helpers ----

// jsNumber is Number(s) for strings.
func jsNumber(s string) float64 {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0
	}
	var f float64
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		var n int64
		if _, err := fmt.Sscanf(t[2:], "%x", &n); err == nil {
			return float64(n)
		}
		return math.NaN()
	}
	if t == "Infinity" || t == "+Infinity" {
		return math.Inf(1)
	}
	if t == "-Infinity" {
		return math.Inf(-1)
	}
	if !numericRe.MatchString(t) {
		return math.NaN()
	}
	_, err := fmt.Sscanf(t, "%g", &f)
	if err != nil {
		return math.NaN()
	}
	return f
}

var nonWordRe = regexp.MustCompile(`[^\w$]`)

var numericRe = regexp.MustCompile(`^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$`)

// toDotPath is z.core.toDotPath.
func toDotPath(path []any) string {
	var b strings.Builder
	for _, seg := range path {
		switch t := seg.(type) {
		case int:
			fmt.Fprintf(&b, "[%d]", t)
		case string:
			if nonWordRe.MatchString(t) {
				q, _ := json.Marshal(t)
				fmt.Fprintf(&b, "[%s]", q)
				continue
			}
			if b.Len() > 0 {
				b.WriteString(".")
			}
			b.WriteString(t)
		default:
			fmt.Fprintf(&b, "[%v]", t)
		}
	}
	return b.String()
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
