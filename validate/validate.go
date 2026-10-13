// Package validate is a small schema validator that reproduces the behaviour and the exact
// English error messages of zod v4, which Better Auth uses to validate request bodies and
// queries. Validation failures surface to clients as
// `{"code":"VALIDATION_ERROR","message":"[body.email] Invalid email address"}`, so the
// wording matters for wire compatibility.
//
// Values are the shapes produced by encoding/json: map[string]any, []any, string, float64,
// bool and nil. A missing object key is "undefined" (see [Undefined]).
package validate

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Issue is a single validation problem.
type Issue struct {
	Path    []any
	Message string
	Code    string
	// abort marks issues that make a union branch "aborted" (zod's continue !== true).
	abort bool
}

// Schema validates a value and returns the (possibly transformed) output.
type Schema interface {
	validate(v any, path []any) (any, []Issue)
}

type undefinedT struct{}

// Undefined represents a missing value (JavaScript undefined).
var Undefined any = undefinedT{}

// IsUndefined reports whether v is Undefined.
func IsUndefined(v any) bool { _, ok := v.(undefinedT); return ok }

// Validate runs schema against v. On success the output has Undefined values removed.
func Validate(s Schema, v any) (any, []Issue) {
	out, issues := s.validate(v, nil)
	if len(issues) > 0 {
		return nil, issues
	}
	if IsUndefined(out) {
		return nil, nil
	}
	return out, nil
}

// FormatIssues renders issues like better-call's fromError:
// "[body.email] Invalid email address; [body.password] ...".
func FormatIssues(issues []Issue, validating string) string {
	parts := make([]string, len(issues))
	for i, is := range issues {
		p := validating
		if len(is.Path) > 0 {
			segs := make([]string, len(is.Path))
			for j, s := range is.Path {
				segs[j] = fmt.Sprint(s)
			}
			p = validating + "." + strings.Join(segs, ".")
		}
		parts[i] = "[" + p + "] " + is.Message
	}
	return strings.Join(parts, "; ")
}

func typeName(v any) string {
	switch t := v.(type) {
	case undefinedT:
		return "undefined"
	case nil:
		return "null"
	case string:
		return "string"
	case float64:
		if math.IsNaN(t) {
			return "NaN"
		}
		return "number"
	case int, int64, int32, float32:
		return "number"
	case bool:
		return "boolean"
	case []any, []string:
		return "array"
	case map[string]any:
		return "object"
	}
	return "object"
}

func appendPath(path []any, seg any) []any {
	out := make([]any, len(path)+1)
	copy(out, path)
	out[len(path)] = seg
	return out
}

func typeIssue(path []any, expected string, v any) []Issue {
	return []Issue{{Path: path, Code: "invalid_type", abort: true,
		Message: "Invalid input: expected " + expected + ", received " + typeName(v)}}
}

// ---- primitives ----

// StringSchema validates strings.
type StringSchema struct {
	min, max  int
	hasMin    bool
	hasMax    bool
	email     bool
	url       bool
	transform func(string) string
	// minMessage overrides the too_small message (.min(n, message) / .nonempty(message)).
	minMessage string
}

// String is z.string().
func String() *StringSchema { return &StringSchema{} }

// Email is z.email().
func Email() *StringSchema { return &StringSchema{email: true} }

// URL is z.url().
func URL() *StringSchema { return &StringSchema{url: true} }

// NonEmpty is .nonempty() (min length 1).
func (s *StringSchema) NonEmpty() *StringSchema { return s.Min(1) }

// Min is .min(n).
func (s *StringSchema) Min(n int) *StringSchema { c := *s; c.min, c.hasMin = n, true; return &c }

// MinMessage is .min(n, message): like Min with a custom error message.
func (s *StringSchema) MinMessage(n int, message string) *StringSchema {
	c := s.Min(n)
	c.minMessage = message
	return c
}

// Max is .max(n).
func (s *StringSchema) Max(n int) *StringSchema { c := *s; c.max, c.hasMax = n, true; return &c }

// Transform applies f to valid values.
func (s *StringSchema) Transform(f func(string) string) *StringSchema {
	c := *s
	c.transform = f
	return &c
}

func (s *StringSchema) validate(v any, path []any) (any, []Issue) {
	str, ok := v.(string)
	if !ok {
		return nil, typeIssue(path, "string", v)
	}
	var issues []Issue
	n := jsLen(str)
	if s.hasMin && n < s.min {
		msg := fmt.Sprintf("Too small: expected string to have >=%d characters", s.min)
		if s.minMessage != "" {
			msg = s.minMessage
		}
		issues = append(issues, Issue{Path: path, Code: "too_small", Message: msg})
	}
	if s.hasMax && n > s.max {
		issues = append(issues, Issue{Path: path, Code: "too_big",
			Message: fmt.Sprintf("Too big: expected string to have <=%d characters", s.max)})
	}
	if s.email && !IsEmail(str) {
		issues = append(issues, Issue{Path: path, Code: "invalid_format", Message: "Invalid email address"})
	}
	if s.url && !isURL(str) {
		issues = append(issues, Issue{Path: path, Code: "invalid_format", Message: "Invalid URL"})
	}
	if len(issues) > 0 {
		return nil, issues
	}
	if s.transform != nil {
		str = s.transform(str)
	}
	return str, nil
}

func jsLen(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

var emailBody = regexp.MustCompile(`^([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)

// IsEmail implements zod v4's default email regex:
// /^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$/
func IsEmail(s string) bool {
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	return emailBody.MatchString(s)
}

var urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:`)

func isURL(s string) bool { return urlScheme.MatchString(s) && len(s) > 2 }

// BooleanSchema is z.boolean().
type BooleanSchema struct{ coerce bool }

// Boolean is z.boolean().
func Boolean() *BooleanSchema { return &BooleanSchema{} }

// CoerceBoolean is z.coerce.boolean(): JavaScript truthiness (so "false" is true).
func CoerceBoolean() *BooleanSchema { return &BooleanSchema{coerce: true} }

func (s *BooleanSchema) validate(v any, path []any) (any, []Issue) {
	if s.coerce {
		return Truthy(v), nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil, typeIssue(path, "boolean", v)
	}
	return b, nil
}

// Truthy implements JavaScript Boolean(v).
func Truthy(v any) bool {
	switch t := v.(type) {
	case undefinedT, nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && !math.IsNaN(t)
	case int:
		return t != 0
	case int64:
		return t != 0
	}
	return true
}

// NumberSchema is z.number().
type NumberSchema struct {
	integer bool
	min     *float64
}

// Number is z.number().
func Number() *NumberSchema { return &NumberSchema{} }

// Int is z.number().int().
func (s *NumberSchema) Int() *NumberSchema { c := *s; c.integer = true; return &c }

// Min is .min(n).
func (s *NumberSchema) Min(n float64) *NumberSchema { c := *s; c.min = &n; return &c }

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case float32:
		return float64(t), true
	}
	return 0, false
}

func (s *NumberSchema) validate(v any, path []any) (any, []Issue) {
	f, ok := toFloat(v)
	if !ok || math.IsNaN(f) {
		return nil, typeIssue(path, "number", v)
	}
	if s.integer && f != math.Trunc(f) {
		return nil, []Issue{{Path: path, Code: "invalid_type", abort: true, Message: "Invalid input: expected int, received number"}}
	}
	if s.min != nil && f < *s.min {
		return nil, []Issue{{Path: path, Code: "too_small",
			Message: "Too small: expected number to be >=" + formatNum(*s.min)}}
	}
	return f, nil
}

func formatNum(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprint(f)
}

type anySchema struct{}

// Any is z.any().
func Any() Schema { return anySchema{} }

func (anySchema) validate(v any, _ []any) (any, []Issue) { return v, nil }

// LiteralSchema is z.literal(v).
type LiteralSchema struct{ value any }

// Literal is z.literal(v).
func Literal(v any) *LiteralSchema { return &LiteralSchema{value: v} }

func (s *LiteralSchema) validate(v any, path []any) (any, []Issue) {
	if v == s.value {
		return v, nil
	}
	return nil, []Issue{{Path: path, Code: "invalid_value", abort: true,
		Message: "Invalid input: expected " + literalString(s.value)}}
}

func literalString(v any) string {
	if s, ok := v.(string); ok {
		return `"` + s + `"`
	}
	return fmt.Sprint(v)
}

// EnumSchema is z.enum([...]).
type EnumSchema struct{ values []string }

// Enum is z.enum(values).
func Enum(values ...string) *EnumSchema { return &EnumSchema{values: values} }

func (s *EnumSchema) validate(v any, path []any) (any, []Issue) {
	if str, ok := v.(string); ok {
		for _, x := range s.values {
			if x == str {
				return str, nil
			}
		}
	}
	quoted := make([]string, len(s.values))
	for i, x := range s.values {
		quoted[i] = `"` + x + `"`
	}
	return nil, []Issue{{Path: path, Code: "invalid_value", abort: true,
		Message: "Invalid option: expected one of " + strings.Join(quoted, "|")}}
}

// ---- wrappers ----

type optional struct{ inner Schema }

// Optional is .optional(): undefined passes through.
func Optional(s Schema) Schema { return optional{inner: s} }

func (o optional) validate(v any, path []any) (any, []Issue) {
	if IsUndefined(v) {
		return Undefined, nil
	}
	return o.inner.validate(v, path)
}

type nullable struct{ inner Schema }

// Nullish is .nullish(): undefined and null pass through.
func Nullish(s Schema) Schema { return nullable{inner: Optional(s)} }

func (n nullable) validate(v any, path []any) (any, []Issue) {
	if v == nil {
		return nil, nil
	}
	return n.inner.validate(v, path)
}

type withDefault struct {
	inner Schema
	def   any
}

// Default is .default(v): undefined becomes v.
func Default(s Schema, v any) Schema { return withDefault{inner: s, def: v} }

func (d withDefault) validate(v any, path []any) (any, []Issue) {
	if IsUndefined(v) {
		return d.def, nil
	}
	return d.inner.validate(v, path)
}

// ArraySchema is z.array(item).
type ArraySchema struct{ item Schema }

// Array is z.array(item).
func Array(item Schema) *ArraySchema { return &ArraySchema{item: item} }

func (s *ArraySchema) validate(v any, path []any) (any, []Issue) {
	var arr []any
	switch t := v.(type) {
	case []any:
		arr = t
	case []string:
		for _, x := range t {
			arr = append(arr, x)
		}
	default:
		return nil, typeIssue(path, "array", v)
	}
	out := make([]any, len(arr))
	var issues []Issue
	for i, x := range arr {
		o, is := s.item.validate(x, appendPath(path, i))
		issues = append(issues, is...)
		out[i] = o
	}
	if len(issues) > 0 {
		return nil, issues
	}
	return out, nil
}

// Field is one object property.
type Field struct {
	Name   string
	Schema Schema
}

// F declares an object field.
func F(name string, s Schema) Field { return Field{Name: name, Schema: s} }

// ObjectSchema is z.object / z.strictObject / z.looseObject.
type ObjectSchema struct {
	fields []Field
	mode   string // "strip" (default), "strict", "loose"
}

// Object is z.object({...}) (unknown keys are stripped).
func Object(fields ...Field) *ObjectSchema { return &ObjectSchema{fields: fields, mode: "strip"} }

// StrictObject is z.strictObject({...}).
func StrictObject(fields ...Field) *ObjectSchema {
	return &ObjectSchema{fields: fields, mode: "strict"}
}

// LooseObject is z.looseObject({...}) (unknown keys are kept).
func LooseObject(fields ...Field) *ObjectSchema { return &ObjectSchema{fields: fields, mode: "loose"} }

func (s *ObjectSchema) validate(v any, path []any) (any, []Issue) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, typeIssue(path, "object", v)
	}
	out := map[string]any{}
	var issues []Issue
	known := map[string]bool{}
	for _, f := range s.fields {
		known[f.Name] = true
		val, present := m[f.Name]
		if !present {
			val = Undefined
		}
		o, is := f.Schema.validate(val, appendPath(path, f.Name))
		issues = append(issues, is...)
		if len(is) == 0 && !IsUndefined(o) {
			out[f.Name] = o
		}
	}
	var unknown []string
	for k, val := range m {
		if known[k] {
			continue
		}
		switch s.mode {
		case "strict":
			unknown = append(unknown, k)
		case "loose":
			out[k] = val
		}
	}
	if len(unknown) > 0 {
		sortStrings(unknown)
		quoted := make([]string, len(unknown))
		for i, k := range unknown {
			quoted[i] = `"` + k + `"`
		}
		msg := "Unrecognized key: " + quoted[0]
		if len(unknown) > 1 {
			msg = "Unrecognized keys: " + strings.Join(quoted, ", ")
		}
		issues = append(issues, Issue{Path: path, Code: "unrecognized_keys", Message: msg})
	}
	if len(issues) > 0 {
		return nil, issues
	}
	return out, nil
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// RecordSchema is z.record(z.string(), value).
type RecordSchema struct{ value Schema }

// Record is z.record(z.string(), value).
func Record(value Schema) *RecordSchema { return &RecordSchema{value: value} }

func (s *RecordSchema) validate(v any, path []any) (any, []Issue) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, typeIssue(path, "record", v)
	}
	out := map[string]any{}
	var issues []Issue
	for k, val := range m {
		o, is := s.value.validate(val, appendPath(path, k))
		issues = append(issues, is...)
		out[k] = o
	}
	if len(issues) > 0 {
		return nil, issues
	}
	return out, nil
}

type unionSchema struct{ options []Schema }

// Union is z.union([...]).
func Union(options ...Schema) Schema { return unionSchema{options: options} }

func (u unionSchema) validate(v any, path []any) (any, []Issue) {
	type res struct {
		out    any
		issues []Issue
	}
	var nonAborted []res
	for _, o := range u.options {
		out, issues := o.validate(v, path)
		if len(issues) == 0 {
			return out, nil
		}
		aborted := false
		for _, is := range issues {
			if is.abort {
				aborted = true
			}
		}
		if !aborted {
			nonAborted = append(nonAborted, res{out, issues})
		}
	}
	if len(nonAborted) == 1 {
		return nil, nonAborted[0].issues
	}
	return nil, []Issue{{Path: path, Code: "invalid_union", abort: true, Message: "Invalid input"}}
}

type intersection struct{ a, b Schema }

// And is a.and(b) (z.intersection). Object outputs are merged.
func And(a, b Schema) Schema { return intersection{a: a, b: b} }

func (s intersection) validate(v any, path []any) (any, []Issue) {
	oa, ia := s.a.validate(v, path)
	ob, ib := s.b.validate(v, path)
	issues := append(ia, ib...)
	if len(issues) > 0 {
		return nil, issues
	}
	ma, aok := oa.(map[string]any)
	mb, bok := ob.(map[string]any)
	if aok && bok {
		out := map[string]any{}
		for k, x := range mb {
			out[k] = x
		}
		for k, x := range ma {
			out[k] = x
		}
		return out, nil
	}
	return oa, nil
}

// Custom wraps a function as a schema.
type Custom func(v any, path []any) (any, []Issue)

func (c Custom) validate(v any, path []any) (any, []Issue) { return c(v, path) }

// NewIssue builds a custom issue.
func NewIssue(path []any, code, message string) Issue {
	return Issue{Path: path, Code: code, Message: message, abort: true}
}
