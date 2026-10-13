package scim

// A small re-implementation of the zod v4 (4.6.x) semantics the SCIM schemas rely on:
// ordered object output (shape order), continue/abort issue propagation, `when`-guarded
// length checks, pipes, transforms, unions and refinements, with zod's English messages.
// Values are JSON-like: *jsonx.Object, []any, string, float64, bool, nil, time.Time and
// jsonx.Undefined for a missing value.

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

var undef any = jsonx.Undefined

func isUndef(v any) bool {
	if v == nil {
		return false
	}
	if v == jsonx.Undefined {
		return true
	}
	return validate.IsUndefined(v)
}

type zIssue struct {
	Path     []any
	Code     string
	Message  string
	Continue bool
}

type zResult struct {
	value   any
	issues  []zIssue
	aborted bool
}

func (r *zResult) isAborted() bool {
	if r.aborted {
		return true
	}
	for _, is := range r.issues {
		if !is.Continue {
			return true
		}
	}
	return false
}

type zSchema interface {
	run(v any) *zResult
	optin() string
	optout() string
}

func prefixIssues(seg any, issues []zIssue) []zIssue {
	out := make([]zIssue, len(issues))
	for i, is := range issues {
		p := make([]any, 0, len(is.Path)+1)
		p = append(p, seg)
		p = append(p, is.Path...)
		is.Path = p
		out[i] = is
	}
	return out
}

// zParsedType mirrors util.parsedType (used in invalid_type messages).
func zParsedType(v any) string {
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
	case int, int64, int32, float32:
		return "number"
	case []any, []string:
		return "array"
	case time.Time, *time.Time:
		return "Date"
	case *jsonx.Object, map[string]any:
		return "object"
	}
	if isUndef(v) {
		return "undefined"
	}
	return "object"
}

func invalidType(expected string, v any) *zResult {
	return &zResult{value: v, issues: []zIssue{{Code: "invalid_type",
		Message: "Invalid input: expected " + expected + ", received " + zParsedType(v)}}}
}

// jsLength counts code points (zod 4.6 measures strings in code points).
func codePoints(s string) int { return utf8.RuneCountInString(s) }

// ---- string ----

type strCheck struct {
	kind   string // trim, lower, min, max, email, startsWith, refine
	n      int
	prefix string
	msg    string
	refine func(string) bool
}

type zString struct{ checks []strCheck }

func zStr() *zString { return &zString{} }

func (s *zString) with(c strCheck) *zString {
	out := &zString{checks: append(append([]strCheck{}, s.checks...), c)}
	return out
}
func (s *zString) trim() *zString     { return s.with(strCheck{kind: "trim"}) }
func (s *zString) lower() *zString    { return s.with(strCheck{kind: "lower"}) }
func (s *zString) min(n int) *zString { return s.with(strCheck{kind: "min", n: n}) }
func (s *zString) max(n int) *zString { return s.with(strCheck{kind: "max", n: n}) }
func (s *zString) email() *zString    { return s.with(strCheck{kind: "email"}) }
func (s *zString) startsWith(p string) *zString {
	return s.with(strCheck{kind: "startsWith", prefix: p})
}
func (s *zString) refine(ok func(string) bool, msg string) *zString {
	return s.with(strCheck{kind: "refine", refine: ok, msg: msg})
}
func (s *zString) optin() string  { return "" }
func (s *zString) optout() string { return "" }

// zodEmail is the zod 4.6 default email regex.
var zodEmail = regexp.MustCompile(`^(?:[A-Za-z0-9_'+\-]+\.)*[A-Za-z0-9_'+\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)

func isZodEmail(s string) bool { return zodEmail.MatchString(s) }

func (s *zString) run(v any) *zResult {
	str, ok := v.(string)
	if !ok {
		return invalidType("string", v)
	}
	r := &zResult{value: str}
	for _, c := range s.checks {
		cur := r.value.(string)
		switch c.kind {
		case "trim":
			r.value = jsTrim(cur)
		case "lower":
			r.value = jsLower(cur)
		case "min":
			if codePoints(cur) < c.n {
				r.issues = append(r.issues, zIssue{Code: "too_small", Continue: true,
					Message: orMsg(c.msg, fmt.Sprintf("Too small: expected string to have >=%d characters", c.n))})
			}
		case "max":
			if codePoints(cur) > c.n {
				r.issues = append(r.issues, zIssue{Code: "too_big", Continue: true,
					Message: orMsg(c.msg, fmt.Sprintf("Too big: expected string to have <=%d characters", c.n))})
			}
		case "email":
			if !isZodEmail(cur) {
				r.issues = append(r.issues, zIssue{Code: "invalid_format", Continue: true, Message: "Invalid email address"})
			}
		case "startsWith":
			if !strings.HasPrefix(cur, c.prefix) {
				r.issues = append(r.issues, zIssue{Code: "invalid_format", Continue: true,
					Message: `Invalid string: must start with "` + c.prefix + `"`})
			}
		case "refine":
			if !c.refine(cur) {
				r.issues = append(r.issues, refineIssue(c.msg))
			}
		}
	}
	return r
}

func orMsg(custom, def string) string {
	if custom != "" {
		return custom
	}
	return def
}

// jsTrim implements String.prototype.trim (ECMAScript WhiteSpace + LineTerminator).
func jsTrim(s string) string {
	return strings.TrimFunc(s, isJSWhitespace)
}

func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// jsLower approximates String.prototype.toLowerCase.
func jsLower(s string) string { return strings.ToLower(s) }

// ---- primitives ----

type zBoolean struct{}

func (zBoolean) run(v any) *zResult {
	if _, ok := v.(bool); !ok {
		return invalidType("boolean", v)
	}
	return &zResult{value: v}
}
func (zBoolean) optin() string  { return "" }
func (zBoolean) optout() string { return "" }

type zDateT struct{}

func (zDateT) run(v any) *zResult {
	switch t := v.(type) {
	case time.Time:
		if t.IsZero() {
			return &zResult{value: v, issues: []zIssue{{Code: "invalid_type", Message: "Invalid input: expected date, received Date"}}}
		}
		return &zResult{value: t}
	case *time.Time:
		if t == nil || t.IsZero() {
			return &zResult{value: v, issues: []zIssue{{Code: "invalid_type", Message: "Invalid input: expected date, received Date"}}}
		}
		return &zResult{value: *t}
	}
	return invalidType("date", v)
}
func (zDateT) optin() string  { return "" }
func (zDateT) optout() string { return "" }

type zUnknownT struct{}

func (zUnknownT) run(v any) *zResult { return &zResult{value: v} }
func (zUnknownT) optin() string      { return "optional" }
func (zUnknownT) optout() string     { return "optional" }

type zLiteralT struct{ value string }

func (l zLiteralT) run(v any) *zResult {
	if s, ok := v.(string); ok && s == l.value {
		return &zResult{value: v}
	}
	return &zResult{value: v, issues: []zIssue{{Code: "invalid_value", Message: `Invalid input: expected "` + l.value + `"`}}}
}
func (zLiteralT) optin() string  { return "" }
func (zLiteralT) optout() string { return "" }

type zEnumT struct{ values []string }

func (e zEnumT) run(v any) *zResult {
	if s, ok := v.(string); ok {
		for _, x := range e.values {
			if x == s {
				return &zResult{value: v}
			}
		}
	}
	if len(e.values) == 1 {
		return &zResult{value: v, issues: []zIssue{{Code: "invalid_value", Message: `Invalid input: expected "` + e.values[0] + `"`}}}
	}
	q := make([]string, len(e.values))
	for i, x := range e.values {
		q[i] = `"` + x + `"`
	}
	return &zResult{value: v, issues: []zIssue{{Code: "invalid_value", Message: "Invalid option: expected one of " + strings.Join(q, "|")}}}
}
func (zEnumT) optin() string  { return "" }
func (zEnumT) optout() string { return "" }

type zNumberT struct{}

func (zNumberT) run(v any) *zResult {
	f, ok := v.(float64)
	if !ok {
		switch t := v.(type) {
		case int:
			return &zResult{value: float64(t)}
		case int64:
			return &zResult{value: float64(t)}
		}
		return invalidType("number", v)
	}
	if math.IsNaN(f) {
		return invalidType("number", v)
	}
	if math.IsInf(f, 0) {
		inf := "Infinity"
		if f < 0 {
			inf = "-Infinity"
		}
		return &zResult{value: v, issues: []zIssue{{Code: "invalid_type", Message: "Invalid input: expected number, received " + inf}}}
	}
	return &zResult{value: f}
}
func (zNumberT) optin() string  { return "" }
func (zNumberT) optout() string { return "" }

// ---- wrappers ----

type zOptional struct{ inner zSchema }

func zOpt(s zSchema) zSchema { return zOptional{inner: s} }

func (o zOptional) run(v any) *zResult {
	if isUndef(v) {
		return &zResult{value: undef}
	}
	return o.inner.run(v)
}
func (zOptional) optin() string  { return "optional" }
func (zOptional) optout() string { return "optional" }

type zDefaultT struct {
	inner zSchema
	def   any
}

func (d zDefaultT) run(v any) *zResult {
	if isUndef(v) {
		return &zResult{value: d.def}
	}
	return d.inner.run(v)
}
func (zDefaultT) optin() string  { return "defaulted" }
func (zDefaultT) optout() string { return "" }

type zPipeT struct{ in, out zSchema }

func zPipe(in, out zSchema) zSchema { return zPipeT{in: in, out: out} }

func (p zPipeT) run(v any) *zResult {
	left := p.in.run(v)
	if len(left.issues) > 0 {
		left.aborted = true
		return left
	}
	return p.out.run(left.value)
}
func (p zPipeT) optin() string  { return p.in.optin() }
func (p zPipeT) optout() string { return p.out.optout() }

type zTransformT struct{ fn func(any) any }

func (t zTransformT) run(v any) *zResult { return &zResult{value: t.fn(v)} }
func (zTransformT) optin() string        { return "" }
func (zTransformT) optout() string       { return "" }

func zTransform(s zSchema, fn func(any) any) zSchema { return zPipe(s, zTransformT{fn: fn}) }

func zPreprocess(fn func(any) any, s zSchema) zSchema { return zPipe(zTransformT{fn: fn}, s) }

type zUnionT struct{ options []zSchema }

func (u zUnionT) run(v any) *zResult {
	results := make([]*zResult, len(u.options))
	for i, o := range u.options {
		r := o.run(v)
		if len(r.issues) == 0 {
			return r
		}
		results[i] = r
	}
	var nonAborted []*zResult
	for _, r := range results {
		if !r.isAborted() {
			nonAborted = append(nonAborted, r)
		}
	}
	if len(nonAborted) == 1 {
		return nonAborted[0]
	}
	return &zResult{value: v, issues: []zIssue{{Code: "invalid_union", Message: "Invalid input"}}}
}
func (zUnionT) optin() string  { return "" }
func (zUnionT) optout() string { return "" }

// ---- refinements ----

// zRefineFn returns the issues a refinement adds (paths relative to the refined value).
type zRefineFn func(v any) []zIssue

func refineIssue(message string, path ...any) zIssue {
	if message == "" {
		message = "Invalid input"
	}
	return zIssue{Code: "custom", Message: message, Path: path, Continue: true}
}

// simpleRefine is .refine(fn, {message}).
func simpleRefine(ok func(v any) bool, message string, path ...any) zRefineFn {
	return func(v any) []zIssue {
		if ok(v) {
			return nil
		}
		return []zIssue{refineIssue(message, path...)}
	}
}

// ---- array ----

type arrCheck struct {
	kind   string // min, max, length, refine
	n      int
	msg    string
	refine zRefineFn
}

type zArray struct {
	item   zSchema
	checks []arrCheck
}

func zArr(item zSchema) *zArray { return &zArray{item: item} }

func (a *zArray) with(c arrCheck) *zArray {
	return &zArray{item: a.item, checks: append(append([]arrCheck{}, a.checks...), c)}
}
func (a *zArray) min(n int) *zArray { return a.with(arrCheck{kind: "min", n: n}) }
func (a *zArray) max(n int) *zArray { return a.with(arrCheck{kind: "max", n: n}) }
func (a *zArray) length(n int, msg string) *zArray {
	return a.with(arrCheck{kind: "length", n: n, msg: msg})
}
func (a *zArray) refine(fn zRefineFn) *zArray { return a.with(arrCheck{kind: "refine", refine: fn}) }
func (a *zArray) optin() string               { return "" }
func (a *zArray) optout() string              { return "" }

func toAnySlice(v any) ([]any, bool) {
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

func (a *zArray) run(v any) *zResult {
	arr, ok := toAnySlice(v)
	if !ok {
		return invalidType("array", v)
	}
	// zod 4.6 capSize: an oversized array fails its leading size checks before any
	// element is parsed, and the issue aborts.
	for _, c := range a.checks {
		if c.kind != "min" && c.kind != "max" && c.kind != "length" {
			break
		}
		if c.kind == "min" || len(arr) <= c.n {
			continue
		}
		r := &zResult{value: arr}
		runArrayChecks(r, arr, []arrCheck{c})
		r.issues[len(r.issues)-1].Continue = false
		return r
	}
	out := make([]any, len(arr))
	r := &zResult{value: out}
	for i, x := range arr {
		ir := a.item.run(x)
		r.issues = append(r.issues, prefixIssues(i, ir.issues)...)
		out[i] = ir.value
	}
	runArrayChecks(r, out, a.checks)
	return r
}

func runArrayChecks(r *zResult, out []any, checks []arrCheck) {
	aborted := r.isAborted()
	for _, c := range checks {
		before := len(r.issues)
		switch c.kind {
		case "min":
			if len(out) < c.n {
				r.issues = append(r.issues, zIssue{Code: "too_small", Continue: true,
					Message: orMsg(c.msg, fmt.Sprintf("Too small: expected array to have >=%d items", c.n))})
			}
		case "max":
			if len(out) > c.n {
				r.issues = append(r.issues, zIssue{Code: "too_big", Continue: true,
					Message: orMsg(c.msg, fmt.Sprintf("Too big: expected array to have <=%d items", c.n))})
			}
		case "length":
			if len(out) > c.n {
				r.issues = append(r.issues, zIssue{Code: "too_big", Continue: true,
					Message: orMsg(c.msg, fmt.Sprintf("Too big: expected array to have exactly %d items", c.n))})
			} else if len(out) < c.n {
				r.issues = append(r.issues, zIssue{Code: "too_small", Continue: true,
					Message: orMsg(c.msg, fmt.Sprintf("Too small: expected array to have exactly %d items", c.n))})
			}
		case "refine":
			if aborted {
				continue
			}
			r.issues = append(r.issues, c.refine(out)...)
		}
		if !aborted && len(r.issues) > before {
			aborted = r.isAborted()
		}
	}
}

// ---- object ----

type zField struct {
	name   string
	schema zSchema
}

type zObject struct {
	fields  []zField
	refines []zRefineFn
}

func zObj(fields ...zField) *zObject { return &zObject{fields: fields} }

func zf(name string, s zSchema) zField { return zField{name: name, schema: s} }

func (o *zObject) refine(fn zRefineFn) *zObject {
	return &zObject{fields: o.fields, refines: append(append([]zRefineFn{}, o.refines...), fn)}
}

// extend replaces or appends fields (zod .extend keeps the original key position).
func (o *zObject) extend(fields ...zField) *zObject {
	out := &zObject{fields: append([]zField{}, o.fields...)}
	for _, f := range fields {
		replaced := false
		for i := range out.fields {
			if out.fields[i].name == f.name {
				out.fields[i] = f
				replaced = true
			}
		}
		if !replaced {
			out.fields = append(out.fields, f)
		}
	}
	return out
}
func (o *zObject) optin() string  { return "" }
func (o *zObject) optout() string { return "" }

func (o *zObject) run(v any) *zResult {
	in, ok := asObject(v)
	if !ok {
		return invalidType("object", v)
	}
	out := jsonx.NewObject()
	r := &zResult{value: out}
	for _, f := range o.fields {
		val, present := in.Get(f.name)
		if !present {
			val = undef
		}
		fr := f.schema.run(val)
		optin, optout := f.schema.optin(), f.schema.optout()
		if !present && optout == "optional" && optin == "optional" {
			continue
		}
		if len(fr.issues) > 0 {
			if optin != "" && optout == "optional" && !present {
				continue
			}
			r.issues = append(r.issues, prefixIssues(f.name, fr.issues)...)
		}
		if !present && optin == "" {
			continue
		}
		if isUndef(fr.value) {
			continue
		}
		out.Set(f.name, fr.value)
	}
	if !r.isAborted() {
		for _, fn := range o.refines {
			r.issues = append(r.issues, fn(out)...)
			if r.isAborted() {
				break
			}
		}
	}
	return r
}

// asObject converts a JSON object value into an ordered object.
func asObject(v any) (*jsonx.Object, bool) {
	switch t := v.(type) {
	case *jsonx.Object:
		if t == nil {
			return nil, false
		}
		return t, true
	case map[string]any:
		return toOrdered(t).(*jsonx.Object), true
	}
	return nil, false
}

// toOrdered converts map[string]any values (recursively) into *jsonx.Object with keys
// sorted (the order jsonx would serialise them in).
func toOrdered(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortStrings(keys)
		o := jsonx.NewObject()
		for _, k := range keys {
			o.Set(k, toOrdered(t[k]))
		}
		return o
	case *jsonx.Object:
		o := jsonx.NewObject()
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			o.Set(k, toOrdered(x))
		}
		return o
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = toOrdered(x)
		}
		return out
	case []string:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = x
		}
		return out
	case int:
		return float64(t)
	case int64:
		return float64(t)
	}
	if isUndef(v) {
		return undef
	}
	return v
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// zParse runs a schema like safeParse.
func zParse(s zSchema, v any) (any, []zIssue) {
	r := s.run(toOrdered(v))
	if len(r.issues) > 0 {
		return nil, r.issues
	}
	return r.value, nil
}

// zodValidator adapts a zod-like schema to the endpoint validator (better-call
// runValidation). The output keeps shape order.
func zodValidator(s zSchema) validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		out, issues := zParse(s, v)
		if len(issues) > 0 {
			vi := make([]validate.Issue, len(issues))
			for i, is := range issues {
				vi[i] = validate.Issue{Path: append(append([]any{}, path...), is.Path...), Code: is.Code, Message: is.Message}
			}
			return nil, vi
		}
		if isUndef(out) {
			return validate.Undefined, nil
		}
		return out, nil
	})
}

func joinPath(path []any) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ".")
}
