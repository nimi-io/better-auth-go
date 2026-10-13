package adaptertest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

// R is a shorthand for adapter.Record.
type R = adapter.Record

// W is a shorthand for adapter.Where.
type W = adapter.Where

// Where builds a where clause list from field/value pairs joined with AND.
func Where(pairs ...any) []adapter.Where {
	var out []adapter.Where
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, adapter.Where{Field: pairs[i].(string), Value: pairs[i+1]})
	}
	return out
}

// Merge returns a shallow copy of a with b's keys applied (object spread).
func Merge(a adapter.Record, b ...adapter.Record) adapter.Record {
	out := clone(a)
	for _, m := range b {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// Omit returns a copy of r without the given keys ({ id: _, ...rest }).
func Omit(r adapter.Record, keys ...string) adapter.Record {
	out := clone(r)
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

func clone(r adapter.Record) adapter.Record {
	out := make(adapter.Record, len(r))
	for k, v := range r {
		out[k] = v
	}
	return out
}

// Firsts maps insertRandom results to their first element (`.map((x) => x[0])`).
func Firsts(rows [][]adapter.Record) []adapter.Record {
	out := make([]adapter.Record, len(rows))
	for i, r := range rows {
		out[i] = r[0]
	}
	return out
}

// IDs returns the ids of records as strings.
func IDs(rows []adapter.Record) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = ID(r)
	}
	return out
}

// ID returns a record's id as a string ("" for a nil record).
func ID(r adapter.Record) string {
	if r == nil {
		return ""
	}
	return adapter.ToString(r["id"])
}

// Str returns a string field ("" when missing or not a string).
func Str(r adapter.Record, field string) string {
	s, _ := r[field].(string)
	return s
}

// Time returns a date field.
func Time(r adapter.Record, field string) time.Time {
	t, _ := adapter.ToTime(r[field])
	return t
}

// Num returns a numeric field as float64.
func Num(r adapter.Record, field string) float64 {
	f, _ := adapter.ToFloat(r[field])
	return f
}

// Contains reports whether s contains v.
func Contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ---- JavaScript-like deep equality (toEqual) ----

// normalize converts values to a canonical form: numbers to float64, maps to
// map[string]any, slices to []any, *time.Time to time.Time.
func normalize(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case time.Time:
		return t
	case *time.Time:
		if t == nil {
			return nil
		}
		return *t
	case string, bool:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	}
	if f, ok := numericValue(v); ok {
		return f
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return v
		}
		out := map[string]any{}
		for _, k := range rv.MapKeys() {
			out[k.String()] = normalize(rv.MapIndex(k).Interface())
		}
		return out
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return []any{}
		}
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = normalize(rv.Index(i).Interface())
		}
		return out
	case reflect.Pointer:
		if rv.IsNil() {
			return nil
		}
		return normalize(rv.Elem().Interface())
	}
	return v
}

func numericValue(v any) (float64, bool) {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return adapter.ToFloat(v)
	}
	return 0, false
}

// DeepEqual compares two values with toEqual semantics for the value kinds adapters
// return (dates by instant, numbers by value, records by keys).
func DeepEqual(a, b any) bool { return deepEqual(normalize(a), normalize(b)) }

func deepEqual(a, b any) bool {
	switch at := a.(type) {
	case nil:
		return b == nil
	case time.Time:
		bt, ok := b.(time.Time)
		return ok && at.Equal(bt)
	case map[string]any:
		bt, ok := b.(map[string]any)
		if !ok || len(at) != len(bt) {
			return false
		}
		for k, v := range at {
			bv, ok := bt[k]
			if !ok || !deepEqual(v, bv) {
				return false
			}
		}
		return true
	case []any:
		bt, ok := b.([]any)
		if !ok || len(at) != len(bt) {
			return false
		}
		for i := range at {
			if !deepEqual(at[i], bt[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

// Format renders a value for failure messages (maps with sorted keys).
func Format(v any) string {
	var b strings.Builder
	format(&b, normalize(v), "")
	return b.String()
}

func format(b *strings.Builder, v any, indent string) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case time.Time:
		b.WriteString(t.UTC().Format(time.RFC3339Nano))
	case string:
		fmt.Fprintf(b, "%q", t)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{\n")
		for _, k := range keys {
			fmt.Fprintf(b, "%s  %s: ", indent, k)
			format(b, t[k], indent+"  ")
			b.WriteString(",\n")
		}
		b.WriteString(indent + "}")
	case []any:
		b.WriteString("[\n")
		for _, x := range t {
			b.WriteString(indent + "  ")
			format(b, x, indent+"  ")
			b.WriteString(",\n")
		}
		b.WriteString(indent + "]")
	default:
		fmt.Fprintf(b, "%v (%T)", t, t)
	}
}

// ---- assertions (expect(...) upstream); all fail the test immediately ----

// Equal asserts DeepEqual(got, want) (toEqual).
func (h *H) Equal(got, want any, msg ...any) {
	h.Helper()
	if !DeepEqual(got, want) {
		h.Fatalf("%sexpected values to be equal\n got: %s\nwant: %s", label(msg), Format(got), Format(want))
	}
}

// True asserts cond.
func (h *H) True(cond bool, msg ...any) {
	h.Helper()
	if !cond {
		h.Fatalf("%sexpected condition to hold", label(msg))
	}
}

// Null asserts that a record is null (toBeNull).
func (h *H) Null(r adapter.Record, msg ...any) {
	h.Helper()
	if r != nil {
		h.Fatalf("%sexpected null, got %s", label(msg), Format(r))
	}
}

// NotNull asserts that a record is not null.
func (h *H) NotNull(r adapter.Record, msg ...any) {
	h.Helper()
	if r == nil {
		h.Fatalf("%sexpected a record, got null", label(msg))
	}
}

// FieldNull asserts that r has the key field with a null value (toBeNull on a property,
// which fails for undefined).
func (h *H) FieldNull(r adapter.Record, field string) {
	h.Helper()
	v, ok := r[field]
	if !ok {
		h.Fatalf("expected %s to be null, but it is undefined", field)
	}
	if v != nil {
		h.Fatalf("expected %s to be null, got %s", field, Format(v))
	}
}

// Len asserts the length of a slice (toHaveLength).
func (h *H) Len(v any, n int, msg ...any) {
	h.Helper()
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) {
		h.Fatalf("%sexpected an array with length %d, got %s", label(msg), n, Format(v))
	}
	if rv.Len() != n {
		h.Fatalf("%sexpected length %d, got %d: %s", label(msg), n, rv.Len(), Format(v))
	}
}

// IsString asserts that v is a string (typeof v === "string").
func (h *H) IsString(v any, msg ...any) {
	h.Helper()
	if _, ok := v.(string); !ok {
		h.Fatalf("%sexpected a string, got %T (%v)", label(msg), v, v)
	}
}

// Array returns v as a slice of records, failing when v is not an array.
func (h *H) Array(v any, msg ...any) []adapter.Record {
	h.Helper()
	switch t := v.(type) {
	case []adapter.Record:
		return t
	case []any:
		out := make([]adapter.Record, len(t))
		for i, x := range t {
			r, ok := x.(adapter.Record)
			if !ok {
				h.Fatalf("%sexpected an array of records, element %d is %T", label(msg), i, x)
			}
			out[i] = r
		}
		return out
	}
	h.Fatalf("%sexpected an array, got %T (%s)", label(msg), v, Format(v))
	return nil
}

// Object returns v as a record (nil for null), failing when v is an array.
func (h *H) Object(v any, msg ...any) adapter.Record {
	h.Helper()
	switch t := v.(type) {
	case nil:
		return nil
	case adapter.Record:
		return t
	}
	h.Fatalf("%sexpected an object, got %T (%s)", label(msg), v, Format(v))
	return nil
}

func label(msg []any) string {
	if len(msg) == 0 {
		return ""
	}
	if f, ok := msg[0].(string); ok {
		return fmt.Sprintf(f, msg[1:]...) + ": "
	}
	return fmt.Sprint(msg...) + ": "
}
