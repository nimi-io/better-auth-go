// Package jsonx implements JSON encoding and decoding with the exact semantics of
// JavaScript's JSON.stringify / JSON.parse.
//
// Better Auth signs some payloads (for example the "compact" session cookie cache)
// over JSON.stringify output. To verify a signature produced by the TypeScript
// implementation, the Go side must re-serialize the parsed payload byte-for-byte
// identically: same key order, same string escaping, same number formatting and
// the same Date handling. The types in this package make that possible:
//
//   - [Object] is an insertion-ordered JSON object.
//   - [Parse] decodes JSON preserving object key order.
//   - [Marshal] encodes values the way JSON.stringify would.
package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Object is a JSON object that remembers the insertion order of its keys,
// mirroring JavaScript object property order for string keys.
type Object struct {
	keys []string
	vals map[string]any
}

// NewObject returns an empty ordered object.
func NewObject() *Object {
	return &Object{vals: map[string]any{}}
}

// O builds an ordered object from alternating key/value pairs.
// Keys must be strings; a nil-able "undefined" value can be expressed with [Undefined].
func O(kv ...any) *Object {
	o := NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			panic(fmt.Sprintf("jsonx.O: key at position %d is not a string", i))
		}
		o.Set(k, kv[i+1])
	}
	return o
}

// Set assigns a value. Assigning an existing key keeps its original position,
// like assigning to an existing property in JavaScript.
func (o *Object) Set(key string, value any) *Object {
	if o.vals == nil {
		o.vals = map[string]any{}
	}
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = value
	return o
}

// Get returns the value for key and whether it was present.
func (o *Object) Get(key string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[key]
	return v, ok
}

// Has reports whether key is present.
func (o *Object) Has(key string) bool {
	_, ok := o.Get(key)
	return ok
}

// Delete removes key.
func (o *Object) Delete(key string) {
	if o == nil {
		return
	}
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Keys returns the keys in insertion order.
func (o *Object) Keys() []string {
	if o == nil {
		return nil
	}
	out := make([]string, len(o.keys))
	copy(out, o.keys)
	return out
}

// Len returns the number of keys.
func (o *Object) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

// Clone returns a shallow copy.
func (o *Object) Clone() *Object {
	c := NewObject()
	for _, k := range o.Keys() {
		c.Set(k, o.vals[k])
	}
	return c
}

// Merge returns a copy of o with the keys of other assigned on top
// (the equivalent of {...o, ...other}).
func (o *Object) Merge(other *Object) *Object {
	c := o.Clone()
	for _, k := range other.Keys() {
		c.Set(k, other.vals[k])
	}
	return c
}

// Map converts the object (recursively) to plain Go maps and slices.
func (o *Object) Map() map[string]any {
	if o == nil {
		return nil
	}
	m := make(map[string]any, len(o.keys))
	for _, k := range o.keys {
		m[k] = ToPlain(o.vals[k])
	}
	return m
}

// MarshalJSON implements json.Marshaler with JavaScript semantics.
func (o *Object) MarshalJSON() ([]byte, error) {
	return Marshal(o)
}

// UnmarshalJSON implements json.Unmarshaler, preserving key order.
func (o *Object) UnmarshalJSON(data []byte) error {
	v, err := Parse(data)
	if err != nil {
		return err
	}
	obj, ok := v.(*Object)
	if !ok {
		return errors.New("jsonx: value is not an object")
	}
	*o = *obj
	return nil
}

// ToPlain converts *Object values (recursively) into map[string]any.
func ToPlain(v any) any {
	switch t := v.(type) {
	case *Object:
		return t.Map()
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = ToPlain(x)
		}
		return out
	default:
		return v
	}
}

// undefinedType marks a value that JSON.stringify would drop (JavaScript `undefined`).
type undefinedType struct{}

// Undefined is a sentinel value that is omitted from objects and encoded as null in arrays,
// exactly like JavaScript's undefined.
var Undefined = undefinedType{}

// RawMessage is pre-encoded JSON inserted verbatim.
type RawMessage []byte

// ISOTime formats t the way JavaScript's Date.prototype.toISOString does
// (UTC, millisecond precision).
func ISOTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// Marshal encodes v with JSON.stringify semantics:
//   - *Object keys keep insertion order; map keys are sorted (Go maps have no order);
//   - strings escape only `"`, `\` and control characters (no HTML escaping, U+2028/9 kept);
//   - numbers use the ECMAScript Number::toString algorithm; NaN/±Inf become null;
//   - time.Time becomes an ISO-8601 string with milliseconds;
//   - Undefined values are omitted from objects and become null in arrays.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v, false); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustMarshal is Marshal that panics on error. Only use with values known to be encodable.
func MustMarshal(v any) []byte {
	b, err := Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// Stringify is Marshal returning a string.
func Stringify(v any) (string, error) {
	b, err := Marshal(v)
	return string(b), err
}

func isUndefined(v any) bool {
	_, ok := v.(undefinedType)
	return ok
}

func encode(buf *bytes.Buffer, v any, inArray bool) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case undefinedType:
		buf.WriteString("null")
	case RawMessage:
		buf.Write(t)
	case json.RawMessage:
		buf.Write(t)
	case *Object:
		if t == nil {
			buf.WriteString("null")
			return nil
		}
		buf.WriteByte('{')
		first := true
		for _, k := range t.keys {
			val := t.vals[k]
			if isUndefined(val) {
				continue
			}
			if !first {
				buf.WriteByte(',')
			}
			first = false
			writeString(buf, k)
			buf.WriteByte(':')
			if err := encode(buf, val, false); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case Object:
		return encode(buf, &t, inArray)
	case string:
		writeString(buf, t)
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		buf.WriteString(FormatNumber(t))
	case float32:
		buf.WriteString(FormatNumber(float64(t)))
	case int:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int8:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int16:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(t), 10))
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(t), 10))
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(t), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(t), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(t, 10))
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return err
		}
		buf.WriteString(FormatNumber(f))
	case time.Time:
		writeString(buf, ISOTime(t))
	case *time.Time:
		if t == nil {
			buf.WriteString("null")
		} else {
			writeString(buf, ISOTime(*t))
		}
	case *string:
		if t == nil {
			buf.WriteString("null")
		} else {
			writeString(buf, *t)
		}
	case *bool:
		if t == nil {
			buf.WriteString("null")
		} else {
			return encode(buf, *t, inArray)
		}
	case []any:
		buf.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, x, true); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		buf.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, x)
		}
		buf.WriteByte(']')
	case map[string]any:
		if t == nil {
			buf.WriteString("null")
			return nil
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		first := true
		for _, k := range keys {
			val := t[k]
			if isUndefined(val) {
				continue
			}
			if !first {
				buf.WriteByte(',')
			}
			first = false
			writeString(buf, k)
			buf.WriteByte(':')
			if err := encode(buf, val, false); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case map[string]string:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = x
		}
		return encode(buf, m, inArray)
	case json.Marshaler:
		rv := reflect.ValueOf(t)
		if rv.Kind() == reflect.Pointer && rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		b, err := t.MarshalJSON()
		if err != nil {
			return err
		}
		buf.Write(b)
	default:
		return encodeReflect(buf, v)
	}
	return nil
}

func encodeReflect(buf *bytes.Buffer, v any) error {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		return encode(buf, rv.Elem().Interface(), false)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		buf.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, rv.Index(i).Interface(), true); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			break
		}
		if rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		m := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			m[iter.Key().String()] = iter.Value().Interface()
		}
		return encode(buf, m, false)
	case reflect.String:
		writeString(buf, rv.String())
		return nil
	case reflect.Bool:
		return encode(buf, rv.Bool(), false)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		buf.WriteString(strconv.FormatInt(rv.Int(), 10))
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		buf.WriteString(strconv.FormatUint(rv.Uint(), 10))
		return nil
	case reflect.Float32, reflect.Float64:
		buf.WriteString(FormatNumber(rv.Float()))
		return nil
	}
	// Structs and anything else: defer to encoding/json, then normalise through Parse so
	// strings get JavaScript escaping.
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	parsed, err := Parse(b)
	if err != nil {
		return err
	}
	return encode(buf, parsed, false)
}

const hexDigits = "0123456789abcdef"

// writeString writes s as a JSON string using JSON.stringify escaping rules.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				buf.WriteString(`\"`)
			case '\\':
				buf.WriteString(`\\`)
			case '\b':
				buf.WriteString(`\b`)
			case '\f':
				buf.WriteString(`\f`)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			default:
				if c < 0x20 {
					buf.WriteString(`\u00`)
					buf.WriteByte(hexDigits[c>>4])
					buf.WriteByte(hexDigits[c&0xF])
				} else {
					buf.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 cannot come from a JavaScript string; encode as U+FFFD.
			buf.WriteString("�")
			i++
			continue
		}
		buf.WriteString(s[i : i+size])
		i += size
	}
	buf.WriteByte('"')
}

// FormatNumber formats f with the ECMAScript Number::toString algorithm
// (the same algorithm encoding/json uses), returning "null" for NaN and ±Inf.
func FormatNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	if f == 0 {
		return "0" // also normalises -0
	}
	abs := math.Abs(f)
	fmtByte := byte('f')
	if abs < 1e-6 || abs >= 1e21 {
		fmtByte = 'e'
	}
	b := strconv.AppendFloat(nil, f, fmtByte, -1, 64)
	if fmtByte == 'e' {
		// clean up e-09 to e-9, and add the explicit + JavaScript uses (1e+21)
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
		// strconv writes e+21; JavaScript writes e+21 as well — keep it.
	}
	return string(b)
}

// Parse decodes JSON. Objects become *Object (order preserved), arrays []any,
// numbers float64, plus string, bool and nil.
func Parse(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("jsonx: trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseFromToken(dec, tok)
}

func parseFromToken(dec *json.Decoder, tok json.Token) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := NewObject()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("jsonx: object key is not a string")
				}
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				// JSON.parse keeps the last duplicate but the first position.
				obj.Set(key, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("jsonx: unexpected delimiter %v", t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			// JSON.parse yields Infinity for overflowing literals.
			var numErr *strconv.NumError
			if errors.As(err, &numErr) && errors.Is(numErr.Err, strconv.ErrRange) {
				return f, nil
			}
			return nil, err
		}
		return f, nil
	default:
		return t, nil
	}
}

// iso8601 matches the strings Better Auth's safeJSONParse revives into Dates.
func isISO8601(s string) bool {
	// ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$
	if len(s) < 20 {
		return false
	}
	digits := func(from, to int) bool {
		for i := from; i < to; i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	if !digits(0, 4) || s[4] != '-' || !digits(5, 7) || s[7] != '-' || !digits(8, 10) ||
		s[10] != 'T' || !digits(11, 13) || s[13] != ':' || !digits(14, 16) || s[16] != ':' ||
		!digits(17, 19) {
		return false
	}
	rest := s[19:]
	if rest == "Z" {
		return true
	}
	if len(rest) < 3 || rest[0] != '.' || rest[len(rest)-1] != 'Z' {
		return false
	}
	frac := rest[1 : len(rest)-1]
	for i := 0; i < len(frac); i++ {
		if frac[i] < '0' || frac[i] > '9' {
			return false
		}
	}
	return len(frac) > 0
}

// ParseJSDate parses a date string the way `new Date(string)` does for the ISO formats
// Better Auth produces. It returns false when the string is not a valid date.
func ParseJSDate(s string) (time.Time, bool) {
	layouts := []string{
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02",
		time.RFC1123,
		time.RFC1123Z,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			// JavaScript dates have millisecond precision.
			return t.Truncate(time.Millisecond), true
		}
	}
	return time.Time{}, false
}

// ReviveDates mirrors Better Auth's safeJSONParse reviver: every string matching
// ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$ that is a valid date becomes a time.Time.
func ReviveDates(v any) any {
	switch t := v.(type) {
	case string:
		if isISO8601(t) {
			if d, ok := ParseJSDate(t); ok {
				return d
			}
		}
		return t
	case *Object:
		out := NewObject()
		for _, k := range t.keys {
			out.Set(k, ReviveDates(t.vals[k]))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = ReviveDates(x)
		}
		return out
	default:
		return v
	}
}

// EncodeUTF16Length returns the length of s in UTF-16 code units (JavaScript string length).
func EncodeUTF16Length(s string) int {
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

// JSSubstring returns s[start:end] measured in UTF-16 code units, like String.prototype.substring.
func JSSubstring(s string, start, end int) string {
	u := utf16.Encode([]rune(s))
	if start < 0 {
		start = 0
	}
	if end > len(u) {
		end = len(u)
	}
	if start >= end {
		return ""
	}
	return string(utf16.Decode(u[start:end]))
}
