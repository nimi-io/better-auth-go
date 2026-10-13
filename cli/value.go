package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/nimi-io/better-auth-go/db"
)

// object is a JSON object that keeps insertion order (like a JavaScript object).
type object struct {
	keys []string
	vals map[string]any
}

func newObject() *object { return &object{vals: map[string]any{}} }

func (o *object) set(k string, v any) *object {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *object) get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *object) len() int { return len(o.keys) }

// MarshalJSON implements json.Marshaler.
func (o *object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// jsonKey turns a Go field name into the camelCase key upstream uses ("BaseURL" → "baseURL",
// "EmailAndPassword" → "emailAndPassword", "IPAddress" → "ipAddress").
func jsonKey(name string) string {
	if k, ok := keyOverrides[name]; ok {
		return k
	}
	r := []rune(name)
	n := 0
	for n < len(r) && unicode.IsUpper(r[n]) {
		n++
	}
	switch {
	case n == 0:
		return name
	case n == len(r):
		return strings.ToLower(name)
	case n > 1:
		n-- // keep the capital that starts the next word
	}
	for i := 0; i < n; i++ {
		r[i] = unicode.ToLower(r[i])
	}
	// "ClientID" → "clientId", "ClientIDs" → "clientIds", "DisableIDTokenSignIn" →
	// "disableIdTokenSignIn" (upstream spells id as "Id").
	for i := 1; i+1 < len(r); i++ {
		if r[i] == 'I' && r[i+1] == 'D' && (i+2 == len(r) || unicode.IsUpper(r[i+2]) || r[i+2] == 's') {
			r[i+1] = 'd'
		}
	}
	return string(r)
}

var keyOverrides = map[string]string{
	"IPv6Subnet": "ipv6Subnet",
	"HTTPOnly":   "httpOnly",
}

var (
	durationType = reflect.TypeOf(time.Duration(0))
	timeType     = reflect.TypeOf(time.Time{})
	fieldsType   = reflect.TypeOf([]db.Field(nil))
	errorType    = reflect.TypeOf((*error)(nil)).Elem()
)

// toValue converts a Go value to the JSON-like tree JSON.parse(JSON.stringify(x)) yields
// upstream: functions and channels are dropped, zero-valued struct fields are omitted
// (Go cannot tell them from unset options), durations are seconds (upstream's unit),
// []db.Field becomes an object keyed by field name (additionalFields). ok=false means
// "omit".
func toValue(v reflect.Value, depth int, seen map[uintptr]bool) (any, bool) {
	if !v.IsValid() || depth > 12 {
		return nil, false
	}
	switch v.Kind() {
	case reflect.Func, reflect.Chan, reflect.UnsafePointer, reflect.Uintptr:
		return nil, false
	case reflect.Interface:
		if v.IsNil() {
			return nil, false
		}
		// an implementation object (logger, storage) with no exported state is omitted
		val, ok := toValue(v.Elem(), depth, seen)
		if o, isObj := val.(*object); ok && isObj && o.len() == 0 {
			return nil, false
		}
		return val, ok
	case reflect.Pointer:
		if v.IsNil() {
			return nil, false
		}
		p := v.Pointer()
		if seen[p] {
			return nil, false
		}
		seen[p] = true
		defer delete(seen, p)
		return toValue(v.Elem(), depth+1, seen)
	}
	if v.Type() == durationType {
		return durationSeconds(time.Duration(v.Int())), true
	}
	if v.Type() == timeType {
		return v.Interface().(time.Time).UTC().Format(time.RFC3339Nano), true
	}
	if v.Type().Implements(errorType) && v.CanInterface() {
		return v.Interface().(error).Error(), true
	}
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint(), true
	case reflect.Float32, reflect.Float64:
		return v.Float(), true
	case reflect.String:
		return v.String(), true
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return nil, false
		}
		if v.Type() == fieldsType {
			o := newObject()
			for i := 0; i < v.Len(); i++ {
				f := v.Index(i)
				val, ok := toValue(f, depth+1, seen)
				if !ok {
					continue
				}
				if m, isObj := val.(*object); isObj {
					name := f.FieldByName("Name").String()
					delete(m.vals, "name")
					m.keys = removeKey(m.keys, "name")
					o.set(name, m)
				}
			}
			return o, true
		}
		out := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			val, ok := toValue(v.Index(i), depth+1, seen)
			if !ok {
				val = nil // JSON.stringify writes null for functions in arrays
			}
			out = append(out, val)
		}
		return out, true
	case reflect.Map:
		if v.IsNil() {
			return nil, false
		}
		o := newObject()
		keys := v.MapKeys()
		strs := make([]string, len(keys))
		for i, k := range keys {
			strs[i] = fmt.Sprint(k.Interface())
		}
		order := make([]int, len(keys))
		for i := range order {
			order[i] = i
		}
		sortIdx(order, strs)
		for _, i := range order {
			if val, ok := toValue(v.MapIndex(keys[i]), depth+1, seen); ok {
				o.set(strs[i], val)
			}
		}
		return o, true
	case reflect.Struct:
		o := newObject()
		structFields(v, o, depth, seen)
		return o, true
	}
	return nil, false
}

func structFields(v reflect.Value, o *object, depth int, seen map[uintptr]bool) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		fv := v.Field(i)
		if sf.Anonymous && deref(fv).Kind() == reflect.Struct {
			if inner := deref(fv); inner.IsValid() {
				structFields(inner, o, depth, seen)
			}
			continue
		}
		if !sf.IsExported() || fv.IsZero() {
			continue
		}
		if val, ok := toValue(fv, depth+1, seen); ok {
			o.set(jsonKey(sf.Name), val)
		}
	}
}

func removeKey(keys []string, k string) []string {
	out := keys[:0]
	for _, x := range keys {
		if x != k {
			out = append(out, x)
		}
	}
	return out
}

func sortIdx(order []int, by []string) {
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && by[order[j]] < by[order[j-1]]; j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
}

func durationSeconds(d time.Duration) any {
	if d%time.Second == 0 {
		return int64(d / time.Second)
	}
	return d.Seconds()
}

// formatScalar prints a primitive the way JavaScript template strings do.
func formatScalar(v any) string {
	switch x := v.(type) {
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32)
	}
	return fmt.Sprint(v)
}

func deref(v reflect.Value) reflect.Value {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}
