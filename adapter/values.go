package adapter

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// ToString converts a value to its JavaScript String() form.
func ToString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	case float64:
		return jsonx.FormatNumber(t)
	case float32:
		return jsonx.FormatNumber(float64(t))
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case time.Time:
		return jsonx.ISOTime(t)
	case interface{ Hex() string }:
		// e.g. MongoDB ObjectIDs: JS String(objectId) is the hex string
		return t.Hex()
	case fmt.Stringer:
		return t.String()
	}
	return fmt.Sprint(v)
}

// ToFloat converts numeric values (and numeric strings from drivers) to float64.
func ToFloat(v any) (float64, bool) {
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
	case int16:
		return float64(t), true
	case int8:
		return float64(t), true
	case uint:
		return float64(t), true
	case uint64:
		return float64(t), true
	case uint32:
		return float64(t), true
	case []byte:
		f, err := strconv.ParseFloat(string(t), 64)
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil && strings.TrimSpace(t) != ""
	}
	return 0, false
}

// ToInt64 converts a numeric value to int64.
func ToInt64(v any) (int64, bool) {
	f, ok := ToFloat(v)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

// ToBool converts a stored boolean.
func ToBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case int64:
		return t == 1
	case float64:
		return t == 1
	case int:
		return t == 1
	case string:
		return t == "true" || t == "1"
	}
	return false
}

// ToTime converts a stored date (time.Time, ISO string, epoch millis) to time.Time.
func ToTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, true
	case string:
		if tm, ok := jsonx.ParseJSDate(t); ok {
			return tm, true
		}
		if tm, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", t); err == nil {
			return tm, true
		}
		if tm, err := time.Parse("2006-01-02 15:04:05.999999999", t); err == nil {
			return tm, true
		}
		return time.Time{}, false
	case []byte:
		return ToTime(string(t))
	case int64:
		return time.UnixMilli(t), true
	case float64:
		return time.UnixMilli(int64(t)), true
	}
	return time.Time{}, false
}

func toAnySlice(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	case []string:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = x
		}
		return out, true
	case []int:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = int64(x)
		}
		return out, true
	case []int64:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = x
		}
		return out, true
	case []float64:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = x
		}
		return out, true
	}
	return nil, false
}

// ToSlice converts a slice value of any element type to []any.
func ToSlice(v any) ([]any, bool) { return toAnySlice(v) }

// Equal compares two stored values (numbers by value, times by instant).
func Equal(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if fa, ok := numeric(a); ok {
		if fb, ok := numeric(b); ok {
			return fa == fb
		}
		return false
	}
	if ta, ok := a.(time.Time); ok {
		if tb, ok := b.(time.Time); ok {
			return ta.Equal(tb)
		}
		return false
	}
	switch at := a.(type) {
	case string:
		bt, ok := b.(string)
		return ok && at == bt
	case bool:
		bt, ok := b.(bool)
		return ok && at == bt
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func numeric(v any) (float64, bool) {
	switch v.(type) {
	case float64, float32, int, int64, int32, int16, int8, uint, uint64, uint32:
		return ToFloat(v)
	}
	return 0, false
}

// Compare orders two values: -1, 0 or 1. ok is false when they are not comparable
// (JavaScript relational operators would yield false).
func Compare(a, b any) (int, bool) {
	if a == nil || b == nil {
		return 0, false
	}
	if fa, ok := numeric(a); ok {
		fb, ok := numeric(b)
		if !ok {
			return 0, false
		}
		switch {
		case fa < fb:
			return -1, true
		case fa > fb:
			return 1, true
		}
		return 0, !math.IsNaN(fa)
	}
	if ta, ok := a.(time.Time); ok {
		tb, ok := b.(time.Time)
		if !ok {
			return 0, false
		}
		return ta.Compare(tb), true
	}
	if sa, ok := a.(string); ok {
		sb, ok := b.(string)
		if !ok {
			return 0, false
		}
		return strings.Compare(sa, sb), true
	}
	if ba, ok := a.(bool); ok {
		bb, ok := b.(bool)
		if !ok {
			return 0, false
		}
		switch {
		case ba == bb:
			return 0, true
		case ba:
			return 1, true
		}
		return -1, true
	}
	return 0, false
}
