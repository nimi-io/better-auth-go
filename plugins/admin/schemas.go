package admin

import (
	"math"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// jsString implements JavaScript String(v) for JSON values.
func jsString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if math.IsNaN(t) {
			return "NaN"
		}
		if math.IsInf(t, 1) {
			return "Infinity"
		}
		if math.IsInf(t, -1) {
			return "-Infinity"
		}
		return jsonx.FormatNumber(t)
	case int:
		return jsonx.FormatNumber(float64(t))
	case int64:
		return jsonx.FormatNumber(float64(t))
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if x == nil || validate.IsUndefined(x) {
				continue
			}
			parts[i] = jsString(x)
		}
		return strings.Join(parts, ",")
	case []string:
		return strings.Join(t, ",")
	}
	if validate.IsUndefined(v) {
		return "undefined"
	}
	return "[object Object]"
}

// coerceString is z.coerce.string() (undefined becomes "undefined", like String(undefined)).
// nonEmptyMessage, when set, adds .nonempty(message).
func coerceString(nonEmptyMessage string) validate.Schema {
	inner := validate.String()
	if nonEmptyMessage != "" {
		inner = inner.MinMessage(1, nonEmptyMessage)
	}
	return validate.Preprocess(func(v any) any { return jsString(v) }, inner)
}

// xor is z.xor([...]): exactly one option must match.
func xor(options ...validate.Schema) validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		var match any
		n := 0
		for _, o := range options {
			out, issues := validate.Validate(o, v)
			if len(issues) == 0 {
				n++
				match = out
			}
		}
		if n == 1 {
			return match, nil
		}
		if n > 1 {
			return nil, []validate.Issue{validate.NewIssue(path, "invalid_union", "Invalid input: more than one option matched")}
		}
		return nil, []validate.Issue{validate.NewIssue(path, "invalid_union", "Invalid input")}
	})
}
