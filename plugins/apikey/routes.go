package apikey

import (
	"context"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// resolveConfiguration returns the configuration with configID, falling back to the
// default configuration (no configId or "default").
func (p *plugin) resolveConfiguration(ac *betterauth.AuthContext, configID string) (*config, error) {
	def := func() (*config, error) {
		for _, c := range p.configs {
			if c.ConfigID == "" || c.ConfigID == "default" {
				cp := *c
				cp.ConfigID = "default"
				return &cp, nil
			}
		}
		ac.Logger.Error("No default api-key configuration found. Either provide an api-key configuration with configId 'default' or provide a configuration with no `configId` set.")
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrNoDefaultAPIKeyConfigurationFound)
	}
	if configID == "" {
		return def()
	}
	for _, c := range p.configs {
		if c.ConfigID == configID {
			return c, nil
		}
	}
	return def()
}

func isDefaultConfigID(id string) bool { return id == "" || id == "default" }

func configIDMatches(keyConfigID, expected string) bool {
	if isDefaultConfigID(keyConfigID) && isDefaultConfigID(expected) {
		return true
	}
	return keyConfigID == expected
}

// deleteAllExpired deletes expired keys from the database, at most every 10 seconds
// unless bypass is set (deleteAllExpiredApiKeys). Errors are logged.
func (p *plugin) deleteAllExpired(ac *betterauth.AuthContext, bypass bool) {
	p.cleanupMu.Lock()
	now := p.now()
	if !p.lastChecked.IsZero() && !bypass && now.Sub(p.lastChecked) < 10*time.Second {
		p.cleanupMu.Unlock()
		return
	}
	p.lastChecked = now
	p.cleanupMu.Unlock()
	if ac.Adapter == nil {
		return
	}
	_, err := ac.Adapter.DeleteMany(context.Background(), TableName, []adapter.Where{
		{Field: "expiresAt", Operator: adapter.Lt, Value: now},
		{Field: "expiresAt", Operator: adapter.Ne, Value: nil},
	})
	if err != nil {
		ac.Logger.Error("Failed to delete expired API keys:", err)
	}
}

// cleanup runs the expired-key cleanup (fire-and-forget upstream; run inline here).
func (p *plugin) cleanup(ctx *betterauth.EndpointContext) {
	p.deleteAllExpired(ctx.Auth, false)
}

// cleanupDeferred runs the cleanup with advanced.backgroundTasks.
func (p *plugin) cleanupDeferred(ctx *betterauth.EndpointContext) {
	ac := ctx.Auth
	ac.RunInBackground(func() { p.deleteAllExpired(ac, false) })
}

func (p *plugin) deleteAllExpiredEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "deleteAllExpiredApiKeys", Methods: []string{"POST"}, ServerOnly: true,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			p.deleteAllExpired(ctx.Auth, true)
			return jsonx.O("success", true, "error", nil), nil
		},
	}
}

// ---- shared validation schemas ----

// jsString is String(v) in JavaScript for JSON values.
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
		return jsonx.FormatNumber(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if x != nil {
				parts[i] = jsString(x)
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

// coerceString is z.coerce.string().
var coerceString = validate.Custom(func(v any, _ []any) (any, []validate.Issue) {
	if validate.IsUndefined(v) {
		return "undefined", nil
	}
	return jsString(v), nil
})

func withPath(issues []validate.Issue, path []any) []validate.Issue {
	for i := range issues {
		issues[i].Path = append(append([]any(nil), path...), issues[i].Path...)
	}
	return issues
}

var prefixRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// prefixSchema is z.string().regex(/^[a-zA-Z0-9_-]+$/, {message}).
var prefixSchema = validate.Custom(func(v any, path []any) (any, []validate.Issue) {
	out, issues := validate.Validate(validate.String(), v)
	if len(issues) > 0 {
		return nil, withPath(issues, path)
	}
	s := out.(string)
	if !prefixRe.MatchString(s) {
		return nil, []validate.Issue{{Path: path, Code: "invalid_format",
			Message: "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens."}}
	}
	return s, nil
})

// coerceNonNegativeInt is z.coerce.number().int().nonnegative().
var coerceNonNegativeInt = validate.Custom(func(v any, path []any) (any, []validate.Issue) {
	f := jsNumber(v)
	if math.IsNaN(f) {
		return nil, []validate.Issue{{Path: path, Code: "invalid_type", Message: "Invalid input: expected number, received NaN"}}
	}
	if math.IsInf(f, 0) || f != math.Trunc(f) {
		return nil, []validate.Issue{{Path: path, Code: "invalid_type", Message: "Invalid input: expected int, received number"}}
	}
	if f < 0 {
		return nil, []validate.Issue{{Path: path, Code: "too_small", Message: "Too small: expected number to be >=0"}}
	}
	return f, nil
})

// jsNumber is Number(v).
func jsNumber(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && !strings.ContainsAny(s, "_") {
			return f
		}
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			if n, err := strconv.ParseInt(s[2:], 16, 64); err == nil {
				return float64(n)
			}
		}
		switch s {
		case "Infinity", "+Infinity":
			return math.Inf(1)
		case "-Infinity":
			return math.Inf(-1)
		}
		return math.NaN()
	case []any:
		if len(t) == 0 {
			return 0
		}
		if len(t) == 1 {
			return jsNumber(jsString(t[0]))
		}
	}
	return math.NaN()
}

var permissionsSchema = validate.Record(validate.Array(validate.String()))

// ---- small helpers ----

func bodyHas(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

func bodyNum(m map[string]any, k string) *float64 {
	if f, ok := m[k].(float64); ok {
		return &f
	}
	return nil
}

func bodyStr(m map[string]any, k string) (string, bool) {
	s, ok := m[k].(string)
	return s, ok
}

func isClientRequest(ctx *betterauth.EndpointContext) bool {
	return ctx.Request != nil || ctx.Headers != nil
}

// truthy is JavaScript truthiness for JSON values.
func truthy(v any) bool { return validate.Truthy(v) }

func isObject(v any) bool {
	switch v.(type) {
	case map[string]any, *jsonx.Object, []any:
		return true
	}
	return false
}

func jsLen(s string) int { return jsonx.EncodeUTF16Length(s) }

func (p *plugin) date(span time.Duration) time.Time {
	return p.now().Add(span).UTC().Truncate(time.Millisecond)
}

func secondsDuration(sec float64) time.Duration {
	return time.Duration(sec * float64(time.Second))
}

func statementsJSON(s any) (string, error) {
	return jsonx.Stringify(s)
}
