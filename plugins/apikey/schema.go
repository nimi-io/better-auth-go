package apikey

import (
	_ "embed"
	"strings"

	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

//go:embed openapi.json
var openapiJSON []byte

var openapi = func() *jsonx.Object {
	v, err := jsonx.Parse(openapiJSON)
	if err != nil {
		panic(err)
	}
	return v.(*jsonx.Object)
}()

func openapiMeta(key string) map[string]any {
	v, ok := openapi.Get(key)
	if !ok {
		return nil
	}
	return map[string]any{"openapi": v}
}

// tables returns the apikey table (apiKeySchema merged with options.schema).
func (p *plugin) tables() []db.PluginTable {
	maxReq, window := 10.0, float64(1000*60*60*24)
	if len(p.configs) == 1 {
		maxReq = p.configs[0].rateLimitMaxRequests
		window = p.configs[0].rateLimitTimeWindow
	}
	no := db.Bool(false)
	yes := db.Bool(true)
	fields := []db.Field{
		{Name: "configId", Type: db.TypeString, Required: yes, DefaultValue: "default", Input: no, Index: true},
		{Name: "name", Type: db.TypeString, Required: no, Input: no},
		{Name: "start", Type: db.TypeString, Required: no, Input: no},
		{Name: "referenceId", Type: db.TypeString, Required: yes, Input: no, Index: true},
		{Name: "prefix", Type: db.TypeString, Required: no, Input: no},
		{Name: "key", Type: db.TypeString, Required: yes, Input: no, Index: true},
		{Name: "refillInterval", Type: db.TypeNumber, Required: no, Input: no},
		{Name: "refillAmount", Type: db.TypeNumber, Required: no, Input: no},
		{Name: "lastRefillAt", Type: db.TypeDate, Required: no, Input: no},
		{Name: "enabled", Type: db.TypeBoolean, Required: no, Input: no, DefaultValue: true},
		{Name: "rateLimitEnabled", Type: db.TypeBoolean, Required: no, Input: no, DefaultValue: true},
		{Name: "rateLimitTimeWindow", Type: db.TypeNumber, Required: no, Input: no, DefaultValue: window},
		{Name: "rateLimitMax", Type: db.TypeNumber, Required: no, Input: no, DefaultValue: maxReq},
		{Name: "requestCount", Type: db.TypeNumber, Required: no, Input: no, DefaultValue: float64(0)},
		{Name: "remaining", Type: db.TypeNumber, Required: no, Input: no},
		{Name: "lastRequest", Type: db.TypeDate, Required: no, Input: no},
		{Name: "expiresAt", Type: db.TypeDate, Required: no, Input: no},
		{Name: "createdAt", Type: db.TypeDate, Required: yes, Input: no},
		{Name: "updatedAt", Type: db.TypeDate, Required: yes, Input: no},
		{Name: "permissions", Type: db.TypeString, Required: no, Input: no},
		{Name: "metadata", Type: db.TypeString, Required: no, Input: yes,
			TransformInput: metadataInput, TransformOutput: metadataOutput},
	}
	t := db.PluginTable{Key: TableName, Fields: fields}
	if s := p.schema; s != nil {
		t.ModelName = s.ModelName
		for i := range t.Fields {
			if col, ok := s.Fields[t.Fields[i].Name]; ok {
				t.Fields[i].FieldName = col
			}
		}
	}
	return []db.PluginTable{t}
}

// metadataInput is transform.input: JSON.stringify(value). The factory passes nil both
// for null and for an absent field; the plugin always writes metadata explicitly, so nil
// is stored as "null" like upstream.
func metadataInput(v any) (any, error) {
	if v == jsonx.Undefined {
		return jsonx.Undefined, nil
	}
	s, err := jsonx.Stringify(v)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// metadataOutput is transform.output: falsy -> null, otherwise parseJSON(value).
func metadataOutput(v any) (any, error) {
	var s string
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		s = t
	case []byte:
		s = string(t)
	default:
		return v, nil
	}
	if s == "" {
		return nil, nil
	}
	return parseJSON(s)
}

// parseJSON is parseJSON from better-auth/client (strict): special literals, JSON with
// date revival, and an error for invalid input.
func parseJSON(s string) (any, error) {
	trimmed := strings.TrimSpace(s)
	switch strings.ToLower(trimmed) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null", "undefined":
		return nil, nil
	}
	v, err := jsonx.Parse([]byte(trimmed))
	if err != nil {
		return nil, err
	}
	return jsonx.ReviveDates(v), nil
}
