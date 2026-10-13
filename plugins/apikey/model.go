package apikey

import (
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// APIKey is an API key row (ApiKey upstream). Numbers are float64 like JavaScript numbers.
type APIKey struct {
	ID                  string
	ConfigID            string
	Name                *string
	Start               *string
	Prefix              *string
	Key                 string
	ReferenceID         string
	RefillInterval      *float64
	RefillAmount        *float64
	LastRefillAt        *time.Time
	Enabled             *bool
	RateLimitEnabled    *bool
	RateLimitTimeWindow *float64
	RateLimitMax        *float64
	RequestCount        float64
	Remaining           *float64
	LastRequest         *time.Time
	ExpiresAt           *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	// Permissions is the stored JSON string.
	Permissions *string
	// Metadata is the parsed metadata (object), a string for legacy double-stringified
	// rows, or nil.
	Metadata any
}

// fieldOrder is the apikey schema field order (adapter output order, "id" last).
var fieldOrder = []string{"configId", "name", "start", "referenceId", "prefix", "key", "refillInterval",
	"refillAmount", "lastRefillAt", "enabled", "rateLimitEnabled", "rateLimitTimeWindow", "rateLimitMax",
	"requestCount", "remaining", "lastRequest", "expiresAt", "createdAt", "updatedAt", "permissions",
	"metadata", "id"}

func strPtr(v any) *string {
	switch t := v.(type) {
	case string:
		return &t
	case []byte:
		s := string(t)
		return &s
	}
	return nil
}

func numPtr(v any) *float64 {
	if v == nil {
		return nil
	}
	if f, ok := adapter.ToFloat(v); ok {
		return &f
	}
	return nil
}

func timePtr(v any) *time.Time {
	switch t := v.(type) {
	case nil:
		return nil
	case time.Time:
		u := t.UTC()
		return &u
	case *time.Time:
		if t == nil {
			return nil
		}
		u := t.UTC()
		return &u
	case string:
		if t == "" {
			return nil
		}
		if d, ok := jsonx.ParseJSDate(t); ok {
			d = d.UTC()
			return &d
		}
	}
	if d, ok := adapter.ToTime(v); ok {
		d = d.UTC()
		return &d
	}
	return nil
}

func boolPtr(v any) *bool {
	switch t := v.(type) {
	case nil:
		return nil
	case bool:
		return &t
	}
	b := adapter.ToBool(v)
	return &b
}

func getField(m any, k string) (any, bool) {
	switch t := m.(type) {
	case map[string]any:
		v, ok := t[k]
		return v, ok
	case *jsonx.Object:
		return t.Get(k)
	}
	return nil, false
}

// keyFromRecord converts an adapter record (or a parsed storage object) to an APIKey.
func keyFromRecord(rec any) *APIKey {
	if rec == nil {
		return nil
	}
	g := func(k string) any { v, _ := getField(rec, k); return v }
	k := &APIKey{
		ID:                  adapter.ToString(g("id")),
		Name:                strPtr(g("name")),
		Start:               strPtr(g("start")),
		Prefix:              strPtr(g("prefix")),
		RefillInterval:      numPtr(g("refillInterval")),
		RefillAmount:        numPtr(g("refillAmount")),
		LastRefillAt:        timePtr(g("lastRefillAt")),
		Enabled:             boolPtr(g("enabled")),
		RateLimitEnabled:    boolPtr(g("rateLimitEnabled")),
		RateLimitTimeWindow: numPtr(g("rateLimitTimeWindow")),
		RateLimitMax:        numPtr(g("rateLimitMax")),
		Remaining:           numPtr(g("remaining")),
		LastRequest:         timePtr(g("lastRequest")),
		ExpiresAt:           timePtr(g("expiresAt")),
		Permissions:         strPtr(g("permissions")),
		Metadata:            g("metadata"),
	}
	if g("id") == nil {
		k.ID = ""
	}
	if s := strPtr(g("configId")); s != nil {
		k.ConfigID = *s
	}
	if s := strPtr(g("key")); s != nil {
		k.Key = *s
	}
	if v := g("referenceId"); v != nil {
		k.ReferenceID = adapter.ToString(v)
	}
	if n := numPtr(g("requestCount")); n != nil {
		k.RequestCount = *n
	}
	if t := timePtr(g("createdAt")); t != nil {
		k.CreatedAt = *t
	}
	if t := timePtr(g("updatedAt")); t != nil {
		k.UpdatedAt = *t
	}
	return k
}

func optStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func optNum(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func optTime(p *time.Time) any {
	if p == nil {
		return nil
	}
	return *p
}

func optBool(p *bool) any {
	if p == nil {
		return nil
	}
	return *p
}

func (k *APIKey) get(field string) any {
	switch field {
	case "id":
		return k.ID
	case "configId":
		if k.ConfigID == "" {
			return nil
		}
		return k.ConfigID
	case "name":
		return optStr(k.Name)
	case "start":
		return optStr(k.Start)
	case "referenceId":
		return k.ReferenceID
	case "prefix":
		return optStr(k.Prefix)
	case "key":
		return k.Key
	case "refillInterval":
		return optNum(k.RefillInterval)
	case "refillAmount":
		return optNum(k.RefillAmount)
	case "lastRefillAt":
		return optTime(k.LastRefillAt)
	case "enabled":
		return optBool(k.Enabled)
	case "rateLimitEnabled":
		return optBool(k.RateLimitEnabled)
	case "rateLimitTimeWindow":
		return optNum(k.RateLimitTimeWindow)
	case "rateLimitMax":
		return optNum(k.RateLimitMax)
	case "requestCount":
		return k.RequestCount
	case "remaining":
		return optNum(k.Remaining)
	case "lastRequest":
		return optTime(k.LastRequest)
	case "expiresAt":
		return optTime(k.ExpiresAt)
	case "createdAt":
		return k.CreatedAt
	case "updatedAt":
		return k.UpdatedAt
	case "permissions":
		return optStr(k.Permissions)
	case "metadata":
		return k.Metadata
	}
	return nil
}

// object renders the key in adapter output order.
func (k *APIKey) object() *jsonx.Object {
	o := jsonx.NewObject()
	for _, f := range fieldOrder {
		o.Set(f, k.get(f))
	}
	return o
}

// record returns the key as an adapter record (without id).
func (k *APIKey) record() adapter.Record {
	r := adapter.Record{}
	for _, f := range fieldOrder {
		if f == "id" {
			continue
		}
		r[f] = k.get(f)
	}
	return r
}

func (k *APIKey) clone() *APIKey {
	c := *k
	return &c
}

func isDisabled(b *bool) bool { return b != nil && !*b }

// parsePermissions is safeJSONParse of the stored permissions (nil when empty or invalid).
func parsePermissions(p *string) any {
	if p == nil || *p == "" {
		return nil
	}
	v, err := jsonx.Parse([]byte(*p))
	if err != nil {
		return nil
	}
	return jsonx.ReviveDates(v)
}

// parseDoubleStringifiedMetadata returns object metadata as-is and parses string metadata.
func parseDoubleStringifiedMetadata(m any) any {
	switch t := m.(type) {
	case nil:
		return nil
	case string:
		v, err := jsonx.Parse([]byte(t))
		if err != nil {
			return nil
		}
		return jsonx.ReviveDates(v)
	}
	return m
}

func needsMetadataMigration(m any) bool {
	_, ok := m.(string)
	return ok
}

// publicObject renders the key without the hashed key, with parsed metadata and
// permissions (the get/update/list/verify response shape).
func (k *APIKey) publicObject(metadata any) *jsonx.Object {
	o := k.object()
	o.Delete("key")
	o.Set("metadata", metadata)
	o.Set("permissions", parsePermissions(k.Permissions))
	return o
}
