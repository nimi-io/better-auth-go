package scim

import (
	"regexp"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// active-normalization.ts: Microsoft Entra sends "True"/"False" strings for booleans.

func normalizeStringBoolean(v any) (any, bool) {
	s, ok := v.(string)
	if !ok {
		return v, false
	}
	switch jsLower(s) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return v, false
}

func normalizeActiveProperty(o *jsonx.Object) *jsonx.Object {
	v, ok := o.Get("active")
	if !ok {
		return o
	}
	n, changed := normalizeStringBoolean(v)
	if !changed {
		return o
	}
	c := o.Clone()
	c.Set("active", n)
	return c
}

var multiValuedPrimaryAttributes = []string{"emails", "phoneNumbers", "addresses", "roles", "entitlements"}

func normalizePrimaryEntry(entry any) (any, bool) {
	o, ok := entry.(*jsonx.Object)
	if !ok {
		return entry, false
	}
	v, ok := o.Get("primary")
	if !ok {
		return entry, false
	}
	n, changed := normalizeStringBoolean(v)
	if !changed {
		return entry, false
	}
	c := o.Clone()
	c.Set("primary", n)
	return c, true
}

func normalizePrimaryValue(v any) (any, bool) {
	arr, ok := v.([]any)
	if !ok {
		return normalizePrimaryEntry(v)
	}
	changed := false
	out := make([]any, len(arr))
	for i, e := range arr {
		n, c := normalizePrimaryEntry(e)
		if c {
			changed = true
		}
		out[i] = n
	}
	if !changed {
		return v, false
	}
	return out, true
}

func normalizeResourcePrimaries(o *jsonx.Object) *jsonx.Object {
	var c *jsonx.Object
	for _, attr := range multiValuedPrimaryAttributes {
		v, ok := o.Get(attr)
		if !ok {
			continue
		}
		n, changed := normalizePrimaryValue(v)
		if !changed {
			continue
		}
		if c == nil {
			c = o.Clone()
		}
		c.Set(attr, n)
	}
	if c == nil {
		return o
	}
	return c
}

func normalizeUserResource(o *jsonx.Object) *jsonx.Object {
	return normalizeResourcePrimaries(normalizeActiveProperty(o))
}

var multiValuedPrimaryPath = regexp.MustCompile(`(?i)^(emails|phonenumbers|addresses|roles|entitlements)\s*(\[[^\]]*\])?(?:\s*\.\s*(primary))?$`)

func isPathless(p any) bool {
	if isUndef(p) {
		return true
	}
	s, ok := p.(string)
	return ok && jsTrim(s) == ""
}

func normalizePatchOperationEntra(op any) (any, bool) {
	o, ok := op.(*jsonx.Object)
	if !ok {
		return op, false
	}
	path := objGet(o, "path")
	value := objGet(o, "value")
	if ps, ok := path.(string); ok && jsLower(stripCoreAttributePrefix(resourceUser, jsTrim(ps))) == "active" {
		n, changed := normalizeStringBoolean(value)
		if !changed {
			return op, false
		}
		c := o.Clone()
		c.Set("value", n)
		return c, true
	}
	if ps, ok := path.(string); ok {
		m := multiValuedPrimaryPath.FindStringSubmatch(stripCoreAttributePrefix(resourceUser, jsTrim(ps)))
		if m != nil {
			var n any
			var changed bool
			if m[3] != "" {
				n, changed = normalizeStringBoolean(value)
			} else {
				n, changed = normalizePrimaryValue(value)
			}
			if !changed {
				return op, false
			}
			c := o.Clone()
			c.Set("value", n)
			return c, true
		}
	}
	if isPathless(path) {
		if vo, ok := value.(*jsonx.Object); ok {
			n := normalizeUserResource(vo)
			if n == vo {
				return op, false
			}
			c := o.Clone()
			c.Set("value", n)
			return c, true
		}
	}
	return op, false
}

// normalizeUserEntraCompatibilityBody is normalizeSCIMUserEntraCompatibilityRequestBody.
// It returns the body unchanged (same pointer) when nothing was normalized.
func normalizeUserEntraCompatibilityBody(method string, body any) any {
	o, ok := body.(*jsonx.Object)
	if !ok {
		return body
	}
	if method == "POST" || method == "PUT" {
		return normalizeUserResource(o)
	}
	ops, ok := objGet(o, "Operations").([]any)
	if method != "PATCH" || !ok {
		return body
	}
	changed := false
	out := make([]any, len(ops))
	for i, op := range ops {
		n, c := normalizePatchOperationEntra(op)
		if c {
			changed = true
		}
		out[i] = n
	}
	if !changed {
		return body
	}
	c := o.Clone()
	c.Set("Operations", out)
	return c
}
