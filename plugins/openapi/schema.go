package openapi

import (
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// This file ports the zod → OpenAPI conversion of upstream's generator
// (packages/better-auth/src/plugins/open-api/generator.ts: toOpenApiSchema and helpers)
// onto validate schemas, using validate.Inspect.

// SchemaFromValidator converts a validator into an OpenAPI 3.1 schema object
// (toOpenApiSchema upstream).
func SchemaFromValidator(s validate.Schema) *jsonx.Object {
	return toOpenAPISchema(s)
}

// RequestBodyRequired reports whether a request body schema rejects a missing body
// (!schemaAcceptsUndefined upstream).
func RequestBodyRequired(s validate.Schema) bool { return !schemaAcceptsUndefined(s) }

func withDescription(schema *jsonx.Object, description string) *jsonx.Object {
	if description == "" {
		return schema
	}
	return schema.Clone().Set("description", description)
}

func addNullType(schema *jsonx.Object) *jsonx.Object {
	if t, ok := schema.Get("type"); ok && t != nil {
		var types []any
		switch tv := t.(type) {
		case []any:
			types = append(types, tv...)
		default:
			types = []any{tv}
		}
		seen := map[any]bool{}
		var out []any
		for _, x := range append(types, "null") {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
		return schema.Clone().Set("type", out)
	}
	return jsonx.O("anyOf", []any{schema, jsonx.O("type", "null")})
}

// unwrapDescribed strips description wrappers: in zod, .describe()/.meta() return a
// clone of the same class, so instanceof checks see the underlying construct.
func unwrapDescribed(s validate.Schema) (validate.Info, string) {
	info := validate.Inspect(s)
	desc := ""
	for info.Kind == validate.KindDescribed {
		if desc == "" {
			desc = info.Description
		}
		info = validate.Inspect(info.Inner)
	}
	return info, desc
}

// inputOptionality mirrors getZodInputOptionality: "optional" when the key may be omitted.
func inputOptional(s validate.Schema) bool {
	info, _ := unwrapDescribed(s)
	switch info.Kind {
	case validate.KindOptional, validate.KindDefault, validate.KindPrefault:
		return true
	case validate.KindNullable, validate.KindCatch:
		return inputOptional(info.Inner)
	case validate.KindPipe:
		return inputOptional(info.Inner)
	case validate.KindUnion:
		for _, o := range info.Options {
			if inputOptional(o) {
				return true
			}
		}
	}
	return false
}

func schemaAcceptsUndefined(s validate.Schema) bool {
	info, _ := unwrapDescribed(s)
	switch info.Kind {
	case validate.KindOptional, validate.KindDefault, validate.KindPrefault, validate.KindCatch,
		validate.KindAny, validate.KindUnknown, validate.KindUndefined, validate.KindVoid:
		return true
	case validate.KindNonOptional:
		return false
	case validate.KindNullable, validate.KindPipe:
		return schemaAcceptsUndefined(info.Inner)
	case validate.KindUnion:
		for _, o := range info.Options {
			if schemaAcceptsUndefined(o) {
				return true
			}
		}
		return false
	case validate.KindIntersection:
		return schemaAcceptsUndefined(info.Left) && schemaAcceptsUndefined(info.Right)
	}
	return false
}

func isUndefinedOnly(s validate.Schema) bool {
	info, _ := unwrapDescribed(s)
	return info.Kind == validate.KindUndefined || info.Kind == validate.KindVoid
}

func typeIncludes(t any, name string) bool {
	switch tv := t.(type) {
	case string:
		return tv == name
	case []any:
		for _, x := range tv {
			if x == name {
				return true
			}
		}
	}
	return false
}

func isMergeableObjectSchema(s *jsonx.Object) bool {
	if s == nil {
		return false
	}
	t, _ := s.Get("type")
	_, hasRef := s.Get("$ref")
	_, hasAllOf := s.Get("allOf")
	_, hasAnyOf := s.Get("anyOf")
	return typeIncludes(t, "object") && !hasRef && !hasAllOf && !hasAnyOf
}

func schemaAllowsNull(s *jsonx.Object) bool {
	t, _ := s.Get("type")
	_, isArr := t.([]any)
	return isArr && typeIncludes(t, "null")
}

func jsonEqual(a, b any) bool {
	x, err1 := jsonx.Marshal(a)
	y, err2 := jsonx.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

func membersCompatible(left, right any, lok, rok bool) bool {
	if !lok || !rok {
		return true
	}
	lb, lIsBool := left.(bool)
	rb, rIsBool := right.(bool)
	if lIsBool || rIsBool {
		return lIsBool && rIsBool && lb == rb
	}
	return jsonEqual(left, right)
}

func mergeObjectSchemas(left, right *jsonx.Object, description string) *jsonx.Object {
	properties := jsonx.NewObject()
	if lp, ok := left.Get("properties"); ok {
		if lo, ok := lp.(*jsonx.Object); ok {
			properties = lo.Clone()
		}
	}
	if rp, ok := right.Get("properties"); ok {
		if ro, ok := rp.(*jsonx.Object); ok {
			for _, k := range ro.Keys() {
				v, _ := ro.Get(k)
				if cur, exists := properties.Get(k); exists && !jsonEqual(cur, v) {
					return nil
				}
				properties.Set(k, v)
			}
		}
	}
	var required []any
	seen := map[any]bool{}
	for _, side := range []*jsonx.Object{left, right} {
		if r, ok := side.Get("required"); ok {
			if arr, ok := r.([]any); ok {
				for _, x := range arr {
					if !seen[x] {
						seen[x] = true
						required = append(required, x)
					}
				}
			}
		}
	}
	lap, lapOK := left.Get("additionalProperties")
	rap, rapOK := right.Get("additionalProperties")
	if !membersCompatible(lap, rap, lapOK, rapOK) {
		return nil
	}
	lpn, lpnOK := left.Get("propertyNames")
	rpn, rpnOK := right.Get("propertyNames")
	if !membersCompatible(lpn, rpn, lpnOK, rpnOK) {
		return nil
	}
	var typ any = "object"
	if schemaAllowsNull(left) && schemaAllowsNull(right) {
		typ = []any{"object", "null"}
	}
	out := jsonx.O("type", typ)
	if properties.Len() > 0 {
		out.Set("properties", properties)
	}
	if len(required) > 0 {
		out.Set("required", required)
	}
	if lapOK {
		out.Set("additionalProperties", lap)
	} else if rapOK {
		out.Set("additionalProperties", rap)
	}
	if lpnOK {
		out.Set("propertyNames", lpn)
	} else if rpnOK {
		out.Set("propertyNames", rpn)
	}
	desc := description
	if desc == "" {
		if d, ok := left.Get("description"); ok {
			desc, _ = d.(string)
		}
	}
	if desc == "" {
		if d, ok := right.Get("description"); ok {
			desc, _ = d.(string)
		}
	}
	if desc != "" {
		out.Set("description", desc)
	}
	return out
}

func toOpenAPISchema(s validate.Schema) *jsonx.Object {
	info, desc := unwrapDescribed(s)
	switch info.Kind {
	case validate.KindOptional, validate.KindDefault, validate.KindPrefault, validate.KindNonOptional:
		return toOpenAPISchema(info.Inner)
	case validate.KindNullable:
		return addNullType(toOpenAPISchema(info.Inner))
	case validate.KindAny, validate.KindUnknown, validate.KindUndefined, validate.KindVoid:
		return withDescription(jsonx.NewObject(), desc)
	case validate.KindObject:
		properties := jsonx.NewObject()
		var required []any
		for _, f := range info.Fields {
			properties.Set(f.Name, toOpenAPISchema(f.Schema))
			if !inputOptional(f.Schema) {
				required = append(required, f.Name)
			}
		}
		out := jsonx.O("type", "object", "properties", properties)
		if len(required) > 0 {
			out.Set("required", required)
		}
		return withDescription(out, desc)
	case validate.KindRecord:
		var key *jsonx.Object
		if info.Key != nil {
			key = toOpenAPISchema(info.Key)
		} else {
			key = jsonx.O("type", "string")
		}
		return withDescription(jsonx.O("type", "object", "propertyNames", key,
			"additionalProperties", toOpenAPISchema(info.Value)), desc)
	case validate.KindIntersection:
		left := toOpenAPISchema(info.Left)
		right := toOpenAPISchema(info.Right)
		if isMergeableObjectSchema(left) && isMergeableObjectSchema(right) {
			if merged := mergeObjectSchemas(left, right, desc); merged != nil {
				return merged
			}
		}
		return withDescription(jsonx.O("allOf", []any{left, right}), desc)
	case validate.KindUnion:
		var schemas []any
		for _, o := range info.Options {
			if isUndefinedOnly(o) {
				continue
			}
			schemas = append(schemas, toOpenAPISchema(o))
		}
		switch len(schemas) {
		case 0:
			return withDescription(jsonx.NewObject(), desc)
		case 1:
			return withDescription(schemas[0].(*jsonx.Object), desc)
		}
		return withDescription(jsonx.O("anyOf", schemas), desc)
	case validate.KindArray:
		return withDescription(jsonx.O("type", "array", "items", toOpenAPISchema(info.Item)), desc)
	case validate.KindLiteral:
		return withDescription(jsonx.O("enum", []any{info.Literal}), desc)
	case validate.KindEnum:
		values := make([]any, len(info.Values))
		for i, v := range info.Values {
			values[i] = v
		}
		return withDescription(jsonx.O("type", "string", "enum", values), desc)
	case validate.KindPipe, validate.KindCatch:
		return withDescription(toOpenAPISchema(info.Inner), desc)
	case validate.KindNull:
		return withDescription(jsonx.O("type", "null"), desc)
	}
	// primitives (getOpenApiTypeFromZodType): unsupported types fall back to "string"
	out := jsonx.NewObject()
	switch info.Kind {
	case validate.KindString:
		out.Set("type", "string")
		// z.email() / z.url() are string formats, not ZodString instances, so their
		// length constraints are not emitted upstream.
		if !info.Email && !info.URL {
			if info.MinLength != nil {
				out.Set("minLength", *info.MinLength)
			}
			if info.MaxLength != nil {
				out.Set("maxLength", *info.MaxLength)
			}
		}
	case validate.KindBoolean:
		out.Set("type", "boolean")
	case validate.KindNumber:
		out.Set("type", "number")
	default:
		out.Set("type", "string")
	}
	return withDescription(out, desc)
}
