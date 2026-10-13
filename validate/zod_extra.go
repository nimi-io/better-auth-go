package validate

// Additional zod constructs. They exist mainly so schemas can carry the same shape (and
// OpenAPI metadata such as descriptions) as their upstream zod counterparts; see
// introspect.go.

type described struct {
	inner       Schema
	description string
}

// Describe attaches a description to a schema (.describe(text) / .meta({description})).
// Validation is unchanged.
func Describe(s Schema, description string) Schema {
	return described{inner: s, description: description}
}

func (d described) validate(v any, path []any) (any, []Issue) { return d.inner.validate(v, path) }

type keyedRecord struct {
	key, value Schema
}

// RecordOf is z.record(key, value) with an explicit key schema.
func RecordOf(key, value Schema) Schema { return keyedRecord{key: key, value: value} }

func (s keyedRecord) validate(v any, path []any) (any, []Issue) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, typeIssue(path, "record", v)
	}
	out := map[string]any{}
	var issues []Issue
	for k, val := range m {
		if s.key != nil {
			if _, is := s.key.validate(k, appendPath(path, k)); len(is) > 0 {
				for _, i := range is {
					issues = append(issues, Issue{Path: appendPath(path, k), Code: "invalid_key",
						Message: "Invalid key in record", abort: i.abort})
					break
				}
				continue
			}
		}
		o, is := s.value.validate(val, appendPath(path, k))
		issues = append(issues, is...)
		out[k] = o
	}
	if len(issues) > 0 {
		return nil, issues
	}
	return out, nil
}

type simpleSchema struct{ kind Kind }

// Unknown is z.unknown().
func Unknown() Schema { return simpleSchema{kind: KindUnknown} }

// UndefinedValue is z.undefined().
func UndefinedValue() Schema { return simpleSchema{kind: KindUndefined} }

// Void is z.void().
func Void() Schema { return simpleSchema{kind: KindVoid} }

// NullValue is z.null().
func NullValue() Schema { return simpleSchema{kind: KindNull} }

func (s simpleSchema) validate(v any, path []any) (any, []Issue) {
	switch s.kind {
	case KindUndefined, KindVoid:
		if IsUndefined(v) {
			return Undefined, nil
		}
		return nil, typeIssue(path, string(s.kind), v)
	case KindNull:
		if v == nil {
			return nil, nil
		}
		return nil, typeIssue(path, "null", v)
	}
	return v, nil
}

type wrapper struct {
	kind  Kind
	inner Schema
	def   any
}

// Nullable is .nullable(): null passes through (undefined does not).
func Nullable(s Schema) Schema { return wrapper{kind: KindNullable, inner: s} }

// Prefault is .prefault(v): undefined is replaced by v before validation.
func Prefault(s Schema, v any) Schema { return wrapper{kind: KindPrefault, inner: s, def: v} }

// Catch is .catch(v): invalid input is replaced by v.
func Catch(s Schema, v any) Schema { return wrapper{kind: KindCatch, inner: s, def: v} }

// NonOptional is .nonoptional(): undefined is rejected.
func NonOptional(s Schema) Schema { return wrapper{kind: KindNonOptional, inner: s} }

func (w wrapper) validate(v any, path []any) (any, []Issue) {
	switch w.kind {
	case KindNullable:
		if v == nil {
			return nil, nil
		}
	case KindPrefault:
		if IsUndefined(v) {
			v = w.def
		}
	case KindCatch:
		out, issues := w.inner.validate(v, path)
		if len(issues) > 0 {
			return w.def, nil
		}
		return out, nil
	case KindNonOptional:
		if IsUndefined(v) {
			return nil, typeIssue(path, "nonoptional", v)
		}
	}
	return w.inner.validate(v, path)
}

type pipeSchema struct {
	fn    func(any) any
	inner Schema
}

// Preprocess is z.preprocess(fn, schema).
func Preprocess(fn func(any) any, s Schema) Schema { return pipeSchema{fn: fn, inner: s} }

func (p pipeSchema) validate(v any, path []any) (any, []Issue) {
	if p.fn != nil {
		v = p.fn(v)
	}
	return p.inner.validate(v, path)
}
