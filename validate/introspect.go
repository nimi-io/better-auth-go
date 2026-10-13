package validate

// Introspection of schemas, used to derive JSON Schema / OpenAPI documents from validators
// (the open-api plugin converts request bodies and queries the way upstream's generator
// converts zod schemas). Nothing in this file changes validation behaviour.

// Kind identifies the zod construct a schema corresponds to.
type Kind string

// Schema kinds.
const (
	KindString       Kind = "string"
	KindBoolean      Kind = "boolean"
	KindNumber       Kind = "number"
	KindAny          Kind = "any"
	KindUnknown      Kind = "unknown"
	KindUndefined    Kind = "undefined"
	KindVoid         Kind = "void"
	KindNull         Kind = "null"
	KindLiteral      Kind = "literal"
	KindEnum         Kind = "enum"
	KindOptional     Kind = "optional"
	KindNullable     Kind = "nullable"
	KindDefault      Kind = "default"
	KindPrefault     Kind = "prefault"
	KindCatch        Kind = "catch"
	KindNonOptional  Kind = "nonoptional"
	KindPipe         Kind = "pipe"
	KindArray        Kind = "array"
	KindObject       Kind = "object"
	KindRecord       Kind = "record"
	KindUnion        Kind = "union"
	KindIntersection Kind = "intersection"
	KindDescribed    Kind = "described"
	// KindCustom is an opaque function schema (z.custom); its JSON type is unknown.
	KindCustom Kind = "custom"
)

// Info describes one schema node. Only the fields relevant to Kind are set.
type Info struct {
	Kind Kind
	// Inner is the wrapped schema of optional, nullable, default, prefault, catch,
	// nonoptional, pipe (the effective schema) and described nodes.
	Inner Schema
	// Description is set on described nodes.
	Description string
	// String constraints.
	MinLength, MaxLength *int
	Email, URL           bool
	// Number constraints.
	Integer bool
	Minimum *float64
	// Coerce is set for z.coerce.boolean().
	Coerce bool
	// Literal is the value of a literal node.
	Literal any
	// Values are the options of an enum node.
	Values []string
	// Item is the element schema of an array node.
	Item Schema
	// Fields are the properties of an object node, in declaration order; Mode is
	// "strip", "strict" or "loose".
	Fields []Field
	Mode   string
	// Key and Value are the key (nil means z.string()) and value schemas of a record.
	Key, Value Schema
	// Options are the members of a union.
	Options []Schema
	// Left and Right are the members of an intersection.
	Left, Right Schema
	// Default is the default value of default / prefault / catch nodes.
	Default any
}

// Inspect describes a schema node.
func Inspect(s Schema) Info {
	switch t := s.(type) {
	case *StringSchema:
		info := Info{Kind: KindString, Email: t.email, URL: t.url}
		if t.hasMin {
			n := t.min
			info.MinLength = &n
		}
		if t.hasMax {
			n := t.max
			info.MaxLength = &n
		}
		return info
	case *BooleanSchema:
		return Info{Kind: KindBoolean, Coerce: t.coerce}
	case *NumberSchema:
		return Info{Kind: KindNumber, Integer: t.integer, Minimum: t.min}
	case anySchema:
		return Info{Kind: KindAny}
	case *LiteralSchema:
		return Info{Kind: KindLiteral, Literal: t.value}
	case *EnumSchema:
		return Info{Kind: KindEnum, Values: append([]string(nil), t.values...)}
	case optional:
		return Info{Kind: KindOptional, Inner: t.inner}
	case nullable:
		return Info{Kind: KindNullable, Inner: t.inner}
	case withDefault:
		return Info{Kind: KindDefault, Inner: t.inner, Default: t.def}
	case *ArraySchema:
		return Info{Kind: KindArray, Item: t.item}
	case *ObjectSchema:
		return Info{Kind: KindObject, Fields: append([]Field(nil), t.fields...), Mode: t.mode}
	case *RecordSchema:
		return Info{Kind: KindRecord, Value: t.value}
	case unionSchema:
		return Info{Kind: KindUnion, Options: append([]Schema(nil), t.options...)}
	case intersection:
		return Info{Kind: KindIntersection, Left: t.a, Right: t.b}
	case Custom:
		return Info{Kind: KindCustom}
	case described:
		return Info{Kind: KindDescribed, Inner: t.inner, Description: t.description}
	case keyedRecord:
		return Info{Kind: KindRecord, Key: t.key, Value: t.value}
	case simpleSchema:
		return Info{Kind: t.kind}
	case wrapper:
		return Info{Kind: t.kind, Inner: t.inner, Default: t.def}
	case pipeSchema:
		return Info{Kind: KindPipe, Inner: t.inner}
	}
	return Info{Kind: KindCustom}
}
