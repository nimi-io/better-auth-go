package mongodb

import (
	"strings"
	"unicode/utf16"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/nimi-io/better-auth-go/adapter"
)

// This file ports packages/mongo-adapter/src/query-builders.ts and the where-clause
// translation (convertWhereClause / serializeID) of mongodb-adapter.ts.

// defaultRegexMaxLength is the default maxLength of escapeForMongoRegex.
const defaultRegexMaxLength = 256

// EscapeForMongoRegex escapes the regular-expression metacharacters of input after
// truncating it to maxLength UTF-16 code units (JavaScript String.prototype.slice). A
// non-positive maxLength uses the upstream default of 256.
func EscapeForMongoRegex(input string, maxLength int) string {
	if maxLength <= 0 {
		maxLength = defaultRegexMaxLength
	}
	input = sliceUTF16(input, maxLength)
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch r {
		case '.', '*', '+', '?', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// escapeAny mirrors escapeForMongoRegex for untyped values: non-strings escape to "".
func escapeAny(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return EscapeForMongoRegex(s, defaultRegexMaxLength)
}

// sliceUTF16 returns the first n UTF-16 code units of s. A surrogate pair cut in half
// becomes U+FFFD, which is what a lone surrogate turns into when JavaScript encodes the
// string as UTF-8 for BSON.
func sliceUTF16(s string, n int) string {
	units := 0
	for i, r := range s {
		w := utf16.RuneLen(r)
		if w < 0 {
			w = 1
		}
		if units+w > n {
			if units < n { // half of a surrogate pair fits
				return s[:i] + "�"
			}
			return s[:i]
		}
		units += w
	}
	return s
}

func regexDoc(pattern string, insensitive bool) bson.D {
	if insensitive {
		return bson.D{{Key: "$regex", Value: pattern}, {Key: "$options", Value: "i"}}
	}
	return bson.D{{Key: "$regex", Value: pattern}}
}

// insensitiveEq ports insensitiveEq.
func insensitiveEq(field, value string) bson.D {
	return bson.D{{Key: field, Value: regexDoc("^"+EscapeForMongoRegex(value, 0)+"$", true)}}
}

// insensitiveIn ports insensitiveIn.
func insensitiveIn(field string, values []string) bson.D {
	if len(values) == 0 {
		return bson.D{{Key: "$expr", Value: bson.D{{Key: "$eq", Value: bson.A{1, 0}}}}}
	}
	or := make(bson.A, len(values))
	for i, v := range values {
		or[i] = bson.D{{Key: field, Value: regexDoc("^"+EscapeForMongoRegex(v, 0)+"$", true)}}
	}
	return bson.D{{Key: "$or", Value: or}}
}

// insensitiveNotIn ports insensitiveNotIn.
func insensitiveNotIn(field string, values []string) bson.D {
	if len(values) == 0 {
		return bson.D{}
	}
	nor := make(bson.A, len(values))
	for i, v := range values {
		nor[i] = bson.D{{Key: field, Value: regexDoc("^"+EscapeForMongoRegex(v, 0)+"$", true)}}
	}
	return bson.D{{Key: "$nor", Value: nor}}
}

// insensitiveNe ports insensitiveNe.
func insensitiveNe(field, value string) bson.D {
	return bson.D{{Key: field, Value: bson.D{{Key: "$not", Value: regexDoc("^"+EscapeForMongoRegex(value, 0)+"$", true)}}}}
}

// insensitiveContains ports insensitiveContains.
func insensitiveContains(field string, value any) bson.D {
	return bson.D{{Key: field, Value: regexDoc(".*"+escapeAny(value)+".*", true)}}
}

// insensitiveStartsWith ports insensitiveStartsWith.
func insensitiveStartsWith(field string, value any) bson.D {
	return bson.D{{Key: field, Value: regexDoc("^"+escapeAny(value), true)}}
}

// insensitiveEndsWith ports insensitiveEndsWith.
func insensitiveEndsWith(field string, value any) bson.D {
	return bson.D{{Key: field, Value: regexDoc(escapeAny(value)+"$", true)}}
}

// stringSlice returns the elements of v when v is a slice whose elements are all strings
// (Array.isArray(value) && value.every((v) => typeof v === "string")).
func stringSlice(v any) ([]string, bool) {
	if s, ok := v.([]string); ok {
		return s, true
	}
	arr, ok := adapter.ToSlice(v)
	if !ok {
		return nil, false
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// physicalField resolves a cleaned where field to its MongoDB field (getFieldName, "id" →
// "_id").
func (a *mongoAdapter) physicalField(modelKey, field string) (string, error) {
	name, err := a.h.FieldName(modelKey, field)
	if err != nil {
		return "", err
	}
	if name == "id" {
		name = "_id"
	}
	return name, nil
}

// isIDReference reports whether a (physical or logical) field references another model's id.
func (a *mongoAdapter) isIDReference(modelKey, field string) bool {
	attr, err := a.h.FieldAttributes(modelKey, field)
	if err != nil {
		return false
	}
	return attr.References != nil && attr.References.Field == "id"
}

// serializeID ports serializeID: id and id-reference values are coerced to ObjectId (or BSON
// UUID when generateId is "uuid") unless a custom id generator is configured.
func (a *mongoAdapter) serializeID(field string, value any, modelKey string) (any, error) {
	if a.ids.custom {
		return value, nil
	}
	if field != "id" && field != "_id" && !a.isIDReference(modelKey, field) {
		return value, nil
	}
	if value == nil {
		return nil, nil
	}
	if s, ok := value.(string); ok {
		if id, ok := a.ids.coerce(s); ok {
			return id, nil
		}
		return s, nil
	}
	if a.ids.isInstance(value) {
		return value, nil
	}
	if arr, ok := adapter.ToSlice(value); ok {
		out := make([]any, len(arr))
		for i, v := range arr {
			switch t := v.(type) {
			case nil:
				out[i] = nil
			case string:
				if id, ok := a.ids.coerce(t); ok {
					out[i] = id
				} else {
					out[i] = t
				}
			default:
				if !a.ids.isInstance(v) {
					return nil, &MongoAdapterError{Code: "INVALID_ID", Message: "Invalid id value"}
				}
				out[i] = v
			}
		}
		return out, nil
	}
	return nil, &MongoAdapterError{Code: "INVALID_ID", Message: "Invalid id value"}
}

func (a *mongoAdapter) serializeList(field string, value any, modelKey string) (bson.A, error) {
	if arr, ok := adapter.ToSlice(value); ok {
		out := make(bson.A, len(arr))
		for i, v := range arr {
			s, err := a.serializeID(field, v, modelKey)
			if err != nil {
				return nil, err
			}
			out[i] = s
		}
		return out, nil
	}
	s, err := a.serializeID(field, value, modelKey)
	if err != nil {
		return nil, err
	}
	return bson.A{s}, nil
}

type whereCondition struct {
	condition bson.D
	connector adapter.Connector
}

// convertWhere ports convertWhereClause. Conditions joined with AND go into $and, those joined
// with OR into $or; a single condition is returned as is.
func (a *mongoAdapter) convertWhere(where []adapter.CleanedWhere, modelKey string) (bson.D, error) {
	if len(where) == 0 {
		return bson.D{}, nil
	}
	conds := make([]whereCondition, 0, len(where))
	for _, w := range where {
		op := strings.ToLower(string(w.Operator))
		if op == "" {
			op = string(adapter.Eq)
		}
		connector := w.Connector
		if connector == "" {
			connector = adapter.And
		}
		field, err := a.physicalField(modelKey, w.Field)
		if err != nil {
			return nil, err
		}
		value := w.Value
		isIDOrRef := field == "_id" || a.isIDReference(modelKey, w.Field)
		strs, allStrings := stringSlice(value)
		_, isString := value.(string)
		insensitive := !isIDOrRef && w.Insensitive && (isString || allStrings)

		var cond bson.D
		ser := func() (any, error) { return a.serializeID(field, value, modelKey) }
		cmp := func(operator string) error {
			v, err := ser()
			if err != nil {
				return err
			}
			cond = bson.D{{Key: field, Value: bson.D{{Key: operator, Value: v}}}}
			return nil
		}
		switch op {
		case "eq":
			if insensitive && isString {
				cond = insensitiveEq(field, value.(string))
			} else {
				v, err := ser()
				if err != nil {
					return nil, err
				}
				cond = bson.D{{Key: field, Value: v}}
			}
		case "in", "not_in":
			_, isArray := adapter.ToSlice(value)
			if insensitive && isArray {
				if op == "in" {
					cond = insensitiveIn(field, strs)
				} else {
					cond = insensitiveNotIn(field, strs)
				}
			} else {
				list, err := a.serializeList(field, value, modelKey)
				if err != nil {
					return nil, err
				}
				key := "$in"
				if op == "not_in" {
					key = "$nin"
				}
				cond = bson.D{{Key: field, Value: bson.D{{Key: key, Value: list}}}}
			}
		case "gt", "gte", "lt", "lte":
			if err := cmp("$" + op); err != nil {
				return nil, err
			}
		case "ne":
			if insensitive && isString {
				cond = insensitiveNe(field, value.(string))
			} else if err := cmp("$ne"); err != nil {
				return nil, err
			}
		case "contains":
			if insensitive {
				cond = insensitiveContains(field, value)
			} else {
				cond = bson.D{{Key: field, Value: regexDoc(".*"+escapeAny(value)+".*", false)}}
			}
		case "starts_with":
			if insensitive {
				cond = insensitiveStartsWith(field, value)
			} else {
				cond = bson.D{{Key: field, Value: regexDoc("^"+escapeAny(value), false)}}
			}
		case "ends_with":
			if insensitive {
				cond = insensitiveEndsWith(field, value)
			} else {
				cond = bson.D{{Key: field, Value: regexDoc(escapeAny(value)+"$", false)}}
			}
		default:
			return nil, &MongoAdapterError{Code: "UNSUPPORTED_OPERATOR", Message: "Unsupported operator: " + string(w.Operator)}
		}
		conds = append(conds, whereCondition{condition: cond, connector: connector})
	}
	if len(conds) == 1 {
		return conds[0].condition, nil
	}
	var and, or bson.A
	for _, c := range conds {
		switch c.connector {
		case adapter.And:
			and = append(and, c.condition)
		case adapter.Or:
			or = append(or, c.condition)
		}
	}
	clause := bson.D{}
	if len(and) > 0 {
		clause = append(clause, bson.E{Key: "$and", Value: and})
	}
	if len(or) > 0 {
		clause = append(clause, bson.E{Key: "$or", Value: or})
	}
	return clause, nil
}
