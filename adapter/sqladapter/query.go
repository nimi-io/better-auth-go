package sqladapter

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// likeEscape is the ESCAPE character of LIKE patterns. A character that is not special in
// any dialect's string literals keeps the clause portable (MySQL treats a backslash in a
// literal as an escape itself).
const likeEscape = "!"

// builder accumulates a SQL statement and its bound arguments. Placeholders are numbered
// in order of appearance, so fragments must be written left to right.
type builder struct {
	d    dialect.Dialect
	sb   strings.Builder
	args []any
}

func (b *builder) write(parts ...string) *builder {
	for _, p := range parts {
		b.sb.WriteString(p)
	}
	return b
}

// bind appends an argument and returns its placeholder.
func (b *builder) bind(v any) string {
	b.args = append(b.args, encodeArg(b.d, v))
	return b.d.Placeholder(len(b.args))
}

func (b *builder) String() string { return b.sb.String() }

// encodeArg converts a value produced by the adapter factory to a driver argument.
func encodeArg(d dialect.Dialect, v any) any {
	switch t := v.(type) {
	case nil, string, bool, int64, float64, []byte:
		return v
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case float32:
		return float64(t)
	case uint64:
		return t
	case time.Time:
		if d == dialect.SQLite {
			// better-sqlite3 cannot bind a Date; the factory already stores ISO strings
			// (supportsDates: false), so stray dates use the same encoding.
			return jsonx.ISOTime(t)
		}
		return t
	case *time.Time:
		if t == nil {
			return nil
		}
		return encodeArg(d, *t)
	case json.RawMessage:
		return string(t)
	case jsonx.RawMessage:
		return string(t)
	case *jsonx.Object, map[string]any, []any, []string, []int64, []float64, []int:
		// Only reachable for PostgreSQL JSON fields (supportsJSON): node-postgres sends
		// objects as JSON text, which jsonb parses.
		s, err := jsonx.Stringify(v)
		if err != nil {
			return v
		}
		return s
	}
	return v
}

// tableRef returns the quoted table reference and the name it exposes for column
// qualification ("auth"."user" exposes "user"; "internal.users" exposes "users").
func (a *sqlAdapter) tableRef(model string) (ref, exposed string) {
	exposed = model
	if i := strings.IndexByte(model, '.'); i >= 0 {
		exposed = model[i+1:]
	}
	return a.d.QuoteTable(a.schemaName, model), a.d.Quote(exposed)
}

// joinAlias is the alias of a joined model (`join_${joinModelName}` upstream).
func (a *sqlAdapter) joinAlias(model string) string {
	if i := strings.IndexByte(model, '.'); i >= 0 {
		model = model[i+1:]
	}
	return a.d.Quote("join_" + model)
}

func (a *sqlAdapter) col(qualifier, column string) string {
	if qualifier == "" {
		return a.d.Quote(column)
	}
	return qualifier + "." + a.d.Quote(column)
}

// isInsensitive mirrors `mode === "insensitive" && (typeof value === "string" ||
// (Array.isArray(value) && value.every((v) => typeof v === "string")))`.
func isInsensitive(w adapter.CleanedWhere) bool {
	if !w.Insensitive {
		return false
	}
	if _, ok := w.Value.(string); ok {
		return true
	}
	arr, ok := adapter.ToSlice(w.Value)
	if !ok {
		return false
	}
	for _, x := range arr {
		if _, ok := x.(string); !ok {
			return false
		}
	}
	return true
}

func asList(v any) []any {
	if arr, ok := adapter.ToSlice(v); ok {
		return arr
	}
	return []any{v}
}

// escapeLike escapes LIKE wildcards so the value matches literally.
func escapeLike(s string) string {
	r := strings.NewReplacer(likeEscape, likeEscape+likeEscape, "%", likeEscape+"%", "_", likeEscape+"_")
	return r.Replace(s)
}

// condition renders one where clause (the `expr` closure of convertWhereClause).
func (a *sqlAdapter) condition(b *builder, qualifier string, w adapter.CleanedWhere) (string, error) {
	f := a.col(qualifier, w.Field)
	insensitive := isInsensitive(w)
	value := w.Value
	op := w.Operator
	if op == "" {
		op = adapter.Eq
	}
	inList := func(not bool) string {
		vals := asList(value)
		lhs := f
		if insensitive {
			lhs = "LOWER(" + f + ")"
		}
		if len(vals) == 0 {
			// `in ()` is a syntax error on PostgreSQL and MySQL: an empty IN matches nothing
			// and an empty NOT IN matches everything.
			if not {
				return "1 = 1"
			}
			return "1 = 0"
		}
		ph := make([]string, len(vals))
		for i, v := range vals {
			if insensitive {
				v = strings.ToLower(v.(string))
			}
			ph[i] = b.bind(v)
		}
		kw := " IN ("
		if not {
			kw = " NOT IN ("
		}
		return lhs + kw + strings.Join(ph, ", ") + ")"
	}
	like := func(prefix, suffix string) string {
		s := adapter.ToString(value)
		if value == nil {
			s = "null"
		}
		pattern := prefix + escapeLike(s) + suffix
		esc := " ESCAPE '" + likeEscape + "'"
		if insensitive {
			if _, ok := value.(string); ok {
				if a.d == dialect.Postgres {
					return f + " ILIKE " + b.bind(pattern) + esc
				}
				return "LOWER(" + f + ") LIKE LOWER(" + b.bind(pattern) + ")" + esc
			}
		}
		return f + " LIKE " + b.bind(pattern) + esc
	}
	switch strings.ToLower(string(op)) {
	case string(adapter.In):
		return inList(false), nil
	case string(adapter.NotIn):
		return inList(true), nil
	}
	switch op {
	case adapter.Contains:
		return like("%", "%"), nil
	case adapter.StartsWith:
		return like("", "%"), nil
	case adapter.EndsWith:
		return like("%", ""), nil
	case adapter.Eq:
		if value == nil {
			return f + " IS NULL", nil
		}
		if s, ok := value.(string); ok && insensitive {
			return "LOWER(" + f + ") = " + b.bind(strings.ToLower(s)), nil
		}
		return f + " = " + b.bind(value), nil
	case adapter.Ne:
		if value == nil {
			return f + " IS NOT NULL", nil
		}
		if s, ok := value.(string); ok && insensitive {
			return "LOWER(" + f + ") <> " + b.bind(strings.ToLower(s)), nil
		}
		return f + " <> " + b.bind(value), nil
	case adapter.Gt:
		return f + " > " + b.bind(value), nil
	case adapter.Gte:
		return f + " >= " + b.bind(value), nil
	case adapter.Lt:
		return f + " < " + b.bind(value), nil
	case adapter.Lte:
		return f + " <= " + b.bind(value), nil
	}
	return "", fmt.Errorf("sqladapter: unsupported where operator %q", op)
}

// where renders the WHERE clause body (without the keyword) of convertWhereClause: AND
// clauses are folded into one group, OR clauses into another, and the groups are ANDed
// (`where(and(...))` then `where(or(...))` in Kysely). An empty result means no filter.
func (a *sqlAdapter) where(b *builder, qualifier string, where []adapter.CleanedWhere) (string, error) {
	var and, or []string
	for _, w := range where {
		c, err := a.condition(b, qualifier, w)
		if err != nil {
			return "", err
		}
		if w.Connector == adapter.Or {
			or = append(or, c)
		} else {
			and = append(and, c)
		}
	}
	var groups []string
	if len(and) > 0 {
		groups = append(groups, "("+strings.Join(and, " AND ")+")")
	}
	if len(or) > 0 {
		groups = append(groups, "("+strings.Join(or, " OR ")+")")
	}
	return strings.Join(groups, " AND "), nil
}

// writeWhere appends " WHERE ..." (or nothing) to b.
func (a *sqlAdapter) writeWhere(b *builder, qualifier string, where []adapter.CleanedWhere) error {
	w, err := a.where(b, qualifier, where)
	if err != nil {
		return err
	}
	if w != "" {
		b.write(" WHERE ", w)
	}
	return nil
}

// appendWhere appends " AND <where>" (or nothing) to a statement that already has a WHERE.
func (a *sqlAdapter) appendWhere(b *builder, qualifier string, where []adapter.CleanedWhere) error {
	w, err := a.where(b, qualifier, where)
	if err != nil {
		return err
	}
	if w != "" {
		b.write(" AND ", w)
	}
	return nil
}

// limitOffset renders LIMIT/OFFSET (OFFSET alone needs a LIMIT on MySQL and SQLite).
func (a *sqlAdapter) limitOffset(b *builder, limit, offset int) {
	if limit > 0 {
		b.write(" LIMIT ", strconv.Itoa(limit))
	} else if offset > 0 {
		switch a.d {
		case dialect.MySQL:
			b.write(" LIMIT 18446744073709551615")
		case dialect.SQLite:
			b.write(" LIMIT -1")
		}
	}
	if offset > 0 {
		b.write(" OFFSET ", strconv.Itoa(offset))
	}
}

// selectList renders the selected columns (all when empty).
func (a *sqlAdapter) selectList(sel []string) string {
	if len(sel) == 0 {
		return "*"
	}
	cols := make([]string, len(sel))
	for i, s := range sel {
		cols[i] = a.d.Quote(s)
	}
	return strings.Join(cols, ", ")
}

// sortedKeys returns the keys of a map in a deterministic order.
func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

// setClause renders "col" = ?, ... for an UPDATE, with increments as "col" = "col" + ?.
func (a *sqlAdapter) setClause(b *builder, set adapter.Record, increment map[string]float64) {
	first := true
	sep := func() {
		if !first {
			b.write(", ")
		}
		first = false
	}
	for _, k := range sortedKeys(set) {
		if _, inc := increment[k]; inc {
			continue
		}
		sep()
		b.write(a.d.Quote(k), " = ", b.bind(set[k]))
	}
	for _, k := range sortedKeys(increment) {
		sep()
		b.write(a.d.Quote(k), " = ", a.d.Quote(k), " + ", b.bind(numberArg(increment[k])))
	}
}

// numberArg passes integral deltas as integers so integer columns accept them.
func numberArg(f float64) any {
	if f == float64(int64(f)) {
		return int64(f)
	}
	return f
}
