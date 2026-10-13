package migration

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
)

// This file reproduces the SQL that Kysely 0.29 compiles for the schema builders used by
// getMigrations (DefaultQueryCompiler and its MySQL / SQLite / PostgreSQL / SQL Server
// subclasses, plus WithSchemaPlugin for database.schemaName).

type compiler struct {
	d dialect.Dialect
	// schema qualifies unqualified tables (Kysely's withSchema).
	schema string
}

func (c compiler) ident(s string) string {
	if c.d == dialect.MySQL {
		return "`" + strings.ReplaceAll(s, "`", "``") + "`"
	}
	// Kysely quotes SQL Server identifiers with double quotes too.
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// table compiles a table reference: parseTable splits "schema.table" on the first dot, and
// WithSchemaPlugin qualifies tables without a schema.
func (c compiler) table(name string) string {
	schema, table := splitTable(name)
	if schema == "" {
		schema = c.schema
	}
	if schema != "" {
		return c.ident(schema) + "." + c.ident(table)
	}
	return c.ident(table)
}

// splitTable is Kysely's parseTable: "a.b" is schema a, table b (anything after a second dot
// is dropped).
func splitTable(name string) (schema, table string) {
	if !strings.Contains(name, ".") {
		return "", name
	}
	parts := strings.Split(name, ".")
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func (c compiler) stringLiteral(s string) string {
	if c.d == dialect.MySQL {
		var b strings.Builder
		b.WriteByte('\'')
		for _, r := range s {
			switch r {
			case '\\':
				b.WriteString(`\\`)
			case '\'':
				b.WriteString("''")
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('\'')
		return b.String()
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// immediate compiles a value the way appendImmediateValue does.
func (c compiler) immediate(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case string:
		return c.stringLiteral(x), nil
	case bool:
		return strconv.FormatBool(x), nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(rv.Uint(), 10), nil
	case reflect.Float32, reflect.Float64:
		return jsNumber(rv.Float()), nil
	case reflect.String:
		return c.stringLiteral(rv.String()), nil
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool()), nil
	}
	return "", fmt.Errorf("migration: invalid immediate value %v (%T)", v, v)
}

// jsNumber formats a float like JavaScript's Number.prototype.toString.
func jsNumber(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e21 || abs < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mant, exp, _ := strings.Cut(s, "e")
		sign := exp[:1]
		digits := strings.TrimLeft(exp[1:], "0")
		if digits == "" {
			digits = "0"
		}
		return mant + "e" + sign + digits
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// column is a ColumnDefinitionNode.
type column struct {
	name          string
	dataType      string
	identity      bool
	defaultTo     string // compiled default expression, empty for none
	notNull       bool
	unique        bool
	primaryKey    bool
	autoIncrement bool
	references    *columnReference
}

type columnReference struct {
	schema, table, column string
	onDelete              string
}

func (c compiler) columnDef(col column) string {
	var b strings.Builder
	b.WriteString(c.ident(col.name))
	b.WriteByte(' ')
	b.WriteString(col.dataType)
	if col.identity {
		b.WriteString(" identity")
	}
	if col.defaultTo != "" {
		b.WriteString(" default ")
		b.WriteString(col.defaultTo)
	}
	if col.notNull {
		b.WriteString(" not null")
	}
	if col.unique {
		b.WriteString(" unique")
	}
	if col.primaryKey {
		b.WriteString(" primary key")
	}
	if col.autoIncrement {
		if c.d == dialect.SQLite {
			b.WriteString(" autoincrement")
		} else {
			b.WriteString(" auto_increment")
		}
	}
	if r := col.references; r != nil {
		b.WriteString(" references ")
		schema := r.schema
		if schema == "" {
			schema = c.schema
		}
		if schema != "" {
			b.WriteString(c.ident(schema) + ".")
		}
		b.WriteString(c.ident(r.table))
		b.WriteString(" (")
		b.WriteString(c.ident(r.column))
		b.WriteString(")")
		if r.onDelete != "" {
			b.WriteString(" on delete ")
			b.WriteString(r.onDelete)
		}
	}
	return b.String()
}

// parseReference is Kysely's parseStringReference for column.references("table.column").
func parseReference(ref string) (*columnReference, error) {
	if !strings.Contains(ref, ".") {
		return nil, fmt.Errorf("invalid call references('%s'). The reference must have format table.column or schema.table.column", ref)
	}
	parts := strings.Split(ref, ".")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	switch len(parts) {
	case 2:
		return &columnReference{table: parts[0], column: parts[1]}, nil
	case 3:
		return &columnReference{schema: parts[0], table: parts[1], column: parts[2]}, nil
	}
	return nil, fmt.Errorf("invalid column reference %s", ref)
}

func (c compiler) createSchema(name string) string {
	return "create schema if not exists " + c.ident(name)
}

func (c compiler) createTable(name string, columns []column) string {
	defs := make([]string, len(columns))
	for i, col := range columns {
		defs[i] = c.columnDef(col)
	}
	return "create table " + c.table(name) + " (" + strings.Join(defs, ", ") + ")"
}

func (c compiler) addColumn(table string, col column) string {
	if c.d == dialect.MSSQL {
		return "alter table " + c.table(table) + " add " + c.columnDef(col)
	}
	return "alter table " + c.table(table) + " add column " + c.columnDef(col)
}

// orderedColumn is parseOrderedColumnName: "col desc" orders the column.
func (c compiler) orderedColumn(name string) string {
	if col, order, ok := strings.Cut(name, " "); ok {
		return c.ident(strings.TrimSpace(col)) + " " + strings.TrimSpace(order)
	}
	return c.ident(name)
}

// createIndex compiles db.schema.createIndex(name).on(table).columns(cols)[.unique()]
// [.where(col, "is not", null)].
func (c compiler) createIndex(name, table string, columns []string, unique bool, whereNotNull string) string {
	var b strings.Builder
	b.WriteString("create ")
	if unique {
		b.WriteString("unique ")
	}
	b.WriteString("index ")
	b.WriteString(c.ident(name))
	b.WriteString(" on ")
	b.WriteString(c.table(table))
	cols := make([]string, len(columns))
	for i, col := range columns {
		cols[i] = c.orderedColumn(col)
	}
	b.WriteString(" (" + strings.Join(cols, ", ") + ")")
	if whereNotNull != "" {
		b.WriteString(" where " + c.ident(whereNotNull) + " is not null")
	}
	return b.String()
}

// hasRowsQuery is db.selectFrom(table).select(sql`1`.as("present")).limit(1) (top(1) on SQL
// Server).
func (c compiler) hasRowsQuery(table string) string {
	if c.d == dialect.MSSQL {
		return `select top(1) 1 as "present" from ` + c.table(table)
	}
	return "select 1 as " + c.ident("present") + " from " + c.table(table) + " limit 1"
}
