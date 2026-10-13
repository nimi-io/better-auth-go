// Package migration compares a Better Auth schema with a live SQL database and produces the
// DDL to reconcile them (packages/better-auth/src/db/get-migration.ts).
//
// The generated SQL is byte-identical to what Better Auth's TypeScript getMigrations compiles
// through Kysely for PostgreSQL, MySQL and SQLite (see testdata/fixtures.json), so a Go
// server and a TypeScript server can share one database and either side's migrations leave
// nothing for the other to do.
package migration

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
	"github.com/nimi-io/better-auth-go/db"
)

// Logger receives the warnings getMigrations logs. adapter.Logger satisfies it; a logger
// that also implements Debug(msg string, args ...any) receives the debug messages.
type Logger interface {
	Warn(msg string, args ...any)
}

type debugLogger interface {
	Debug(msg string, args ...any)
}

// Options configure Plan.
type Options struct {
	// Dialect is detected from the driver when empty.
	Dialect dialect.Dialect
	// SchemaName is the PostgreSQL schema (database.schemaName); empty uses the search_path.
	// When set, every statement is qualified with it and the plan starts with
	// `create schema if not exists` whenever tables are created.
	SchemaName string
	// IDMode selects the id column type (serial ids use an auto-increment integer column,
	// uuid ids a uuid column on PostgreSQL).
	IDMode adapter.IDMode
	// ReportUnsafe reports unsafe changes (a required column without a default added to a
	// populated table) in MigrationPlan.UnsafeChanges instead of failing with
	// *UnsafeMigrationError (throwOnUnsafe: false upstream).
	ReportUnsafe bool
	// Logger receives warnings (nullable drift, type mismatches, unique backfills).
	Logger Logger
}

// UnsafeMigrationError is returned when Plan refuses to add a required column with no
// default value to a populated table.
type UnsafeMigrationError struct{ Message string }

func (e *UnsafeMigrationError) Error() string { return e.Message }

// pending is one entry of toBeCreated / toBeAdded.
type pending struct {
	table  string
	fields []physField
	order  int
}

func orderValue(o int) float64 {
	if o == 0 {
		return math.Inf(1)
	}
	return float64(o)
}

// Plan introspects db and returns the pending migrations for schema (getMigrations).
func Plan(ctx context.Context, conn *sql.DB, schema *db.Schema, opts Options) (*adapter.MigrationPlan, error) {
	d := opts.Dialect
	if d == "" {
		detected, err := dialect.Detect(conn)
		if err != nil {
			return nil, err
		}
		d = detected
	}
	switch d {
	case dialect.Postgres, dialect.MySQL, dialect.SQLite, dialect.MSSQL:
	default:
		return nil, fmt.Errorf("migration: unsupported dialect %q", d)
	}
	if opts.SchemaName != "" && d != dialect.Postgres {
		return nil, &SchemaError{Message: fmt.Sprintf("`database.schemaName` is only supported on PostgreSQL, but the configured database type is %q.", string(d))}
	}
	warn := func(msg string) {
		if opts.Logger != nil {
			opts.Logger.Warn(msg)
		}
	}
	debug := func(msg string) {
		if l, ok := opts.Logger.(debugLogger); ok {
			l.Debug(msg)
		}
	}

	tables, err := physicalSchema(schema)
	if err != nil {
		return nil, err
	}

	allTables, err := IntrospectTables(ctx, conn, d)
	if err != nil {
		return nil, fmt.Errorf("migration: introspect tables: %w", err)
	}
	tableMetadata := allTables
	var targetSchema string
	switch d {
	case dialect.Postgres:
		targetSchema = opts.SchemaName
		source := "from database.schemaName"
		if targetSchema == "" {
			source = "from search_path"
			if targetSchema, err = postgresCurrentSchema(ctx, conn); err != nil {
				return nil, fmt.Errorf("migration: current schema: %w", err)
			}
		}
		debug(fmt.Sprintf("PostgreSQL migration: Using schema '%s' (%s)", targetSchema, source))
		if schemas, err := postgresSchemas(ctx, conn); err != nil {
			debug("Could not verify schema existence: " + err.Error())
		} else if !contains(schemas, targetSchema) {
			if opts.SchemaName != "" {
				debug(fmt.Sprintf("Schema '%s' does not exist yet. The migration creates it before creating tables.", targetSchema))
			} else {
				warn(fmt.Sprintf("Schema '%s' does not exist. Create it before running migrations or check your database configuration.", targetSchema))
			}
		}
		tableMetadata = nil
		for _, t := range allTables {
			if t.Schema == targetSchema && !t.IsView && !t.IsForeign {
				tableMetadata = append(tableMetadata, t)
			}
		}
		names := make([]string, len(tableMetadata))
		for i, t := range tableMetadata {
			names[i] = t.Name
		}
		list := strings.Join(names, ", ")
		if list == "" {
			list = "(none)"
		}
		debug(fmt.Sprintf("Found %d table(s) in schema '%s': %s", len(tableMetadata), targetSchema, list))
	case dialect.MSSQL:
		if targetSchema, err = mssqlCurrentSchema(ctx, conn); err != nil {
			return nil, fmt.Errorf("migration: current schema: %w", err)
		}
		debug(fmt.Sprintf("SQL Server migration: Using schema '%s' (from the current user's default schema)", targetSchema))
		tableMetadata = nil
		for _, t := range allTables {
			if t.Schema == targetSchema {
				tableMetadata = append(tableMetadata, t)
			}
		}
	}

	indexes, err := databaseIndexMap(ctx, conn, d, targetSchema)
	if err != nil {
		return nil, fmt.Errorf("migration: introspect indexes: %w", err)
	}
	bounds, err := columnBounds(ctx, conn, d, targetSchema)
	if err != nil {
		return nil, fmt.Errorf("migration: introspect columns: %w", err)
	}

	plan := &adapter.MigrationPlan{}
	for _, finding := range DiffSchema(expectedFromPhysical(tables, opts.SchemaName), tableMetadata) {
		if finding.Kind == FindingUnexpectedRequiredColumn {
			plan.SchemaProblems = append(plan.SchemaProblems, FormatSchemaFinding(finding))
		}
	}

	var toBeCreated, toBeAdded []pending
	plannedIndexes := map[string]resolvedIndex{}
	for _, value := range tables {
		if value.DisableMigrations {
			continue
		}
		key := value.Name
		var table *TableMetadata
		for i := range tableMetadata {
			if tableMetadata[i].Name == key {
				table = &tableMetadata[i]
				break
			}
		}
		for _, index := range value.Indexes {
			name := index.Name
			ik := indexKey(key, name)
			if existing, ok := indexes.get(ik); ok {
				if !indexMatches(existing, index) {
					return nil, &SchemaError{Message: fmt.Sprintf("Database index %q on table %q does not match the configured fields and uniqueness. Rename or replace the existing index, then run the migration again.", name, key)}
				}
				continue
			}
			if d == dialect.SQLite || d == dialect.Postgres {
				for _, k := range indexes.keys {
					other := indexes.defs[k]
					if portableIdentifierKey(other.name) == portableIdentifierKey(name) && portableIdentifierKey(other.table) != portableIdentifierKey(key) {
						return nil, &SchemaError{Message: fmt.Sprintf("Database index name %q is already used by table %q. Index names must be unique across the schema.", name, other.table)}
					}
				}
			}
			if prev, ok := plannedIndexes[ik]; ok {
				def := indexDefinition{columns: prev.Columns, name: prev.Name, table: key, unique: prev.Unique, validFullColumns: true}
				if !indexMatches(def, index) {
					return nil, &SchemaError{Message: fmt.Sprintf("Database index name %q identifies more than one index on table %q.", name, key)}
				}
				continue
			}
			if table != nil && (d == dialect.MySQL || d == dialect.MSSQL) {
				if err := assertExistingTableIndexFits(bounds, d, table, value, index); err != nil {
					return nil, err
				}
			}
			plannedIndexes[ik] = index
			plan.ToBeAddedIndexes = append(plan.ToBeAddedIndexes, adapter.IndexChange{
				Table: key, Name: name, Columns: append([]string(nil), index.Columns...), Unique: index.Unique,
			})
		}
		if table == nil {
			data := pending{table: key, fields: value.Fields, order: value.Order}
			insertAt := -1
			for i, t := range toBeCreated {
				if orderValue(t.order) > orderValue(data.order) {
					insertAt = i
					break
				}
			}
			if insertAt == -1 {
				toBeCreated = append(toBeCreated, data)
			} else {
				toBeCreated = append(toBeCreated[:insertAt], append([]pending{data}, toBeCreated[insertAt:]...)...)
			}
			continue
		}
		var add []physField
		for _, pf := range value.Fields {
			col, ok := table.column(pf.Column)
			if !ok {
				add = append(add, pf)
				continue
			}
			if pf.Field.NotNull() && col.IsNullable {
				warn(fmt.Sprintf("Column %q on table %q stays nullable while the schema declares the field required, so existing rows can still hold null. Backfill every row for this column and enforce NOT NULL to remove the drift.", pf.Column, key))
			}
			if !MatchType(col.DataType, pf.Field.Type, d) {
				warn(fmt.Sprintf("Field %s in table %s has a different type in the database. Expected %s but got %s.", pf.Column, key, fieldTypeString(pf.Field), col.DataType))
			}
		}
		if len(add) > 0 {
			toBeAdded = append(toBeAdded, pending{table: key, fields: add, order: value.Order})
		}
	}

	c := compiler{d: d, schema: opts.SchemaName}
	tablesByName := map[string]*physTable{}
	for _, t := range tables {
		tablesByName[t.Name] = t
	}
	g := generator{c: c, d: d, idMode: opts.IDMode, schema: schema, tables: tablesByName}

	var statements, deferred []string
	if opts.SchemaName != "" && len(toBeCreated) > 0 {
		statements = append(statements, c.createSchema(opts.SchemaName))
	}

	if len(toBeAdded) > 0 {
		populated := map[string]bool{}
		for _, t := range toBeAdded {
			for _, pf := range t.fields {
				f := pf.Field
				timestampDefault := hasTimestampColumnDefault(f, d)
				staticDefault := hasStaticColumnDefault(f)
				if f.NotNull() && !timestampDefault && !staticDefault {
					has, ok := populated[t.table]
					if !ok {
						if has, err = tableHasRows(ctx, conn, c, t.table); err != nil {
							return nil, fmt.Errorf("migration: probe table %q: %w", t.table, err)
						}
						populated[t.table] = has
					}
					if has {
						detail := ""
						if f.Type == db.TypeString {
							detail = " For a text column, every existing row ends up with the same empty string."
						}
						msg := fmt.Sprintf("Cannot add required column %q to populated table %q: the schema declares no default value, so existing rows have no value to backfill. MySQL accepts this statement instead of rejecting it and fills every existing row with an implicit default for the column type, reporting a successful migration over corrupted data.%s Add the column as nullable, backfill a correct value for every row, then make it NOT NULL.", pf.Column, t.table, detail)
						if !opts.ReportUnsafe {
							return nil, &UnsafeMigrationError{Message: msg}
						}
						plan.UnsafeChanges = append(plan.UnsafeChanges, msg)
					}
				}
				typ, err := g.columnType(f, pf.Column, g.tableIndexStringLength(t.table, pf.Column))
				if err != nil {
					return nil, err
				}
				if f.Index || f.Unique {
					indexName := fieldIndexName(t.table, pf.Column, f.Unique)
					where := ""
					if f.Unique {
						if f.IsOptional() && d == dialect.MSSQL {
							where = pf.Column
						}
						if f.NotNull() && f.DefaultFunc == nil && f.DefaultValue != nil {
							warn(fmt.Sprintf("Adding unique column %q to existing table %q backfills every existing row with its default value. If the table has more than one row, creating the unique index %q will fail; backfill distinct values manually, then re-run the migration or create the index yourself.", pf.Column, t.table, indexName))
						}
					}
					deferred = append(deferred, c.createIndex(indexName, t.table, []string{pf.Column}, f.Unique, where))
				}
				col := column{name: pf.Column, dataType: typ, notNull: f.NotNull()}
				if err := g.applyReference(&col, f); err != nil {
					return nil, err
				}
				if timestampDefault {
					col.defaultTo = "CURRENT_TIMESTAMP"
					if d == dialect.MySQL {
						col.defaultTo = "CURRENT_TIMESTAMP(3)"
					}
				} else if staticDefault {
					v := f.DefaultValue
					if b, ok := v.(bool); ok && (d == dialect.SQLite || d == dialect.MSSQL) {
						v = 0
						if b {
							v = 1
						}
					}
					if col.defaultTo, err = c.immediate(v); err != nil {
						return nil, err
					}
				}
				statements = append(statements, c.addColumn(t.table, col))
			}
		}
	}

	for _, t := range toBeCreated {
		columns := []column{g.idColumn()}
		for _, pf := range t.fields {
			f := pf.Field
			typ, err := g.columnType(f, pf.Column, g.tableIndexStringLength(t.table, pf.Column))
			if err != nil {
				return nil, err
			}
			col := column{name: pf.Column, dataType: typ, notNull: f.NotNull(), unique: f.Unique}
			if err := g.applyReference(&col, f); err != nil {
				return nil, err
			}
			if hasTimestampColumnDefault(f, d) {
				col.defaultTo = "CURRENT_TIMESTAMP"
				if d == dialect.MySQL {
					col.defaultTo = "CURRENT_TIMESTAMP(3)"
				}
			}
			columns = append(columns, col)
			if f.Index && !f.Unique {
				deferred = append(deferred, c.createIndex(fieldIndexName(t.table, pf.Column, false), t.table, []string{pf.Column}, false, ""))
			}
		}
		statements = append(statements, c.createTable(t.table, columns))
	}

	for _, ix := range plan.ToBeAddedIndexes {
		deferred = append(deferred, c.createIndex(ix.Name, ix.Table, ix.Columns, ix.Unique, ""))
	}
	statements = append(statements, deferred...)

	for _, t := range toBeCreated {
		plan.ToBeCreated = append(plan.ToBeCreated, adapter.TableChange{Table: t.table, Fields: fieldsOf(t.fields), Order: t.order})
	}
	for _, t := range toBeAdded {
		plan.ToBeAdded = append(plan.ToBeAdded, adapter.TableChange{Table: t.table, Fields: fieldsOf(t.fields), Order: t.order})
	}
	plan.Statements = statements
	plan.Exec = func(ctx context.Context) error {
		for _, stmt := range statements {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migration: %s: %w", stmt, err)
			}
		}
		return nil
	}
	return plan, nil
}

func fieldsOf(fields []physField) []db.Field {
	out := make([]db.Field, len(fields))
	for i, pf := range fields {
		f := pf.Field
		f.FieldName = pf.Column
		out[i] = f
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// hasTimestampColumnDefault: a date field with a function default gets CURRENT_TIMESTAMP on
// PostgreSQL, MySQL and SQL Server.
func hasTimestampColumnDefault(f db.Field, d dialect.Dialect) bool {
	return f.Type == db.TypeDate && f.DefaultFunc != nil && (d == dialect.Postgres || d == dialect.MySQL || d == dialect.MSSQL)
}

// hasStaticColumnDefault: a string, number or boolean field with a static default (nullable
// unique columns excepted: NULL is their only unique-safe backfill).
func hasStaticColumnDefault(f db.Field) bool {
	return !(f.Unique && f.IsOptional()) &&
		(f.Type == db.TypeString || f.Type == db.TypeNumber || f.Type == db.TypeBoolean) &&
		f.DefaultValue != nil && f.DefaultFunc == nil
}

func tableHasRows(ctx context.Context, conn *sql.DB, c compiler, table string) (bool, error) {
	rows, err := conn.QueryContext(ctx, c.hasRowsQuery(table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	has := rows.Next()
	return has, rows.Err()
}

func fieldTypeString(f db.Field) string {
	if f.Type == db.TypeEnum {
		return strings.Join(f.Enum, ",")
	}
	return string(f.Type)
}

// assertExistingTableIndexFits refuses an index on an existing MySQL / SQL Server table whose
// key can exceed the engine's index-key limit.
func assertExistingTableIndexFits(bounds map[string]int64, d dialect.Dialect, table *TableMetadata, value *physTable, index resolvedIndex) error {
	budget, engine, bd, perChar := int64(1700), "SQL Server", boundedMSSQL, int64(1)
	if d == dialect.MySQL {
		budget, engine, bd, perChar = 3072, "MySQL", boundedMySQL, 4
	}
	existing := map[string]bool{}
	for _, c := range table.Columns {
		existing[c.Name] = true
	}
	var required int64
	for _, column := range index.Columns {
		f, ok := value.field(column)
		if !ok {
			continue
		}
		if isStringType(f.Type) {
			if !existing[column] {
				n, _ := indexStringLength(value, column, bd)
				required += int64(n) * perChar
				continue
			}
			bound := bounds[columnKey(value.Name, column)]
			if bound == 0 {
				return &SchemaError{Message: fmt.Sprintf("Cannot create database index %q on existing table %q because column %q is not bounded for %s. Change it to a bounded string column, resolve oversized values, then run the migration again.", index.Name, value.Name, column, engine)}
			}
			required += bound
		} else {
			required += 16
		}
	}
	if required > budget {
		return &SchemaError{Message: fmt.Sprintf("Cannot create database index %q on existing table %q because its columns can exceed %s's %d-byte index-key limit. Bound the indexed string columns to the generated schema lengths, resolve oversized values, then run the migration again.", index.Name, value.Name, engine, budget)}
	}
	return nil
}

// generator holds what getType and the reference resolution need.
type generator struct {
	c      compiler
	d      dialect.Dialect
	idMode adapter.IDMode
	schema *db.Schema
	tables map[string]*physTable
}

func (g generator) tableIndexStringLength(table, column string) int {
	if g.d != dialect.MySQL && g.d != dialect.MSSQL {
		return 0
	}
	t := g.tables[table]
	if t == nil {
		return 0
	}
	bd := boundedMySQL
	if g.d == dialect.MSSQL {
		bd = boundedMSSQL
	}
	n, _ := indexStringLength(t, column, bd)
	return n
}

// columnType is getType.
func (g generator) columnType(f db.Field, column string, indexLength int) (string, error) {
	serial := g.idMode == adapter.IDSerial
	uuid := g.idMode == adapter.IDUUID
	if column == "id" || (f.References != nil && f.References.Field == "id") {
		if column == "id" {
			switch g.d {
			case dialect.Postgres:
				if serial {
					return "integer GENERATED BY DEFAULT AS IDENTITY", nil
				}
				if uuid {
					return "uuid", nil
				}
				return "text", nil
			case dialect.SQLite:
				if serial {
					return "integer", nil
				}
				return "text", nil
			default: // mysql, mssql
				if serial {
					return "integer", nil
				}
				return "varchar(36)", nil
			}
		}
		switch g.d {
		case dialect.Postgres:
			if serial {
				return "integer", nil
			}
			if uuid {
				return "uuid", nil
			}
			return "text", nil
		case dialect.SQLite:
			if serial {
				return "integer", nil
			}
			return "text", nil
		default:
			if serial {
				return "integer", nil
			}
			return "varchar(36)", nil
		}
	}
	if f.Type == db.TypeEnum {
		return "text", nil
	}
	switch f.Type {
	case db.TypeString:
		switch g.d {
		case dialect.SQLite, dialect.Postgres:
			return "text", nil
		case dialect.MySQL:
			switch {
			case indexLength > 0:
				return fmt.Sprintf("varchar(%d)", indexLength), nil
			case f.Unique:
				return "varchar(255)", nil
			case f.References != nil:
				return "varchar(36)", nil
			case f.Sortable, f.Index:
				return "varchar(255)", nil
			}
			return "text", nil
		default: // mssql
			switch {
			case indexLength > 0:
				return fmt.Sprintf("varchar(%d)", indexLength), nil
			case f.Unique || f.Sortable:
				return "varchar(255)", nil
			case f.References != nil:
				return "varchar(36)", nil
			}
			return "varchar(8000)", nil
		}
	case db.TypeBoolean:
		switch g.d {
		case dialect.SQLite:
			return "integer", nil
		case dialect.MSSQL:
			return "smallint", nil
		}
		return "boolean", nil
	case db.TypeNumber:
		if f.BigInt {
			return "bigint", nil
		}
		return "integer", nil
	case db.TypeDate:
		switch g.d {
		case dialect.SQLite:
			return "date", nil
		case dialect.Postgres:
			return "timestamptz", nil
		case dialect.MySQL:
			return "timestamp(3)", nil
		}
		return "datetime2(3)", nil
	case db.TypeJSON, db.TypeStringArray, db.TypeNumberArray:
		switch g.d {
		case dialect.SQLite:
			return "text", nil
		case dialect.Postgres:
			return "jsonb", nil
		case dialect.MySQL:
			return "json", nil
		}
		return "varchar(8000)", nil
	}
	return "", &SchemaError{Message: fmt.Sprintf("Unsupported field type '%s' for field '%s'. Allowed types are: string, number, boolean, date, string[], number[]. If you need to store structured data, store it as a JSON string (type: \"string\") or split it into primitive fields. See https://better-auth.com/docs/advanced/schema#additional-fields", f.Type, column)}
}

// idColumn is the "id" column of createTable.
func (g generator) idColumn() column {
	serial := g.idMode == adapter.IDSerial
	idType := db.TypeString
	if serial {
		idType = db.TypeNumber
	}
	typ, _ := g.columnType(db.Field{Type: idType}, "id", 0)
	col := column{name: "id", dataType: typ, notNull: true, primaryKey: true}
	switch {
	case serial:
		switch g.d {
		case dialect.MSSQL:
			col.identity = true
		case dialect.MySQL:
			col.autoIncrement = true
		}
	case g.idMode == adapter.IDUUID && g.d == dialect.Postgres:
		col.defaultTo = "pg_catalog.gen_random_uuid()"
	}
	return col
}

// applyReference adds `references <path> on delete <action>` (getReferencePath).
func (g generator) applyReference(col *column, f db.Field) error {
	if f.References == nil {
		return nil
	}
	ref, err := parseReference(g.referencePath(f.References.Model, f.References.Field))
	if err != nil {
		return err
	}
	ref.onDelete = f.References.OnDelete
	if ref.onDelete == "" {
		ref.onDelete = db.OnDeleteCascade
	}
	col.references = ref
	return nil
}

// referencePath is getReferencePath: model (already the referenced model name, see
// physicalSchema) and field resolved through the logical schema, falling back to the given
// strings for tables outside the Better Auth schema.
func (g generator) referencePath(model, field string) string {
	t := g.defaultModel(model)
	if t == nil {
		return model + "." + field
	}
	modelName := model
	if t.ModelName != model {
		modelName = t.ModelName
	}
	var found *db.Field
	if field == "id" || field == "_id" {
		field = "id"
		for i := range t.Fields {
			if t.Fields[i].Name == "id" {
				found = &t.Fields[i]
			}
		}
	} else {
		for i := range t.Fields {
			if t.Fields[i].Name == field {
				found = &t.Fields[i]
				break
			}
		}
		if found == nil {
			for i := range t.Fields {
				if t.Fields[i].FieldName != "" && t.Fields[i].FieldName == field {
					found = &t.Fields[i]
					break
				}
			}
		}
		if found == nil {
			return model + "." + field
		}
	}
	if found != nil {
		return modelName + "." + found.Column()
	}
	return modelName + "." + field
}

// defaultModel is getDefaultModelName: the table with that key, or the first whose model
// name matches.
func (g generator) defaultModel(model string) *db.Table {
	if t := g.schema.Table(model); t != nil {
		return t
	}
	for _, t := range g.schema.Tables {
		if t.ModelName == model {
			return t
		}
	}
	return nil
}
