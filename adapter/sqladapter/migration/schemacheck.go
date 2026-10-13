package migration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
	"github.com/nimi-io/better-auth-go/db"
)

// This file ports packages/core/src/db/schema-diff.ts (diffSchema, formatSchemaFinding) and
// packages/kysely-adapter/src/schema-check.ts (findSchemaProblems) plus getMigrations'
// matchType.

// ExpectedTable is an entry of ExpectedSchema: the physical columns Better Auth writes.
type ExpectedTable struct {
	Name string
	// Schema restricts the match to tables of that schema when set.
	Schema            string
	Columns           []string
	IDColumn          string // defaults to "id"
	DisableMigrations bool
}

// FindingKind classifies a SchemaFinding.
type FindingKind string

// Finding kinds.
const (
	FindingMissingTable             FindingKind = "missing-table"
	FindingMissingColumn            FindingKind = "missing-column"
	FindingUnexpectedRequiredColumn FindingKind = "unexpected-required-column"
)

// SchemaFinding is a difference between the expected schema and the database.
type SchemaFinding struct {
	Kind   FindingKind
	Table  string
	Column string
}

// ExpectedSchema returns the expected physical tables of schema (getExpectedSchema with
// usePlural false, followed by toPhysicalSchema for a connection qualified with schemaName).
func ExpectedSchema(schema *db.Schema, schemaName string) ([]ExpectedTable, error) {
	tables, err := physicalSchema(schema)
	if err != nil {
		return nil, err
	}
	return expectedFromPhysical(tables, schemaName), nil
}

// expectedFromPhysical is toPhysicalSchema(db, getSchema(config)): a "schema.table" model
// name is split by Kysely's table parser, and a withSchema connection qualifies the rest.
func expectedFromPhysical(tables []*physTable, schemaName string) []ExpectedTable {
	out := make([]ExpectedTable, 0, len(tables))
	for _, t := range tables {
		schema, name := splitTable(t.Name)
		if schema == "" {
			schema = schemaName
		}
		e := ExpectedTable{Name: name, Schema: schema, DisableMigrations: t.DisableMigrations}
		for _, f := range t.Fields {
			e.Columns = append(e.Columns, f.Column)
		}
		out = append(out, e)
	}
	return out
}

// DiffSchema compares the expected tables with introspected ones (diffSchema).
func DiffSchema(expected []ExpectedTable, actual []TableMetadata) []SchemaFinding {
	var findings []SchemaFinding
	for _, table := range expected {
		if table.DisableMigrations {
			continue
		}
		var found *TableMetadata
		for i := range actual {
			if actual[i].Name == table.Name && (table.Schema == "" || actual[i].Schema == table.Schema) {
				found = &actual[i]
				break
			}
		}
		if found == nil {
			findings = append(findings, SchemaFinding{Kind: FindingMissingTable, Table: table.Name})
			continue
		}
		id := table.IDColumn
		if id == "" {
			id = "id"
		}
		written := []string{id}
		seen := map[string]bool{id: true}
		for _, c := range table.Columns {
			if !seen[c] {
				seen[c] = true
				written = append(written, c)
			}
		}
		for _, c := range written {
			if _, ok := found.column(c); !ok {
				findings = append(findings, SchemaFinding{Kind: FindingMissingColumn, Table: table.Name, Column: c})
			}
		}
		for _, c := range found.Columns {
			if seen[c.Name] || c.IsNullable || c.HasDefaultValue || c.IsAutoIncrementing {
				continue
			}
			findings = append(findings, SchemaFinding{Kind: FindingUnexpectedRequiredColumn, Table: table.Name, Column: c.Name})
		}
	}
	return findings
}

// FormatSchemaFinding renders a finding for the "database" source (formatSchemaFinding).
func FormatSchemaFinding(f SchemaFinding) string {
	switch f.Kind {
	case FindingMissingTable:
		return fmt.Sprintf("Table %q is missing. Run `npx auth migrate` to add it.", f.Table)
	case FindingMissingColumn:
		return fmt.Sprintf("Column %q is missing from table %q. Run `npx auth migrate` to add it.", f.Column, f.Table)
	}
	issuer := ""
	if f.Column == "issuer" {
		issuer = " If this column came from Better Auth 1.7.0 through 1.7.2, follow the upgrade guide before removing it: https://www.better-auth.com/docs/guides/1-7-upgrade-guide"
	}
	return fmt.Sprintf("Column %q on table %q is required but Better Auth never writes it, so every insert into %q fails. Drop the column, make it nullable, or give it a database default.%s", f.Column, f.Table, f.Table, issuer)
}

// Querier runs queries; *sql.DB, *sql.Conn and *sql.Tx satisfy it.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// FindSchemaProblems compares the expected tables with the database (findSchemaProblems):
// on PostgreSQL an unqualified table resolves to the first search_path schema that has it,
// on SQL Server to the user's default schema or dbo. A *sql.DB is pinned to one connection
// so the search path is the one the tables are read with.
func FindSchemaProblems(ctx context.Context, q Querier, d dialect.Dialect, expected []ExpectedTable) ([]SchemaFinding, error) {
	if d == dialect.SQLite {
		tables, err := IntrospectTables(ctx, q, d)
		if err != nil {
			return nil, err
		}
		return DiffSchema(expected, tables), nil
	}
	if pool, ok := q.(*sql.DB); ok {
		c, err := pool.Conn(ctx)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		q = c
	}
	var (
		searchPath []string
		err        error
	)
	switch d {
	case dialect.Postgres:
		if searchPath, err = postgresSearchPath(ctx, q); err != nil {
			return nil, err
		}
	case dialect.MSSQL:
		s, err := mssqlCurrentSchema(ctx, q)
		if err != nil {
			return nil, err
		}
		searchPath = []string{s, "dbo"}
	}
	tables, err := IntrospectTables(ctx, q, d)
	if err != nil {
		return nil, err
	}
	resolved := append([]ExpectedTable(nil), expected...)
	if searchPath != nil {
		for i := range resolved {
			if resolved[i].Schema != "" {
				continue
			}
			resolved[i].Schema = unmatchedSchema
			for _, schema := range searchPath {
				if hasTable(tables, resolved[i].Name, schema) {
					resolved[i].Schema = schema
					break
				}
			}
		}
	}
	return DiffSchema(resolved, tables), nil
}

// unmatchedSchema stands for upstream's "" schema (a table in no search_path schema), which
// matches no introspected table.
const unmatchedSchema = "\x00"

func hasTable(tables []TableMetadata, name, schema string) bool {
	for _, t := range tables {
		if t.Name == name && t.Schema == schema {
			return true
		}
	}
	return false
}

var typeMaps = map[dialect.Dialect]map[db.FieldType][]string{
	dialect.Postgres: {
		db.TypeString:  {"character varying", "varchar", "text", "uuid"},
		db.TypeNumber:  {"int4", "integer", "bigint", "smallint", "numeric", "real", "double precision"},
		db.TypeBoolean: {"bool", "boolean"},
		db.TypeDate:    {"timestamptz", "timestamp", "date"},
		db.TypeJSON:    {"json", "jsonb"},
	},
	dialect.MySQL: {
		db.TypeString:  {"varchar", "text", "uuid"},
		db.TypeNumber:  {"integer", "int", "bigint", "smallint", "decimal", "float", "double"},
		db.TypeBoolean: {"boolean", "tinyint"},
		db.TypeDate:    {"timestamp", "datetime", "date"},
		db.TypeJSON:    {"json"},
	},
	dialect.SQLite: {
		db.TypeString:  {"TEXT"},
		db.TypeNumber:  {"INTEGER", "REAL", "BIGINT"},
		db.TypeBoolean: {"INTEGER", "BOOLEAN"},
		db.TypeDate:    {"DATE", "INTEGER"},
		db.TypeJSON:    {"TEXT"},
	},
	dialect.MSSQL: {
		db.TypeString:  {"varchar", "nvarchar", "uniqueidentifier"},
		db.TypeNumber:  {"int", "bigint", "smallint", "decimal", "float", "double"},
		db.TypeBoolean: {"bit", "smallint"},
		db.TypeDate:    {"datetime2", "date", "datetime"},
		db.TypeJSON:    {"varchar", "nvarchar"},
	},
}

// MatchType reports whether an introspected column data type fits a field type (matchType).
func MatchType(columnDataType string, fieldType db.FieldType, d dialect.Dialect) bool {
	if fieldType == db.TypeStringArray || fieldType == db.TypeNumberArray {
		return strings.Contains(strings.ToLower(columnDataType), "json")
	}
	if fieldType == db.TypeEnum {
		fieldType = db.TypeString
	}
	normalized := strings.TrimSpace(strings.SplitN(strings.ToLower(columnDataType), "(", 2)[0])
	for _, t := range typeMaps[d][fieldType] {
		if strings.ToLower(t) == normalized {
			return true
		}
	}
	return false
}
