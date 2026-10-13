package migration

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
)

// Kysely's migration bookkeeping tables, hidden from introspection
// (kysely-adapter/src/kysely-migration-tables.ts).
const (
	defaultMigrationTable     = "kysely_migration"
	defaultMigrationLockTable = "kysely_migration_lock"
)

// ColumnMetadata describes an introspected column (Kysely's ColumnMetadata).
type ColumnMetadata struct {
	Name               string
	DataType           string
	IsNullable         bool
	IsAutoIncrementing bool
	HasDefaultValue    bool
}

// TableMetadata describes an introspected table (Kysely's TableMetadata).
type TableMetadata struct {
	Name      string
	Schema    string // empty when the dialect has no schemas (SQLite)
	IsView    bool
	IsForeign bool
	Columns   []ColumnMetadata
}

func (t *TableMetadata) column(name string) (ColumnMetadata, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return ColumnMetadata{}, false
}

// IntrospectTables returns the tables of the database (db.introspection.getTables()): for
// SQLite the port of kysely-adapter's createSqliteIntrospector, for the other dialects the
// queries of Kysely's PostgresIntrospector, MysqlIntrospector and MssqlIntrospector.
func IntrospectTables(ctx context.Context, q Querier, d dialect.Dialect) ([]TableMetadata, error) {
	switch d {
	case dialect.SQLite:
		return introspectSQLite(ctx, q)
	case dialect.Postgres:
		return introspectPostgres(ctx, q)
	case dialect.MySQL:
		return introspectMySQL(ctx, q)
	case dialect.MSSQL:
		return introspectMSSQL(ctx, q)
	}
	return nil, fmt.Errorf("migration: unsupported dialect %q", d)
}

// ---- SQLite (kysely-adapter/src/sqlite-introspector.ts) --------------------------------

type pragmaTableInfo struct {
	cid     int
	name    string
	typ     string
	notnull int
	dflt    sql.NullString
	pk      int
}

// sqliteIntegerPrimaryKeyColumn is sqliteIntegerPrimaryKeyColumn: the single primary-key
// column declared INTEGER.
func sqliteIntegerPrimaryKeyColumn(columns []pragmaTableInfo) string {
	var pks []pragmaTableInfo
	for _, c := range columns {
		if c.pk > 0 {
			pks = append(pks, c)
		}
	}
	if len(pks) == 1 && strings.ToLower(pks[0].typ) == "integer" {
		return pks[0].name
	}
	return ""
}

// sqliteGeneratedPrimaryKeyColumn returns the rowid-alias column: an INTEGER primary key that
// is not backed by a separate primary-key index (DESC and WITHOUT ROWID keys are).
func sqliteGeneratedPrimaryKeyColumn(ctx context.Context, q Querier, table string, columns []pragmaTableInfo) (string, error) {
	column := sqliteIntegerPrimaryKeyColumn(columns)
	if column == "" {
		return "", nil
	}
	rows, err := q.QueryContext(ctx, "PRAGMA index_list("+dialect.SQLite.Quote(table)+")")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return "", err
	}
	originIdx := -1
	for i, c := range cols {
		if c == "origin" {
			originIdx = i
		}
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return "", err
		}
		if originIdx >= 0 && asString(vals[originIdx]) == "pk" {
			return "", rows.Err()
		}
	}
	return column, rows.Err()
}

func sqliteTableInfo(ctx context.Context, q Querier, table string) ([]pragmaTableInfo, error) {
	rows, err := q.QueryContext(ctx, `select "cid", "name", "type", "notnull", "dflt_value", "pk" from pragma_table_info(?) as "table_info"`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pragmaTableInfo
	for rows.Next() {
		var c pragmaTableInfo
		if err := rows.Scan(&c.cid, &c.name, &c.typ, &c.notnull, &c.dflt, &c.pk); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func toSqliteTableMetadata(name string, columns []pragmaTableInfo, autoIncrement string) TableMetadata {
	t := TableMetadata{Name: name}
	for _, c := range columns {
		t.Columns = append(t.Columns, ColumnMetadata{
			Name:               c.name,
			DataType:           c.typ,
			IsNullable:         c.notnull == 0,
			IsAutoIncrementing: c.name == autoIncrement,
			HasDefaultValue:    c.dflt.Valid,
		})
	}
	return t
}

func introspectSQLite(ctx context.Context, q Querier) ([]TableMetadata, error) {
	rows, err := q.QueryContext(ctx, `select "name" from "sqlite_schema" where "type" = 'table' and "name" not like 'sqlite_%' and "name" != ? and "name" != ?`,
		defaultMigrationTable, defaultMigrationLockTable)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]TableMetadata, 0, len(names))
	for _, name := range names {
		columns, err := sqliteTableInfo(ctx, q, name)
		if err != nil {
			return nil, err
		}
		generated, err := sqliteGeneratedPrimaryKeyColumn(ctx, q, name, columns)
		if err != nil {
			return nil, err
		}
		out = append(out, toSqliteTableMetadata(name, columns, generated))
	}
	return out, nil
}

// ---- PostgreSQL (Kysely PostgresIntrospector) -------------------------------------------

const postgresTablesQuery = `select "a"."attname" as "column", "a"."attnotnull" as "not_null", "a"."atthasdef" as "has_default", "c"."relname" as "table", "c"."relkind"::text as "table_type", "ns"."nspname" as "schema", "typ"."typname" as "type", pg_get_serial_sequence(quote_ident(ns.nspname) || '.' || quote_ident(c.relname), a.attname) as "auto_incrementing"
from "pg_catalog"."pg_attribute" as "a"
inner join "pg_catalog"."pg_class" as "c" on "a"."attrelid" = "c"."oid"
inner join "pg_catalog"."pg_namespace" as "ns" on "c"."relnamespace" = "ns"."oid"
inner join "pg_catalog"."pg_type" as "typ" on "a"."atttypid" = "typ"."oid"
inner join "pg_catalog"."pg_namespace" as "dtns" on "typ"."typnamespace" = "dtns"."oid"
where "c"."relkind" in ('r', 'v', 'p', 'f')
and "ns"."nspname" !~ '^pg_'
and "ns"."nspname" != 'information_schema'
and "ns"."nspname" != 'crdb_internal'
and has_schema_privilege(ns.nspname, 'USAGE')
and "a"."attnum" >= 0
and "a"."attisdropped" != true
and "c"."relname" != $1
and "c"."relname" != $2
order by "ns"."nspname", "c"."relname", "a"."attnum"`

func introspectPostgres(ctx context.Context, q Querier) ([]TableMetadata, error) {
	rows, err := q.QueryContext(ctx, postgresTablesQuery, defaultMigrationTable, defaultMigrationLockTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TableMetadata
	index := map[[2]string]*TableMetadata{}
	for rows.Next() {
		var column, table, tableType, schema, typ string
		var notNull, hasDefault bool
		var autoInc sql.NullString
		if err := rows.Scan(&column, &notNull, &hasDefault, &table, &tableType, &schema, &typ, &autoInc); err != nil {
			return nil, err
		}
		key := [2]string{schema, table}
		t, ok := index[key]
		if !ok {
			t = &TableMetadata{Name: table, Schema: schema, IsView: tableType == "v", IsForeign: tableType == "f"}
			index[key] = t
			out = append(out, t)
		}
		t.Columns = append(t.Columns, ColumnMetadata{
			Name:               column,
			DataType:           typ,
			IsNullable:         !notNull,
			IsAutoIncrementing: autoInc.Valid,
			HasDefaultValue:    hasDefault,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res := make([]TableMetadata, len(out))
	for i, t := range out {
		res[i] = *t
	}
	return res, nil
}

// postgresCurrentSchema is getPostgresSchema: current_schema(), or "public" when no schema
// of the search_path exists.
func postgresCurrentSchema(ctx context.Context, q Querier) (string, error) {
	rows, err := q.QueryContext(ctx, `SELECT pg_catalog.current_schema() AS schema`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var s sql.NullString
	if rows.Next() {
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if !s.Valid {
		return "public", nil
	}
	return s.String, nil
}

func postgresSchemas(ctx context.Context, q Querier) ([]string, error) {
	rows, err := q.QueryContext(ctx, `select "nspname" from "pg_catalog"."pg_namespace"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// postgresSearchPath is current_schemas(true) (schemaSearchPath upstream).
func postgresSearchPath(ctx context.Context, q Querier) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.name::text FROM unnest(pg_catalog.current_schemas(true)) WITH ORDINALITY AS s(name, position) ORDER BY s.position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---- MySQL (Kysely MysqlIntrospector) ---------------------------------------------------

const mysqlTablesQuery = "select `columns`.`COLUMN_NAME`, `columns`.`COLUMN_DEFAULT`, `columns`.`TABLE_NAME`, `columns`.`TABLE_SCHEMA`, `tables`.`TABLE_TYPE`, `tables`.`ENGINE`, `columns`.`IS_NULLABLE`, `columns`.`DATA_TYPE`, `columns`.`EXTRA`" +
	" from `information_schema`.`columns` as `columns`" +
	" inner join `information_schema`.`tables` as `tables` on `columns`.`TABLE_CATALOG` = `tables`.`TABLE_CATALOG` and `columns`.`TABLE_SCHEMA` = `tables`.`TABLE_SCHEMA` and `columns`.`TABLE_NAME` = `tables`.`TABLE_NAME`" +
	" where `columns`.`TABLE_SCHEMA` = database() and `columns`.`TABLE_NAME` != ? and `columns`.`TABLE_NAME` != ?" +
	" order by `columns`.`TABLE_NAME`, `columns`.`ORDINAL_POSITION`"

func introspectMySQL(ctx context.Context, q Querier) ([]TableMetadata, error) {
	rows, err := q.QueryContext(ctx, mysqlTablesQuery, defaultMigrationTable, defaultMigrationLockTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TableMetadata
	index := map[string]*TableMetadata{}
	for rows.Next() {
		var column, table, schema, tableType, nullable, dataType string
		var def, engine, extra sql.NullString
		if err := rows.Scan(&column, &def, &table, &schema, &tableType, &engine, &nullable, &dataType, &extra); err != nil {
			return nil, err
		}
		t, ok := index[table]
		if !ok {
			t = &TableMetadata{Name: table, Schema: schema, IsView: tableType == "VIEW", IsForeign: engine.String == "FEDERATED"}
			index[table] = t
			out = append(out, t)
		}
		t.Columns = append(t.Columns, ColumnMetadata{
			Name:               column,
			DataType:           dataType,
			IsNullable:         nullable == "YES",
			IsAutoIncrementing: strings.Contains(strings.ToLower(extra.String), "auto_increment"),
			HasDefaultValue:    def.Valid,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res := make([]TableMetadata, len(out))
	for i, t := range out {
		res[i] = *t
	}
	return res, nil
}

// ---- SQL Server (Kysely MssqlIntrospector; untested: no driver is available) -------------

const mssqlTablesQuery = `select "tables"."name" as "table_name", "tables"."type" as "table_type", "table_schemas"."name" as "table_schema_name", "columns"."default_object_id", "columns"."generated_always_type_desc", "columns"."is_computed", "columns"."is_identity", "columns"."is_nullable", "columns"."is_rowguidcol", "columns"."name" as "column_name", "types"."is_nullable" as "type_is_nullable", "types"."name" as "type_name"
from "sys"."tables" as "tables"
left join "sys"."schemas" as "table_schemas" on "table_schemas"."schema_id" = "tables"."schema_id"
inner join "sys"."columns" as "columns" on "columns"."object_id" = "tables"."object_id"
inner join "sys"."types" as "types" on "types"."user_type_id" = "columns"."user_type_id"
where "tables"."name" != @p1 and "tables"."name" != @p2
union all
select "views"."name", "views"."type", "view_schemas"."name", "columns"."default_object_id", "columns"."generated_always_type_desc", "columns"."is_computed", "columns"."is_identity", "columns"."is_nullable", "columns"."is_rowguidcol", "columns"."name", "types"."is_nullable", "types"."name"
from "sys"."views" as "views"
left join "sys"."schemas" as "view_schemas" on "view_schemas"."schema_id" = "views"."schema_id"
inner join "sys"."columns" as "columns" on "columns"."object_id" = "views"."object_id"
inner join "sys"."types" as "types" on "types"."user_type_id" = "columns"."user_type_id"
order by "table_schema_name", "table_name", "column_name"`

func introspectMSSQL(ctx context.Context, q Querier) ([]TableMetadata, error) {
	rows, err := q.QueryContext(ctx, mssqlTablesQuery, defaultMigrationTable, defaultMigrationLockTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TableMetadata
	index := map[string]*TableMetadata{}
	for rows.Next() {
		var table, tableType, column, typeName string
		var schema, generated sql.NullString
		var defaultObject int64
		var computed, identity, nullable, rowguid, typeNullable bool
		if err := rows.Scan(&table, &tableType, &schema, &defaultObject, &generated, &computed, &identity, &nullable, &rowguid, &column, &typeNullable, &typeName); err != nil {
			return nil, err
		}
		key := schema.String + "." + table
		t, ok := index[key]
		if !ok {
			t = &TableMetadata{Name: table, Schema: schema.String, IsView: tableType == "V "}
			index[key] = t
			out = append(out, t)
		}
		t.Columns = append(t.Columns, ColumnMetadata{
			Name:               column,
			DataType:           typeName,
			IsNullable:         nullable && typeNullable,
			IsAutoIncrementing: identity,
			HasDefaultValue:    defaultObject > 0 || generated.String != "NOT_APPLICABLE" || identity || computed || rowguid,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res := make([]TableMetadata, len(out))
	for i, t := range out {
		res[i] = *t
	}
	return res, nil
}

func mssqlCurrentSchema(ctx context.Context, q Querier) (string, error) {
	rows, err := q.QueryContext(ctx, `SELECT SCHEMA_NAME() AS "schemaName"`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var s sql.NullString
	if rows.Next() {
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if s.String == "" {
		return "dbo", nil
	}
	return s.String, nil
}

// ---- indexes (getDatabaseIndexMap) ------------------------------------------------------

type indexColumn struct {
	fullLength bool
	name       *string
	position   float64
}

type indexMetadata struct {
	columns []indexColumn
	name    string
	partial bool
	table   string
	unique  bool
	valid   bool
}

// indexDefinition is DatabaseIndexDefinition.
type indexDefinition struct {
	columns          []string
	name             string
	table            string
	unique           bool
	validFullColumns bool
}

func indexKey(table, name string) string {
	return portableIdentifierKey(table) + "\x00" + portableIdentifierKey(name)
}

func columnKey(table, column string) string { return table + "\x00" + column }

func indexMatches(existing indexDefinition, configured resolvedIndex) bool {
	if existing.unique != configured.Unique || !existing.validFullColumns || len(existing.columns) != len(configured.Columns) {
		return false
	}
	for i, c := range existing.columns {
		if c != configured.Columns[i] {
			return false
		}
	}
	return true
}

// valueIsTrue is databaseValueIsTrue for values scanned as strings.
func valueIsTrue(v sql.NullString) bool {
	if !v.Valid {
		return false
	}
	s := v.String
	return s == "1" || strings.ToLower(s) == "true" || s == "t"
}

// indexMap is an insertion-ordered map of index definitions keyed by indexKey.
type indexMap struct {
	keys []string
	defs map[string]indexDefinition
}

func (m *indexMap) get(key string) (indexDefinition, bool) {
	d, ok := m.defs[key]
	return d, ok
}

func toIndexMap(indexes []*indexMetadata) *indexMap {
	m := &indexMap{defs: map[string]indexDefinition{}}
	for _, index := range indexes {
		cols := append([]indexColumn(nil), index.columns...)
		sort.SliceStable(cols, func(i, j int) bool { return cols[i].position < cols[j].position })
		def := indexDefinition{name: index.name, table: index.table, unique: index.unique}
		full := index.valid && !index.partial && len(cols) > 0
		for _, c := range cols {
			if c.name != nil {
				def.columns = append(def.columns, *c.name)
			}
			if c.name == nil || !c.fullLength {
				full = false
			}
		}
		def.validFullColumns = full
		key := indexKey(index.table, index.name)
		if _, ok := m.defs[key]; !ok {
			m.keys = append(m.keys, key)
		}
		m.defs[key] = def
	}
	return m
}

const sqliteIndexQuery = `SELECT
	tables.name AS "tableName",
	index_list.name AS "indexName",
	index_info.name AS "columnName",
	index_list."unique" AS "isUnique",
	index_list.partial AS "isPartial",
	index_info.seqno AS "columnPosition"
FROM sqlite_master AS tables
INNER JOIN pragma_index_list(tables.name) AS index_list
INNER JOIN pragma_index_info(index_list.name) AS index_info
WHERE tables.type = 'table'`

const postgresIndexQuery = `SELECT
	table_class.relname AS "tableName",
	index_class.relname AS "indexName",
	index_attribute.attname AS "columnName",
	index_data.indisunique AS "isUnique",
	index_data.indisvalid AS "isValid",
	(index_data.indpred IS NOT NULL) AS "isPartial",
	index_column.ordinality AS "columnPosition"
FROM pg_class AS table_class
INNER JOIN pg_namespace AS table_namespace
	ON table_namespace.oid = table_class.relnamespace
INNER JOIN pg_index AS index_data
	ON index_data.indrelid = table_class.oid
INNER JOIN pg_class AS index_class
	ON index_class.oid = index_data.indexrelid
INNER JOIN LATERAL unnest(index_data.indkey)
	WITH ORDINALITY AS index_column(attribute_number, ordinality)
	ON TRUE
LEFT JOIN pg_attribute AS index_attribute
	ON index_attribute.attrelid = table_class.oid
	AND index_attribute.attnum = index_column.attribute_number
WHERE table_namespace.nspname = $1
	AND table_class.relkind = 'r'
	AND index_column.ordinality <= index_data.indnkeyatts`

const mysqlIndexQuery = `SELECT
	table_name AS tableName,
	index_name AS indexName,
	column_name AS columnName,
	non_unique AS nonUnique,
	seq_in_index AS columnPosition,
	sub_part AS prefixLength,
	COALESCE(LOWER(comment) = 'disabled', FALSE) AS isDisabled
FROM information_schema.statistics
WHERE table_schema = DATABASE()`

const mssqlIndexQuery = `SELECT
	tables.name AS "tableName",
	indexes.name AS "indexName",
	columns.name AS "columnName",
	indexes.is_unique AS "isUnique",
	indexes.is_disabled AS "isDisabled",
	indexes.is_hypothetical AS "isHypothetical",
	indexes.has_filter AS "isPartial",
	index_columns.key_ordinal AS "columnPosition"
FROM sys.indexes AS indexes
INNER JOIN sys.tables AS tables
	ON indexes.object_id = tables.object_id
INNER JOIN sys.schemas AS table_schemas
	ON table_schemas.schema_id = tables.schema_id
INNER JOIN sys.index_columns AS index_columns
	ON index_columns.object_id = indexes.object_id
	AND index_columns.index_id = indexes.index_id
INNER JOIN sys.columns AS columns
	ON columns.object_id = index_columns.object_id
	AND columns.column_id = index_columns.column_id
WHERE table_schemas.name = @p1
	AND indexes.name IS NOT NULL
	AND index_columns.key_ordinal > 0`

// databaseIndexMap ports getDatabaseIndexMap (without the D1 introspector hook).
func databaseIndexMap(ctx context.Context, q Querier, d dialect.Dialect, schema string) (*indexMap, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch d {
	case dialect.SQLite:
		rows, err = q.QueryContext(ctx, sqliteIndexQuery)
	case dialect.Postgres:
		rows, err = q.QueryContext(ctx, postgresIndexQuery, schema)
	case dialect.MySQL:
		rows, err = q.QueryContext(ctx, mysqlIndexQuery)
	case dialect.MSSQL:
		rows, err = q.QueryContext(ctx, mssqlIndexQuery, schema)
	default:
		return nil, fmt.Errorf("migration: unsupported dialect %q", d)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var order []*indexMetadata
	metadata := map[string]*indexMetadata{}
	for rows.Next() {
		raw := make([]sql.NullString, len(names))
		ptrs := make([]any, len(names))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := map[string]sql.NullString{}
		for i, n := range names {
			row[n] = raw[i]
		}
		table, name := row["tableName"], row["indexName"]
		if table.String == "" || name.String == "" {
			continue
		}
		var unique bool
		if nonUnique, ok := row["nonUnique"]; ok {
			unique = !valueIsTrue(nonUnique)
		} else {
			unique = valueIsTrue(row["isUnique"])
		}
		position, _ := strconv.ParseFloat(row["columnPosition"].String, 64)
		col := indexColumn{position: position}
		if c := row["columnName"]; c.Valid {
			n := c.String
			col.name = &n
			col.fullLength = !row["prefixLength"].Valid
		}
		partial := valueIsTrue(row["isPartial"])
		isValid, hasValid := row["isValid"]
		valid := !valueIsTrue(row["isDisabled"]) && !valueIsTrue(row["isHypothetical"]) && (!hasValid || valueIsTrue(isValid))
		key := indexKey(table.String, name.String)
		if existing, ok := metadata[key]; ok {
			existing.columns = append(existing.columns, col)
			existing.partial = existing.partial || partial
			existing.valid = existing.valid && valid
			continue
		}
		m := &indexMetadata{columns: []indexColumn{col}, name: name.String, partial: partial, table: table.String, unique: unique, valid: valid}
		metadata[key] = m
		order = append(order, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return toIndexMap(order), nil
}

// columnBounds ports getDatabaseColumnBounds: the maximum index-key bytes of each column on
// MySQL and SQL Server (absent when unbounded).
func columnBounds(ctx context.Context, q Querier, d dialect.Dialect, schema string) (map[string]int64, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch d {
	case dialect.MySQL:
		rows, err = q.QueryContext(ctx, `SELECT
	table_name AS tableName,
	column_name AS columnName,
	character_octet_length AS maxIndexBytes
FROM information_schema.columns
WHERE table_schema = DATABASE()`)
	case dialect.MSSQL:
		rows, err = q.QueryContext(ctx, `SELECT
	tables.name AS "tableName",
	columns.name AS "columnName",
	columns.max_length AS "maxIndexBytes"
FROM sys.columns AS columns
INNER JOIN sys.tables AS tables
	ON tables.object_id = columns.object_id
INNER JOIN sys.schemas AS table_schemas
	ON table_schemas.schema_id = tables.schema_id
WHERE table_schemas.name = @p1`, schema)
	default:
		return map[string]int64{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var table, column, bytes sql.NullString
		if err := rows.Scan(&table, &column, &bytes); err != nil {
			return nil, err
		}
		if table.String == "" || column.String == "" {
			continue
		}
		n := int64(-1)
		if bytes.Valid {
			if v, err := strconv.ParseInt(bytes.String, 10, 64); err == nil {
				n = v
			}
		}
		if n >= 0 {
			out[columnKey(table.String, column.String)] = n
		} else {
			delete(out, columnKey(table.String, column.String))
		}
	}
	return out, rows.Err()
}

func asString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return fmt.Sprint(x)
	}
}
