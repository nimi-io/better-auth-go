// Package dialect identifies the SQL database behind a *sql.DB (KyselyDatabaseType upstream)
// and holds the per-dialect syntax shared by the SQL adapter and its migrations.
package dialect

import (
	"database/sql"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Dialect is a SQL database family.
type Dialect string

// Supported dialects.
const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
	SQLite   Dialect = "sqlite"
	MSSQL    Dialect = "mssql"
)

// Detect infers the dialect from the driver registered for db (getKyselyDatabaseType).
func Detect(db *sql.DB) (Dialect, error) {
	if db == nil {
		return "", fmt.Errorf("dialect: nil *sql.DB")
	}
	if d, ok := FromDriver(db.Driver()); ok {
		return d, nil
	}
	return "", fmt.Errorf("dialect: cannot detect the database type of driver %T; set the dialect explicitly", db.Driver())
}

// FromDriver infers the dialect from a database/sql driver value by its package path.
func FromDriver(drv any) (Dialect, bool) {
	t := reflect.TypeOf(drv)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return "", false
	}
	pkg := strings.ToLower(t.PkgPath())
	switch {
	case strings.Contains(pkg, "jackc/pgx"), strings.Contains(pkg, "lib/pq"), strings.Contains(pkg, "postgres"):
		return Postgres, true
	case strings.Contains(pkg, "mysql"):
		return MySQL, true
	case strings.Contains(pkg, "sqlite"), strings.Contains(pkg, "libsql"):
		return SQLite, true
	case strings.Contains(pkg, "mssql"), strings.Contains(pkg, "sqlserver"):
		return MSSQL, true
	}
	return "", false
}

// FromDriverName maps a database/sql driver name ("pgx", "postgres", "mysql", "sqlite",
// "sqlite3", "sqlserver") to a dialect.
func FromDriverName(name string) (Dialect, bool) {
	switch strings.ToLower(name) {
	case "pgx", "postgres", "postgresql", "pq":
		return Postgres, true
	case "mysql", "mariadb":
		return MySQL, true
	case "sqlite", "sqlite3", "libsql":
		return SQLite, true
	case "sqlserver", "mssql":
		return MSSQL, true
	}
	return "", false
}

// Quote quotes an identifier.
func (d Dialect) Quote(ident string) string {
	switch d {
	case MySQL:
		return "`" + strings.ReplaceAll(ident, "`", "``") + "`"
	case MSSQL:
		return "[" + strings.ReplaceAll(ident, "]", "]]") + "]"
	default:
		return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
	}
}

// Placeholder returns the bind parameter for the n-th (1-based) argument.
func (d Dialect) Placeholder(n int) string {
	switch d {
	case Postgres:
		return "$" + strconv.Itoa(n)
	case MSSQL:
		return "@p" + strconv.Itoa(n)
	default:
		return "?"
	}
}

// Valid reports whether d is one of the known dialects.
func (d Dialect) Valid() bool {
	switch d {
	case Postgres, MySQL, SQLite, MSSQL:
		return true
	}
	return false
}

// SupportsReturning reports whether INSERT/UPDATE/DELETE ... RETURNING is available
// (MySQL has no RETURNING; SQL Server uses OUTPUT instead).
func (d Dialect) SupportsReturning() bool { return d == Postgres || d == SQLite }

// QuoteTable quotes a table reference the way Kysely parses one: "schema.table" (a dotted
// name) becomes a schema-qualified reference, otherwise schemaName (when non-empty) is
// prepended as a single identifier (Kysely's withSchema).
func (d Dialect) QuoteTable(schemaName, table string) string {
	if i := strings.IndexByte(table, '.'); i >= 0 {
		return d.Quote(table[:i]) + "." + d.Quote(table[i+1:])
	}
	if schemaName != "" {
		return d.Quote(schemaName) + "." + d.Quote(table)
	}
	return d.Quote(table)
}
