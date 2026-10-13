// Package sqladapter is the SQL database adapter for PostgreSQL, MySQL and SQLite built on
// database/sql (packages/kysely-adapter).
//
// It is database-compatible with the TypeScript Kysely adapter: it reads and writes the same
// tables with the same value encodings, so a Go and a TypeScript Better Auth server can share
// one database. Per dialect (the kyselyAdapter config upstream):
//
//	            booleans        dates                    json / arrays      uuid ids
//	PostgreSQL  boolean         timestamptz              jsonb (JSON text)  database default
//	MySQL       tinyint 1/0     timestamp(3), UTC wall   JSON text          generated
//	SQLite      integer 1/0     ISO-8601 text (ms, Z)    JSON text          generated
//
// MySQL dates are written in the connection's time zone (go-sql-driver's loc, UTC by
// default); mysql2 must use `timezone: "Z"` for the TypeScript server to agree.
package sqladapter

import (
	"database/sql"
	"fmt"
	"sync/atomic"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
)

// Dialect re-exports dialect.Dialect.
type Dialect = dialect.Dialect

// Dialects.
const (
	Postgres = dialect.Postgres
	MySQL    = dialect.MySQL
	SQLite   = dialect.SQLite
)

// Adapter identity (adapterId / adapterName upstream).
const (
	AdapterID   = "kysely"
	AdapterName = "Kysely Adapter"
)

// Config configures the adapter (kyselyAdapter options plus database.schemaName).
type Config struct {
	// Dialect is detected from the driver when empty. When detection fails the adapter
	// falls back to SQLite (`type: databaseType || "sqlite"` upstream).
	Dialect Dialect
	// SchemaName is the PostgreSQL schema (database.schemaName). Every table reference is
	// qualified with it; it is rejected on other dialects.
	SchemaName string
	// UsePlural expects plural table names.
	UsePlural bool
	// Transaction enables database transactions. The default is true for every detected
	// (or explicitly configured) dialect, matching createKyselyAdapter for connection pools;
	// it is false when the dialect could not be determined.
	Transaction *bool
	// DebugLogs logs every SQL statement and its arguments (at Info level when the
	// configured logger has an Info method, through log/slog otherwise).
	DebugLogs bool
}

// checkSchemaName ports checkSchemaName from dialect.ts. An empty Go string means "not
// configured", so the upstream empty-name error cannot occur.
func checkSchemaName(schemaName string, d Dialect) error {
	if schemaName == "" {
		return nil
	}
	if d != Postgres {
		name := string(d)
		if name == "" {
			name = "unknown"
		}
		return fmt.Errorf("`database.schemaName` is only supported on PostgreSQL, but the configured database type is %q.", name)
	}
	return nil
}

// resolved is the outcome of createKyselyAdapter for a *sql.DB.
type resolved struct {
	dialect     Dialect
	transaction bool
}

func resolve(conn *sql.DB, cfg Config) (resolved, error) {
	d := cfg.Dialect
	known := d != ""
	if d == "" && conn != nil {
		if det, err := dialect.Detect(conn); err == nil {
			d, known = det, true
		}
	}
	if err := checkSchemaName(cfg.SchemaName, d); err != nil {
		return resolved{}, err
	}
	if d == "" {
		d = SQLite
	}
	if !d.Valid() {
		return resolved{}, fmt.Errorf("sqladapter: unknown dialect %q", d)
	}
	if d == dialect.MSSQL {
		return resolved{}, fmt.Errorf("sqladapter: the %q dialect is not supported", d)
	}
	tx := known
	if cfg.Transaction != nil {
		tx = *cfg.Transaction
	}
	return resolved{dialect: d, transaction: tx}, nil
}

// factoryConfig is the createAdapterFactory config of kyselyAdapter for a dialect.
func factoryConfig(d Dialect, usePlural bool) adapter.Config {
	f := false
	t := true
	cfg := adapter.Config{
		AdapterID:      AdapterID,
		AdapterName:    AdapterName,
		UsePlural:      usePlural,
		SupportsJSON:   d == Postgres,
		SupportsArrays: false,
		SupportsUUIDs:  d == Postgres,
	}
	switch d {
	case Postgres:
		cfg.SupportsBooleans, cfg.SupportsDates = &t, &t
	case MySQL:
		cfg.SupportsBooleans, cfg.SupportsDates = &f, &t
	default:
		cfg.SupportsBooleans, cfg.SupportsDates = &f, &f
	}
	return cfg
}

// New returns an adapter factory for conn (kyselyAdapter(createKyselyAdapter(db))).
func New(conn *sql.DB, cfg Config) adapter.Factory {
	var warnedNoID atomic.Bool
	return func(opts adapter.Options) (adapter.Adapter, error) {
		if conn == nil {
			return nil, fmt.Errorf("sqladapter: nil *sql.DB")
		}
		r, err := resolve(conn, cfg)
		if err != nil {
			return nil, err
		}
		return adapter.NewFactory(factoryConfig(r.dialect, cfg.UsePlural), func(opts adapter.Options, h adapter.Helpers) (adapter.CustomAdapter, error) {
			base := &sqlAdapter{
				db:         conn,
				q:          rootExecer(conn, r.dialect),
				d:          r.dialect,
				schemaName: cfg.SchemaName,
				opts:       opts,
				h:          h,
				debug:      cfg.DebugLogs,
			}
			if r.dialect == MySQL && opts.IDMode == adapter.IDNone && warnedNoID.CompareAndSwap(false, true) && opts.Logger != nil {
				opts.Logger.Warn("[Kysely Adapter] MySQL does not support INSERT...RETURNING. " +
					"With generateId set to false, the adapter uses best-effort fallback " +
					"strategies (unique columns, full-field match) to retrieve inserted rows. " +
					"For reliable behavior, use Better Auth's default ID generation, a custom generateId function, or generateId: \"serial\" for auto-increment.")
			}
			if r.transaction {
				return &txAdapter{base}, nil
			}
			return base, nil
		})(opts)
	}
}

// rootExecer is the execer used outside transactions.
func rootExecer(conn *sql.DB, d Dialect) execer {
	if d == Postgres {
		return stalePlanRetrier{db: conn}
	}
	return conn
}
