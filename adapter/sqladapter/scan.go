package sqladapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
)

// execer is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// binaryTypes are column types whose []byte values are kept as bytes.
var binaryTypes = map[string]bool{
	"BYTEA": true, "BLOB": true, "TINYBLOB": true, "MEDIUMBLOB": true, "LONGBLOB": true,
	"BINARY": true, "VARBINARY": true, "BIT": true, "GEOMETRY": true,
}

// normalize converts driver values to the shapes JavaScript drivers return: text-like
// []byte (MySQL strings, PostgreSQL jsonb) becomes string. Everything else (int64,
// float64, bool, time.Time, decimal strings) is left to the factory's output transform.
func normalize(v any, ct *sql.ColumnType) any {
	if b, ok := v.([]byte); ok {
		if ct != nil && binaryTypes[strings.ToUpper(ct.DatabaseTypeName())] {
			return append([]byte(nil), b...)
		}
		return string(b)
	}
	return v
}

// scanRows reads every row into records keyed by column name.
func scanRows(rows *sql.Rows) ([]adapter.Record, error) {
	defer rows.Close()
	cols, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	var out []adapter.Record
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		rec := make(adapter.Record, len(cols))
		for i, c := range cols {
			rec[c.Name()] = normalize(vals[i], c)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// infoLogger is implemented by loggers with an Info level (betterauth.Logger).
type infoLogger interface {
	Info(msg string, args ...any)
}

func (a *sqlAdapter) logQuery(kind, query string, args []any) {
	if !a.debug {
		return
	}
	msg := fmt.Sprintf("[%s] %s: %s", AdapterName, kind, query)
	if l, ok := a.opts.Logger.(infoLogger); ok {
		l.Info(msg, args)
		return
	}
	slog.Info(msg, "args", args)
}

func (a *sqlAdapter) query(ctx context.Context, q execer, b *builder) ([]adapter.Record, error) {
	query := b.String()
	a.logQuery("query", query, b.args)
	rows, err := q.QueryContext(ctx, query, b.args...)
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}

func (a *sqlAdapter) queryFirst(ctx context.Context, q execer, b *builder) (adapter.Record, error) {
	rows, err := a.query(ctx, q, b)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (a *sqlAdapter) exec(ctx context.Context, q execer, b *builder) (int64, error) {
	query := b.String()
	a.logQuery("exec", query, b.args)
	res, err := q.ExecContext(ctx, query, b.args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
