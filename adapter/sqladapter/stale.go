package sqladapter

import (
	"context"
	"database/sql"
	"strings"
)

// staleRetries bounds the retries of a statement whose cached plan went stale. Each failed
// attempt evicts the statement from one pooled connection's cache.
const staleRetries = 8

// isStalePlan reports PostgreSQL's "cached plan must not change result type" (SQLSTATE
// 0A000), raised when a prepared statement outlives a schema change (e.g. migrations run
// while the server is up). Drivers that cache prepared statements per connection (pgx's
// default QueryExecMode) evict the statement on this error, so a retry re-prepares it.
// node-postgres uses unnamed statements, so TypeScript Better Auth never sees this error.
func isStalePlan(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "cached plan must not change result type")
}

// stalePlanRetrier retries statements outside transactions after a stale-plan error.
// Inside a transaction the error aborts the transaction, so it cannot be retried; use
// pgx's default_query_exec_mode=exec (or describe_exec) to avoid statement caching there.
type stalePlanRetrier struct{ db *sql.DB }

func (r stalePlanRetrier) ExecContext(ctx context.Context, query string, args ...any) (res sql.Result, err error) {
	for i := 0; i <= staleRetries; i++ {
		if res, err = r.db.ExecContext(ctx, query, args...); !isStalePlan(err) {
			return res, err
		}
	}
	return res, err
}

func (r stalePlanRetrier) QueryContext(ctx context.Context, query string, args ...any) (rows *sql.Rows, err error) {
	for i := 0; i <= staleRetries; i++ {
		if rows, err = r.db.QueryContext(ctx, query, args...); !isStalePlan(err) {
			return rows, err
		}
	}
	return rows, err
}
