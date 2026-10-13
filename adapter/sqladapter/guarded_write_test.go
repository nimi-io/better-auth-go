package sqladapter

// Port of e2e/adapter/test/kysely-adapter/adapter.kysely.guarded-write.pg.test.ts: a guarded
// incrementOne/consumeOne that waits on a row lock must re-check its guard against the row
// as committed by the lock holder. Upstream runs it on PostgreSQL; the MySQL path (SELECT
// ... FOR UPDATE in a transaction) is held to the same contract.

import (
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

func guardedAdapter(t *testing.T, e *env) adapter.Adapter {
	t.Helper()
	a, _ := e.newAdapter(t, setup{schema: dbschema.Options{User: dbschema.ModelOptions{AdditionalFields: []dbschema.Field{
		{Name: "authority", Type: dbschema.TypeString},
		{Name: "attempts", Type: dbschema.TypeNumber},
	}}}})
	insertGuarded(t, e, "user-1", "test@example.com")
	return a
}

func insertGuarded(t *testing.T, e *env, id, email string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	e.exec(t, `INSERT INTO "user" ("id", "name", "email", "emailVerified", "createdAt", "updatedAt", "authority", "attempts") VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "Test", email, false, now, now, "old", 1)
}

// lockWaiters counts sessions of this database waiting on a row lock.
func lockWaiters(t *testing.T, e *env) int64 {
	t.Helper()
	var q string
	if e.d == Postgres {
		q = `SELECT COUNT(*) AS "n" FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`
	} else {
		q = `SELECT COUNT(*) AS "n" FROM performance_schema.data_lock_waits w JOIN performance_schema.threads th ON th.THREAD_ID = w.REQUESTING_THREAD_ID WHERE th.PROCESSLIST_DB = DATABASE()`
	}
	n, _ := adapter.ToInt64(e.row(t, q)["n"])
	return n
}

// whileGuardChanges holds a row lock while changing the guard columns, starts operation,
// waits until it blocks on the lock, then commits the change.
func whileGuardChanges(t *testing.T, e *env, operation func() (adapter.Record, error)) adapter.Record {
	t.Helper()
	blocker, err := e.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback() }()
	if _, err := blocker.Exec(e.sql(`UPDATE "user" SET "authority" = 'new', "attempts" = 0 WHERE "id" = 'user-1'`)); err != nil {
		t.Fatal(err)
	}
	type result struct {
		rec adapter.Record
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := operation()
		done <- result{r, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for lockWaiters(t, e) == 0 {
		select {
		case r := <-done:
			t.Fatalf("the guarded operation finished without waiting for the row lock: %v %v", r.rec, r.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the guarded operation did not reach the held row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.rec
}

func guardedRows(t *testing.T, e *env) []adapter.Record {
	t.Helper()
	return e.rows(t, `SELECT "id", "authority", "attempts" FROM "user" ORDER BY "id"`)
}

func forGuardedDialects(t *testing.T, fn func(t *testing.T, e *env)) {
	forEachDialect(t, func(t *testing.T, e *env) {
		if e.d == SQLite {
			t.Skip("SQLite has no row locks: writers are serialized on the database lock")
		}
		fn(t, e)
	})
}

func TestGuardedWrites(t *testing.T) {
	t.Run("rejects a set-only mutation whose guard changed while waiting", func(t *testing.T) {
		forGuardedDialects(t, func(t *testing.T, e *env) {
			a := guardedAdapter(t, e)
			res := whileGuardChanges(t, e, func() (adapter.Record, error) {
				return a.IncrementOne(ctx, adapter.IncrementInput{Model: "user",
					Where: []adapter.Where{{Field: "id", Value: "user-1"}, {Field: "authority", Value: "old"}},
					Set:   adapter.Record{"authority": "stale"}})
			})
			if res != nil {
				t.Fatalf("result %v", res)
			}
			rows := guardedRows(t, e)
			if len(rows) != 1 || rows[0]["authority"] != "new" || rows[0]["attempts"] != int64(0) {
				t.Fatalf("rows %v", rows)
			}
		})
	})
	t.Run("does not decrement a counter whose guard became false", func(t *testing.T) {
		forGuardedDialects(t, func(t *testing.T, e *env) {
			a := guardedAdapter(t, e)
			res := whileGuardChanges(t, e, func() (adapter.Record, error) {
				return a.IncrementOne(ctx, adapter.IncrementInput{Model: "user",
					Where:     []adapter.Where{{Field: "attempts", Value: 0, Operator: adapter.Gt}},
					Increment: map[string]float64{"attempts": -1}})
			})
			if res != nil {
				t.Fatalf("result %v", res)
			}
			if rows := guardedRows(t, e); rows[0]["attempts"] != int64(0) {
				t.Fatalf("rows %v", rows)
			}
		})
	})
	t.Run("does not consume a row whose guard changed while waiting", func(t *testing.T) {
		forGuardedDialects(t, func(t *testing.T, e *env) {
			a := guardedAdapter(t, e)
			res := whileGuardChanges(t, e, func() (adapter.Record, error) {
				return a.ConsumeOne(ctx, "user", []adapter.Where{{Field: "id", Value: "user-1"}, {Field: "authority", Value: "old"}})
			})
			if res != nil {
				t.Fatalf("result %v", res)
			}
			rows := guardedRows(t, e)
			if len(rows) != 1 || rows[0]["authority"] != "new" || rows[0]["attempts"] != int64(0) {
				t.Fatalf("rows %v", rows)
			}
		})
	})
	t.Run("mutates only one row and preserves ordinary successful guards", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			a := guardedAdapter(t, e)
			insertGuarded(t, e, "user-2", "other@example.com")
			res, err := a.IncrementOne(ctx, adapter.IncrementInput{Model: "user",
				Where:     []adapter.Where{{Field: "authority", Value: "old"}},
				Increment: map[string]float64{"attempts": -1},
				Set:       adapter.Record{"authority": "new"}})
			if err != nil || res == nil || res["authority"] != "new" || res["attempts"] != int64(0) {
				t.Fatalf("%v %v", res, err)
			}
			if n := e.row(t, `SELECT COUNT(*) AS "n" FROM "user" WHERE "authority" = 'new'`)["n"]; n != int64(1) {
				t.Fatalf("%v rows mutated", n)
			}
			consumed, err := a.ConsumeOne(ctx, "user", []adapter.Where{{Field: "authority", Value: "old"}})
			if err != nil || consumed == nil || consumed["authority"] != "old" || consumed["attempts"] != int64(1) {
				t.Fatalf("%v %v", consumed, err)
			}
		})
	})
}
