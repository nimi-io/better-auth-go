package sqladapter

// Port of packages/kysely-adapter/src/with-returning-mysql.test.ts. Upstream runs the MySQL
// `withReturning` branch against SQLite; here every case runs against real MySQL, and the
// same contract is checked on PostgreSQL and SQLite (whose RETURNING path must agree).

import (
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

func tokensAdapter(t *testing.T, e *env) adapter.Adapter {
	t.Helper()
	idType := "TEXT"
	if e.d == MySQL {
		idType = "varchar(36)"
	}
	e.exec(t, `CREATE TABLE "tokens" ("id" `+idType+` PRIMARY KEY, "revoked" TEXT, "clientId" TEXT)`)
	schema := dbschema.GetAuthTables(dbschema.Options{Plugins: [][]dbschema.PluginTable{{testPlugin[1]}}})
	a, _ := e.newAdapter(t, setup{opts: adapter.Options{Schema: schema}, noTables: true})
	return a
}

func insertToken(t *testing.T, e *env, id string, revoked any, clientID string) {
	t.Helper()
	e.exec(t, `INSERT INTO "tokens" ("id", "revoked", "clientId") VALUES (?, ?, ?)`, id, revoked, clientID)
}

func TestWithReturningUpdate(t *testing.T) {
	// Predicate-drop CAS regression: an unmatched guarded UPDATE returns null.
	t.Run("returns null when a multi-predicate UPDATE matches no row", func(t *testing.T) {
		forEachDialectAndMySQLOnSQLite(t, func(t *testing.T, e *env) {
			a := tokensAdapter(t, e)
			insertToken(t, e, "a", nil, "c1")
			guard := []adapter.Where{{Field: "id", Value: "a"}, {Field: "revoked", Operator: adapter.Eq, Value: nil}}
			winner, err := a.Update(ctx, "tokens", guard, adapter.Record{"revoked": "2024-01-01T00:00:00.000Z"})
			if err != nil || winner == nil || winner["id"] != "a" || winner["revoked"] != "2024-01-01T00:00:00.000Z" {
				t.Fatalf("winner %v %v", winner, err)
			}
			loser, err := a.Update(ctx, "tokens", guard, adapter.Record{"revoked": "2099-01-01T00:00:00.000Z"})
			if err != nil || loser != nil {
				t.Fatalf("loser %v %v", loser, err)
			}
			after := e.row(t, `SELECT * FROM "tokens" WHERE "id" = ?`, "a")
			if after["revoked"] != "2024-01-01T00:00:00.000Z" {
				t.Fatalf("after %v", after)
			}
		})
	})

	t.Run("returns no row when the where matches nothing at all", func(t *testing.T) {
		forEachDialectAndMySQLOnSQLite(t, func(t *testing.T, e *env) {
			a := tokensAdapter(t, e)
			insertToken(t, e, "a", nil, "c1")
			result, err := a.Update(ctx, "tokens", []adapter.Where{{Field: "id", Value: "does-not-exist"}}, adapter.Record{"clientId": "c2"})
			if err != nil || result != nil {
				t.Fatalf("%v %v", result, err)
			}
			if row := e.row(t, `SELECT * FROM "tokens" WHERE "id" = ?`, "a"); row["clientId"] != "c1" {
				t.Fatalf("row %v", row)
			}
		})
	})

	t.Run("returns the updated row when a single-predicate UPDATE matches", func(t *testing.T) {
		forEachDialectAndMySQLOnSQLite(t, func(t *testing.T, e *env) {
			a := tokensAdapter(t, e)
			insertToken(t, e, "a", nil, "c1")
			result, err := a.Update(ctx, "tokens", []adapter.Where{{Field: "id", Value: "a"}}, adapter.Record{"clientId": "c2"})
			if err != nil || result == nil || result["id"] != "a" || result["clientId"] != "c2" {
				t.Fatalf("%v %v", result, err)
			}
		})
	})

	t.Run("re-SELECTs by id when id is not the first where predicate", func(t *testing.T) {
		forEachDialectAndMySQLOnSQLite(t, func(t *testing.T, e *env) {
			a := tokensAdapter(t, e)
			for _, id := range []string{"a", "b", "c"} {
				insertToken(t, e, id, nil, "c1")
			}
			result, err := a.Update(ctx, "tokens", []adapter.Where{
				{Field: "revoked", Operator: adapter.Eq, Value: nil},
				{Field: "id", Value: "b"},
			}, adapter.Record{"clientId": "c2"})
			if err != nil || result == nil || result["id"] != "b" || result["clientId"] != "c2" {
				t.Fatalf("%v %v", result, err)
			}
			for _, r := range e.rows(t, `SELECT * FROM "tokens" WHERE "id" IN (?, ?)`, "a", "c") {
				if r["clientId"] != "c1" {
					t.Fatalf("other row changed: %v", r)
				}
			}
		})
	})

	t.Run("does not key the re-SELECT off a non-eq `id` predicate", func(t *testing.T) {
		forEachDialectAndMySQLOnSQLite(t, func(t *testing.T, e *env) {
			a := tokensAdapter(t, e)
			insertToken(t, e, "a", nil, "c1")
			insertToken(t, e, "b", nil, "c2")
			result, err := a.Update(ctx, "tokens", []adapter.Where{
				{Field: "clientId", Operator: adapter.Eq, Value: "c2"},
				{Field: "id", Operator: adapter.Ne, Value: "a"},
			}, adapter.Record{"revoked": "2024-01-01T00:00:00.000Z"})
			if err != nil || result == nil || result["id"] != "b" || result["revoked"] != "2024-01-01T00:00:00.000Z" {
				t.Fatalf("%v %v", result, err)
			}
			if rowA := e.row(t, `SELECT * FROM "tokens" WHERE "id" = ?`, "a"); rowA["revoked"] != nil {
				t.Fatalf("row a %v", rowA)
			}
		})
	})

	// `update` is the single-row variant: an empty where must not mutate every row.
	t.Run("returns null and does not mutate any row when where is empty", func(t *testing.T) {
		forEachDialectAndMySQLOnSQLite(t, func(t *testing.T, e *env) {
			a := tokensAdapter(t, e)
			insertToken(t, e, "a", nil, "c1")
			insertToken(t, e, "b", nil, "c1")
			result, err := a.Update(ctx, "tokens", []adapter.Where{}, adapter.Record{"clientId": "c2"})
			if err != nil || result != nil {
				t.Fatalf("%v %v", result, err)
			}
			// The CustomAdapter also refuses an empty where on its own.
			result, err = customOf(a).Update(ctx, adapter.Query{Model: "tokens", ModelKey: "tokens"}, adapter.Record{"clientId": "c2"})
			if err != nil || result != nil {
				t.Fatalf("custom: %v %v", result, err)
			}
			rows := e.rows(t, `SELECT * FROM "tokens" ORDER BY "id"`)
			if len(rows) != 2 {
				t.Fatalf("rows %v", rows)
			}
			for _, r := range rows {
				if r["clientId"] != "c1" {
					t.Fatalf("row mutated: %v", r)
				}
			}
		})
	})
}
