package sqladapter

// Port of packages/kysely-adapter/src/increment-one.test.ts, run against every dialect.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

// countersAdapter registers `counters` through a plugin schema and creates the table with
// the upstream DDL.
func countersAdapter(t *testing.T, e *env) (adapter.Adapter, *captureLogger) {
	t.Helper()
	idType := "TEXT"
	if e.d == MySQL {
		idType = "varchar(36)"
	}
	e.exec(t, `CREATE TABLE "counters" ("id" `+idType+` PRIMARY KEY, "name" TEXT, "remaining" INTEGER, "used" INTEGER, "status" TEXT)`)
	schema := dbschema.GetAuthTables(dbschema.Options{Plugins: [][]dbschema.PluginTable{{testPlugin[0]}}})
	return e.newAdapter(t, setup{opts: adapter.Options{Schema: schema}, noTables: true})
}

func insertCounter(t *testing.T, e *env, id, name string, remaining, used int, status string) {
	t.Helper()
	e.exec(t, `INSERT INTO "counters" ("id", "name", "remaining", "used", "status") VALUES (?, ?, ?, ?, ?)`, id, name, remaining, used, status)
}

var selfIncrement = regexp.MustCompile(`(?i)["` + "`" + `]remaining["` + "`" + `]\s*=\s*["` + "`" + `]remaining["` + "`" + `]\s*\+`)

func TestIncrementOneNative(t *testing.T) {
	t.Run("applies deltas atomically and returns the updated row", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			a, log := countersAdapter(t, e)
			insertCounter(t, e, "a", "alpha", 3, 0, "open")
			log.reset()
			result, err := a.IncrementOne(ctx, adapter.IncrementInput{
				Model:     "counters",
				Where:     []adapter.Where{{Field: "name", Value: "alpha"}},
				Increment: map[string]float64{"remaining": -1, "used": 1},
			})
			if err != nil || result == nil {
				t.Fatalf("%v %v", result, err)
			}
			if result["remaining"] != int64(2) || result["used"] != int64(1) {
				t.Fatalf("result %v", result)
			}
			stmts := log.statements()
			var updates, selects []string
			for _, s := range stmts {
				switch {
				case strings.HasPrefix(s, "UPDATE"):
					updates = append(updates, s)
				case strings.HasPrefix(s, "SELECT"):
					selects = append(selects, s)
				}
			}
			if len(updates) != 1 || !selfIncrement.MatchString(updates[0]) {
				t.Fatalf("expected one self-referential UPDATE: %q", stmts)
			}
			if e.d == MySQL {
				// No RETURNING: lock the target with SELECT ... FOR UPDATE, update it by id, then
				// read it back, all in one transaction.
				if len(selects) != 2 || !strings.HasSuffix(selects[0], "FOR UPDATE") {
					t.Fatalf("mysql statements: %q", stmts)
				}
			} else {
				// The native path issues a single UPDATE ... RETURNING, not the fallback's
				// SELECT-then-UPDATE pair.
				if !regexp.MustCompile(`(?i)returning`).MatchString(updates[0]) || len(selects) != 0 {
					t.Fatalf("statements: %q", stmts)
				}
			}
			row := e.row(t, `SELECT * FROM "counters" WHERE "name" = ?`, "alpha")
			if row["remaining"] != int64(2) || row["used"] != int64(1) {
				t.Fatalf("stored row %v", row)
			}
		})
	})

	t.Run("applies absolute `set` assignments alongside increments", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			a, _ := countersAdapter(t, e)
			insertCounter(t, e, "b", "beta", 5, 2, "open")
			result, err := a.IncrementOne(ctx, adapter.IncrementInput{
				Model:     "counters",
				Where:     []adapter.Where{{Field: "name", Value: "beta"}},
				Increment: map[string]float64{"remaining": -1},
				Set:       adapter.Record{"status": "closed"},
			})
			if err != nil || result == nil || result["remaining"] != int64(4) || result["status"] != "closed" {
				t.Fatalf("%v %v", result, err)
			}
		})
	})

	t.Run("mutates exactly one row when the guard matches multiple", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			a, _ := countersAdapter(t, e)
			for _, id := range []string{"d1", "d2", "d3"} {
				insertCounter(t, e, id, "shared", 5, 0, "open")
			}
			result, err := a.IncrementOne(ctx, adapter.IncrementInput{
				Model: "counters",
				Where: []adapter.Where{
					{Field: "name", Value: "shared"},
					{Field: "remaining", Value: 0, Operator: adapter.Gt},
				},
				Increment: map[string]float64{"remaining": -1, "used": 1},
			})
			if err != nil || result == nil || result["remaining"] != int64(4) || result["used"] != int64(1) {
				t.Fatalf("%v %v", result, err)
			}
			rows := e.rows(t, `SELECT * FROM "counters" WHERE "name" = ? ORDER BY "id"`, "shared")
			var mutated, untouched []adapter.Record
			for _, r := range rows {
				switch {
				case r["remaining"] == int64(4) && r["used"] == int64(1):
					mutated = append(mutated, r)
				case r["remaining"] == int64(5) && r["used"] == int64(0):
					untouched = append(untouched, r)
				}
			}
			if len(mutated) != 1 || len(untouched) != 2 {
				t.Fatalf("rows %v", rows)
			}
			// The returned row is the one that was actually mutated.
			if mutated[0]["id"] != result["id"] {
				t.Fatalf("returned %v, mutated %v", result["id"], mutated[0]["id"])
			}
		})
	})

	t.Run("returns null when the guard matches no row and leaves data untouched", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			a, _ := countersAdapter(t, e)
			insertCounter(t, e, "c", "gamma", 0, 4, "open")
			result, err := a.IncrementOne(ctx, adapter.IncrementInput{
				Model: "counters",
				Where: []adapter.Where{
					{Field: "name", Value: "gamma"},
					{Field: "remaining", Value: 0, Operator: adapter.Gt},
				},
				Increment: map[string]float64{"remaining": -1},
			})
			if err != nil || result != nil {
				t.Fatalf("%v %v", result, err)
			}
			row := e.row(t, `SELECT * FROM "counters" WHERE "name" = ?`, "gamma")
			if row["remaining"] != int64(0) || row["used"] != int64(4) {
				t.Fatalf("stored row %v", row)
			}
		})
	})
}
