package sqladapter

// Port of packages/kysely-adapter/src/kysely-adapter.test.ts.

import (
	"regexp"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

func TestKyselyAdapter(t *testing.T) {
	t.Run("should create kysely adapter", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			f := New(e.db, Config{})
			if f == nil {
				t.Fatal("nil factory")
			}
			a, err := f(adapter.Options{Schema: dbschema.GetAuthTables(dbschema.Options{})})
			if err != nil || a == nil || a.ID() != "kysely" {
				t.Fatalf("%v %v", a, err)
			}
		})
	})

	t.Run("keeps model identity when a custom name matches another schema key", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			id, boolean, date := "TEXT", "INTEGER", "TEXT"
			switch e.d {
			case Postgres:
				boolean, date = "boolean", "timestamptz"
			case MySQL:
				id, boolean, date = "varchar(36)", "boolean", "timestamp(3)"
			}
			e.exec(t, `CREATE TABLE "account" (
				"id" `+id+` PRIMARY KEY,
				"name" TEXT NOT NULL,
				"email" TEXT NOT NULL,
				"emailVerified" `+boolean+` NOT NULL,
				"image" TEXT,
				"createdAt" `+date+` NOT NULL,
				"updatedAt" `+date+` NOT NULL
			)`)
			e.exec(t, `CREATE TABLE "session" (
				"id" `+id+` PRIMARY KEY,
				"token" TEXT NOT NULL,
				"userId" TEXT NOT NULL,
				"expiresAt" `+date+` NOT NULL,
				"ipAddress" TEXT,
				"userAgent" TEXT,
				"createdAt" `+date+` NOT NULL,
				"updatedAt" `+date+` NOT NULL
			)`)
			schema := dbschema.GetAuthTables(dbschema.Options{
				User:    dbschema.ModelOptions{ModelName: "account"},
				Account: dbschema.ModelOptions{ModelName: "identity"},
			})
			a, _ := e.newAdapter(t, setup{opts: adapter.Options{Schema: schema, Joins: true}, noTables: true})
			now := time.Now()
			mustCreateForce(t, a, "user", adapter.Record{
				"id": "user-id", "name": "Ada", "email": "ada@example.com", "emailVerified": false,
				"createdAt": now, "updatedAt": now,
			})
			mustCreateForce(t, a, "session", adapter.Record{
				"id": "session-id", "token": "session-token", "userId": "user-id",
				"expiresAt": now.Add(time.Minute), "createdAt": now, "updatedAt": now,
			})
			session, err := a.FindOne(ctx, adapter.FindOneInput{
				Model: "session",
				Where: []adapter.Where{{Field: "id", Value: "session-id"}},
				Join:  map[string]adapter.Join{"user": {}},
			})
			if err != nil || session == nil {
				t.Fatalf("%v %v", session, err)
			}
			u, _ := session["user"].(adapter.Record)
			if u == nil || u["email"] != "ada@example.com" {
				t.Fatalf("joined user %#v", session["user"])
			}
		})
	})

	t.Run("consumeOne deletes only the selected row for non-unique predicates", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			a, log := e.newAdapter(t, setup{})
			for _, v := range []string{"first", "second"} {
				mustCreate(t, a, "verification", adapter.Record{"identifier": "same-identifier", "value": v, "expiresAt": time.Now()})
			}
			log.reset()
			result, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "identifier", Value: "same-identifier"}})
			if err != nil || result == nil || result["identifier"] != "same-identifier" {
				t.Fatalf("%v %v", result, err)
			}
			stmts := log.statements()
			if e.d != MySQL {
				// select "verification"."id" ... limit 1 as the target of `id in (...)`, and the
				// where clause applied again to the delete itself.
				re := regexp.MustCompile(`^DELETE FROM "verification" WHERE "verification"\."id" IN \(SELECT "verification"\."id" FROM "verification" WHERE .+ LIMIT 1\) AND \(.+\) RETURNING \*$`)
				if len(stmts) != 1 || !re.MatchString(stmts[0]) {
					t.Fatalf("statement %q", stmts)
				}
			}
			left := e.rows(t, `SELECT * FROM "verification"`)
			if len(left) != 1 || left[0]["id"] == result["id"] {
				t.Fatalf("remaining rows %v", left)
			}
		})
	})

	t.Run("consumeOne uses a top(1) subquery and OUTPUT on mssql", func(t *testing.T) {
		t.Skip("SQL Server is not supported by the Go SQL adapter (no driver in this module)")
	})
}
