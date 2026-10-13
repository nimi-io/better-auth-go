package sqladapter

// Port of packages/kysely-adapter/src/dialect.test.ts (createKyselyAdapter): transaction
// defaults, dialect detection and the PostgreSQL schema namespace.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

// unknownDriver is a database/sql driver whose package the dialect detection does not know.
type unknownDriver struct{}

func (unknownDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not implemented") }

func init() { sql.Register("ba-unknown", unknownDriver{}) }

func isTransactor(t *testing.T, a adapter.Adapter) bool {
	t.Helper()
	_, ok := customOf(a).(adapter.Transactor)
	return ok
}

func TestCreateKyselyAdapterTransactionDetection(t *testing.T) {
	schema := dbschema.GetAuthTables(dbschema.Options{})
	t.Run("reports native transaction support for a raw database pool", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			r, err := resolve(e.db, Config{})
			if err != nil || !r.transaction || r.dialect != e.d {
				t.Fatalf("%+v %v", r, err)
			}
			a, err := New(e.db, Config{})(adapter.Options{Schema: schema})
			if err != nil || !isTransactor(t, a) {
				t.Fatalf("transactions should be enabled: %v", err)
			}
		})
	})
	t.Run("does not report native transaction support for a Cloudflare D1 database", func(t *testing.T) {
		t.Skip("Cloudflare D1 is a JavaScript binding; there is no D1 database/sql driver")
	})
	t.Run("leaves transaction support unspecified for a driver of unknown capability", func(t *testing.T) {
		db, err := sql.Open("ba-unknown", "")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		r, err := resolve(db, Config{})
		if err != nil {
			t.Fatal(err)
		}
		// databaseType null → kyselyAdapter falls back to "sqlite", transaction undefined.
		if r.dialect != SQLite || r.transaction {
			t.Fatalf("%+v", r)
		}
		a, err := New(db, Config{})(adapter.Options{Schema: schema})
		if err != nil || isTransactor(t, a) {
			t.Fatalf("unknown drivers get no transactions: %v", err)
		}
	})
	t.Run("still honors an explicit transaction: false override", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			off := false
			a, err := New(e.db, Config{Dialect: e.d, Transaction: &off})(adapter.Options{Schema: schema})
			if err != nil || isTransactor(t, a) {
				t.Fatalf("transaction: false must be honored: %v", err)
			}
		})
	})
	t.Run("an explicit dialect wins over detection", func(t *testing.T) {
		db := openDB(t, SQLite)
		r, err := resolve(db, Config{Dialect: MySQL})
		if err != nil || r.dialect != MySQL || !r.transaction {
			t.Fatalf("%+v %v", r, err)
		}
	})
	t.Run("rejects SQL Server", func(t *testing.T) {
		db := openDB(t, SQLite)
		if _, err := New(db, Config{Dialect: "mssql"})(adapter.Options{Schema: schema}); err == nil {
			t.Fatal("mssql must be rejected")
		}
	})
}

func TestD1IndexIntrospection(t *testing.T) {
	t.Skip("D1 index/table introspection belongs to the D1 dialect (JavaScript only) and to migrations")
}

func TestCreateKyselyAdapterSchemaNamespace(t *testing.T) {
	t.Run("qualifies every statement with the configured PostgreSQL schema", func(t *testing.T) {
		e := &env{d: Postgres, db: openDB(t, Postgres)}
		a, log := e.newAdapter(t, setup{cfg: Config{SchemaName: "auth"}, opts: adapter.Options{Joins: true}})
		log.reset()
		if _, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: "x"}}, Select: []string{"id"}}); err != nil {
			t.Fatal(err)
		}
		if stmts := log.statements(); len(stmts) != 1 || !strings.HasPrefix(stmts[0], `SELECT "id" FROM "auth"."user"`) {
			t.Fatalf("statement %q", stmts)
		}
		exerciseSchema(t, e, a, log, `"auth".`)
		// Nothing leaked into public.
		if n := e.row(t, `SELECT COUNT(*) AS "n" FROM information_schema.tables WHERE table_schema = 'public'`)["n"]; n != int64(0) {
			t.Fatalf("%v tables in public", n)
		}
		if n := e.row(t, `SELECT COUNT(*) AS "n" FROM "auth"."user"`)["n"]; n != int64(1) {
			t.Fatalf("%v users in auth", n)
		}
	})

	t.Run("preserves a dotted schema name as one PostgreSQL identifier", func(t *testing.T) {
		e := &env{d: Postgres, db: openDB(t, Postgres)}
		a, log := e.newAdapter(t, setup{cfg: Config{SchemaName: "tenant.auth"}})
		log.reset()
		if _, err := a.Count(ctx, "user", nil); err != nil {
			t.Fatal(err)
		}
		if stmts := log.statements(); len(stmts) != 1 || !strings.Contains(stmts[0], `FROM "tenant.auth"."user"`) {
			t.Fatalf("statement %q", stmts)
		}
		exerciseSchema(t, e, a, log, `"tenant.auth".`)
	})

	t.Run("leaves statements unqualified when no schema is configured", func(t *testing.T) {
		forEachDialect(t, func(t *testing.T, e *env) {
			a, log := e.newAdapter(t, setup{})
			log.reset()
			if _, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: "x"}}, Select: []string{"id"}}); err != nil {
				t.Fatal(err)
			}
			want := "SELECT " + e.d.Quote("id") + " FROM " + e.d.Quote("user") + " WHERE"
			if stmts := log.statements(); len(stmts) != 1 || !strings.HasPrefix(stmts[0], want) {
				t.Fatalf("statement %q", stmts)
			}
		})
	})

	t.Run("refuses a schema on a dialect that does not support it", func(t *testing.T) {
		for _, d := range []Dialect{MySQL, SQLite} {
			db := openDB(t, d)
			_, err := New(db, Config{SchemaName: "auth"})(adapter.Options{Schema: dbschema.GetAuthTables(dbschema.Options{})})
			want := "`database.schemaName` is only supported on PostgreSQL, but the configured database type is \"" + string(d) + "\"."
			if err == nil || err.Error() != want {
				t.Fatalf("%s: %v", d, err)
			}
		}
		db, _ := sql.Open("ba-unknown", "")
		defer db.Close()
		_, err := New(db, Config{SchemaName: "auth"})(adapter.Options{Schema: dbschema.GetAuthTables(dbschema.Options{})})
		if err == nil || !strings.HasSuffix(err.Error(), `the configured database type is "unknown".`) {
			t.Fatalf("unknown: %v", err)
		}
	})

	t.Run("refuses an empty schema name", func(t *testing.T) {
		t.Skip("Config.SchemaName is a Go string: the empty string means \"not configured\"")
	})
}

// exerciseSchema runs every operation against a schema-qualified database.
func exerciseSchema(t *testing.T, e *env, a adapter.Adapter, log *captureLogger, prefix string) {
	t.Helper()
	u := mustCreate(t, a, "user", user("Schemed"))
	mustCreate(t, a, "account", adapter.Record{"accountId": "a", "providerId": "p", "userId": u["id"], "updatedAt": time.Now()})
	got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u["id"]}}, Join: map[string]adapter.Join{"account": {}}})
	if err != nil || got == nil || len(got["account"].([]adapter.Record)) != 1 {
		t.Fatalf("join: %v %v", got, err)
	}
	if _, err := a.Update(ctx, "user", []adapter.Where{{Field: "id", Value: u["id"]}}, adapter.Record{"name": "Renamed"}); err != nil {
		t.Fatal(err)
	}
	if n, err := a.UpdateMany(ctx, "user", nil, adapter.Record{"image": "i"}); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	v := mustCreate(t, a, "verification", adapter.Record{"identifier": "i", "value": "v", "expiresAt": time.Now()})
	if r, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "id", Value: v["id"]}}); err != nil || r == nil {
		t.Fatal(r, err)
	}
	c := mustCreate(t, a, "counters", adapter.Record{"name": "n", "remaining": 1, "used": 0})
	if r, err := a.IncrementOne(ctx, adapter.IncrementInput{Model: "counters", Where: []adapter.Where{{Field: "id", Value: c["id"]}}, Increment: map[string]float64{"used": 2}}); err != nil || r["used"] != int64(2) {
		t.Fatal(r, err)
	}
	if err := a.Transaction(ctx, func(c2 context.Context, tx adapter.Adapter) error {
		_, err := tx.DeleteMany(c2, "counters", nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range log.statements() {
		if s == "BEGIN" || s == "COMMIT" || s == "ROLLBACK" {
			continue
		}
		if !strings.Contains(s, prefix) {
			t.Fatalf("statement without the schema: %s", s)
		}
	}
}
