package sqladapter

// Database compatibility with the TypeScript Kysely adapter: the stored representation of
// every field type, in both directions (rows written by Go as TypeScript would write them,
// rows written the TypeScript way read back by Go).

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

var encodedAt = time.Date(2024, 1, 2, 3, 4, 5, 678_000_000, time.UTC)

func TestStoredEncodingMatchesTypeScript(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		k := mustCreate(t, a, "kitchen", adapter.Record{
			"str": "s<&>é", "num": 42, "big": int64(1) << 40, "flag": true, "at": encodedAt,
			"meta": map[string]any{"a": 1, "b": []any{1, "x"}}, "tags": []string{"a", "b"},
			"nums": []any{1, 2.5}, "kind": "a",
		})
		if k["flag"] != true || !k["at"].(time.Time).Equal(encodedAt) || k["big"] != int64(1)<<40 {
			t.Fatalf("returned %#v", k)
		}
		id := k["id"]
		switch e.d {
		case SQLite:
			// better-sqlite3 + Kysely: booleans 1/0, dates toISOString(), JSON.stringify text.
			raw := e.row(t, `SELECT typeof("flag") AS "tf", "flag", typeof("at") AS "ta", CAST("at" AS TEXT) AS "at",
				typeof("num") AS "tn", "num", "big", "str", "meta", "tags", "nums", "kind" FROM "kitchen" WHERE "id" = ?`, id)
			want := adapter.Record{"tf": "integer", "flag": int64(1), "ta": "text", "at": "2024-01-02T03:04:05.678Z",
				"tn": "integer", "num": int64(42), "big": int64(1) << 40, "str": "s<&>é",
				"meta": `{"a":1,"b":[1,"x"]}`, "tags": `["a","b"]`, "nums": `[1,2.5]`, "kind": "a"}
			if !reflect.DeepEqual(raw, want) {
				t.Fatalf("stored\n got %#v\nwant %#v", raw, want)
			}
		case MySQL:
			// mysql2 (timezone "Z") + Kysely: tinyint 1/0, timestamp(3) UTC wall clock, JSON.
			raw := e.row(t, "SELECT `flag`, CAST(`at` AS CHAR) AS `at`, `num`, `big`, `str`, JSON_TYPE(`meta`) AS `mt`, "+
				"JSON_EXTRACT(`meta`, '$.b[1]') AS `mb`, JSON_TYPE(`tags`) AS `tt`, CAST(`tags` AS CHAR) AS `tags`, CAST(`nums` AS CHAR) AS `nums`, `kind` FROM `kitchen` WHERE `id` = ?", id)
			want := adapter.Record{"flag": int64(1), "at": "2024-01-02 03:04:05.678", "num": int64(42), "big": int64(1) << 40,
				"str": "s<&>é", "mt": "OBJECT", "mb": `"x"`, "tt": "ARRAY", "tags": `["a", "b"]`, "nums": `[1, 2.5]`, "kind": "a"}
			if !reflect.DeepEqual(raw, want) {
				t.Fatalf("stored\n got %#v\nwant %#v", raw, want)
			}
		case Postgres:
			// node-postgres + Kysely: boolean, timestamptz, jsonb (arrays as JSON, not PG arrays).
			raw := e.row(t, `SELECT "flag", "at", "num", "big", "str", "meta"::text AS "meta", jsonb_typeof("tags") AS "tt",
				"tags"::text AS "tags", "nums"::text AS "nums", "kind" FROM "kitchen" WHERE "id" = ?`, id)
			at, _ := raw["at"].(time.Time)
			if !at.Equal(encodedAt) {
				t.Fatalf("at %v", raw["at"])
			}
			delete(raw, "at")
			want := adapter.Record{"flag": true, "num": int64(42), "big": int64(1) << 40, "str": "s<&>é",
				"meta": `{"a": 1, "b": [1, "x"]}`, "tt": "array", "tags": `["a", "b"]`, "nums": `[1, 2.5]`, "kind": "a"}
			if !reflect.DeepEqual(raw, want) {
				t.Fatalf("stored\n got %#v\nwant %#v", raw, want)
			}
		}
		// ids are 32-character alphanumeric strings stored as text
		if s, _ := id.(string); len(s) != 32 || strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
			t.Fatalf("id %v", id)
		}
		// booleans in where clauses use the stored encoding
		if n, err := a.Count(ctx, "kitchen", []adapter.Where{{Field: "flag", Value: true}}); err != nil || n != 1 {
			t.Fatalf("count flag: %d %v", n, err)
		}
		if n, err := a.Count(ctx, "kitchen", []adapter.Where{{Field: "at", Value: encodedAt}}); err != nil || n != 1 {
			t.Fatalf("count date: %d %v", n, err)
		}
	})
}

func TestReadsRowsWrittenByTypeScript(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		cols := `INSERT INTO "kitchen" ("id", "str", "num", "big", "flag", "at", "meta", "tags", "nums", "kind") VALUES `
		switch e.d {
		case SQLite:
			e.exec(t, cols+`(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "ts-row", "q", 7, 5, 1, "2024-01-02T03:04:05.678Z", `{"z":1,"y":[true]}`, `["x"]`, `[3]`, "b")
		case MySQL:
			e.exec(t, cols+`(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "ts-row", "q", 7, 5, 1, "2024-01-02 03:04:05.678", `{"z":1,"y":[true]}`, `["x"]`, `[3]`, "b")
		case Postgres:
			// node-postgres sends a Date with the local offset
			e.exec(t, cols+`(?, ?, ?, ?, ?, ?::timestamptz, ?::jsonb, ?::jsonb, ?::jsonb, ?)`, "ts-row", "q", 7, 5, true, "2024-01-02T04:04:05.678+01:00", `{"z":1,"y":[true]}`, `["x"]`, `[3]`, "b")
		}
		got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "kitchen", Where: []adapter.Where{{Field: "id", Value: "ts-row"}}})
		if err != nil || got == nil {
			t.Fatalf("%v %v", got, err)
		}
		at, _ := got["at"].(time.Time)
		if !at.Equal(encodedAt) || at.Location() != time.UTC {
			t.Fatalf("at %#v", got["at"])
		}
		want := adapter.Record{"id": "ts-row", "str": "q", "num": int64(7), "big": int64(5), "flag": true, "at": at,
			"meta": map[string]any{"z": float64(1), "y": []any{true}}, "tags": []any{"x"}, "nums": []any{float64(3)}, "kind": "b"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("decoded\n got %#v\nwant %#v", got, want)
		}
		// false / null round trip
		e.exec(t, `UPDATE "kitchen" SET "flag" = ?, "meta" = NULL, "tags" = NULL WHERE "id" = ?`, map[bool]any{true: false, false: 0}[e.d == Postgres], "ts-row")
		got, _ = a.FindOne(ctx, adapter.FindOneInput{Model: "kitchen", Where: []adapter.Where{{Field: "id", Value: "ts-row"}}})
		if got["flag"] != false || got["meta"] != nil || got["tags"] != nil {
			t.Fatalf("false/null: %#v", got)
		}
	})
}

// generateId: false — the database assigns ids; MySQL has no RETURNING, so inserted rows are
// found by unique columns, then by matching every inserted value.
func TestDatabaseGeneratedIDs(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		def := map[Dialect]string{
			Postgres: "(gen_random_uuid())::text",
			MySQL:    "(uuid())",
			SQLite:   "(lower(hex(randomblob(16))))",
		}[e.d]
		a, log := e.newAdapter(t, setup{opts: adapter.Options{IDMode: adapter.IDNone}, ddl: ddlOptions{idDefault: def}})
		u := mustCreate(t, a, "user", user("NoID"))
		if s, _ := u["id"].(string); len(s) < 32 || u["email"] != "noid@example.com" {
			t.Fatalf("user %v", u)
		}
		v := mustCreate(t, a, "verification", adapter.Record{"identifier": "i", "value": "v", "expiresAt": encodedAt})
		if v["identifier"] != "i" || v["id"] == nil {
			t.Fatalf("verification %v", v)
		}
		dup, err := a.Create(ctx, adapter.CreateInput{Model: "verification", Data: adapter.Record{"identifier": "i", "value": "v", "expiresAt": encodedAt, "createdAt": v["createdAt"], "updatedAt": v["updatedAt"]}})
		if err != nil {
			t.Fatal(err)
		}
		warns := strings.Join(log.warnings(), "\n")
		if e.d == MySQL {
			// two identical rows: the inserted one cannot be identified safely
			if dup != nil {
				t.Fatalf("ambiguous insert should return nil, got %v", dup)
			}
			if !strings.Contains(warns, "MySQL does not support INSERT...RETURNING") || !strings.Contains(warns, `Unable to safely identify the inserted "verification" row on MySQL`) {
				t.Fatalf("warnings: %s", warns)
			}
			// warned once per adapter factory
			if strings.Count(warns, "MySQL does not support INSERT...RETURNING") != 1 {
				t.Fatalf("warnings: %s", warns)
			}
		} else {
			if dup == nil || dup["id"] == v["id"] {
				t.Fatalf("RETURNING identifies the row: %v", dup)
			}
			if warns != "" {
				t.Fatalf("unexpected warnings: %s", warns)
			}
		}
	})
}

// Model names with a schema reference ("internal.users") are qualified the way Kysely parses
// them (schema-reference-test-suite.ts).
func TestSchemaReferenceModelNames(t *testing.T) {
	for _, joins := range []bool{false, true} {
		t.Run(map[bool]string{false: "schema-reference", true: "schema-reference-join"}[joins], func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, e *env) {
				ns := "internal"
				switch e.d {
				case Postgres:
					e.exec(t, `CREATE SCHEMA "internal"`)
				case MySQL:
					ns, _ = e.row(t, "SELECT DATABASE() AS `db`")["db"].(string)
				case SQLite:
					ns = "main"
				}
				a, log := e.newAdapter(t, setup{opts: adapter.Options{Joins: joins}, schema: testSchemaOptions(ns)})
				u := mustCreate(t, a, "user", user("Ref"))
				mustCreate(t, a, "account", adapter.Record{"accountId": "a", "providerId": "p", "userId": u["id"], "updatedAt": time.Now()})
				got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: "ref@example.com"}}, Join: map[string]adapter.Join{"account": {}}})
				if err != nil || got == nil || len(got["account"].([]adapter.Record)) != 1 {
					t.Fatalf("%v %v", got, err)
				}
				if _, err := a.Update(ctx, "user", []adapter.Where{{Field: "id", Value: u["id"]}}, adapter.Record{"name": "R2"}); err != nil {
					t.Fatal(err)
				}
				if r, err := a.ConsumeOne(ctx, "account", []adapter.Where{{Field: "userId", Value: u["id"]}}); err != nil || r == nil {
					t.Fatal(r, err)
				}
				if n, err := a.Count(ctx, "user", nil); err != nil || n != 1 {
					t.Fatal(n, err)
				}
				qualified := e.d.Quote(ns) + "." + e.d.Quote("users")
				found := false
				for _, s := range log.statements() {
					if strings.Contains(s, qualified) {
						found = true
					}
				}
				if !found {
					t.Fatalf("no statement references %s: %q", qualified, log.statements())
				}
			})
		})
	}
}

func testSchemaOptions(ns string) dbschema.Options {
	return dbschema.Options{
		User:    dbschema.ModelOptions{ModelName: ns + ".users"},
		Session: dbschema.ModelOptions{ModelName: ns + ".sessions"},
		Account: dbschema.ModelOptions{ModelName: ns + ".accounts"},
	}
}
