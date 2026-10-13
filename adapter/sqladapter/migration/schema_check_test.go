package migration

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
	"github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
)

// Ports of packages/kysely-adapter/src/sqlite-introspector.test.ts,
// packages/kysely-adapter/src/schema-check.test.ts, the migration parts of
// packages/better-auth/src/db/account-schema-compat.test.ts and the index-name cases of
// packages/core/src/db/database-index.test.ts.

func introspect(t *testing.T, tdb testDB) []TableMetadata {
	t.Helper()
	tables, err := IntrospectTables(context.Background(), tdb.conn, tdb.d)
	if err != nil {
		t.Fatal(err)
	}
	return tables
}

func TestSQLiteIntrospector(t *testing.T) {
	t.Run("reports tables as non-views", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t, "CREATE TABLE accounts (id INTEGER PRIMARY KEY, name TEXT)",
			"CREATE TABLE sessions (id INTEGER PRIMARY KEY, token TEXT)",
			"CREATE VIEW active_accounts AS SELECT * FROM accounts")
		tables := introspect(t, tdb)
		if len(tables) == 0 {
			t.Fatal("no tables")
		}
		for _, table := range tables {
			if table.IsView || table.Name == "active_accounts" {
				t.Fatalf("view reported: %+v", table)
			}
		}
	})

	t.Run("BunSqliteDialect reports tables as non-views", func(t *testing.T) {
		t.Skip("TS-only: Bun's SQLite dialect; Go has one SQLite introspector")
	})

	t.Run("hides Kysely's internal migration tables during introspection", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t, "CREATE TABLE users (id INTEGER PRIMARY KEY)",
			"CREATE TABLE "+defaultMigrationTable+" (name TEXT)",
			"CREATE TABLE "+defaultMigrationLockTable+" (id TEXT)")
		var tableNames []string
		for _, table := range introspect(t, tdb) {
			tableNames = append(tableNames, table.Name)
		}
		if !contains(tableNames, "users") || contains(tableNames, defaultMigrationTable) || contains(tableNames, defaultMigrationLockTable) {
			t.Fatalf("tables = %v", tableNames)
		}
	})

	t.Run("mirrors Kysely's migration-table constants", func(t *testing.T) {
		if defaultMigrationTable != "kysely_migration" || defaultMigrationLockTable != "kysely_migration_lock" {
			t.Fatal("constants drifted from Kysely")
		}
	})
}

func TestSQLiteGeneratedPrimaryKeys(t *testing.T) {
	cases := []struct {
		name, definition, generated string
	}{
		{"an explicit AUTOINCREMENT declaration after whitespace", "CREATE TABLE entries (\n\t\t\t\tseq INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n\t\t\t\tid TEXT NOT NULL UNIQUE\n\t\t\t)", "seq"},
		{"an AUTOINCREMENT declaration separated by a comment", "CREATE TABLE entries (seq INTEGER PRIMARY KEY/**/AUTOINCREMENT, id TEXT)", "seq"},
		{"an INTEGER PRIMARY KEY without AUTOINCREMENT", "CREATE TABLE entries (seq INTEGER PRIMARY KEY, id TEXT)", "seq"},
		{"a quoted primary key identifier", `CREATE TABLE entries ("sequence number" INTEGER PRIMARY KEY, id TEXT)`, "sequence number"},
		{"AUTOINCREMENT inside a default string", "CREATE TABLE entries (ref INTEGER PRIMARY KEY,note TEXT DEFAULT 'use AUTOINCREMENT')", "ref"},
		{"AUTOINCREMENT inside a default string on a WITHOUT ROWID table", "CREATE TABLE entries (ref INTEGER PRIMARY KEY, note TEXT DEFAULT 'use AUTOINCREMENT') WITHOUT ROWID", ""},
		{"an INTEGER PRIMARY KEY DESC column", "CREATE TABLE entries (seq INTEGER PRIMARY KEY DESC, id TEXT)", ""},
		{"a table-level PRIMARY KEY with DESC ordering", "CREATE TABLE entries (seq INTEGER, id TEXT, PRIMARY KEY (seq DESC))", "seq"},
		{"an INTEGER PRIMARY KEY on a WITHOUT ROWID table", "CREATE TABLE entries (seq INTEGER PRIMARY KEY, id TEXT) WITHOUT ROWID", ""},
		{"an INT PRIMARY KEY column", "CREATE TABLE entries (seq INT PRIMARY KEY, id TEXT)", ""},
	}
	for _, c := range cases {
		t.Run("recognizes "+c.name, func(t *testing.T) {
			tdb := sqliteDB(t)
			tdb.exec(t, c.definition)
			var generated []string
			for _, table := range introspect(t, tdb) {
				if table.Name != "entries" {
					continue
				}
				for _, col := range table.Columns {
					if col.IsAutoIncrementing {
						generated = append(generated, col.Name)
					}
				}
			}
			var want []string
			if c.generated != "" {
				want = []string{c.generated}
			}
			if !reflect.DeepEqual(generated, want) {
				t.Fatalf("generated = %v, want %v", generated, want)
			}
		})
	}

	t.Run("BunSqliteDialect recognizes an INTEGER PRIMARY KEY", func(t *testing.T) {
		t.Skip("TS-only: Bun's SQLite dialect")
	})

	t.Run("quotes table names in the statement-form PRAGMA", func(t *testing.T) {
		// Upstream exercises the PRAGMA fallback used when dialect introspection is
		// unavailable; the Go introspector always issues PRAGMA index_list(<quoted name>).
		tdb := sqliteDB(t)
		tdb.exec(t, `CREATE TABLE "generated""name" (id INTEGER PRIMARY KEY)`, "CREATE TABLE descending (id INTEGER PRIMARY KEY DESC)")
		got := map[string]bool{}
		for _, table := range introspect(t, tdb) {
			got[table.Name] = table.Columns[0].IsAutoIncrementing
		}
		if want := map[string]bool{`generated"name`: true, "descending": false}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func expected(tables ...ExpectedTable) []ExpectedTable { return tables }

func TestExpectedSchema(t *testing.T) {
	twoFactor := &db.Schema{Tables: []*db.Table{{Key: "twoFactor", ModelName: "twoFactor", Fields: []db.Field{
		{Name: "userId", Type: db.TypeString, Required: db.True},
		{Name: "backupCodes", Type: db.TypeString},
	}}}}

	t.Run("keeps the schema when no plugin renames identifiers", func(t *testing.T) {
		got, err := ExpectedSchema(twoFactor, "")
		if err != nil {
			t.Fatal(err)
		}
		want := expected(ExpectedTable{Name: "twoFactor", Columns: []string{"userId", "backupCodes"}})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("uses the identifiers the plugins send", func(t *testing.T) {
		t.Skip("TS-only: Kysely's CamelCasePlugin rewrites identifiers; Go configures column names through fields")
	})

	t.Run("carries the schema a plugin qualifies tables with", func(t *testing.T) {
		got, _ := ExpectedSchema(twoFactor, "auth")
		if got[0].Schema != "auth" {
			t.Fatalf("schema = %q", got[0].Schema)
		}
		got, _ = ExpectedSchema(twoFactor, "")
		if got[0].Schema != "" {
			t.Fatalf("schema = %q", got[0].Schema)
		}
	})

	t.Run("splits a schema-qualified model name into schema and table", func(t *testing.T) {
		got, _ := ExpectedSchema(&db.Schema{Tables: []*db.Table{{Key: "users", ModelName: "internal.users", Fields: []db.Field{{Name: "email", Type: db.TypeString, Required: db.True}}}}}, "")
		want := expected(ExpectedTable{Name: "users", Schema: "internal", Columns: []string{"email"}})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("compares the implicit id using its physical identifier", func(t *testing.T) {
		exp := expected(ExpectedTable{Name: "TWO_FACTOR", IDColumn: "ID", Columns: []string{"USER_ID", "BACKUP_CODES"}})
		var columns []ColumnMetadata
		for _, n := range []string{"ID", "USER_ID", "BACKUP_CODES"} {
			columns = append(columns, ColumnMetadata{Name: n})
		}
		if got := DiffSchema(exp, []TableMetadata{{Name: "TWO_FACTOR", Columns: columns}}); len(got) != 0 {
			t.Fatalf("findings = %v", got)
		}
		got := DiffSchema(exp, []TableMetadata{{Name: "TWO_FACTOR", Columns: columns[1:]}})
		if want := []SchemaFinding{{Kind: FindingMissingColumn, Table: "TWO_FACTOR", Column: "ID"}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("findings = %v", got)
		}
	})
}

func TestFindSchemaProblems(t *testing.T) {
	ctx := context.Background()

	t.Run("validates SQLite tables", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t, "CREATE TABLE widget (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL)")
		got, err := FindSchemaProblems(ctx, tdb.conn, dialect.SQLite, expected(ExpectedTable{Name: "widget", Columns: []string{"name"}}))
		if err != nil || len(got) != 0 {
			t.Fatalf("findings = %v, %v", got, err)
		}
		got, err = FindSchemaProblems(ctx, tdb.conn, dialect.SQLite, expected(ExpectedTable{Name: "missingWidget", Columns: []string{"name"}}))
		if want := []SchemaFinding{{Kind: FindingMissingTable, Table: "missingWidget"}}; err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("findings = %v, %v", got, err)
		}
	})

	t.Run("distinguishes generated and required SQLite primary keys", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t,
			"CREATE TABLE generated (seq INTEGER PRIMARY KEY NOT NULL, id TEXT NOT NULL UNIQUE)",
			"CREATE TABLE descending (seq INTEGER PRIMARY KEY DESC NOT NULL, id TEXT NOT NULL UNIQUE)",
			"CREATE TABLE without_rowid (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE) WITHOUT ROWID")
		got, err := FindSchemaProblems(ctx, tdb.conn, dialect.SQLite, expected(
			ExpectedTable{Name: "generated"}, ExpectedTable{Name: "descending"}, ExpectedTable{Name: "without_rowid"}))
		want := []SchemaFinding{
			{Kind: FindingUnexpectedRequiredColumn, Table: "descending", Column: "seq"},
			{Kind: FindingUnexpectedRequiredColumn, Table: "without_rowid", Column: "seq"},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("findings = %v, %v", got, err)
		}
	})

	t.Run("keeps the migration fallback when search_path is empty", func(t *testing.T) {
		tdb := openDB(t, dialect.Postgres, "")
		tx, err := tdb.conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`SELECT pg_catalog.set_config('search_path', '', true)`); err != nil {
			t.Fatal(err)
		}
		if got, err := postgresCurrentSchema(ctx, tx); err != nil || got != "public" {
			t.Fatalf("schema = %q, %v", got, err)
		}
	})

	t.Run("reads PostgreSQL metadata without changing the schema", func(t *testing.T) {
		tdb := openDB(t, dialect.Postgres, "")
		table := "ba_missing_" + strings.ToLower(crypto.RandomStringFrom(16, "a-z", "0-9"))
		got, err := FindSchemaProblems(ctx, tdb.conn, dialect.Postgres, expected(ExpectedTable{Name: table}))
		if want := []SchemaFinding{{Kind: FindingMissingTable, Table: table}}; err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("findings = %v, %v", got, err)
		}
	})

	t.Run("resolves role schemas and each table in search-path order", func(t *testing.T) {
		tdb := openDB(t, dialect.Postgres, "")
		role := "ba_readiness_" + strings.ToLower(crypto.RandomStringFrom(16, "a-z", "0-9"))
		fallback := role + "_fallback"
		conn, err := tdb.conn.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		exec := func(q string) {
			t.Helper()
			if _, err := conn.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		exec(fmt.Sprintf(`CREATE ROLE "%s"`, role))
		t.Cleanup(func() {
			_, _ = conn.ExecContext(ctx, "RESET ROLE")
			_, _ = conn.ExecContext(ctx, fmt.Sprintf(`DROP SCHEMA IF EXISTS "%s" CASCADE`, role))
			_, _ = conn.ExecContext(ctx, fmt.Sprintf(`DROP SCHEMA IF EXISTS "%s" CASCADE`, fallback))
			_, _ = conn.ExecContext(ctx, fmt.Sprintf(`DROP ROLE "%s"`, role))
			conn.Close()
		})
		exec(fmt.Sprintf(`CREATE SCHEMA "%s" AUTHORIZATION "%s"`, role, role))
		exec(fmt.Sprintf(`CREATE SCHEMA "%s" AUTHORIZATION "%s"`, fallback, role))
		exec(fmt.Sprintf(`SET ROLE "%s"`, role))
		exec(fmt.Sprintf(`SET search_path TO "$user", "%s"`, fallback))
		exec(`CREATE TABLE account (id text PRIMARY KEY, "providerId" text NOT NULL)`)
		exec(fmt.Sprintf(`CREATE TABLE "%s".account (id text PRIMARY KEY, issuer text NOT NULL)`, fallback))
		exec(fmt.Sprintf(`CREATE TABLE "%s".session (id text PRIMARY KEY, token text NOT NULL)`, fallback))
		got, err := FindSchemaProblems(ctx, conn, dialect.Postgres, expected(
			ExpectedTable{Name: "account", Columns: []string{"providerId"}},
			ExpectedTable{Name: "session", Columns: []string{"token"}}))
		if err != nil || len(got) != 0 {
			t.Fatalf("findings = %v, %v", got, err)
		}
	})
}

// Hand-written DDL of a v1 database (account-schema-compat.test.ts).
const (
	compatUserTable         = `create table "user" ("id" text not null primary key, "name" text not null, "email" text not null unique, "emailVerified" integer not null, "image" text, "createdAt" date not null, "updatedAt" date not null)`
	compatSessionTable      = `create table "session" ("id" text not null primary key, "expiresAt" date not null, "token" text not null unique, "createdAt" date not null, "updatedAt" date not null, "ipAddress" text, "userAgent" text, "userId" text not null references "user" ("id") on delete cascade)`
	compatVerificationTable = `create table "verification" ("id" text not null primary key, "identifier" text not null, "value" text not null, "expiresAt" date not null, "createdAt" date not null, "updatedAt" date not null)`
	compatAccountTable      = `create table "account" ("id" text not null primary key, "accountId" text not null, "providerId" text not null, "userId" text not null references "user" ("id") on delete cascade, "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" date, "refreshTokenExpiresAt" date, "scope" text, "password" text, "createdAt" date not null, "updatedAt" date not null)`
	compatAccountWithIssuer = `create table "account" ("id" text not null primary key, "issuer" text not null, "accountId" text not null, "providerId" text not null, "userId" text not null references "user" ("id") on delete cascade, "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" date, "refreshTokenExpiresAt" date, "scope" text, "password" text, "createdAt" date not null, "updatedAt" date not null)`
)

func TestAccountSchemaCompat(t *testing.T) {
	create := func(t *testing.T, account string, extra ...string) testDB {
		tdb := sqliteDB(t)
		tdb.exec(t, append([]string{compatUserTable, compatSessionTable, account, compatVerificationTable}, extra...)...)
		return tdb
	}

	t.Run("asks for no migration without the issuer column", func(t *testing.T) {
		w := &warnings{}
		p := mustPlan(t, create(t, compatAccountTable), `{}`, Options{Logger: w})
		if len(p.ToBeCreated) != 0 || len(p.ToBeAdded) != 0 || len(p.SchemaProblems) != 0 {
			t.Fatalf("plan: created %v added %v problems %v", p.ToBeCreated, p.ToBeAdded, p.SchemaProblems)
		}
		if len(w.msgs) != 0 {
			t.Fatalf("warnings = %v", w.msgs)
		}
		// The sign-up and account linking half of the upstream test exercises the runtime.
	})

	t.Run("reports the required issuer column the migration cannot relax", func(t *testing.T) {
		tdb := create(t, compatAccountWithIssuer, `create unique index "account_issuer_accountId_uidx" on "account" ("issuer", "accountId")`)
		p := mustPlan(t, tdb, `{}`, Options{})
		if len(p.ToBeAdded) != 0 || len(p.SchemaProblems) != 1 || !strings.Contains(p.SchemaProblems[0], `Column "issuer" on table "account"`) {
			t.Fatalf("added %v problems %v", p.ToBeAdded, p.SchemaProblems)
		}
		if !strings.Contains(p.SchemaProblems[0], "1-7-upgrade-guide") {
			t.Fatalf("missing upgrade hint: %s", p.SchemaProblems[0])
		}
	})

	for _, name := range []string{
		"keeps accounts written by 1.7 readable through their provider key",
		"surfaces the raw constraint error when the check is disabled",
		"schema check with the adapter passed as a function",
		"schema check timing",
		"schema check with Kysely's CamelCasePlugin",
	} {
		t.Run(name, func(t *testing.T) {
			t.Skip("runtime schema check / request handling (betterauth and the SQL adapter), not migration planning")
		})
	}
}

func TestDatabaseIndexNames(t *testing.T) {
	t.Run("generates readable names within the portable database limit", func(t *testing.T) {
		if got, _ := databaseIndexName("directory_user", []string{"connection_id", "external_id"}, nil, true); got != "directory_user_connection_id_external_id_uidx" {
			t.Fatalf("got %s", got)
		}
		fields := []string{"provisioning_connection_identifier", "external_directory_subject_identifier"}
		first, _ := databaseIndexName("enterprise_directory_user_identity", fields, nil, true)
		second, _ := databaseIndexName("enterprise_directory_user_identity", fields, nil, true)
		if len(first) > 63 || first != second || !strings.HasSuffix(first, "_uidx") || first[len(first)-14] != '_' {
			t.Fatalf("got %s", first)
		}
		// The hashed names Better Auth 1.7.7 generates (testdata/fixtures.json, long-index-names).
		if first != "enterprise_directory_user_identity_provisioning_c_e1bb1624_uidx" {
			t.Fatalf("got %s", first)
		}
		if got := fieldIndexName("enterprise_directory_user_identity", "étiquette_ünïcödé_subject_identifier", false); got != "enterprise_directory_user_identity_étiquette_ün_6c9ffb65_idx" {
			t.Fatalf("got %s", got)
		}
	})

	t.Run("rejects malformed runtime definitions", func(t *testing.T) {
		for name, want := range map[string]string{
			" ":                     "Database index names must contain at least one visible character.",
			strings.Repeat("a", 64): "Database index names must be at most 63 UTF-8 bytes.",
			`directory_"lookup"`:    "Database index names must start with a letter or underscore and contain only letters, numbers, and underscores.",
		} {
			n := name
			_, err := databaseIndexName("directory_user", []string{"connectionId"}, &n, false)
			expectError(t, err, want)
		}
		src := func(indexes ...db.Index) *indexSource {
			var fields []db.Field
			for i := 0; i < 17; i++ {
				fields = append(fields, db.Field{Name: fmt.Sprintf("field%d", i), Type: db.TypeString, Required: db.True})
			}
			return &indexSource{tableName: "portable_lookup", fields: fields, indexes: indexes}
		}
		var sixteen, seventeen []string
		for i := 0; i < 17; i++ {
			if i < 16 {
				sixteen = append(sixteen, fmt.Sprintf("field%d", i))
			}
			seventeen = append(seventeen, fmt.Sprintf("field%d", i))
		}
		if got, err := resolveDatabaseTableIndexes(src(db.Index{Fields: sixteen})); err != nil || len(got) != 1 {
			t.Fatalf("16 fields: %v %v", got, err)
		}
		_, err := resolveDatabaseTableIndexes(src(db.Index{Fields: seventeen}))
		expectError(t, err, `Index on table "portable_lookup" can include at most 16 fields`)
		_, err = resolveDatabaseTableIndexes(src(db.Index{}))
		expectError(t, err, `Index on table "portable_lookup" must include at least one field.`)
	})

	t.Run("resolves logical fields, explicit names and enum fields", func(t *testing.T) {
		got, err := resolveDatabaseTableIndexes(&indexSource{tableName: "directory_user", fields: []db.Field{
			{Name: "connectionId", Type: db.TypeString, FieldName: "connection_id", Required: db.True},
			{Name: "externalId", Type: db.TypeString, FieldName: "external_id", Required: db.True},
			{Name: "status", Type: db.TypeEnum, Enum: []string{"active", "suspended"}, FieldName: "provisioning_status", Required: db.True},
		}, indexes: []db.Index{
			{Fields: []string{"connectionId", "externalId"}, Name: "directory_identity_uidx", Unique: true},
			{Fields: []string{"connectionId", "status"}},
		}})
		want := []resolvedIndex{
			{Columns: []string{"connection_id", "external_id"}, Name: "directory_identity_uidx", Unique: true},
			{Columns: []string{"connection_id", "provisioning_status"}, Name: "directory_user_connection_id_provisioning_status_idx"},
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
}
