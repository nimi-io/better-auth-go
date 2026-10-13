package migration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
)

// Port of packages/better-auth/src/db/get-migration.test.ts. Configurations are written in
// the upstream option shape (see config_test.go); node:sqlite in-memory databases become
// fresh SQLite files.

func parseSpec(t *testing.T, js string) optionsSpec {
	t.Helper()
	var s optionsSpec
	if err := json.Unmarshal([]byte(js), &s); err != nil {
		t.Fatalf("spec: %v", err)
	}
	return s
}

// planJSON plans the configuration js against tdb. o.Dialect defaults to tdb's dialect and
// o.IDMode to the spec's advanced.database.generateId.
func planJSON(t *testing.T, tdb testDB, js string, o Options) (*adapter.MigrationPlan, error) {
	t.Helper()
	schema, mode, err := parseSpec(t, js).schema()
	if err != nil {
		t.Fatal(err)
	}
	if o.Dialect == "" {
		o.Dialect = tdb.d
	}
	if o.IDMode == "" {
		o.IDMode = mode
	}
	return Plan(context.Background(), tdb.conn, schema, o)
}

func mustPlan(t *testing.T, tdb testDB, js string, o Options) *adapter.MigrationPlan {
	t.Helper()
	p, err := planJSON(t, tdb, js, o)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return p
}

func run(t *testing.T, p *adapter.MigrationPlan) {
	t.Helper()
	if err := p.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func lowerSQL(p *adapter.MigrationPlan) string { return strings.ToLower(compiled(p)) }

func findChange(changes []adapter.TableChange, table string) *adapter.TableChange {
	for i := range changes {
		if changes[i].Table == table {
			return &changes[i]
		}
	}
	return nil
}

func hasField(c *adapter.TableChange, column string) bool {
	if c == nil {
		return false
	}
	for _, f := range c.Fields {
		if f.Column() == column {
			return true
		}
	}
	return false
}

func expectError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err.Error(), want)
	}
}

func queryString(t *testing.T, tdb testDB, query string) string {
	t.Helper()
	var s string
	if err := tdb.conn.QueryRow(query).Scan(&s); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return s
}

func sqliteDB(t *testing.T) testDB { return openDB(t, dialect.SQLite, "") }

// teamsPlugin is the part of organization({ teams: { enabled: true } }) the legacy database
// exercises (organization, team and teamMember tables).
const teamsPlugin = `{"plugins": [{"id": "organization", "schema": {
	"organization": {"fields": {
		"name": {"type": "string", "required": true, "sortable": true},
		"slug": {"type": "string", "required": true, "unique": true, "sortable": true},
		"logo": {"type": "string", "required": false},
		"createdAt": {"type": "date", "required": true},
		"metadata": {"type": "string", "required": false}}},
	"team": {"fields": {
		"name": {"type": "string", "required": true},
		"memberCount": {"type": "number", "required": true, "defaultValue": 0},
		"organizationId": {"type": "string", "required": true, "references": {"model": "organization", "field": "id"}},
		"createdAt": {"type": "date", "required": true},
		"updatedAt": {"type": "date", "required": false}}},
	"teamMember": {"fields": {
		"teamId": {"type": "string", "required": true, "references": {"model": "team", "field": "id"}},
		"userId": {"type": "string", "required": true, "references": {"model": "user", "field": "id"}},
		"membershipKey": {"type": "string", "required": false, "unique": true},
		"createdAt": {"type": "date", "required": false}}}
}}]}`

func createLegacyOrgDB(t *testing.T) testDB {
	tdb := sqliteDB(t)
	tdb.exec(t,
		`CREATE TABLE "team" ("id" text primary key not null, "name" text not null, "organizationId" text not null, "createdAt" date not null, "updatedAt" date)`,
		`CREATE TABLE "teamMember" ("id" text primary key not null, "teamId" text not null, "userId" text not null, "createdAt" date)`,
		`INSERT INTO "team" ("id", "name", "organizationId", "createdAt") VALUES ('t1', 'Engineering', 'org1', '2020-01-01')`,
		`INSERT INTO "teamMember" ("id", "teamId", "userId", "createdAt") VALUES ('tm1', 't1', 'u1', '2020-01-01')`,
	)
	return tdb
}

func TestAlterTableAddColumnSQLite(t *testing.T) {
	t.Run("adds a required column with a static default and a unique column to a populated table", func(t *testing.T) {
		tdb := createLegacyOrgDB(t)
		p := mustPlan(t, tdb, teamsPlugin, Options{})
		if !hasField(findChange(p.ToBeAdded, "team"), "memberCount") {
			t.Fatal("memberCount not planned")
		}
		if !hasField(findChange(p.ToBeAdded, "teamMember"), "membershipKey") {
			t.Fatal("membershipKey not planned")
		}
		sql := lowerSQL(p)
		if !strings.Contains(sql, `add column "membercount" integer default 0 not null`) {
			t.Fatalf("missing memberCount column:\n%s", sql)
		}
		if !strings.Contains(sql, "create unique index") {
			t.Fatal("missing unique index")
		}
		for _, stmt := range p.Statements {
			s := strings.ToLower(stmt)
			if strings.Contains(s, `add column "membershipkey"`) && strings.Contains(s, "unique") {
				t.Fatalf("inline unique on ALTER: %s", stmt)
			}
			if strings.HasPrefix(s, "create unique index") && strings.Contains(s, "where") {
				t.Fatalf("partial unique index: %s", stmt)
			}
		}
		run(t, p)
		if got := queryString(t, tdb, `SELECT "memberCount" FROM "team" WHERE "id" = 't1'`); got != "0" {
			t.Fatalf("memberCount = %s", got)
		}
		tdb.exec(t, `INSERT INTO "teamMember" ("id", "teamId", "userId", "createdAt", "membershipKey") VALUES ('tm2', 't1', 'u2', '2020-01-01', 'org1:t1:u2')`)
		if _, err := tdb.conn.Exec(`INSERT INTO "teamMember" ("id", "teamId", "userId", "createdAt", "membershipKey") VALUES ('tm3', 't1', 'u3', '2020-01-01', 'org1:t1:u2')`); err == nil {
			t.Fatal("duplicate membershipKey accepted")
		}
	})

	t.Run("adds a required unique column with a static default when the table has one row", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t,
			`CREATE TABLE "user" ("id" text primary key not null, "name" text not null, "email" text not null unique, "emailVerified" integer not null, "image" text, "createdAt" date not null, "updatedAt" date not null)`,
			`INSERT INTO "user" ("id", "name", "email", "emailVerified", "createdAt", "updatedAt") VALUES ('u1', 'Ada', 'ada@example.com', 1, '2020-01-01', '2020-01-01')`,
		)
		w := &warnings{}
		p := mustPlan(t, tdb, `{"user": {"additionalFields": {"referralCode": {"type": "string", "required": true, "unique": true, "defaultValue": "unset"}}}}`, Options{Logger: w})
		if !w.has(`"referralCode"`) {
			t.Fatalf("no referralCode warning: %v", w.msgs)
		}
		sql := lowerSQL(p)
		if !strings.Contains(sql, `add column "referralcode" text default 'unset' not null`) {
			t.Fatalf("missing column:\n%s", sql)
		}
		if !strings.Contains(sql, `create unique index "user_referralcode_uidx"`) {
			t.Fatalf("missing index:\n%s", sql)
		}
		run(t, p)
		if got := queryString(t, tdb, `SELECT "referralCode" FROM "user" WHERE "id" = 'u1'`); got != "unset" {
			t.Fatalf("referralCode = %s", got)
		}
	})
}

const directorySubjectPlugin = `{"plugins": [{"id": "directory", "schema": {"directoryUser": {
	"fields": {"subject": {"type": "string", "index": true}},
	"indexes": [{"fields": ["subject"]}]}}}]}`

const directoryIdentityPlugin = `{"plugins": [{"id": "directory", "schema": {"directoryUser": {
	"modelName": "directory_user",
	"fields": {
		"connectionId": {"type": "string", "fieldName": "connection_id"},
		"externalId": {"type": "string", "fieldName": "external_id"}},
	"indexes": [{"fields": ["connectionId", "externalId"], "name": "directory_identity_uidx", "unique": true}]}}}]}`

func TestCompoundIndexesSQLite(t *testing.T) {
	t.Run("rejects duplicate field-level and table-level indexes before creating a table", func(t *testing.T) {
		_, err := planJSON(t, sqliteDB(t), directorySubjectPlugin, Options{})
		expectError(t, err, `Database index name "directoryUser_subject_idx" is already reserved by field-level index metadata on table "directoryUser".`)
	})

	t.Run("does not classify an index-definition conflict as UnsafeMigrationError", func(t *testing.T) {
		_, err := planJSON(t, sqliteDB(t), directorySubjectPlugin, Options{})
		var schemaErr *SchemaError
		if !errors.As(err, &schemaErr) {
			t.Fatalf("expected *SchemaError, got %T", err)
		}
		var unsafe *UnsafeMigrationError
		if errors.As(err, &unsafe) {
			t.Fatal("classified as UnsafeMigrationError")
		}
	})

	t.Run("enforces a compound unique index with configured table and field names", func(t *testing.T) {
		tdb := sqliteDB(t)
		cfg := `{"plugins": [{"id": "directory", "schema": {"directoryUser": {
			"modelName": "directory_user",
			"fields": {
				"connectionId": {"type": "string", "fieldName": "connection_id"},
				"externalId": {"type": "string", "fieldName": "external_id"}},
			"indexes": [{"fields": ["connectionId", "externalId"], "unique": true}]}}}]}`
		p := mustPlan(t, tdb, cfg, Options{})
		if !strings.Contains(lowerSQL(p), `create unique index "directory_user_connection_id_external_id_uidx" on "directory_user" ("connection_id", "external_id")`) {
			t.Fatalf("missing index:\n%s", compiled(p))
		}
		run(t, p)
		tdb.exec(t, `INSERT INTO "directory_user" ("id", "connection_id", "external_id") VALUES ('du1', 'okta', 'employee-1'), ('du2', 'entra', 'employee-1')`)
		if _, err := tdb.conn.Exec(`INSERT INTO "directory_user" ("id", "connection_id", "external_id") VALUES ('du3', 'okta', 'employee-1')`); err == nil {
			t.Fatal("duplicate accepted")
		}
		next := mustPlan(t, tdb, cfg, Options{})
		if strings.Contains(compiled(next), "directory_user_connection_id_external_id_uidx") {
			t.Fatal("index planned again")
		}
	})

	t.Run("rejects an existing index with the requested name but different semantics", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t,
			`CREATE TABLE "directory_user" ("id" text primary key not null, "connection_id" text not null, "external_id" text not null)`,
			`CREATE INDEX "directory_identity_uidx" ON "directory_user" ("external_id")`)
		_, err := planJSON(t, tdb, directoryIdentityPlugin, Options{})
		expectError(t, err, `Database index "directory_identity_uidx" on table "directory_user" does not match the configured fields and uniqueness.`)
	})

	t.Run("recognizes existing index names case-insensitively", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t,
			`CREATE TABLE "directory_user" ("id" text primary key not null, "connection_id" text not null, "external_id" text not null)`,
			`CREATE UNIQUE INDEX "Directory_Identity_UIDX" ON "directory_user" ("connection_id", "external_id")`)
		p := mustPlan(t, tdb, directoryIdentityPlugin, Options{})
		if strings.Contains(compiled(p), "directory_identity_uidx") {
			t.Fatalf("index planned again:\n%s", compiled(p))
		}
	})

	t.Run("rejects a case-insensitive existing index name on another table", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t,
			`CREATE TABLE "reserved_index_owner" ("id" text primary key not null, "subject" text not null)`,
			`CREATE INDEX "Directory_Identity_UIDX" ON "reserved_index_owner" ("subject")`)
		_, err := planJSON(t, tdb, `{"plugins": [{"id": "directory", "schema": {"directoryUser": {
			"fields": {"subject": {"type": "string"}},
			"indexes": [{"fields": ["subject"], "name": "directory_identity_uidx"}]}}}]}`, Options{})
		expectError(t, err, `Database index name "directory_identity_uidx" is already used by table "reserved_index_owner".`)
	})

	t.Run("does not accept a partial unique index as a full uniqueness guarantee", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t,
			`CREATE TABLE "directory_user" ("id" text primary key not null, "connection_id" text not null, "external_id" text not null)`,
			`CREATE UNIQUE INDEX "directory_identity_uidx" ON "directory_user" ("connection_id", "external_id") WHERE "external_id" IS NOT NULL`)
		_, err := planJSON(t, tdb, directoryIdentityPlugin, Options{})
		expectError(t, err, `Database index "directory_identity_uidx" on table "directory_user" does not match the configured fields and uniqueness.`)
	})
}

type accountDBOptions struct {
	plan       string // "", "nullable" or "notNull"
	planColumn string
	unseeded   bool
}

func createAccountDB(t *testing.T, o accountDBOptions) testDB {
	t.Helper()
	tdb := sqliteDB(t)
	if o.planColumn == "" {
		o.planColumn = "plan"
	}
	planDefinition := ""
	switch o.plan {
	case "nullable":
		planDefinition = `"` + o.planColumn + `" text,`
	case "notNull":
		planDefinition = `"` + o.planColumn + `" text not null,`
	}
	tdb.exec(t,
		`CREATE TABLE "user" ("id" text primary key not null, "name" text not null, "email" text not null unique, "emailVerified" integer not null, "image" text, "createdAt" date not null, "updatedAt" date not null)`,
		`CREATE TABLE "account" ("id" text primary key not null, `+planDefinition+` "accountId" text not null, "providerId" text not null, "userId" text not null references "user" ("id"), "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" date, "refreshTokenExpiresAt" date, "scope" text, "password" text, "createdAt" date not null, "updatedAt" date not null)`,
	)
	if o.unseeded {
		return tdb
	}
	tdb.exec(t, `INSERT INTO "user" ("id", "name", "email", "emailVerified", "createdAt", "updatedAt") VALUES ('u1', 'Ada', 'ada@example.com', 1, '2020-01-01', '2020-01-01')`)
	planTarget, planValue := "", ""
	if o.plan != "" {
		planTarget, planValue = `, "`+o.planColumn+`"`, `, 'free'`
	}
	tdb.exec(t, `INSERT INTO "account" ("id", "accountId", "providerId", "userId", "createdAt", "updatedAt"`+planTarget+`) VALUES ('a1', '10769150350006150715113082367', 'google', 'u1', '2020-01-01', '2020-01-01'`+planValue+`)`)
	return tdb
}

func addNullableTierColumn(t *testing.T, tdb testDB) testDB {
	tdb.exec(t, `ALTER TABLE "user" ADD COLUMN "tier" text`, `UPDATE "user" SET "tier" = 'free'`)
	return tdb
}

const accountPlanField = `{"account": {"additionalFields": {"plan": {"type": "string", "required": true}}}}`

func directoryUserTable(t *testing.T) testDB {
	tdb := sqliteDB(t)
	tdb.exec(t,
		`CREATE TABLE "directoryUser" ("id" text primary key not null, "externalId" text not null)`,
		`INSERT INTO "directoryUser" ("id", "externalId") VALUES ('du1', 'employee-1')`)
	return tdb
}

func TestUnsafeChangesOnPopulatedTables(t *testing.T) {
	t.Run("refuses to add a required column without a default to a populated table", func(t *testing.T) {
		_, err := planJSON(t, directoryUserTable(t), `{"plugins": [{"id": "directory", "schema": {"directoryUser": {"fields": {
			"externalId": {"type": "string"},
			"connectionIssuer": {"type": "string", "required": true}}}}}]}`, Options{})
		var unsafe *UnsafeMigrationError
		if !errors.As(err, &unsafe) {
			t.Fatalf("expected *UnsafeMigrationError, got %v", err)
		}
		for _, want := range []string{`Cannot add required column "connectionIssuer" to populated table "directoryUser"`, "MySQL", "empty string"} {
			expectError(t, err, want)
		}
	})

	t.Run("refuses to add a required additional field to a populated account table", func(t *testing.T) {
		_, err := planJSON(t, createAccountDB(t, accountDBOptions{}), accountPlanField, Options{})
		expectError(t, err, `Cannot add required column "plan" to populated table "account"`)
	})

	t.Run("reports the physical column name of a renamed required field", func(t *testing.T) {
		_, err := planJSON(t, createAccountDB(t, accountDBOptions{}), `{"account": {"additionalFields": {"plan": {"type": "string", "required": true, "fieldName": "account_plan"}}}}`, Options{})
		expectError(t, err, `Cannot add required column "account_plan" to populated table "account"`)
	})

	t.Run("plans a required column without a default when the table is empty", func(t *testing.T) {
		p := mustPlan(t, createAccountDB(t, accountDBOptions{unseeded: true}), accountPlanField, Options{})
		if !hasField(findChange(p.ToBeAdded, "account"), "plan") {
			t.Fatal("plan not added")
		}
		if !strings.Contains(lowerSQL(p), `add column "plan" text not null`) {
			t.Fatalf("missing column:\n%s", compiled(p))
		}
	})

	t.Run("still adds a required column with a static default to a populated table", func(t *testing.T) {
		tdb := directoryUserTable(t)
		p := mustPlan(t, tdb, `{"plugins": [{"id": "directory", "schema": {"directoryUser": {"fields": {
			"externalId": {"type": "string"},
			"connectionIssuer": {"type": "string", "required": true, "defaultValue": "local:directory"}}}}}]}`, Options{})
		if !strings.Contains(lowerSQL(p), `add column "connectionissuer" text default 'local:directory' not null`) {
			t.Fatalf("missing column:\n%s", compiled(p))
		}
		run(t, p)
		if got := queryString(t, tdb, `SELECT "connectionIssuer" FROM "directoryUser"`); got != "local:directory" {
			t.Fatalf("connectionIssuer = %s", got)
		}
	})
}

func TestNullableColumnsForRequiredFields(t *testing.T) {
	t.Run("warns and proceeds when a required field's live column is nullable", func(t *testing.T) {
		tdb := addNullableTierColumn(t, createAccountDB(t, accountDBOptions{}))
		w := &warnings{}
		p := mustPlan(t, tdb, `{"user": {"additionalFields": {"tier": {"type": "string", "required": true}}},
			"plugins": [{"id": "directory", "schema": {"directoryUser": {"fields": {"externalId": {"type": "string", "required": true}}}}}]}`, Options{Logger: w})
		if !w.has(`Column "tier" on table "user"`) {
			t.Fatalf("no drift warning: %v", w.msgs)
		}
		if findChange(p.ToBeCreated, "directoryUser") == nil {
			t.Fatal("directoryUser not created")
		}
		run(t, p)
		if got := queryString(t, tdb, `SELECT "name" FROM sqlite_master WHERE "name" = 'directoryUser'`); got != "directoryUser" {
			t.Fatal("directoryUser missing")
		}
	})

	t.Run("accepts a required field whose live column is not null", func(t *testing.T) {
		p := mustPlan(t, createAccountDB(t, accountDBOptions{plan: "notNull"}), accountPlanField, Options{})
		if findChange(p.ToBeAdded, "account") != nil {
			t.Fatal("account change planned")
		}
		if strings.Contains(lowerSQL(p), `alter table "account"`) {
			t.Fatal("alter table planned")
		}
	})

	t.Run("warns with the real field and table name for a nullable account column", func(t *testing.T) {
		w := &warnings{}
		mustPlan(t, createAccountDB(t, accountDBOptions{plan: "nullable"}), accountPlanField, Options{Logger: w})
		if !w.has(`Column "plan" on table "account"`) {
			t.Fatalf("no warning: %v", w.msgs)
		}
	})

	t.Run("warns about both nullable drift and a type mismatch on the same column", func(t *testing.T) {
		tdb := sqliteDB(t)
		tdb.exec(t, `CREATE TABLE "directoryUser" ("id" text primary key not null, "seatCount" text)`, `INSERT INTO "directoryUser" ("id") VALUES ('du1')`)
		w := &warnings{}
		mustPlan(t, tdb, `{"plugins": [{"id": "directory", "schema": {"directoryUser": {"fields": {"seatCount": {"type": "number", "required": true}}}}}]}`, Options{Logger: w})
		if !w.has(`Column "seatCount" on table "directoryUser"`) {
			t.Fatalf("no drift warning: %v", w.msgs)
		}
		if !w.has("Field seatCount in table directoryUser has a different type in the database") {
			t.Fatalf("no type warning: %v", w.msgs)
		}
	})
}

func TestInspectingAnUnappliableMigration(t *testing.T) {
	t.Run("reports the unsafe column change and still compiles the statements", func(t *testing.T) {
		p := mustPlan(t, createAccountDB(t, accountDBOptions{}), accountPlanField, Options{ReportUnsafe: true})
		if len(p.UnsafeChanges) != 1 || !strings.Contains(p.UnsafeChanges[0], `Cannot add required column "plan" to populated table "account"`) {
			t.Fatalf("unsafe changes = %v", p.UnsafeChanges)
		}
		if !strings.Contains(lowerSQL(p), `alter table "account" add column "plan" text not null`) {
			t.Fatalf("missing statement:\n%s", compiled(p))
		}
	})

	t.Run("keeps the empty-string detail out of a non-text column's message", func(t *testing.T) {
		p := mustPlan(t, directoryUserTable(t), `{"plugins": [{"id": "directory", "schema": {"directoryUser": {"fields": {
			"externalId": {"type": "string"},
			"seatCount": {"type": "number", "required": true}}}}}]}`, Options{ReportUnsafe: true})
		if len(p.UnsafeChanges) == 0 {
			t.Fatal("no unsafe change")
		}
		msg := p.UnsafeChanges[0]
		if !strings.Contains(msg, `Cannot add required column "seatCount" to populated table "directoryUser"`) || !strings.Contains(msg, "implicit default for the column type") || strings.Contains(msg, "empty string") {
			t.Fatalf("message = %s", msg)
		}
	})
}

func TestSchemaProblemsTheMigrationCannotFix(t *testing.T) {
	t.Run("reports a required column Better Auth never writes", func(t *testing.T) {
		p := mustPlan(t, createAccountDB(t, accountDBOptions{plan: "notNull"}), `{}`, Options{})
		if len(p.SchemaProblems) != 1 || !strings.Contains(p.SchemaProblems[0], `Column "plan" on table "account" is required but Better Auth never writes it`) {
			t.Fatalf("schema problems = %v", p.SchemaProblems)
		}
		if len(p.ToBeAdded) != 0 {
			t.Fatalf("toBeAdded = %v", p.ToBeAdded)
		}
	})

	t.Run("reports nothing for a nullable or a configured extra column", func(t *testing.T) {
		if p := mustPlan(t, createAccountDB(t, accountDBOptions{plan: "nullable"}), `{}`, Options{}); len(p.SchemaProblems) != 0 {
			t.Fatalf("nullable: %v", p.SchemaProblems)
		}
		if p := mustPlan(t, createAccountDB(t, accountDBOptions{plan: "notNull"}), accountPlanField, Options{}); len(p.SchemaProblems) != 0 {
			t.Fatalf("configured: %v", p.SchemaProblems)
		}
	})
}

// The upstream "configured PostgreSQL schema" tests use a fake dialect; these run against
// a real, empty PostgreSQL database.
func TestConfiguredPostgresSchema(t *testing.T) {
	t.Run("qualifies every planned statement with the configured schema", func(t *testing.T) {
		p := mustPlan(t, openDB(t, dialect.Postgres, ""), `{}`, Options{SchemaName: "auth"})
		sql := compiled(p)
		for _, want := range []string{
			`create schema if not exists "auth"`,
			`create table "auth"."user"`,
			`create table "auth"."session"`,
			`references "auth"."user" ("id")`,
			`create index "session_userId_idx" on "auth"."session"`,
		} {
			if !strings.Contains(sql, want) {
				t.Fatalf("missing %q in\n%s", want, sql)
			}
		}
		if strings.Contains(sql, `create table "user"`) {
			t.Fatal("unqualified table")
		}
	})

	t.Run("creates the schema before the tables that live in it", func(t *testing.T) {
		tdb := openDB(t, dialect.Postgres, "")
		p := mustPlan(t, tdb, `{}`, Options{SchemaName: "auth"})
		schemaAt, userAt := -1, -1
		for i, s := range p.Statements {
			if strings.HasPrefix(s, `create schema if not exists "auth"`) {
				schemaAt = i
			}
			if strings.HasPrefix(s, `create table "auth"."user"`) {
				userAt = i
			}
		}
		if schemaAt < 0 || schemaAt >= userAt {
			t.Fatalf("schema at %d, user at %d", schemaAt, userAt)
		}
		run(t, p)
	})

	t.Run("leaves the plan unqualified when no schema is configured", func(t *testing.T) {
		sql := compiled(mustPlan(t, openDB(t, dialect.Postgres, ""), `{}`, Options{}))
		if strings.Contains(sql, "create schema") || !strings.Contains(sql, `create table "user"`) || !strings.Contains(sql, `references "user" ("id")`) {
			t.Fatalf("unexpected plan:\n%s", sql)
		}
	})

	t.Run("ignores tables from other schemas", func(t *testing.T) {
		tdb := openDB(t, dialect.Postgres, "")
		tdb.exec(t, `CREATE TABLE public."user" ("id" text primary key)`)
		p := mustPlan(t, tdb, `{}`, Options{SchemaName: "auth"})
		if findChange(p.ToBeCreated, "user") == nil {
			t.Fatal("user not created")
		}
	})

	t.Run("rejects a schema name on other dialects", func(t *testing.T) {
		_, err := planJSON(t, sqliteDB(t), `{}`, Options{SchemaName: "auth"})
		expectError(t, err, "`database.schemaName` is only supported on PostgreSQL")
	})
}
