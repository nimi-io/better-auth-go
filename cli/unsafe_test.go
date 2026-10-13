package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/migration"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

const unsafeMsg = `Cannot add required column "plan" to populated table "account": the schema declares no default value.`

// reportingSQL plans in report mode only through PlanMigrationsReportUnsafe.
type reportingSQL struct{ fakeSQL }

func (f *reportingSQL) PlanMigrations(context.Context, *db.Schema) (*adapter.MigrationPlan, error) {
	return nil, &migration.UnsafeMigrationError{Message: unsafeMsg}
}

func (f *reportingSQL) PlanMigrationsReportUnsafe(_ context.Context, s *db.Schema) (*adapter.MigrationPlan, error) {
	return f.plan(s)
}

func unsafePlan(*db.Schema) (*adapter.MigrationPlan, error) {
	return &adapter.MigrationPlan{
		ToBeAdded:     []adapter.TableChange{{Table: "account", Fields: []db.Field{{Name: "plan"}}}},
		UnsafeChanges: []string{unsafeMsg},
		Statements:    []string{`alter table "account" add column "plan" text not null`},
		Exec:          func(context.Context) error { panic("must not run") },
	}, nil
}

func TestMigrateRefusesUnsafeError(t *testing.T) {
	fake := &fakeSQL{plan: func(*db.Schema) (*adapter.MigrationPlan, error) {
		return nil, &migration.UnsafeMigrationError{Message: unsafeMsg}
	}}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "--yes")
	want := "The migration was refused, and nothing ran.\n" + unsafeMsg + "\nRun better-auth generate to read the statements without executing them.\n"
	if r.code != 1 || r.stderr != want {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	// a report-mode plan is refused the same way
	fake = &fakeSQL{plan: unsafePlan}
	r = run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "--yes")
	if r.code != 1 || r.stderr != want {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestMigrateSchemaProblems(t *testing.T) {
	fake := &fakeSQL{plan: func(s *db.Schema) (*adapter.MigrationPlan, error) {
		p, _ := pendingPlan(nil)(s)
		p.SchemaProblems = []string{`Column "issuer" on table "account" is required but Better Auth never writes it.`}
		p.Exec = func(context.Context) error { panic("must not run") }
		return p, nil
	}}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "--yes")
	want := "The database has 1 column Better Auth cannot write to. Nothing ran.\n-> Column \"issuer\" on table \"account\" is required but Better Auth never writes it.\n"
	if r.code != 1 || r.stderr != want || r.stdout != "" {
		t.Fatalf("%d %q %q", r.code, r.stderr, r.stdout)
	}
}

func TestMigrateIndexes(t *testing.T) {
	executed := 0
	fake := &fakeSQL{plan: func(*db.Schema) (*adapter.MigrationPlan, error) {
		return &adapter.MigrationPlan{
			ToBeAddedIndexes: []adapter.IndexChange{
				{Table: "directory_user", Columns: []string{"connection_id", "external_id"}, Unique: true},
				{Table: "directory_user", Columns: []string{"connection_id", "provisioning_status"}},
			},
			Statements: []string{`create index "x" on "directory_user" ("connection_id")`},
			Exec:       func(context.Context) error { executed++; return nil },
		}, nil
	}}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "-y")
	want := "🔑 The migration will affect the following:\n" +
		"-> connection_id, external_id fields in a unique index on directory_user table.\n" +
		"-> connection_id, provisioning_status fields indexed on directory_user table.\n" +
		"🚀 migration was completed successfully!\n"
	if r.code != 0 || r.stdout != want || executed != 1 {
		t.Fatalf("%d executed %d\n%q", r.code, executed, r.stdout)
	}
}

func TestGenerateUnsafeBanner(t *testing.T) {
	dir := t.TempDir()
	fake := &reportingSQL{fakeSQL{plan: unsafePlan}}
	opts := Options{Auth: newAuth(t, betterauth.Config{Database: adapter.NewFactory(adapter.Config{AdapterID: "kysely"},
		func(adapter.Options, adapter.Helpers) (adapter.CustomAdapter, error) { return fake, nil })})}
	r := run(t, opts, "", "generate", "--cwd", dir, "--output", "migration.sql", "--yes")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	contains(t, r.stderr, "⚠ 1 change in this schema corrupts a populated database.\n-> "+unsafeMsg+"\n")
	contains(t, r.stderr, "The generated script carries the same warning. Fix the reported columns before you run it.")
	b, err := os.ReadFile(filepath.Join(dir, "migration.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := string(b)
	if !strings.HasPrefix(sql, "-- "+strings.Repeat("-", 77)+"\n-- DO NOT RUN THIS SCRIPT AS IT IS.\n") {
		t.Fatalf("banner missing:\n%s", sql)
	}
	contains(t, sql, "-- "+unsafeMsg+"\n")
	if !strings.HasSuffix(sql, `alter table "account" add column "plan" text not null;`) {
		t.Fatalf("statements missing:\n%s", sql)
	}
}

func TestGenerateUnsafeWithoutReportMode(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeSQL{plan: func(*db.Schema) (*adapter.MigrationPlan, error) {
		return nil, &migration.UnsafeMigrationError{Message: unsafeMsg}
	}}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "generate", "--cwd", dir, "--yes")
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stderr, "⚠ 1 change in this schema corrupts a populated database.")
	contains(t, r.stderr, unsafeMsg)
}

func TestGenerateSchemaProblems(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeSQL{plan: func(s *db.Schema) (*adapter.MigrationPlan, error) {
		p, _ := pendingPlan(nil)(s)
		p.SchemaProblems = []string{"problem one", "problem two"}
		return p, nil
	}}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "generate", "--cwd", dir, "--yes")
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	if r.stderr != "⚠ 2 columns reject every insert Better Auth makes. No migration fixes this.\n-> problem one\n-> problem two\n" {
		t.Fatalf("%q", r.stderr)
	}
}
