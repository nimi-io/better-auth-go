package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

const wantSQL = `create table "user" ("id" text not null primary key, "name" text not null, "email" text not null);

alter table "session" add column "ip_address" text;`

func TestISOTimestamp(t *testing.T) {
	got := isoTimestamp(time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.FixedZone("x", 3600)))
	if got != "2026-01-02T02-04-05.006Z" {
		t.Fatal(got)
	}
	if got := defaultSchemaFileName("prisma", time.Now()); got != "schema.prisma" {
		t.Fatal(got)
	}
	if got := defaultSchemaFileName("drizzle", time.Now()); got != "auth-schema.ts" {
		t.Fatal(got)
	}
}

func TestGenerateDefaultPath(t *testing.T) {
	dir := t.TempDir()
	executed := 0
	fake := &fakeSQL{plan: pendingPlan(&executed)}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "generate", "--cwd", dir, "--yes")
	if r.code != 0 {
		t.Fatalf("exit %d: %s %s", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "🚀 Schema was generated successfully!\n" {
		t.Fatalf("stdout %q", r.stdout)
	}
	if executed != 0 {
		t.Fatal("generate must not run the migration")
	}
	b, err := os.ReadFile(filepath.Join(dir, "better-auth_migrations", "2026-01-02T03-04-05.006Z.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != wantSQL {
		t.Fatalf("sql:\n%s", b)
	}
}

func TestGenerateOutputDirectoryAndFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "schema-output"), 0o755); err != nil {
		t.Fatal(err)
	}
	fake := &fakeSQL{plan: pendingPlan(nil)}
	opts := migrateAuth(t, fake, betterauth.Config{})
	r := run(t, opts, "", "generate", "-c", dir, "--output", "schema-output", "-y")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "schema-output"))
	if len(entries) != 1 || entries[0].Name() != "2026-01-02T03-04-05.006Z.sql" {
		t.Fatalf("entries %v", entries)
	}

	r = run(t, opts, "", "generate", "--cwd", dir, "--output", "nested/migration.sql", "--yes")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nested", "migration.sql"))
	if err != nil || string(b) != wantSQL {
		t.Fatalf("%v %q", err, b)
	}

	// --adapter kysely selects the SQL generator explicitly
	abs := filepath.Join(dir, "abs.sql")
	r = run(t, opts, "", "generate", "--output", abs, "--adapter", "kysely", "--yes")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratePrompt(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeSQL{plan: pendingPlan(nil)}
	opts := migrateAuth(t, fake, betterauth.Config{})
	r := run(t, opts, "n\n", "generate", "--cwd", dir, "--output", "m.sql")
	if r.code != 1 || r.stderr != "Schema generation aborted.\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
	contains(t, r.stdout, "? Do you want to generate the schema to "+filepath.Join(dir, "m.sql")+"? › (y/N) ")
	if _, err := os.Stat(filepath.Join(dir, "m.sql")); !os.IsNotExist(err) {
		t.Fatal("file written after abort")
	}

	r = run(t, opts, "y\n", "generate", "--cwd", dir)
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stdout, "? Do you want to generate the schema to ./better-auth_migrations/2026-01-02T03-04-05.006Z.sql?")
	contains(t, r.stdout, "🚀 Schema was generated successfully!")

	r = run(t, opts, "", "generate", "--cwd", dir, "--output", "dep.sql", "--y")
	if r.code != 0 || r.stderr != "WARNING: --y is deprecated. Consider -y or --yes\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestGenerateUpToDate(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeSQL{plan: func(*db.Schema) (*adapter.MigrationPlan, error) { return &adapter.MigrationPlan{}, nil }}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "generate", "--cwd", dir, "--yes")
	if r.code != 0 || r.stdout != "Your schema is already up to date.\n" {
		t.Fatalf("%d %q", r.code, r.stdout)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("unexpected files %v", entries)
	}
}

func TestGenerateUnsupported(t *testing.T) {
	r := run(t, Options{Auth: memoryAuth(t)}, "", "generate", "--yes", "--cwd", t.TempDir())
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stderr, "Error running Better Auth CLI: memory is not supported.")

	fake := &fakeSQL{plan: pendingPlan(nil)}
	for _, a := range []string{"prisma", "drizzle"} {
		r = run(t, migrateAuth(t, fake, betterauth.Config{}), "", "generate", "--adapter", a, "--dialect", "sqlite", "--yes", "--cwd", t.TempDir())
		if r.code != 1 {
			t.Fatalf("%s: exit %d", a, r.code)
		}
		contains(t, r.stderr, "the "+a+" generator is not available in the Go CLI")
	}
}

func TestGenerateWithoutConfig(t *testing.T) {
	r := run(t, Options{}, "", "generate", "--yes")
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stderr, "No Better Auth instance configured")
}

func TestCommentBanner(t *testing.T) {
	got := commentBanner([]string{"first change", "second change"})
	lines := strings.Split(got, "\n")
	rule := "-- " + strings.Repeat("-", 77)
	want := []string{rule, "-- DO NOT RUN THIS SCRIPT AS IT IS.", "-- Applying it to a populated database corrupts the rows it touches:",
		"--", "-- first change", "--", "-- second change", rule, ""}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("banner:\n%s", got)
	}
}
