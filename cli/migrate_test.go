package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

func migrateAuth(t *testing.T, fake *fakeSQL, cfg betterauth.Config) Options {
	t.Helper()
	cfg.Database = fakeFactory(fake)
	return Options{Auth: newAuth(t, cfg)}
}

func TestMigrateRejectsMissingCwd(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-directory")
	r := run(t, Options{NewAuth: func(context.Context, string) (*betterauth.Auth, error) {
		t.Fatal("NewAuth must not be called")
		return nil, nil
	}}, "", "migrate", "--cwd", missing)
	if r.code != 1 || r.stderr != `The directory "`+missing+`" does not exist.`+"\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestMigrateWithoutConfig(t *testing.T) {
	r := run(t, Options{}, "", "migrate")
	if r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stderr, "No Better Auth instance configured")

	r = run(t, Options{NewAuth: func(context.Context, string) (*betterauth.Auth, error) {
		return nil, NoConfig("No database configured. Pass --database-url or set DATABASE_URL.")
	}}, "", "migrate", "-y")
	if r.code != 0 || r.stderr != "No database configured. Pass --database-url or set DATABASE_URL.\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestMigrateNewAuthError(t *testing.T) {
	r := run(t, Options{NewAuth: func(context.Context, string) (*betterauth.Auth, error) {
		return nil, errors.New("dial tcp: connection refused")
	}}, "", "migrate")
	if r.code != 1 || r.stderr != "Error running Better Auth CLI: dial tcp: connection refused\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestMigrateUnsupportedAdapter(t *testing.T) {
	r := run(t, Options{Auth: memoryAuth(t)}, "", "migrate", "--yes")
	if r.code != 1 || r.stderr != "Migrate command isn't supported for this adapter.\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestMigrateNothingToDo(t *testing.T) {
	fake := &fakeSQL{plan: func(*db.Schema) (*adapter.MigrationPlan, error) { return &adapter.MigrationPlan{}, nil }}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate")
	if r.code != 0 || r.stdout != "🚀 No migrations needed.\n" {
		t.Fatalf("%d %q %q", r.code, r.stdout, r.stderr)
	}
}

func TestMigrateYes(t *testing.T) {
	executed := 0
	fake := &fakeSQL{plan: pendingPlan(&executed)}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "--yes")
	if r.code != 0 || executed != 1 {
		t.Fatalf("exit %d executed %d: %s %s", r.code, executed, r.stdout, r.stderr)
	}
	want := "🔑 The migration will affect the following:\n" +
		"-> id, name, email fields on user table.\n" +
		"-> ip_address fields on session table.\n" +
		"🚀 migration was completed successfully!\n"
	if r.stdout != want {
		t.Fatalf("stdout:\n%q\nwant:\n%q", r.stdout, want)
	}
	if r.stderr != "" {
		t.Fatalf("stderr: %q", r.stderr)
	}
}

func TestMigrateReceivesFullSchema(t *testing.T) {
	fake := &fakeSQL{plan: func(*db.Schema) (*adapter.MigrationPlan, error) { return &adapter.MigrationPlan{}, nil }}
	opts := migrateAuth(t, fake, betterauth.Config{
		User: &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{
			ModelName:        "users",
			AdditionalFields: []db.Field{{Name: "plan", Type: db.TypeString}},
		}},
	})
	if r := run(t, opts, "", "migrate"); r.code != 0 {
		t.Fatalf("exit %d", r.code)
	}
	user := fake.schema.Table("user")
	if user == nil || user.ModelName != "users" {
		t.Fatalf("user table not renamed: %+v", user)
	}
	if _, ok := user.Field("plan"); !ok {
		t.Fatal("additional field missing from the schema passed to the migrator")
	}
}

func TestMigratePrompt(t *testing.T) {
	for _, tc := range []struct {
		stdin    string
		executed int
		message  string
	}{
		{"y\n", 1, "🚀 migration was completed successfully!"},
		{"yes\n", 1, "🚀 migration was completed successfully!"},
		{"n\n", 0, "Migration cancelled."},
		{"\n", 0, "Migration cancelled."},
		{"", 0, "Migration cancelled."}, // EOF
	} {
		executed := 0
		fake := &fakeSQL{plan: pendingPlan(&executed)}
		r := run(t, migrateAuth(t, fake, betterauth.Config{}), tc.stdin, "migrate")
		if r.code != 0 || executed != tc.executed {
			t.Fatalf("%q: exit %d executed %d", tc.stdin, r.code, executed)
		}
		contains(t, r.stdout, "? Are you sure you want to run these migrations? › (y/N) ")
		contains(t, r.stdout, tc.message)
	}
}

func TestMigrateDeprecatedY(t *testing.T) {
	executed := 0
	fake := &fakeSQL{plan: pendingPlan(&executed)}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "--y")
	if r.code != 0 || executed != 1 {
		t.Fatalf("exit %d executed %d", r.code, executed)
	}
	if r.stderr != "WARNING: --y is deprecated. Consider -y or --yes\n" {
		t.Fatalf("stderr %q", r.stderr)
	}
	notContains(t, r.stdout, "Are you sure")

	executed = 0
	r = run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "-y")
	if r.code != 0 || executed != 1 || r.stderr != "" {
		t.Fatalf("-y: exit %d executed %d stderr %q", r.code, executed, r.stderr)
	}
}

func TestMigrateErrors(t *testing.T) {
	fake := &fakeSQL{plan: func(*db.Schema) (*adapter.MigrationPlan, error) { return nil, errors.New("introspection failed") }}
	r := run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "-y")
	if r.code != 1 || r.stderr != "Error running Better Auth CLI: introspection failed\n" {
		t.Fatalf("%d %q", r.code, r.stderr)
	}

	fake = &fakeSQL{plan: func(s *db.Schema) (*adapter.MigrationPlan, error) {
		p, _ := pendingPlan(nil)(s)
		p.Exec = func(context.Context) error { return errors.New("syntax error") }
		return p, nil
	}}
	r = run(t, migrateAuth(t, fake, betterauth.Config{}), "", "migrate", "-y")
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	contains(t, r.stderr, "Error running Better Auth CLI: syntax error")
	notContains(t, r.stdout, "completed successfully")
}
