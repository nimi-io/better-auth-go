package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/cli"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// End-to-end tests: the built binary against real databases (SQLite always; PostgreSQL
// and MySQL from docker-compose.yml, skipped when unreachable unless BA_TEST_REQUIRE_DBS=1).

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "better-auth-cli-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "better-auth")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goTool); err != nil {
		goTool = "go"
	}
	build := exec.Command(goTool, "build", "-o", binary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("building the CLI: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type cliResult struct {
	code           int
	stdout, stderr string
}

func (r cliResult) String() string {
	return fmt.Sprintf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
}

// runBinary runs the CLI in cwd with DATABASE_URL and BETTER_AUTH_* cleared unless env sets them.
func runBinary(t *testing.T, cwd, stdin string, env []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = cwd
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DATABASE_URL=") || strings.HasPrefix(kv, "BETTER_AUTH_") {
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, "BETTER_AUTH_SECRET=an-integration-test-secret-long-enough", "NO_COLOR=1")
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
}

type dbCase struct {
	name    string
	dialect string
	// args returns the database flags for a fresh database.
	args func(t *testing.T) []string
	// quote quotes an identifier in generated SQL.
	quote func(string) string
}

func dbCases() []dbCase {
	dq := func(s string) string { return `"` + s + `"` }
	bq := func(s string) string { return "`" + s + "`" }
	return []dbCase{
		{"sqlite", "sqlite", func(t *testing.T) []string { return []string{"--database-url", "sqlite:" + testdb.SQLitePath(t)} }, dq},
		{"sqlite-path", "sqlite", func(t *testing.T) []string { return []string{"--database-url", testdb.SQLitePath(t)} }, dq},
		{"postgres", "postgres", func(t *testing.T) []string { return []string{"--database-url", testdb.PostgresURL(t)} }, dq},
		{"mysql-dsn", "mysql", func(t *testing.T) []string {
			return []string{"--database-url", testdb.MySQLDSN(t), "--dialect", "mysql"}
		}, bq},
		{"mysql-url", "mysql", func(t *testing.T) []string { return []string{"--database-url", mysqlDSNToURL(t, testdb.MySQLDSN(t))} }, bq},
	}
}

func mysqlDSNToURL(t *testing.T, dsn string) string {
	t.Helper()
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u := url.URL{Scheme: "mysql", User: url.UserPassword(cfg.User, cfg.Passwd), Host: cfg.Addr, Path: "/" + cfg.DBName}
	return u.String()
}

func TestBinaryWorkflow(t *testing.T) {
	for _, tc := range dbCases() {
		t.Run(tc.name, func(t *testing.T) {
			dbArgs := tc.args(t)
			cwd := t.TempDir()
			with := func(args ...string) []string { return append(args, dbArgs...) }

			// generate writes the pending migration to --output
			r := runBinary(t, cwd, "", nil, with("generate", "--output", "schema.sql", "--yes")...)
			if r.code != 0 || !strings.Contains(r.stdout, "🚀 Schema was generated successfully!") {
				t.Fatalf("generate: %s", r)
			}
			sqlText, err := os.ReadFile(filepath.Join(cwd, "schema.sql"))
			if err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"user", "session", "account", "verification"} {
				if !strings.Contains(string(sqlText), "create table "+tc.quote(table)) {
					t.Fatalf("schema.sql lacks table %s:\n%s", table, sqlText)
				}
			}

			// declining the prompt leaves the database untouched
			r = runBinary(t, cwd, "n\n", nil, with("migrate")...)
			if r.code != 0 || !strings.Contains(r.stdout, "Migration cancelled.") {
				t.Fatalf("migrate (declined): %s", r)
			}
			for _, want := range []string{
				"🔑 The migration will affect the following:",
				"-> name, email, emailVerified, image, createdAt, updatedAt fields on user table.",
				"? Are you sure you want to run these migrations? › (y/N)",
			} {
				if !strings.Contains(r.stdout, want) {
					t.Fatalf("migrate output lacks %q: %s", want, r)
				}
			}

			r = runBinary(t, cwd, "", nil, with("migrate", "--yes")...)
			if r.code != 0 || !strings.Contains(r.stdout, "🚀 migration was completed successfully!") {
				t.Fatalf("migrate --yes: %s", r)
			}
			r = runBinary(t, cwd, "", nil, with("migrate", "-y")...)
			if r.code != 0 || strings.TrimSpace(r.stdout) != "🚀 No migrations needed." {
				t.Fatalf("migrate (up to date): %s", r)
			}
			r = runBinary(t, cwd, "", nil, with("generate", "--output", "again.sql", "-y")...)
			if r.code != 0 || strings.TrimSpace(r.stdout) != "Your schema is already up to date." {
				t.Fatalf("generate (up to date): %s", r)
			}
			if _, err := os.Stat(filepath.Join(cwd, "again.sql")); !os.IsNotExist(err) {
				t.Fatal("generate wrote a file although the schema is up to date")
			}

			// info reports the dialect and redacts the database URL
			r = runBinary(t, cwd, "", nil, with("info", "--json")...)
			if r.code != 0 {
				t.Fatalf("info: %s", r)
			}
			var info map[string]any
			if err := json.Unmarshal([]byte(r.stdout), &info); err != nil {
				t.Fatalf("info JSON: %v\n%s", err, r.stdout)
			}
			ba := info["betterAuth"].(map[string]any)
			if ba["error"] != nil {
				t.Fatalf("info error: %v", ba["error"])
			}
			database := ba["database"].(map[string]any)
			if database["adapter"] != sqladapter.AdapterID || database["dialect"] != tc.dialect {
				t.Fatalf("info database %v", database)
			}
			if strings.Contains(r.stdout, "an-integration-test-secret") {
				t.Fatal("info leaked the secret")
			}
			dbs, _ := json.Marshal(info["databases"])
			for _, driver := range []string{"pgx", "go-sql-driver/mysql", "modernc.org/sqlite"} {
				if !strings.Contains(string(dbs), driver) {
					t.Fatalf("info databases lacks %s: %s", driver, dbs)
				}
			}
		})
	}
}

func TestBinaryDefaultOutputPath(t *testing.T) {
	cwd := t.TempDir()
	r := runBinary(t, cwd, "", nil, "generate", "--database-url", "sqlite:"+testdb.SQLitePath(t), "-y")
	if r.code != 0 {
		t.Fatalf("%s", r)
	}
	entries, err := os.ReadDir(filepath.Join(cwd, "better-auth_migrations"))
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "Z.sql") {
		t.Fatalf("better-auth_migrations: %v %v", entries, err)
	}

	out := filepath.Join(cwd, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	r = runBinary(t, cwd, "", nil, "generate", "--database-url", "sqlite:"+testdb.SQLitePath(t), "--output", "out", "--yes")
	if r.code != 0 {
		t.Fatalf("%s", r)
	}
	entries, _ = os.ReadDir(out)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".sql") {
		t.Fatalf("out: %v", entries)
	}
}

func TestBinaryEnvironment(t *testing.T) {
	cwd := t.TempDir()
	// DATABASE_URL
	r := runBinary(t, cwd, "", []string{"DATABASE_URL=sqlite:" + testdb.SQLitePath(t)}, "migrate", "--yes")
	if r.code != 0 || !strings.Contains(r.stdout, "migration was completed successfully") {
		t.Fatalf("DATABASE_URL: %s", r)
	}
	// .env in the working directory
	envDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(envDir, ".env"), []byte("DATABASE_URL=sqlite:"+filepath.Join(envDir, "env.db")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = runBinary(t, envDir, "", nil, "migrate", "--yes")
	if r.code != 0 || !strings.Contains(r.stdout, "migration was completed successfully") {
		t.Fatalf(".env: %s", r)
	}
	// no database: upstream's "no configuration" path (message, status 0)
	r = runBinary(t, cwd, "", nil, "migrate", "--yes")
	if r.code != 0 || strings.TrimSpace(r.stderr) != "No database configured. Pass --database-url or set DATABASE_URL." {
		t.Fatalf("no database: %s", r)
	}
	// secret and info work without a database
	r = runBinary(t, cwd, "", nil, "secret")
	if r.code != 0 || !strings.Contains(r.stdout, "BETTER_AUTH_SECRET=") {
		t.Fatalf("secret: %s", r)
	}
	r = runBinary(t, cwd, "", nil, "info")
	if r.code != 0 || !strings.Contains(r.stdout, "🔐 Better Auth:") || strings.Contains(r.stdout, "Error:") {
		t.Fatalf("info: %s", r)
	}
	// unreachable database: an error, not a crash
	r = runBinary(t, cwd, "", nil, "migrate", "--database-url", "postgres://nobody:secret@127.0.0.1:1/none?connect_timeout=2", "--yes")
	if r.code != 1 || !strings.HasPrefix(r.stderr, "Error running Better Auth CLI:") {
		t.Fatalf("unreachable: %s", r)
	}
}

func TestBinarySchemaProblem(t *testing.T) {
	path := testdb.SQLitePath(t)
	conn, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// a required column Better Auth never writes
	if _, err := conn.Exec(`CREATE TABLE "verification" ("id" text primary key not null, "identifier" text not null, "value" text not null, "expiresAt" date not null, "createdAt" date not null, "updatedAt" date not null, "issuer" text not null)`); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	r := runBinary(t, t.TempDir(), "", nil, "migrate", "--database-url", "sqlite:"+path, "--yes")
	if r.code != 1 || !strings.Contains(r.stderr, "Better Auth cannot write to. Nothing ran.") || !strings.Contains(r.stderr, "issuer") {
		t.Fatalf("%s", r)
	}
}

// populatedAccountDB mirrors upstream's migrate-cli test: populated user and account tables,
// and a config that adds a required account column without a default.
func populatedAccountDB(t *testing.T) (*sql.DB, betterauth.Config) {
	conn := testdb.SQLite(t)
	for _, stmt := range []string{
		`CREATE TABLE "user" ("id" text primary key not null, "name" text not null, "email" text not null unique, "emailVerified" integer not null, "image" text, "createdAt" date not null, "updatedAt" date not null)`,
		`CREATE TABLE "account" ("id" text primary key not null, "accountId" text not null, "providerId" text not null, "userId" text not null references "user" ("id") on delete cascade, "createdAt" date not null, "updatedAt" date not null)`,
		`INSERT INTO "user" ("id", "name", "email", "emailVerified", "createdAt", "updatedAt") VALUES ('u1', 'Ada', 'ada@example.com', 1, '2020-01-01', '2020-01-01')`,
		`INSERT INTO "account" ("id", "accountId", "providerId", "userId", "createdAt", "updatedAt") VALUES ('a1', 'g-1', 'google', 'u1', '2020-01-01', '2020-01-01')`,
	} {
		if _, err := conn.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	return conn, betterauth.Config{
		Secret:   "a-secret-long-enough-to-keep-the-cli-quiet",
		BaseURL:  "http://localhost:3000",
		Logger:   betterauth.NewLogger(betterauth.LevelError, nil),
		Database: sqladapter.New(conn, sqladapter.Config{}),
		Account: &betterauth.AccountConfig{ModelConfig: betterauth.ModelConfig{
			AdditionalFields: []db.Field{{Name: "plan", Type: db.TypeString, Required: db.True}},
		}},
	}
}

func runEmbedded(t *testing.T, cfg betterauth.Config, args ...string) cliResult {
	t.Helper()
	auth, err := betterauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := cli.Run(context.Background(), args, cli.Options{Auth: auth, Stdout: &out, Stderr: &errb, Stdin: strings.NewReader("")})
	return cliResult{code: code, stdout: out.String(), stderr: errb.String()}
}

// TestEmbeddedRefusesUnsafeMigration is upstream's "refusing a destructive column add".
func TestEmbeddedRefusesUnsafeMigration(t *testing.T) {
	_, cfg := populatedAccountDB(t)
	r := runEmbedded(t, cfg, "migrate", "--yes")
	if r.code != 1 {
		t.Fatalf("%s", r)
	}
	for _, want := range []string{
		"The migration was refused, and nothing ran.",
		`Cannot add required column "plan" to populated table "account"`,
		"Run better-auth generate to read the statements without executing them.",
	} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr lacks %q: %s", want, r)
		}
	}
}

// TestEmbeddedGenerateUnsafeBanner is upstream's "emitting the refused migration with a
// warning". It needs the SQL adapter to plan in report mode (throwOnUnsafe: false) through
// PlanMigrationsReportUnsafe.
func TestEmbeddedGenerateUnsafeBanner(t *testing.T) {
	_, cfg := populatedAccountDB(t)
	cwd := t.TempDir()
	r := runEmbedded(t, cfg, "generate", "--cwd", cwd, "--output", "migration.sql", "--yes")
	if r.code != 0 || !strings.Contains(r.stderr, "corrupts a populated database") {
		t.Fatalf("%s", r)
	}
	b, err := os.ReadFile(filepath.Join(cwd, "migration.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sqlText := string(b)
	if !strings.Contains(sqlText, "DO NOT RUN THIS SCRIPT AS IT IS.") ||
		!strings.Contains(strings.ToLower(sqlText), `alter table "account" add column "plan" text not null`) {
		t.Fatalf("migration.sql:\n%s", sqlText)
	}
}

// TestEmbeddedAdditionalFields checks that an embedded CLI migrates the full configuration.
func TestEmbeddedAdditionalFields(t *testing.T) {
	conn := testdb.SQLite(t)
	cfg := betterauth.Config{
		Secret:   "a-secret-long-enough-to-keep-the-cli-quiet",
		Logger:   betterauth.NewLogger(betterauth.LevelError, nil),
		Database: sqladapter.New(conn, sqladapter.Config{}),
		User: &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{
			ModelName:        "users",
			Fields:           map[string]string{"email": "email_address"},
			AdditionalFields: []db.Field{{Name: "plan", Type: db.TypeString, Required: db.False}},
		}},
	}
	r := runEmbedded(t, cfg, "migrate", "--yes")
	if r.code != 0 || !strings.Contains(r.stdout, "fields on users table.") || !strings.Contains(r.stdout, "email_address") || !strings.Contains(r.stdout, "plan") {
		t.Fatalf("%s", r)
	}
	if _, err := conn.Exec(`SELECT "email_address", "plan" FROM "users"`); err != nil {
		t.Fatal(err)
	}
}
