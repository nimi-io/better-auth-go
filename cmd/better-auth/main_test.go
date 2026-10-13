package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
)

func TestParseDatabaseURL(t *testing.T) {
	for _, tc := range []struct {
		raw, dialect string
		want         sqladapter.Dialect
		driver, dsn  string
	}{
		{raw: "postgres://u:p@localhost:5432/app?sslmode=disable", want: sqladapter.Postgres, driver: "pgx", dsn: "postgres://u:p@localhost:5432/app?sslmode=disable"},
		{raw: "postgresql://localhost/app", want: sqladapter.Postgres, driver: "pgx", dsn: "postgresql://localhost/app"},
		{raw: "host=localhost dbname=app", dialect: "postgres", want: sqladapter.Postgres, driver: "pgx", dsn: "host=localhost dbname=app"},
		{raw: "sqlite:./app.db", want: sqladapter.SQLite, driver: "sqlite", dsn: "file:./app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{raw: "sqlite:///tmp/app.db", want: sqladapter.SQLite, driver: "sqlite", dsn: "file:/tmp/app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{raw: "sqlite://app.db", want: sqladapter.SQLite, driver: "sqlite", dsn: "file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{raw: "file:app.db?mode=rwc", want: sqladapter.SQLite, driver: "sqlite", dsn: "file:app.db?mode=rwc&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{raw: "data/app.sqlite3", want: sqladapter.SQLite, driver: "sqlite", dsn: "file:data/app.sqlite3?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{raw: "/abs/app.db", dialect: "sqlite3", want: sqladapter.SQLite, driver: "sqlite", dsn: "file:/abs/app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{raw: "app", dialect: "sqlite", want: sqladapter.SQLite, driver: "sqlite", dsn: "file:app?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
	} {
		got, err := parseDatabaseURL(tc.raw, tc.dialect)
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if got.dialect != tc.want || got.driver != tc.driver || got.dsn != tc.dsn {
			t.Errorf("%s: got %+v", tc.raw, got)
		}
	}
}

func TestParseMySQL(t *testing.T) {
	got, err := parseDatabaseURL("mysql://user:p%40ss@db.example.com:3307/app?tls=preferred&timeout=5s", "")
	if err != nil {
		t.Fatal(err)
	}
	c := got.mysql
	if got.dialect != sqladapter.MySQL || c == nil {
		t.Fatalf("%+v", got)
	}
	if c.User != "user" || c.Passwd != "p@ss" || c.Net != "tcp" || c.Addr != "db.example.com:3307" || c.DBName != "app" || !c.ParseTime || c.TLSConfig != "preferred" || c.Timeout.String() != "5s" {
		t.Fatalf("config %+v", c)
	}
	got, err = parseDatabaseURL("mariadb://root@localhost/app?parseTime=false", "mysql")
	if err != nil {
		t.Fatal(err)
	}
	if got.mysql.Addr != "localhost:3306" || got.mysql.ParseTime {
		t.Fatalf("config %+v", got.mysql)
	}
	// a go-sql-driver DSN with --dialect mysql
	got, err = parseDatabaseURL("root:root@tcp(localhost:3307)/app", "mysql")
	if err != nil {
		t.Fatal(err)
	}
	if got.mysql.Addr != "localhost:3307" || got.mysql.DBName != "app" || !got.mysql.ParseTime {
		t.Fatalf("config %+v", got.mysql)
	}
}

func TestParseDatabaseURLErrors(t *testing.T) {
	for _, tc := range []struct{ raw, dialect, want string }{
		{"redis://localhost", "", "cannot detect the database"},
		{"whatever", "", "cannot detect the database"},
		{"postgres://localhost/app", "mysql", "--dialect mysql does not match the postgres database URL"},
		{"postgres://localhost/app", "oracle", `unsupported dialect "oracle"`},
		{"not a dsn", "mysql", "invalid MySQL DSN"},
	} {
		_, err := parseDatabaseURL(tc.raw, tc.dialect)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s (%s): got %v, want %q", tc.raw, tc.dialect, err, tc.want)
		}
		if err != nil && strings.Contains(tc.raw, "://") && strings.Contains(err.Error(), tc.raw) {
			t.Errorf("error leaks the URL: %v", err)
		}
	}
}

func TestLoadDotEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := "# comment\nBA_TEST_A=plain\nexport BA_TEST_B=\"quoted value\\nline\"\nBA_TEST_C='single # not a comment'\nBA_TEST_D=value # trailing comment\nBA_TEST_PRESET=from-file\n\nnot a pair\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"BA_TEST_A", "BA_TEST_B", "BA_TEST_C", "BA_TEST_D"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("BA_TEST_PRESET", "from-env")
	loadDotEnv(path)
	for k, want := range map[string]string{
		"BA_TEST_A":      "plain",
		"BA_TEST_B":      "quoted value\nline",
		"BA_TEST_C":      "single # not a comment",
		"BA_TEST_D":      "value",
		"BA_TEST_PRESET": "from-env",
	} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	loadDotEnv(filepath.Join(t.TempDir(), "missing.env")) // no-op
}
