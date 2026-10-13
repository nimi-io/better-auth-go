package dialect

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/stdlib"
	"modernc.org/sqlite"
)

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return nil, errors.New("no") }

func init() { sql.Register("dialect-test-unknown", fakeDriver{}) }

// TestDetect is the Go counterpart of getKyselyDatabaseType: one database/sql driver per
// dialect.
func TestDetect(t *testing.T) {
	for _, c := range []struct {
		driver, dsn string
		want        Dialect
	}{
		{"pgx", "postgres://u:p@localhost:1/db", Postgres},
		{"mysql", "u:p@tcp(localhost:1)/db", MySQL},
		{"sqlite", ":memory:", SQLite},
	} {
		t.Run(string(c.want), func(t *testing.T) {
			db, err := sql.Open(c.driver, c.dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			got, err := Detect(db)
			if err != nil || got != c.want {
				t.Fatalf("Detect = %q, %v", got, err)
			}
		})
	}
	db, _ := sql.Open("dialect-test-unknown", "")
	defer db.Close()
	if _, err := Detect(db); err == nil {
		t.Fatal("unknown driver must not be detected")
	}
	if _, err := Detect(nil); err == nil {
		t.Fatal("nil db")
	}
}

func TestFromDriver(t *testing.T) {
	for _, c := range []struct {
		drv  any
		want Dialect
	}{
		{&stdlib.Driver{}, Postgres},
		{mysql.MySQLDriver{}, MySQL},
		{&mysql.MySQLDriver{}, MySQL},
		{&sqlite.Driver{}, SQLite},
	} {
		if got, ok := FromDriver(c.drv); !ok || got != c.want {
			t.Errorf("FromDriver(%T) = %q %v", c.drv, got, ok)
		}
	}
	if _, ok := FromDriver(fakeDriver{}); ok {
		t.Error("fake driver detected")
	}
	if _, ok := FromDriver(nil); ok {
		t.Error("nil driver detected")
	}
}

func TestFromDriverName(t *testing.T) {
	for name, want := range map[string]Dialect{
		"pgx": Postgres, "postgres": Postgres, "PostgreSQL": Postgres, "pq": Postgres,
		"mysql": MySQL, "mariadb": MySQL,
		"sqlite": SQLite, "sqlite3": SQLite, "libsql": SQLite,
		"sqlserver": MSSQL, "mssql": MSSQL,
	} {
		if got, ok := FromDriverName(name); !ok || got != want {
			t.Errorf("FromDriverName(%q) = %q %v", name, got, ok)
		}
	}
	if _, ok := FromDriverName("oracle"); ok {
		t.Error("oracle")
	}
}

func TestQuotingAndPlaceholders(t *testing.T) {
	cases := []struct {
		d                            Dialect
		in, quote, ph, table, dotted string
	}{
		{Postgres, `a"b`, `"a""b"`, "$3", `"auth"."user"`, `"internal"."users"`},
		{MySQL, "a`b", "`a``b`", "?", "`auth`.`user`", "`internal`.`users`"},
		{SQLite, `a"b`, `"a""b"`, "?", `"auth"."user"`, `"internal"."users"`},
		{MSSQL, "a]b", "[a]]b]", "@p3", "[auth].[user]", "[internal].[users]"},
	}
	for _, c := range cases {
		if got := c.d.Quote(c.in); got != c.quote {
			t.Errorf("%s Quote = %s", c.d, got)
		}
		if got := c.d.Placeholder(3); got != c.ph {
			t.Errorf("%s Placeholder = %s", c.d, got)
		}
		if got := c.d.QuoteTable("auth", "user"); got != c.table {
			t.Errorf("%s QuoteTable = %s", c.d, got)
		}
		// a dotted model name is a schema reference and wins over the configured schema
		if got := c.d.QuoteTable("auth", "internal.users"); got != c.dotted {
			t.Errorf("%s QuoteTable dotted = %s", c.d, got)
		}
		if got := c.d.QuoteTable("", "user"); got != c.d.Quote("user") {
			t.Errorf("%s QuoteTable unqualified = %s", c.d, got)
		}
	}
	// a dotted schema name stays one identifier (dialect.test.ts)
	if got := Postgres.QuoteTable("tenant.auth", "user"); got != `"tenant.auth"."user"` {
		t.Errorf("dotted schema = %s", got)
	}
	if !Postgres.SupportsReturning() || !SQLite.SupportsReturning() || MySQL.SupportsReturning() || MSSQL.SupportsReturning() {
		t.Error("SupportsReturning")
	}
	if !Postgres.Valid() || Dialect("oracle").Valid() {
		t.Error("Valid")
	}
}
