// Package testdb provides isolated test databases for the adapter and migration tests.
//
// Each helper creates a fresh database (dropped on cleanup) so packages can run in
// parallel against the shared servers from docker-compose.yml. Connection settings come
// from BA_TEST_POSTGRES_URL, BA_TEST_MYSQL_DSN and BA_TEST_MONGO_URI; when a variable is
// unset the docker-compose defaults are tried, and the test is skipped if that server is
// unreachable. Setting BA_TEST_REQUIRE_DBS=1 turns those skips into failures (CI).
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	_ "modernc.org/sqlite" // registers "sqlite"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Default connection settings (docker-compose.yml).
const (
	DefaultPostgresURL = "postgres://better_auth:better_auth@localhost:5433/better_auth?sslmode=disable"
	DefaultMySQLDSN    = "root:root@tcp(localhost:3307)/?parseTime=true"
	DefaultMongoURI    = "mongodb://localhost:27018/?directConnection=true"
)

func setting(env, def string) (string, bool) {
	if v := os.Getenv(env); v != "" {
		return v, true
	}
	return def, false
}

func unavailable(t testing.TB, explicit bool, what string, err error) {
	t.Helper()
	if explicit || os.Getenv("BA_TEST_REQUIRE_DBS") == "1" {
		t.Fatalf("%s unavailable: %v", what, err)
	}
	t.Skipf("%s unavailable (start it with `docker compose up -d`): %v", what, err)
}

func dbName() string {
	return "ba_test_" + strings.ToLower(bacrypto.RandomStringFrom(12, "a-z", "0-9"))
}

// Postgres returns a connection (driver "pgx") to a new, empty PostgreSQL database.
func Postgres(t testing.TB) *sql.DB {
	t.Helper()
	raw, explicit := setting("BA_TEST_POSTGRES_URL", DefaultPostgresURL)
	admin, err := sql.Open("pgx", raw)
	if err != nil {
		unavailable(t, explicit, "PostgreSQL", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		unavailable(t, explicit, "PostgreSQL", err)
	}
	name := dbName()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		admin.Close()
	})
	return db
}

// MySQL returns a connection (driver "mysql", parseTime=true) to a new, empty MySQL
// database. The DSN must name a user allowed to create databases.
func MySQL(t testing.TB) *sql.DB {
	t.Helper()
	raw, explicit := setting("BA_TEST_MYSQL_DSN", DefaultMySQLDSN)
	cfg, err := mysql.ParseDSN(raw)
	if err != nil {
		t.Fatalf("BA_TEST_MYSQL_DSN: %v", err)
	}
	cfg.DBName = ""
	cfg.ParseTime = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		unavailable(t, explicit, "MySQL", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		unavailable(t, explicit, "MySQL", err)
	}
	name := dbName()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	cfg.DBName = name
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name)
		admin.Close()
	})
	return db
}

// MySQLDSN returns the DSN of a new, empty MySQL database (for code that opens its own
// connection, e.g. the CLI).
func MySQLDSN(t testing.TB) string {
	t.Helper()
	raw, explicit := setting("BA_TEST_MYSQL_DSN", DefaultMySQLDSN)
	cfg, err := mysql.ParseDSN(raw)
	if err != nil {
		t.Fatalf("BA_TEST_MYSQL_DSN: %v", err)
	}
	cfg.DBName = ""
	cfg.ParseTime = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		unavailable(t, explicit, "MySQL", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		unavailable(t, explicit, "MySQL", err)
	}
	name := dbName()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name)
		admin.Close()
	})
	cfg.DBName = name
	return cfg.FormatDSN()
}

// PostgresURL returns the URL of a new, empty PostgreSQL database.
func PostgresURL(t testing.TB) string {
	t.Helper()
	raw, explicit := setting("BA_TEST_POSTGRES_URL", DefaultPostgresURL)
	admin, err := sql.Open("pgx", raw)
	if err != nil {
		unavailable(t, explicit, "PostgreSQL", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		unavailable(t, explicit, "PostgreSQL", err)
	}
	name := dbName()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		admin.Close()
	})
	u, _ := url.Parse(raw)
	u.Path = "/" + name
	return u.String()
}

// SQLitePath returns the path of a new SQLite database file in a temporary directory.
func SQLitePath(t testing.TB) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.db")
}

// SQLite returns a connection (driver "sqlite", modernc.org/sqlite) to a new file-backed
// SQLite database with foreign keys enabled.
func SQLite(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+SQLitePath(t)+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// Mongo returns a new, empty MongoDB database (dropped on cleanup) and its client.
func Mongo(t testing.TB) (*mongo.Database, *mongo.Client) {
	t.Helper()
	uri, explicit := setting("BA_TEST_MONGO_URI", DefaultMongoURI)
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(3 * time.Second))
	if err != nil {
		unavailable(t, explicit, "MongoDB", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		unavailable(t, explicit, "MongoDB", err)
	}
	database := client.Database(dbName())
	t.Cleanup(func() {
		_ = database.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	return database, client
}

// Describe returns a short label for a database handle (for subtest names).
func Describe(db *sql.DB) string { return fmt.Sprintf("%T", db.Driver()) }
