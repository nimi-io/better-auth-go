// Command better-auth is the Better Auth CLI for the default schema (no plugins or
// additional fields). It runs migrate, generate, secret and info against the database named
// by --database-url or $DATABASE_URL:
//
//	better-auth migrate --database-url postgres://user:pass@localhost:5432/app --yes
//	better-auth generate --database-url mysql://user:pass@localhost:3306/app --output migrations/
//	better-auth generate --database-url sqlite:./app.db
//	better-auth secret
//	better-auth info --json
//
// Supported URLs: postgres:// and postgresql:// (pgx), mysql:// and mariadb://
// (go-sql-driver/mysql), sqlite:path, sqlite://path, file:path and *.db / *.sqlite /
// *.sqlite3 paths (modernc.org/sqlite). With --dialect a driver-native DSN is accepted too
// (e.g. a go-sql-driver DSN "user:pass@tcp(host:3306)/app").
//
// Like upstream, a .env file in the working directory is loaded first (existing environment
// variables win), and BETTER_AUTH_SECRET / BETTER_AUTH_URL are read by betterauth.New.
//
// Projects with plugins, additional fields or renamed tables should embed the cli package
// in their own binary instead, so the CLI sees the full configuration (see package cli).
package main

import (
	"context"
	"database/sql"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/cli"
)

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		os.Exit(0) // upstream exits 0 on SIGINT/SIGTERM
	}()
	os.Exit(run(context.Background(), os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	loadDotEnv(".env")
	var (
		databaseURL string
		dialectName string
		conn        *sql.DB
		resolved    string
	)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	opts := cli.Options{
		Flags: func(command string, fs *flag.FlagSet) {
			fs.StringVar(&databaseURL, "database-url", "", "the database connection URL (postgres://, mysql://, sqlite:path). defaults to $DATABASE_URL")
			fs.StringVar(&dialectName, "dialect", "", "the SQL dialect (postgres, mysql or sqlite). detected from the URL by default")
		},
	}
	opts.NewAuth = func(ctx context.Context, command string) (*betterauth.Auth, error) {
		raw := databaseURL
		if raw == "" {
			raw = os.Getenv("DATABASE_URL")
		}
		cfg := betterauth.Config{Logger: betterauth.NewLogger(betterauth.LevelError, nil)}
		if raw == "" {
			if command == "info" {
				return betterauth.New(cfg)
			}
			return nil, cli.NoConfig("No database configured. Pass --database-url or set DATABASE_URL.")
		}
		t, err := parseDatabaseURL(raw, dialectName)
		if err != nil {
			return nil, err
		}
		db, err := t.open()
		if err != nil {
			return nil, err
		}
		conn = db
		resolved = string(t.dialect)
		cfg.Database = sqladapter.New(db, sqladapter.Config{Dialect: t.dialect})
		return betterauth.New(cfg)
	}
	opts.Dialect = func() string { return resolved }
	return cli.Run(ctx, args, opts)
}
