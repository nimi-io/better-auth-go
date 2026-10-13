package sqladapter_test

import (
	"context"
	"database/sql"
	"regexp"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/adaptertest"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// Ports of e2e/adapter/test/kysely-adapter/adapter.kysely.{pg,mysql,sqlite}.test.ts: every
// shared suite runs against each dialect, and each migration starts from an empty database
// (upstream drops the public schema, recreates the MySQL database or deletes the SQLite file).
func runConformance(t *testing.T, name string, conn *sql.DB, d sqladapter.Dialect, reset func(ctx context.Context) error, mismatch []string, caseOpts ...adaptertest.SuiteOptions) {
	yes := true
	adaptertest.Run(t, adaptertest.Harness{
		Name: name,
		Factory: func(testing.TB, *betterauth.Config) adapter.Factory {
			return sqladapter.New(conn, sqladapter.Config{Dialect: d, Transaction: &yes})
		},
		Migrate: func(ctx context.Context, auth *betterauth.Auth) error {
			if err := reset(ctx); err != nil {
				return err
			}
			return auth.RunMigrations(ctx)
		},
	},
		adaptertest.NormalSuite(),
		adaptertest.TransactionsSuite(),
		adaptertest.AuthFlowSuite(),
		adaptertest.NumberIDSuite(),
		adaptertest.JoinsSuite(),
		adaptertest.UUIDSuite(),
		adaptertest.CaseInsensitiveSuite(caseOpts...),
		compoundIndexSuite(conn, d, mismatch),
	)
}

// compoundIndexSuite wires compound-index-test-suite.ts like upstream's Kysely files:
// migrations re-plan against the live database, and a hand-made index with the configured
// name but other columns must make the planner fail. mismatch holds the SQL that replaces
// the index (first half) and restores it (second half).
func compoundIndexSuite(conn *sql.DB, d sqladapter.Dialect, mismatch []string) adaptertest.Suite {
	plan := func(ctx context.Context, cfg *betterauth.Config) (*adapter.MigrationPlan, error) {
		c := *cfg
		c.Database = sqladapter.New(conn, sqladapter.Config{Dialect: d})
		auth, err := betterauth.New(c)
		if err != nil {
			return nil, err
		}
		return auth.PlanMigrations(ctx)
	}
	exec := func(ctx context.Context, stmts []string) error {
		for _, q := range stmts {
			if _, err := conn.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}
	return adaptertest.CompoundIndexSuite(adaptertest.CompoundIndexOptions{
		RerunMigrations: func(ctx context.Context, cfg *betterauth.Config) (string, error) {
			p, err := plan(ctx, cfg)
			if err != nil {
				return "", err
			}
			return p.SQL(), p.Run(ctx)
		},
		MismatchError: regexp.MustCompile(regexp.QuoteMeta(`Database index "compound_identity_uidx" on table "compound_index_subject" does not match the configured fields and uniqueness.`)),
		VerifyMismatchedIndexRejected: func(ctx context.Context, cfg *betterauth.Config) error {
			half := len(mismatch) / 2
			if err := exec(ctx, mismatch[:half]); err != nil {
				return err
			}
			_, planErr := plan(ctx, cfg)
			if err := exec(ctx, mismatch[half:]); err != nil {
				return err
			}
			return planErr
		},
	})
}

var quotedMismatch = []string{
	`DROP INDEX "compound_identity_uidx"`,
	`CREATE INDEX "compound_identity_uidx" ON "compound_index_subject" ("provider_subject")`,
	`DROP INDEX IF EXISTS "compound_identity_uidx"`,
	`CREATE UNIQUE INDEX "compound_identity_uidx" ON "compound_index_subject" ("issuer_url", "provider_subject")`,
}

func TestConformancePostgres(t *testing.T) {
	// The suites recreate the same tables with different id column types (text, integer,
	// uuid). pgx's default statement cache keeps parameter types across those schema
	// changes, which real deployments never make, so the cache is disabled here.
	conn, err := sql.Open("pgx", testdb.PostgresURL(t)+"&default_query_exec_mode=exec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	runConformance(t, "pg", conn, sqladapter.Postgres, func(ctx context.Context) error {
		if _, err := conn.ExecContext(ctx, `DROP SCHEMA public CASCADE`); err != nil {
			return err
		}
		_, err := conn.ExecContext(ctx, `CREATE SCHEMA public`)
		return err
	}, quotedMismatch)
}

func TestConformanceMySQL(t *testing.T) {
	conn := testdb.MySQL(t)
	runConformance(t, "mysql", conn, sqladapter.MySQL, func(ctx context.Context) error {
		return dropAllTables(ctx, conn, "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()",
			"SET FOREIGN_KEY_CHECKS = 0", "SET FOREIGN_KEY_CHECKS = 1", "`")
	}, []string{
		"ALTER TABLE `compound_index_subject` DROP INDEX `compound_identity_uidx`",
		"CREATE INDEX `compound_identity_uidx` ON `compound_index_subject` (`provider_subject`)",
		"ALTER TABLE `compound_index_subject` DROP INDEX `compound_identity_uidx`",
		"CREATE UNIQUE INDEX `compound_identity_uidx` ON `compound_index_subject` (`issuer_url`, `provider_subject`)",
	},
		// MySQL's default collation compares case-insensitively; upstream disables this case
		// too. (Upstream also disables the transactions suite on MySQL; it passes here.)
		adaptertest.SuiteOptions{DisableTests: map[string]bool{
			"findOne - eq with mode sensitive (default) should not match different case": true,
		}})
}

func TestConformanceSQLite(t *testing.T) {
	conn := testdb.SQLite(t)
	runConformance(t, "sqlite", conn, sqladapter.SQLite, func(ctx context.Context) error {
		return dropAllTables(ctx, conn, "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
			"PRAGMA foreign_keys = OFF", "PRAGMA foreign_keys = ON", `"`)
	}, quotedMismatch)
}

// dropAllTables drops every table on one connection with foreign key checks disabled.
func dropAllTables(ctx context.Context, db *sql.DB, list, disable, enable, quote string) error {
	c, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	rows, err := c.QueryContext(ctx, list)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, n)
	}
	rows.Close()
	if _, err := c.ExecContext(ctx, disable); err != nil {
		return err
	}
	for _, tbl := range tables {
		if _, err := c.ExecContext(ctx, "DROP TABLE IF EXISTS "+quote+tbl+quote); err != nil {
			return err
		}
	}
	_, err = c.ExecContext(ctx, enable)
	return err
}
