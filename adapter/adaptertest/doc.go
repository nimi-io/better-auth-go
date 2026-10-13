// Package adaptertest is the shared database adapter conformance suite, a port of
// packages/test-utils/src/adapter (create-test-suite.ts, test-adapter.ts, cleanup.ts and
// suites/*) from Better Auth.
//
// Every adapter runs the same suites so their behaviour can be compared with upstream test
// for test. Test names are kept verbatim from the TypeScript sources; each suite is a
// subtest named after the upstream suite ("normal", "transactions", "auth-flow",
// "number-id", "joins", "uuid", "case-insensitive") and each case a subtest named after the
// upstream test ("create - should create a model", ...).
//
// # Usage
//
// An adapter package wires the suite from a _test.go file:
//
//	func TestConformance(t *testing.T) {
//		store := memory.NewDB()
//		adaptertest.Run(t, adaptertest.Harness{
//			Name: "memory",
//			Factory: func(t testing.TB, cfg *betterauth.Config) adapter.Factory {
//				return memory.New(store)
//			},
//			// Migrations start from an empty database (upstream recreates the store,
//			// deletes the SQLite file or drops the Postgres schema).
//			Migrate: func(ctx context.Context, auth *betterauth.Auth) error {
//				store.Reset()
//				return nil
//			},
//		},
//			adaptertest.NormalSuite(),
//			adaptertest.TransactionsSuite(adaptertest.SuiteOptions{DisableTests: adaptertest.DisableAll}),
//			adaptertest.AuthFlowSuite(),
//			adaptertest.NumberIDSuite(),
//			adaptertest.JoinsSuite(),
//			adaptertest.UUIDSuite(),
//			adaptertest.CaseInsensitiveSuite(),
//		)
//	}
//
// A SQL adapter typically drops and recreates its schema in Migrate and then calls
// auth.RunMigrations(ctx):
//
//	Migrate: func(ctx context.Context, auth *betterauth.Auth) error {
//		if _, err := conn.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
//			return err
//		}
//		return auth.RunMigrations(ctx)
//	},
//
// # Lifecycle (mirrors testAdapter / createTestSuite)
//
//   - Run migrates once with the default configuration (beforeAll) and hard-cleans every
//     auth table when it finishes (afterAll).
//   - Each suite first hard-cleans the tables and applies its default options (the
//     "header" test upstream), migrating when the suite sets AlwaysMigrate.
//   - Before a test runs, the configuration is reset to the suite defaults plus the test's
//     MigrateBetterAuth fragment and migrated whenever that fragment differs from the one
//     the previous test ran with. Tests may call H.ModifyOptions to change the
//     configuration (and migrate) themselves; such changes stay in effect for the following
//     tests exactly like upstream.
//   - After each test (pass or fail) every row created through H.Adapter (or by an Auth
//     instance obtained from H.GetAuth) is deleted again; rows whose model no longer
//     resolves are retried after the next test (cleanupRows).
//
// Harness.Factory is called whenever the configuration changes and after every migration,
// so it should be cheap (reuse connection pools). Harness.Migrate receives an Auth built from
// the current configuration with Database set to the factory; when nil, auth.RunMigrations
// is used and adapter.ErrMigrationsNotSupported is ignored.
//
// Per-adapter skips are expressed like upstream's disableTests option: pass
// SuiteOptions{DisableTests: map[string]bool{"<test name>": true}} (or DisableAll) to a suite
// constructor. A test explicitly mapped to false still runs when "ALL" is set.
//
// CompoundIndexSuite (e2e/adapter/test/adapter-factory/compound-index-test-suite.ts) is not
// part of AllSuites: it needs a database that enforces schema-level indexes and takes
// migration hooks (CompoundIndexOptions), so adapters opt in explicitly.
//
// Custom suites can be declared with CreateTestSuite; they receive an *H with the same
// helpers as the built-in suites (Generate, InsertRandom, SortModels, GetAuth, ...).
package adaptertest
