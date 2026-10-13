package adaptertest

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// ---- e2e/adapter/test/adapter-factory/compound-index-test-suite.ts ----

// Names used by the compound index suite (compoundIndexName / compoundIndexTableName).
const (
	// CompoundIndexName is the name of the unique (issuer, providerSubject) index.
	CompoundIndexName = "compound_identity_uidx"
	// CompoundIndexTableName is the physical table of the compoundIndexSubject model.
	CompoundIndexTableName = "compound_index_subject"
	// CompoundIndexModel is the logical model key of the suite's table.
	CompoundIndexModel = "compoundIndexSubject"
)

// CompoundIndexPlugin is the "compound-index-workflow" plugin the suite migrates
// (compoundIndexBetterAuthOptions.plugins): the compoundIndexSubject model with renamed
// columns and a unique index over (issuer, providerSubject).
func CompoundIndexPlugin() *betterauth.Plugin {
	return schemaPlugin("compound-index-workflow", db.PluginTable{
		Key:       CompoundIndexModel,
		ModelName: CompoundIndexTableName,
		Fields: []db.Field{
			{Name: "issuer", Type: db.TypeString, FieldName: "issuer_url"},
			{Name: "providerSubject", Type: db.TypeString, FieldName: "provider_subject"},
			{Name: "displayName", Type: db.TypeString, FieldName: "display_name"},
		},
		Indexes: []db.Index{{
			Fields: []string{"issuer", "providerSubject"},
			Name:   CompoundIndexName,
			Unique: true,
		}},
	})
}

// compoundIndexConfig is compoundIndexBetterAuthOptions as a configuration fragment.
func compoundIndexConfig(c *betterauth.Config) {
	c.Plugins = append(c.Plugins, CompoundIndexPlugin())
}

// CompoundIndexOptions are the adapter hooks of the compound index suite
// (CompoundIndexTestSuiteOptions). Every hook is optional. The configuration passed to the
// hooks is the suite's current configuration: the harness defaults plus the
// compound-index-workflow plugin (upstream passes compoundIndexBetterAuthOptions); its
// Database is unset.
type CompoundIndexOptions struct {
	// RerunMigrations recompiles the pending migrations for cfg against the migrated
	// database and returns the SQL script (compileMigrations upstream: statements joined by
	// ";\n\n" plus a trailing ";"). Once the compound index exists nothing may be pending,
	// so the script must be ";" (surrounding whitespace is ignored).
	RerunMigrations func(ctx context.Context, cfg *betterauth.Config) (string, error)
	// MismatchError is the error VerifyMismatchedIndexRejected must fail with
	// (toThrow(mismatchError)). Use regexp.QuoteMeta for literal text (vitest's string form
	// matches a substring). nil accepts any error.
	MismatchError *regexp.Regexp
	// VerifyIndexState inspects the database after the writes, e.g. that the index named
	// CompoundIndexName exists on CompoundIndexTableName with the expected columns.
	VerifyIndexState func(ctx context.Context) error
	// VerifyMismatchedIndexRejected must fail when the database holds an index named
	// CompoundIndexName whose definition differs from the schema (typically by recreating
	// it with other columns and re-running the migration planner for cfg).
	VerifyMismatchedIndexRejected func(ctx context.Context, cfg *betterauth.Config) error
}

// CompoundIndexSuite is compoundIndexTestSuite: it checks that a schema-level compound
// unique index reaches the real database and is enforced there, then runs the adapter's
// migration hooks.
func CompoundIndexSuite(opts CompoundIndexOptions) Suite {
	return CreateTestSuite("compound-index", SuiteConfig{}, func() []Test {
		return []Test{
			{
				Name:              "enforces the configured tuple through the real database",
				MigrateBetterAuth: compoundIndexConfig,
				Fn: func(h *H) {
					createSubject := func(issuer, providerSubject, displayName string) (adapter.Record, error) {
						return h.Adapter.Create(h.Ctx, adapter.CreateInput{
							Model: CompoundIndexModel,
							Data:  R{"issuer": issuer, "providerSubject": providerSubject, "displayName": displayName},
						})
					}

					// Promise.all: the three distinct tuples are written concurrently.
					subjects := [][3]string{
						{"https://idp.example", "employee-1", "Ada"},
						{"https://idp.example", "employee-2", "Lin"},
						{"https://partner.example", "employee-1", "Kai"},
					}
					results := make([]adapter.Record, len(subjects))
					errs := make([]error, len(subjects))
					var wg sync.WaitGroup
					for i, s := range subjects {
						wg.Add(1)
						go func() {
							defer wg.Done()
							results[i], errs[i] = createSubject(s[0], s[1], s[2])
						}()
					}
					wg.Wait()
					for i, err := range errs {
						if err != nil {
							h.Fatalf("creating subject %v: %v", subjects[i], err)
						}
					}
					created := 0
					for _, r := range results {
						if r != nil {
							created++
						}
					}
					h.Equal(created, 3, "created subjects")

					if _, err := createSubject("https://idp.example", "employee-1", "Duplicate"); err == nil {
						h.Fatalf("creating a duplicate (issuer, providerSubject) tuple should fail")
					}

					if opts.RerunMigrations != nil {
						pending, err := opts.RerunMigrations(h.Ctx, h.Options())
						if err != nil {
							h.Fatalf("rerunMigrations: %v", err)
						}
						h.Equal(strings.TrimSpace(pending), ";", "pending migration")
					}

					if opts.VerifyIndexState != nil {
						if err := opts.VerifyIndexState(h.Ctx); err != nil {
							h.Fatalf("verifyIndexState: %v", err)
						}
					}

					if opts.VerifyMismatchedIndexRejected != nil {
						err := opts.VerifyMismatchedIndexRejected(h.Ctx, h.Options())
						if err == nil {
							h.Fatalf("verifyMismatchedIndexRejected should reject a mismatched index")
						}
						if opts.MismatchError != nil && !opts.MismatchError.MatchString(err.Error()) {
							h.Fatalf("verifyMismatchedIndexRejected error %q does not match %s", err.Error(), opts.MismatchError)
						}
					}
				},
			},
		}
	})()
}
