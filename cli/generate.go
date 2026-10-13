package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/migration"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

func generateCommand() *command {
	return &command{
		name:   "generate",
		desc:   "Generate the SQL migration for the Better Auth schema",
		config: true,
		options: []option{
			{short: "c", long: "cwd", arg: "cwd", desc: "the working directory. defaults to the current directory."},
			{long: "output", arg: "output", desc: "the file to output to the generated schema"},
			{long: "adapter", arg: "adapter", desc: "specify the adapter type (only kysely, the SQL generator, is available in Go)"},
			{long: "dialect", arg: "dialect", desc: "specify the database dialect/provider (used by the prisma and drizzle generators, which are not available in Go)"},
			{short: "y", long: "yes", desc: "automatically answer yes to all prompts"},
			{long: "deprecated-y", desc: "(deprecated) same as --yes"},
		},
		run: (*runner).generate,
	}
}

// isoTimestamp formats t like JavaScript's Date#toISOString with ":" replaced by "-".
func isoTimestamp(t time.Time) string {
	return strings.ReplaceAll(t.UTC().Format("2006-01-02T15:04:05.000Z"), ":", "-")
}

// defaultSchemaFileName is getDefaultSchemaOutputFileName.
func defaultSchemaFileName(adapterID string, now time.Time) string {
	switch adapterID {
	case "prisma":
		return "schema.prisma"
	case "kysely":
		return isoTimestamp(now) + ".sql"
	}
	return "auth-schema.ts"
}

// commentBanner is the warning prepended to scripts with unsafe changes (kysely generator).
func commentBanner(unsafe []string) string {
	rule := "-- " + strings.Repeat("-", 77)
	lines := []string{rule, "-- DO NOT RUN THIS SCRIPT AS IT IS.", "-- Applying it to a populated database corrupts the rows it touches:"}
	for _, c := range unsafe {
		lines = append(lines, "--", "-- "+c)
	}
	lines = append(lines, rule, "")
	return strings.Join(lines, "\n")
}

// generatorID maps the configured adapter to the generator upstream would pick: SQL
// adapters (adapter.Migrator) use the kysely generator.
func generatorID(a *betterauth.Auth) string {
	if a != nil && a.Context() != nil && a.Context().Adapter != nil {
		if _, ok := adapter.AsMigrator(a.Context().Adapter); ok {
			return "kysely"
		}
	}
	return adapterID(a)
}

func (r *runner) generate(fs *flag.FlagSet) int {
	cwd, ok := checkCwd(r.stderr, str(fs, "cwd", "c"))
	if !ok {
		return 1
	}
	output := str(fs, "output")
	now := r.now()
	auth, err := r.loadAuth("generate")
	if err != nil {
		if errors.Is(err, ErrNoConfig) {
			fmt.Fprintln(r.stderr, err.Error())
			return 0
		}
		return r.fail(err)
	}
	id := generatorID(auth)
	if a := str(fs, "adapter"); a != "" {
		id = a
	}
	if id == "prisma" || id == "drizzle" {
		return r.fail(fmt.Errorf("the %s generator is not available in the Go CLI (it emits a JavaScript ORM schema). Run `%s generate` without --adapter to write a SQL migration", id, r.name))
	}
	if id != "kysely" {
		return r.fail(fmt.Errorf("%s is not supported. If it is a custom adapter, please request the maintainer to implement adapter.Migrator on the adapter.", id))
	}
	resolvedOutput := ""
	if output != "" {
		resolvedOutput = resolve(cwd, output)
		if st, err := os.Stat(resolvedOutput); err == nil && st.IsDir() {
			output = filepath.Join(output, defaultSchemaFileName(id, now))
			resolvedOutput = resolve(cwd, output)
		}
	}
	plan, err := r.planReportingUnsafe(auth)
	if err != nil {
		if errors.Is(err, adapter.ErrMigrationsNotSupported) {
			return r.fail(fmt.Errorf("%s is not supported. If it is a custom adapter, please request the maintainer to implement adapter.Migrator on the adapter.", adapterID(auth)))
		}
		var refused *migration.UnsafeMigrationError
		if errors.As(err, &refused) {
			// The migrator cannot plan in report mode (throwOnUnsafe: false), so there is
			// no script to write; report the change the way upstream's warning does.
			r.warnUnsafe([]string{refused.Message})
			fmt.Fprintln(r.stderr, "The SQL adapter refused to compile the migration, so no script was written.")
			return 1
		}
		return r.fail(err)
	}
	unsafe := plan.UnsafeChanges
	problems := plan.SchemaProblems
	code := plan.SQL()
	if strings.TrimSpace(code) == ";" {
		code = ""
	}
	if len(unsafe) > 0 {
		code = commentBanner(unsafe) + code
	}
	fileName := resolvedOutput
	if fileName == "" {
		fileName = "./better-auth_migrations/" + isoTimestamp(now) + ".sql"
	}

	if len(problems) > 0 {
		what := "columns reject"
		if len(problems) == 1 {
			what = "column rejects"
		}
		fmt.Fprintln(r.stderr, r.st.redBold(fmt.Sprintf("⚠ %d %s every insert Better Auth makes. No migration fixes this.", len(problems), what)))
		for _, p := range problems {
			fmt.Fprintln(r.stderr, r.st.red("-> "+p))
		}
	}
	if len(unsafe) > 0 {
		r.warnUnsafe(unsafe)
		fmt.Fprintln(r.stderr, r.st.redBold("The generated script carries the same warning. Fix the reported columns before you run it."))
	}
	if code == "" {
		fmt.Fprintln(r.stdout, "Your schema is already up to date.")
		return 0
	}
	yes := boolean(fs, "yes", "y")
	if boolean(fs, "deprecated-y") {
		fmt.Fprintln(r.stderr, "WARNING: --y is deprecated. Consider -y or --yes")
		yes = true
	}
	if !yes {
		yes = r.confirm(fmt.Sprintf("Do you want to generate the schema to %s?", r.st.yellow(fileName)))
	}
	if !yes {
		fmt.Fprintln(r.stderr, "Schema generation aborted.")
		return 1
	}
	writePath := resolvedOutput
	if writePath == "" {
		writePath = filepath.Join(cwd, fileName)
	}
	if err := os.MkdirAll(filepath.Dir(writePath), 0o755); err != nil {
		return r.fail(err)
	}
	if err := os.WriteFile(writePath, []byte(code), 0o644); err != nil {
		return r.fail(err)
	}
	fmt.Fprintln(r.stdout, "🚀 Schema was generated successfully!")
	return 0
}

func (r *runner) warnUnsafe(unsafe []string) {
	what := "changes in this schema corrupt"
	if len(unsafe) == 1 {
		what = "change in this schema corrupts"
	}
	fmt.Fprintln(r.stderr, r.st.redBold(fmt.Sprintf("⚠ %d %s a populated database.", len(unsafe), what)))
	for _, c := range unsafe {
		fmt.Fprintln(r.stderr, r.st.red("-> "+c))
	}
}

// unsafeReporter is an optional adapter.Migrator capability: planning with unsafe changes
// reported in MigrationPlan.UnsafeChanges instead of refused (getMigrations(options,
// { throwOnUnsafe: false }), which upstream's generate uses).
type unsafeReporter interface {
	PlanMigrationsReportUnsafe(ctx context.Context, schema *db.Schema) (*adapter.MigrationPlan, error)
}

// planReportingUnsafe plans for generate: in report mode when the migrator supports it.
func (r *runner) planReportingUnsafe(auth *betterauth.Auth) (*adapter.MigrationPlan, error) {
	if ad := auth.Context().Adapter; ad != nil {
		if m, ok := adapter.AsMigrator(ad); ok {
			if rep, ok := m.(unsafeReporter); ok {
				return rep.PlanMigrationsReportUnsafe(r.ctx, ad.Schema())
			}
		}
	}
	return auth.PlanMigrations(r.ctx)
}

func resolve(cwd, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(cwd, p)
}
