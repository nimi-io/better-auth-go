package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/migration"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func migrateCommand() *command {
	return &command{
		name:   "migrate",
		desc:   "Apply pending Better Auth schema changes to the database",
		config: true,
		options: []option{
			{short: "c", long: "cwd", arg: "cwd", desc: "the working directory. defaults to the current directory."},
			{short: "y", long: "yes", desc: "automatically accept and run migrations without prompting"},
			{long: "deprecated-y", desc: "(deprecated) same as --yes"},
		},
		run: (*runner).migrate,
	}
}

func adapterID(a *betterauth.Auth) string {
	if a == nil || a.Context() == nil || a.Context().Adapter == nil {
		return ""
	}
	return a.Context().Adapter.ID()
}

func (r *runner) migrate(fs *flag.FlagSet) int {
	if _, ok := checkCwd(r.stderr, str(fs, "cwd", "c")); !ok {
		return 1
	}
	auth, err := r.loadAuth("migrate")
	if err != nil {
		if errors.Is(err, ErrNoConfig) {
			fmt.Fprintln(r.stderr, err.Error())
			return 0
		}
		return r.fail(err)
	}
	plan, err := auth.PlanMigrations(r.ctx)
	if err != nil {
		var unsafe *migration.UnsafeMigrationError
		if errors.As(err, &unsafe) {
			return r.refuseUnsafe(unsafe.Message)
		}
		if errors.Is(err, adapter.ErrMigrationsNotSupported) {
			switch adapterID(auth) {
			case "prisma":
				fmt.Fprintf(r.stderr, "The migrate command only works with the built-in SQL adapter. For Prisma, run `%s generate` to create the schema, then use Prisma's migrate or push to apply it.\n", r.name)
				return 0
			case "drizzle":
				fmt.Fprintf(r.stderr, "The migrate command only works with the built-in SQL adapter. For Drizzle, run `%s generate` to create the schema, then use Drizzle's migrate or push to apply it.\n", r.name)
				return 0
			}
			fmt.Fprintln(r.stderr, "Migrate command isn't supported for this adapter.")
			return 1
		}
		return r.fail(err)
	}
	if len(plan.UnsafeChanges) > 0 {
		// a planner in report mode: refuse like upstream's UnsafeMigrationError
		return r.refuseUnsafe(plan.UnsafeChanges[0])
	}
	if problems := plan.SchemaProblems; len(problems) > 0 {
		noun := "columns"
		if len(problems) == 1 {
			noun = "column"
		}
		fmt.Fprintln(r.stderr, r.st.redBold(fmt.Sprintf("The database has %d %s Better Auth cannot write to. Nothing ran.", len(problems), noun)))
		for _, p := range problems {
			fmt.Fprintln(r.stderr, r.st.red("-> "+p))
		}
		return 1
	}
	indexes := plan.ToBeAddedIndexes
	if len(plan.ToBeAdded) == 0 && len(indexes) == 0 && len(plan.ToBeCreated) == 0 {
		fmt.Fprintln(r.stdout, "🚀 No migrations needed.")
		return 0
	}
	fmt.Fprintln(r.stdout, "🔑 The migration will affect the following:")
	for _, t := range append(append([]adapter.TableChange{}, plan.ToBeCreated...), plan.ToBeAdded...) {
		cols := make([]string, len(t.Fields))
		for i, f := range t.Fields {
			cols[i] = f.Column()
		}
		fmt.Fprintln(r.stdout, "->", r.st.magenta(strings.Join(cols, ", ")), r.st.white("fields on"), r.st.yellow(t.Table), r.st.white("table."))
	}
	for _, ix := range indexes {
		what := "fields indexed on"
		if ix.Unique {
			what = "fields in a unique index on"
		}
		fmt.Fprintln(r.stdout, "->", r.st.magenta(strings.Join(ix.Columns, ", ")), r.st.white(what), r.st.yellow(ix.Table), r.st.white("table."))
	}
	yes := boolean(fs, "yes", "y")
	if boolean(fs, "deprecated-y") {
		fmt.Fprintln(r.stderr, "WARNING: --y is deprecated. Consider -y or --yes")
		yes = true
	}
	if !yes {
		yes = r.confirm("Are you sure you want to run these migrations?")
	}
	if !yes {
		fmt.Fprintln(r.stdout, "Migration cancelled.")
		return 0
	}
	if err := plan.Run(r.ctx); err != nil {
		return r.fail(err)
	}
	fmt.Fprintln(r.stdout, "🚀 migration was completed successfully!")
	return 0
}

// refuseUnsafe reports a refused migration (UnsafeMigrationError upstream) and returns 1.
func (r *runner) refuseUnsafe(message string) int {
	fmt.Fprintln(r.stderr, r.st.red("The migration was refused, and nothing ran."))
	fmt.Fprintln(r.stderr, message)
	fmt.Fprintf(r.stderr, "Run %s to read the statements without executing them.\n", r.st.yellow(r.name+" generate"))
	return 1
}
