package adapter

import (
	"context"
	"errors"
	"strings"

	"github.com/nimi-io/better-auth-go/db"
)

// ErrMigrationsNotSupported is returned when the configured adapter cannot migrate its
// schema (upstream only supports migrations for the built-in Kysely adapter).
var ErrMigrationsNotSupported = errors.New("adapter: migrations are not supported by this adapter")

// TableChange is a pending schema change for one table (toBeCreated / toBeAdded upstream).
// Table is the physical table name; Fields are the fields to create or add.
type TableChange struct {
	Table  string
	Fields []db.Field
	Order  int
}

// IndexChange is a pending table-level index (toBeAddedIndexes upstream). Table is the
// physical table name and Columns the physical column names.
type IndexChange struct {
	Table   string
	Name    string
	Columns []string
	Unique  bool
}

// MigrationPlan is the result of comparing a schema with the database (getMigrations).
type MigrationPlan struct {
	ToBeCreated []TableChange
	ToBeAdded   []TableChange
	// ToBeAddedIndexes are the table-level indexes (schema "indexes") still missing.
	ToBeAddedIndexes []IndexChange
	// UnsafeChanges lists changes that cannot be applied safely (a required column without a
	// default added to a populated table) when the planner was asked to report rather than
	// refuse them.
	UnsafeChanges []string
	// SchemaProblems lists database columns the migration cannot fix: required, without a
	// default, and never written by Better Auth.
	SchemaProblems []string
	// Statements are the SQL statements that Run executes, in order.
	Statements []string
	// Exec executes the plan; set by the adapter that produced it.
	Exec func(ctx context.Context) error
}

// Empty reports whether the database is already up to date.
func (p *MigrationPlan) Empty() bool {
	return len(p.ToBeCreated) == 0 && len(p.ToBeAdded) == 0 && len(p.ToBeAddedIndexes) == 0
}

// SQL returns the migration as a SQL script exactly like compileMigrations: statements
// joined by ";\n\n" with a trailing ";" (just ";" when nothing is pending).
func (p *MigrationPlan) SQL() string {
	return strings.Join(p.Statements, ";\n\n") + ";"
}

// Run applies the plan (runMigrations).
func (p *MigrationPlan) Run(ctx context.Context) error {
	if p.Exec == nil || p.Empty() {
		return nil
	}
	return p.Exec(ctx)
}

// Migrator is an optional CustomAdapter capability: comparing a schema with the live
// database and producing the DDL to reconcile them.
type Migrator interface {
	PlanMigrations(ctx context.Context, schema *db.Schema) (*MigrationPlan, error)
}

// AsMigrator returns the Migrator behind an adapter created by NewFactory (or an adapter
// implementing Migrator itself).
func AsMigrator(a Adapter) (Migrator, bool) {
	if m, ok := a.(Migrator); ok {
		return m, true
	}
	if c, ok := a.(interface{ Custom() CustomAdapter }); ok {
		if m, ok := c.Custom().(Migrator); ok {
			return m, true
		}
	}
	return nil, false
}
