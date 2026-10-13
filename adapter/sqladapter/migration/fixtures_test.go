package migration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
)

// fixture is one entry of testdata/fixtures.json, produced by the TypeScript getMigrations
// of better-auth 1.7.7 (e2e/scripts/gen-migration-fixtures.mjs).
type fixture struct {
	Config             string        `json:"config"`
	Dialect            string        `json:"dialect"`
	Error              string        `json:"error"`
	SQL                string        `json:"sql"`
	ToBeCreated        []tableNames  `json:"toBeCreated"`
	ToBeAdded          []tableNames  `json:"toBeAdded"`
	ToBeAddedIndexes   []indexChange `json:"toBeAddedIndexes"`
	UnsafeChanges      []string      `json:"unsafeChanges"`
	SchemaProblems     []string      `json:"schemaProblems"`
	Warnings           []string      `json:"warnings"`
	AfterApply         *string       `json:"afterApply"`
	AfterApplyWarnings []string      `json:"afterApplyWarnings"`
}

type tableNames struct {
	Table  string   `json:"table"`
	Fields []string `json:"fields"`
}

type indexChange struct {
	Table   string   `json:"table"`
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique"`
}

func loadFixtures(t *testing.T) []fixture {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		BetterAuth string    `json:"betterAuth"`
		Fixtures   []fixture `json:"fixtures"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Fixtures
}

func names(changes []adapter.TableChange) []tableNames {
	out := []tableNames{}
	for _, c := range changes {
		tn := tableNames{Table: c.Table, Fields: []string{}}
		for _, f := range c.Fields {
			tn.Fields = append(tn.Fields, f.Column())
		}
		out = append(out, tn)
	}
	return out
}

func indexChanges(changes []adapter.IndexChange) []indexChange {
	out := []indexChange{}
	for _, c := range changes {
		out = append(out, indexChange{Table: c.Table, Name: c.Name, Columns: c.Columns, Unique: c.Unique})
	}
	return out
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// errorString renders an error like the fixture script: "<class>: <message>".
func errorString(err error) string {
	var unsafe *UnsafeMigrationError
	if errors.As(err, &unsafe) {
		return "UnsafeMigrationError: " + unsafe.Message
	}
	var schemaErr *SchemaError
	if errors.As(err, &schemaErr) {
		return "BetterAuthError: " + schemaErr.Message
	}
	return "Error: " + err.Error()
}

// TestFixtures verifies that Plan produces exactly what the TypeScript getMigrations
// produced for every configuration and dialect: the compiled SQL byte for byte, the
// toBeCreated / toBeAdded / toBeAddedIndexes lists, unsafe changes, schema problems, logged
// warnings and errors — and that applying the plan leaves nothing to do.
func TestFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	counts := map[string]int{}
	for _, fx := range fixtures {
		fx := fx
		cfg := findConfig(t, fx.Config)
		d := dialect.Dialect(fx.Dialect)
		counts[fx.Dialect]++
		t.Run(fx.Config+"/"+fx.Dialect, func(t *testing.T) {
			t.Parallel()
			tdb := openDB(t, d, cfg.SearchPath)
			if cfg.Base != nil {
				apply(t, tdb, cfg, *cfg.Base)
			}
			tdb.exec(t, cfg.Setup[fx.Dialect]...)
			w := &warnings{}
			plan, err := planFor(t, tdb, cfg, cfg.Options, cfg.ReportUnsafe, w)
			if fx.Error != "" {
				if err == nil {
					t.Fatalf("expected error %q, got plan:\n%s", fx.Error, compiled(plan))
				}
				if got := errorString(err); got != fx.Error {
					t.Fatalf("error mismatch\n got: %s\nwant: %s", got, fx.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if got := compiled(plan); got != fx.SQL {
				t.Fatalf("SQL mismatch\n--- got ---\n%s\n--- want ---\n%s", got, fx.SQL)
			}
			if got := plan.SQL(); got != fx.SQL {
				t.Fatalf("MigrationPlan.SQL() = %q", got)
			}
			check := func(what string, got, want any) {
				t.Helper()
				if !reflect.DeepEqual(got, want) {
					gj, _ := json.Marshal(got)
					wj, _ := json.Marshal(want)
					t.Errorf("%s mismatch\n got: %s\nwant: %s", what, gj, wj)
				}
			}
			check("toBeCreated", names(plan.ToBeCreated), orEmpty(fx.ToBeCreated))
			check("toBeAdded", names(plan.ToBeAdded), orEmpty(fx.ToBeAdded))
			check("toBeAddedIndexes", indexChanges(plan.ToBeAddedIndexes), orEmpty(fx.ToBeAddedIndexes))
			check("unsafeChanges", orEmpty(plan.UnsafeChanges), orEmpty(fx.UnsafeChanges))
			check("schemaProblems", orEmpty(plan.SchemaProblems), orEmpty(fx.SchemaProblems))
			check("warnings", orEmpty(w.msgs), orEmpty(fx.Warnings))
			if fx.AfterApply == nil {
				return
			}
			if err := plan.Run(context.Background()); err != nil {
				t.Fatalf("run: %v", err)
			}
			w2 := &warnings{}
			again, err := planFor(t, tdb, cfg, cfg.Options, false, w2)
			if err != nil {
				t.Fatalf("plan after apply: %v", err)
			}
			if got := compiled(again); got != *fx.AfterApply {
				t.Fatalf("plan after apply = %q, want %q", got, *fx.AfterApply)
			}
			check("warnings after apply", orEmpty(w2.msgs), orEmpty(fx.AfterApplyWarnings))
		})
	}
	t.Logf("fixtures per dialect: %v", counts)
}
