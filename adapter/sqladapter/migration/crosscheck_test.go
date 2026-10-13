package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
)

// The cross-check tests share databases with the TypeScript implementation: a schema the
// TypeScript migrations created must leave an empty Go plan, and a schema the Go migrations
// created must leave an empty TypeScript plan. They drive e2e/scripts/gen-migration-fixtures.mjs
// in "crosscheck" mode and are skipped when node or e2e/node_modules is unavailable.

const e2eDir = "../../../e2e"

type crossJob struct {
	Config  string `json:"config"`
	Dialect string `json:"dialect"`
	URL     string `json:"url"`
	Action  string `json:"action"`
	// Spec replaces the configuration's options (used for "base").
	Spec json.RawMessage `json:"spec,omitempty"`
}

type crossResult struct {
	OK          bool         `json:"ok"`
	Error       string       `json:"error"`
	SQL         string       `json:"sql"`
	ToBeCreated []tableNames `json:"toBeCreated"`
	ToBeAdded   []tableNames `json:"toBeAdded"`
}

func requireNode(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed; skipping the TypeScript cross-check (install Node.js and run `npm install` in e2e/)")
	}
	for _, mod := range []string{"better-auth", "better-sqlite3", "pg", "mysql2", "kysely"} {
		if _, err := os.Stat(filepath.Join(e2eDir, "node_modules", mod)); err != nil {
			t.Skipf("e2e/node_modules/%s is missing; run `npm install` in e2e/ to enable the TypeScript cross-check", mod)
		}
	}
}

func runNode(t *testing.T, jobs []crossJob) []crossResult {
	t.Helper()
	in, err := json.Marshal(jobs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "scripts/gen-migration-fixtures.mjs", "crosscheck")
	cmd.Dir = e2eDir
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("node crosscheck: %v\n%s", err, stderr.String())
	}
	var results []crossResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("node crosscheck output: %v\n%s", err, stdout.String())
	}
	if len(results) != len(jobs) {
		t.Fatalf("node returned %d results for %d jobs", len(results), len(jobs))
	}
	return results
}

// crossConfigs are the configurations applied to a fresh database (with their setup SQL):
// those without a base migration, an expected error or an unappliable plan.
func crossConfigs(t *testing.T) []struct {
	cfg configSpec
	d   dialect.Dialect
} {
	var out []struct {
		cfg configSpec
		d   dialect.Dialect
	}
	errored := map[string]bool{}
	for _, fx := range loadFixtures(t) {
		if fx.Error != "" {
			errored[fx.Config+"/"+fx.Dialect] = true
		}
	}
	for _, cfg := range loadConfigs(t) {
		if cfg.Base != nil {
			continue
		}
		for _, d := range allDialects {
			if !cfg.runsOn(d) || !cfg.applies(d) || errored[cfg.Name+"/"+string(d)] {
				continue
			}
			out = append(out, struct {
				cfg configSpec
				d   dialect.Dialect
			}{cfg, d})
		}
	}
	return out
}

// TestCrossCheckTypeScriptToGo: tables created by the TypeScript migrations need no Go
// migration.
func TestCrossCheckTypeScriptToGo(t *testing.T) {
	requireNode(t)
	cases := crossConfigs(t)
	dbs := make([]testDB, len(cases))
	var jobs []crossJob
	for i, c := range cases {
		dbs[i] = openDB(t, c.d, c.cfg.SearchPath)
		dbs[i].exec(t, c.cfg.Setup[string(c.d)]...)
		jobs = append(jobs, crossJob{Config: c.cfg.Name, Dialect: string(c.d), URL: dbs[i].url, Action: "apply"})
	}
	results := runNode(t, jobs)
	for i, c := range cases {
		t.Run(c.cfg.Name+"/"+string(c.d), func(t *testing.T) {
			if results[i].Error != "" || !results[i].OK {
				t.Fatalf("TypeScript migration failed: %s", results[i].Error)
			}
			plan, err := planFor(t, dbs[i], c.cfg, c.cfg.Options, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Statements) != 0 || !plan.Empty() {
				t.Fatalf("Go plans changes on a TypeScript-migrated database:\n%s", compiled(plan))
			}
		})
	}
	t.Logf("%d configurations cross-checked", len(cases))
}

// TestCrossCheckGoToTypeScript: tables created by the Go migrations need no TypeScript
// migration.
func TestCrossCheckGoToTypeScript(t *testing.T) {
	requireNode(t)
	cases := crossConfigs(t)
	dbs := make([]testDB, len(cases))
	var jobs []crossJob
	for i, c := range cases {
		dbs[i] = openDB(t, c.d, c.cfg.SearchPath)
		dbs[i].exec(t, c.cfg.Setup[string(c.d)]...)
		apply(t, dbs[i], c.cfg, c.cfg.Options)
		jobs = append(jobs, crossJob{Config: c.cfg.Name, Dialect: string(c.d), URL: dbs[i].url, Action: "plan"})
	}
	results := runNode(t, jobs)
	for i, c := range cases {
		t.Run(c.cfg.Name+"/"+string(c.d), func(t *testing.T) {
			r := results[i]
			if r.Error != "" {
				t.Fatalf("TypeScript plan failed: %s", r.Error)
			}
			if r.SQL != ";" || len(r.ToBeCreated) != 0 || len(r.ToBeAdded) != 0 {
				t.Fatalf("TypeScript plans changes on a Go-migrated database:\n%s", r.SQL)
			}
		})
	}
	t.Logf("%d configurations cross-checked", len(cases))
}

// rawBase returns the "base" options of a configuration as JSON.
func rawBase(t *testing.T, name string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile("testdata/configs.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Configs []struct {
			Name string          `json:"name"`
			Base json.RawMessage `json:"base"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Configs {
		if c.Name == name {
			return c.Base
		}
	}
	t.Fatalf("no config %q", name)
	return nil
}

// partialConfigs are the configurations migrated in two steps (base, then options).
func partialConfigs(t *testing.T) []struct {
	cfg configSpec
	d   dialect.Dialect
} {
	var out []struct {
		cfg configSpec
		d   dialect.Dialect
	}
	errored := map[string]bool{}
	for _, fx := range loadFixtures(t) {
		if fx.Error != "" {
			errored[fx.Config+"/"+fx.Dialect] = true
		}
	}
	for _, cfg := range loadConfigs(t) {
		if cfg.Base == nil {
			continue
		}
		for _, d := range allDialects {
			if cfg.runsOn(d) && cfg.applies(d) && !errored[cfg.Name+"/"+string(d)] {
				out = append(out, struct {
					cfg configSpec
					d   dialect.Dialect
				}{cfg, d})
			}
		}
	}
	return out
}

// TestCrossCheckMixedUpgrade shares one database across an upgrade: one implementation
// creates the base schema, the other migrates it to the new configuration, and the first
// then finds nothing left to do — in both directions.
func TestCrossCheckMixedUpgrade(t *testing.T) {
	requireNode(t)
	cases := partialConfigs(t)

	// TypeScript creates the base, Go upgrades, TypeScript plans.
	tsBase := make([]testDB, len(cases))
	var jobs []crossJob
	for i, c := range cases {
		tsBase[i] = openDB(t, c.d, c.cfg.SearchPath)
		jobs = append(jobs, crossJob{Config: c.cfg.Name, Dialect: string(c.d), URL: tsBase[i].url, Action: "apply", Spec: rawBase(t, c.cfg.Name)})
	}
	for i, r := range runNode(t, jobs) {
		if !r.OK {
			t.Fatalf("%s/%s: TypeScript base migration failed: %s", cases[i].cfg.Name, cases[i].d, r.Error)
		}
	}
	jobs = nil
	for i, c := range cases {
		tsBase[i].exec(t, c.cfg.Setup[string(c.d)]...)
		apply(t, tsBase[i], c.cfg, c.cfg.Options)
		jobs = append(jobs, crossJob{Config: c.cfg.Name, Dialect: string(c.d), URL: tsBase[i].url, Action: "plan"})
	}
	for i, r := range runNode(t, jobs) {
		if r.Error != "" || r.SQL != ";" {
			t.Errorf("%s/%s: TypeScript plans changes after a Go upgrade of a TypeScript schema: %s%s", cases[i].cfg.Name, cases[i].d, r.Error, r.SQL)
		}
	}

	// Go creates the base, TypeScript upgrades, Go plans.
	goBase := make([]testDB, len(cases))
	jobs = nil
	for i, c := range cases {
		goBase[i] = openDB(t, c.d, c.cfg.SearchPath)
		apply(t, goBase[i], c.cfg, *c.cfg.Base)
		goBase[i].exec(t, c.cfg.Setup[string(c.d)]...)
		jobs = append(jobs, crossJob{Config: c.cfg.Name, Dialect: string(c.d), URL: goBase[i].url, Action: "apply"})
	}
	for i, r := range runNode(t, jobs) {
		if !r.OK {
			t.Fatalf("%s/%s: TypeScript upgrade failed: %s", cases[i].cfg.Name, cases[i].d, r.Error)
		}
	}
	for i, c := range cases {
		plan, err := planFor(t, goBase[i], c.cfg, c.cfg.Options, false, nil)
		if err != nil {
			t.Fatalf("%s/%s: %v", c.cfg.Name, c.d, err)
		}
		if len(plan.Statements) != 0 {
			t.Errorf("%s/%s: Go plans changes after a TypeScript upgrade of a Go schema:\n%s", c.cfg.Name, c.d, compiled(plan))
		}
	}
	t.Logf("%d upgrades cross-checked in both directions", len(cases))
}
