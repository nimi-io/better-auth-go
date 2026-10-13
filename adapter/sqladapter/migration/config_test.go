package migration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// This file turns testdata/configs.json (shared with e2e/scripts/gen-migration-fixtures.mjs)
// into db.Options, and opens the per-dialect test databases.

// ordered is a JSON object that keeps its key order (JavaScript object semantics).
type ordered []struct {
	Key   string
	Value json.RawMessage
}

func (o *ordered) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("expected object, got %v", tok)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		*o = append(*o, struct {
			Key   string
			Value json.RawMessage
		}{tok.(string), raw})
	}
	return nil
}

type fieldSpec struct {
	Type       json.RawMessage `json:"type"`
	Required   *bool           `json:"required"`
	Unique     bool            `json:"unique"`
	Index      bool            `json:"index"`
	Sortable   bool            `json:"sortable"`
	BigInt     bool            `json:"bigint"`
	FieldName  string          `json:"fieldName"`
	References *struct {
		Model    string `json:"model"`
		Field    string `json:"field"`
		OnDelete string `json:"onDelete"`
	} `json:"references"`
	DefaultValue json.RawMessage `json:"defaultValue"`
}

func (s fieldSpec) toField(name string) (db.Field, error) {
	f := db.Field{Name: name, FieldName: s.FieldName, Unique: s.Unique, Index: s.Index, Sortable: s.Sortable, BigInt: s.BigInt}
	// A field without "required" is required, as upstream (required !== false).
	f.Required = s.Required
	var typ string
	if err := json.Unmarshal(s.Type, &typ); err != nil {
		var enum []string
		if err := json.Unmarshal(s.Type, &enum); err != nil {
			return f, fmt.Errorf("field %s: bad type %s", name, s.Type)
		}
		f.Type, f.Enum = db.TypeEnum, enum
	} else {
		f.Type = db.FieldType(typ)
	}
	if s.References != nil {
		f.References = &db.Reference{Model: s.References.Model, Field: s.References.Field, OnDelete: s.References.OnDelete}
	}
	if len(s.DefaultValue) > 0 {
		var fn struct {
			Fn string `json:"$fn"`
		}
		if s.DefaultValue[0] == '{' && json.Unmarshal(s.DefaultValue, &fn) == nil && fn.Fn != "" {
			if fn.Fn == "date" {
				f.DefaultFunc = func() any { return time.Now() }
			} else {
				f.DefaultFunc = func() any { return time.Now().UnixMilli() }
			}
		} else {
			dec := json.NewDecoder(bytes.NewReader(s.DefaultValue))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err != nil {
				return f, err
			}
			if n, ok := v.(json.Number); ok {
				if i, err := n.Int64(); err == nil {
					v = i
				} else {
					v, _ = n.Float64()
				}
			}
			f.DefaultValue = v
		}
	}
	return f, nil
}

func parseFields(o ordered) ([]db.Field, error) {
	var out []db.Field
	for _, kv := range o {
		var s fieldSpec
		if err := json.Unmarshal(kv.Value, &s); err != nil {
			return nil, err
		}
		f, err := s.toField(kv.Key)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

type modelSpec struct {
	ModelName        string            `json:"modelName"`
	Fields           map[string]string `json:"fields"`
	AdditionalFields ordered           `json:"additionalFields"`
	Storage          string            `json:"storage"`
}

type pluginTableSpec struct {
	ModelName        string  `json:"modelName"`
	Fields           ordered `json:"fields"`
	DisableMigration bool    `json:"disableMigration"`
	Indexes          []struct {
		Fields []string `json:"fields"`
		Name   string   `json:"name"`
		Unique bool     `json:"unique"`
	} `json:"indexes"`
}

type optionsSpec struct {
	User         *modelSpec `json:"user"`
	Session      *modelSpec `json:"session"`
	Account      *modelSpec `json:"account"`
	Verification *modelSpec `json:"verification"`
	RateLimit    *modelSpec `json:"rateLimit"`
	Advanced     *struct {
		Database struct {
			GenerateID string `json:"generateId"`
		} `json:"database"`
	} `json:"advanced"`
	Plugins []struct {
		ID     string  `json:"id"`
		Schema ordered `json:"schema"`
	} `json:"plugins"`
}

// schema builds the db.Schema and id mode for an options spec (what betterauth.GetSchema
// does for the equivalent Config).
func (o optionsSpec) schema() (*db.Schema, adapter.IDMode, error) {
	var opts db.Options
	model := func(m *modelSpec) (db.ModelOptions, error) {
		if m == nil {
			return db.ModelOptions{}, nil
		}
		fields, err := parseFields(m.AdditionalFields)
		return db.ModelOptions{ModelName: m.ModelName, Fields: m.Fields, AdditionalFields: fields}, err
	}
	var err error
	if opts.User, err = model(o.User); err != nil {
		return nil, "", err
	}
	if opts.Session, err = model(o.Session); err != nil {
		return nil, "", err
	}
	if opts.Account, err = model(o.Account); err != nil {
		return nil, "", err
	}
	if opts.Verification, err = model(o.Verification); err != nil {
		return nil, "", err
	}
	if o.RateLimit != nil && o.RateLimit.Storage == "database" {
		opts.RateLimitInDatabase = true
		if opts.RateLimit, err = model(o.RateLimit); err != nil {
			return nil, "", err
		}
	}
	for _, p := range o.Plugins {
		var tables []db.PluginTable
		for _, kv := range p.Schema {
			var t pluginTableSpec
			if err := json.Unmarshal(kv.Value, &t); err != nil {
				return nil, "", err
			}
			fields, err := parseFields(t.Fields)
			if err != nil {
				return nil, "", err
			}
			pt := db.PluginTable{Key: kv.Key, ModelName: t.ModelName, Fields: fields, DisableMigration: t.DisableMigration}
			for _, ix := range t.Indexes {
				pt.Indexes = append(pt.Indexes, db.Index{Fields: ix.Fields, Name: ix.Name, Unique: ix.Unique})
			}
			tables = append(tables, pt)
		}
		opts.Plugins = append(opts.Plugins, tables)
	}
	mode := adapter.IDDefault
	if o.Advanced != nil {
		mode = adapter.IDMode(o.Advanced.Database.GenerateID)
	}
	return db.GetAuthTables(opts), mode, nil
}

type configSpec struct {
	Name         string              `json:"name"`
	Dialects     []string            `json:"dialects"`
	SchemaName   string              `json:"schemaName"`
	SearchPath   string              `json:"searchPath"`
	Base         *optionsSpec        `json:"base"`
	Setup        map[string][]string `json:"setup"`
	Options      optionsSpec         `json:"options"`
	ReportUnsafe bool                `json:"reportUnsafe"`
	SkipApply    []string            `json:"skipApply"`
}

func (c configSpec) runsOn(d dialect.Dialect) bool {
	if len(c.Dialects) == 0 {
		return true
	}
	return contains(c.Dialects, string(d))
}

func (c configSpec) applies(d dialect.Dialect) bool { return !contains(c.SkipApply, string(d)) }

var (
	configsOnce sync.Once
	configsList []configSpec
	configsErr  error
)

func loadConfigs(t *testing.T) []configSpec {
	t.Helper()
	configsOnce.Do(func() {
		data, err := os.ReadFile("testdata/configs.json")
		if err != nil {
			configsErr = err
			return
		}
		var file struct {
			Configs []configSpec `json:"configs"`
		}
		configsErr = json.Unmarshal(data, &file)
		configsList = file.Configs
	})
	if configsErr != nil {
		t.Fatal(configsErr)
	}
	return configsList
}

func findConfig(t *testing.T, name string) configSpec {
	t.Helper()
	for _, c := range loadConfigs(t) {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no config %q", name)
	return configSpec{}
}

var allDialects = []dialect.Dialect{dialect.SQLite, dialect.Postgres, dialect.MySQL}

// testDB is a fresh database: an open handle and the URL node uses to reach it.
type testDB struct {
	d    dialect.Dialect
	conn *sql.DB
	url  string
}

// openDB creates a fresh database. searchPath sets the PostgreSQL search_path of the
// connection.
func openDB(t *testing.T, d dialect.Dialect, searchPath string) testDB {
	t.Helper()
	switch d {
	case dialect.SQLite:
		path := testdb.SQLitePath(t)
		conn, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return testDB{d: d, conn: conn, url: path}
	case dialect.Postgres:
		raw := testdb.PostgresURL(t)
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if searchPath != "" {
			q := u.Query()
			q.Set("search_path", searchPath)
			u.RawQuery = q.Encode()
		}
		conn, err := sql.Open("pgx", u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return testDB{d: d, conn: conn, url: u.String()}
	case dialect.MySQL:
		dsn := testdb.MySQLDSN(t)
		conn, err := sql.Open("mysql", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u := url.URL{Scheme: "mysql", User: url.UserPassword(cfg.User, cfg.Passwd), Host: cfg.Addr, Path: "/" + cfg.DBName}
		return testDB{d: d, conn: conn, url: u.String()}
	case dialect.MSSQL:
		return testDB{d: d, conn: emptyDB(t)}
	}
	t.Fatalf("unsupported dialect %s", d)
	return testDB{}
}

func (tdb testDB) exec(t *testing.T, statements ...string) {
	t.Helper()
	for _, s := range statements {
		if _, err := tdb.conn.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// warnings collects Logger.Warn messages.
type warnings struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnings) Warn(msg string, _ ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, msg)
}

func (w *warnings) Error(msg string, _ ...any) {}

func (w *warnings) has(sub string) bool {
	for _, m := range w.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// planFor plans spec against tdb.
func planFor(t *testing.T, tdb testDB, cfg configSpec, spec optionsSpec, reportUnsafe bool, logger Logger) (*adapter.MigrationPlan, error) {
	t.Helper()
	schema, mode, err := spec.schema()
	if err != nil {
		t.Fatal(err)
	}
	return Plan(context.Background(), tdb.conn, schema, Options{
		Dialect: tdb.d, SchemaName: cfg.SchemaName, IDMode: mode, ReportUnsafe: reportUnsafe, Logger: logger,
	})
}

// apply plans and runs spec against tdb.
func apply(t *testing.T, tdb testDB, cfg configSpec, spec optionsSpec) {
	t.Helper()
	plan, err := planFor(t, tdb, cfg, spec, false, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := plan.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// compiled is compileMigrations: the statements joined by ";\n\n" with a trailing ";" (";"
// for an empty plan).
func compiled(p *adapter.MigrationPlan) string {
	return strings.Join(p.Statements, ";\n\n") + ";"
}
