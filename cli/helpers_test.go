package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

var errStub = errors.New("fake adapter: not implemented")

// fakeSQL is a CustomAdapter that only plans migrations.
type fakeSQL struct {
	plan    func(schema *db.Schema) (*adapter.MigrationPlan, error)
	dialect string
	schema  *db.Schema
}

func (f *fakeSQL) Create(context.Context, string, string, adapter.Record) (adapter.Record, error) {
	return nil, errStub
}
func (f *fakeSQL) FindOne(context.Context, adapter.Query) (adapter.Record, error) {
	return nil, errStub
}
func (f *fakeSQL) FindMany(context.Context, adapter.Query) ([]adapter.Record, error) {
	return nil, errStub
}
func (f *fakeSQL) Count(context.Context, adapter.Query) (int64, error) { return 0, errStub }
func (f *fakeSQL) Update(context.Context, adapter.Query, adapter.Record) (adapter.Record, error) {
	return nil, errStub
}
func (f *fakeSQL) UpdateMany(context.Context, adapter.Query, adapter.Record) (int64, error) {
	return 0, errStub
}
func (f *fakeSQL) Delete(context.Context, adapter.Query) error { return errStub }
func (f *fakeSQL) DeleteMany(context.Context, adapter.Query) (int64, error) {
	return 0, errStub
}
func (f *fakeSQL) Dialect() string { return f.dialect }

func (f *fakeSQL) PlanMigrations(_ context.Context, schema *db.Schema) (*adapter.MigrationPlan, error) {
	f.schema = schema
	return f.plan(schema)
}

// fakeFactory returns an adapter factory whose migrations come from plan.
func fakeFactory(fake *fakeSQL) adapter.Factory {
	return adapter.NewFactory(adapter.Config{AdapterID: "kysely", AdapterName: "Fake SQL"},
		func(adapter.Options, adapter.Helpers) (adapter.CustomAdapter, error) { return fake, nil })
}

func newAuth(t *testing.T, cfg betterauth.Config) *betterauth.Auth {
	t.Helper()
	if cfg.Secret == "" && cfg.Secrets == nil {
		cfg.Secret = "a-test-secret-that-is-long-enough-1234"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:3000"
	}
	cfg.Logger = betterauth.NewLogger(betterauth.LevelError, nil)
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// pendingPlan is a plan that creates the user table and adds a column to session.
func pendingPlan(executed *int) func(*db.Schema) (*adapter.MigrationPlan, error) {
	return func(*db.Schema) (*adapter.MigrationPlan, error) {
		return &adapter.MigrationPlan{
			ToBeCreated: []adapter.TableChange{{Table: "user", Fields: []db.Field{{Name: "id"}, {Name: "name"}, {Name: "email"}}}},
			ToBeAdded:   []adapter.TableChange{{Table: "session", Fields: []db.Field{{Name: "ipAddress", FieldName: "ip_address"}}}},
			Statements: []string{
				`create table "user" ("id" text not null primary key, "name" text not null, "email" text not null)`,
				`alter table "session" add column "ip_address" text`,
			},
			Exec: func(context.Context) error {
				if executed != nil {
					*executed++
				}
				return nil
			},
		}, nil
	}
}

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, opts Options, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	opts.Stdout, opts.Stderr = &out, &errb
	opts.Stdin = strings.NewReader(stdin)
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC) }
	}
	code := Run(context.Background(), args, opts)
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func memoryAuth(t *testing.T) *betterauth.Auth {
	return newAuth(t, betterauth.Config{Database: memory.New()})
}

func contains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("output does not contain %q:\n%s", want, got)
	}
}

func notContains(t *testing.T, got, unwanted string) {
	t.Helper()
	if strings.Contains(got, unwanted) {
		t.Fatalf("output unexpectedly contains %q:\n%s", unwanted, got)
	}
}
