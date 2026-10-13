package adaptertest_test

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/adaptertest"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// tupleUnique wraps the memory adapter (which only enforces single-column uniqueness) with
// the compound unique index of the compound index suite, standing in for a real database.
type tupleUnique struct {
	adapter.Adapter
	mu *sync.Mutex
}

func (a tupleUnique) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if in.Model != adaptertest.CompoundIndexModel {
		return a.Adapter.Create(ctx, in)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	existing, err := a.Adapter.FindOne(ctx, adapter.FindOneInput{Model: in.Model, Where: []adapter.Where{
		{Field: "issuer", Value: in.Data["issuer"]},
		{Field: "providerSubject", Value: in.Data["providerSubject"]},
	}})
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("UNIQUE constraint failed: index %s", adaptertest.CompoundIndexName)
	}
	return a.Adapter.Create(ctx, in)
}

func hasCompoundIndex(cfg *betterauth.Config) bool {
	for _, p := range cfg.Plugins {
		for _, table := range p.Schema {
			for _, idx := range table.Indexes {
				if table.Key == adaptertest.CompoundIndexModel && idx.Name == adaptertest.CompoundIndexName && idx.Unique {
					return true
				}
			}
		}
	}
	return false
}

func TestCompoundIndexSuite(t *testing.T) {
	store := memory.NewDB()
	mu := &sync.Mutex{}
	var rerun, verified, mismatched bool
	adaptertest.Run(t, adaptertest.Harness{
		Name: "memory with compound unique index",
		Factory: func(testing.TB, *betterauth.Config) adapter.Factory {
			inner := memory.New(store)
			return func(opts adapter.Options) (adapter.Adapter, error) {
				ad, err := inner(opts)
				if err != nil {
					return nil, err
				}
				return tupleUnique{Adapter: ad, mu: mu}, nil
			}
		},
		Migrate: func(context.Context, *betterauth.Auth) error {
			store.Reset()
			return nil
		},
	}, adaptertest.CompoundIndexSuite(adaptertest.CompoundIndexOptions{
		RerunMigrations: func(_ context.Context, cfg *betterauth.Config) (string, error) {
			rerun = true
			if !hasCompoundIndex(cfg) {
				return "", errors.New("the compound index plugin is missing from the configuration")
			}
			return ";\n", nil
		},
		VerifyIndexState: func(context.Context) error {
			verified = true
			return nil
		},
		MismatchError: regexp.MustCompile(regexp.QuoteMeta(adaptertest.CompoundIndexName) + ` .*does not match`),
		VerifyMismatchedIndexRejected: func(_ context.Context, cfg *betterauth.Config) error {
			mismatched = true
			if !hasCompoundIndex(cfg) {
				return nil // makes the suite fail
			}
			return fmt.Errorf("index %s on %s does not match the schema", adaptertest.CompoundIndexName, adaptertest.CompoundIndexTableName)
		},
	}))
	if !rerun || !verified || !mismatched {
		t.Fatalf("hooks called: rerunMigrations=%v verifyIndexState=%v verifyMismatchedIndexRejected=%v", rerun, verified, mismatched)
	}
}
