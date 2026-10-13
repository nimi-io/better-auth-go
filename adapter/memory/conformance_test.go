package memory_test

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/adaptertest"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// Port of e2e/adapter/test/memory-adapter/adapter.memory.test.ts: the shared adapter
// conformance suites run against the memory adapter with the same per-adapter options.
func TestConformance(t *testing.T) {
	store := memory.NewDB()
	adaptertest.Run(t, adaptertest.Harness{
		Name: "Memory Adapter",
		Factory: func(testing.TB, *betterauth.Config) adapter.Factory {
			return memory.New(store)
		},
		// runMigrations replaces the store with empty tables upstream.
		Migrate: func(context.Context, *betterauth.Auth) error {
			store.Reset()
			return nil
		},
	},
		adaptertest.NormalSuite(),
		adaptertest.TransactionsSuite(adaptertest.SuiteOptions{DisableTests: adaptertest.DisableAll}),
		adaptertest.AuthFlowSuite(),
		adaptertest.NumberIDSuite(),
		adaptertest.JoinsSuite(),
		adaptertest.UUIDSuite(),
		adaptertest.CaseInsensitiveSuite(),
	)
}
