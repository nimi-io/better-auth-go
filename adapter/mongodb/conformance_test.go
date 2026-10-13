package mongodb_test

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/adaptertest"
	"github.com/nimi-io/better-auth-go/adapter/mongodb"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// Port of e2e/adapter/test/mongo-adapter/adapter.mongo-db.test.ts: the shared conformance
// suites run against MongoDB with the same per-adapter options (transaction: false, ObjectId
// custom id generator, no number-id suite). The adapter-specific suites of that file
// (update-object-id, compound-index) are ported in mongodb_test.go.
func TestConformance(t *testing.T) {
	database, _ := testdb.Mongo(t)
	no := false
	adaptertest.Run(t, adaptertest.Harness{
		Name: "MongoDB Adapter",
		Factory: func(testing.TB, *betterauth.Config) adapter.Factory {
			return mongodb.New(database, mongodb.Config{Transaction: &no})
		},
		// runMigrations is a no-op upstream: MongoDB has no schema.
		Migrate:           func(context.Context, *betterauth.Auth) error { return nil },
		CustomIDGenerator: func() string { return bson.NewObjectID().Hex() },
	},
		adaptertest.NormalSuite(),
		adaptertest.AuthFlowSuite(),
		adaptertest.TransactionsSuite(),
		adaptertest.JoinsSuite(),
		adaptertest.CaseInsensitiveSuite(),
		adaptertest.UUIDSuite(),
		// numberIdTestSuite: no support
	)
}

// The transactions suite again with real MongoDB transactions (client + transaction: true,
// the upstream default when a client is passed).
func TestConformanceWithTransactions(t *testing.T) {
	database, client := testdb.Mongo(t)
	adaptertest.Run(t, adaptertest.Harness{
		Name: "MongoDB Adapter (transactions)",
		Factory: func(testing.TB, *betterauth.Config) adapter.Factory {
			return mongodb.New(database, mongodb.Config{Client: client})
		},
		Migrate:           func(context.Context, *betterauth.Auth) error { return nil },
		CustomIDGenerator: func() string { return bson.NewObjectID().Hex() },
	},
		adaptertest.TransactionsSuite(),
	)
}
