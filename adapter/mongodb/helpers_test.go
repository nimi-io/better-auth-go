package mongodb

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/internal/testdb"
)

// recorder captures the commands sent to one database (the vi.fn() mocks upstream).
type recorder struct {
	mu   sync.Mutex
	db   string
	cmds []recorded
}

type recorded struct {
	name string
	cmd  bson.Raw
}

func (r *recorder) started(_ context.Context, e *event.CommandStartedEvent) {
	if e.DatabaseName != r.db {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmds = append(r.cmds, recorded{name: e.CommandName, cmd: append(bson.Raw(nil), e.Command...)})
}

// named returns the recorded commands with the given name.
func (r *recorder) named(name string) []bson.Raw {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []bson.Raw
	for _, c := range r.cmds {
		if c.name == name {
			out = append(out, c.cmd)
		}
	}
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmds = nil
}

// env is a fresh database plus a second, monitored client on the same database.
type env struct {
	db       *mongo.Database // monitored handle
	plain    *mongo.Database // unmonitored handle (for assertions)
	client   *mongo.Client   // monitored client
	recorder *recorder
}

func newEnv(t *testing.T) *env {
	t.Helper()
	database, _ := testdb.Mongo(t)
	uri := os.Getenv("BA_TEST_MONGO_URI")
	if uri == "" {
		uri = testdb.DefaultMongoURI
	}
	rec := &recorder{db: database.Name()}
	client, err := mongo.Connect(options.Client().ApplyURI(uri).
		SetServerSelectionTimeout(3 * time.Second).
		SetMonitor(&event.CommandMonitor{Started: rec.started}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return &env{db: client.Database(database.Name()), plain: database, client: client, recorder: rec}
}

func schemaOf(o db.Options) *db.Schema { return db.GetAuthTables(o) }

func mustAdapter(t *testing.T, f adapter.Factory, opts adapter.Options) adapter.Adapter {
	t.Helper()
	if opts.Schema == nil {
		opts.Schema = schemaOf(db.Options{})
	}
	a, err := f(opts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// extJSON renders a BSON value as relaxed extended JSON.
func extJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := bson.MarshalExtJSON(bson.D{{Key: "v", Value: v}}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[len(`{"v":`) : len(b)-1])
}

// field returns a top-level field of a recorded command.
func field(t *testing.T, cmd bson.Raw, key string) bson.RawValue {
	t.Helper()
	v, err := cmd.LookupErr(key)
	if err != nil {
		t.Fatalf("command has no %q: %v", key, cmd)
	}
	return v
}

// rawDoc reads a stored document without any adapter transformation.
func rawDoc(t *testing.T, database *mongo.Database, coll string, filter any) bson.Raw {
	t.Helper()
	raw, err := database.Collection(coll).FindOne(context.Background(), filter).Raw()
	if err != nil {
		t.Fatalf("find %s %v: %v", coll, filter, err)
	}
	return raw
}

func oid(t *testing.T, hex string) bson.ObjectID {
	t.Helper()
	id, err := bson.ObjectIDFromHex(hex)
	if err != nil {
		t.Fatalf("not an ObjectId: %q", hex)
	}
	return id
}

func boolp(b bool) *bool { return &b }
