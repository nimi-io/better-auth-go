package mongodb

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
)

// Ports of packages/mongo-adapter/src/mongodb-adapter.test.ts. Upstream mocks the Db object;
// these tests run against a real MongoDB and observe the commands with a command monitor.

func directorySchema(disable bool, fieldNames bool) *db.Schema {
	conn := db.Field{Name: "connectionId", Type: db.TypeString}
	ext := db.Field{Name: "externalId", Type: db.TypeString}
	model := ""
	if fieldNames {
		conn.FieldName, ext.FieldName, model = "connection_id", "external_id", "directory_user"
	}
	return schemaOf(db.Options{Plugins: [][]db.PluginTable{{{
		Key: "directoryUser", ModelName: model, DisableMigration: disable,
		Fields:  []db.Field{conn, ext},
		Indexes: []db.Index{{Fields: []string{"connectionId", "externalId"}, Unique: true}},
	}}}})
}

func TestShouldCreateMongoDBAdapter(t *testing.T) {
	e := newEnv(t)
	f := New(e.db, Config{})
	if f == nil {
		t.Fatal("factory is nil")
	}
	a := mustAdapter(t, f, adapter.Options{})
	if a.ID() != "mongodb-adapter" {
		t.Fatalf("id %q", a.ID())
	}
}

func TestCreatesConfiguredCompoundIndexesBeforeTheFirstWrite(t *testing.T) {
	e := newEnv(t)
	reg := newIndexRegistry()
	release := make(chan struct{})
	var calls atomic.Int32
	type call struct {
		coll   string
		keys   string
		name   string
		unique bool
	}
	called := make(chan call, 4)
	reg.create = func(ctx context.Context, coll *mongo.Collection, keys bson.D, name string, unique bool) error {
		calls.Add(1)
		called <- call{coll.Name(), extJSON(t, keys), name, unique}
		<-release
		return defaultCreateIndex(ctx, coll, keys, name, unique)
	}
	a := mustAdapter(t, newFactory(e.db, Config{Transaction: boolp(false)}, reg), adapter.Options{Schema: directorySchema(false, true)})
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, ext := range []string{"employee-1", "employee-2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = a.Create(ctx, adapter.CreateInput{Model: "directoryUser", Data: adapter.Record{"connectionId": "okta", "externalId": ext}})
		}()
	}
	select {
	case c := <-called:
		if c.coll != "directory_user" || c.keys != `{"connection_id":1,"external_id":1}` ||
			c.name != "directory_user_connection_id_external_id_uidx" || !c.unique {
			t.Fatalf("createIndex called with %+v", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("createIndex was not called")
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(e.recorder.named("insert")); n != 0 {
		t.Fatalf("insertOne ran before the index setup resolved (%d inserts)", n)
	}
	if calls.Load() != 1 {
		t.Fatalf("createIndex called %d times", calls.Load())
	}
	close(release)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("createIndex called %d times", calls.Load())
	}
	if n := len(e.recorder.named("insert")); n != 2 {
		t.Fatalf("expected 2 inserts, got %d", n)
	}
	// the unique index is really there
	_, err := a.Create(ctx, adapter.CreateInput{Model: "directoryUser", Data: adapter.Record{"connectionId": "okta", "externalId": "employee-1"}})
	if !mongo.IsDuplicateKeyError(err) {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestResolvesConfiguredIndexesOncePerModel(t *testing.T) {
	e := newEnv(t)
	var resolves atomic.Int32
	orig := resolveIndexes
	resolveIndexes = func(tb *db.Table, name string) ([]resolvedIndex, error) {
		resolves.Add(1)
		return orig(tb, name)
	}
	t.Cleanup(func() { resolveIndexes = orig })
	reg := newIndexRegistry()
	var creates atomic.Int32
	reg.create = func(ctx context.Context, coll *mongo.Collection, keys bson.D, name string, unique bool) error {
		creates.Add(1)
		return defaultCreateIndex(ctx, coll, keys, name, unique)
	}
	a := mustAdapter(t, newFactory(e.db, Config{Transaction: boolp(false)}, reg), adapter.Options{Schema: directorySchema(false, false)})
	ctx := context.Background()
	if _, err := a.Create(ctx, adapter.CreateInput{Model: "directoryUser", Data: adapter.Record{"connectionId": "okta", "externalId": "employee-1"}}); err != nil {
		t.Fatal(err)
	}
	after := resolves.Load()
	if _, err := a.Create(ctx, adapter.CreateInput{Model: "directoryUser", Data: adapter.Record{"connectionId": "okta", "externalId": "employee-2"}}); err != nil {
		t.Fatal(err)
	}
	if resolves.Load() != after {
		t.Fatalf("indexes resolved again (%d → %d)", after, resolves.Load())
	}
	if creates.Load() != 1 || len(e.recorder.named("insert")) != 2 {
		t.Fatalf("createIndex %d, inserts %d", creates.Load(), len(e.recorder.named("insert")))
	}
}

func TestDoesNotCreateIndexesForTablesWithMigrationsDisabled(t *testing.T) {
	e := newEnv(t)
	a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{Schema: directorySchema(true, false)})
	if _, err := a.Create(context.Background(), adapter.CreateInput{Model: "directoryUser", Data: adapter.Record{"connectionId": "okta", "externalId": "employee-1"}}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.recorder.named("createIndexes")); n != 0 {
		t.Fatalf("createIndexes sent %d times", n)
	}
	if n := len(e.recorder.named("insert")); n != 1 {
		t.Fatalf("inserts %d", n)
	}
}

func TestAllowsDuplicateCleanupBeforeTheFirstIndexEnforcingMutation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := e.plain.Collection("directoryUser").InsertOne(ctx, bson.D{{Key: "connectionId", Value: "duplicate"}, {Key: "externalId", Value: "x"}}); err != nil {
			t.Fatal(err)
		}
	}
	a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{Schema: directorySchema(false, false)})
	n, err := a.DeleteMany(ctx, "directoryUser", []adapter.Where{{Field: "connectionId", Value: "duplicate"}})
	if err != nil || n != 2 {
		t.Fatalf("deleteMany = %d, %v", n, err)
	}
	if c := len(e.recorder.named("createIndexes")); c != 0 {
		t.Fatalf("createIndexes sent %d times", c)
	}
	if c := len(e.recorder.named("delete")); c != 1 {
		t.Fatalf("delete sent %d times", c)
	}
}

func TestConsumeOneReturnsTheDeletedDocument(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.plain.Collection("verification").InsertOne(ctx, bson.D{{Key: "_id", Value: "verification-id"}, {Key: "identifier", Value: "magic-link-token"}}); err != nil {
		t.Fatal(err)
	}
	a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{})
	res, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "identifier", Value: "magic-link-token"}})
	if err != nil {
		t.Fatal(err)
	}
	if res["id"] != "verification-id" || res["identifier"] != "magic-link-token" {
		t.Fatalf("result %v", res)
	}
	cmds := e.recorder.named("findAndModify")
	if len(cmds) != 1 {
		t.Fatalf("findAndModify sent %d times", len(cmds))
	}
	if q := extJSON(t, field(t, cmds[0], "query")); q != `{"identifier":"magic-link-token"}` {
		t.Fatalf("query %s", q)
	}
	if !field(t, cmds[0], "remove").Boolean() {
		t.Fatal("expected remove: true")
	}
	again, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "identifier", Value: "magic-link-token"}})
	if err != nil || again != nil {
		t.Fatalf("second consume = %v, %v", again, err)
	}
}

func rateLimitAdapter(t *testing.T, e *env) adapter.Adapter {
	return mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{Schema: schemaOf(db.Options{RateLimitInDatabase: true})})
}

func insertCounter(t *testing.T, e *env, doc bson.D) {
	t.Helper()
	if _, err := e.plain.Collection("rateLimit").InsertOne(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementOneAppliesIncAndSetAtomicallyAgainstTheGuardFilter(t *testing.T) {
	e := newEnv(t)
	insertCounter(t, e, bson.D{{Key: "_id", Value: "counter-id"}, {Key: "key", Value: "a"}, {Key: "count", Value: int32(3)}, {Key: "lastRequest", Value: float64(1)}})
	a := rateLimitAdapter(t, e)
	res, err := a.IncrementOne(context.Background(), adapter.IncrementInput{
		Model: "rateLimit", Where: []adapter.Where{{Field: "count", Value: 5, Operator: adapter.Lt}},
		Increment: map[string]float64{"count": 1}, Set: adapter.Record{"lastRequest": int64(1700000000000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res["id"] != "counter-id" || res["count"] != int64(4) || res["lastRequest"] != int64(1700000000000) {
		t.Fatalf("result %v", res)
	}
	cmds := e.recorder.named("findAndModify")
	if len(cmds) != 1 {
		t.Fatalf("findAndModify sent %d times", len(cmds))
	}
	if q := extJSON(t, field(t, cmds[0], "query")); q != `{"count":{"$lt":5}}` {
		t.Fatalf("query %s", q)
	}
	if u := extJSON(t, field(t, cmds[0], "update")); u != `{"$inc":{"count":1},"$set":{"lastRequest":1.7E+12}}` {
		t.Fatalf("update %s", u)
	}
	if !field(t, cmds[0], "new").Boolean() {
		t.Fatal(`expected returnDocument: "after"`)
	}
	// $inc keeps the int32 encoding the Node.js driver uses
	raw := rawDoc(t, e.plain, "rateLimit", bson.D{{Key: "_id", Value: "counter-id"}})
	if typ := raw.Lookup("count").Type; typ != bson.TypeInt32 {
		t.Fatalf("count stored as %v", typ)
	}
}

func TestIncrementOneOmitsSetWhenNoAbsoluteAssignmentsAreProvided(t *testing.T) {
	e := newEnv(t)
	insertCounter(t, e, bson.D{{Key: "_id", Value: "counter-id"}, {Key: "key", Value: "a"}, {Key: "count", Value: int32(10)}})
	a := rateLimitAdapter(t, e)
	res, err := a.IncrementOne(context.Background(), adapter.IncrementInput{
		Model: "rateLimit", Where: []adapter.Where{{Field: "key", Value: "a"}}, Increment: map[string]float64{"count": 1},
	})
	if err != nil || res["count"] != int64(11) {
		t.Fatalf("result %v, %v", res, err)
	}
	cmd := e.recorder.named("findAndModify")[0]
	if q := extJSON(t, field(t, cmd, "query")); q != `{"key":"a"}` {
		t.Fatalf("query %s", q)
	}
	if u := extJSON(t, field(t, cmd, "update")); u != `{"$inc":{"count":1}}` {
		t.Fatalf("update %s", u)
	}
}

func TestIncrementOneOmitsIncForGuardedSetOnlyUpdates(t *testing.T) {
	e := newEnv(t)
	insertCounter(t, e, bson.D{{Key: "_id", Value: "counter-id"}, {Key: "key", Value: "a"}, {Key: "count", Value: int32(11)}})
	a := rateLimitAdapter(t, e)
	res, err := a.IncrementOne(context.Background(), adapter.IncrementInput{
		Model: "rateLimit", Where: []adapter.Where{{Field: "key", Value: "a"}},
		Increment: map[string]float64{}, Set: adapter.Record{"lastRequest": int64(1700000000000)},
	})
	if err != nil || res["id"] != "counter-id" || res["count"] != int64(11) || res["lastRequest"] != int64(1700000000000) {
		t.Fatalf("result %v, %v", res, err)
	}
	cmd := e.recorder.named("findAndModify")[0]
	if u := extJSON(t, field(t, cmd, "update")); u != `{"$set":{"lastRequest":1.7E+12}}` {
		t.Fatalf("update %s", u)
	}
	if !field(t, cmd, "new").Boolean() {
		t.Fatal(`expected returnDocument: "after"`)
	}
}

func TestIncrementOneRejectsAnEmptyGuardedUpdate(t *testing.T) {
	e := newEnv(t)
	a := rateLimitAdapter(t, e)
	_, err := a.IncrementOne(context.Background(), adapter.IncrementInput{
		Model: "rateLimit", Where: []adapter.Where{{Field: "key", Value: "a"}}, Increment: map[string]float64{},
	})
	if err == nil || err.Error() != "incrementOne requires a non-empty `increment` or `set`; both were empty." {
		t.Fatalf("err %v", err)
	}
	if n := len(e.recorder.named("find")) + len(e.recorder.named("findAndModify")); n != 0 {
		t.Fatalf("%d commands sent", n)
	}
}

func TestIncrementOneReturnsNullWhenTheGuardMatchesNoDocument(t *testing.T) {
	e := newEnv(t)
	insertCounter(t, e, bson.D{{Key: "_id", Value: "counter-id"}, {Key: "key", Value: "a"}, {Key: "count", Value: int32(5)}})
	a := rateLimitAdapter(t, e)
	res, err := a.IncrementOne(context.Background(), adapter.IncrementInput{
		Model: "rateLimit", Where: []adapter.Where{{Field: "count", Value: 5, Operator: adapter.Lt}}, Increment: map[string]float64{"count": 1},
	})
	if err != nil || res != nil {
		t.Fatalf("result %v, %v", res, err)
	}
}

// ---- uuid support ----

func TestUUIDSupport(t *testing.T) {
	const uuid = "550e8400-e29b-41d4-a716-446655440000"
	ctx := context.Background()
	userData := func() adapter.Record {
		return adapter.Record{"name": "Test", "email": "test@test.com", "emailVerified": true, "createdAt": time.Now(), "updatedAt": time.Now()}
	}
	isUUIDRegex := func(s string) bool { _, ok := parseUUID(s); return ok && len(s) == 36 }

	t.Run("should store _id as BSON UUID when generateId is 'uuid'", func(t *testing.T) {
		e := newEnv(t)
		a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{IDMode: adapter.IDUUID})
		u, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: userData()})
		if err != nil {
			t.Fatal(err)
		}
		raw := rawDoc(t, e.plain, "user", bson.D{})
		id := raw.Lookup("_id")
		sub, data, ok := id.BinaryOK()
		if !ok || sub != bson.TypeBinaryUUID || len(data) != 16 {
			t.Fatalf("_id stored as %v", id)
		}
		if !isUUIDRegex(formatUUID(data)) || u["id"] != formatUUID(data) {
			t.Fatalf("id %v vs %s", u["id"], formatUUID(data))
		}
	})
	t.Run("should store FK fields as BSON UUID when generateId is 'uuid'", func(t *testing.T) {
		e := newEnv(t)
		a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{IDMode: adapter.IDUUID})
		s, err := a.Create(ctx, adapter.CreateInput{Model: "session", Data: adapter.Record{
			"userId": uuid, "token": "test-token", "expiresAt": time.Now(), "createdAt": time.Now(), "updatedAt": time.Now()}})
		if err != nil {
			t.Fatal(err)
		}
		raw := rawDoc(t, e.plain, "session", bson.D{})
		if sub, _, ok := raw.Lookup("_id").BinaryOK(); !ok || sub != bson.TypeBinaryUUID {
			t.Fatalf("_id stored as %v", raw.Lookup("_id"))
		}
		sub, data, ok := raw.Lookup("userId").BinaryOK()
		if !ok || sub != bson.TypeBinaryUUID || formatUUID(data) != uuid {
			t.Fatalf("userId stored as %v", raw.Lookup("userId"))
		}
		if s["userId"] != uuid {
			t.Fatalf("userId output %v", s["userId"])
		}
		found, err := a.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "userId", Value: uuid}}})
		if err != nil || found == nil || found["id"] != s["id"] {
			t.Fatalf("find by uuid FK: %v, %v", found, err)
		}
	})
	t.Run("should store _id as ObjectId when generateId is not set", func(t *testing.T) {
		e := newEnv(t)
		a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{})
		u, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: userData()})
		if err != nil {
			t.Fatal(err)
		}
		raw := rawDoc(t, e.plain, "user", bson.D{})
		id, ok := raw.Lookup("_id").ObjectIDOK()
		if !ok || id.Hex() != u["id"] {
			t.Fatalf("_id stored as %v (output %v)", raw.Lookup("_id"), u["id"])
		}
	})
	t.Run("should convert BSON UUID to string in output", func(t *testing.T) {
		e := newEnv(t)
		b, _ := parseUUID(uuid)
		if _, err := e.plain.Collection("user").InsertOne(ctx, bson.D{
			{Key: "_id", Value: bson.Binary{Subtype: bson.TypeBinaryUUID, Data: b}}, {Key: "name", Value: "Test"}, {Key: "email", Value: "test@test.com"}}); err != nil {
			t.Fatal(err)
		}
		a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{IDMode: adapter.IDUUID})
		res, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: uuid}}})
		if err != nil || res == nil {
			t.Fatalf("findOne %v, %v", res, err)
		}
		if res["id"] != uuid {
			t.Fatalf("id %v", res["id"])
		}
	})
}

// ---- adapter.mongo-db.test.ts (e2e) ----

func TestUpdateKeepsObjectIDForIDAndFKFields(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), adapter.Options{})
	user, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{
		"name": "Test User", "email": "test@test.com", "emailVerified": true, "image": "test-image", "createdAt": time.Now(), "updatedAt": time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := a.Create(ctx, adapter.CreateInput{Model: "session", Data: adapter.Record{
		"userId": user["id"], "expiresAt": time.UnixMilli(0), "createdAt": time.Now(), "updatedAt": time.Now(), "token": "test-token"}})
	if err != nil {
		t.Fatal(err)
	}
	filter := bson.D{{Key: "_id", Value: oid(t, session["id"].(string))}}
	if _, ok := rawDoc(t, e.plain, "session", filter).Lookup("userId").ObjectIDOK(); !ok {
		t.Fatal("userId should be an ObjectId before the update")
	}
	upd := adapter.Record{}
	for k, v := range session {
		if k != "id" {
			upd[k] = v
		}
	}
	upd["expiresAt"] = time.UnixMilli(1)
	res, err := a.Update(ctx, "session", []adapter.Where{{Field: "id", Value: session["id"]}}, upd)
	if err != nil || res == nil {
		t.Fatalf("update %v, %v", res, err)
	}
	raw := rawDoc(t, e.plain, "session", filter)
	if _, ok := raw.Lookup("userId").ObjectIDOK(); !ok {
		t.Fatal("userId should still be an ObjectId after the update")
	}
	if res["userId"] != user["id"] || !res["expiresAt"].(time.Time).Equal(time.UnixMilli(1)) {
		t.Fatalf("update result %v", res)
	}
}

func compoundSchema() *db.Schema {
	return schemaOf(db.Options{Plugins: [][]db.PluginTable{{{
		Key: "compoundIndexSubject", ModelName: "compound_index_subject",
		Fields: []db.Field{
			{Name: "issuer", Type: db.TypeString, FieldName: "issuer_url"},
			{Name: "providerSubject", Type: db.TypeString, FieldName: "provider_subject"},
			{Name: "displayName", Type: db.TypeString, FieldName: "display_name"},
		},
		Indexes: []db.Index{{Fields: []string{"issuer", "providerSubject"}, Name: "compound_identity_uidx", Unique: true}},
	}}}})
}

func TestCompoundIndexEnforcesTheConfiguredTupleThroughTheRealDatabase(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	opts := adapter.Options{Schema: compoundSchema()}
	a := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), opts)
	create := func(a adapter.Adapter, issuer, subject, name string) error {
		_, err := a.Create(ctx, adapter.CreateInput{Model: "compoundIndexSubject", Data: adapter.Record{"issuer": issuer, "providerSubject": subject, "displayName": name}})
		return err
	}
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i, row := range [][3]string{{"https://idp.example", "employee-1", "Ada"}, {"https://idp.example", "employee-2", "Lin"}, {"https://partner.example", "employee-1", "Kai"}} {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = create(a, row[0], row[1], row[2]) }()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	if err := create(a, "https://idp.example", "employee-1", "Duplicate"); err == nil {
		t.Fatal("duplicate tuple should be rejected")
	}
	// verifyIndexState
	cur, err := e.plain.Collection("compound_index_subject").Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var specs []bson.M
	if err := cur.All(ctx, &specs); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range specs {
		if s["name"] == "compound_identity_uidx" && s["unique"] == true && extJSON(t, s["key"]) == `{"issuer_url":1,"provider_subject":1}` {
			found = true
		}
	}
	if !found {
		t.Fatalf("index not found in %v", specs)
	}
	// verifyMismatchedIndexRejected
	coll := e.plain.Collection("compound_index_subject")
	if err := coll.Indexes().DropOne(ctx, "compound_identity_uidx"); err != nil {
		t.Fatal(err)
	}
	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "provider_subject", Value: 1}},
		Options: options.Index().SetName("compound_identity_uidx")}); err != nil {
		t.Fatal(err)
	}
	fresh := mustAdapter(t, New(e.db, Config{Transaction: boolp(false)}), opts)
	err = create(fresh, "https://mismatch.example", "employee-mismatch", "Mismatch probe")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "existing index has the same name") {
		t.Fatalf("expected mismatch error, got %v", err)
	}
}
