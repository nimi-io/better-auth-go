package mongodb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
)

// Integration tests against a real MongoDB covering the document encoding, every operation
// and the configuration options of the adapter.

var ctx = context.Background()

func seedUsers(t *testing.T, a adapter.Adapter, names ...string) []adapter.Record {
	t.Helper()
	var out []adapter.Record
	for i, n := range names {
		u, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{
			"name": n, "email": strings.ToLower(n) + "@example.com", "createdAt": time.UnixMilli(int64(1000 * (i + 1)))}})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, u)
	}
	return out
}

func names(rows []adapter.Record) string {
	var s []string
	for _, r := range rows {
		s = append(s, r["name"].(string))
	}
	return strings.Join(s, ",")
}

// docTypes returns "key:type" pairs of a stored document in order.
func docTypes(t *testing.T, raw bson.Raw) string {
	t.Helper()
	elems, err := raw.Elements()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range elems {
		typ := e.Key() + ":" + e.Value().Type.String()
		if sub, _, ok := e.Value().BinaryOK(); ok {
			typ += fmt.Sprintf("/%#02x", sub)
		}
		out = append(out, typ)
	}
	return strings.Join(out, " ")
}

func TestDocumentEncoding(t *testing.T) {
	e := newEnv(t)
	schema := schemaOf(db.Options{RateLimitInDatabase: true, User: db.ModelOptions{AdditionalFields: []db.Field{
		{Name: "tags", Type: db.TypeStringArray}, {Name: "scores", Type: db.TypeNumberArray},
		{Name: "meta", Type: db.TypeJSON}, {Name: "age", Type: db.TypeNumber},
	}}})
	a := mustAdapter(t, New(e.db, Config{}), adapter.Options{Schema: schema})
	u, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{
		"name": "Ada", "email": "ada@example.com", "image": nil,
		"tags": []string{"a", "b"}, "scores": []any{int64(1), 2.5}, "meta": map[string]any{"k": "v"}, "age": int64(36)}})
	if err != nil {
		t.Fatal(err)
	}
	raw := rawDoc(t, e.plain, "user", bson.D{})
	if got, want := docTypes(t, raw), "_id:objectID name:string email:string emailVerified:boolean image:null createdAt:UTC datetime updatedAt:UTC datetime tags:array scores:array meta:string age:32-bit integer"; got != want {
		t.Fatalf("user document\n got %s\nwant %s", got, want)
	}
	if raw.Lookup("meta").StringValue() != `{"k":"v"}` {
		t.Fatalf("json field %v", raw.Lookup("meta"))
	}
	if u["meta"].(map[string]any)["k"] != "v" || len(u["tags"].([]any)) != 2 || u["age"] != int64(36) {
		t.Fatalf("output %v", u)
	}
	s, err := a.Create(ctx, adapter.CreateInput{Model: "session", Data: adapter.Record{
		"userId": u["id"], "token": "tok", "expiresAt": time.Now().Add(time.Hour), "ipAddress": "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := docTypes(t, rawDoc(t, e.plain, "session", bson.D{})), "_id:objectID expiresAt:UTC datetime token:string createdAt:UTC datetime ipAddress:string userId:objectID"; got != want {
		t.Fatalf("session document\n got %s\nwant %s", got, want)
	}
	if s["userId"] != u["id"] {
		t.Fatalf("session output %v", s)
	}
	if _, err := a.Create(ctx, adapter.CreateInput{Model: "account", Data: adapter.Record{
		"accountId": "acc", "providerId": "credential", "userId": u["id"], "password": "hash"}}); err != nil {
		t.Fatal(err)
	}
	if got, want := docTypes(t, rawDoc(t, e.plain, "account", bson.D{})), "_id:objectID accountId:string providerId:string userId:objectID password:string createdAt:UTC datetime"; got != want {
		t.Fatalf("account document\n got %s\nwant %s", got, want)
	}
	if _, err := a.Create(ctx, adapter.CreateInput{Model: "rateLimit", Data: adapter.Record{"key": "k", "count": int64(1), "lastRequest": time.Now().UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if got, want := docTypes(t, rawDoc(t, e.plain, "rateLimit", bson.D{})), "_id:objectID key:string count:32-bit integer lastRequest:double"; got != want {
		t.Fatalf("rateLimit document\n got %s\nwant %s", got, want)
	}
}

func TestWhereOperatorsAgainstMongo(t *testing.T) {
	e := newEnv(t)
	a := mustAdapter(t, New(e.db, Config{}), adapter.Options{})
	users := seedUsers(t, a, "Alice", "Bob", "Carol", "a.b", "axb")
	find := func(where ...adapter.Where) string {
		t.Helper()
		rows, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: where, SortBy: &adapter.SortBy{Field: "createdAt", Direction: "asc"}})
		if err != nil {
			t.Fatal(err)
		}
		return names(rows)
	}
	cases := []struct {
		got, want string
	}{
		{find(adapter.Where{Field: "id", Value: users[1]["id"]}), "Bob"},
		{find(adapter.Where{Field: "id", Value: []any{users[0]["id"], users[2]["id"]}, Operator: adapter.In}), "Alice,Carol"},
		{find(adapter.Where{Field: "id", Value: []any{users[0]["id"]}, Operator: adapter.NotIn}), "Bob,Carol,a.b,axb"},
		{find(adapter.Where{Field: "name", Value: "a.b", Operator: adapter.Contains}), "a.b"},
		{find(adapter.Where{Field: "name", Value: "a.", Operator: adapter.StartsWith}), "a.b"},
		{find(adapter.Where{Field: "name", Value: "ob", Operator: adapter.EndsWith}), "Bob"},
		{find(adapter.Where{Field: "name", Value: "alice"}), ""},
		{find(adapter.Where{Field: "name", Value: "alice", Insensitive: true}), "Alice"},
		{find(adapter.Where{Field: "name", Value: "ALI", Operator: adapter.StartsWith, Insensitive: true}), "Alice"},
		{find(adapter.Where{Field: "name", Value: "OL", Operator: adapter.Contains, Insensitive: true}), "Carol"},
		{find(adapter.Where{Field: "name", Value: []string{"ALICE", "bob"}, Operator: adapter.In, Insensitive: true}), "Alice,Bob"},
		{find(adapter.Where{Field: "name", Value: []string{"ALICE", "bob"}, Operator: adapter.NotIn, Insensitive: true}), "Carol,a.b,axb"},
		{find(adapter.Where{Field: "name", Value: "ALICE", Operator: adapter.Ne, Insensitive: true}), "Bob,Carol,a.b,axb"},
		{find(adapter.Where{Field: "createdAt", Value: time.UnixMilli(2000), Operator: adapter.Gt}), "Carol,a.b,axb"},
		{find(adapter.Where{Field: "createdAt", Value: time.UnixMilli(2000), Operator: adapter.Gte}), "Bob,Carol,a.b,axb"},
		{find(adapter.Where{Field: "createdAt", Value: time.UnixMilli(2000), Operator: adapter.Lt}), "Alice"},
		{find(adapter.Where{Field: "createdAt", Value: time.UnixMilli(2000), Operator: adapter.Lte}), "Alice,Bob"},
		{find(adapter.Where{Field: "name", Value: "Alice", Operator: adapter.Ne}), "Bob,Carol,a.b,axb"},
		// AND + OR: (name = Alice) AND (email = bob@… OR email = carol@…) → nothing
		{find(adapter.Where{Field: "name", Value: "Alice"}, adapter.Where{Field: "email", Value: "bob@example.com", Connector: adapter.Or},
			adapter.Where{Field: "email", Value: "carol@example.com", Connector: adapter.Or}), ""},
		{find(adapter.Where{Field: "name", Value: "Bob"}, adapter.Where{Field: "email", Value: "bob@example.com", Connector: adapter.Or},
			adapter.Where{Field: "email", Value: "carol@example.com", Connector: adapter.Or}), "Bob"},
		{find(adapter.Where{Field: "name", Value: "Bob", Connector: adapter.Or}, adapter.Where{Field: "name", Value: "Carol", Connector: adapter.Or}), "Bob,Carol"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Errorf("case %d: got %q want %q", i, c.got, c.want)
		}
	}
	if find(adapter.Where{Field: "image", Value: nil}) != "Alice,Bob,Carol,a.b,axb" {
		t.Error("eq null should match missing fields")
	}
}

func TestSelectSortLimitOffsetCount(t *testing.T) {
	e := newEnv(t)
	a := mustAdapter(t, New(e.db, Config{}), adapter.Options{})
	seedUsers(t, a, "c", "a", "d", "b")
	rows, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "name", Direction: "desc"}, Limit: 2, Offset: 1})
	if err != nil || names(rows) != "c,b" {
		t.Fatalf("sort/limit/offset: %q %v", names(rows), err)
	}
	rows, _ = a.FindMany(ctx, adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "name", Direction: "asc"}})
	if names(rows) != "a,b,c,d" {
		t.Fatalf("asc: %q", names(rows))
	}
	one, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: "a"}}, Select: []string{"email"}})
	if err != nil || one["email"] != "a@example.com" || len(one) != 1 {
		t.Fatalf("select: %v %v", one, err)
	}
	if n, err := a.Count(ctx, "user", nil); err != nil || n != 4 {
		t.Fatalf("count %d %v", n, err)
	}
	if n, _ := a.Count(ctx, "user", []adapter.Where{{Field: "name", Value: []string{"a", "b"}, Operator: adapter.In}}); n != 2 {
		t.Fatalf("count where %d", n)
	}
	if n, _ := a.Count(ctx, "session", nil); n != 0 {
		t.Fatalf("count empty collection %d", n)
	}
	if r, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: "zzz"}}}); r != nil || err != nil {
		t.Fatalf("findOne none: %v %v", r, err)
	}
}

func TestUpdateDelete(t *testing.T) {
	e := newEnv(t)
	a := mustAdapter(t, New(e.db, Config{}), adapter.Options{})
	users := seedUsers(t, a, "a", "b", "c")
	before := users[0]["updatedAt"].(time.Time)
	time.Sleep(5 * time.Millisecond)
	u, err := a.Update(ctx, "user", []adapter.Where{{Field: "id", Value: users[0]["id"]}}, adapter.Record{"name": "a2", "emailVerified": true})
	if err != nil || u["name"] != "a2" || u["emailVerified"] != true || u["id"] != users[0]["id"] || !u["updatedAt"].(time.Time).After(before) {
		t.Fatalf("update %v %v", u, err)
	}
	if u, err := a.Update(ctx, "user", []adapter.Where{{Field: "name", Value: "nobody"}}, adapter.Record{"name": "x"}); u != nil || err != nil {
		t.Fatalf("update none %v %v", u, err)
	}
	n, err := a.UpdateMany(ctx, "user", []adapter.Where{{Field: "name", Value: []string{"b", "c"}, Operator: adapter.In}}, adapter.Record{"image": "img"})
	if err != nil || n != 2 {
		t.Fatalf("updateMany %d %v", n, err)
	}
	if err := a.Delete(ctx, "user", []adapter.Where{{Field: "name", Value: "a2"}}); err != nil {
		t.Fatal(err)
	}
	n, err = a.DeleteMany(ctx, "user", []adapter.Where{{Field: "image", Value: "img"}})
	if err != nil || n != 2 {
		t.Fatalf("deleteMany %d %v", n, err)
	}
	if c, _ := a.Count(ctx, "user", nil); c != 0 {
		t.Fatalf("left %d", c)
	}
}

func joinFixture(t *testing.T, a adapter.Adapter) (adapter.Record, []adapter.Record) {
	t.Helper()
	u := seedUsers(t, a, "joined")[0]
	other := seedUsers(t, a, "other")[0]
	var sessions []adapter.Record
	for i := 0; i < 3; i++ {
		s, err := a.Create(ctx, adapter.CreateInput{Model: "session", Data: adapter.Record{"userId": u["id"], "token": "t" + string(rune('0'+i)), "expiresAt": time.Now()}})
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	if _, err := a.Create(ctx, adapter.CreateInput{Model: "session", Data: adapter.Record{"userId": other["id"], "token": "other", "expiresAt": time.Now()}}); err != nil {
		t.Fatal(err)
	}
	return u, sessions
}

func TestJoins(t *testing.T) {
	for _, native := range []bool{true, false} {
		t.Run(map[bool]string{true: "native $lookup", false: "fallback"}[native], func(t *testing.T) {
			e := newEnv(t)
			a := mustAdapter(t, New(e.db, Config{}), adapter.Options{Joins: native})
			u, sessions := joinFixture(t, a)
			e.recorder.reset()
			got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u["id"]}}, Join: map[string]adapter.Join{"session": {}}})
			if err != nil {
				t.Fatal(err)
			}
			ss := got["session"].([]adapter.Record)
			if len(ss) != 3 || ss[0]["userId"] != u["id"] {
				t.Fatalf("one-to-many join: %v", got["session"])
			}
			aggs := e.recorder.named("aggregate")
			if native && (len(aggs) != 1 || !strings.Contains(aggs[0].String(), "$lookup")) {
				t.Fatalf("native join should use a single $lookup aggregation, got %d", len(aggs))
			}
			if !native && len(aggs) != 2 {
				t.Fatalf("fallback join should query twice, got %d", len(aggs))
			}
			limited, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u["id"]}}, Join: map[string]adapter.Join{"session": {Limit: 2}}})
			if err != nil || len(limited["session"].([]adapter.Record)) != 2 {
				t.Fatalf("join limit: %v %v", limited["session"], err)
			}
			s, err := a.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "id", Value: sessions[0]["id"]}}, Join: map[string]adapter.Join{"user": {}}})
			if err != nil {
				t.Fatal(err)
			}
			if ju, ok := s["user"].(adapter.Record); !ok || ju["id"] != u["id"] || ju["name"] != "joined" {
				t.Fatalf("one-to-one join: %v", s["user"])
			}
			many, err := a.FindMany(ctx, adapter.FindManyInput{Model: "session", Join: map[string]adapter.Join{"user": {}}, SortBy: &adapter.SortBy{Field: "token", Direction: "asc"}})
			if err != nil || len(many) != 4 {
				t.Fatalf("findMany join: %v %v", many, err)
			}
			for _, m := range many {
				ju, ok := m["user"].(adapter.Record)
				if !ok || ju["id"] != m["userId"] {
					t.Fatalf("findMany one-to-one join: %v", m)
				}
			}
			users, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Join: map[string]adapter.Join{"session": {}}, SortBy: &adapter.SortBy{Field: "name", Direction: "asc"}})
			if err != nil || len(users) != 2 || len(users[0]["session"].([]adapter.Record)) != 3 || len(users[1]["session"].([]adapter.Record)) != 1 {
				t.Fatalf("findMany one-to-many join: %v %v", users, err)
			}
			sel, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u["id"]}}, Select: []string{"name"}, Join: map[string]adapter.Join{"session": {}}})
			if err != nil || sel["name"] != "joined" || sel["id"] != u["id"] || len(sel["session"].([]adapter.Record)) != 3 {
				t.Fatalf("join with select: %v %v", sel, err)
			}
			none, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: "other"}}, Join: map[string]adapter.Join{"account": {}}})
			if err != nil || len(none["account"].([]adapter.Record)) != 0 {
				t.Fatalf("empty join: %v %v", none, err)
			}
		})
	}
}

func TestTransactions(t *testing.T) {
	e := newEnv(t)
	a := mustAdapter(t, New(e.db, Config{Client: e.client}), adapter.Options{})
	err := a.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
		if _, err := tx.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{"name": "rolled", "email": "r@example.com"}}); err != nil {
			return err
		}
		// visible inside the transaction, invisible outside
		if n, _ := tx.Count(ctx, "user", nil); n != 1 {
			t.Errorf("inside tx count %d", n)
		}
		if n, _ := a.Count(context.Background(), "user", nil); n != 0 {
			t.Errorf("outside tx count %d", n)
		}
		return errors.New("rollback")
	})
	if err == nil || err.Error() != "rollback" {
		t.Fatalf("err %v", err)
	}
	if n, _ := a.Count(ctx, "user", nil); n != 0 {
		t.Fatalf("rolled back insert is visible: %d", n)
	}
	err = a.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
		u, err := tx.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{"name": "kept", "email": "k@example.com"}})
		if err != nil {
			return err
		}
		// nested transactions reuse the outer one
		return tx.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
			_, err := tx.Update(ctx, "user", []adapter.Where{{Field: "id", Value: u["id"]}}, adapter.Record{"image": "x"})
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: "kept"}}})
	if got == nil || got["image"] != "x" {
		t.Fatalf("committed row %v", got)
	}
	// commands inside the transaction carry a transaction number
	inTx := 0
	for _, c := range e.recorder.named("insert") {
		if _, err := c.LookupErr("txnNumber"); err == nil {
			inTx++
		}
	}
	if inTx != 2 {
		t.Fatalf("inserts in a transaction: %d", inTx)
	}
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("panic not propagated: %v", r)
			}
		}()
		_ = a.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
			_, _ = tx.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{"name": "panic", "email": "p@example.com"}})
			panic("boom")
		})
	}()
	if n, _ := a.Count(ctx, "user", []adapter.Where{{Field: "name", Value: "panic"}}); n != 0 {
		t.Fatal("panicking transaction must be aborted")
	}
}

func TestTransactionsDisabled(t *testing.T) {
	e := newEnv(t)
	for name, cfg := range map[string]Config{
		"no client":          {},
		"transaction: false": {Client: e.client, Transaction: boolp(false)},
	} {
		t.Run(name, func(t *testing.T) {
			f := New(e.db, cfg)
			a := mustAdapter(t, f, adapter.Options{})
			if _, ok := a.(interface{ Custom() adapter.CustomAdapter }).Custom().(adapter.Transactor); ok {
				t.Fatal("adapter should not implement transactions")
			}
			email := strings.ReplaceAll(name, " ", "") + "@example.com"
			_ = a.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
				_, _ = tx.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{"name": name, "email": email}})
				return errors.New("no rollback")
			})
			if n, _ := a.Count(ctx, "user", []adapter.Where{{Field: "email", Value: email}}); n != 1 {
				t.Fatalf("without transactions the write stays: %d", n)
			}
		})
	}
}

func TestUsePluralAndRenames(t *testing.T) {
	e := newEnv(t)
	schema := schemaOf(db.Options{Session: db.ModelOptions{Fields: map[string]string{"userId": "user_id"}}})
	a := mustAdapter(t, New(e.db, Config{UsePlural: true}), adapter.Options{Schema: schema, Joins: true})
	u := seedUsers(t, a, "plural")[0]
	if _, err := a.Create(ctx, adapter.CreateInput{Model: "session", Data: adapter.Record{"userId": u["id"], "token": "t", "expiresAt": time.Now()}}); err != nil {
		t.Fatal(err)
	}
	cols, _ := e.plain.ListCollectionNames(ctx, bson.D{})
	sortStrings(cols)
	if strings.Join(cols, ",") != "sessions,users" {
		t.Fatalf("collections %v", cols)
	}
	raw := rawDoc(t, e.plain, "sessions", bson.D{})
	if _, ok := raw.Lookup("user_id").ObjectIDOK(); !ok {
		t.Fatalf("renamed FK not stored as ObjectId: %v", raw)
	}
	s, err := a.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "userId", Value: u["id"]}}, Join: map[string]adapter.Join{"user": {}}})
	if err != nil || s == nil || s["userId"] != u["id"] || s["user"].(adapter.Record)["id"] != u["id"] {
		t.Fatalf("renamed FK lookup: %v %v", s, err)
	}
}

func TestIDModes(t *testing.T) {
	t.Run("custom generator stores strings", func(t *testing.T) {
		e := newEnv(t)
		n := 0
		a := mustAdapter(t, New(e.db, Config{}), adapter.Options{GenerateID: func(model string, _ int) (string, bool) {
			n++
			return model + "-" + string(rune('0'+n)), true
		}})
		u := seedUsers(t, a, "c")[0]
		if u["id"] != "user-1" {
			t.Fatalf("id %v", u["id"])
		}
		if _, err := a.Create(ctx, adapter.CreateInput{Model: "session", Data: adapter.Record{"userId": u["id"], "token": "t", "expiresAt": time.Now()}}); err != nil {
			t.Fatal(err)
		}
		raw := rawDoc(t, e.plain, "session", bson.D{})
		if raw.Lookup("_id").StringValue() != "session-2" || raw.Lookup("userId").StringValue() != "user-1" {
			t.Fatalf("stored %v", raw)
		}
		s, err := a.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "userId", Value: "user-1"}}})
		if err != nil || s["id"] != "session-2" {
			t.Fatalf("find %v %v", s, err)
		}
	})
	t.Run("custom generator with hex ids still stores strings", func(t *testing.T) {
		e := newEnv(t)
		a := mustAdapter(t, New(e.db, Config{}), adapter.Options{GenerateID: func(string, int) (string, bool) { return bson.NewObjectID().Hex(), true }})
		u := seedUsers(t, a, "c")[0]
		raw := rawDoc(t, e.plain, "user", bson.D{})
		if raw.Lookup("_id").StringValue() != u["id"] {
			t.Fatalf("stored %v", raw)
		}
	})
	t.Run("generateId false lets the driver create an ObjectId", func(t *testing.T) {
		e := newEnv(t)
		a := mustAdapter(t, New(e.db, Config{}), adapter.Options{IDMode: adapter.IDNone})
		u := seedUsers(t, a, "n")[0]
		raw := rawDoc(t, e.plain, "user", bson.D{})
		if id, ok := raw.Lookup("_id").ObjectIDOK(); !ok || id.Hex() != u["id"] {
			t.Fatalf("stored %v, output %v", raw, u["id"])
		}
	})
	t.Run("serial ids are rejected", func(t *testing.T) {
		e := newEnv(t)
		_, err := New(e.db, Config{})(adapter.Options{Schema: schemaOf(db.Options{}), IDMode: adapter.IDSerial})
		if err == nil || !strings.Contains(err.Error(), "does not support numeric ids") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("forceAllowId", func(t *testing.T) {
		e := newEnv(t)
		a := mustAdapter(t, New(e.db, Config{}), adapter.Options{})
		const hex = "65a1b2c3d4e5f6a7b8c9d0e1"
		u, err := a.Create(ctx, adapter.CreateInput{Model: "user", ForceAllowID: true, Data: adapter.Record{"id": hex, "name": "f", "email": "f@example.com"}})
		if err != nil || u["id"] != hex {
			t.Fatalf("%v %v", u, err)
		}
		if id, ok := rawDoc(t, e.plain, "user", bson.D{}).Lookup("_id").ObjectIDOK(); !ok || id.Hex() != hex {
			t.Fatal("forced id must be stored as ObjectId")
		}
	})
	t.Run("uuid mode joins and lookups", func(t *testing.T) {
		e := newEnv(t)
		a := mustAdapter(t, New(e.db, Config{}), adapter.Options{IDMode: adapter.IDUUID, Joins: true})
		u, _ := joinFixture(t, a)
		if _, ok := parseUUID(u["id"].(string)); !ok {
			t.Fatalf("id %v", u["id"])
		}
		got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u["id"]}}, Join: map[string]adapter.Join{"session": {}}})
		if err != nil || len(got["session"].([]adapter.Record)) != 3 || got["session"].([]adapter.Record)[0]["userId"] != u["id"] {
			t.Fatalf("%v %v", got, err)
		}
	})
}

func TestDebugLogs(t *testing.T) {
	e := newEnv(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	a := mustAdapter(t, New(e.db, Config{DebugLogs: true, Logger: logger}), adapter.Options{})
	seedUsers(t, a, "dbg")
	_, _ = a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: "dbg"}}})
	out := buf.String()
	for _, want := range []string{"[MongoDB Adapter] create Parsed Input", "[MongoDB Adapter] create DB Result", "[MongoDB Adapter] findOne Pipeline", `$match`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in logs:\n%s", want, out)
		}
	}
	buf.Reset()
	cond := false
	a = mustAdapter(t, New(e.db, Config{Logger: logger, DebugLogOptions: &DebugLogOptions{FindOne: true, LogCondition: func() bool { return cond }}}), adapter.Options{})
	_, _ = a.FindOne(ctx, adapter.FindOneInput{Model: "user"})
	if buf.Len() != 0 {
		t.Fatalf("logCondition false should silence logs: %s", buf.String())
	}
	cond = true
	seedUsers(t, a, "dbg2")
	_, _ = a.FindOne(ctx, adapter.FindOneInput{Model: "user"})
	out = buf.String()
	if strings.Contains(out, "create Parsed") || !strings.Contains(out, "findOne Pipeline") {
		t.Fatalf("only findOne should be logged:\n%s", out)
	}
	buf.Reset()
	a = mustAdapter(t, New(e.db, Config{Logger: logger}), adapter.Options{})
	_, _ = a.FindOne(ctx, adapter.FindOneInput{Model: "user"})
	if buf.Len() != 0 {
		t.Fatal("logs are off by default")
	}
}
