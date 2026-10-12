package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
)

func newAdapter(t *testing.T) adapter.Adapter {
	t.Helper()
	a, err := New()(adapter.Options{Schema: db.GetAuthTables(db.Options{User: db.ModelOptions{
		ModelName: "users", Fields: map[string]string{"emailVerified": "email_verified"}}})})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCRUDWhereSortAndRenames(t *testing.T) {
	ctx := context.Background()
	a := newAdapter(t)
	for i, name := range []string{"carol", "alice", "bob"} {
		u, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{
			"name": name, "email": name + "@example.com", "createdAt": time.Unix(int64(i), 0)}})
		if err != nil {
			t.Fatal(err)
		}
		if len(u["id"].(string)) != 32 || u["emailVerified"] != false {
			t.Fatalf("defaults not applied: %v", u)
		}
	}
	rows, _ := a.FindMany(ctx, adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "name", Direction: "asc"}})
	if len(rows) != 3 || rows[0]["name"] != "alice" || rows[2]["name"] != "carol" {
		t.Fatalf("sort: %v", rows)
	}
	n, _ := a.Count(ctx, "user", []adapter.Where{{Field: "email", Value: "ALICE@example.com", Insensitive: true}})
	if n != 1 {
		t.Fatalf("insensitive count %d", n)
	}
	upd, err := a.Update(ctx, "user", []adapter.Where{{Field: "name", Value: "bob"}}, adapter.Record{"emailVerified": true})
	if err != nil || upd["emailVerified"] != true {
		t.Fatalf("update %v %v", upd, err)
	}
	// renamed table and column are used physically
	if _, err := a.FindOne(ctx, adapter.FindOneInput{Model: "users", Where: []adapter.Where{{Field: "email_verified", Value: true}}}); err != nil {
		t.Fatalf("physical names should resolve: %v", err)
	}
	or, _ := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{
		{Field: "name", Value: "alice"}, {Field: "name", Value: "carol", Connector: adapter.Or}}})
	if len(or) != 2 {
		t.Fatalf("OR where: %d", len(or))
	}
	in, _ := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: []string{"alice", "bob"}, Operator: adapter.In}}, Limit: 1, Offset: 1})
	if len(in) != 1 {
		t.Fatalf("in + pagination: %d", len(in))
	}
	if d, _ := a.DeleteMany(ctx, "user", []adapter.Where{{Field: "name", Value: "a", Operator: adapter.StartsWith}}); d != 1 {
		t.Fatalf("deleteMany %d", d)
	}
}

func TestUniqueJoinsConsumeIncrementTransaction(t *testing.T) {
	ctx := context.Background()
	a := newAdapter(t)
	u, _ := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{"name": "u", "email": "u@example.com"}})
	_, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{"name": "dup", "email": "u@example.com"}})
	var uv *ErrUniqueViolation
	if !errors.As(err, &uv) {
		t.Fatalf("expected unique violation, got %v", err)
	}
	for i := 0; i < 2; i++ {
		_, _ = a.Create(ctx, adapter.CreateInput{Model: "account", Data: adapter.Record{"accountId": "a", "providerId": "p", "userId": u["id"]}})
	}
	withAcc, _ := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u["id"]}}, Join: map[string]adapter.Join{"account": {}}})
	if accs := withAcc["account"].([]adapter.Record); len(accs) != 2 {
		t.Fatalf("join: %v", withAcc["account"])
	}
	v, _ := a.Create(ctx, adapter.CreateInput{Model: "verification", Data: adapter.Record{"identifier": "x", "value": "1", "expiresAt": time.Now()}})
	got, _ := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "id", Value: v["id"]}})
	again, _ := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "id", Value: v["id"]}})
	if got == nil || again != nil {
		t.Fatal("consumeOne must return the row exactly once")
	}
	err = a.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
		_, _ = tx.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{"name": "tx", "email": "tx@example.com"}})
		return errors.New("rollback")
	})
	if n, _ := a.Count(ctx, "user", []adapter.Where{{Field: "email", Value: "tx@example.com"}}); err == nil || n != 0 {
		t.Fatal("transaction should roll back")
	}
}
