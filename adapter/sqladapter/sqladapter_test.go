package sqladapter

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

func TestCreateAndFind(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		u := mustCreate(t, a, "user", adapter.Record{"name": "Ada", "email": "ada@example.com", "age": 36})
		id, _ := u["id"].(string)
		if len(id) != 32 {
			t.Fatalf("generated id %q", u["id"])
		}
		if u["emailVerified"] != false || u["age"] != int64(36) || u["image"] != nil {
			t.Fatalf("create result %#v", u)
		}
		if _, ok := u["createdAt"].(time.Time); !ok {
			t.Fatalf("createdAt %T", u["createdAt"])
		}
		got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: id}}})
		if err != nil || got == nil || got["email"] != "ada@example.com" {
			t.Fatalf("findOne by id: %v %v", got, err)
		}
		if !got["createdAt"].(time.Time).Equal(u["createdAt"].(time.Time)) {
			t.Fatalf("createdAt round trip: %v vs %v", got["createdAt"], u["createdAt"])
		}
		sel, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: "ada@example.com"}}, Select: []string{"email", "name"}})
		if err != nil || len(sel) != 2 || sel["name"] != "Ada" {
			t.Fatalf("select: %v %v", sel, err)
		}
		none, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: "nobody@example.com"}}})
		if err != nil || none != nil {
			t.Fatalf("missing row: %v %v", none, err)
		}
		// select on findMany
		many, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Select: []string{"id"}})
		if err != nil || len(many) != 1 || len(many[0]) != 1 || many[0]["id"] != id {
			t.Fatalf("findMany select: %v %v", many, err)
		}
		// unique violation surfaces the driver error
		if _, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: user("ada")}); err == nil {
			t.Fatal("expected unique violation")
		}
	})
}

func seedUsers(t *testing.T, a adapter.Adapter) {
	t.Helper()
	for i, r := range []adapter.Record{
		{"name": "alice", "email": "alice@example.com", "age": 30, "nickname": "Al"},
		{"name": "bob", "email": "bob@example.com", "age": 25, "nickname": nil},
		{"name": "carol", "email": "carol@test.org", "age": 35, "nickname": "CC"},
		{"name": "dave", "email": "Dave@Example.com", "age": 40, "nickname": "d_1%"},
	} {
		r["createdAt"] = time.Date(2024, 1, 1+i, 0, 0, 0, 0, time.UTC)
		mustCreate(t, a, "user", r)
	}
}

func TestWhereOperators(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		seedUsers(t, a)
		cases := []struct {
			name  string
			where []adapter.Where
			want  string
		}{
			{"eq", []adapter.Where{{Field: "name", Value: "bob"}}, "bob"},
			{"eq null", []adapter.Where{{Field: "nickname", Value: nil}}, "bob"},
			{"ne", []adapter.Where{{Field: "name", Value: "bob", Operator: adapter.Ne}}, "alice,carol,dave"},
			{"ne null", []adapter.Where{{Field: "nickname", Value: nil, Operator: adapter.Ne}}, "alice,carol,dave"},
			{"lt", []adapter.Where{{Field: "age", Value: 30, Operator: adapter.Lt}}, "bob"},
			{"lte", []adapter.Where{{Field: "age", Value: 30, Operator: adapter.Lte}}, "alice,bob"},
			{"gt", []adapter.Where{{Field: "age", Value: 35, Operator: adapter.Gt}}, "dave"},
			{"gte", []adapter.Where{{Field: "age", Value: 35, Operator: adapter.Gte}}, "carol,dave"},
			{"gt date", []adapter.Where{{Field: "createdAt", Value: time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC), Operator: adapter.Gt}}, "carol,dave"},
			{"lte date", []adapter.Where{{Field: "createdAt", Value: time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC), Operator: adapter.Lte}}, "alice,bob"},
			{"in", []adapter.Where{{Field: "name", Value: []string{"alice", "carol", "zed"}, Operator: adapter.In}}, "alice,carol"},
			{"in numbers", []adapter.Where{{Field: "age", Value: []any{25, 40}, Operator: adapter.In}}, "bob,dave"},
			{"not_in", []adapter.Where{{Field: "name", Value: []string{"alice", "carol"}, Operator: adapter.NotIn}}, "bob,dave"},
			{"in empty", []adapter.Where{{Field: "name", Value: []string{}, Operator: adapter.In}}, ""},
			{"not_in empty", []adapter.Where{{Field: "name", Value: []string{}, Operator: adapter.NotIn}}, "alice,bob,carol,dave"},
			{"contains", []adapter.Where{{Field: "email", Value: "example", Operator: adapter.Contains}}, "alice,bob"},
			{"starts_with", []adapter.Where{{Field: "name", Value: "ca", Operator: adapter.StartsWith}}, "carol"},
			{"ends_with", []adapter.Where{{Field: "email", Value: ".org", Operator: adapter.EndsWith}}, "carol"},
			{"emailVerified bool", []adapter.Where{{Field: "emailVerified", Value: false}}, "alice,bob,carol,dave"},
			{"emailVerified string", []adapter.Where{{Field: "emailVerified", Value: "true"}}, ""},
		}
		if e.d == MySQL || e.d == SQLite {
			// LIKE is case-insensitive for ASCII on SQLite and under MySQL's default
			// collation (as with the TypeScript adapter).
			cases[15].want = "alice,bob,dave"
		}
		for _, c := range cases {
			rs, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: c.where})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if got := sortedNames(rs); got != c.want {
				t.Errorf("%s: got %q, want %q", c.name, got, c.want)
			}
			n, err := a.Count(ctx, "user", c.where)
			if err != nil || int(n) != len(rs) {
				t.Errorf("%s: count %d (%v), findMany %d", c.name, n, err, len(rs))
			}
		}
	})
}

func TestWhereAndOrFolding(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, log := e.newAdapter(t, setup{})
		seedUsers(t, a)
		// a OR b OR c AND d  →  (a AND d) AND (b OR c), as convertWhereClause folds them.
		where := []adapter.Where{
			{Field: "age", Value: 30, Operator: adapter.Gte},
			{Field: "name", Value: "alice", Connector: adapter.Or},
			{Field: "name", Value: "dave", Connector: adapter.Or},
			{Field: "nickname", Value: nil, Operator: adapter.Ne},
		}
		log.reset()
		rs, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: where})
		if err != nil {
			t.Fatal(err)
		}
		if got := sortedNames(rs); got != "alice,dave" {
			t.Fatalf("got %q", got)
		}
		stmts := log.statements()
		q := func(s string) string { return e.d.Quote(s) }
		u := q("user") + "."
		wantFrag := "WHERE (" + u + q("age") + " >= " + e.d.Placeholder(1) + " AND " + u + q("nickname") + " IS NOT NULL) AND (" +
			u + q("name") + " = " + e.d.Placeholder(2) + " OR " + u + q("name") + " = " + e.d.Placeholder(3) + ")"
		if len(stmts) != 1 || !strings.Contains(stmts[0], wantFrag) {
			t.Fatalf("sql %q does not contain %q", stmts, wantFrag)
		}
		// Only OR clauses: the first clause (connector AND by default) still joins the AND
		// group, exactly like upstream.
		rs, _ = a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{
			{Field: "name", Value: "bob", Connector: adapter.Or},
			{Field: "name", Value: "carol", Connector: adapter.Or},
		}})
		if got := sortedNames(rs); got != "bob,carol" {
			t.Fatalf("or-only: %q", got)
		}
		rs, _ = a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{
			{Field: "name", Value: "bob"},
			{Field: "name", Value: "carol", Connector: adapter.Or},
		}})
		// (name = bob) AND (name = carol): upstream ANDs the OR group with the AND group.
		if got := sortedNames(rs); got != "" {
			t.Fatalf("and + single or: %q", got)
		}
	})
}

func TestCaseInsensitive(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		seedUsers(t, a)
		cases := []struct {
			name  string
			where adapter.Where
			want  string
		}{
			{"eq", adapter.Where{Field: "email", Value: "DAVE@EXAMPLE.COM", Insensitive: true}, "dave"},
			{"ne", adapter.Where{Field: "email", Value: "dave@example.com", Operator: adapter.Ne, Insensitive: true}, "alice,bob,carol"},
			{"in", adapter.Where{Field: "email", Value: []string{"ALICE@example.com", "dave@example.com"}, Operator: adapter.In, Insensitive: true}, "alice,dave"},
			{"not_in", adapter.Where{Field: "email", Value: []string{"ALICE@example.com", "dave@example.com"}, Operator: adapter.NotIn, Insensitive: true}, "bob,carol"},
			{"contains", adapter.Where{Field: "email", Value: "EXAMPLE", Operator: adapter.Contains, Insensitive: true}, "alice,bob,dave"},
			{"starts_with", adapter.Where{Field: "name", Value: "CA", Operator: adapter.StartsWith, Insensitive: true}, "carol"},
			{"ends_with", adapter.Where{Field: "email", Value: ".ORG", Operator: adapter.EndsWith, Insensitive: true}, "carol"},
			// non-string values ignore the mode
			{"number", adapter.Where{Field: "age", Value: 25, Insensitive: true}, "bob"},
		}
		for _, c := range cases {
			rs, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{c.where}})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if got := sortedNames(rs); got != c.want {
				t.Errorf("%s: got %q, want %q", c.name, got, c.want)
			}
		}
		// Sensitive eq does not match a different case. MySQL's default collation is
		// case-insensitive (the upstream MySQL suite disables this test too).
		if e.d != MySQL {
			rs, _ := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: "DAVE@EXAMPLE.COM"}}})
			if len(rs) != 0 {
				t.Errorf("sensitive eq matched %v", names(rs))
			}
		}
	})
}

func TestLikeEscaping(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		for _, n := range []string{"100%", "1000", "a_b", "axb", "x!y", "back\\slash"} {
			mustCreate(t, a, "user", adapter.Record{"name": n, "email": strings.NewReplacer("%", "p", "!", "e", "\\", "s").Replace(n) + "@x.io"})
		}
		cases := []struct {
			op   adapter.Operator
			v    string
			want string
		}{
			{adapter.Contains, "%", "100%"},
			{adapter.EndsWith, "0%", "100%"},
			{adapter.StartsWith, "100", "100%,1000"},
			{adapter.Contains, "_", "a_b"},
			{adapter.Contains, "!", "x!y"},
			{adapter.Contains, "!y", "x!y"},
			{adapter.Contains, "\\", "back\\slash"},
		}
		for _, c := range cases {
			for _, insensitive := range []bool{false, true} {
				rs, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: c.v, Operator: c.op, Insensitive: insensitive}}})
				if err != nil {
					t.Fatal(err)
				}
				if got := sortedNames(rs); got != c.want {
					t.Errorf("%s %q (insensitive=%v): got %q, want %q", c.op, c.v, insensitive, got, c.want)
				}
			}
		}
	})
}

func TestSortLimitOffset(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		seedUsers(t, a)
		find := func(in adapter.FindManyInput) string {
			t.Helper()
			in.Model = "user"
			rs, err := a.FindMany(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			return strings.Join(names(rs), ",")
		}
		if got := find(adapter.FindManyInput{SortBy: &adapter.SortBy{Field: "age", Direction: "desc"}}); got != "dave,carol,alice,bob" {
			t.Errorf("sort desc: %s", got)
		}
		if got := find(adapter.FindManyInput{SortBy: &adapter.SortBy{Field: "createdAt", Direction: "asc"}, Limit: 2}); got != "alice,bob" {
			t.Errorf("sort+limit: %s", got)
		}
		if got := find(adapter.FindManyInput{SortBy: &adapter.SortBy{Field: "name", Direction: "asc"}, Limit: 2, Offset: 1}); got != "bob,carol" {
			t.Errorf("limit+offset: %s", got)
		}
		if got := find(adapter.FindManyInput{SortBy: &adapter.SortBy{Field: "name", Direction: "asc"}, Offset: 3}); got != "dave" {
			t.Errorf("offset: %s", got)
		}
		if got := find(adapter.FindManyInput{Where: []adapter.Where{{Field: "age", Value: 26, Operator: adapter.Gt}}, SortBy: &adapter.SortBy{Field: "age", Direction: "asc"}, Limit: 1}); got != "alice" {
			t.Errorf("where+sort+limit: %s", got)
		}
		// OFFSET without LIMIT (needs a LIMIT clause on MySQL and SQLite).
		q := adapter.Query{Model: "user", ModelKey: "user", Offset: 2, SortBy: &adapter.SortBy{Field: "name", Direction: "asc"}}
		rs, err := customOf(a).FindMany(ctx, q)
		if err != nil || strings.Join(names(rs), ",") != "carol,dave" {
			t.Errorf("offset only: %v %v", names(rs), err)
		}
	})
}

func TestUpdateCountDelete(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		seedUsers(t, a)
		upd, err := a.Update(ctx, "user", []adapter.Where{{Field: "name", Value: "bob"}}, adapter.Record{"emailVerified": true, "age": 26})
		if err != nil || upd == nil || upd["emailVerified"] != true || upd["age"] != int64(26) || upd["name"] != "bob" {
			t.Fatalf("update: %v %v", upd, err)
		}
		// updatedAt onUpdate
		if ts, ok := upd["updatedAt"].(time.Time); !ok || time.Since(ts) > time.Minute {
			t.Fatalf("updatedAt: %v", upd["updatedAt"])
		}
		none, err := a.Update(ctx, "user", []adapter.Where{{Field: "name", Value: "nobody"}}, adapter.Record{"age": 1})
		if err != nil || none != nil {
			t.Fatalf("update no match: %v %v", none, err)
		}
		empty, err := a.Update(ctx, "user", nil, adapter.Record{"age": 1})
		if err != nil || empty != nil {
			t.Fatalf("update empty where: %v %v", empty, err)
		}
		if n, _ := a.Count(ctx, "user", []adapter.Where{{Field: "age", Value: 1}}); n != 0 {
			t.Fatal("update with empty where must not touch rows")
		}
		// Update targeting several rows updates all of them and returns one.
		upd, err = a.Update(ctx, "user", []adapter.Where{{Field: "age", Value: 35, Operator: adapter.Gte}}, adapter.Record{"nickname": "senior"})
		if err != nil || upd == nil || upd["nickname"] != "senior" {
			t.Fatalf("multi-row update: %v %v", upd, err)
		}
		if n, _ := a.Count(ctx, "user", []adapter.Where{{Field: "nickname", Value: "senior"}}); n != 2 {
			t.Fatalf("multi-row update count %d", n)
		}
		n, err := a.UpdateMany(ctx, "user", []adapter.Where{{Field: "age", Value: 30, Operator: adapter.Lt}}, adapter.Record{"image": "img"})
		if err != nil || n != 1 {
			t.Fatalf("updateMany: %d %v", n, err)
		}
		total, err := a.Count(ctx, "user", nil)
		if err != nil || total != 4 {
			t.Fatalf("count: %d %v", total, err)
		}
		if err := a.Delete(ctx, "user", []adapter.Where{{Field: "name", Value: "alice"}}); err != nil {
			t.Fatal(err)
		}
		d, err := a.DeleteMany(ctx, "user", []adapter.Where{{Field: "age", Value: 35, Operator: adapter.Gte}})
		if err != nil || d != 2 {
			t.Fatalf("deleteMany: %d %v", d, err)
		}
		if total, _ := a.Count(ctx, "user", nil); total != 1 {
			t.Fatalf("remaining %d", total)
		}
	})
}

// A matched row whose values do not change is still a match (mysql2 reports found rows;
// go-sql-driver reports changed rows by default).
func TestUpdateWithUnchangedValues(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		seedUsers(t, a)
		pin := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
		if _, err := a.UpdateMany(ctx, "user", nil, adapter.Record{"updatedAt": pin}); err != nil {
			t.Fatal(err)
		}
		upd, err := a.Update(ctx, "user", []adapter.Where{{Field: "name", Value: "bob"}}, adapter.Record{"emailVerified": false, "updatedAt": pin})
		if err != nil || upd == nil || upd["name"] != "bob" {
			t.Fatalf("unchanged update: %v %v", upd, err)
		}
		n, err := a.UpdateMany(ctx, "user", []adapter.Where{{Field: "emailVerified", Value: false}}, adapter.Record{"emailVerified": false, "updatedAt": pin})
		if err != nil || n != 4 {
			t.Fatalf("unchanged updateMany: %d %v", n, err)
		}
		// set-only incrementOne whose values are unchanged still returns the row
		r, err := a.IncrementOne(ctx, adapter.IncrementInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: "bob"}}, Set: adapter.Record{"age": 25, "updatedAt": pin}})
		if err != nil || r == nil || r["age"] != int64(25) {
			t.Fatalf("unchanged incrementOne: %v %v", r, err)
		}
	})
}

func TestJoins(t *testing.T) {
	for _, native := range []bool{true, false} {
		t.Run(map[bool]string{true: "native", false: "fallback"}[native], func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, e *env) {
				a, log := e.newAdapter(t, setup{opts: adapter.Options{Joins: native}})
				u1 := mustCreate(t, a, "user", user("Ann"))
				u2 := mustCreate(t, a, "user", user("Ben"))
				mustCreate(t, a, "user", user("Cid"))
				for i := 0; i < 3; i++ {
					mustCreate(t, a, "account", adapter.Record{"accountId": "acc" + string(rune('0'+i)), "providerId": "credential", "userId": u1["id"], "updatedAt": time.Now()})
				}
				mustCreate(t, a, "account", adapter.Record{"accountId": "b0", "providerId": "github", "userId": u2["id"], "updatedAt": time.Now()})
				s := mustCreate(t, a, "session", adapter.Record{"token": "tok", "userId": u1["id"], "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})

				log.reset()
				got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u1["id"]}}, Join: map[string]adapter.Join{"account": {}, "session": {}}})
				if err != nil || got == nil {
					t.Fatalf("findOne join: %v %v", got, err)
				}
				accs, _ := got["account"].([]adapter.Record)
				sess, _ := got["session"].([]adapter.Record)
				if len(accs) != 3 || len(sess) != 1 || sess[0]["token"] != "tok" || accs[0]["userId"] != u1["id"] {
					t.Fatalf("joined: %#v", got)
				}
				if _, ok := sess[0]["expiresAt"].(time.Time); !ok {
					t.Fatalf("joined values must be decoded: %#v", sess[0])
				}
				if native {
					stmts := log.statements()
					if len(stmts) != 1 || !strings.Contains(stmts[0], "LEFT JOIN") {
						t.Fatalf("native join should be one query: %q", stmts)
					}
				}
				// join limit
				got, _ = a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u1["id"]}}, Join: map[string]adapter.Join{"account": {Limit: 2}}})
				if accs, _ := got["account"].([]adapter.Record); len(accs) != 2 {
					t.Fatalf("join limit: %v", got["account"])
				}
				// one-to-one (session → user)
				gs, err := a.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "id", Value: s["id"]}}, Join: map[string]adapter.Join{"user": {}}})
				if err != nil || gs == nil {
					t.Fatal(err)
				}
				if ju, _ := gs["user"].(adapter.Record); ju == nil || ju["name"] != "Ann" || ju["emailVerified"] != false {
					t.Fatalf("one-to-one: %#v", gs["user"])
				}
				// findMany with joins, sort and limit; users without accounts get []
				many, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "name", Direction: "desc"}, Join: map[string]adapter.Join{"account": {}}})
				if err != nil || len(many) != 3 {
					t.Fatalf("findMany join: %v %v", many, err)
				}
				if strings.Join(names(many), ",") != "Cid,Ben,Ann" {
					t.Fatalf("join order: %v", names(many))
				}
				counts := []int{len(many[0]["account"].([]adapter.Record)), len(many[1]["account"].([]adapter.Record)), len(many[2]["account"].([]adapter.Record))}
				if counts[0] != 0 || counts[1] != 1 || counts[2] != 3 {
					t.Fatalf("join counts %v", counts)
				}
				paged, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "name", Direction: "asc"}, Limit: 1, Offset: 1, Join: map[string]adapter.Join{"account": {}}})
				if err != nil || len(paged) != 1 || paged[0]["name"] != "Ben" || len(paged[0]["account"].([]adapter.Record)) != 1 {
					t.Fatalf("paged join: %v %v", paged, err)
				}
				// select + join keeps the join key
				sel, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u2["id"]}}, Select: []string{"name"}, Join: map[string]adapter.Join{"account": {}}})
				if err != nil || sel == nil || sel["name"] != "Ben" || len(sel["account"].([]adapter.Record)) != 1 {
					t.Fatalf("select+join: %v %v", sel, err)
				}
				// session with no user match (one-to-one null) via a where that matches nothing
				nothing, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "name", Value: "zzz"}}, Join: map[string]adapter.Join{"account": {}}})
				if err != nil || len(nothing) != 0 {
					t.Fatalf("empty join result: %v %v", nothing, err)
				}
			})
		})
	}
}

func TestConsumeOne(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, log := e.newAdapter(t, setup{})
		for _, v := range []string{"first", "second", "third"} {
			mustCreate(t, a, "verification", adapter.Record{"identifier": "same-identifier", "value": v, "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
		}
		log.reset()
		got, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "identifier", Value: "same-identifier"}})
		if err != nil || got == nil || got["identifier"] != "same-identifier" {
			t.Fatalf("consumeOne: %v %v", got, err)
		}
		stmts := log.statements()
		if _, ok := got["expiresAt"].(time.Time); !ok {
			t.Fatalf("consumed row must be decoded: %#v", got)
		}
		if n, _ := a.Count(ctx, "verification", nil); n != 2 {
			t.Fatalf("consumeOne must delete exactly one row, %d left", n)
		}
		if gone, _ := a.FindOne(ctx, adapter.FindOneInput{Model: "verification", Where: []adapter.Where{{Field: "id", Value: got["id"]}}}); gone != nil {
			t.Fatal("consumed row still present")
		}
		if e.d == MySQL {
			if len(stmts) != 2 || !strings.HasSuffix(stmts[0], "LIMIT 1 FOR UPDATE") || !strings.HasPrefix(stmts[1], "DELETE FROM") {
				t.Fatalf("mysql consumeOne statements: %q", stmts)
			}
		} else {
			// delete ... where id in (select id ... limit 1) and <where> returning *
			want := regexp.MustCompile(`^DELETE FROM "verification" WHERE "verification"\."id" IN \(SELECT "verification"\."id" FROM "verification" WHERE \("verification"\."identifier" = \S+\) LIMIT 1\) AND \("verification"\."identifier" = \S+\) RETURNING \*$`)
			if len(stmts) != 1 || !want.MatchString(stmts[0]) {
				t.Fatalf("consumeOne statement: %q", stmts)
			}
		}
		none, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "identifier", Value: "other"}})
		if err != nil || none != nil {
			t.Fatalf("consumeOne no match: %v %v", none, err)
		}
		// concurrent consumers: each row is handed out exactly once
		var wg sync.WaitGroup
		var won atomic.Int32
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := a.ConsumeOne(ctx, "verification", []adapter.Where{{Field: "value", Value: "third"}})
				if err != nil {
					errs <- err
					return
				}
				if r != nil {
					won.Add(1)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if e.d == MySQL && isDeadlock(err) {
				continue
			}
			t.Fatal(err)
		}
		if won.Load() > 1 {
			t.Fatalf("row consumed %d times", won.Load())
		}
	})
}

func isDeadlock(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Deadlock")
}

func TestTransactions(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		if _, ok := customOf(a).(adapter.Transactor); !ok {
			t.Fatal("transactions are enabled by default")
		}
		// commit
		err := a.Transaction(ctx, func(c2 contextT, tx adapter.Adapter) error {
			mustCreateCtx(t, c2, tx, "user", user("Tx1"))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := a.Count(ctx, "user", nil); n != 1 {
			t.Fatalf("commit: %d", n)
		}
		// rollback on error, including writes of a nested transaction
		boom := errors.New("boom")
		err = a.Transaction(ctx, func(c2 contextT, tx adapter.Adapter) error {
			mustCreateCtx(t, c2, tx, "user", user("Tx2"))
			inner := tx.Transaction(c2, func(c3 contextT, tx2 adapter.Adapter) error {
				// the nested transaction reuses the outer one: it sees Tx2
				n, err := tx2.Count(c3, "user", nil)
				if err != nil || n != 2 {
					t.Errorf("nested tx should see outer writes: %d %v", n, err)
				}
				mustCreateCtx(t, c3, tx2, "user", user("Tx3"))
				return nil
			})
			if inner != nil {
				return inner
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("expected boom, got %v", err)
		}
		if n, _ := a.Count(ctx, "user", nil); n != 1 {
			t.Fatalf("rollback: %d users", n)
		}
		// rollback on panic
		func() {
			defer func() { _ = recover() }()
			_ = a.Transaction(ctx, func(c2 contextT, tx adapter.Adapter) error {
				mustCreateCtx(t, c2, tx, "user", user("Tx4"))
				panic("boom")
			})
		}()
		if n, _ := a.Count(ctx, "user", nil); n != 1 {
			t.Fatalf("panic rollback: %d users", n)
		}
		// atomic operations inside a transaction use it
		err = a.Transaction(ctx, func(c2 contextT, tx adapter.Adapter) error {
			v := mustCreateCtx(t, c2, tx, "verification", adapter.Record{"identifier": "i", "value": "v", "expiresAt": time.Now()})
			got, err := tx.ConsumeOne(c2, "verification", []adapter.Where{{Field: "id", Value: v["id"]}})
			if err != nil || got == nil {
				t.Errorf("consume in tx: %v %v", got, err)
			}
			c := mustCreateCtx(t, c2, tx, "counters", adapter.Record{"name": "c", "remaining": 1, "used": 0})
			inc, err := tx.IncrementOne(c2, adapter.IncrementInput{Model: "counters", Where: []adapter.Where{{Field: "id", Value: c["id"]}}, Increment: map[string]float64{"used": 1}})
			if err != nil || inc == nil || inc["used"] != int64(1) {
				t.Errorf("increment in tx: %v %v", inc, err)
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if n, _ := a.Count(ctx, "counters", nil); n != 0 {
			t.Fatal("counter insert should be rolled back")
		}
	})
}

func TestTransactionDisabled(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		off := false
		a, _ := e.newAdapter(t, setup{cfg: Config{Transaction: &off}})
		if _, ok := customOf(a).(adapter.Transactor); ok {
			t.Fatal("transaction: false must not expose a Transactor")
		}
		boom := errors.New("boom")
		err := a.Transaction(ctx, func(c2 contextT, tx adapter.Adapter) error {
			mustCreateCtx(t, c2, tx, "user", user("NoTx"))
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if n, _ := a.Count(ctx, "user", nil); n != 1 {
			t.Fatalf("without transactions writes persist, got %d", n)
		}
	})
}

func TestSerialIDs(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{opts: adapter.Options{IDMode: adapter.IDSerial}})
		u1 := mustCreate(t, a, "user", user("One"))
		u2 := mustCreate(t, a, "user", user("Two"))
		if u1["id"] != "1" || u2["id"] != "2" {
			t.Fatalf("serial ids: %v %v", u1["id"], u2["id"])
		}
		s := mustCreate(t, a, "session", adapter.Record{"token": "t", "userId": u2["id"], "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
		if s["userId"] != "2" || s["id"] != "1" {
			t.Fatalf("session: %v", s)
		}
		got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "session", Where: []adapter.Where{{Field: "userId", Value: "2"}}, Join: map[string]adapter.Join{"user": {}}})
		if err != nil || got == nil || got["user"].(adapter.Record)["name"] != "Two" {
			t.Fatalf("serial join: %v %v", got, err)
		}
		forced := mustCreateForce(t, a, "user", adapter.Record{"id": "100", "name": "Hundred", "email": "h@example.com"})
		if forced["id"] != "100" {
			t.Fatalf("forceAllowId: %v", forced["id"])
		}
		raw := e.row(t, `SELECT "id" FROM "user" WHERE "email" = ?`, "h@example.com")
		if raw["id"] != int64(100) {
			t.Fatalf("serial ids are stored as integers: %#v", raw["id"])
		}
		if n, _ := a.DeleteMany(ctx, "user", []adapter.Where{{Field: "id", Value: []string{"1", "100"}, Operator: adapter.In}}); n != 2 {
			t.Fatalf("delete by serial ids: %d", n)
		}
	})
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUUIDIDs(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, log := e.newAdapter(t, setup{opts: adapter.Options{IDMode: adapter.IDUUID}})
		log.reset()
		u := mustCreate(t, a, "user", user("Uu"))
		id, _ := u["id"].(string)
		if !uuidRe.MatchString(id) {
			t.Fatalf("uuid id %q", u["id"])
		}
		stmts := log.statements()
		hasID := strings.Contains(stmts[0], e.d.Quote("id"))
		if e.d == Postgres && hasID {
			t.Fatalf("PostgreSQL generates uuids in the database (supportsUUIDs): %s", stmts[0])
		}
		if e.d != Postgres && !hasID {
			t.Fatalf("uuid must be generated by the adapter: %s", stmts[0])
		}
		s := mustCreate(t, a, "session", adapter.Record{"token": "t", "userId": id, "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
		if s["userId"] != id {
			t.Fatal(s)
		}
		const fixed = "9b2f3a3e-6c7d-4e8f-9a0b-1c2d3e4f5a6b"
		forced := mustCreateForce(t, a, "user", adapter.Record{"id": fixed, "name": "F", "email": "f@example.com"})
		if forced["id"] != fixed {
			t.Fatalf("forced uuid: %v", forced["id"])
		}
		got, _ := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: fixed}}})
		if got == nil {
			t.Fatal("find by uuid")
		}
	})
}

func TestUsePlural(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, log := e.newAdapter(t, setup{cfg: Config{UsePlural: true}})
		u := mustCreate(t, a, "user", user("Pl"))
		mustCreate(t, a, "session", adapter.Record{"token": "t", "userId": u["id"], "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
		log.reset()
		got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: u["id"]}}, Join: map[string]adapter.Join{"session": {}}})
		if err != nil || got == nil || len(got["session"].([]adapter.Record)) != 1 {
			t.Fatalf("plural: %v %v", got, err)
		}
		if n := e.row(t, `SELECT COUNT(*) AS "n" FROM "users"`)["n"]; n != int64(1) {
			t.Fatalf("rows in users: %v", n)
		}
		_ = log
	})
}

func TestModifiedModelAndFieldNames(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{schema: dbschema.Options{
			User:    dbschema.ModelOptions{ModelName: "members", Fields: map[string]string{"emailVerified": "email_verified", "createdAt": "created_at"}},
			Session: dbschema.ModelOptions{Fields: map[string]string{"userId": "member_id"}},
		}, opts: adapter.Options{Joins: true}})
		u := mustCreate(t, a, "user", user("Renamed"))
		mustCreate(t, a, "session", adapter.Record{"token": "t", "userId": u["id"], "expiresAt": time.Now().Add(time.Hour), "updatedAt": time.Now()})
		raw := e.row(t, `SELECT "email_verified", "created_at" FROM "members"`)
		if raw["email_verified"] == nil || raw["created_at"] == nil {
			t.Fatalf("physical columns: %v", raw)
		}
		got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "emailVerified", Value: false}}, Join: map[string]adapter.Join{"session": {}}})
		if err != nil || got == nil || got["emailVerified"] != false {
			t.Fatalf("renamed: %v %v", got, err)
		}
		if ss := got["session"].([]adapter.Record); len(ss) != 1 || ss[0]["userId"] != u["id"] {
			t.Fatalf("renamed join: %v", got["session"])
		}
		rs, err := a.FindMany(ctx, adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "createdAt", Direction: "desc"}})
		if err != nil || len(rs) != 1 {
			t.Fatal(err)
		}
	})
}

func TestIncrementConcurrency(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{})
		c := mustCreate(t, a, "counters", adapter.Record{"name": "c", "remaining": 5, "used": 0, "status": "open"})
		var wg sync.WaitGroup
		var ok atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for attempt := 0; attempt < 20; attempt++ {
					r, err := a.IncrementOne(ctx, adapter.IncrementInput{Model: "counters",
						Where:     []adapter.Where{{Field: "id", Value: c["id"]}, {Field: "remaining", Value: 0, Operator: adapter.Gt}},
						Increment: map[string]float64{"remaining": -1, "used": 1}})
					if err != nil && isDeadlock(err) {
						continue
					}
					if err != nil {
						t.Error(err)
					}
					if r != nil {
						ok.Add(1)
					}
					return
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 5 {
			t.Fatalf("%d decrements succeeded, want 5", ok.Load())
		}
		row, _ := a.FindOne(ctx, adapter.FindOneInput{Model: "counters", Where: []adapter.Where{{Field: "id", Value: c["id"]}}})
		if row["remaining"] != int64(0) || row["used"] != int64(5) {
			t.Fatalf("final counter %v", row)
		}
	})
}

func TestDebugLogs(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, log := e.newAdapter(t, setup{})
		log.reset()
		mustCreate(t, a, "user", user("Logged"))
		stmts := log.statements()
		if len(stmts) == 0 || !strings.HasPrefix(stmts[0], "INSERT INTO "+e.d.Quote("user")) {
			t.Fatalf("debug logs: %q", stmts)
		}
		// disabled
		quiet := &captureLogger{}
		b, err := New(e.db, Config{})(adapter.Options{Schema: a.Schema(), Logger: quiet})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Count(ctx, "user", nil); err != nil {
			t.Fatal(err)
		}
		if len(quiet.statements()) != 0 {
			t.Fatal("debug logs must be off by default")
		}
	})
}

func TestMigratorDelegates(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		a, _ := e.newAdapter(t, setup{noTables: true})
		m, ok := adapter.AsMigrator(a)
		if !ok {
			t.Fatal("the SQL adapter implements adapter.Migrator")
		}
		plan, err := m.PlanMigrations(ctx, a.Schema())
		if plan == nil && err == nil {
			t.Fatal("PlanMigrations returned neither a plan nor an error")
		}
	})
}
