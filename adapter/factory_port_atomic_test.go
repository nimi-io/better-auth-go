package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"

	_ "modernc.org/sqlite"
)

// Port of packages/core/src/db/adapter/factory.test.ts.

// coreTestAdapter is createTestAdapter in factory.test.ts.
func coreTestAdapter(t testing.TB, driver CustomAdapter) Adapter {
	t.Helper()
	cfg := Config{
		AdapterID:   "test-adapter",
		AdapterName: "Test Adapter",
		UsePlural:   true,
		CustomTransformInput: func(p TransformParams) any {
			if s, ok := p.Data.(string); ok && p.Field == "identifier_text" {
				return s + ":" + p.Action
			}
			return p.Data
		},
		CustomTransformOutput: func(p TransformParams) any {
			if s, ok := p.Data.(string); ok && p.Field == "identifier" {
				return s + ":output"
			}
			return p.Data
		},
	}
	return newAdapter(t, cfg, driver, Options{}, db.Options{Verification: db.ModelOptions{
		ModelName: "verificationRecord",
		Fields:    map[string]string{"identifier": "identifier_text"},
		AdditionalFields: []db.Field{
			{Name: "attempts", Type: db.TypeNumber, Required: db.False, FieldName: "attempt_count"},
		},
	}})
}

func TestCreateAdapterFactoryModelIdentity(t *testing.T) {
	t.Run("keeps the schema model when its custom name matches another schema key", func(t *testing.T) {
		var got Query
		calls := 0
		ad := newAdapter(t, Config{AdapterID: "test-adapter"}, &fakeAtomicDriver{fakeDriver: &fakeDriver{
			findOne: func(_ context.Context, q Query) (Record, error) {
				got = q
				calls++
				return nil, nil
			},
		}}, Options{Joins: true}, db.Options{
			User:    db.ModelOptions{ModelName: "account"},
			Account: db.ModelOptions{ModelName: "identity"},
		})
		_, err := ad.FindOne(context.Background(), FindOneInput{
			Model: "session",
			Where: []Where{{Field: "id", Value: "session-id"}},
			Join:  map[string]Join{"user": {}},
		})
		mustNoErr(t, err)
		if calls != 1 {
			t.Fatalf("findOne called %d times", calls)
		}
		if got.Model != "session" || got.ModelKey != "session" {
			t.Fatalf("model = %q, modelKey = %q", got.Model, got.ModelKey)
		}
		if len(got.Join) != 1 || got.Join["account"].ModelKey != "user" {
			t.Fatalf("join = %#v", got.Join)
		}
	})
}

func TestCreateAdapterFactoryAtomicPrimitives(t *testing.T) {
	ctx := context.Background()

	t.Run("delegates consumeOne to the native adapter with transformed where and output", func(t *testing.T) {
		ad := coreTestAdapter(t, &fakeAtomicDriver{fakeDriver: &fakeDriver{}, consumeOne: func(_ context.Context, q Query) (Record, error) {
			if q.Model != "verificationRecords" {
				t.Errorf("model = %q", q.Model)
			}
			wantEqual(t, q.Where, []CleanedWhere{{Field: "identifier_text", Value: "token:consumeOne", Operator: Eq, Connector: And}}, "where")
			return Record{"id": "verification-id", "identifier_text": "stored-token"}, nil
		}})
		res, err := ad.ConsumeOne(ctx, "verification", []Where{{Field: "identifier", Value: "token"}})
		mustNoErr(t, err)
		wantEqual(t, map[string]any(res), map[string]any{"id": "verification-id", "identifier": "stored-token:output"}, "result")
	})

	t.Run("delegates incrementOne to the native adapter with mapped increment fields", func(t *testing.T) {
		ad := coreTestAdapter(t, &fakeAtomicDriver{fakeDriver: &fakeDriver{}, incrementOne: func(_ context.Context, q Query, inc map[string]float64, set Record) (Record, error) {
			if q.Model != "verificationRecords" {
				t.Errorf("model = %q", q.Model)
			}
			wantEqual(t, q.Where, []CleanedWhere{{Field: "identifier_text", Value: "token:incrementOne", Operator: Eq, Connector: And}}, "where")
			wantEqual(t, map[string]any{"attempt_count": inc["attempt_count"]}, map[string]any{"attempt_count": 1}, "increment")
			if len(inc) != 1 {
				t.Errorf("increment = %#v", inc)
			}
			if _, ok := set["updatedAt"].(time.Time); !ok || len(set) != 2 || set["value"] != "next" {
				t.Errorf("set = %#v", set)
			}
			return Record{"id": "verification-id", "identifier_text": "stored-token", "attempt_count": 2, "value": "next"}, nil
		}})
		res, err := ad.IncrementOne(ctx, IncrementInput{
			Model:     "verification",
			Where:     []Where{{Field: "identifier", Value: "token"}},
			Increment: map[string]float64{"attempts": 1},
			Set:       Record{"value": "next"},
		})
		mustNoErr(t, err)
		wantEqual(t, map[string]any(res), map[string]any{
			"id": "verification-id", "identifier": "stored-token:output", "attempts": 2, "value": "next",
		}, "result")
	})

	t.Run("throws before native incrementOne when every update field is transformed away", func(t *testing.T) {
		// JavaScript `undefined` is jsonx.Undefined in Go.
		cfg := Config{
			AdapterID:   "test-adapter",
			AdapterName: "Test Adapter",
			UsePlural:   true,
			CustomTransformInput: func(p TransformParams) any {
				if p.Action == "update" {
					return jsonx.Undefined
				}
				return p.Data
			},
		}
		ad := newAdapter(t, cfg, &fakeAtomicDriver{fakeDriver: &fakeDriver{}, incrementOne: func(context.Context, Query, map[string]float64, Record) (Record, error) {
			return nil, errors.New("incrementOne should not be called")
		}}, Options{}, db.Options{Verification: db.ModelOptions{
			ModelName:        "verificationRecord",
			AdditionalFields: []db.Field{{Name: "attempts", Type: db.TypeNumber, FieldName: "attempt_count"}},
		}})
		_, err := ad.IncrementOne(ctx, IncrementInput{
			Model:     "verification",
			Where:     []Where{{Field: "identifier", Value: "token"}},
			Increment: map[string]float64{},
			Set:       Record{"attempts": 1},
		})
		wantErr(t, err, `resolved to an empty update`)
	})

	t.Run("throws a clear error when updateMany does not return a finite count", func(t *testing.T) {
		t.Skip("CustomAdapter.UpdateMany returns int64, so a non-finite count (NaN) cannot be expressed")
	})
}

func TestCreateAdapterFactoryWhereValueCoercion(t *testing.T) {
	t.Run("coerces string where values to match field types before querying", func(t *testing.T) {
		var seen [][]CleanedWhere
		ad := newAdapter(t, Config{AdapterID: "test-adapter", AdapterName: "Test Adapter", SupportsBooleans: boolp(true)},
			&fakeAtomicDriver{fakeDriver: &fakeDriver{findMany: func(_ context.Context, q Query) ([]Record, error) {
				if q.Where != nil {
					seen = append(seen, q.Where)
				}
				return []Record{}, nil
			}}}, Options{}, db.Options{User: db.ModelOptions{AdditionalFields: []db.Field{
				{Name: "age", Type: db.TypeNumber, Required: db.False},
			}}})
		ctx := context.Background()
		for _, w := range []Where{
			{Field: "emailVerified", Operator: Eq, Value: "false"},
			{Field: "age", Operator: Eq, Value: "25"},
			{Field: "age", Operator: In, Value: []any{"25", "30"}},
		} {
			_, err := ad.FindMany(ctx, FindManyInput{Model: "user", Where: []Where{w}})
			mustNoErr(t, err)
		}
		want := [][]CleanedWhere{
			{{Field: "emailVerified", Value: false, Operator: Eq, Connector: And}},
			{{Field: "age", Value: 25, Operator: Eq, Connector: And}},
			{{Field: "age", Value: []any{25, 30}, Operator: In, Connector: And}},
		}
		if len(seen) != len(want) {
			t.Fatalf("seen = %#v", seen)
		}
		for i := range want {
			wantEqual(t, seen[i], want[i], fmt.Sprintf("where #%d", i))
		}
		if _, ok := seen[0][0].Value.(bool); !ok {
			t.Fatalf("emailVerified should be a boolean: %#v", seen[0][0].Value)
		}
		if _, ok := seen[1][0].Value.(string); ok {
			t.Fatalf("age should be a number: %#v", seen[1][0].Value)
		}
	})
}

// ---- legacy adapter atomic fallbacks ----

// legacySetup mirrors setup() upstream: a SQLite table behind a driver without native
// consumeOne / incrementOne, and two independent adapters built from the same factory.
type legacySetup struct {
	db            *sql.DB
	raw           *fakeDriver
	first, second Adapter
}

func sqlQuote(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

func sqlCondition(where []CleanedWhere) (string, error) {
	parts := make([]string, 0, len(where))
	for i, w := range where {
		if w.Operator != Eq && w.Operator != Gt {
			return "", errors.New("Unsupported test predicate")
		}
		p := ""
		if i > 0 {
			p = string(w.Connector) + " "
		}
		p += sqlQuote(w.Field) + " "
		switch {
		case w.Value == nil:
			p += "IS NULL"
		case w.Operator == Gt:
			p += "> ?"
		default:
			p += "= ?"
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "1=1", nil
	}
	return strings.Join(parts, " "), nil
}

func sqlValues(where []CleanedWhere) ([]any, error) {
	var out []any
	for _, w := range where {
		if w.Value == nil {
			continue
		}
		if _, isStr := w.Value.(string); !isStr {
			if _, isNum := numeric(w.Value); !isNum {
				return nil, errors.New("Unsupported test value")
			}
		}
		out = append(out, w.Value)
	}
	return out, nil
}

func queryRow(ctx context.Context, conn *sql.DB, query string, args ...any) (Record, error) {
	rows, err := conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, rows.Err()
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	out := Record{}
	for i, c := range cols {
		out[c] = vals[i]
	}
	return out, nil
}

func setupLegacy(t *testing.T) *legacySetup {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	mustNoErr(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
	_, err = conn.Exec(`CREATE TABLE verification (_id TEXT PRIMARY KEY, identifier TEXT, value TEXT, counter REAL, updatedAt TEXT)`)
	mustNoErr(t, err)
	_, err = conn.Exec(`INSERT INTO verification VALUES ('a', 'token', 'secret', NULL, NULL)`)
	mustNoErr(t, err)

	raw := &fakeDriver{}
	raw.findOne = func(ctx context.Context, q Query) (Record, error) {
		cond, err := sqlCondition(q.Where)
		if err != nil {
			return nil, err
		}
		args, err := sqlValues(q.Where)
		if err != nil {
			return nil, err
		}
		return queryRow(ctx, conn, `SELECT * FROM verification WHERE `+cond+` LIMIT 1`, args...)
	}
	raw.deleteMany = func(ctx context.Context, q Query) (int64, error) {
		cond, err := sqlCondition(q.Where)
		if err != nil {
			return 0, err
		}
		args, err := sqlValues(q.Where)
		if err != nil {
			return 0, err
		}
		res, err := conn.ExecContext(ctx, `DELETE FROM verification WHERE `+cond, args...)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	raw.updateMany = func(ctx context.Context, q Query, update Record) (int64, error) {
		fields := sortedKeys(update)
		sets := make([]string, len(fields))
		params := make([]any, 0, len(fields))
		for i, field := range fields {
			v := update[field]
			switch tv := v.(type) {
			case nil, string:
			case time.Time:
				// The Go port cannot disable input transforms, so the onUpdate updatedAt
				// reaches the driver; store it as ISO text.
				v = jsonx.ISOTime(tv)
			default:
				if _, isNum := numeric(v); !isNum {
					return 0, errors.New("Unsupported test update")
				}
			}
			sets[i] = sqlQuote(field) + " = ?"
			params = append(params, v)
		}
		cond, err := sqlCondition(q.Where)
		if err != nil {
			return 0, err
		}
		args, err := sqlValues(q.Where)
		if err != nil {
			return 0, err
		}
		res, err := conn.ExecContext(ctx, `UPDATE verification SET `+strings.Join(sets, ", ")+` WHERE `+cond, append(params, args...)...)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	factory := NewFactory(Config{
		AdapterID:              "legacy",
		MapKeysTransformInput:  map[string]string{"id": "_id"},
		MapKeysTransformOutput: map[string]string{"_id": "id"},
	}, func(Options, Helpers) (CustomAdapter, error) { return raw, nil })
	opts := func() Options {
		return Options{Schema: db.GetAuthTables(db.Options{Verification: db.ModelOptions{AdditionalFields: []db.Field{
			{Name: "attempts", Type: db.TypeNumber, Required: db.False, FieldName: "counter"},
		}}})}
	}
	first, err := factory(opts())
	mustNoErr(t, err)
	second, err := factory(opts())
	mustNoErr(t, err)
	return &legacySetup{db: conn, raw: raw, first: first, second: second}
}

func (s *legacySetup) row(t *testing.T, query string) Record {
	t.Helper()
	r, err := queryRow(context.Background(), s.db, query)
	mustNoErr(t, err)
	return r
}

func (s *legacySetup) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	_, err := s.db.Exec(query, args...)
	mustNoErr(t, err)
}

// parallel runs fns concurrently (Promise.all) and returns their results in order.
func parallel(fns ...func() (Record, error)) ([]Record, []error) {
	res := make([]Record, len(fns))
	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i], errs[i] = fn()
		}()
	}
	wg.Wait()
	return res, errs
}

func nonNil(rs []Record) []Record {
	var out []Record
	for _, r := range rs {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

func TestLegacyAdapterAtomicFallbacks(t *testing.T) {
	ctx := context.Background()
	request := []Where{{Field: "identifier", Value: "token"}}
	consume := func(ad Adapter) func() (Record, error) {
		return func() (Record, error) { return ad.ConsumeOne(ctx, "verification", request) }
	}
	incrementBy := func(ad Adapter, delta float64) func() (Record, error) {
		return func() (Record, error) {
			return ad.IncrementOne(ctx, IncrementInput{Model: "verification", Where: request, Increment: map[string]float64{"attempts": delta}})
		}
	}
	increment := func(ad Adapter) func() (Record, error) { return incrementBy(ad, 1) }
	noErrs := func(t *testing.T, errs []error) {
		t.Helper()
		for _, err := range errs {
			mustNoErr(t, err)
		}
	}

	t.Run("lets only one independent adapter consume a credential", func(t *testing.T) {
		s := setupLegacy(t)
		results, errs := parallel(consume(s.first), consume(s.second))
		noErrs(t, errs)
		got := nonNil(results)
		if len(got) != 1 {
			t.Fatalf("results = %#v", results)
		}
		matchObject(t, got[0], Record{"id": "a", "value": "secret"}, "consumed row")
		matchObject(t, s.row(t, "SELECT count(*) AS count FROM verification"), Record{"count": 0}, "remaining")
	})

	t.Run("does not lose concurrent increments starting from null", func(t *testing.T) {
		s := setupLegacy(t)
		results, errs := parallel(increment(s.first), increment(s.second), increment(s.first))
		noErrs(t, errs)
		var attempts []float64
		for _, r := range results {
			f, _ := ToFloat(r["attempts"])
			attempts = append(attempts, f)
		}
		sort.Float64s(attempts)
		wantEqual(t, attempts, []float64{1, 2, 3}, "attempts")
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": 3}, "stored counter")
	})

	t.Run("increments despite unrelated concurrent writes", func(t *testing.T) {
		s := setupLegacy(t)
		update := s.raw.updateMany
		s.raw.updateMany = func(ctx context.Context, q Query, u Record) (int64, error) {
			if _, err := s.db.ExecContext(ctx, "UPDATE verification SET value = value || '-changed'"); err != nil {
				return 0, err
			}
			return update(ctx, q, u)
		}
		res, err := increment(s.first)()
		mustNoErr(t, err)
		matchObject(t, res, Record{"attempts": 1}, "result")
		matchObject(t, s.row(t, "SELECT counter, value FROM verification"), Record{"counter": 1, "value": "secret-changed"}, "stored")
	})

	t.Run("treats an undefined legacy read as a missing row", func(t *testing.T) {
		s := setupLegacy(t)
		s.raw.findOne = func(context.Context, Query) (Record, error) { return nil, nil }
		res, err := consume(s.first)()
		mustNoErr(t, err)
		if res != nil {
			t.Fatalf("consumeOne = %#v", res)
		}
		res, err = increment(s.first)()
		mustNoErr(t, err)
		if res != nil {
			t.Fatalf("incrementOne = %#v", res)
		}
	})

	t.Run("uses stored counters even when output transformation is lossy", func(t *testing.T) {
		s := setupLegacy(t)
		s.exec(t, "UPDATE verification SET counter = 2")
		ad := newAdapter(t, Config{
			AdapterID:              "masked-counter",
			MapKeysTransformInput:  map[string]string{"id": "_id"},
			MapKeysTransformOutput: map[string]string{"_id": "id"},
			CustomTransformOutput: func(p TransformParams) any {
				if p.Field == "attempts" {
					return 0
				}
				return p.Data
			},
		}, s.raw, Options{}, db.Options{Verification: db.ModelOptions{AdditionalFields: []db.Field{
			{Name: "attempts", Type: db.TypeNumber, Required: db.False, FieldName: "counter"},
		}}})
		found, err := ad.FindOne(ctx, FindOneInput{Model: "verification", Where: request})
		mustNoErr(t, err)
		matchObject(t, found, Record{"attempts": 0}, "findOne")
		res, err := increment(ad)()
		mustNoErr(t, err)
		matchObject(t, res, Record{"attempts": 0}, "incrementOne")
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": 3}, "stored counter")
	})

	t.Run("returns the row produced by its own update", func(t *testing.T) {
		s := setupLegacy(t)
		update := s.raw.updateMany
		s.raw.updateMany = func(ctx context.Context, q Query, u Record) (int64, error) {
			n, err := update(ctx, q, u)
			if err != nil {
				return n, err
			}
			_, err = s.db.ExecContext(ctx, "UPDATE verification SET counter = 99")
			return n, err
		}
		res, err := increment(s.first)()
		mustNoErr(t, err)
		matchObject(t, res, Record{"attempts": 1}, "result")
	})

	t.Run("does not return a credential replaced between read and delete", func(t *testing.T) {
		s := setupLegacy(t)
		remove := s.raw.deleteMany
		s.raw.deleteMany = func(ctx context.Context, q Query) (int64, error) {
			if _, err := s.db.ExecContext(ctx, "UPDATE verification SET value = 'replacement'"); err != nil {
				return 0, err
			}
			return remove(ctx, q)
		}
		res, err := consume(s.first)()
		mustNoErr(t, err)
		if res != nil {
			t.Fatalf("consumeOne = %#v", res)
		}
		matchObject(t, s.row(t, "SELECT value FROM verification"), Record{"value": "replacement"}, "stored")
	})

	t.Run("keeps OR selectors from widening the guarded deletion", func(t *testing.T) {
		s := setupLegacy(t)
		s.exec(t, "INSERT INTO verification VALUES ('b', 'other', 'other-secret', 0, NULL)")
		_, err := s.first.ConsumeOne(ctx, "verification", []Where{
			{Field: "identifier", Value: "token"},
			{Field: "identifier", Value: "other", Connector: Or},
		})
		mustNoErr(t, err)
		matchObject(t, s.row(t, "SELECT count(*) AS count FROM verification"), Record{"count": 1}, "remaining")
	})

	t.Run("rejects contention exhaustion instead of reporting a missing row", func(t *testing.T) {
		s := setupLegacy(t)
		s.raw.updateMany = func(context.Context, Query, Record) (int64, error) { return 0, nil }
		_, err := increment(s.first)()
		wantErr(t, err, `contention`)
	})

	for _, count := range []any{2, -1, 0.5, math.NaN()} {
		t.Run(fmt.Sprintf("rejects invalid affected counts (%v)", count), func(t *testing.T) {
			n, ok := count.(int)
			if !ok {
				t.Skip("affected counts are int64 in Go; fractional and NaN counts cannot be expressed")
			}
			s := setupLegacy(t)
			s.raw.deleteMany = func(context.Context, Query) (int64, error) { return int64(n), nil }
			s.raw.updateMany = func(context.Context, Query, Record) (int64, error) { return int64(n), nil }
			_, err := consume(s.first)()
			wantErr(t, err, `affected`)
			_, err = increment(s.first)()
			wantErr(t, err, `affected`)
		})
	}

	t.Run("identifies invalid increment input before writing", func(t *testing.T) {
		s := setupLegacy(t)
		_, err := incrementBy(s.first, math.NaN())()
		wantErr(t, err, `^incrementOne requires finite increments`)
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": nil}, "stored counter")
	})

	t.Run("rejects bigint counters without coercion or writes", func(t *testing.T) {
		s := setupLegacy(t)
		read := s.raw.findOne
		s.raw.findOne = func(ctx context.Context, q Query) (Record, error) {
			r, err := read(ctx, q)
			if err != nil || r == nil {
				return r, err
			}
			big, _ := new(big.Int).SetString("9007199254740993", 10)
			r["counter"] = big
			return r, nil
		}
		_, err := increment(s.first)()
		wantErr(t, err, `finite numeric counter`)
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": nil}, "stored counter")
	})

	t.Run("rejects invalid counters before writing", func(t *testing.T) {
		s := setupLegacy(t)
		s.exec(t, "UPDATE verification SET counter = 'invalid'")
		_, err := increment(s.first)()
		wantErr(t, err, `counter`)
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": "invalid"}, "stored counter")
	})

	t.Run("handles an absent nullable counter with the null guard", func(t *testing.T) {
		s := setupLegacy(t)
		find := s.raw.findOne
		s.raw.findOne = func(ctx context.Context, q Query) (Record, error) {
			r, err := find(ctx, q)
			if r != nil {
				if v, ok := r["counter"]; ok && v == nil {
					delete(r, "counter")
				}
			}
			return r, err
		}
		_, errs := parallel(increment(s.first), increment(s.second))
		noErrs(t, errs)
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": 2}, "stored counter")
	})

	t.Run("honors a counter guard after losing a race", func(t *testing.T) {
		s := setupLegacy(t)
		s.exec(t, "UPDATE verification SET counter = 1")
		guarded := func(ad Adapter) func() (Record, error) {
			return func() (Record, error) {
				return ad.IncrementOne(ctx, IncrementInput{
					Model:     "verification",
					Where:     []Where{{Field: "attempts", Value: 0, Operator: Gt}},
					Increment: map[string]float64{"attempts": -1},
				})
			}
		}
		results, errs := parallel(guarded(s.first), guarded(s.second))
		noErrs(t, errs)
		if got := nonNil(results); len(got) != 1 {
			t.Fatalf("results = %#v", results)
		}
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": 0}, "stored counter")
	})

	t.Run("completes a no-op without relying on changed-row counts", func(t *testing.T) {
		s := setupLegacy(t)
		s.exec(t, "UPDATE verification SET counter = 1")
		s.raw.updateMany = func(context.Context, Query, Record) (int64, error) {
			return 0, errors.New("A no-op should not write")
		}
		res, err := incrementBy(s.first, 0)()
		mustNoErr(t, err)
		matchObject(t, res, Record{"attempts": 1}, "result")
	})

	t.Run("compares date values when a set-only update is a no-op", func(t *testing.T) {
		s := setupLegacy(t)
		find := s.raw.findOne
		tm := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		s.raw.findOne = func(ctx context.Context, q Query) (Record, error) {
			r, err := find(ctx, q)
			if r != nil {
				r["updatedAt"] = tm
			}
			return r, err
		}
		s.raw.updateMany = func(context.Context, Query, Record) (int64, error) {
			return 0, errors.New("A date no-op should not write")
		}
		res, err := s.first.IncrementOne(ctx, IncrementInput{
			Model: "verification", Where: request, Increment: map[string]float64{}, Set: Record{"updatedAt": tm},
		})
		mustNoErr(t, err)
		matchObject(t, res, Record{"updatedAt": tm}, "result")
	})

	t.Run("fails before writing when the row id is missing", func(t *testing.T) {
		s := setupLegacy(t)
		s.raw.findOne = func(context.Context, Query) (Record, error) {
			return Record{"identifier": "token", "value": "secret"}, nil
		}
		_, err := consume(s.first)()
		wantErr(t, err, `row id`)
		matchObject(t, s.row(t, "SELECT count(*) AS count FROM verification"), Record{"count": 1}, "remaining")
	})

	t.Run("allows unrelated structured data in returned rows", func(t *testing.T) {
		s := setupLegacy(t)
		find := s.raw.findOne
		s.raw.findOne = func(ctx context.Context, q Query) (Record, error) {
			r, err := find(ctx, q)
			if r != nil {
				r["metadata"] = map[string]any{"locale": "en"}
				r["tags"] = []any{"test"}
			}
			return r, err
		}
		res, err := consume(s.first)()
		mustNoErr(t, err)
		matchObject(t, res, Record{"id": "a", "value": "secret"}, "result")
		matchObject(t, s.row(t, "SELECT count(*) AS count FROM verification"), Record{"count": 0}, "remaining")
	})

	t.Run("rejects malformed reads instead of treating them as missing", func(t *testing.T) {
		t.Skip("CustomAdapter.FindOne returns a Record, so a non-object read (false) cannot be expressed")
	})

	t.Run("propagates write failures without reporting a successful increment", func(t *testing.T) {
		s := setupLegacy(t)
		failure := errors.New("backend unavailable")
		s.raw.updateMany = func(context.Context, Query, Record) (int64, error) { return 0, failure }
		_, err := increment(s.first)()
		if !errors.Is(err, failure) {
			t.Fatalf("err = %v, want %v", err, failure)
		}
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": nil}, "stored counter")
	})

	t.Run("uses adapter-owned transforms for object IDs", func(t *testing.T) {
		type objectID struct{ encoded string }
		physicalID := &objectID{encoded: "a"}
		raw := &fakeDriver{
			findOne: func(context.Context, Query) (Record, error) {
				return Record{"_id": physicalID, "identifier": "token", "value": "secret"}, nil
			},
			deleteMany: func(_ context.Context, q Query) (int64, error) {
				var found any
				for _, w := range q.Where {
					if w.Field == "_id" {
						found = w.Value
						break
					}
				}
				if found != physicalID {
					t.Errorf("_id guard value = %#v, want the physical id", found)
				}
				return 1, nil
			},
		}
		ad := newAdapter(t, Config{
			AdapterID:              "object-id",
			MapKeysTransformInput:  map[string]string{"id": "_id"},
			MapKeysTransformOutput: map[string]string{"_id": "id"},
			CustomTransformInput: func(p TransformParams) any {
				if p.Field == "_id" {
					return physicalID
				}
				return p.Data
			},
			CustomTransformOutput: func(p TransformParams) any {
				if p.Field == "id" {
					return "a"
				}
				return p.Data
			},
		}, raw, Options{}, db.Options{})
		res, err := ad.ConsumeOne(ctx, "verification", request)
		mustNoErr(t, err)
		matchObject(t, res, Record{"id": "a", "value": "secret"}, "result")
	})

	t.Run("rejects increments that cannot change a large counter", func(t *testing.T) {
		s := setupLegacy(t)
		s.exec(t, "UPDATE verification SET counter = ?", math.Pow(2, 53))
		_, err := increment(s.first)()
		wantErr(t, err, `safely`)
		matchObject(t, s.row(t, "SELECT counter FROM verification"), Record{"counter": math.Pow(2, 53)}, "stored counter")
	})

	t.Run("omits undefined assignments even when input transformation is disabled", func(t *testing.T) {
		t.Skip("adapter.Config has no DisableTransformInput, so undefined set values cannot reach the fallback untransformed")
	})

	t.Run("preserves explicit null assignments", func(t *testing.T) {
		// Upstream disables input transforms; the Go factory always transforms `set`, which
		// adds the onUpdate updatedAt next to the explicit null.
		s := setupLegacy(t)
		res, err := s.first.IncrementOne(ctx, IncrementInput{
			Model: "verification", Where: request, Increment: map[string]float64{}, Set: Record{"value": nil},
		})
		mustNoErr(t, err)
		if v, ok := res["value"]; !ok || v != nil {
			t.Fatalf("value = %#v (present %v)", v, ok)
		}
		stored := s.row(t, "SELECT value FROM verification")
		if v, ok := stored["value"]; !ok || v != nil {
			t.Fatalf("stored value = %#v", v)
		}
	})

	t.Run("treats undefined-only assignments as a no-op", func(t *testing.T) {
		t.Skip("adapter.Config has no DisableTransformInput, so undefined set values cannot reach the fallback untransformed")
	})

	t.Run("returns null when the selector does not match", func(t *testing.T) {
		s := setupLegacy(t)
		missing := []Where{{Field: "identifier", Value: "missing"}}
		res, err := s.first.ConsumeOne(ctx, "verification", missing)
		mustNoErr(t, err)
		if res != nil {
			t.Fatalf("consumeOne = %#v", res)
		}
		res, err = s.first.IncrementOne(ctx, IncrementInput{Model: "verification", Where: missing, Increment: map[string]float64{"attempts": 1}})
		mustNoErr(t, err)
		if res != nil {
			t.Fatalf("incrementOne = %#v", res)
		}
	})
}
