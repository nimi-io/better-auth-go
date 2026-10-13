package adapter

import (
	"context"
	"math"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Shared helpers for the ports of
//   - e2e/adapter/test/adapter-factory/adapter-factory.test.ts (factory_port_test.go)
//   - packages/core/src/db/adapter/factory.test.ts (factory_port_atomic_test.go)
//
// JavaScript `undefined` has no Go equivalent: the factory omits a key whose value would be
// undefined, so upstream's `toHaveProperty(key)` on an undefined value and
// `toEqual(undefined)` both map to "absent or nil" here (see undef).

// fakeDriver is a CustomAdapter whose operations default to the createTestAdapter wrapper
// upstream: create returns the data, update returns the update, finders return nothing.
type fakeDriver struct {
	create     func(ctx context.Context, model, modelKey string, data Record) (Record, error)
	findOne    func(ctx context.Context, q Query) (Record, error)
	findMany   func(ctx context.Context, q Query) ([]Record, error)
	count      func(ctx context.Context, q Query) (int64, error)
	update     func(ctx context.Context, q Query, update Record) (Record, error)
	updateMany func(ctx context.Context, q Query, update Record) (int64, error)
	delete     func(ctx context.Context, q Query) error
	deleteMany func(ctx context.Context, q Query) (int64, error)
}

func (d *fakeDriver) Create(ctx context.Context, model, modelKey string, data Record) (Record, error) {
	if d.create != nil {
		return d.create(ctx, model, modelKey, data)
	}
	return data, nil
}

func (d *fakeDriver) FindOne(ctx context.Context, q Query) (Record, error) {
	if d.findOne != nil {
		return d.findOne(ctx, q)
	}
	return nil, nil
}

func (d *fakeDriver) FindMany(ctx context.Context, q Query) ([]Record, error) {
	if d.findMany != nil {
		return d.findMany(ctx, q)
	}
	return []Record{}, nil
}

func (d *fakeDriver) Count(ctx context.Context, q Query) (int64, error) {
	if d.count != nil {
		return d.count(ctx, q)
	}
	return 0, nil
}

func (d *fakeDriver) Update(ctx context.Context, q Query, update Record) (Record, error) {
	if d.update != nil {
		return d.update(ctx, q, update)
	}
	return update, nil
}

func (d *fakeDriver) UpdateMany(ctx context.Context, q Query, update Record) (int64, error) {
	if d.updateMany != nil {
		return d.updateMany(ctx, q, update)
	}
	return 0, nil
}

func (d *fakeDriver) Delete(ctx context.Context, q Query) error {
	if d.delete != nil {
		return d.delete(ctx, q)
	}
	return nil
}

func (d *fakeDriver) DeleteMany(ctx context.Context, q Query) (int64, error) {
	if d.deleteMany != nil {
		return d.deleteMany(ctx, q)
	}
	return 0, nil
}

// fakeAtomicDriver adds native consumeOne / incrementOne (both returning null by default).
type fakeAtomicDriver struct {
	*fakeDriver
	consumeOne   func(ctx context.Context, q Query) (Record, error)
	incrementOne func(ctx context.Context, q Query, increment map[string]float64, set Record) (Record, error)
}

func (d *fakeAtomicDriver) ConsumeOne(ctx context.Context, q Query) (Record, error) {
	if d.consumeOne != nil {
		return d.consumeOne(ctx, q)
	}
	return nil, nil
}

func (d *fakeAtomicDriver) IncrementOne(ctx context.Context, q Query, increment map[string]float64, set Record) (Record, error) {
	if d.incrementOne != nil {
		return d.incrementOne(ctx, q, increment, set)
	}
	return nil, nil
}

func boolp(b bool) *bool { return &b }

// newAdapter instantiates NewFactory(cfg, driver) for the schema described by schemaOpts.
func newAdapter(t testing.TB, cfg Config, driver CustomAdapter, opts Options, schemaOpts db.Options) Adapter {
	t.Helper()
	opts.Schema = db.GetAuthTables(schemaOpts)
	ad, err := NewFactory(cfg, func(Options, Helpers) (CustomAdapter, error) { return driver, nil })(opts)
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}
	return ad
}

// undef reports whether key is "undefined" in a factory result (absent or nil).
func undef(r Record, key string) bool {
	v, ok := r[key]
	return !ok || v == nil
}

// has reports whether the key is present (toHaveProperty with a defined value).
func has(r Record, key string) bool {
	_, ok := r[key]
	return ok
}

// norm converts values to a comparable JSON-like form: numbers to float64, slices to []any,
// maps recursively and times to UTC.
func norm(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case time.Time:
		return t.UTC()
	case *jsonx.Object:
		return norm(t.Map())
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = norm(x)
		}
		return out
	case []CleanedWhere:
		out := make([]any, len(t))
		for i, w := range t {
			out[i] = map[string]any{"field": w.Field, "value": norm(w.Value), "operator": string(w.Operator),
				"connector": string(w.Connector), "insensitive": w.Insensitive}
		}
		return out
	}
	if f, ok := numeric(v); ok {
		return f
	}
	if arr, ok := toAnySlice(v); ok {
		out := make([]any, len(arr))
		for i, x := range arr {
			out[i] = norm(x)
		}
		return out
	}
	return v
}

func jsEqual(a, b any) bool {
	na, nb := norm(a), norm(b)
	if ta, ok := na.(time.Time); ok {
		tb, ok := nb.(time.Time)
		return ok && ta.Equal(tb)
	}
	if fa, ok := na.(float64); ok && math.IsNaN(fa) {
		fb, ok := nb.(float64)
		return ok && math.IsNaN(fb)
	}
	return reflect.DeepEqual(na, nb)
}

func wantEqual(t testing.TB, got, want any, what string) {
	t.Helper()
	if !jsEqual(got, want) {
		t.Fatalf("%s: got %#v, want %#v", what, got, want)
	}
}

// matchObject is toMatchObject: every key of want must equal the value in got (a want
// value of nil requires the key to be undefined or null).
func matchObject(t testing.TB, got Record, want Record, what string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: got nil, want object matching %#v", what, want)
	}
	for k, v := range want {
		if v == nil {
			if !undef(got, k) {
				t.Fatalf("%s: %s = %#v, want null", what, k, got[k])
			}
			continue
		}
		if !jsEqual(got[k], v) {
			t.Fatalf("%s: %s = %#v, want %#v", what, k, got[k], v)
		}
	}
}

// wantErr is `rejects.toThrow(pattern)`.
func wantErr(t testing.TB, err error, pattern string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error matching %q, got nil", pattern)
	}
	if !regexp.MustCompile(pattern).MatchString(err.Error()) {
		t.Fatalf("expected an error matching %q, got %q", pattern, err.Error())
	}
}

func mustNoErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
