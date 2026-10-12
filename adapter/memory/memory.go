// Package memory is an in-memory Better Auth adapter, a port of @better-auth/memory-adapter.
// It is intended for tests and prototypes; data lives in process memory.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

// DB is the backing store: physical model name → rows.
type DB struct {
	mu     sync.RWMutex
	tables map[string][]adapter.Record
}

// NewDB returns an empty store.
func NewDB() *DB { return &DB{tables: map[string][]adapter.Record{}} }

// Rows returns a copy of the rows of a physical table (useful in tests).
func (d *DB) Rows(model string) []adapter.Record {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]adapter.Record, len(d.tables[model]))
	for i, r := range d.tables[model] {
		out[i] = cloneRecord(r)
	}
	return out
}

// Reset removes all rows.
func (d *DB) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tables = map[string][]adapter.Record{}
}

func cloneRecord(r adapter.Record) adapter.Record {
	if r == nil {
		return nil
	}
	out := make(adapter.Record, len(r))
	for k, v := range r {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneRecord(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = cloneValue(x)
		}
		return out
	case []string:
		return append([]string(nil), t...)
	}
	return v
}

func (d *DB) snapshot() map[string][]adapter.Record {
	out := map[string][]adapter.Record{}
	for k, rows := range d.tables {
		cp := make([]adapter.Record, len(rows))
		for i, r := range rows {
			cp[i] = cloneRecord(r)
		}
		out[k] = cp
	}
	return out
}

// New returns an adapter factory backed by a fresh store (or the given one).
func New(store ...*DB) adapter.Factory {
	var d *DB
	if len(store) > 0 && store[0] != nil {
		d = store[0]
	} else {
		d = NewDB()
	}
	return adapter.NewFactory(adapter.Config{
		AdapterID:      "memory",
		AdapterName:    "Memory Adapter",
		SupportsArrays: true,
		SupportsJSON:   true,
	}, func(opts adapter.Options, h adapter.Helpers) (adapter.CustomAdapter, error) {
		return &memAdapter{db: d, opts: opts, h: h}, nil
	})
}

type memAdapter struct {
	db   *DB
	opts adapter.Options
	h    adapter.Helpers
}

func (m *memAdapter) table(model string) []adapter.Record {
	return m.db.tables[model]
}

func lower(v any) (string, bool) {
	s, ok := v.(string)
	return strings.ToLower(s), ok
}

func evalClause(rec adapter.Record, c adapter.CleanedWhere) bool {
	val := rec[c.Field]
	insensitive := false
	if c.Insensitive {
		switch t := c.Value.(type) {
		case string:
			insensitive = true
		default:
			if arr, ok := adapter.ToSlice(t); ok {
				insensitive = true
				for _, x := range arr {
					if _, isStr := x.(string); !isStr {
						insensitive = false
					}
				}
			}
		}
	}
	switch c.Operator {
	case adapter.In, adapter.NotIn:
		arr, _ := adapter.ToSlice(c.Value)
		found := false
		for _, x := range arr {
			if insensitive {
				rs, rok := lower(val)
				xs, xok := lower(x)
				if rok && xok && rs == xs {
					found = true
				} else if !rok && adapter.Equal(val, x) {
					found = true
				}
			} else if adapter.Equal(val, x) {
				found = true
			}
		}
		if c.Operator == adapter.In {
			return found
		}
		return !found
	case adapter.Contains, adapter.StartsWith, adapter.EndsWith:
		s, ok := val.(string)
		v, vok := c.Value.(string)
		if !ok || !vok {
			return false
		}
		if insensitive {
			s, v = strings.ToLower(s), strings.ToLower(v)
		}
		switch c.Operator {
		case adapter.Contains:
			return strings.Contains(s, v)
		case adapter.StartsWith:
			return strings.HasPrefix(s, v)
		}
		return strings.HasSuffix(s, v)
	case adapter.Ne:
		if insensitive {
			rs, rok := lower(val)
			vs, _ := lower(c.Value)
			if rok {
				return rs != vs
			}
		}
		return !adapter.Equal(val, c.Value)
	case adapter.Gt, adapter.Gte, adapter.Lt, adapter.Lte:
		if c.Value == nil {
			return false
		}
		cmp, ok := adapter.Compare(val, c.Value)
		if !ok {
			return false
		}
		switch c.Operator {
		case adapter.Gt:
			return cmp > 0
		case adapter.Gte:
			return cmp >= 0
		case adapter.Lt:
			return cmp < 0
		}
		return cmp <= 0
	default:
		if insensitive {
			rs, rok := lower(val)
			vs, _ := lower(c.Value)
			if rok {
				return rs == vs
			}
		}
		if c.Value == nil {
			return val == nil
		}
		return adapter.Equal(val, c.Value)
	}
}

func matches(rec adapter.Record, where []adapter.CleanedWhere) bool {
	if len(where) == 0 {
		return true
	}
	result := evalClause(rec, where[0])
	for _, c := range where {
		r := evalClause(rec, c)
		if c.Connector == adapter.Or {
			result = result || r
		} else {
			result = result && r
		}
	}
	return result
}

// filter returns indexes of matching rows.
func (m *memAdapter) filter(model string, where []adapter.CleanedWhere) ([]int, error) {
	rows, ok := m.db.tables[model]
	if !ok {
		// unknown tables behave as empty (tables are created lazily on insert)
		return nil, nil
	}
	var idx []int
	for i, r := range rows {
		if matches(r, where) {
			idx = append(idx, i)
		}
	}
	return idx, nil
}

func (m *memAdapter) project(rec adapter.Record, q adapter.Query) adapter.Record {
	out := cloneRecord(rec)
	if len(q.Select) > 0 {
		sel := map[string]bool{}
		for _, s := range q.Select {
			sel[s] = true
		}
		for k := range out {
			if !sel[k] {
				delete(out, k)
			}
		}
	}
	for jm, cfg := range q.Join {
		var matched []adapter.Record
		for _, jr := range m.db.tables[jm] {
			if adapter.Equal(jr[cfg.To], rec[cfg.From]) {
				matched = append(matched, cloneRecord(jr))
			}
		}
		if cfg.Relation == "one-to-one" {
			if len(matched) > 0 {
				out[jm] = matched[0]
			} else {
				out[jm] = nil
			}
		} else {
			limit := cfg.Limit
			if limit <= 0 {
				limit = 100
			}
			if len(matched) > limit {
				matched = matched[:limit]
			}
			arr := make([]any, len(matched))
			for i, r := range matched {
				arr[i] = r
			}
			out[jm] = arr
		}
	}
	return out
}

func (m *memAdapter) Create(_ context.Context, model, _ string, data adapter.Record) (adapter.Record, error) {
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	rec := cloneRecord(data)
	if m.h.UseNumberID() {
		rec["id"] = int64(len(m.db.tables[model]) + 1)
	}
	if err := m.checkUnique(model, rec, -1); err != nil {
		return nil, err
	}
	m.db.tables[model] = append(m.db.tables[model], rec)
	return cloneRecord(rec), nil
}

// ErrUniqueViolation is returned when a write would duplicate a unique column.
type ErrUniqueViolation struct{ Model, Field string }

func (e *ErrUniqueViolation) Error() string {
	return fmt.Sprintf("UNIQUE constraint failed: %s.%s", e.Model, e.Field)
}

// uniqueColumns returns the physical columns that must be unique (id + unique fields).
func (m *memAdapter) uniqueColumns(model string) []string {
	cols := []string{"id"}
	t, err := m.h.Table(model)
	if err != nil || t == nil {
		return cols
	}
	for _, f := range t.Fields {
		if f.Unique {
			cols = append(cols, f.Column())
		}
	}
	return cols
}

// checkUnique enforces unique columns like a real database would. skip is the index of
// the row being updated (-1 for inserts).
func (m *memAdapter) checkUnique(model string, rec adapter.Record, skip int) error {
	for _, col := range m.uniqueColumns(model) {
		v, ok := rec[col]
		if !ok || v == nil {
			continue
		}
		for i, row := range m.db.tables[model] {
			if i != skip && adapter.Equal(row[col], v) {
				return &ErrUniqueViolation{Model: model, Field: col}
			}
		}
	}
	return nil
}

func (m *memAdapter) FindOne(_ context.Context, q adapter.Query) (adapter.Record, error) {
	m.db.mu.RLock()
	defer m.db.mu.RUnlock()
	idx, err := m.filter(q.Model, q.Where)
	if err != nil || len(idx) == 0 {
		return nil, err
	}
	return m.project(m.table(q.Model)[idx[0]], q), nil
}

func sortRecords(recs []adapter.Record, s *adapter.SortBy) {
	if s == nil {
		return
	}
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i][s.Field], recs[j][s.Field]
		var c int
		switch {
		case a == nil && b == nil:
			c = 0
		case a == nil:
			c = -1
		case b == nil:
			c = 1
		default:
			if cmp, ok := adapter.Compare(a, b); ok {
				c = cmp
			} else {
				c = strings.Compare(adapter.ToString(a), adapter.ToString(b))
			}
		}
		if s.Direction == "desc" {
			return c > 0
		}
		return c < 0
	})
}

func (m *memAdapter) FindMany(_ context.Context, q adapter.Query) ([]adapter.Record, error) {
	m.db.mu.RLock()
	defer m.db.mu.RUnlock()
	idx, err := m.filter(q.Model, q.Where)
	if err != nil {
		return nil, err
	}
	rows := m.table(q.Model)
	recs := make([]adapter.Record, 0, len(idx))
	for _, i := range idx {
		recs = append(recs, rows[i])
	}
	if q.SortBy != nil {
		sorted := make([]adapter.Record, len(recs))
		copy(sorted, recs)
		sortRecords(sorted, q.SortBy)
		recs = sorted
	}
	if q.Offset > 0 {
		if q.Offset >= len(recs) {
			recs = nil
		} else {
			recs = recs[q.Offset:]
		}
	}
	if q.Limit > 0 && len(recs) > q.Limit {
		recs = recs[:q.Limit]
	}
	out := make([]adapter.Record, len(recs))
	for i, r := range recs {
		out[i] = m.project(r, q)
	}
	return out, nil
}

func (m *memAdapter) Count(_ context.Context, q adapter.Query) (int64, error) {
	m.db.mu.RLock()
	defer m.db.mu.RUnlock()
	idx, err := m.filter(q.Model, q.Where)
	return int64(len(idx)), err
}

func (m *memAdapter) Update(_ context.Context, q adapter.Query, update adapter.Record) (adapter.Record, error) {
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	if len(q.Where) == 0 {
		return nil, nil
	}
	idx, err := m.filter(q.Model, q.Where)
	if err != nil || len(idx) == 0 {
		return nil, err
	}
	rows := m.table(q.Model)
	for _, i := range idx {
		merged := cloneRecord(rows[i])
		maps.Copy(merged, update)
		if err := m.checkUnique(q.Model, merged, i); err != nil {
			return nil, err
		}
	}
	for _, i := range idx {
		maps.Copy(rows[i], cloneRecord(update))
	}
	return cloneRecord(rows[idx[0]]), nil
}

func (m *memAdapter) UpdateMany(_ context.Context, q adapter.Query, update adapter.Record) (int64, error) {
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	idx, err := m.filter(q.Model, q.Where)
	if err != nil {
		return 0, err
	}
	rows := m.table(q.Model)
	for _, i := range idx {
		maps.Copy(rows[i], cloneRecord(update))
	}
	return int64(len(idx)), nil
}

func (m *memAdapter) removeIdx(model string, idx []int) {
	if len(idx) == 0 {
		return
	}
	drop := map[int]bool{}
	for _, i := range idx {
		drop[i] = true
	}
	rows := m.table(model)
	kept := rows[:0:0]
	for i, r := range rows {
		if !drop[i] {
			kept = append(kept, r)
		}
	}
	m.db.tables[model] = kept
}

func (m *memAdapter) Delete(_ context.Context, q adapter.Query) error {
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	if len(q.Where) == 0 {
		return nil
	}
	idx, err := m.filter(q.Model, q.Where)
	if err != nil {
		return err
	}
	m.removeIdx(q.Model, idx)
	return nil
}

func (m *memAdapter) DeleteMany(_ context.Context, q adapter.Query) (int64, error) {
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	idx, err := m.filter(q.Model, q.Where)
	if err != nil {
		return 0, err
	}
	m.removeIdx(q.Model, idx)
	return int64(len(idx)), nil
}

func (m *memAdapter) ConsumeOne(_ context.Context, q adapter.Query) (adapter.Record, error) {
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	idx, err := m.filter(q.Model, q.Where)
	if err != nil || len(idx) == 0 {
		return nil, err
	}
	rec := cloneRecord(m.table(q.Model)[idx[0]])
	m.removeIdx(q.Model, idx[:1])
	return rec, nil
}

func (m *memAdapter) IncrementOne(_ context.Context, q adapter.Query, inc map[string]float64, set adapter.Record) (adapter.Record, error) {
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	idx, err := m.filter(q.Model, q.Where)
	if err != nil || len(idx) == 0 {
		return nil, err
	}
	rec := m.table(q.Model)[idx[0]]
	for field, delta := range inc {
		cur := 0.0
		if f, ok := adapter.ToFloat(rec[field]); ok {
			if _, isNum := rec[field].(string); !isNum {
				cur = f
			}
		}
		n := cur + delta
		if n == float64(int64(n)) {
			rec[field] = int64(n)
		} else {
			rec[field] = n
		}
	}
	maps.Copy(rec, cloneRecord(set))
	return cloneRecord(rec), nil
}

// Transaction runs fn against a private copy of the store and merges the changes back on
// success (mirroring the TypeScript memory adapter). Concurrent writers outside the
// transaction are preserved unless they touch the same rows.
func (m *memAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.CustomAdapter) error) error {
	m.db.mu.RLock()
	base := m.db.snapshot()
	clone := &DB{tables: m.db.snapshot()}
	m.db.mu.RUnlock()
	tx := &memAdapter{db: clone, opts: m.opts, h: m.h}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	m.db.mu.Lock()
	defer m.db.mu.Unlock()
	clone.mu.RLock()
	defer clone.mu.RUnlock()
	merge(m.db.tables, base, clone.tables)
	return nil
}

func rowKey(r adapter.Record) string { return fmt.Sprint(r["id"]) }

func rowJSON(r adapter.Record) string {
	norm := map[string]any{}
	for k, v := range r {
		if t, ok := v.(time.Time); ok {
			norm[k] = t.UnixNano()
		} else {
			norm[k] = v
		}
	}
	b, _ := json.Marshal(norm)
	return string(b)
}

func merge(target, base, clone map[string][]adapter.Record) {
	models := map[string]bool{}
	for k := range base {
		models[k] = true
	}
	for k := range clone {
		models[k] = true
	}
	for model := range models {
		cloneRows, inClone := clone[model]
		if !inClone {
			delete(target, model)
			continue
		}
		baseByID := map[string]adapter.Record{}
		for _, r := range base[model] {
			baseByID[rowKey(r)] = r
		}
		cloneByID := map[string]adapter.Record{}
		for _, r := range cloneRows {
			cloneByID[rowKey(r)] = r
		}
		var merged []adapter.Record
		placed := map[string]bool{}
		for _, live := range target[model] {
			id := rowKey(live)
			baseRow, inBase := baseByID[id]
			cloneRow, inCloneRow := cloneByID[id]
			if inBase && !inCloneRow {
				continue // deleted in transaction
			}
			if inCloneRow && (!inBase || rowJSON(baseRow) != rowJSON(cloneRow)) {
				merged = append(merged, cloneRow)
			} else {
				merged = append(merged, live)
			}
			placed[id] = true
		}
		for _, r := range cloneRows {
			id := rowKey(r)
			if _, inBase := baseByID[id]; !inBase && !placed[id] {
				merged = append(merged, r)
			}
		}
		target[model] = merged
	}
}
