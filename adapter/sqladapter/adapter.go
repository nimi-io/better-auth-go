package sqladapter

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/dialect"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter/migration"
	dbschema "github.com/nimi-io/better-auth-go/db"
)

// sqlAdapter is the CustomAdapter (createCustomAdapter upstream). q is the root *sql.DB or,
// inside a transaction, the *sql.Tx.
type sqlAdapter struct {
	db         *sql.DB
	q          execer
	inTx       bool
	d          dialect.Dialect
	schemaName string
	opts       adapter.Options
	h          adapter.Helpers
	debug      bool
}

// txAdapter adds native transactions (config.transaction upstream). The adapter handed to
// the callback is a plain sqlAdapter bound to the transaction, so nested Transaction calls
// run inside the outer transaction (the inner factory has transaction: false upstream).
type txAdapter struct{ *sqlAdapter }

var (
	_ adapter.CustomAdapter = (*sqlAdapter)(nil)
	_ adapter.ConsumeOner   = (*sqlAdapter)(nil)
	_ adapter.IncrementOner = (*sqlAdapter)(nil)
	_ adapter.Migrator      = (*sqlAdapter)(nil)
	_ adapter.Transactor    = (*txAdapter)(nil)
)

func (a *sqlAdapter) newBuilder() *builder { return &builder{d: a.d} }

// Transaction runs fn in a database transaction, committing when it returns nil and
// rolling back on error or panic.
func (t *txAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.CustomAdapter) error) error {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	t.logQuery("exec", "BEGIN", nil)
	child := *t.sqlAdapter
	child.q, child.inTx = tx, true
	done := false
	defer func() {
		if !done {
			t.logQuery("exec", "ROLLBACK", nil)
			_ = tx.Rollback()
		}
	}()
	if err := fn(ctx, &child); err != nil {
		return err
	}
	done = true
	t.logQuery("exec", "COMMIT", nil)
	return tx.Commit()
}

// withTx runs fn in the current transaction, or in a new one (`inTransaction ?
// fn(db) : db.transaction().execute(fn)` upstream).
func (a *sqlAdapter) withTx(ctx context.Context, fn func(q execer) (adapter.Record, error)) (adapter.Record, error) {
	if a.inTx {
		return fn(a.q)
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	res, err := fn(tx)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

// PlanMigrations implements adapter.Migrator.
func (a *sqlAdapter) PlanMigrations(ctx context.Context, schema *dbschema.Schema) (*adapter.MigrationPlan, error) {
	return migration.Plan(ctx, a.db, schema, migration.Options{Dialect: a.d, SchemaName: a.schemaName, IDMode: a.opts.IDMode})
}

// PlanMigrationsReportUnsafe plans like PlanMigrations but reports unsafe changes in the
// plan instead of refusing (getMigrations with throwOnUnsafe: false, used by `generate`).
func (a *sqlAdapter) PlanMigrationsReportUnsafe(ctx context.Context, schema *dbschema.Schema) (*adapter.MigrationPlan, error) {
	return migration.Plan(ctx, a.db, schema, migration.Options{Dialect: a.d, SchemaName: a.schemaName, IDMode: a.opts.IDMode, ReportUnsafe: true})
}

// table returns the schema table of a query (by logical key, so a model whose physical
// name equals another model's key keeps its identity).
func (a *sqlAdapter) table(model, modelKey string) *dbschema.Table {
	if a.opts.Schema != nil {
		if t := a.opts.Schema.Table(modelKey); t != nil {
			return t
		}
	}
	t, _ := a.h.Table(model)
	return t
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case int64:
		return t != 0
	case int:
		return t != 0
	case float64:
		return t != 0
	}
	return true
}

// ---- create ----

func (a *sqlAdapter) Create(ctx context.Context, model, modelKey string, data adapter.Record) (adapter.Record, error) {
	ref, _ := a.tableRef(model)
	b := a.newBuilder()
	b.write("INSERT INTO ", ref)
	keys := sortedKeys(data)
	if len(keys) == 0 {
		if a.d == dialect.MySQL {
			b.write(" () VALUES ()")
		} else {
			b.write(" DEFAULT VALUES")
		}
	} else {
		cols := make([]string, len(keys))
		phs := make([]string, len(keys))
		for i, k := range keys {
			cols[i] = a.d.Quote(k)
		}
		for i, k := range keys {
			phs[i] = b.bind(data[k])
		}
		b.write(" (", strings.Join(cols, ", "), ") VALUES (", strings.Join(phs, ", "), ")")
	}
	if a.d.SupportsReturning() {
		b.write(" RETURNING *")
		return a.queryFirst(ctx, a.q, b)
	}
	query := b.String()
	a.logQuery("exec", query, b.args)
	res, err := a.q.ExecContext(ctx, query, b.args...)
	if err != nil {
		return nil, err
	}
	return a.fetchInserted(ctx, model, modelKey, data, res)
}

// selectOneBy reads one row where column equals value (IS NULL for nil).
func (a *sqlAdapter) selectOneBy(ctx context.Context, q execer, model, column string, value any) (adapter.Record, error) {
	ref, _ := a.tableRef(model)
	b := a.newBuilder()
	b.write("SELECT * FROM ", ref, " WHERE ", a.d.Quote(column))
	if value == nil {
		b.write(" IS NULL")
	} else if arr, ok := adapter.ToSlice(value); ok && len(arr) > 0 {
		phs := make([]string, len(arr))
		for i, x := range arr {
			phs[i] = b.bind(x)
		}
		b.write(" IN (", strings.Join(phs, ", "), ")")
	} else {
		b.write(" = ", b.bind(value))
	}
	b.write(" LIMIT 1")
	return a.queryFirst(ctx, q, b)
}

// fetchInserted re-reads a row inserted on MySQL, which has no RETURNING: by id, by the
// auto-increment id (serial), by a unique column, and finally by matching every inserted
// value when that identifies exactly one row.
func (a *sqlAdapter) fetchInserted(ctx context.Context, model, modelKey string, values adapter.Record, res sql.Result) (adapter.Record, error) {
	if id := values["id"]; truthy(id) {
		return a.selectOneBy(ctx, a.q, model, "id", id)
	}
	if a.opts.IDMode == adapter.IDSerial {
		// LAST_INSERT_ID() of the connection that ran the INSERT.
		if lastID, err := res.LastInsertId(); err == nil && lastID != 0 {
			return a.selectOneBy(ctx, a.q, model, "id", lastID)
		}
	}
	if t := a.table(model, modelKey); t != nil {
		for _, f := range t.Fields {
			if !f.Unique {
				continue
			}
			v, ok := values[f.Column()]
			if !ok || v == nil {
				continue
			}
			row, err := a.selectOneBy(ctx, a.q, model, f.Column(), v)
			if err != nil || row != nil {
				return row, err
			}
		}
	}
	if len(values) > 0 {
		ref, _ := a.tableRef(model)
		b := a.newBuilder()
		b.write("SELECT * FROM ", ref, " WHERE ")
		for i, k := range sortedKeys(values) {
			if i > 0 {
				b.write(" AND ")
			}
			if values[k] == nil {
				b.write(a.d.Quote(k), " IS NULL")
			} else {
				b.write(a.d.Quote(k), " = ", b.bind(values[k]))
			}
		}
		b.write(" LIMIT 2")
		rows, err := a.query(ctx, a.q, b)
		if err != nil {
			return nil, err
		}
		if len(rows) == 1 {
			return rows[0], nil
		}
	}
	if a.opts.Logger != nil {
		a.opts.Logger.Warn(fmt.Sprintf("[Kysely Adapter] Unable to safely identify the inserted %q row on MySQL. "+
			"Enable Better Auth ID generation or use generateId: \"serial\" for reliable behavior.", model))
	}
	return nil, nil
}

// ---- reads ----

type joinSpec struct {
	model   string // physical model name (key of Query.Join and of the result record)
	cfg     adapter.JoinConfig
	alias   string
	columns []string
}

func (a *sqlAdapter) joinSpecs(join map[string]adapter.JoinConfig) []joinSpec {
	specs := make([]joinSpec, 0, len(join))
	for _, model := range sortedKeys(join) {
		cfg := join[model]
		spec := joinSpec{model: model, cfg: cfg, alias: a.joinAlias(model)}
		if t := a.table(model, cfg.ModelKey); t != nil {
			for _, f := range t.Fields {
				spec.columns = append(spec.columns, f.Column())
			}
		}
		spec.columns = append(spec.columns, "id") // `fields.id = { type: "string" }`
		specs = append(specs, spec)
	}
	return specs
}

// selectJoined runs `select "primary".*, <joined columns> from (<base query>) as "primary"
// left join <model> as "join_<model>" on ...` and groups the rows (processJoinedResults).
func (a *sqlAdapter) selectJoined(ctx context.Context, q adapter.Query, limit, offset int) ([]adapter.Record, error) {
	ref, exposed := a.tableRef(q.Model)
	specs := a.joinSpecs(q.Join)
	primary := a.d.Quote("primary")
	type target struct{ spec, col int }
	aliases := map[string]target{}
	b := a.newBuilder()
	b.write("SELECT ", primary, ".*")
	for si, s := range specs {
		for ci, c := range s.columns {
			alias := "_j" + strconv.Itoa(si) + "_" + strconv.Itoa(ci)
			aliases[alias] = target{si, ci}
			b.write(", ", s.alias, ".", a.d.Quote(c), " AS ", a.d.Quote(alias))
		}
	}
	b.write(" FROM (SELECT ", a.selectList(q.Select), " FROM ", ref)
	if err := a.writeWhere(b, exposed, q.Where); err != nil {
		return nil, err
	}
	if q.SortBy != nil {
		b.write(" ORDER BY ", a.d.Quote(q.SortBy.Field), " ", sortDir(q.SortBy.Direction))
	}
	a.limitOffset(b, limit, offset)
	b.write(") AS ", primary)
	for _, s := range specs {
		jref, _ := a.tableRef(s.model)
		b.write(" LEFT JOIN ", jref, " AS ", s.alias, " ON ", s.alias, ".", a.d.Quote(s.cfg.To), " = ", primary, ".", a.d.Quote(s.cfg.From))
	}
	if q.SortBy != nil {
		b.write(" ORDER BY ", primary, ".", a.d.Quote(q.SortBy.Field), " ", sortDir(q.SortBy.Direction))
	}
	rows, err := a.query(ctx, a.q, b)
	if err != nil {
		return nil, err
	}

	var order []string
	grouped := map[string]adapter.Record{}
	for _, row := range rows {
		main := adapter.Record{}
		joined := make([]adapter.Record, len(specs))
		for i := range joined {
			joined[i] = adapter.Record{}
		}
		for k, v := range row {
			if t, ok := aliases[k]; ok {
				joined[t.spec][specs[t.spec].columns[t.col]] = v
			} else {
				main[k] = v
			}
		}
		mainID := main["id"]
		if !truthy(mainID) {
			continue
		}
		key := fmt.Sprintf("%T:%v", mainID, mainID)
		rec, ok := grouped[key]
		if !ok {
			rec = adapter.Record{}
			for k, v := range main {
				rec[k] = v
			}
			for _, s := range specs {
				if s.cfg.Relation == "one-to-one" {
					rec[s.model] = nil
				} else {
					rec[s.model] = []any{}
				}
			}
			grouped[key] = rec
			order = append(order, key)
		}
		for i, s := range specs {
			obj := joined[i]
			hasData := false
			for _, v := range obj {
				if v != nil {
					hasData = true
					break
				}
			}
			if s.cfg.Relation == "one-to-one" {
				if hasData {
					rec[s.model] = obj
				} else {
					rec[s.model] = nil
				}
				continue
			}
			list, _ := rec[s.model].([]any)
			lim := s.cfg.Limit
			if lim <= 0 {
				lim = 100
			}
			if !hasData || len(list) >= lim {
				continue
			}
			if id := obj["id"]; truthy(id) {
				exists := false
				for _, item := range list {
					if adapter.Equal(item.(adapter.Record)["id"], id) {
						exists = true
						break
					}
				}
				if exists {
					continue
				}
			}
			rec[s.model] = append(list, obj)
		}
	}
	out := make([]adapter.Record, 0, len(order))
	for _, k := range order {
		out = append(out, grouped[k])
	}
	return out, nil
}

func sortDir(d string) string {
	if strings.EqualFold(d, "desc") {
		return "DESC"
	}
	return "ASC"
}

func (a *sqlAdapter) FindOne(ctx context.Context, q adapter.Query) (adapter.Record, error) {
	if len(q.Join) > 0 {
		rows, err := a.selectJoined(ctx, q, 1, 0)
		if err != nil || len(rows) == 0 {
			return nil, err
		}
		return rows[0], nil
	}
	ref, exposed := a.tableRef(q.Model)
	b := a.newBuilder()
	b.write("SELECT ", a.selectList(q.Select), " FROM ", ref)
	if err := a.writeWhere(b, exposed, q.Where); err != nil {
		return nil, err
	}
	b.write(" LIMIT 1")
	return a.queryFirst(ctx, a.q, b)
}

func (a *sqlAdapter) FindMany(ctx context.Context, q adapter.Query) ([]adapter.Record, error) {
	var (
		rows []adapter.Record
		err  error
	)
	if len(q.Join) > 0 {
		rows, err = a.selectJoined(ctx, q, q.Limit, q.Offset)
	} else {
		ref, exposed := a.tableRef(q.Model)
		b := a.newBuilder()
		b.write("SELECT ", a.selectList(q.Select), " FROM ", ref)
		if err := a.writeWhere(b, exposed, q.Where); err != nil {
			return nil, err
		}
		if q.SortBy != nil {
			b.write(" ORDER BY ", a.d.Quote(q.SortBy.Field), " ", sortDir(q.SortBy.Direction))
		}
		a.limitOffset(b, q.Limit, q.Offset)
		rows, err = a.query(ctx, a.q, b)
	}
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []adapter.Record{}
	}
	return rows, nil
}

func (a *sqlAdapter) Count(ctx context.Context, q adapter.Query) (int64, error) {
	ref, exposed := a.tableRef(q.Model)
	b := a.newBuilder()
	b.write("SELECT COUNT(", a.d.Quote("id"), ") AS ", a.d.Quote("count"), " FROM ", ref)
	if err := a.writeWhere(b, exposed, q.Where); err != nil {
		return 0, err
	}
	row, err := a.queryFirst(ctx, a.q, b)
	if err != nil || row == nil {
		return 0, err
	}
	n, ok := adapter.ToInt64(row["count"])
	if !ok {
		return 0, fmt.Errorf("sqladapter: unexpected count value %v", row["count"])
	}
	return n, nil
}

// ---- writes ----

func (a *sqlAdapter) Update(ctx context.Context, q adapter.Query, update adapter.Record) (adapter.Record, error) {
	if len(q.Where) == 0 {
		return nil, nil
	}
	if len(update) == 0 {
		// Nothing to set: report the row the update would have targeted.
		return a.FindOne(ctx, adapter.Query{Model: q.Model, ModelKey: q.ModelKey, Where: q.Where})
	}
	ref, exposed := a.tableRef(q.Model)
	b := a.newBuilder()
	b.write("UPDATE ", ref, " SET ")
	a.setClause(b, update, nil)
	if err := a.writeWhere(b, exposed, q.Where); err != nil {
		return nil, err
	}
	if a.d.SupportsReturning() {
		b.write(" RETURNING *")
		return a.queryFirst(ctx, a.q, b)
	}
	affected, err := a.exec(ctx, a.q, b)
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		// go-sql-driver reports changed rows unless clientFoundRows is set, while mysql2
		// reports matched rows: a matched row whose values did not change still matches the
		// where clause, so look for one before concluding nothing matched.
		found, err := a.exists(ctx, a.q, q.Model, q.Where, nil)
		if err != nil || !found {
			return nil, err
		}
	}
	return a.reselect(ctx, q, update)
}

// reselect re-reads the updated row on MySQL (withReturning upstream): by the updated id,
// by an `id = value` predicate, or by the first predicate's field.
func (a *sqlAdapter) reselect(ctx context.Context, q adapter.Query, values adapter.Record) (adapter.Record, error) {
	var field string
	var value any
	var idEq *adapter.CleanedWhere
	for i, w := range q.Where {
		if w.Field == "id" && (w.Operator == "" || w.Operator == adapter.Eq) && w.Connector != adapter.Or && w.Value != nil {
			idEq = &q.Where[i]
			break
		}
	}
	switch {
	case values["id"] != nil:
		field, value = "id", values["id"]
	case idEq != nil:
		field, value = "id", idEq.Value
	case q.Where[0].Field != "":
		field = q.Where[0].Field
		if v, ok := values[field]; ok {
			value = v
		} else {
			value = q.Where[0].Value
		}
	default:
		return nil, nil
	}
	return a.selectOneBy(ctx, a.q, q.Model, field, value)
}

// exists reports whether a row matches where (and id = targetID when non-nil).
func (a *sqlAdapter) exists(ctx context.Context, q execer, model string, where []adapter.CleanedWhere, targetID any) (bool, error) {
	ref, exposed := a.tableRef(model)
	b := a.newBuilder()
	b.write("SELECT 1 AS ", a.d.Quote("found"), " FROM ", ref)
	w, err := a.where(b, exposed, where)
	if err != nil {
		return false, err
	}
	var conds []string
	if w != "" {
		conds = append(conds, w)
	}
	if targetID != nil {
		conds = append(conds, a.col(exposed, "id")+" = "+b.bind(targetID))
	}
	if len(conds) > 0 {
		b.write(" WHERE ", strings.Join(conds, " AND "))
	}
	b.write(" LIMIT 1")
	row, err := a.queryFirst(ctx, q, b)
	return row != nil, err
}

func (a *sqlAdapter) UpdateMany(ctx context.Context, q adapter.Query, update adapter.Record) (int64, error) {
	if len(update) == 0 {
		return a.Count(ctx, q)
	}
	ref, exposed := a.tableRef(q.Model)
	build := func() (*builder, error) {
		b := a.newBuilder()
		b.write("UPDATE ", ref, " SET ")
		a.setClause(b, update, nil)
		return b, a.writeWhere(b, exposed, q.Where)
	}
	if a.d != dialect.MySQL {
		b, err := build()
		if err != nil {
			return 0, err
		}
		return a.exec(ctx, a.q, b)
	}
	// MySQL: count the matched rows (locking them) so unchanged rows are counted like
	// mysql2's found-rows semantics, then update them.
	var n int64
	_, err := a.withTx(ctx, func(tx execer) (adapter.Record, error) {
		c := a.newBuilder()
		c.write("SELECT COUNT(*) AS ", a.d.Quote("count"), " FROM ", ref)
		if err := a.writeWhere(c, exposed, q.Where); err != nil {
			return nil, err
		}
		c.write(" FOR UPDATE")
		row, err := a.queryFirst(ctx, tx, c)
		if err != nil {
			return nil, err
		}
		matched, _ := adapter.ToInt64(row["count"])
		b, err := build()
		if err != nil {
			return nil, err
		}
		affected, err := a.exec(ctx, tx, b)
		if err != nil {
			return nil, err
		}
		n = max(matched, affected)
		return nil, nil
	})
	return n, err
}

func (a *sqlAdapter) deleteBuilder(q adapter.Query) (*builder, error) {
	ref, exposed := a.tableRef(q.Model)
	b := a.newBuilder()
	b.write("DELETE FROM ", ref)
	return b, a.writeWhere(b, exposed, q.Where)
}

func (a *sqlAdapter) Delete(ctx context.Context, q adapter.Query) error {
	b, err := a.deleteBuilder(q)
	if err != nil {
		return err
	}
	_, err = a.exec(ctx, a.q, b)
	return err
}

func (a *sqlAdapter) DeleteMany(ctx context.Context, q adapter.Query) (int64, error) {
	b, err := a.deleteBuilder(q)
	if err != nil {
		return 0, err
	}
	return a.exec(ctx, a.q, b)
}

// ---- atomic operations ----

// targetSubquery renders `"t"."id" IN (SELECT "t"."id" FROM t WHERE <where> LIMIT 1)`.
func (a *sqlAdapter) targetSubquery(b *builder, q adapter.Query) error {
	ref, exposed := a.tableRef(q.Model)
	id := a.col(exposed, "id")
	b.write(id, " IN (SELECT ", id, " FROM ", ref)
	if err := a.writeWhere(b, exposed, q.Where); err != nil {
		return err
	}
	b.write(" LIMIT 1)")
	return nil
}

// ConsumeOne atomically deletes and returns one matching row. PostgreSQL and SQLite delete
// `where id in (select id ... limit 1) and <where>` with RETURNING, so the guard is
// re-checked against the row actually deleted; MySQL locks the row with SELECT ... FOR
// UPDATE inside a transaction, then deletes it by id.
func (a *sqlAdapter) ConsumeOne(ctx context.Context, q adapter.Query) (adapter.Record, error) {
	ref, exposed := a.tableRef(q.Model)
	if a.d == dialect.MySQL {
		return a.withTx(ctx, func(tx execer) (adapter.Record, error) {
			s := a.newBuilder()
			s.write("SELECT * FROM ", ref)
			if err := a.writeWhere(s, exposed, q.Where); err != nil {
				return nil, err
			}
			s.write(" LIMIT 1 FOR UPDATE")
			row, err := a.queryFirst(ctx, tx, s)
			if err != nil || row == nil {
				return nil, err
			}
			targetID := row["id"]
			if targetID == nil {
				return nil, nil
			}
			d := a.newBuilder()
			d.write("DELETE FROM ", ref, " WHERE ", a.col(exposed, "id"), " = ", d.bind(targetID))
			n, err := a.exec(ctx, tx, d)
			if err != nil || n == 0 {
				return nil, err
			}
			return row, nil
		})
	}
	b := a.newBuilder()
	b.write("DELETE FROM ", ref, " WHERE ")
	if err := a.targetSubquery(b, q); err != nil {
		return nil, err
	}
	if err := a.appendWhere(b, exposed, q.Where); err != nil {
		return nil, err
	}
	b.write(" RETURNING *")
	return a.queryFirst(ctx, a.q, b)
}

// IncrementOne atomically applies `field = field + delta` (and absolute set values) to one
// matching row and returns it, re-checking the guard on the row actually updated.
func (a *sqlAdapter) IncrementOne(ctx context.Context, q adapter.Query, increment map[string]float64, set adapter.Record) (adapter.Record, error) {
	ref, exposed := a.tableRef(q.Model)
	if a.d == dialect.MySQL {
		return a.withTx(ctx, func(tx execer) (adapter.Record, error) {
			s := a.newBuilder()
			s.write("SELECT ", a.col(exposed, "id"), " FROM ", ref)
			if err := a.writeWhere(s, exposed, q.Where); err != nil {
				return nil, err
			}
			s.write(" LIMIT 1 FOR UPDATE")
			target, err := a.queryFirst(ctx, tx, s)
			if err != nil || target == nil {
				return nil, err
			}
			targetID := target["id"]
			if targetID == nil {
				return nil, nil
			}
			u := a.newBuilder()
			u.write("UPDATE ", ref, " SET ")
			a.setClause(u, set, increment)
			w, err := a.where(u, exposed, q.Where)
			if err != nil {
				return nil, err
			}
			u.write(" WHERE ")
			if w != "" {
				u.write(w, " AND ")
			}
			u.write(a.col(exposed, "id"), " = ", u.bind(targetID))
			n, err := a.exec(ctx, tx, u)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				// Changed-rows semantics (see Update): a set-only assignment that matches the
				// current values changes nothing but still matched.
				found, err := a.exists(ctx, tx, q.Model, q.Where, targetID)
				if err != nil || !found {
					return nil, err
				}
			}
			return a.selectOneBy(ctx, tx, q.Model, "id", targetID)
		})
	}
	b := a.newBuilder()
	b.write("UPDATE ", ref, " SET ")
	a.setClause(b, set, increment)
	w, err := a.where(b, exposed, q.Where)
	if err != nil {
		return nil, err
	}
	b.write(" WHERE ")
	if w != "" {
		b.write(w, " AND ")
	}
	if err := a.targetSubquery(b, q); err != nil {
		return nil, err
	}
	b.write(" RETURNING *")
	return a.queryFirst(ctx, a.q, b)
}
