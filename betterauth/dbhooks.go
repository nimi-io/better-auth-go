package betterauth

import (
	"context"
	"sync"

	"github.com/nimi-io/better-auth-go/adapter"
)

// DBHookResult is returned by a "before" database hook. Abort cancels the operation;
// Data is merged into the record being written.
type DBHookResult struct {
	Abort bool
	Data  adapter.Record
}

// DBBeforeHook runs before a write. Use EndpointContextFrom(ctx) to access the request.
// Returning nil continues unchanged.
type DBBeforeHook func(ctx context.Context, data adapter.Record) (*DBHookResult, error)

// DBAfterHook runs after a write (after the transaction commits, when one is active).
type DBAfterHook func(ctx context.Context, data adapter.Record) error

// DBOperationHooks are before/after hooks for one operation.
type DBOperationHooks struct {
	Before DBBeforeHook
	After  DBAfterHook
}

// DBModelHooks are the hooks of one model.
type DBModelHooks struct {
	Create DBOperationHooks
	Update DBOperationHooks
	Delete DBOperationHooks
}

// DatabaseHooks configures databaseHooks.
type DatabaseHooks struct {
	User         DBModelHooks
	Session      DBModelHooks
	Account      DBModelHooks
	Verification DBModelHooks
}

func (h *DatabaseHooks) model(m string) *DBModelHooks {
	if h == nil {
		return nil
	}
	switch m {
	case "user":
		return &h.User
	case "session":
		return &h.Session
	case "account":
		return &h.Account
	case "verification":
		return &h.Verification
	}
	return nil
}

type dbHooksEntry struct {
	source string
	hooks  *DatabaseHooks
}

// ---- transactions ----

type txKey struct{}

type txState struct {
	mu    sync.Mutex
	hooks []func(context.Context) error
}

// InTransaction reports whether ctx is inside RunWithTransaction.
func InTransaction(ctx context.Context) bool {
	_, ok := ctx.Value(txKey{}).(*txState)
	return ok
}

// RunWithTransaction runs fn inside a database transaction (runWithTransaction). Nested
// calls reuse the outer transaction. After-commit hooks run once the transaction commits.
func (a *AuthContext) RunWithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if InTransaction(ctx) {
		return fn(ctx)
	}
	st := &txState{}
	err := a.Adapter.Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error {
		return fn(context.WithValue(txCtx, txKey{}, st))
	})
	if err != nil {
		return err
	}
	st.mu.Lock()
	hooks := st.hooks
	st.mu.Unlock()
	for _, h := range hooks {
		if err := h(ctx); err != nil {
			return err
		}
	}
	return nil
}

// QueueAfterTransactionHook runs hook after the active transaction commits, or immediately
// when no transaction is active. Errors are passed to onError (or logged when nil).
func (a *AuthContext) QueueAfterTransactionHook(ctx context.Context, hook func(ctx context.Context) error, onError func(error)) error {
	run := func(c context.Context) error {
		err := hook(c)
		if err != nil && onError != nil {
			onError(err)
			return nil
		}
		return err
	}
	st, ok := ctx.Value(txKey{}).(*txState)
	if !ok {
		return run(ctx)
	}
	st.mu.Lock()
	st.hooks = append(st.hooks, run)
	st.mu.Unlock()
	return nil
}

// Transaction runs fn inside a database transaction bound to this endpoint context.
func (c *EndpointContext) Transaction(fn func() error) error {
	outer := c.Context()
	return c.Auth.RunWithTransaction(outer, func(txCtx context.Context) error {
		c.ctx = txCtx
		defer func() { c.ctx = outer }()
		return fn()
	})
}

// ---- hook runners (db/with-hooks.ts) ----

type withHooks struct {
	a *AuthContext
}

func mergeRecord(base, patch adapter.Record) adapter.Record {
	out := adapter.Record{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range patch {
		out[k] = v
	}
	return out
}

func (w withHooks) runBefore(ctx context.Context, model, op string, data adapter.Record) (adapter.Record, bool, error) {
	actual := data
	for _, e := range w.a.dbHooks {
		mh := e.hooks.model(model)
		if mh == nil {
			continue
		}
		var h DBBeforeHook
		switch op {
		case "create":
			h = mh.Create.Before
		case "update":
			h = mh.Update.Before
		case "delete":
			h = mh.Delete.Before
		}
		if h == nil {
			continue
		}
		arg := actual
		if op == "update" {
			arg = data // upstream passes the original update data
		}
		res, err := h(ctx, arg)
		if err != nil {
			return nil, false, err
		}
		if res != nil {
			if res.Abort {
				return nil, false, nil
			}
			if res.Data != nil {
				actual = mergeRecord(actual, res.Data)
			}
		}
	}
	return actual, true, nil
}

func (w withHooks) runAfter(ctx context.Context, model, op string, data adapter.Record) error {
	for _, e := range w.a.dbHooks {
		mh := e.hooks.model(model)
		if mh == nil {
			continue
		}
		var h DBAfterHook
		switch op {
		case "create":
			h = mh.Create.After
		case "update":
			h = mh.Update.After
		case "delete":
			h = mh.Delete.After
		}
		if h == nil {
			continue
		}
		hook := h
		rec := data
		if err := w.a.QueueAfterTransactionHook(ctx, func(c context.Context) error { return hook(c, rec) }, nil); err != nil {
			return err
		}
	}
	return nil
}

type customFn struct {
	fn            func(ctx context.Context, data adapter.Record) (adapter.Record, error)
	executeMainFn bool
}

func (w withHooks) create(ctx context.Context, data adapter.Record, model string, custom *customFn) (adapter.Record, error) {
	actual, ok, err := w.runBefore(ctx, model, "create", data)
	if err != nil || !ok {
		return nil, err
	}
	var created adapter.Record
	if custom == nil || custom.executeMainFn {
		created, err = w.a.Adapter.Create(ctx, adapter.CreateInput{Model: model, Data: actual, ForceAllowID: true})
		if err != nil {
			return nil, err
		}
	}
	if custom != nil && custom.fn != nil {
		in := created
		if in == nil {
			in = actual
		}
		created, err = custom.fn(ctx, in)
		if err != nil {
			return nil, err
		}
	}
	if err := w.runAfter(ctx, model, "create", created); err != nil {
		return nil, err
	}
	return created, nil
}

func (w withHooks) update(ctx context.Context, data adapter.Record, where []adapter.Where, model string, custom *customFn) (adapter.Record, error) {
	actual, ok, err := w.runBefore(ctx, model, "update", data)
	if err != nil || !ok {
		return nil, err
	}
	var customUpdated adapter.Record
	if custom != nil {
		customUpdated, err = custom.fn(ctx, actual)
		if err != nil {
			return nil, err
		}
	}
	var updated adapter.Record
	if custom == nil || custom.executeMainFn {
		updated, err = w.a.Adapter.Update(ctx, model, where, actual)
		if err != nil {
			return nil, err
		}
	} else {
		updated = customUpdated
	}
	if err := w.runAfter(ctx, model, "update", updated); err != nil {
		return nil, err
	}
	return updated, nil
}

func (w withHooks) updateMany(ctx context.Context, data adapter.Record, where []adapter.Where, model string) (int64, bool, error) {
	actual, ok, err := w.runBefore(ctx, model, "update", data)
	if err != nil || !ok {
		return 0, false, err
	}
	n, err := w.a.Adapter.UpdateMany(ctx, model, where, actual)
	if err != nil {
		return 0, false, err
	}
	if err := w.runAfter(ctx, model, "update", adapter.Record{"count": n}); err != nil {
		return 0, false, err
	}
	return n, true, nil
}

// delete returns ran=false when a before hook aborted.
func (w withHooks) delete(ctx context.Context, where []adapter.Where, model string, custom *func(ctx context.Context) error, executeMain bool) (bool, error) {
	var entity adapter.Record
	if rows, err := w.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: model, Where: where, Limit: 1}); err == nil && len(rows) > 0 {
		entity = rows[0]
	}
	if entity != nil {
		if _, ok, err := w.runBefore(ctx, model, "delete", entity); err != nil || !ok {
			return false, err
		}
	}
	if custom != nil {
		if err := (*custom)(ctx); err != nil {
			return false, err
		}
	}
	if (custom == nil || executeMain) && entity != nil {
		if err := w.a.Adapter.Delete(ctx, model, where); err != nil {
			return false, err
		}
	}
	if entity != nil {
		if err := w.runAfter(ctx, model, "delete", entity); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (w withHooks) deleteMany(ctx context.Context, where []adapter.Where, model string, custom *func(ctx context.Context) error, executeMain bool) (bool, error) {
	entities, _ := w.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: model, Where: where})
	for _, e := range entities {
		if _, ok, err := w.runBefore(ctx, model, "delete", e); err != nil || !ok {
			return false, err
		}
	}
	if custom != nil {
		if err := (*custom)(ctx); err != nil {
			return false, err
		}
	}
	if custom == nil || executeMain {
		if _, err := w.a.Adapter.DeleteMany(ctx, model, where); err != nil {
			return false, err
		}
	}
	for _, e := range entities {
		if err := w.runAfter(ctx, model, "delete", e); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (w withHooks) consumeOne(ctx context.Context, model string, hookWhere []adapter.Where, consume func() (adapter.Record, error), snapshot adapter.Record) (adapter.Record, error) {
	hasBefore := false
	for _, e := range w.a.dbHooks {
		if mh := e.hooks.model(model); mh != nil && mh.Delete.Before != nil {
			hasBefore = true
		}
	}
	if hasBefore {
		if snapshot == nil {
			if rows, err := w.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: model, Where: hookWhere, Limit: 1}); err == nil && len(rows) > 0 {
				snapshot = rows[0]
			}
		}
		if snapshot != nil {
			if _, ok, err := w.runBefore(ctx, model, "delete", snapshot); err != nil || !ok {
				return nil, err
			}
		}
	}
	consumed, err := consume()
	if err != nil || consumed == nil {
		return nil, err
	}
	if err := w.runAfter(ctx, model, "delete", consumed); err != nil {
		return nil, err
	}
	return consumed, nil
}
