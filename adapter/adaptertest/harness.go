package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Harness describes the adapter under test (the arguments of testAdapter upstream).
type Harness struct {
	// Name is the adapter display name; Run groups all suites under a subtest with this name
	// (the describe block upstream).
	Name string
	// Factory returns the adapter factory for cfg, the Better Auth configuration a suite
	// needs (plugins / additional tables, renamed models and fields,
	// advanced.database.generateId "serial"/"uuid", joins, ...). It is called again
	// whenever the configuration changes and after every migration.
	Factory func(t testing.TB, cfg *betterauth.Config) adapter.Factory
	// Migrate prepares the database for auth (runMigrations upstream). Upstream adapters
	// start every migration from an empty database, so implementations should drop existing
	// data/tables first. nil means auth.RunMigrations, with
	// adapter.ErrMigrationsNotSupported treated as a no-op.
	Migrate func(ctx context.Context, auth *betterauth.Auth) error
	// AdditionalCleanup runs after the hard cleanup of all auth tables (additionalCleanups).
	AdditionalCleanup func(ctx context.Context) error
	// OverrideConfig adjusts every configuration the suites build
	// (overrideBetterAuthOptions).
	OverrideConfig func(cfg *betterauth.Config)
	// CustomIDGenerator generates ids for generated models (customIdGenerator), e.g. Mongo
	// ObjectIDs. A suite-level generator takes precedence.
	CustomIDGenerator func() string
	// TransformIDOutput maps generated ids to the form the adapter returns
	// (transformIdOutput).
	TransformIDOutput func(id any) string
	// Prefix is prepended to the statistics log lines (prefixTests).
	Prefix string
	// SupportsTransactions overrides transaction detection (adapterConfig.transaction
	// upstream). When nil, an adapter built with adapter.NewFactory supports transactions if
	// its driver implements adapter.Transactor.
	SupportsTransactions *bool
	// OnFinish runs after all suites (onFinish).
	OnFinish func()
}

// testSecret is the secret of every Auth instance the suites build.
const testSecret = "better-auth-adapter-conformance-secret-0123456789"

// ConfigMod is a fragment of Better Auth configuration (a partial BetterAuthOptions):
// it mutates a configuration that already carries the suite defaults, which is how
// deepmerge(defaults, options) composes upstream.
type ConfigMod func(cfg *betterauth.Config)

// Run executes the given suites (all built-in suites with default options when none are
// given) against the adapter described by h.
func Run(t *testing.T, h Harness, suites ...Suite) {
	t.Helper()
	if h.Factory == nil {
		t.Fatal("adaptertest: Harness.Factory is required")
	}
	if len(suites) == 0 {
		suites = AllSuites()
	}
	name := h.Name
	if name == "" {
		name = "adapter"
	}
	t.Run(name, func(t *testing.T) {
		r := &runner{t: t, h: h, ctx: context.Background()}
		r.setOptions(nil)
		// beforeAll
		if err := r.runMigrations(); err != nil {
			t.Fatalf("Error while running migrations: %v", err)
		}
		defer func() {
			// afterAll
			if err := r.cleanup(); err != nil {
				t.Errorf("%v", err)
			}
			r.printStats()
			if h.OnFinish != nil {
				h.OnFinish()
			}
		}()
		for _, s := range suites {
			s.run(t, r)
		}
	})
}

// AllSuites returns every built-in suite with default options, in upstream order.
func AllSuites() []Suite {
	return []Suite{
		NormalSuite(),
		TransactionsSuite(),
		AuthFlowSuite(),
		NumberIDSuite(),
		JoinsSuite(),
		UUIDSuite(),
		CaseInsensitiveSuite(),
	}
}

// runner holds the state of testAdapter: the current options and adapter.
type runner struct {
	t   *testing.T
	h   Harness
	ctx context.Context

	mu   sync.Mutex
	mods []ConfigMod
	cfg  *betterauth.Config
	ad   adapter.Adapter

	stats []SuiteStats
}

// buildConfig composes a configuration from fragments, then applies the harness override.
func (r *runner) buildConfig(mods []ConfigMod) *betterauth.Config {
	cfg := &betterauth.Config{
		BaseURL: "http://localhost:3000",
		Secret:  testSecret,
		Logger:  betterauth.NopLogger{},
	}
	for _, m := range mods {
		if m != nil {
			m(cfg)
		}
	}
	if r.h.OverrideConfig != nil {
		r.h.OverrideConfig(cfg)
	}
	return cfg
}

// setOptions replaces the current options (modifyBetterAuthOptions in test-adapter.ts) and
// refreshes the adapter.
func (r *runner) setOptions(mods []ConfigMod) *betterauth.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mods = append([]ConfigMod(nil), mods...)
	r.cfg = r.buildConfig(r.mods)
	r.ad = nil
	return r.cfg
}

// options returns a fresh copy of the current configuration (getBetterAuthOptions).
func (r *runner) options() *betterauth.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buildConfig(r.mods)
}

// adapterOptions maps a configuration to adapter options the way betterauth.New does.
func adapterOptions(cfg *betterauth.Config) adapter.Options {
	o := adapter.Options{Schema: betterauth.GetSchema(*cfg), Logger: nopAdapterLogger{}}
	if adv := cfg.Advanced; adv != nil && adv.Database != nil {
		o.IDMode = adv.Database.GenerateID
		o.GenerateID = adv.Database.GenerateIDFunc
		o.DefaultFindManyLimit = adv.Database.DefaultFindManyLimit
		o.Joins = adv.Database.Joins
	}
	return o
}

type nopAdapterLogger struct{}

func (nopAdapterLogger) Warn(string, ...any)  {}
func (nopAdapterLogger) Error(string, ...any) {}

// adapter returns the adapter for the current options (helpers.adapter()). The instance is
// cached until the options change or a migration runs, so transactions started through it
// stay bound to the same instance.
func (r *runner) adapter() (adapter.Adapter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ad != nil {
		return r.ad, nil
	}
	ad, err := r.h.Factory(r.t, r.cfg)(adapterOptions(r.cfg))
	if err != nil {
		return nil, err
	}
	r.ad = ad
	return ad, nil
}

// newAuth builds an Auth instance for the current options with the given database.
func (r *runner) newAuth(db adapter.Factory) (*betterauth.Auth, error) {
	cfg := r.options()
	cfg.Database = db
	return betterauth.New(*cfg)
}

// runMigrations is migrate() in test-adapter.ts.
func (r *runner) runMigrations() error {
	r.mu.Lock()
	cfg := r.cfg
	r.mu.Unlock()
	auth, err := r.newAuth(r.h.Factory(r.t, cfg))
	if err != nil {
		return fmt.Errorf("Error while running migrations: %w", err)
	}
	if r.h.Migrate != nil {
		err = r.h.Migrate(r.ctx, auth)
	} else {
		err = auth.RunMigrations(r.ctx)
		if errors.Is(err, adapter.ErrMigrationsNotSupported) {
			err = nil
		}
	}
	r.mu.Lock()
	r.ad = nil
	r.mu.Unlock()
	if err != nil {
		return fmt.Errorf("Error while running migrations: %w", err)
	}
	return nil
}

// cleanup deletes every row of every auth table (cleanup() in test-adapter.ts, the
// hardCleanup helper).
func (r *runner) cleanup() error {
	r.mu.Lock()
	r.ad = nil
	cfg := r.cfg
	r.mu.Unlock()
	ad, err := r.adapter()
	if err != nil {
		return fmt.Errorf("Error while cleaning up: %w", err)
	}
	for _, table := range betterauth.GetSchema(*cfg).Tables {
		if _, err := ad.DeleteMany(r.ctx, table.Key, nil); err != nil {
			return fmt.Errorf("Error while cleaning up all rows from %s: %w", table.Key, err)
		}
	}
	if r.h.AdditionalCleanup != nil {
		if err := r.h.AdditionalCleanup(r.ctx); err != nil {
			return fmt.Errorf("Error while running additional cleanups: %w", err)
		}
	}
	r.mu.Lock()
	r.ad = nil
	r.mu.Unlock()
	return nil
}

func (r *runner) supportsTransactions() bool {
	if r.h.SupportsTransactions != nil {
		return *r.h.SupportsTransactions
	}
	ad, err := r.adapter()
	if err != nil {
		return false
	}
	if c, ok := ad.(interface{ Custom() adapter.CustomAdapter }); ok {
		_, ok := c.Custom().(adapter.Transactor)
		return ok
	}
	return false
}

// SuiteStats are the per-suite statistics printed after the run (TestSuiteStats).
type SuiteStats struct {
	SuiteName          string
	TestCount          int
	MigrationCount     int
	TotalMigrationTime time.Duration
	SuiteDuration      time.Duration
}

func (r *runner) logPrefix() string {
	if r.h.Prefix == "" {
		return ""
	}
	return "[" + r.h.Prefix + "] "
}

func (r *runner) printStats() {
	if len(r.stats) == 0 {
		return
	}
	var tests, migrations int
	var migTime, dur time.Duration
	r.t.Logf("%sTEST SUITE STATISTICS SUMMARY", r.logPrefix())
	for _, s := range r.stats {
		avg := time.Duration(0)
		if s.MigrationCount > 0 {
			avg = s.TotalMigrationTime / time.Duration(s.MigrationCount)
		}
		r.t.Logf("%s: tests=%d migrations=%d (avg %s) migrationTime=%s duration=%s",
			s.SuiteName, s.TestCount, s.MigrationCount, avg, s.TotalMigrationTime, s.SuiteDuration)
		tests += s.TestCount
		migrations += s.MigrationCount
		migTime += s.TotalMigrationTime
		dur += s.SuiteDuration
	}
	r.t.Logf("TOTALS: tests=%d migrations=%d migrationTime=%s duration=%s", tests, migrations, migTime, dur)
}

// ---- tracking adapter (wrapperAdapter in create-test-suite.ts) ----

// trackingAdapter forwards every call to the current adapter. Create always passes
// forceAllowId and records the created row so it can be deleted after the test.
type trackingAdapter struct {
	r *runner
	s *suiteRun
}

var _ adapter.Adapter = (*trackingAdapter)(nil)

// inner returns the current adapter; it panics when the adapter cannot be built and is only
// used by methods without an error result.
func (w *trackingAdapter) inner() adapter.Adapter {
	ad, err := w.r.adapter()
	if err != nil {
		panic(fmt.Sprintf("adaptertest: building adapter: %v", err))
	}
	return ad
}

// Custom exposes the driver so capability checks (adapter.AsMigrator, transactions) see
// through the wrapper.
func (w *trackingAdapter) Custom() adapter.CustomAdapter {
	if c, ok := w.inner().(interface{ Custom() adapter.CustomAdapter }); ok {
		return c.Custom()
	}
	return nil
}

func (w *trackingAdapter) ID() string { return w.inner().ID() }

func (w *trackingAdapter) Schema() *db.Schema { return w.inner().Schema() }

func (w *trackingAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	data := in.Data
	if _, ok := data["id"]; ok && !in.ForceAllowID {
		// the wrapper factory drops ids passed without forceAllowId
		cp := make(adapter.Record, len(data))
		for k, v := range data {
			if k != "id" {
				cp[k] = v
			}
		}
		data = cp
	}
	ad, err := w.r.adapter()
	if err != nil {
		return nil, err
	}
	res, err := ad.Create(ctx, adapter.CreateInput{Model: in.Model, Data: data, Select: in.Select, ForceAllowID: true})
	if err != nil {
		return nil, err
	}
	if res != nil {
		w.s.track(in.Model, res["id"])
	}
	return res, nil
}

func (w *trackingAdapter) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return nil, err
	}
	return ad.FindOne(ctx, in)
}

func (w *trackingAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return nil, err
	}
	return ad.FindMany(ctx, in)
}

func (w *trackingAdapter) Count(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return 0, err
	}
	return ad.Count(ctx, model, where)
}

func (w *trackingAdapter) Update(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (adapter.Record, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return nil, err
	}
	return ad.Update(ctx, model, where, update)
}

func (w *trackingAdapter) UpdateMany(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (int64, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return 0, err
	}
	return ad.UpdateMany(ctx, model, where, update)
}

func (w *trackingAdapter) Delete(ctx context.Context, model string, where []adapter.Where) error {
	ad, err := w.r.adapter()
	if err != nil {
		return err
	}
	return ad.Delete(ctx, model, where)
}

func (w *trackingAdapter) DeleteMany(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return 0, err
	}
	return ad.DeleteMany(ctx, model, where)
}

func (w *trackingAdapter) ConsumeOne(ctx context.Context, model string, where []adapter.Where) (adapter.Record, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return nil, err
	}
	return ad.ConsumeOne(ctx, model, where)
}

func (w *trackingAdapter) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	ad, err := w.r.adapter()
	if err != nil {
		return nil, err
	}
	return ad.IncrementOne(ctx, in)
}

// Transaction uses the real adapter's transaction (config.transaction = adapter.transaction
// upstream); fn receives the transactional adapter itself, so rows created through tx are
// not tracked.
func (w *trackingAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	ad, err := w.r.adapter()
	if err != nil {
		return err
	}
	return ad.Transaction(ctx, fn)
}
