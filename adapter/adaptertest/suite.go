package adaptertest

import (
	"context"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Test is one test entry (TestEntry upstream).
type Test struct {
	// Name is the upstream test name.
	Name string
	// MigrateBetterAuth, when set, is merged into the suite defaults and migrated before
	// the test runs (migrateBetterAuth).
	MigrateBetterAuth ConfigMod
	// Fn runs the test.
	Fn func(h *H)
}

// SuiteConfig configures a suite (the second argument of createTestSuite).
type SuiteConfig struct {
	// DefaultOptions are the suite's defaultBetterAuthOptions.
	DefaultOptions ConfigMod
	// AlwaysMigrate migrates whenever the options change.
	AlwaysMigrate bool
	// PrefixTests is the display prefix upstream (informational: suites already run as
	// named subtests).
	PrefixTests string
	// CustomIDGenerator generates ids for generated models; it takes precedence over the
	// harness generator.
	CustomIDGenerator func() string
}

// DisableAll disables every test of a suite (disableTests: { ALL: true }).
var DisableAll = map[string]bool{"ALL": true}

// SuiteOptions are the options a suite is instantiated with.
type SuiteOptions struct {
	// DisableTests maps test names to true to skip them. The key "ALL" skips every test
	// that is not explicitly mapped to false.
	DisableTests map[string]bool
}

// Suite is an instantiated test suite.
type Suite struct {
	Name   string
	Config SuiteConfig
	Tests  []Test
	opts   SuiteOptions
}

// SuiteFactory instantiates a suite with options (the function createTestSuite returns).
type SuiteFactory func(opts ...SuiteOptions) Suite

// CreateTestSuite declares a suite (createTestSuite).
func CreateTestSuite(name string, cfg SuiteConfig, tests func() []Test) SuiteFactory {
	return func(opts ...SuiteOptions) Suite {
		s := Suite{Name: name, Config: cfg, Tests: tests()}
		for _, o := range opts {
			if o.DisableTests != nil {
				if s.opts.DisableTests == nil {
					s.opts.DisableTests = map[string]bool{}
				}
				for k, v := range o.DisableTests {
					s.opts.DisableTests[k] = v
				}
			}
		}
		return s
	}
}

func (s Suite) skipped(name string) bool {
	d := s.opts.DisableTests
	if d == nil {
		return false
	}
	v, ok := d[name]
	if d["ALL"] && !(ok && !v) {
		return true
	}
	return ok && v
}

type createdRow struct{ ID any }

// suiteRun is the state of one suite execution.
type suiteRun struct {
	r       *runner
	s       Suite
	mu      sync.Mutex
	created ModelRows[createdRow]
	wrapper *trackingAdapter
	stats   SuiteStats
	start   time.Time
}

func (sr *suiteRun) track(model string, id any) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.created.Add(model, createdRow{ID: id})
}

// cleanupCreatedRows deletes the rows created during the test.
func (sr *suiteRun) cleanupCreatedRows() {
	sr.mu.Lock()
	tracked := sr.created
	sr.created = ModelRows[createdRow]{}
	sr.mu.Unlock()
	if tracked.Len() == 0 {
		return
	}
	ad, err := sr.r.adapter()
	if err != nil {
		sr.mu.Lock()
		for _, m := range tracked.Models {
			for _, row := range tracked.Rows[m] {
				sr.created.Add(m, row)
			}
		}
		sr.mu.Unlock()
		return
	}
	retry := CleanupRows(tracked, func(model string, row createdRow) (CleanupResult, error) {
		if ad.Schema() == nil || !schemaHasModel(ad, model) {
			return CleanupRetry, nil
		}
		return CleanupComplete, ad.Delete(sr.r.ctx, model, []adapter.Where{{Field: "id", Value: row.ID}})
	})
	sr.mu.Lock()
	for _, m := range retry.Models {
		for _, row := range retry.Rows[m] {
			sr.created.Add(m, row)
		}
	}
	sr.mu.Unlock()
}

func schemaHasModel(ad adapter.Adapter, model string) bool {
	for _, t := range ad.Schema().Tables {
		if t.Key == model || t.ModelName == model {
			return true
		}
	}
	return false
}

// applyOptionsAndMigrate is applyOptionsAndMigrate in create-test-suite.ts. Options with
// function values never compare equal upstream, so every call counts as a change.
func (sr *suiteRun) applyOptionsAndMigrate(mod ConfigMod, forceMigrate bool) (*betterauth.Config, error) {
	cfg := sr.r.setOptions([]ConfigMod{sr.s.Config.DefaultOptions, mod})
	if sr.s.Config.AlwaysMigrate || forceMigrate {
		start := time.Now()
		if err := sr.r.runMigrations(); err != nil {
			return nil, err
		}
		sr.stats.MigrationCount++
		sr.stats.TotalMigrationTime += time.Since(start)
	}
	return cfg, nil
}

func (s Suite) run(t *testing.T, r *runner) {
	t.Run(s.Name, func(t *testing.T) {
		sr := &suiteRun{r: r, s: s, start: time.Now(), stats: SuiteStats{SuiteName: s.Name}}
		sr.wrapper = &trackingAdapter{r: r, s: sr}
		allDisabled := s.opts.DisableTests != nil && s.opts.DisableTests["ALL"]
		// header test: hard cleanup and apply the suite defaults
		_ = r.cleanup()
		if s.Config.DefaultOptions != nil && !allDisabled {
			if _, err := sr.applyOptionsAndMigrate(nil, s.Config.AlwaysMigrate); err != nil {
				t.Fatalf("%v", err)
			}
		}
		defer func() {
			sr.stats.SuiteDuration = time.Since(sr.start)
			r.stats = append(r.stats, sr.stats)
		}()
		// currentGroupMigrationOptions starts as null, which never equals a test's
		// (undefined or object) migrateBetterAuth.
		groupSet := false
		var group ConfigMod
		for _, test := range s.Tests {
			test := test
			skip := s.skipped(test.Name)
			t.Run(test.Name, func(t *testing.T) {
				if skip {
					t.Skipf("disabled for this adapter (disableTests)")
				}
				if !groupSet || !(group == nil && test.MigrateBetterAuth == nil) {
					if _, err := sr.applyOptionsAndMigrate(test.MigrateBetterAuth, true); err != nil {
						t.Fatalf("%v", err)
					}
					group, groupSet = test.MigrateBetterAuth, true
				}
				sr.stats.TestCount++
				h := &H{T: t, Ctx: context.Background(), Adapter: sr.wrapper, sr: sr}
				defer sr.cleanupCreatedRows()
				test.Fn(h)
			})
		}
	})
}

// H is the helper set passed to every test (the helpers argument of createTestSuite).
type H struct {
	*testing.T
	Ctx context.Context
	// Adapter forwards to the adapter under test; Create always passes ForceAllowID and
	// records created rows for cleanup.
	Adapter adapter.Adapter
	sr      *suiteRun
}

// Options returns the current configuration (getBetterAuthOptions).
func (h *H) Options() *betterauth.Config { return h.sr.r.options() }

// ModifyOptions replaces the test options with the suite defaults plus mod, migrating when
// requested or when the suite always migrates (modifyBetterAuthOptions).
func (h *H) ModifyOptions(mod ConfigMod, migrate bool) *betterauth.Config {
	h.Helper()
	cfg, err := h.sr.applyOptionsAndMigrate(mod, migrate)
	if err != nil {
		h.Fatalf("%v", err)
	}
	return cfg
}

// CleanupRows deletes the rows created so far in this test (the cleanup helper).
func (h *H) CleanupRows() { h.sr.cleanupCreatedRows() }

// HardCleanup deletes every row of every auth table (hardCleanup).
func (h *H) HardCleanup() {
	h.Helper()
	if err := h.sr.r.cleanup(); err != nil {
		h.Fatalf("%v", err)
	}
}

// GetAuth builds an Auth instance for the current options whose database is the tracking
// adapter (getAuth).
func (h *H) GetAuth() *betterauth.Auth {
	h.Helper()
	w := h.sr.wrapper
	auth, err := h.sr.r.newAuth(func(adapter.Options) (adapter.Adapter, error) { return w, nil })
	if err != nil {
		h.Fatalf("betterauth.New: %v", err)
	}
	return auth
}

// CustomIDGenerator returns the harness id generator (nil when unset).
func (h *H) CustomIDGenerator() func() string { return h.sr.r.h.CustomIDGenerator }

// TransformIDOutput returns the harness id output transform (nil when unset).
func (h *H) TransformIDOutput() func(id any) string { return h.sr.r.h.TransformIDOutput }

// TransformGeneratedModel applies TransformIDOutput to a generated model's id.
func (h *H) TransformGeneratedModel(data adapter.Record) adapter.Record {
	out := clone(data)
	if f := h.sr.r.h.TransformIDOutput; f != nil {
		out["id"] = f(out["id"])
	}
	return out
}

func (h *H) idGenerator() string {
	if g := h.sr.s.Config.CustomIDGenerator; g != nil {
		return g()
	}
	if g := h.sr.r.h.CustomIDGenerator; g != nil {
		return g()
	}
	return bacrypto.GenerateID()
}

func jsNow() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// Generate returns a random user, session, verification or account (generate).
func (h *H) Generate(model string) adapter.Record {
	h.Helper()
	id := h.idGenerator()
	randomDate := time.UnixMilli(time.Now().UnixMilli() - int64(rand.Float64()*1000*60*60*24*365)).UTC()
	idOut := id
	if f := h.sr.r.h.TransformIDOutput; f != nil {
		idOut = f(id)
	}
	switch model {
	case "user":
		return adapter.Record{
			"id":            id,
			"createdAt":     randomDate,
			"updatedAt":     jsNow(),
			"email":         strings.ToLower("user-" + idOut + "@email.com"),
			"emailVerified": true,
			"name":          "user-" + idOut,
			"image":         nil,
		}
	case "session":
		return adapter.Record{
			"id":        id,
			"createdAt": randomDate,
			"updatedAt": jsNow(),
			"expiresAt": jsNow(),
			"token":     bacrypto.GenerateID(32),
			"userId":    bacrypto.GenerateID(),
			"ipAddress": "127.0.0.1",
			"userAgent": "Some User Agent",
		}
	case "verification":
		return adapter.Record{
			"id":         id,
			"createdAt":  randomDate,
			"updatedAt":  jsNow(),
			"expiresAt":  jsNow(),
			"identifier": "test:" + bacrypto.GenerateID(),
			"value":      bacrypto.GenerateID(),
		}
	case "account":
		return adapter.Record{
			"id":                    id,
			"createdAt":             randomDate,
			"updatedAt":             jsNow(),
			"accountId":             bacrypto.GenerateID(),
			"providerId":            "test",
			"userId":                bacrypto.GenerateID(),
			"accessToken":           bacrypto.GenerateID(),
			"refreshToken":          bacrypto.GenerateID(),
			"idToken":               bacrypto.GenerateID(),
			"accessTokenExpiresAt":  jsNow(),
			"refreshTokenExpiresAt": jsNow(),
			"scope":                 "test",
		}
	}
	h.Fatalf("Unknown model type: %s", model)
	return nil
}

// InsertRandom inserts one random model and returns [user] / [user, session] /
// [verification] / [user, account] (insertRandom with count 1).
func (h *H) InsertRandom(model string) []adapter.Record {
	h.Helper()
	return h.InsertRandomN(model, 1)[0]
}

// InsertRandomN inserts count random models (insertRandom).
func (h *H) InsertRandomN(model string, count int) [][]adapter.Record {
	h.Helper()
	var res [][]adapter.Record
	create := func(m string, data adapter.Record) adapter.Record {
		return h.Create(adapter.CreateInput{Model: m, Data: data, ForceAllowID: true})
	}
	for i := 0; i < count; i++ {
		var results []adapter.Record
		switch model {
		case "user":
			results = append(results, create("user", h.Generate("user")))
		case "session":
			userRes := create("user", h.Generate("user"))
			session := h.Generate("session")
			session["userId"] = userRes["id"]
			results = append(results, userRes, create("session", session))
		case "verification":
			results = append(results, create("verification", h.Generate("verification")))
		case "account":
			user := h.Generate("user")
			account := h.Generate("account")
			userRes := create("user", user)
			account["userId"] = userRes["id"]
			results = append(results, userRes, create("account", account))
		}
		res = append(res, results)
	}
	return res
}

// SortModels sorts records in place by id (default) or createdAt and returns them
// (sortModels).
func (h *H) SortModels(models []adapter.Record, by ...string) []adapter.Record {
	field := "id"
	if len(by) > 0 {
		field = by[0]
	}
	sort.SliceStable(models, func(i, j int) bool {
		if field == "createdAt" {
			a, _ := adapter.ToTime(models[i]["createdAt"])
			b, _ := adapter.ToTime(models[j]["createdAt"])
			return a.Before(b)
		}
		return adapter.ToString(models[i]["id"]) < adapter.ToString(models[j]["id"])
	})
	return models
}

// ---- adapter calls failing the test on error ----

// Create calls Adapter.Create.
func (h *H) Create(in adapter.CreateInput) adapter.Record {
	h.Helper()
	res, err := h.Adapter.Create(h.Ctx, in)
	if err != nil {
		h.Fatalf("create %s: %v", in.Model, err)
	}
	return res
}

// FindOne calls Adapter.FindOne.
func (h *H) FindOne(in adapter.FindOneInput) adapter.Record {
	h.Helper()
	res, err := h.Adapter.FindOne(h.Ctx, in)
	if err != nil {
		h.Fatalf("findOne %s: %v", in.Model, err)
	}
	return res
}

// FindMany calls Adapter.FindMany.
func (h *H) FindMany(in adapter.FindManyInput) []adapter.Record {
	h.Helper()
	res, err := h.Adapter.FindMany(h.Ctx, in)
	if err != nil {
		h.Fatalf("findMany %s: %v", in.Model, err)
	}
	return res
}

// Count calls Adapter.Count.
func (h *H) Count(model string, where ...adapter.Where) int64 {
	h.Helper()
	n, err := h.Adapter.Count(h.Ctx, model, where)
	if err != nil {
		h.Fatalf("count %s: %v", model, err)
	}
	return n
}

// Update calls Adapter.Update.
func (h *H) Update(model string, where []adapter.Where, update adapter.Record) adapter.Record {
	h.Helper()
	res, err := h.Adapter.Update(h.Ctx, model, where, update)
	if err != nil {
		h.Fatalf("update %s: %v", model, err)
	}
	return res
}

// UpdateMany calls Adapter.UpdateMany.
func (h *H) UpdateMany(model string, where []adapter.Where, update adapter.Record) int64 {
	h.Helper()
	n, err := h.Adapter.UpdateMany(h.Ctx, model, where, update)
	if err != nil {
		h.Fatalf("updateMany %s: %v", model, err)
	}
	return n
}

// Delete calls Adapter.Delete.
func (h *H) Delete(model string, where ...adapter.Where) {
	h.Helper()
	if err := h.Adapter.Delete(h.Ctx, model, where); err != nil {
		h.Fatalf("delete %s: %v", model, err)
	}
}

// DeleteMany calls Adapter.DeleteMany.
func (h *H) DeleteMany(model string, where ...adapter.Where) int64 {
	h.Helper()
	n, err := h.Adapter.DeleteMany(h.Ctx, model, where)
	if err != nil {
		h.Fatalf("deleteMany %s: %v", model, err)
	}
	return n
}

// IncrementOne calls Adapter.IncrementOne.
func (h *H) IncrementOne(in adapter.IncrementInput) adapter.Record {
	h.Helper()
	res, err := h.Adapter.IncrementOne(h.Ctx, in)
	if err != nil {
		h.Fatalf("incrementOne %s: %v", in.Model, err)
	}
	return res
}
