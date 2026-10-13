package twofactor

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// Port of two-factor.account-lockout.test.ts.

// legacyDriver is a CustomAdapter without the native ConsumeOne / IncrementOne / transaction
// capabilities (createDbWithoutAtomicMethods), so the factory uses its fallbacks. It
// delegates to a regular memory adapter.
type legacyDriver struct{ inner adapter.Adapter }

func toWhere(cw []adapter.CleanedWhere) []adapter.Where {
	out := make([]adapter.Where, len(cw))
	for i, c := range cw {
		out[i] = adapter.Where{Field: c.Field, Value: c.Value, Operator: c.Operator, Connector: c.Connector, Insensitive: c.Insensitive}
	}
	return out
}

func (d legacyDriver) Create(ctx context.Context, _, modelKey string, data adapter.Record) (adapter.Record, error) {
	return d.inner.Create(ctx, adapter.CreateInput{Model: modelKey, Data: data, ForceAllowID: true})
}

func (d legacyDriver) FindOne(ctx context.Context, q adapter.Query) (adapter.Record, error) {
	return d.inner.FindOne(ctx, adapter.FindOneInput{Model: q.ModelKey, Where: toWhere(q.Where), Select: q.Select})
}

func (d legacyDriver) FindMany(ctx context.Context, q adapter.Query) ([]adapter.Record, error) {
	return d.inner.FindMany(ctx, adapter.FindManyInput{Model: q.ModelKey, Where: toWhere(q.Where), Limit: q.Limit, Offset: q.Offset, SortBy: q.SortBy, Select: q.Select})
}

func (d legacyDriver) Count(ctx context.Context, q adapter.Query) (int64, error) {
	return d.inner.Count(ctx, q.ModelKey, toWhere(q.Where))
}

func (d legacyDriver) Update(ctx context.Context, q adapter.Query, update adapter.Record) (adapter.Record, error) {
	return d.inner.Update(ctx, q.ModelKey, toWhere(q.Where), update)
}

func (d legacyDriver) UpdateMany(ctx context.Context, q adapter.Query, update adapter.Record) (int64, error) {
	return d.inner.UpdateMany(ctx, q.ModelKey, toWhere(q.Where), update)
}

func (d legacyDriver) Delete(ctx context.Context, q adapter.Query) error {
	return d.inner.Delete(ctx, q.ModelKey, toWhere(q.Where))
}

func (d legacyDriver) DeleteMany(ctx context.Context, q adapter.Query) (int64, error) {
	return d.inner.DeleteMany(ctx, q.ModelKey, toWhere(q.Where))
}

func legacyDatabase() adapter.Factory {
	store := memory.NewDB()
	return adapter.NewFactory(adapter.Config{AdapterID: "legacy-memory", SupportsArrays: true, SupportsJSON: true},
		func(opts adapter.Options, _ adapter.Helpers) (adapter.CustomAdapter, error) {
			inner, err := memory.New(store)(opts)
			if err != nil {
				return nil, err
			}
			return legacyDriver{inner: inner}, nil
		})
}

type lockoutSetup struct {
	*challengeSetup
	otp func() string
}

func setupLockout(t *testing.T, lockout *AccountLockoutOptions, database adapter.Factory) *lockoutSetup {
	t.Helper()
	opts, otp := otpCapture()
	var io instanceOpts
	if database != nil {
		io.mutate = func(c *betterauth.Config) { c.Database = database }
	}
	c := setupTwoFactorChallenge(t, []*betterauth.Plugin{New(Options{AccountLockout: lockout, OTPOptions: opts})}, io)
	return &lockoutSetup{challengeSetup: c, otp: otp}
}

func (l *lockoutSetup) correctTotp() string { return totpNow(l.t, l.secret) }

func (l *lockoutSetup) failOtpOnce() *res {
	h := l.startChallenge()
	l.api("sendTwoFactorOTP", h, map[string]any{})
	return l.api("verifyTwoFactorOTP", h, map[string]any{"code": "000000"})
}

func TestAccountLockoutAcrossChallenges(t *testing.T) {
	t.Run("enforces account lockout through legacy adapter fallbacks", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{MaxFailedAttempts: 3}, legacyDatabase())
		challenges := make([]http.Header, 3)
		for k := range challenges {
			challenges[k] = l.startChallenge()
		}
		rs := parallel(3, func(k int) *res { return l.verifyBackup(challenges[k], "0000-0000") })
		for _, r := range rs {
			expectStatus(t, r, 401)
		}
		expectStatus(t, l.verifyBackup(l.startChallenge(), l.backupCodes[0]), 429)
	})
	t.Run("consumes an email OTP once through legacy adapter fallbacks", func(t *testing.T) {
		l := setupLockout(t, nil, legacyDatabase())
		h := l.startChallenge()
		l.api("sendTwoFactorOTP", h, map[string]any{})
		code := l.otp()
		if !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
			t.Fatalf("code %q", code)
		}
		rs := parallel(2, func(int) *res { return l.api("verifyTwoFactorOTP", h, map[string]any{"code": code}) })
		ok, client := 0, 0
		for _, r := range rs {
			if r.Status == 200 {
				ok++
			} else if r.Status >= 400 && r.Status < 500 {
				client++
			}
		}
		if ok != 1 || client != 1 {
			t.Fatalf("statuses %d %d", rs[0].Status, rs[1].Status)
		}
	})
	t.Run("allows a backup code to be consumed once through legacy adapter fallbacks", func(t *testing.T) {
		l := setupLockout(t, nil, legacyDatabase())
		challenges := []http.Header{l.startChallenge(), l.startChallenge()}
		rs := parallel(2, func(k int) *res { return l.verifyBackup(challenges[k], l.backupCodes[0]) })
		statuses := []int{rs[0].Status, rs[1].Status}
		sort.Ints(statuses)
		// Exactly one request may consume the code. Upstream (single-threaded Node) always
		// interleaves both reads before either write, so the loser sees the guarded update
		// fail (409). With real parallelism the loser can also read after the winner
		// committed and then simply finds no matching code (401).
		if statuses[0] != 200 || (statuses[1] != 409 && statuses[1] != 401) {
			t.Fatalf("statuses %v", statuses)
		}
	})
	t.Run("locks the account after failures accumulate across separate challenges", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{MaxFailedAttempts: 3}, nil)
		for k := 0; k < 3; k++ {
			r := l.verifyTotp(l.startChallenge(), "000000")
			expectStatus(t, r, 401)
			expectMessage(t, r, ErrInvalidCode.Message)
		}
		locked := l.verifyTotp(l.startChallenge(), l.correctTotp())
		expectStatus(t, locked, 429)
		expectMessage(t, locked, ErrAccountTemporarilyLocked.Message)
	})
	t.Run("counts failures from all factors toward one account lock", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{MaxFailedAttempts: 3}, nil)
		for k := 0; k < 2; k++ {
			expectStatus(t, l.verifyTotp(l.startChallenge(), "000000"), 401)
		}
		expectStatus(t, l.verifyBackup(l.startChallenge(), "0000-0000"), 401)
		locked := l.verifyTotp(l.startChallenge(), l.correctTotp())
		expectStatus(t, locked, 429)
		expectMessage(t, locked, ErrAccountTemporarilyLocked.Message)
	})
	t.Run("counts email-OTP failures toward the same account lock", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{MaxFailedAttempts: 3}, nil)
		for k := 0; k < 2; k++ {
			expectStatus(t, l.verifyTotp(l.startChallenge(), "000000"), 401)
		}
		expectStatus(t, l.failOtpOnce(), 401)
		expectStatus(t, l.verifyTotp(l.startChallenge(), l.correctTotp()), 429)
	})
	t.Run("resets the counter on a successful verification", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{MaxFailedAttempts: 3}, nil)
		for k := 0; k < 2; k++ {
			expectStatus(t, l.verifyTotp(l.startChallenge(), "000000"), 401)
		}
		expectStatus(t, l.verifyTotp(l.startChallenge(), l.correctTotp()), 200)
		for k := 0; k < 2; k++ {
			expectStatus(t, l.verifyTotp(l.startChallenge(), "000000"), 401)
		}
		expectStatus(t, l.verifyTotp(l.startChallenge(), l.correctTotp()), 200)
	})
	t.Run("releases the lock once its window elapses", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{MaxFailedAttempts: 3}, nil)
		for k := 0; k < 3; k++ {
			expectStatus(t, l.verifyTotp(l.startChallenge(), "000000"), 401)
		}
		expectStatus(t, l.verifyTotp(l.startChallenge(), l.correctTotp()), 429)
		l.update("twoFactor", adapter.Record{"lockedUntil": time.Now().Add(-time.Second)}, eq("userId", l.userID))
		expectStatus(t, l.verifyTotp(l.startChallenge(), l.correctTotp()), 200)
	})
	t.Run("does not lock when account lockout is disabled", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{Enabled: betterauth.Bool(false), MaxFailedAttempts: 3}, nil)
		for k := 0; k < 5; k++ {
			expectStatus(t, l.verifyTotp(l.startChallenge(), "000000"), 401)
		}
		expectStatus(t, l.verifyTotp(l.startChallenge(), l.correctTotp()), 200)
	})
	t.Run("counts a row with no prior failure count without locking on the first failure", func(t *testing.T) {
		l := setupLockout(t, &AccountLockoutOptions{MaxFailedAttempts: 3}, nil)
		l.update("twoFactor", adapter.Record{"failedVerificationCount": nil}, eq("userId", l.userID))
		expectStatus(t, l.verifyTotp(l.startChallenge(), "000000"), 401)
		expectStatus(t, l.verifyTotp(l.startChallenge(), l.correctTotp()), 200)
	})
	t.Run("sets the lock with a guarded counter transition", func(t *testing.T) {
		row := adapter.Record{"id": "two-factor-id", "userId": "user-id", "secret": "secret", "backupCodes": "codes",
			"verified": true, "failedVerificationCount": 2, "lockedUntil": nil}
		fake := &recordingAdapter{onIncrement: func(n int) adapter.Record {
			if n == 1 {
				r := adapter.Record{}
				for k, v := range row {
					r[k] = v
				}
				r["failedVerificationCount"] = 3
				return r
			}
			return nil
		}}
		p := &plugin{opts: Options{AccountLockout: &AccountLockoutOptions{MaxFailedAttempts: 3, DurationSeconds: 60}}}
		ctx := &betterauth.EndpointContext{Auth: &betterauth.AuthContext{Adapter: fake}}
		if err := p.recordFailure(ctx, row); err != nil {
			t.Fatal(err)
		}
		if len(fake.calls) != 2 {
			t.Fatalf("calls %d", len(fake.calls))
		}
		c := fake.calls[1]
		if c.Model != "twoFactor" || len(c.Where) != 2 ||
			c.Where[0].Field != "id" || c.Where[0].Value != "two-factor-id" ||
			c.Where[1].Field != "failedVerificationCount" || c.Where[1].Operator != adapter.Gte || c.Where[1].Value != 3 ||
			len(c.Increment) != 0 {
			t.Fatalf("call %+v", c)
		}
		if _, ok := c.Set["lockedUntil"].(time.Time); !ok {
			t.Fatalf("set %+v", c.Set)
		}
	})
}

// recordingAdapter records IncrementOne calls (the other methods are unused).
type recordingAdapter struct {
	adapter.Adapter
	calls       []adapter.IncrementInput
	onIncrement func(n int) adapter.Record
}

func (r *recordingAdapter) IncrementOne(_ context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	r.calls = append(r.calls, in)
	return r.onIncrement(len(r.calls)), nil
}
