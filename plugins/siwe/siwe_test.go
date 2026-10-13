package siwe

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Ported from packages/better-auth/src/plugins/siwe/siwe.test.ts. Monkey-patched
// internalAdapter methods are replaced by adapter wrappers (see spyAdapter).

const (
	walletAddress = "0x000000000000000000000000000000000000dEaD"
	domain        = "example.com"
	chainID       = 1
	testNonce     = "A1b2C3d4E5f6G7h8J"
)

type msgOpts struct {
	domain, address, nonce, expirationTime, notBefore string
	chainID                                           int
}

func siweMessage(o msgOpts) string {
	d, a, c, n := domain, walletAddress, chainID, testNonce
	if o.domain != "" {
		d = o.domain
	}
	if o.address != "" {
		a = o.address
	}
	if o.chainID != 0 {
		c = o.chainID
	}
	if o.nonce != "" {
		n = o.nonce
	}
	msg := fmt.Sprintf("%s wants you to sign in with your Ethereum account:\n%s\n\nSign in.\n\nURI: https://%s\nVersion: 1\nChain ID: %d\nNonce: %s\nIssued At: 2024-01-01T00:00:00.000Z", d, a, d, c, n)
	if o.expirationTime != "" {
		msg += "\nExpiration Time: " + o.expirationTime
	}
	if o.notBefore != "" {
		msg += "\nNot Before: " + o.notBefore
	}
	return msg
}

func baseOptions(nonce string) Options {
	return Options{
		Domain:   domain,
		GetNonce: func(context.Context) (string, error) { return nonce, nil },
		VerifyMessage: func(_ context.Context, a VerifyMessageArgs) (bool, error) {
			return a.Signature == "valid_signature", nil
		},
	}
}

func anon(o Options, v bool) Options { o.Anonymous = &v; return o }

// spyAdapter wraps the database adapter to observe or fail specific operations (the
// upstream tests monkey-patch internalAdapter methods instead).
type spyAdapter struct {
	adapter.Adapter
	consumes   atomic.Int32
	failCreate func(in adapter.CreateInput) error
}

func (s *spyAdapter) ConsumeOne(ctx context.Context, model string, where []adapter.Where) (adapter.Record, error) {
	if model == "verification" {
		s.consumes.Add(1)
	}
	return s.Adapter.ConsumeOne(ctx, model, where)
}

func (s *spyAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	if in.Model == "verification" && len(in.Where) == 1 && in.Where[0].Field == "identifier" && betterauth.InTransaction(ctx) {
		s.consumes.Add(1)
	}
	return s.Adapter.FindMany(ctx, in)
}

func (s *spyAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if s.failCreate != nil {
		if err := s.failCreate(in); err != nil {
			return nil, err
		}
	}
	return s.Adapter.Create(ctx, in)
}

func (s *spyAdapter) PlanMigrations(ctx context.Context, sc *db.Schema) (*adapter.MigrationPlan, error) {
	m, _ := adapter.AsMigrator(s.Adapter)
	return m.PlanMigrations(ctx, sc)
}

func withSpy(spy *spyAdapter) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		orig := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := orig(o)
			spy.Adapter = a
			return spy, err
		}
	}
}

func verifyReq(c *client, body map[string]any) *response {
	c.inst.t.Helper()
	return c.post("/siwe/verify", body)
}

func nonce(c *client) *response {
	c.inst.t.Helper()
	return c.post("/siwe/nonce", nil)
}

func findWallets(t *testing.T, inst *instance, where ...adapter.Where) []adapter.Record {
	t.Helper()
	rows, err := inst.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "walletAddress", Where: where})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func countSessions(t *testing.T, inst *instance) int {
	t.Helper()
	rows, err := inst.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "session"})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func num(v any) float64 { f, _ := adapter.ToFloat(v); return f }

func addressIs(v string) adapter.Where {
	return adapter.Where{Field: "address", Operator: adapter.Eq, Value: v}
}
func chainIs(v int) adapter.Where {
	return adapter.Where{Field: "chainId", Operator: adapter.Eq, Value: v}
}

func plugins(o Options) []*betterauth.Plugin { return []*betterauth.Plugin{New(o)} }

func TestSIWE(t *testing.T) {
	t.Run("should generate a valid nonce before the wallet address and chain are known", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		d := expectOK(t, nonce(inst.client()))
		if !regexp.MustCompile(`^[a-zA-Z0-9]{17}$`).MatchString(d["nonce"].(string)) {
			t.Fatalf("bad nonce %v", d)
		}
	})

	t.Run("should allow an empty body when generating a nonce", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		d := expectOK(t, inst.client().post("/siwe/nonce", map[string]any{}))
		if !regexp.MustCompile(`^[a-zA-Z0-9]{17}$`).MatchString(d["nonce"].(string)) {
			t.Fatalf("bad nonce %v", d)
		}
	})

	t.Run("should reject obsolete wallet-bound nonce inputs", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		res := inst.client().post("/siwe/nonce", map[string]any{"walletAddress": walletAddress, "chainId": chainID})
		eq(t, res.Status, 400)
	})

	t.Run("should support getNonce alias", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		eq(t, expectOK(t, inst.client().post("/siwe/get-nonce", nil))["nonce"], testNonce)
	})

	t.Run("should reject server nonce generation that does not follow ERC-4361", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions("your-secure-random-nonce")), nil)
		expectStatus(t, nonce(inst.client()), 500, "SIWE_INVALID_NONCE")
	})

	t.Run("should reject verification if nonce is missing", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		res := verifyReq(inst.client(), map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"})
		expectStatus(t, res, 401, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")
		if !strings.Contains(strings.ToLower(res.Message()), "nonce") {
			t.Fatalf("message %q", res.Message())
		}
	})

	for _, tc := range []struct{ name, nonce string }{
		{"short", "abc1234"},
		{"non-alphanumeric", "some-other-nonce"},
		{"oversized", strings.Repeat("A", 251)},
	} {
		t.Run("should reject a signed SIWE message with a "+tc.name+" nonce before lookup", func(t *testing.T) {
			spy := &spyAdapter{}
			inst := newInstance(t, plugins(baseOptions(testNonce)), withSpy(spy))
			spy.consumes.Store(0)
			res := verifyReq(inst.client(), map[string]any{"message": siweMessage(msgOpts{nonce: tc.nonce}), "signature": "valid_signature"})
			expectStatus(t, res, 401, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")
			eq(t, spy.consumes.Load(), int32(0))
		})
	}

	t.Run("should reject a signed SIWE message without a valid address", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		expectStatus(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{address: "invalid"}), "signature": "valid_signature"}), 401, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")
	})

	t.Run("should reject verification with invalid signature", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		eq(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "invalid_signature"}).Status, 401)
	})

	t.Run("should reject a signed SIWE message without a positive chain ID", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		msg := strings.Replace(siweMessage(msgOpts{}), "Chain ID: 1", "Chain ID: 0", 1)
		expectStatus(t, verifyReq(c, map[string]any{"message": msg, "signature": "valid_signature"}), 401, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")
	})

	t.Run("should reject obsolete wallet-bound verification inputs", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		res := verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "walletAddress": walletAddress, "chainId": chainID})
		eq(t, res.Status, 400)
	})

	t.Run("should reject invalid message", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		eq(t, verifyReq(inst.client(), map[string]any{"message": "invalid_message", "signature": "valid_signature"}).Status, 401)
	})

	t.Run("should reject verification without email when anonymous is false", func(t *testing.T) {
		inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), nil)
		res := verifyReq(inst.client(), map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"})
		eq(t, res.Status, 400)
		eq(t, res.Message(), "[body.email] Email is required when the anonymous plugin option is disabled.")
	})

	t.Run("should accept verification with email when anonymous is false", func(t *testing.T) {
		inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), nil)
		c := inst.client()
		nonce(c)
		d := expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "email": "user@example.com"}))
		eq(t, d["success"], true)
		accounts, err := inst.auth.Context().InternalAdapter.FindAccounts(context.Background(), d["user"].(map[string]any)["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, a := range accounts {
			if a.ProviderID == "siwe" && a.AccountID == fmt.Sprintf("%s:%d", walletAddress, chainID) {
				found = true
			}
		}
		if !found {
			t.Fatal("siwe account not found")
		}
	})

	for _, reservationErr := range []error{
		errors.New("reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values."),
		errors.New("reservation adapter unavailable"),
	} {
		t.Run("should keep wallet email fallback when email reservation fails with "+reservationErr.Error(), func(t *testing.T) {
			spy := &spyAdapter{failCreate: func(in adapter.CreateInput) error {
				if id, _ := in.Data["identifier"].(string); in.Model == "verification" && strings.HasPrefix(id, "siwe-email-claim-") {
					return reservationErr
				}
				return nil
			}}
			inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), withSpy(spy))
			c := inst.client()
			nonce(c)
			d := expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "email": "user@example.com"}))
			eq(t, d["success"], true)
			eq(t, c.sessionUser()["email"], strings.ToLower(walletAddress)+"@siwe.placeholder.invalid")
		})
	}

	t.Run("should reject new SIWE user when validateUserInfo returns error", func(t *testing.T) {
		var methodErr error
		inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, _ map[string]any, s betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
				if s.Method != "siwe" {
					methodErr = errors.New("unexpected method " + s.Method)
				}
				return &betterauth.ValidateUserInfoResult{Error: "siwe_blocked", ErrorDescription: "SIWE sign-up is not allowed"}, nil
			}}
		}, instanceOpts{disableTestUser: true})
		c := inst.client()
		nonce(c)
		res := verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "email": "siwe@example.com"})
		eq(t, res.Code(), "siwe_blocked")
		eq(t, res.Message(), "SIWE sign-up is not allowed")
		if methodErr != nil {
			t.Fatal(methodErr)
		}
	})

	t.Run("should not bind a caller-supplied email that already belongs to another account", func(t *testing.T) {
		inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), nil)
		c := inst.client()
		nonce(c)
		d := expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "email": "test@test.com"}))
		eq(t, d["success"], true)
		if c.sessionUser()["email"] == "test@test.com" {
			t.Fatal("email must not be bound")
		}
		users, _ := inst.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: "test@test.com"}}})
		eq(t, len(users), 1)
	})

	t.Run("should treat a case-variant of an existing email as the same email", func(t *testing.T) {
		inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), nil)
		first := inst.client()
		nonce(first)
		expectOK(t, verifyReq(first, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "email": "Mixed@Case.com"}))
		eq(t, first.sessionUser()["email"], "mixed@case.com")
		second := inst.client()
		nonce(second)
		expectOK(t, verifyReq(second, map[string]any{"message": siweMessage(msgOpts{address: "0x000000000000000000000000000000000000bEEF"}), "signature": "valid_signature", "email": "mixed@case.com"}))
		if second.sessionUser()["email"] == "mixed@case.com" {
			t.Fatal("email must not be reused")
		}
	})

	t.Run("should reject invalid email format when anonymous is false", func(t *testing.T) {
		inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), nil)
		res := verifyReq(inst.client(), map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "email": "not-an-email"})
		eq(t, res.Status, 400)
		eq(t, res.Message(), "[body.email] Invalid email address")
	})

	t.Run("uses a namespaced placeholder email when no email is provided", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		eq(t, expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}))["success"], true)
		eq(t, c.sessionUser()["email"], strings.ToLower(walletAddress)+"@siwe.placeholder.invalid")
	})

	t.Run("should mint exactly one session when the same nonce is verified concurrently", func(t *testing.T) {
		o := baseOptions(testNonce)
		o.VerifyMessage = func(_ context.Context, a VerifyMessageArgs) (bool, error) {
			time.Sleep(50 * time.Millisecond)
			return a.Signature == "valid_signature", nil
		}
		inst := newInstance(t, plugins(o), nil)
		nonce(inst.client())
		before := countSessions(t, inst)
		results := make([]*response, 2)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = verifyReq(inst.client(), map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"})
			}(i)
		}
		wg.Wait()
		successes, failures := 0, []*response{}
		for _, r := range results {
			if r.Status == 200 && r.JSON()["success"] == true {
				successes++
			} else {
				failures = append(failures, r)
			}
		}
		eq(t, successes, 1)
		eq(t, len(failures), 1)
		eq(t, failures[0].Status, 401)
		eq(t, len(findWallets(t, inst, addressIs(walletAddress))), 1)
		eq(t, countSessions(t, inst), before+1)
	})

	t.Run("should reject an expired nonce and consume the row", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		ia := inst.auth.Context().InternalAdapter
		identifier := "siwe:" + testNonce
		if _, err := ia.CreateVerificationValue(context.Background(), identifier, testNonce, time.Now().Add(-time.Second), nil); err != nil {
			t.Fatal(err)
		}
		expectStatus(t, verifyReq(inst.client(), map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}), 401, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")
		v, err := ia.FindVerificationValue(context.Background(), identifier)
		if err != nil || v != nil {
			t.Fatalf("expected consumed row: %v %v", v, err)
		}
	})

	t.Run("should not allow nonce reuse", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		eq(t, expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}))["success"], true)
		expectStatus(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}), 401, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")
	})

	t.Run("should reject empty string email when anonymous is false", func(t *testing.T) {
		inst := newInstance(t, plugins(anon(baseOptions(testNonce), false)), nil)
		c := inst.client()
		nonce(c)
		res := verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature", "email": ""})
		eq(t, res.Status, 400)
		eq(t, res.Message(), "[body.email] Invalid email address; [body.email] Email is required when the anonymous plugin option is disabled.")
	})

	t.Run("should store and return the wallet address in checksum format", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		eq(t, expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{address: strings.ToLower(walletAddress)}), "signature": "valid_signature"}))["success"], true)
		w := findWallets(t, inst, addressIs(walletAddress))
		eq(t, len(w), 1)
		eq(t, w[0]["address"], walletAddress)
		nonce(c)
		upper := "0x" + strings.ToUpper(walletAddress[2:])
		eq(t, expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{address: upper}), "signature": "valid_signature"}))["success"], true)
		eq(t, len(findWallets(t, inst, addressIs(walletAddress))), 1)
	})

	t.Run("should reject duplicate wallet address entries", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		first := expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}))
		eq(t, first["success"], true)
		w := findWallets(t, inst, addressIs(walletAddress), chainIs(chainID))
		eq(t, len(w), 1)
		eq(t, w[0]["address"], walletAddress)
		eq(t, num(w[0]["chainId"]), float64(chainID))
		eq(t, w[0]["isPrimary"], true)
		nonce(c)
		second := expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}))
		eq(t, second["success"], true)
		eq(t, second["user"].(map[string]any)["id"], first["user"].(map[string]any)["id"])
		after := findWallets(t, inst, addressIs(walletAddress), chainIs(chainID))
		eq(t, len(after), 1)
		users, _ := inst.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "user"})
		n := 0
		for _, u := range users {
			for _, wa := range after {
				if wa["userId"] == u["id"] {
					n++
				}
			}
		}
		eq(t, n, 1)
	})

	t.Run("should support custom schema with mergeSchema", func(t *testing.T) {
		o := baseOptions(testNonce)
		o.Schema = &SchemaOptions{ModelName: "wallet_address", Fields: map[string]string{
			"userId": "user_id", "address": "wallet_address", "chainId": "chain_id", "isPrimary": "is_primary", "createdAt": "created_at"}}
		inst := newInstance(t, plugins(o), nil)
		c := inst.client()
		nonce(c)
		eq(t, expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}))["success"], true)
		w := findWallets(t, inst, addressIs(walletAddress), chainIs(chainID))
		eq(t, len(w), 1)
		eq(t, w[0]["address"], walletAddress)
		eq(t, num(w[0]["chainId"]), float64(chainID))
		eq(t, w[0]["isPrimary"], true)
		if w[0]["userId"] == nil || w[0]["createdAt"] == nil {
			t.Fatalf("missing fields: %v", w[0])
		}
	})

	t.Run("should allow same address on different chains for same user", func(t *testing.T) {
		inst := newInstance(t, plugins(baseOptions(testNonce)), nil)
		c := inst.client()
		nonce(c)
		eth := expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}))
		nonce(c)
		poly := expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{chainID: 137}), "signature": "valid_signature"}))
		eq(t, poly["user"].(map[string]any)["id"], eth["user"].(map[string]any)["id"])
		all := findWallets(t, inst, addressIs(walletAddress))
		eq(t, len(all), 2)
		var ethRec, polyRec adapter.Record
		for _, w := range all {
			switch num(w["chainId"]) {
			case 1:
				ethRec = w
			case 137:
				polyRec = w
			}
		}
		if ethRec == nil || polyRec == nil {
			t.Fatalf("records: %v", all)
		}
		eq(t, ethRec["isPrimary"], true)
		eq(t, polyRec["isPrimary"], false)
		eq(t, ethRec["userId"], polyRec["userId"])
	})

	setup := func(t *testing.T) *instance { return newInstance(t, plugins(baseOptions(testNonce)), nil) }

	t.Run("message binding", func(t *testing.T) {
		t.Run("rejects a valid signature over a message with an unknown nonce", func(t *testing.T) {
			c := setup(t).client()
			nonce(c)
			expectStatus(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{nonce: "SomeOtherNonce123"}), "signature": "valid_signature"}), 401, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")
		})
		t.Run("rejects a message bound to a different domain", func(t *testing.T) {
			c := setup(t).client()
			nonce(c)
			expectStatus(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{domain: "other.example.com"}), "signature": "valid_signature"}), 401, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")
		})
		t.Run("rejects a message with an invalid chain id", func(t *testing.T) {
			c := setup(t).client()
			nonce(c)
			msg := strings.Replace(siweMessage(msgOpts{}), "Chain ID: 1", "Chain ID: 0", 1)
			expectStatus(t, verifyReq(c, map[string]any{"message": msg, "signature": "valid_signature"}), 401, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")
		})
		t.Run("rejects an arbitrary (non-SIWE) message even with a valid signature", func(t *testing.T) {
			c := setup(t).client()
			nonce(c)
			expectStatus(t, verifyReq(c, map[string]any{"message": "gm, please sign this to continue", "signature": "valid_signature"}), 401, "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")
		})
		t.Run("rejects an expired SIWE message", func(t *testing.T) {
			c := setup(t).client()
			nonce(c)
			expectStatus(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{expirationTime: "2020-01-01T00:00:00.000Z"}), "signature": "valid_signature"}), 401, "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED")
		})
		t.Run("does not mint a session for an existing wallet user when an unrelated signature is reused", func(t *testing.T) {
			inst := setup(t)
			c := inst.client()
			nonce(c)
			eq(t, expectOK(t, verifyReq(c, map[string]any{"message": siweMessage(msgOpts{}), "signature": "valid_signature"}))["success"], true)
			before := countSessions(t, inst)
			nonce(c)
			res := verifyReq(c, map[string]any{"message": "Approve transfer of 1 ETH", "signature": "valid_signature"})
			eq(t, res.Status, 401)
			if res.Data() != nil {
				t.Fatal("expected no data")
			}
			eq(t, countSessions(t, inst), before)
		})
	})
}

// Go-specific coverage for the message parser and checksum helper.
func TestParseMessageAndChecksum(t *testing.T) {
	p := ParseMessage("https://Example.com/login wants you to sign in with your Ethereum account:\r\n 0x000000000000000000000000000000000000dead \n\nURI: x\nChain ID: 0x89\nNonce: abc\nNot Before: 2999-01-01T00:00:00Z")
	eq(t, p.Scheme, "https")
	eq(t, p.Domain, "Example.com/login")
	eq(t, p.Address, "0x000000000000000000000000000000000000dead")
	eq(t, p.ChainID, float64(137))
	eq(t, NormalizeDomain(p.Domain), "example.com")
	eq(t, ToChecksumAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
}
