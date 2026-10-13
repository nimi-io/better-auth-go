package scim

// Port of upstream scim-create-uniqueness.test.ts.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

type createUniquenessTxKey struct{}

// createUniquenessAdapter is createConcurrentCommitAdapter: inside a transaction, the
// first create of a scimGroup or scimUser runs inject (a concurrent commit outside the
// transaction) and then fails like a unique constraint violation.
type createUniquenessAdapter struct {
	adapter.Adapter
	mu       sync.Mutex
	injected bool
	inject   func(base adapter.Adapter, model string)
}

func (a *createUniquenessAdapter) SupportsNativeTransactions() bool { return true }

func (a *createUniquenessAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return a.Adapter.Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error {
		return fn(context.WithValue(txCtx, createUniquenessTxKey{}, true), a)
	})
}

func (a *createUniquenessAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if inTx, _ := ctx.Value(createUniquenessTxKey{}).(bool); inTx && (in.Model == "scimGroup" || in.Model == "scimUser") {
		a.mu.Lock()
		first := !a.injected
		a.injected = true
		a.mu.Unlock()
		if first {
			a.inject(a.Adapter, in.Model)
			return nil, errors.New("Simulated " + in.Model + " unique constraint")
		}
	}
	return a.Adapter.Create(ctx, in)
}

func createUniquenessEnv(t *testing.T, inject func(base adapter.Adapter, model string)) *testEnv {
	t.Helper()
	return newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")}}, envOptions{
		mutate: func(cfg *betterauth.Config) {
			inner := cfg.Database
			cfg.Database = func(opts adapter.Options) (adapter.Adapter, error) {
				a, err := inner(opts)
				if err != nil {
					return nil, err
				}
				return &createUniquenessAdapter{Adapter: a, inject: inject}, nil
			}
		},
	})
}

// createUniquenessCommit writes a row outside the running transaction.
func createUniquenessCommit(t *testing.T, base adapter.Adapter, model string, data adapter.Record) {
	if _, err := base.Create(context.Background(), adapter.CreateInput{Model: model, Data: data, ForceAllowID: true}); err != nil {
		t.Errorf("concurrent commit %s: %v", model, err)
	}
}

func createUniquenessExpect409(t *testing.T, ae *betterauth.APIError) {
	t.Helper()
	if ae == nil {
		t.Fatal("expected a rejection")
	}
	httpContractMustMatch(t, errBody(ae), map[string]any{"status": "409", "scimType": "uniqueness"})
}

func TestCreateUniqueness(t *testing.T) {
	headers := bearer("test-scim-token")

	t.Run("normalizes a concurrent Group displayName commit to SCIM uniqueness", func(t *testing.T) {
		now := time.Now()
		e := createUniquenessEnv(t, func(base adapter.Adapter, model string) {
			if model != "scimGroup" {
				return
			}
			createUniquenessCommit(t, base, "scimGroup", adapter.Record{
				"id":                   "concurrent-group",
				"connectionId":         "workforce",
				"provisioningDomainId": "workforce",
				"revision":             0,
				"displayName":          "Engineering",
				"displayNameKey":       createScopedKey("scim-group-display-name", "workforce", "engineering"),
				"orderKey":             "concurrent-group-order",
				"createdAt":            now,
				"updatedAt":            now,
			})
		})
		_, ae := e.call("createSCIMGroup", betterauth.CallInput{
			Body:    map[string]any{"schemas": []any{httpContractGroupSchema}, "displayName": "Engineering"},
			Headers: headers,
		})
		createUniquenessExpect409(t, ae)
	})

	t.Run("normalizes a concurrent User userName commit to SCIM uniqueness", func(t *testing.T) {
		now := time.Now()
		e := createUniquenessEnv(t, func(base adapter.Adapter, model string) {
			if model != "scimUser" {
				return
			}
			createUniquenessCommit(t, base, "user", adapter.Record{
				"id":            "concurrent-user",
				"name":          "Concurrent User",
				"email":         "ada@example.com",
				"emailVerified": false,
				"image":         nil,
				"createdAt":     now,
				"updatedAt":     now,
			})
			createUniquenessCommit(t, base, "scimUser", adapter.Record{
				"id":                   "concurrent-scim-user",
				"connectionId":         "workforce",
				"provisioningDomainId": "workforce",
				"userId":               "concurrent-user",
				"connectionUserKey":    createScopedKey("scim-user", "workforce", "concurrent-user"),
				"userName":             "ada@example.com",
				"userNameKey":          createScopedKey("scim-user-name", "workforce", "ada@example.com"),
				"primaryEmail":         "ada@example.com",
				"workEmailValueIndex":  "|ada@example.com|",
				"emailValueIndex":      "|ada@example.com|",
				"displayName":          "Concurrent User",
				"formattedName":        "Concurrent User",
				"serializedEmails":     `[{"value":"ada@example.com","primary":true}]`,
				"serializedAttributes": `{"schemas":["` + httpContractUserSchema + `"],"name":{"formatted":"Concurrent User"},"emails":[{"value":"ada@example.com","primary":true}]}`,
				"active":               true,
				"orderKey":             "concurrent-user-order",
				"createdAt":            now,
				"updatedAt":            now,
			})
		})
		_, ae := e.call("createSCIMUser", betterauth.CallInput{
			Body:    map[string]any{"schemas": []any{httpContractUserSchema}, "userName": "ada@example.com"},
			Headers: headers,
		})
		createUniquenessExpect409(t, ae)
	})

	t.Run("preserves a create failure when no committed uniqueness conflict exists", func(t *testing.T) {
		e := createUniquenessEnv(t, func(adapter.Adapter, string) {})
		_, err := e.callErr("createSCIMGroup", betterauth.CallInput{
			Body:    map[string]any{"schemas": []any{httpContractGroupSchema}, "displayName": "Engineering"},
			Headers: headers,
		})
		if err == nil || !strings.Contains(err.Error(), "Simulated scimGroup unique constraint") {
			t.Fatalf("err = %v, want the simulated unique constraint failure", err)
		}
	})
}
