package scim

// Port of upstream scim-user-fencing.test.ts ("SCIM User connection fencing").

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// ufRaceAdapter is createDecommissionRaceAdapter: before the next transaction it marks the
// workforce connection binding as decommissioned.
type ufRaceAdapter struct {
	adapter.Adapter
	mu      sync.Mutex
	pending bool
}

func (a *ufRaceAdapter) decommissionBeforeNextTransaction() {
	a.mu.Lock()
	a.pending = true
	a.mu.Unlock()
}

func (a *ufRaceAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	a.mu.Lock()
	pending := a.pending
	a.pending = false
	a.mu.Unlock()
	if pending {
		n, err := a.Adapter.UpdateMany(ctx, "scimConnectionBinding",
			[]adapter.Where{{Field: "connectionId", Value: "workforce"}},
			adapter.Record{"decommissionStatus": "complete"})
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("Expected the SCIM connection binding")
		}
	}
	return a.Adapter.Transaction(ctx, fn)
}

func TestUserFencing_SCIMUserConnectionFencing(t *testing.T) {
	t.Run("rejects a no-op PATCH when the connection retires before commit", func(t *testing.T) {
		race := &ufRaceAdapter{}
		e := newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")}},
			envOptions{mutate: func(cfg *betterauth.Config) {
				inner := cfg.Database
				cfg.Database = func(o adapter.Options) (adapter.Adapter, error) {
					a, err := inner(o)
					if err != nil {
						return nil, err
					}
					race.Adapter = a
					return race, nil
				}
			}})
		headers := bearer("test-scim-token")
		user := e.mustCall("createSCIMUser", betterauth.CallInput{Headers: headers, Body: map[string]any{"schemas": []any{SchemaUser}, "userName": "ada@example.com"}})
		race.decommissionBeforeNextTransaction()

		_, ae := e.call("patchSCIMUser", betterauth.CallInput{Headers: headers,
			Params: map[string]string{"userId": user["id"].(string)},
			Body: map[string]any{"schemas": []any{SchemaPatchOp}, "Operations": []any{
				map[string]any{"op": "replace", "path": "active", "value": true},
			}}})
		if ae == nil {
			t.Fatal("expected error")
		}
		rapMatchObject(t, errBody(ae), `{"status":"401"}`)
	})
}
