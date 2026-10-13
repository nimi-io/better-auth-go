package scim

import (
	"context"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const decommissionLeaseDuration = 5 * time.Minute

func createDecommissionResult(b *connectionBinding) (*jsonx.Object, error) {
	if b.DecommissionStatus == decommissionActive {
		return nil, newBetterAuthError(`SCIM connection "` + b.ConnectionID + `" has not started decommissioning.`)
	}
	var retryAfter any
	if b.DecommissionStatus == decommissionReconciling {
		retryAfter = nullTime(b.DecommissionLeaseExpiresAt)
	}
	return jsonx.O("connectionId", b.ConnectionID, "provisioningDomainId", b.ProvisioningDomainID,
		"status", b.DecommissionStatus, "decommissionedAt", nullTime(b.DecommissionedAt),
		"completedAt", nullTime(b.DecommissionCompletedAt), "retryAfter", retryAfter,
		"reconciledUsers", b.DecommissionReconciledUserCount, "batches", b.DecommissionBatchCount), nil
}

func assertDomainBinding(b *connectionBinding, domain string) error {
	if b.ProvisioningDomainID == domain {
		return nil
	}
	return newBetterAuthError(`SCIM connection "` + b.ConnectionID + `" is already bound to provisioning domain "` + b.ProvisioningDomainID + `".`)
}

func findConnectionBinding(ctx context.Context, db adapter.Adapter, connectionID string) (*connectionBinding, error) {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelConnectionBinding, Where: []adapter.Where{w("connectionKey", CreateConnectionKey(connectionID))}})
	if err != nil {
		return nil, err
	}
	if b := toBinding(r); b != nil {
		return b, nil
	}
	return nil, newBetterAuthError(`SCIM connection "` + connectionID + `" has no persisted binding.`)
}

func acquireDecommissionLease(ctx context.Context, db adapter.Adapter, connectionID, domain string) (*connectionBinding, string, error) {
	leaseID := bacrypto.GenerateID(32)
	for attempt := 0; attempt < 10; attempt++ {
		var b *connectionBinding
		var err error
		if attempt == 0 {
			completedAt := time.Now()
			b, err = findOrCreateConnectionBinding(ctx, db, connectionID, domain, completedAt,
				bindingInit{status: decommissionComplete, decommissioned: &completedAt, completedAt: &completedAt},
				func(b *connectionBinding) error {
					if domain != "" {
						return assertDomainBinding(b, domain)
					}
					return nil
				})
		} else {
			b, err = findConnectionBinding(ctx, db, connectionID)
		}
		if err != nil {
			return nil, "", err
		}
		if domain != "" {
			if err := assertDomainBinding(b, domain); err != nil {
				return nil, "", err
			}
		}
		if b.DecommissionStatus == decommissionComplete {
			return b, "", nil
		}
		now := time.Now()
		if b.DecommissionStatus == decommissionReconciling && b.DecommissionLeaseID != nil && *b.DecommissionLeaseID != "" &&
			b.DecommissionLeaseExpiresAt != nil && b.DecommissionLeaseExpiresAt.After(now) {
			return b, "", nil
		}
		decommissionedAt := now
		if b.DecommissionedAt != nil {
			decommissionedAt = *b.DecommissionedAt
		}
		r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelConnectionBinding, Where: []adapter.Where{
			w("id", b.ID), w("decommissionRevision", b.DecommissionRevision), w("decommissionStatus", b.DecommissionStatus)},
			Increment: map[string]float64{"decommissionRevision": 1},
			Set: adapter.Record{"decommissionStatus": decommissionReconciling, "decommissionedAt": decommissionedAt,
				"decommissionCompletedAt": nil, "decommissionLeaseId": leaseID,
				"decommissionLeaseExpiresAt": now.Add(decommissionLeaseDuration)}})
		if err != nil {
			return nil, "", err
		}
		if r != nil {
			return toBinding(r), leaseID, nil
		}
	}
	return nil, "", newBetterAuthError(`SCIM connection "` + connectionID + `" changed repeatedly while decommissioning; retry the operation.`)
}

func releaseDecommissionLease(ctx context.Context, db adapter.Adapter, bindingID, leaseID string) error {
	for attempt := 0; attempt < 3; attempt++ {
		r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelConnectionBinding, Where: []adapter.Where{w("id", bindingID)}})
		if err != nil {
			return err
		}
		b := toBinding(r)
		if b == nil || b.DecommissionStatus == decommissionComplete || b.DecommissionLeaseID == nil || *b.DecommissionLeaseID != leaseID {
			return nil
		}
		rr, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelConnectionBinding, Where: []adapter.Where{
			w("id", b.ID), w("decommissionRevision", b.DecommissionRevision), w("decommissionLeaseId", leaseID)},
			Increment: map[string]float64{"decommissionRevision": 1},
			Set:       adapter.Record{"decommissionLeaseId": nil, "decommissionLeaseExpiresAt": nil}})
		if err != nil {
			return err
		}
		if rr != nil {
			return nil
		}
	}
	return nil
}

func lockAndRenewDecommissionLease(ctx context.Context, db adapter.Adapter, b *connectionBinding, leaseID string) (*connectionBinding, error) {
	r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelConnectionBinding, Where: []adapter.Where{
		w("id", b.ID), w("decommissionRevision", b.DecommissionRevision), w("decommissionStatus", decommissionReconciling),
		w("decommissionLeaseId", leaseID)}, Increment: map[string]float64{},
		Set: adapter.Record{"decommissionLeaseExpiresAt": time.Now().Add(decommissionLeaseDuration)}})
	if err != nil {
		return nil, err
	}
	if r != nil {
		return toBinding(r), nil
	}
	return nil, newBetterAuthError(`SCIM connection "` + b.ConnectionID + `" decommission lease changed before reconciliation.`)
}

func (p *plugin) reconcileDecommissionedConnection(ctx context.Context, auth *betterauth.AuthContext, binding *connectionBinding, leaseID string) (*connectionBinding, error) {
	db := auth.Adapter
	for {
		var checkpoint *connectionBinding
		err := runInTransaction(ctx, auth, func(tx context.Context) error {
			r, err := db.FindOne(tx, adapter.FindOneInput{Model: modelConnectionBinding, Where: []adapter.Where{w("id", binding.ID)}})
			if err != nil {
				return err
			}
			stored := toBinding(r)
			if stored == nil {
				return newBetterAuthError(`SCIM connection "` + binding.ConnectionID + `" binding disappeared during decommissioning.`)
			}
			if stored.DecommissionStatus == decommissionComplete {
				checkpoint = stored
				return nil
			}
			if stored.DecommissionLeaseID == nil || *stored.DecommissionLeaseID != leaseID {
				return newBetterAuthError(`SCIM connection "` + stored.ConnectionID + `" decommission lease was taken over by another worker.`)
			}
			batch, err := findProjectionDomainBatch(tx, db, stored.ProvisioningDomainID, stored.DecommissionCursorUserID)
			if err != nil {
				return err
			}
			if batch != nil {
				if err := p.projection.acquireUserLocks(tx, db, stored.ProvisioningDomainID, batch.scimUserIDs); err != nil {
					return err
				}
			}
			b, err := lockAndRenewDecommissionLease(tx, db, stored, leaseID)
			if err != nil {
				return err
			}
			if batch == nil {
				cr, err := db.IncrementOne(tx, adapter.IncrementInput{Model: modelConnectionBinding, Where: []adapter.Where{
					w("id", b.ID), w("decommissionRevision", b.DecommissionRevision), w("decommissionLeaseId", leaseID)},
					Increment: map[string]float64{"decommissionRevision": 1},
					Set: adapter.Record{"decommissionStatus": decommissionComplete, "decommissionCompletedAt": time.Now(),
						"decommissionLeaseId": nil, "decommissionLeaseExpiresAt": nil}})
				if err != nil {
					return err
				}
				if cr != nil {
					checkpoint = toBinding(cr)
					return nil
				}
				return newBetterAuthError(`SCIM connection "` + b.ConnectionID + `" decommission checkpoint changed concurrently.`)
			}
			if err := reconcileProjectionDomainBatch(tx, auth, db, p.projection, p.identity, b.ProvisioningDomainID, batch, true); err != nil {
				return err
			}
			now := time.Now()
			set := adapter.Record{"decommissionCursorUserId": batch.cursorUserID}
			if batch.hasMore {
				set["decommissionLeaseExpiresAt"] = now.Add(decommissionLeaseDuration)
			} else {
				set["decommissionStatus"] = decommissionComplete
				set["decommissionCompletedAt"] = now
				set["decommissionLeaseId"] = nil
				set["decommissionLeaseExpiresAt"] = nil
			}
			ar, err := db.IncrementOne(tx, adapter.IncrementInput{Model: modelConnectionBinding, Where: []adapter.Where{
				w("id", b.ID), w("decommissionRevision", b.DecommissionRevision), w("decommissionLeaseId", leaseID)},
				Increment: map[string]float64{"decommissionRevision": 1, "decommissionReconciledUserCount": float64(len(batch.userIDs)),
					"decommissionBatchCount": 1}, Set: set})
			if err != nil {
				return err
			}
			if ar != nil {
				checkpoint = toBinding(ar)
				return nil
			}
			return newBetterAuthError(`SCIM connection "` + b.ConnectionID + `" decommission checkpoint changed concurrently.`)
		})
		if err != nil {
			_ = safeCall(func() error { return releaseDecommissionLease(ctx, db, binding.ID, leaseID) })
			return nil, err
		}
		if checkpoint.DecommissionStatus == decommissionComplete {
			return checkpoint, nil
		}
	}
}

// decommissionConnection is decommissionSCIMConnection.
func (p *plugin) decommissionConnection(ctx context.Context, auth *betterauth.AuthContext, connectionID, domain string) (*jsonx.Object, error) {
	b, leaseID, err := acquireDecommissionLease(ctx, auth.Adapter, connectionID, domain)
	if err != nil {
		return nil, err
	}
	if leaseID == "" {
		return createDecommissionResult(b)
	}
	b, err = p.reconcileDecommissionedConnection(ctx, auth, b, leaseID)
	if err != nil {
		return nil, err
	}
	return createDecommissionResult(b)
}

func (p *plugin) decommissionEndpoint() *betterauth.Endpoint {
	return serverOnly("decommissionSCIMConnection", zObj(
		zf("connectionId", zStr().trim().min(1).max(255)),
		zf("provisioningDomainId", zOpt(zStr().trim().min(1).max(255))),
	), false, func(ctx *betterauth.EndpointContext) (any, error) {
		body := ctx.Body.(*jsonx.Object)
		return p.decommissionConnection(ctx.Context(), ctx.Auth, getStr(body, "connectionId"), getStr(body, "provisioningDomainId"))
	})
}
