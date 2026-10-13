package scim

import (
	"context"
	"sort"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func concurrentGroupMutation() error {
	return &betterAuthError{msg: "The SCIM Group changed concurrently; retry the request.", kind: conflictGroupMutation}
}

func runGroupMutationTransaction(ctx context.Context, auth *betterauth.AuthContext, fn func(tx context.Context) error) error {
	for attempt := 1; attempt <= transactionAttempts; attempt++ {
		err := runInTransaction(ctx, auth, fn)
		if err == nil {
			return nil
		}
		if !isIdentityConflict(err) && !isConflictKind(err, conflictProjectionSubject) && !isConflictKind(err, conflictGroupMutation) {
			return err
		}
	}
	return scimErr("CONFLICT", "The SCIM Group changed concurrently; retry the request")
}

func findGroup(ctx context.Context, db adapter.Adapter, conn Connection, groupID string) (*groupRow, error) {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelGroup, Where: []adapter.Where{w("id", groupID), w("connectionId", conn.ID)}})
	if err != nil {
		return nil, err
	}
	g := toGroup(r)
	if g != nil && g.ProvisioningDomainID != conn.ProvisioningDomainID {
		return nil, scimErr("CONFLICT", "The connection provisioningDomainId changed after resources were created")
	}
	return g, nil
}

func acquireGroupMutationLock(ctx context.Context, db adapter.Adapter, conn Connection, groupID string, missingConflict bool) (*groupRow, error) {
	g, err := findGroup(ctx, db, conn, groupID)
	if err != nil {
		return nil, err
	}
	if g == nil {
		if missingConflict {
			return nil, concurrentGroupMutation()
		}
		return nil, scimErr("NOT_FOUND", "SCIM Group not found")
	}
	r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelGroup, Where: []adapter.Where{
		w("id", g.ID), w("connectionId", conn.ID), w("revision", g.Revision)}, Increment: map[string]float64{"revision": 1}})
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, concurrentGroupMutation()
	}
	return toGroup(r), nil
}

func acquireGroupMutationLocks(ctx context.Context, db adapter.Adapter, conn Connection, groupIDs []string) ([]*groupRow, error) {
	ids := uniqueStrings(groupIDs)
	sort.Strings(ids)
	var out []*groupRow
	for _, id := range ids {
		g, err := acquireGroupMutationLock(ctx, db, conn, id, true)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func markGroupsModified(ctx context.Context, db adapter.Adapter, connectionID string, groups []*groupRow, updatedAt time.Time) error {
	for _, g := range groups {
		r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelGroup, Where: []adapter.Where{
			w("id", g.ID), w("connectionId", connectionID), w("revision", g.Revision)},
			Increment: map[string]float64{}, Set: adapter.Record{"updatedAt": updatedAt}})
		if err != nil {
			return err
		}
		if r == nil {
			return concurrentGroupMutation()
		}
	}
	return nil
}
