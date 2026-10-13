package scim

import (
	"context"
	"sort"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const projectionBatchSize = 50

func concurrentProjectionSubjectMutation() error {
	return &betterAuthError{msg: "The SCIM projection subject changed concurrently; retry the request.", kind: conflictProjectionSubject}
}

func normalizeMappedRoles(roles []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, c := range roles {
		r := jsTrim(c)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

func chunk(ids []string, size int) [][]string {
	var out [][]string
	for i := 0; i < len(ids); i += size {
		end := i + size
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, ids[i:end])
	}
	return out
}

func acquireProjectionSubjectLocks(ctx context.Context, db adapter.Adapter, domain string, scimUserIDs []string) error {
	affected := map[string]bool{}
	for _, c := range chunk(scimUserIDs, projectionBatchSize) {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: []adapter.Where{
			wop("id", adapter.In, strsToAny(c)), w("provisioningDomainId", domain)}})
		if err != nil {
			return err
		}
		for _, r := range rows {
			affected[recStr(r, "userId")] = true
		}
	}
	userIDs := make([]string, 0, len(affected))
	for id := range affected {
		userIDs = append(userIDs, id)
	}
	sort.Strings(userIDs)
	if len(userIDs) == 0 {
		return nil
	}
	subjects := map[string]*subjectRow{}
	for _, c := range chunk(userIDs, projectionBatchSize) {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelSubject, Where: []adapter.Where{wop("userId", adapter.In, strsToAny(c))}})
		if err != nil {
			return err
		}
		for _, r := range rows {
			s := toSubject(r)
			subjects[s.UserID] = s
		}
	}
	if len(subjects) != len(userIDs) {
		return newBetterAuthError("A SCIM User selected for projection has no subject aggregate.")
	}
	now := time.Now()
	for _, id := range userIDs {
		s := subjects[id]
		if s == nil {
			return newBetterAuthError("A SCIM User selected for projection has no subject aggregate.")
		}
		r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelSubject, Where: []adapter.Where{
			w("id", s.ID), w("revision", s.Revision)}, Increment: map[string]float64{"revision": 1}, Set: adapter.Record{"updatedAt": now}})
		if err != nil {
			return err
		}
		if r == nil {
			return concurrentProjectionSubjectMutation()
		}
	}
	return nil
}

func createProjectionGrantKey(connectionID, scimUserID, kind, sourceID, role string) string {
	return createScopedKey("scim-projection-grant", connectionID, scimUserID, kind, sourceID, role)
}

type desiredGrant struct {
	grantRow
	source AuthorizationSource
}

type projectionCoordinator struct{ opts *Options }

func (p *projectionCoordinator) buildDesiredGrants(ctx context.Context, db adapter.Adapter, domain, userID string,
	active []*scimUserRow, memberships []*memberRow, groupByID map[string]*groupRow) ([]desiredGrant, error) {
	var roles *RoleProjection
	if p.opts.Projection != nil {
		roles = p.opts.Projection.Roles
	}
	if roles == nil || len(active) == 0 {
		return nil, nil
	}
	byID := map[string]*scimUserRow{}
	var ids []string
	for _, u := range active {
		byID[u.ID] = u
		ids = append(ids, u.ID)
	}
	if memberships == nil {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{wop("scimUserId", adapter.In, strsToAny(ids))}})
		if err != nil {
			return nil, err
		}
		memberships = toMembers(rows)
	}
	if len(memberships) == 0 {
		return nil, nil
	}
	if groupByID == nil {
		var gids []string
		for _, m := range memberships {
			gids = append(gids, m.GroupID)
		}
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroup, Where: []adapter.Where{wop("id", adapter.In, strsToAny(uniqueStrings(gids)))}})
		if err != nil {
			return nil, err
		}
		groupByID = map[string]*groupRow{}
		for _, r := range rows {
			g := toGroup(r)
			groupByID[g.ID] = g
		}
	}
	var order []string
	desired := map[string]desiredGrant{}
	existence := map[string]bool{}
	dbCtx := DatabaseContext{Context: ctx, Database: db}
	for _, m := range memberships {
		u := byID[m.SCIMUserID]
		g := groupByID[m.GroupID]
		if u == nil || g == nil || g.ConnectionID != u.ConnectionID || g.ProvisioningDomainID != domain {
			continue
		}
		source := AuthorizationSource{Type: "group", ID: g.ID, DisplayName: g.DisplayName}
		if g.ExternalID != nil {
			source.ExternalID = *g.ExternalID
		}
		var mapped []string
		if err := runApplicationCallback("SCIM role mapping failed", func() error {
			r, err := roles.Map(RoleMappingInput{ConnectionID: u.ConnectionID, ProvisioningDomainID: domain,
				SCIMUserID: u.ID, UserID: userID, Source: source}, dbCtx)
			if err != nil {
				return err
			}
			mapped = normalizeMappedRoles(r)
			return nil
		}); err != nil {
			return nil, err
		}
		for _, role := range mapped {
			ek := createScopedKey("scim-role-existence", u.ConnectionID, domain, role)
			exists, ok := existence[ek]
			if !ok {
				if err := runApplicationCallback("SCIM role validation failed", func() error {
					e, err := roles.Exists(RoleExistenceInput{ConnectionID: u.ConnectionID, ProvisioningDomainID: domain, Role: role}, dbCtx)
					exists = e
					return err
				}); err != nil {
					return nil, err
				}
				existence[ek] = exists
			}
			if !exists {
				continue
			}
			key := createProjectionGrantKey(u.ConnectionID, u.ID, "group", g.ID, role)
			value := g.DisplayName
			if source.ExternalID != "" {
				value = source.ExternalID
			}
			if _, exists := desired[key]; !exists {
				order = append(order, key)
			}
			desired[key] = desiredGrant{grantRow: grantRow{ConnectionID: u.ConnectionID, ProvisioningDomainID: domain,
				SCIMUserID: u.ID, UserID: userID, SourceKind: "group", SourceID: g.ID, SourceValue: &value,
				Role: role, GrantKey: key}, source: source}
		}
	}
	out := make([]desiredGrant, 0, len(order))
	for _, k := range order {
		out = append(out, desired[k])
	}
	return out, nil
}

func (p *projectionCoordinator) reconcileUserState(ctx context.Context, db adapter.Adapter, domain, userID string,
	sources []*scimUserRow, memberships []*memberRow, groupByID map[string]*groupRow, existing []*grantRow) error {
	var active []*scimUserRow
	for _, u := range sources {
		if u.Active {
			active = append(active, u)
		}
	}
	desired, err := p.buildDesiredGrants(ctx, db, domain, userID, active, memberships, groupByID)
	if err != nil {
		return err
	}
	if existing == nil {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelProjectionGrant, Where: []adapter.Where{
			w("provisioningDomainId", domain), w("userId", userID)}})
		if err != nil {
			return err
		}
		for _, r := range rows {
			existing = append(existing, toGrant(r))
		}
	}
	desiredKeys := map[string]bool{}
	for _, d := range desired {
		desiredKeys[d.GrantKey] = true
	}
	existingKeys := map[string]bool{}
	var removed []string
	for _, e := range existing {
		existingKeys[e.GrantKey] = true
		if !desiredKeys[e.GrantKey] {
			removed = append(removed, e.GrantKey)
		}
	}
	if len(removed) > 0 {
		if _, err := db.DeleteMany(ctx, modelProjectionGrant, []adapter.Where{w("provisioningDomainId", domain),
			w("userId", userID), wop("grantKey", adapter.In, strsToAny(removed))}); err != nil {
			return err
		}
	}
	now := time.Now()
	for _, d := range desired {
		if existingKeys[d.GrantKey] {
			continue
		}
		if _, err := db.Create(ctx, adapter.CreateInput{Model: modelProjectionGrant, Data: adapter.Record{
			"connectionId": d.ConnectionID, "provisioningDomainId": d.ProvisioningDomainID, "scimUserId": d.SCIMUserID,
			"userId": d.UserID, "sourceKind": d.SourceKind, "sourceId": d.SourceID, "sourceValue": optStrValue(d.SourceValue),
			"role": d.Role, "grantKey": d.GrantKey, "createdAt": now, "updatedAt": now}}); err != nil {
			return err
		}
	}
	if p.opts.Projection == nil || p.opts.Projection.ReconcileUser == nil {
		return nil
	}
	sorted := append([]desiredGrant{}, desired...)
	sort.SliceStable(sorted, func(i, j int) bool { return localeCompare(sorted[i].GrantKey, sorted[j].GrantKey) < 0 })
	grants := make([]ProjectedRoleGrant, len(sorted))
	for i, d := range sorted {
		grants[i] = ProjectedRoleGrant{Source: d.source, Role: d.Role}
	}
	srcs := make([]IdentitySource, 0, len(sources))
	for _, u := range sources {
		srcs = append(srcs, IdentitySource{ID: u.ID, ConnectionID: u.ConnectionID, ProvisioningDomainID: u.ProvisioningDomainID, Active: u.Active})
	}
	sortSources(srcs)
	return runApplicationCallback("SCIM projection reconciliation failed", func() error {
		return p.opts.Projection.ReconcileUser(ProjectedUserState{ProvisioningDomainID: domain, UserID: userID,
			Active: len(active) > 0, Sources: srcs, Grants: grants}, DatabaseContext{Context: ctx, Database: db})
	})
}

func (p *projectionCoordinator) reconcileBatch(ctx context.Context, db adapter.Adapter, domain string, scimUserIDs []string) error {
	if len(scimUserIDs) == 0 {
		return nil
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: []adapter.Where{
		wop("id", adapter.In, strsToAny(scimUserIDs)), w("provisioningDomainId", domain)}})
	if err != nil {
		return err
	}
	byID := map[string]*scimUserRow{}
	for _, u := range toSCIMUsers(rows) {
		byID[u.ID] = u
	}
	var userIDs []string
	seen := map[string]bool{}
	for _, id := range scimUserIDs {
		u := byID[id]
		if u == nil || u.UserID == "" || seen[u.UserID] {
			continue
		}
		seen[u.UserID] = true
		userIDs = append(userIDs, u.UserID)
	}
	if len(userIDs) == 0 {
		return nil
	}
	rows, err = db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: []adapter.Where{
		wop("userId", adapter.In, strsToAny(userIDs)), w("provisioningDomainId", domain)}})
	if err != nil {
		return err
	}
	domainUsers := toSCIMUsers(rows)
	var connIDs []string
	for _, u := range domainUsers {
		connIDs = append(connIDs, u.ConnectionID)
	}
	decommissioned, err := findDecommissionedConnectionIDs(ctx, db, uniqueStrings(connIDs))
	if err != nil {
		return err
	}
	var activeIDs []string
	for _, u := range domainUsers {
		if !decommissioned[u.ConnectionID] && u.Active {
			activeIDs = append(activeIDs, u.ID)
		}
	}
	var memberships []*memberRow
	if p.opts.Projection != nil && p.opts.Projection.Roles != nil && len(activeIDs) > 0 {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{wop("scimUserId", adapter.In, strsToAny(activeIDs))}})
		if err != nil {
			return err
		}
		memberships = toMembers(rows)
	}
	var gids []string
	for _, m := range memberships {
		gids = append(gids, m.GroupID)
	}
	gids = uniqueStrings(gids)
	groupByID := map[string]*groupRow{}
	if len(gids) > 0 {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroup, Where: []adapter.Where{wop("id", adapter.In, strsToAny(gids))}})
		if err != nil {
			return err
		}
		for _, r := range rows {
			g := toGroup(r)
			groupByID[g.ID] = g
		}
	}
	grows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelProjectionGrant, Where: []adapter.Where{
		w("provisioningDomainId", domain), wop("userId", adapter.In, strsToAny(userIDs))}})
	if err != nil {
		return err
	}
	usersByUserID := map[string][]*scimUserRow{}
	for _, u := range domainUsers {
		usersByUserID[u.UserID] = append(usersByUserID[u.UserID], u)
	}
	membershipsByUser := map[string][]*memberRow{}
	for _, m := range memberships {
		membershipsByUser[m.SCIMUserID] = append(membershipsByUser[m.SCIMUserID], m)
	}
	grantsByUser := map[string][]*grantRow{}
	for _, r := range grows {
		g := toGrant(r)
		grantsByUser[g.UserID] = append(grantsByUser[g.UserID], g)
	}
	for _, userID := range userIDs {
		var sources []*scimUserRow
		for _, u := range usersByUserID[userID] {
			if !decommissioned[u.ConnectionID] {
				sources = append(sources, u)
			}
		}
		userMemberships := []*memberRow{}
		for _, u := range sources {
			if u.Active {
				userMemberships = append(userMemberships, membershipsByUser[u.ID]...)
			}
		}
		existing := grantsByUser[userID]
		if existing == nil {
			existing = []*grantRow{}
		}
		if err := p.reconcileUserState(ctx, db, domain, userID, sources, userMemberships, groupByID, existing); err != nil {
			return err
		}
	}
	return nil
}

func (p *projectionCoordinator) acquireUserLocks(ctx context.Context, db adapter.Adapter, domain string, scimUserIDs []string) error {
	ids := uniqueStrings(scimUserIDs)
	if len(ids) == 0 {
		return nil
	}
	return acquireProjectionSubjectLocks(ctx, db, domain, ids)
}

// reconcileUser re-derives the projection of the Better Auth User linked to a SCIM User.
// userID/domain may be given for a deleted SCIM User.
func (p *projectionCoordinator) reconcileUser(ctx context.Context, db adapter.Adapter, domain, scimUserID, userID string) error {
	subjectUserID, subjectDomain := userID, domain
	if userID == "" {
		r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{w("id", scimUserID)}})
		if err != nil {
			return err
		}
		if r == nil {
			return nil
		}
		u := toSCIMUser(r)
		subjectUserID, subjectDomain = u.UserID, u.ProvisioningDomainID
	}
	if subjectDomain == "" {
		return nil
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: []adapter.Where{
		w("userId", subjectUserID), w("provisioningDomainId", subjectDomain)}})
	if err != nil {
		return err
	}
	users := toSCIMUsers(rows)
	var connIDs []string
	for _, u := range users {
		connIDs = append(connIDs, u.ConnectionID)
	}
	decommissioned, err := findDecommissionedConnectionIDs(ctx, db, uniqueStrings(connIDs))
	if err != nil {
		return err
	}
	var sources []*scimUserRow
	for _, u := range users {
		if !decommissioned[u.ConnectionID] {
			sources = append(sources, u)
		}
	}
	return p.reconcileUserState(ctx, db, subjectDomain, subjectUserID, sources, nil, nil, nil)
}

func (p *projectionCoordinator) reconcileUsers(ctx context.Context, db adapter.Adapter, domain string, scimUserIDs []string, locksAcquired bool) error {
	ids := uniqueStrings(scimUserIDs)
	if len(ids) == 0 {
		return nil
	}
	if !locksAcquired {
		if err := acquireProjectionSubjectLocks(ctx, db, domain, ids); err != nil {
			return err
		}
	}
	for _, c := range chunk(ids, projectionBatchSize) {
		if err := p.reconcileBatch(ctx, db, domain, c); err != nil {
			return err
		}
	}
	return nil
}

type projectionDomainBatch struct {
	scimUserIDs  []string
	userIDs      []string
	cursorUserID string
	hasMore      bool
}

func findProjectionDomainBatch(ctx context.Context, db adapter.Adapter, domain string, cursor *string) (*projectionDomainBatch, error) {
	where := []adapter.Where{w("provisioningDomainId", domain)}
	if cursor != nil && *cursor != "" {
		where = append(where, wop("userId", adapter.Gt, *cursor))
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: where, Limit: projectionBatchSize + 1,
		SortBy: &adapter.SortBy{Field: "userId", Direction: "asc"}})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	page := rows
	if len(page) > projectionBatchSize {
		page = page[:projectionBatchSize]
	}
	var order []string
	byUser := map[string]string{}
	for _, r := range page {
		uid := recStr(r, "userId")
		if _, ok := byUser[uid]; !ok {
			order = append(order, uid)
		}
		byUser[uid] = recStr(r, "id")
	}
	cursorUserID := recStr(page[len(page)-1], "userId")
	if cursorUserID == "" {
		return nil, nil
	}
	b := &projectionDomainBatch{userIDs: order, cursorUserID: cursorUserID, hasMore: len(rows) > projectionBatchSize}
	for _, uid := range order {
		b.scimUserIDs = append(b.scimUserIDs, byUser[uid])
	}
	return b, nil
}

func reconcileProjectionDomainBatch(ctx context.Context, auth *betterauth.AuthContext, db adapter.Adapter, projection *projectionCoordinator,
	identity *identityCoordinator, domain string, batch *projectionDomainBatch, locksAcquired bool) error {
	if err := projection.reconcileUsers(ctx, db, domain, batch.scimUserIDs, locksAcquired); err != nil {
		return err
	}
	if identity == nil {
		return nil
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelSubject, Where: []adapter.Where{wop("userId", adapter.In, strsToAny(batch.userIDs))}})
	if err != nil {
		return err
	}
	byUser := map[string]*subjectRow{}
	for _, r := range rows {
		s := toSubject(r)
		byUser[s.UserID] = s
	}
	for _, uid := range batch.userIDs {
		s := byUser[uid]
		if s == nil {
			continue
		}
		if _, err := identity.reconcileUser(ctx, auth, db, s); err != nil {
			return err
		}
	}
	return nil
}

func (p *plugin) reconcileProjectionEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "reconcileSCIMProjection", Methods: []string{"POST"}, ServerOnly: true,
		Body: zodValidator(zObj(zf("provisioningDomainId", zStr().trim().min(1).max(255)))),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if p.opts.Projection == nil {
				return nil, newBetterAuthError("SCIM projection reconciliation requires projection.reconcileUser to be configured.")
			}
			body, _ := ctx.Body.(*jsonx.Object)
			domain := getStr(body, "provisioningDomainId")
			reconciled, batches := 0, 0
			var cursor *string
			for {
				batch, err := findProjectionDomainBatch(ctx.Context(), ctx.Auth.Adapter, domain, cursor)
				if err != nil {
					return nil, err
				}
				if batch == nil {
					break
				}
				if err := runInTransaction(ctx.Context(), ctx.Auth, func(tx context.Context) error {
					return reconcileProjectionDomainBatch(tx, ctx.Auth, ctx.Auth.Adapter, p.projection, nil, domain, batch, false)
				}); err != nil {
					return nil, err
				}
				batches++
				reconciled += len(batch.userIDs)
				c := batch.cursorUserID
				cursor = &c
				if !batch.hasMore {
					break
				}
			}
			return jsonx.O("provisioningDomainId", domain, "reconciledUsers", reconciled, "batches", batches), nil
		},
	}
}
