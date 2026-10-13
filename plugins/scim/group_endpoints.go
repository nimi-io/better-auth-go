package scim

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const userIDQueryChunkSize = 500

var groupMemberValuePath = regexp.MustCompile(`(?i)^members\s*\[\s*value\s+eq\s+("(?:\\.|[^"\\])*")\s*\]$`)

func groupNotFound() error { return scimErr("NOT_FOUND", "SCIM Group not found") }

func createGroupCollectionWhere(connectionID string, filters []equalityFilter) []adapter.Where {
	where := []adapter.Where{w("connectionId", connectionID)}
	for _, f := range filters {
		switch f.attribute {
		case "id":
			where = append(where, w("id", f.value))
		case "displayName":
			where = append(where, w("displayNameKey", createGroupDisplayNameKey(connectionID, f.value)))
		case "externalId":
			k := ""
			if p := createGroupExternalIDKey(connectionID, f.value); p != nil {
				k = *p
			}
			where = append(where, w("externalIdKey", k))
		}
	}
	return where
}

func assertGroupConnectionDomainStable(ctx context.Context, db adapter.Adapter, conn Connection) error {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelGroup, Where: []adapter.Where{
		w("connectionId", conn.ID), wop("provisioningDomainId", adapter.Ne, conn.ProvisioningDomainID)}})
	if err != nil {
		return err
	}
	if r != nil {
		return scimErr("CONFLICT", "The connection provisioningDomainId changed after resources were created")
	}
	return nil
}

func assertGroupExternalIDAvailable(ctx context.Context, db adapter.Adapter, connectionID string, key *string, exclude string) error {
	if key == nil {
		return nil
	}
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelGroup, Where: []adapter.Where{w("connectionId", connectionID), w("externalIdKey", *key)}})
	if err != nil {
		return err
	}
	if r != nil && recStr(r, "id") != exclude {
		return scimErr("CONFLICT", "SCIM Group externalId already exists", errUniqueness)
	}
	return nil
}

func assertGroupDisplayNameAvailable(ctx context.Context, db adapter.Adapter, connectionID, key, exclude string) error {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelGroup, Where: []adapter.Where{w("connectionId", connectionID), w("displayNameKey", key)}})
	if err != nil {
		return err
	}
	if r != nil && recStr(r, "id") != exclude {
		return scimErr("CONFLICT", "SCIM Group displayName already exists", errUniqueness)
	}
	return nil
}

type memberRef struct {
	value *string
	typ   *string
}

func invalidMemberReference() error {
	return scimErr("BAD_REQUEST", "Group members must reference a SCIM User", errInvalidValue)
}

func normalizeGroupMemberIDs(members []memberRef) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	for _, m := range members {
		if m.value == nil || jsTrim(*m.value) == "" || (m.typ != nil && jsLower(*m.typ) != "user") {
			return nil, invalidMemberReference()
		}
		if !seen[*m.value] {
			seen[*m.value] = true
			ids = append(ids, *m.value)
		}
	}
	return ids, nil
}

func assertGroupMemberCount(n int) error {
	if n <= MaxGroupMembers {
		return nil
	}
	return scimErr("BAD_REQUEST", "Groups cannot contain more than "+strconv.Itoa(MaxGroupMembers)+" direct members", errInvalidValue)
}

func readPatchMemberIDs(value any) ([]string, error) {
	arr, ok := value.([]any)
	if !ok {
		return nil, scimErr("BAD_REQUEST", "members must be an array", errInvalidValue)
	}
	if err := assertGroupMemberCount(len(arr)); err != nil {
		return nil, err
	}
	refs := make([]memberRef, 0, len(arr))
	for _, x := range arr {
		o, ok := x.(*jsonx.Object)
		if !ok {
			return nil, invalidMemberReference()
		}
		var r memberRef
		if s, ok := getOptStr(o, "value"); ok {
			r.value = &s
		}
		if s, ok := getOptStr(o, "type"); ok {
			r.typ = &s
		}
		refs = append(refs, r)
	}
	return normalizeGroupMemberIDs(refs)
}

func normalizeGroupPatchPath(path string) string {
	return stripCoreAttributePrefix(resourceGroup, jsTrim(path))
}

func readMemberIDFromValuePath(path string) string {
	m := groupMemberValuePath.FindStringSubmatch(normalizeGroupPatchPath(path))
	if m == nil || m[1] == "" {
		return ""
	}
	var id any
	if err := json.Unmarshal([]byte(m[1]), &id); err != nil {
		return ""
	}
	s, _ := id.(string)
	return s
}

type incrementalMembershipPatch struct {
	order    []string
	desired  map[string]bool
	validate []string
}

func parseIncrementalMembershipPatch(ops []patchOperation) (*incrementalMembershipPatch, error) {
	p := &incrementalMembershipPatch{desired: map[string]bool{}}
	validateSet := map[string]bool{}
	set := func(id string, desired bool) {
		if _, ok := p.desired[id]; !ok {
			p.order = append(p.order, id)
		}
		p.desired[id] = desired
	}
	for _, op := range ops {
		path := ""
		if op.Path != nil {
			path = jsTrim(*op.Path)
		}
		if path == "" {
			return nil, nil
		}
		if jsLower(normalizeGroupPatchPath(path)) == "members" {
			if op.Op == "replace" || isUndef(op.Value) {
				return nil, nil
			}
			ids, err := readPatchMemberIDs(op.Value)
			if err != nil {
				return nil, err
			}
			desired := op.Op == "add"
			for _, id := range ids {
				set(id, desired)
				if desired && !validateSet[id] {
					validateSet[id] = true
					p.validate = append(p.validate, id)
				}
			}
			continue
		}
		id := readMemberIDFromValuePath(path)
		if op.Op != "remove" || id == "" {
			return nil, nil
		}
		set(id, false)
	}
	return p, nil
}

func readPatchString(value any, attribute string) (string, error) {
	s, ok := unwrapSinglePatchValue(value).(string)
	if !ok || jsTrim(s) == "" {
		return "", scimErr("BAD_REQUEST", attribute+" must be a non-empty string", errInvalidValue)
	}
	return jsTrim(s), nil
}

type groupPatchResult struct {
	displayName string
	externalID  *string
	memberIDs   []string
}

type orderedSet struct {
	order []string
	has   map[string]bool
}

func newOrderedSet(items []string) *orderedSet {
	s := &orderedSet{has: map[string]bool{}}
	for _, i := range items {
		s.add(i)
	}
	return s
}
func (s *orderedSet) add(v string) {
	if !s.has[v] {
		s.has[v] = true
		s.order = append(s.order, v)
	}
}
func (s *orderedSet) remove(v string) {
	if !s.has[v] {
		return
	}
	delete(s.has, v)
	for i, x := range s.order {
		if x == v {
			s.order = append(s.order[:i:i], s.order[i+1:]...)
			break
		}
	}
}
func (s *orderedSet) clear() { s.order, s.has = nil, map[string]bool{} }

func applyGroupPatch(g *groupRow, current []string, ops []patchOperation) (*groupPatchResult, error) {
	members := newOrderedSet(current)
	displayName := g.DisplayName
	externalID := g.ExternalID
	applyAttribute := func(op, path string, value any) error {
		n := jsLower(normalizeGroupPatchPath(path))
		if n == "id" || n == "schemas" || n == "meta" || strings.HasPrefix(n, "meta.") {
			return scimErr("BAD_REQUEST", path+" is read-only", errMutability)
		}
		if n == "displayname" {
			if op == "remove" {
				return scimErr("BAD_REQUEST", "displayName is required and cannot be removed", errMutability)
			}
			v, err := readPatchString(value, "displayName")
			if err != nil {
				return err
			}
			displayName = v
			return nil
		}
		if n == "externalid" {
			if op == "remove" {
				externalID = nil
				return nil
			}
			v, err := readPatchString(value, "externalId")
			if err != nil {
				return err
			}
			externalID = &v
			return nil
		}
		return scimErr("BAD_REQUEST", "Unsupported Group PATCH path", errInvalidPath)
	}
	for _, op := range ops {
		path := ""
		if op.Path != nil {
			path = jsTrim(*op.Path)
		}
		if path == "" {
			if op.Op == "remove" {
				return nil, scimErr("BAD_REQUEST", "A pathless remove operation has no target", errNoTarget)
			}
			vo, ok := op.Value.(*jsonx.Object)
			if !ok {
				return nil, scimErr("BAD_REQUEST", "A pathless Group PATCH value must be an object", errInvalidValue)
			}
			for _, k := range vo.Keys() {
				v, _ := vo.Get(k)
				lk := jsLower(k)
				if lk == "id" {
					if s, ok := v.(string); !ok || s != g.ID {
						return nil, scimErr("BAD_REQUEST", "A Group PATCH cannot change id", errMutability)
					}
					continue
				}
				if lk == "schemas" || lk == "meta" {
					continue
				}
				if lk == "members" {
					ids, err := readPatchMemberIDs(v)
					if err != nil {
						return nil, err
					}
					if op.Op == "replace" {
						members.clear()
					}
					for _, id := range ids {
						members.add(id)
					}
					continue
				}
				if err := applyAttribute(op.Op, k, v); err != nil {
					return nil, err
				}
			}
			continue
		}
		if jsLower(normalizeGroupPatchPath(path)) == "members" {
			switch {
			case op.Op == "add":
				ids, err := readPatchMemberIDs(op.Value)
				if err != nil {
					return nil, err
				}
				for _, id := range ids {
					members.add(id)
				}
			case op.Op == "replace":
				members.clear()
				ids, err := readPatchMemberIDs(op.Value)
				if err != nil {
					return nil, err
				}
				for _, id := range ids {
					members.add(id)
				}
			case isUndef(op.Value):
				members.clear()
			default:
				ids, err := readPatchMemberIDs(op.Value)
				if err != nil {
					return nil, err
				}
				for _, id := range ids {
					members.remove(id)
				}
			}
			continue
		}
		if id := readMemberIDFromValuePath(path); op.Op == "remove" && id != "" {
			members.remove(id)
			continue
		}
		if err := applyAttribute(op.Op, path, op.Value); err != nil {
			return nil, err
		}
	}
	if err := assertGroupMemberCount(len(members.order)); err != nil {
		return nil, err
	}
	return &groupPatchResult{displayName: displayName, externalID: externalID, memberIDs: append([]string{}, members.order...)}, nil
}

func assertConnectionOwnsUsers(ctx context.Context, db adapter.Adapter, connectionID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: []adapter.Where{
		w("connectionId", connectionID), wop("id", adapter.In, strsToAny(ids))}})
	if err != nil {
		return err
	}
	if len(rows) != len(ids) {
		return scimErr("BAD_REQUEST", "One or more Group members are invalid", errInvalidValue)
	}
	return nil
}

func createMembership(ctx context.Context, db adapter.Adapter, connectionID, groupID, scimUserID string, createdAt time.Time) (*memberRow, error) {
	r, err := db.Create(ctx, adapter.CreateInput{Model: modelGroupMember, Data: adapter.Record{
		"connectionId": connectionID, "groupId": groupID, "scimUserId": scimUserID,
		"membershipKey": createGroupMembershipKey(connectionID, groupID, scimUserID), "createdAt": createdAt}})
	if err != nil {
		return nil, err
	}
	return toMember(r), nil
}

type membershipDelta struct {
	added, removed []*memberRow
}

func applyIncrementalMembershipPatch(ctx context.Context, db adapter.Adapter, connectionID, groupID string, patch *incrementalMembershipPatch, createdAt time.Time) (*membershipDelta, error) {
	if err := assertConnectionOwnsUsers(ctx, db, connectionID, patch.validate); err != nil {
		return nil, err
	}
	if len(patch.order) == 0 {
		return &membershipDelta{}, nil
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{
		w("connectionId", connectionID), w("groupId", groupID), wop("scimUserId", adapter.In, strsToAny(patch.order))}})
	if err != nil {
		return nil, err
	}
	existing := toMembers(rows)
	existingByUser := map[string]*memberRow{}
	for _, m := range existing {
		existingByUser[m.SCIMUserID] = m
	}
	delta := &membershipDelta{}
	for _, m := range existing {
		if d, ok := patch.desired[m.SCIMUserID]; ok && !d {
			delta.removed = append(delta.removed, m)
		}
	}
	var added []string
	for _, id := range patch.order {
		if patch.desired[id] && existingByUser[id] == nil {
			added = append(added, id)
		}
	}
	count, err := db.Count(ctx, modelGroupMember, []adapter.Where{w("connectionId", connectionID), w("groupId", groupID)})
	if err != nil {
		return nil, err
	}
	if err := assertGroupMemberCount(int(count) + len(added) - len(delta.removed)); err != nil {
		return nil, err
	}
	if len(delta.removed) > 0 {
		var ids []string
		for _, m := range delta.removed {
			ids = append(ids, m.SCIMUserID)
		}
		if _, err := db.DeleteMany(ctx, modelGroupMember, []adapter.Where{w("connectionId", connectionID), w("groupId", groupID),
			wop("scimUserId", adapter.In, strsToAny(ids))}); err != nil {
			return nil, err
		}
	}
	for _, id := range added {
		m, err := createMembership(ctx, db, connectionID, groupID, id, createdAt)
		if err != nil {
			return nil, err
		}
		delta.added = append(delta.added, m)
	}
	return delta, nil
}

func replaceGroupMemberships(ctx context.Context, db adapter.Adapter, connectionID, groupID string, ids []string, createdAt time.Time, existing []*memberRow) (*membershipDelta, error) {
	if err := assertConnectionOwnsUsers(ctx, db, connectionID, ids); err != nil {
		return nil, err
	}
	if existing == nil {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{
			w("connectionId", connectionID), w("groupId", groupID)}})
		if err != nil {
			return nil, err
		}
		existing = toMembers(rows)
	}
	existingIDs := map[string]bool{}
	for _, m := range existing {
		existingIDs[m.SCIMUserID] = true
	}
	requested := map[string]bool{}
	for _, id := range ids {
		requested[id] = true
	}
	delta := &membershipDelta{}
	for _, m := range existing {
		if !requested[m.SCIMUserID] {
			delta.removed = append(delta.removed, m)
		}
	}
	if len(delta.removed) > 0 {
		var rids []string
		for _, m := range delta.removed {
			rids = append(rids, m.SCIMUserID)
		}
		if _, err := db.DeleteMany(ctx, modelGroupMember, []adapter.Where{w("connectionId", connectionID), w("groupId", groupID),
			wop("scimUserId", adapter.In, strsToAny(rids))}); err != nil {
			return nil, err
		}
	}
	for _, id := range ids {
		if existingIDs[id] {
			continue
		}
		m, err := createMembership(ctx, db, connectionID, groupID, id, createdAt)
		if err != nil {
			return nil, err
		}
		delta.added = append(delta.added, m)
	}
	return delta, nil
}

func createGroupResourceBase(baseURL string, g *groupRow) *jsonx.Object {
	o := jsonx.O("schemas", []any{SchemaGroup}, "id", g.ID)
	if g.ExternalID != nil && *g.ExternalID != "" {
		o.Set("externalId", *g.ExternalID)
	}
	o.Set("displayName", g.DisplayName)
	o.Set("meta", jsonx.O("resourceType", "Group", "created", g.CreatedAt, "lastModified", g.UpdatedAt,
		"location", getResourceURL("/scim/v2/Groups/"+encodeURIComponent(g.ID), baseURL)))
	return o
}

func membershipLimitExceeded() error {
	return scimErr("INTERNAL_SERVER_ERROR", "Persisted SCIM Group membership exceeds the server limit")
}

func createGroupResourceFromMemberships(baseURL string, g *groupRow, memberships []*memberRow, users map[string]*scimUserRow) (*jsonx.Object, error) {
	if len(memberships) > MaxGroupMembers {
		return nil, membershipLimitExceeded()
	}
	members := []any{}
	for _, m := range memberships {
		u := users[m.SCIMUserID]
		if u == nil {
			continue
		}
		members = append(members, jsonx.O("value", u.ID,
			"$ref", getResourceURL("/scim/v2/Users/"+encodeURIComponent(u.ID), baseURL),
			"display", u.DisplayName, "type", "User"))
	}
	o := createGroupResourceBase(baseURL, g)
	o.Set("members", members)
	return o, nil
}

func findUsersForMemberships(ctx context.Context, db adapter.Adapter, connectionID string, memberships []*memberRow) (map[string]*scimUserRow, error) {
	var ids []string
	for _, m := range memberships {
		ids = append(ids, m.SCIMUserID)
	}
	ids = uniqueStrings(ids)
	out := map[string]*scimUserRow{}
	for _, c := range chunk(ids, userIDQueryChunkSize) {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: []adapter.Where{
			w("connectionId", connectionID), wop("id", adapter.In, strsToAny(c))}, Limit: len(c)})
		if err != nil {
			return nil, err
		}
		for _, u := range toSCIMUsers(rows) {
			out[u.ID] = u
		}
	}
	return out, nil
}

func createGroupResource(ctx context.Context, db adapter.Adapter, baseURL string, g *groupRow) (*jsonx.Object, error) {
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{
		w("connectionId", g.ConnectionID), w("groupId", g.ID)}, Limit: MaxGroupMembers + 1,
		SortBy: &adapter.SortBy{Field: "createdAt", Direction: "asc"}})
	if err != nil {
		return nil, err
	}
	if len(rows) > MaxGroupMembers {
		return nil, membershipLimitExceeded()
	}
	ms := toMembers(rows)
	users, err := findUsersForMemberships(ctx, db, g.ConnectionID, ms)
	if err != nil {
		return nil, err
	}
	return createGroupResourceFromMemberships(baseURL, g, ms, users)
}

func projectionRequestsMembers(p attributeProjection) bool {
	switch p.mode {
	case "exclude":
		return !p.attributes["members"]
	case "include":
		for _, a := range p.order {
			if a == "members" || strings.HasPrefix(a, "members.") {
				return true
			}
		}
		return false
	}
	return true
}

func createProjectedGroupResource(ctx context.Context, db adapter.Adapter, baseURL string, g *groupRow, p attributeProjection) (*jsonx.Object, error) {
	var res *jsonx.Object
	if projectionRequestsMembers(p) {
		r, err := createGroupResource(ctx, db, baseURL, g)
		if err != nil {
			return nil, err
		}
		res = r
	} else {
		res = createGroupResourceBase(baseURL, g)
		res.Set("members", []any{})
	}
	return projectResourceAttributes(res, p), nil
}

func createProjectedGroupResources(ctx context.Context, db adapter.Adapter, baseURL string, groups []*groupRow, p attributeProjection) ([]any, error) {
	out := []any{}
	if !projectionRequestsMembers(p) {
		for _, g := range groups {
			res := createGroupResourceBase(baseURL, g)
			res.Set("members", []any{})
			out = append(out, projectResourceAttributes(res, p))
		}
		return out, nil
	}
	if len(groups) == 0 {
		return out, nil
	}
	first := groups[0]
	maxRows := len(groups) * MaxGroupMembers
	var gids []string
	for _, g := range groups {
		gids = append(gids, g.ID)
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{
		w("connectionId", first.ConnectionID), wop("groupId", adapter.In, strsToAny(gids))}, Limit: maxRows + 1,
		SortBy: &adapter.SortBy{Field: "createdAt", Direction: "asc"}})
	if err != nil {
		return nil, err
	}
	if len(rows) > maxRows {
		return nil, membershipLimitExceeded()
	}
	ms := toMembers(rows)
	byGroup := map[string][]*memberRow{}
	for _, m := range ms {
		byGroup[m.GroupID] = append(byGroup[m.GroupID], m)
	}
	for _, l := range byGroup {
		if len(l) > MaxGroupMembers {
			return nil, membershipLimitExceeded()
		}
	}
	users, err := findUsersForMemberships(ctx, db, first.ConnectionID, ms)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		res, err := createGroupResourceFromMemberships(baseURL, g, byGroup[g.ID], users)
		if err != nil {
			return nil, err
		}
		out = append(out, projectResourceAttributes(res, p))
	}
	return out, nil
}

func (p *plugin) groupEndpoints() []*betterauth.Endpoint {
	return []*betterauth.Endpoint{
		p.scimEndpoint("createSCIMGroup", "/scim/v2/Groups", "POST", apiGroupSchema, true, p.createGroup),
		p.scimEndpoint("deleteSCIMGroup", "/scim/v2/Groups/:groupId", "DELETE", nil, false, p.deleteGroup),
		p.scimEndpoint("getSCIMGroup", "/scim/v2/Groups/:groupId", "GET", nil, true, p.getGroup),
		p.scimEndpoint("listSCIMGroups", "/scim/v2/Groups", "GET", nil, true, p.listGroups),
		p.scimEndpoint("patchSCIMGroup", "/scim/v2/Groups/:groupId", "PATCH", patchBodySchema, true, p.patchGroup),
		p.scimEndpoint("replaceSCIMGroup", "/scim/v2/Groups/:groupId", "PUT", apiGroupSchema, true, p.replaceGroup),
	}
}

func readGroupBody(body *jsonx.Object) (displayName string, externalID string, members []memberRef) {
	displayName = jsTrim(getStr(body, "displayName"))
	externalID = getStr(body, "externalId")
	for _, x := range getArr(body, "members") {
		o, ok := x.(*jsonx.Object)
		if !ok {
			continue
		}
		var r memberRef
		if s, ok := getOptStr(o, "value"); ok {
			r.value = &s
		}
		if s, ok := getOptStr(o, "type"); ok {
			r.typ = &s
		}
		members = append(members, r)
	}
	return
}

func (p *plugin) createGroup(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	conn := ConnectionFrom(ctx)
	projection, err := queryProjection(resourceGroup, ctx.Query)
	if err != nil {
		return nil, err
	}
	if err := assertGroupConnectionDomainStable(base, db, conn); err != nil {
		return nil, err
	}
	displayName, externalID, refs := readGroupBody(bodyObject(ctx, apiGroupSchema))
	if displayName == "" {
		return nil, scimErr("BAD_REQUEST", "displayName cannot be empty", errInvalidValue)
	}
	ids, err := normalizeGroupMemberIDs(refs)
	if err != nil {
		return nil, err
	}
	if err := assertGroupMemberCount(len(ids)); err != nil {
		return nil, err
	}
	externalIDKey := createGroupExternalIDKey(conn.ID, externalID)
	displayNameKey := createGroupDisplayNameKey(conn.ID, displayName)
	if err := assertGroupDisplayNameAvailable(base, db, conn.ID, displayNameKey, ""); err != nil {
		return nil, err
	}
	if err := assertGroupExternalIDAvailable(base, db, conn.ID, externalIDKey, ""); err != nil {
		return nil, err
	}
	var group *groupRow
	err = runCreateWithUniquenessCheck(func() error {
		return runGroupMutationTransaction(base, ctx.Auth, func(tx context.Context) error {
			if err := assertGroupDisplayNameAvailable(tx, db, conn.ID, displayNameKey, ""); err != nil {
				return err
			}
			if err := assertGroupExternalIDAvailable(tx, db, conn.ID, externalIDKey, ""); err != nil {
				return err
			}
			now := time.Now()
			data := adapter.Record{"connectionId": conn.ID, "provisioningDomainId": conn.ProvisioningDomainID, "revision": 0,
				"displayName": displayName, "displayNameKey": displayNameKey, "orderKey": createOrderKey(now),
				"createdAt": now, "updatedAt": now}
			if externalID != "" {
				data["externalId"] = externalID
			}
			if externalIDKey != nil {
				data["externalIdKey"] = *externalIDKey
			}
			r, err := db.Create(tx, adapter.CreateInput{Model: modelGroup, Data: data})
			if err != nil {
				return err
			}
			created := toGroup(r)
			if err := p.projection.acquireUserLocks(tx, db, conn.ProvisioningDomainID, ids); err != nil {
				return err
			}
			if _, err := replaceGroupMemberships(tx, db, conn.ID, created.ID, ids, now, nil); err != nil {
				return err
			}
			if err := p.projection.reconcileUsers(tx, db, conn.ProvisioningDomainID, ids, true); err != nil {
				return err
			}
			if _, err := fenceActiveConnection(tx, db, conn.ID); err != nil {
				return err
			}
			group = created
			return nil
		})
	}, func() error {
		if err := assertGroupDisplayNameAvailable(base, db, conn.ID, displayNameKey, ""); err != nil {
			return err
		}
		return assertGroupExternalIDAvailable(base, db, conn.ID, externalIDKey, "")
	})
	if err != nil {
		return nil, err
	}
	complete := createGroupResourceBase(ctx.BaseURL(), group)
	res, err := createProjectedGroupResource(base, db, ctx.BaseURL(), group, projection)
	if err != nil {
		return nil, err
	}
	ctx.SetStatus(201)
	ctx.SetHeader("Location", resourceLocation(complete))
	ctx.SetHeader("Content-Location", resourceLocation(complete))
	return res, nil
}

func (p *plugin) getGroup(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	g, err := findGroup(ctx.Context(), db, ConnectionFrom(ctx), ctx.Params["groupId"])
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, groupNotFound()
	}
	projection, err := queryProjection(resourceGroup, ctx.Query)
	if err != nil {
		return nil, err
	}
	return createProjectedGroupResource(ctx.Context(), db, ctx.BaseURL(), g, projection)
}

func (p *plugin) listGroups(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	conn := ConnectionFrom(ctx)
	if err := assertGroupConnectionDomainStable(ctx.Context(), db, conn); err != nil {
		return nil, err
	}
	q, qerr := parseCollectionQuery(resourceGroup, queryInputFrom(ctx.Query))
	if qerr != nil {
		return nil, scimErr("BAD_REQUEST", qerr.detail, qerr.scimType)
	}
	where := createGroupCollectionWhere(conn.ID, q.filters)
	total, err := db.Count(ctx.Context(), modelGroup, where)
	if err != nil {
		return nil, err
	}
	var groups []*groupRow
	if q.pagination.count > 0 {
		rows, err := db.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelGroup, Where: where, Limit: q.pagination.count,
			Offset: q.pagination.offset, SortBy: &adapter.SortBy{Field: "orderKey", Direction: "asc"}})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			groups = append(groups, toGroup(r))
		}
	}
	resources, err := createProjectedGroupResources(ctx.Context(), db, ctx.BaseURL(), groups, q.projection)
	if err != nil {
		return nil, err
	}
	return jsonx.O("schemas", []any{SchemaListResponse}, "totalResults", total, "startIndex", q.pagination.startIndex,
		"itemsPerPage", len(resources), "Resources", resources), nil
}

func (p *plugin) replaceGroup(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	conn := ConnectionFrom(ctx)
	projection, err := queryProjection(resourceGroup, ctx.Query)
	if err != nil {
		return nil, err
	}
	g, err := findGroup(base, db, conn, ctx.Params["groupId"])
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, groupNotFound()
	}
	displayName, externalID, refs := readGroupBody(bodyObject(ctx, apiGroupSchema))
	if displayName == "" {
		return nil, scimErr("BAD_REQUEST", "displayName cannot be empty", errInvalidValue)
	}
	ids, err := normalizeGroupMemberIDs(refs)
	if err != nil {
		return nil, err
	}
	if err := assertGroupMemberCount(len(ids)); err != nil {
		return nil, err
	}
	externalIDKey := createGroupExternalIDKey(conn.ID, externalID)
	displayNameKey := createGroupDisplayNameKey(conn.ID, displayName)
	if err := assertGroupDisplayNameAvailable(base, db, conn.ID, displayNameKey, g.ID); err != nil {
		return nil, err
	}
	if err := assertGroupExternalIDAvailable(base, db, conn.ID, externalIDKey, g.ID); err != nil {
		return nil, err
	}
	var updated *groupRow
	err = runGroupMutationTransaction(base, ctx.Auth, func(tx context.Context) error {
		current, err := acquireGroupMutationLock(tx, db, conn, g.ID, false)
		if err != nil {
			return err
		}
		now := time.Now()
		if err := assertGroupDisplayNameAvailable(tx, db, conn.ID, displayNameKey, current.ID); err != nil {
			return err
		}
		if err := assertGroupExternalIDAvailable(tx, db, conn.ID, externalIDKey, current.ID); err != nil {
			return err
		}
		rows, err := db.FindMany(tx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{
			w("connectionId", conn.ID), w("groupId", current.ID)}})
		if err != nil {
			return err
		}
		currentMembers := toMembers(rows)
		lockIDs := append([]string{}, ids...)
		for _, m := range currentMembers {
			lockIDs = append(lockIDs, m.SCIMUserID)
		}
		if err := p.projection.acquireUserLocks(tx, db, conn.ProvisioningDomainID, uniqueStrings(lockIDs)); err != nil {
			return err
		}
		delta, err := replaceGroupMemberships(tx, db, conn.ID, current.ID, ids, now, currentMembers)
		if err != nil {
			return err
		}
		r, err := db.Update(tx, modelGroup, []adapter.Where{w("id", current.ID), w("connectionId", conn.ID)}, adapter.Record{
			"displayName": displayName, "displayNameKey": displayNameKey, "externalId": nilIfEmpty(externalID),
			"externalIdKey": optValue(externalIDKey), "updatedAt": now})
		if err != nil {
			return err
		}
		if r == nil {
			return groupNotFound()
		}
		updated = toGroup(r)
		affected := append([]string{}, ids...)
		for _, m := range delta.removed {
			affected = append(affected, m.SCIMUserID)
		}
		if err := p.projection.reconcileUsers(tx, db, conn.ProvisioningDomainID, uniqueStrings(affected), true); err != nil {
			return err
		}
		_, err = fenceActiveConnection(tx, db, conn.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	complete := createGroupResourceBase(ctx.BaseURL(), updated)
	res, err := createProjectedGroupResource(base, db, ctx.BaseURL(), updated, projection)
	if err != nil {
		return nil, err
	}
	ctx.SetHeader("Location", resourceLocation(complete))
	return res, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (p *plugin) patchGroup(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	conn := ConnectionFrom(ctx)
	projection, err := queryProjection(resourceGroup, ctx.Query)
	if err != nil {
		return nil, err
	}
	g, err := findGroup(base, db, conn, ctx.Params["groupId"])
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, groupNotFound()
	}
	ops := readPatchOperations(bodyObject(ctx, patchBodySchema))
	incremental, err := parseIncrementalMembershipPatch(ops)
	if err != nil {
		return nil, err
	}
	var result *groupRow
	err = runGroupMutationTransaction(base, ctx.Auth, func(tx context.Context) error {
		current, err := acquireGroupMutationLock(tx, db, conn, g.ID, false)
		if err != nil {
			return err
		}
		now := time.Now()
		var affected []string
		changed := false
		update := adapter.Record{"updatedAt": now}
		if incremental != nil {
			if err := p.projection.acquireUserLocks(tx, db, conn.ProvisioningDomainID, incremental.order); err != nil {
				return err
			}
			delta, err := applyIncrementalMembershipPatch(tx, db, conn.ID, current.ID, incremental, now)
			if err != nil {
				return err
			}
			for _, m := range delta.added {
				affected = append(affected, m.SCIMUserID)
			}
			for _, m := range delta.removed {
				affected = append(affected, m.SCIMUserID)
			}
			affected = uniqueStrings(affected)
			changed = len(affected) > 0
		} else {
			rows, err := db.FindMany(tx, adapter.FindManyInput{Model: modelGroupMember, Where: []adapter.Where{
				w("connectionId", conn.ID), w("groupId", current.ID)}})
			if err != nil {
				return err
			}
			currentMembers := toMembers(rows)
			var currentIDs []string
			for _, m := range currentMembers {
				currentIDs = append(currentIDs, m.SCIMUserID)
			}
			patch, err := applyGroupPatch(current, currentIDs, ops)
			if err != nil {
				return err
			}
			if err := p.projection.acquireUserLocks(tx, db, conn.ProvisioningDomainID,
				uniqueStrings(append(append([]string{}, patch.memberIDs...), currentIDs...))); err != nil {
				return err
			}
			ext := ""
			if patch.externalID != nil {
				ext = *patch.externalID
			}
			externalIDKey := createGroupExternalIDKey(conn.ID, ext)
			displayNameKey := createGroupDisplayNameKey(conn.ID, patch.displayName)
			if err := assertGroupDisplayNameAvailable(tx, db, conn.ID, displayNameKey, current.ID); err != nil {
				return err
			}
			if err := assertGroupExternalIDAvailable(tx, db, conn.ID, externalIDKey, current.ID); err != nil {
				return err
			}
			delta, err := replaceGroupMemberships(tx, db, conn.ID, current.ID, patch.memberIDs, now, currentMembers)
			if err != nil {
				return err
			}
			currentExt := ""
			if current.ExternalID != nil {
				currentExt = *current.ExternalID
			}
			metadataChanged := patch.displayName != current.DisplayName || ext != currentExt
			if metadataChanged {
				affected = append(affected, patch.memberIDs...)
			}
			for _, m := range delta.added {
				affected = append(affected, m.SCIMUserID)
			}
			for _, m := range delta.removed {
				affected = append(affected, m.SCIMUserID)
			}
			affected = uniqueStrings(affected)
			changed = metadataChanged || len(affected) > 0
			update = adapter.Record{"displayName": patch.displayName, "displayNameKey": displayNameKey,
				"externalId": nilIfEmpty(ext), "externalIdKey": optValue(externalIDKey), "updatedAt": now}
		}
		result = current
		if changed {
			r, err := db.Update(tx, modelGroup, []adapter.Where{w("id", current.ID), w("connectionId", conn.ID)}, update)
			if err != nil {
				return err
			}
			if r == nil {
				return groupNotFound()
			}
			if err := p.projection.reconcileUsers(tx, db, conn.ProvisioningDomainID, affected, true); err != nil {
				return err
			}
			result = toGroup(r)
		}
		_, err = fenceActiveConnection(tx, db, conn.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	complete := createGroupResourceBase(ctx.BaseURL(), result)
	ctx.SetHeader("Location", resourceLocation(complete))
	return createProjectedGroupResource(base, db, ctx.BaseURL(), result, projection)
}

func (p *plugin) deleteGroup(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	conn := ConnectionFrom(ctx)
	g, err := findGroup(base, db, conn, ctx.Params["groupId"])
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, groupNotFound()
	}
	err = runGroupMutationTransaction(base, ctx.Auth, func(tx context.Context) error {
		current, err := acquireGroupMutationLock(tx, db, conn, g.ID, false)
		if err != nil {
			return err
		}
		where := []adapter.Where{w("connectionId", conn.ID), w("groupId", current.ID)}
		rows, err := db.FindMany(tx, adapter.FindManyInput{Model: modelGroupMember, Where: where})
		if err != nil {
			return err
		}
		var ids []string
		for _, m := range toMembers(rows) {
			ids = append(ids, m.SCIMUserID)
		}
		if err := p.projection.acquireUserLocks(tx, db, conn.ProvisioningDomainID, ids); err != nil {
			return err
		}
		if _, err := db.DeleteMany(tx, modelGroupMember, where); err != nil {
			return err
		}
		if err := db.Delete(tx, modelGroup, []adapter.Where{w("id", current.ID), w("connectionId", conn.ID)}); err != nil {
			return err
		}
		if err := p.projection.reconcileUsers(tx, db, conn.ProvisioningDomainID, ids, true); err != nil {
			return err
		}
		_, err = fenceActiveConnection(tx, db, conn.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	ctx.SetStatus(204)
	return betterauth.NoContent, nil
}
