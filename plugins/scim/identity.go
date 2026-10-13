package scim

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// UserExternalIDReference is SCIMUserExternalIdReference.
type UserExternalIDReference struct {
	ConnectionID string
	ExternalID   string
}

// ActiveUserLink is SCIMActiveUserLink.
type ActiveUserLink struct {
	SCIMUserID string
	UserID     string
}

// LinkDatabase is the database capability used by AcquireActiveUserLink (findOne and
// incrementOne of a transaction adapter).
type LinkDatabase interface {
	FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error)
	IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error)
}

func concurrentIdentityMutation() error {
	return &identityConflict{scimErr("CONFLICT", "The SCIM identity changed concurrently; retry the request")}
}

// AcquireActiveUserLink is acquireActiveSCIMUserLink: it finds the active SCIM User with
// the external id and fences its subject so a concurrent deprovisioning conflicts. Call it
// inside a transaction (ctx carries the transaction).
func AcquireActiveUserLink(ctx context.Context, ref UserExternalIDReference, db LinkDatabase) (*ActiveUserLink, error) {
	key := CreateUserExternalIDKey(ref.ConnectionID, ref.ExternalID)
	src, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{
		w("connectionId", ref.ConnectionID), w("externalIdKey", key), w("externalId", ref.ExternalID), w("active", true)}})
	if err != nil || src == nil {
		return nil, err
	}
	source := toSCIMUser(src)
	br, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelConnectionBinding, Where: []adapter.Where{
		w("connectionKey", CreateConnectionKey(ref.ConnectionID)), w("connectionId", ref.ConnectionID),
		w("decommissionStatus", decommissionActive)}})
	if err != nil {
		return nil, err
	}
	binding := toBinding(br)
	if binding == nil || binding.ProvisioningDomainID != source.ProvisioningDomainID {
		return nil, nil
	}
	tombstoneWhere := []adapter.Where{w("connectionId", ref.ConnectionID), w("externalIdKey", key), w("externalId", ref.ExternalID)}
	tomb, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelIdentityTombstone, Where: tombstoneWhere})
	if err != nil || tomb != nil {
		return nil, err
	}
	sr, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelSubject, Where: []adapter.Where{w("userId", source.UserID)}})
	if err != nil || sr == nil {
		return nil, err
	}
	subject := toSubject(sr)
	ur, err := db.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{w("id", source.UserID)}})
	if err != nil || ur == nil {
		return nil, err
	}
	ar, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelSubject, Where: []adapter.Where{
		w("id", subject.ID), w("userId", source.UserID), w("revision", subject.Revision)},
		Increment: map[string]float64{"revision": 1}, Set: adapter.Record{"updatedAt": time.Now()}})
	if err != nil {
		return nil, err
	}
	if ar == nil {
		return nil, concurrentIdentityMutation()
	}
	acquiredSubject := toSubject(ar)
	asr, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{
		w("id", source.ID), w("connectionId", ref.ConnectionID), w("provisioningDomainId", binding.ProvisioningDomainID),
		w("userId", source.UserID), w("connectionUserKey", source.ConnectionUserKey), w("externalIdKey", key),
		w("externalId", ref.ExternalID), w("active", true)}})
	if err != nil {
		return nil, err
	}
	acquiredSource := toSCIMUser(asr)
	if acquiredSource == nil || !acquiredSource.Active || acquiredSource.UserID != acquiredSubject.UserID {
		return nil, concurrentIdentityMutation()
	}
	au, err := db.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{w("id", acquiredSource.UserID)}})
	if err != nil {
		return nil, err
	}
	if au == nil {
		return nil, concurrentIdentityMutation()
	}
	at, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelIdentityTombstone, Where: tombstoneWhere})
	if err != nil {
		return nil, err
	}
	if at != nil {
		return nil, concurrentIdentityMutation()
	}
	fr, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelConnectionBinding, Where: []adapter.Where{
		w("connectionKey", CreateConnectionKey(ref.ConnectionID)), w("connectionId", ref.ConnectionID),
		w("decommissionStatus", decommissionActive)}, Increment: map[string]float64{"decommissionRevision": 1}})
	if err != nil {
		return nil, err
	}
	fenced := toBinding(fr)
	if fenced == nil || fenced.ID != binding.ID || fenced.ProvisioningDomainID != acquiredSource.ProvisioningDomainID {
		return nil, concurrentIdentityMutation()
	}
	return &ActiveUserLink{SCIMUserID: source.ID, UserID: source.UserID}, nil
}

const transactionAttempts = 3

// runInTransaction is runWithTransaction(adapter, () => callback(getCurrentAdapter())).
func runInTransaction(ctx context.Context, auth *betterauth.AuthContext, fn func(tx context.Context) error) error {
	return auth.RunWithTransaction(ctx, fn)
}

// runIdentityMutationTransaction retries identity conflicts.
func runIdentityMutationTransaction(ctx context.Context, auth *betterauth.AuthContext, subjectCreationUserID string, fn func(tx context.Context) error) error {
	db := auth.Adapter
	observed := false
	if subjectCreationUserID != "" {
		r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelSubject, Where: []adapter.Where{w("userId", subjectCreationUserID)}})
		if err != nil {
			return err
		}
		observed = r != nil
	}
	for attempt := 1; attempt <= transactionAttempts; attempt++ {
		err := runInTransaction(ctx, auth, fn)
		if err == nil {
			return nil
		}
		if isIdentityConflict(err) {
			continue
		}
		if subjectCreationUserID == "" || observed {
			return err
		}
		r, ferr := db.FindOne(ctx, adapter.FindOneInput{Model: modelSubject, Where: []adapter.Where{w("userId", subjectCreationUserID)}})
		if ferr != nil || r == nil {
			return err
		}
		observed = true
	}
	return scimErr("CONFLICT", "The SCIM identity changed concurrently; retry the request")
}

type identityCoordinator struct{ opts *Options }

type resolvedIdentity struct {
	resolution  IdentityResolution
	tombstoneID string
}

func (c *identityCoordinator) resolveUser(ctx context.Context, db adapter.Adapter, input IdentityResolutionInput) (*resolvedIdentity, error) {
	if input.Resource.ExternalID != "" {
		key := CreateUserExternalIDKey(input.ConnectionID, input.Resource.ExternalID)
		tr, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelIdentityTombstone, Where: []adapter.Where{
			w("connectionId", input.ConnectionID), w("externalIdKey", key)}})
		if err != nil {
			return nil, err
		}
		if t := toTombstone(tr); t != nil {
			if t.ProvisioningDomainID != input.ProvisioningDomainID {
				return nil, scimErr("CONFLICT", "The connection provisioningDomainId changed after this User was deleted")
			}
			return &resolvedIdentity{resolution: IdentityResolution{Action: "link", UserID: t.UserID, Profile: t.Profile}, tombstoneID: t.ID}, nil
		}
	}
	var res *IdentityResolution
	if c.opts.Identity != nil && c.opts.Identity.ResolveUser != nil {
		err := runApplicationCallback("SCIM identity resolution failed", func() error {
			r, err := c.opts.Identity.ResolveUser(input, DatabaseContext{Context: ctx, Database: db})
			res = r
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	if res == nil {
		res = &IdentityResolution{Action: "create"}
	}
	return &resolvedIdentity{resolution: *res}, nil
}

func (c *identityCoordinator) consumeTombstone(ctx context.Context, db adapter.Adapter, id string) error {
	if id == "" {
		return nil
	}
	return db.Delete(ctx, modelIdentityTombstone, []adapter.Where{w("id", id)})
}

func (c *identityCoordinator) preserveDeletedSource(ctx context.Context, db adapter.Adapter, source *scimUserRow, subject *subjectRow, deletedAt time.Time) error {
	if source.ExternalID == nil || *source.ExternalID == "" || source.ExternalIDKey == nil || *source.ExternalIDKey == "" {
		return nil
	}
	profile := "preserve"
	if subject.profileSource() == source.ID {
		profile = "manage"
	}
	existing, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelIdentityTombstone, Where: []adapter.Where{w("externalIdKey", *source.ExternalIDKey)}})
	if err != nil {
		return err
	}
	if existing != nil {
		_, err := db.Update(ctx, modelIdentityTombstone, []adapter.Where{w("id", recStr(existing, "id"))},
			adapter.Record{"userId": source.UserID, "profile": profile, "deletedAt": deletedAt})
		return err
	}
	_, err = db.Create(ctx, adapter.CreateInput{Model: modelIdentityTombstone, Data: adapter.Record{
		"connectionId": source.ConnectionID, "provisioningDomainId": source.ProvisioningDomainID,
		"externalId": *source.ExternalID, "externalIdKey": *source.ExternalIDKey, "userId": source.UserID,
		"profile": profile, "deletedAt": deletedAt}})
	return err
}

func advanceSubjectRevision(ctx context.Context, db adapter.Adapter, s *subjectRow, now time.Time) (*subjectRow, error) {
	r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelSubject, Where: []adapter.Where{
		w("id", s.ID), w("revision", s.Revision)}, Increment: map[string]float64{"revision": 1}, Set: adapter.Record{"updatedAt": now}})
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, concurrentIdentityMutation()
	}
	return toSubject(r), nil
}

func clearProfileSource(ctx context.Context, db adapter.Adapter, s *subjectRow, scimUserID string, now time.Time) (*subjectRow, error) {
	if s.profileSource() != scimUserID {
		return s, nil
	}
	r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelSubject, Where: []adapter.Where{
		w("id", s.ID), w("revision", s.Revision), w("profileSourceId", scimUserID)},
		Increment: map[string]float64{"revision": 1}, Set: adapter.Record{"profileSourceId": nil, "updatedAt": now}})
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, concurrentIdentityMutation()
	}
	return toSubject(r), nil
}

func (c *identityCoordinator) acquireSubject(ctx context.Context, db adapter.Adapter, userID string, now time.Time) (*subjectRow, error) {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelSubject, Where: []adapter.Where{w("userId", userID)}})
	if err != nil {
		return nil, err
	}
	if r == nil {
		created, err := db.Create(ctx, adapter.CreateInput{Model: modelSubject, Data: adapter.Record{
			"userId": userID, "profileSourceId": nil, "revision": 1, "createdAt": now, "updatedAt": now}})
		if err != nil {
			return nil, err
		}
		return toSubject(created), nil
	}
	return advanceSubjectRevision(ctx, db, toSubject(r), now)
}

func (c *identityCoordinator) claimProfileSource(ctx context.Context, db adapter.Adapter, s *subjectRow, scimUserID string, now time.Time) (*subjectRow, error) {
	if s.profileSource() != "" && s.profileSource() != scimUserID {
		return nil, scimErr("CONFLICT", "Another SCIM source already manages this User profile", errUniqueness)
	}
	r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelSubject, Where: []adapter.Where{
		w("id", s.ID), w("revision", s.Revision), w("profileSourceId", nil)},
		Increment: map[string]float64{"revision": 1}, Set: adapter.Record{"profileSourceId": scimUserID, "updatedAt": now}})
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, concurrentIdentityMutation()
	}
	return toSubject(r), nil
}

func sortSources(sources []IdentitySource) {
	sort.SliceStable(sources, func(i, j int) bool { return localeCompare(sources[i].ID, sources[j].ID) < 0 })
}

// icuASCIIOrder is the CLDR root collation order of ASCII whitespace, punctuation and
// symbols (they sort before digits and letters).
const icuASCIIOrder = "\t\n\v\f\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789"

func primaryWeight(r rune) int {
	if r < 128 {
		if i := strings.IndexRune(icuASCIIOrder, r); i >= 0 {
			return i + 1
		}
		if r >= 'a' && r <= 'z' {
			return 1000 + int(r-'a')
		}
		if r >= 'A' && r <= 'Z' {
			return 1000 + int(r-'A')
		}
	}
	return 2000 + int(r)
}

// localeCompare approximates String.prototype.localeCompare (ICU root collation) for
// identifiers and keys: primary order punctuation < digits < letters (case-insensitive),
// then lowercase before uppercase.
func localeCompare(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		wa, wb := primaryWeight(ra[i]), primaryWeight(rb[i])
		if wa != wb {
			if wa < wb {
				return -1
			}
			return 1
		}
	}
	if len(ra) != len(rb) {
		if len(ra) < len(rb) {
			return -1
		}
		return 1
	}
	for i := range ra {
		if ra[i] != rb[i] {
			la := ra[i] >= 'a' && ra[i] <= 'z'
			if la {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (c *identityCoordinator) reconcileUser(ctx context.Context, auth *betterauth.AuthContext, db adapter.Adapter, subject *subjectRow) (*IdentityState, error) {
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelUser, Where: []adapter.Where{w("userId", subject.UserID)}})
	if err != nil {
		return nil, err
	}
	users := toSCIMUsers(rows)
	var connIDs []string
	for _, u := range users {
		connIDs = append(connIDs, u.ConnectionID)
	}
	decommissioned, err := findDecommissionedConnectionIDs(ctx, db, connIDs)
	if err != nil {
		return nil, err
	}
	var participating []*scimUserRow
	for _, u := range users {
		if !decommissioned[u.ConnectionID] {
			participating = append(participating, u)
		}
	}
	current := subject
	if ps := current.profileSource(); ps != "" {
		found := false
		for _, u := range participating {
			if u.ID == ps {
				found = true
			}
		}
		if !found {
			current, err = clearProfileSource(ctx, db, current, ps, time.Now())
			if err != nil {
				return nil, err
			}
		}
	}
	sources := make([]IdentitySource, 0, len(participating))
	active := false
	for _, u := range participating {
		sources = append(sources, IdentitySource{ID: u.ID, ConnectionID: u.ConnectionID, ProvisioningDomainID: u.ProvisioningDomainID, Active: u.Active})
		if u.Active {
			active = true
		}
	}
	sortSources(sources)
	state := IdentityState{UserID: subject.UserID, Active: active, ProfileSourceID: current.profileSource(),
		Sources: append([]IdentitySource{}, sources...)}
	if c.opts.Identity != nil && c.opts.Identity.ReconcileUser != nil {
		if err := runApplicationCallback("SCIM identity reconciliation failed", func() error {
			return c.opts.Identity.ReconcileUser(state, DatabaseContext{Context: ctx, Database: db})
		}); err != nil {
			return nil, err
		}
	}
	if !active {
		if err := auth.InternalAdapter.DeleteUserSessions(ctx, subject.UserID); err != nil {
			return nil, err
		}
	}
	return &IdentityState{UserID: subject.UserID, Active: active, ProfileSourceID: current.profileSource(), Sources: sources}, nil
}
