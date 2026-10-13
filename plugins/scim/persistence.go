package scim

import (
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

// Model names (identical to upstream).
const (
	modelConnectionBinding  = "scimConnectionBinding"
	modelIdentityTombstone  = "scimIdentityTombstone"
	modelSubject            = "scimSubject"
	modelUser               = "scimUser"
	modelProjectionGrant    = "scimProjectionGrant"
	modelGroup              = "scimGroup"
	modelGroupMember        = "scimGroupMember"
	modelManagedConnection  = "scimManagedConnection"
	modelManagedCredential  = "scimManagedCredential"
	modelManagedEvent       = "scimManagedConnectionEvent"
	decommissionActive      = "active"
	decommissionReconciling = "reconciling"
	decommissionComplete    = "complete"
)

func recStr(r adapter.Record, k string) string {
	switch t := r[k].(type) {
	case string:
		return t
	case []byte:
		return string(t)
	}
	return ""
}

func recOptStr(r adapter.Record, k string) *string {
	switch t := r[k].(type) {
	case string:
		return &t
	case []byte:
		s := string(t)
		return &s
	}
	return nil
}

func recBool(r adapter.Record, k string) bool {
	switch t := r[k].(type) {
	case bool:
		return t
	case int64:
		return t == 1
	case float64:
		return t == 1
	case int:
		return t == 1
	}
	return false
}

func recInt(r adapter.Record, k string) int64 {
	if f, ok := adapter.ToFloat(r[k]); ok {
		return int64(f)
	}
	return 0
}

func recTime(r adapter.Record, k string) time.Time {
	if t, ok := adapter.ToTime(r[k]); ok {
		return t
	}
	return time.Time{}
}

func recOptTime(r adapter.Record, k string) *time.Time {
	if r[k] == nil {
		return nil
	}
	if t, ok := adapter.ToTime(r[k]); ok {
		return &t
	}
	return nil
}

func optStrValue(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func optTimeValue(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// connectionBinding is SCIMConnectionBinding.
type connectionBinding struct {
	ID                              string
	ConnectionID                    string
	ConnectionKey                   string
	ProvisioningDomainID            string
	CreatedAt                       time.Time
	DecommissionStatus              string
	DecommissionCursorUserID        *string
	DecommissionReconciledUserCount int64
	DecommissionBatchCount          int64
	DecommissionRevision            int64
	DecommissionedAt                *time.Time
	DecommissionCompletedAt         *time.Time
	DecommissionLeaseID             *string
	DecommissionLeaseExpiresAt      *time.Time
}

func toBinding(r adapter.Record) *connectionBinding {
	if r == nil {
		return nil
	}
	return &connectionBinding{
		ID: recStr(r, "id"), ConnectionID: recStr(r, "connectionId"), ConnectionKey: recStr(r, "connectionKey"),
		ProvisioningDomainID: recStr(r, "provisioningDomainId"), CreatedAt: recTime(r, "createdAt"),
		DecommissionStatus: recStr(r, "decommissionStatus"), DecommissionCursorUserID: recOptStr(r, "decommissionCursorUserId"),
		DecommissionReconciledUserCount: recInt(r, "decommissionReconciledUserCount"),
		DecommissionBatchCount:          recInt(r, "decommissionBatchCount"),
		DecommissionRevision:            recInt(r, "decommissionRevision"),
		DecommissionedAt:                recOptTime(r, "decommissionedAt"),
		DecommissionCompletedAt:         recOptTime(r, "decommissionCompletedAt"),
		DecommissionLeaseID:             recOptStr(r, "decommissionLeaseId"),
		DecommissionLeaseExpiresAt:      recOptTime(r, "decommissionLeaseExpiresAt"),
	}
}

// scimUserRow is SCIMUser.
type scimUserRow struct {
	ID                   string
	ConnectionID         string
	ProvisioningDomainID string
	UserID               string
	ConnectionUserKey    string
	UserName             string
	UserNameKey          string
	PrimaryEmail         string
	WorkEmailValueIndex  string
	EmailValueIndex      string
	DisplayName          string
	FormattedName        string
	GivenName            *string
	FamilyName           *string
	SerializedEmails     string
	SerializedAttributes *string
	ExternalID           *string
	ExternalIDKey        *string
	Active               bool
	OrderKey             string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func toSCIMUser(r adapter.Record) *scimUserRow {
	if r == nil {
		return nil
	}
	return &scimUserRow{
		ID: recStr(r, "id"), ConnectionID: recStr(r, "connectionId"), ProvisioningDomainID: recStr(r, "provisioningDomainId"),
		UserID: recStr(r, "userId"), ConnectionUserKey: recStr(r, "connectionUserKey"), UserName: recStr(r, "userName"),
		UserNameKey: recStr(r, "userNameKey"), PrimaryEmail: recStr(r, "primaryEmail"),
		WorkEmailValueIndex: recStr(r, "workEmailValueIndex"), EmailValueIndex: recStr(r, "emailValueIndex"),
		DisplayName: recStr(r, "displayName"), FormattedName: recStr(r, "formattedName"),
		GivenName: recOptStr(r, "givenName"), FamilyName: recOptStr(r, "familyName"),
		SerializedEmails: recStr(r, "serializedEmails"), SerializedAttributes: recOptStr(r, "serializedAttributes"),
		ExternalID: recOptStr(r, "externalId"), ExternalIDKey: recOptStr(r, "externalIdKey"),
		Active: recBool(r, "active"), OrderKey: recStr(r, "orderKey"),
		CreatedAt: recTime(r, "createdAt"), UpdatedAt: recTime(r, "updatedAt"),
	}
}

func toSCIMUsers(rs []adapter.Record) []*scimUserRow {
	out := make([]*scimUserRow, len(rs))
	for i, r := range rs {
		out[i] = toSCIMUser(r)
	}
	return out
}

// groupRow is SCIMGroup.
type groupRow struct {
	ID                   string
	ConnectionID         string
	ProvisioningDomainID string
	Revision             int64
	DisplayName          string
	DisplayNameKey       string
	ExternalID           *string
	ExternalIDKey        *string
	OrderKey             string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func toGroup(r adapter.Record) *groupRow {
	if r == nil {
		return nil
	}
	return &groupRow{
		ID: recStr(r, "id"), ConnectionID: recStr(r, "connectionId"), ProvisioningDomainID: recStr(r, "provisioningDomainId"),
		Revision: recInt(r, "revision"), DisplayName: recStr(r, "displayName"), DisplayNameKey: recStr(r, "displayNameKey"),
		ExternalID: recOptStr(r, "externalId"), ExternalIDKey: recOptStr(r, "externalIdKey"), OrderKey: recStr(r, "orderKey"),
		CreatedAt: recTime(r, "createdAt"), UpdatedAt: recTime(r, "updatedAt"),
	}
}

// subjectRow is SCIMSubject.
type subjectRow struct {
	ID              string
	UserID          string
	ProfileSourceID *string
	Revision        int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func toSubject(r adapter.Record) *subjectRow {
	if r == nil {
		return nil
	}
	return &subjectRow{ID: recStr(r, "id"), UserID: recStr(r, "userId"), ProfileSourceID: recOptStr(r, "profileSourceId"),
		Revision: recInt(r, "revision"), CreatedAt: recTime(r, "createdAt"), UpdatedAt: recTime(r, "updatedAt")}
}

func (s *subjectRow) profileSource() string {
	if s.ProfileSourceID == nil {
		return ""
	}
	return *s.ProfileSourceID
}

// tombstoneRow is SCIMIdentityTombstone.
type tombstoneRow struct {
	ID                   string
	ConnectionID         string
	ProvisioningDomainID string
	ExternalID           string
	ExternalIDKey        string
	UserID               string
	Profile              string
	DeletedAt            time.Time
}

func toTombstone(r adapter.Record) *tombstoneRow {
	if r == nil {
		return nil
	}
	return &tombstoneRow{ID: recStr(r, "id"), ConnectionID: recStr(r, "connectionId"),
		ProvisioningDomainID: recStr(r, "provisioningDomainId"), ExternalID: recStr(r, "externalId"),
		ExternalIDKey: recStr(r, "externalIdKey"), UserID: recStr(r, "userId"), Profile: recStr(r, "profile"),
		DeletedAt: recTime(r, "deletedAt")}
}

// memberRow is SCIMGroupMember.
type memberRow struct {
	ID            string
	ConnectionID  string
	GroupID       string
	SCIMUserID    string
	MembershipKey string
	CreatedAt     time.Time
}

func toMember(r adapter.Record) *memberRow {
	return &memberRow{ID: recStr(r, "id"), ConnectionID: recStr(r, "connectionId"), GroupID: recStr(r, "groupId"),
		SCIMUserID: recStr(r, "scimUserId"), MembershipKey: recStr(r, "membershipKey"), CreatedAt: recTime(r, "createdAt")}
}

func toMembers(rs []adapter.Record) []*memberRow {
	out := make([]*memberRow, len(rs))
	for i, r := range rs {
		out[i] = toMember(r)
	}
	return out
}

// grantRow is SCIMProjectionGrant.
type grantRow struct {
	ID                   string
	ConnectionID         string
	ProvisioningDomainID string
	SCIMUserID           string
	UserID               string
	SourceKind           string
	SourceID             string
	SourceValue          *string
	Role                 string
	GrantKey             string
}

func toGrant(r adapter.Record) *grantRow {
	return &grantRow{ID: recStr(r, "id"), ConnectionID: recStr(r, "connectionId"),
		ProvisioningDomainID: recStr(r, "provisioningDomainId"), SCIMUserID: recStr(r, "scimUserId"),
		UserID: recStr(r, "userId"), SourceKind: recStr(r, "sourceKind"), SourceID: recStr(r, "sourceId"),
		SourceValue: recOptStr(r, "sourceValue"), Role: recStr(r, "role"), GrantKey: recStr(r, "grantKey")}
}

func w(field string, value any) adapter.Where { return adapter.Where{Field: field, Value: value} }

func wop(field string, op adapter.Operator, value any) adapter.Where {
	return adapter.Where{Field: field, Value: value, Operator: op}
}

func strsToAny(s []string) []any {
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
