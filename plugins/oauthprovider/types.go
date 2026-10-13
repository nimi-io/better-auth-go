package oauthprovider

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// SchemaClient is an oauthClient row (SchemaClient upstream). Empty strings / nil slices /
// nil pointers mean the column is unset (null).
type SchemaClient struct {
	// ID is the row id (not part of the upstream type, present on stored rows).
	ID                               string
	ClientID                         string
	ClientSecret                     string
	ClientDiscoveryID                string
	Disabled                         *bool
	Scopes                           []string
	ClientCredentialsScopes          []string
	UserID                           string
	CreatedAt                        *time.Time
	UpdatedAt                        *time.Time
	ExpiresAt                        *time.Time
	Name                             string
	URI                              string
	Icon                             string
	Contacts                         []string
	Tos                              string
	Policy                           string
	SoftwareID                       string
	SoftwareVersion                  string
	SoftwareStatement                string
	RedirectURIs                     []string
	PostLogoutRedirectURIs           []string
	BackchannelLogoutURI             string
	BackchannelLogoutSessionRequired *bool
	TokenEndpointAuthMethod          string
	GrantTypes                       []string
	ResponseTypes                    []string
	ApplicationType                  string
	Jwks                             string
	JwksURI                          string
	RequirePKCE                      *bool
	DPoPBoundAccessTokens            *bool
	SkipConsent                      *bool
	EnableEndSession                 *bool
	SubjectType                      string
	ReferenceID                      string
	// Metadata is the JSON metadata column (a JSON string or a decoded object).
	Metadata any
	// Extra holds columns not listed above (additional fields).
	Extra map[string]any
}

func isTrue(b *bool) bool { return b != nil && *b }

func boolPtr(b bool) *bool { return &b }

// IsDisabled reports client.disabled.
func (c *SchemaClient) IsDisabled() bool { return isTrue(c.Disabled) }

// Clone returns a shallow copy (Object.assign({}, client)).
func (c *SchemaClient) Clone() *SchemaClient {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

func recStr(r adapter.Record, k string) string {
	v, ok := r[k]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return adapter.ToString(v)
}

func recBool(r adapter.Record, k string) *bool {
	v, ok := r[k]
	if !ok || v == nil {
		return nil
	}
	b := adapter.ToBool(v)
	return &b
}

func recTime(r adapter.Record, k string) *time.Time {
	v, ok := r[k]
	if !ok || v == nil {
		return nil
	}
	t, ok := adapter.ToTime(v)
	if !ok {
		return nil
	}
	return &t
}

// recStrings returns a string[] column: nil when null/absent, non-nil (possibly empty)
// otherwise.
func recStrings(r adapter.Record, k string) []string {
	v, ok := r[k]
	if !ok || v == nil {
		return nil
	}
	return toStrings(v)
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return append([]string{}, t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			} else if x != nil {
				out = append(out, adapter.ToString(x))
			}
		}
		return out
	case string:
		var arr []string
		if err := json.Unmarshal([]byte(t), &arr); err == nil {
			if arr == nil {
				arr = []string{}
			}
			return arr
		}
	}
	return nil
}

var clientColumns = map[string]bool{"id": true, "clientId": true, "clientSecret": true, "clientDiscoveryId": true,
	"disabled": true, "scopes": true, "clientCredentialsScopes": true, "userId": true, "createdAt": true,
	"updatedAt": true, "expiresAt": true, "name": true, "uri": true, "icon": true, "contacts": true, "tos": true,
	"policy": true, "softwareId": true, "softwareVersion": true, "softwareStatement": true, "redirectUris": true,
	"postLogoutRedirectUris": true, "backchannelLogoutUri": true, "backchannelLogoutSessionRequired": true,
	"tokenEndpointAuthMethod": true, "grantTypes": true, "responseTypes": true, "applicationType": true,
	"jwks": true, "jwksUri": true, "requirePKCE": true, "dpopBoundAccessTokens": true, "skipConsent": true,
	"enableEndSession": true, "subjectType": true, "referenceId": true, "metadata": true}

// ClientFromRecord converts an adapter row into a SchemaClient (nil for nil).
func ClientFromRecord(r adapter.Record) *SchemaClient {
	if r == nil {
		return nil
	}
	c := &SchemaClient{
		ID: recStr(r, "id"), ClientID: recStr(r, "clientId"), ClientSecret: recStr(r, "clientSecret"),
		ClientDiscoveryID: recStr(r, "clientDiscoveryId"), Disabled: recBool(r, "disabled"),
		Scopes: recStrings(r, "scopes"), ClientCredentialsScopes: recStrings(r, "clientCredentialsScopes"),
		UserID: recStr(r, "userId"), CreatedAt: recTime(r, "createdAt"), UpdatedAt: recTime(r, "updatedAt"),
		ExpiresAt: recTime(r, "expiresAt"), Name: recStr(r, "name"), URI: recStr(r, "uri"), Icon: recStr(r, "icon"),
		Contacts: recStrings(r, "contacts"), Tos: recStr(r, "tos"), Policy: recStr(r, "policy"),
		SoftwareID: recStr(r, "softwareId"), SoftwareVersion: recStr(r, "softwareVersion"),
		SoftwareStatement: recStr(r, "softwareStatement"), RedirectURIs: recStrings(r, "redirectUris"),
		PostLogoutRedirectURIs: recStrings(r, "postLogoutRedirectUris"), BackchannelLogoutURI: recStr(r, "backchannelLogoutUri"),
		BackchannelLogoutSessionRequired: recBool(r, "backchannelLogoutSessionRequired"),
		TokenEndpointAuthMethod:          recStr(r, "tokenEndpointAuthMethod"), GrantTypes: recStrings(r, "grantTypes"),
		ResponseTypes: recStrings(r, "responseTypes"), ApplicationType: recStr(r, "applicationType"),
		Jwks: recStr(r, "jwks"), JwksURI: recStr(r, "jwksUri"), RequirePKCE: recBool(r, "requirePKCE"),
		DPoPBoundAccessTokens: recBool(r, "dpopBoundAccessTokens"), SkipConsent: recBool(r, "skipConsent"),
		EnableEndSession: recBool(r, "enableEndSession"), SubjectType: recStr(r, "subjectType"),
		ReferenceID: recStr(r, "referenceId"),
	}
	if v, ok := r["metadata"]; ok && v != nil {
		c.Metadata = v
	}
	for k, v := range r {
		if !clientColumns[k] {
			if c.Extra == nil {
				c.Extra = map[string]any{}
			}
			c.Extra[k] = v
		}
	}
	return c
}

func setStr(r adapter.Record, k, v string) {
	if v != "" {
		r[k] = v
	}
}

func setBool(r adapter.Record, k string, v *bool) {
	if v != nil {
		r[k] = *v
	}
}

func setTime(r adapter.Record, k string, v *time.Time) {
	if v != nil {
		r[k] = *v
	}
}

func setStrings(r adapter.Record, k string, v []string) {
	if v != nil {
		r[k] = stringsToAny(v)
	}
}

func stringsToAny(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// ToRecord converts the client into an adapter row with only the set columns.
func (c *SchemaClient) ToRecord() adapter.Record {
	r := adapter.Record{}
	setStr(r, "clientId", c.ClientID)
	setStr(r, "clientSecret", c.ClientSecret)
	setStr(r, "clientDiscoveryId", c.ClientDiscoveryID)
	setBool(r, "disabled", c.Disabled)
	setStrings(r, "scopes", c.Scopes)
	setStrings(r, "clientCredentialsScopes", c.ClientCredentialsScopes)
	setStr(r, "userId", c.UserID)
	setTime(r, "createdAt", c.CreatedAt)
	setTime(r, "updatedAt", c.UpdatedAt)
	setTime(r, "expiresAt", c.ExpiresAt)
	setStr(r, "name", c.Name)
	setStr(r, "uri", c.URI)
	setStr(r, "icon", c.Icon)
	setStrings(r, "contacts", c.Contacts)
	setStr(r, "tos", c.Tos)
	setStr(r, "policy", c.Policy)
	setStr(r, "softwareId", c.SoftwareID)
	setStr(r, "softwareVersion", c.SoftwareVersion)
	setStr(r, "softwareStatement", c.SoftwareStatement)
	setStrings(r, "redirectUris", c.RedirectURIs)
	setStrings(r, "postLogoutRedirectUris", c.PostLogoutRedirectURIs)
	setStr(r, "backchannelLogoutUri", c.BackchannelLogoutURI)
	setBool(r, "backchannelLogoutSessionRequired", c.BackchannelLogoutSessionRequired)
	setStr(r, "tokenEndpointAuthMethod", c.TokenEndpointAuthMethod)
	setStrings(r, "grantTypes", c.GrantTypes)
	setStrings(r, "responseTypes", c.ResponseTypes)
	setStr(r, "applicationType", c.ApplicationType)
	setStr(r, "jwks", c.Jwks)
	setStr(r, "jwksUri", c.JwksURI)
	setBool(r, "requirePKCE", c.RequirePKCE)
	setBool(r, "dpopBoundAccessTokens", c.DPoPBoundAccessTokens)
	setBool(r, "skipConsent", c.SkipConsent)
	setBool(r, "enableEndSession", c.EnableEndSession)
	setStr(r, "subjectType", c.SubjectType)
	setStr(r, "referenceId", c.ReferenceID)
	if c.Metadata != nil {
		r["metadata"] = c.Metadata
	}
	for k, v := range c.Extra {
		r[k] = v
	}
	return r
}

// toObject converts any decoded JSON value (map, *jsonx.Object or JSON string) into an
// ordered object. Plain maps are ordered by key (Go maps carry no insertion order).
func toObject(v any) *jsonx.Object {
	switch t := v.(type) {
	case nil:
		return nil
	case *jsonx.Object:
		return t
	case map[string]any:
		o := jsonx.NewObject()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			o.Set(k, normalizeJSON(t[k]))
		}
		return o
	case string:
		pv, err := jsonx.Parse([]byte(t))
		if err != nil {
			return nil
		}
		o, _ := pv.(*jsonx.Object)
		return o
	}
	return nil
}

// normalizeJSON converts nested Go maps into ordered objects.
func normalizeJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return toObject(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalizeJSON(x)
		}
		return out
	}
	return v
}

// ParseClientMetadata is parseClientMetadata: the client's metadata as an object (nil when
// unset). Invalid JSON strings yield an error like JSON.parse.
func ParseClientMetadata(metadata any) (*jsonx.Object, error) {
	switch t := metadata.(type) {
	case nil:
		return nil, nil
	case string:
		if t == "" {
			return nil, nil
		}
		pv, err := jsonx.Parse([]byte(t))
		if err != nil {
			return nil, err
		}
		o, _ := pv.(*jsonx.Object)
		return o, nil
	}
	return toObject(metadata), nil
}

// VerificationValue is the stored authorization code payload (VerificationValue).
type VerificationValue struct {
	Type        string
	Query       *jsonx.Object
	SessionID   string
	UserID      string
	ReferenceID string
	AuthTime    *float64
	Resource    []string
	// Raw is the parsed JSON value.
	Raw *jsonx.Object
}

// QueryString returns a string query parameter of the stored authorization request.
func (v *VerificationValue) QueryString(key string) string {
	if v == nil || v.Query == nil {
		return ""
	}
	x, _ := v.Query.Get(key)
	s, _ := x.(string)
	return s
}

// TokenRecord is an oauthAccessToken / oauthRefreshToken row.
type TokenRecord struct {
	ID                      string
	Token                   string
	ClientID                string
	SessionID               string
	UserID                  string
	ReferenceID             string
	AuthorizationCodeID     string
	RefreshID               string
	ExpiresAt               *time.Time
	CreatedAt               *time.Time
	Revoked                 *time.Time
	RotatedAt               *time.Time
	RotationReplayResponse  string
	RotationReplayExpiresAt *time.Time
	AuthTime                *time.Time
	Scopes                  []string
	Resources               []string
	RequestedUserInfoClaims []string
	Confirmation            *jsonx.Object
}

func tokenRecordFrom(r adapter.Record) *TokenRecord {
	if r == nil {
		return nil
	}
	t := &TokenRecord{
		ID: recStr(r, "id"), Token: recStr(r, "token"), ClientID: recStr(r, "clientId"), SessionID: recStr(r, "sessionId"),
		UserID: recStr(r, "userId"), ReferenceID: recStr(r, "referenceId"), AuthorizationCodeID: recStr(r, "authorizationCodeId"),
		RefreshID: recStr(r, "refreshId"), ExpiresAt: recTime(r, "expiresAt"), CreatedAt: recTime(r, "createdAt"),
		Revoked: recTime(r, "revoked"), RotatedAt: recTime(r, "rotatedAt"), RotationReplayResponse: recStr(r, "rotationReplayResponse"),
		RotationReplayExpiresAt: recTime(r, "rotationReplayExpiresAt"), AuthTime: recTime(r, "authTime"),
		Scopes: recStrings(r, "scopes"), Resources: recStrings(r, "resources"),
		RequestedUserInfoClaims: recStrings(r, "requestedUserInfoClaims"),
	}
	if v, ok := r["confirmation"]; ok && v != nil {
		t.Confirmation = toObject(v)
	}
	return t
}

func hasScope(scopes []string, s string) bool { return contains(scopes, s) }
