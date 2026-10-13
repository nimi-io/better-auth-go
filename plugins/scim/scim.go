// Package scim ports the Better Auth SCIM 2.0 plugin (@better-auth/scim 1.7.7): SCIM
// Users and Groups provisioning with RFC 7644 responses, discovery endpoints, bearer token
// connections (static, application-verified and managed), identity linking, role
// projection and connection decommissioning.
package scim

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// PackageVersion is the upstream package version.
const PackageVersion = "1.7.7"

const responseMarker = "X-Better-Auth-Scim-Response"

type plugin struct {
	opts       *Options
	configured map[string]Connection
	managed    *resolvedManagedOptions
	identity   *identityCoordinator
	projection *projectionCoordinator
}

func validationError(msg string) error { return newBetterAuthError(msg) }

// validateOptions is validateConnections.
func validateOptions(o *Options) error {
	authProvided := o.Authentication != nil
	hasVerifier := authProvided && o.Authentication.VerifyBearerToken != nil
	if authProvided && !hasVerifier {
		return validationError("SCIM authentication requires a callable verifyBearerToken.")
	}
	if m := o.ManagedConnections; m != nil {
		if utf16Len(m.CredentialHashSecret) < 32 {
			return validationError("SCIM managed credentialHashSecret must contain at least 32 characters.")
		}
		max := managedDefaultMaxActive
		if m.MaxActiveCredentials != nil {
			max = *m.MaxActiveCredentials
		}
		if max < 1 || max > 100 {
			return validationError("SCIM managed maxActiveCredentials must be an integer between 1 and 100.")
		}
		interval := managedDefaultLastUsedInterval
		if m.LastUsedWriteIntervalSeconds != nil {
			interval = *m.LastUsedWriteIntervalSeconds
		}
		if interval < 0 {
			return validationError("SCIM managed lastUsedWriteIntervalSeconds must be a non-negative integer.")
		}
	}
	if len(o.Connections) == 0 && !hasVerifier && o.ManagedConnections == nil {
		return validationError("The scim plugin requires a provisioning connection, bearer token verifier, or managed connection catalog.")
	}
	ids := map[string]bool{}
	tokens := map[string]bool{}
	for _, c := range o.Connections {
		if !isValidIdentifier(c.ID) {
			return validationError("SCIM connection ids must be trimmed and contain between 1 and 255 characters.")
		}
		if strings.HasPrefix(c.ID, managedConnectionIDPrefix) {
			return validationError(`Static SCIM connection ids cannot use the reserved "` + managedConnectionIDPrefix + `" prefix.`)
		}
		if len(c.Credentials) == 0 && !hasVerifier {
			return validationError("SCIM connections require a static credential or bearer token verifier.")
		}
		if c.ProvisioningDomainID != "" && !isValidIdentifier(c.ProvisioningDomainID) {
			return validationError("SCIM provisioning domain ids must be trimmed and contain between 1 and 255 characters.")
		}
		if ids[c.ID] {
			return validationError("SCIM connection ids must be unique.")
		}
		ids[c.ID] = true
		credIDs := map[string]bool{}
		for _, cred := range c.Credentials {
			if !isValidIdentifier(cred.ID) {
				return validationError("SCIM credential ids must be trimmed and contain between 1 and 255 characters.")
			}
			if credIDs[cred.ID] {
				return validationError("SCIM credential ids must be unique within a connection.")
			}
			credIDs[cred.ID] = true
			if cred.Token == "" || strings.ContainsFunc(cred.Token, jsIsSpace) {
				return validationError("SCIM bearer tokens cannot be empty or contain whitespace.")
			}
			if cred.Scopes != nil && !areValidScopes(cred.Scopes) {
				return validationError("SCIM credential scopes must be non-empty, unique, and supported.")
			}
			if !validExpiry(cred.ExpiresAt) {
				return validationError("SCIM credential expiry must be a valid Date.")
			}
			if tokens[cred.Token] {
				return validationError("SCIM bearer tokens must be unique.")
			}
			tokens[cred.Token] = true
		}
	}
	return nil
}

// NewE validates the options and builds the SCIM plugin.
func NewE(opts Options) (*betterauth.Plugin, error) {
	if err := validateOptions(&opts); err != nil {
		return nil, err
	}
	p := &plugin{opts: &opts, configured: map[string]Connection{}}
	for _, c := range opts.Connections {
		d := c.ProvisioningDomainID
		if d == "" {
			d = c.ID
		}
		p.configured[c.ID] = Connection{ID: c.ID, ProvisioningDomainID: d}
	}
	if opts.ManagedConnections != nil {
		p.managed = resolveManagedOptions(opts.ManagedConnections)
	}
	p.identity = &identityCoordinator{opts: p.opts}
	p.projection = &projectionCoordinator{opts: p.opts}
	return p.build(), nil
}

// New builds the SCIM plugin; it panics when the options are invalid (scim() throws).
func New(opts Options) *betterauth.Plugin {
	pl, err := NewE(opts)
	if err != nil {
		panic(err)
	}
	return pl
}

// errNoNativeTransactions is returned by Init for adapters without native transactions.
var errNoNativeTransactions = errors.New("The scim plugin requires a database adapter with native transaction support.")

// NativeTransactionReporter lets custom adapters report native transaction support.
type NativeTransactionReporter interface {
	SupportsNativeTransactions() bool
}

func supportsNativeTransactions(a adapter.Adapter) bool {
	if r, ok := a.(NativeTransactionReporter); ok {
		return r.SupportsNativeTransactions()
	}
	if c, ok := a.(interface{ Custom() adapter.CustomAdapter }); ok {
		_, ok := c.Custom().(adapter.Transactor)
		return ok
	}
	return true
}

func (p *plugin) build() *betterauth.Plugin {
	var endpoints []*betterauth.Endpoint
	endpoints = append(endpoints, p.managedEndpoints()...)
	endpoints = append(endpoints, p.decommissionEndpoint(), p.reconcileProjectionEndpoint())
	endpoints = append(endpoints, p.groupEndpoints()...)
	endpoints = append(endpoints, p.userEndpoints()...)
	endpoints = append(endpoints, discoveryEndpoints()...)
	return &betterauth.Plugin{
		ID:      "scim",
		Version: PackageVersion,
		Init: func(ctx *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			if !supportsNativeTransactions(ctx.Adapter) {
				return nil, errNoNativeTransactions
			}
			return nil, nil
		},
		Endpoints:  endpoints,
		OnRequest:  p.onRequest,
		OnResponse: onResponse,
		Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool { return strings.HasPrefix(ctx.Path, "/scim/v2") },
			Handler: afterHook,
		}}},
		Schema:  p.schema(),
		Options: p.opts,
	}
}

func scimErrorResponse(status, detail, scimType string) *betterauth.Response {
	e := scimErr(status, detail, scimType)
	h := http.Header{}
	h.Set("Content-Type", MediaType)
	return &betterauth.Response{Status: e.StatusCode, Header: h, Body: jsonx.MustMarshal(e.Body)}
}

var (
	userMutationPath  = regexp.MustCompile(`/scim/v2/Users(?:/[^/]+)?$`)
	groupCreatePath   = regexp.MustCompile(`/scim/v2/Groups$`)
	groupMutationPath = regexp.MustCompile(`/scim/v2/Groups(?:/[^/]+)?$`)
)

func (p *plugin) onRequest(r *http.Request, _ *betterauth.AuthContext) (*http.Request, *betterauth.Response, error) {
	path := r.URL.EscapedPath()
	if !strings.Contains(path, "/scim/v2/") {
		return nil, nil, nil
	}
	if r.Method == http.MethodDelete {
		nr := r.Clone(r.Context())
		nr.Body = http.NoBody
		nr.ContentLength = 0
		return nr, nil, nil
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return nil, nil, nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if r.Header.Get("Content-Type") == "" || (mediaType != "application/json" && mediaType != MediaType) {
		return nil, scimErrorResponse("UNSUPPORTED_MEDIA_TYPE", "SCIM requests must use application/scim+json or application/json", ""), nil
	}
	var raw []byte
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, err
		}
		raw = b
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	body, err := parseJSON(raw)
	if err != nil {
		return nil, scimErrorResponse("BAD_REQUEST", "SCIM request body must contain valid JSON", errInvalidSyntax), nil
	}
	isUserMutation := userMutationPath.MatchString(path) && ((r.Method == http.MethodPost && strings.HasSuffix(path, "/Users")) ||
		(r.Method != http.MethodPost && !strings.HasSuffix(path, "/Users")))
	isGroupCreate := r.Method == http.MethodPost && groupCreatePath.MatchString(path)
	isGroupMutation := groupMutationPath.MatchString(path) && (isGroupCreate ||
		(r.Method != http.MethodPost && !strings.HasSuffix(path, "/Groups")))
	normalized := body
	if isGroupMutation {
		accept := isGroupCreate && p.opts.Compatibility != nil && p.opts.Compatibility.MicrosoftEntra != nil &&
			p.opts.Compatibility.MicrosoftEntra.AcceptLegacyGroupSchema
		out, detail, ok := normalizeMicrosoftEntraGroupSchema(normalized, accept)
		if !ok {
			return nil, scimErrorResponse("BAD_REQUEST", detail, errInvalidValue), nil
		}
		normalized = out
	}
	if isUserMutation {
		normalized = normalizeUserEntraCompatibilityBody(r.Method, normalized)
	}
	if sameValue(normalized, body) {
		return nil, nil, nil
	}
	encoded, err := jsonx.Marshal(normalized)
	if err != nil {
		return nil, nil, err
	}
	nr := r.Clone(r.Context())
	nr.Header = r.Header.Clone()
	nr.Header.Del("Content-Length")
	nr.Body = io.NopCloser(bytes.NewReader(encoded))
	nr.ContentLength = int64(len(encoded))
	return nr, nil, nil
}

// sameValue reports reference equality for normalized bodies (normalizedBody === body).
func sameValue(a, b any) bool {
	ao, aok := a.(*jsonx.Object)
	bo, bok := b.(*jsonx.Object)
	if aok && bok {
		return ao == bo
	}
	if aok != bok {
		return false
	}
	return true
}

func onResponse(res *betterauth.Response, _ *betterauth.AuthContext) (*betterauth.Response, error) {
	if res == nil || res.Header.Get(responseMarker) != "1" {
		return nil, nil
	}
	h := res.Header.Clone()
	h.Del(responseMarker)
	h.Set("Content-Type", MediaType)
	return &betterauth.Response{Status: res.Status, Header: h, Body: res.Body}, nil
}

func afterHook(ctx *betterauth.EndpointContext) (any, error) {
	ctx.SetHeader(responseMarker, "1")
	e, ok := ctx.Returned.(*betterauth.APIError)
	if !ok || e == nil {
		return nil, nil
	}
	if isSCIMErrorBody(e.Body) {
		return nil, nil
	}
	detail := e.Message()
	validation := e.StatusCode == 400 && e.Body != nil && getStr(e.Body, "code") == "VALIDATION_ERROR"
	scimType := ""
	if validation {
		scimType = errInvalidValue
	}
	status := e.Status
	if status == "" {
		status = statusName(e.StatusCode)
	}
	out := newSCIMError(status, &detail, scimType)
	out.StatusCode = e.StatusCode
	if out.Body != nil {
		out.Body.Set("status", strconv.Itoa(e.StatusCode))
	}
	return nil, out
}

func statusName(code int) string {
	for k, v := range betterauth.StatusCodes {
		if v == code {
			return k
		}
	}
	return "INTERNAL_SERVER_ERROR"
}

// ---- schema ----

func field(name string, t db.FieldType, required bool, opts ...func(*db.Field)) db.Field {
	f := db.Field{Name: name, Type: t}
	if required {
		f.Required = db.True
	} else {
		f.Required = db.False
	}
	for _, o := range opts {
		o(&f)
	}
	return f
}

func indexed(f *db.Field)     { f.Index = true }
func unique(f *db.Field)      { f.Unique = true }
func notReturned(f *db.Field) { f.Returned = db.False }
func defaultValue(v any) func(*db.Field) {
	return func(f *db.Field) { f.DefaultValue = v }
}
func references(model string, onDelete string) func(*db.Field) {
	return func(f *db.Field) { f.References = &db.Reference{Model: model, Field: "id", OnDelete: onDelete} }
}

const (
	tString = db.TypeString
	tNumber = db.TypeNumber
	tBool   = db.TypeBoolean
	tDate   = db.TypeDate
)

func (p *plugin) schema() []db.PluginTable {
	var tables []db.PluginTable
	if p.opts.ManagedConnections != nil {
		tables = append(tables, managedSchema()...)
	}
	tables = append(tables,
		db.PluginTable{Key: modelConnectionBinding, Fields: []db.Field{
			field("connectionId", tString, true, indexed),
			field("connectionKey", tString, true, unique, notReturned),
			field("provisioningDomainId", tString, true),
			field("createdAt", tDate, true),
			field("decommissionedAt", tDate, false),
			field("decommissionStatus", tString, true, defaultValue("active")),
			field("decommissionCursorUserId", tString, false, notReturned),
			field("decommissionReconciledUserCount", tNumber, true, defaultValue(0)),
			field("decommissionBatchCount", tNumber, true, defaultValue(0)),
			field("decommissionRevision", tNumber, true, defaultValue(0), notReturned),
			field("decommissionCompletedAt", tDate, false),
			field("decommissionLeaseId", tString, false, notReturned),
			field("decommissionLeaseExpiresAt", tDate, false, notReturned),
		}},
		db.PluginTable{Key: modelIdentityTombstone, Fields: []db.Field{
			field("connectionId", tString, true, indexed),
			field("provisioningDomainId", tString, true, indexed),
			field("externalId", tString, true),
			field("externalIdKey", tString, true, unique, notReturned),
			field("userId", tString, true, indexed, references("user", "")),
			field("profile", tString, true),
			field("deletedAt", tDate, true),
		}},
		db.PluginTable{Key: modelSubject, Fields: []db.Field{
			field("userId", tString, true, unique, references("user", "")),
			field("profileSourceId", tString, false, indexed),
			field("revision", tNumber, true),
			field("createdAt", tDate, true),
			field("updatedAt", tDate, true),
		}},
		db.PluginTable{Key: modelUser, Fields: []db.Field{
			field("connectionId", tString, true, indexed),
			field("provisioningDomainId", tString, true, indexed),
			field("userId", tString, true, indexed, references("user", "")),
			field("connectionUserKey", tString, true, unique, notReturned),
			field("userName", tString, true),
			field("userNameKey", tString, true, unique, notReturned),
			field("primaryEmail", tString, true),
			field("workEmailValueIndex", tString, true, notReturned),
			field("emailValueIndex", tString, true, notReturned),
			field("displayName", tString, true),
			field("formattedName", tString, true),
			field("givenName", tString, false),
			field("familyName", tString, false),
			field("serializedEmails", tString, true, notReturned),
			field("serializedAttributes", tString, false, notReturned),
			field("externalId", tString, false),
			field("externalIdKey", tString, false, unique, notReturned),
			field("active", tBool, true),
			field("orderKey", tString, true, unique, notReturned),
			field("createdAt", tDate, true),
			field("updatedAt", tDate, true),
		}},
		db.PluginTable{Key: modelProjectionGrant, Fields: []db.Field{
			field("connectionId", tString, true, indexed),
			field("provisioningDomainId", tString, true, indexed),
			field("scimUserId", tString, true, indexed, references(modelUser, "")),
			field("userId", tString, true, indexed, references("user", "")),
			field("sourceKind", tString, true),
			field("sourceId", tString, true),
			field("sourceValue", tString, false),
			field("role", tString, true),
			field("grantKey", tString, true, unique, notReturned),
			field("createdAt", tDate, true),
			field("updatedAt", tDate, true),
		}},
		db.PluginTable{Key: modelGroup, Fields: []db.Field{
			field("connectionId", tString, true, indexed),
			field("provisioningDomainId", tString, true, indexed),
			field("revision", tNumber, true, defaultValue(0), notReturned),
			field("displayName", tString, true),
			field("displayNameKey", tString, true, unique, notReturned),
			field("externalId", tString, false),
			field("externalIdKey", tString, false, unique, notReturned),
			field("orderKey", tString, true, unique, notReturned),
			field("createdAt", tDate, true),
			field("updatedAt", tDate, true),
		}},
		db.PluginTable{Key: modelGroupMember, Fields: []db.Field{
			field("connectionId", tString, true, indexed),
			field("groupId", tString, true, indexed, references(modelGroup, "")),
			field("scimUserId", tString, true, indexed, references(modelUser, "")),
			field("membershipKey", tString, true, unique, notReturned),
			field("createdAt", tDate, true),
		}},
	)
	return tables
}

func managedSchema() []db.PluginTable {
	return []db.PluginTable{
		{Key: modelManagedConnection, Fields: []db.Field{
			field("creationRequestId", tString, true, unique),
			field("connectionId", tString, true, unique),
			field("provisioningDomainId", tString, true, indexed),
			field("status", tString, true),
			field("revision", tNumber, true, notReturned),
			field("createdAt", tDate, true),
			field("createdBy", tString, true),
			field("decommissionStartedAt", tDate, false),
			field("decommissionStartedBy", tString, false),
			field("decommissionedAt", tDate, false),
			field("decommissionedBy", tString, false),
		}},
		{Key: modelManagedCredential, Fields: []db.Field{
			field("connectionRecordId", tString, true, indexed, references(modelManagedConnection, db.OnDeleteCascade)),
			field("credentialId", tString, true, unique),
			field("tokenDigest", tString, true, notReturned),
			field("hashVersion", tString, true, notReturned),
			field("activeSlotKey", tString, true, unique, notReturned),
			field("status", tString, true),
			field("serializedScopes", tString, true, notReturned),
			field("expiresAt", tDate, true),
			field("createdAt", tDate, true),
			field("createdBy", tString, true),
			field("lastUsedAt", tDate, false),
			field("revokedAt", tDate, false),
			field("revokedBy", tString, false),
			field("decommissionedAt", tDate, false),
		}},
		{Key: modelManagedEvent, Fields: []db.Field{
			field("connectionRecordId", tString, true, indexed, references(modelManagedConnection, db.OnDeleteCascade)),
			field("eventKey", tString, true, unique, notReturned),
			field("sequence", tNumber, true),
			field("type", tString, true),
			field("actorId", tString, true),
			field("credentialId", tString, false),
			field("createdAt", tDate, true),
		}},
	}
}

var _ = time.Now
