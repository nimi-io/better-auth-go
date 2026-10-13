package scim

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Managed connection constants.
const (
	managedConnectionIDPrefix = "ba_scim_connection_"
	managedCredentialIDPrefix = "ba_scim_credential_"
	// ManagedCreationRequestIDConflict is SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT.
	ManagedCreationRequestIDConflict = "SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT"
	managedHashVersion               = "v1"
	managedEventLimit                = 100
	managedDefaultMaxActive          = 5
	managedDefaultLastUsedInterval   = 300
	managedActiveCredentialScanLimit = 101
	managedIdentifierLength          = 32
	managedSecretLength              = 48
)

// ManagedConnectionIDPrefix is SCIM_MANAGED_CONNECTION_ID_PREFIX.
const ManagedConnectionIDPrefix = managedConnectionIDPrefix

type resolvedManagedOptions struct {
	secret                string
	maxActiveCredentials  int
	lastUsedWriteInterval int
}

func resolveManagedOptions(o *ManagedConnectionOptions) *resolvedManagedOptions {
	r := &resolvedManagedOptions{secret: o.CredentialHashSecret, maxActiveCredentials: managedDefaultMaxActive,
		lastUsedWriteInterval: managedDefaultLastUsedInterval}
	if o.MaxActiveCredentials != nil {
		r.maxActiveCredentials = *o.MaxActiveCredentials
	}
	if o.LastUsedWriteIntervalSeconds != nil {
		r.lastUsedWriteInterval = *o.LastUsedWriteIntervalSeconds
	}
	return r
}

var scimScopeSchema = zEnumT{values: []string{"scim.users.read", "scim.users.write", "scim.groups.read", "scim.groups.write"}}

var (
	creationRequestIDSchema    = zStr().trim().min(16).max(255)
	provisioningDomainIDSchema = zStr().trim().min(1).max(255)
	managedConnectionIDSchema  = zStr().startsWith(managedConnectionIDPrefix).max(255)
	managedCredentialIDSchema  = zStr().startsWith(managedCredentialIDPrefix).max(255)
	actorIDSchema              = zStr().trim().min(1).max(255)

	createManagedConnectionBody = zObj(
		zf("creationRequestId", creationRequestIDSchema),
		zf("provisioningDomainId", provisioningDomainIDSchema),
		zf("actorId", actorIDSchema),
		zf("scopes", zArr(scimScopeSchema).min(1)),
		zf("expiresAt", zDateT{}),
	)
	listManagedConnectionsBody  = zObj(zf("provisioningDomainId", provisioningDomainIDSchema))
	getManagedConnectionBody    = zObj(zf("connectionId", managedConnectionIDSchema), zf("provisioningDomainId", provisioningDomainIDSchema))
	rotateManagedCredentialBody = zObj(
		zf("connectionId", managedConnectionIDSchema),
		zf("provisioningDomainId", provisioningDomainIDSchema),
		zf("actorId", actorIDSchema),
		zf("scopes", zArr(scimScopeSchema).min(1)),
		zf("expiresAt", zDateT{}),
	)
	revokeManagedCredentialBody = zObj(
		zf("connectionId", managedConnectionIDSchema),
		zf("provisioningDomainId", provisioningDomainIDSchema),
		zf("credentialId", managedCredentialIDSchema),
		zf("actorId", actorIDSchema),
	)
	decommissionManagedConnectionBody = zObj(
		zf("connectionId", managedConnectionIDSchema),
		zf("provisioningDomainId", provisioningDomainIDSchema),
		zf("actorId", actorIDSchema),
	)
)

type managedConnectionRow struct {
	ID, CreationRequestID, ConnectionID, ProvisioningDomainID, Status string
	Revision                                                          int64
	CreatedAt                                                         time.Time
	CreatedBy                                                         string
	DecommissionStartedAt                                             *time.Time
	DecommissionStartedBy                                             *string
	DecommissionedAt                                                  *time.Time
	DecommissionedBy                                                  *string
}

func toManagedConnectionRow(r adapter.Record) *managedConnectionRow {
	if r == nil {
		return nil
	}
	return &managedConnectionRow{ID: recStr(r, "id"), CreationRequestID: recStr(r, "creationRequestId"),
		ConnectionID: recStr(r, "connectionId"), ProvisioningDomainID: recStr(r, "provisioningDomainId"),
		Status: recStr(r, "status"), Revision: recInt(r, "revision"), CreatedAt: recTime(r, "createdAt"),
		CreatedBy: recStr(r, "createdBy"), DecommissionStartedAt: recOptTime(r, "decommissionStartedAt"),
		DecommissionStartedBy: recOptStr(r, "decommissionStartedBy"), DecommissionedAt: recOptTime(r, "decommissionedAt"),
		DecommissionedBy: recOptStr(r, "decommissionedBy")}
}

type managedCredentialRow struct {
	ID, ConnectionRecordID, CredentialID, TokenDigest, HashVersion, ActiveSlotKey, Status, SerializedScopes string
	ExpiresAt, CreatedAt                                                                                    time.Time
	CreatedBy                                                                                               string
	LastUsedAt, RevokedAt                                                                                   *time.Time
	RevokedBy                                                                                               *string
}

func toManagedCredentialRow(r adapter.Record) *managedCredentialRow {
	if r == nil {
		return nil
	}
	return &managedCredentialRow{ID: recStr(r, "id"), ConnectionRecordID: recStr(r, "connectionRecordId"),
		CredentialID: recStr(r, "credentialId"), TokenDigest: recStr(r, "tokenDigest"), HashVersion: recStr(r, "hashVersion"),
		ActiveSlotKey: recStr(r, "activeSlotKey"), Status: recStr(r, "status"), SerializedScopes: recStr(r, "serializedScopes"),
		ExpiresAt: recTime(r, "expiresAt"), CreatedAt: recTime(r, "createdAt"), CreatedBy: recStr(r, "createdBy"),
		LastUsedAt: recOptTime(r, "lastUsedAt"), RevokedAt: recOptTime(r, "revokedAt"), RevokedBy: recOptStr(r, "revokedBy")}
}

func managedNotFound() error {
	return betterauth.NewAPIError("NOT_FOUND", jsonx.O("message", "Managed SCIM connection not found"))
}

func managedConflict(msg string) error {
	return betterauth.NewAPIError("CONFLICT", jsonx.O("message", msg))
}

func managedCreationConflict() error {
	return betterauth.NewAPIError("CONFLICT", jsonx.O("code", ManagedCreationRequestIDConflict,
		"message", "Managed SCIM connection creation request ID already exists"))
}

func activeSlotKey(recordID string, slot int) string {
	return recordID + ":active:" + strconv.Itoa(slot)
}
func inactiveSlotKey(credentialID string) string { return credentialID + ":inactive" }

func assertFutureExpiry(t time.Time) error {
	if !t.After(time.Now()) {
		return betterauth.NewAPIError("BAD_REQUEST", jsonx.O("message", "Managed SCIM credential expiry must be in the future"))
	}
	return nil
}

func generateOpaqueIdentifier(prefix string) string {
	return prefix + bacrypto.RandomStringFrom(managedIdentifierLength, bacrypto.AlphaLower, bacrypto.AlphaUpper, bacrypto.Digits, bacrypto.DashUnder)
}

func createManagedToken(credentialID string) string {
	return credentialID + "." + bacrypto.RandomStringFrom(managedSecretLength, bacrypto.AlphaLower, bacrypto.AlphaUpper, bacrypto.Digits, bacrypto.DashUnder)
}

// digestManagedToken is createHMAC("SHA-256", "base64urlnopad").sign(secret, token).
func digestManagedToken(token, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyManagedDigest(token, secret, digest string) bool {
	expected, err := base64.RawURLEncoding.DecodeString(digest)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token))
	return hmac.Equal(mac.Sum(nil), expected)
}

func invalidScopePolicy() error {
	return betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("message", "Managed SCIM credential scope policy is invalid"))
}

func parseManagedScopes(serialized string) ([]Scope, error) {
	v, err := parseJSON([]byte(serialized))
	if err != nil {
		return nil, invalidScopePolicy()
	}
	out, issues := zParse(zArr(scimScopeSchema).min(1), v)
	if len(issues) > 0 {
		return nil, invalidScopePolicy()
	}
	seen := map[string]bool{}
	var scopes []Scope
	for _, x := range anyList(out) {
		s := x.(string)
		if seen[s] {
			return nil, invalidScopePolicy()
		}
		seen[s] = true
		scopes = append(scopes, Scope(s))
	}
	return scopes, nil
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func toManagedConnection(c *managedConnectionRow) *jsonx.Object {
	return jsonx.O("creationRequestId", c.CreationRequestID, "connectionId", c.ConnectionID,
		"provisioningDomainId", c.ProvisioningDomainID, "status", c.Status, "createdAt", c.CreatedAt,
		"createdBy", c.CreatedBy, "decommissionStartedAt", nullTime(c.DecommissionStartedAt),
		"decommissionStartedBy", optStrValue(c.DecommissionStartedBy), "decommissionedAt", nullTime(c.DecommissionedAt),
		"decommissionedBy", optStrValue(c.DecommissionedBy))
}

func toManagedCredential(c *managedCredentialRow, observedAt time.Time) (*jsonx.Object, error) {
	status := c.Status
	if status == "active" && !c.ExpiresAt.After(observedAt) {
		status = "expired"
	}
	scopes, err := parseManagedScopes(c.SerializedScopes)
	if err != nil {
		return nil, err
	}
	sc := make([]any, len(scopes))
	for i, s := range scopes {
		sc[i] = string(s)
	}
	return jsonx.O("credentialId", c.CredentialID, "status", status, "scopes", sc, "expiresAt", c.ExpiresAt,
		"createdAt", c.CreatedAt, "createdBy", c.CreatedBy, "lastUsedAt", nullTime(c.LastUsedAt),
		"revokedAt", nullTime(c.RevokedAt), "revokedBy", optStrValue(c.RevokedBy)), nil
}

func findManagedConnectionByCreationRequestID(ctx context.Context, db adapter.Adapter, id string) (*managedConnectionRow, error) {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelManagedConnection, Where: []adapter.Where{w("creationRequestId", id)}})
	if err != nil {
		return nil, err
	}
	return toManagedConnectionRow(r), nil
}

func findManagedConnection(ctx context.Context, db adapter.Adapter, connectionID, domain string) (*managedConnectionRow, error) {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelManagedConnection, Where: []adapter.Where{
		w("connectionId", connectionID), w("provisioningDomainId", domain)}})
	if err != nil {
		return nil, err
	}
	return toManagedConnectionRow(r), nil
}

func getManagedConnectionState(ctx context.Context, db adapter.Adapter, c *managedConnectionRow) (*jsonx.Object, error) {
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelManagedCredential, Where: []adapter.Where{
		w("connectionRecordId", c.ID)}, SortBy: &adapter.SortBy{Field: "createdAt", Direction: "desc"}})
	if err != nil {
		return nil, err
	}
	creds := []any{}
	now := time.Now()
	for _, r := range rows {
		o, err := toManagedCredential(toManagedCredentialRow(r), now)
		if err != nil {
			return nil, err
		}
		creds = append(creds, o)
	}
	return jsonx.O("connection", toManagedConnection(c), "credentials", creds), nil
}

func createManagedEvent(ctx context.Context, db adapter.Adapter, recordID string, sequence int64, typ, actorID, credentialID string, createdAt time.Time) error {
	data := adapter.Record{"connectionRecordId": recordID, "eventKey": recordID + ":" + strconv.FormatInt(sequence, 10),
		"sequence": sequence, "type": typ, "actorId": actorID, "createdAt": createdAt}
	if credentialID != "" {
		data["credentialId"] = credentialID
	}
	_, err := db.Create(ctx, adapter.CreateInput{Model: modelManagedEvent, Data: data})
	return err
}

// runManagedMutationTransaction joins an ambient transaction or opens a native one.
func runManagedMutationTransaction(ctx context.Context, auth *betterauth.AuthContext, fn func(tx context.Context) error) error {
	if betterauth.InTransaction(ctx) {
		return fn(ctx)
	}
	return auth.Adapter.Transaction(ctx, func(tx context.Context, _ adapter.Adapter) error { return fn(tx) })
}

func isManagedBearerToken(token string) bool {
	return strings.HasPrefix(token, managedCredentialIDPrefix)
}

var managedTokenPattern = regexp.MustCompile(`^(ba_scim_credential_[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$`)

func verifyManagedBearerToken(ctx context.Context, db adapter.Adapter, token string, o *resolvedManagedOptions) (*Principal, error) {
	m := managedTokenPattern.FindStringSubmatch(token)
	if m == nil {
		return nil, nil
	}
	credentialID := m[1]
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelManagedCredential, Where: []adapter.Where{w("credentialId", credentialID)}})
	if err != nil {
		return nil, err
	}
	cred := toManagedCredentialRow(r)
	if cred == nil || cred.HashVersion != managedHashVersion || cred.Status != "active" || !cred.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	if !verifyManagedDigest(token, o.secret, cred.TokenDigest) {
		return nil, nil
	}
	cr, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelManagedConnection, Where: []adapter.Where{
		w("id", cred.ConnectionRecordID), w("status", "active")}})
	if err != nil {
		return nil, err
	}
	conn := toManagedConnectionRow(cr)
	if conn == nil {
		return nil, nil
	}
	now := time.Now()
	due := cred.LastUsedAt == nil || !cred.LastUsedAt.Add(time.Duration(o.lastUsedWriteInterval)*time.Second).After(now)
	if due {
		_, _ = db.Update(ctx, modelManagedCredential, []adapter.Where{w("id", cred.ID), w("status", "active"),
			w("lastUsedAt", nullTime(cred.LastUsedAt))}, adapter.Record{"lastUsedAt": now})
	}
	scopes, err := parseManagedScopes(cred.SerializedScopes)
	if err != nil {
		return nil, err
	}
	exp := cred.ExpiresAt
	return &Principal{Type: PrincipalManagedBearer, ConnectionID: conn.ConnectionID, ProvisioningDomainID: conn.ProvisioningDomainID,
		CredentialID: credentialID, Scopes: scopes, ExpiresAt: &exp}, nil
}

type managedInput struct {
	creationRequestID, provisioningDomainID, actorID, connectionID, credentialID string
	scopes                                                                       []string
	expiresAt                                                                    time.Time
}

func readManagedInput(body *jsonx.Object) managedInput {
	in := managedInput{creationRequestID: getStr(body, "creationRequestId"), provisioningDomainID: getStr(body, "provisioningDomainId"),
		actorID: getStr(body, "actorId"), connectionID: getStr(body, "connectionId"), credentialID: getStr(body, "credentialId")}
	for _, s := range getArr(body, "scopes") {
		in.scopes = append(in.scopes, s.(string))
	}
	if t, ok := objGet(body, "expiresAt").(time.Time); ok {
		in.expiresAt = t
	}
	return in
}

func scopesUnique(scopes []string) bool { return len(uniqueStrings(scopes)) == len(scopes) }

func (p *plugin) requireManaged() (*resolvedManagedOptions, error) {
	if p.managed == nil {
		return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("message", "SCIM managed connections are not configured"))
	}
	return p.managed, nil
}

func serverOnly(key string, body zSchema, noStore bool, handler func(*betterauth.EndpointContext) (any, error)) *betterauth.Endpoint {
	ep := &betterauth.Endpoint{Key: key, Methods: []string{"POST"}, ServerOnly: true, Body: zodValidator(body), Handler: handler}
	if noStore {
		ep.Metadata = map[string]any{"noStore": true}
	}
	return ep
}

func (p *plugin) managedEndpoints() []*betterauth.Endpoint {
	return []*betterauth.Endpoint{
		serverOnly("createSCIMManagedConnection", createManagedConnectionBody, true, p.createManagedConnection),
		serverOnly("listSCIMManagedConnections", listManagedConnectionsBody, false, p.listManagedConnections),
		serverOnly("getSCIMManagedConnection", getManagedConnectionBody, false, p.getManagedConnection),
		serverOnly("rotateSCIMManagedCredential", rotateManagedCredentialBody, true, p.rotateManagedCredential),
		serverOnly("revokeSCIMManagedCredential", revokeManagedCredentialBody, false, p.revokeManagedCredential),
		serverOnly("listSCIMManagedConnectionEvents", getManagedConnectionBody, false, p.listManagedConnectionEvents),
		serverOnly("decommissionSCIMManagedConnection", decommissionManagedConnectionBody, false, p.decommissionManagedConnection),
	}
}

func (p *plugin) createManagedConnection(ctx *betterauth.EndpointContext) (any, error) {
	o, err := p.requireManaged()
	if err != nil {
		return nil, err
	}
	in := readManagedInput(ctx.Body.(*jsonx.Object))
	if err := assertFutureExpiry(in.expiresAt); err != nil {
		return nil, err
	}
	if !scopesUnique(in.scopes) {
		return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("message", "Managed SCIM credential scopes must be unique"))
	}
	base := ctx.Context()
	joinsAmbient := betterauth.InTransaction(base)
	createdAt := time.Now()
	connectionID := generateOpaqueIdentifier(managedConnectionIDPrefix)
	credentialID := generateOpaqueIdentifier(managedCredentialIDPrefix)
	token := createManagedToken(credentialID)
	digest := digestManagedToken(token, o.secret)
	db := ctx.Auth.Adapter
	var conn *managedConnectionRow
	var cred *managedCredentialRow
	err = runManagedMutationTransaction(base, ctx.Auth, func(tx context.Context) error {
		dup, err := findManagedConnectionByCreationRequestID(tx, db, in.creationRequestID)
		if err != nil {
			return err
		}
		if dup != nil {
			return managedCreationConflict()
		}
		cr, err := db.Create(tx, adapter.CreateInput{Model: modelManagedConnection, Data: adapter.Record{
			"creationRequestId": in.creationRequestID, "connectionId": connectionID, "provisioningDomainId": in.provisioningDomainID,
			"status": "active", "revision": 2, "createdAt": createdAt, "createdBy": in.actorID}})
		if err != nil {
			return err
		}
		conn = toManagedConnectionRow(cr)
		kr, err := db.Create(tx, adapter.CreateInput{Model: modelManagedCredential, Data: adapter.Record{
			"connectionRecordId": conn.ID, "credentialId": credentialID, "tokenDigest": digest, "hashVersion": managedHashVersion,
			"activeSlotKey": activeSlotKey(conn.ID, 0), "status": "active", "serializedScopes": mustStringify(strsToAny(in.scopes)),
			"expiresAt": in.expiresAt, "createdAt": createdAt, "createdBy": in.actorID}})
		if err != nil {
			return err
		}
		cred = toManagedCredentialRow(kr)
		if err := createManagedEvent(tx, db, conn.ID, 1, "connection.created", in.actorID, "", createdAt); err != nil {
			return err
		}
		return createManagedEvent(tx, db, conn.ID, 2, "credential.issued", in.actorID, credentialID, createdAt)
	})
	if err != nil {
		if _, ok := betterauth.AsAPIError(err); ok || joinsAmbient {
			return nil, err
		}
		dup, ferr := findManagedConnectionByCreationRequestID(base, db, in.creationRequestID)
		if ferr == nil && dup != nil {
			return nil, managedCreationConflict()
		}
		return nil, err
	}
	credObj, err := toManagedCredential(cred, createdAt)
	if err != nil {
		return nil, err
	}
	return jsonx.O("connection", toManagedConnection(conn), "credential", credObj, "token", token), nil
}

func (p *plugin) listManagedConnections(ctx *betterauth.EndpointContext) (any, error) {
	if _, err := p.requireManaged(); err != nil {
		return nil, err
	}
	body := ctx.Body.(*jsonx.Object)
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelManagedConnection, Where: []adapter.Where{
		w("provisioningDomainId", getStr(body, "provisioningDomainId"))}, SortBy: &adapter.SortBy{Field: "createdAt", Direction: "desc"}})
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range rows {
		out = append(out, toManagedConnection(toManagedConnectionRow(r)))
	}
	return jsonx.O("connections", out), nil
}

func (p *plugin) getManagedConnection(ctx *betterauth.EndpointContext) (any, error) {
	if _, err := p.requireManaged(); err != nil {
		return nil, err
	}
	in := readManagedInput(ctx.Body.(*jsonx.Object))
	c, err := findManagedConnection(ctx.Context(), ctx.Auth.Adapter, in.connectionID, in.provisioningDomainID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, managedNotFound()
	}
	return getManagedConnectionState(ctx.Context(), ctx.Auth.Adapter, c)
}

func (p *plugin) rotateManagedCredential(ctx *betterauth.EndpointContext) (any, error) {
	o, err := p.requireManaged()
	if err != nil {
		return nil, err
	}
	in := readManagedInput(ctx.Body.(*jsonx.Object))
	if err := assertFutureExpiry(in.expiresAt); err != nil {
		return nil, err
	}
	if !scopesUnique(in.scopes) {
		return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("message", "Managed SCIM credential scopes must be unique"))
	}
	createdAt := time.Now()
	credentialID := generateOpaqueIdentifier(managedCredentialIDPrefix)
	token := createManagedToken(credentialID)
	digest := digestManagedToken(token, o.secret)
	db := ctx.Auth.Adapter
	for attempt := 0; attempt < 5; attempt++ {
		var fenced *managedConnectionRow
		var cred *managedCredentialRow
		err := runManagedMutationTransaction(ctx.Context(), ctx.Auth, func(tx context.Context) error {
			conn, err := findManagedConnection(tx, db, in.connectionID, in.provisioningDomainID)
			if err != nil {
				return err
			}
			if conn == nil {
				return managedNotFound()
			}
			if conn.Status != "active" {
				return managedConflict("Managed SCIM connection is not active")
			}
			fr, err := db.IncrementOne(tx, adapter.IncrementInput{Model: modelManagedConnection, Where: []adapter.Where{
				w("id", conn.ID), w("status", "active"), w("revision", conn.Revision)}, Increment: map[string]float64{"revision": 1}})
			if err != nil || fr == nil {
				return err
			}
			f := toManagedConnectionRow(fr)
			rows, err := db.FindMany(tx, adapter.FindManyInput{Model: modelManagedCredential, Where: []adapter.Where{
				w("connectionRecordId", conn.ID), w("status", "active")}, Limit: managedActiveCredentialScanLimit})
			if err != nil {
				return err
			}
			live := map[string]bool{}
			for _, r := range rows {
				c := toManagedCredentialRow(r)
				if !c.ExpiresAt.After(createdAt) {
					if _, err := db.Update(tx, modelManagedCredential, []adapter.Where{w("id", c.ID), w("status", "active"),
						w("activeSlotKey", c.ActiveSlotKey)}, adapter.Record{"status": "expired", "activeSlotKey": inactiveSlotKey(c.CredentialID)}); err != nil {
						return err
					}
				} else {
					live[c.ActiveSlotKey] = true
				}
			}
			if len(live) >= o.maxActiveCredentials {
				return managedConflict("Managed SCIM connection has the maximum number of active credentials")
			}
			slot := -1
			for cand := 0; cand < o.maxActiveCredentials; cand++ {
				if !live[activeSlotKey(conn.ID, cand)] {
					slot = cand
					break
				}
			}
			if slot < 0 {
				return managedConflict("Managed SCIM connection has the maximum number of active credentials")
			}
			kr, err := db.Create(tx, adapter.CreateInput{Model: modelManagedCredential, Data: adapter.Record{
				"connectionRecordId": conn.ID, "credentialId": credentialID, "tokenDigest": digest, "hashVersion": managedHashVersion,
				"activeSlotKey": activeSlotKey(conn.ID, slot), "status": "active", "serializedScopes": mustStringify(strsToAny(in.scopes)),
				"expiresAt": in.expiresAt, "createdAt": createdAt, "createdBy": in.actorID}})
			if err != nil {
				return err
			}
			cred = toManagedCredentialRow(kr)
			if err := createManagedEvent(tx, db, conn.ID, f.Revision, "credential.rotated", in.actorID, credentialID, createdAt); err != nil {
				return err
			}
			fenced = f
			return nil
		})
		if err != nil {
			return nil, err
		}
		if fenced == nil {
			continue
		}
		credObj, err := toManagedCredential(cred, createdAt)
		if err != nil {
			return nil, err
		}
		return jsonx.O("connection", toManagedConnection(fenced), "credential", credObj, "token", token), nil
	}
	return nil, managedConflict("Managed SCIM connection changed repeatedly during credential rotation")
}

func (p *plugin) revokeManagedCredential(ctx *betterauth.EndpointContext) (any, error) {
	if _, err := p.requireManaged(); err != nil {
		return nil, err
	}
	in := readManagedInput(ctx.Body.(*jsonx.Object))
	db := ctx.Auth.Adapter
	for attempt := 0; attempt < 5; attempt++ {
		var revoked *managedConnectionRow
		err := runManagedMutationTransaction(ctx.Context(), ctx.Auth, func(tx context.Context) error {
			conn, err := findManagedConnection(tx, db, in.connectionID, in.provisioningDomainID)
			if err != nil {
				return err
			}
			if conn == nil {
				return managedNotFound()
			}
			kr, err := db.FindOne(tx, adapter.FindOneInput{Model: modelManagedCredential, Where: []adapter.Where{
				w("credentialId", in.credentialID), w("connectionRecordId", conn.ID)}})
			if err != nil {
				return err
			}
			cred := toManagedCredentialRow(kr)
			if cred == nil {
				return managedNotFound()
			}
			if cred.Status == "revoked" {
				revoked = conn
				return nil
			}
			if conn.Status != "active" || cred.Status != "active" {
				return managedConflict("Managed SCIM credential is not active")
			}
			fr, err := db.IncrementOne(tx, adapter.IncrementInput{Model: modelManagedConnection, Where: []adapter.Where{
				w("id", conn.ID), w("status", "active"), w("revision", conn.Revision)}, Increment: map[string]float64{"revision": 1}})
			if err != nil || fr == nil {
				return err
			}
			fenced := toManagedConnectionRow(fr)
			revokedAt := time.Now()
			ur, err := db.Update(tx, modelManagedCredential, []adapter.Where{w("id", cred.ID), w("status", "active"),
				w("activeSlotKey", cred.ActiveSlotKey)}, adapter.Record{"status": "revoked", "activeSlotKey": inactiveSlotKey(cred.CredentialID),
				"revokedAt": revokedAt, "revokedBy": in.actorID})
			if err != nil || ur == nil {
				return err
			}
			if err := createManagedEvent(tx, db, conn.ID, fenced.Revision, "credential.revoked", in.actorID, cred.CredentialID, revokedAt); err != nil {
				return err
			}
			revoked = fenced
			return nil
		})
		if err != nil {
			return nil, err
		}
		if revoked == nil {
			continue
		}
		return getManagedConnectionState(ctx.Context(), db, revoked)
	}
	return nil, managedConflict("Managed SCIM connection changed repeatedly during credential revocation")
}

func (p *plugin) listManagedConnectionEvents(ctx *betterauth.EndpointContext) (any, error) {
	if _, err := p.requireManaged(); err != nil {
		return nil, err
	}
	in := readManagedInput(ctx.Body.(*jsonx.Object))
	db := ctx.Auth.Adapter
	conn, err := findManagedConnection(ctx.Context(), db, in.connectionID, in.provisioningDomainID)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, managedNotFound()
	}
	rows, err := db.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelManagedEvent, Where: []adapter.Where{
		w("connectionRecordId", conn.ID)}, Limit: managedEventLimit, SortBy: &adapter.SortBy{Field: "sequence", Direction: "desc"}})
	if err != nil {
		return nil, err
	}
	events := []any{}
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		events = append(events, jsonx.O("sequence", recInt(r, "sequence"), "type", recStr(r, "type"), "actorId", recStr(r, "actorId"),
			"credentialId", optStrValue(recOptStr(r, "credentialId")), "createdAt", recTime(r, "createdAt")))
	}
	return jsonx.O("events", events), nil
}

func (p *plugin) managedDecommissionStep(ctx *betterauth.EndpointContext, in managedInput, begin bool) (*managedConnectionRow, error) {
	db := ctx.Auth.Adapter
	for attempt := 0; attempt < 5; attempt++ {
		var result *managedConnectionRow
		err := runManagedMutationTransaction(ctx.Context(), ctx.Auth, func(tx context.Context) error {
			conn, err := findManagedConnection(tx, db, in.connectionID, in.provisioningDomainID)
			if err != nil {
				return err
			}
			if conn == nil {
				return managedNotFound()
			}
			if begin {
				if conn.Status == "decommissioning" || conn.Status == "decommissioned" {
					result = conn
					return nil
				}
				startedAt := time.Now()
				fr, err := db.IncrementOne(tx, adapter.IncrementInput{Model: modelManagedConnection, Where: []adapter.Where{
					w("id", conn.ID), w("status", "active"), w("revision", conn.Revision)}, Increment: map[string]float64{"revision": 1},
					Set: adapter.Record{"status": "decommissioning", "decommissionStartedAt": startedAt, "decommissionStartedBy": in.actorID}})
				if err != nil || fr == nil {
					return err
				}
				fenced := toManagedConnectionRow(fr)
				rows, err := db.FindMany(tx, adapter.FindManyInput{Model: modelManagedCredential, Where: []adapter.Where{
					w("connectionRecordId", conn.ID), w("status", "active")}, Limit: 100})
				if err != nil {
					return err
				}
				for _, r := range rows {
					c := toManagedCredentialRow(r)
					if _, err := db.Update(tx, modelManagedCredential, []adapter.Where{w("id", c.ID), w("status", "active"),
						w("activeSlotKey", c.ActiveSlotKey)}, adapter.Record{"status": "decommissioned",
						"activeSlotKey": inactiveSlotKey(c.CredentialID), "decommissionedAt": startedAt}); err != nil {
						return err
					}
				}
				if err := createManagedEvent(tx, db, conn.ID, fenced.Revision, "connection.decommissioning", in.actorID, "", startedAt); err != nil {
					return err
				}
				result = fenced
				return nil
			}
			if conn.Status == "decommissioned" {
				result = conn
				return nil
			}
			if conn.Status != "decommissioning" {
				return managedConflict("Managed SCIM connection did not begin decommissioning")
			}
			at := time.Now()
			fr, err := db.IncrementOne(tx, adapter.IncrementInput{Model: modelManagedConnection, Where: []adapter.Where{
				w("id", conn.ID), w("status", "decommissioning"), w("revision", conn.Revision)}, Increment: map[string]float64{"revision": 1},
				Set: adapter.Record{"status": "decommissioned", "decommissionedAt": at, "decommissionedBy": in.actorID}})
			if err != nil || fr == nil {
				return err
			}
			fenced := toManagedConnectionRow(fr)
			if err := createManagedEvent(tx, db, conn.ID, fenced.Revision, "connection.decommissioned", in.actorID, "", at); err != nil {
				return err
			}
			result = fenced
			return nil
		})
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
	}
	if begin {
		return nil, managedConflict("Managed SCIM connection changed repeatedly while decommissioning began")
	}
	return nil, managedConflict("Managed SCIM connection changed repeatedly while decommissioning completed")
}

func (p *plugin) decommissionManagedConnection(ctx *betterauth.EndpointContext) (any, error) {
	if _, err := p.requireManaged(); err != nil {
		return nil, err
	}
	in := readManagedInput(ctx.Body.(*jsonx.Object))
	db := ctx.Auth.Adapter
	started, err := p.managedDecommissionStep(ctx, in, true)
	if err != nil {
		return nil, err
	}
	if started.Status == "decommissioned" {
		state, err := getManagedConnectionState(ctx.Context(), db, started)
		if err != nil {
			return nil, err
		}
		state.Set("decommission", jsonx.O("status", "complete", "retryAfter", nil))
		return state, nil
	}
	core, err := p.decommissionConnection(ctx.Context(), ctx.Auth, started.ConnectionID, started.ProvisioningDomainID)
	if err != nil {
		return nil, err
	}
	if getStr(core, "status") != decommissionComplete {
		state, err := getManagedConnectionState(ctx.Context(), db, started)
		if err != nil {
			return nil, err
		}
		state.Set("decommission", core)
		return state, nil
	}
	completed, err := p.managedDecommissionStep(ctx, in, false)
	if err != nil {
		return nil, err
	}
	state, err := getManagedConnectionState(ctx.Context(), db, completed)
	if err != nil {
		return nil, err
	}
	state.Set("decommission", core)
	return state, nil
}
