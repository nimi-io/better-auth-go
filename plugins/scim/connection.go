package scim

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// ---- connection-state.ts ----

type bindingInit struct {
	status         string
	decommissioned *time.Time
	completedAt    *time.Time
}

func findOrCreateConnectionBinding(ctx context.Context, db adapter.Adapter, connectionID string, provisioningDomainID string,
	now time.Time, init bindingInit, assert func(*connectionBinding) error) (*connectionBinding, error) {
	key := CreateConnectionKey(connectionID)
	find := func() (*connectionBinding, error) {
		r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelConnectionBinding, Where: []adapter.Where{w("connectionKey", key)}})
		if err != nil {
			return nil, err
		}
		return toBinding(r), nil
	}
	existing, err := find()
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if err := assert(existing); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if provisioningDomainID == "" {
		return nil, newBetterAuthError(`SCIM connection "` + connectionID + `" has no persisted binding.`)
	}
	data := adapter.Record{
		"connectionId": connectionID, "connectionKey": key, "provisioningDomainId": provisioningDomainID,
		"createdAt": now, "decommissionReconciledUserCount": 0, "decommissionBatchCount": 0, "decommissionRevision": 0,
		"decommissionStatus": init.status,
	}
	if init.decommissioned != nil {
		data["decommissionedAt"] = *init.decommissioned
	}
	if init.completedAt != nil {
		data["decommissionCompletedAt"] = *init.completedAt
	}
	created, cerr := db.Create(ctx, adapter.CreateInput{Model: modelConnectionBinding, Data: data})
	if cerr == nil {
		return toBinding(created), nil
	}
	concurrent, err := find()
	if err != nil || concurrent == nil {
		return nil, cerr
	}
	if err := assert(concurrent); err != nil {
		return nil, err
	}
	return concurrent, nil
}

func findDecommissionedConnectionIDs(ctx context.Context, db adapter.Adapter, connectionIDs []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(connectionIDs) == 0 {
		return out, nil
	}
	rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: modelConnectionBinding,
		Where: []adapter.Where{wop("connectionId", adapter.In, strsToAny(uniqueStrings(connectionIDs)))}})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		b := toBinding(r)
		if b.DecommissionStatus != decommissionActive {
			out[b.ConnectionID] = true
		}
	}
	return out, nil
}

func fenceActiveConnection(ctx context.Context, db adapter.Adapter, connectionID string) (*connectionBinding, error) {
	b, err := tryFenceActiveConnection(ctx, db, connectionID)
	if err != nil {
		return nil, err
	}
	if b != nil {
		return b, nil
	}
	return nil, scimErr("UNAUTHORIZED", "SCIM connection is decommissioned")
}

func tryFenceActiveConnection(ctx context.Context, db adapter.Adapter, connectionID string) (*connectionBinding, error) {
	r, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: modelConnectionBinding,
		Where: []adapter.Where{
			w("connectionKey", CreateConnectionKey(connectionID)),
			w("connectionId", connectionID),
			w("decommissionStatus", decommissionActive),
		},
		Increment: map[string]float64{"decommissionRevision": 1}})
	if err != nil {
		return nil, err
	}
	return toBinding(r), nil
}

// ---- connection-authentication.ts ----

func requiredScope(path, method string) Scope {
	op := "write"
	if method == "GET" || method == "HEAD" {
		op = "read"
	}
	if strings.Contains(path, "/Groups") {
		return Scope("scim.groups." + op)
	}
	return Scope("scim.users." + op)
}

// isValidIdentifier is isValidSCIMConnectionIdentifier.
func isValidIdentifier(v string) bool {
	return len(v) > 0 && utf16Len(v) <= 255 && v == jsTrim(v)
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func areValidScopes(scopes []Scope) bool {
	if len(scopes) == 0 {
		return false
	}
	seen := map[Scope]bool{}
	for _, s := range scopes {
		if seen[s] {
			return false
		}
		seen[s] = true
		ok := false
		for _, c := range AllScopes {
			if c == s {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func validExpiry(t *time.Time) bool { return t == nil || !t.IsZero() }

func resolveVerifiedPrincipal(v *BearerTokenVerification, configured map[string]Connection) *Principal {
	if v == nil {
		return nil
	}
	hasID, hasConn := v.ConnectionID != nil, v.Connection != nil
	if hasID == hasConn {
		return nil
	}
	if !isValidIdentifier(v.CredentialID) || !areValidScopes(v.Scopes) || !validExpiry(v.ExpiresAt) {
		return nil
	}
	if v.ExpiresAt != nil && !v.ExpiresAt.After(time.Now()) {
		return nil
	}
	var conn *Connection
	if hasID {
		if isValidIdentifier(*v.ConnectionID) {
			if c, ok := configured[*v.ConnectionID]; ok {
				conn = &c
			}
		}
	} else {
		c := v.Connection
		_, collides := configured[c.ID]
		if isValidIdentifier(c.ID) && !strings.HasPrefix(c.ID, managedConnectionIDPrefix) &&
			isValidIdentifier(c.ProvisioningDomainID) && !collides {
			conn = &Connection{ID: c.ID, ProvisioningDomainID: c.ProvisioningDomainID}
		}
	}
	if conn == nil {
		return nil
	}
	p := &Principal{Type: PrincipalOAuthBearer, ConnectionID: conn.ID, ProvisioningDomainID: conn.ProvisioningDomainID,
		CredentialID: v.CredentialID, Scopes: v.Scopes}
	if v.ExpiresAt != nil {
		t := *v.ExpiresAt
		p.ExpiresAt = &t
	}
	return p
}

func bindConnection(ctx context.Context, db adapter.Adapter, conn Connection) (*connectionBinding, error) {
	return findOrCreateConnectionBinding(ctx, db, conn.ID, conn.ProvisioningDomainID, time.Now(),
		bindingInit{status: decommissionActive}, func(b *connectionBinding) error {
			if b.ConnectionID != conn.ID || b.ProvisioningDomainID != conn.ProvisioningDomainID {
				return scimErr("CONFLICT", "The connection provisioningDomainId changed after the connection was first used")
			}
			return nil
		})
}

var bearerPattern = regexp.MustCompile(`(?i)^Bearer\s+(.+)$`)

const (
	ctxConnectionKey = "scimConnection"
	ctxPrincipalKey  = "scimPrincipal"
)

// ConnectionFrom returns the authenticated SCIM connection of a request.
func ConnectionFrom(ctx *betterauth.EndpointContext) Connection {
	c, _ := ctx.Value(ctxConnectionKey).(Connection)
	return c
}

// PrincipalFrom returns the authenticated SCIM principal of a request.
func PrincipalFrom(ctx *betterauth.EndpointContext) *Principal {
	p, _ := ctx.Value(ctxPrincipalKey).(*Principal)
	return p
}

func (p *plugin) connectionMiddleware(ctx *betterauth.EndpointContext) error {
	authorization := ctx.GetHeader("Authorization")
	token := ""
	if m := bearerPattern.FindStringSubmatch(authorization); m != nil {
		token = m[1]
	}
	reject := func(detail string) error {
		ctx.SetHeader("WWW-Authenticate", `Bearer realm="SCIM"`)
		return scimErr("UNAUTHORIZED", detail)
	}
	if token == "" {
		return reject("SCIM bearer token is required")
	}
	var principal *Principal
	now := time.Now()
	for _, conn := range p.opts.Connections {
		for _, cred := range conn.Credentials {
			matches := bacrypto.ConstantTimeEqual([]byte(cred.Token), []byte(token))
			active := cred.ExpiresAt == nil || cred.ExpiresAt.After(now)
			if principal == nil && matches && active {
				domain := conn.ProvisioningDomainID
				if domain == "" {
					domain = conn.ID
				}
				scopes := cred.Scopes
				if scopes == nil {
					scopes = AllScopes
				}
				principal = &Principal{Type: PrincipalStaticBearer, ConnectionID: conn.ID, ProvisioningDomainID: domain,
					CredentialID: cred.ID, Scopes: scopes}
				if cred.ExpiresAt != nil {
					t := *cred.ExpiresAt
					principal.ExpiresAt = &t
				}
			}
		}
	}
	managedToken := isManagedBearerToken(token)
	if principal == nil && managedToken && p.managed != nil {
		pr, err := verifyManagedBearerToken(ctx.Context(), ctx.Auth.Adapter, token, p.managed)
		if err != nil {
			return err
		}
		principal = pr
	}
	if principal == nil && !managedToken && p.opts.Authentication != nil {
		headers := ctx.Headers.Clone()
		verified, err := p.opts.Authentication.VerifyBearerToken(BearerTokenVerificationInput{
			Token: token, Method: ctx.Method, Path: ctx.Path, Headers: headers,
		}, BearerTokenVerificationContext{Context: ctx.Context(), Database: findOneUpdater{ctx.Auth.Adapter}})
		if err != nil {
			return err
		}
		principal = resolveVerifiedPrincipal(verified, p.configured)
	}
	if principal == nil {
		return reject("Invalid SCIM bearer token")
	}
	scope := requiredScope(ctx.Path, ctx.Method)
	has := false
	for _, s := range principal.Scopes {
		if s == scope {
			has = true
		}
	}
	if !has {
		return scimErr("FORBIDDEN", "The SCIM bearer token is missing the "+string(scope)+" scope")
	}
	conn := Connection{ID: principal.ConnectionID, ProvisioningDomainID: principal.ProvisioningDomainID}
	binding, err := bindConnection(ctx.Context(), ctx.Auth.Adapter, conn)
	if err != nil {
		return err
	}
	if binding.DecommissionStatus != decommissionActive {
		return reject("SCIM connection is decommissioned")
	}
	ctx.Set(ctxConnectionKey, conn)
	ctx.Set(ctxPrincipalKey, principal)
	return nil
}

// findOneUpdater exposes only findOne and update to bearer token verifiers.
type findOneUpdater struct{ a adapter.Adapter }

func (f findOneUpdater) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	return f.a.FindOne(ctx, in)
}

func (f findOneUpdater) Update(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (adapter.Record, error) {
	return f.a.Update(ctx, model, where, update)
}
