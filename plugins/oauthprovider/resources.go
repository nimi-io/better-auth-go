package oauthprovider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of packages/oauth-provider/src/resources.ts (RFC 8707 resource indicators).

// JWSAlgorithms are the signing algorithms a resource may pin.
var JWSAlgorithms = []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"}

const maxAudValues = 64

// Resource is an oauthResource row (OAuthResource).
type Resource struct {
	ID                            string
	Identifier                    string
	Name                          string
	AccessTokenTTL                *float64
	RefreshTokenTTL               *float64
	SigningAlgorithm              string
	SigningKeyID                  string
	AllowedScopes                 []string
	CustomClaims                  *jsonx.Object
	DPoPBoundAccessTokensRequired bool
	Disabled                      bool
	Record                        adapter.Record
}

func resourceFromRecord(r adapter.Record) *Resource {
	if r == nil {
		return nil
	}
	res := &Resource{ID: recStr(r, "id"), Identifier: recStr(r, "identifier"), Name: recStr(r, "name"),
		SigningAlgorithm: recStr(r, "signingAlgorithm"), SigningKeyID: recStr(r, "signingKeyId"),
		AllowedScopes: recStrings(r, "allowedScopes"), Record: r}
	if v, ok := adapter.ToFloat(r["accessTokenTtl"]); ok && r["accessTokenTtl"] != nil {
		res.AccessTokenTTL = &v
	}
	if v, ok := adapter.ToFloat(r["refreshTokenTtl"]); ok && r["refreshTokenTtl"] != nil {
		res.RefreshTokenTTL = &v
	}
	if v := r["customClaims"]; v != nil {
		res.CustomClaims = toObject(v)
	}
	if b := recBool(r, "dpopBoundAccessTokensRequired"); b != nil {
		res.DPoPBoundAccessTokensRequired = *b
	}
	if b := recBool(r, "disabled"); b != nil {
		res.Disabled = *b
	}
	return res
}

func checkIdentifier(o *resolved, identifier string) (bool, string, error) {
	if o.IdentifierValidator != nil {
		ok, err := o.IdentifierValidator(identifier)
		if err != nil {
			return false, "", err
		}
		if !ok {
			return false, fmt.Sprintf("resource identifier %s failed validation", identifier), nil
		}
		return true, "", nil
	}
	u, err := parseURL(identifier)
	if err != nil {
		return false, fmt.Sprintf("resource identifier %s must be an absolute URI (RFC 8707 §2)", identifier), nil
	}
	if u.Fragment != "" {
		return false, fmt.Sprintf("resource identifier %s must not contain a URI fragment (RFC 8707 §2)", identifier), nil
	}
	return true, "", nil
}

func assertIdentifierValid(o *resolved, identifier string) error {
	ok, reason, err := checkIdentifier(o, identifier)
	if err != nil {
		return err
	}
	if !ok {
		return oauthErr("BAD_REQUEST", "invalid_target", reason)
	}
	return nil
}

// resourcePolicy is ResolvedResourcePolicy.
type resourcePolicy struct {
	audience                      []string
	accessTokenTTL                *float64
	refreshTokenTTL               *float64
	signingAlgorithm              string
	signingKeyID                  string
	rawCustomClaims               *jsonx.Object
	dpopBoundAccessTokensRequired bool
	effectiveScopes               []string
}

// extractRepeatedResourceFromForm returns all non-empty resource values of a urlencoded
// body (nil when none).
func extractRepeatedResourceFromForm(ctx *betterauth.EndpointContext) []string {
	form := requestForm(ctx)
	if form == nil {
		return nil
	}
	var out []string
	for _, v := range form.getAll("resource") {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func normalizeResourceParam(resource any) []string {
	switch t := resource.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case []string:
		var out []string
		for _, s := range t {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// isAudienceClaimAllowed reports whether every audience is a configured resource (or one
// of the implicit audiences).
func isAudienceClaimAllowed(ctx *betterauth.EndpointContext, o *resolved, aud any, implicit []string) (bool, error) {
	var values []string
	switch t := aud.(type) {
	case nil:
		return true, nil
	case string:
		values = []string{t}
	case []string:
		values = t
	case []any:
		for _, x := range t {
			s, _ := x.(string)
			values = append(values, s)
		}
	default:
		if isUndef(aud) {
			return true, nil
		}
	}
	if len(values) > maxAudValues {
		return false, nil
	}
	for _, v := range uniqueStrings(values) {
		if contains(implicit, v) {
			continue
		}
		r, err := getResource(ctx, o, v)
		if err != nil {
			return false, err
		}
		if r == nil {
			return false, nil
		}
	}
	return true, nil
}

func resolveEnforcePerClient(o *resolved) (bool, string) {
	if o.EnforcePerClientResources != nil {
		return *o.EnforcePerClientResources, "explicit"
	}
	return true, "default"
}

// resolveResourcePolicy validates requested resources and merges their policies.
func resolveResourcePolicy(ctx *betterauth.EndpointContext, o *resolved, resource any, clientID string, requestedScopes []string) (*resourcePolicy, error) {
	requested := normalizeResourceParam(resource)
	includesOpenID := contains(requestedScopes, "openid")
	userInfo := ctx.Auth.BaseURL + "/oauth2/userinfo"
	if len(requested) == 0 {
		return &resourcePolicy{rawCustomClaims: jsonx.NewObject(), effectiveScopes: append([]string{}, requestedScopes...)}, nil
	}
	unique := uniqueStrings(requested)
	var rows []*Resource
	for _, id := range unique {
		if id == userInfo {
			continue
		}
		r, err := getResource(ctx, o, id)
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, oauthErr("BAD_REQUEST", "invalid_target", fmt.Sprintf("requested resource %s is not configured", id))
		}
		if r.Disabled {
			return nil, oauthErr("BAD_REQUEST", "invalid_target", fmt.Sprintf("requested resource %s is disabled", id))
		}
		rows = append(rows, r)
	}
	if enforce, _ := resolveEnforcePerClient(o); enforce && len(rows) > 0 {
		if err := assertClientLinkedToResources(ctx, o, clientID, rows); err != nil {
			return nil, err
		}
	}
	effective := append([]string{}, requestedScopes...)
	for _, r := range rows {
		if r.AllowedScopes == nil {
			continue
		}
		var inter []string
		for _, s := range effective {
			if contains(r.AllowedScopes, s) {
				inter = append(inter, s)
			}
		}
		if len(inter) == 0 {
			return nil, oauthErr("BAD_REQUEST", "invalid_scope", "none of the requested scopes are allowed for resource "+r.Identifier)
		}
		effective = inter
	}
	p := &resourcePolicy{rawCustomClaims: jsonx.NewObject(), effectiveScopes: effective}
	for _, r := range rows {
		if r.AccessTokenTTL != nil && (p.accessTokenTTL == nil || *r.AccessTokenTTL < *p.accessTokenTTL) {
			v := *r.AccessTokenTTL
			p.accessTokenTTL = &v
		}
		if r.RefreshTokenTTL != nil && (p.refreshTokenTTL == nil || *r.RefreshTokenTTL < *p.refreshTokenTTL) {
			v := *r.RefreshTokenTTL
			p.refreshTokenTTL = &v
		}
	}
	var algs, kids []string
	for _, r := range rows {
		if r.SigningAlgorithm != "" {
			algs = append(algs, r.SigningAlgorithm)
		}
		if r.SigningKeyID != "" {
			kids = append(kids, r.SigningKeyID)
		}
	}
	algs, kids = uniqueStrings(algs), uniqueStrings(kids)
	if len(algs) > 1 {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "multi-resource request has conflicting signingAlgorithm pins; a single JWS signature cannot satisfy multiple algorithms")
	}
	if len(kids) > 1 {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "multi-resource request has conflicting signingKeyId pins; a single JWS signature cannot satisfy multiple key ids")
	}
	if len(algs) == 1 {
		p.signingAlgorithm = algs[0]
	}
	if len(kids) == 1 {
		p.signingKeyID = kids[0]
	}
	for _, r := range rows {
		mergeInto(p.rawCustomClaims, r.CustomClaims)
		if r.DPoPBoundAccessTokensRequired {
			p.dpopBoundAccessTokensRequired = true
		}
	}
	aud := unique
	if includesOpenID {
		aud = append(append([]string{}, unique...), userInfo)
	}
	p.audience = uniqueStrings(aud)
	return p, nil
}

func linkModel(o *resolved) string { return modelClientResource }

func assertClientLinkedToResources(ctx *betterauth.EndpointContext, o *resolved, clientID string, rows []*Resource) error {
	links, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelClientResource,
		Where: []adapter.Where{{Field: "clientId", Value: clientID}}})
	if err != nil {
		return err
	}
	linked := map[string]bool{}
	for _, l := range links {
		linked[recStr(l, "resourceId")] = true
	}
	var unlinked []string
	for _, r := range rows {
		if !linked[r.Identifier] {
			unlinked = append(unlinked, r.Identifier)
		}
	}
	if len(unlinked) > 0 {
		return oauthErr("BAD_REQUEST", "invalid_target", fmt.Sprintf("client %s is not linked to resource(s) %s", clientID, strings.Join(unlinked, ", ")))
	}
	return nil
}

func isClientLinkedToAnyResource(ctx *betterauth.EndpointContext, clientID string, ids []string) (bool, error) {
	if len(ids) == 0 {
		return false, nil
	}
	links, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelClientResource,
		Where: []adapter.Where{{Field: "clientId", Value: clientID}, {Field: "resourceId", Operator: adapter.In, Value: stringsToAny(ids)}},
		Limit: 1})
	if err != nil {
		return false, err
	}
	return len(links) > 0, nil
}

func getResourceCustomClaims(ctx *betterauth.EndpointContext, ids []string) (*jsonx.Object, error) {
	merged := jsonx.NewObject()
	if len(ids) == 0 {
		return merged, nil
	}
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelResource,
		Where: []adapter.Where{{Field: "identifier", Operator: adapter.In, Value: stringsToAny(ids)}}})
	if err != nil {
		return nil, err
	}
	byID := map[string]*Resource{}
	for _, r := range rows {
		res := resourceFromRecord(r)
		byID[res.Identifier] = res
	}
	for _, id := range ids {
		if r := byID[id]; r != nil {
			mergeInto(merged, r.CustomClaims)
		}
	}
	return merged, nil
}

// ---- cache & seeding ----

type resourceCache struct {
	mu sync.Mutex
	m  map[string]adapter.Record
}

func (c *resourceCache) get(id string) adapter.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[id]
}

func (c *resourceCache) set(id string, r adapter.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]adapter.Record{}
	}
	c.m[id] = r
}

func (c *resourceCache) invalidate(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == "" {
		c.m = nil
		return
	}
	delete(c.m, id)
}

func copyRecord(r adapter.Record) adapter.Record {
	out := adapter.Record{}
	for k, v := range r {
		out[k] = v
	}
	return out
}

func getResource(ctx *betterauth.EndpointContext, o *resolved, identifier string) (*Resource, error) {
	if err := seedResourcesOnce(ctx.Context(), ctx.Auth, o); err != nil {
		return nil, err
	}
	if o.cachedResources[identifier] {
		if c := o.resourceCache.get(identifier); c != nil {
			return resourceFromRecord(copyRecord(c)), nil
		}
	}
	r, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelResource,
		Where: []adapter.Where{{Field: "identifier", Value: identifier}}})
	if err != nil {
		return nil, err
	}
	if r != nil && o.cachedResources[identifier] {
		o.resourceCache.set(identifier, copyRecord(r))
	}
	return resourceFromRecord(r), nil
}

func optionalOr(v any, ok bool) any {
	if !ok {
		return nil
	}
	return v
}

func buildResourceRow(in ResourceInput, now time.Time) adapter.Record {
	name := in.Identifier
	if in.Name != nil {
		name = *in.Name
	}
	r := adapter.Record{"identifier": in.Identifier, "name": name}
	r["accessTokenTtl"] = nilIntPtr(in.AccessTokenTTL)
	r["refreshTokenTtl"] = nilIntPtr(in.RefreshTokenTTL)
	r["signingAlgorithm"] = nilStrPtr(in.SigningAlgorithm)
	r["signingKeyId"] = nilStrPtr(in.SigningKeyID)
	if in.AllowedScopes != nil {
		r["allowedScopes"] = stringsToAny(in.AllowedScopes)
	} else {
		r["allowedScopes"] = nil
	}
	if in.CustomClaims != nil {
		r["customClaims"] = in.CustomClaims
	} else {
		r["customClaims"] = nil
	}
	r["dpopBoundAccessTokensRequired"] = in.DPoPBoundAccessTokensRequired != nil && *in.DPoPBoundAccessTokensRequired
	r["disabled"] = in.Disabled != nil && *in.Disabled
	r["policyVersion"] = 1
	if in.Metadata != nil {
		r["metadata"] = in.Metadata
	} else {
		r["metadata"] = nil
	}
	r["createdAt"] = now
	r["updatedAt"] = now
	return r
}

func nilIntPtr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func nilStrPtr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func buildSeedUpdate(in ResourceInput, mode string, now time.Time) adapter.Record {
	if mode == "overwrite" {
		r := buildResourceRow(in, now)
		delete(r, "identifier")
		delete(r, "createdAt")
		return r
	}
	u := adapter.Record{"updatedAt": now}
	if in.Name != nil {
		u["name"] = *in.Name
	}
	if in.AccessTokenTTL != nil {
		u["accessTokenTtl"] = *in.AccessTokenTTL
	}
	if in.RefreshTokenTTL != nil {
		u["refreshTokenTtl"] = *in.RefreshTokenTTL
	}
	if in.SigningAlgorithm != nil {
		u["signingAlgorithm"] = *in.SigningAlgorithm
	}
	if in.SigningKeyID != nil {
		u["signingKeyId"] = *in.SigningKeyID
	}
	if in.AllowedScopes != nil {
		u["allowedScopes"] = stringsToAny(in.AllowedScopes)
	}
	if in.CustomClaims != nil {
		u["customClaims"] = in.CustomClaims
	}
	if in.DPoPBoundAccessTokensRequired != nil {
		u["dpopBoundAccessTokensRequired"] = *in.DPoPBoundAccessTokensRequired
	}
	if in.Disabled != nil {
		u["disabled"] = *in.Disabled
	}
	if in.Metadata != nil {
		u["metadata"] = in.Metadata
	}
	return u
}

var (
	missingTableRe = regexp.MustCompile(`(?i)no such table|relation.*does not exist|table.*does(?: not|n['']?t) exist`)
	uniqueRe       = regexp.MustCompile(`(?i)unique|duplicate|UNIQUE`)
)

type seedState struct {
	mu        sync.Mutex
	completed map[adapter.Adapter]bool
}

// seedResources inserts / updates the configured resources.
func seedResources(c context.Context, ac *betterauth.AuthContext, o *resolved) error {
	if len(o.Resources) == 0 {
		return nil
	}
	mode := o.ResourceSeedMode
	if mode == "" {
		mode = "insertOnly"
	}
	log := ac.Logger
	for _, raw := range o.Resources {
		ok, reason, err := checkIdentifier(o, raw.Identifier)
		if err != nil {
			return err
		}
		if !ok {
			log.Warn(fmt.Sprintf("oauth-provider: skipping resource seed for %s — %s", raw.Identifier, reason))
			continue
		}
		in := raw
		if in.SigningAlgorithm != nil && !contains(JWSAlgorithms, *in.SigningAlgorithm) {
			log.Warn(fmt.Sprintf("oauth-provider: dropping unsupported signingAlgorithm \"%s\" for resource %s — must be one of %s. Continuing without an algorithm override.",
				*in.SigningAlgorithm, in.Identifier, strings.Join(JWSAlgorithms, ", ")))
			in.SigningAlgorithm = nil
		}
		existing, err := ac.Adapter.FindOne(c, adapter.FindOneInput{Model: modelResource,
			Where: []adapter.Where{{Field: "identifier", Value: in.Identifier}}})
		if err != nil {
			if missingTableRe.MatchString(err.Error()) {
				log.Debug("oauth-provider: oauthResource table not yet created; deferring resource seed to first access.")
				return errSeedDeferred
			}
			return err
		}
		now := time.Now()
		if existing == nil {
			if _, err := ac.Adapter.Create(c, adapter.CreateInput{Model: modelResource, Data: buildResourceRow(in, now)}); err != nil {
				if uniqueRe.MatchString(err.Error()) {
					log.Debug(fmt.Sprintf("oauth-provider: resource %s already inserted by a concurrent process — skipping.", in.Identifier))
					continue
				}
				if missingTableRe.MatchString(err.Error()) {
					log.Debug("oauth-provider: oauthResource table not yet created; deferring resource seed to first access.")
					return errSeedDeferred
				}
				return err
			}
			continue
		}
		if mode == "insertOnly" {
			continue
		}
		if _, err := ac.Adapter.Update(c, modelResource, []adapter.Where{{Field: "identifier", Value: in.Identifier}},
			buildSeedUpdate(in, mode, now)); err != nil {
			return err
		}
	}
	return nil
}

// errSeedDeferred reports that the resource table does not exist yet. Upstream returns
// without error and marks seeding complete.
var errSeedDeferred = fmt.Errorf("seed deferred")

func seedResourcesOnce(c context.Context, ac *betterauth.AuthContext, o *resolved) error {
	o.seed.mu.Lock()
	defer o.seed.mu.Unlock()
	if o.seed.completed == nil {
		o.seed.completed = map[adapter.Adapter]bool{}
	}
	key := ac.Adapter
	if o.seed.completed[key] {
		return nil
	}
	err := seedResources(c, ac, o)
	if err == errSeedDeferred {
		err = nil
	}
	if err != nil {
		return err
	}
	o.seed.completed[key] = true
	return nil
}

// ResetSeedStateForTests forgets which adapters have been seeded (resetSeedStateForTests).
func ResetSeedStateForTests(p *betterauth.Plugin) {
	if o, ok := p.Options.(*resolved); ok {
		o.seed.mu.Lock()
		o.seed.completed = nil
		o.seed.mu.Unlock()
	}
}
