package sso

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// routes/providers.ts

var adminRoles = []string{"owner", "admin"}

func hasOrgAdminRole(role string) bool {
	for _, r := range strings.Split(role, ",") {
		if inList(adminRoles, strings.TrimSpace(r)) {
			return true
		}
	}
	return false
}

// stableStringify is the order-insensitive serialization used for identity comparisons.
func stableStringify(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case undefinedT:
		return "undefined"
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = stableStringify(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case []string:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = stableStringify(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			kb, _ := jsonx.Marshal(k)
			parts[i] = string(kb) + ":" + stableStringify(t[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	b, err := jsonx.Marshal(v)
	if err != nil {
		return "undefined"
	}
	return string(b)
}

func identityValueChanged(a, b any) bool { return stableStringify(a) != stableStringify(b) }

func optStr(s string) any {
	if s == "" {
		return undefined
	}
	return s
}

func oidcIdentityBoundaryChanged(cur, upd *OIDCConfig) bool {
	pairs := [][2]string{
		{cur.AuthorizationEndpoint, upd.AuthorizationEndpoint}, {cur.ClientID, upd.ClientID},
		{cur.DiscoveryEndpoint, upd.DiscoveryEndpoint}, {cur.JwksEndpoint, upd.JwksEndpoint},
		{cur.TokenEndpoint, upd.TokenEndpoint}, {cur.UserInfoEndpoint, upd.UserInfoEndpoint},
	}
	for _, p := range pairs {
		if identityValueChanged(optStr(p[0]), optStr(p[1])) {
			return true
		}
	}
	return false
}

type samlBoundary struct {
	IdpEntityID          string
	IdpRedirectService   []string
	IdpPostService       []string
	SpEntityID           string
	SpNameIDFormat       string
	SpPostServices       []string
	WantAssertionsSigned bool
}

func (b samlBoundary) plain() map[string]any {
	svc := func(l []string) any {
		if len(l) == 1 {
			return l[0]
		}
		if len(l) == 0 {
			return undefined
		}
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out
	}
	spPost := make([]any, len(b.SpPostServices))
	for i, s := range b.SpPostServices {
		spPost[i] = s
	}
	return map[string]any{
		"idpEntityId": b.IdpEntityID, "idpRedirectService": svc(b.IdpRedirectService), "idpPostService": svc(b.IdpPostService),
		"spEntityId": b.SpEntityID, "spNameIDFormat": optStr(b.SpNameIDFormat), "spPostServices": spPost,
		"wantAssertionsSigned": b.WantAssertionsSigned,
	}
}

func samlIdentityBoundaryChanged(cur, upd *SAMLConfig) (bool, error) {
	curIdP, err := createIdP(cur)
	if err != nil {
		return false, err
	}
	updIdP, err := createIdP(upd)
	if err != nil {
		return false, err
	}
	parseSP := func(c *SAMLConfig) (*parsedSPMetadata, error) {
		if m := c.sp().Metadata; m != "" {
			return parseSAMLServiceProviderMetadata(m)
		}
		return nil, nil
	}
	curSP, err := parseSP(cur)
	if err != nil {
		return true, nil
	}
	updSP, err := parseSP(upd)
	if err != nil {
		return true, nil
	}
	boundary := func(c *SAMLConfig, idp *samlifyEntity, sp *parsedSPMetadata) samlBoundary {
		b := samlBoundary{
			IdpEntityID:        idp.Meta.GetEntityID(),
			IdpRedirectService: idp.Meta.GetSingleSignOnService("redirect"),
			IdpPostService:     idp.Meta.GetSingleSignOnService("post"),
		}
		if sp != nil {
			b.SpEntityID = sp.EntityID
			if len(sp.NameIDFormats) > 0 {
				b.SpNameIDFormat = sp.NameIDFormats[0]
			} else {
				b.SpNameIDFormat = c.IdentifierFormat
			}
			b.SpPostServices = getSAMLPostAssertionConsumerServiceURLs(c.sp().Metadata)
			b.WantAssertionsSigned = sp.WantAssertionsSigned
		} else {
			b.SpEntityID = c.sp().EntityID
			if b.SpEntityID == "" {
				b.SpEntityID = c.Issuer
			}
			b.SpNameIDFormat = c.IdentifierFormat
			if c.CallbackURL != "" {
				b.SpPostServices = []string{c.CallbackURL}
			}
			b.WantAssertionsSigned = isTrue(c.WantAssertionsSigned)
		}
		return b
	}
	trustAnchors := func(idp *samlifyEntity) []any {
		var certs []string
		for _, c := range idp.Meta.GetX509Certificates("signing") {
			certs = append(certs, normalizePem(c))
		}
		sort.Strings(certs)
		out := make([]any, len(certs))
		for i, c := range certs {
			out[i] = c
		}
		return out
	}
	if identityValueChanged(optStr(cur.Audience), optStr(upd.Audience)) || identityValueChanged(optStr(cur.CallbackURL), optStr(upd.CallbackURL)) {
		return true, nil
	}
	if identityValueChanged(trustAnchors(curIdP), trustAnchors(updIdP)) {
		return true, nil
	}
	return identityValueChanged(boundary(cur, curIdP, curSP).plain(), boundary(upd, updIdP, updSP).plain()), nil
}

func parseAndValidateConfig[T any](raw string, configType string) (*T, error) {
	c, err := safeJSONParse[T](raw)
	if err != nil || c == nil {
		return nil, badRequest("Cannot update " + configType + " config for a provider that doesn't have " + configType + " configured")
	}
	return c, nil
}

// providerSnapshot is a provider identity snapshot (ProviderIdentitySnapshot).
type providerSnapshot struct {
	ID         string
	ProviderID string
	Issuer     string
	OIDCConfig *OIDCConfig
	SAMLConfig *SAMLConfig
}

func snapshotFromRecord(r adapter.Record) (providerSnapshot, error) {
	s := providerSnapshot{ID: recString(r, "id"), ProviderID: recString(r, "providerId"), Issuer: recString(r, "issuer")}
	if raw := recString(r, "samlConfig"); raw != "" {
		c, err := parseAndValidateConfig[SAMLConfig](raw, "SAML")
		if err != nil {
			return s, err
		}
		s.SAMLConfig = c
	}
	if raw := recString(r, "oidcConfig"); raw != "" {
		c, err := parseAndValidateConfig[OIDCConfig](raw, "OIDC")
		if err != nil {
			return s, err
		}
		s.OIDCConfig = c
	}
	return s, nil
}

func ssoProviderIdentityBoundaryChanged(cur, upd providerSnapshot) (bool, error) {
	if cur.Issuer != upd.Issuer {
		return true, nil
	}
	if cur.SAMLConfig != nil {
		if upd.SAMLConfig == nil {
			return true, nil
		}
		changed, err := samlIdentityBoundaryChanged(cur.SAMLConfig, upd.SAMLConfig)
		if err != nil || changed {
			return changed, err
		}
	}
	if cur.OIDCConfig != nil {
		return upd.OIDCConfig == nil || oidcIdentityBoundaryChanged(cur.OIDCConfig, upd.OIDCConfig), nil
	}
	return false, nil
}

// lockSSOProviderRow takes a row lock by rewriting providerId (inside the transaction).
func lockSSOProviderRow(ctx context.Context, a adapter.Adapter, id, providerID string) (adapter.Record, error) {
	var where []adapter.Where
	if id != "" {
		where = append(where, adapter.Where{Field: "id", Value: id})
	}
	where = append(where, adapter.Where{Field: "providerId", Value: providerID})
	return a.Update(ctx, "ssoProvider", where, adapter.Record{"providerId": providerID})
}

func providerChangedError() *betterauth.APIError {
	return apiErr("CONFLICT", "code", "SSO_PROVIDER_CHANGED", "message", "SSO provider changed while account linking was in progress")
}

// lockSSOProviderForAccountLink locks a persisted provider and rejects authentication when
// its identity boundary changed.
func lockSSOProviderForAccountLink(ctx context.Context, a adapter.Adapter, p *SSOProvider) error {
	if p.ID == "" {
		return nil
	}
	locked, err := lockSSOProviderRow(ctx, a, p.ID, p.ProviderID)
	if err != nil {
		return err
	}
	if locked == nil {
		return providerChangedError()
	}
	lockedSnap, err := snapshotFromRecord(locked)
	if err != nil {
		return err
	}
	changed, err := ssoProviderIdentityBoundaryChanged(providerSnapshot{ID: p.ID, ProviderID: p.ProviderID, Issuer: p.Issuer, OIDCConfig: p.OIDCConfig, SAMLConfig: p.SAMLConfig}, lockedSnap)
	if err != nil {
		return err
	}
	if changed {
		return providerChangedError()
	}
	return nil
}

func guardSSOProviderMutation(ctx context.Context, o *Options, action string, boundary bool, rec adapter.Record, db adapter.Adapter, logger errorLogger) error {
	if o.GuardProviderMutation == nil {
		return nil
	}
	p, _, _ := providerFromRecord(rec)
	snap, err := snapshotFromRecord(rec)
	if err != nil {
		return err
	}
	p.OIDCConfig, p.SAMLConfig = snap.OIDCConfig, snap.SAMLConfig
	in := ProviderMutationGuardInput{Action: action, IsAuthenticationBoundaryChange: boundary && action == "update", ProviderReference: computeProviderReference(p)}
	in.Provider.ID = p.ID
	in.Provider.ProviderID = p.ProviderID
	if p.OrganizationID != "" {
		org := p.OrganizationID
		in.Provider.OrganizationID = &org
	}
	if gerr := callGuard(ctx, o, in, db); gerr != nil {
		safeLog(logger, "SSO provider mutation guard rejected the mutation")
		return apiErr("CONFLICT", "code", "SSO_PROVIDER_MUTATION_REJECTED", "message", "SSO provider mutation is not allowed")
	}
	return nil
}

func callGuard(ctx context.Context, o *Options, in ProviderMutationGuardInput, db adapter.Adapter) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errGuardPanic
		}
	}()
	return o.GuardProviderMutation(ctx, in, ProviderMutationGuardContext{Adapter: db})
}

type guardPanic struct{}

func (guardPanic) Error() string { return "guard panicked" }

var errGuardPanic error = guardPanic{}

func assertProviderMutationGuardCapabilities(ctx context.Context, o *Options, a adapter.Adapter) error {
	if o.GuardProviderMutation == nil {
		return nil
	}
	return assertNativeTransactionSupport(ctx, a, "SSO_PROVIDER_MUTATION_GUARD_REQUIRES_NATIVE_TRANSACTIONS",
		"SSO provider mutation guards require a database adapter with native transaction support")
}

// ---- output ----

func returnedAdditionalFields(o *Options, rec adapter.Record) *jsonx.Object {
	out := jsonx.NewObject()
	for _, f := range o.additionalFields() {
		if !f.IsReturned() {
			continue
		}
		if v, ok := rec[f.Name]; ok {
			out.Set(f.Name, v)
		}
	}
	return out
}

func sanitizeCerts(c *SAMLConfig) any {
	certs := resolveSigningCerts(c)
	if certs == nil && (c.IdpMetadata == nil || c.IdpMetadata.Cert == nil) && c.Cert == nil {
		return undefinedJSON
	}
	out := make([]any, len(certs))
	for i, cert := range certs {
		info, err := parseCertificate(cert)
		if err != nil {
			out[i] = jsonx.O("error", "Failed to parse certificate")
			continue
		}
		out[i] = jsonx.O("fingerprintSha256", info.FingerprintSha256, "notBefore", info.NotBefore, "notAfter", info.NotAfter, "publicKeyAlgorithm", info.PublicKeyAlgorithm)
	}
	return out
}

// undefinedJSON is dropped from jsonx objects.
var undefinedJSON = jsonx.Undefined

func setOpt(o *jsonx.Object, k, v string) {
	if v != "" {
		o.Set(k, v)
	}
}

func setOptBool(o *jsonx.Object, k string, v *bool) {
	if v != nil {
		o.Set(k, *v)
	}
}

// sanitizeProvider renders a provider without secrets (sanitizeProvider).
func sanitizeProvider(rec adapter.Record, baseURL string, o *Options) *jsonx.Object {
	var oidc *OIDCConfig
	var saml *SAMLConfig
	if c, err := safeJSONParse[OIDCConfig](recString(rec, "oidcConfig")); err == nil {
		oidc = c
	}
	if c, err := safeJSONParse[SAMLConfig](recString(rec, "samlConfig")); err == nil {
		saml = c
	}
	typ := "oidc"
	if saml != nil {
		typ = "saml"
	}
	out := returnedAdditionalFields(o, rec)
	pid := recString(rec, "providerId")
	out.Set("providerId", pid)
	out.Set("type", typ)
	out.Set("issuer", recString(rec, "issuer"))
	out.Set("domain", recString(rec, "domain"))
	if org := recString(rec, "organizationId"); org != "" {
		out.Set("organizationId", org)
	} else {
		out.Set("organizationId", nil)
	}
	dv, _ := rec["domainVerified"].(bool)
	out.Set("domainVerified", dv)
	if oidc != nil {
		oc := jsonx.NewObject()
		oc.Set("discoveryEndpoint", oidc.DiscoveryEndpoint)
		oc.Set("clientIdLastFour", maskClientID(oidc.ClientID))
		oc.Set("pkce", oidc.PKCE)
		setOpt(oc, "authorizationEndpoint", oidc.AuthorizationEndpoint)
		setOpt(oc, "tokenEndpoint", oidc.TokenEndpoint)
		setOpt(oc, "userInfoEndpoint", oidc.UserInfoEndpoint)
		setOpt(oc, "jwksEndpoint", oidc.JwksEndpoint)
		if oidc.Scopes != nil {
			oc.Set("scopes", oidc.Scopes)
		}
		setOpt(oc, "tokenEndpointAuthentication", oidc.TokenEndpointAuthentication)
		out.Set("oidcConfig", oc)
	}
	if saml != nil {
		sc := jsonx.NewObject()
		setOpt(sc, "entryPoint", saml.EntryPoint)
		setOpt(sc, "callbackUrl", saml.CallbackURL)
		setOpt(sc, "idpInitiatedCallbackUrl", saml.IdpInitiatedCallbackURL)
		setOpt(sc, "audience", saml.Audience)
		setOptBool(sc, "wantAssertionsSigned", saml.WantAssertionsSigned)
		setOptBool(sc, "authnRequestsSigned", saml.AuthnRequestsSigned)
		setOpt(sc, "identifierFormat", saml.IdentifierFormat)
		setOpt(sc, "signatureAlgorithm", saml.SignatureAlgorithm)
		setOpt(sc, "digestAlgorithm", saml.DigestAlgorithm)
		sc.Set("certificate", sanitizeCerts(saml))
		out.Set("samlConfig", sc)
	}
	out.Set("spMetadataUrl", baseURL+"/sso/saml2/sp/metadata?providerId="+betterauth.EncodeURIComponent(pid))
	return out
}

// checkProviderAccess loads a provider the session user may manage.
func checkProviderAccess(ctx *betterauth.EndpointContext, providerID string) (adapter.Record, error) {
	userID := ctx.Session.User.ID
	rec, err := findProviderRecord(ctx.Context(), ctx.Auth.Adapter, providerID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, apiErr("NOT_FOUND", "message", "Provider not found")
	}
	hasAccess := false
	if org := recString(rec, "organizationId"); org != "" {
		if ctx.Auth.HasPlugin("organization") {
			m, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "member", Where: []adapter.Where{
				{Field: "userId", Value: userID}, {Field: "organizationId", Value: org}}})
			if err != nil {
				return nil, err
			}
			hasAccess = m != nil && hasOrgAdminRole(recString(m, "role"))
		} else {
			hasAccess = recString(rec, "userId") == userID
		}
	} else {
		hasAccess = recString(rec, "userId") == userID
	}
	if !hasAccess {
		return nil, apiErr("FORBIDDEN", "message", "You don't have access to this provider")
	}
	return rec, nil
}

func (p *plugin) listSSOProviders() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listSSOProviders", Path: "/sso/providers", Methods: []string{"GET"},
		Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: endpointMeta("listSSOProviders", false),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			userID := ctx.Session.User.ID
			all, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "ssoProvider"})
			if err != nil {
				return nil, err
			}
			var accessible, orgProviders []adapter.Record
			for _, r := range all {
				org := r["organizationId"]
				if recString(r, "userId") == userID && (org == nil || org == "") {
					accessible = append(accessible, r)
				}
				if org != nil {
					orgProviders = append(orgProviders, r)
				}
			}
			orgPlugin := ctx.Auth.HasPlugin("organization")
			if orgPlugin && len(orgProviders) > 0 {
				seen := map[string]bool{}
				var ids []any
				for _, r := range orgProviders {
					if id := recString(r, "organizationId"); id != "" && !seen[id] {
						seen[id] = true
						ids = append(ids, id)
					}
				}
				admin := map[string]bool{}
				if len(ids) > 0 {
					members, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "member", Where: []adapter.Where{
						{Field: "userId", Value: userID}, {Field: "organizationId", Value: ids, Operator: adapter.In}}})
					if err != nil {
						return nil, err
					}
					for _, m := range members {
						if hasOrgAdminRole(recString(m, "role")) {
							admin[recString(m, "organizationId")] = true
						}
					}
				}
				for _, r := range orgProviders {
					if id := recString(r, "organizationId"); id != "" && admin[id] {
						accessible = append(accessible, r)
					}
				}
			} else if !orgPlugin {
				for _, r := range orgProviders {
					if recString(r, "userId") == userID {
						accessible = append(accessible, r)
					}
				}
			}
			list := make([]any, len(accessible))
			for i, r := range accessible {
				list[i] = sanitizeProvider(r, ctx.Auth.BaseURL, p.o)
			}
			return jsonx.O("providers", list), nil
		},
	}
}

func (p *plugin) getSSOProvider() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getSSOProvider", Path: "/sso/get-provider", Methods: []string{"GET"},
		Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: endpointMeta("getSSOProvider", false),
		Query: validate.Object(validate.F("providerId", validate.String())),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			rec, err := checkProviderAccess(ctx, ctx.QueryString("providerId"))
			if err != nil {
				return nil, err
			}
			return sanitizeProvider(rec, ctx.Auth.BaseURL, p.o), nil
		},
	}
}

// ---- update ----

func decodeInto[T any](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func mergeSAMLConfig(cur *SAMLConfig, upd map[string]any, issuer string) (*SAMLConfig, error) {
	out := *cur
	u, err := decodeInto[SAMLConfig](upd)
	if err != nil {
		return nil, err
	}
	out.Issuer = issuer
	if u.EntryPoint != "" {
		out.EntryPoint = u.EntryPoint
	}
	if u.Cert != nil {
		out.Cert = u.Cert
	}
	if _, ok := upd["spMetadata"]; ok && u.SpMetadata != nil {
		merged := cur.sp()
		m := *merged
		sm, _ := upd["spMetadata"].(map[string]any)
		mergeStructMap(&m, sm)
		out.SpMetadata = &m
	}
	if im, ok := upd["idpMetadata"].(map[string]any); ok {
		base := cur.idp()
		m := *base
		mergeStructMap(&m, im)
		cfg := &SAMLConfig{IdpMetadata: &m}
		if err := assertSAMLIdentityProviderAuthority(cfg); err != nil {
			return nil, err
		}
		out.IdpMetadata = &m
	}
	if u.Mapping != nil {
		out.Mapping = u.Mapping
	}
	if u.Audience != "" {
		out.Audience = u.Audience
	}
	if u.CallbackURL != "" {
		out.CallbackURL = u.CallbackURL
	}
	if v, ok := upd["idpInitiatedCallbackUrl"]; ok {
		if v == nil {
			out.IdpInitiatedCallbackURL = ""
		} else if s, ok := v.(string); ok {
			out.IdpInitiatedCallbackURL = s
		}
	}
	if u.WantAssertionsSigned != nil {
		out.WantAssertionsSigned = u.WantAssertionsSigned
	}
	if u.AuthnRequestsSigned != nil {
		out.AuthnRequestsSigned = u.AuthnRequestsSigned
	}
	if u.IdentifierFormat != "" {
		out.IdentifierFormat = u.IdentifierFormat
	}
	if u.SignatureAlgorithm != "" {
		out.SignatureAlgorithm = u.SignatureAlgorithm
	}
	if u.DigestAlgorithm != "" {
		out.DigestAlgorithm = u.DigestAlgorithm
	}
	if u.PrivateKey != "" {
		out.PrivateKey = u.PrivateKey
	}
	return &out, nil
}

// mergeStructMap applies the JSON keys of m onto dst ({...dst, ...m}).
func mergeStructMap(dst any, m map[string]any) {
	b, err := json.Marshal(dst)
	if err != nil {
		return
	}
	var base map[string]any
	_ = json.Unmarshal(b, &base)
	if base == nil {
		base = map[string]any{}
	}
	for k, v := range m {
		base[k] = v
	}
	nb, _ := json.Marshal(base)
	_ = json.Unmarshal(nb, dst)
}

func mergeOIDCConfig(cur *OIDCConfig, upd map[string]any, issuer string) (*OIDCConfig, error) {
	out := *cur
	mergeStructMap(&out, upd)
	out.Issuer = issuer
	if v, ok := upd["pkce"].(bool); ok {
		out.PKCE = v
	} else {
		out.PKCE = cur.PKCE
	}
	return &out, nil
}

func (p *plugin) updateSSOProvider() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "updateSSOProvider", Path: "/sso/update-provider", Methods: []string{"POST"},
		Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: endpointMeta("updateSSOProvider", false),
		Body: updateBodySchema(p.o),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			o := p.o
			body := ctx.BodyMap()
			providerID, _ := body["providerId"].(string)
			rest := map[string]any{}
			for k, v := range body {
				if k != "providerId" {
					rest[k] = v
				}
			}
			additional, err := parseAdditionalFields(o, rest, "update")
			if err != nil {
				return nil, err
			}
			issuer, hasIssuer := rest["issuer"].(string)
			domain, hasDomain := rest["domain"].(string)
			samlBody, hasSAML := rest["samlConfig"].(map[string]any)
			oidcBody, hasOIDC := rest["oidcConfig"].(map[string]any)
			if issuer == "" && domain == "" && !hasSAML && !hasOIDC && len(additional) == 0 {
				return nil, badRequest("No fields provided for update")
			}
			authorized, err := checkProviderAccess(ctx, providerID)
			if err != nil {
				return nil, err
			}
			a := ctx.Auth.Adapter
			if err := assertProviderMutationGuardCapabilities(ctx.Context(), o, a); err != nil {
				return nil, err
			}
			var full adapter.Record
			err = ctx.Auth.RunWithTransaction(ctx.Context(), func(tx context.Context) error {
				existing, err := lockSSOProviderRow(tx, a, recString(authorized, "id"), providerID)
				if err != nil {
					return err
				}
				if existing == nil {
					return apiErr("NOT_FOUND", "message", "Provider not found")
				}
				update := adapter.Record{}
				for k, v := range additional {
					update[k] = v
				}
				boundary := hasIssuer && issuer != recString(existing, "issuer")
				if hasIssuer {
					update["issuer"] = issuer
				}
				if hasDomain {
					update["domain"] = domain
					if domain != recString(existing, "domain") {
						update["domainVerified"] = false
					}
				}
				effectiveIssuer := func(cfgIssuer string) string {
					if s, ok := update["issuer"].(string); ok && s != "" {
						return s
					}
					if cfgIssuer != "" {
						return cfgIssuer
					}
					return recString(existing, "issuer")
				}
				if hasSAML {
					maxSize := o.saml().MaxMetadataSize
					if maxSize == 0 {
						maxSize = DefaultMaxSAMLMetadataSize
					}
					idpMeta, _ := samlBody["idpMetadata"].(map[string]any)
					spMeta, _ := samlBody["spMetadata"].(map[string]any)
					if s, _ := idpMeta["metadata"].(string); true {
						if err := assertSAMLMetadataSize(s, "IdP", maxSize); err != nil {
							return err
						}
					}
					if s, _ := spMeta["metadata"].(string); true {
						if err := assertSAMLMetadataSize(s, "SP", maxSize); err != nil {
							return err
						}
					}
					_, hasSig := samlBody["signatureAlgorithm"]
					_, hasDig := samlBody["digestAlgorithm"]
					if hasSig || hasDig {
						sig, _ := samlBody["signatureAlgorithm"].(string)
						dig, _ := samlBody["digestAlgorithm"].(string)
						if err := validateConfigAlgorithms(sig, dig, o.saml().Algorithms); err != nil {
							return err
						}
					}
					cur, err := parseAndValidateConfig[SAMLConfig](recString(existing, "samlConfig"), "SAML")
					if err != nil {
						return err
					}
					merged, err := mergeSAMLConfig(cur, samlBody, effectiveIssuer(cur.Issuer))
					if err != nil {
						return err
					}
					if err := validateCertSources(merged); err != nil {
						return err
					}
					if err := assertSAMLIdentityProviderAuthority(merged); err != nil {
						return err
					}
					if err := assertSAMLServiceProviderMetadataPolicy(merged); err != nil {
						return err
					}
					changed, err := samlIdentityBoundaryChanged(cur, merged)
					if err != nil {
						return err
					}
					if changed {
						boundary = true
					}
					update["samlConfig"] = mustJSON(merged)
				}
				if hasOIDC {
					urls := oidcEndpointURLs{}
					urls.AuthorizationEndpoint, _ = oidcBody["authorizationEndpoint"].(string)
					urls.TokenEndpoint, _ = oidcBody["tokenEndpoint"].(string)
					urls.UserInfoEndpoint, _ = oidcBody["userInfoEndpoint"].(string)
					urls.JwksEndpoint, _ = oidcBody["jwksEndpoint"].(string)
					urls.DiscoveryEndpoint, _ = oidcBody["discoveryEndpoint"].(string)
					if err := validateOIDCEndpointURLs(urls, func(u string) bool { return ctx.Auth.IsTrustedOrigin(u, false) }); err != nil {
						if de, ok := err.(*DiscoveryError); ok {
							return mapDiscoveryErrorToAPIError(de)
						}
						return err
					}
					cur, err := parseAndValidateConfig[OIDCConfig](recString(existing, "oidcConfig"), "OIDC")
					if err != nil {
						return err
					}
					merged, err := mergeOIDCConfig(cur, oidcBody, effectiveIssuer(cur.Issuer))
					if err != nil {
						return err
					}
					if merged.TokenEndpointAuthentication != "private_key_jwt" && merged.ClientSecret == "" {
						return badRequest("clientSecret is required when using client_secret_basic or client_secret_post authentication")
					}
					if merged.TokenEndpointAuthentication == "private_key_jwt" && o.ResolvePrivateKey == nil && !o.hasDefaultPrivateKey(providerID) {
						return badRequest("private_key_jwt authentication requires either a resolvePrivateKey callback or a privateKey in defaultSSO")
					}
					if oidcIdentityBoundaryChanged(cur, merged) {
						boundary = true
					}
					update["oidcConfig"] = mustJSON(merged)
				}
				if err := guardSSOProviderMutation(tx, o, "update", boundary, existing, a, ctx.Auth.Logger); err != nil {
					return err
				}
				if boundary {
					linked, err := a.FindOne(tx, adapter.FindOneInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: providerID}}})
					if err != nil {
						return err
					}
					if linked != nil {
						return apiErr("CONFLICT", "message", "Cannot change SSO provider identity fields while linked accounts exist")
					}
				}
				if _, err := a.Update(tx, "ssoProvider", []adapter.Where{{Field: "providerId", Value: providerID}}, update); err != nil {
					return err
				}
				updated, err := findProviderRecord(tx, a, providerID)
				if err != nil {
					return err
				}
				if updated == nil {
					return apiErr("NOT_FOUND", "message", "Provider not found after update")
				}
				full = updated
				return nil
			})
			if err != nil {
				return nil, err
			}
			return sanitizeProvider(full, ctx.Auth.BaseURL, o), nil
		},
	}
}

func (o *Options) hasDefaultPrivateKey(providerID string) bool {
	d := o.findDefault(providerID)
	return d != nil && d.PrivateKey != nil
}

func mustJSON(v any) string {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}

func (p *plugin) deleteSSOProvider() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "deleteSSOProvider", Path: "/sso/delete-provider", Methods: []string{"POST"},
		Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: endpointMeta("deleteSSOProvider", false),
		Body: validate.Object(validate.F("providerId", validate.String())),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			providerID := ctx.BodyString("providerId")
			authorized, err := checkProviderAccess(ctx, providerID)
			if err != nil {
				return nil, err
			}
			a := ctx.Auth.Adapter
			if err := assertProviderMutationGuardCapabilities(ctx.Context(), p.o, a); err != nil {
				return nil, err
			}
			err = ctx.Auth.RunWithTransaction(ctx.Context(), func(tx context.Context) error {
				existing, err := lockSSOProviderRow(tx, a, recString(authorized, "id"), providerID)
				if err != nil {
					return err
				}
				if existing == nil {
					return apiErr("NOT_FOUND", "message", "Provider not found")
				}
				if err := guardSSOProviderMutation(tx, p.o, "delete", false, existing, a, ctx.Auth.Logger); err != nil {
					return err
				}
				if _, err := a.DeleteMany(tx, "account", []adapter.Where{{Field: "providerId", Value: providerID}}); err != nil {
					return err
				}
				return a.Delete(tx, "ssoProvider", []adapter.Where{{Field: "id", Value: recString(existing, "id")}, {Field: "providerId", Value: providerID}})
			})
			if err != nil {
				return nil, err
			}
			return jsonx.O("success", true), nil
		},
	}
}
