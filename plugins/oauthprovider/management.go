package oauthprovider

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Ports of oauthClient/endpoints.ts, oauthConsent/endpoints.ts and
// oauthResource/endpoints.ts.

// recordObject renders an adapter row in the TypeScript adapter key order (schema field
// order, then id; unknown keys sorted).
func recordObject(ctx *betterauth.EndpointContext, model string, rec adapter.Record) *jsonx.Object {
	if rec == nil {
		return nil
	}
	o := jsonx.NewObject()
	seen := map[string]bool{"id": true}
	if t := ctx.Auth.Tables.Table(model); t != nil {
		for _, fl := range t.Fields {
			seen[fl.Name] = true
			// SQL adapters return every column; absent values render as null.
			o.Set(fl.Name, normalizeJSON(rec[fl.Name]))
		}
	}
	if v, ok := rec["id"]; ok {
		o.Set("id", v)
	}
	var rest []string
	for k := range rec {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		o.Set(k, normalizeJSON(rec[k]))
	}
	return o
}

func notFound(desc string) error { return oauthErr("NOT_FOUND", "not_found", desc) }

func (o *resolved) clientReferenceFor(ctx *betterauth.EndpointContext, s *betterauth.SessionWithUser) (string, error) {
	if o.ClientReference == nil {
		return "", nil
	}
	return o.ClientReference(UserSessionContext{Ctx: ctx, Headers: ctx.Headers, User: s.User, Session: s.Session})
}

func assertOwnsClient(ctx *betterauth.EndpointContext, o *resolved, s *betterauth.SessionWithUser, c *SchemaClient) error {
	switch {
	case c.UserID != "":
		if c.UserID != s.User.ID {
			return apiErr("UNAUTHORIZED")
		}
	case c.ReferenceID != "" && o.ClientReference != nil:
		ref, err := o.clientReferenceFor(ctx, s)
		if err != nil {
			return err
		}
		if c.ReferenceID != ref {
			return apiErr("UNAUTHORIZED")
		}
	default:
		return apiErr("UNAUTHORIZED")
	}
	return nil
}

func sessionWithPrivileges(ctx *betterauth.EndpointContext, o *resolved, action string) (*betterauth.SessionWithUser, error) {
	s, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err := assertClientPrivileges(ctx, s, o, action); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, apiErr("UNAUTHORIZED")
	}
	return s, nil
}

func withoutSecret(c *SchemaClient) *jsonx.Object {
	out := SchemaToOAuth(c)
	out.Set("client_secret", jsonx.Undefined)
	return out
}

func getClientEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	s, err := sessionWithPrivileges(ctx, o, "read")
	if err != nil {
		return nil, err
	}
	c, err := getClient(ctx, o, ctx.QueryString("client_id"))
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, notFound("client not found")
	}
	if err := assertOwnsClient(ctx, o, s, c); err != nil {
		return nil, err
	}
	return withoutSecret(c), nil
}

func getClientPublicEndpoint(ctx *betterauth.EndpointContext, o *resolved, clientID string) (any, error) {
	c, err := getClient(ctx, o, clientID)
	if err != nil {
		return nil, err
	}
	if c == nil || c.IsDisabled() {
		return nil, notFound("client not found")
	}
	return SchemaToOAuth(&SchemaClient{ClientID: c.ClientID, Name: c.Name, URI: c.URI, Contacts: c.Contacts,
		Icon: c.Icon, Tos: c.Tos, Policy: c.Policy}), nil
}

func getClientsEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	s, err := sessionWithPrivileges(ctx, o, "list")
	if err != nil {
		return nil, err
	}
	ref, err := o.clientReferenceFor(ctx, s)
	if err != nil {
		return nil, err
	}
	var where []adapter.Where
	switch {
	case ref != "":
		where = []adapter.Where{{Field: "referenceId", Value: ref}}
	case s.User.ID != "":
		where = []adapter.Where{{Field: "userId", Value: s.User.ID}}
	default:
		return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("message", "either user_id or reference_id must be provided"))
	}
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelClient, Where: where})
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range rows {
		out = append(out, withoutSecret(ClientFromRecord(r)))
	}
	return out, nil
}

func trustedClientError() error {
	return oauthErr("INTERNAL_SERVER_ERROR", "invalid_client", "trusted clients must be updated manually")
}

func deleteClientEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	s, err := sessionWithPrivileges(ctx, o, "delete")
	if err != nil {
		return nil, err
	}
	clientID := bodyStr(ctx, "client_id")
	if o.cachedTrusted[clientID] {
		return nil, trustedClientError()
	}
	c, err := getClient(ctx, o, clientID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, notFound("client not found")
	}
	if err := assertOwnsClient(ctx, o, s, c); err != nil {
		return nil, err
	}
	if err := ctx.Auth.Adapter.Delete(ctx.Context(), modelClient, []adapter.Where{{Field: "clientId", Value: clientID}}); err != nil {
		return nil, err
	}
	return betterauth.NoContent, nil
}

func secondsNow() time.Time { return time.Unix(time.Now().Unix(), 0) }

func updateClientEndpoint(ctx *betterauth.EndpointContext, o *resolved, admin bool) (any, error) {
	s, err := sessionWithPrivileges(ctx, o, "update")
	if err != nil {
		return nil, err
	}
	body := bodyMap(ctx)
	clientID, _ := body["client_id"].(string)
	if o.cachedTrusted[clientID] {
		return nil, trustedClientError()
	}
	c, err := getClient(ctx, o, clientID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, notFound("client not found")
	}
	updates := mapToObjectOrdered(body["update"])
	rawCC, hasCC := updates.Get("client_credentials_scopes")
	updates.Delete("client_credentials_scopes")
	owns := false
	switch {
	case c.UserID != "":
		owns = c.UserID == s.User.ID
	case c.ReferenceID != "" && o.ClientReference != nil:
		ref, err := o.clientReferenceFor(ctx, s)
		if err != nil {
			return nil, err
		}
		owns = c.ReferenceID == ref
	}
	crossOwner := !owns && admin && hasCC && updates.Len() == 0
	if !owns && !crossOwner {
		return nil, apiErr("UNAUTHORIZED")
	}
	if crossOwner {
		if err := assertClientPrivileges(ctx, s, o, "configure-client-credentials-scopes"); err != nil {
			return nil, err
		}
	}
	render := func(cl *SchemaClient) *jsonx.Object {
		out := withoutSecret(cl)
		if admin {
			out.Set("client_credentials_scopes", stringsToAny(nonNil(cl.ClientCredentialsScopes)))
		}
		return out
	}
	if updates.Len() == 0 && !hasCC {
		return render(c), nil
	}
	finalGrants := mdStrings(updates, "grant_types")
	if finalGrants == nil {
		finalGrants = nonNil(c.GrantTypes)
	}
	finalMethod := mdStr(updates, "token_endpoint_auth_method")
	if finalMethod == "" {
		finalMethod = c.TokenEndpointAuthMethod
	}
	var ccScopes []string
	if hasCC {
		ccScopes = normalizeClientCredentialsScopes(toStrings(rawCC))
		if err := validateClientCredentialsScopes(ccScopes, finalGrants, finalMethod, o); err != nil {
			return nil, err
		}
		if len(ccScopes) > 0 && !crossOwner {
			if err := assertClientPrivileges(ctx, s, o, "configure-client-credentials-scopes"); err != nil {
				return nil, err
			}
		}
	}
	merged := SchemaToOAuth(c)
	mergeInto(merged, updates)
	if err := checkOAuthClient(merged, o, checkSettings{ctx: ctx}); err != nil {
		return nil, err
	}
	upd := oauthToSchema(updates).ToRecord()
	if !contains(finalGrants, "client_credentials") || finalMethod == "none" {
		upd["clientCredentialsScopes"] = []any{}
	} else if hasCC {
		upd["clientCredentialsScopes"] = stringsToAny(ccScopes)
	}
	if m := mdStr(updates, "token_endpoint_auth_method"); m != "" {
		if m == "private_key_jwt" {
			upd["clientSecret"] = nil
		} else {
			upd["jwks"] = nil
			upd["jwksUri"] = nil
			if v, _ := upd["clientSecret"].(string); v == "" {
				raw := ""
				if o.GenerateClientSecret != nil {
					raw = o.GenerateClientSecret()
				}
				if raw == "" {
					raw = bacrypto.RandomString(32, "a-z", "A-Z")
				}
				stored, err := storeClientSecret(ctx, o, raw)
				if err != nil {
					return nil, err
				}
				upd["clientSecret"] = stored
			}
		}
	}
	upd["updatedAt"] = secondsNow()
	r, err := ctx.Auth.Adapter.Update(ctx.Context(), modelClient, []adapter.Where{{Field: "clientId", Value: clientID}}, upd)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, oauthErr("INTERNAL_SERVER_ERROR", "invalid_client", "unable to update client")
	}
	return render(ClientFromRecord(r)), nil
}

func rotateClientSecretEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	s, err := sessionWithPrivileges(ctx, o, "rotate")
	if err != nil {
		return nil, err
	}
	clientID := bodyStr(ctx, "client_id")
	if o.cachedTrusted[clientID] {
		return nil, trustedClientError()
	}
	c, err := getClient(ctx, o, clientID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, notFound("client not found")
	}
	if err := assertOwnsClient(ctx, o, s, c); err != nil {
		return nil, err
	}
	if c.TokenEndpointAuthMethod == "none" || c.ClientSecret == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_client", "secret rotation is only available for clients using client_secret authentication")
	}
	secret := ""
	if o.GenerateClientSecret != nil {
		secret = o.GenerateClientSecret()
	}
	if secret == "" {
		secret = bacrypto.RandomString(32, "a-z", "A-Z")
	}
	stored, err := storeClientSecret(ctx, o, secret)
	if err != nil {
		return nil, err
	}
	r, err := ctx.Auth.Adapter.Update(ctx.Context(), modelClient, []adapter.Where{{Field: "clientId", Value: clientID}},
		adapter.Record{"clientSecret": stored, "updatedAt": secondsNow()})
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, oauthErr("INTERNAL_SERVER_ERROR", "invalid_client", "unable to update client")
	}
	updated := ClientFromRecord(r)
	updated.ClientSecret = o.prefix().ClientSecret + secret
	return SchemaToOAuth(updated), nil
}

// ---- consents ----

func consentByID(ctx *betterauth.EndpointContext, id string) (adapter.Record, error) {
	return ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelConsent,
		Where: []adapter.Where{{Field: "id", Value: id}}})
}

func ownedConsent(ctx *betterauth.EndpointContext, id string) (*betterauth.SessionWithUser, adapter.Record, error) {
	s, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	if s == nil {
		return nil, nil, apiErr("UNAUTHORIZED")
	}
	if id == "" {
		return nil, nil, notFound("missing id parameter")
	}
	r, err := consentByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if r == nil {
		return nil, nil, notFound("no consent")
	}
	if recStr(r, "userId") != s.User.ID {
		return nil, nil, apiErr("UNAUTHORIZED")
	}
	return s, r, nil
}

func getConsentEndpoint(ctx *betterauth.EndpointContext) (any, error) {
	_, r, err := ownedConsent(ctx, ctx.QueryString("id"))
	if err != nil {
		return nil, err
	}
	return recordObject(ctx, modelConsent, r), nil
}

func getConsentsEndpoint(ctx *betterauth.EndpointContext) (any, error) {
	s, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, apiErr("UNAUTHORIZED")
	}
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelConsent,
		Where: []adapter.Where{{Field: "userId", Value: s.User.ID}}})
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range rows {
		out = append(out, recordObject(ctx, modelConsent, r))
	}
	return out, nil
}

func deleteConsentEndpoint(ctx *betterauth.EndpointContext) (any, error) {
	id := bodyStr(ctx, "id")
	if _, _, err := ownedConsent(ctx, id); err != nil {
		return nil, err
	}
	if err := ctx.Auth.Adapter.Delete(ctx.Context(), modelConsent, []adapter.Where{{Field: "id", Value: id}}); err != nil {
		return nil, err
	}
	return betterauth.NoContent, nil
}

func updateConsentEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	id := bodyStr(ctx, "id")
	_, r, err := ownedConsent(ctx, id)
	if err != nil {
		return nil, err
	}
	c, err := getClient(ctx, o, recStr(r, "clientId"))
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, notFound("client not found")
	}
	allowed := c.Scopes
	if allowed == nil {
		allowed = o.Scopes
	}
	upd := adapter.Record{}
	// The validated body keeps nested objects as ordered *jsonx.Object values.
	update := objectToMap(asObject(bodyMap(ctx)["update"]))
	for k, v := range update {
		upd[k] = v
	}
	if sv, ok := update["scopes"]; ok {
		for _, s := range toStrings(sv) {
			if !contains(allowed, s) {
				owner := c.ReferenceID
				if owner == "" {
					owner = c.UserID
				}
				if owner == "" {
					owner = "undefined"
				}
				return nil, oauthErr("BAD_REQUEST", "invalid_request", "unable to provide scopes to "+owner)
			}
		}
	}
	upd["updatedAt"] = secondsNow()
	res, err := ctx.Auth.Adapter.Update(ctx.Context(), modelConsent, []adapter.Where{{Field: "id", Value: id}}, upd)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return betterauth.Null, nil
	}
	return recordObject(ctx, modelConsent, res), nil
}

// ---- resources ----

func assertResourcePrivileges(ctx *betterauth.EndpointContext, s *betterauth.SessionWithUser, o *resolved, action, resourceID string) error {
	if s == nil {
		return apiErr("UNAUTHORIZED")
	}
	if ctx.Headers == nil {
		return apiErr("BAD_REQUEST")
	}
	if o.ResourcePrivileges == nil {
		return nil
	}
	ok, err := o.ResourcePrivileges(PrivilegeContext{Ctx: ctx, Headers: ctx.Headers, Action: action, User: s.User,
		Session: s.Session, ResourceID: resourceID})
	if err != nil {
		return err
	}
	if !ok {
		return apiErr("UNAUTHORIZED")
	}
	return nil
}

func decodePathParam(v string) string {
	if out, err := url.PathUnescape(v); err == nil {
		return out
	}
	return v
}

func resourceSession(ctx *betterauth.EndpointContext, o *resolved, action, id string) error {
	s, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return err
	}
	return assertResourcePrivileges(ctx, s, o, action, id)
}

func resourceInputFromBody(b map[string]any) ResourceInput {
	in := ResourceInput{}
	in.Identifier, _ = b["identifier"].(string)
	if v, ok := b["name"].(string); ok {
		in.Name = &v
	}
	if v, ok := b["accessTokenTtl"].(float64); ok {
		n := int(v)
		in.AccessTokenTTL = &n
	}
	if v, ok := b["refreshTokenTtl"].(float64); ok {
		n := int(v)
		in.RefreshTokenTTL = &n
	}
	if v, ok := b["signingAlgorithm"].(string); ok {
		in.SigningAlgorithm = &v
	}
	if v, ok := b["signingKeyId"].(string); ok {
		in.SigningKeyID = &v
	}
	if v, ok := b["allowedScopes"]; ok && v != nil {
		in.AllowedScopes = nonNil(toStrings(v))
	}
	if v, ok := b["customClaims"]; ok && v != nil {
		in.CustomClaims = asObject(v)
	}
	if v, ok := b["dpopBoundAccessTokensRequired"].(bool); ok {
		in.DPoPBoundAccessTokensRequired = &v
	}
	if v, ok := b["disabled"].(bool); ok {
		in.Disabled = &v
	}
	if v, ok := b["metadata"]; ok && v != nil {
		in.Metadata = asObject(v)
	}
	return in
}

func createResourceEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	if err := resourceSession(ctx, o, "create", ""); err != nil {
		return nil, err
	}
	in := resourceInputFromBody(bodyMap(ctx))
	if in.Identifier == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "identifier is required")
	}
	if err := assertIdentifierValid(o, in.Identifier); err != nil {
		return nil, err
	}
	r, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: modelResource, Data: buildResourceRow(in, time.Now())})
	if err != nil {
		if uniqueRe.MatchString(err.Error()) {
			return nil, oauthErr("BAD_REQUEST", "invalid_request", "resource "+in.Identifier+" already exists")
		}
		return nil, err
	}
	if r == nil {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "resource "+in.Identifier+" could not be created")
	}
	o.resourceCache.invalidate(recStr(r, "identifier"))
	ctx.SetStatus(201)
	return recordObject(ctx, modelResource, r), nil
}

func listResourcesEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	if err := resourceSession(ctx, o, "list", ""); err != nil {
		return nil, err
	}
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelResource})
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range rows {
		out = append(out, recordObject(ctx, modelResource, r))
	}
	return out, nil
}

func findResourceRecord(ctx *betterauth.EndpointContext, id string) (adapter.Record, error) {
	return ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelResource,
		Where: []adapter.Where{{Field: "identifier", Value: id}}})
}

func getResourceEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	id := decodePathParam(ctx.Params["identifier"])
	if err := resourceSession(ctx, o, "read", id); err != nil {
		return nil, err
	}
	r, err := findResourceRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound("resource " + id + " not found")
	}
	return recordObject(ctx, modelResource, r), nil
}

var resourceUpdatable = []string{"name", "accessTokenTtl", "refreshTokenTtl", "signingAlgorithm", "signingKeyId",
	"allowedScopes", "customClaims", "dpopBoundAccessTokensRequired", "disabled", "metadata"}

func updateResourceEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	id := decodePathParam(ctx.Params["identifier"])
	if err := resourceSession(ctx, o, "update", id); err != nil {
		return nil, err
	}
	r, err := findResourceRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound("resource " + id + " not found")
	}
	upd := adapter.Record{"updatedAt": time.Now()}
	body := bodyMap(ctx)
	for _, k := range resourceUpdatable {
		if v, ok := body[k]; ok {
			upd[k] = v
		}
	}
	if _, err := ctx.Auth.Adapter.Update(ctx.Context(), modelResource, []adapter.Where{{Field: "identifier", Value: id}}, upd); err != nil {
		return nil, err
	}
	o.resourceCache.invalidate(id)
	r, err = findResourceRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound("resource " + id + " not found")
	}
	return recordObject(ctx, modelResource, r), nil
}

func deleteResourceEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	id := decodePathParam(ctx.Params["identifier"])
	if err := resourceSession(ctx, o, "delete", id); err != nil {
		return nil, err
	}
	r, err := findResourceRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound("resource " + id + " not found")
	}
	if err := ctx.Auth.Adapter.Delete(ctx.Context(), modelResource, []adapter.Where{{Field: "identifier", Value: id}}); err != nil {
		return nil, err
	}
	o.resourceCache.invalidate(id)
	return jsonx.O("deleted", true), nil
}

func linkClientResourceEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	rid := decodePathParam(ctx.Params["identifier"])
	cid := decodePathParam(ctx.Params["client_id"])
	if err := resourceSession(ctx, o, "link", rid); err != nil {
		return nil, err
	}
	r, err := findResourceRecord(ctx, rid)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, notFound("resource " + rid + " not found")
	}
	c, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelClient,
		Where: []adapter.Where{{Field: "clientId", Value: cid}}})
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, notFound("client " + cid + " not found")
	}
	if _, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: modelClientResource,
		Data: adapter.Record{"clientId": cid, "resourceId": rid, "createdAt": time.Now()}}); err != nil {
		if uniqueRe.MatchString(err.Error()) || isUniqueConstraintError(err) {
			return jsonx.O("linked", true, "alreadyLinked", true), nil
		}
		return nil, err
	}
	return jsonx.O("linked", true), nil
}

func unlinkClientResourceEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	rid := decodePathParam(ctx.Params["identifier"])
	cid := decodePathParam(ctx.Params["client_id"])
	if err := resourceSession(ctx, o, "unlink", rid); err != nil {
		return nil, err
	}
	if _, err := ctx.Auth.Adapter.DeleteMany(ctx.Context(), modelClientResource,
		[]adapter.Where{{Field: "clientId", Value: cid}, {Field: "resourceId", Value: rid}}); err != nil {
		return nil, err
	}
	return jsonx.O("unlinked", true), nil
}

var _ = strings.TrimSpace
