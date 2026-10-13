package apikey

import (
	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// ---- get ----

var getQuery = validate.Object(
	validate.F("configId", validate.Optional(validate.String())),
	validate.F("id", validate.String()),
)

func (p *plugin) getEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getApiKey", Path: "/api-key/get", Methods: []string{"GET"}, Query: getQuery,
		Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: openapiMeta("getApiKey"),
		Handler: p.get,
	}
}

// findOwnedKey looks a key up by id under configId and checks access (shared by get,
// update and delete).
func (p *plugin) findOwnedKey(ctx *betterauth.EndpointContext, configID, id, userID, action string) (*APIKey, *config, error) {
	lookup, err := p.resolveConfiguration(ctx.Auth, configID)
	if err != nil {
		return nil, nil, err
	}
	k, err := p.getByID(ctx, id, lookup)
	if err != nil {
		return nil, nil, err
	}
	if k == nil || !configIDMatches(k.ConfigID, lookup.ConfigID) {
		return nil, nil, betterauth.ErrFrom("NOT_FOUND", ErrKeyNotFound)
	}
	opts, err := p.resolveConfiguration(ctx.Auth, k.ConfigID)
	if err != nil {
		return nil, nil, err
	}
	if opts.references == ReferencesOrganization {
		if _, err := p.checkOrgPermission(ctx, userID, k.ReferenceID, action); err != nil {
			return nil, nil, err
		}
	} else if k.ReferenceID != userID {
		return nil, nil, betterauth.ErrFrom("NOT_FOUND", ErrKeyNotFound)
	}
	return k, opts, nil
}

func (p *plugin) get(ctx *betterauth.EndpointContext) (any, error) {
	k, opts, err := p.findOwnedKey(ctx, ctx.QueryString("configId"), ctx.QueryString("id"), ctx.Session.User.ID, actionRead)
	if err != nil {
		return nil, err
	}
	p.cleanup(ctx)
	metadata := p.migrateMetadata(ctx, k, opts)
	return k.publicObject(metadata), nil
}

// ---- update ----

var updateBody = validate.Object(
	validate.F("configId", validate.Optional(validate.String())),
	validate.F("keyId", validate.String()),
	validate.F("userId", validate.Optional(coerceString)),
	validate.F("name", validate.Optional(validate.String())),
	validate.F("enabled", validate.Optional(validate.Boolean())),
	validate.F("remaining", validate.Optional(validate.Number().Min(1))),
	validate.F("refillAmount", validate.Optional(validate.Number())),
	validate.F("refillInterval", validate.Optional(validate.Number())),
	validate.F("metadata", validate.Optional(validate.Any())),
	validate.F("expiresIn", validate.Nullish(validate.Number().Min(1))),
	validate.F("rateLimitEnabled", validate.Optional(validate.Boolean())),
	validate.F("rateLimitTimeWindow", validate.Optional(validate.Number())),
	validate.F("rateLimitMax", validate.Optional(validate.Number())),
	validate.F("permissions", validate.Nullish(permissionsSchema)),
)

func (p *plugin) updateEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "updateApiKey", Path: "/api-key/update", Methods: []string{"POST"}, Body: updateBody,
		Metadata: openapiMeta("updateApiKey"), Handler: p.update,
	}
}

func (p *plugin) update(ctx *betterauth.EndpointContext) (any, error) {
	body := ctx.BodyMap()
	session, err := betterauth.GetSessionFromCtx(ctx, &betterauth.GetSessionOptions{DisableCookieCache: true})
	if err != nil {
		return nil, err
	}
	authRequired := isClientRequest(ctx)
	bodyUserID, _ := bodyStr(body, "userId")
	var userID string
	switch {
	case authRequired && session == nil:
	case session != nil && session.User != nil:
		userID = session.User.ID
	default:
		userID = bodyUserID
	}
	if userID == "" {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnauthorizedSession)
	}
	if session != nil && bodyUserID != "" && session.User.ID != bodyUserID {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnauthorizedSession)
	}
	if authRequired {
		for _, f := range []string{"refillAmount", "refillInterval", "rateLimitMax", "rateLimitTimeWindow",
			"rateLimitEnabled", "remaining", "permissions"} {
			if bodyHas(body, f) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrServerOnlyProperty)
			}
		}
	}
	configID, _ := bodyStr(body, "configId")
	keyID, _ := bodyStr(body, "keyId")
	k, opts, err := p.findOwnedKey(ctx, configID, keyID, userID, actionUpdate)
	if err != nil {
		return nil, err
	}

	newValues := adapter.Record{}
	if name, ok := bodyStr(body, "name"); ok {
		if jsLen(name) < opts.minimumNameLength || jsLen(name) > opts.maximumNameLength {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidNameLength)
		}
		newValues["name"] = name
	}
	if b := ctx.BodyBool("enabled"); b != nil {
		newValues["enabled"] = *b
	}
	if bodyHas(body, "expiresIn") {
		if opts.disableCustomExpiresIn {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrKeyDisabledExpiration)
		}
		expiresIn := bodyNum(body, "expiresIn")
		if expiresIn != nil {
			days := *expiresIn / (60 * 60 * 24)
			if days < opts.minExpiresIn {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrExpiresInIsTooSmall)
			} else if days > opts.maxExpiresIn {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrExpiresInIsTooLarge)
			}
		}
		if isTruthyNum(expiresIn) {
			newValues["expiresAt"] = p.date(secondsDuration(*expiresIn))
		} else {
			newValues["expiresAt"] = nil
		}
	}
	if metadata, ok := body["metadata"]; ok && opts.EnableMetadata {
		if metadata != nil && !isObject(metadata) {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidMetadataType)
		}
		newValues["metadata"] = metadata
	}
	if r := bodyNum(body, "remaining"); r != nil {
		newValues["remaining"] = *r
	}
	refillAmount, refillInterval := bodyNum(body, "refillAmount"), bodyNum(body, "refillInterval")
	if refillAmount != nil || refillInterval != nil {
		if refillAmount != nil && refillInterval == nil {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrRefillAmountAndIntervalRequired)
		} else if refillInterval != nil && refillAmount == nil {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrRefillIntervalAndAmountRequired)
		}
		newValues["refillAmount"] = *refillAmount
		newValues["refillInterval"] = *refillInterval
	}
	if b := ctx.BodyBool("rateLimitEnabled"); b != nil {
		newValues["rateLimitEnabled"] = *b
	}
	if v := bodyNum(body, "rateLimitTimeWindow"); v != nil {
		newValues["rateLimitTimeWindow"] = *v
	}
	if v := bodyNum(body, "rateLimitMax"); v != nil {
		newValues["rateLimitMax"] = *v
	}
	if perms, ok := body["permissions"]; ok {
		s, err := statementsJSON(perms)
		if err != nil {
			return nil, err
		}
		newValues["permissions"] = s
	}
	if len(newValues) == 0 {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrNoValuesToUpdate)
	}

	newKey := k
	internal := func(err error) error {
		return betterauth.ErrMessage("INTERNAL_SERVER_ERROR", err.Error())
	}
	switch {
	case opts.storage == StorageSecondary && opts.FallbackToDatabase:
		rec, err := ctx.Auth.Adapter.Update(ctx.Context(), TableName, []adapter.Where{{Field: "id", Value: k.ID}}, newValues)
		if err != nil {
			return nil, internal(err)
		}
		if rec != nil {
			updated := keyFromRecord(rec)
			if err := p.setKey(ctx, updated, opts); err != nil {
				return nil, internal(err)
			}
			newKey = updated
		}
	case opts.storage == StorageDatabase:
		rec, err := ctx.Auth.Adapter.Update(ctx.Context(), TableName, []adapter.Where{{Field: "id", Value: k.ID}}, newValues)
		if err != nil {
			return nil, internal(err)
		}
		if rec != nil {
			newKey = keyFromRecord(rec)
		}
	default:
		updated := applyValues(k, newValues)
		updated.UpdatedAt = p.date(0)
		if err := p.setKey(ctx, updated, opts); err != nil {
			return nil, internal(err)
		}
		newKey = updated
	}
	p.cleanup(ctx)
	metadata := p.migrateMetadata(ctx, newKey, opts)
	return newKey.publicObject(metadata), nil
}

// applyValues is {...apiKey, ...newValues} for secondary-storage updates.
func applyValues(k *APIKey, v adapter.Record) *APIKey {
	r := k.object()
	for f, val := range v {
		r.Set(f, val)
	}
	return keyFromRecord(r)
}

// ---- delete ----

var deleteBody = validate.Object(
	validate.F("configId", validate.Optional(validate.String())),
	validate.F("keyId", validate.String()),
)

func (p *plugin) deleteEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "deleteApiKey", Path: "/api-key/delete", Methods: []string{"POST"}, Body: deleteBody,
		Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: openapiMeta("deleteApiKey"),
		Handler: p.delete,
	}
}

func (p *plugin) delete(ctx *betterauth.EndpointContext) (any, error) {
	user := ctx.Session.User
	if banned, _ := user.Get("banned").(bool); banned {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUserBanned)
	}
	k, opts, err := p.findOwnedKey(ctx, ctx.BodyString("configId"), ctx.BodyString("keyId"), user.ID, actionDelete)
	if err != nil {
		return nil, err
	}
	del := func() error {
		return ctx.Auth.Adapter.Delete(ctx.Context(), TableName, []adapter.Where{{Field: "id", Value: k.ID}})
	}
	switch {
	case opts.storage == StorageSecondary && opts.FallbackToDatabase:
		err = p.deleteKey(ctx, k, opts)
		if err == nil {
			err = del()
		}
	case opts.storage == StorageDatabase:
		err = del()
	default:
		err = p.deleteKey(ctx, k, opts)
	}
	if err != nil {
		return nil, betterauth.ErrMessage("INTERNAL_SERVER_ERROR", err.Error())
	}
	p.cleanup(ctx)
	return jsonx.O("success", true), nil
}

// ---- list ----

var listQuery = validate.Optional(validate.Object(
	validate.F("configId", validate.Optional(validate.String())),
	validate.F("organizationId", validate.Optional(validate.String())),
	validate.F("limit", validate.Optional(coerceNonNegativeInt)),
	validate.F("offset", validate.Optional(coerceNonNegativeInt)),
	validate.F("sortBy", validate.Optional(validate.String())),
	validate.F("sortDirection", validate.Optional(validate.Enum("asc", "desc"))),
))

func (p *plugin) listEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listApiKeys", Path: "/api-key/list", Methods: []string{"GET"}, Query: listQuery,
		Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: openapiMeta("listApiKeys"),
		Handler: p.list_,
	}
}

func storageIdentifier(c *config) string {
	if c.storage == StorageDatabase {
		return "database"
	}
	if c.CustomStorage != nil {
		id := c.ConfigID
		if id == "" {
			id = "default"
		}
		return "custom:" + id
	}
	if c.FallbackToDatabase {
		return "secondary-storage-with-fallback"
	}
	return "secondary-storage"
}

func (p *plugin) list_(ctx *betterauth.EndpointContext) (any, error) {
	session := ctx.Session
	q := ctx.Query
	configID, _ := q["configId"].(string)
	organizationID, _ := q["organizationId"].(string)
	var limit, offset *int
	if f, ok := q["limit"].(float64); ok {
		n := int(f)
		limit = &n
	}
	if f, ok := q["offset"].(float64); ok {
		n := int(f)
		offset = &n
	}
	sortBy, _ := q["sortBy"].(string)
	sortDirection, _ := q["sortDirection"].(string)
	if organizationID != "" {
		if _, err := p.checkOrgPermission(ctx, session.User.ID, organizationID, actionRead); err != nil {
			return nil, err
		}
	}
	referenceID := session.User.ID
	expectedType := ReferencesUser
	if organizationID != "" {
		referenceID = organizationID
		expectedType = ReferencesOrganization
	}
	lo := listOptions{sortBy: sortBy, sortDirection: sortDirection}
	var all []*APIKey
	if configID != "" {
		resolved, err := p.resolveConfiguration(ctx.Auth, configID)
		if err != nil {
			return nil, err
		}
		all, err = p.list(ctx, referenceID, resolved, lo)
		if err != nil {
			return nil, err
		}
	} else {
		var groups []*config
		seenGroup := map[string]bool{}
		for _, c := range p.configs {
			id := storageIdentifier(c)
			if !seenGroup[id] {
				seenGroup[id] = true
				groups = append(groups, c)
			}
		}
		results, err := mapConcurrent(groups, len(groups), func(c *config) ([]*APIKey, error) {
			return p.list(ctx, referenceID, c, lo)
		})
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, keys := range results {
			for _, k := range keys {
				if !seen[k.ID] {
					seen[k.ID] = true
					all = append(all, k)
				}
			}
		}
	}
	filtered := make([]*APIKey, 0, len(all))
	for _, k := range all {
		var keyConfig *config
		for _, c := range p.configs {
			if isDefaultConfigID(k.ConfigID) {
				if isDefaultConfigID(c.ConfigID) {
					keyConfig = c
					break
				}
			} else if c.ConfigID == k.ConfigID {
				keyConfig = c
				break
			}
		}
		refType := ReferencesUser
		if keyConfig != nil {
			refType = keyConfig.references
		}
		if refType == expectedType && k.ReferenceID == referenceID {
			if configID == "" || configIDMatches(k.ConfigID, configID) {
				filtered = append(filtered, k)
			}
		}
	}
	total := len(filtered)
	page := filtered
	if offset != nil {
		if *offset >= len(page) {
			page = nil
		} else {
			page = page[*offset:]
		}
	}
	if limit != nil && *limit < len(page) {
		page = page[:*limit]
	}
	p.cleanup(ctx)
	items := make([]any, 0, len(page))
	for _, k := range page {
		items = append(items, k.publicObject(parseDoubleStringifiedMetadata(k.Metadata)))
	}
	for _, c := range p.configs {
		if c.storage == StorageDatabase || c.FallbackToDatabase {
			ctx.Auth.RunInBackgroundOrAwait(func() error {
				p.batchMigrateMetadata(ctx, page, c)
				return nil
			})
			break
		}
	}
	out := jsonx.O("apiKeys", items, "total", total)
	if limit != nil {
		out.Set("limit", *limit)
	} else {
		out.Set("limit", jsonx.Undefined)
	}
	if offset != nil {
		out.Set("offset", *offset)
	} else {
		out.Set("offset", jsonx.Undefined)
	}
	return out, nil
}
