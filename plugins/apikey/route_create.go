package apikey

import (
	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

var createBody = validate.Object(
	validate.F("configId", validate.Optional(validate.String())),
	validate.F("name", validate.Optional(validate.String())),
	validate.F("expiresIn", validate.Default(validate.Nullish(validate.Number().Min(1)), nil)),
	validate.F("prefix", validate.Optional(prefixSchema)),
	validate.F("remaining", validate.Default(validate.Nullish(validate.Number().Min(0)), nil)),
	validate.F("metadata", validate.Optional(validate.Any())),
	validate.F("refillAmount", validate.Optional(validate.Number().Min(1))),
	validate.F("refillInterval", validate.Optional(validate.Number())),
	validate.F("rateLimitTimeWindow", validate.Optional(validate.Number())),
	validate.F("rateLimitMax", validate.Optional(validate.Number())),
	validate.F("rateLimitEnabled", validate.Optional(validate.Boolean())),
	validate.F("permissions", validate.Optional(permissionsSchema)),
	validate.F("userId", validate.Optional(coerceString)),
	validate.F("organizationId", validate.Optional(coerceString)),
)

func (p *plugin) createEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "createApiKey", Path: "/api-key/create", Methods: []string{"POST"},
		Body: createBody, Metadata: openapiMeta("createApiKey"), Handler: p.create,
	}
}

func (p *plugin) create(ctx *betterauth.EndpointContext) (any, error) {
	body := ctx.BodyMap()
	configID, _ := bodyStr(body, "configId")
	name, hasName := bodyStr(body, "name")
	expiresIn := bodyNum(body, "expiresIn")
	prefix, _ := bodyStr(body, "prefix")
	remaining := bodyNum(body, "remaining")
	metadata, hasMetadata := body["metadata"]
	refillAmount := bodyNum(body, "refillAmount")
	refillInterval := bodyNum(body, "refillInterval")
	_, hasPermissions := body["permissions"]
	rateLimitMax := bodyNum(body, "rateLimitMax")
	rateLimitTimeWindow := bodyNum(body, "rateLimitTimeWindow")
	rateLimitEnabled := ctx.BodyBool("rateLimitEnabled")
	bodyUserID, hasUserID := bodyStr(body, "userId")

	opts, err := p.resolveConfiguration(ctx.Auth, configID)
	if err != nil {
		return nil, err
	}
	session, err := betterauth.GetSessionFromCtx(ctx, &betterauth.GetSessionOptions{DisableCookieCache: true})
	if err != nil {
		return nil, err
	}
	client := isClientRequest(ctx)
	serverOnly := refillAmount != nil || refillInterval != nil || rateLimitMax != nil ||
		rateLimitTimeWindow != nil || rateLimitEnabled != nil || hasPermissions || remaining != nil
	if client && serverOnly {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrServerOnlyProperty)
	}
	if ctx.Request != nil && hasUserID {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnauthorizedSession)
	}
	sessionUserID := ""
	if session != nil && session.User != nil {
		sessionUserID = session.User.ID
	}
	var referenceID string
	if opts.references == ReferencesOrganization {
		orgID, _ := bodyStr(body, "organizationId")
		if orgID == "" {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrOrganizationIDRequired)
		}
		userID := sessionUserID
		if userID == "" {
			userID = bodyUserID
		}
		if userID == "" {
			return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnauthorizedSession)
		}
		if _, err := p.checkOrgPermission(ctx, userID, orgID, actionCreate); err != nil {
			return nil, err
		}
		referenceID = orgID
	} else if client {
		if sessionUserID == "" {
			return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnauthorizedSession)
		}
		referenceID = sessionUserID
	} else {
		if sessionUserID == "" && bodyUserID == "" {
			return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnauthorizedSession)
		}
		if session != nil && bodyUserID != "" && sessionUserID != bodyUserID {
			return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnauthorizedSession)
		}
		referenceID = sessionUserID
		if referenceID == "" {
			referenceID = bodyUserID
		}
	}

	if truthy(metadata) {
		if !opts.EnableMetadata {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrMetadataDisabled)
		}
		if !isObject(metadata) {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidMetadataType)
		}
	}
	if isTruthyNum(refillAmount) && !isTruthyNum(refillInterval) {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrRefillAmountAndIntervalRequired)
	}
	if isTruthyNum(refillInterval) && !isTruthyNum(refillAmount) {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrRefillIntervalAndAmountRequired)
	}
	if isTruthyNum(expiresIn) {
		if opts.disableCustomExpiresIn {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrKeyDisabledExpiration)
		}
		days := *expiresIn / (60 * 60 * 24)
		if opts.minExpiresIn > days {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrExpiresInIsTooSmall)
		} else if opts.maxExpiresIn < days {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrExpiresInIsTooLarge)
		}
	}
	if prefix != "" {
		if jsLen(prefix) < opts.minimumPrefixLength || jsLen(prefix) > opts.maximumPrefixLength {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidPrefixLength)
		}
	}
	if hasName && name != "" {
		if jsLen(name) < opts.minimumNameLength || jsLen(name) > opts.maximumNameLength {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidNameLength)
		}
	} else if opts.RequireName {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrNameRequired)
	}

	p.cleanup(ctx)

	genPrefix := prefix
	if genPrefix == "" {
		genPrefix = opts.DefaultPrefix
	}
	gen := opts.CustomKeyGenerator
	if gen == nil {
		gen = DefaultKeyGenerator
	}
	key, err := gen(opts.defaultKeyLength, genPrefix)
	if err != nil {
		return nil, err
	}
	hashed := key
	if !opts.DisableKeyHashing {
		hashed = DefaultKeyHasher(key)
	}
	var start *string
	if opts.startShouldStore {
		s := jsonx.JSSubstring(key, 0, opts.startLength)
		start = &s
	}

	var permissionsToApply *string
	if hasPermissions {
		s, err := statementsJSON(body["permissions"])
		if err != nil {
			return nil, err
		}
		permissionsToApply = &s
	} else if perms := opts.Permissions; perms != nil {
		var def Statements
		if perms.DefaultPermissionsFunc != nil {
			def, err = perms.DefaultPermissionsFunc(referenceID, ctx)
			if err != nil {
				return nil, err
			}
		} else {
			def = perms.DefaultPermissions
		}
		if def != nil {
			s, err := statementsJSON(def)
			if err != nil {
				return nil, err
			}
			permissionsToApply = &s
		}
	}

	now := p.date(0)
	resolvedConfigID := opts.ConfigID
	if resolvedConfigID == "" {
		resolvedConfigID = "default"
	}
	k := &APIKey{
		ConfigID: resolvedConfigID, CreatedAt: now, UpdatedAt: now, Key: hashed, Start: start,
		ReferenceID: referenceID, Enabled: Bool(true), Permissions: permissionsToApply,
	}
	if hasName {
		k.Name = &name
	}
	if prefix != "" {
		k.Prefix = &prefix
	} else if opts.DefaultPrefix != "" {
		dp := opts.DefaultPrefix
		k.Prefix = &dp
	}
	switch {
	case isTruthyNum(expiresIn):
		t := p.date(secondsDuration(*expiresIn))
		k.ExpiresAt = &t
	case opts.defaultExpiresIn != nil && *opts.defaultExpiresIn != 0:
		t := p.date(secondsDuration(*opts.defaultExpiresIn))
		k.ExpiresAt = &t
	}
	if rateLimitMax != nil {
		k.RateLimitMax = rateLimitMax
	} else {
		k.RateLimitMax = Float(opts.rateLimitMaxRequests)
	}
	if rateLimitTimeWindow != nil {
		k.RateLimitTimeWindow = rateLimitTimeWindow
	} else {
		k.RateLimitTimeWindow = Float(opts.rateLimitTimeWindow)
	}
	// remaining defaults to null (zod .default(null)), so refillAmount never seeds it.
	k.Remaining = remaining
	k.RefillAmount = refillAmount
	k.RefillInterval = refillInterval
	if rateLimitEnabled == nil {
		k.RateLimitEnabled = Bool(opts.rateLimitEnabled)
	} else {
		k.RateLimitEnabled = rateLimitEnabled
	}
	if truthy(metadata) {
		k.Metadata = metadata
	}

	var created *APIKey
	switch {
	case opts.storage == StorageSecondary && opts.FallbackToDatabase:
		created, err = p.dbCreate(ctx, k)
		if err != nil {
			return nil, err
		}
		if err := p.setKey(ctx, created, opts); err != nil {
			return nil, err
		}
	case opts.storage == StorageSecondary:
		id, ok := ctx.Auth.GenerateID(TableName)
		if !ok || id == "" {
			id = bacrypto.GenerateID()
		}
		created = k.clone()
		created.ID = id
		if err := p.setKey(ctx, created, opts); err != nil {
			return nil, err
		}
	default:
		created, err = p.dbCreate(ctx, k)
		if err != nil {
			return nil, err
		}
	}
	o := created.object()
	o.Set("key", key)
	if hasMetadata {
		o.Set("metadata", metadata)
	} else {
		o.Set("metadata", nil)
	}
	o.Set("permissions", parsePermissions(created.Permissions))
	return o, nil
}

func isTruthyNum(f *float64) bool { return f != nil && *f != 0 && *f == *f }

func (p *plugin) dbCreate(ctx *betterauth.EndpointContext, k *APIKey) (*APIKey, error) {
	rec, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: TableName, Data: k.record()})
	if err != nil {
		return nil, err
	}
	return keyFromRecord(rec), nil
}
