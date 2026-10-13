package apikey

import (
	"math"
	"sort"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/access"
	"github.com/nimi-io/better-auth-go/validate"
)

var verifyBody = validate.Object(
	validate.F("configId", validate.Optional(validate.String())),
	validate.F("key", validate.String()),
	validate.F("permissions", validate.Optional(permissionsSchema)),
)

func (p *plugin) verifyEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "verifyApiKey", Methods: []string{"POST"}, ServerOnly: true,
		Body: verifyBody, Handler: p.verify,
	}
}

type validateInput struct {
	key              string
	lookup           *config
	permissions      any
	expectedConfigID *string
	runCustomValid   bool
}

// validateKey is validateApiKey: it looks the key up, checks it and claims one use.
func (p *plugin) validateKey(ctx *betterauth.EndpointContext, in validateInput) (*APIKey, *config, error) {
	hashed := in.key
	if !in.lookup.DisableKeyHashing {
		hashed = DefaultKeyHasher(in.key)
	}
	k, err := p.getByHash(ctx, hashed, in.lookup)
	if err != nil {
		return nil, nil, err
	}
	if k == nil {
		return nil, nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidAPIKey)
	}
	if in.expectedConfigID != nil && !configIDMatches(k.ConfigID, *in.expectedConfigID) {
		return nil, nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidAPIKey)
	}
	opts, err := p.resolveConfiguration(ctx.Auth, k.ConfigID)
	if err != nil {
		return nil, nil, err
	}
	if in.runCustomValid && opts.CustomAPIKeyValidator != nil {
		ok, err := opts.CustomAPIKeyValidator(ctx, in.key)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, betterauth.ErrFrom("UNAUTHORIZED", ErrKeyNotFound)
		}
	}
	if isDisabled(k.Enabled) {
		return nil, nil, betterauth.ErrFrom("UNAUTHORIZED", ErrKeyDisabled)
	}
	if k.ExpiresAt != nil && p.now().After(*k.ExpiresAt) {
		if err := p.removeKey(ctx, k, opts); err != nil {
			return nil, nil, err
		}
		return nil, nil, betterauth.ErrFrom("UNAUTHORIZED", ErrKeyExpired)
	}
	if in.permissions != nil {
		perms := parsePermissions(k.Permissions)
		obj, ok := perms.(*jsonx.Object)
		if !ok || obj == nil {
			return nil, nil, betterauth.ErrFrom("UNAUTHORIZED", ErrKeyNotFound)
		}
		statements := access.Statements{}
		for _, res := range obj.Keys() {
			v, _ := obj.Get(res)
			list, _ := v.([]any)
			actions := make([]string, 0, len(list))
			for _, a := range list {
				if s, ok := a.(string); ok {
					actions = append(actions, s)
				}
			}
			statements[res] = actions
		}
		req := jsonx.NewObject()
		if m, ok := in.permissions.(map[string]any); ok {
			for _, kk := range sortedKeys(m) {
				req.Set(kk, m[kk])
			}
		}
		res, err := access.NewRole(statements).Authorize(req, access.AND)
		if err != nil || !res.Success {
			return nil, nil, betterauth.ErrFrom("UNAUTHORIZED", ErrKeyNotFound)
		}
	}
	if k.Remaining != nil && *k.Remaining == 0 && k.RefillAmount == nil {
		if err := p.removeKey(ctx, k, opts); err != nil {
			return nil, nil, err
		}
		return nil, nil, betterauth.ErrFrom("TOO_MANY_REQUESTS", ErrUsageExceeded)
	}
	usesDB := opts.storage == StorageDatabase || (opts.storage == StorageSecondary && opts.FallbackToDatabase)
	var out *APIKey
	if usesDB {
		out, err = p.claimUsageInDatabase(ctx, k, opts)
	} else {
		out, err = p.claimUsageInSecondaryStorage(ctx, k, opts, hashed)
	}
	if err != nil {
		return nil, nil, err
	}
	return out, opts, nil
}

// removeKey deletes an expired or exhausted key (deferred with deferUpdates).
func (p *plugin) removeKey(ctx *betterauth.EndpointContext, k *APIKey, opts *config) error {
	run := func() error {
		switch {
		case opts.storage == StorageSecondary && opts.FallbackToDatabase:
			if err := p.deleteKey(ctx, k, opts); err != nil {
				return err
			}
			return ctx.Auth.Adapter.Delete(ctx.Context(), TableName, []adapter.Where{{Field: "id", Value: k.ID}})
		case opts.storage == StorageSecondary:
			return p.deleteKey(ctx, k, opts)
		default:
			return ctx.Auth.Adapter.Delete(ctx.Context(), TableName, []adapter.Where{{Field: "id", Value: k.ID}})
		}
	}
	if opts.DeferUpdates {
		ac := ctx.Auth
		ac.RunInBackground(func() {
			if err := run(); err != nil {
				ac.Logger.Error("Deferred update failed:", err)
			}
		})
		return nil
	}
	return run()
}

func (p *plugin) incrementOne(ctx *betterauth.EndpointContext, where []adapter.Where, inc map[string]float64, set adapter.Record) (*APIKey, error) {
	rec, err := ctx.Auth.Adapter.IncrementOne(ctx.Context(), adapter.IncrementInput{Model: TableName, Where: where, Increment: inc, Set: set})
	if err != nil || rec == nil {
		return nil, err
	}
	return keyFromRecord(rec), nil
}

func (p *plugin) claimUsageInDatabase(ctx *betterauth.EndpointContext, k *APIKey, opts *config) (*APIKey, error) {
	row := k
	var err error
	if k.Remaining != nil {
		row, err = p.consumeRemaining(ctx, k)
		if err != nil {
			return nil, err
		}
	}
	row, err = p.consumeRateLimit(ctx, row, opts)
	if err != nil {
		return nil, err
	}
	rec, err := ctx.Auth.Adapter.Update(ctx.Context(), TableName, []adapter.Where{{Field: "id", Value: row.ID}},
		adapter.Record{"updatedAt": p.date(0)})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidAPIKey)
	}
	final := keyFromRecord(rec)
	if opts.storage == StorageSecondary && opts.FallbackToDatabase {
		if err := p.setKey(ctx, final, opts); err != nil {
			return nil, err
		}
	}
	return final, nil
}

func (p *plugin) consumeRemaining(ctx *betterauth.EndpointContext, k *APIKey) (*APIKey, error) {
	now := p.date(0)
	if isTruthyNum(k.RefillInterval) && isTruthyNum(k.RefillAmount) {
		last := k.CreatedAt
		if k.LastRefillAt != nil {
			last = *k.LastRefillAt
		}
		if float64(now.Sub(last).Milliseconds()) > *k.RefillInterval {
			refilled, err := p.incrementOne(ctx,
				[]adapter.Where{{Field: "id", Value: k.ID}, {Field: "lastRefillAt", Value: optTime(k.LastRefillAt)}},
				nil, adapter.Record{"remaining": *k.RefillAmount - 1, "lastRefillAt": now})
			if err != nil {
				return nil, err
			}
			if refilled != nil {
				return refilled, nil
			}
		}
	}
	dec, err := p.incrementOne(ctx,
		[]adapter.Where{{Field: "id", Value: k.ID}, {Field: "remaining", Operator: adapter.Gt, Value: float64(0)}},
		map[string]float64{"remaining": -1}, nil)
	if err != nil {
		return nil, err
	}
	if dec == nil {
		return nil, betterauth.ErrFrom("TOO_MANY_REQUESTS", ErrUsageExceeded)
	}
	return dec, nil
}

func rateLimitedError(d rateLimitDecision) *betterauth.APIError {
	return betterauth.NewAPIError("TOO_MANY_REQUESTS", jsonx.O(
		"message", d.message, "code", "RATE_LIMITED", "details", jsonx.O("tryAgainIn", d.tryAgainIn)))
}

func (p *plugin) consumeRateLimit(ctx *betterauth.EndpointContext, k *APIKey, opts *config) (*APIKey, error) {
	for {
		d := p.evaluateRateLimit(k, opts)
		switch d.kind {
		case decisionDeny:
			return nil, rateLimitedError(d)
		case decisionSkip:
			if d.lastRequest == nil {
				return k, nil
			}
			rec, err := ctx.Auth.Adapter.Update(ctx.Context(), TableName, []adapter.Where{{Field: "id", Value: k.ID}},
				adapter.Record{"lastRequest": *d.lastRequest})
			if err != nil {
				return nil, err
			}
			if rec == nil {
				return k, nil
			}
			return keyFromRecord(rec), nil
		case decisionIncrement:
			inc, err := p.incrementOne(ctx, []adapter.Where{
				{Field: "id", Value: k.ID},
				{Field: "lastRequest", Operator: adapter.Gt, Value: d.windowStart},
				{Field: "requestCount", Operator: adapter.Lt, Value: d.max},
			}, map[string]float64{"requestCount": 1}, adapter.Record{"lastRequest": d.now})
			if err != nil {
				return nil, err
			}
			if inc != nil {
				return inc, nil
			}
		default: // start, reset
			guard := adapter.Where{Field: "lastRequest", Operator: adapter.Eq, Value: nil}
			if d.kind == decisionReset {
				guard = adapter.Where{Field: "lastRequest", Operator: adapter.Lte, Value: d.windowStart}
			}
			started, err := p.incrementOne(ctx, []adapter.Where{{Field: "id", Value: k.ID}, guard},
				nil, adapter.Record{"requestCount": float64(1), "lastRequest": d.now})
			if err != nil {
				return nil, err
			}
			if started != nil {
				return started, nil
			}
		}
		fresh, err := p.dbFindOne(ctx, "id", k.ID)
		if err != nil {
			return nil, err
		}
		if fresh == nil {
			return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidAPIKey)
		}
		k = fresh
	}
}

func (p *plugin) claimUsageInSecondaryStorage(ctx *betterauth.EndpointContext, k *APIKey, opts *config, hashed string) (*APIKey, error) {
	remaining := k.Remaining
	lastRefillAt := k.LastRefillAt
	if remaining != nil {
		r := *remaining
		now := p.now()
		last := k.CreatedAt
		if lastRefillAt != nil {
			last = *lastRefillAt
		}
		if isTruthyNum(k.RefillInterval) && isTruthyNum(k.RefillAmount) && float64(now.Sub(last).Milliseconds()) > *k.RefillInterval {
			r = *k.RefillAmount
			t := p.date(0)
			lastRefillAt = &t
		}
		if r == 0 {
			return nil, betterauth.ErrFrom("TOO_MANY_REQUESTS", ErrUsageExceeded)
		}
		r--
		remaining = &r
	}
	d := p.evaluateRateLimit(k, opts)
	type mutation struct {
		setLastRequest bool
		lastRequest    *time.Time
		setCount       bool
		count          float64
	}
	var m mutation
	switch d.kind {
	case decisionDeny:
		return nil, rateLimitedError(d)
	case decisionSkip:
		if d.lastRequest != nil {
			m.setLastRequest, m.lastRequest = true, d.lastRequest
		}
	case decisionStart, decisionReset:
		now := d.now
		m.setLastRequest, m.lastRequest, m.setCount, m.count = true, &now, true, 1
	case decisionIncrement:
		now := d.now
		m.setLastRequest, m.lastRequest, m.setCount, m.count = true, &now, true, k.RequestCount+1
	}
	updatedAt := p.date(0)
	apply := func(base *APIKey) *APIKey {
		out := base.clone()
		if m.setLastRequest {
			out.LastRequest = m.lastRequest
		}
		if m.setCount {
			out.RequestCount = m.count
		}
		out.Remaining = remaining
		out.LastRefillAt = lastRefillAt
		out.UpdatedAt = updatedAt
		return out
	}
	perform := func() (*APIKey, error) {
		fresh, err := p.getByHash(ctx, hashed, opts)
		if err != nil || fresh == nil {
			return nil, err
		}
		merged := apply(fresh)
		if err := p.setKey(ctx, merged, opts); err != nil {
			return nil, err
		}
		return merged, nil
	}
	if opts.DeferUpdates {
		ac := ctx.Auth
		ac.RunInBackground(func() {
			if _, err := perform(); err != nil {
				ac.Logger.Error("Failed to update API key:", err)
			}
		})
		return apply(k), nil
	}
	updated, err := perform()
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToUpdateAPIKey)
	}
	return updated, nil
}

func (p *plugin) verify(ctx *betterauth.EndpointContext) (any, error) {
	body := ctx.BodyMap()
	configID, hasConfigID := bodyStr(body, "configId")
	key, _ := bodyStr(body, "key")
	lookup, err := p.resolveConfiguration(ctx.Auth, configID)
	if err != nil {
		return nil, err
	}
	if hasConfigID && lookup.CustomAPIKeyValidator != nil {
		ok, err := lookup.CustomAPIKeyValidator(ctx, key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return jsonx.O("valid", false, "error", jsonx.O("message", errorCodeObject(ErrInvalidAPIKey),
				"code", "KEY_NOT_FOUND"), "key", nil), nil
		}
	}
	in := validateInput{key: key, lookup: lookup, permissions: body["permissions"], runCustomValid: !hasConfigID}
	if hasConfigID {
		in.expectedConfigID = &configID
	}
	k, opts, err := p.validateKey(ctx, in)
	if err != nil {
		ctx.Auth.Logger.Error("Failed to validate API key:", err)
		if e, ok := betterauth.AsAPIError(err); ok {
			errObj := jsonx.NewObject()
			if e.Body != nil {
				for _, kk := range e.Body.Keys() {
					v, _ := e.Body.Get(kk)
					errObj.Set(kk, v)
				}
			}
			errObj.Set("message", nilIfEmpty(e.Message()))
			errObj.Set("code", nilIfEmpty(e.Code()))
			return jsonx.O("valid", false, "error", errObj, "key", nil), nil
		}
		return jsonx.O("valid", false, "error", jsonx.O("message", errorCodeObject(ErrInvalidAPIKey),
			"code", "INVALID_API_KEY"), "key", nil), nil
	}
	if opts.DeferUpdates {
		p.cleanupDeferred(ctx)
	}
	metadata := p.migrateMetadata(ctx, k, opts)
	o := k.object()
	o.Delete("key")
	o.Set("permissions", parsePermissions(k.Permissions))
	o.Set("metadata", metadata)
	return jsonx.O("valid", true, "error", nil, "key", o), nil
}

// nilIfEmpty renders a missing body field as undefined (omitted).
func nilIfEmpty(s string) any {
	if s == "" {
		return jsonx.Undefined
	}
	return s
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- rate limit (rate-limit.ts) ----

type decisionKind int

const (
	decisionSkip decisionKind = iota
	decisionStart
	decisionReset
	decisionIncrement
	decisionDeny
)

type rateLimitDecision struct {
	kind        decisionKind
	lastRequest *time.Time
	now         time.Time
	windowStart time.Time
	max         float64
	message     string
	tryAgainIn  float64
}

func (p *plugin) evaluateRateLimit(k *APIKey, opts *config) rateLimitDecision {
	now := p.date(0)
	if !opts.rateLimitEnabled || isDisabled(k.RateLimitEnabled) {
		return rateLimitDecision{kind: decisionSkip, lastRequest: &now}
	}
	if k.RateLimitTimeWindow == nil || k.RateLimitMax == nil {
		return rateLimitDecision{kind: decisionSkip}
	}
	window := *k.RateLimitTimeWindow
	if k.LastRequest == nil {
		return rateLimitDecision{kind: decisionStart, now: now}
	}
	since := float64(now.Sub(*k.LastRequest).Milliseconds())
	windowStart := now.Add(-time.Duration(window * float64(time.Millisecond)))
	if since > window {
		return rateLimitDecision{kind: decisionReset, now: now, windowStart: windowStart}
	}
	if k.RequestCount >= *k.RateLimitMax {
		return rateLimitDecision{kind: decisionDeny, message: ErrRateLimitExceeded.Message,
			tryAgainIn: math.Ceil(window - since)}
	}
	return rateLimitDecision{kind: decisionIncrement, now: now, max: *k.RateLimitMax, windowStart: windowStart}
}
