package apikey

import (
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

type keyAndConfig struct {
	key    string
	config *config
}

func (p *plugin) keyFromRequest(ctx *betterauth.EndpointContext, c *config) string {
	if c.CustomAPIKeyGetter != nil {
		return c.CustomAPIKeyGetter(ctx)
	}
	for _, h := range c.apiKeyHeaders {
		if v := ctx.GetHeader(h); v != "" {
			return v
		}
	}
	return ""
}

// findKeyAndConfig returns the first configuration with sessions enabled whose header
// (or getter) yields a key.
func (p *plugin) findKeyAndConfig(ctx *betterauth.EndpointContext) *keyAndConfig {
	for _, c := range p.configs {
		if !c.EnableSessionForAPIKeys {
			continue
		}
		if k := p.keyFromRequest(ctx, c); k != "" {
			return &keyAndConfig{key: k, config: c}
		}
	}
	return nil
}

// sessionHook turns an API key header into a session (hooks.before upstream).
func (p *plugin) sessionHook(ctx *betterauth.EndpointContext) (any, error) {
	found := p.findKeyAndConfig(ctx)
	if found == nil {
		return nil, nil
	}
	key, c := found.key, found.config
	if jsLen(key) < c.defaultKeyLength {
		return nil, betterauth.ErrFrom("FORBIDDEN", ErrInvalidAPIKey)
	}
	if c.CustomAPIKeyValidator != nil {
		ok, err := c.CustomAPIKeyValidator(ctx, key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, betterauth.ErrFrom("FORBIDDEN", ErrInvalidAPIKey)
		}
	}
	expected := c.ConfigID
	k, _, err := p.validateKey(ctx, validateInput{key: key, lookup: c, expectedConfigID: &expected})
	if err != nil {
		return nil, err
	}
	if c.DeferUpdates {
		p.cleanupDeferred(ctx)
	} else {
		p.cleanup(ctx)
	}
	if c.references != ReferencesUser {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidReferenceIDFromAPIKey)
	}
	user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), k.ReferenceID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidReferenceIDFromAPIKey)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	var expiresAt time.Time
	if k.ExpiresAt != nil {
		expiresAt = *k.ExpiresAt
	} else {
		exp := 7 * 24 * time.Hour
		if s := ctx.Auth.Options.Session; s != nil && s.ExpiresIn > 0 {
			exp = s.ExpiresIn
		}
		expiresAt = now.Add(exp)
	}
	sess := &betterauth.Session{ID: k.ID, Token: key, UserID: k.ReferenceID, CreatedAt: now, UpdatedAt: now,
		ExpiresAt: expiresAt}
	if ctx.Request != nil {
		if ua := ctx.Request.Header.Get("User-Agent"); ua != "" {
			sess.UserAgent = &ua
		}
		ip := betterauth.GetIP(ctx.Request.Header, ctx.Auth.Options)
		if ip != "" {
			sess.IPAddress = &ip
		}
	}
	sw := &betterauth.SessionWithUser{Session: sess, User: user}
	ctx.Session = sw
	if ctx.Path == "/get-session" {
		rendered := jsonx.O("user", user, "session", jsonx.O(
			"id", sess.ID, "token", sess.Token, "userId", sess.UserID,
			"userAgent", strOrNil(sess.UserAgent), "ipAddress", strOrNil(sess.IPAddress),
			"createdAt", sess.CreatedAt, "updatedAt", sess.UpdatedAt, "expiresAt", sess.ExpiresAt))
		return betterauth.NewAPIKeySessionResult(sw, rendered), nil
	}
	return nil, nil
}

func strOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
