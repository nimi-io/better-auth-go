package jwt

import (
	"errors"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

var errCookieCacheNeedsLocalKeys = errors.New("`jwt({ sessionCookieCache: true })` requires locally managed JWT plugin keys and does not support `jwt.sign`.")

// cookieCacheSigner signs the session cookie cache with the plugin keys
// (createCookieCacheSigner).
type cookieCacheSigner struct {
	opts *Options
}

var _ betterauth.CookieCacheSigner = (*cookieCacheSigner)(nil)

func cookieCacheIssuer(ctx *betterauth.EndpointContext) string {
	if b := ctx.Auth.Options.BaseURL; b != "" {
		return b
	}
	return SessionCookieJWTIssuer
}

func (s *cookieCacheSigner) Sign(ctx *betterauth.EndpointContext, payload *jsonx.Object, maxAge time.Duration) (string, error) {
	key, err := ResolveSigningKey(ctx, s.opts, nil)
	if err != nil {
		return "", err
	}
	if key == nil {
		return "", errCookieCacheNeedsLocalKeys
	}
	claims := payload.Clone()
	var token, userID any
	if sv, ok := payload.Get("session"); ok {
		if so, ok := sv.(*jsonx.Object); ok {
			token, _ = so.Get("token")
		}
	}
	if uv, ok := payload.Get("user"); ok {
		if uo, ok := uv.(*jsonx.Object); ok {
			userID, _ = uo.Get("id")
		}
	}
	now := time.Now().Unix()
	claims.Set("sid", token)
	claims.Set("iat", float64(now))
	claims.Set("exp", float64(now+int64(maxAge/time.Second)))
	claims.Set("iss", cookieCacheIssuer(ctx))
	claims.Set("aud", SessionCookieJWTAudience)
	claims.Set("sub", userID)
	header := jsonx.O("alg", key.Alg, "kid", key.Kid, "typ", SessionCookieJWTType)
	return jose.SignJWT(header, claims, key.PrivateKey)
}

func (s *cookieCacheSigner) Verify(ctx *betterauth.EndpointContext, token string) (*jsonx.Object, time.Time, bool) {
	log := ctx.Auth.Logger
	header, err := jose.Header(token)
	if err != nil {
		log.Debug("Cookie-cache JWT verification failed", err)
		return nil, time.Time{}, false
	}
	if typ, _ := header.Get("typ"); typ != SessionCookieJWTType {
		return nil, time.Time{}, false
	}
	kidV, _ := header.Get("kid")
	kid, _ := kidV.(string)
	if kid == "" {
		log.Debug("Cookie-cache JWT missing kid in header")
		return nil, time.Time{}, false
	}
	keys, err := GetJwksAdapter(s.opts).GetAllKeys(ctx)
	if err != nil {
		log.Debug("Cookie-cache JWT verification failed", err)
		return nil, time.Time{}, false
	}
	if len(keys) == 0 {
		log.Debug("No JWKS keys available for cookie-cache JWT")
		return nil, time.Time{}, false
	}
	var key *Jwk
	for _, k := range keys {
		if k != nil && k.ID == kid {
			key = k
			break
		}
	}
	if key == nil {
		log.Debug("No JWKS key found for cookie-cache JWT kid: " + kid)
		return nil, time.Time{}, false
	}
	alg := key.Alg
	if alg == "" {
		if kc := s.opts.keyPairConfig(); kc != nil {
			alg = kc.Alg
		}
	}
	if alg == "" {
		a, _ := header.Get("alg")
		alg, _ = a.(string)
	}
	if alg == "" {
		log.Debug("No JWT algorithm available for cookie-cache JWT kid: " + kid)
		return nil, time.Time{}, false
	}
	pub, err := importPublicJWK(key.PublicKey, alg)
	if err != nil {
		log.Debug("Cookie-cache JWT verification failed", err)
		return nil, time.Time{}, false
	}
	_, payload, err := jose.VerifyJWT(token, jose.StaticKey(pub), sessionCookieVerifyOptions(SessionCookieJWTOptions{Issuer: cookieCacheIssuer(ctx)}, alg))
	if err != nil {
		log.Debug("Cookie-cache JWT verification failed", err)
		return nil, time.Time{}, false
	}
	if !checkSessionCookieClaims(payload) {
		return nil, time.Time{}, false
	}
	expiresAt := time.Now()
	if v, ok := payload.Get("exp"); ok {
		if f, ok := adapter.ToFloat(v); ok && f != 0 {
			expiresAt = time.UnixMilli(int64(f * 1000))
		}
	}
	return payload, expiresAt, true
}
