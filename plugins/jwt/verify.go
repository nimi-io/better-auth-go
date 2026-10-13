package jwt

import (
	"net/http"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

func audienceList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return t
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func decodeHeaderLoose(token string) (*jsonx.Object, bool) {
	parts := strings.Split(token, ".")
	raw, err := bacrypto.DecodeBase64Loose(parts[0])
	if err != nil {
		return nil, false
	}
	v, err := jsonx.Parse(raw)
	if err != nil {
		return nil, false
	}
	o, ok := v.(*jsonx.Object)
	return o, ok
}

// VerifyJWT verifies a token issued by the plugin against the stored keys and the
// configured issuer / audience (verifyJWT). It returns nil when the token is invalid or
// lacks sub / aud.
func VerifyJWT(ctx *betterauth.EndpointContext, token string, opts *Options) *jsonx.Object {
	log := ctx.Auth.Logger
	if len(strings.Split(token, ".")) != 3 {
		return nil
	}
	header, ok := decodeHeaderLoose(token)
	if !ok {
		log.Debug("JWT verification failed", "invalid header")
		return nil
	}
	kidV, _ := header.Get("kid")
	kid, _ := kidV.(string)
	if kid == "" {
		log.Debug("JWT missing kid in header")
		return nil
	}
	keys, err := GetJwksAdapter(opts).GetAllKeys(ctx)
	if err != nil {
		log.Debug("JWT verification failed", err)
		return nil
	}
	if len(keys) == 0 {
		log.Debug("No JWKS keys available")
		return nil
	}
	var key *Jwk
	for _, k := range keys {
		if k != nil && k.ID == kid {
			key = k
			break
		}
	}
	if key == nil {
		log.Debug("No JWKS key found for kid: " + kid)
		return nil
	}
	alg := key.Alg
	if alg == "" {
		alg = opts.primaryAlg()
	}
	pub, err := importPublicJWK(key.PublicKey, alg)
	if err != nil {
		log.Debug("JWT verification failed", err)
		return nil
	}
	jo := opts.jwt()
	baseURL := ctx.Auth.Options.BaseURL
	issuer := jo.Issuer
	if issuer == "" {
		issuer = baseURL
	}
	var aud any = baseURL
	if jo.Audience != nil {
		aud = jo.Audience
	}
	vo := jose.VerifyOptions{Algorithms: []string{alg}, Audience: audienceList(aud)}
	if issuer != "" {
		vo.Issuer = []string{issuer}
	}
	_, payload, err := jose.VerifyJWT(token, jose.StaticKey(pub), vo)
	if err != nil {
		log.Debug("JWT verification failed", err)
		return nil
	}
	sub, _ := payload.Get("sub")
	if s, _ := sub.(string); s == "" {
		return nil
	}
	audV, ok := payload.Get("aud")
	if !ok || audV == nil {
		return nil
	}
	if s, isStr := audV.(string); isStr && s == "" {
		return nil
	}
	return payload
}

// Session cookie cache JWTs (cookies/jwt.ts).
const (
	SessionCookieJWTType     = "better-auth.session-cache+jwt"
	SessionCookieJWTAudience = "better-auth:session-cache"
	SessionCookieJWTIssuer   = "better-auth:session-cache"
)

// SessionCookieJWTOptions configure VerifySessionCookieJWTWithJWKS.
type SessionCookieJWTOptions struct {
	// Issuer, when set, must match the iss claim.
	Issuer string
	// Audience defaults to "better-auth:session-cache".
	Audience string
}

func sessionCookieVerifyOptions(o SessionCookieJWTOptions, alg string) jose.VerifyOptions {
	aud := o.Audience
	if aud == "" {
		aud = SessionCookieJWTAudience
	}
	vo := jose.VerifyOptions{Algorithms: []string{alg}, Audience: []string{aud}, ClockTolerance: 15 * time.Second}
	if o.Issuer != "" {
		vo.Issuer = []string{o.Issuer}
	}
	return vo
}

// checkSessionCookieClaims is parseSessionCookieJwtPayload's binding check: iss must be a
// non-empty string, sub the cached user id and sid the cached session token.
func checkSessionCookieClaims(p *jsonx.Object) bool {
	iss, _ := p.Get("iss")
	if s, ok := iss.(string); !ok || s == "" {
		return false
	}
	sv, _ := p.Get("session")
	uv, _ := p.Get("user")
	so, ok1 := sv.(*jsonx.Object)
	uo, ok2 := uv.(*jsonx.Object)
	if !ok1 || !ok2 {
		return false
	}
	uid, _ := uo.Get("id")
	tok, _ := so.Get("token")
	sub, _ := p.Get("sub")
	sid, _ := p.Get("sid")
	return sub == uid && sid == tok
}

// VerifySessionCookieJWTWithJWKS verifies a session cookie cache JWT against a public
// JWKS (verifySessionCookieJwtWithJwks). It returns the claims, or nil when invalid.
func VerifySessionCookieJWTWithJWKS(token string, set jose.JWKS, o SessionCookieJWTOptions) *jsonx.Object {
	header, err := jose.Header(token)
	if err != nil {
		return nil
	}
	if typ, _ := header.Get("typ"); typ != SessionCookieJWTType {
		return nil
	}
	kidV, _ := header.Get("kid")
	kid, _ := kidV.(string)
	if kid == "" {
		return nil
	}
	var key *jose.JWK
	for i := range set.Keys {
		if set.Keys[i].Kid == kid {
			key = &set.Keys[i]
			break
		}
	}
	if key == nil {
		return nil
	}
	alg := key.Alg
	if alg == "" {
		a, _ := header.Get("alg")
		alg, _ = a.(string)
	}
	if alg == "" || !jose.KeyMatchesAlg(*key, alg) {
		return nil
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil
	}
	_, payload, err := jose.VerifyJWT(token, jose.StaticKey(pub), sessionCookieVerifyOptions(o, alg))
	if err != nil {
		return nil
	}
	if !checkSessionCookieClaims(payload) {
		return nil
	}
	return payload
}

// CookieCacheOptions configure GetCookieCache.
type CookieCacheOptions struct {
	betterauth.CookieCacheOptions
	// JWKS verifies "jwt" strategy caches signed by the plugin (jwt.jwks upstream).
	JWKS *jose.JWKS
	// Issuer / Audience for the JWKS verification.
	Issuer   string
	Audience string
}

// GetCookieCache is betterauth.GetCookieCache with getCookieCache's `jwt: { jwks }`
// option: with strategy "jwt" and a JWKS the cache is verified with the public keys
// instead of the secret.
func GetCookieCache(h http.Header, o CookieCacheOptions) (*betterauth.SessionWithUser, error) {
	if o.Strategy != "jwt" || o.JWKS == nil {
		return betterauth.GetCookieCache(h, o.CookieCacheOptions)
	}
	set := *o.JWKS
	return betterauth.GetCookieCacheWithVerifier(h, o.CookieCacheOptions, func(token string) (*jsonx.Object, bool) {
		p := VerifySessionCookieJWTWithJWKS(token, set, SessionCookieJWTOptions{Issuer: o.Issuer, Audience: o.Audience})
		return p, p != nil
	})
}
