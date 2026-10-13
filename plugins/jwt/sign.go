package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// SigningKeyOverrides pin the signing key (SigningKeyOverrides).
type SigningKeyOverrides struct {
	SigningKeyID     string
	SigningAlgorithm string
}

// ErrDecryptPrivateKey is returned when a stored private key cannot be decrypted.
var ErrDecryptPrivateKey = errors.New("Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption.")

// ResolveSigningKey selects (and lazily mints) the signing key and decrypts it
// (resolveSigningKey). It returns nil when a custom JWT.Sign function is configured.
func ResolveSigningKey(ctx *betterauth.EndpointContext, opts *Options, overrides *SigningKeyOverrides) (*ResolvedSigningKey, error) {
	if opts.customSign() {
		return nil, nil
	}
	var ov SigningKeyOverrides
	if overrides != nil {
		ov = *overrides
	}
	ad := GetJwksAdapter(opts)
	var key *Jwk
	var err error
	primaryAlg := opts.primaryAlg()
	switch {
	case ov.SigningKeyID != "":
		key, err = ad.GetKeyByID(ctx, ov.SigningKeyID)
		if err != nil {
			return nil, err
		}
		if key == nil {
			return nil, fmt.Errorf("signJWT: signingKeyId %q not found in JWKS. The key must be provisioned before it can be referenced.", ov.SigningKeyID)
		}
		if ov.SigningAlgorithm != "" {
			effective := key.Alg
			if effective == "" {
				effective = primaryAlg
			}
			if effective != ov.SigningAlgorithm {
				desc := key.Alg
				if desc == "" {
					desc = fmt.Sprintf("unset (inherits keyPairConfig.alg %q)", primaryAlg)
				}
				return nil, fmt.Errorf("signJWT: signingKeyId %q has alg \"%s\" but signingAlgorithm was set to %q.", ov.SigningKeyID, desc, ov.SigningAlgorithm)
			}
		}
	case ov.SigningAlgorithm != "":
		key, err = ad.GetLatestKeyByAlg(ctx, ov.SigningAlgorithm)
		if err != nil {
			return nil, err
		}
		if key == nil {
			j := opts.jwks()
			var pre *JWKOptions
			for i := range j.KeyPairConfigs {
				if j.KeyPairConfigs[i].Alg == ov.SigningAlgorithm {
					pre = &j.KeyPairConfigs[i]
					break
				}
			}
			if pre != nil || primaryAlg == ov.SigningAlgorithm {
				o := Options{}
				if opts != nil {
					o = *opts
				}
				nj := j
				if pre != nil {
					nj.KeyPairConfig = pre
				}
				o.JWKS = &nj
				key, err = CreateJwk(ctx, &o)
				if err != nil {
					return nil, err
				}
			} else {
				var algs []string
				for _, c := range j.KeyPairConfigs {
					algs = append(algs, c.Alg)
				}
				extra := strings.Join(algs, ", ")
				if extra == "" {
					extra = "none"
				}
				return nil, fmt.Errorf("signJWT: no key with alg %q found in JWKS. The plugin auto-mints only one key matching keyPairConfig.alg=%q; additional algs configured via keyPairConfigs: %s. Add %q to jwks.keyPairConfigs so the plugin provisions it on first use, or mint the key explicitly via createJwk().", ov.SigningAlgorithm, primaryAlg, extra, ov.SigningAlgorithm)
			}
		}
	default:
		key, err = ad.GetLatestKeyByAlg(ctx, primaryAlg)
		if err != nil {
			return nil, err
		}
		if key == nil {
			key, err = ad.GetLatestKey(ctx)
			if err != nil {
				return nil, err
			}
		}
	}
	if key == nil || (key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now())) {
		if ov.SigningKeyID != "" || ov.SigningAlgorithm != "" {
			return nil, errors.New("signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.")
		}
		key, err = CreateJwk(ctx, opts)
		if err != nil {
			return nil, err
		}
	}
	privateJSON := key.PrivateKey
	if !opts.jwks().DisablePrivateKeyEncryption {
		var data string
		if err := json.Unmarshal([]byte(key.PrivateKey), &data); err != nil {
			return nil, err
		}
		dec, err := bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, data)
		if err != nil {
			return nil, ErrDecryptPrivateKey
		}
		privateJSON = dec
	}
	alg := key.Alg
	if alg == "" {
		alg = primaryAlg
	}
	pk, err := importPrivateJWK(privateJSON, alg)
	if err != nil {
		return nil, err
	}
	return &ResolvedSigningKey{Alg: alg, Kid: key.ID, PrivateKey: pk}, nil
}

func importPrivateJWK(raw, alg string) (any, error) {
	var k jose.JWK
	if err := json.Unmarshal([]byte(raw), &k); err != nil {
		return nil, err
	}
	if !jose.KeyMatchesAlg(k, alg) {
		return nil, fmt.Errorf("Invalid key for the %s algorithm", alg)
	}
	return k.PrivateKey()
}

func importPublicJWK(raw, alg string) (any, error) {
	var k jose.JWK
	if err := json.Unmarshal([]byte(raw), &k); err != nil {
		return nil, err
	}
	if !jose.KeyMatchesAlg(k, alg) {
		return nil, fmt.Errorf("Invalid key for the %s algorithm", alg)
	}
	return k.PublicKey()
}

// SignConfig is the input of SignJWT.
type SignConfig struct {
	Options *Options
	// Payload holds the claims; iat, exp, nbf, iss, aud, sub and jti are honoured.
	Payload *jsonx.Object
	// ResolvedKey skips key resolution.
	ResolvedKey      *ResolvedSigningKey
	Header           *Header
	SigningKeyID     string
	SigningAlgorithm string
}

func present(o *jsonx.Object, k string) (any, bool) {
	v, ok := o.Get(k)
	if !ok || v == nil {
		return nil, false
	}
	if v == jsonx.Undefined {
		return nil, false
	}
	return v, true
}

func truthy(v any, ok bool) bool {
	if !ok {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, isNum := adapter.ToFloat(v); isNum {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

// numericDate mirrors jose's numericDate for setExpirationTime / setNotBefore / setIssuedAt.
func numericDate(v any, label string) (any, error) {
	switch t := v.(type) {
	case time.Time:
		return math.Floor(float64(t.UnixMilli()) / 1000), nil
	case string:
		s, err := Sec(t)
		if err != nil {
			return nil, err
		}
		return float64(time.Now().Unix() + s), nil
	}
	f, ok := adapter.ToFloat(v)
	if !ok || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, fmt.Errorf("Invalid %s input", label)
	}
	return f, nil
}

func validAudience(v any) bool {
	switch t := v.(type) {
	case string:
		return true
	case []string:
		return true
	case []any:
		for _, x := range t {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}

// SignJWT signs a JWT with the plugin keys or the custom JWT.Sign function (signJWT).
func SignJWT(ctx *betterauth.EndpointContext, cfg SignConfig) (string, error) {
	opts := cfg.Options
	payload := cfg.Payload
	if payload == nil {
		payload = jsonx.NewObject()
	}
	now := time.Now().Unix()
	jo := opts.jwt()
	iatV, hasIat := present(payload, "iat")
	base := now
	if hasIat {
		if f, ok := adapter.ToFloat(iatV); ok {
			base = int64(f)
		}
	}
	var expTime any = "15m"
	if jo.ExpirationTime != nil {
		expTime = jo.ExpirationTime
	}
	defaultExp, err := ToExpJWT(expTime, base)
	if err != nil {
		return "", err
	}
	var exp any = defaultExp
	if v, ok := present(payload, "exp"); ok {
		exp = v
	}
	baseURL := ctx.Auth.Options.BaseURL
	var defaultIss any = baseURL
	if jo.Issuer != "" {
		defaultIss = jo.Issuer
	}
	var defaultAud any = baseURL
	if jo.Audience != nil {
		defaultAud = jo.Audience
	}
	iss := defaultIss
	if v, ok := present(payload, "iss"); ok {
		iss = v
	}
	aud := defaultAud
	if v, ok := present(payload, "aud"); ok {
		aud = v
	}
	if opts.customSign() {
		p := payload.Clone()
		orUndef := func(k string) any {
			if v, ok := present(payload, k); ok {
				return v
			}
			return jsonx.Undefined
		}
		p.Set("iat", orUndef("iat"))
		p.Set("exp", exp)
		p.Set("nbf", orUndef("nbf"))
		p.Set("iss", iss)
		p.Set("aud", aud)
		return jo.Sign(ctx, p, cfg.Header, SigningConfig{SigningKeyID: cfg.SigningKeyID, SigningAlgorithm: cfg.SigningAlgorithm})
	}
	key := cfg.ResolvedKey
	if key == nil {
		key, err = ResolveSigningKey(ctx, opts, &SigningKeyOverrides{SigningKeyID: cfg.SigningKeyID, SigningAlgorithm: cfg.SigningAlgorithm})
		if err != nil {
			return "", err
		}
	}
	header := jsonx.NewObject()
	if cfg.Header != nil {
		if cfg.Header.Typ != "" {
			header.Set("typ", cfg.Header.Typ)
		}
		if cfg.Header.Cty != "" {
			header.Set("cty", cfg.Header.Cty)
		}
	}
	header.Set("alg", key.Alg)
	header.Set("kid", key.Kid)
	claims := payload.Clone()
	ev, err := numericDate(exp, "setExpirationTime")
	if err != nil {
		return "", err
	}
	claims.Set("exp", ev)
	if _, ok := iss.(string); !ok {
		return "", errors.New(`JWT Claim "iss" must be a string`)
	}
	claims.Set("iss", iss)
	if !validAudience(aud) {
		return "", errors.New(`JWT Claim "aud" must be a string or an array of strings`)
	}
	claims.Set("aud", aud)
	if truthy(iatV, hasIat) {
		v, err := numericDate(iatV, "setIssuedAt")
		if err != nil {
			return "", err
		}
		claims.Set("iat", v)
	}
	if v, ok := present(payload, "sub"); truthy(v, ok) {
		if _, isStr := v.(string); !isStr {
			return "", errors.New(`JWT Claim "sub" must be a string`)
		}
	}
	if v, ok := present(payload, "nbf"); truthy(v, ok) {
		nv, err := numericDate(v, "setNotBefore")
		if err != nil {
			return "", err
		}
		claims.Set("nbf", nv)
	}
	if v, ok := present(payload, "jti"); truthy(v, ok) {
		if _, isStr := v.(string); !isStr {
			return "", errors.New(`JWT Claim "jti" must be a string`)
		}
	}
	return jose.SignJWT(header, claims, key.PrivateKey)
}

// userClaims renders the session user as a claims object.
func userClaims(u *betterauth.User) *jsonx.Object {
	if u == nil {
		return jsonx.NewObject()
	}
	b, err := json.Marshal(u)
	if err != nil {
		return jsonx.NewObject()
	}
	v, err := jsonx.Parse(b)
	if err != nil {
		return jsonx.NewObject()
	}
	o, _ := v.(*jsonx.Object)
	if o == nil {
		return jsonx.NewObject()
	}
	return o
}

// GetJwtToken signs a token for the current session (getJwtToken): the user object (or
// DefinePayload) with iat and sub.
func GetJwtToken(ctx *betterauth.EndpointContext, opts *Options) (string, error) {
	session := ctx.Session
	if session == nil {
		session = ctx.NewSession()
	}
	if session == nil {
		return "", errors.New("jwt: no session")
	}
	jo := opts.jwt()
	var data *jsonx.Object
	if jo.DefinePayload == nil {
		data = userClaims(session.User)
	} else {
		d, err := jo.DefinePayload(ctx, session)
		if err != nil {
			return "", err
		}
		data = d
	}
	payload := jsonx.O("iat", float64(time.Now().Unix()))
	if data != nil {
		for _, k := range data.Keys() {
			v, _ := data.Get(k)
			payload.Set(k, v)
		}
	}
	sub := ""
	if jo.GetSubject != nil {
		s, err := jo.GetSubject(ctx, session)
		if err != nil {
			return "", err
		}
		sub = s
	}
	if sub == "" && session.User != nil {
		sub = session.User.ID
	}
	payload.Set("sub", sub)
	return SignJWT(ctx, SignConfig{Options: opts, Payload: payload})
}
