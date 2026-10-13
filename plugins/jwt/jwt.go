// Package jwt is the jwt plugin (packages/better-auth/src/plugins/jwt): it issues JWTs for
// sessions (/token and the set-auth-jwt header of /get-session), publishes the public keys
// at /jwks, manages (encrypted, rotating) signing keys in the jwks table, and can sign the
// session cookie cache with those keys.
package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// DefaultGracePeriod keeps expired keys in /jwks for 30 days.
const DefaultGracePeriod = 30 * 24 * time.Hour

// Validate checks the options like the jwt() constructor.
func Validate(opts *Options) error {
	j := opts.jwks()
	if opts.customSign() && j.RemoteURL == "" {
		return errors.New("options.jwks.remoteUrl must be set when using options.jwt.sign")
	}
	if j.RemoteURL != "" && (j.KeyPairConfig == nil || j.KeyPairConfig.Alg == "") {
		return errors.New("options.jwks.keyPairConfig.alg must be specified when options.jwks.remoteUrl is used for OpenID metadata")
	}
	p := jwksPath(opts)
	if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return errors.New("options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'")
	}
	return nil
}

func jwksPath(opts *Options) string {
	if opts != nil && opts.JWKS != nil && opts.JWKS.JWKSPath != "" {
		return opts.JWKS.JWKSPath
	}
	return "/jwks"
}

// Schema returns the jwks table definition.
func Schema(opts *Options) []db.PluginTable {
	col := func(name string) string {
		if opts != nil && opts.Schema != nil {
			if c := opts.Schema.Fields[name]; c != "" {
				return c
			}
		}
		return ""
	}
	model := ""
	if opts != nil && opts.Schema != nil {
		model = opts.Schema.ModelName
	}
	return []db.PluginTable{{
		Key: "jwks", ModelName: model,
		Fields: []db.Field{
			{Name: "publicKey", Type: db.TypeString, Required: db.True, FieldName: col("publicKey")},
			{Name: "privateKey", Type: db.TypeString, Required: db.True, FieldName: col("privateKey")},
			{Name: "createdAt", Type: db.TypeDate, Required: db.True, FieldName: col("createdAt")},
			{Name: "expiresAt", Type: db.TypeDate, Required: db.False, FieldName: col("expiresAt")},
			{Name: "alg", Type: db.TypeString, Required: db.False, FieldName: col("alg")},
			{Name: "crv", Type: db.TypeString, Required: db.False, FieldName: col("crv")},
		},
	}}
}

// New creates the jwt plugin. Invalid options make betterauth.New fail.
func New(options ...Options) *betterauth.Plugin {
	var o Options
	if len(options) > 0 {
		o = options[0]
	}
	opts := &o
	validationErr := Validate(opts)
	return &betterauth.Plugin{
		ID:      "jwt",
		Options: opts,
		Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			if validationErr != nil {
				return nil, validationErr
			}
			if !opts.SessionCookieCache {
				return nil, nil
			}
			s := ac.Options.Session
			if s == nil || s.CookieCache == nil || s.CookieCache.Strategy != "jwt" {
				return nil, errors.New("`jwt({ sessionCookieCache: true })` requires `session.cookieCache.strategy = \"jwt\"`.")
			}
			if opts.customSign() {
				return nil, errCookieCacheNeedsLocalKeys
			}
			maxAge := s.CookieCache.MaxAge
			if maxAge == 0 {
				maxAge = 5 * time.Minute
			}
			if gp := opts.jwks().GracePeriod; gp != nil && maxAge > *gp {
				ac.Logger.Warn(fmt.Sprintf("[better-auth] `session.cookieCache.maxAge` (%ds) exceeds the JWT plugin JWKS grace period (%ds). Rotated keys may stop verifying cookie-cache JWTs before the cookie expires.",
					int64(maxAge/time.Second), int64(*gp/time.Second)))
			}
			ac.SessionConfig.CookieCacheSigner = &cookieCacheSigner{opts: opts}
			return nil, nil
		},
		Endpoints: []*betterauth.Endpoint{
			getJwksEndpoint(opts),
			getTokenEndpoint(opts),
			signJWTEndpoint(opts),
			verifyJWTEndpoint(opts),
		},
		Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool { return ctx.Path == "/get-session" },
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if opts.DisableSettingJwtHeader {
					return nil, nil
				}
				session := ctx.Session
				if session == nil {
					session = ctx.NewSession()
				}
				if session == nil || session.Session == nil {
					return nil, nil
				}
				token, err := GetJwtToken(ctx, opts)
				if err != nil {
					return nil, err
				}
				exposed := ctx.ResponseHeaders.Get("Access-Control-Expose-Headers")
				var list []string
				seen := map[string]bool{}
				for _, h := range strings.Split(exposed, ",") {
					h = strings.TrimSpace(h)
					if h == "" || seen[h] {
						continue
					}
					seen[h] = true
					list = append(list, h)
				}
				if !seen["set-auth-jwt"] {
					list = append(list, "set-auth-jwt")
				}
				ctx.SetHeader("set-auth-jwt", token)
				ctx.SetHeader("Access-Control-Expose-Headers", strings.Join(list, ", "))
				return nil, nil
			},
		}}},
		Schema: Schema(opts),
	}
}

func jwksOpenAPI() *jsonx.Object {
	str := func(desc string, nullable bool) *jsonx.Object {
		o := jsonx.O("type", "string", "description", desc)
		if nullable {
			o.Set("nullable", true)
		}
		return o
	}
	return jsonx.O(
		"operationId", "getJSONWebKeySet",
		"description", "Get the JSON Web Key Set",
		"responses", jsonx.O("200", jsonx.O(
			"description", "JSON Web Key Set retrieved successfully",
			"content", jsonx.O("application/json", jsonx.O("schema", jsonx.O(
				"type", "object",
				"properties", jsonx.O("keys", jsonx.O(
					"type", "array",
					"description", "Array of public JSON Web Keys",
					"items", jsonx.O(
						"type", "object",
						"properties", jsonx.O(
							"kid", str("Key ID uniquely identifying the key, corresponds to the 'id' from the stored Jwk", false),
							"kty", str("Key type (e.g., 'RSA', 'EC', 'OKP')", false),
							"alg", str("Algorithm intended for use with the key (e.g., 'EdDSA', 'RS256')", false),
							"use", jsonx.O("type", "string", "description", "Intended use of the public key (e.g., 'sig' for signature)", "enum", []any{"sig"}, "nullable", true),
							"n", str("Modulus for RSA keys (base64url-encoded)", true),
							"e", str("Exponent for RSA keys (base64url-encoded)", true),
							"crv", str("Curve name for elliptic curve keys (e.g., 'Ed25519', 'P-256')", true),
							"x", str("X coordinate for elliptic curve keys (base64url-encoded)", true),
							"y", str("Y coordinate for elliptic curve keys (base64url-encoded)", true),
						),
						"required", []any{"kid", "kty", "alg"},
					),
				)),
				"required", []any{"keys"},
			))),
		)),
	)
}

// PublicJWKS renders the public key set served at /jwks for the given keys.
func PublicJWKS(keys []*Jwk, opts *Options) (*jsonx.Object, error) {
	gp := DefaultGracePeriod
	if g := opts.jwks().GracePeriod; g != nil {
		gp = *g
	}
	now := time.Now()
	var defaultCrv any = jsonx.Undefined
	if kc := opts.keyPairConfig(); kc != nil && kc.Crv != "" {
		defaultCrv = kc.Crv
	}
	out := []any{}
	for _, k := range keys {
		if k == nil {
			continue
		}
		if k.ExpiresAt != nil && !k.ExpiresAt.Add(gp).After(now) {
			continue
		}
		alg := k.Alg
		if alg == "" {
			alg = opts.primaryAlg()
		}
		var crv = defaultCrv
		if k.Crv != "" {
			crv = k.Crv
		}
		o := jsonx.O("alg", alg, "crv", crv)
		parsed, err := jsonx.Parse([]byte(k.PublicKey))
		if err != nil {
			return nil, err
		}
		if po, ok := parsed.(*jsonx.Object); ok {
			for _, key := range po.Keys() {
				v, _ := po.Get(key)
				o.Set(key, v)
			}
		}
		o.Set("kid", k.ID)
		out = append(out, o)
	}
	return jsonx.O("keys", out), nil
}

func getJwksEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getJwks", Path: jwksPath(opts), Methods: []string{"GET"},
		Metadata: map[string]any{"openapi": jwksOpenAPI()},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if opts.jwks().RemoteURL != "" {
				return nil, betterauth.ErrStatus("NOT_FOUND")
			}
			ad := GetJwksAdapter(opts)
			keys, err := ad.GetAllKeys(ctx)
			if err != nil {
				return nil, err
			}
			if len(keys) == 0 {
				if _, err := CreateJwk(ctx, opts); err != nil {
					return nil, err
				}
				keys, err = ad.GetAllKeys(ctx)
				if err != nil {
					return nil, err
				}
			}
			if len(keys) == 0 {
				return nil, errors.New("No key sets found. Make sure you have a key in your database.")
			}
			return PublicJWKS(keys, opts)
		},
	}
}

func getTokenEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getToken", Path: "/token", Methods: []string{"GET"}, RequireHeaders: true,
		Use: []betterauth.Middleware{betterauth.SessionMiddleware},
		Metadata: map[string]any{"openapi": jsonx.O(
			"operationId", "getJSONWebToken",
			"description", "Get a JWT token",
			"responses", jsonx.O("200", jsonx.O(
				"description", "Success",
				"content", jsonx.O("application/json", jsonx.O("schema", jsonx.O(
					"type", "object",
					"properties", jsonx.O("token", jsonx.O("type", "string")),
				))),
			)),
		)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			token, err := GetJwtToken(ctx, opts)
			if err != nil {
				return nil, err
			}
			return jsonx.O("token", token), nil
		},
	}
}

var signJWTBody = validate.Object(
	validate.F("payload", validate.Record(validate.Any())),
	validate.F("overrideOptions", validate.Optional(validate.Record(validate.Any()))),
)

var verifyJWTBody = validate.Object(
	validate.F("token", validate.String()),
	validate.F("issuer", validate.Optional(validate.String())),
)

func signJWTEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "signJWT", Methods: []string{"POST"}, ServerOnly: true, Body: signJWTBody,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			body := ctx.BodyMap()
			merged := opts
			if ov, ok := body["overrideOptions"].(map[string]any); ok {
				m, err := mergeOverrideOptions(opts, ov)
				if err != nil {
					return nil, err
				}
				merged = m
			}
			payload, err := toObject(body["payload"])
			if err != nil {
				return nil, err
			}
			token, err := SignJWT(ctx, SignConfig{Options: merged, Payload: payload})
			if err != nil {
				return nil, err
			}
			return jsonx.O("token", token), nil
		},
	}
}

func verifyJWTEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "verifyJWT", Methods: []string{"POST"}, ServerOnly: true, Body: verifyJWTBody,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			o := opts
			if iss := ctx.BodyString("issuer"); iss != "" {
				c := *opts
				jo := opts.jwt()
				jo.Issuer = iss
				c.JWT = &jo
				o = &c
			}
			payload := VerifyJWT(ctx, ctx.BodyString("token"), o)
			if payload == nil {
				return jsonx.O("payload", nil), nil
			}
			return jsonx.O("payload", payload), nil
		},
	}
}

func toObject(v any) (*jsonx.Object, error) {
	if o, ok := v.(*jsonx.Object); ok {
		return o, nil
	}
	b, err := jsonx.Marshal(v)
	if err != nil {
		return nil, err
	}
	parsed, err := jsonx.Parse(b)
	if err != nil {
		return nil, err
	}
	o, _ := parsed.(*jsonx.Object)
	if o == nil {
		o = jsonx.NewObject()
	}
	return o, nil
}

// mergeOverrideOptions applies the signJWT endpoint's overrideOptions
// ({...options, ...overrideOptions}): top-level keys replace the configured ones.
func mergeOverrideOptions(base *Options, ov map[string]any) (*Options, error) {
	c := Options{}
	if base != nil {
		c = *base
	}
	if v, ok := ov["jwt"]; ok {
		m, _ := v.(map[string]any)
		jo := &JWTOptions{}
		if m != nil {
			if s, ok := m["issuer"].(string); ok {
				jo.Issuer = s
			}
			if a, ok := m["audience"]; ok {
				jo.Audience = a
			}
			if e, ok := m["expirationTime"]; ok {
				jo.ExpirationTime = e
			}
		} else {
			jo = nil
		}
		c.JWT = jo
	}
	if v, ok := ov["jwks"]; ok {
		m, _ := v.(map[string]any)
		if m == nil {
			c.JWKS = nil
		} else {
			j := &JWKSOptions{}
			if s, ok := m["remoteUrl"].(string); ok {
				j.RemoteURL = s
			}
			if s, ok := m["jwksPath"].(string); ok {
				j.JWKSPath = s
			}
			if b, ok := m["disablePrivateKeyEncryption"].(bool); ok {
				j.DisablePrivateKeyEncryption = b
			}
			if f, ok := m["rotationInterval"].(float64); ok {
				j.RotationInterval = time.Duration(f * float64(time.Second))
			}
			if f, ok := m["gracePeriod"].(float64); ok {
				d := time.Duration(f * float64(time.Second))
				j.GracePeriod = &d
			}
			if kc, ok := m["keyPairConfig"].(map[string]any); ok {
				j.KeyPairConfig = jwkOptionsFromMap(kc)
			}
			if list, ok := m["keyPairConfigs"].([]any); ok {
				for _, x := range list {
					if km, ok := x.(map[string]any); ok {
						j.KeyPairConfigs = append(j.KeyPairConfigs, *jwkOptionsFromMap(km))
					}
				}
			}
			c.JWKS = j
		}
	}
	if b, ok := ov["disableSettingJwtHeader"].(bool); ok {
		c.DisableSettingJwtHeader = b
	}
	if b, ok := ov["sessionCookieCache"].(bool); ok {
		c.SessionCookieCache = b
	}
	return &c, nil
}

func jwkOptionsFromMap(m map[string]any) *JWKOptions {
	o := &JWKOptions{}
	o.Alg, _ = m["alg"].(string)
	o.Crv, _ = m["crv"].(string)
	if f, ok := m["modulusLength"].(float64); ok {
		o.ModulusLength = int(f)
	}
	return o
}
