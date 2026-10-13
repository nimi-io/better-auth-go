// Package oauthcore ports the OAuth 2.0 helpers of @better-auth/core/oauth2 that the
// oauth-provider, mcp and cimd packages rely on and that the Go core does not ship:
// jose-compatible JWT verification (same error classes and messages as the `jose`
// library), DPoP proofs (RFC 9449), access-token verification for resource servers
// (verifyAccessTokenRequest / verifyBearerToken), insufficient-scope errors, JWKS
// fetching with caching, and Basic client credentials.
package oauthcore

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// JoseError mirrors the error classes thrown by the `jose` library. Name is the class name
// ("JWSInvalid", "JWTExpired", "TypeError", ...), Code the jose error code.
type JoseError struct {
	Name    string
	Code    string
	Message string
	// Claim / Reason are set for claim validation failures.
	Claim  string
	Reason string
}

func (e *JoseError) Error() string { return e.Message }

func joseErr(name, code, msg string) *JoseError {
	return &JoseError{Name: name, Code: code, Message: msg}
}

// jose error constructors (util/errors.js).
func errJWSInvalid(msg string) *JoseError { return joseErr("JWSInvalid", "ERR_JWS_INVALID", msg) }
func errJWTInvalid(msg string) *JoseError { return joseErr("JWTInvalid", "ERR_JWT_INVALID", msg) }
func errTypeError(msg string) *JoseError  { return joseErr("TypeError", "", msg) }
func errClaim(msg, claim, reason string) *JoseError {
	return &JoseError{Name: "JWTClaimValidationFailed", Code: "ERR_JWT_CLAIM_VALIDATION_FAILED", Message: msg, Claim: claim, Reason: reason}
}
func errExpired(msg, claim string) *JoseError {
	return &JoseError{Name: "JWTExpired", Code: "ERR_JWT_EXPIRED", Message: msg, Claim: claim, Reason: "check_failed"}
}

// ErrJWKSNoMatchingKey and friends are the jose JWKS errors.
func errNoMatchingKey() *JoseError {
	return joseErr("JWKSNoMatchingKey", "ERR_JWKS_NO_MATCHING_KEY", "no applicable key found in the JSON Web Key Set")
}
func errMultipleMatchingKeys() *JoseError {
	return joseErr("JWKSMultipleMatchingKeys", "ERR_JWKS_MULTIPLE_MATCHING_KEYS", "multiple matching keys found in the JSON Web Key Set")
}
func errJWKSInvalid(msg string) *JoseError {
	return joseErr("JWKSInvalid", "ERR_JWKS_INVALID", msg)
}
func errNotSupported(msg string) *JoseError {
	return joseErr("JOSENotSupported", "ERR_JOSE_NOT_SUPPORTED", msg)
}
func errSignatureFailed() *JoseError {
	return joseErr("JWSSignatureVerificationFailed", "ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "signature verification failed")
}

// AsJoseError extracts a *JoseError.
func AsJoseError(err error) (*JoseError, bool) {
	var e *JoseError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// ErrorName returns the JavaScript error name of err: the jose class name for jose errors,
// "Error" otherwise.
func ErrorName(err error) string {
	if e, ok := AsJoseError(err); ok {
		return e.Name
	}
	return "Error"
}

// IsJoseError reports whether err is a jose error (JOSEError subclass, not a TypeError).
func IsJoseError(err error) bool {
	e, ok := AsJoseError(err)
	return ok && e.Code != ""
}

func b64urlDecode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "+/=") {
		// jose decodes with a lenient decoder; base64url without padding is the norm.
		s = strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(s), "=")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func parseJoseHeader(b64 string, mk func(string) *JoseError, msg string) (*jsonx.Object, error) {
	raw, err := b64urlDecode(b64)
	if err != nil {
		return nil, mk(msg)
	}
	v, err := jsonx.Parse(raw)
	if err != nil {
		return nil, mk(msg)
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		return nil, mk(msg)
	}
	return o, nil
}

// DecodeProtectedHeader is jose's decodeProtectedHeader for compact tokens.
func DecodeProtectedHeader(token string) (*jsonx.Object, error) {
	parts := strings.Split(token, ".")
	invalid := "Invalid Token or Protected Header formatting"
	if (len(parts) != 3 && len(parts) != 5) || parts[0] == "" {
		return nil, errTypeError(invalid)
	}
	return parseJoseHeader(parts[0], errTypeError, invalid)
}

// DecodeJWT is jose's decodeJwt: it returns the (unverified) claims of a compact JWT.
func DecodeJWT(token string) (*jsonx.Object, error) {
	parts := strings.Split(token, ".")
	if len(parts) == 5 {
		return nil, errJWTInvalid("Only JWTs using Compact JWS serialization can be decoded")
	}
	if len(parts) != 3 {
		return nil, errJWTInvalid("Invalid JWT")
	}
	if parts[1] == "" {
		return nil, errJWTInvalid("JWTs must contain a payload")
	}
	raw, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, errJWTInvalid("Failed to base64url decode the payload")
	}
	v, err := jsonx.Parse(raw)
	if err != nil {
		return nil, errJWTInvalid("Failed to parse the decoded payload as JSON")
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		return nil, errJWTInvalid("Invalid JWT Claims Set")
	}
	return o, nil
}

// KeyResolver resolves the verification key for a protected header (a crypto public key,
// or []byte for HMAC algorithms).
type KeyResolver func(header *jsonx.Object) (any, error)

// StaticKey returns a resolver for a fixed key.
func StaticKey(key any) KeyResolver { return func(*jsonx.Object) (any, error) { return key, nil } }

// VerifyOptions are jose's JWTVerifyOptions.
type VerifyOptions struct {
	Algorithms []string
	// Issuer: any listed value is accepted (nil = no check).
	Issuer []string
	// Audience: the token must contain at least one listed value (nil = no check).
	Audience []string
	Subject  *string
	// Typ checks the "typ" header (normalised like jose).
	Typ string
	// MaxTokenAge in seconds (nil = no check).
	MaxTokenAge *float64
	// ClockTolerance in seconds.
	ClockTolerance float64
	RequiredClaims []string
	// CurrentDate overrides "now".
	CurrentDate time.Time
}

// VerifiedJWT is the result of JWTVerify / CompactVerify.
type VerifiedJWT struct {
	Header  *jsonx.Object
	Payload *jsonx.Object
	// RawPayload is the decoded payload bytes (CompactVerify).
	RawPayload []byte
}

var jwsAlgorithms = map[string]bool{
	"HS256": true, "HS384": true, "HS512": true,
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true, "Ed25519": true,
}

// CompactVerify verifies a compact JWS signature (jose compactVerify) without claim checks.
func CompactVerify(token string, key KeyResolver, algorithms []string) (*VerifiedJWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errJWSInvalid("Invalid Compact JWS")
	}
	header, err := parseJoseHeader(parts[0], errJWSInvalid, "JWS Protected Header is invalid")
	if err != nil {
		return nil, err
	}
	if crit, ok := header.Get("crit"); ok {
		if _, isArr := crit.([]any); !isArr {
			return nil, errJWSInvalid(`"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present`)
		}
		for _, c := range crit.([]any) {
			s, _ := c.(string)
			if s != "b64" {
				return nil, joseErr("JOSENotSupported", "ERR_JOSE_NOT_SUPPORTED", fmt.Sprintf(`Extension Header Parameter "%s" is not recognized`, s))
			}
		}
	}
	algV, _ := header.Get("alg")
	alg, _ := algV.(string)
	if alg == "" {
		return nil, errJWSInvalid(`JWS "alg" (Algorithm) Header Parameter missing or invalid`)
	}
	if algorithms != nil {
		allowed := false
		for _, a := range algorithms {
			if a == alg {
				allowed = true
			}
		}
		if !allowed {
			return nil, joseErr("JOSEAlgNotAllowed", "ERR_JOSE_ALG_NOT_ALLOWED", `"alg" (Algorithm) Header Parameter value not allowed`)
		}
	}
	k, err := key(header)
	if err != nil {
		return nil, err
	}
	if !jwsAlgorithms[alg] {
		return nil, errNotSupported(fmt.Sprintf(`Unsupported JWS algorithm: %s`, alg))
	}
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return nil, errJWSInvalid("Failed to base64url decode the signature")
	}
	if pk, ok := k.(*rsa.PublicKey); ok && (strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")) {
		if pk.N.BitLen() < 2048 {
			return nil, errTypeError(alg + " requires key modulusLength to be 2048 bits or larger")
		}
	}
	if err := jose.Verify(alg, k, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		if errors.Is(err, jose.ErrAlgorithm) {
			return nil, errTypeError("CryptoKey does not support this operation")
		}
		return nil, errSignatureFailed()
	}
	payload, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, errJWSInvalid("Failed to base64url decode the payload")
	}
	return &VerifiedJWT{Header: header, RawPayload: payload}, nil
}

func normalizeTyp(v string) string {
	n := strings.ToLower(v)
	if strings.Contains(v, "/") {
		return n
	}
	return "application/" + n
}

// JWTVerify is jose's jwtVerify: signature verification followed by claim validation.
func JWTVerify(token string, key KeyResolver, o VerifyOptions) (*VerifiedJWT, error) {
	v, err := CompactVerify(token, key, o.Algorithms)
	if err != nil {
		return nil, err
	}
	payload, err := ValidateClaimsSet(v.Header, v.RawPayload, o)
	if err != nil {
		return nil, err
	}
	v.Payload = payload
	return v, nil
}

func numClaim(p *jsonx.Object, claim string, required bool) (float64, bool, error) {
	val, ok := p.Get(claim)
	if !ok {
		if required {
			return 0, false, errClaim(fmt.Sprintf(`"%s" claim must be a number`, claim), claim, "invalid")
		}
		return 0, false, nil
	}
	f, isNum := val.(float64)
	if !isNum {
		return 0, false, errClaim(fmt.Sprintf(`"%s" claim must be a number`, claim), claim, "invalid")
	}
	return f, true, nil
}

// ValidateClaimsSet mirrors jose's validateClaimsSet.
func ValidateClaimsSet(header *jsonx.Object, raw []byte, o VerifyOptions) (*jsonx.Object, error) {
	pv, err := jsonx.Parse(raw)
	payload, ok := pv.(*jsonx.Object)
	if err != nil || !ok {
		return nil, errJWTInvalid("JWT Claims Set must be a top-level JSON object")
	}
	if o.Typ != "" {
		tv, _ := header.Get("typ")
		ts, isStr := tv.(string)
		if !isStr || normalizeTyp(ts) != normalizeTyp(o.Typ) {
			return nil, errClaim(`unexpected "typ" JWT header value`, "typ", "check_failed")
		}
	}
	presence := append([]string(nil), o.RequiredClaims...)
	if o.MaxTokenAge != nil {
		presence = append(presence, "iat")
	}
	if o.Audience != nil {
		presence = append(presence, "aud")
	}
	if o.Subject != nil {
		presence = append(presence, "sub")
	}
	if o.Issuer != nil {
		presence = append(presence, "iss")
	}
	seen := map[string]bool{}
	for i := len(presence) - 1; i >= 0; i-- {
		c := presence[i]
		if seen[c] {
			continue
		}
		seen[c] = true
		if !payload.Has(c) {
			return nil, errClaim(fmt.Sprintf(`missing required "%s" claim`, c), c, "missing")
		}
	}
	if o.Issuer != nil {
		iv, _ := payload.Get("iss")
		match := false
		for _, i := range o.Issuer {
			if s, ok := iv.(string); ok && s == i {
				match = true
			}
		}
		if !match {
			return nil, errClaim(`unexpected "iss" claim value`, "iss", "check_failed")
		}
	}
	if o.Subject != nil {
		sv, _ := payload.Get("sub")
		if s, ok := sv.(string); !ok || s != *o.Subject {
			return nil, errClaim(`unexpected "sub" claim value`, "sub", "check_failed")
		}
	}
	if o.Audience != nil {
		av, _ := payload.Get("aud")
		match := false
		switch t := av.(type) {
		case string:
			for _, a := range o.Audience {
				if a == t {
					match = true
				}
			}
		case []any:
			for _, a := range o.Audience {
				for _, x := range t {
					if s, ok := x.(string); ok && s == a {
						match = true
					}
				}
			}
		}
		if !match {
			return nil, errClaim(`unexpected "aud" claim value`, "aud", "check_failed")
		}
	}
	now := time.Now()
	if !o.CurrentDate.IsZero() {
		now = o.CurrentDate
	}
	ts := math.Floor(float64(now.UnixMilli()) / 1000)
	tol := o.ClockTolerance
	iat, _, err := numClaim(payload, "iat", o.MaxTokenAge != nil)
	if err != nil {
		return nil, err
	}
	nbf, hasNbf, err := numClaim(payload, "nbf", false)
	if err != nil {
		return nil, err
	}
	if hasNbf && nbf > ts+tol {
		return nil, errClaim(`"nbf" claim timestamp check failed`, "nbf", "check_failed")
	}
	exp, hasExp, err := numClaim(payload, "exp", false)
	if err != nil {
		return nil, err
	}
	if hasExp && exp <= ts-tol {
		return nil, errExpired(`"exp" claim timestamp check failed`, "exp")
	}
	if o.MaxTokenAge != nil {
		age := ts - iat
		if age-tol > *o.MaxTokenAge {
			return nil, errExpired(`"iat" claim timestamp check failed (too far in the past)`, "iat")
		}
		if age < -tol {
			return nil, errClaim(`"iat" claim timestamp check failed (it should be in the past)`, "iat", "check_failed")
		}
	}
	return payload, nil
}

// ---- JWK handling ----

// ParseJWK converts a JWK object into a jose.JWK.
func ParseJWK(v any) (jose.JWK, error) {
	var k jose.JWK
	b, err := jsonx.Marshal(v)
	if err != nil {
		return k, err
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return k, err
	}
	return k, nil
}

func algKty(alg string) ([]string, string) {
	switch {
	case alg == "EdDSA":
		return []string{"OKP"}, ""
	case alg == "Ed25519":
		return []string{"OKP"}, "Ed25519"
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return []string{"RSA"}, ""
	case alg == "ES256":
		return []string{"EC"}, "P-256"
	case alg == "ES384":
		return []string{"EC"}, "P-384"
	case alg == "ES512":
		return []string{"EC"}, "P-521"
	}
	return nil, ""
}

// LocalJWKSet mirrors jose's createLocalJWKSet: keys are selected by kid, alg, kty, crv,
// use and key_ops. jwks is the JWK Set document (keys as objects).
func LocalJWKSet(jwks any) (KeyResolver, error) {
	var keys []any
	switch t := jwks.(type) {
	case *jsonx.Object:
		kv, _ := t.Get("keys")
		keys, _ = kv.([]any)
		if kv == nil {
			return nil, errJWKSInvalid("JSON Web Key Set malformed")
		}
	case map[string]any:
		keys, _ = t["keys"].([]any)
		if t["keys"] == nil {
			return nil, errJWKSInvalid("JSON Web Key Set malformed")
		}
	case jose.JWKS:
		for _, k := range t.Keys {
			keys = append(keys, k)
		}
	default:
		return nil, errJWKSInvalid("JSON Web Key Set malformed")
	}
	type entry struct {
		raw map[string]any
		jwk jose.JWK
	}
	var entries []entry
	for _, k := range keys {
		b, err := jsonx.Marshal(k)
		if err != nil {
			return nil, errJWKSInvalid("JSON Web Key Set malformed")
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil || raw == nil {
			return nil, errJWKSInvalid("JSON Web Key Set malformed")
		}
		var jk jose.JWK
		_ = json.Unmarshal(b, &jk)
		entries = append(entries, entry{raw: raw, jwk: jk})
	}
	return func(h *jsonx.Object) (any, error) {
		algV, _ := h.Get("alg")
		alg, _ := algV.(string)
		ktys, crv := algKty(alg)
		if ktys == nil {
			return nil, errNotSupported(`Unsupported "alg" value for a JSON Web Key Set`)
		}
		kidV, hasKid := h.Get("kid")
		var candidates []entry
		for _, e := range entries {
			if ext, ok := e.raw["ext"]; ok {
				if _, isBool := ext.(bool); !isBool {
					continue
				}
			}
			if ops, ok := e.raw["key_ops"]; ok {
				arr, isArr := ops.([]any)
				if !isArr {
					continue
				}
				hasVerify := false
				for _, op := range arr {
					if s, _ := op.(string); s == "verify" {
						hasVerify = true
					}
				}
				if !hasVerify {
					continue
				}
			}
			kty, _ := e.raw["kty"].(string)
			ktyOK := false
			for _, k := range ktys {
				if k == kty {
					ktyOK = true
				}
			}
			if !ktyOK {
				continue
			}
			if hasKid {
				ks, isStr := kidV.(string)
				if !isStr || e.raw["kid"] != ks {
					continue
				}
			}
			if ja, ok := e.raw["alg"]; ok && ja != alg {
				continue
			}
			if use, ok := e.raw["use"]; ok && use != "sig" {
				continue
			}
			if crv != "" && e.raw["crv"] != crv {
				continue
			}
			candidates = append(candidates, e)
		}
		if len(candidates) == 0 {
			return nil, errNoMatchingKey()
		}
		if len(candidates) != 1 {
			return nil, errMultipleMatchingKeys()
		}
		c := candidates[0]
		if c.jwk.D != "" {
			return nil, errJWKSInvalid("JSON Web Key Set members must be public keys")
		}
		pk, err := c.jwk.PublicKey()
		if err != nil {
			return nil, errTypeError("Invalid keyData")
		}
		return pk, nil
	}, nil
}

// ImportJWK is jose's importJWK for public keys: it checks the key type matches alg.
func ImportJWK(jwk jose.JWK, alg string) (any, error) {
	if jwk.Kty == "oct" {
		return nil, errNotSupported("unsupported JWK key type")
	}
	if !jose.KeyMatchesAlg(jwk, alg) {
		return nil, errNotSupported("Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
	}
	pk, err := jwk.PublicKey()
	if err != nil {
		return nil, errTypeError("Invalid keyData")
	}
	return pk, nil
}
