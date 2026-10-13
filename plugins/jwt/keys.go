package jwt

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

var timeStringRe = regexp.MustCompile(`(?i)^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?|mo|years?|yrs?|y)(?: (ago|from now))?$`)

// ErrInvalidTimeString is returned (wrapped) for malformed time strings (a TypeError
// upstream).
var ErrInvalidTimeString = errors.New("invalid time string")

// ParseTimeString parses a time string ("7d", "30m", "1 hour", "2 hours ago", "-5m") and
// returns milliseconds (ms() in utils/time).
func ParseTimeString(value string) (float64, error) {
	m := timeStringRe.FindStringSubmatch(value)
	if m == nil || (m[4] != "" && m[1] != "") {
		return 0, fmt.Errorf("%w: Invalid time string format: %q. Use formats like \"7d\", \"30m\", \"1 hour\", etc.", ErrInvalidTimeString, value)
	}
	n, _ := strconv.ParseFloat(m[2], 64)
	const sec, minute, hour, day = 1000.0, 60 * 1000.0, 3600 * 1000.0, 86400 * 1000.0
	var result float64
	switch strings.ToLower(m[3]) {
	case "years", "year", "yrs", "yr", "y":
		result = n * day * 365.25
	case "months", "month", "mo":
		result = n * day * 30
	case "weeks", "week", "w":
		result = n * day * 7
	case "days", "day", "d":
		result = n * day
	case "hours", "hour", "hrs", "hr", "h":
		result = n * hour
	case "minutes", "minute", "mins", "min", "m":
		result = n * minute
	default:
		result = n * sec
	}
	if m[1] == "-" || m[4] == "ago" {
		return -result, nil
	}
	return result, nil
}

// Sec parses a time string and returns whole seconds (sec() in utils/time).
func Sec(value string) (int64, error) {
	ms, err := ParseTimeString(value)
	if err != nil {
		return 0, err
	}
	return int64(math.Floor(ms/1000 + 0.5)), nil
}

// ToExpJWT computes the exp claim (toExpJWT): numbers are absolute NumericDates, times are
// converted to seconds, time strings and durations are added to iat.
func ToExpJWT(expirationTime any, iat int64) (int64, error) {
	switch t := expirationTime.(type) {
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case float64:
		return int64(t), nil
	case time.Time:
		return int64(math.Floor(float64(t.UnixMilli()) / 1000)), nil
	case *time.Time:
		return int64(math.Floor(float64(t.UnixMilli()) / 1000)), nil
	case time.Duration:
		return iat + int64(math.Floor(t.Seconds()+0.5)), nil
	case string:
		s, err := Sec(t)
		if err != nil {
			return 0, err
		}
		return iat + s, nil
	}
	return 0, fmt.Errorf("%w: unsupported expirationTime %T", ErrInvalidTimeString, expirationTime)
}

// ExportedKeyPair is a generated key pair (generateExportedKeyPair).
type ExportedKeyPair struct {
	PublicWebKey  jose.JWK
	PrivateWebKey jose.JWK
	Alg           string
	// Cfg is the key pair config without the alg.
	Cfg JWKOptions
}

// GenerateExportedKeyPair generates a key pair for opts.JWKS.KeyPairConfig (default
// EdDSA / Ed25519).
func GenerateExportedKeyPair(opts *Options) (*ExportedKeyPair, error) {
	cfg := JWKOptions{Alg: "EdDSA", Crv: "Ed25519"}
	if kc := opts.keyPairConfig(); kc != nil {
		cfg = *kc
	}
	pub, priv, err := jose.GenerateKeyPair(cfg.Alg, jose.GenerateKeyOptions{Crv: cfg.Crv, ModulusLength: cfg.ModulusLength})
	if err != nil {
		return nil, err
	}
	pubJWK, err := jose.JWKFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	privJWK, err := jose.JWKFromPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	alg := cfg.Alg
	cfg.Alg = ""
	return &ExportedKeyPair{PublicWebKey: pubJWK, PrivateWebKey: privJWK, Alg: alg, Cfg: cfg}, nil
}

// CreateJwk generates, (optionally) encrypts and stores a new key (createJwk).
func CreateJwk(ctx *betterauth.EndpointContext, opts *Options) (*Jwk, error) {
	kp, err := GenerateExportedKeyPair(opts)
	if err != nil {
		return nil, err
	}
	crv := kp.Cfg.Crv
	if crv == "" {
		crv = kp.PublicWebKey.Crv
	}
	privateJSON := string(jsonx.MustMarshal(jose.ExportJWK(kp.PrivateWebKey)))
	j := opts.jwks()
	privateKey := privateJSON
	if !j.DisablePrivateKeyEncryption {
		enc, err := bacrypto.SymmetricEncrypt(ctx.Auth.SecretConfig, privateJSON)
		if err != nil {
			return nil, err
		}
		privateKey = string(jsonx.MustMarshal(enc))
	}
	key := Jwk{
		Alg:        kp.Alg,
		Crv:        crv,
		PublicKey:  string(jsonx.MustMarshal(jose.ExportJWK(kp.PublicWebKey))),
		PrivateKey: privateKey,
		CreatedAt:  time.Now(),
	}
	if j.RotationInterval > 0 {
		exp := time.Now().Add(j.RotationInterval)
		key.ExpiresAt = &exp
	}
	return GetJwksAdapter(opts).CreateJwk(ctx, key)
}

// jwkFromRecord converts an adapter row.
func jwkFromRecord(r adapter.Record) *Jwk {
	if r == nil {
		return nil
	}
	j := &Jwk{
		ID:         adapter.ToString(r["id"]),
		PublicKey:  str(r["publicKey"]),
		PrivateKey: str(r["privateKey"]),
		Alg:        str(r["alg"]),
		Crv:        str(r["crv"]),
	}
	if t, ok := adapter.ToTime(r["createdAt"]); ok {
		j.CreatedAt = t
	}
	if r["expiresAt"] != nil {
		if t, ok := adapter.ToTime(r["expiresAt"]); ok {
			j.ExpiresAt = &t
		}
	}
	return j
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return adapter.ToString(v)
}

func (j *Jwk) record() adapter.Record {
	r := adapter.Record{
		"publicKey":  j.PublicKey,
		"privateKey": j.PrivateKey,
		"createdAt":  j.CreatedAt,
	}
	if j.Alg != "" {
		r["alg"] = j.Alg
	}
	if j.Crv != "" {
		r["crv"] = j.Crv
	}
	if j.ExpiresAt != nil {
		r["expiresAt"] = *j.ExpiresAt
	}
	return r
}
