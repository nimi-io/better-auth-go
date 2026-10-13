package oauthcore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of packages/core/src/oauth2/dpop.ts.

// DPoP constants.
const (
	DPoPAuthorizationScheme   = "DPoP"
	BearerAuthorizationScheme = "Bearer"
	DPoPProofType             = "dpop+jwt"
	defaultDPoPProofMaxAge    = 300
	maxDPoPJTILength          = 512
)

// DPoPSigningAlgorithms are the default accepted DPoP proof algorithms.
var DPoPSigningAlgorithms = []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"}

var jwkPrivateFields = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// AccessTokenAuthorization is a parsed Authorization header.
type AccessTokenAuthorization struct {
	// Scheme is "Bearer", "DPoP" or "Unknown".
	Scheme string
	Token  string
}

// DPoPError is a DPoP proof or binding error; Code is "invalid_dpop_proof" or
// "invalid_token".
type DPoPError struct {
	Code    string
	Message string
	// Binding marks errors created by EnforceDPoPBinding (createDpopBindingError).
	Binding bool
}

func (e *DPoPError) Error() string { return e.Message }

func proofError(msg string) *DPoPError { return &DPoPError{Code: "invalid_dpop_proof", Message: msg} }

// IsDPoPProofError reports isDpopProofError(err).
func IsDPoPProofError(err error) bool {
	var e *DPoPError
	return errors.As(err, &e) && e.Code == "invalid_dpop_proof"
}

// IsDPoPBindingError reports isDpopBindingError(err).
func IsDPoPBindingError(err error) (*DPoPError, bool) {
	var e *DPoPError
	if errors.As(err, &e) && (e.Code == "invalid_token" || e.Code == "invalid_dpop_proof") {
		return e, true
	}
	return nil, false
}

// DPoPReplayReservation is one replay-store reservation.
type DPoPReplayReservation struct {
	Key       string
	ExpiresAt time.Time
	Now       time.Time
}

// DPoPReplayStore reserves proof identifiers; Reserve returns false on replay.
type DPoPReplayStore interface {
	Reserve(ctx context.Context, r DPoPReplayReservation) (bool, error)
}

type memoryReplayStore struct {
	mu   sync.Mutex
	keys map[string]time.Time
}

// NewInMemoryDPoPReplayStore is createInMemoryDpopReplayStore.
func NewInMemoryDPoPReplayStore() DPoPReplayStore {
	return &memoryReplayStore{keys: map[string]time.Time{}}
}

func (s *memoryReplayStore) Reserve(_ context.Context, r DPoPReplayReservation) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.keys {
		if !exp.After(r.Now) {
			delete(s.keys, k)
		}
	}
	if _, ok := s.keys[r.Key]; ok {
		return false, nil
	}
	s.keys[r.Key] = r.ExpiresAt
	return true, nil
}

// DPoPReplayReservations reserves verification values (the internal adapter's
// reserveVerificationValue).
type DPoPReplayReservations interface {
	ReserveVerificationValue(ctx context.Context, identifier, value string, expiresAt time.Time) (bool, error)
}

type reservationStore struct{ r DPoPReplayReservations }

// NewDPoPReplayStore is createDpopReplayStore: replays are tracked as verification rows
// with identifier "dpop-proof:<key>".
func NewDPoPReplayStore(r DPoPReplayReservations) DPoPReplayStore { return reservationStore{r} }

func (s reservationStore) Reserve(ctx context.Context, r DPoPReplayReservation) (bool, error) {
	return s.r.ReserveVerificationValue(ctx, "dpop-proof:"+r.Key, r.Key, r.ExpiresAt)
}

var authorizationRe = regexp.MustCompile("^([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\\s+(.+)$")

// ParseAccessTokenAuthorization is parseAccessTokenAuthorization (nil when empty).
func ParseAccessTokenAuthorization(authorization string) *AccessTokenAuthorization {
	if authorization == "" {
		return nil
	}
	value := strings.TrimSpace(authorization)
	if value == "" {
		return nil
	}
	m := authorizationRe.FindStringSubmatch(value)
	if m == nil {
		return &AccessTokenAuthorization{Scheme: "Unknown", Token: value}
	}
	token := strings.TrimSpace(m[2])
	switch strings.ToLower(m[1]) {
	case "bearer":
		return &AccessTokenAuthorization{Scheme: "Bearer", Token: token}
	case "dpop":
		return &AccessTokenAuthorization{Scheme: "DPoP", Token: token}
	}
	return &AccessTokenAuthorization{Scheme: "Unknown", Token: value}
}

// StripAccessTokenAuthorizationScheme removes a leading "Bearer " / "DPoP " scheme.
func StripAccessTokenAuthorizationScheme(token string) string {
	if a := ParseAccessTokenAuthorization(token); a != nil {
		return a.Token
	}
	return token
}

// NormalizeDPoPHTU returns origin + pathname of url (normalizeDpopHtu).
func NormalizeDPoPHTU(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return "", errors.New("Invalid URL")
	}
	if u.Fragment != "" {
		return "", errors.New("DPoP proof htu must not contain a fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch {
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	}
	path := u.EscapedPath()
	if path == "" && (scheme == "http" || scheme == "https") {
		path = "/"
	}
	if host == "" {
		return "null" + path, nil
	}
	return scheme + "://" + host + path, nil
}

// DeriveDPoPAth is base64url(SHA-256(accessToken)).
func DeriveDPoPAth(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GetConfirmationJKT returns cnf.jkt when it is a non-empty string.
func GetConfirmationJKT(confirmation any) string {
	switch t := confirmation.(type) {
	case *jsonx.Object:
		if t == nil {
			return ""
		}
		v, _ := t.Get("jkt")
		s, _ := v.(string)
		return s
	case map[string]any:
		s, _ := t["jkt"].(string)
		return s
	case map[string]string:
		return t["jkt"]
	}
	return ""
}

// GetDPoPJKTFromPayload returns payload.cnf.jkt.
func GetDPoPJKTFromPayload(payload *jsonx.Object) string {
	if payload == nil {
		return ""
	}
	v, _ := payload.Get("cnf")
	return GetConfirmationJKT(v)
}

// VerifyDPoPProofOptions are verifyDpopProof options.
type VerifyDPoPProofOptions struct {
	ProofJWT    string
	Method      string
	URL         string
	AccessToken *string
	ExpectedJKT string
	RequireAth  bool
	// NowSeconds overrides the current time (0 = now).
	NowSeconds         int64
	ProofMaxAgeSeconds int
	SigningAlgorithms  []string
	ReplayStore        DPoPReplayStore
}

// VerifiedDPoPProof is the verified proof.
type VerifiedDPoPProof struct {
	JWK       *jsonx.Object
	JKT       string
	JTI       string
	HTM       string
	HTU       string
	IAT       float64
	Ath       string
	ReplayKey string
	ExpiresAt time.Time
}

func stringClaim(p *jsonx.Object, k string) string {
	v, _ := p.Get(k)
	s, _ := v.(string)
	return s
}

// VerifyDPoPProof is verifyDpopProof.
func VerifyDPoPProof(ctx context.Context, o VerifyDPoPProofOptions) (*VerifiedDPoPProof, error) {
	if o.ProofJWT == "" || len(strings.Split(o.ProofJWT, ".")) != 3 {
		return nil, proofError("DPoP proof must be a compact JWT")
	}
	now := o.NowSeconds
	if now == 0 {
		now = time.Now().Unix()
	}
	maxAge := o.ProofMaxAgeSeconds
	if maxAge == 0 {
		maxAge = defaultDPoPProofMaxAge
	}
	algs := o.SigningAlgorithms
	if algs == nil {
		algs = DPoPSigningAlgorithms
	}
	header, err := DecodeProtectedHeader(o.ProofJWT)
	if err != nil {
		return nil, proofError(err.Error())
	}
	typV, _ := header.Get("typ")
	if typ, _ := typV.(string); typ != DPoPProofType {
		return nil, proofError(`DPoP proof typ must be "dpop+jwt"`)
	}
	algV, _ := header.Get("alg")
	alg, _ := algV.(string)
	if alg == "" || alg == "none" || strings.HasPrefix(alg, "HS") {
		return nil, proofError("DPoP proof must use an asymmetric JWS algorithm")
	}
	supported := false
	for _, a := range algs {
		if a == alg {
			supported = true
		}
	}
	if !supported {
		return nil, proofError("DPoP proof uses an unsupported JWS algorithm")
	}
	jwkV, _ := header.Get("jwk")
	jwkObj, ok := jwkV.(*jsonx.Object)
	if !ok || jwkObj == nil {
		return nil, proofError("DPoP proof header must include a public jwk")
	}
	if kty, _ := jwkObj.Get("kty"); kty == "oct" {
		return nil, proofError("DPoP proof jwk must be asymmetric")
	}
	for _, f := range jwkPrivateFields {
		if jwkObj.Has(f) {
			return nil, proofError("DPoP proof jwk must not contain private key material")
		}
	}
	jwk, err := ParseJWK(jwkObj)
	if err != nil {
		return nil, proofError("Invalid keyData")
	}
	pub, err := ImportJWK(jwk, alg)
	if err != nil {
		return nil, proofError(err.Error())
	}
	verified, err := JWTVerify(o.ProofJWT, StaticKey(pub), VerifyOptions{Typ: DPoPProofType})
	if err != nil {
		return nil, proofError(err.Error())
	}
	payload := verified.Payload
	htm := stringClaim(payload, "htm")
	htu := stringClaim(payload, "htu")
	jti := stringClaim(payload, "jti")
	iatV, _ := payload.Get("iat")
	iat, iatOK := iatV.(float64)
	if iatOK && (math.IsInf(iat, 0) || math.IsNaN(iat)) {
		iatOK = false
	}
	if htm == "" || htu == "" || jti == "" || !iatOK {
		return nil, proofError("DPoP proof must include htm, htu, jti, and iat claims")
	}
	if len([]rune(jti)) > maxDPoPJTILength {
		return nil, proofError("DPoP proof jti is too large")
	}
	if !strings.EqualFold(htm, o.Method) {
		return nil, proofError("DPoP proof htm does not match the request method")
	}
	normalized, err := NormalizeDPoPHTU(o.URL)
	if err != nil {
		return nil, proofError(err.Error())
	}
	proofHTU, err := NormalizeDPoPHTU(htu)
	if err != nil {
		return nil, proofError(err.Error())
	}
	if proofHTU != normalized {
		return nil, proofError("DPoP proof htu does not match the request URL")
	}
	nowF := float64(now)
	if iat > nowF+5 || nowF-iat > float64(maxAge) {
		return nil, proofError("DPoP proof iat is outside the accepted window")
	}
	ath := stringClaim(payload, "ath")
	if o.RequireAth && ath == "" {
		return nil, proofError("DPoP proof must include an ath claim")
	}
	if o.AccessToken != nil {
		if ath != DeriveDPoPAth(*o.AccessToken) {
			return nil, proofError("DPoP proof ath does not match the access token")
		}
	}
	jkt := jwk.Thumbprint()
	if o.ExpectedJKT != "" && jkt != o.ExpectedJKT {
		return nil, proofError("DPoP proof key does not match the bound token")
	}
	sum := sha256.Sum256([]byte(jkt + "\n" + strings.ToUpper(htm) + "\n" + normalized + "\n" + jti))
	replayKey := base64.RawURLEncoding.EncodeToString(sum[:])
	expiresAt := time.Unix(int64(iat)+int64(maxAge), 0)
	if o.ReplayStore != nil {
		ok, err := o.ReplayStore.Reserve(ctx, DPoPReplayReservation{Key: replayKey, ExpiresAt: expiresAt, Now: time.Unix(now, 0)})
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, proofError("DPoP proof jti has already been used")
		}
	}
	return &VerifiedDPoPProof{JWK: jwkObj, JKT: jkt, JTI: jti, HTM: htm, HTU: normalized, IAT: iat,
		Ath: ath, ReplayKey: replayKey, ExpiresAt: expiresAt}, nil
}

// EnforceDPoPBindingParams are enforceDpopBinding parameters.
type EnforceDPoPBindingParams struct {
	Payload            *jsonx.Object
	Authorization      *AccessTokenAuthorization
	ProofJWT           string
	Method             string
	URL                string
	ReplayStore        DPoPReplayStore
	ProofMaxAgeSeconds int
	SigningAlgorithms  []string
}

func bindingError(code, msg string) *DPoPError {
	return &DPoPError{Code: code, Message: msg, Binding: true}
}

// EnforceDPoPBinding is enforceDpopBinding.
func EnforceDPoPBinding(ctx context.Context, p EnforceDPoPBindingParams) error {
	jkt := GetDPoPJKTFromPayload(p.Payload)
	if jkt == "" {
		if p.Authorization.Scheme == "DPoP" {
			return bindingError("invalid_token", "DPoP authorization requires a DPoP-bound access token")
		}
		return nil
	}
	if p.Authorization.Scheme != "DPoP" {
		return bindingError("invalid_token", "DPoP-bound access token requires the DPoP authorization scheme")
	}
	if p.ProofJWT == "" {
		return bindingError("invalid_dpop_proof", "DPoP proof header is required")
	}
	token := p.Authorization.Token
	_, err := VerifyDPoPProof(ctx, VerifyDPoPProofOptions{
		ProofJWT: p.ProofJWT, Method: p.Method, URL: p.URL, AccessToken: &token, ExpectedJKT: jkt,
		RequireAth: true, ProofMaxAgeSeconds: p.ProofMaxAgeSeconds, SigningAlgorithms: p.SigningAlgorithms,
		ReplayStore: p.ReplayStore,
	})
	if err != nil {
		if IsDPoPProofError(err) {
			return bindingError("invalid_dpop_proof", err.Error())
		}
		return err
	}
	return nil
}
