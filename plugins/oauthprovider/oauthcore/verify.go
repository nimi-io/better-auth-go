package oauthcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of packages/core/src/oauth2/verify.ts.

// HTTPClient performs JWKS and introspection requests; redirects are refused
// (fetchRefusingRedirects). Tests may replace it.
var HTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	},
}

const (
	jwksCacheTTL             = 5 * time.Minute
	jwksNoKidRefetchCooldown = 30 * time.Second
)

type jwksCacheEntry struct {
	jwks             *jsonx.Object
	fetchedAt        time.Time
	noKidRefetchedAt time.Time
}

var (
	jwksCacheMu sync.Mutex
	// urlJwksCache caches JWKS fetched from URLs (jwksCache upstream).
	urlJwksCache = map[string]*jwksCacheEntry{}
	// keyedJwksCache caches JWKS returned by fetch functions, keyed by JWKSFetch.CacheKey.
	keyedJwksCache = map[any]*jwksCacheEntry{}
)

// ResetJWKSCache clears the JWKS caches (tests).
func ResetJWKSCache() {
	jwksCacheMu.Lock()
	defer jwksCacheMu.Unlock()
	urlJwksCache = map[string]*jwksCacheEntry{}
	keyedJwksCache = map[any]*jwksCacheEntry{}
}

// JWKSFetch selects the JWKS source: a URL, or a function (optionally cached by CacheKey).
type JWKSFetch struct {
	URL      string
	Func     func(ctx context.Context) (*jsonx.Object, error)
	CacheKey any
}

type resolvedJWKS struct {
	jwks             *jsonx.Object
	fromCache        bool
	kid              string
	noKidRefetchedAt time.Time
}

func jwksHasKid(jwks *jsonx.Object, kid string) bool {
	kv, _ := jwks.Get("keys")
	keys, _ := kv.([]any)
	for _, k := range keys {
		if o, ok := k.(*jsonx.Object); ok {
			if v, _ := o.Get("kid"); v == kid {
				return true
			}
		}
	}
	return false
}

func freshWithKid(c *jwksCacheEntry, kid string) *jsonx.Object {
	if c == nil || time.Since(c.fetchedAt) >= jwksCacheTTL {
		return nil
	}
	if kid != "" && !jwksHasKid(c.jwks, kid) {
		return nil
	}
	return c.jwks
}

// FetchJSON fetches a JSON document refusing redirects (fetchRefusingRedirects).
func FetchJSON(ctx context.Context, rawURL string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("%s", http.StatusText(res.StatusCode))
	}
	return jsonx.Parse(body)
}

func fetchJWKS(ctx context.Context, f JWKSFetch) (*jsonx.Object, error) {
	if f.URL != "" {
		v, err := FetchJSON(ctx, f.URL)
		if err != nil {
			return nil, fmt.Errorf("Jwks failed: %s", err.Error())
		}
		o, _ := v.(*jsonx.Object)
		if o == nil {
			return nil, errors.New("No jwks found")
		}
		return o, nil
	}
	o, err := f.Func(ctx)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, errors.New("No jwks found")
	}
	return o, nil
}

func getJWKSForVerification(ctx context.Context, token string, f JWKSFetch, forceRefresh bool) (*resolvedJWKS, error) {
	header, err := DecodeProtectedHeader(token)
	if err != nil {
		return nil, err
	}
	kidV, _ := header.Get("kid")
	kid, _ := kidV.(string)
	if f.URL == "" {
		if f.CacheKey == nil {
			j, err := fetchJWKS(ctx, f)
			if err != nil {
				return nil, err
			}
			return &resolvedJWKS{jwks: j, kid: kid}, nil
		}
		jwksCacheMu.Lock()
		cached := keyedJwksCache[f.CacheKey]
		jwksCacheMu.Unlock()
		if !forceRefresh {
			if j := freshWithKid(cached, kid); j != nil {
				return &resolvedJWKS{jwks: j, fromCache: true, kid: kid, noKidRefetchedAt: cached.noKidRefetchedAt}, nil
			}
		}
		j, err := fetchJWKS(ctx, f)
		if err != nil {
			return nil, err
		}
		e := &jwksCacheEntry{jwks: j, fetchedAt: time.Now()}
		if forceRefresh && kid == "" {
			e.noKidRefetchedAt = e.fetchedAt
		}
		jwksCacheMu.Lock()
		keyedJwksCache[f.CacheKey] = e
		jwksCacheMu.Unlock()
		return &resolvedJWKS{jwks: j, kid: kid}, nil
	}
	jwksCacheMu.Lock()
	cached := urlJwksCache[f.URL]
	jwksCacheMu.Unlock()
	var j *jsonx.Object
	if !forceRefresh {
		j = freshWithKid(cached, kid)
	}
	if j == nil {
		j, err = fetchJWKS(ctx, f)
		if err != nil {
			return nil, err
		}
		e := &jwksCacheEntry{jwks: j, fetchedAt: time.Now()}
		if forceRefresh && kid == "" {
			e.noKidRefetchedAt = e.fetchedAt
		}
		jwksCacheMu.Lock()
		urlJwksCache[f.URL] = e
		jwksCacheMu.Unlock()
		return &resolvedJWKS{jwks: j, kid: kid}, nil
	}
	return &resolvedJWKS{jwks: j, fromCache: true, kid: kid, noKidRefetchedAt: cached.noKidRefetchedAt}, nil
}

// GetJWKS is getJwks: it returns the (possibly cached) JWKS for token.
func GetJWKS(ctx context.Context, token string, f JWKSFetch) (*jsonx.Object, error) {
	r, err := getJWKSForVerification(ctx, token, f, false)
	if err != nil {
		return nil, err
	}
	return r.jwks, nil
}

func shouldRefetchWithoutKid(err error, r *resolvedJWKS) bool {
	name := ErrorName(err)
	retryable := r.fromCache && r.kid == "" && (name == "JWKSNoMatchingKey" || name == "JWSSignatureVerificationFailed")
	if !retryable {
		return false
	}
	if r.noKidRefetchedAt.IsZero() {
		return true
	}
	return time.Since(r.noKidRefetchedAt) >= jwksNoKidRefetchCooldown
}

// VerifyJWSAccessToken is verifyJwsAccessToken (azp is copied to client_id).
func VerifyJWSAccessToken(ctx context.Context, token string, f JWKSFetch, o VerifyOptions) (*jsonx.Object, error) {
	r, err := getJWKSForVerification(ctx, token, f, false)
	if err != nil {
		return nil, err
	}
	verify := func(j *jsonx.Object) (*VerifiedJWT, error) {
		keys, err := LocalJWKSet(j)
		if err != nil {
			return nil, err
		}
		return JWTVerify(token, keys, o)
	}
	v, err := verify(r.jwks)
	if err != nil {
		if !shouldRefetchWithoutKid(err, r) {
			return nil, err
		}
		r2, err2 := getJWKSForVerification(ctx, token, f, true)
		if err2 != nil {
			return nil, err2
		}
		v, err = verify(r2.jwks)
		if err != nil {
			return nil, err
		}
	}
	if azp, ok := v.Payload.Get("azp"); ok && truthy(azp) {
		v.Payload.Set("client_id", azp)
	}
	return v.Payload, nil
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		return t != 0
	}
	return true
}

// RemoteVerify configures token introspection (VerifyAccessTokenRemote).
type RemoteVerify struct {
	IntrospectURL        string
	ClientID             string
	ClientSecret         string
	Force                bool
	AllowMissingAudience bool
}

// VerifyAccessTokenOptions are verifyAccessToken options. VerifyOptions.Issuer and
// Audience are required.
type VerifyAccessTokenOptions struct {
	VerifyOptions  VerifyOptions
	RequiredScopes []string
	// IsScopeSatisfied overrides the default "scope is granted" check.
	IsScopeSatisfied func(required string, granted map[string]bool) bool
	JWKSURL          string
	RemoteVerify     *RemoteVerify
}

// DPoPVerifyOptions configure DPoP proof checks in VerifyAccessTokenRequest.
type DPoPVerifyOptions struct {
	ProofMaxAgeSeconds int
	ReplayStore        DPoPReplayStore
	SigningAlgorithms  []string
}

// VerifyAccessTokenRequestOptions add DPoP options.
type VerifyAccessTokenRequestOptions struct {
	VerifyAccessTokenOptions
	DPoP *DPoPVerifyOptions
}

// ResourceRequestInput is the resource request (ResourceRequestInput).
type ResourceRequestInput struct {
	AuthorizationHeader string
	DPoPProofJWT        string
	Method              string
	URL                 string
}

// RequestToResourceInput is requestToResourceInput.
func RequestToResourceInput(r *http.Request) ResourceRequestInput {
	u := r.URL.String()
	if r.URL.Host == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		u = scheme + "://" + r.Host + r.URL.RequestURI()
	}
	return ResourceRequestInput{
		AuthorizationHeader: r.Header.Get("Authorization"),
		DPoPProofJWT:        r.Header.Get("DPoP"),
		Method:              r.Method,
		URL:                 u,
	}
}

var defaultReplayStore = NewInMemoryDPoPReplayStore()

func unauthorizedMsg(msg string) *betterauth.APIError {
	return betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", msg))
}

var joseInfrastructureCodes = map[string]bool{
	"ERR_JWKS_TIMEOUT": true, "ERR_JWKS_INVALID": true, "ERR_JWKS_MULTIPLE_MATCHING_KEYS": true,
}

func verifyAccessTokenPayload(ctx context.Context, token string, o VerifyAccessTokenOptions) (*jsonx.Object, error) {
	var payload *jsonx.Object
	if o.JWKSURL != "" && (o.RemoteVerify == nil || !o.RemoteVerify.Force) {
		p, err := VerifyJWSAccessToken(ctx, token, JWKSFetch{URL: o.JWKSURL}, o.VerifyOptions)
		if err != nil {
			je, isJose := AsJoseError(err)
			switch {
			case isJose && (je.Name == "TypeError" || je.Name == "JWSInvalid"):
			case isJose && je.Name == "JWTExpired":
				return nil, unauthorizedMsg("token expired")
			case isJose && je.Code != "":
				if joseInfrastructureCodes[je.Code] {
					return nil, err
				}
				return nil, unauthorizedMsg("invalid access token")
			default:
				return nil, err
			}
		} else {
			payload = p
		}
	}
	if o.RemoteVerify != nil {
		body := "client_id=" + formEncode(o.RemoteVerify.ClientID) + "&client_secret=" + formEncode(o.RemoteVerify.ClientSecret) +
			"&token=" + formEncode(token) + "&token_type_hint=access_token"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.RemoteVerify.IntrospectURL, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		var introspect *jsonx.Object
		res, err := HTTPClient.Do(req)
		if err == nil {
			raw, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode >= 200 && res.StatusCode < 300 {
				if v, perr := jsonx.Parse(raw); perr == nil {
					introspect, _ = v.(*jsonx.Object)
				}
			}
		}
		if introspect == nil {
			return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("message", "introspection failed"))
		}
		if av, _ := introspect.Get("active"); av != true {
			return nil, unauthorizedMsg("token inactive")
		}
		vo := o.VerifyOptions
		if _, hasAud := introspect.Get("aud"); (!hasAud || !truthy(mustGet(introspect, "aud"))) && o.RemoteVerify.AllowMissingAudience {
			vo.Audience = nil
		}
		raw, _ := jsonx.Marshal(introspect)
		p, err := ValidateClaimsSet(jsonx.O("alg", "none"), raw, vo)
		if err != nil {
			return nil, errors.New(err.Error())
		}
		payload = p
	}
	if payload == nil {
		return nil, unauthorizedMsg("no token payload")
	}
	granted, err := parseGrantedScopes(payload)
	if err != nil {
		return nil, err
	}
	if o.RequiredScopes != nil {
		check := o.IsScopeSatisfied
		if check == nil {
			check = func(req string, g map[string]bool) bool { return g[req] }
		}
		var missing []string
		for _, s := range o.RequiredScopes {
			if !check(s, granted) {
				missing = append(missing, s)
			}
		}
		if len(missing) > 0 {
			return nil, CreateInsufficientScopeError(missing, "")
		}
	}
	return payload, nil
}

func mustGet(o *jsonx.Object, k string) any { v, _ := o.Get(k); return v }

var (
	scopeTokenRe       = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]+$`)
	errorDescriptionRe = regexp.MustCompile(`^[\x20-\x21\x23-\x5b\x5d-\x7e]+$`)
)

// IsOAuthScopeToken reports whether s is a valid scope-token (RFC 6749 §3.3).
func IsOAuthScopeToken(s string) bool { return scopeTokenRe.MatchString(s) }

// IsValidErrorDescription reports whether s is a valid error_description value.
func IsValidErrorDescription(s string) bool { return errorDescriptionRe.MatchString(s) }

func parseGrantedScopes(payload *jsonx.Object) (map[string]bool, error) {
	v, ok := payload.Get("scope")
	if !ok {
		return map[string]bool{}, nil
	}
	s, isStr := v.(string)
	invalid := !isStr || s == ""
	if !invalid {
		for _, t := range strings.Split(s, " ") {
			if !IsOAuthScopeToken(t) {
				invalid = true
			}
		}
	}
	if invalid {
		return nil, betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "access token scope claim is invalid",
			"error", "invalid_token", "error_description", "access token scope claim is invalid"))
	}
	out := map[string]bool{}
	for _, t := range strings.Split(s, " ") {
		out[t] = true
	}
	return out, nil
}

// CreateInsufficientScopeError is createInsufficientScopeError. It panics (TypeError
// upstream) when requiredScopes is empty or invalid. An empty description uses the default.
func CreateInsufficientScopeError(requiredScopes []string, description string) *betterauth.APIError {
	if len(requiredScopes) == 0 {
		panic("requiredScopes must contain at least one scope")
	}
	for _, s := range requiredScopes {
		if !IsOAuthScopeToken(s) {
			b, _ := json.Marshal(s)
			panic("invalid required scope: " + string(b))
		}
	}
	if description == "" {
		description = "access token is missing required scope: " + strings.Join(requiredScopes, " ")
	}
	if !IsValidErrorDescription(description) {
		panic("invalid error_description")
	}
	seen := map[string]bool{}
	var uniq []string
	for _, s := range requiredScopes {
		if !seen[s] {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	return betterauth.NewAPIError("FORBIDDEN", jsonx.O("message", description, "error", "insufficient_scope",
		"error_description", description, "scope", strings.Join(uniq, " ")))
}

// IsInsufficientScopeError is isInsufficientScopeError. Go cannot track error identity
// across copies, so the error shape is checked instead.
func IsInsufficientScopeError(err error) (*betterauth.APIError, bool) {
	e, ok := betterauth.AsAPIError(err)
	if !ok || e.Status != "FORBIDDEN" || e.Body == nil {
		return nil, false
	}
	ev, _ := e.Body.Get("error")
	sv, _ := e.Body.Get("scope")
	scope, isStr := sv.(string)
	if ev != "insufficient_scope" || !isStr {
		return nil, false
	}
	for _, s := range strings.Split(scope, " ") {
		if !IsOAuthScopeToken(s) {
			return nil, false
		}
	}
	return e, true
}

func throwDPoPUnauthorized(msg, code string) *betterauth.APIError {
	if code == "" {
		return unauthorizedMsg(msg)
	}
	return betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", msg, "error", code, "error_description", msg))
}

func validateRequiredScopes(scopes []string) error {
	for _, s := range scopes {
		if !IsOAuthScopeToken(s) {
			b, _ := json.Marshal(s)
			return fmt.Errorf("invalid required scope: %s", b)
		}
	}
	return nil
}

// VerifyBearerToken is verifyBearerToken (DPoP-bound tokens are rejected).
func VerifyBearerToken(ctx context.Context, token string, o VerifyAccessTokenOptions) (*jsonx.Object, error) {
	if err := validateRequiredScopes(o.RequiredScopes); err != nil {
		return nil, err
	}
	payload, err := verifyAccessTokenPayload(ctx, token, o)
	if err != nil {
		return nil, err
	}
	if GetDPoPJKTFromPayload(payload) != "" {
		return nil, throwDPoPUnauthorized("DPoP-bound access token requires verifyAccessTokenRequest", "invalid_token")
	}
	return payload, nil
}

// VerifyAccessTokenRequest is verifyAccessTokenRequest.
func VerifyAccessTokenRequest(ctx context.Context, r ResourceRequestInput, o VerifyAccessTokenRequestOptions) (*jsonx.Object, error) {
	if err := validateRequiredScopes(o.RequiredScopes); err != nil {
		return nil, err
	}
	auth := ParseAccessTokenAuthorization(r.AuthorizationHeader)
	if auth == nil || auth.Token == "" {
		return nil, throwDPoPUnauthorized("missing authorization header", "")
	}
	if auth.Scheme == "Unknown" {
		return nil, throwDPoPUnauthorized("authorization scheme must be Bearer or DPoP", "invalid_token")
	}
	payload, err := verifyAccessTokenPayload(ctx, auth.Token, o.VerifyAccessTokenOptions)
	if err != nil {
		return nil, err
	}
	p := EnforceDPoPBindingParams{Payload: payload, Authorization: auth, ProofJWT: r.DPoPProofJWT,
		Method: r.Method, URL: r.URL, ReplayStore: defaultReplayStore}
	if o.DPoP != nil {
		if o.DPoP.ReplayStore != nil {
			p.ReplayStore = o.DPoP.ReplayStore
		}
		p.ProofMaxAgeSeconds = o.DPoP.ProofMaxAgeSeconds
		p.SigningAlgorithms = o.DPoP.SigningAlgorithms
	}
	if err := EnforceDPoPBinding(ctx, p); err != nil {
		if de, ok := IsDPoPBindingError(err); ok {
			return nil, throwDPoPUnauthorized(de.Message, de.Code)
		}
		return nil, err
	}
	return payload, nil
}

func formEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '*' || c == '-' || c == '.' || c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
