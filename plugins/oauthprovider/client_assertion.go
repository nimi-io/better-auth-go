package oauthprovider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Ports of utils/client-assertion.ts (private_key_jwt), client-jwks.ts and
// client-metadata.ts.

const (
	clientJwksCacheTTL        = 5 * time.Minute
	clientJwksCacheMaxEntries = 500
	clientJwksFetchTimeout    = 5 * time.Second
	maxJwksResponseBytes      = 64 * 1024
)

var jsonContentTypeRe = regexp.MustCompile(`(?i)^application/(?:[-\w.]+\+)?json\s*(?:;|$)`)

// DefaultClientMetadataFetch is the default transport for client JWKS (and other client
// metadata resources): an HTTP client that refuses redirects.
var DefaultClientMetadataFetch ClientMetadataResourceFetch = func(req *http.Request) (*http.Response, error) {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect")
	}}
	return client.Do(req)
}

type jwksCacheEntry struct {
	jwks      *jsonx.Object
	fetchedAt time.Time
}

type clientJwksCache struct {
	mu    sync.Mutex
	order []string
	m     map[string]jwksCacheEntry
}

func (c *clientJwksCache) get(k string) (jwksCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	return e, ok
}

func (c *clientJwksCache) set(k string, jwks *jsonx.Object, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]jwksCacheEntry{}
	}
	if _, ok := c.m[k]; !ok {
		c.order = append(c.order, k)
	}
	c.m[k] = jwksCacheEntry{jwks, at}
	if len(c.m) > clientJwksCacheMaxEntries && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.m, oldest)
	}
}

func jwksCacheKey(c *SchemaClient) string {
	d := c.ClientDiscoveryID
	if d == "" {
		d = "managed"
	}
	return d + ":" + c.JwksURI
}

func clientErr(desc string) *betterauth.APIError {
	return oauthErr("BAD_REQUEST", "invalid_client", desc)
}

func validateJwksURI(ctx *betterauth.EndpointContext, jwksURI, clientIDOrigin string) error {
	u, err := parseURL(jwksURI)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return clientErr("jwks_uri must use HTTPS")
	}
	if urlHasCredentials(u) {
		return clientErr("jwks_uri must not contain credentials")
	}
	if containsRune(jwksURI, '#') {
		return clientErr("jwks_uri must not include a fragment component")
	}
	if isPrivateHostname(u.Hostname()) {
		return clientErr("jwks_uri must not point to a private or reserved address")
	}
	if clientIDOrigin != "" && originOf(u) == clientIDOrigin {
		return nil
	}
	if !ctx.Auth.IsTrustedOrigin(u.String(), false) {
		return clientErr("client jwks_uri is not trusted")
	}
	return nil
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func urlClientIDOrigin(clientID string) string {
	u, err := parseURL(clientID)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return originOf(u)
}

// fetchJwksFromURI fetches and validates a client JWKS. ok=false means the document is not
// a valid public JWKS; err means the fetch failed.
func fetchJwksFromURI(ctx context.Context, jwksURI string, fetch ClientMetadataResourceFetch) (*jsonx.Object, bool, error) {
	if fetch == nil {
		fetch = DefaultClientMetadataFetch
	}
	cctx, cancel := context.WithTimeout(ctx, clientJwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("accept", "application/json")
	res, err := fetch(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, false, fmt.Errorf("JWKS fetch returned %d", res.StatusCode)
	}
	ct := res.Header.Get("content-type")
	if ct == "" || !jsonContentTypeRe.MatchString(ct) {
		return nil, false, errors.New("JWKS response must use a JSON media type")
	}
	if cl := res.Header.Get("content-length"); cl != "" {
		if n, err := strconv.ParseFloat(cl, 64); err == nil && n > maxJwksResponseBytes {
			return nil, false, errors.New("JWKS response exceeds 64 KiB")
		}
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxJwksResponseBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > maxJwksResponseBytes {
		return nil, false, errors.New("JWKS response exceeds 64 KiB")
	}
	pv, err := jsonx.Parse(body)
	if err != nil {
		return nil, false, nil
	}
	res2 := ValidatePublicClientJwks(pv)
	if !res2.Valid {
		return nil, false, nil
	}
	return res2.JWKS, true, nil
}

func (o *resolved) discoveryByID(id string) *ClientDiscovery {
	for _, d := range o.clientDiscoveries() {
		if d.ID == id {
			return d
		}
	}
	return nil
}

func fetchClientJwks(ctx *betterauth.EndpointContext, o *resolved, c *SchemaClient) (*jsonx.Object, error) {
	if c.Jwks != "" {
		pv, err := jsonx.Parse([]byte(c.Jwks))
		if err != nil {
			return nil, err
		}
		j, _ := pv.(*jsonx.Object)
		return j, nil
	}
	if c.JwksURI == "" {
		return nil, clientErr("client has no JWKS configured")
	}
	var d *ClientDiscovery
	if c.ClientDiscoveryID != "" {
		d = o.discoveryByID(c.ClientDiscoveryID)
		if d == nil || d.FetchClientMetadataResource == nil {
			return nil, clientErr("client discovery does not provide a metadata resource transport")
		}
	}
	origin := ""
	if c.ClientDiscoveryID != "" {
		origin = urlClientIDOrigin(c.ClientID)
	}
	if err := validateJwksURI(ctx, c.JwksURI, origin); err != nil {
		return nil, err
	}
	now := time.Now()
	key := jwksCacheKey(c)
	cached, hasCached := o.jwksCache.get(key)
	if hasCached && now.Sub(cached.fetchedAt) < clientJwksCacheTTL {
		return cached.jwks, nil
	}
	var fetch ClientMetadataResourceFetch
	if d != nil {
		fetch = d.FetchClientMetadataResource
	}
	jwks, ok, err := fetchJwksFromURI(ctx.Context(), c.JwksURI, fetch)
	if err != nil {
		if hasCached && now.Sub(cached.fetchedAt) < 2*clientJwksCacheTTL {
			return cached.jwks, nil
		}
		return nil, clientErr("failed to fetch client JWKS")
	}
	if !ok {
		return nil, clientErr("failed to fetch client JWKS")
	}
	o.jwksCache.set(key, jwks, now)
	return jwks, nil
}

func refetchClientJwks(ctx *betterauth.EndpointContext, o *resolved, c *SchemaClient) *jsonx.Object {
	if c.JwksURI == "" {
		return nil
	}
	var fetch ClientMetadataResourceFetch
	if c.ClientDiscoveryID != "" {
		d := o.discoveryByID(c.ClientDiscoveryID)
		if d == nil || d.FetchClientMetadataResource == nil {
			return nil
		}
		fetch = d.FetchClientMetadataResource
	}
	jwks, ok, err := fetchJwksFromURI(ctx.Context(), c.JwksURI, fetch)
	if err != nil || !ok {
		return nil
	}
	o.jwksCache.set(jwksCacheKey(c), jwks, time.Now())
	return jwks
}

// ClientAssertionPayload holds the claims ConsumeClientAssertion checks.
type ClientAssertionPayload struct {
	Aud any
	Exp any
	Iat any
	Jti any
}

func payloadFromObject(p *jsonx.Object) ClientAssertionPayload {
	get := func(k string) any {
		v, ok := p.Get(k)
		if !ok {
			return jsonx.Undefined
		}
		return v
	}
	return ClientAssertionPayload{Aud: get("aud"), Exp: get("exp"), Iat: get("iat"), Jti: get("jti")}
}

// ConsumeClientAssertion checks a client assertion's audience, lifetime and jti and records
// the jti so it cannot be replayed (consumeClientAssertion). Exported for extensions that
// implement their own assertion types.
func ConsumeClientAssertion(ctx *betterauth.EndpointContext, namespace string, payload ClientAssertionPayload, expectedAudience string) error {
	o, err := pluginOptions(ctx.Auth)
	if err != nil {
		return err
	}
	return consumeClientAssertion(ctx, o, namespace, payload, expectedAudience)
}

func consumeClientAssertion(ctx *betterauth.EndpointContext, o *resolved, namespace string, payload ClientAssertionPayload, expectedAudience string) error {
	var auds []any
	switch t := payload.Aud.(type) {
	case []any:
		auds = t
	case nil:
	default:
		if t != jsonx.Undefined {
			auds = []any{t}
		}
	}
	found := false
	for _, a := range auds {
		if a == expectedAudience {
			found = true
		}
	}
	if !found {
		return clientErr("client assertion aud does not match the endpoint")
	}
	maxLifetime := float64(o.assertionMaxLifetime())
	now := float64(time.Now().Unix())
	exp, isNum := payload.Exp.(float64)
	if !isNum {
		return clientErr("client assertion must include exp claim")
	}
	if exp <= now {
		return clientErr("client assertion has expired")
	}
	if exp-now > maxLifetime {
		return clientErr(fmt.Sprintf("client assertion exp is too far in the future (max %ds)", int(maxLifetime)))
	}
	if iat, ok := payload.Iat.(float64); ok && now-iat > maxLifetime {
		return clientErr(fmt.Sprintf("client assertion iat is too far in the past (max %ds)", int(maxLifetime)))
	}
	jti, ok := payload.Jti.(string)
	if !ok || jti == "" {
		return clientErr("client assertion must include jti claim")
	}
	sum := sha256.Sum256([]byte(namespace + ":" + jti))
	jtiID := base64.RawURLEncoding.EncodeToString(sum[:24])
	_, createErr := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: modelClientAssertion,
		Data: adapter.Record{"id": jtiID, "expiresAt": time.UnixMilli(int64(exp * 1000))}, ForceAllowID: true})
	if createErr != nil {
		used := false
		if r, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelClientAssertion,
			Where: []adapter.Where{{Field: "id", Value: jtiID}}}); err == nil && r != nil {
			used = true
		}
		if used {
			return clientErr("client assertion jti has already been used")
		}
		return createErr
	}
	return nil
}

// verifyClientAssertion verifies a private_key_jwt client assertion and returns the
// client id.
func verifyClientAssertion(ctx *betterauth.EndpointContext, o *resolved, assertion, assertionType, clientIDHint, expectedAudience string) (string, error) {
	if assertionType != oauthcore.ClientAssertionType {
		return "", clientErr("unsupported client_assertion_type")
	}
	header, err := oauthcore.DecodeProtectedHeader(assertion)
	if err != nil {
		return "", clientErr("malformed client assertion: invalid JWT header")
	}
	algV, _ := header.Get("alg")
	alg, _ := algV.(string)
	if alg == "" || !contains(oauthcore.PrivateKeyJWTSigningAlgorithms, alg) {
		algStr := "undefined"
		if algV != nil {
			b, _ := json.Marshal(algV)
			algStr = string(b)
			if s, ok := algV.(string); ok {
				algStr = s
			}
		}
		return "", clientErr("unsupported assertion signing algorithm: " + algStr)
	}
	unverified, err := oauthcore.DecodeJWT(assertion)
	if err != nil {
		return "", clientErr("malformed client assertion: invalid JWT payload")
	}
	clientID := ""
	if v, ok := unverified.Get("sub"); ok && v != nil {
		clientID, _ = v.(string)
	} else if v, ok := unverified.Get("iss"); ok {
		clientID, _ = v.(string)
	}
	if clientID == "" {
		return "", clientErr("client assertion must contain sub or iss claim identifying the client")
	}
	if clientIDHint != "" && clientIDHint != clientID {
		return "", clientErr("client_id in body does not match assertion sub/iss")
	}
	client, err := getClient(ctx, o, clientID)
	if err != nil {
		return "", err
	}
	if client == nil {
		return "", clientErr("unknown client")
	}
	if client.IsDisabled() {
		return "", clientErr("client is disabled")
	}
	if client.TokenEndpointAuthMethod != "private_key_jwt" {
		return "", clientErr("client is not registered for private_key_jwt authentication")
	}
	jwks, err := fetchClientJwks(ctx, o, client)
	if err != nil {
		return "", err
	}
	endpointAud := expectedAudience
	if endpointAud == "" {
		endpointAud = ctx.Auth.BaseURL + "/oauth2/token"
	}
	accepted := uniqueStrings([]string{endpointAud, getIssuer(ctx, o)})
	sub := clientID
	vo := oauthcore.VerifyOptions{Issuer: []string{clientID}, Subject: &sub, Audience: accepted,
		Algorithms: oauthcore.PrivateKeyJWTSigningAlgorithms}
	failed := oauthErr("UNAUTHORIZED", "invalid_client", "client assertion signature verification failed")
	verify := func(set *jsonx.Object) (*oauthcore.VerifiedJWT, error) {
		keys, err := oauthcore.LocalJWKSet(set)
		if err != nil {
			return nil, err
		}
		return oauthcore.JWTVerify(assertion, keys, vo)
	}
	v, err := verify(jwks)
	if err != nil {
		isKeyErr := regexp.MustCompile(`(?i)no matching key|no applicable key`).MatchString(err.Error())
		if !isKeyErr {
			return "", failed
		}
		refreshed := refetchClientJwks(ctx, o, client)
		if refreshed == nil {
			return "", failed
		}
		v, err = verify(refreshed)
		if err != nil {
			return "", failed
		}
	}
	audV, _ := v.Payload.Get("aud")
	var auds []any
	if arr, ok := audV.([]any); ok {
		auds = arr
	} else {
		auds = []any{audV}
	}
	acceptedAud := ""
	for _, a := range auds {
		if s, ok := a.(string); ok && contains(accepted, s) {
			acceptedAud = s
			break
		}
	}
	if err := consumeClientAssertion(ctx, o, "private_key_jwt:"+clientID, payloadFromObject(v.Payload), acceptedAud); err != nil {
		return "", err
	}
	return clientID, nil
}

// ---- client-jwks.ts ----

var ecAlgByCurve = map[string]string{"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}

var privateJwkMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth"}

// PublicClientJwksValidationResult is the result of ValidatePublicClientJwks.
type PublicClientJwksValidationResult struct {
	Valid bool
	JWKS  *jsonx.Object
	Error string
}

func hasStringMember(k *jsonx.Object, name string) bool {
	v, _ := k.Get(name)
	s, ok := v.(string)
	return ok && s != ""
}

// ValidatePublicClientJwks checks a client JWK Set: non-empty, public asymmetric keys
// usable for private_key_jwt (validatePublicClientJwks).
func ValidatePublicClientJwks(input any) PublicClientJwksValidationResult {
	o := asObject(input)
	var keys []any
	if o != nil {
		kv, _ := o.Get("keys")
		keys, _ = kv.([]any)
	}
	if len(keys) == 0 {
		return PublicClientJwksValidationResult{Error: "jwks must be an RFC 7517 JWK Set object with a non-empty keys array"}
	}
	for _, kv := range keys {
		k := asObject(kv)
		if k == nil {
			return PublicClientJwksValidationResult{Error: "jwks keys must be supported public JWKs with required key parameters"}
		}
		kty, _ := k.Get("kty")
		if kty == "oct" || k.Has("k") {
			return PublicClientJwksValidationResult{Error: "jwks must contain only public asymmetric keys"}
		}
		for _, m := range privateJwkMembers {
			if k.Has(m) {
				return PublicClientJwksValidationResult{Error: "jwks must contain only public asymmetric keys"}
			}
		}
		crvV, _ := k.Get("crv")
		crv, _ := crvV.(string)
		supported := false
		switch kty {
		case "RSA":
			supported = hasStringMember(k, "n") && hasStringMember(k, "e")
		case "EC":
			_, okCrv := ecAlgByCurve[crv]
			supported = okCrv && hasStringMember(k, "x") && hasStringMember(k, "y")
		case "OKP":
			supported = crv == "Ed25519" && hasStringMember(k, "x")
		}
		if !supported {
			return PublicClientJwksValidationResult{Error: "jwks keys must be supported public JWKs with required key parameters"}
		}
		if algV, has := k.Get("alg"); has {
			alg, isStr := algV.(string)
			ok := isStr && contains(oauthcore.PrivateKeyJWTSigningAlgorithms, alg)
			if ok {
				switch kty {
				case "RSA":
					ok = len(alg) > 2 && (alg[:2] == "RS" || alg[:2] == "PS")
				case "EC":
					ok = ecAlgByCurve[crv] == alg
				case "OKP":
					ok = crv == "Ed25519" && alg == "EdDSA"
				default:
					ok = false
				}
			}
			if !ok {
				return PublicClientJwksValidationResult{Error: "jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve"}
			}
		}
	}
	return PublicClientJwksValidationResult{Valid: true, JWKS: jsonx.O("keys", keys)}
}

// ---- client-metadata.ts ----

var oauthClientWireFieldNames = []string{"client_id", "client_secret", "client_secret_expires_at", "scope",
	"user_id", "client_id_issued_at", "client_name", "client_uri", "logo_uri", "contacts", "tos_uri",
	"policy_uri", "jwks", "jwks_uri", "software_id", "software_version", "software_statement",
	"redirect_uris", "post_logout_redirect_uris", "backchannel_logout_uri",
	"backchannel_logout_session_required", "token_endpoint_auth_method", "grant_types", "response_types",
	"application_type", "disabled", "skip_consent", "enable_end_session", "require_pkce",
	"dpop_bound_access_tokens", "subject_type", "reference_id"}

var opaqueMetadataReserved = func() map[string]bool {
	m := map[string]bool{"public": true, "type": true, "resources": true, "client_credentials_scopes": true}
	for k := range clientColumns {
		if k != "id" {
			m[k] = true
		}
	}
	for _, k := range oauthClientWireFieldNames {
		m[k] = true
	}
	return m
}()

var cimdForbiddenFields = map[string]bool{"disabled": true, "client_secret": true, "client_secret_expires_at": true,
	"client_id_issued_at": true, "skip_consent": true, "enable_end_session": true, "require_pkce": true,
	"reference_id": true, "user_id": true, "resources": true, "clientSecret": true, "clientDiscoveryId": true,
	"skipConsent": true, "enableEndSession": true, "requirePKCE": true, "referenceId": true, "userId": true,
	"clientId": true, "applicationType": true, "tokenEndpointAuthMethod": true, "redirectUris": true,
	"postLogoutRedirectUris": true, "grantTypes": true, "responseTypes": true, "scopes": true, "expiresAt": true,
	"createdAt": true, "updatedAt": true, "softwareId": true, "softwareVersion": true, "softwareStatement": true,
	"backchannelLogoutUri": true, "backchannelLogoutSessionRequired": true, "jwksUri": true,
	"dpopBoundAccessTokens": true, "subjectType": true}

// IsForbiddenCimdClientMetadataField reports whether a Client ID Metadata Document must not
// set field (isForbiddenCimdClientMetadataField).
func IsForbiddenCimdClientMetadataField(field string) bool { return cimdForbiddenFields[field] }

// stripReservedMetadata removes reserved field names from opaque client metadata.
func stripReservedMetadata(metadata *jsonx.Object) *jsonx.Object {
	if metadata == nil {
		return nil
	}
	out := jsonx.NewObject()
	for _, k := range metadata.Keys() {
		if opaqueMetadataReserved[k] {
			continue
		}
		v, _ := metadata.Get(k)
		out.Set(k, v)
	}
	return out
}
