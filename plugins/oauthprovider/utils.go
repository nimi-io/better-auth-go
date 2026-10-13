package oauthprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/utils/index.ts.

// errJwtConfig is thrown when the jwt plugin is missing (BetterAuthError("jwt_config")).
var errJwtConfig = errors.New("jwt_config")

// jwtOptions returns the jwt plugin options (getJwtPlugin(ctx).options).
func jwtOptions(ac *betterauth.AuthContext) (*jwt.Options, error) {
	p := ac.GetPlugin("jwt")
	if p == nil {
		return nil, errJwtConfig
	}
	o, _ := p.Options.(*jwt.Options)
	if o == nil {
		o = &jwt.Options{}
	}
	return o, nil
}

func jwtIssuer(o *jwt.Options) string {
	if o != nil && o.JWT != nil {
		return o.JWT.Issuer
	}
	return ""
}

// issuerOrBase returns jwtPluginOptions?.jwt?.issuer ?? ctx.context.baseURL.
func (o *resolved) issuerOrBase(ctx *betterauth.EndpointContext) string {
	if o.DisableJwtPlugin {
		return ctx.Auth.BaseURL
	}
	jo, err := jwtOptions(ctx.Auth)
	if err == nil {
		if iss := jwtIssuer(jo); iss != "" {
			return iss
		}
	}
	return ctx.Auth.BaseURL
}

// parseBearerToken returns the bearer credentials of an Authorization header ("" when
// the scheme is not Bearer); malformed bearer headers are an error.
func parseBearerToken(authorization string) (string, error) {
	if authorization == "" {
		return "", nil
	}
	parts := strings.Fields(strings.TrimSpace(authorization))
	if len(parts) == 0 || strings.ToLower(parts[0]) != "bearer" {
		return "", nil
	}
	if len(parts) != 2 {
		return "", oauthErr("BAD_REQUEST", "invalid_request", "Malformed Bearer Authorization header")
	}
	return parts[1], nil
}

// normalizeTimestampValue converts dates, epoch milliseconds and date strings.
func normalizeTimestampValue(v any) *time.Time {
	switch t := v.(type) {
	case nil:
		return nil
	case time.Time:
		return &t
	case *time.Time:
		return t
	case float64:
		if math.IsInf(t, 0) || math.IsNaN(t) || math.Abs(t) > 8.64e15 {
			return nil
		}
		tm := time.UnixMilli(int64(t))
		return &tm
	case int64:
		tm := time.UnixMilli(t)
		return &tm
	case int:
		tm := time.UnixMilli(int64(t))
		return &tm
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		if n := jsNumber(s); !math.IsNaN(n) && !math.IsInf(n, 0) {
			return normalizeTimestampValue(n)
		}
		if tm, ok := jsonx.ParseJSDate(s); ok {
			return &tm
		}
		if tm, ok := adapter.ToTime(s); ok {
			return &tm
		}
	}
	return nil
}

// resolveSessionAuthTime reads the session creation time (createdAt / created_at) from a
// session value or a nested {session} payload; updatedAt is never used.
func resolveSessionAuthTime(v any) *time.Time {
	var m map[string]any
	switch t := v.(type) {
	case map[string]any:
		m = t
	case *jsonx.Object:
		m = objectToMap(t)
	default:
		return normalizeTimestampValue(v)
	}
	if d := normalizeTimestampValue(m["createdAt"]); d != nil {
		return d
	}
	if d := normalizeTimestampValue(m["created_at"]); d != nil {
		return d
	}
	var nested map[string]any
	switch t := m["session"].(type) {
	case map[string]any:
		nested = t
	case *jsonx.Object:
		nested = objectToMap(t)
	default:
		return nil
	}
	if d := normalizeTimestampValue(nested["createdAt"]); d != nil {
		return d
	}
	return normalizeTimestampValue(nested["created_at"])
}

func toResourceList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		if len(t) == 0 {
			return nil
		}
		return t
	case []any:
		if len(t) == 0 {
			return nil
		}
		return toStrings(t)
	}
	return nil
}

// toAudienceClaim returns a string for one audience, a list for several, nil for none.
func toAudienceClaim(aud []string) any {
	switch len(aud) {
	case 0:
		return nil
	case 1:
		return aud[0]
	}
	return stringsToAny(aud)
}

// ---- client lookup ----

type trustedClientCache struct {
	mu      sync.Mutex
	clients map[string]*SchemaClient
}

func (c *trustedClientCache) get(id string) *SchemaClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.clients[id]
	if e == nil {
		return nil
	}
	if e.ExpiresAt != nil && e.ExpiresAt.Before(time.Now()) {
		delete(c.clients, id)
		return nil
	}
	return e
}

func (c *trustedClientCache) set(id string, cl *SchemaClient) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clients == nil {
		c.clients = map[string]*SchemaClient{}
	}
	c.clients[id] = cl
}

// getClient finds a client by id (database, trusted cache or client discoveries).
func getClient(ctx *betterauth.EndpointContext, o *resolved, clientID string) (*SchemaClient, error) {
	if tc := o.trustedCache.get(clientID); tc != nil && tc.ClientDiscoveryID == "" {
		return tc.Clone(), nil
	}
	rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelClient,
		Where: []adapter.Where{{Field: "clientId", Value: clientID}}})
	if err != nil {
		return nil, err
	}
	dbClient := ClientFromRecord(rec)
	discoveries := o.clientDiscoveries()
	switch {
	case dbClient != nil && dbClient.ClientDiscoveryID != "":
		var d *ClientDiscovery
		for _, c := range discoveries {
			if c.ID == dbClient.ClientDiscoveryID {
				d = c
			}
		}
		if d == nil || !d.Matches(clientID) {
			return nil, nil
		}
		return d.Resolve(ctx, clientID, dbClient)
	case dbClient != nil:
		if o.cachedTrusted[clientID] {
			o.trustedCache.set(clientID, dbClient.Clone())
		}
		return dbClient, nil
	}
	for _, d := range discoveries {
		if !d.Matches(clientID) {
			continue
		}
		r, err := d.Resolve(ctx, clientID, nil)
		if err != nil {
			return nil, err
		}
		if r != nil {
			return r, nil
		}
	}
	return nil, nil
}

func mergeDiscoveryMetadata(ds []*ClientDiscovery) *jsonx.Object {
	out := jsonx.NewObject()
	for _, d := range ds {
		mergeInto(out, d.DiscoveryMetadata)
	}
	return out
}

// ---- secrets & tokens ----

func defaultHasher(value string) string {
	h := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func decryptStoredClientSecret(ctx *betterauth.EndpointContext, m *StoreClientSecretOptions, stored string) (string, error) {
	switch {
	case m.Mode == "encrypted":
		return bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, stored)
	case m.Decrypt != nil:
		return m.Decrypt(stored)
	}
	return "", errors.New("Unsupported decryption storageMethod type '" + m.Mode + "'")
}

func constantTimeEqual(a, b string) bool {
	return bacrypto.ConstantTimeEqual([]byte(a), []byte(b))
}

func verifyStoredClientSecret(ctx *betterauth.EndpointContext, o *resolved, stored, secret string) (bool, error) {
	m := o.storeClientSecretMode()
	if p := o.prefix().ClientSecret; secret != "" && p != "" {
		if strings.HasPrefix(secret, p) {
			secret = strings.Replace(secret, p, "", 1)
		} else {
			return false, oauthErr("UNAUTHORIZED", "invalid_client", "invalid client_secret")
		}
	}
	switch {
	case m.Mode == "hashed":
		return secret != "" && constantTimeEqual(defaultHasher(secret), stored), nil
	case m.Hash != nil:
		if m.Verify != nil {
			if secret == "" {
				return false, nil
			}
			return m.Verify(secret, stored)
		}
		if secret == "" {
			return false, nil
		}
		h, err := m.Hash(secret)
		if err != nil {
			return false, err
		}
		return h != "" && constantTimeEqual(h, stored), nil
	case m.Mode == "encrypted":
		dec, err := decryptStoredClientSecret(ctx, m, stored)
		if err != nil {
			return false, nil
		}
		return secret != "" && constantTimeEqual(dec, secret), nil
	case m.Decrypt != nil:
		dec, err := decryptStoredClientSecret(ctx, m, stored)
		if err != nil {
			return false, err
		}
		return secret != "" && constantTimeEqual(dec, secret), nil
	}
	return false, errors.New("Unsupported verify storageMethod type '" + m.Mode + "'")
}

// storeClientSecret encodes a client secret for storage.
func storeClientSecret(ctx *betterauth.EndpointContext, o *resolved, secret string) (string, error) {
	m := o.storeClientSecretMode()
	switch {
	case m.Mode == "encrypted":
		return bacrypto.SymmetricEncrypt(ctx.Auth.SecretConfig, secret)
	case m.Mode == "hashed":
		return defaultHasher(secret), nil
	case m.Hash != nil:
		return m.Hash(secret)
	case m.Encrypt != nil:
		return m.Encrypt(secret)
	}
	return "", errors.New("Unsupported storeClientSecret type '" + m.Mode + "'")
}

// storeToken hashes a token for storage (storeToken / getStoredToken).
func storeToken(o *resolved, token, tokenType string) (string, error) {
	if o.StoreTokens == nil || o.StoreTokens.Hash == nil {
		return defaultHasher(token), nil
	}
	return o.StoreTokens.Hash(token, tokenType)
}

// ---- client authentication ----

var (
	basicSchemePrefix = regexp.MustCompile(`(?i)^Basic +`)
	authSchemeToken   = regexp.MustCompile("^([!#$%&'*+\\-.^_`|~0-9A-Za-z]+)(?:\\s|$)")
)

var clientAuthenticationFields = []string{"client_secret", "client_assertion", "client_assertion_type"}

func invalidAuthenticationRequest(desc string) error {
	return oauthErr("BAD_REQUEST", "invalid_request", desc)
}

// requestForm returns the raw urlencoded request body (nil when the request is not a
// form request).
func requestForm(ctx *betterauth.EndpointContext) *searchParams {
	r := ctx.Request
	if r == nil || r.Body == nil {
		return nil
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/x-www-form-urlencoded") {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return parseSearchParams(string(raw))
}

// normalizeClientAuthenticationParameters rejects repeated or conflicting client
// authentication parameters and writes the effective values into body.
func normalizeClientAuthenticationParameters(ctx *betterauth.EndpointContext, body map[string]any) (bool, error) {
	clientID := ""
	if v, ok := body["client_id"]; ok && v != nil && v != "" && !isUndef(v) {
		s, isStr := v.(string)
		if !isStr {
			return false, invalidAuthenticationRequest("client_id must be a string")
		}
		clientID = s
	}
	fields := map[string]string{}
	set := func(field string, v any) error {
		if v == nil || isUndef(v) || v == "" {
			return nil
		}
		s, ok := v.(string)
		if !ok {
			return invalidAuthenticationRequest(field + " must be a string")
		}
		fields[field] = s
		return nil
	}
	for _, f := range clientAuthenticationFields {
		if v, ok := body[f]; ok {
			if err := set(f, v); err != nil {
				return false, err
			}
		}
	}
	authorization := ""
	if ctx.Request != nil {
		authorization = ctx.Request.Header.Get("Authorization")
	}
	hasAuthHeader := authorization != ""
	if form := requestForm(ctx); form != nil {
		var ids []string
		for _, v := range form.getAll("client_id") {
			if v != "" {
				ids = append(ids, v)
			}
		}
		if len(ids) > 1 {
			return false, invalidAuthenticationRequest("client_id must not be repeated")
		}
		clientID = ""
		if len(ids) == 1 {
			clientID = ids[0]
		}
		for _, f := range clientAuthenticationFields {
			var vals []string
			for _, v := range form.getAll(f) {
				if v != "" {
					vals = append(vals, v)
				}
			}
			if len(vals) > 1 {
				return false, invalidAuthenticationRequest(f + " must not be repeated")
			}
			if len(vals) == 1 {
				fields[f] = vals[0]
			}
		}
	}
	_, hasSecret := fields["client_secret"]
	_, hasAssertion := fields["client_assertion"]
	_, hasAssertionType := fields["client_assertion_type"]
	hasClientAssertion := hasAssertion || hasAssertionType
	if (hasAuthHeader && (hasSecret || hasClientAssertion)) || (hasSecret && hasClientAssertion) {
		return false, invalidAuthenticationRequest("A request must use only one client authentication method")
	}
	if clientID != "" {
		body["client_id"] = clientID
	} else {
		delete(body, "client_id")
	}
	for _, f := range clientAuthenticationFields {
		if v, ok := fields[f]; ok {
			body[f] = v
		} else {
			delete(body, f)
		}
	}
	return hasAuthHeader || len(fields) > 0, nil
}

// clientCredentials are the extracted client credentials (ExtractedCredentials).
type clientCredentials struct {
	// Kind is "client_secret", "pre_verified" or "public".
	Kind         string
	Method       string
	ClientID     string
	ClientSecret string
	Confirmation *jsonx.Object
}

func (c *clientCredentials) destructure() (clientID, secret string, preVerified bool, method string, conf *jsonx.Object) {
	if c == nil {
		return "", "", false, "", nil
	}
	if c.Kind == "client_secret" {
		secret = c.ClientSecret
	}
	if c.Kind == "pre_verified" {
		conf = c.Confirmation
	}
	return c.ClientID, secret, c.Kind == "pre_verified", c.Method, conf
}

func invalidClient(desc, method, scheme string) error {
	challenge := scheme
	if challenge == "" && method == "client_secret_basic" {
		challenge = "Basic"
	}
	if challenge != "" {
		e := oauthErr("UNAUTHORIZED", "invalid_client", desc)
		e.Headers.Set("WWW-Authenticate", challenge)
		return e
	}
	return oauthErr("BAD_REQUEST", "invalid_client", desc)
}

func copyBody(ctx *betterauth.EndpointContext) map[string]any {
	out := map[string]any{}
	for k, v := range bodyMap(ctx) {
		out[k] = v
	}
	return out
}

// extractClientCredentials reads client credentials from the Authorization header, the
// body, or a client assertion.
func extractClientCredentials(ctx *betterauth.EndpointContext, o *resolved, expectedAudience string) (*clientCredentials, error) {
	body := copyBody(ctx)
	if _, err := normalizeClientAuthenticationParameters(ctx, body); err != nil {
		return nil, err
	}
	authorization := ""
	if ctx.Request != nil {
		authorization = ctx.Request.Header.Get("Authorization")
	}
	assertion, _ := body["client_assertion"].(string)
	assertionType, _ := body["client_assertion_type"].(string)
	bodyClientID, _ := body["client_id"].(string)
	if assertion != "" || assertionType != "" {
		if assertion == "" || assertionType == "" {
			return nil, oauthErr("BAD_REQUEST", "invalid_client", "client_assertion and client_assertion_type must both be provided")
		}
		if s := o.extensionClientAuthStrategy(assertionType); s != nil {
			res, err := s.Authenticate(ClientAuthenticationInput{Ctx: ctx, Assertion: assertion, AssertionType: assertionType,
				ClientID: bodyClientID, ExpectedAudience: expectedAudience})
			if err != nil {
				return nil, err
			}
			return &clientCredentials{Kind: "pre_verified", Method: s.Method, ClientID: res.ClientID, Confirmation: res.Confirmation}, nil
		}
		clientID, err := verifyClientAssertion(ctx, o, assertion, assertionType, bodyClientID, expectedAudience)
		if err != nil {
			return nil, err
		}
		return &clientCredentials{Kind: "pre_verified", Method: "private_key_jwt", ClientID: clientID}, nil
	}
	if authorization != "" && !basicSchemePrefix.MatchString(authorization) {
		m := authSchemeToken.FindStringSubmatch(authorization)
		if m == nil {
			return nil, oauthErr("BAD_REQUEST", "invalid_request", "Invalid authorization header format")
		}
		return nil, invalidClient("unsupported authorization scheme", "", m[1])
	}
	if authorization != "" {
		id, secret, err := oauthcore.DecodeBasicCredentials(authorization)
		if err != nil {
			e := oauthErr("UNAUTHORIZED", "invalid_client", "invalid authorization header format")
			e.Headers.Set("WWW-Authenticate", "Basic")
			return nil, e
		}
		return &clientCredentials{Kind: "client_secret", Method: "client_secret_basic", ClientID: id, ClientSecret: secret}, nil
	}
	secret, _ := body["client_secret"].(string)
	if bodyClientID != "" && secret != "" {
		return &clientCredentials{Kind: "client_secret", Method: "client_secret_post", ClientID: bodyClientID, ClientSecret: secret}, nil
	}
	if bodyClientID != "" {
		return &clientCredentials{Kind: "public", Method: "none", ClientID: bodyClientID}, nil
	}
	return nil, nil
}

// clientAllowsGrant reports whether the client may use grantType (refresh_token is implied
// by authorization_code).
func clientAllowsGrant(c *SchemaClient, grantType string) bool {
	allowed := c.GrantTypes
	if len(allowed) == 0 {
		allowed = []string{"authorization_code"}
	}
	if grantType == "refresh_token" && contains(allowed, "authorization_code") {
		return true
	}
	return contains(allowed, grantType)
}

func validateClientScopes(c *SchemaClient, scopes []string) error {
	if scopes == nil || c.Scopes == nil {
		return nil
	}
	for _, s := range scopes {
		if !contains(c.Scopes, s) {
			return oauthErr("BAD_REQUEST", "invalid_scope", "client does not allow scope "+s)
		}
	}
	return nil
}

// validateClientCredentials loads the client and checks its credentials, scopes and grant.
func validateClientCredentials(ctx *betterauth.EndpointContext, o *resolved, clientID, secret string, scopes []string,
	preVerified bool, grantType, authMethod string) (*SchemaClient, error) {
	client, err := getClient(ctx, o, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, invalidClient("missing client", authMethod, "")
	}
	if client.IsDisabled() {
		return nil, invalidClient("client is disabled", authMethod, "")
	}
	registered := client.TokenEndpointAuthMethod
	if registered == "" {
		registered = "client_secret_basic"
	}
	if authMethod != "" && registered != authMethod {
		return nil, invalidClient("client registered for "+registered+" cannot use "+authMethod, authMethod, "")
	}
	if (client.TokenEndpointAuthMethod == "private_key_jwt" || o.isExtensionAuthMethod(client.TokenEndpointAuthMethod)) && !preVerified {
		return nil, oauthErr("BAD_REQUEST", "invalid_client", "client registered for "+client.TokenEndpointAuthMethod+" must use client_assertion")
	}
	if !preVerified {
		if client.TokenEndpointAuthMethod != "none" && secret == "" {
			return nil, invalidClient("client secret must be provided", authMethod, "")
		}
		if secret != "" && client.ClientSecret == "" {
			return nil, invalidClient("public client, client secret should not be received", authMethod, "")
		}
		if secret != "" {
			ok, err := verifyStoredClientSecret(ctx, o, client.ClientSecret, secret)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, invalidClient("invalid client_secret", authMethod, "")
			}
		}
	}
	if err := validateClientScopes(client, scopes); err != nil {
		return nil, err
	}
	if grantType != "" && !clientAllowsGrant(client, grantType) {
		return nil, oauthErr("BAD_REQUEST", "unauthorized_client", "client is not authorized to use grant type "+grantType)
	}
	return client, nil
}

// ---- prompts & queries ----

func parsePrompt(prompt string) map[string]bool {
	set := map[string]bool{}
	for _, p := range strings.Split(prompt, " ") {
		p = strings.TrimSpace(p)
		if contains(promptTokens, p) {
			set[p] = true
		}
	}
	return set
}

// resolveSubjectIdentifier returns the pairwise subject for pairwise clients.
func resolveSubjectIdentifier(userID string, c *SchemaClient, o *resolved) (string, error) {
	if c.SubjectType == "pairwise" && o.PairwiseSecret != "" {
		if len(c.RedirectURIs) == 0 {
			return "", errors.New("Client has no redirect URIs for sector identifier")
		}
		u, err := parseURL(c.RedirectURIs[0])
		if err != nil {
			return "", err
		}
		return bacrypto.MakeSignature(u.Host+"."+userID, o.PairwiseSecret), nil
	}
	return userID, nil
}

// isSessionFreshForSignedQuery reports whether the session was created after the login
// page query was signed.
func isSessionFreshForSignedQuery(createdAt time.Time, issuedAt *time.Time) bool {
	if issuedAt == nil || createdAt.IsZero() {
		return false
	}
	return createdAt.UnixMilli() >= issuedAt.UnixMilli()
}

func removePromptFromQuery(q *searchParams, prompt string) *searchParams {
	next := q.clone()
	v, ok := next.get("prompt")
	if !ok {
		return next
	}
	prompts := strings.Split(v, " ")
	idx := -1
	for i, p := range prompts {
		if p == prompt {
			idx = i
			break
		}
	}
	if idx >= 0 {
		prompts = append(prompts[:idx], prompts[idx+1:]...)
		if len(prompts) > 0 {
			next.set("prompt", strings.Join(prompts, " "))
		} else {
			next.delete("prompt")
		}
	}
	return next
}

func removeMaxAgeFromQuery(q *searchParams) *searchParams {
	next := q.clone()
	next.delete("max_age")
	return next
}

// searchParamsToQuery converts params into a query object (repeated keys become arrays).
func searchParamsToQuery(p *searchParams) *jsonx.Object {
	out := jsonx.NewObject()
	for _, k := range p.keys() {
		vals := p.getAll(k)
		if len(vals) == 1 {
			out.Set(k, vals[0])
		} else {
			out.Set(k, stringsToAny(vals))
		}
	}
	return out
}

// pkce requirement errors (PKCERequirementErrors).
const (
	pkcePublicClient  = "pkce is required for public clients"
	pkceOfflineScope  = "pkce or OIDC nonce is required when requesting offline_access scope"
	pkceClientRequire = "pkce is required for this client"
)

// isPKCERequired returns the reason PKCE is required ("" when optional).
func isPKCERequired(c *SchemaClient, scopes []string, nonce string) string {
	if c.TokenEndpointAuthMethod == "none" {
		return pkcePublicClient
	}
	hasOIDCNonce := contains(scopes, "openid") && nonce != ""
	if contains(scopes, "offline_access") && !hasOIDCNonce {
		return pkceOfflineScope
	}
	if c.RequirePKCE == nil || *c.RequirePKCE {
		return pkceClientRequire
	}
	return ""
}

// VerifyOAuthQueryParams verifies a signed login-page query (verifyOAuthQueryParams).
func VerifyOAuthQueryParams(oauthQuery, secret string) bool {
	p := parseSearchParams(oauthQuery)
	sigs := p.getAll("sig")
	sig := p.getString("sig")
	exp := jsNumber(p.getString("exp"))
	p.delete("sig")
	expected := bacrypto.MakeSignature(canonicalizeOAuthQueryParams(p).String(), secret)
	if len(sigs) != 1 || sig == "" || !constantTimeEqual(sig, expected) {
		return false
	}
	if math.IsNaN(exp) {
		return false
	}
	return exp*1000 >= float64(time.Now().UnixMilli())
}
