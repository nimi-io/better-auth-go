package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// ReservedAuthorizationParams cannot be overridden through additionalParams.
var ReservedAuthorizationParams = []string{"state", "client_id", "redirect_uri", "response_type",
	"code_challenge", "code_challenge_method", "nonce", "scope"}

func isReserved(k string) bool {
	for _, r := range ReservedAuthorizationParams {
		if r == k {
			return true
		}
	}
	return false
}

// GenerateCodeChallenge returns the S256 PKCE challenge for a verifier.
func GenerateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// orderedParams emulates URLSearchParams.set ordering on top of an existing query.
type orderedParams struct {
	keys []string
	vals map[string][]string
}

func newOrderedParams(raw string) *orderedParams {
	p := &orderedParams{vals: map[string][]string{}}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		if _, ok := p.vals[k]; !ok {
			p.keys = append(p.keys, k)
		}
		p.vals[k] = append(p.vals[k], v)
	}
	return p
}

func (p *orderedParams) set(k, v string) {
	if _, ok := p.vals[k]; !ok {
		p.keys = append(p.keys, k)
	}
	p.vals[k] = []string{v}
}

func (p *orderedParams) has(k string) bool { _, ok := p.vals[k]; return ok }

func (p *orderedParams) append(k, v string) {
	if _, ok := p.vals[k]; !ok {
		p.keys = append(p.keys, k)
	}
	p.vals[k] = append(p.vals[k], v)
}

// FormEncode is URLSearchParams value serialisation.
func FormEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '*' || c == '-' || c == '.' || c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (p *orderedParams) encode() string {
	var parts []string
	for _, k := range p.keys {
		for _, v := range p.vals[k] {
			parts = append(parts, FormEncode(k)+"="+FormEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// AuthorizationURLOptions are the inputs of CreateAuthorizationURL.
type AuthorizationURLOptions struct {
	ID string
	// ClientID is the primary client id; ClientIDs[0] is used when ClientID is empty.
	ClientID              string
	AuthorizationEndpoint string
	// OverrideEndpoint replaces AuthorizationEndpoint when set (options.authorizationEndpoint).
	OverrideEndpoint string
	RedirectURI      string
	// OverrideRedirectURI replaces RedirectURI when set (options.redirectURI).
	OverrideRedirectURI string
	State               string
	CodeVerifier        string
	Scopes              []string
	Claims              []string
	Duration            string
	Prompt              string
	AccessType          string
	ResponseType        string
	Display             string
	LoginHint           string
	Nonce               string
	HD                  string
	ResponseMode        string
	AdditionalParams    map[string]string
	ScopeJoiner         string
}

// CreateAuthorizationURL builds the provider authorization URL (createAuthorizationURL).
func CreateAuthorizationURL(o AuthorizationURLOptions) (*url.URL, error) {
	endpoint := o.AuthorizationEndpoint
	if o.OverrideEndpoint != "" {
		endpoint = o.OverrideEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if o.ClientID == "" {
		return nil, errors.New("OAuth provider requires clientId")
	}
	q := newOrderedParams(u.RawQuery)
	rt := o.ResponseType
	if rt == "" {
		rt = "code"
	}
	q.set("response_type", rt)
	q.set("client_id", o.ClientID)
	q.set("state", o.State)
	if len(o.Scopes) > 0 {
		j := o.ScopeJoiner
		if j == "" {
			j = " "
		}
		q.set("scope", strings.Join(o.Scopes, j))
	}
	redirect := o.RedirectURI
	if o.OverrideRedirectURI != "" {
		redirect = o.OverrideRedirectURI
	}
	q.set("redirect_uri", redirect)
	for _, kv := range [][2]string{{"duration", o.Duration}, {"display", o.Display}, {"login_hint", o.LoginHint},
		{"nonce", o.Nonce}, {"prompt", o.Prompt}, {"hd", o.HD}, {"access_type", o.AccessType}, {"response_mode", o.ResponseMode}} {
		if kv[1] != "" {
			q.set(kv[0], kv[1])
		}
	}
	if o.CodeVerifier != "" {
		q.set("code_challenge_method", "S256")
		q.set("code_challenge", GenerateCodeChallenge(o.CodeVerifier))
	}
	if o.Claims != nil {
		inner := jsonx.O("email", nil, "email_verified", nil)
		for _, c := range o.Claims {
			inner.Set(c, nil)
		}
		q.set("claims", string(jsonx.MustMarshal(jsonx.O("id_token", inner))))
	}
	keys := make([]string, 0, len(o.AdditionalParams))
	for k := range o.AdditionalParams {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		if isReserved(k) {
			continue
		}
		q.set(k, o.AdditionalParams[k])
	}
	u.RawQuery = q.encode()
	return u, nil
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// ParseScopeField parses a scope value (space-separated string or array).
func ParseScopeField(scope any) []string {
	switch t := scope.(type) {
	case []any:
		var out []string
		for _, s := range t {
			if str, ok := s.(string); ok && strings.TrimSpace(str) != "" {
				out = append(out, strings.TrimSpace(str))
			}
		}
		return out
	case []string:
		var out []string
		for _, s := range t {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		return strings.Fields(t)
	}
	return []string{}
}

func numberValue(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		var f float64
		_, err := fmt.Sscan(t, &f)
		return f, err == nil
	}
	return 0, false
}

// TokensFromResponse converts a token endpoint response (getOAuth2Tokens).
func TokensFromResponse(data map[string]any) *Tokens {
	t := &Tokens{Raw: data}
	t.TokenType, _ = data["token_type"].(string)
	t.AccessToken, _ = data["access_token"].(string)
	t.RefreshToken, _ = data["refresh_token"].(string)
	t.IDToken, _ = data["id_token"].(string)
	if n, ok := numberValue(data["expires_in"]); ok && n != 0 {
		e := time.Now().Add(time.Duration(n * float64(time.Second)))
		t.AccessTokenExpiresAt = &e
	}
	if n, ok := numberValue(data["refresh_token_expires_in"]); ok && n != 0 {
		e := time.Now().Add(time.Duration(n * float64(time.Second)))
		t.RefreshTokenExpiresAt = &e
	}
	t.Scopes = ParseScopeField(data["scope"])
	return t
}

// ApplyDefaultAccessTokenExpiry sets AccessTokenExpiresAt when the provider omitted it.
func ApplyDefaultAccessTokenExpiry(t *Tokens, expiresIn time.Duration) *Tokens {
	if t != nil && t.AccessTokenExpiresAt == nil && expiresIn > 0 {
		e := time.Now().Add(expiresIn)
		t.AccessTokenExpiresAt = &e
	}
	return t
}

// MergeScopes merges stored comma-separated scopes with newly granted scopes.
func MergeScopes(stored string, incoming []string) string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range strings.Split(stored, ",") {
		add(s)
	}
	for _, s := range incoming {
		add(s)
	}
	return strings.Join(out, ",")
}

// ---- token endpoint authentication ----

// TokenEndpointAuthMethod selects client authentication at the token endpoint.
type TokenEndpointAuthMethod string

// Token endpoint auth methods.
const (
	AuthNone              TokenEndpointAuthMethod = "none"
	AuthClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	AuthClientSecretPost  TokenEndpointAuthMethod = "client_secret_post"
	AuthPrivateKeyJWT     TokenEndpointAuthMethod = "private_key_jwt"
	AuthCustom            TokenEndpointAuthMethod = "custom"
)

// TokenRequest is a token endpoint request being prepared.
type TokenRequest struct {
	Body      *orderedParams
	Headers   http.Header
	GrantType string
	Endpoint  string
}

// Set sets a body parameter.
func (r *TokenRequest) Set(k, v string) { r.Body.set(k, v) }

// Has reports whether a body parameter is set.
func (r *TokenRequest) Has(k string) bool { return r.Body.has(k) }

// TokenEndpointAuth configures client authentication.
type TokenEndpointAuth struct {
	Method TokenEndpointAuthMethod
	// GetClientAssertion returns a signed client assertion for private_key_jwt.
	GetClientAssertion func(clientID, tokenEndpoint, grantType string) (string, error)
	// Customize mutates the request for the custom method.
	Customize func(r *TokenRequest) error
}

// ClientCredentials identifies the OAuth client.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
	// ClientKey is sent as client_key (TikTok).
	ClientKey string
}

// EncodeBasicCredentials returns an HTTP Basic authorization value with form-encoded parts.
func EncodeBasicCredentials(clientID, clientSecret string) string {
	payload := FormEncode(clientID) + ":" + FormEncode(clientSecret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(payload))
}

// ClientAssertionType is the RFC 7523 client assertion type.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func applyTokenEndpointAuth(r *TokenRequest, c ClientCredentials, auth *TokenEndpointAuth, basic bool) error {
	if r.Has("client_assertion") != r.Has("client_assertion_type") {
		return errors.New("client_assertion and client_assertion_type must both be provided")
	}
	if r.Has("client_assertion") {
		if auth != nil {
			return errors.New("client_assertion body parameters cannot be combined with tokenEndpointAuth")
		}
		if c.ClientSecret != "" || r.Has("client_secret") {
			return errors.New("private_key_jwt token endpoint authentication cannot be combined with clientSecret")
		}
		if c.ClientID != "" {
			r.Set("client_id", c.ClientID)
		}
		return nil
	}
	method := AuthNone
	if auth != nil {
		method = auth.Method
	} else if basic {
		method = AuthClientSecretBasic
	} else if c.ClientSecret != "" {
		method = AuthClientSecretPost
	}
	switch method {
	case AuthCustom:
		if auth.Customize != nil {
			if err := auth.Customize(r); err != nil {
				return err
			}
		}
		if r.Has("client_assertion") != r.Has("client_assertion_type") {
			return errors.New("client_assertion and client_assertion_type must both be provided")
		}
	case AuthPrivateKeyJWT:
		if c.ClientSecret != "" || r.Has("client_secret") {
			return errors.New("private_key_jwt token endpoint authentication cannot be combined with clientSecret")
		}
		if c.ClientID == "" {
			return errors.New("private_key_jwt token endpoint authentication requires clientId")
		}
		if r.Endpoint == "" {
			return errors.New("private_key_jwt token endpoint authentication requires tokenEndpoint")
		}
		a, err := auth.GetClientAssertion(c.ClientID, r.Endpoint, r.GrantType)
		if err != nil {
			return err
		}
		r.Set("client_id", c.ClientID)
		r.Set("client_assertion_type", ClientAssertionType)
		r.Set("client_assertion", a)
	case AuthNone:
		if c.ClientSecret != "" || r.Has("client_secret") {
			return errors.New("none token endpoint authentication cannot be combined with clientSecret")
		}
		if r.GrantType == "client_credentials" {
			return errors.New("none token endpoint authentication cannot be used with client_credentials grant")
		}
		if c.ClientID == "" {
			return errors.New("none token endpoint authentication requires clientId")
		}
		r.Set("client_id", c.ClientID)
	case AuthClientSecretBasic:
		if r.Has("client_secret") {
			return errors.New("client_secret_basic token endpoint authentication cannot be combined with client_secret body parameters")
		}
		if c.ClientSecret == "" {
			return errors.New("client_secret_basic token endpoint authentication requires clientSecret")
		}
		if c.ClientID == "" {
			return errors.New("client_secret_basic token endpoint authentication requires clientId")
		}
		r.Headers.Set("Authorization", EncodeBasicCredentials(c.ClientID, c.ClientSecret))
	default: // post
		if auth != nil && auth.Method == AuthClientSecretPost && c.ClientSecret == "" {
			return errors.New("client_secret_post token endpoint authentication requires clientSecret")
		}
		if c.ClientSecret != "" {
			if c.ClientID == "" {
				return errors.New("client_secret_post token endpoint authentication requires clientId")
			}
			r.Set("client_id", c.ClientID)
			r.Set("client_secret", c.ClientSecret)
		}
	}
	return nil
}

// HTTPClient is used for all provider requests; it refuses redirects (SSRF protection).
var HTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// FetchError is returned when a provider responds with a non-2xx status.
type FetchError struct {
	Status     int
	StatusText string
	Body       map[string]any
	Raw        string
}

func (e *FetchError) Error() string {
	if m, ok := e.Body["error_description"].(string); ok {
		return m
	}
	if m, ok := e.Body["error"].(string); ok {
		return m
	}
	return fmt.Sprintf("request failed with status %d", e.Status)
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// DoJSON performs a request and decodes a JSON object response, refusing redirects.
func DoJSON(ctx context.Context, req *http.Request) (map[string]any, error) {
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	res, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if isRedirect(res.StatusCode) {
		return nil, fmt.Errorf("The OAuth endpoint %q returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.", req.URL.String())
	}
	var data map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &data); err != nil {
			// some providers (e.g. GitHub legacy) answer form-encoded
			if vals, perr := url.ParseQuery(string(body)); perr == nil && len(vals) > 0 && res.StatusCode < 400 {
				data = map[string]any{}
				for k, v := range vals {
					data[k] = v[0]
				}
			} else if res.StatusCode < 400 {
				return nil, fmt.Errorf("invalid JSON response from %s: %w", req.URL.Host, err)
			}
		}
	}
	if res.StatusCode >= 400 {
		return nil, &FetchError{Status: res.StatusCode, StatusText: res.Status, Body: data, Raw: string(body)}
	}
	if data == nil {
		data = map[string]any{}
	}
	return data, nil
}

// GetJSON performs a GET with headers and decodes the JSON object response.
func GetJSON(ctx context.Context, endpoint string, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return DoJSON(ctx, req)
}

func postForm(ctx context.Context, r *TokenRequest) (map[string]any, error) {
	req, err := http.NewRequest("POST", r.Endpoint, strings.NewReader(r.Body.encode()))
	if err != nil {
		return nil, err
	}
	req.Header = r.Headers
	return DoJSON(ctx, req)
}

// CodeExchange are the inputs of ValidateAuthorizationCode.
type CodeExchange struct {
	Code          string
	CodeVerifier  string
	RedirectURI   string
	TokenEndpoint string
	Client        ClientCredentials
	DeviceID      string
	// Basic selects client_secret_basic (authentication: "basic").
	Basic             bool
	TokenEndpointAuth *TokenEndpointAuth
	Headers           map[string]string
	AdditionalParams  map[string]string
	Resource          []string
}

// NewTokenRequest prepares an authorization_code token request (authorizationCodeRequest).
func NewTokenRequest(o CodeExchange) (*TokenRequest, error) {
	r := &TokenRequest{Body: newOrderedParams(""), Headers: http.Header{}, GrantType: "authorization_code", Endpoint: o.TokenEndpoint}
	r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Headers.Set("Accept", "application/json")
	for k, v := range o.Headers {
		r.Headers.Set(k, v)
	}
	r.Set("grant_type", "authorization_code")
	r.Set("code", o.Code)
	if o.CodeVerifier != "" {
		r.Set("code_verifier", o.CodeVerifier)
	}
	if o.Client.ClientKey != "" {
		r.Set("client_key", o.Client.ClientKey)
	}
	if o.DeviceID != "" {
		r.Set("device_id", o.DeviceID)
	}
	r.Set("redirect_uri", o.RedirectURI)
	for _, res := range o.Resource {
		r.Body.append("resource", res)
	}
	keys := make([]string, 0, len(o.AdditionalParams))
	for k := range o.AdditionalParams {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		if !r.Has(k) {
			r.Body.append(k, o.AdditionalParams[k])
		}
	}
	if err := applyTokenEndpointAuth(r, o.Client, o.TokenEndpointAuth, o.Basic); err != nil {
		return nil, err
	}
	return r, nil
}

// ValidateAuthorizationCode exchanges an authorization code for tokens.
func ValidateAuthorizationCode(ctx context.Context, o CodeExchange) (*Tokens, error) {
	r, err := NewTokenRequest(o)
	if err != nil {
		return nil, err
	}
	data, err := postForm(ctx, r)
	if err != nil {
		return nil, err
	}
	return TokensFromResponse(data), nil
}

// RefreshRequest are the inputs of RefreshAccessToken.
type RefreshRequest struct {
	RefreshToken      string
	TokenEndpoint     string
	Client            ClientCredentials
	Basic             bool
	TokenEndpointAuth *TokenEndpointAuth
	ExtraParams       map[string]string
	Resource          []string
}

// RefreshAccessToken performs a refresh_token grant.
func RefreshAccessToken(ctx context.Context, o RefreshRequest) (*Tokens, error) {
	r := &TokenRequest{Body: newOrderedParams(""), Headers: http.Header{}, GrantType: "refresh_token", Endpoint: o.TokenEndpoint}
	r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Headers.Set("Accept", "application/json")
	r.Set("grant_type", "refresh_token")
	r.Set("refresh_token", o.RefreshToken)
	for _, res := range o.Resource {
		r.Body.append("resource", res)
	}
	keys := make([]string, 0, len(o.ExtraParams))
	for k := range o.ExtraParams {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		switch k {
		case "grant_type", "refresh_token", "__proto__", "constructor", "prototype":
			continue
		}
		r.Set(k, o.ExtraParams[k])
	}
	if err := applyTokenEndpointAuth(r, o.Client, o.TokenEndpointAuth, o.Basic); err != nil {
		return nil, err
	}
	data, err := postForm(ctx, r)
	if err != nil {
		return nil, err
	}
	t := &Tokens{Raw: data}
	t.AccessToken, _ = data["access_token"].(string)
	t.RefreshToken, _ = data["refresh_token"].(string)
	t.TokenType, _ = data["token_type"].(string)
	t.IDToken, _ = data["id_token"].(string)
	t.Scopes = ParseScopeField(data["scope"])
	if n, ok := numberValue(data["expires_in"]); ok && n != 0 {
		e := time.Now().Add(time.Duration(n * float64(time.Second)))
		t.AccessTokenExpiresAt = &e
	}
	if n, ok := numberValue(data["refresh_token_expires_in"]); ok && n != 0 {
		e := time.Now().Add(time.Duration(n * float64(time.Second)))
		t.RefreshTokenExpiresAt = &e
	}
	return t, nil
}

// ClientCredentialsToken performs a client_credentials grant.
func ClientCredentialsToken(ctx context.Context, tokenEndpoint string, c ClientCredentials, scope string, basic bool, auth *TokenEndpointAuth, resource []string) (*Tokens, error) {
	r := &TokenRequest{Body: newOrderedParams(""), Headers: http.Header{}, GrantType: "client_credentials", Endpoint: tokenEndpoint}
	r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Headers.Set("Accept", "application/json")
	r.Set("grant_type", "client_credentials")
	if scope != "" {
		r.Set("scope", scope)
	}
	for _, res := range resource {
		r.Body.append("resource", res)
	}
	if err := applyTokenEndpointAuth(r, c, auth, basic); err != nil {
		return nil, err
	}
	data, err := postForm(ctx, r)
	if err != nil {
		return nil, err
	}
	t := &Tokens{Raw: data}
	t.AccessToken, _ = data["access_token"].(string)
	t.TokenType, _ = data["token_type"].(string)
	if s, ok := data["scope"].(string); ok {
		t.Scopes = strings.Split(s, " ")
	}
	if n, ok := numberValue(data["expires_in"]); ok && n != 0 {
		e := time.Now().Add(time.Duration(n * float64(time.Second)))
		t.AccessTokenExpiresAt = &e
	}
	return t, nil
}

// ---- JWKS / id token verification ----

type jwksEntry struct {
	set       jose.JWKS
	fetchedAt time.Time
}

var (
	jwksMu    sync.Mutex
	jwksCache = map[string]jwksEntry{}
)

const jwksTTL = 5 * time.Minute

// FetchJWKS fetches (and caches for 5 minutes) a remote JWKS. When kid is not found in the
// cached set the JWKS is refetched.
func FetchJWKS(ctx context.Context, endpoint, kid string) (jose.JWKS, error) {
	jwksMu.Lock()
	e, ok := jwksCache[endpoint]
	jwksMu.Unlock()
	if ok && time.Since(e.fetchedAt) < jwksTTL {
		if kid == "" {
			return e.set, nil
		}
		for _, k := range e.set.Keys {
			if k.Kid == kid {
				return e.set, nil
			}
		}
	}
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return jose.JWKS{}, err
	}
	req.Header.Set("Accept", "application/json")
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	res, err := HTTPClient.Do(req)
	if err != nil {
		return jose.JWKS{}, err
	}
	defer res.Body.Close()
	if isRedirect(res.StatusCode) {
		return jose.JWKS{}, fmt.Errorf("The OAuth endpoint %q returned an HTTP redirect.", endpoint)
	}
	if res.StatusCode >= 400 {
		return jose.JWKS{}, fmt.Errorf("Jwks failed: %s", res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return jose.JWKS{}, err
	}
	set, err := jose.ParseJWKS(b)
	if err != nil {
		return jose.JWKS{}, err
	}
	jwksMu.Lock()
	jwksCache[endpoint] = jwksEntry{set: set, fetchedAt: time.Now()}
	jwksMu.Unlock()
	return set, nil
}

// IDTokenConfig verifies provider id tokens against a JWKS (OAuthIdTokenConfig).
type IDTokenConfig struct {
	JWKSURL    string
	JWKS       *jose.JWKS
	Issuer     []string
	Audience   []string
	Algorithms []string
	// MaxTokenAge rejects tokens with an old iat.
	MaxTokenAge time.Duration
	// NonceComparison is "exact" (default) or "exact-or-sha256".
	NonceComparison string
	// AllowOpaqueToken accepts non-JWT tokens.
	AllowOpaqueToken bool
	VerifyClaims     func(claims *jsonx.Object) bool
}

func nonceMatches(claim any, nonce, comparison string) bool {
	s, ok := claim.(string)
	if !ok {
		return false
	}
	if s == nonce {
		return true
	}
	if comparison == "exact-or-sha256" {
		h := sha256.Sum256([]byte(nonce))
		return s == hex.EncodeToString(h[:])
	}
	return false
}

// VerifyIDToken verifies an id token with the config (verifyProviderIdToken).
func (c *IDTokenConfig) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	if strings.Count(token, ".") != 2 {
		return c.AllowOpaqueToken, nil
	}
	header, err := jose.Header(token)
	if err != nil {
		return false, nil
	}
	kidV, _ := header.Get("kid")
	kid, _ := kidV.(string)
	algV, _ := header.Get("alg")
	alg, _ := algV.(string)
	var set jose.JWKS
	if c.JWKS != nil {
		set = *c.JWKS
	} else {
		set, err = FetchJWKS(ctx, c.JWKSURL, kid)
		if err != nil {
			return false, err
		}
	}
	algs := c.Algorithms
	if len(algs) == 0 && alg != "" {
		algs = []string{alg}
	}
	_, payload, err := jose.VerifyJWT(token, jose.KeySetFunc(set), jose.VerifyOptions{
		Issuer: c.Issuer, Audience: c.Audience, Algorithms: algs, MaxTokenAge: c.MaxTokenAge,
	})
	if err != nil {
		return false, nil
	}
	if nonce != "" {
		v, _ := payload.Get("nonce")
		if !nonceMatches(v, nonce, c.NonceComparison) {
			return false, nil
		}
	}
	if c.VerifyClaims != nil && !c.VerifyClaims(payload) {
		return false, nil
	}
	return true, nil
}

// DecodeJWTPayload returns the payload of a JWT without verifying it.
func DecodeJWTPayload(token string) (map[string]any, error) {
	_, p, err := jose.Decode(token)
	if err != nil {
		return nil, err
	}
	return p.Map(), nil
}

var placeholderSafe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// PlaceholderEmail builds "<identifier>@<namespace>.placeholder.invalid"
// (createPlaceholderEmail).
func PlaceholderEmail(identifier, namespace string) string {
	return placeholderSafe.ReplaceAllString(identifier, "") + "@" + namespace + ".placeholder.invalid"
}
