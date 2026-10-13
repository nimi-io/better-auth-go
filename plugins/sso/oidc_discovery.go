package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// DefaultDiscoveryTimeout is the OIDC discovery request timeout.
const DefaultDiscoveryTimeout = 10 * time.Second

// RequiredDiscoveryFields are the discovery document fields that must be present.
var RequiredDiscoveryFields = []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"}

// DiscoveryError is an OIDC discovery failure (DiscoveryError). Code is one of
// discovery_timeout, discovery_not_found, discovery_invalid_json, discovery_invalid_url,
// discovery_untrusted_origin, discovery_private_host, oidc_endpoint_redirect,
// issuer_mismatch, discovery_incomplete, unsupported_token_auth_method,
// discovery_unexpected_error.
type DiscoveryError struct {
	Code    string
	Message string
	Details map[string]any
	Cause   error
}

func (e *DiscoveryError) Error() string { return e.Message }
func (e *DiscoveryError) Unwrap() error { return e.Cause }

func newDiscoveryError(code, msg string, details map[string]any) *DiscoveryError {
	return &DiscoveryError{Code: code, Message: msg, Details: details}
}

// HydratedOIDCConfig is the result of discovery (HydratedOIDCConfig).
type HydratedOIDCConfig struct {
	Issuer                      string
	DiscoveryEndpoint           string
	AuthorizationEndpoint       string
	TokenEndpoint               string
	JwksEndpoint                string
	UserInfoEndpoint            string
	TokenEndpointAuthentication string
	ScopesSupported             []string
}

// DiscoverOIDCConfigParams are the inputs of discoverOIDCConfig.
type DiscoverOIDCConfigParams struct {
	Issuer            string
	ExistingConfig    *HydratedOIDCConfig
	DiscoveryEndpoint string
	Timeout           time.Duration
	IsTrustedOrigin   func(u string) bool
}

// lookupHost resolves host names for the SSRF guard (replaceable in tests).
var lookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// discoverOIDCConfig fetches and validates the discovery document and merges it with an
// existing configuration.
func discoverOIDCConfig(ctx context.Context, p DiscoverOIDCConfigParams) (*HydratedOIDCConfig, error) {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = DefaultDiscoveryTimeout
	}
	existing := p.ExistingConfig
	if existing == nil {
		existing = &HydratedOIDCConfig{}
	}
	discoveryURL := p.DiscoveryEndpoint
	if discoveryURL == "" {
		discoveryURL = existing.DiscoveryEndpoint
	}
	if discoveryURL == "" {
		discoveryURL = computeDiscoveryURL(p.Issuer)
	}
	if err := validateDiscoveryURL(discoveryURL, p.IsTrustedOrigin); err != nil {
		return nil, err
	}
	doc, err := fetchDiscoveryDocument(ctx, discoveryURL, timeout, p.IsTrustedOrigin)
	if err != nil {
		return nil, err
	}
	if err := validateDiscoveryDocument(doc, p.Issuer); err != nil {
		return nil, err
	}
	norm, err := normalizeDiscoveryURLs(doc, p.Issuer, p.IsTrustedOrigin)
	if err != nil {
		return nil, err
	}
	auth := selectTokenEndpointAuthMethod(norm, existing.TokenEndpointAuthentication)
	or := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	h := &HydratedOIDCConfig{
		Issuer:                      or(existing.Issuer, docString(norm, "issuer")),
		DiscoveryEndpoint:           or(existing.DiscoveryEndpoint, discoveryURL),
		AuthorizationEndpoint:       or(existing.AuthorizationEndpoint, docString(norm, "authorization_endpoint")),
		TokenEndpoint:               or(existing.TokenEndpoint, docString(norm, "token_endpoint")),
		JwksEndpoint:                or(existing.JwksEndpoint, docString(norm, "jwks_uri")),
		UserInfoEndpoint:            or(existing.UserInfoEndpoint, docString(norm, "userinfo_endpoint")),
		TokenEndpointAuthentication: or(existing.TokenEndpointAuthentication, auth),
		ScopesSupported:             existing.ScopesSupported,
	}
	if h.ScopesSupported == nil {
		h.ScopesSupported = docStrings(norm, "scopes_supported")
	}
	return h, nil
}

func docString(doc map[string]any, k string) string { s, _ := doc[k].(string); return s }

func docStrings(doc map[string]any, k string) []string {
	arr, ok := doc[k].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// computeDiscoveryURL appends /.well-known/openid-configuration to the issuer.
func computeDiscoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

// jsURL is a parsed absolute http(s) URL with WHATWG-like serialization.
type jsURL struct{ u *url.URL }

func (j jsURL) String() string {
	u := *j.u
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func (j jsURL) hostname() string { return j.u.Hostname() }

func parseURLBase(name, endpoint, base string) (jsURL, error) {
	invalid := func(err error) *DiscoveryError {
		e := newDiscoveryError("discovery_invalid_url", fmt.Sprintf("The url %q must be valid: %s", name, endpoint), map[string]any{"url": endpoint})
		e.Cause = err
		return e
	}
	var u *url.URL
	var err error
	if base != "" {
		b, berr := url.Parse(base)
		if berr != nil {
			return jsURL{}, invalid(berr)
		}
		r, rerr := url.Parse(endpoint)
		if rerr != nil {
			return jsURL{}, invalid(rerr)
		}
		u = b.ResolveReference(r)
	} else {
		u, err = url.Parse(strings.TrimSpace(endpoint))
		if err != nil || u.Scheme == "" || (u.Host == "" && u.Opaque == "" && (u.Scheme == "http" || u.Scheme == "https")) {
			if err == nil {
				err = errors.New("invalid URL")
			}
			return jsURL{}, invalid(err)
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme == "http" || u.Scheme == "https" {
		if u.Host == "" {
			return jsURL{}, invalid(errors.New("invalid URL"))
		}
		u.Host = strings.ToLower(u.Host)
		if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
			u.Host = u.Hostname()
		}
		return jsURL{u}, nil
	}
	return jsURL{}, newDiscoveryError("discovery_invalid_url", fmt.Sprintf("The url %q must use the http or https supported protocols: %s", name, endpoint),
		map[string]any{"url": endpoint, "protocol": u.Scheme + ":"})
}

func parseURL(name, endpoint string) (jsURL, error) { return parseURLBase(name, endpoint, "") }

// validateDiscoveryURL requires the discovery URL to be a trusted origin.
func validateDiscoveryURL(u string, isTrusted func(string) bool) error {
	p, err := parseURL("discoveryEndpoint", u)
	if err != nil {
		return err
	}
	s := p.String()
	if !isTrusted(s) {
		return newDiscoveryError("discovery_untrusted_origin",
			fmt.Sprintf("The main discovery endpoint %q is not trusted by your trusted origins configuration.", s), map[string]any{"url": s})
	}
	return nil
}

func validateOIDCEndpointURL(name, endpoint string, isTrusted func(string) bool) error {
	p, err := parseURL(name, endpoint)
	if err != nil {
		return err
	}
	if isPublicRoutableHost(p.hostname()) {
		return nil
	}
	if isTrusted(p.String()) {
		return nil
	}
	return newDiscoveryError("discovery_private_host",
		fmt.Sprintf("The %s URL (%s) is not publicly routable: %s. If this is an internal IdP, add its origin to trustedOrigins.", name, p.String(), p.hostname()),
		map[string]any{"endpoint": name, "url": endpoint, "hostname": p.hostname()})
}

// oidcEndpointURLs are the endpoint URLs validated at registration/update.
type oidcEndpointURLs struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JwksEndpoint          string
	DiscoveryEndpoint     string
}

// validateOIDCEndpointURLs rejects non-public endpoints that are not trusted origins.
func validateOIDCEndpointURLs(c oidcEndpointURLs, isTrusted func(string) bool) error {
	for _, f := range [][2]string{{"authorizationEndpoint", c.AuthorizationEndpoint}, {"tokenEndpoint", c.TokenEndpoint},
		{"userInfoEndpoint", c.UserInfoEndpoint}, {"jwksEndpoint", c.JwksEndpoint}, {"discoveryEndpoint", c.DiscoveryEndpoint}} {
		if f[1] != "" {
			if err := validateOIDCEndpointURL(f[0], f[1], isTrusted); err != nil {
				return err
			}
		}
	}
	return nil
}

// assertEndpointResolvesPublic rejects FQDN endpoints that resolve to non-public
// addresses unless trusted.
func assertEndpointResolvesPublic(ctx context.Context, name, endpoint string, isTrusted func(string) bool) error {
	p, err := parseURL(name, endpoint)
	if err != nil {
		return err
	}
	if isTrusted(p.String()) {
		return nil
	}
	host := p.hostname()
	if classifyHost(host).literal != "fqdn" {
		return nil
	}
	addrs, err := lookupHost(ctx, host)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if !isPublicRoutableHost(a) {
			return newDiscoveryError("discovery_private_host",
				fmt.Sprintf("The %s host %q resolves to a non-publicly-routable address (%s). If this is an internal IdP, add its origin to trustedOrigins.", name, host, a),
				map[string]any{"endpoint": name, "url": endpoint, "hostname": host, "resolved": a})
		}
	}
	return nil
}

func assertOIDCEndpointAllowed(ctx context.Context, name, endpoint string, isTrusted func(string) bool) error {
	if err := validateOIDCEndpointURL(name, endpoint, isTrusted); err != nil {
		return err
	}
	return assertEndpointResolvesPublic(ctx, name, endpoint, isTrusted)
}

// assertServerFetchedOIDCEndpointsAllowed checks the endpoints the server fetches.
func assertServerFetchedOIDCEndpointsAllowed(ctx context.Context, tokenEndpoint, userInfoEndpoint, jwksEndpoint string, isTrusted func(string) bool) error {
	for _, f := range [][2]string{{"tokenEndpoint", tokenEndpoint}, {"userInfoEndpoint", userInfoEndpoint}, {"jwksEndpoint", jwksEndpoint}} {
		if f[1] == "" {
			continue
		}
		if err := assertOIDCEndpointAllowed(ctx, f[0], f[1], isTrusted); err != nil {
			return err
		}
	}
	return nil
}

func redirectError(name, endpoint string, status int, location string) *DiscoveryError {
	var loc any
	if location != "" {
		loc = location
	}
	return newDiscoveryError("oidc_endpoint_redirect",
		fmt.Sprintf("The %s (%s) returned an HTTP %d redirect. Configure the final OIDC endpoint URL instead of a redirecting URL.", name, endpoint, status),
		map[string]any{"endpoint": name, "url": endpoint, "status": status, "location": loc})
}

// fetchError mirrors betterFetch's error object ({ status, statusText, ...body }).
type fetchError struct {
	Status     int
	StatusText string
	Body       map[string]any
}

func (e *fetchError) Error() string {
	if e.StatusText != "" {
		return e.StatusText
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// fetchResult is a betterFetch result.
type fetchResult struct {
	Data any
	Err  *fetchError
}

// fetchOIDCEndpoint performs an SSRF-checked request that refuses redirects.
func fetchOIDCEndpoint(ctx context.Context, name, endpoint, method string, body string, headers http.Header, timeout time.Duration, isTrusted func(string) bool) (*fetchResult, error) {
	if err := assertOIDCEndpointAllowed(ctx, name, endpoint, isTrusted); err != nil {
		return nil, err
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	if method == "" {
		method = "GET"
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	res, err := oauth2.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, redirectError(name, endpoint, res.StatusCode, res.Header.Get("Location"))
	}
	var data any
	if len(raw) > 0 {
		ct := res.Header.Get("Content-Type")
		if strings.Contains(ct, "json") || ct == "" {
			if v, perr := jsonx.Parse(raw); perr == nil {
				data = jsonx.ToPlain(v)
			} else {
				data = string(raw)
			}
		} else {
			if v, perr := jsonx.Parse(raw); perr == nil {
				data = jsonx.ToPlain(v)
			} else {
				data = string(raw)
			}
		}
	}
	if res.StatusCode >= 400 {
		fe := &fetchError{Status: res.StatusCode, StatusText: http.StatusText(res.StatusCode)}
		if m, ok := data.(map[string]any); ok {
			fe.Body = m
		}
		return &fetchResult{Err: fe}, nil
	}
	return &fetchResult{Data: data}, nil
}

// fetchDiscoveryDocument loads the discovery document.
func fetchDiscoveryDocument(ctx context.Context, u string, timeout time.Duration, isTrusted func(string) bool) (map[string]any, error) {
	if isTrusted == nil {
		isTrusted = func(string) bool { return false }
	}
	if timeout == 0 {
		timeout = DefaultDiscoveryTimeout
	}
	res, err := fetchOIDCEndpoint(ctx, "discoveryEndpoint", u, "GET", "", nil, timeout, isTrusted)
	if err != nil {
		var de *DiscoveryError
		if errors.As(err, &de) {
			return nil, de
		}
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return nil, newDiscoveryError("discovery_timeout", "Discovery request timed out", map[string]any{"url": u, "timeout": timeout.Milliseconds()})
		}
		return nil, &DiscoveryError{Code: "discovery_unexpected_error", Message: "Unexpected error during discovery: " + err.Error(), Details: map[string]any{"url": u}, Cause: err}
	}
	if res.Err != nil {
		switch res.Err.Status {
		case 404:
			return nil, newDiscoveryError("discovery_not_found", "Discovery endpoint not found", map[string]any{"url": u, "status": 404})
		case 408:
			return nil, newDiscoveryError("discovery_timeout", "Discovery request timed out", map[string]any{"url": u, "timeout": timeout.Milliseconds()})
		}
		return nil, newDiscoveryError("discovery_unexpected_error", "Unexpected discovery error: "+res.Err.StatusText, map[string]any{"url": u, "status": res.Err.Status})
	}
	if res.Data == nil {
		return nil, newDiscoveryError("discovery_invalid_json", "Discovery endpoint returned an empty response", map[string]any{"url": u})
	}
	switch d := res.Data.(type) {
	case string:
		preview := d
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, newDiscoveryError("discovery_invalid_json", "Discovery endpoint returned invalid JSON", map[string]any{"url": u, "bodyPreview": preview})
	case map[string]any:
		return d, nil
	}
	return nil, newDiscoveryError("discovery_invalid_json", "Discovery endpoint returned invalid JSON", map[string]any{"url": u})
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// validateDiscoveryDocument checks required fields and the issuer.
func validateDiscoveryDocument(doc map[string]any, configuredIssuer string) error {
	var missing []string
	for _, f := range RequiredDiscoveryFields {
		if !validate_truthy(doc[f]) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return newDiscoveryError("discovery_incomplete", "Discovery document is missing required fields: "+strings.Join(missing, ", "), map[string]any{"missingFields": missing})
	}
	iss := docString(doc, "issuer")
	if strings.TrimSuffix(iss, "/") != strings.TrimSuffix(configuredIssuer, "/") {
		return newDiscoveryError("issuer_mismatch", fmt.Sprintf("Discovered issuer %q does not match configured issuer %q", iss, configuredIssuer),
			map[string]any{"discovered": iss, "configured": configuredIssuer})
	}
	return nil
}

func validate_truthy(v any) bool { //nolint:revive
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

// normalizeDiscoveryURLs resolves relative endpoints against the issuer and requires
// every endpoint to be a trusted origin.
func normalizeDiscoveryURLs(doc map[string]any, issuer string, isTrusted func(string) bool) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range doc {
		out[k] = v
	}
	for _, f := range []string{"token_endpoint", "authorization_endpoint", "jwks_uri"} {
		u, err := normalizeAndValidateURL(f, docString(out, f), issuer, isTrusted)
		if err != nil {
			return nil, err
		}
		out[f] = u
	}
	for _, f := range []string{"userinfo_endpoint", "revocation_endpoint", "end_session_endpoint", "introspection_endpoint"} {
		if s := docString(out, f); s != "" {
			u, err := normalizeAndValidateURL(f, s, issuer, isTrusted)
			if err != nil {
				return nil, err
			}
			out[f] = u
		}
	}
	return out, nil
}

func normalizeAndValidateURL(name, endpoint, issuer string, isTrusted func(string) bool) (string, error) {
	u, err := normalizeURL(name, endpoint, issuer)
	if err != nil {
		return "", err
	}
	if !isTrusted(u) {
		return "", newDiscoveryError("discovery_untrusted_origin", fmt.Sprintf("The %s %q is not trusted by your trusted origins configuration.", name, u),
			map[string]any{"endpoint": name, "url": u})
	}
	return u, nil
}

// normalizeURL returns endpoint as an absolute URL, resolving relative paths against the
// issuer's path.
func normalizeURL(name, endpoint, issuer string) (string, error) {
	if p, err := parseURL(name, endpoint); err == nil {
		return p.String(), nil
	}
	iss, err := parseURL(name, issuer)
	if err != nil {
		return "", err
	}
	basePath := strings.TrimRight(iss.u.Path, "/")
	endpointPath := strings.TrimLeft(endpoint, "/")
	origin := iss.u.Scheme + "://" + iss.u.Host
	p, err := parseURLBase(name, basePath+"/"+endpointPath, origin)
	if err != nil {
		return "", err
	}
	return p.String(), nil
}

// selectTokenEndpointAuthMethod picks the token endpoint auth method.
func selectTokenEndpointAuthMethod(doc map[string]any, existing string) string {
	if existing != "" {
		return existing
	}
	supported := docStrings(doc, "token_endpoint_auth_methods_supported")
	if len(supported) == 0 {
		return "client_secret_basic"
	}
	has := func(s string) bool {
		for _, x := range supported {
			if x == s {
				return true
			}
		}
		return false
	}
	switch {
	case has("client_secret_basic"):
		return "client_secret_basic"
	case has("client_secret_post"):
		return "client_secret_post"
	case has("private_key_jwt"):
		return "private_key_jwt"
	}
	return "client_secret_basic"
}

// needsRuntimeDiscovery reports whether endpoints are missing.
func needsRuntimeDiscovery(c *OIDCConfig) bool {
	if c == nil {
		return true
	}
	return c.TokenEndpoint == "" || c.JwksEndpoint == "" || c.AuthorizationEndpoint == ""
}

// ensureRuntimeDiscovery fills missing endpoints via discovery and validates the
// server-fetched endpoints.
func ensureRuntimeDiscovery(ctx context.Context, c *OIDCConfig, issuer string, isTrusted func(string) bool) (*OIDCConfig, error) {
	resolved := *c
	if needsRuntimeDiscovery(c) {
		h, err := discoverOIDCConfig(ctx, DiscoverOIDCConfigParams{Issuer: issuer, ExistingConfig: &HydratedOIDCConfig{
			Issuer: c.Issuer, DiscoveryEndpoint: c.DiscoveryEndpoint, AuthorizationEndpoint: c.AuthorizationEndpoint,
			TokenEndpoint: c.TokenEndpoint, JwksEndpoint: c.JwksEndpoint, UserInfoEndpoint: c.UserInfoEndpoint,
			TokenEndpointAuthentication: c.TokenEndpointAuthentication,
		}, IsTrustedOrigin: isTrusted})
		if err != nil {
			return nil, err
		}
		resolved.AuthorizationEndpoint = h.AuthorizationEndpoint
		resolved.TokenEndpoint = h.TokenEndpoint
		resolved.TokenEndpointAuthentication = h.TokenEndpointAuthentication
		resolved.UserInfoEndpoint = h.UserInfoEndpoint
		resolved.JwksEndpoint = h.JwksEndpoint
	}
	if err := assertServerFetchedOIDCEndpointsAllowed(ctx, resolved.TokenEndpoint, resolved.UserInfoEndpoint, resolved.JwksEndpoint, isTrusted); err != nil {
		return nil, err
	}
	return &resolved, nil
}

// assertOIDCAuthorizedParty checks azp for multi-audience tokens.
func assertOIDCAuthorizedParty(payload map[string]any, clientID string) error {
	aud, isArr := payload["aud"].([]any)
	multi := isArr && len(aud) > 1
	azp, hasAzp := payload["azp"]
	if (multi && !hasAzp) || (hasAzp && azp != clientID) {
		return errors.New("OIDC ID token authorized party does not match the client")
	}
	return nil
}

// verifiedIDToken is a verified ID token.
type verifiedIDToken struct {
	Payload map[string]any
}

// validateOIDCIdToken verifies an ID token against the JWKS endpoint.
func validateOIDCIdToken(ctx context.Context, token, jwksEndpoint, audience, issuer string, isTrusted func(string) bool) (*verifiedIDToken, error) {
	if _, err := url.Parse(jwksEndpoint); err != nil {
		return nil, err
	}
	res, err := fetchOIDCEndpoint(ctx, "jwksEndpoint", jwksEndpoint, "GET", "", nil, 0, isTrusted)
	if err != nil {
		return nil, err
	}
	if res.Err != nil {
		return nil, errors.New("Expected 200 OK from the JSON Web Key Set HTTP response")
	}
	b, err := json.Marshal(res.Data)
	if err != nil {
		return nil, err
	}
	set, err := jose.ParseJWKS(b)
	if err != nil {
		return nil, err
	}
	o := jose.VerifyOptions{Issuer: []string{issuer}}
	if audience != "" {
		o.Audience = []string{audience}
	}
	_, payload, err := jose.VerifyJWT(token, jose.KeySetFunc(set), o)
	if err != nil {
		return nil, err
	}
	p := jsonx.ToPlain(payload).(map[string]any)
	if audience != "" {
		if err := assertOIDCAuthorizedParty(p, audience); err != nil {
			return nil, err
		}
	}
	return &verifiedIDToken{Payload: p}, nil
}

// mapDiscoveryErrorToAPIError converts discovery errors into API errors.
func mapDiscoveryErrorToAPIError(e *DiscoveryError) *betterauth.APIError {
	mk := func(status, msg string) *betterauth.APIError {
		return betterauth.NewAPIError(status, jsonx.O("message", msg, "code", e.Code))
	}
	switch e.Code {
	case "discovery_timeout":
		return mk("BAD_GATEWAY", "OIDC discovery timed out: "+e.Message)
	case "discovery_unexpected_error":
		return mk("BAD_GATEWAY", "OIDC discovery failed: "+e.Message)
	case "discovery_not_found":
		return mk("BAD_REQUEST", "OIDC discovery endpoint not found. The issuer may not support OIDC discovery, or the URL is incorrect. "+e.Message)
	case "discovery_invalid_url":
		return mk("BAD_REQUEST", "Invalid OIDC endpoint URL: "+e.Message)
	case "discovery_untrusted_origin":
		return mk("BAD_REQUEST", "Untrusted OIDC discovery URL: "+e.Message)
	case "discovery_private_host", "oidc_endpoint_redirect":
		return mk("BAD_REQUEST", e.Message)
	case "discovery_invalid_json":
		return mk("BAD_REQUEST", "OIDC discovery returned invalid data: "+e.Message)
	case "discovery_incomplete":
		return mk("BAD_REQUEST", "OIDC discovery document is missing required fields: "+e.Message)
	case "issuer_mismatch":
		return mk("BAD_REQUEST", "OIDC issuer mismatch: "+e.Message)
	case "unsupported_token_auth_method":
		return mk("BAD_REQUEST", "Incompatible OIDC provider: "+e.Message)
	}
	return betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("message", "Unexpected discovery error: "+e.Message, "code", "discovery_unexpected_error"))
}
