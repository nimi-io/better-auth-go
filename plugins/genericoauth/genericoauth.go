// Package genericoauth ports Better Auth's generic-oauth plugin
// (packages/better-auth/src/plugins/generic-oauth): config-driven OAuth 2.0 / OpenID
// Connect providers that are registered next to the built-in social providers. Sign-in,
// callback, linking and token refresh go through the core routes (/sign-in/social,
// /callback/:id, /link-social, /get-access-token, /refresh-token), exactly like social
// providers.
package genericoauth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Error codes (GENERIC_OAUTH_ERROR_CODES).
var (
	ErrInvalidOAuthConfiguration = betterauth.ErrorCode{Code: "INVALID_OAUTH_CONFIGURATION", Message: "Invalid OAuth configuration"}
	ErrTokenURLNotFound          = betterauth.ErrorCode{Code: "TOKEN_URL_NOT_FOUND", Message: "Invalid OAuth configuration. Token URL not found."}
)

// ErrorCodes lists the plugin error codes ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{ErrInvalidOAuthConfiguration, ErrTokenURLNotFound}

// Options configure the plugin (GenericOAuthOptions).
type Options struct {
	Config []Config
}

// Config configures one provider (GenericOAuthConfig).
type Config struct {
	// ProviderID is the unique provider id used in /sign-in/social and /callback/:id.
	ProviderID string
	// Name is the display name (defaults to ProviderID).
	Name string
	// AccountSubject derives the stable account id from the provider response. It may return
	// a string or a number (stringified like JavaScript String()). By default OIDC providers
	// (discovery advertising id_token signing algorithms) use profile "sub", others "id".
	AccountSubject func(ctx context.Context, tokens *oauth2.Tokens, profile map[string]any) (any, error)
	// DiscoveryURL is the OpenID Connect discovery document URL.
	DiscoveryURL string
	// RequireIDTokenVerification skips (or rejects) the provider when discovery does not
	// provide an issuer and jwks_uri.
	RequireIDTokenVerification bool
	AuthorizationURL           string
	TokenURL                   string
	UserInfoURL                string
	// EndSessionEndpoint is the RP-initiated logout endpoint (discovered when unset).
	EndSessionEndpoint    string
	PostLogoutRedirectURI string
	DisableProviderLogout bool
	ClientID              string
	ClientSecret          string
	TokenEndpointAuth     *oauth2.TokenEndpointAuth
	Scopes                []string
	// RedirectURI overrides the callback URL sent to the provider.
	RedirectURI  string
	ResponseType string
	// ResponseMode is "query" or "form_post".
	ResponseMode string
	Prompt       string
	// PKCE defaults to true.
	PKCE       *bool
	AccessType string
	// AccessTokenExpiresIn is applied when the token response omits expires_in.
	AccessTokenExpiresIn time.Duration
	// GetToken replaces the standard code exchange.
	GetToken func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error)
	// GetUserInfo replaces the standard user info lookup; it returns the raw profile
	// (GenericOAuthUserInfo) or nil.
	GetUserInfo func(ctx context.Context, tokens *oauth2.Tokens) (map[string]any, error)
	// MapProfileToUser maps the raw profile to user fields; name, email, image and
	// emailVerified override the defaults, other keys become additional user fields.
	MapProfileToUser func(profile map[string]any) (map[string]any, error)
	// AuthorizationURLParams are extra authorization request parameters.
	AuthorizationURLParams map[string]string
	// AuthorizationURLParamsOrder is the key order of AuthorizationURLParams (JavaScript
	// object order); keys missing from it are appended in sorted order.
	AuthorizationURLParamsOrder []string
	TokenURLParams              map[string]string
	// RefreshTokenParams are extra refresh_token grant parameters; RefreshTokenParamsFunc
	// computes them per refresh (it wins over RefreshTokenParams).
	RefreshTokenParams     map[string]string
	RefreshTokenParamsFunc func(ctx context.Context, rc *oauth2.RefreshContext) (map[string]string, error)
	DisableImplicitSignUp  bool
	DisableSignUp          bool
	// Authentication is "basic" or "post" (default).
	Authentication             string
	DiscoveryHeaders           map[string]string
	AuthorizationHeaders       map[string]string
	OverrideUserInfo           bool
	RequireEmailVerification   bool
	AllowIDPInitiated          bool
	DisableIDTokenNonceBinding bool
}

func (c Config) pkce() bool { return c.PKCE == nil || *c.PKCE }

// warn prints construction warnings (console.warn upstream).
var warn = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

// New creates the generic-oauth plugin (genericOAuth).
func New(opts Options) *betterauth.Plugin {
	seen := map[string]bool{}
	var dups []string
	dupSeen := map[string]bool{}
	for _, c := range opts.Config {
		if seen[c.ProviderID] && !dupSeen[c.ProviderID] {
			dupSeen[c.ProviderID] = true
			dups = append(dups, c.ProviderID)
		}
		seen[c.ProviderID] = true
	}
	if len(dups) > 0 {
		warn("Duplicate provider IDs found: " + strings.Join(dups, ", "))
	}
	return &betterauth.Plugin{
		ID:         "generic-oauth",
		Options:    opts,
		ErrorCodes: ErrorCodes,
		Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			var providers []oauth2.Provider
			for _, c := range opts.Config {
				p, err := buildProvider(ac, c)
				if err != nil {
					return nil, err
				}
				if p != nil {
					providers = append(providers, p)
				}
			}
			existing := map[string]bool{}
			for _, p := range ac.SocialProviders {
				existing[p.ID()] = true
			}
			for _, p := range providers {
				if existing[p.ID()] {
					ac.Logger.Warn(`Generic OAuth provider "` + p.ID() + `" shadows a built-in social provider with the same ID`)
				}
			}
			ac.SocialProviders = append(providers, ac.SocialProviders...)
			return nil, nil
		},
	}
}

func isSecretless(a *oauth2.TokenEndpointAuth) bool {
	return a != nil && (a.Method == oauth2.AuthPrivateKeyJWT || a.Method == oauth2.AuthNone)
}

func isClientSecretAuth(a *oauth2.TokenEndpointAuth) bool {
	return a != nil && (a.Method == oauth2.AuthClientSecretBasic || a.Method == oauth2.AuthClientSecretPost)
}

type discoveryDocument map[string]any

func (d discoveryDocument) str(k string) string { s, _ := d[k].(string); return s }

func fetchDiscovery(ctx context.Context, u string, headers map[string]string) (discoveryDocument, error) {
	data, err := oauth2.GetJSON(ctx, u, headers)
	if err != nil {
		var fe *oauth2.FetchError
		if errors.As(err, &fe) {
			return nil, nil
		}
		return nil, err
	}
	if iss, ok := data["issuer"]; ok && validTruthy(iss) {
		s, _ := iss.(string)
		if pu, err := url.Parse(s); err != nil || pu.Scheme == "" {
			return nil, nil
		}
	}
	return discoveryDocument(data), nil
}

func validTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	}
	return true
}

// buildProvider resolves a config into a provider; (nil, nil) skips the provider.
func buildProvider(ac *betterauth.AuthContext, c Config) (*Provider, error) {
	authorizationURL, tokenURL, userInfoURL, endSession := c.AuthorizationURL, c.TokenURL, c.UserInfoURL, c.EndSessionEndpoint
	var issuer string
	isOIDC := false
	var idt *oauth2.IDTokenConfig
	if c.DiscoveryURL != "" {
		doc, err := fetchDiscovery(context.Background(), c.DiscoveryURL, c.DiscoveryHeaders)
		if err != nil {
			ac.Logger.Error(fmt.Sprintf(`Discovery fetch failed for "%s": %v`, c.ProviderID, err))
			doc = nil
		}
		if doc != nil {
			if authorizationURL == "" {
				authorizationURL = doc.str("authorization_endpoint")
			}
			if tokenURL == "" {
				tokenURL = doc.str("token_endpoint")
			}
			if userInfoURL == "" {
				userInfoURL = doc.str("userinfo_endpoint")
			}
			if endSession == "" {
				endSession = doc.str("end_session_endpoint")
			}
			issuer = doc.str("issuer")
			var algs []string
			if arr, ok := doc["id_token_signing_alg_values_supported"].([]any); ok && len(arr) > 0 {
				isOIDC = true
				for _, a := range arr {
					if s, ok := a.(string); ok {
						algs = append(algs, s)
					}
				}
			}
			if jwks := doc.str("jwks_uri"); jwks != "" && issuer != "" {
				base, err := url.Parse(c.DiscoveryURL)
				var ju *url.URL
				if err == nil {
					ju, err = base.Parse(jwks)
				}
				if err != nil {
					ac.Logger.Error(fmt.Sprintf(`Provider "%s": invalid jwks_uri "%s" in discovery document. Provider skipped.`, c.ProviderID, jwks))
					return nil, nil
				}
				idt = &oauth2.IDTokenConfig{JWKSURL: ju.String(), Issuer: []string{issuer}, Audience: []string{c.ClientID}}
				if isOIDC {
					idt.Algorithms = algs
				}
			}
		}
		if authorizationURL == "" || (tokenURL == "" && c.GetToken == nil) {
			ac.Logger.Error(fmt.Sprintf(`Provider "%s": discovery left no usable authorization endpoint or token exchange. Provider skipped.`, c.ProviderID))
			return nil, nil
		}
	}
	if c.RequireIDTokenVerification && idt == nil {
		if c.DiscoveryURL != "" {
			ac.Logger.Error(fmt.Sprintf(`Provider "%s": requires verified ID tokens, but discovery did not provide a usable issuer and jwks_uri. Provider skipped.`, c.ProviderID))
			return nil, nil
		}
		return nil, fmt.Errorf(`Provider "%s": requires verified ID tokens, but discovery did not provide a usable issuer and jwks_uri.`, c.ProviderID)
	}
	if c.ClientSecret != "" && isSecretless(c.TokenEndpointAuth) {
		return nil, fmt.Errorf(`Provider "%s": tokenEndpointAuth.method "%s" cannot be combined with clientSecret`, c.ProviderID, c.TokenEndpointAuth.Method)
	}
	if c.ClientSecret == "" && isClientSecretAuth(c.TokenEndpointAuth) {
		return nil, fmt.Errorf(`Provider "%s": tokenEndpointAuth.method "%s" requires clientSecret`, c.ProviderID, c.TokenEndpointAuth.Method)
	}
	if c.ClientSecret == "" && c.TokenEndpointAuth == nil && c.Authentication == "basic" {
		return nil, fmt.Errorf(`Provider "%s": authentication "basic" requires clientSecret`, c.ProviderID)
	}
	p := &Provider{
		cfg: c, authorizationURL: authorizationURL, tokenURL: tokenURL, userInfoURL: userInfoURL,
		endSessionEndpoint: endSession, issuer: issuer, isOIDC: isOIDC, idToken: idt,
		baseURL: ac.BaseURL, logger: ac.Logger,
	}
	p.settings = oauth2.ProviderSettings{
		RequiresIDTokenNonce:     idt != nil && !c.DisableIDTokenNonceBinding,
		AllowIDPInitiated:        c.AllowIDPInitiated,
		Issuer:                   issuer,
		DisableImplicitSignUp:    c.DisableImplicitSignUp,
		DisableSignUp:            c.DisableSignUp,
		OverrideUserInfoOnSignIn: c.OverrideUserInfo,
		RequireEmailVerification: c.RequireEmailVerification,
	}
	return p, nil
}

// Provider is a generic OAuth provider built from a Config. It implements
// oauth2.Provider, oauth2.Settings, oauth2.Refresher, oauth2.IDTokenVerifier and
// oauth2.EndSessioner.
type Provider struct {
	cfg                Config
	settings           oauth2.ProviderSettings
	authorizationURL   string
	tokenURL           string
	userInfoURL        string
	endSessionEndpoint string
	issuer             string
	isOIDC             bool
	idToken            *oauth2.IDTokenConfig
	baseURL            string
	logger             betterauth.Logger
}

// ID implements oauth2.Provider.
func (p *Provider) ID() string { return p.cfg.ProviderID }

// Name implements oauth2.Provider.
func (p *Provider) Name() string {
	if p.cfg.Name != "" {
		return p.cfg.Name
	}
	return p.cfg.ProviderID
}

// Issuer is the discovered issuer ("" when unknown).
func (p *Provider) Issuer() string { return p.issuer }

// IDTokenConfig is the discovery-based id token verification config (nil when the provider
// has no discovery JWKS).
func (p *Provider) IDTokenConfig() *oauth2.IDTokenConfig { return p.idToken }

// Config returns the provider configuration.
func (p *Provider) Config() Config { return p.cfg }

// ProviderSettings implements oauth2.Settings. The returned pointer may be mutated.
func (p *Provider) ProviderSettings() *oauth2.ProviderSettings { return &p.settings }

// CreateAuthorizationURL implements oauth2.Provider.
func (p *Provider) CreateAuthorizationURL(_ context.Context, d oauth2.AuthorizationURLParams) (*url.URL, error) {
	c := p.cfg
	if p.authorizationURL == "" {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOAuthConfiguration)
	}
	scopes := append(append([]string{}, d.Scopes...), c.Scopes...)
	if p.isOIDC && !contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	params := map[string]string{}
	for k, v := range c.AuthorizationURLParams {
		params[k] = v
	}
	for k, v := range d.AdditionalParams {
		params[k] = v
	}
	order := append(oauth2.OrderedKeys(c.AuthorizationURLParams, c.AuthorizationURLParamsOrder), d.AdditionalParamsOrder...)
	verifier := ""
	if c.pkce() {
		verifier = d.CodeVerifier
	}
	return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
		ID: c.ProviderID, ClientID: c.ClientID, AuthorizationEndpoint: p.authorizationURL,
		RedirectURI: d.RedirectURI, OverrideRedirectURI: c.RedirectURI, State: d.State,
		CodeVerifier: verifier, Scopes: scopes, Prompt: c.Prompt, AccessType: c.AccessType,
		ResponseType: c.ResponseType, ResponseMode: c.ResponseMode, Nonce: d.IDTokenNonce,
		AdditionalParams: params, AdditionalParamsOrder: order, LoginHint: d.LoginHint,
	})
}

// ValidateAuthorizationCode implements oauth2.Provider.
func (p *Provider) ValidateAuthorizationCode(ctx context.Context, d oauth2.CodeParams) (*oauth2.Tokens, error) {
	c := p.cfg
	if c.GetToken != nil {
		t, err := c.GetToken(ctx, d)
		if err != nil {
			return nil, err
		}
		return oauth2.ApplyDefaultAccessTokenExpiry(t, c.AccessTokenExpiresIn), nil
	}
	if p.tokenURL == "" {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTokenURLNotFound)
	}
	verifier := ""
	if c.pkce() {
		verifier = d.CodeVerifier
	}
	redirect := d.RedirectURI
	if c.RedirectURI != "" {
		redirect = c.RedirectURI
	}
	t, err := oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
		Headers: c.AuthorizationHeaders, Code: d.Code, CodeVerifier: verifier, RedirectURI: redirect,
		TokenEndpoint: p.tokenURL, Client: oauth2.ClientCredentials{ClientID: c.ClientID, ClientSecret: c.ClientSecret},
		Basic: c.Authentication == "basic", TokenEndpointAuth: c.TokenEndpointAuth, AdditionalParams: c.TokenURLParams,
		DeviceID: d.DeviceID,
	})
	if err != nil {
		return nil, err
	}
	return oauth2.ApplyDefaultAccessTokenExpiry(t, c.AccessTokenExpiresIn), nil
}

// SupportsRefresh reports refresh support (always: refresh fails without a token URL).
func (p *Provider) SupportsRefresh() bool { return true }

// RefreshAccessToken implements oauth2.Refresher.
func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string, rc *oauth2.RefreshContext) (*oauth2.Tokens, error) {
	c := p.cfg
	if p.tokenURL == "" {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTokenURLNotFound)
	}
	extra := c.RefreshTokenParams
	if c.RefreshTokenParamsFunc != nil {
		m, err := c.RefreshTokenParamsFunc(ctx, rc)
		if err != nil {
			return nil, err
		}
		extra = m
	}
	t, err := oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{
		RefreshToken: refreshToken, TokenEndpoint: p.tokenURL,
		Client: oauth2.ClientCredentials{ClientID: c.ClientID, ClientSecret: c.ClientSecret},
		Basic:  c.Authentication == "basic", TokenEndpointAuth: c.TokenEndpointAuth, ExtraParams: extra,
	})
	if err != nil {
		return nil, err
	}
	return oauth2.ApplyDefaultAccessTokenExpiry(t, c.AccessTokenExpiresIn), nil
}

// SupportsIDToken reports id-token sign-in support (a discovery JWKS is available).
func (p *Provider) SupportsIDToken() bool { return p.idToken != nil }

// VerifyIDToken implements oauth2.IDTokenVerifier (verifyProviderIdToken).
func (p *Provider) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	if p.idToken == nil {
		return false, nil
	}
	ok, err := p.idToken.VerifyIDToken(ctx, token, nonce)
	if err != nil {
		return false, nil
	}
	return ok, nil
}

// SupportsEndSession reports RP-initiated logout support.
func (p *Provider) SupportsEndSession() bool { return true }

// CreateEndSessionURL implements oauth2.EndSessioner; it returns nil when provider logout is
// disabled or no end_session_endpoint is known.
func (p *Provider) CreateEndSessionURL(_ context.Context, d oauth2.EndSessionParams) (*url.URL, error) {
	c := p.cfg
	if c.DisableProviderLogout || p.endSessionEndpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(p.endSessionEndpoint)
	if err != nil || u.Scheme == "" {
		return nil, nil
	}
	q := newSearchParams(u.RawQuery)
	if d.IDToken != "" {
		q.set("id_token_hint", d.IDToken)
	}
	configured := d.PostLogoutRedirectURI
	if configured == "" {
		configured = c.PostLogoutRedirectURI
	}
	if configured != "" {
		base, err := url.Parse(p.baseURL)
		if err != nil {
			return nil, nil
		}
		ref, err := url.Parse(configured)
		if err != nil {
			return nil, nil
		}
		q.set("post_logout_redirect_uri", base.ResolveReference(ref).String())
		q.set("client_id", c.ClientID)
		if d.State != "" {
			q.set("state", d.State)
		}
	} else if d.IDToken == "" {
		q.set("client_id", c.ClientID)
	}
	u.RawQuery = q.encode()
	return u, nil
}

// AccountSubject implements oauth2.Provider.
func (p *Provider) AccountSubject(ctx context.Context, tokens *oauth2.Tokens, profile map[string]any) (string, error) {
	var v any
	if p.cfg.AccountSubject != nil {
		r, err := p.cfg.AccountSubject(ctx, tokens, profile)
		if err != nil {
			return "", err
		}
		v = r
	} else {
		key := "id"
		if p.isOIDC {
			key = "sub"
		}
		v = profile[key]
		if v == nil {
			v = ""
		}
	}
	return jsString(v)
}

// jsString is JavaScript String(v); non-finite numbers are rejected.
func jsString(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "undefined", nil
	case string:
		return t, nil
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return "", betterauth.ErrAccountSubjectInvalid
		}
		return jsonx.FormatNumber(t), nil
	case float32:
		return jsString(float64(t))
	case int:
		return strconv.Itoa(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case int32:
		return strconv.FormatInt(int64(t), 10), nil
	case uint64:
		return strconv.FormatUint(t, 10), nil
	case bool:
		return strconv.FormatBool(t), nil
	case fmt.Stringer:
		return t.String(), nil
	}
	return fmt.Sprint(v), nil
}

// GetUserInfo implements oauth2.Provider.
func (p *Provider) GetUserInfo(ctx context.Context, d oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
	c := p.cfg
	tokens := d.Tokens
	if tokens.IDToken != "" && p.idToken != nil {
		ok, err := p.idToken.VerifyIDToken(ctx, tokens.IDToken, d.ExpectedIDTokenNonce)
		if err != nil || !ok {
			p.logger.Error(fmt.Sprintf(`Provider "%s": id_token failed verification against the discovery JWKS or expected nonce`, c.ProviderID))
			return nil, nil
		}
	}
	var raw map[string]any
	var err error
	if c.GetUserInfo != nil {
		raw, err = c.GetUserInfo(ctx, &tokens)
	} else {
		raw, err = fetchUserInfo(ctx, &tokens, p.userInfoURL)
	}
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var mapped map[string]any
	if c.MapProfileToUser != nil {
		mapped, err = c.MapProfileToUser(raw)
		if err != nil {
			return nil, err
		}
	}
	fields := map[string]any{"email": raw["email"], "emailVerified": raw["emailVerified"], "image": raw["image"], "name": raw["name"]}
	info := oauth2.UserInfo{}
	for k, v := range mapped {
		switch k {
		case "email", "emailVerified", "image", "name":
			fields[k] = v
		case "id":
		default:
			if info.Extra == nil {
				info.Extra = map[string]any{}
			}
			info.Extra[k] = v
		}
	}
	info.Email = optString(fields["email"])
	info.Name = optString(fields["name"])
	info.Image = optString(fields["image"])
	info.EmailVerified = truthy(fields["emailVerified"])
	return &oauth2.UserInfoResult{User: info, Data: raw}, nil
}

func optString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	}
	s, _ := jsString(v)
	return s
}

func truthy(v any) bool { return validTruthy(v) }

// fetchUserInfo decodes the id token (when it carries sub and email) or calls the user info
// endpoint.
func fetchUserInfo(ctx context.Context, tokens *oauth2.Tokens, userInfoURL string) (map[string]any, error) {
	if tokens.IDToken != "" {
		if decoded, err := oauth2.DecodeJWTPayload(tokens.IDToken); err == nil && truthy(decoded["sub"]) && truthy(decoded["email"]) {
			out := map[string]any{"id": decoded["sub"]}
			if v, ok := decoded["email_verified"]; ok {
				out["emailVerified"] = v
			}
			if v, ok := decoded["picture"]; ok {
				out["image"] = v
			}
			for k, v := range decoded {
				out[k] = v
			}
			return out, nil
		}
	}
	if userInfoURL == "" {
		return nil, nil
	}
	data, err := oauth2.GetJSON(ctx, userInfoURL, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
	if err != nil || data == nil {
		return nil, nil
	}
	out := map[string]any{}
	for k, v := range data {
		out[k] = v
	}
	copyKey(out, "email", data, "email")
	if v, ok := data["email_verified"]; ok && v != nil {
		out["emailVerified"] = v
	} else {
		out["emailVerified"] = false
	}
	copyKey(out, "image", data, "picture")
	copyKey(out, "name", data, "name")
	return out, nil
}

// copyKey assigns dst[k] = src[from], removing k when src has no such key (an undefined
// value disappears from the JSON profile).
func copyKey(dst map[string]any, k string, src map[string]any, from string) {
	if v, ok := src[from]; ok {
		dst[k] = v
		return
	}
	delete(dst, k)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// searchParams emulates URLSearchParams.set on an existing query.
type searchParams struct {
	keys []string
	vals map[string][]string
}

func newSearchParams(raw string) *searchParams {
	p := &searchParams{vals: map[string][]string{}}
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

func (p *searchParams) set(k, v string) {
	if _, ok := p.vals[k]; !ok {
		p.keys = append(p.keys, k)
	}
	p.vals[k] = []string{v}
}

func (p *searchParams) encode() string {
	var parts []string
	for _, k := range p.keys {
		for _, v := range p.vals[k] {
			parts = append(parts, oauth2.FormEncode(k)+"="+oauth2.FormEncode(v))
		}
	}
	return strings.Join(parts, "&")
}
