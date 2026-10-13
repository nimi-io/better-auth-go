package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// ProviderOptions are the options shared by every social provider (ProviderOptions).
type ProviderOptions struct {
	// ClientID is the primary client id. ClientIDs lists extra accepted audiences for
	// id-token sign-in (clientId: string[] upstream).
	ClientID     string
	ClientIDs    []string
	ClientSecret string
	// Scope adds scopes to the provider defaults; DisableDefaultScope drops the defaults.
	Scope               []string
	DisableDefaultScope bool
	// RedirectURI overrides the callback URL sent to the provider.
	RedirectURI string
	// AuthorizationEndpoint overrides the provider authorization endpoint.
	AuthorizationEndpoint string
	// ClientKey is sent as client_key (TikTok).
	ClientKey            string
	DisableIDTokenSignIn bool
	// VerifyIDToken replaces the built-in id token verification.
	VerifyIDToken func(ctx context.Context, token, nonce string) (bool, error)
	// GetUserInfo replaces the built-in profile lookup.
	GetUserInfo func(ctx context.Context, tokens *Tokens) (*UserInfoResult, error)
	// RefreshAccessToken replaces the built-in refresh.
	RefreshAccessToken func(ctx context.Context, refreshToken string) (*Tokens, error)
	// MapProfileToUser maps the raw profile to user fields; returned keys override name,
	// email, image and emailVerified, other keys become additional user fields.
	MapProfileToUser      func(profile map[string]any) (map[string]any, error)
	DisableImplicitSignUp bool
	DisableSignUp         bool
	// Prompt is sent as the prompt parameter ("select_account", "consent", ...).
	Prompt string
	// ResponseMode is "query" or "form_post".
	ResponseMode             string
	OverrideUserInfoOnSignIn bool
	RequireEmailVerification bool
}

// PrimaryClientID returns the client id used for authorization requests.
func (o ProviderOptions) PrimaryClientID() string {
	if o.ClientID != "" {
		return o.ClientID
	}
	if len(o.ClientIDs) > 0 {
		return o.ClientIDs[0]
	}
	return ""
}

// Audiences returns every accepted client id (id-token audience).
func (o ProviderOptions) Audiences() []string {
	var out []string
	if o.ClientID != "" {
		out = append(out, o.ClientID)
	}
	for _, c := range o.ClientIDs {
		if c != "" && c != o.ClientID {
			out = append(out, c)
		}
	}
	return out
}

// Credentials returns the client credentials.
func (o ProviderOptions) Credentials() ClientCredentials {
	return ClientCredentials{ClientID: o.PrimaryClientID(), ClientSecret: o.ClientSecret, ClientKey: o.ClientKey}
}

// BuildScopes returns defaults (unless disabled) + options.scope + request scopes.
func (o ProviderOptions) BuildScopes(defaults, request []string) []string {
	var out []string
	if !o.DisableDefaultScope {
		out = append(out, defaults...)
	}
	out = append(out, o.Scope...)
	return append(out, request...)
}

// Settings derives ProviderSettings from the options.
func (o ProviderOptions) Settings() ProviderSettings {
	return ProviderSettings{
		DisableImplicitSignUp: o.DisableImplicitSignUp, DisableSignUp: o.DisableSignUp,
		DisableIDTokenSignIn: o.DisableIDTokenSignIn, OverrideUserInfoOnSignIn: o.OverrideUserInfoOnSignIn,
		RequireEmailVerification: o.RequireEmailVerification,
	}
}

// BuildUserInfo applies MapProfileToUser on top of the provider's base mapping
// ({...base, ...userMap}).
func BuildUserInfo(o ProviderOptions, profile map[string]any, base UserInfo) (*UserInfoResult, error) {
	if o.MapProfileToUser != nil {
		m, err := o.MapProfileToUser(profile)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			switch k {
			case "name":
				base.Name = stringOf(v)
			case "email":
				base.Email = stringOf(v)
			case "image":
				base.Image = stringOf(v)
			case "emailVerified":
				b, _ := v.(bool)
				base.EmailVerified = b
			case "id":
				// id is never taken from the mapper (accountSubject resolves it)
			default:
				if base.Extra == nil {
					base.Extra = map[string]any{}
				}
				base.Extra[k] = v
			}
		}
	}
	return &UserInfoResult{User: base, Data: profile}, nil
}

func stringOf(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case float64:
		return jsonx.FormatNumber(t)
	}
	return fmt.Sprint(v)
}

// String returns profile[key] as a string ("" when absent; numbers use JS formatting).
func String(profile map[string]any, key string) string { return stringOf(profile[key]) }

// Bool returns profile[key] as a boolean (accepting "true"/"false" strings).
func Bool(profile map[string]any, key string) bool {
	switch t := profile[key].(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}

// Path returns a nested value, e.g. Path(p, "data", "user", "id").
func Path(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// ---- generic provider ----

// Spec configures a GenericProvider.
type Spec struct {
	ID       string
	Name     string
	Options  ProviderOptions
	Settings ProviderSettings
	// AuthorizationURL builds the authorization URL.
	AuthorizationURL func(ctx context.Context, p AuthorizationURLParams) (*url.URL, error)
	// ExchangeCode exchanges the authorization code.
	ExchangeCode func(ctx context.Context, p CodeParams) (*Tokens, error)
	// UserInfo returns the user (MapProfileToUser is applied by the provider via
	// BuildUserInfo; Options.GetUserInfo overrides this when set).
	UserInfo func(ctx context.Context, p UserInfoParams) (*UserInfoResult, error)
	// Refresh refreshes tokens; nil means unsupported (Options.RefreshAccessToken overrides).
	Refresh func(ctx context.Context, refreshToken string, rc *RefreshContext) (*Tokens, error)
	// Subject returns the account id; defaults to profile "sub", then "id".
	Subject func(tokens *Tokens, profile map[string]any) (string, error)
	// IDToken verifies id tokens with a JWKS; VerifyIDTokenFunc is a custom verifier.
	IDToken           *IDTokenConfig
	VerifyIDTokenFunc func(ctx context.Context, token, nonce string) (bool, error)
	EndSession        func(ctx context.Context, p EndSessionParams) (*url.URL, error)
	Revoke            func(ctx context.Context, token string) error
}

// GenericProvider implements Provider and the optional capabilities declared by its Spec.
type GenericProvider struct {
	S Spec
}

// NewProvider creates a provider from a spec.
func NewProvider(s Spec) *GenericProvider {
	settings := s.Options.Settings()
	settings.CallbackPath = s.Settings.CallbackPath
	settings.RequiresIDTokenNonce = s.Settings.RequiresIDTokenNonce
	settings.AllowIDPInitiated = s.Settings.AllowIDPInitiated
	settings.Issuer = s.Settings.Issuer
	if s.Settings.DisableIDTokenSignIn {
		settings.DisableIDTokenSignIn = true
	}
	s.Settings = settings
	return &GenericProvider{S: s}
}

// ID implements Provider.
func (g *GenericProvider) ID() string { return g.S.ID }

// Name implements Provider.
func (g *GenericProvider) Name() string { return g.S.Name }

// Options returns the provider options.
func (g *GenericProvider) Options() *ProviderOptions { return &g.S.Options }

// ProviderSettings implements Settings.
func (g *GenericProvider) ProviderSettings() *ProviderSettings { return &g.S.Settings }

// CreateAuthorizationURL implements Provider.
func (g *GenericProvider) CreateAuthorizationURL(ctx context.Context, p AuthorizationURLParams) (*url.URL, error) {
	return g.S.AuthorizationURL(ctx, p)
}

// ValidateAuthorizationCode implements Provider.
func (g *GenericProvider) ValidateAuthorizationCode(ctx context.Context, p CodeParams) (*Tokens, error) {
	return g.S.ExchangeCode(ctx, p)
}

// GetUserInfo implements Provider.
func (g *GenericProvider) GetUserInfo(ctx context.Context, p UserInfoParams) (*UserInfoResult, error) {
	if g.S.Options.GetUserInfo != nil {
		t := p.Tokens
		return g.S.Options.GetUserInfo(ctx, &t)
	}
	return g.S.UserInfo(ctx, p)
}

// AccountSubject implements Provider.
func (g *GenericProvider) AccountSubject(_ context.Context, tokens *Tokens, profile map[string]any) (string, error) {
	if g.S.Subject != nil {
		return g.S.Subject(tokens, profile)
	}
	for _, k := range []string{"sub", "id"} {
		if v, ok := profile[k]; ok && v != nil {
			return stringOf(v), nil
		}
	}
	return "", errors.New("OAUTH_ACCOUNT_SUBJECT_INVALID")
}

// SupportsRefresh reports refresh support.
func (g *GenericProvider) SupportsRefresh() bool {
	return g.S.Options.RefreshAccessToken != nil || g.S.Refresh != nil
}

// RefreshAccessToken implements Refresher.
func (g *GenericProvider) RefreshAccessToken(ctx context.Context, refreshToken string, rc *RefreshContext) (*Tokens, error) {
	if g.S.Options.RefreshAccessToken != nil {
		return g.S.Options.RefreshAccessToken(ctx, refreshToken)
	}
	if g.S.Refresh == nil {
		return nil, errors.New("token refresh not supported")
	}
	return g.S.Refresh(ctx, refreshToken, rc)
}

// SupportsIDToken reports id-token sign-in support.
func (g *GenericProvider) SupportsIDToken() bool {
	if g.S.Options.DisableIDTokenSignIn || g.S.Settings.DisableIDTokenSignIn {
		return false
	}
	return g.S.Options.VerifyIDToken != nil || g.S.VerifyIDTokenFunc != nil || g.S.IDToken != nil
}

// VerifyIDToken implements IDTokenVerifier (verifyProviderIdToken).
func (g *GenericProvider) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	if g.S.Options.DisableIDTokenSignIn {
		return false, nil
	}
	switch {
	case g.S.Options.VerifyIDToken != nil:
		return g.S.Options.VerifyIDToken(ctx, token, nonce)
	case g.S.VerifyIDTokenFunc != nil:
		return g.S.VerifyIDTokenFunc(ctx, token, nonce)
	case g.S.IDToken != nil:
		ok, err := g.S.IDToken.VerifyIDToken(ctx, token, nonce)
		if err != nil {
			return false, nil
		}
		return ok, nil
	}
	return false, nil
}

// SupportsEndSession reports RP-initiated logout support.
func (g *GenericProvider) SupportsEndSession() bool { return g.S.EndSession != nil }

// CreateEndSessionURL implements EndSessioner.
func (g *GenericProvider) CreateEndSessionURL(ctx context.Context, p EndSessionParams) (*url.URL, error) {
	if g.S.EndSession == nil {
		return nil, nil
	}
	return g.S.EndSession(ctx, p)
}

// SupportsRevoke reports token revocation support.
func (g *GenericProvider) SupportsRevoke() bool { return g.S.Revoke != nil }

// RevokeToken implements Revoker.
func (g *GenericProvider) RevokeToken(ctx context.Context, token string) error {
	if g.S.Revoke == nil {
		return errors.New("revoke not supported")
	}
	return g.S.Revoke(ctx, token)
}

// ---- capability helpers ----

// AsRefresher returns the provider's refresher when supported.
func AsRefresher(p Provider) (Refresher, bool) {
	r, ok := p.(Refresher)
	if !ok {
		return nil, false
	}
	if c, ok := p.(interface{ SupportsRefresh() bool }); ok && !c.SupportsRefresh() {
		return nil, false
	}
	return r, true
}

// AsIDTokenVerifier returns the provider's id-token verifier when supported.
func AsIDTokenVerifier(p Provider) (IDTokenVerifier, bool) {
	v, ok := p.(IDTokenVerifier)
	if !ok || SettingsOf(p).DisableIDTokenSignIn {
		return nil, false
	}
	if c, ok := p.(interface{ SupportsIDToken() bool }); ok && !c.SupportsIDToken() {
		return nil, false
	}
	return v, true
}

// AsEndSessioner returns the provider's end-session builder when supported.
func AsEndSessioner(p Provider) (EndSessioner, bool) {
	e, ok := p.(EndSessioner)
	if !ok {
		return nil, false
	}
	if c, ok := p.(interface{ SupportsEndSession() bool }); ok && !c.SupportsEndSession() {
		return nil, false
	}
	return e, true
}

// AsRevoker returns the provider's revoker when supported.
func AsRevoker(p Provider) (Revoker, bool) {
	r, ok := p.(Revoker)
	if !ok {
		return nil, false
	}
	if c, ok := p.(interface{ SupportsRevoke() bool }); ok && !c.SupportsRevoke() {
		return nil, false
	}
	return r, true
}

// StandardAuthorizationURL builds a typical authorization URL from options and defaults.
func StandardAuthorizationURL(o ProviderOptions, endpoint string, defaultScopes []string, p AuthorizationURLParams, extra AuthorizationURLOptions) (*url.URL, error) {
	extra.ClientID = o.PrimaryClientID()
	extra.AuthorizationEndpoint = endpoint
	extra.OverrideEndpoint = o.AuthorizationEndpoint
	extra.RedirectURI = p.RedirectURI
	extra.OverrideRedirectURI = o.RedirectURI
	extra.State = p.State
	if extra.CodeVerifier == "" {
		extra.CodeVerifier = p.CodeVerifier
	}
	if extra.Scopes == nil {
		extra.Scopes = o.BuildScopes(defaultScopes, p.Scopes)
	}
	if extra.LoginHint == "" {
		extra.LoginHint = p.LoginHint
	}
	if extra.Prompt == "" {
		extra.Prompt = o.Prompt
	}
	if extra.ResponseMode == "" {
		extra.ResponseMode = o.ResponseMode
	}
	if extra.Display == "" {
		extra.Display = p.Display
	}
	// {...providerParams, ...additionalParams}
	params := map[string]string{}
	for k, v := range extra.AdditionalParams {
		params[k] = v
	}
	for k, v := range p.AdditionalParams {
		params[k] = v
	}
	extra.AdditionalParamsOrder = append(OrderedKeys(extra.AdditionalParams, extra.AdditionalParamsOrder), p.AdditionalParamsOrder...)
	extra.AdditionalParams = params
	return CreateAuthorizationURL(extra)
}

// StandardExchange exchanges a code at tokenEndpoint with client_secret_post.
func StandardExchange(ctx context.Context, o ProviderOptions, tokenEndpoint string, p CodeParams, extra CodeExchange) (*Tokens, error) {
	extra.Code = p.Code
	extra.CodeVerifier = p.CodeVerifier
	if extra.DeviceID == "" {
		extra.DeviceID = p.DeviceID
	}
	extra.RedirectURI = p.RedirectURI
	if o.RedirectURI != "" {
		extra.RedirectURI = o.RedirectURI
	}
	extra.TokenEndpoint = tokenEndpoint
	extra.Client = o.Credentials()
	return ValidateAuthorizationCode(ctx, extra)
}

// StandardRefresh refreshes at tokenEndpoint.
func StandardRefresh(ctx context.Context, o ProviderOptions, tokenEndpoint, refreshToken string, extra RefreshRequest) (*Tokens, error) {
	extra.RefreshToken = refreshToken
	extra.TokenEndpoint = tokenEndpoint
	extra.Client = o.Credentials()
	return RefreshAccessToken(ctx, extra)
}

// BearerHeaders returns an Authorization: Bearer header map.
func BearerHeaders(accessToken string, extra ...string) map[string]string {
	h := map[string]string{"Authorization": "Bearer " + accessToken}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

// JoinName joins non-empty name parts with a space.
func JoinName(parts ...string) string {
	var out []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}
