// Package oauth2 defines the OAuth provider interface shared by Better Auth's social
// providers (packages/core/src/oauth2), plus helpers to build authorization URLs, exchange
// codes and refresh tokens.
package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Tokens are OAuth tokens returned by a provider (OAuth2Tokens).
type Tokens struct {
	TokenType             string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scopes                []string
	IDToken               string
	Raw                   map[string]any
}

// UserInfo is the normalised user returned by GetUserInfo (OAuth2UserInfo plus any
// additional mapped fields in Extra).
type UserInfo struct {
	Name string
	// Email is empty when the provider returned no email.
	Email         string
	Image         string
	EmailVerified bool
	// Extra holds additional fields produced by mapProfileToUser.
	Extra map[string]any
}

// UserInfoResult is the result of GetUserInfo: the normalised user and the raw profile.
type UserInfoResult struct {
	User UserInfo
	Data map[string]any
}

// AppleUserName is the optional user payload some providers (Apple) send on first sign-in.
type AppleUserName struct {
	FirstName string
	LastName  string
}

// UserInfoParams are the inputs of GetUserInfo.
type UserInfoParams struct {
	Tokens
	// ExpectedIDTokenNonce is the nonce stored in the OAuth state, when one was sent.
	ExpectedIDTokenNonce string
	// User is the optional user object (Apple form_post / id-token sign-in).
	User *struct {
		Name  *AppleUserName
		Email string
	}
}

// AuthorizationURLParams are the inputs of CreateAuthorizationURL.
type AuthorizationURLParams struct {
	State            string
	CodeVerifier     string
	Scopes           []string
	RedirectURI      string
	Display          string
	LoginHint        string
	IDTokenNonce     string
	AdditionalParams map[string]string
	// AdditionalParamsOrder is the key order of AdditionalParams in the request body.
	AdditionalParamsOrder []string
}

// CodeParams are the inputs of ValidateAuthorizationCode.
type CodeParams struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	DeviceID     string
}

// EndSessionParams are the inputs of CreateEndSessionURL.
type EndSessionParams struct {
	IDToken               string
	PostLogoutRedirectURI string
	State                 string
}

// RefreshContext carries the incoming request (if any) during a token refresh.
type RefreshContext struct {
	Headers http.Header
	Request *http.Request
}

// Provider is an OAuth/OIDC provider (OAuthProvider upstream).
type Provider interface {
	ID() string
	Name() string
	CreateAuthorizationURL(ctx context.Context, p AuthorizationURLParams) (*url.URL, error)
	ValidateAuthorizationCode(ctx context.Context, p CodeParams) (*Tokens, error)
	GetUserInfo(ctx context.Context, p UserInfoParams) (*UserInfoResult, error)
	// AccountSubject returns the provider account id for the (tokens, profile) pair.
	AccountSubject(ctx context.Context, tokens *Tokens, profile map[string]any) (string, error)
}

// Refresher is implemented by providers that support refresh tokens.
type Refresher interface {
	RefreshAccessToken(ctx context.Context, refreshToken string, rc *RefreshContext) (*Tokens, error)
}

// Revoker is implemented by providers that can revoke tokens.
type Revoker interface {
	RevokeToken(ctx context.Context, token string) error
}

// EndSessioner is implemented by providers with RP-initiated logout.
type EndSessioner interface {
	CreateEndSessionURL(ctx context.Context, p EndSessionParams) (*url.URL, error)
}

// IDTokenVerifier is implemented by providers that support id-token sign-in.
type IDTokenVerifier interface {
	VerifyIDToken(ctx context.Context, token, nonce string) (bool, error)
}

// Settings exposes optional provider settings. Providers embedding [BaseProvider] get it.
type Settings interface {
	ProviderSettings() *ProviderSettings
}

// ProviderSettings are flags shared by all providers.
type ProviderSettings struct {
	CallbackPath          string
	RequiresIDTokenNonce  bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
	DisableIDTokenSignIn  bool
	AllowIDPInitiated     bool
	Issuer                string
	// OverrideUserInfoOnSignIn updates the user's profile on every sign-in.
	OverrideUserInfoOnSignIn bool
	// RequireEmailVerification rejects unverified provider emails.
	RequireEmailVerification bool
}

// SettingsOf returns the provider settings (zero value when the provider has none).
func SettingsOf(p Provider) ProviderSettings {
	if s, ok := p.(Settings); ok && s.ProviderSettings() != nil {
		return *s.ProviderSettings()
	}
	return ProviderSettings{}
}

// SupportsIDTokenSignIn mirrors supportsIdTokenSignIn upstream.
func SupportsIDTokenSignIn(p Provider) bool {
	_, ok := AsIDTokenVerifier(p)
	return ok
}

// CallbackPath returns the callback path of a provider (getOAuthCallbackPath).
func CallbackPath(p Provider) string {
	cp := SettingsOf(p).CallbackPath
	if cp == "" {
		return "/callback/" + p.ID()
	}
	if cp[0] != '/' {
		return "/" + cp
	}
	return cp
}
