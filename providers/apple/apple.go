// Package apple implements the Sign in with Apple social provider (social-providers/apple.ts).
package apple

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://appleid.apple.com/auth/authorize"
	TokenEndpoint         = "https://appleid.apple.com/auth/token"
	JWKSEndpoint          = "https://appleid.apple.com/auth/keys"
	Issuer                = "https://appleid.apple.com"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"email", "name"}

// Options configure the provider. ClientSecret is the pre-signed client secret JWT.
type Options struct {
	oauth2.ProviderOptions
	// AppBundleIdentifier is the iOS bundle id accepted as id-token audience (native sign-in).
	AppBundleIdentifier string
	// Audience overrides the accepted id-token audiences.
	Audience []string
}

// audience mirrors `audience?.length ? audience : appBundleIdentifier ? appBundleIdentifier : clientId`.
func (o Options) audience() []string {
	if len(o.Audience) > 0 {
		return o.Audience
	}
	if o.AppBundleIdentifier != "" {
		return []string{o.AppBundleIdentifier}
	}
	return o.Audiences()
}

// New creates the Apple provider.
func New(o Options) *oauth2.GenericProvider {
	idt := &oauth2.IDTokenConfig{
		JWKSURL: JWKSEndpoint, Issuer: []string{Issuer}, Audience: o.audience(),
		MaxTokenAge: time.Hour, NonceComparison: "exact-or-sha256",
	}
	return oauth2.NewProvider(oauth2.Spec{
		ID: "apple", Name: "Apple", Options: o.ProviderOptions, IDToken: idt,
		VerifyIDTokenFunc: verifyWithKid(idt),
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" || o.ClientSecret == "" {
				return nil, errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "apple", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, CodeVerifier: p.CodeVerifier,
				Scopes:       o.BuildScopes(DefaultScopes, p.Scopes),
				ResponseMode: "form_post", ResponseType: "code id_token",
				AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			redirect := p.RedirectURI
			if o.RedirectURI != "" {
				redirect = o.RedirectURI
			}
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect,
				TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "sub"), nil
		},
		UserInfo: func(_ context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.IDToken == "" {
				return nil, nil
			}
			profile, err := oauth2.DecodeJWTPayload(p.IDToken)
			if err != nil {
				return nil, err
			}
			if profile == nil {
				return nil, nil
			}
			var name string
			if p.User != nil && p.User.Name != nil {
				name = strings.TrimSpace(p.User.Name.FirstName + " " + p.User.Name.LastName)
			} else {
				name = oauth2.String(profile, "name")
			}
			profile["name"] = name
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: oauth2.String(profile, "email"),
				EmailVerified: oauth2.Bool(profile, "email_verified"),
			})
		},
	})
}

// verifyWithKid mirrors getApplePublicKey(header.kid!): a token without a kid never
// matches a key, and every failure resolves to false (verifyProviderIdToken is fail-closed).
func verifyWithKid(cfg *oauth2.IDTokenConfig) func(ctx context.Context, token, nonce string) (bool, error) {
	return func(ctx context.Context, token, nonce string) (bool, error) {
		if strings.Count(token, ".") == 2 {
			h, err := jose.Header(token)
			if err != nil {
				return false, nil
			}
			v, _ := h.Get("kid")
			if kid, ok := v.(string); !ok || kid == "" {
				return false, nil
			}
		}
		ok, err := cfg.VerifyIDToken(ctx, token, nonce)
		if err != nil {
			return false, nil
		}
		return ok, nil
	}
}
