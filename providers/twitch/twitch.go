// Package twitch implements the Twitch (OIDC) social provider (social-providers/twitch.ts).
package twitch

import (
	"context"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://id.twitch.tv/oauth2/authorize"
	TokenEndpoint         = "https://id.twitch.tv/oauth2/token"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"user:read:email", "openid"}

// DefaultClaims are the id_token claims requested when Options.Claims is nil.
var DefaultClaims = []string{"email", "email_verified", "preferred_username", "picture"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Claims are the id_token claims requested (in addition to email and
	// email_verified). nil uses DefaultClaims; an empty non-nil slice requests only
	// email and email_verified.
	Claims []string
}

// New creates the Twitch provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "twitch", Name: "Twitch", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			claims := o.Claims
			if claims == nil {
				claims = DefaultClaims
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "twitch", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, Scopes: o.BuildScopes(DefaultScopes, p.Scopes),
				Claims: claims, AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			// upstream sends no code_verifier
			redirect := p.RedirectURI
			if o.RedirectURI != "" {
				redirect = o.RedirectURI
			}
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, RedirectURI: redirect, TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
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
				// upstream: logger.error("No idToken found in token"); return null
				return nil, nil
			}
			// the id token is decoded, not verified (decodeJwt upstream)
			profile, err := oauth2.DecodeJWTPayload(p.IDToken)
			if err != nil {
				return nil, err
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "preferred_username"), Email: oauth2.String(profile, "email"),
				Image: oauth2.String(profile, "picture"), EmailVerified: oauth2.Bool(profile, "email_verified"),
			})
		},
	})
}
