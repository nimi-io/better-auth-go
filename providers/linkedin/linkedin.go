// Package linkedin implements the LinkedIn social provider (social-providers/linkedin.ts).
package linkedin

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization"
	TokenEndpoint         = "https://www.linkedin.com/oauth/v2/accessToken"
	UserInfoEndpoint      = "https://api.linkedin.com/v2/userinfo"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"profile", "email", "openid"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the LinkedIn provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "linkedin", Name: "Linkedin", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "linkedin", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, Scopes: o.BuildScopes(DefaultScopes, p.Scopes),
				LoginHint: p.LoginHint, AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
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
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, map[string]string{"Authorization": "Bearer " + p.AccessToken})
			if err != nil {
				var fe *oauth2.FetchError
				if errors.As(err, &fe) {
					return nil, nil
				}
				return nil, err
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
				EmailVerified: oauth2.Bool(profile, "email_verified"), Image: oauth2.String(profile, "picture"),
			})
		},
	})
}
