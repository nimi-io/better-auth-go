// Package railway implements the Railway social provider (social-providers/railway.ts).
package railway

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://backboard.railway.com/oauth/auth"
	TokenEndpoint         = "https://backboard.railway.com/oauth/token"
	UserInfoEndpoint      = "https://backboard.railway.com/oauth/me"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "email", "profile"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Railway provider. The token endpoint uses client_secret_basic.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "railway", Name: "Railway", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "railway",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				State:                 p.State,
				CodeVerifier:          p.CodeVerifier,
				Scopes:                o.BuildScopes(DefaultScopes, p.Scopes),
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.StandardExchange(ctx, o.ProviderOptions, TokenEndpoint,
				oauth2.CodeParams{Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: p.RedirectURI}, oauth2.CodeExchange{Basic: true})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{Basic: true})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "sub"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil {
				var fe *oauth2.FetchError
				if errors.As(err, &fe) {
					return nil, nil
				}
				return nil, err
			}
			// Railway does not provide an email_verified claim; default to false.
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name:          oauth2.String(profile, "name"),
				Email:         oauth2.String(profile, "email"),
				Image:         oauth2.String(profile, "picture"),
				EmailVerified: false,
			})
		},
	})
}
