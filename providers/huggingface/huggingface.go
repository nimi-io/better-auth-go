// Package huggingface implements the Hugging Face social provider
// (social-providers/huggingface.ts).
package huggingface

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://huggingface.co/oauth/authorize"
	TokenEndpoint         = "https://huggingface.co/oauth/token"
	UserInfoEndpoint      = "https://huggingface.co/oauth/userinfo"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "profile", "email"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Hugging Face provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "huggingface", Name: "Hugging Face", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			// Upstream forwards only state, scopes, codeVerifier, redirectURI and
			// additionalParams (no prompt / login_hint / display / response_mode).
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "huggingface",
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
				oauth2.CodeParams{Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: p.RedirectURI}, oauth2.CodeExchange{})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
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
			name := oauth2.String(profile, "name")
			if name == "" {
				name = oauth2.String(profile, "preferred_username")
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name:          name,
				Email:         oauth2.String(profile, "email"),
				Image:         oauth2.String(profile, "picture"),
				EmailVerified: profile["email_verified"] == true,
			})
		},
	})
}
