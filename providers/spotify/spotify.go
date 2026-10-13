// Package spotify implements the Spotify social provider (social-providers/spotify.ts).
package spotify

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://accounts.spotify.com/authorize"
	TokenEndpoint         = "https://accounts.spotify.com/api/token"
	UserEndpoint          = "https://api.spotify.com/v1/me"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"user-read-email"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Spotify provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "spotify", Name: "Spotify", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "spotify", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, Scopes: o.BuildScopes(DefaultScopes, p.Scopes),
				CodeVerifier: p.CodeVerifier, AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
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
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserEndpoint, map[string]string{"Authorization": "Bearer " + p.AccessToken})
			if err != nil {
				var fe *oauth2.FetchError
				if errors.As(err, &fe) {
					return nil, nil
				}
				return nil, err
			}
			// profile.images[0]?.url — upstream throws when images is not an array
			images, ok := profile["images"].([]any)
			if !ok {
				return nil, errors.New("spotify: profile.images is not an array")
			}
			image := ""
			if len(images) > 0 {
				image = oauth2.String(asMap(images[0]), "url")
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "display_name"), Email: oauth2.String(profile, "email"),
				Image: image, EmailVerified: false,
			})
		},
	})
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
