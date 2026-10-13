// Package kick implements the Kick social provider (social-providers/kick.ts).
package kick

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://id.kick.com/oauth/authorize"
	TokenEndpoint         = "https://id.kick.com/oauth/token"
	UsersEndpoint         = "https://api.kick.com/public/v1/users"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"user:read"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Kick provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "kick", Name: "Kick", Options: o.ProviderOptions,
		// Upstream forwards state, scopes, codeVerifier (PKCE), redirectURI and
		// additionalParams.
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "kick", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI, State: p.State,
				CodeVerifier: p.CodeVerifier,
				Scopes:       o.BuildScopes(DefaultScopes, p.Scopes), AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect(o, p.RedirectURI),
				TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{
				RefreshToken: rt, TokenEndpoint: TokenEndpoint,
				Client: oauth2.ClientCredentials{ClientID: o.PrimaryClientID(), ClientSecret: o.ClientSecret},
			})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "user_id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			data, err := oauth2.GetJSON(ctx, UsersEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil {
				return nil, nil
			}
			list, _ := data["data"].([]any)
			var profile map[string]any
			if len(list) > 0 {
				profile, _ = list[0].(map[string]any)
			}
			if profile == nil {
				// upstream dereferences data.data[0]! and throws
				return nil, errors.New("kick: user info response contains no user")
			}
			// Kick does not provide an email_verified claim; default to false.
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
				Image: oauth2.String(profile, "profile_picture"), EmailVerified: false,
			})
		},
	})
}

func redirect(o Options, fallback string) string {
	if o.RedirectURI != "" {
		return o.RedirectURI
	}
	return fallback
}
