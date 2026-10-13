// Package notion implements the Notion social provider (social-providers/notion.ts).
package notion

import (
	"context"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://api.notion.com/v1/oauth/authorize"
	TokenEndpoint         = "https://api.notion.com/v1/oauth/token"
	UserInfoEndpoint      = "https://api.notion.com/v1/users/me"
	// APIVersion is sent as the Notion-Version header.
	APIVersion = "2022-06-28"
)

// Options configure the provider. Notion has no default scopes.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Notion provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "notion", Name: "Notion", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			params := map[string]string{}
			for k, v := range p.AdditionalParams {
				params[k] = v
			}
			params["owner"] = "user"
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "notion",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				Scopes:                o.BuildScopes(nil, p.Scopes),
				State:                 p.State,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				LoginHint:             p.LoginHint,
				AdditionalParams:      params, AdditionalParamsOrder: append(append([]string(nil), p.AdditionalParamsOrder...), "owner"),
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			// authentication: "basic"
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code:          p.Code,
				RedirectURI:   firstNonEmpty(o.RedirectURI, p.RedirectURI),
				TokenEndpoint: TokenEndpoint,
				Client:        o.Credentials(),
				Basic:         true,
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{RefreshToken: rt, TokenEndpoint: TokenEndpoint, Client: o.Credentials()})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			data, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken, "Notion-Version", APIVersion))
			if err != nil || data == nil {
				return nil, nil
			}
			profile, _ := oauth2.Path(data, "bot", "owner", "user").(map[string]any)
			if profile == nil {
				return nil, nil
			}
			person, _ := profile["person"].(map[string]any)
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(person, "email"),
				Image: oauth2.String(profile, "avatar_url"), EmailVerified: false,
			})
		},
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
