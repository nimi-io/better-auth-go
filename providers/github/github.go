// Package github implements the GitHub social provider (social-providers/github.ts).
package github

import (
	"context"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://github.com/login/oauth/authorize"
	TokenEndpoint         = "https://github.com/login/oauth/access_token"
	UserEndpoint          = "https://api.github.com/user"
	EmailsEndpoint        = "https://api.github.com/user/emails"
)

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the GitHub provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "github", Name: "GitHub", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.StandardAuthorizationURL(o.ProviderOptions, AuthorizationEndpoint, []string{"read:user", "user:email"}, p, oauth2.AuthorizationURLOptions{})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			req, err := oauth2.NewTokenRequest(oauth2.CodeExchange{Code: p.Code, CodeVerifier: p.CodeVerifier,
				RedirectURI: redirect(o, p.RedirectURI), TokenEndpoint: TokenEndpoint, Client: o.Credentials()})
			if err != nil {
				return nil, err
			}
			data, err := oauth2.PostTokenRequest(ctx, req)
			if err != nil {
				return nil, nil // GitHub token errors yield null (upstream logs and returns null)
			}
			if _, isErr := data["error"]; isErr {
				return nil, nil
			}
			return oauth2.TokensFromResponse(data), nil
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			headers := oauth2.BearerHeaders(p.AccessToken, "User-Agent", "better-auth")
			profile, err := oauth2.GetJSON(ctx, UserEndpoint, headers)
			if err != nil {
				return nil, nil
			}
			emails, _ := oauth2.GetJSONArray(ctx, EmailsEndpoint, headers)
			email := oauth2.String(profile, "email")
			if email == "" && len(emails) > 0 {
				pick := emails[0]
				for _, e := range emails {
					if oauth2.Bool(e, "primary") {
						pick = e
						break
					}
				}
				email = oauth2.String(pick, "email")
				profile["email"] = email
			}
			verified := false
			for _, e := range emails {
				if oauth2.String(e, "email") == email {
					verified = oauth2.Bool(e, "verified")
					break
				}
			}
			name := oauth2.String(profile, "name")
			if name == "" {
				name = oauth2.String(profile, "login")
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: email, Image: oauth2.String(profile, "avatar_url"), EmailVerified: verified,
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
