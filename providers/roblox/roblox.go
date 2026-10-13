// Package roblox implements the Roblox social provider (social-providers/roblox.ts).
package roblox

import (
	"context"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://apis.roblox.com/oauth/v1/authorize"
	TokenEndpoint         = "https://apis.roblox.com/oauth/v1/token"
	UserInfoEndpoint      = "https://apis.roblox.com/oauth/v1/userinfo"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "profile"}

// DefaultPrompt is sent when Options.Prompt is empty.
const DefaultPrompt = "select_account consent"

// Options configure the provider. Prompt (from ProviderOptions) accepts "none",
// "consent", "login", "select_account" or "select_account consent".
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Roblox provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "roblox", Name: "Roblox", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			prompt := o.Prompt
			if prompt == "" {
				prompt = DefaultPrompt
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "roblox",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				Scopes:                o.BuildScopes(DefaultScopes, p.Scopes),
				State:                 p.State,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				Prompt:                prompt,
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			// authentication: "post" (client_secret_post when a secret is configured)
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code:          p.Code,
				RedirectURI:   firstNonEmpty(o.RedirectURI, p.RedirectURI),
				TokenEndpoint: TokenEndpoint,
				Client:        o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{RefreshToken: rt, TokenEndpoint: TokenEndpoint, Client: o.Credentials()})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "sub"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil {
				return nil, nil
			}
			name := oauth2.String(profile, "nickname")
			if name == "" {
				name = oauth2.String(profile, "preferred_username")
			}
			// Roblox returns no email: use a non-routable placeholder keyed to the user id.
			email, err := oauth2.PlaceholderEmail(oauth2.String(profile, "sub"), "roblox")
			if err != nil {
				return nil, err
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Image: oauth2.String(profile, "picture"), Email: email, EmailVerified: false,
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
