// Package slack implements the Slack (Sign in with Slack / OpenID Connect) social
// provider (social-providers/slack.ts).
package slack

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://slack.com/openid/connect/authorize"
	TokenEndpoint         = "https://slack.com/api/openid.connect.token"
	UserInfoEndpoint      = "https://slack.com/api/openid.connect.userInfo"
)

// Profile claim keys.
const (
	ClaimUserID       = "https://slack.com/user_id"
	ClaimUserImage512 = "https://slack.com/user_image_512"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "profile", "email"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Slack provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "slack", Name: "Slack", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			// upstream order: defaults, request scopes, options.scope
			var scopes []string
			if !o.DisableDefaultScope {
				scopes = append(scopes, DefaultScopes...)
			}
			scopes = append(scopes, p.Scopes...)
			scopes = append(scopes, o.Scope...)
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "slack", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, Scopes: scopes, AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
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
			return oauth2.String(profile, ClaimUserID), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, map[string]string{"authorization": "Bearer " + p.AccessToken})
			if err != nil {
				var fe *oauth2.FetchError
				if errors.As(err, &fe) {
					return nil, nil
				}
				return nil, err
			}
			image := oauth2.String(profile, "picture")
			if image == "" {
				image = oauth2.String(profile, ClaimUserImage512)
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
				EmailVerified: oauth2.Bool(profile, "email_verified"), Image: image,
			})
		},
	})
}
