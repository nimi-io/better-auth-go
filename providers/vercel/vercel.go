// Package vercel implements the Vercel social provider (social-providers/vercel.ts).
package vercel

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://vercel.com/oauth/authorize"
	TokenEndpoint         = "https://api.vercel.com/login/oauth/token"
	UserInfoEndpoint      = "https://api.vercel.com/login/oauth/userinfo"
)

// ErrCodeVerifierRequired is returned when building an authorization URL without PKCE.
var ErrCodeVerifierRequired = errors.New("codeVerifier is required for Vercel")

// Options configure the provider. Vercel has no default scopes (the scope parameter is
// only sent when Scope or request scopes are given) and does not support token refresh.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Vercel provider.
func New(o Options) *oauth2.GenericProvider {
	// Upstream exposes no refreshAccessToken for Vercel, so options.refreshAccessToken is
	// never consulted.
	spec := o.ProviderOptions
	spec.RefreshAccessToken = nil
	return oauth2.NewProvider(oauth2.Spec{
		ID: "vercel", Name: "Vercel", Options: spec,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if p.CodeVerifier == "" {
				return nil, ErrCodeVerifierRequired
			}
			var scopes []string
			scopes = append(scopes, o.Scope...)
			scopes = append(scopes, p.Scopes...)
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "vercel",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				State:                 p.State,
				CodeVerifier:          p.CodeVerifier,
				Scopes:                scopes,
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.StandardExchange(ctx, o.ProviderOptions, TokenEndpoint,
				oauth2.CodeParams{Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: p.RedirectURI}, oauth2.CodeExchange{})
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
			// name ?? preferred_username ?? "" (nullish, so an empty name is kept).
			name := ""
			if v, ok := profile["name"]; ok && v != nil {
				name = oauth2.String(profile, "name")
			} else if v, ok := profile["preferred_username"]; ok && v != nil {
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
