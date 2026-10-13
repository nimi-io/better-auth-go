// Package atlassian implements the Atlassian social provider
// (social-providers/atlassian.ts).
package atlassian

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://auth.atlassian.com/authorize"
	TokenEndpoint         = "https://auth.atlassian.com/oauth/token"
	UserInfoEndpoint      = "https://api.atlassian.com/me"
	// Audience is always sent as the audience authorization parameter.
	Audience = "api.atlassian.com"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"read:jira-user", "offline_access"}

// Errors returned when building the authorization URL.
var (
	ErrClientIDAndSecretRequired = errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
	ErrCodeVerifierRequired      = errors.New("codeVerifier is required for Atlassian")
)

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Atlassian provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "atlassian", Name: "Atlassian", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" || o.ClientSecret == "" {
				return nil, ErrClientIDAndSecretRequired
			}
			if p.CodeVerifier == "" {
				return nil, ErrCodeVerifierRequired
			}
			params := map[string]string{}
			for k, v := range p.AdditionalParams {
				params[k] = v
			}
			params["audience"] = Audience
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "atlassian",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				State:                 p.State,
				CodeVerifier:          p.CodeVerifier,
				Scopes:                o.BuildScopes(DefaultScopes, p.Scopes),
				Prompt:                o.Prompt,
				AdditionalParams:      params, AdditionalParamsOrder: append(append([]string(nil), p.AdditionalParamsOrder...), "audience"),
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.StandardExchange(ctx, o.ProviderOptions, TokenEndpoint,
				oauth2.CodeParams{Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: p.RedirectURI}, oauth2.CodeExchange{})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			// Upstream refreshes with clientId + clientSecret only (no clientKey).
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{
				RefreshToken:  rt,
				TokenEndpoint: TokenEndpoint,
				Client:        oauth2.ClientCredentials{ClientID: o.PrimaryClientID(), ClientSecret: o.ClientSecret},
			})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "account_id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.AccessToken == "" {
				return nil, nil
			}
			// Upstream wraps the lookup in try/catch and returns null on any failure.
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil || profile == nil {
				return nil, nil
			}
			res, err := oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name:          oauth2.String(profile, "name"),
				Email:         oauth2.String(profile, "email"),
				Image:         oauth2.String(profile, "picture"),
				EmailVerified: false,
			})
			if err != nil {
				return nil, nil
			}
			return res, nil
		},
	})
}
