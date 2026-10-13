// Package reddit implements the Reddit social provider (social-providers/reddit.ts).
package reddit

import (
	"context"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://www.reddit.com/api/v1/authorize"
	TokenEndpoint         = "https://www.reddit.com/api/v1/access_token"
	UserInfoEndpoint      = "https://oauth.reddit.com/api/v1/me"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"identity"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Duration is sent as the duration parameter ("temporary" or "permanent").
	Duration string
}

// tokenEndpointAuth: Reddit requires HTTP Basic client authentication (RFC 6749 §2.3.1).
var tokenEndpointAuth = &oauth2.TokenEndpointAuth{Method: oauth2.AuthClientSecretBasic}

// New creates the Reddit provider.
func New(o Options) *oauth2.GenericProvider {
	// tokenRequestOptions upstream carry only clientId/clientSecret (no clientKey).
	client := oauth2.ClientCredentials{ClientID: o.PrimaryClientID(), ClientSecret: o.ClientSecret}
	return oauth2.NewProvider(oauth2.Spec{
		ID: "reddit", Name: "Reddit", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "reddit",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				Scopes:                o.BuildScopes(DefaultScopes, p.Scopes),
				State:                 p.State,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				Duration:              o.Duration,
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code:              p.Code,
				RedirectURI:       firstNonEmpty(o.RedirectURI, p.RedirectURI),
				TokenEndpoint:     TokenEndpoint,
				Client:            client,
				TokenEndpointAuth: tokenEndpointAuth,
				Headers:           map[string]string{"accept": "text/plain", "user-agent": "better-auth"},
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{
				RefreshToken: rt, TokenEndpoint: TokenEndpoint, Client: client, TokenEndpointAuth: tokenEndpointAuth,
			})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken, "User-Agent", "better-auth"))
			if err != nil {
				return nil, nil
			}
			image := ""
			if s, ok := profile["icon_img"].(string); ok {
				image, _, _ = strings.Cut(s, "?")
			}
			res, err := oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Image: image,
			})
			if err != nil {
				return nil, err
			}
			// Reddit's identity scope returns no email: synthesise a stable, non-routable
			// placeholder keyed to the Reddit id (never oauth_client_id), left unverified
			// unless mapProfileToUser supplies an email / emailVerified.
			if res.User.Email == "" {
				email, err := oauth2.PlaceholderEmail(oauth2.String(profile, "id"), "reddit")
				if err != nil {
					return nil, err
				}
				res.User.Email = email
			}
			return res, nil
		},
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
