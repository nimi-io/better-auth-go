// Package twitter implements the Twitter (X) social provider (social-providers/twitter.ts).
package twitter

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://x.com/i/oauth2/authorize"
	TokenEndpoint         = "https://api.x.com/2/oauth2/token"
	// ProfileEndpoint returns the profile (with profile_image_url).
	ProfileEndpoint = "https://api.x.com/2/users/me?user.fields=profile_image_url"
	// EmailEndpoint returns the confirmed email (requires the users.email scope).
	EmailEndpoint = "https://api.x.com/2/users/me?user.fields=confirmed_email"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"users.read", "tweet.read", "offline.access", "users.email"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Twitter provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "twitter", Name: "Twitter", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "twitter", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, CodeVerifier: p.CodeVerifier, Scopes: o.BuildScopes(DefaultScopes, p.Scopes),
				AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect(o, p.RedirectURI),
				TokenEndpoint: TokenEndpoint, Client: o.Credentials(), Basic: true,
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{Basic: true})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			data, ok := profile["data"].(map[string]any)
			if !ok {
				return "", errors.New("OAUTH_ACCOUNT_SUBJECT_INVALID")
			}
			return oauth2.String(data, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			headers := oauth2.BearerHeaders(p.AccessToken)
			profile, err := oauth2.GetJSON(ctx, ProfileEndpoint, headers)
			if err != nil {
				return nil, nil
			}
			data, ok := profile["data"].(map[string]any)
			if !ok {
				return nil, nil
			}
			emailVerified := false
			if emailData, err := oauth2.GetJSON(ctx, EmailEndpoint, headers); err == nil {
				if confirmed, _ := oauth2.Path(emailData, "data", "confirmed_email").(string); confirmed != "" {
					data["email"] = confirmed
					emailVerified = true
				}
			}
			email := oauth2.String(data, "email")
			if email == "" {
				var err error
				if email, err = oauth2.PlaceholderEmail(oauth2.String(data, "id"), "twitter"); err != nil {
					return nil, err
				}
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(data, "name"), Email: email,
				Image: oauth2.String(data, "profile_image_url"), EmailVerified: emailVerified,
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
