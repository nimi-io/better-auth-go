// Package zoom implements the Zoom social provider (social-providers/zoom.ts).
package zoom

import (
	"context"
	"math"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://zoom.us/oauth/authorize"
	TokenEndpoint         = "https://zoom.us/oauth/token"
	UserInfoEndpoint      = "https://api.zoom.us/v2/users/me"
)

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// PKCE sends a code challenge in the authorization URL (default true).
	PKCE *bool
}

// New creates the Zoom provider. As upstream, the authorization URL carries no scope
// parameter (scopes are configured on the Zoom app), so Scope/DisableDefaultScope and
// request scopes are ignored.
func New(o Options) *oauth2.GenericProvider {
	pkce := o.PKCE == nil || *o.PKCE
	return oauth2.NewProvider(oauth2.Spec{
		ID: "zoom", Name: "Zoom", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			verifier := ""
			if pkce {
				verifier = p.CodeVerifier
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "zoom",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				State:                 p.State,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				CodeVerifier:          verifier,
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			// authentication: "post"; the code verifier is forwarded whenever present.
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code:          p.Code,
				CodeVerifier:  p.CodeVerifier,
				RedirectURI:   firstNonEmpty(o.RedirectURI, p.RedirectURI),
				TokenEndpoint: TokenEndpoint,
				Client:        o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{RefreshToken: rt, TokenEndpoint: TokenEndpoint, Client: o.Credentials()})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil {
				return nil, nil
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "display_name"), Image: oauth2.String(profile, "pic_url"),
				Email: oauth2.String(profile, "email"), EmailVerified: truthy(profile["verified"]),
			})
		},
	})
}

// truthy mirrors Boolean(v) for JSON values (Zoom's verified is a number, e.g. 1).
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && !math.IsNaN(t)
	}
	return true
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
