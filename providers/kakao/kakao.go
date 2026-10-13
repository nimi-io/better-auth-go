// Package kakao implements the Kakao social provider (social-providers/kakao.ts).
package kakao

import (
	"context"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://kauth.kakao.com/oauth/authorize"
	TokenEndpoint         = "https://kauth.kakao.com/oauth/token"
	UserInfoEndpoint      = "https://kapi.kakao.com/v2/user/me"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"account_email", "profile_image", "profile_nickname"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Kakao provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "kakao", Name: "Kakao", Options: o.ProviderOptions,
		// Upstream forwards only state, scopes, redirectURI and additionalParams (no PKCE,
		// login hint or prompt).
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "kakao", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI, State: p.State,
				Scopes: o.BuildScopes(DefaultScopes, p.Scopes), AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		// The code verifier is not forwarded upstream.
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, RedirectURI: redirect(o, p.RedirectURI), TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil || profile == nil {
				return nil, nil
			}
			account, _ := profile["kakao_account"].(map[string]any)
			if account == nil {
				account = map[string]any{}
			}
			kp, _ := account["profile"].(map[string]any)
			if kp == nil {
				kp = map[string]any{}
			}
			name := oauth2.String(kp, "nickname")
			if name == "" {
				name = oauth2.String(account, "name")
			}
			image := oauth2.String(kp, "profile_image_url")
			if image == "" {
				image = oauth2.String(kp, "thumbnail_image_url")
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: oauth2.String(account, "email"), Image: image,
				EmailVerified: truthy(account["is_email_valid"]) && truthy(account["is_email_verified"]),
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

// truthy mirrors JavaScript's !!value for JSON values.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	}
	return true
}
