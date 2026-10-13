// Package naver implements the Naver social provider (social-providers/naver.ts).
package naver

import (
	"context"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://nid.naver.com/oauth2.0/authorize"
	TokenEndpoint         = "https://nid.naver.com/oauth2.0/token"
	UserInfoEndpoint      = "https://openapi.naver.com/v1/nid/me"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"profile", "email"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Naver provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "naver", Name: "Naver", Options: o.ProviderOptions,
		// Upstream forwards only state, scopes, redirectURI and additionalParams (no PKCE,
		// login hint or prompt).
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "naver", ClientID: o.PrimaryClientID(),
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
		// The raw profile is the whole API envelope; the subject is response.id.
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			res, _ := profile["response"].(map[string]any)
			return oauth2.String(res, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil || profile == nil {
				return nil, nil
			}
			if rc, _ := profile["resultcode"].(string); rc != "00" {
				return nil, nil
			}
			res, _ := profile["response"].(map[string]any)
			if res == nil {
				res = map[string]any{}
			}
			name := oauth2.String(res, "name")
			if name == "" {
				name = oauth2.String(res, "nickname")
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: oauth2.String(res, "email"), Image: oauth2.String(res, "profile_image"),
				EmailVerified: false,
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
