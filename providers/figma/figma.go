// Package figma implements the Figma social provider (social-providers/figma.ts).
package figma

import (
	"context"
	"errors"
	"log/slog"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://www.figma.com/oauth"
	TokenEndpoint         = "https://api.figma.com/v1/oauth/token"
	UserInfoEndpoint      = "https://api.figma.com/v1/me"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"current_user:read"}

// Errors returned by CreateAuthorizationURL.
var (
	ErrClientIDAndSecretRequired = errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
	ErrCodeVerifierRequired      = errors.New("codeVerifier is required for Figma")
)

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Figma provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "figma", Name: "Figma", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" || o.ClientSecret == "" {
				slog.Error("Client Id and Client Secret are required for Figma. Make sure to provide them in the options.")
				return nil, ErrClientIDAndSecretRequired
			}
			if p.CodeVerifier == "" {
				return nil, ErrCodeVerifierRequired
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "figma", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI, State: p.State,
				CodeVerifier: p.CodeVerifier,
				Scopes:       o.BuildScopes(DefaultScopes, p.Scopes), AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		// client_secret_basic (authentication: "basic").
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
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil || profile == nil {
				slog.Error("Failed to fetch user from Figma")
				return nil, nil
			}
			res, err := oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "handle"), Email: oauth2.String(profile, "email"),
				Image: oauth2.String(profile, "img_url"), EmailVerified: false,
			})
			if err != nil {
				// upstream catches every error (including mapProfileToUser) and returns null
				slog.Error("Failed to fetch user info from Figma:", "error", err)
				return nil, nil
			}
			return res, nil
		},
	})
}

func redirect(o Options, fallback string) string {
	if o.RedirectURI != "" {
		return o.RedirectURI
	}
	return fallback
}
