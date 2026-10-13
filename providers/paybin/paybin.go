// Package paybin implements the Paybin social provider (social-providers/paybin.ts).
package paybin

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// DefaultIssuer is the Paybin OAuth server used when Options.Issuer is empty.
const DefaultIssuer = "https://idp.paybin.io"

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "email", "profile"}

// Errors returned when building the authorization URL.
var (
	ErrClientIDAndSecretRequired = errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
	ErrCodeVerifierRequired      = errors.New("codeVerifier is required for Paybin")
)

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Issuer is the issuer URL of the Paybin OAuth server (default "https://idp.paybin.io").
	Issuer string
}

// AuthorizationEndpoint returns the authorization endpoint for an issuer.
func AuthorizationEndpoint(issuer string) string { return issuerOf(issuer) + "/oauth2/authorize" }

// TokenEndpoint returns the token endpoint for an issuer.
func TokenEndpoint(issuer string) string { return issuerOf(issuer) + "/oauth2/token" }

func issuerOf(issuer string) string {
	if issuer == "" {
		return DefaultIssuer
	}
	return issuer
}

// New creates the Paybin provider.
func New(o Options) *oauth2.GenericProvider {
	authorizationEndpoint := AuthorizationEndpoint(o.Issuer)
	tokenEndpoint := TokenEndpoint(o.Issuer)
	return oauth2.NewProvider(oauth2.Spec{
		ID: "paybin", Name: "Paybin", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" || o.ClientSecret == "" {
				return nil, ErrClientIDAndSecretRequired
			}
			if p.CodeVerifier == "" {
				return nil, ErrCodeVerifierRequired
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "paybin",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: authorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				State:                 p.State,
				CodeVerifier:          p.CodeVerifier,
				Scopes:                o.BuildScopes(DefaultScopes, p.Scopes),
				Prompt:                o.Prompt,
				LoginHint:             p.LoginHint,
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.StandardExchange(ctx, o.ProviderOptions, tokenEndpoint,
				oauth2.CodeParams{Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: p.RedirectURI}, oauth2.CodeExchange{})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, tokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "sub"), nil
		},
		UserInfo: func(_ context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.IDToken == "" {
				return nil, nil
			}
			// The profile is the (unverified) id token payload, as upstream (decodeJwt).
			user, err := oauth2.DecodeJWTPayload(p.IDToken)
			if err != nil {
				return nil, err
			}
			name := oauth2.String(user, "name")
			if name == "" {
				name = oauth2.String(user, "preferred_username")
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, user, oauth2.UserInfo{
				Name:          name,
				Email:         oauth2.String(user, "email"),
				Image:         oauth2.String(user, "picture"),
				EmailVerified: user["email_verified"] == true,
			})
		},
	})
}
