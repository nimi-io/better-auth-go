// Package paypal implements the PayPal social provider (social-providers/paypal.ts).
package paypal

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Sandbox endpoints (the default environment).
const (
	SandboxAuthorizationEndpoint = "https://www.sandbox.paypal.com/signin/authorize"
	SandboxTokenEndpoint         = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
	SandboxUserInfoEndpoint      = "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo"
)

// Live endpoints.
const (
	LiveAuthorizationEndpoint = "https://www.paypal.com/signin/authorize"
	LiveTokenEndpoint         = "https://api-m.paypal.com/v1/oauth2/token"
	LiveUserInfoEndpoint      = "https://api-m.paypal.com/v1/identity/oauth2/userinfo"
)

// Environments.
const (
	EnvironmentSandbox = "sandbox"
	EnvironmentLive    = "live"
)

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Environment is "sandbox" (default) or "live".
	Environment string
	// RequestShippingAddress is accepted for parity with upstream (currently unused).
	RequestShippingAddress bool
}

// Endpoints returns the authorization, token and userinfo endpoints for an environment.
func Endpoints(environment string) (authorization, token, userInfo string) {
	if environment == "" || environment == EnvironmentSandbox {
		return SandboxAuthorizationEndpoint, SandboxTokenEndpoint, SandboxUserInfoEndpoint
	}
	return LiveAuthorizationEndpoint, LiveTokenEndpoint, LiveUserInfoEndpoint
}

// New creates the PayPal provider.
func New(o Options) *oauth2.GenericProvider {
	authorizationEndpoint, tokenEndpoint, userInfoEndpoint := Endpoints(o.Environment)
	client := oauth2.ClientCredentials{ClientID: o.ClientID, ClientSecret: o.ClientSecret}
	auth := &oauth2.TokenEndpointAuth{Method: oauth2.AuthClientSecretBasic}
	return oauth2.NewProvider(oauth2.Spec{
		ID: "paypal", Name: "PayPal", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.ClientID == "" || o.ClientSecret == "" {
				return nil, errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
			}
			// Log in with PayPal permissions are configured in the developer dashboard; no
			// scopes are sent to avoid "invalid scope" errors.
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "paypal", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: authorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, CodeVerifier: p.CodeVerifier, Prompt: o.Prompt,
				AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			t, err := oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect(o, p.RedirectURI),
				TokenEndpoint: tokenEndpoint, Client: client, TokenEndpointAuth: auth,
			})
			if err != nil {
				return nil, errors.New("FAILED_TO_GET_ACCESS_TOKEN")
			}
			return t, nil
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			t, err := oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{
				RefreshToken: rt, TokenEndpoint: tokenEndpoint, Client: client, TokenEndpointAuth: auth,
			})
			if err != nil {
				return nil, errors.New("FAILED_TO_REFRESH_ACCESS_TOKEN")
			}
			return t, nil
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "user_id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.AccessToken == "" {
				return nil, nil
			}
			profile, err := oauth2.GetJSON(ctx, userInfoEndpoint+"?schema=paypalv1.1",
				oauth2.BearerHeaders(p.AccessToken, "Accept", "application/json"))
			if err != nil {
				return nil, nil
			}
			if p.IDToken != "" {
				claims, err := oauth2.DecodeJWTPayload(p.IDToken)
				if err != nil {
					return nil, nil
				}
				// OIDC binds UserInfo to the ID token with sub; user_id stays the account id.
				idSub, _ := claims["sub"].(string)
				subject, ok := profile["sub"]
				if !ok || subject == nil {
					subject = profile["user_id"]
				}
				if s, _ := subject.(string); idSub == "" || s != idSub {
					return nil, nil
				}
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
				Image: oauth2.String(profile, "picture"), EmailVerified: oauth2.Bool(profile, "email_verified"),
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
