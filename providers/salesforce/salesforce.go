// Package salesforce implements the Salesforce social provider (social-providers/salesforce.ts).
package salesforce

import (
	"context"
	"errors"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Production and sandbox hosts.
const (
	ProductionHost = "login.salesforce.com"
	SandboxHost    = "test.salesforce.com"
)

// Endpoint paths appended to the login host.
const (
	AuthorizationPath = "/services/oauth2/authorize"
	TokenPath         = "/services/oauth2/token"
	UserInfoPath      = "/services/oauth2/userinfo"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "email", "profile"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Environment is "production" (default) or "sandbox".
	Environment string
	// LoginURL is a custom login host (e.g. "mycompany.my.salesforce.com"); it takes
	// precedence over Environment.
	LoginURL string
}

// Endpoints returns the authorization, token and userinfo endpoints for the options.
func (o Options) Endpoints() (authorization, token, userInfo string) {
	host := ProductionHost
	switch {
	case o.LoginURL != "":
		host = o.LoginURL
	case o.Environment == "sandbox":
		host = SandboxHost
	}
	base := "https://" + host
	return base + AuthorizationPath, base + TokenPath, base + UserInfoPath
}

// New creates the Salesforce provider.
func New(o Options) *oauth2.GenericProvider {
	authorizationEndpoint, tokenEndpoint, userInfoEndpoint := o.Endpoints()
	return oauth2.NewProvider(oauth2.Spec{
		ID: "salesforce", Name: "Salesforce", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" || o.ClientSecret == "" {
				return nil, errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
			}
			if p.CodeVerifier == "" {
				return nil, errors.New("codeVerifier is required for Salesforce")
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "salesforce",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: authorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				Scopes:                o.BuildScopes(DefaultScopes, p.Scopes),
				State:                 p.State,
				CodeVerifier:          p.CodeVerifier,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code:          p.Code,
				CodeVerifier:  p.CodeVerifier,
				RedirectURI:   firstNonEmpty(o.RedirectURI, p.RedirectURI),
				TokenEndpoint: tokenEndpoint,
				Client:        o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{
				RefreshToken: rt, TokenEndpoint: tokenEndpoint,
				Client: oauth2.ClientCredentials{ClientID: o.PrimaryClientID(), ClientSecret: o.ClientSecret},
			})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "user_id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			user, err := oauth2.GetJSON(ctx, userInfoEndpoint, oauth2.BearerHeaders(p.AccessToken))
			if err != nil || user == nil {
				return nil, nil // "Failed to fetch user info from Salesforce"
			}
			image := oauth2.String(asMap(user["photos"]), "picture")
			if image == "" {
				image = oauth2.String(asMap(user["photos"]), "thumbnail")
			}
			res, err := oauth2.BuildUserInfo(o.ProviderOptions, user, oauth2.UserInfo{
				Name: oauth2.String(user, "name"), Email: oauth2.String(user, "email"), Image: image,
				EmailVerified: oauth2.Bool(user, "email_verified"),
			})
			if err != nil {
				return nil, nil // upstream catches every error (including mapProfileToUser) and returns null
			}
			return res, nil
		},
	})
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
