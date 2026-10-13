// Package line implements the LINE Login v2.1 social provider (social-providers/line.ts).
package line

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://access.line.me/oauth2/v2.1/authorize"
	TokenEndpoint         = "https://api.line.me/oauth2/v2.1/token"
	UserInfoEndpoint      = "https://api.line.me/oauth2/v2.1/userinfo"
	VerifyIDTokenEndpoint = "https://api.line.me/oauth2/v2.1/verify"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "profile", "email"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the LINE provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "line", Name: "LINE", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "line", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, CodeVerifier: p.CodeVerifier, Scopes: o.BuildScopes(DefaultScopes, p.Scopes),
				LoginHint: p.LoginHint, AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect(o, p.RedirectURI),
				TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{RefreshToken: rt, TokenEndpoint: TokenEndpoint,
				Client: oauth2.ClientCredentials{ClientID: o.PrimaryClientID(), ClientSecret: o.ClientSecret}})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "sub"), nil
		},
		// LINE verifies id tokens remotely with its verify endpoint.
		VerifyIDTokenFunc: func(ctx context.Context, token, nonce string) (bool, error) {
			return verifyIDToken(ctx, o.PrimaryClientID(), token, nonce), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			var profile map[string]any
			// Prefer the id token when available.
			if p.IDToken != "" {
				if claims, err := oauth2.DecodeJWTPayload(p.IDToken); err == nil {
					profile = claims
				}
			}
			// Fall back to the UserInfo endpoint.
			if profile == nil {
				data, err := oauth2.GetJSON(ctx, UserInfoEndpoint, map[string]string{"authorization": "Bearer " + p.AccessToken})
				if err != nil {
					return nil, nil
				}
				profile = data
			}
			// LINE does not expose email verification status.
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
				Image: oauth2.String(profile, "picture"), EmailVerified: false,
			})
		},
	})
}

// verifyIDToken posts the token to the LINE verify endpoint; the returned aud must equal
// the client id and a returned nonce must equal the expected nonce. Failures are false.
func verifyIDToken(ctx context.Context, clientID, token, nonce string) bool {
	body := "id_token=" + oauth2.FormEncode(token) + "&client_id=" + oauth2.FormEncode(clientID)
	if nonce != "" {
		body += "&nonce=" + oauth2.FormEncode(nonce)
	}
	req, err := http.NewRequest("POST", VerifyIDTokenEndpoint, strings.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	data, err := oauth2.DoJSON(ctx, req)
	if err != nil || data == nil {
		return false
	}
	if aud, _ := data["aud"].(string); aud != clientID {
		return false
	}
	// a truthy nonce in the response must match the expected nonce
	switch n := data["nonce"].(type) {
	case nil:
	case string:
		if n != "" && n != nonce {
			return false
		}
	case bool:
		if n {
			return false
		}
	case float64:
		if n != 0 {
			return false
		}
	default:
		return false
	}
	return true
}

func redirect(o Options, fallback string) string {
	if o.RedirectURI != "" {
		return o.RedirectURI
	}
	return fallback
}
