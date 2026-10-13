// Package cloudflare implements the Cloudflare social provider (social-providers/cloudflare.ts).
package cloudflare

import (
	"context"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider. Cloudflare's OIDC userinfo endpoint only returns sub, so
// the profile is read from the Cloudflare API /user endpoint (scope user-details.read).
const (
	AuthorizationEndpoint = "https://dash.cloudflare.com/oauth2/auth"
	TokenEndpoint         = "https://dash.cloudflare.com/oauth2/token"
	UserEndpoint          = "https://api.cloudflare.com/client/v4/user"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"user-details.read"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// TokenEndpointAuthMethod is "client_secret_basic" (default with a ClientSecret),
	// "client_secret_post", or "none" (default without a ClientSecret, PKCE clients).
	TokenEndpointAuthMethod oauth2.TokenEndpointAuthMethod
}

func (o Options) tokenEndpointAuth() *oauth2.TokenEndpointAuth {
	method := o.TokenEndpointAuthMethod
	if method == "" {
		method = oauth2.AuthNone
		if o.ClientSecret != "" {
			method = oauth2.AuthClientSecretBasic
		}
	}
	return &oauth2.TokenEndpointAuth{Method: method}
}

// New creates the Cloudflare provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "cloudflare", Name: "Cloudflare", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			// upstream does not forward additionalParams, prompt or login hints
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "cloudflare", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, CodeVerifier: p.CodeVerifier,
				Scopes: dedupe(o.BuildScopes(DefaultScopes, p.Scopes)),
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			redirect := p.RedirectURI
			if o.RedirectURI != "" {
				redirect = o.RedirectURI
			}
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect,
				TokenEndpoint: TokenEndpoint, Client: o.Credentials(), TokenEndpointAuth: o.tokenEndpointAuth(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt,
				oauth2.RefreshRequest{TokenEndpointAuth: o.tokenEndpointAuth()})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			data, err := oauth2.GetJSON(ctx, UserEndpoint, map[string]string{"authorization": "Bearer " + p.AccessToken})
			if err != nil || !truthy(data["success"]) {
				return nil, nil
			}
			profile, ok := data["result"].(map[string]any)
			if !ok {
				return nil, nil
			}
			name := joinTruthy(profile["first_name"], profile["last_name"])
			if name == "" {
				name = oauth2.String(profile, "email")
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: oauth2.String(profile, "email"),
				// Cloudflare does not expose email verification status
				EmailVerified: false,
			})
		},
	})
}

// dedupe mirrors [...new Set(scopes)]; an empty list yields nil (no scope parameter).
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

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

// joinTruthy mirrors [a, b].filter(Boolean).join(" ").
func joinTruthy(parts ...any) string {
	var out []string
	for _, p := range parts {
		if s, ok := p.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}
