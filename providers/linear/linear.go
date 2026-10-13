// Package linear implements the Linear social provider (social-providers/linear.ts).
package linear

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://linear.app/oauth/authorize"
	TokenEndpoint         = "https://api.linear.app/oauth/token"
	GraphQLEndpoint       = "https://api.linear.app/graphql"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"read"}

// ViewerQuery is the GraphQL query sent to fetch the user (byte-identical to upstream,
// including the template-literal indentation).
const ViewerQuery = "\n\t\t\t\t\t\t\tquery {\n\t\t\t\t\t\t\t\tviewer {\n\t\t\t\t\t\t\t\t\tid\n\t\t\t\t\t\t\t\t\tname\n\t\t\t\t\t\t\t\t\temail\n\t\t\t\t\t\t\t\t\tavatarUrl\n\t\t\t\t\t\t\t\t\tactive\n\t\t\t\t\t\t\t\t\tcreatedAt\n\t\t\t\t\t\t\t\t\tupdatedAt\n\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t"

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the Linear provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "linear", Name: "Linear", Options: o.ProviderOptions,
		// Upstream forwards state, scopes, loginHint, redirectURI and additionalParams
		// (no PKCE or prompt).
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "linear", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI, State: p.State,
				LoginHint: p.LoginHint,
				Scopes:    o.BuildScopes(DefaultScopes, p.Scopes), AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
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
		// The raw profile is the GraphQL viewer object.
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			body, _ := json.Marshal(map[string]string{"query": ViewerQuery})
			req, err := http.NewRequest("POST", GraphQLEndpoint, strings.NewReader(string(body)))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+p.AccessToken)
			res, err := oauth2.DoJSON(ctx, req)
			if err != nil {
				return nil, nil
			}
			viewer, _ := oauth2.Path(res, "data", "viewer").(map[string]any)
			if viewer == nil {
				return nil, nil
			}
			// Linear does not provide an email_verified claim; default to false.
			return oauth2.BuildUserInfo(o.ProviderOptions, viewer, oauth2.UserInfo{
				Name: oauth2.String(viewer, "name"), Email: oauth2.String(viewer, "email"),
				Image: oauth2.String(viewer, "avatarUrl"), EmailVerified: false,
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
