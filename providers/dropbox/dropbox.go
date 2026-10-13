// Package dropbox implements the Dropbox social provider (social-providers/dropbox.ts).
package dropbox

import (
	"context"
	"net/http"
	"net/url"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://www.dropbox.com/oauth2/authorize"
	TokenEndpoint         = "https://api.dropboxapi.com/oauth2/token"
	UserInfoEndpoint      = "https://api.dropboxapi.com/2/users/get_current_account"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"account_info.read"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// AccessType is sent as token_access_type: "offline", "online" or "legacy".
	AccessType string
}

// New creates the Dropbox provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "dropbox", Name: "Dropbox", Options: o.ProviderOptions,
		// Upstream forwards state, scopes, codeVerifier (PKCE), redirectURI and
		// additionalParams (call-time params override token_access_type).
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			params := map[string]string{}
			if o.AccessType != "" {
				params["token_access_type"] = o.AccessType
			}
			for k, v := range p.AdditionalParams {
				params[k] = v
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "dropbox", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI, State: p.State,
				CodeVerifier: p.CodeVerifier,
				Scopes:       o.BuildScopes(DefaultScopes, p.Scopes), AdditionalParams: params, AdditionalParamsOrder: append([]string{"token_access_type"}, p.AdditionalParamsOrder...),
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect(o, p.RedirectURI),
				TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "account_id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			// Dropbox RPC endpoint: POST with no body.
			req, err := http.NewRequest("POST", UserInfoEndpoint, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+p.AccessToken)
			profile, err := oauth2.DoJSON(ctx, req)
			if err != nil {
				return nil, nil
			}
			name, _ := oauth2.Path(profile, "name", "display_name").(string)
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: oauth2.String(profile, "email"),
				EmailVerified: oauth2.Bool(profile, "email_verified"),
				Image:         oauth2.String(profile, "profile_photo_url"),
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
