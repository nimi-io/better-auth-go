// Package tiktok implements the TikTok social provider (social-providers/tiktok.ts).
//
// TikTok identifies the client with client_key (ProviderOptions.ClientKey) instead of
// client_id, joins scopes with commas and does not expose the user's email.
package tiktok

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://www.tiktok.com/v2/auth/authorize"
	TokenEndpoint         = "https://open.tiktokapis.com/v2/oauth/token/"
	UserInfoEndpoint      = "https://open.tiktokapis.com/v2/user/info/"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"user.info.profile"}

// UserInfoFields are requested from the user info endpoint.
var UserInfoFields = []string{"open_id", "avatar_large_url", "display_name", "username"}

// Options configure the provider. ClientKey and ClientSecret are required; ClientID is
// not used by TikTok.
type Options struct {
	oauth2.ProviderOptions
}

// New creates the TikTok provider.
func New(o Options) *oauth2.GenericProvider {
	// TikTok authenticates the client with client_key + client_secret body parameters.
	auth := &oauth2.TokenEndpointAuth{Method: oauth2.AuthCustom, Customize: func(r *oauth2.TokenRequest) error {
		r.Set("client_key", o.ClientKey)
		r.Set("client_secret", o.ClientSecret)
		return nil
	}}
	return oauth2.NewProvider(oauth2.Spec{
		ID: "tiktok", Name: "TikTok", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			// TikTok uses client_key instead of client_id, so the shared helper cannot be used.
			u, err := url.Parse(AuthorizationEndpoint)
			if err != nil {
				return nil, err
			}
			q := &query{}
			q.set("scope", strings.Join(o.BuildScopes(DefaultScopes, p.Scopes), ","))
			q.set("response_type", "code")
			q.set("client_key", o.ClientKey)
			q.set("redirect_uri", redirect(o, p.RedirectURI))
			q.set("state", p.State)
			for _, k := range oauth2.OrderedKeys(p.AdditionalParams, p.AdditionalParamsOrder) {
				if isReserved(k) || k == "client_key" {
					continue
				}
				q.set(k, p.AdditionalParams[k])
			}
			u.RawQuery = q.encode()
			return u, nil
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect(o, p.RedirectURI),
				TokenEndpoint: TokenEndpoint, TokenEndpointAuth: auth,
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{RefreshToken: rt, TokenEndpoint: TokenEndpoint, TokenEndpointAuth: auth})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			user, ok := oauth2.Path(profile, "data", "user").(map[string]any)
			if !ok {
				return "", errors.New("OAUTH_ACCOUNT_SUBJECT_INVALID")
			}
			return oauth2.String(user, "open_id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint+"?fields="+strings.Join(UserInfoFields, ","),
				map[string]string{"authorization": "Bearer " + p.AccessToken})
			if err != nil {
				return nil, nil
			}
			user, ok := oauth2.Path(profile, "data", "user").(map[string]any)
			if !ok {
				return nil, nil
			}
			email := oauth2.String(user, "email")
			if email == "" {
				var err error
				if email, err = oauth2.PlaceholderEmail(oauth2.String(user, "open_id"), "tiktok"); err != nil {
					return nil, err
				}
			}
			name := oauth2.String(user, "display_name")
			if name == "" {
				name = oauth2.String(user, "username")
			}
			// Upstream TikTok does not apply mapProfileToUser.
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{
				Email: email, Name: name, Image: oauth2.String(user, "avatar_large_url"), EmailVerified: false,
			}, Data: profile}, nil
		},
	})
}

func redirect(o Options, fallback string) string {
	if o.RedirectURI != "" {
		return o.RedirectURI
	}
	return fallback
}

func isReserved(k string) bool {
	for _, r := range oauth2.ReservedAuthorizationParams {
		if r == k {
			return true
		}
	}
	return false
}

// query is an insertion-ordered URLSearchParams.
type query struct {
	keys []string
	vals map[string]string
}

func (q *query) set(k, v string) {
	if q.vals == nil {
		q.vals = map[string]string{}
	}
	if _, ok := q.vals[k]; !ok {
		q.keys = append(q.keys, k)
	}
	q.vals[k] = v
}

func (q *query) encode() string {
	parts := make([]string, 0, len(q.keys))
	for _, k := range q.keys {
		parts = append(parts, oauth2.FormEncode(k)+"="+oauth2.FormEncode(q.vals[k]))
	}
	return strings.Join(parts, "&")
}
