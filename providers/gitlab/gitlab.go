// Package gitlab implements the GitLab social provider (social-providers/gitlab.ts).
package gitlab

import (
	"context"
	"errors"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// DefaultIssuer is the GitLab base URL used when Options.Issuer is empty.
const DefaultIssuer = "https://gitlab.com"

// Endpoints for the default issuer (https://gitlab.com).
const (
	AuthorizationEndpoint = DefaultIssuer + "/oauth/authorize"
	TokenEndpoint         = DefaultIssuer + "/oauth/token"
	UserEndpoint          = DefaultIssuer + "/api/v4/user"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"read_user"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Issuer is the base URL of a self-hosted GitLab instance (default https://gitlab.com).
	Issuer string
}

// Endpoints are the issuer-derived endpoints.
type Endpoints struct {
	Authorization string
	Token         string
	UserInfo      string
}

var multiSlash = regexp.MustCompile(`/{2,}`)

// cleanDoubleSlashes collapses repeated slashes outside the scheme separator.
func cleanDoubleSlashes(input string) string {
	parts := strings.Split(input, "://")
	for i, p := range parts {
		parts[i] = multiSlash.ReplaceAllString(p, "/")
	}
	return strings.Join(parts, "://")
}

// IssuerEndpoints mirrors issuerToEndpoints.
func IssuerEndpoints(issuer string) Endpoints {
	base := issuer
	if base == "" {
		base = DefaultIssuer
	}
	return Endpoints{
		Authorization: cleanDoubleSlashes(base + "/oauth/authorize"),
		Token:         cleanDoubleSlashes(base + "/oauth/token"),
		UserInfo:      cleanDoubleSlashes(base + "/api/v4/user"),
	}
}

// New creates the GitLab provider.
func New(o Options) *oauth2.GenericProvider {
	ep := IssuerEndpoints(o.Issuer)
	return oauth2.NewProvider(oauth2.Spec{
		ID: "gitlab", Name: "Gitlab", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "gitlab", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: ep.Authorization, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, Scopes: o.BuildScopes(DefaultScopes, p.Scopes),
				CodeVerifier: p.CodeVerifier, LoginHint: p.LoginHint, AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			redirect := p.RedirectURI
			if o.RedirectURI != "" {
				redirect = o.RedirectURI
			}
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect,
				TokenEndpoint: ep.Token, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, ep.Token, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, ep.UserInfo, map[string]string{"authorization": "Bearer " + p.AccessToken})
			if err != nil {
				var fe *oauth2.FetchError
				if errors.As(err, &fe) {
					return nil, nil
				}
				return nil, err
			}
			if state, _ := profile["state"].(string); state != "active" || truthy(profile["locked"]) {
				return nil, nil
			}
			// name ?? username ?? ""
			name := ""
			if v := profile["name"]; v != nil {
				name = oauth2.String(profile, "name")
			} else if v := profile["username"]; v != nil {
				name = oauth2.String(profile, "username")
			}
			// email_verified ?? false
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: oauth2.String(profile, "email"), Image: oauth2.String(profile, "avatar_url"),
				EmailVerified: oauth2.Bool(profile, "email_verified"),
			})
		},
	})
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
		return t != 0 && !math.IsNaN(t)
	}
	return true
}
