// Package vk implements the VK ID social provider (social-providers/vk.ts).
package vk

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://id.vk.com/authorize"
	TokenEndpoint         = "https://id.vk.com/oauth2/auth"
	UserInfoEndpoint      = "https://id.vk.com/oauth2/user_info"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"email", "phone"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Scheme is "light" or "dark". It is accepted for parity with upstream (VkOption.scheme)
	// but, as upstream, it is not sent anywhere.
	Scheme string
}

// New creates the VK provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "vk", Name: "VK", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID:                    "vk",
				ClientID:              o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint,
				OverrideEndpoint:      o.AuthorizationEndpoint,
				Scopes:                o.BuildScopes(DefaultScopes, p.Scopes),
				State:                 p.State,
				RedirectURI:           p.RedirectURI,
				OverrideRedirectURI:   o.RedirectURI,
				CodeVerifier:          p.CodeVerifier,
				AdditionalParams:      p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code:          p.Code,
				CodeVerifier:  p.CodeVerifier,
				RedirectURI:   firstNonEmpty(o.RedirectURI, p.RedirectURI),
				DeviceID:      p.DeviceID,
				TokenEndpoint: TokenEndpoint,
				Client:        o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{RefreshToken: rt, TokenEndpoint: TokenEndpoint, Client: o.Credentials()})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(user(profile), "user_id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.AccessToken == "" {
				return nil, nil
			}
			body := "access_token=" + oauth2.FormEncode(p.AccessToken) + "&client_id=" + oauth2.FormEncode(o.PrimaryClientID())
			req, err := http.NewRequest("POST", UserInfoEndpoint, strings.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			profile, err := oauth2.DoJSON(ctx, req)
			if err != nil {
				return nil, nil
			}
			var userMap map[string]any
			if o.MapProfileToUser != nil {
				if userMap, err = o.MapProfileToUser(profile); err != nil {
					return nil, err
				}
			}
			u := user(profile)
			if u == nil {
				// upstream dereferences profile.user and throws a TypeError
				return nil, errors.New("vk: user info response has no user")
			}
			if oauth2.String(u, "email") == "" && !truthy(userMap["email"]) {
				return nil, nil
			}
			extra := map[string]any{}
			for _, k := range []string{"first_name", "last_name", "birthday", "sex"} {
				if v, ok := u[k]; ok {
					extra[k] = v
				}
			}
			base := oauth2.UserInfo{
				Name:  jsTemplate(u, "first_name") + " " + jsTemplate(u, "last_name"),
				Email: oauth2.String(u, "email"), Image: oauth2.String(u, "avatar"), EmailVerified: false, Extra: extra,
			}
			// re-apply the already computed userMap on top of the base mapping ({...base, ...userMap})
			mapped := o.ProviderOptions
			if userMap != nil {
				mapped.MapProfileToUser = func(map[string]any) (map[string]any, error) { return userMap, nil }
			}
			return oauth2.BuildUserInfo(mapped, profile, base)
		},
	})
}

func user(profile map[string]any) map[string]any {
	u, _ := profile["user"].(map[string]any)
	return u
}

// jsTemplate renders a value as a JS template literal would (`${v}`).
func jsTemplate(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return "undefined"
	}
	if v == nil {
		return "null"
	}
	return oauth2.String(m, key)
}

// truthy mirrors JavaScript truthiness for JSON values.
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
	case int:
		return t != 0
	}
	return true
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
