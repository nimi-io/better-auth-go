// Package wechat implements the WeChat social provider (social-providers/wechat.ts).
//
// WeChat uses appid/secret instead of client_id/client_secret, exchanges and refreshes
// tokens with GET query parameters, and needs the openid returned with the access token
// to load the profile. The token response (including openid and unionid) is kept in
// Tokens.Raw, which GetUserInfo reads.
package wechat

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect"
	TokenEndpoint         = "https://api.weixin.qq.com/sns/oauth2/access_token"
	RefreshEndpoint       = "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	UserInfoEndpoint      = "https://api.weixin.qq.com/sns/userinfo"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"snsapi_login"}

// Options configure the provider. ClientID is the WeChat AppID and ClientSecret the
// AppSecret.
type Options struct {
	oauth2.ProviderOptions
	// PlatformType is the WeChat login platform; only "WebsiteApp" (the default) is supported.
	PlatformType string
	// Lang is the UI language of the login page: "cn" (default) or "en".
	Lang string
}

// New creates the WeChat provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "wechat", Name: "WeChat", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			u, err := url.Parse(AuthorizationEndpoint)
			if err != nil {
				return nil, err
			}
			lang := o.Lang
			if lang == "" {
				lang = "cn"
			}
			q := &query{}
			q.set("scope", strings.Join(o.BuildScopes(DefaultScopes, p.Scopes), ","))
			q.set("response_type", "code")
			q.set("appid", o.ClientID)
			q.set("redirect_uri", redirect(o, p.RedirectURI))
			q.set("state", p.State)
			q.set("lang", lang)
			for _, k := range oauth2.OrderedKeys(p.AdditionalParams, p.AdditionalParamsOrder) {
				if isReserved(k) || k == "appid" {
					continue
				}
				q.set(k, p.AdditionalParams[k])
			}
			u.RawQuery = q.encode()
			u.Fragment = "wechat_redirect"
			return u, nil
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			q := &query{}
			q.set("appid", o.ClientID)
			q.set("secret", o.ClientSecret)
			q.set("code", p.Code)
			q.set("grant_type", "authorization_code")
			data, err := getToken(ctx, TokenEndpoint+"?"+q.encode(), "Failed to validate authorization code")
			if err != nil {
				return nil, err
			}
			return tokensFrom(data), nil
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			q := &query{}
			q.set("appid", o.ClientID)
			q.set("grant_type", "refresh_token")
			q.set("refresh_token", rt)
			data, err := getToken(ctx, RefreshEndpoint+"?"+q.encode(), "Failed to refresh access token")
			if err != nil {
				return nil, err
			}
			t := tokensFrom(data)
			// upstream returns only the standard token fields on refresh
			t.Raw = nil
			return t, nil
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			if s := oauth2.String(profile, "unionid"); s != "" {
				return s, nil
			}
			return oauth2.String(profile, "openid"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			openid := oauth2.String(p.Raw, "openid")
			if openid == "" {
				return nil, nil
			}
			q := &query{}
			q.set("access_token", p.AccessToken)
			q.set("openid", openid)
			q.set("lang", "zh_CN")
			profile, err := oauth2.GetJSON(ctx, UserInfoEndpoint+"?"+q.encode(), nil)
			if err != nil || hasErrCode(profile) {
				return nil, nil
			}
			userID := oauth2.String(profile, "unionid")
			if userID == "" {
				userID = oauth2.String(profile, "openid")
			}
			if userID == "" {
				userID = openid
			}
			email := oauth2.String(profile, "email")
			if email == "" {
				var err error
				if email, err = oauth2.PlaceholderEmail(userID, "wechat"); err != nil {
					return nil, err
				}
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "nickname"), Email: email,
				Image: oauth2.String(profile, "headimgurl"), EmailVerified: false,
			})
		},
	})
}

// getToken performs a GET token request and maps WeChat errcode responses to errors.
func getToken(ctx context.Context, endpoint, prefix string) (map[string]any, error) {
	data, err := oauth2.GetJSON(ctx, endpoint, nil)
	if err != nil {
		var fe *oauth2.FetchError
		if errors.As(err, &fe) {
			msg := "Unknown error"
			if s, ok := fe.Body["errmsg"].(string); ok && s != "" {
				msg = s
			} else if s, ok := fe.Body["message"].(string); ok && s != "" {
				msg = s
			}
			return nil, fmt.Errorf("%s: %s", prefix, msg)
		}
		return nil, err
	}
	if hasErrCode(data) {
		msg := oauth2.String(data, "errmsg")
		if msg == "" {
			msg = "Unknown error"
		}
		return nil, fmt.Errorf("%s: %s", prefix, msg)
	}
	return data, nil
}

// hasErrCode mirrors the truthiness check on errcode (0 means success).
func hasErrCode(data map[string]any) bool {
	switch v := data["errcode"].(type) {
	case nil:
		return false
	case float64:
		return v != 0
	case string:
		return v != ""
	case bool:
		return v
	}
	return true
}

func tokensFrom(data map[string]any) *oauth2.Tokens {
	t := &oauth2.Tokens{TokenType: "Bearer", Raw: data}
	t.AccessToken, _ = data["access_token"].(string)
	t.RefreshToken, _ = data["refresh_token"].(string)
	if n, ok := data["expires_in"].(float64); ok {
		e := time.Now().Add(time.Duration(n * float64(time.Second)))
		t.AccessTokenExpiresAt = &e
	}
	scope, _ := data["scope"].(string)
	t.Scopes = strings.Split(scope, ",")
	return t
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
