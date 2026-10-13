// Package discord implements the Discord social provider (social-providers/discord.ts).
package discord

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://discord.com/api/oauth2/authorize"
	TokenEndpoint         = "https://discord.com/api/oauth2/token"
	UserEndpoint          = "https://discord.com/api/users/@me"
	CDNBase               = "https://cdn.discordapp.com"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"identify", "email"}

// Options configure the provider. ProviderOptions.Prompt ("none" | "consent") defaults
// to "none".
type Options struct {
	oauth2.ProviderOptions
	// Permissions is sent as the permissions parameter when the "bot" scope is requested.
	Permissions *int64
}

// New creates the Discord provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "discord", Name: "Discord", Options: o.ProviderOptions,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			// upstream order: defaults, request scopes, options.scope
			var scopes []string
			if !o.DisableDefaultScope {
				scopes = append(scopes, DefaultScopes...)
			}
			scopes = append(scopes, p.Scopes...)
			scopes = append(scopes, o.Scope...)
			hasBot := false
			for _, s := range scopes {
				if s == "bot" {
					hasBot = true
					break
				}
			}
			params := map[string]string{}
			if hasBot && o.Permissions != nil {
				params["permissions"] = strconv.FormatInt(*o.Permissions, 10)
			}
			for k, v := range p.AdditionalParams {
				params[k] = v
			}
			prompt := o.Prompt
			if prompt == "" {
				prompt = "none"
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "discord", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, Scopes: scopes, Prompt: prompt, AdditionalParams: params, AdditionalParamsOrder: append([]string{"permissions"}, p.AdditionalParamsOrder...),
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			// upstream sends neither code_verifier nor device_id
			redirect := p.RedirectURI
			if o.RedirectURI != "" {
				redirect = o.RedirectURI
			}
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, RedirectURI: redirect, TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			profile, err := oauth2.GetJSON(ctx, UserEndpoint, map[string]string{"authorization": "Bearer " + p.AccessToken})
			if err != nil {
				var fe *oauth2.FetchError
				if errors.As(err, &fe) {
					return nil, nil
				}
				return nil, err
			}
			image, err := AvatarURL(profile)
			if err != nil {
				return nil, err
			}
			profile["image_url"] = image
			name := truthyString(profile["global_name"])
			if name == "" {
				name = truthyString(profile["username"])
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: name, Email: oauth2.String(profile, "email"),
				EmailVerified: oauth2.Bool(profile, "verified"), Image: image,
			})
		},
	})
}

// AvatarURL computes the profile image URL exactly like upstream: the default avatar
// (embed/avatars/N.png) when avatar is null, otherwise the user's avatar (gif when the
// hash starts with "a_").
func AvatarURL(profile map[string]any) (string, error) {
	avatar, present := profile["avatar"]
	if present && avatar == nil {
		var n float64
		if d, ok := profile["discriminator"].(string); ok && d == "0" {
			id, err := jsBigInt(profile["id"], hasKey(profile, "id"))
			if err != nil {
				return "", err
			}
			shifted := new(big.Int).Rsh(id, 22)
			f, _ := new(big.Float).SetInt(shifted).Float64()
			n = math.Mod(f, 6)
		} else {
			n = math.Mod(jsParseInt(jsToString(profile, "discriminator")), 5)
		}
		return CDNBase + "/embed/avatars/" + jsNumber(n) + ".png", nil
	}
	s, ok := avatar.(string)
	if !ok {
		return "", fmt.Errorf("discord: profile.avatar.startsWith is not a function")
	}
	format := "png"
	if strings.HasPrefix(s, "a_") {
		format = "gif"
	}
	return CDNBase + "/avatars/" + jsToString(profile, "id") + "/" + s + "." + format, nil
}

func hasKey(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// truthyString returns v when it is a non-empty string-ish JS truthy value.
func truthyString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if !t {
			return ""
		}
		return "true"
	case float64:
		if t == 0 || math.IsNaN(t) {
			return ""
		}
	}
	return oauth2.String(map[string]any{"v": v}, "v") // String(value) for other truthy values
}

// jsToString mirrors String(profile[key]) (template literal interpolation).
func jsToString(profile map[string]any, key string) string {
	v, ok := profile[key]
	if !ok {
		return "undefined"
	}
	if v == nil {
		return "null"
	}
	return oauth2.String(profile, key)
}

func jsNumber(f float64) string {
	if math.IsNaN(f) {
		return "NaN"
	}
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	return jsonx.FormatNumber(f)
}

func isJSSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// jsParseInt mirrors parseInt(s) with no radix.
func jsParseInt(s string) float64 {
	s = strings.TrimLeftFunc(s, isJSSpace)
	sign := 1.0
	if s != "" && (s[0] == '+' || s[0] == '-') {
		if s[0] == '-' {
			sign = -1
		}
		s = s[1:]
	}
	base := 10.0
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		base = 16
		s = s[2:]
	}
	var n float64
	digits := 0
	for _, c := range s {
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			d = -1
		}
		if d < 0 {
			break
		}
		n = n*base + float64(d)
		digits++
	}
	if digits == 0 {
		return math.NaN()
	}
	if base == 10 {
		// exact decimal rounding for long digit strings
		if f, err := strconv.ParseFloat(s[:digits], 64); err == nil {
			n = f
		}
	}
	return sign * n
}

// jsBigInt mirrors BigInt(v) for the values a Discord profile id can take.
func jsBigInt(v any, present bool) (*big.Int, error) {
	if !present {
		return nil, errors.New("discord: Cannot convert undefined to a BigInt")
	}
	switch t := v.(type) {
	case nil:
		return nil, errors.New("discord: Cannot convert null to a BigInt")
	case float64:
		if t != math.Trunc(t) || math.IsInf(t, 0) || math.IsNaN(t) {
			return nil, fmt.Errorf("discord: The number %s cannot be converted to a BigInt because it is not an integer", jsNumber(t))
		}
		i, _ := new(big.Float).SetFloat64(t).Int(nil)
		return i, nil
	case bool:
		if t {
			return big.NewInt(1), nil
		}
		return big.NewInt(0), nil
	case string:
		s := strings.TrimFunc(t, isJSSpace)
		if s == "" {
			return big.NewInt(0), nil
		}
		base := 10
		if len(s) > 2 && s[0] == '0' {
			switch s[1] {
			case 'x', 'X':
				base = 16
			case 'o', 'O':
				base = 8
			case 'b', 'B':
				base = 2
			}
			if base != 10 {
				s = s[2:]
			}
		}
		if strings.ContainsAny(s, "_") || (base != 10 && (s[0] == '+' || s[0] == '-')) {
			return nil, fmt.Errorf("discord: Cannot convert %s to a BigInt", t)
		}
		i, ok := new(big.Int).SetString(s, base)
		if !ok {
			return nil, fmt.Errorf("discord: Cannot convert %s to a BigInt", t)
		}
		return i, nil
	}
	return nil, fmt.Errorf("discord: Cannot convert %v to a BigInt", v)
}
