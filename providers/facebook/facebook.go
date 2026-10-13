// Package facebook implements the Facebook social provider (social-providers/facebook.ts).
package facebook

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://www.facebook.com/v24.0/dialog/oauth"
	TokenEndpoint         = "https://graph.facebook.com/v24.0/oauth/access_token"
	DebugTokenEndpoint    = "https://graph.facebook.com/debug_token"
	ProfileEndpoint       = "https://graph.facebook.com/me"
	// JWKSEndpoint serves the keys of Limited Login id tokens.
	JWKSEndpoint = "https://limited.facebook.com/.well-known/oauth/openid/jwks/"
	// Issuer of Limited Login id tokens.
	Issuer = "https://www.facebook.com"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"email", "public_profile"}

// DefaultFields are always requested from the Graph API /me endpoint.
var DefaultFields = []string{"id", "name", "email", "picture"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Fields extends the profile fields requested from the Graph API
	// (["id", "name", "email", "picture"] are always requested).
	Fields []string
	// ConfigID is sent as config_id on the authorization request.
	ConfigID string
}

// New creates the Facebook provider.
func New(o Options) *oauth2.GenericProvider {
	return oauth2.NewProvider(oauth2.Spec{
		ID: "facebook", Name: "Facebook", Options: o.ProviderOptions,
		IDToken: &oauth2.IDTokenConfig{
			JWKSURL: JWKSEndpoint, Issuer: []string{Issuer}, Audience: o.Audiences(),
			Algorithms: []string{"RS256"},
			// Facebook also accepts an opaque Graph access token on the client sign-in path;
			// identity is then resolved by GetUserInfo via the Graph API, which validates it.
			AllowOpaqueToken: true,
		},
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" || o.ClientSecret == "" {
				return nil, errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
			}
			params := map[string]string{}
			if o.ConfigID != "" {
				params["config_id"] = o.ConfigID
			}
			for k, v := range p.AdditionalParams {
				params[k] = v
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "facebook", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: AuthorizationEndpoint, OverrideEndpoint: o.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, Scopes: o.BuildScopes(DefaultScopes, p.Scopes), LoginHint: p.LoginHint,
				AdditionalParams: params, AdditionalParamsOrder: append([]string{"config_id"}, p.AdditionalParamsOrder...),
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			// Facebook does not use PKCE: only the code and redirect URI are sent.
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, RedirectURI: redirect(o, p.RedirectURI), TokenEndpoint: TokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			if _, ok := profile["sub"]; ok {
				return oauth2.String(profile, "sub"), nil
			}
			return oauth2.String(profile, "id"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.IDToken != "" && len(strings.Split(p.IDToken, ".")) == 3 {
				profile, err := oauth2.DecodeJWTPayload(p.IDToken)
				if err != nil {
					return nil, err
				}
				// Limited Login id tokens carry no email_verified claim: default to false.
				return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
					Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
					Image: oauth2.String(profile, "picture"), EmailVerified: false,
				})
			}
			if p.AccessToken == "" {
				return nil, nil
			}
			tokenUserID := verifyAccessToken(ctx, p.AccessToken, o)
			if tokenUserID == "" {
				return nil, nil
			}
			fields := append(append([]string{}, DefaultFields...), o.Fields...)
			profile, err := oauth2.GetJSON(ctx, ProfileEndpoint+"?fields="+strings.Join(fields, ","), oauth2.BearerHeaders(p.AccessToken))
			if err != nil {
				return nil, nil
			}
			// Bind the validated token to the profile it returned.
			if id, ok := profile["id"].(string); !ok || id != tokenUserID {
				return nil, nil
			}
			image, _ := oauth2.Path(profile, "picture", "data", "url").(string)
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
				Image: image, EmailVerified: oauth2.Bool(profile, "email_verified"),
			})
		},
	})
}

// verifyAccessToken validates an opaque access token with the debug_token endpoint
// (verifyFacebookAccessToken). Graph access tokens are not audience-bound at /me, so the
// token must be valid, issued to one of the configured client ids and tied to a user. It
// returns the token's user_id, or "" when the token is not acceptable.
func verifyAccessToken(ctx context.Context, accessToken string, o Options) string {
	primary := o.PrimaryClientID()
	if primary == "" || o.ClientSecret == "" {
		return ""
	}
	q := "input_token=" + oauth2.FormEncode(accessToken) + "&access_token=" + oauth2.FormEncode(primary+"|"+o.ClientSecret)
	res, err := oauth2.GetJSON(ctx, DebugTokenEndpoint+"?"+q, nil)
	if err != nil {
		return ""
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return ""
	}
	valid, _ := data["is_valid"].(bool)
	appID, _ := data["app_id"].(string)
	userID, _ := data["user_id"].(string)
	if !valid || appID == "" || userID == "" {
		return ""
	}
	for _, id := range o.Audiences() {
		if id == appID {
			return userID
		}
	}
	return ""
}

func redirect(o Options, fallback string) string {
	if o.RedirectURI != "" {
		return o.RedirectURI
	}
	return fallback
}
