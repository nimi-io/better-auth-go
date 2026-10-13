// Package cognito implements the Amazon Cognito social provider (social-providers/cognito.ts).
package cognito

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "profile", "email"}

// Errors returned by the provider.
var (
	ErrDomainAndRegionRequired = errors.New("DOMAIN_AND_REGION_REQUIRED")
	ErrClientIDRequired        = errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
	ErrClientSecretRequired    = errors.New("CLIENT_SECRET_REQUIRED")
)

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// Domain is the Cognito domain, e.g. "your-app.auth.us-east-1.amazoncognito.com"
	// (an http(s):// prefix is stripped).
	Domain string
	// Region is the AWS region hosting the user pool, e.g. "us-east-1".
	Region     string
	UserPoolID string
	// RequireClientSecret makes ClientSecret mandatory for authorization requests.
	RequireClientSecret bool
	// IdentityProvider preselects a hosted-UI identity provider (identity_provider);
	// per-request additionalParams take precedence.
	IdentityProvider string
}

var schemePrefix = regexp.MustCompile(`^https?://`)

// CleanDomain returns the domain without its http(s):// prefix.
func (o Options) CleanDomain() string { return schemePrefix.ReplaceAllString(o.Domain, "") }

// AuthorizationEndpoint returns https://{domain}/oauth2/authorize.
func (o Options) AuthorizationEndpoint() string {
	return "https://" + o.CleanDomain() + "/oauth2/authorize"
}

// TokenEndpoint returns https://{domain}/oauth2/token.
func (o Options) TokenEndpoint() string { return "https://" + o.CleanDomain() + "/oauth2/token" }

// UserInfoEndpoint returns https://{domain}/oauth2/userinfo.
func (o Options) UserInfoEndpoint() string {
	return "https://" + o.CleanDomain() + "/oauth2/userinfo"
}

// Issuer returns https://cognito-idp.{region}.amazonaws.com/{userPoolId}.
func (o Options) Issuer() string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", o.Region, o.UserPoolID)
}

// JWKSEndpoint returns {issuer}/.well-known/jwks.json.
func (o Options) JWKSEndpoint() string { return o.Issuer() + "/.well-known/jwks.json" }

// TryNew creates the provider, returning the error upstream throws at construction.
func TryNew(o Options) (*oauth2.GenericProvider, error) {
	if o.Domain == "" || o.Region == "" || o.UserPoolID == "" {
		return nil, ErrDomainAndRegionRequired
	}
	tokenEndpoint := o.TokenEndpoint()
	idt := &oauth2.IDTokenConfig{JWKSURL: o.JWKSEndpoint(), Issuer: []string{o.Issuer()}, Audience: o.Audiences(), MaxTokenAge: time.Hour}
	return oauth2.NewProvider(oauth2.Spec{
		ID: "cognito", Name: "Cognito", Options: o.ProviderOptions, IDToken: idt,
		VerifyIDTokenFunc: verifyWithKid(idt),
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" {
				return nil, ErrClientIDRequired
			}
			if o.RequireClientSecret && o.ClientSecret == "" {
				return nil, ErrClientSecretRequired
			}
			params := map[string]string{}
			if o.IdentityProvider != "" {
				params["identity_provider"] = o.IdentityProvider
			}
			for k, v := range p.AdditionalParams {
				params[k] = v
			}
			u, err := oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "cognito", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: o.AuthorizationEndpoint(), OverrideEndpoint: o.ProviderOptions.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, CodeVerifier: p.CodeVerifier,
				Scopes: o.BuildScopes(DefaultScopes, p.Scopes), Prompt: o.Prompt,
				AdditionalParams: params, AdditionalParamsOrder: append([]string{"identity_provider"}, p.AdditionalParamsOrder...),
			})
			if err != nil {
				return nil, err
			}
			return moveScopeToEnd(u), nil
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			redirect := p.RedirectURI
			if o.RedirectURI != "" {
				redirect = o.RedirectURI
			}
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect,
				TokenEndpoint: tokenEndpoint, Client: o.Credentials(),
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, tokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "sub"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.IDToken != "" {
				// a token that cannot be decoded falls through to the userinfo endpoint
				if profile, err := oauth2.DecodeJWTPayload(p.IDToken); err == nil && profile != nil {
					profile["name"] = displayName(profile)
					return oauth2.BuildUserInfo(o.ProviderOptions, profile, toUser(profile))
				}
			}
			if p.AccessToken != "" {
				info, err := oauth2.GetJSON(ctx, o.UserInfoEndpoint(), oauth2.BearerHeaders(p.AccessToken))
				if err == nil && info != nil {
					return oauth2.BuildUserInfo(o.ProviderOptions, info, toUser(info))
				}
			}
			return nil, nil
		},
	}), nil
}

// New creates the Cognito provider. It panics when Domain, Region or UserPoolID is missing
// (upstream throws DOMAIN_AND_REGION_REQUIRED at construction); use TryNew to get the error.
func New(o Options) *oauth2.GenericProvider {
	p, err := TryNew(o)
	if err != nil {
		panic(err)
	}
	return p
}

// displayName is name || given_name || username || "".
func displayName(p map[string]any) string {
	for _, k := range []string{"name", "given_name", "username"} {
		if s := oauth2.String(p, k); s != "" {
			return s
		}
	}
	return ""
}

func toUser(p map[string]any) oauth2.UserInfo {
	return oauth2.UserInfo{
		Name: displayName(p), Email: oauth2.String(p, "email"), Image: oauth2.String(p, "picture"),
		EmailVerified: oauth2.Bool(p, "email_verified"),
	}
}

// moveScopeToEnd mirrors upstream: Cognito requires %20 rather than + in scope, so the
// scope parameter is removed and re-appended (encodeURIComponent) at the end of the query.
func moveScopeToEnd(u *url.URL) *url.URL {
	scope := u.Query().Get("scope")
	if scope == "" {
		return u
	}
	var kept []string
	for _, part := range strings.Split(u.RawQuery, "&") {
		k, _, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil && dk == "scope" {
			continue
		}
		if part != "" {
			kept = append(kept, part)
		}
	}
	kept = append(kept, "scope="+encodeURIComponent(scope))
	out := *u
	out.RawQuery = strings.Join(kept, "&")
	return &out
}

// encodeURIComponent escapes like JavaScript's encodeURIComponent; "'" is then
// percent-encoded as the WHATWG URL parser does for special-scheme queries.
func encodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			strings.IndexByte("-_.!~*()", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// verifyWithKid mirrors getCognitoPublicKey(header.kid!): a token without a kid never
// matches a key, and every failure resolves to false.
func verifyWithKid(cfg *oauth2.IDTokenConfig) func(ctx context.Context, token, nonce string) (bool, error) {
	return func(ctx context.Context, token, nonce string) (bool, error) {
		if strings.Count(token, ".") == 2 {
			h, err := jose.Header(token)
			if err != nil {
				return false, nil
			}
			v, _ := h.Get("kid")
			if kid, ok := v.(string); !ok || kid == "" {
				return false, nil
			}
		}
		ok, err := cfg.VerifyIDToken(ctx, token, nonce)
		if err != nil {
			return false, nil
		}
		return ok, nil
	}
}
