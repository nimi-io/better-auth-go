// Package google implements the Google social provider (social-providers/google.ts).
package google

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Endpoints used by the provider.
const (
	AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenEndpoint         = "https://oauth2.googleapis.com/token"
	JWKSEndpoint          = "https://www.googleapis.com/oauth2/v3/certs"
)

// Issuers accepted in Google id tokens.
var Issuers = []string{"https://accounts.google.com", "accounts.google.com"}

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// AccessType is "offline" or "online".
	AccessType string
	// Display is "page", "popup", "touch" or "wap".
	Display string
	// HD restricts sign-in to a hosted domain ("*" accepts any hosted domain).
	HD string
	// IncludeGrantedScopes defaults to true.
	IncludeGrantedScopes *bool
}

// HostedDomainAllowed mirrors isGoogleHostedDomainAllowed.
func HostedDomainAllowed(configured string, tokenHD any) bool {
	if configured == "" {
		return true
	}
	s, ok := tokenHD.(string)
	if !ok || s == "" {
		return false
	}
	return configured == "*" || s == configured
}

// New creates the Google provider.
func New(o Options) *oauth2.GenericProvider {
	idt := &oauth2.IDTokenConfig{JWKSURL: JWKSEndpoint, Issuer: Issuers, Audience: o.Audiences(),
		Algorithms: []string{"RS256"}, MaxTokenAge: time.Hour}
	if o.HD != "" {
		idt.VerifyClaims = func(c *jsonx.Object) bool {
			v, _ := c.Get("hd")
			return HostedDomainAllowed(o.HD, v)
		}
	}
	return oauth2.NewProvider(oauth2.Spec{
		ID: "google", Name: "Google", Options: o.ProviderOptions, IDToken: idt,
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			if o.PrimaryClientID() == "" || o.ClientSecret == "" {
				return nil, errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
			}
			if p.CodeVerifier == "" {
				return nil, errors.New("codeVerifier is required for Google")
			}
			extra := map[string]string{}
			if o.IncludeGrantedScopes == nil || *o.IncludeGrantedScopes {
				extra["include_granted_scopes"] = "true"
			}
			display := p.Display
			if display == "" {
				display = o.Display
			}
			return oauth2.StandardAuthorizationURL(o.ProviderOptions, AuthorizationEndpoint, []string{"email", "profile", "openid"}, p,
				oauth2.AuthorizationURLOptions{AccessType: o.AccessType, Display: display, HD: o.HD, AdditionalParams: extra})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			return oauth2.StandardExchange(ctx, o.ProviderOptions, TokenEndpoint, p, oauth2.CodeExchange{})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			return oauth2.StandardRefresh(ctx, o.ProviderOptions, TokenEndpoint, rt, oauth2.RefreshRequest{})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "sub"), nil
		},
		UserInfo: func(_ context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.IDToken == "" {
				return nil, nil
			}
			profile, err := oauth2.DecodeJWTPayload(p.IDToken)
			if err != nil {
				return nil, err
			}
			if !HostedDomainAllowed(o.HD, profile["hd"]) {
				return nil, nil
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, profile, oauth2.UserInfo{
				Name: oauth2.String(profile, "name"), Email: oauth2.String(profile, "email"),
				Image: oauth2.String(profile, "picture"), EmailVerified: oauth2.Bool(profile, "email_verified"),
			})
		},
	})
}
