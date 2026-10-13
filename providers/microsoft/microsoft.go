// Package microsoft implements the Microsoft Entra ID social provider
// (social-providers/microsoft-entra-id.ts).
package microsoft

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Defaults used by the provider.
const (
	DefaultAuthority = "https://login.microsoftonline.com"
	DefaultTenant    = "common"
	// GraphPhotoEndpoint is formatted with the photo size twice.
	GraphPhotoEndpoint = "https://graph.microsoft.com/v1.0/me/photos/%dx%d/$value"
	// ConsumerTenantID is Microsoft's fixed tenant id for personal accounts.
	ConsumerTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"
)

// DefaultScopes are requested unless DisableDefaultScope is set.
var DefaultScopes = []string{"openid", "profile", "email", "User.Read", "offline_access"}

// ErrClientAssertionWithSecret is returned when ClientAssertion and ClientSecret are both set.
var ErrClientAssertionWithSecret = errors.New("Microsoft Entra ID clientAssertion cannot be combined with clientSecret")

// Options configure the provider.
type Options struct {
	oauth2.ProviderOptions
	// TenantID defaults to "common" ("organizations", "consumers" or a tenant id).
	TenantID string
	// Authority defaults to https://login.microsoftonline.com (https://<tenant>.ciamlogin.com for CIAM).
	Authority string
	// ClientAssertion returns a JWT client assertion (private_key_jwt) used instead of ClientSecret.
	ClientAssertion func(clientID, tokenEndpoint, grantType string) (string, error)
	// ProfilePhotoSize is 48 (default), 64, 96, 120, 240, 360, 432, 504 or 648.
	ProfilePhotoSize int
	// DisableProfilePhoto skips the Graph profile photo request.
	DisableProfilePhoto bool
}

// Tenant returns the configured tenant ("common" by default).
func (o Options) Tenant() string {
	if o.TenantID != "" {
		return o.TenantID
	}
	return DefaultTenant
}

// AuthorityURL returns the authority with any trailing slashes removed.
func (o Options) AuthorityURL() string {
	a := o.Authority
	if a == "" {
		a = DefaultAuthority
	}
	return strings.TrimRight(a, "/")
}

// AuthorizationEndpoint returns {authority}/{tenant}/oauth2/v2.0/authorize.
func (o Options) AuthorizationEndpoint() string {
	return o.AuthorityURL() + "/" + o.Tenant() + "/oauth2/v2.0/authorize"
}

// TokenEndpoint returns {authority}/{tenant}/oauth2/v2.0/token.
func (o Options) TokenEndpoint() string {
	return o.AuthorityURL() + "/" + o.Tenant() + "/oauth2/v2.0/token"
}

// JWKSEndpoint returns {authority}/{tenant}/discovery/v2.0/keys.
func (o Options) JWKSEndpoint() string {
	return o.AuthorityURL() + "/" + o.Tenant() + "/discovery/v2.0/keys"
}

// TryNew creates the provider, returning the error upstream throws at construction.
func TryNew(o Options) (*oauth2.GenericProvider, error) {
	if o.ClientSecret != "" && o.ClientAssertion != nil {
		return nil, ErrClientAssertionWithSecret
	}
	tenant := o.Tenant()
	authority := o.AuthorityURL()
	tokenEndpoint := o.TokenEndpoint()
	var tokenAuth *oauth2.TokenEndpointAuth
	if o.ClientAssertion != nil {
		tokenAuth = &oauth2.TokenEndpointAuth{Method: oauth2.AuthPrivateKeyJWT, GetClientAssertion: o.ClientAssertion}
	}
	idt := &oauth2.IDTokenConfig{
		JWKSURL: o.JWKSEndpoint(), Audience: o.Audiences(), MaxTokenAge: time.Hour,
		VerifyClaims: func(c *jsonx.Object) bool {
			tidV, _ := c.Get("tid")
			tid, ok := tidV.(string)
			if !ok {
				return false
			}
			issV, _ := c.Get("iss")
			if iss, _ := issV.(string); iss != authority+"/"+tid+"/v2.0" {
				return false
			}
			if tenant == "organizations" && tid == ConsumerTenantID {
				return false
			}
			if tenant == "consumers" && tid != ConsumerTenantID {
				return false
			}
			return true
		},
	}
	// The issuer varies per tenant on the multi-tenant endpoints; only pin it for a
	// specific tenant.
	if tenant != "common" && tenant != "organizations" && tenant != "consumers" {
		idt.Issuer = []string{authority + "/" + tenant + "/v2.0"}
	}
	return oauth2.NewProvider(oauth2.Spec{
		ID: "microsoft", Name: "Microsoft EntraID", Options: o.ProviderOptions, IDToken: idt,
		VerifyIDTokenFunc: verifyWithKid(idt),
		AuthorizationURL: func(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
			// public clients (PKCE only) are supported, so clientSecret is not required
			if o.PrimaryClientID() == "" {
				return nil, errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
			}
			return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
				ID: "microsoft", ClientID: o.PrimaryClientID(),
				AuthorizationEndpoint: o.AuthorizationEndpoint(), OverrideEndpoint: o.ProviderOptions.AuthorizationEndpoint,
				RedirectURI: p.RedirectURI, OverrideRedirectURI: o.RedirectURI,
				State: p.State, CodeVerifier: p.CodeVerifier,
				Scopes: o.BuildScopes(DefaultScopes, p.Scopes),
				Prompt: o.Prompt, LoginHint: p.LoginHint,
				AdditionalParams: p.AdditionalParams, AdditionalParamsOrder: p.AdditionalParamsOrder,
			})
		},
		ExchangeCode: func(ctx context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
			redirect := p.RedirectURI
			if o.RedirectURI != "" {
				redirect = o.RedirectURI
			}
			return oauth2.ValidateAuthorizationCode(ctx, oauth2.CodeExchange{
				Code: p.Code, CodeVerifier: p.CodeVerifier, RedirectURI: redirect,
				TokenEndpoint: tokenEndpoint, Client: o.Credentials(), TokenEndpointAuth: tokenAuth,
			})
		},
		Refresh: func(ctx context.Context, rt string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
			scopes := o.BuildScopes(DefaultScopes, nil)
			return oauth2.RefreshAccessToken(ctx, oauth2.RefreshRequest{
				RefreshToken: rt, TokenEndpoint: tokenEndpoint,
				Client:            oauth2.ClientCredentials{ClientID: o.PrimaryClientID(), ClientSecret: o.ClientSecret},
				TokenEndpointAuth: tokenAuth,
				ExtraParams:       map[string]string{"scope": strings.Join(scopes, " ")},
			})
		},
		Subject: func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "oid"), nil
		},
		UserInfo: func(ctx context.Context, p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
			if p.IDToken == "" {
				return nil, nil
			}
			user, err := oauth2.DecodeJWTPayload(p.IDToken)
			if err != nil {
				return nil, err
			}
			if oid, ok := user["oid"].(string); !ok || strings.TrimSpace(oid) == "" {
				// no stable account identifier
				return nil, nil
			}
			size := o.ProfilePhotoSize
			if size == 0 {
				size = 48
			}
			if !o.DisableProfilePhoto && p.AccessToken != "" {
				if pic, ok := fetchPhoto(ctx, fmt.Sprintf(GraphPhotoEndpoint, size, size), p.AccessToken); ok {
					user["picture"] = pic
				}
			}
			return oauth2.BuildUserInfo(o.ProviderOptions, user, oauth2.UserInfo{
				Name: oauth2.String(user, "name"), Email: oauth2.String(user, "email"),
				Image: oauth2.String(user, "picture"), EmailVerified: emailVerified(user),
			})
		},
	}), nil
}

// New creates the Microsoft Entra ID provider. It panics when the options are invalid
// (upstream throws at construction); use TryNew to get the error instead.
func New(o Options) *oauth2.GenericProvider {
	p, err := TryNew(o)
	if err != nil {
		panic(err)
	}
	return p
}

// emailVerified mirrors upstream: the optional email_verified claim when present, else
// whether the email appears in verified_primary_email / verified_secondary_email.
func emailVerified(user map[string]any) bool {
	if _, ok := user["email_verified"]; ok {
		return oauth2.Bool(user, "email_verified")
	}
	email := oauth2.String(user, "email")
	if email == "" {
		return false
	}
	return containsString(user["verified_primary_email"], email) || containsString(user["verified_secondary_email"], email)
}

func containsString(list any, s string) bool {
	switch t := list.(type) {
	case []any:
		for _, v := range t {
			if v == s {
				return true
			}
		}
	case string: // String.prototype.includes
		return strings.Contains(t, s)
	}
	return false
}

// fetchPhoto downloads the Graph profile photo as a data URL. Failures are ignored.
func fetchPhoto(ctx context.Context, endpoint, accessToken string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := oauth2.HTTPClient.Do(req)
	if err != nil {
		return "", false
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 10<<20))
	if err != nil {
		return "", false
	}
	return "data:image/jpeg;base64, " + base64.StdEncoding.EncodeToString(b), true
}

// verifyWithKid mirrors getMicrosoftPublicKey(header.kid!): a token without a kid never
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
