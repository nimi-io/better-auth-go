package genericoauth

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/nimi-io/better-auth-go/oauth2"
)

// BaseOptions are the options shared by the pre-built provider helpers
// (BaseOAuthProviderOptions).
type BaseOptions struct {
	ClientID              string
	ClientSecret          string
	TokenEndpointAuth     *oauth2.TokenEndpointAuth
	Scopes                []string
	RedirectURI           string
	EndSessionEndpoint    string
	PostLogoutRedirectURI string
	DisableProviderLogout bool
	PKCE                  *bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
	OverrideUserInfo      bool
}

func (o BaseOptions) config(providerID string, defaultScopes []string) Config {
	scopes := o.Scopes
	if scopes == nil {
		scopes = defaultScopes
	}
	return Config{
		ProviderID: providerID, ClientID: o.ClientID, ClientSecret: o.ClientSecret,
		TokenEndpointAuth: o.TokenEndpointAuth, Scopes: scopes, RedirectURI: o.RedirectURI,
		EndSessionEndpoint: o.EndSessionEndpoint, PostLogoutRedirectURI: o.PostLogoutRedirectURI,
		DisableProviderLogout: o.DisableProviderLogout, PKCE: o.PKCE,
		DisableImplicitSignUp: o.DisableImplicitSignUp, DisableSignUp: o.DisableSignUp,
		OverrideUserInfo: o.OverrideUserInfo,
	}
}

var oidcScopes = []string{"openid", "profile", "email"}

func subjectFrom(key string) func(context.Context, *oauth2.Tokens, map[string]any) (any, error) {
	return func(_ context.Context, _ *oauth2.Tokens, profile map[string]any) (any, error) {
		if v := profile[key]; v != nil {
			return v, nil
		}
		return "", nil
	}
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// Auth0Options configure Auth0.
type Auth0Options struct {
	BaseOptions
	// Domain is the Auth0 domain, with or without scheme.
	Domain string
}

// Auth0 returns the Auth0 provider config (auth0).
func Auth0(o Auth0Options) Config {
	domainURL := o.Domain
	if !strings.HasPrefix(domainURL, "http://") && !strings.HasPrefix(domainURL, "https://") {
		domainURL = "https://" + domainURL
	}
	host := ""
	if u, err := url.Parse(domainURL); err == nil {
		host = u.Host
	}
	c := o.config("auth0", oidcScopes)
	c.DiscoveryURL = "https://" + host + "/.well-known/openid-configuration"
	return c
}

// OktaOptions configure Okta.
type OktaOptions struct {
	BaseOptions
	Issuer string
}

// Okta returns the Okta provider config (okta).
func Okta(o OktaOptions) Config {
	c := o.config("okta", oidcScopes)
	c.DiscoveryURL = strings.TrimSuffix(o.Issuer, "/") + "/.well-known/openid-configuration"
	return c
}

// KeycloakOptions configure Keycloak.
type KeycloakOptions struct {
	BaseOptions
	Issuer string
}

// Keycloak returns the Keycloak provider config (keycloak).
func Keycloak(o KeycloakOptions) Config {
	c := o.config("keycloak", oidcScopes)
	c.DiscoveryURL = strings.TrimSuffix(o.Issuer, "/") + "/.well-known/openid-configuration"
	return c
}

// SlackOptions configure Slack.
type SlackOptions struct{ BaseOptions }

// Slack returns the Slack (OpenID Connect) provider config (slack).
func Slack(o SlackOptions) Config {
	c := o.config("slack", oidcScopes)
	c.AccountSubject = subjectFrom("sub")
	c.AuthorizationURL = "https://slack.com/openid/connect/authorize"
	c.TokenURL = "https://slack.com/api/openid.connect.token"
	c.UserInfoURL = "https://slack.com/api/openid.connect.userInfo"
	c.GetUserInfo = func(ctx context.Context, t *oauth2.Tokens) (map[string]any, error) {
		profile, err := oauth2.GetJSON(ctx, "https://slack.com/api/openid.connect.userInfo", bearer(t.AccessToken))
		if err != nil || profile == nil {
			return nil, nil
		}
		out := map[string]any{"sub": profile["sub"], "name": profile["name"], "email": profile["email"]}
		if v := profile["picture"]; v != nil {
			out["image"] = v
		} else {
			out["image"] = profile["https://slack.com/user_image_512"]
		}
		if v := profile["email_verified"]; v != nil {
			out["emailVerified"] = v
		} else {
			out["emailVerified"] = false
		}
		return dropNil(out), nil
	}
	return c
}

// LineOptions configure LINE.
type LineOptions struct {
	BaseOptions
	// ProviderID defaults to "line" (use distinct ids for multiple LINE channels).
	ProviderID string
}

// Line returns the LINE provider config (line).
func Line(o LineOptions) Config {
	id := o.ProviderID
	if id == "" {
		id = "line"
	}
	const userInfoURL = "https://api.line.me/oauth2/v2.1/userinfo"
	c := o.config(id, oidcScopes)
	c.AccountSubject = subjectFrom("sub")
	c.AuthorizationURL = "https://access.line.me/oauth2/v2.1/authorize"
	c.TokenURL = "https://api.line.me/oauth2/v2.1/token"
	c.UserInfoURL = userInfoURL
	c.GetUserInfo = func(ctx context.Context, t *oauth2.Tokens) (map[string]any, error) {
		var profile map[string]any
		if t.IDToken != "" {
			if p, err := oauth2.DecodeJWTPayload(t.IDToken); err == nil {
				profile = p
			}
		}
		if profile == nil {
			data, err := oauth2.GetJSON(ctx, userInfoURL, bearer(t.AccessToken))
			if err != nil || data == nil {
				return nil, nil
			}
			profile = data
		}
		return dropNil(map[string]any{"sub": profile["sub"], "name": profile["name"], "email": profile["email"],
			"image": profile["picture"], "emailVerified": false}), nil
	}
	return c
}

// GumroadOptions configure Gumroad.
type GumroadOptions struct{ BaseOptions }

// Gumroad returns the Gumroad provider config (gumroad).
func Gumroad(o GumroadOptions) Config {
	c := o.config("gumroad", []string{"view_profile"})
	c.AccountSubject = subjectFrom("id")
	c.AuthorizationURL = "https://gumroad.com/oauth/authorize"
	c.TokenURL = "https://api.gumroad.com/oauth/token"
	c.GetUserInfo = func(ctx context.Context, t *oauth2.Tokens) (map[string]any, error) {
		profile, err := oauth2.GetJSON(ctx, "https://api.gumroad.com/v2/user", bearer(t.AccessToken))
		if err != nil || profile == nil || !truthy(profile["success"]) {
			return nil, nil
		}
		user, ok := profile["user"].(map[string]any)
		if !ok {
			return nil, nil
		}
		return dropNil(map[string]any{"id": user["user_id"], "name": user["name"], "email": user["email"],
			"image": user["profile_url"], "emailVerified": false}), nil
	}
	return c
}

// PatreonOptions configure Patreon.
type PatreonOptions struct{ BaseOptions }

// Patreon returns the Patreon provider config (patreon).
func Patreon(o PatreonOptions) Config {
	c := o.config("patreon", []string{"identity[email]"})
	c.AccountSubject = subjectFrom("id")
	c.AuthorizationURL = "https://www.patreon.com/oauth2/authorize"
	c.TokenURL = "https://www.patreon.com/api/oauth2/token"
	c.GetUserInfo = func(ctx context.Context, t *oauth2.Tokens) (map[string]any, error) {
		profile, err := oauth2.GetJSON(ctx, "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified", bearer(t.AccessToken))
		if err != nil || profile == nil {
			return nil, nil
		}
		attrs, _ := oauth2.Path(profile, "data", "attributes").(map[string]any)
		return dropNil(map[string]any{"id": oauth2.Path(profile, "data", "id"), "name": attrs["full_name"],
			"email": attrs["email"], "image": attrs["image_url"], "emailVerified": attrs["is_email_verified"]}), nil
	}
	return c
}

// HubSpotOptions configure HubSpot.
type HubSpotOptions struct{ BaseOptions }

// HubSpot returns the HubSpot provider config (hubspot).
func HubSpot(o HubSpotOptions) Config {
	c := o.config("hubspot", []string{"oauth"})
	c.AccountSubject = subjectFrom("id")
	c.AuthorizationURL = "https://app.hubspot.com/oauth/authorize"
	c.TokenURL = "https://api.hubapi.com/oauth/v1/token"
	c.Authentication = "post"
	c.GetUserInfo = func(ctx context.Context, t *oauth2.Tokens) (map[string]any, error) {
		profile, err := oauth2.GetJSON(ctx, "https://api.hubapi.com/oauth/v1/access-tokens/"+t.AccessToken,
			map[string]string{"Content-Type": "application/json"})
		if err != nil || profile == nil {
			return nil, nil
		}
		id := profile["user_id"]
		if id == nil {
			id = oauth2.Path(profile, "signed_access_token", "userId")
		}
		if !truthy(id) {
			return nil, nil
		}
		return dropNil(map[string]any{"id": id, "name": profile["user"], "email": profile["user"], "emailVerified": false}), nil
	}
	return c
}

// YandexOptions configure Yandex.
type YandexOptions struct{ BaseOptions }

// Yandex returns the Yandex provider config (yandex).
func Yandex(o YandexOptions) Config {
	c := o.config("yandex", []string{"login:info", "login:email", "login:avatar"})
	c.AccountSubject = subjectFrom("id")
	c.AuthorizationURL = "https://oauth.yandex.com/authorize"
	c.TokenURL = "https://oauth.yandex.com/token"
	c.GetUserInfo = func(ctx context.Context, t *oauth2.Tokens) (map[string]any, error) {
		profile, err := oauth2.GetJSON(ctx, "https://login.yandex.ru/info?format=json",
			map[string]string{"Authorization": "OAuth " + t.AccessToken})
		if err != nil || profile == nil {
			return nil, nil
		}
		email := profile["default_email"]
		if email == nil {
			if arr, ok := profile["emails"].([]any); ok && len(arr) > 0 {
				email = arr[0]
			}
		}
		if !truthy(email) {
			return nil, nil
		}
		name := firstNonNil(profile["display_name"], profile["real_name"], profile["first_name"], profile["login"])
		out := map[string]any{"id": profile["id"], "name": name, "email": email, "emailVerified": false}
		if !truthy(profile["is_avatar_empty"]) && truthy(profile["default_avatar_id"]) {
			out["image"] = "https://avatars.yandex.net/get-yapic/" + optString(profile["default_avatar_id"]) + "/islands-200"
		}
		return dropNil(out), nil
	}
	return c
}

// MicrosoftEntraIDOptions configure Microsoft Entra ID.
type MicrosoftEntraIDOptions struct {
	BaseOptions
	// TenantID must be a concrete tenant GUID.
	TenantID string
}

var tenantGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrMicrosoftTenantRequired is returned for a missing or multi-tenant tenant id.
var ErrMicrosoftTenantRequired = errors.New("The generic microsoftEntraId helper requires a concrete Microsoft Entra tenant GUID. Use the built-in Microsoft provider for common, organizations, or consumers.")

func microsoftProfileName(p map[string]any) any {
	if v := p["name"]; v != nil {
		return v
	}
	given := firstNonNil(p["given_name"], p["givenname"])
	family := firstNonNil(p["family_name"], p["familyname"])
	s := strings.TrimSpace(optString(given) + " " + optString(family))
	if s == "" {
		return nil
	}
	return s
}

// MicrosoftEntraID returns the Microsoft Entra ID provider config (microsoftEntraId). The
// account id is the token "oid" claim.
func MicrosoftEntraID(o MicrosoftEntraIDOptions) (Config, error) {
	tenant := strings.ToLower(o.TenantID)
	if !tenantGUID.MatchString(tenant) {
		return Config{}, ErrMicrosoftTenantRequired
	}
	const userInfoURL = "https://graph.microsoft.com/oidc/userinfo"
	c := o.config("microsoft-entra-id", oidcScopes)
	c.AccountSubject = func(_ context.Context, _ *oauth2.Tokens, profile map[string]any) (any, error) {
		if s, ok := profile["oid"].(string); ok {
			return s, nil
		}
		return "", nil
	}
	c.DiscoveryURL = "https://login.microsoftonline.com/" + tenant + "/v2.0/.well-known/openid-configuration"
	c.RequireIDTokenVerification = true
	c.AuthorizationURL = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize"
	c.TokenURL = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
	c.UserInfoURL = userInfoURL
	c.GetUserInfo = func(ctx context.Context, t *oauth2.Tokens) (map[string]any, error) {
		if t.IDToken == "" {
			return nil, nil
		}
		token, err := oauth2.DecodeJWTPayload(t.IDToken)
		if err != nil {
			return nil, nil
		}
		oid, _ := token["oid"].(string)
		if strings.TrimSpace(oid) == "" {
			return nil, nil
		}
		placeholder := func() any {
			e, err := oauth2.PlaceholderEmail(oid, "microsoft-entra-id")
			if err != nil {
				return nil
			}
			return e
		}
		tokenInfo := map[string]any{}
		for k, v := range token {
			tokenInfo[k] = v
		}
		tokenInfo["name"] = microsoftProfileName(token)
		if e := token["email"]; e != nil {
			tokenInfo["email"] = e
			tokenInfo["emailVerified"] = token["email_verified"]
			if tokenInfo["emailVerified"] == nil {
				tokenInfo["emailVerified"] = false
			}
			if !truthy(e) {
				tokenInfo["emailVerified"] = false
			}
		} else {
			tokenInfo["email"] = placeholder()
			tokenInfo["emailVerified"] = false
		}
		tokenInfo["image"] = token["picture"]
		tokenInfo = dropNil(tokenInfo)
		if t.AccessToken == "" {
			return tokenInfo, nil
		}
		profile, err := oauth2.GetJSON(ctx, userInfoURL, bearer(t.AccessToken))
		if err != nil || profile == nil {
			return tokenInfo, nil
		}
		sub, ok := token["sub"].(string)
		if ps, _ := profile["sub"].(string); !ok || profile["sub"] == nil || ps != sub {
			return tokenInfo, nil
		}
		out := map[string]any{}
		for k, v := range profile {
			out[k] = v
		}
		for k, v := range token {
			out[k] = v
		}
		name := microsoftProfileName(token)
		if name == nil {
			name = microsoftProfileName(profile)
		}
		out["name"] = name
		emailClaim := firstNonNil(token["email"], profile["email"])
		if emailClaim != nil {
			out["email"] = emailClaim
			out["emailVerified"] = firstNonNil(token["email_verified"], profile["email_verified"], false)
		} else {
			out["email"] = placeholder()
			out["emailVerified"] = false
		}
		out["image"] = firstNonNil(token["picture"], profile["picture"])
		return dropNil(out), nil
	}
	return c, nil
}

func firstNonNil(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

// dropNil removes nil values (JavaScript undefined disappears from the JSON profile).
func dropNil(m map[string]any) map[string]any {
	for k, v := range m {
		if v == nil {
			delete(m, k)
		}
	}
	return m
}
