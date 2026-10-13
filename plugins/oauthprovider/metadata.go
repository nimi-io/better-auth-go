package oauthprovider

import (
	"net/http"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/metadata.ts.

// AuthServerMetadataOverrides are the authServerMetadata overrides.
type AuthServerMetadataOverrides struct {
	ScopesSupported                    []string
	DynamicClientRegistrationSupported bool
	PublicClientSupported              bool
	GrantTypesSupported                []string
	TokenEndpointAuthMethodsSupported  []string
	EndpointAuthMethodsSupported       []string
	JwtDisabled                        bool
	DPoPSigningAlgValuesSupported      []string
}

func strList(v []string) []any { return stringsToAny(v) }

// AuthServerMetadata builds the RFC 8414 document (authServerMetadata).
func AuthServerMetadata(ctx *betterauth.EndpointContext, jo *jwt.Options, ov AuthServerMetadataOverrides) *jsonx.Object {
	base := ctx.Auth.BaseURL
	backchannel := !ov.JwtDisabled
	m := jsonx.NewObject()
	if ov.ScopesSupported != nil {
		m.Set("scopes_supported", strList(ov.ScopesSupported))
	}
	iss := jwtIssuer(jo)
	if iss == "" {
		iss = base
	}
	m.Set("issuer", validateIssuerURL(iss))
	m.Set("authorization_endpoint", base+"/oauth2/authorize")
	m.Set("token_endpoint", base+"/oauth2/token")
	if !ov.JwtDisabled {
		switch {
		case jo != nil && jo.JWKS != nil && jo.JWKS.RemoteURL != "":
			m.Set("jwks_uri", jo.JWKS.RemoteURL)
		case jo != nil && jo.JWKS != nil && jo.JWKS.JWKSPath != "":
			m.Set("jwks_uri", base+jo.JWKS.JWKSPath)
		default:
			m.Set("jwks_uri", base+"/jwks")
		}
	}
	if ov.DynamicClientRegistrationSupported {
		m.Set("registration_endpoint", base+"/oauth2/register")
	}
	m.Set("introspection_endpoint", base+"/oauth2/introspect")
	m.Set("revocation_endpoint", base+"/oauth2/revoke")
	if ov.GrantTypesSupported != nil && !contains(ov.GrantTypesSupported, "authorization_code") {
		m.Set("response_types_supported", []any{})
	} else {
		m.Set("response_types_supported", []any{"code"})
	}
	m.Set("response_modes_supported", []any{"query"})
	grants := ov.GrantTypesSupported
	if grants == nil {
		grants = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	m.Set("grant_types_supported", strList(grants))
	tokenMethods := ov.TokenEndpointAuthMethodsSupported
	if tokenMethods == nil {
		if ov.PublicClientSupported {
			tokenMethods = append(tokenMethods, "none")
		}
		tokenMethods = append(tokenMethods, builtInConfidentialAuthMethods...)
	}
	m.Set("token_endpoint_auth_methods_supported", strList(tokenMethods))
	algs := strList(oauthcore.PrivateKeyJWTSigningAlgorithms)
	m.Set("token_endpoint_auth_signing_alg_values_supported", algs)
	endpointMethods := ov.EndpointAuthMethodsSupported
	if endpointMethods == nil {
		endpointMethods = builtInConfidentialAuthMethods
	}
	m.Set("introspection_endpoint_auth_methods_supported", strList(endpointMethods))
	m.Set("introspection_endpoint_auth_signing_alg_values_supported", strList(oauthcore.PrivateKeyJWTSigningAlgorithms))
	m.Set("revocation_endpoint_auth_methods_supported", strList(endpointMethods))
	m.Set("revocation_endpoint_auth_signing_alg_values_supported", strList(oauthcore.PrivateKeyJWTSigningAlgorithms))
	m.Set("code_challenge_methods_supported", []any{"S256"})
	m.Set("authorization_response_iss_parameter_supported", true)
	dpopAlgs := ov.DPoPSigningAlgValuesSupported
	if dpopAlgs == nil {
		dpopAlgs = oauthcore.DPoPSigningAlgorithms
	}
	m.Set("dpop_signing_alg_values_supported", strList(dpopAlgs))
	m.Set("backchannel_logout_supported", backchannel)
	m.Set("backchannel_logout_session_supported", backchannel)
	return m
}

func buildAuthServerMetadata(ctx *betterauth.EndpointContext, o *resolved) (*jwt.Options, []*ClientDiscovery, *jsonx.Object, error) {
	var jo *jwt.Options
	if !o.DisableJwtPlugin {
		var err error
		jo, err = jwtOptions(ctx.Auth)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	ds := o.clientDiscoveries()
	public := o.AllowUnauthenticatedClientRegistration || len(ds) > 0
	scopes := o.Scopes
	if o.AdvertisedMetadata != nil && o.AdvertisedMetadata.ScopesSupported != nil {
		scopes = o.AdvertisedMetadata.ScopesSupported
	}
	ov := AuthServerMetadataOverrides{
		ScopesSupported:                    scopes,
		DynamicClientRegistrationSupported: o.AllowDynamicClientRegistration,
		PublicClientSupported:              public,
		GrantTypesSupported:                o.supportedGrantTypes(),
		TokenEndpointAuthMethodsSupported:  o.supportedAuthMethods(public),
		EndpointAuthMethodsSupported:       o.supportedAuthMethods(false),
		JwtDisabled:                        o.DisableJwtPlugin,
	}
	if o.DPoP != nil {
		ov.DPoPSigningAlgValuesSupported = o.DPoP.SigningAlgorithms
	}
	return jo, ds, AuthServerMetadata(ctx, jo, ov), nil
}

func spread(a, b *jsonx.Object) *jsonx.Object {
	out := a.Clone()
	mergeInto(out, b)
	return out
}

// oauthAuthorizationServerMetadata is the /.well-known/oauth-authorization-server document
// for OAuth-only deployments.
func oauthAuthorizationServerMetadata(ctx *betterauth.EndpointContext, o *resolved) (*jsonx.Object, error) {
	_, ds, m, err := buildAuthServerMetadata(ctx, o)
	if err != nil {
		return nil, err
	}
	return o.applyMetadataExtensions(ctx, "oauth-authorization-server", spread(mergeDiscoveryMetadata(ds), m)), nil
}

// oidcServerMetadata is the OpenID Provider metadata document.
func oidcServerMetadata(ctx *betterauth.EndpointContext, o *resolved) (*jsonx.Object, error) {
	base := ctx.Auth.BaseURL
	jo, ds, auth, err := buildAuthServerMetadata(ctx, o)
	if err != nil {
		return nil, err
	}
	m := auth.Clone()
	m.Set("claims_supported", strList(nonNil(o.supportedClaims())))
	m.Set("claims_parameter_supported", true)
	m.Set("userinfo_endpoint", base+"/oauth2/userinfo")
	if o.PairwiseSecret != "" {
		m.Set("subject_types_supported", []any{"public", "pairwise"})
	} else {
		m.Set("subject_types_supported", []any{"public"})
	}
	m.Set("acr_values_supported", []any{level0ACR})
	var idAlgs []string
	if o.DisableJwtPlugin {
		idAlgs = []string{"HS256"}
	} else {
		primary := "EdDSA"
		if jo != nil && jo.JWKS != nil && jo.JWKS.KeyPairConfig != nil && jo.JWKS.KeyPairConfig.Alg != "" {
			primary = jo.JWKS.KeyPairConfig.Alg
		}
		idAlgs = []string{primary}
		if jo != nil && jo.JWKS != nil {
			for _, c := range jo.JWKS.KeyPairConfigs {
				idAlgs = append(idAlgs, c.Alg)
			}
		}
		idAlgs = uniqueStrings(idAlgs)
	}
	m.Set("id_token_signing_alg_values_supported", strList(idAlgs))
	m.Set("end_session_endpoint", base+"/oauth2/end-session")
	m.Set("request_parameter_supported", false)
	m.Set("request_uri_parameter_supported", false)
	m.Set("prompt_values_supported", []any{"login", "consent", "create", "select_account", "none"})
	return o.applyMetadataExtensions(ctx, "openid-configuration", spread(mergeDiscoveryMetadata(ds), m)), nil
}

const metadataCacheControl = "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"

// MetadataResponse renders a discovery document with the default caching headers
// (metadataResponse). extra headers are applied first; Cache-Control is only set when
// absent.
func MetadataResponse(body any, extra http.Header) *betterauth.Response {
	h := http.Header{}
	for k, vs := range extra {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	if h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", metadataCacheControl)
	}
	h.Set("Content-Type", "application/json")
	b, _ := jsonx.Marshal(body)
	return &betterauth.Response{Status: 200, Header: h, Body: b}
}

// OAuthProviderAuthServerMetadata returns a handler serving the authorization server
// metadata (auth.api.getOAuthServerConfig) for an incoming request, for mounting at the
// root /.well-known/oauth-authorization-server (oauthProviderAuthServerMetadata). The
// base URL is resolved from the request (dynamic baseURL). headers are added to the
// response.
func OAuthProviderAuthServerMetadata(auth *betterauth.Auth, headers http.Header) func(*http.Request) (*betterauth.Response, error) {
	return metadataWrapper(auth, "getOAuthServerConfig", headers)
}

// OAuthProviderOpenIDConfigMetadata is OAuthProviderAuthServerMetadata for the OpenID
// configuration (oauthProviderOpenIdConfigMetadata).
func OAuthProviderOpenIDConfigMetadata(auth *betterauth.Auth, headers http.Header) func(*http.Request) (*betterauth.Response, error) {
	return metadataWrapper(auth, "getOpenIdConfig", headers)
}

func metadataWrapper(auth *betterauth.Auth, key string, headers http.Header) func(*http.Request) (*betterauth.Response, error) {
	return func(r *http.Request) (*betterauth.Response, error) {
		res, err := auth.API.Call(r.Context(), key, betterauth.CallInput{Request: r})
		if err != nil {
			return nil, err
		}
		body := res.Data
		if raw, ok := body.(*betterauth.Response); ok {
			v, perr := jsonx.Parse(raw.Body)
			if perr != nil {
				return nil, perr
			}
			body = v
		}
		return MetadataResponse(body, headers), nil
	}
}
