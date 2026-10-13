package oauthprovider

import (
	"context"
	"errors"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/client-resource.ts (oauthProviderResourceClient):
// helpers for resource servers that accept tokens issued by this provider.

// ResourceClient verifies access tokens and builds protected resource metadata. Auth may
// be nil (then verify options must be complete).
type ResourceClient struct {
	Auth *betterauth.Auth
}

// NewResourceClient is oauthProviderResourceClient(auth).
func NewResourceClient(auth *betterauth.Auth) *ResourceClient { return &ResourceClient{Auth: auth} }

// ResourceVerifyOptions are the verify options of the resource client actions.
type ResourceVerifyOptions struct {
	// Audience / Issuer default to the auth server base URL (and jwt issuer).
	Audience                 []string
	Issuer                   []string
	Extra                    oauthcore.VerifyOptions
	RequiredScopes           []string
	IsScopeSatisfied         func(required string, granted map[string]bool) bool
	JWKSURL                  string
	RemoteVerify             *oauthcore.RemoteVerify
	ResourceMetadataMappings map[string]string
	DPoP                     *oauthcore.DPoPVerifyOptions
}

func (rc *ResourceClient) context() (*betterauth.AuthContext, *resolved) {
	if rc == nil || rc.Auth == nil {
		return nil, nil
	}
	ac := rc.Auth.Context()
	o, _ := pluginOptions(ac)
	return ac, o
}

func (rc *ResourceClient) baseURL() string {
	if rc == nil || rc.Auth == nil {
		return ""
	}
	ac := rc.Auth.Context()
	return ac.Options.BaseURL
}

func (rc *ResourceClient) resolve(opts ResourceVerifyOptions) (oauthcore.VerifyAccessTokenRequestOptions, error) {
	ac, o := rc.context()
	base := rc.baseURL()
	basePath := ""
	issuerOpt := ""
	jwksPath := "/jwks"
	remoteURL := ""
	if ac != nil {
		basePath = ac.Options.BasePath
		if o != nil && !o.DisableJwtPlugin {
			if jo, err := jwtOptions(ac); err == nil {
				issuerOpt = jwtIssuer(jo)
				if jo.JWKS != nil {
					if jo.JWKS.JWKSPath != "" {
						jwksPath = jo.JWKS.JWKSPath
					}
					remoteURL = jo.JWKS.RemoteURL
				}
			}
		}
	}
	vo := opts.Extra
	vo.Audience = opts.Audience
	if vo.Audience == nil && base != "" {
		vo.Audience = []string{base}
	}
	vo.Issuer = opts.Issuer
	if vo.Issuer == nil {
		switch {
		case issuerOpt != "":
			vo.Issuer = []string{issuerOpt}
		case base != "":
			vo.Issuer = []string{base}
		}
	}
	if vo.Audience == nil {
		return oauthcore.VerifyAccessTokenRequestOptions{}, errors.New("please define opts.verifyOptions.audience")
	}
	if vo.Issuer == nil {
		return oauthcore.VerifyAccessTokenRequestOptions{}, errors.New("please define opts.verifyOptions.issuer")
	}
	jwksURL := opts.JWKSURL
	if jwksURL == "" {
		jwksURL = remoteURL
	}
	if jwksURL == "" && base != "" {
		jwksURL = base + basePath + jwksPath
	}
	var remote *oauthcore.RemoteVerify
	if opts.RemoteVerify != nil {
		introspect := opts.RemoteVerify.IntrospectURL
		if introspect == "" && base != "" {
			introspect = base + basePath + "/oauth2/introspect"
		}
		if introspect != "" {
			r := *opts.RemoteVerify
			r.IntrospectURL = introspect
			remote = &r
		}
	}
	return oauthcore.VerifyAccessTokenRequestOptions{VerifyAccessTokenOptions: oauthcore.VerifyAccessTokenOptions{
		VerifyOptions: vo, RequiredScopes: opts.RequiredScopes, IsScopeSatisfied: opts.IsScopeSatisfied,
		JWKSURL: jwksURL, RemoteVerify: remote}, DPoP: opts.DPoP}, nil
}

func challengeOr(err error, aud []string, mappings map[string]string, algs []string) error {
	ch, cerr := CreateResourceServerChallenge(err, aud, &ResourceChallengeOptions{ResourceMetadataMappings: mappings, DPoPSigningAlgorithms: algs})
	if cerr != nil {
		return cerr
	}
	if ch != nil {
		return ch
	}
	return err
}

// VerifyBearerToken verifies a bearer access token (verifyBearerToken action).
func (rc *ResourceClient) VerifyBearerToken(ctx context.Context, token string, opts ResourceVerifyOptions) (*jsonx.Object, error) {
	vo, err := rc.resolve(opts)
	if err != nil {
		return nil, err
	}
	var p *jsonx.Object
	if token == "" {
		err = betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "missing authorization header"))
	} else {
		p, err = oauthcore.VerifyBearerToken(ctx, token, vo.VerifyAccessTokenOptions)
	}
	if err != nil {
		return nil, challengeOr(err, vo.VerifyOptions.Audience, opts.ResourceMetadataMappings, oauthcore.DPoPSigningAlgorithms)
	}
	return p, nil
}

// VerifyAccessTokenRequest verifies the access token of a resource request (Bearer or
// DPoP).
func (rc *ResourceClient) VerifyAccessTokenRequest(ctx context.Context, in oauthcore.ResourceRequestInput, opts ResourceVerifyOptions) (*jsonx.Object, error) {
	vo, err := rc.resolve(opts)
	if err != nil {
		return nil, err
	}
	p, err := oauthcore.VerifyAccessTokenRequest(ctx, in, vo)
	if err != nil {
		algs := oauthcore.DPoPSigningAlgorithms
		if opts.DPoP != nil && opts.DPoP.SigningAlgorithms != nil {
			algs = opts.DPoP.SigningAlgorithms
		}
		return nil, challengeOr(err, vo.VerifyOptions.Audience, opts.ResourceMetadataMappings, algs)
	}
	return p, nil
}

// GetProtectedResourceMetadata builds RFC 9728 metadata (getProtectedResourceMetadata).
// overrides keys are appended after the defaults (object spread).
func (rc *ResourceClient) GetProtectedResourceMetadata(overrides *jsonx.Object, externalScopes []string) (*jsonx.Object, error) {
	resource := objString(overrides, "resource")
	if resource == "" {
		resource = rc.baseURL()
	}
	ac, o := rc.context()
	if resource == "" {
		return nil, errors.New("missing required resource")
	}
	var authServers []string
	if overrides != nil {
		if v, ok := overrides.Get("authorization_servers"); ok {
			authServers = toStrings(v)
		}
	}
	if o != nil && externalScopes != nil && len(authServers) <= 1 {
		return nil, errors.New("external scopes should not be provided with one authorization server")
	}
	if overrides != nil {
		if v, ok := overrides.Get("scopes_supported"); ok {
			var valid []string
			if o != nil {
				valid = append(valid, o.Scopes...)
			}
			valid = append(valid, externalScopes...)
			for _, sc := range toStrings(v) {
				if sc == "openid" {
					return nil, errors.New("Only the Auth Server should utilize the openid scope")
				}
				if !contains(valid, sc) {
					return nil, errors.New("Unsupported scope " + sc + `. If external, please add to "externalScopes"`)
				}
			}
		}
	}
	as := rc.baseURL()
	if ac != nil && o != nil && !o.DisableJwtPlugin {
		if jo, err := jwtOptions(ac); err == nil && jwtIssuer(jo) != "" {
			as = jwtIssuer(jo)
		}
	}
	out := jsonx.O("resource", resource)
	if as != "" {
		out.Set("authorization_servers", []any{as})
	}
	algs := oauthcore.DPoPSigningAlgorithms
	if o != nil && o.DPoP != nil && o.DPoP.SigningAlgorithms != nil {
		algs = o.DPoP.SigningAlgorithms
	}
	out.Set("dpop_signing_alg_values_supported", stringsToAny(algs))
	mergeInto(out, overrides)
	return out, nil
}
