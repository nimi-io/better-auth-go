package oauthprovider

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/introspect.ts (and the JWT parts of revoke.ts).

const invalidAccessTokenDescription = "Invalid access token"

func inactive() *jsonx.Object { return jsonx.O("active", false) }

func invalidAccessTokenError() *betterauth.APIError {
	e := oauthErr("UNAUTHORIZED", "invalid_token", invalidAccessTokenDescription)
	e.Headers.Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+invalidAccessTokenDescription+`"`)
	return e
}

// jwksFetch returns the JWKS source of the jwt plugin (remote URL or its /jwks endpoint).
func jwksFetch(ctx *betterauth.EndpointContext, jo *jwt.Options) oauthcore.JWKSFetch {
	if jo != nil && jo.JWKS != nil && jo.JWKS.RemoteURL != "" {
		return oauthcore.JWKSFetch{URL: jo.JWKS.RemoteURL}
	}
	return oauthcore.JWKSFetch{CacheKey: jwksCacheKeyFor(ctx), Func: func(c context.Context) (*jsonx.Object, error) {
		return localJWKS(ctx, jo)
	}}
}

type jwksKey struct{ p *betterauth.Plugin }

func jwksCacheKeyFor(ctx *betterauth.EndpointContext) any {
	return jwksKey{ctx.Auth.GetPlugin("jwt")}
}

// localJWKS runs the jwt plugin getJwks endpoint (jwtPlugin.endpoints.getJwks(ctx)).
func localJWKS(ctx *betterauth.EndpointContext, jo *jwt.Options) (*jsonx.Object, error) {
	p := ctx.Auth.GetPlugin("jwt")
	if p == nil {
		return nil, nil
	}
	for _, ep := range p.Endpoints {
		if ep.Key == "getJwks" {
			res, err := ep.Handler(ctx)
			if err != nil {
				return nil, err
			}
			switch t := res.(type) {
			case *jsonx.Object:
				return t, nil
			case *betterauth.Response:
				pv, err := jsonx.Parse(t.Body)
				if err != nil {
					return nil, err
				}
				o, _ := pv.(*jsonx.Object)
				return o, nil
			default:
				b, err := jsonx.Marshal(t)
				if err != nil {
					return nil, err
				}
				pv, err := jsonx.Parse(b)
				if err != nil {
					return nil, err
				}
				o, _ := pv.(*jsonx.Object)
				return o, nil
			}
		}
	}
	return nil, nil
}

// verifyLocalJWT verifies a JWT issued by this server (getJwks + jwtVerify with issuer).
func verifyLocalJWT(ctx *betterauth.EndpointContext, o *resolved, token string) (*jsonx.Object, error) {
	var jo *jwt.Options
	if !o.DisableJwtPlugin {
		var err error
		jo, err = jwtOptions(ctx.Auth)
		if err != nil {
			return nil, err
		}
	}
	fetch := jwksFetch(ctx, jo)
	if o.DisableJwtPlugin {
		fetch = oauthcore.JWKSFetch{Func: func(context.Context) (*jsonx.Object, error) { return nil, nil }}
	}
	jwks, err := oauthcore.GetJWKS(ctx.Context(), token, fetch)
	if err != nil {
		return nil, err
	}
	keys, err := oauthcore.LocalJWKSet(jwks)
	if err != nil {
		return nil, err
	}
	iss := ctx.Auth.BaseURL
	if v := jwtIssuer(jo); v != "" {
		iss = v
	}
	v, err := oauthcore.JWTVerify(token, keys, oauthcore.VerifyOptions{Issuer: []string{iss}})
	if err != nil {
		return nil, err
	}
	return v.Payload, nil
}

func audienceResources(aud any, userInfo string) []string {
	var vals []any
	switch t := aud.(type) {
	case nil:
		return nil
	case []any:
		vals = t
	default:
		vals = []any{t}
	}
	var out []string
	for _, v := range vals {
		if s, ok := v.(string); ok && s != userInfo {
			out = append(out, s)
		}
	}
	return out
}

func isIntrospectionAuthorized(ctx *betterauth.EndpointContext, introspecting, issuer string, resources []string) (bool, error) {
	if introspecting == "" || introspecting == issuer {
		return true, nil
	}
	if len(resources) == 0 {
		return false, nil
	}
	return isClientLinkedToAnyResource(ctx, introspecting, resources)
}

func sessionActive(ctx *betterauth.EndpointContext, sessionID string) (bool, error) {
	s, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "session",
		Where: []adapter.Where{{Field: "id", Value: sessionID}}})
	if err != nil {
		return false, err
	}
	if s == nil {
		return false, nil
	}
	if exp := recTime(s, "expiresAt"); exp != nil && exp.Before(time.Now()) {
		return false, nil
	}
	return true, nil
}

// errNotAPI wraps non-APIError failures so callers can distinguish them.
func validateJwtAccessToken(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (*jsonx.Object, error) {
	userInfoAud := ctx.Auth.BaseURL + "/oauth2/userinfo"
	payload, err := verifyLocalJWT(ctx, o, token)
	if err != nil {
		switch oauthcore.ErrorName(err) {
		case "TypeError", "JWSInvalid":
			return nil, oauthErr("BAD_REQUEST", "invalid_request", "invalid JWT signature")
		case "JWTExpired", "JWTInvalid":
			return inactive(), nil
		}
		return nil, err
	}
	aud, _ := payload.Get("aud")
	ok, err := isAudienceClaimAllowed(ctx, o, aud, []string{userInfoAud})
	if err != nil {
		return nil, err
	}
	if !ok {
		return inactive(), nil
	}
	azpV, _ := payload.Get("azp")
	azp, _ := azpV.(string)
	if azp == "" {
		return inactive(), nil
	}
	client, err := getClient(ctx, o, azp)
	if err != nil {
		return nil, err
	}
	if client == nil || client.IsDisabled() {
		return inactive(), nil
	}
	authorized, err := isIntrospectionAuthorized(ctx, clientID, azp, audienceResources(aud, userInfoAud))
	if err != nil {
		return nil, err
	}
	if !authorized {
		return inactive(), nil
	}
	if sidV, ok := payload.Get("sid"); ok {
		if sid, _ := sidV.(string); sid != "" {
			active, err := sessionActive(ctx, sid)
			if err != nil {
				return nil, err
			}
			if !active {
				return inactive(), nil
			}
		}
	}
	payload.Set("client_id", azp)
	payload.Set("active", true)
	cnf, _ := payload.Get("cnf")
	payload.Set("token_type", confirmationTokenType(cnf))
	return payload, nil
}

type validatedAccessToken struct {
	payload                 *jsonx.Object
	requestedUserInfoClaims []string
}

func unixSeconds(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return int64(math.Floor(float64(t.UnixMilli()) / 1000))
}

func validateOpaqueAccessToken(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (*validatedAccessToken, error) {
	inactiveResult := &validatedAccessToken{payload: inactive(), requestedUserInfoClaims: []string{}}
	value := token
	if p := o.prefix().OpaqueAccessToken; p != "" {
		if len(value) < len(p) || value[:len(p)] != p {
			return nil, oauthErr("BAD_REQUEST", "invalid_request", "opaque access token not found")
		}
		value = replaceFirst(value, p)
	}
	stored, err := storeToken(o, value, TokenTypeAccessToken)
	if err != nil {
		return nil, err
	}
	rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelAccessToken,
		Where: []adapter.Where{{Field: "token", Value: stored}}})
	if err != nil {
		return nil, err
	}
	at := tokenRecordFrom(rec)
	if at == nil {
		return nil, oauthErr("BAD_REQUEST", "invalid_token", "opaque access token not found")
	}
	if at.ExpiresAt == nil || at.ExpiresAt.Before(time.Now()) {
		return inactiveResult, nil
	}
	if at.Revoked != nil {
		return inactiveResult, nil
	}
	resources := at.Resources
	var client *SchemaClient
	if at.ClientID != "" {
		client, err = getClient(ctx, o, at.ClientID)
		if err != nil {
			return nil, err
		}
		if client == nil || client.IsDisabled() {
			return inactiveResult, nil
		}
		ok, err := isIntrospectionAuthorized(ctx, clientID, at.ClientID, resources)
		if err != nil {
			return nil, err
		}
		if !ok {
			return inactiveResult, nil
		}
	}
	if at.SessionID != "" {
		active, err := sessionActive(ctx, at.SessionID)
		if err != nil {
			return nil, err
		}
		if !active {
			return inactiveResult, nil
		}
	}
	var user *betterauth.User
	if at.UserID != "" {
		user, err = ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), at.UserID)
		if err != nil {
			return nil, err
		}
	}
	userInfo := ctx.Auth.BaseURL + "/oauth2/userinfo"
	if len(resources) > 0 {
		ok, err := isAudienceClaimAllowed(ctx, o, stringsToAny(resources), []string{userInfo})
		if err != nil {
			return nil, err
		}
		if !ok {
			return inactiveResult, nil
		}
	}
	var audience []string
	if resources != nil {
		audience = append([]string{}, resources...)
	}
	if len(audience) > 0 && contains(at.Scopes, "openid") && !contains(audience, userInfo) {
		audience = append(audience, userInfo)
	}
	resourceClaims := jsonx.NewObject()
	if len(resources) > 0 {
		resourceClaims, err = getResourceCustomClaims(ctx, resources)
		if err != nil {
			return nil, err
		}
	}
	claims := jsonx.NewObject()
	if client != nil {
		md, _ := ParseClientMetadata(client.Metadata)
		claims, err = resolveAccessTokenClaims(accessTokenClaimsInput{ctx: ctx, opts: o, user: user, client: client,
			scopes: nonNil(at.Scopes), resources: resources, referenceID: at.ReferenceID, metadata: md,
			resourcePolicyClaims: resourceClaims})
		if err != nil {
			return nil, err
		}
	}
	payload := claims.Clone()
	payload.Set("active", true)
	payload.Set("iss", o.issuerOrBase(ctx))
	if aud := toAudienceClaim(audience); aud != nil {
		payload.Set("aud", aud)
	} else {
		payload.Set("aud", jsonx.Undefined)
	}
	payload.Set("client_id", at.ClientID)
	payload.Set("azp", at.ClientID)
	if user != nil {
		payload.Set("sub", user.ID)
	} else {
		payload.Set("sub", jsonx.Undefined)
	}
	if at.SessionID != "" {
		payload.Set("sid", at.SessionID)
	} else {
		payload.Set("sid", jsonx.Undefined)
	}
	payload.Set("exp", unixSeconds(at.ExpiresAt))
	payload.Set("iat", unixSeconds(at.CreatedAt))
	if at.Scopes != nil {
		payload.Set("scope", joinSpace(at.Scopes))
	} else {
		payload.Set("scope", jsonx.Undefined)
	}
	payload.Set("token_type", confirmationTokenType(at.Confirmation))
	if at.Confirmation != nil {
		payload.Set("cnf", at.Confirmation)
	}
	return &validatedAccessToken{payload: payload, requestedUserInfoClaims: nonNil(at.RequestedUserInfoClaims)}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func replaceFirst(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func joinSpace(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

func validateRefreshToken(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (*jsonx.Object, error) {
	stored, err := storeToken(o, token, TokenTypeRefreshToken)
	if err != nil {
		return nil, err
	}
	rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelRefreshToken,
		Where: []adapter.Where{{Field: "token", Value: stored}}})
	if err != nil {
		return nil, err
	}
	rt := tokenRecordFrom(rec)
	if rt == nil {
		return nil, oauthErr("BAD_REQUEST", "invalid_token", "token not found")
	}
	if rt.ClientID == "" || rt.ClientID != clientID {
		return inactive(), nil
	}
	if rt.ExpiresAt == nil || rt.ExpiresAt.Before(time.Now()) {
		return inactive(), nil
	}
	if rt.Revoked != nil {
		return inactive(), nil
	}
	sid := rt.SessionID
	if sid != "" {
		active, err := sessionActive(ctx, sid)
		if err != nil {
			return nil, err
		}
		if !active {
			sid = ""
		}
	}
	var user *betterauth.User
	if rt.UserID != "" {
		user, err = ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), rt.UserID)
		if err != nil {
			return nil, err
		}
	}
	p := jsonx.O("active", true, "client_id", clientID, "iss", o.issuerOrBase(ctx))
	if user != nil {
		p.Set("sub", user.ID)
	}
	if sid != "" {
		p.Set("sid", sid)
	}
	p.Set("exp", unixSeconds(rt.ExpiresAt))
	p.Set("iat", unixSeconds(rt.CreatedAt))
	if rt.Scopes != nil {
		p.Set("scope", joinSpace(rt.Scopes))
	}
	p.Set("token_type", confirmationTokenType(rt.Confirmation))
	if rt.Confirmation != nil {
		p.Set("cnf", rt.Confirmation)
	}
	return p, nil
}

func resolveAccessTokenValidation(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (*validatedAccessToken, error) {
	p, err := validateJwtAccessToken(ctx, o, token, clientID)
	if err == nil {
		return &validatedAccessToken{payload: p, requestedUserInfoClaims: []string{}}, nil
	}
	if _, ok := betterauth.AsAPIError(err); !ok {
		return nil, err
	}
	v, err := validateOpaqueAccessToken(ctx, o, token, clientID)
	if err == nil {
		return v, nil
	}
	if _, ok := betterauth.AsAPIError(err); !ok {
		return nil, err
	}
	return nil, invalidAccessTokenError()
}

func validateAccessToken(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (*jsonx.Object, error) {
	v, err := resolveAccessTokenValidation(ctx, o, token, clientID)
	if err != nil {
		return nil, err
	}
	return v.payload, nil
}

func isActive(p *jsonx.Object) bool {
	v, _ := p.Get("active")
	return v == true
}

func requireActiveAccessToken(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (*jsonx.Object, error) {
	p, err := validateAccessToken(ctx, o, token, clientID)
	if err != nil {
		return nil, err
	}
	if isActive(p) {
		return p, nil
	}
	return nil, invalidAccessTokenError()
}

func requireActiveAccessTokenWithClaims(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (*validatedAccessToken, error) {
	v, err := resolveAccessTokenValidation(ctx, o, token, clientID)
	if err != nil {
		return nil, err
	}
	if isActive(v.payload) {
		return v, nil
	}
	return nil, invalidAccessTokenError()
}

func resolveIntrospectionSub(ctx *betterauth.EndpointContext, o *resolved, payload *jsonx.Object, introspecting *SchemaClient) (*jsonx.Object, error) {
	subV, _ := payload.Get("sub")
	sub, _ := subV.(string)
	if !isActive(payload) || sub == "" {
		return payload, nil
	}
	issuerID := objString(payload, "client_id")
	if issuerID == "" {
		issuerID = objString(payload, "azp")
	}
	if issuerID == "" {
		return payload, nil
	}
	issuing := introspecting
	if issuerID != introspecting.ClientID {
		var err error
		issuing, err = getClient(ctx, o, issuerID)
		if err != nil {
			return nil, err
		}
	}
	if issuing == nil {
		return payload, nil
	}
	resolvedSub, err := resolveSubjectIdentifier(sub, issuing, o)
	if err != nil {
		return nil, err
	}
	out := payload.Clone()
	out.Set("sub", resolvedSub)
	return out, nil
}

var errInternal = errors.New("internal")

// introspectEndpoint handles POST /oauth2/introspect.
func introspectEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	body := bodyMap(ctx)
	token, _ := body["token"].(string)
	hint, _ := body["token_type_hint"].(string)
	if hint != "access_token" && hint != "refresh_token" {
		hint = ""
	}
	creds, err := extractClientCredentials(ctx, o, ctx.Auth.BaseURL+"/oauth2/introspect")
	if err != nil {
		return nil, err
	}
	clientID, secret, preVerified, method, _ := creds.destructure()
	if clientID == "" || (secret == "" && !preVerified) {
		return nil, oauthErr("UNAUTHORIZED", "invalid_client", "missing required credentials")
	}
	token = oauthcore.StripAccessTokenAuthorizationScheme(token)
	if token == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "missing a required token for introspection")
	}
	client, err := validateClientCredentials(ctx, o, clientID, secret, nil, preVerified, "", method)
	if err != nil {
		return nil, err
	}
	result, err := func() (*jsonx.Object, error) {
		if hint == "" || hint == "access_token" {
			p, err := validateAccessToken(ctx, o, token, client.ClientID)
			if err == nil {
				return resolveIntrospectionSub(ctx, o, p, client)
			}
			if _, ok := betterauth.AsAPIError(err); !ok || hint == "access_token" {
				return nil, err
			}
		}
		if hint == "" || hint == "refresh_token" {
			rt, err := decodeRefreshToken(o, token)
			if err == nil {
				var p *jsonx.Object
				p, err = validateRefreshToken(ctx, o, rt.Token, client.ClientID)
				if err == nil {
					return resolveIntrospectionSub(ctx, o, p, client)
				}
			}
			if _, ok := betterauth.AsAPIError(err); !ok || hint == "refresh_token" {
				return nil, err
			}
		}
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "token not found")
	}()
	if err != nil {
		if e, ok := betterauth.AsAPIError(err); ok {
			if e.Status == "BAD_REQUEST" || errorBodyString(e, "error") == "invalid_token" {
				return inactive(), nil
			}
			return nil, err
		}
		ctx.Auth.Logger.Error("Introspection error:", err.Error())
		return nil, apiErr("INTERNAL_SERVER_ERROR")
	}
	return result, nil
}
