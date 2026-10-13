package oauthprovider

import (
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Ports of revoke.ts and userinfo.ts.

// The revocation helpers return betterauth.Null (`return null`) or betterauth.NoContent
// (`undefined`): better-call renders the former as "null" and the latter as an empty body.

func revokeJwtAccessToken(ctx *betterauth.EndpointContext, o *resolved, token string) (bool, error) {
	payload, err := verifyLocalJWT(ctx, o, token)
	if err != nil {
		switch oauthcore.ErrorName(err) {
		case "TypeError", "JWSInvalid":
			return false, oauthErr("BAD_REQUEST", "invalid_request", "invalid JWT signature")
		case "JWTExpired", "JWTInvalid":
			return true, nil
		}
		return false, err
	}
	azp := objString(payload, "azp")
	aud, _ := payload.Get("aud")
	ok, err := isAudienceClaimAllowed(ctx, o, aud, []string{ctx.Auth.BaseURL + "/oauth2/userinfo"})
	if err != nil {
		return false, err
	}
	if azp == "" || !ok {
		return true, nil
	}
	return false, oauthErr("BAD_REQUEST", "unsupported_token_type", "JWT access tokens are self-contained and cannot be revoked server-side")
}

func revokeOpaqueAccessToken(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (any, error) {
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
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "opaque access token not found")
	}
	if at.ClientID == "" || at.ClientID != clientID {
		return betterauth.Null, nil
	}
	where := []adapter.Where{{Field: "token", Value: at.Token}}
	if at.ID != "" {
		where = []adapter.Where{{Field: "id", Value: at.ID}}
	}
	return betterauth.NoContent, ctx.Auth.Adapter.Delete(ctx.Context(), modelAccessToken, where)
}

func revokeRefreshToken(ctx *betterauth.EndpointContext, o *resolved, token, clientID string) (any, error) {
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
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "token not found")
	}
	if rt.Revoked != nil {
		if err := invalidateRefreshFamily(ctx, clientID, rt.UserID); err != nil {
			return nil, err
		}
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "refresh token revoked")
	}
	if rt.ClientID == "" || rt.ClientID != clientID {
		return betterauth.Null, nil
	}
	won, err := ctx.Auth.Adapter.IncrementOne(ctx.Context(), adapter.IncrementInput{Model: modelRefreshToken,
		Where:     []adapter.Where{{Field: "id", Value: rt.ID}, {Field: "revoked", Operator: adapter.Eq, Value: nil}},
		Increment: map[string]float64{}, Set: adapter.Record{"revoked": time.Unix(nowSeconds(), 0)}})
	if err != nil {
		return nil, err
	}
	if won == nil {
		if err := invalidateRefreshFamily(ctx, clientID, rt.UserID); err != nil {
			return nil, err
		}
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "refresh token revoked")
	}
	_, err = ctx.Auth.Adapter.DeleteMany(ctx.Context(), modelAccessToken, []adapter.Where{{Field: "refreshId", Value: rt.ID}})
	return betterauth.NoContent, err
}

func isUnsupportedTokenType(err error) bool {
	e, ok := betterauth.AsAPIError(err)
	return ok && errorBodyString(e, "error") == "unsupported_token_type"
}

func revokeAccessToken(ctx *betterauth.EndpointContext, o *resolved, clientID, token string) (any, error) {
	done, err := revokeJwtAccessToken(ctx, o, token)
	if err == nil && done {
		return betterauth.Null, nil
	}
	if err != nil {
		if _, ok := betterauth.AsAPIError(err); !ok || isUnsupportedTokenType(err) {
			return nil, err
		}
	}
	res, err := revokeOpaqueAccessToken(ctx, o, token, clientID)
	if err == nil {
		return res, nil
	}
	if _, ok := betterauth.AsAPIError(err); !ok {
		return nil, err
	}
	return nil, oauthErr("BAD_REQUEST", "invalid_request", "Invalid access token")
}

// revokeEndpoint handles POST /oauth2/revoke.
func revokeEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	body := bodyMap(ctx)
	token, _ := body["token"].(string)
	hint, _ := body["token_type_hint"].(string)
	if hint != "access_token" && hint != "refresh_token" {
		hint = ""
	}
	creds, err := extractClientCredentials(ctx, o, ctx.Auth.BaseURL+"/oauth2/revoke")
	if err != nil {
		return nil, err
	}
	clientID, secret, preVerified, method, _ := creds.destructure()
	if clientID == "" {
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
	res, err := func() (any, error) {
		if hint == "" || hint == "access_token" {
			res, err := revokeAccessToken(ctx, o, client.ClientID, token)
			if err == nil {
				return res, nil
			}
			if _, ok := betterauth.AsAPIError(err); !ok || hint == "access_token" || isUnsupportedTokenType(err) {
				return nil, err
			}
		}
		if hint == "" || hint == "refresh_token" {
			rt, err := decodeRefreshToken(o, token)
			if err == nil {
				var res any
				res, err = revokeRefreshToken(ctx, o, rt.Token, client.ClientID)
				if err == nil {
					return res, nil
				}
			}
			if _, ok := betterauth.AsAPIError(err); !ok || hint == "refresh_token" {
				return nil, err
			}
		}
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "token not found")
	}()
	if err != nil {
		if _, ok := betterauth.AsAPIError(err); ok {
			return nil, err
		}
		ctx.Auth.Logger.Error("Introspection error:", err.Error())
		return nil, apiErr("INTERNAL_SERVER_ERROR")
	}
	return res, nil
}

// ---- userinfo ----

func userNormalClaims(u *betterauth.User, scopes, requested []string) *jsonx.Object {
	claims := jsonx.O("sub", u.ID)
	for _, name := range standardClaimNames {
		if contains(scopes, standardClaimScope[name]) || contains(requested, name) {
			claims.Set(name, resolveStandardClaim(name, u))
		}
	}
	return claims
}

// pickClaims keeps defined claims that are not already in base.
func pickClaims(claims, base *jsonx.Object) *jsonx.Object {
	out := jsonx.NewObject()
	if claims == nil {
		return out
	}
	for _, k := range claims.Keys() {
		v, _ := claims.Get(k)
		if v == jsonx.Undefined {
			continue
		}
		if base != nil && base.Has(k) {
			continue
		}
		out.Set(k, v)
	}
	return out
}

// userInfoEndpoint handles GET/POST /oauth2/userinfo.
func userInfoEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	header := oauthcore.ParseAccessTokenAuthorization(ctx.GetHeader("Authorization"))
	bodyToken := ""
	if ctx.Request != nil && ctx.Request.Method == "POST" {
		bodyToken, _ = bodyMap(ctx)["access_token"].(string)
	}
	if header != nil && bodyToken != "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "Multiple access token transport methods are not allowed")
	}
	auth := header
	if auth == nil && bodyToken != "" {
		auth = &oauthcore.AccessTokenAuthorization{Scheme: "Bearer", Token: bodyToken}
	}
	if auth == nil || auth.Token == "" {
		return nil, oauthErr("UNAUTHORIZED", "invalid_request", "access token not found")
	}
	v, err := requireActiveAccessTokenWithClaims(ctx, o, auth.Token, "")
	if err != nil {
		return nil, err
	}
	jwtPayload := v.payload
	if oauthcore.GetDPoPJKTFromPayload(jwtPayload) != "" && ctx.Request == nil {
		return nil, oauthErr("UNAUTHORIZED", "invalid_token", "DPoP-bound access token requires an HTTP request context")
	}
	method := "GET"
	if ctx.Request != nil {
		method = ctx.Request.Method
	}
	if err := oauthcore.EnforceDPoPBinding(ctx.Context(), oauthcore.EnforceDPoPBindingParams{Payload: jwtPayload,
		Authorization: auth, ProofJWT: dpopProof(ctx), Method: method, URL: endpointURL(ctx, "/oauth2/userinfo"),
		ProofMaxAgeSeconds: o.dpopMaxAge(), SigningAlgorithms: o.dpopAlgs(), ReplayStore: replayStore(ctx)}); err != nil {
		if de, ok := oauthcore.IsDPoPBindingError(err); ok {
			return nil, oauthErr("UNAUTHORIZED", de.Code, de.Message)
		}
		return nil, err
	}
	var scopes []string
	if s, ok := jwtPayload.Get("scope"); ok {
		if str, isStr := s.(string); isStr {
			scopes = splitSpace(str)
		}
	}
	if !contains(scopes, "openid") {
		return nil, oauthErr("BAD_REQUEST", "invalid_scope", "Missing required scope")
	}
	sub := objString(jwtPayload, "sub")
	if sub == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "user not found")
	}
	user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), sub)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "user not found")
	}
	base := userNormalClaims(user, scopes, v.requestedUserInfoClaims)
	clientID := objString(jwtPayload, "client_id")
	if clientID == "" {
		clientID = objString(jwtPayload, "azp")
	}
	var client *SchemaClient
	if clientID != "" && (o.PairwiseSecret != "" || o.hasUserInfoClaimExtension()) {
		client, err = getClient(ctx, o, clientID)
		if err != nil {
			return nil, err
		}
	}
	if o.PairwiseSecret != "" && client != nil {
		s, err := resolveSubjectIdentifier(user.ID, client, o)
		if err != nil {
			return nil, err
		}
		base.Set("sub", s)
	}
	extension := jsonx.NewObject()
	if len(scopes) > 0 {
		extension, err = collectExtensionUserInfoClaims(o, UserInfoExtensionInput{Ctx: ctx, User: user, Scopes: scopes,
			JWT: jwtPayload, Client: client, RequestedClaims: v.requestedUserInfoClaims})
		if err != nil {
			return nil, err
		}
	}
	additional := jsonx.NewObject()
	if o.CustomUserInfoClaims != nil && len(scopes) > 0 {
		additional, err = o.CustomUserInfoClaims(UserInfoClaimsInput{Ctx: ctx, User: user, Scopes: scopes, JWT: jwtPayload,
			RequestedClaims: v.requestedUserInfoClaims})
		if err != nil {
			return nil, err
		}
	}
	out := base.Clone()
	mergeInto(out, pickClaims(extension, base))
	mergeInto(out, pickClaims(additional, nil))
	subV, _ := base.Get("sub")
	out.Set("sub", subV)
	return out, nil
}

func splitSpace(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}
