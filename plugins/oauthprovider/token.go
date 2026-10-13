package oauthprovider

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/token.ts.

const jwtAccessTokenType = "at+jwt"

func confirmationTokenType(conf any) string {
	if oauthcore.GetConfirmationJKT(conf) != "" {
		return "DPoP"
	}
	return "Bearer"
}

// tokenEndpoint handles POST /oauth2/token.
func tokenEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	grantType := bodyStr(ctx, "grant_type")
	if !contains(o.supportedGrantTypes(), grantType) {
		return nil, oauthErr("BAD_REQUEST", "unsupported_grant_type", "unsupported grant_type "+grantType)
	}
	switch grantType {
	case "authorization_code":
		return handleAuthorizationCodeGrant(ctx, o)
	case "client_credentials":
		return handleClientCredentialsGrant(ctx, o)
	case "refresh_token":
		return handleRefreshTokenGrant(ctx, o)
	}
	if h := o.extensionGrantHandler(grantType); h != nil {
		return h(GrantHandlerInput{Ctx: ctx, GrantType: grantType, Provider: newProviderAPI(ctx, o, grantType), opts: o})
	}
	return nil, oauthErr("BAD_REQUEST", "unsupported_grant_type", "unsupported grant_type "+grantType)
}

// ProviderAPI is the provider API handed to extension grant handlers (OAuthProviderApi).
type ProviderAPI struct {
	ctx       *betterauth.EndpointContext
	o         *resolved
	grantType string
}

func newProviderAPI(ctx *betterauth.EndpointContext, o *resolved, grantType string) *ProviderAPI {
	return &ProviderAPI{ctx: ctx, o: o, grantType: grantType}
}

// GetOAuthProviderAPI returns the provider API for the current request (getOAuthProviderApi).
func GetOAuthProviderAPI(ctx *betterauth.EndpointContext, grantType string) (*ProviderAPI, error) {
	o, err := pluginOptions(ctx.Auth)
	if err != nil {
		return nil, err
	}
	return newProviderAPI(ctx, o, grantType), nil
}

// GetClient loads a client.
func (p *ProviderAPI) GetClient(clientID string) (*SchemaClient, error) {
	return getClient(p.ctx, p.o, clientID)
}

// AuthenticateClient authenticates the requesting client.
func (p *ProviderAPI) AuthenticateClient(req *ClientAuthenticationRequest) (*AuthenticatedClient, error) {
	path := p.ctx.Path
	if path == "" {
		path = "/oauth2/token"
	}
	creds, err := extractClientCredentials(p.ctx, p.o, p.ctx.Auth.BaseURL+path)
	if err != nil {
		return nil, err
	}
	clientID, secret, preVerified, method, conf := creds.destructure()
	if clientID == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "Missing required client_id")
	}
	requireCreds := req == nil || req.RequireCredentials == nil || *req.RequireCredentials
	if requireCreds && secret == "" && !preVerified {
		return nil, oauthErr("BAD_REQUEST", "invalid_client", "Missing required client credentials")
	}
	var scopes []string
	if req != nil {
		scopes = req.Scopes
	}
	client, err := validateClientCredentials(p.ctx, p.o, clientID, secret, scopes, preVerified, p.grantType, method)
	if err != nil {
		return nil, err
	}
	return &AuthenticatedClient{ClientID: clientID, Client: client, Method: method, Confirmation: conf}, nil
}

// IssueTokens issues tokens for the grant (createUserTokens).
func (p *ProviderAPI) IssueTokens(params TokenIssueParams) (*jsonx.Object, error) {
	if p.grantType == "" {
		return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error_description",
			"issueTokens requires a grant type; pass it to getOAuthProviderApi(ctx, opts, grantType).", "error", "server_error"))
	}
	return createUserTokens(p.ctx, p.o, createTokensParams{TokenIssueParams: params, grantType: p.grantType})
}

// HashToken hashes a token for storage.
func (p *ProviderAPI) HashToken(token, tokenType string) (string, error) {
	return storeToken(p.o, token, tokenType)
}

// ValidateAccessToken validates an access token (inactive tokens return {active:false}).
func (p *ProviderAPI) ValidateAccessToken(token, clientID string) (*jsonx.Object, error) {
	return validateAccessToken(p.ctx, p.o, token, clientID)
}

// RequireActiveAccessToken validates an access token and requires it to be active.
func (p *ProviderAPI) RequireActiveAccessToken(token, clientID string) (*jsonx.Object, error) {
	return requireActiveAccessToken(p.ctx, p.o, token, clientID)
}

func nowSeconds() int64 { return time.Now().Unix() }

func createJwtAccessToken(ctx *betterauth.EndpointContext, o *resolved, user *betterauth.User, client *SchemaClient,
	audience []string, scopes []string, iat, exp int64, sid, signingAlg, signingKid string, claims *jsonx.Object, conf *jsonx.Object) (string, error) {
	jo, err := jwtOptions(ctx.Auth)
	if err != nil {
		return "", err
	}
	subject := client.ClientID
	if user != nil {
		subject = user.ID
	}
	payload := jsonx.NewObject()
	mergeInto(payload, claims)
	payload.Set("sub", subject)
	if aud := toAudienceClaim(audience); aud != nil {
		payload.Set("aud", aud)
	} else {
		payload.Set("aud", jsonx.Undefined)
	}
	payload.Set("client_id", client.ClientID)
	payload.Set("azp", client.ClientID)
	payload.Set("scope", strings.Join(scopes, " "))
	if sid != "" {
		payload.Set("sid", sid)
	} else {
		payload.Set("sid", jsonx.Undefined)
	}
	iss := jwtIssuer(jo)
	if iss == "" {
		iss = ctx.Auth.BaseURL
	}
	payload.Set("iss", iss)
	payload.Set("iat", iat)
	payload.Set("exp", exp)
	payload.Set("jti", bacrypto.RandomString(32))
	if conf != nil {
		payload.Set("cnf", conf)
	}
	return jwt.SignJWT(ctx, jwt.SignConfig{Options: jo, Header: &jwt.Header{Typ: jwtAccessTokenType},
		SigningKeyID: signingKid, SigningAlgorithm: signingAlg, Payload: payload})
}

func computeOIDCHash(token, alg string) string {
	var h hash.Hash
	switch {
	case alg == "EdDSA":
		h = sha512.New()
	case strings.HasSuffix(alg, "384"):
		h = sha512.New384()
	case strings.HasSuffix(alg, "512"):
		h = sha512.New()
	default:
		h = sha256.New()
	}
	h.Write([]byte(token))
	d := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(d[:len(d)/2])
}

func createIDToken(ctx *betterauth.EndpointContext, o *resolved, user *betterauth.User, client *SchemaClient, scopes []string,
	nonce, sessionID string, authTime *time.Time, accessToken string, extra *jsonx.Object) (string, error) {
	iat := nowSeconds()
	exp := iat + int64(o.idTokenExpiresIn())
	sub, err := resolveSubjectIdentifier(user.ID, client, o)
	if err != nil {
		return "", err
	}
	var custom *jsonx.Object
	if o.CustomIDTokenClaims != nil {
		md, _ := ParseClientMetadata(client.Metadata)
		c, err := o.CustomIDTokenClaims(IDTokenClaimsInput{Ctx: ctx, User: user, Scopes: scopes, Metadata: md})
		if err != nil {
			return "", err
		}
		custom = c
	}
	customClaims := stripReservedIDTokenClaims(custom, ctx.Auth.Logger)
	var jo *jwt.Options
	if !o.DisableJwtPlugin {
		jo, err = jwtOptions(ctx.Auth)
		if err != nil {
			return "", err
		}
	}
	var key *jwt.ResolvedSigningKey
	customSign := jo != nil && jo.JWT != nil && jo.JWT.Sign != nil
	if !o.DisableJwtPlugin && !customSign {
		key, err = jwt.ResolveSigningKey(ctx, jo, nil)
		if err != nil {
			return "", err
		}
	}
	signingAlg := "HS256"
	if !o.DisableJwtPlugin {
		switch {
		case key != nil:
			signingAlg = key.Alg
		case jo.JWKS != nil && jo.JWKS.KeyPairConfig != nil:
			signingAlg = jo.JWKS.KeyPairConfig.Alg
		default:
			signingAlg = ""
		}
	}
	atHash := ""
	if accessToken != "" {
		atHash = computeOIDCHash(accessToken, signingAlg)
	}
	emitSid := isTrue(client.EnableEndSession) || client.BackchannelLogoutURI != ""
	payload := jsonx.NewObject()
	for _, n := range standardClaimNames {
		payload.Set(n, jsonx.Undefined)
	}
	if authTime != nil {
		payload.Set("auth_time", int64(math.Floor(float64(authTime.UnixMilli())/1000)))
	} else {
		payload.Set("auth_time", jsonx.Undefined)
	}
	payload.Set("acr", level0ACR)
	mergeInto(payload, customClaims)
	setOrUndef := func(k, v string) {
		if v != "" {
			payload.Set(k, v)
		} else {
			payload.Set(k, jsonx.Undefined)
		}
	}
	setOrUndef("at_hash", atHash)
	iss := ctx.Auth.BaseURL
	if jo != nil && jwtIssuer(jo) != "" {
		iss = jwtIssuer(jo)
	}
	payload.Set("iss", iss)
	payload.Set("sub", sub)
	payload.Set("aud", client.ClientID)
	setOrUndef("nonce", nonce)
	payload.Set("iat", iat)
	payload.Set("exp", exp)
	if emitSid {
		setOrUndef("sid", sessionID)
	} else {
		payload.Set("sid", jsonx.Undefined)
	}
	additive := stripReservedIDTokenClaims(extra, ctx.Auth.Logger)
	for _, k := range additive.Keys() {
		v, _ := additive.Get(k)
		if v == jsonx.Undefined || payload.Has(k) {
			continue
		}
		payload.Set(k, v)
	}
	if o.DisableJwtPlugin && client.ClientSecret == "" {
		return "", nil
	}
	var token string
	if o.DisableJwtPlugin {
		secret, err := decryptStoredClientSecret(ctx, o.storeClientSecretMode(), client.ClientSecret)
		if err != nil {
			return "", err
		}
		token, err = jose.SignJWT(jsonx.O("alg", "HS256"), payload, []byte(secret))
		if err != nil {
			return "", err
		}
	} else {
		token, err = jwt.SignJWT(ctx, jwt.SignConfig{Options: jo, Payload: payload, ResolvedKey: key})
		if err != nil {
			return "", err
		}
	}
	if token != "" && atHash != "" && customSign {
		h, err := oauthcore.DecodeProtectedHeader(token)
		if err == nil {
			alg, _ := h.Get("alg")
			if alg != signingAlg {
				return "", betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error_description",
					"ID token signed with \""+jsString(alg)+"\" but at_hash was computed for \""+signingAlg+"\". Ensure jwt.sign uses the algorithm declared in keyPairConfig.alg.",
					"error", "server_error"))
			}
		}
	}
	return token, nil
}

func encodeRefreshToken(o *resolved, token, sessionID string) (string, error) {
	if o.FormatRefreshToken != nil && o.FormatRefreshToken.Encrypt != nil {
		enc, err := o.FormatRefreshToken.Encrypt(token, sessionID)
		if err != nil {
			return "", err
		}
		token = enc
	}
	return o.prefix().RefreshToken + token, nil
}

func decodeRefreshToken(o *resolved, token string) (DecodedRefreshToken, error) {
	if p := o.prefix().RefreshToken; p != "" {
		if !strings.HasPrefix(token, p) {
			return DecodedRefreshToken{}, oauthErr("BAD_REQUEST", "invalid_token", "refresh token not found")
		}
		token = strings.Replace(token, p, "", 1)
	}
	if o.FormatRefreshToken != nil && o.FormatRefreshToken.Decrypt != nil {
		return o.FormatRefreshToken.Decrypt(token)
	}
	return DecodedRefreshToken{Token: token}, nil
}

func createOpaqueAccessToken(ctx *betterauth.EndpointContext, o *resolved, user *betterauth.User, client *SchemaClient,
	scopes []string, iat, exp int64, sid string, resources []string, referenceID, authorizationCodeID, refreshID string,
	conf *jsonx.Object, requestedUserInfoClaims []string) (string, error) {
	var token string
	var err error
	if o.GenerateOpaqueAccessToken != nil {
		token, err = o.GenerateOpaqueAccessToken()
		if err != nil {
			return "", err
		}
	} else {
		token = bacrypto.RandomString(32, "A-Z", "a-z")
	}
	stored, err := storeToken(o, token, TokenTypeAccessToken)
	if err != nil {
		return "", err
	}
	data := adapter.Record{"token": stored, "clientId": client.ClientID, "scopes": stringsToAny(scopes),
		"createdAt": time.Unix(iat, 0), "expiresAt": time.Unix(exp, 0)}
	if sid != "" {
		data["sessionId"] = sid
	}
	if user != nil {
		data["userId"] = user.ID
	}
	if referenceID != "" {
		data["referenceId"] = referenceID
	}
	if authorizationCodeID != "" {
		data["authorizationCodeId"] = authorizationCodeID
	}
	if resources != nil {
		data["resources"] = stringsToAny(resources)
	}
	if refreshID != "" {
		data["refreshId"] = refreshID
	}
	if conf != nil {
		data["confirmation"] = conf
	}
	if len(requestedUserInfoClaims) > 0 {
		data["requestedUserInfoClaims"] = stringsToAny(requestedUserInfoClaims)
	}
	if _, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: modelAccessToken, Data: data}); err != nil {
		return "", err
	}
	return o.prefix().OpaqueAccessToken + token, nil
}

// invalidateRefreshFamily deletes every refresh token (and linked access token) of a
// client / user pair.
func invalidateRefreshFamily(ctx *betterauth.EndpointContext, clientID, userID string) error {
	where := []adapter.Where{{Field: "clientId", Value: clientID}, {Field: "userId", Value: userID}}
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelRefreshToken, Where: where})
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		ids := make([]any, len(rows))
		for i, r := range rows {
			ids[i] = recStr(r, "id")
		}
		if _, err := ctx.Auth.Adapter.DeleteMany(ctx.Context(), modelAccessToken,
			[]adapter.Where{{Field: "refreshId", Operator: adapter.In, Value: ids}}); err != nil {
			return err
		}
	}
	_, err = ctx.Auth.Adapter.DeleteMany(ctx.Context(), modelRefreshToken, where)
	return err
}

func revokeTokensIssuedForAuthorizationCode(ctx *betterauth.EndpointContext, codeID string) {
	for _, m := range []string{modelAccessToken, modelRefreshToken} {
		if _, err := ctx.Auth.Adapter.DeleteMany(ctx.Context(), m, []adapter.Where{{Field: "authorizationCodeId", Value: codeID}}); err != nil {
			ctx.Auth.Logger.Error("authorization code replay cleanup failed", err)
		}
	}
}

type issuedRefresh struct {
	id    string
	token string
}

func createRefreshToken(ctx *betterauth.EndpointContext, o *resolved, user *betterauth.User, referenceID, authorizationCodeID string,
	client *SchemaClient, scopes []string, iat, exp int64, sid string, original *TokenRecord, authTime *time.Time,
	resources []string, conf *jsonx.Object, requestedUserInfoClaims []string) (*issuedRefresh, error) {
	var token string
	var err error
	if o.GenerateRefreshToken != nil {
		token, err = o.GenerateRefreshToken()
		if err != nil {
			return nil, err
		}
	} else {
		token = bacrypto.RandomString(32, "A-Z", "a-z")
	}
	stored, err := storeToken(o, token, TokenTypeRefreshToken)
	if err != nil {
		return nil, err
	}
	row := adapter.Record{"token": stored, "clientId": client.ClientID, "userId": user.ID, "scopes": stringsToAny(scopes),
		"createdAt": time.Unix(iat, 0), "expiresAt": time.Unix(exp, 0)}
	if sid != "" {
		row["sessionId"] = sid
	}
	if referenceID != "" {
		row["referenceId"] = referenceID
	}
	if authorizationCodeID != "" {
		row["authorizationCodeId"] = authorizationCodeID
	}
	if authTime != nil {
		row["authTime"] = *authTime
	}
	if conf != nil {
		row["confirmation"] = conf
	}
	if len(requestedUserInfoClaims) > 0 {
		row["requestedUserInfoClaims"] = stringsToAny(requestedUserInfoClaims)
	}
	if resources != nil {
		row["resources"] = stringsToAny(resources)
	}
	if original != nil && original.ID != "" {
		rotatedAt := time.Unix(iat, 0)
		set := adapter.Record{"revoked": rotatedAt, "rotatedAt": rotatedAt}
		if o.RefreshTokenReuseInterval > 0 {
			set["rotationReplayExpiresAt"] = time.Unix(iat+int64(o.RefreshTokenReuseInterval), 0)
		}
		won, err := ctx.Auth.Adapter.IncrementOne(ctx.Context(), adapter.IncrementInput{Model: modelRefreshToken,
			Where:     []adapter.Where{{Field: "id", Value: original.ID}, {Field: "revoked", Operator: adapter.Eq, Value: nil}},
			Increment: map[string]float64{}, Set: set})
		if err != nil {
			return nil, err
		}
		if won == nil {
			return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid refresh token")
		}
	}
	created, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: modelRefreshToken, Data: row})
	if err != nil {
		return nil, err
	}
	enc, err := encodeRefreshToken(o, token, sid)
	if err != nil {
		return nil, err
	}
	return &issuedRefresh{id: recStr(created, "id"), token: enc}, nil
}

type grantIssuance struct {
	audience                      []string
	effectiveScopes               []string
	accessTokenExp                int64
	refreshTokenExp               int64
	refreshResources              []string
	signingAlgorithm              string
	signingKeyID                  string
	resourceCustomClaims          *jsonx.Object
	dpopBoundAccessTokensRequired bool
}

func resolveGrantIssuance(ctx *betterauth.EndpointContext, o *resolved, clientID string, requestedScopes, resources,
	originalResources []string, refresh *TokenRecord, iat, scopeExp int64) (*grantIssuance, error) {
	var resourceArg any
	if resources != nil {
		resourceArg = stringsToAny(resources)
	}
	p, err := resolveResourcePolicy(ctx, o, resourceArg, clientID, requestedScopes)
	if err != nil {
		return nil, err
	}
	resourceExp := scopeExp
	if p.accessTokenTTL != nil {
		resourceExp = iat + int64(*p.accessTokenTTL)
	}
	refreshTTL := int64(o.refreshTokenExpiresIn())
	if p.refreshTokenTTL != nil && int64(*p.refreshTokenTTL) < refreshTTL {
		refreshTTL = int64(*p.refreshTokenTTL)
	}
	g := &grantIssuance{audience: p.audience, effectiveScopes: p.effectiveScopes,
		accessTokenExp: min(scopeExp, resourceExp), refreshTokenExp: iat + refreshTTL,
		signingAlgorithm: p.signingAlgorithm, signingKeyID: p.signingKeyID, resourceCustomClaims: p.rawCustomClaims,
		dpopBoundAccessTokensRequired: p.dpopBoundAccessTokensRequired}
	switch {
	case refresh != nil && refresh.Resources != nil:
		g.refreshResources = refresh.Resources
	case originalResources != nil:
		g.refreshResources = originalResources
	default:
		g.refreshResources = resources
	}
	return g, nil
}

// requestURL returns the request URL (request.url) or baseURL + path.
func endpointURL(ctx *betterauth.EndpointContext, path string) string {
	r := ctx.Request
	if r == nil {
		return ctx.Auth.BaseURL + path
	}
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

func dpopProof(ctx *betterauth.EndpointContext) string { return ctx.GetHeader("DPoP") }

func (o *resolved) dpopMaxAge() int {
	if o.DPoP == nil {
		return 0
	}
	return o.DPoP.ProofMaxAgeSeconds
}

func (o *resolved) dpopAlgs() []string {
	if o.DPoP == nil {
		return nil
	}
	return o.DPoP.SigningAlgorithms
}

func replayStore(ctx *betterauth.EndpointContext) oauthcore.DPoPReplayStore {
	return oauthcore.NewDPoPReplayStore(ctx.Auth.InternalAdapter)
}

func clientRequiresDPoP(c *SchemaClient) bool {
	if isTrue(c.DPoPBoundAccessTokens) {
		return true
	}
	md, _ := ParseClientMetadata(c.Metadata)
	if md != nil {
		v, _ := md.Get("dpop_bound_access_tokens")
		return v == true
	}
	return false
}

func resolveDPoPTokenBinding(ctx *betterauth.EndpointContext, o *resolved, client *SchemaClient, g *grantIssuance,
	vv *VerificationValue, refresh *TokenRecord) (*jsonx.Object, error) {
	authCodeJKT := ""
	if vv != nil {
		authCodeJKT = vv.QueryString("dpop_jkt")
	}
	refreshJKT := ""
	if refresh != nil {
		refreshJKT = oauthcore.GetConfirmationJKT(refresh.Confirmation)
	}
	expected := refreshJKT
	if expected == "" {
		expected = authCodeJKT
	}
	proof := dpopProof(ctx)
	required := clientRequiresDPoP(client) || g.dpopBoundAccessTokensRequired || authCodeJKT != "" || refreshJKT != ""
	if proof == "" {
		if required {
			return nil, oauthErr("BAD_REQUEST", "invalid_dpop_proof", "DPoP proof header is required")
		}
		return nil, nil
	}
	v, err := oauthcore.VerifyDPoPProof(ctx.Context(), oauthcore.VerifyDPoPProofOptions{ProofJWT: proof, Method: "POST",
		URL: endpointURL(ctx, "/oauth2/token"), ExpectedJKT: expected, ProofMaxAgeSeconds: o.dpopMaxAge(),
		SigningAlgorithms: o.dpopAlgs(), ReplayStore: replayStore(ctx)})
	if err != nil {
		if oauthcore.IsDPoPProofError(err) {
			return nil, oauthErr("BAD_REQUEST", "invalid_dpop_proof", err.Error())
		}
		return nil, err
	}
	return jsonx.O("jkt", v.JKT), nil
}

// ---- refresh token rotation replay ----

type replayRequest struct {
	effectiveScopes    []string
	requestedResources []string
	confirmation       *jsonx.Object
}

func normalizeReplayValues(v []string) []string {
	if v == nil {
		return nil
	}
	out := uniqueStrings(v)
	sort.Slice(out, func(i, j int) bool { return jsLess(out[i], out[j]) })
	if out == nil {
		out = []string{}
	}
	return out
}

func sameReplayValues(a, b []string) bool {
	na, nb := normalizeReplayValues(a), normalizeReplayValues(b)
	if na == nil || nb == nil {
		return na == nil && nb == nil
	}
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}

func confirmationReplayKey(c *jsonx.Object) string {
	if c == nil {
		return ""
	}
	if v, ok := c.Get("jkt"); ok {
		return "jkt:" + jsString(v)
	}
	v, _ := c.Get("x5t#S256")
	return "x5t#S256:" + jsString(v)
}

func buildReplayRequest(effective, resources []string, conf *jsonx.Object) replayRequest {
	scopes := normalizeReplayValues(effective)
	if scopes == nil {
		scopes = []string{}
	}
	return replayRequest{effectiveScopes: scopes, requestedResources: normalizeReplayValues(resources), confirmation: conf}
}

func (r replayRequest) object() *jsonx.Object {
	o := jsonx.O("effectiveScopes", stringsToAny(r.effectiveScopes))
	if r.requestedResources != nil {
		o.Set("requestedResources", stringsToAny(r.requestedResources))
	}
	if r.confirmation != nil {
		o.Set("confirmation", r.confirmation)
	}
	return o
}

func sameReplayRequest(a, b replayRequest) bool {
	return sameReplayValues(a.effectiveScopes, b.effectiveScopes) &&
		sameReplayValues(a.requestedResources, b.requestedResources) &&
		confirmationReplayKey(a.confirmation) == confirmationReplayKey(b.confirmation)
}

func isConfirmationValue(v any) bool {
	o := asObject(v)
	if o == nil {
		return false
	}
	jkt, hasJKT := o.Get("jkt")
	x5t, hasX5t := o.Get("x5t#S256")
	_, jktStr := jkt.(string)
	_, x5tStr := x5t.(string)
	return (jktStr && !hasX5t) || (x5tStr && !hasJKT)
}

func isTokenResponse(v any) bool {
	o := asObject(v)
	if o == nil {
		return false
	}
	isStr := func(k string) bool { x, _ := o.Get(k); _, ok := x.(string); return ok }
	isNum := func(k string) bool { x, _ := o.Get(k); _, ok := x.(float64); return ok }
	tt, _ := o.Get("token_type")
	optStr := func(k string) bool {
		x, ok := o.Get(k)
		if !ok {
			return true
		}
		_, s := x.(string)
		return s
	}
	return isStr("access_token") && isNum("expires_in") && isNum("expires_at") && (tt == "Bearer" || tt == "DPoP") &&
		isStr("scope") && optStr("refresh_token") && optStr("id_token")
}

func parseReplay(v any) (*replayRequest, *jsonx.Object) {
	o := asObject(v)
	if o == nil {
		return nil, nil
	}
	reqV, _ := o.Get("request")
	req := asObject(reqV)
	if req == nil {
		return nil, nil
	}
	es, _ := req.Get("effectiveScopes")
	esArr, ok := es.([]any)
	if !ok {
		return nil, nil
	}
	for _, x := range esArr {
		if _, s := x.(string); !s {
			return nil, nil
		}
	}
	rr := &replayRequest{effectiveScopes: toStrings(esArr)}
	if rv, ok := req.Get("requestedResources"); ok {
		arr, isArr := rv.([]any)
		if !isArr {
			return nil, nil
		}
		for _, x := range arr {
			if _, s := x.(string); !s {
				return nil, nil
			}
		}
		rr.requestedResources = toStrings(arr)
	}
	if cv, ok := req.Get("confirmation"); ok {
		if !isConfirmationValue(cv) {
			return nil, nil
		}
		rr.confirmation = asObject(cv)
	}
	respV, _ := o.Get("response")
	if !isTokenResponse(respV) {
		return nil, nil
	}
	return rr, asObject(respV)
}

func withinReuseInterval(r *TokenRecord) bool {
	return r.RotatedAt != nil && r.RotationReplayExpiresAt != nil && !r.RotationReplayExpiresAt.Before(time.Now())
}

func storeRotationReplay(ctx *betterauth.EndpointContext, o *resolved, refresh *TokenRecord, req replayRequest, response *jsonx.Object) error {
	if o.RefreshTokenReuseInterval <= 0 {
		return nil
	}
	raw, err := jsonx.Marshal(jsonx.O("request", req.object(), "response", response))
	if err != nil {
		return err
	}
	enc, err := bacrypto.SymmetricEncrypt(ctx.Auth.SecretConfig, string(raw))
	if err != nil {
		return err
	}
	_, err = ctx.Auth.Adapter.Update(ctx.Context(), modelRefreshToken, []adapter.Where{{Field: "id", Value: refresh.ID}},
		adapter.Record{"rotationReplayResponse": enc})
	return err
}

func getRotationReplay(ctx *betterauth.EndpointContext, refresh *TokenRecord, req replayRequest) *jsonx.Object {
	if !withinReuseInterval(refresh) || refresh.RotationReplayResponse == "" {
		return nil
	}
	dec, err := bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, refresh.RotationReplayResponse)
	if err != nil {
		ctx.Auth.Logger.Error("refresh token rotation replay failed", err)
		return nil
	}
	pv, err := jsonx.Parse([]byte(dec))
	if err != nil {
		ctx.Auth.Logger.Error("refresh token rotation replay failed", err)
		return nil
	}
	rr, resp := parseReplay(pv)
	if rr == nil || !sameReplayRequest(*rr, req) {
		return nil
	}
	return resp
}

type createTokensParams struct {
	TokenIssueParams
	grantType           string
	authorizationCodeID string
}

// createUserTokens issues the access, refresh and id tokens of a grant.
func createUserTokens(ctx *betterauth.EndpointContext, o *resolved, p createTokensParams) (*jsonx.Object, error) {
	client, scopes, user := p.Client, p.Scopes, p.User
	iat := nowSeconds()
	base := o.m2mAccessTokenExpiresIn()
	if user != nil {
		base = o.accessTokenExpiresIn()
	}
	defaultExp := iat + int64(base)
	scopeExp := defaultExp
	if o.ScopeExpirations != nil {
		for _, sc := range scopes {
			e := defaultExp
			if v, ok := o.ScopeExpirations[sc]; ok && v != nil && v != 0 && v != "" {
				x, err := jwt.ToExpJWT(v, iat)
				if err != nil {
					return nil, err
				}
				e = x
			}
			if e < scopeExp {
				scopeExp = e
			}
		}
	}
	g, err := resolveGrantIssuance(ctx, o, client.ClientID, scopes, p.Resources, p.OriginalResources, p.RefreshToken, iat, scopeExp)
	if err != nil {
		return nil, err
	}
	effective := g.effectiveScopes
	exp := g.accessTokenExp
	isRefresh := user != nil && clientAllowsGrant(client, "refresh_token") &&
		((p.RefreshToken != nil && contains(p.RefreshToken.Scopes, "offline_access")) || contains(scopes, "offline_access"))
	isJWT := len(g.audience) > 0 && !o.DisableJwtPlugin
	isIDToken := user != nil && contains(effective, "openid")
	metadata, _ := ParseClientMetadata(client.Metadata)
	var additionalID *jsonx.Object
	if isIDToken {
		ext, err := collectExtensionIDTokenClaims(o, ClaimExtensionInput{Ctx: ctx, User: user, Client: client, Scopes: effective,
			GrantType: p.grantType, ReferenceID: p.ReferenceID, SessionID: p.SessionID, Resources: p.Resources, Metadata: metadata})
		if err != nil {
			return nil, err
		}
		additionalID = ext
		mergeInto(additionalID, p.IDTokenClaims)
	}
	var customFields *jsonx.Object
	if o.CustomTokenResponseFields != nil {
		customFields, err = o.CustomTokenResponseFields(TokenResponseFieldsInput{Ctx: ctx, GrantType: p.grantType, User: user,
			Scopes: effective, Metadata: metadata, VerificationValue: p.VerificationValue})
		if err != nil {
			return nil, err
		}
	}
	conf := p.Confirmation
	if conf == nil {
		conf, err = resolveDPoPTokenBinding(ctx, o, client, g, p.VerificationValue, p.RefreshToken)
		if err != nil {
			return nil, err
		}
	}
	requestedClaims := p.RequestedUserInfoClaims
	if requestedClaims == nil && p.RefreshToken != nil {
		requestedClaims = p.RefreshToken.RequestedUserInfoClaims
	}
	if requestedClaims == nil {
		requestedClaims = []string{}
	}
	var refresh *issuedRefresh
	mkRefresh := func() (*issuedRefresh, error) {
		return createRefreshToken(ctx, o, user, p.ReferenceID, p.authorizationCodeID, client, effective, iat, g.refreshTokenExp,
			p.SessionID, p.RefreshToken, p.AuthTime, g.refreshResources, conf, requestedClaims)
	}
	if isRefresh && !isJWT {
		refresh, err = mkRefresh()
		if err != nil {
			return nil, err
		}
	}
	var accessToken string
	if isJWT {
		claims, err := resolveAccessTokenClaims(accessTokenClaimsInput{ctx: ctx, opts: o, user: user, client: client,
			scopes: effective, grantType: p.grantType, sessionID: p.SessionID, resources: p.Resources,
			referenceID: p.ReferenceID, metadata: metadata, perRequestClaims: p.AccessTokenClaims,
			resourcePolicyClaims: g.resourceCustomClaims})
		if err != nil {
			return nil, err
		}
		accessToken, err = createJwtAccessToken(ctx, o, user, client, g.audience, effective, iat, exp, p.SessionID,
			g.signingAlgorithm, g.signingKeyID, claims, conf)
		if err != nil {
			return nil, err
		}
		if isRefresh {
			refresh, err = mkRefresh()
			if err != nil {
				return nil, err
			}
		}
	} else {
		refreshID := ""
		if refresh != nil {
			refreshID = refresh.id
		}
		accessToken, err = createOpaqueAccessToken(ctx, o, user, client, effective, iat, exp, p.SessionID, p.Resources,
			p.ReferenceID, p.authorizationCodeID, refreshID, conf, requestedClaims)
		if err != nil {
			return nil, err
		}
	}
	idToken := ""
	if isIDToken {
		idToken, err = createIDToken(ctx, o, user, client, effective, p.Nonce, p.SessionID, p.AuthTime, accessToken, additionalID)
		if err != nil {
			return nil, err
		}
	}
	body := jsonx.NewObject()
	mergeInto(body, customFields)
	mergeInto(body, p.TokenResponse)
	body.Set("access_token", accessToken)
	body.Set("expires_in", exp-iat)
	body.Set("expires_at", exp)
	body.Set("token_type", confirmationTokenType(conf))
	if refresh != nil {
		body.Set("refresh_token", refresh.token)
	} else {
		body.Set("refresh_token", jsonx.Undefined)
	}
	body.Set("scope", strings.Join(effective, " "))
	if idToken != "" {
		body.Set("id_token", idToken)
	} else {
		body.Set("id_token", jsonx.Undefined)
	}
	if p.RefreshToken != nil && p.RefreshToken.ID != "" && refresh != nil && refresh.id != "" {
		if err := storeRotationReplay(ctx, o, p.RefreshToken, buildReplayRequest(effective, p.Resources, conf), body); err != nil {
			ctx.Auth.Logger.Error("failed to store refresh token rotation replay", err)
		}
	}
	return body, nil
}

type checkedCode struct {
	value               *VerificationValue
	effectiveResources  []string
	authorizedResources []string
	codeID              string
}

func parseVerificationValue(raw string) (*VerificationValue, error) {
	pv, err := jsonx.Parse([]byte(raw))
	if err != nil {
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "malformed verification value")
	}
	parsed, issues := zParse(verificationValueSchema, pv)
	if len(issues) > 0 {
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "malformed verification value")
	}
	o := parsed.(*jsonx.Object)
	vv := &VerificationValue{Type: "authorization_code", Raw: o}
	q, _ := o.Get("query")
	vv.Query, _ = q.(*jsonx.Object)
	vv.SessionID = objString(o, "sessionId")
	vv.UserID = objString(o, "userId")
	vv.ReferenceID = objString(o, "referenceId")
	if at, ok := o.Get("authTime"); ok {
		if f, isNum := at.(float64); isNum {
			vv.AuthTime = &f
		}
	}
	if r, ok := o.Get("resource"); ok {
		vv.Resource = toStrings(r)
	}
	return vv, nil
}

func checkVerificationValue(ctx *betterauth.EndpointContext, o *resolved, code, clientID, redirectURI string, resources []string) (*checkedCode, error) {
	codeID, err := storeToken(o, code, TokenTypeAuthorizationCode)
	if err != nil {
		return nil, err
	}
	v, err := ctx.Auth.InternalAdapter.ConsumeVerificationValue(ctx.Context(), codeID)
	if err != nil {
		return nil, err
	}
	if v == nil {
		revokeTokensIssuedForAuthorizationCode(ctx, codeID)
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid code")
	}
	vv, err := parseVerificationValue(v.Value)
	if err != nil {
		return nil, err
	}
	if vv.QueryString("client_id") != clientID {
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid client_id")
	}
	bound := vv.QueryString("redirect_uri")
	if bound != "" {
		if redirectURI == "" {
			return nil, oauthErr("BAD_REQUEST", "invalid_request", "redirect_uri is required")
		}
		if bound != redirectURI {
			return nil, oauthErr("BAD_REQUEST", "invalid_grant", "redirect_uri mismatch")
		}
	} else if redirectURI != "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "redirect_uri mismatch")
	}
	stored := toResourceList(stringsToAnyOrNil(vv.Resource))
	if stored == nil && vv.Query != nil {
		rv, _ := vv.Query.Get("resource")
		stored = toResourceList(rv)
	}
	effective := resources
	if effective == nil {
		effective = stored
	}
	if resources != nil && stored != nil {
		for _, r := range uniqueStrings(resources) {
			if !contains(stored, r) {
				return nil, oauthErr("BAD_REQUEST", "invalid_target", "requested resource not authorized")
			}
		}
	}
	return &checkedCode{value: vv, effectiveResources: effective, authorizedResources: stored, codeID: codeID}, nil
}

func stringsToAnyOrNil(v []string) any {
	if v == nil {
		return nil
	}
	return stringsToAny(v)
}

func handleAuthorizationCodeGrant(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	creds, err := extractClientCredentials(ctx, o, ctx.Auth.BaseURL+"/oauth2/token")
	if err != nil {
		return nil, err
	}
	clientID, secret, preVerified, method, _ := creds.destructure()
	body := bodyMap(ctx)
	code, _ := body["code"].(string)
	verifier, _ := body["code_verifier"].(string)
	redirectURI, _ := body["redirect_uri"].(string)
	resources := toResourceList(body["resource"])
	if clientID == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "client_id is required")
	}
	if code == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "code is required")
	}
	withSecret := secret != ""
	withPKCE := verifier != ""
	if !withSecret && !withPKCE && !preVerified {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "Either code_verifier or client_secret is required")
	}
	checked, err := checkVerificationValue(ctx, o, code, clientID, redirectURI, resources)
	if err != nil {
		return nil, err
	}
	vv := checked.value
	scopeV, hasScope := vv.Query.Get("scope")
	scopeStr, _ := scopeV.(string)
	if !hasScope || scopeV == nil {
		return nil, oauthErr("INTERNAL_SERVER_ERROR", "invalid_scope", "verification scope unset")
	}
	scopes := strings.Split(scopeStr, " ")
	client, err := validateClientCredentials(ctx, o, clientID, secret, scopes, preVerified, "authorization_code", method)
	if err != nil {
		return nil, err
	}
	if reason := isPKCERequired(client, scopes, vv.QueryString("nonce")); reason != "" {
		if !withPKCE {
			return nil, oauthErr("BAD_REQUEST", "invalid_request", "PKCE is required for this client")
		}
	} else if !(withPKCE || withSecret || preVerified) {
		return nil, oauthErr("BAD_REQUEST", "invalid_request",
			"Either PKCE (code_verifier) or client authentication (client_secret or client_assertion) is required")
	}
	inAuth := vv.QueryString("code_challenge") != ""
	if inAuth || withPKCE {
		if inAuth && !withPKCE {
			return nil, oauthErr("UNAUTHORIZED", "invalid_request", "code_verifier required because PKCE was used in authorization")
		}
		if !inAuth && withPKCE {
			return nil, oauthErr("UNAUTHORIZED", "invalid_request", "code_verifier provided but PKCE was not used in authorization")
		}
		challenge := ""
		if vv.QueryString("code_challenge_method") == "S256" {
			sum := sha256.Sum256([]byte(verifier))
			challenge = base64.RawURLEncoding.EncodeToString(sum[:])
		}
		if challenge != vv.QueryString("code_challenge") {
			return nil, oauthErr("UNAUTHORIZED", "invalid_request", "code verification failed")
		}
	}
	if vv.UserID == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_user", "missing user, user may have been deleted")
	}
	user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), vv.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, oauthErr("BAD_REQUEST", "invalid_user", "missing user, user may have been deleted")
	}
	sess, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "session",
		Where: []adapter.Where{{Field: "id", Value: vv.SessionID}}})
	if err != nil {
		return nil, err
	}
	sessExp := recTime(sess, "expiresAt")
	if sess == nil || (sessExp != nil && sessExp.Before(time.Now())) {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "session no longer exists")
	}
	var authTime *time.Time
	if vv.AuthTime != nil {
		authTime = normalizeTimestampValue(*vv.AuthTime)
	} else {
		authTime = resolveSessionAuthTime(sess)
	}
	cv, _ := vv.Query.Get("claims")
	requested := getRequestedUserInfoClaims(cv, o.supportedClaims())
	return createUserTokens(ctx, o, createTokensParams{TokenIssueParams: TokenIssueParams{
		Client: client, Scopes: scopes, User: user, ReferenceID: vv.ReferenceID, SessionID: recStr(sess, "id"),
		Nonce: vv.QueryString("nonce"), AuthTime: authTime, VerificationValue: vv, RequestedUserInfoClaims: requested,
		Resources: checked.effectiveResources, OriginalResources: checked.authorizedResources,
	}, grantType: "authorization_code", authorizationCodeID: checked.codeID})
}

func handleClientCredentialsGrant(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	creds, err := extractClientCredentials(ctx, o, ctx.Auth.BaseURL+"/oauth2/token")
	if err != nil {
		return nil, err
	}
	clientID, secret, preVerified, method, _ := creds.destructure()
	body := bodyMap(ctx)
	resources := toResourceList(body["resource"])
	if clientID == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "Missing required client_id")
	}
	client, err := validateClientCredentials(ctx, o, clientID, secret, nil, preVerified, "client_credentials", method)
	if err != nil {
		return nil, err
	}
	if client.TokenEndpointAuthMethod == "none" {
		return nil, oauthErr("BAD_REQUEST", "unauthorized_client", "public clients cannot use the client_credentials grant")
	}
	ccScopes := client.ClientCredentialsScopes
	if len(ccScopes) == 0 {
		return nil, oauthErr("BAD_REQUEST", "unauthorized_client", "client has no authorized client_credentials scopes")
	}
	var requested []string
	if s, ok := body["scope"].(string); ok {
		requested = strings.Split(s, " ")
		var invalid []string
		for _, sc := range requested {
			if !contains(ccScopes, sc) || isUserDelegatedScope(sc) {
				invalid = append(invalid, sc)
			}
		}
		if len(invalid) > 0 {
			return nil, oauthErr("BAD_REQUEST", "invalid_scope", "The following scopes are invalid: "+strings.Join(invalid, ", "))
		}
	} else {
		requested = append([]string{}, ccScopes...)
	}
	return createUserTokens(ctx, o, createTokensParams{TokenIssueParams: TokenIssueParams{Client: client, Scopes: requested,
		Resources: resources}, grantType: "client_credentials"})
}

func handleRefreshTokenGrant(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	creds, err := extractClientCredentials(ctx, o, ctx.Auth.BaseURL+"/oauth2/token")
	if err != nil {
		return nil, err
	}
	clientID, secret, preVerified, method, _ := creds.destructure()
	body := bodyMap(ctx)
	refreshTokenStr, _ := body["refresh_token"].(string)
	resources := toResourceList(body["resource"])
	if clientID == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "Missing required client_id")
	}
	if refreshTokenStr == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "Missing a required refresh_token for refresh_token grant")
	}
	decoded, err := decodeRefreshToken(o, refreshTokenStr)
	if err != nil {
		return nil, err
	}
	stored, err := storeToken(o, decoded.Token, TokenTypeRefreshToken)
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
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "session not found")
	}
	if rt.ClientID != clientID {
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid refresh token")
	}
	if rt.ExpiresAt != nil && rt.ExpiresAt.Before(time.Now()) {
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid refresh token")
	}
	if resources != nil && rt.Resources != nil {
		for _, r := range resources {
			if !contains(rt.Resources, r) {
				return nil, oauthErr("BAD_REQUEST", "invalid_target", "requested resource invalid")
			}
		}
	}
	scopes := rt.Scopes
	var requested []string
	if s, ok := body["scope"].(string); ok {
		requested = strings.Split(s, " ")
		for _, sc := range requested {
			if !contains(scopes, sc) {
				return nil, oauthErr("BAD_REQUEST", "invalid_scope", "unable to issue scope "+sc)
			}
		}
	}
	effectiveScopes := requested
	if effectiveScopes == nil {
		effectiveScopes = scopes
	}
	client, err := validateClientCredentials(ctx, o, clientID, secret, effectiveScopes, preVerified, "refresh_token", method)
	if err != nil {
		return nil, err
	}
	effectiveResources := resources
	if effectiveResources == nil {
		effectiveResources = rt.Resources
	}
	if rt.Revoked != nil {
		if withinReuseInterval(rt) {
			iat := nowSeconds()
			g, err := resolveGrantIssuance(ctx, o, client.ClientID, effectiveScopes, effectiveResources, nil, rt, iat,
				iat+int64(o.accessTokenExpiresIn()))
			if err != nil {
				return nil, err
			}
			conf, err := resolveDPoPTokenBinding(ctx, o, client, g, nil, rt)
			if err != nil {
				return nil, err
			}
			req := buildReplayRequest(g.effectiveScopes, effectiveResources, conf)
			if resp := getRotationReplay(ctx, rt, req); resp != nil {
				out := resp.Clone()
				expAt, _ := resp.Get("expires_at")
				ea, _ := expAt.(float64)
				out.Set("expires_in", math.Max(0, ea-float64(nowSeconds())))
				return out, nil
			}
			return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid refresh token")
		}
		if err := invalidateRefreshFamily(ctx, clientID, rt.UserID); err != nil {
			return nil, err
		}
		return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid refresh token")
	}
	user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), rt.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "user not found")
	}
	return createUserTokens(ctx, o, createTokensParams{TokenIssueParams: TokenIssueParams{
		Client: client, Scopes: effectiveScopes, User: user, ReferenceID: rt.ReferenceID, SessionID: rt.SessionID,
		RefreshToken: rt, Resources: effectiveResources, AuthTime: rt.AuthTime, RequestedUserInfoClaims: rt.RequestedUserInfoClaims,
	}, grantType: "refresh_token", authorizationCodeID: rt.AuthorizationCodeID})
}

var userDelegatedScopes = map[string]bool{"openid": true, "profile": true, "email": true, "offline_access": true}

func isUserDelegatedScope(s string) bool { return userDelegatedScopes[s] }
