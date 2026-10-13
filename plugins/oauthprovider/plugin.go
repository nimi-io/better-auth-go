// Package oauthprovider is a port of Better Auth's @better-auth/oauth-provider plugin
// (v1.7.7): it turns the application into an OAuth 2.1 authorization server and OpenID
// Connect provider.
//
// Endpoints: /oauth2/authorize (PKCE, consent, prompts, login redirects), /oauth2/token
// (authorization_code, refresh_token, client_credentials and extension grants such as the
// device code grant), /oauth2/introspect, /oauth2/revoke, /oauth2/userinfo,
// /oauth2/end-session (RP-initiated logout, plus back-channel logout), /oauth2/register
// (dynamic client registration), client / consent / resource management endpoints and the
// discovery documents (/.well-known/openid-configuration and
// /.well-known/oauth-authorization-server, served from the issuer path).
//
// Companion packages (mcp, cimd) use the exported helpers: ExtendOAuthProvider,
// GetIssuer, MetadataResponse, CreateResourceServerChallenge, GetOAuthProviderAPI,
// ConsumeClientAssertion, RegisterClientMetadataDocument, ValidatePublicClientJwks,
// IsForbiddenCimdClientMetadataField, OAuthClientMetadataSchema (ValidateClientMetadata),
// VerifyOAuthQueryParams and the oauthcore subpackage (access-token verification, DPoP).
package oauthprovider

import (
	"context"
	_ "embed"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Version is the upstream package version.
const Version = "1.7.7"

//go:embed openapi.json
var openapiJSON []byte

var openapiSpecs = func() *jsonx.Object {
	v, err := jsonx.Parse(openapiJSON)
	if err != nil {
		panic(err)
	}
	return v.(*jsonx.Object)
}()

func openapiMeta(key string, extra map[string]any) map[string]any {
	m := map[string]any{}
	if v, ok := openapiSpecs.Get(key); ok {
		m["openapi"] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func pluginOptions(ac *betterauth.AuthContext) (*resolved, error) {
	p := ac.GetPlugin("oauth-provider")
	if p == nil {
		return nil, errors.New("oauth-provider plugin is not registered")
	}
	o, ok := p.Options.(*resolved)
	if !ok {
		return nil, errors.New("oauth-provider plugin is not registered")
	}
	return o, nil
}

// ---- endpoint body schemas ----

var consentBody = zObject("strip", nil,
	zf("accept", zBool()),
	zf("scope", zOptional(zString())),
	zf("claims", zOptional(claimsRequestParameter())),
	zf("oauth_query", zOptional(zString())),
)

var continueBody = zObject("strip", nil,
	zf("selected", zOptional(zBool())),
	zf("created", zOptional(zBool())),
	zf("postLogin", zOptional(zBool())),
	zf("oauth_query", zOptional(zString())),
)

var tokenBody = zObject("loose", nil,
	zf("grant_type", zString(trimCheck(), minLen(1, ""))),
	zf("client_id", zOptional(zString())),
	zf("client_secret", zOptional(zString())),
	zf("client_assertion", zOptional(zString())),
	zf("client_assertion_type", zOptional(zString())),
	zf("code", zOptional(zString())),
	zf("code_verifier", zOptional(zString())),
	zf("redirect_uri", zOptional(safeURL())),
	zf("refresh_token", zOptional(zString())),
	zf("resource", zOptional(resourceParam())),
	zf("scope", zOptional(zString())),
)

var tokenFieldErrors = map[string]fieldErrorCodes{
	"grant_type": {Missing: "invalid_request", Invalid: "unsupported_grant_type"},
	"resource":   {Invalid: "invalid_target"},
}

var introspectBody = zObject("strip", nil,
	zf("client_id", zOptional(zString())),
	zf("client_secret", zOptional(zString())),
	zf("client_assertion", zOptional(zString())),
	zf("client_assertion_type", zOptional(zString())),
	zf("token", zString()),
	zf("token_type_hint", zOptional(zString())),
)

var userInfoBody = zOptional(zObject("loose", nil, zf("access_token", zOptional(zString()))))

var logoutRequestSchema = zOptional(zObject("strip", nil,
	zf("id_token_hint", zOptional(zString())),
	zf("client_id", zOptional(zString())),
	zf("post_logout_redirect_uri", zOptional(safeURL())),
	zf("state", zOptional(zString())),
))

var logoutConfirmBody = zObject("strip", nil, zf("action", zLiteral("confirm")))

var registerFieldErrors = map[string]fieldErrorCodes{
	"redirect_uris":             {All: "invalid_redirect_uri"},
	"post_logout_redirect_uris": {All: "invalid_redirect_uri"},
	"software_statement":        {All: "invalid_software_statement"},
	"resources":                 {All: "invalid_target"},
}

func clientMetadataFields(admin bool) []zField {
	fs := []zField{
		zf("redirect_uris", zOptional(zArray(safeURL(), 1))),
		zf("scope", zOptional(zString())),
		zf("client_name", zOptional(zString())),
		zf("client_uri", zOptional(zString())),
		zf("logo_uri", zOptional(zString())),
		zf("contacts", zOptional(zArray(zString(minLen(1, "")), 1))),
		zf("tos_uri", zOptional(zString())),
		zf("policy_uri", zOptional(zString())),
		zf("software_id", zOptional(zString())),
		zf("software_version", zOptional(zString())),
		zf("software_statement", zOptional(zString())),
		zf("post_logout_redirect_uris", zOptional(zArray(safeURL(), 1))),
		zf("backchannel_logout_uri", zOptional(safeURL())),
		zf("backchannel_logout_session_required", zOptional(zBool())),
		zf("token_endpoint_auth_method", zOptional(zString(trimCheck(), minLen(1, "")))),
		zf("application_type", zOptional(zEnum("web", "native"))),
		zf("jwks", zOptional(clientJwksSchema())),
		zf("jwks_uri", zOptional(zString())),
		zf("grant_types", zOptional(zArray(zString(trimCheck(), minLen(1, "")), 1))),
	}
	if admin {
		fs = append(fs,
			zf("client_credentials_scopes", zOptional(zArray(zString(trimCheck(), minLen(1, "")), 0))),
			zf("response_types", zOptional(zArray(zEnum("code"), 0))),
			zf("client_secret_expires_at", zDefault(zUnion(zString(), zNumber(false, false, false)), 0.0)),
			zf("skip_consent", zOptional(zBool())),
			zf("enable_end_session", zOptional(zBool())),
			zf("require_pkce", zOptional(zBool())),
			zf("dpop_bound_access_tokens", zOptional(zBool())),
			zf("subject_type", zOptional(zEnum("public", "pairwise"))),
			zf("metadata", zOptional(zRecord(zUnknown()))),
		)
	} else {
		fs = append(fs,
			zf("response_types", zOptional(zArray(zEnum("code"), 0))),
			zf("dpop_bound_access_tokens", zOptional(zBool())),
		)
	}
	return fs
}

func updateFields(admin bool) []zField {
	fs := []zField{
		zf("redirect_uris", zOptional(zArray(safeURL(), 1))),
		zf("scope", zOptional(zString())),
		zf("client_name", zOptional(zString())),
		zf("client_uri", zOptional(zString())),
		zf("logo_uri", zOptional(zString())),
		zf("contacts", zOptional(zArray(zString(minLen(1, "")), 1))),
		zf("tos_uri", zOptional(zString())),
		zf("policy_uri", zOptional(zString())),
		zf("software_id", zOptional(zString())),
		zf("software_version", zOptional(zString())),
		zf("software_statement", zOptional(zString())),
		zf("post_logout_redirect_uris", zOptional(zArray(safeURL(), 1))),
		zf("backchannel_logout_uri", zOptional(safeURL())),
		zf("backchannel_logout_session_required", zOptional(zBool())),
		zf("application_type", zOptional(zEnum("web", "native"))),
		zf("grant_types", zOptional(zArray(zString(trimCheck(), minLen(1, "")), 1))),
	}
	if admin {
		fs = append(fs,
			zf("client_credentials_scopes", zOptional(zArray(zString(trimCheck(), minLen(1, "")), 0))),
			zf("response_types", zOptional(zArray(zEnum("code"), 0))),
			zf("client_secret_expires_at", zOptional(zUnion(zString(), zNumber(false, false, false)))),
			zf("skip_consent", zOptional(zBool())),
			zf("enable_end_session", zOptional(zBool())),
			zf("dpop_bound_access_tokens", zOptional(zBool())),
			zf("metadata", zOptional(zRecord(zUnknown()))),
		)
	} else {
		fs = append(fs, zf("response_types", zOptional(zArray(zEnum("code"), 0))))
	}
	return fs
}

var resourceBodyFields = []zField{
	zf("identifier", zOptional(zString(minLen(1, "")))),
	zf("name", zOptional(zString())),
	zf("accessTokenTtl", zOptional(zNullable(zNumber(true, true, false)))),
	zf("refreshTokenTtl", zOptional(zNullable(zNumber(true, true, false)))),
	zf("signingAlgorithm", zOptional(zNullable(zEnum(JWSAlgorithms...)))),
	zf("signingKeyId", zOptional(zNullable(zString()))),
	zf("allowedScopes", zOptional(zNullable(zArray(zString(), 0)))),
	zf("customClaims", zOptional(zNullable(zRecord(zUnknown())))),
	zf("dpopBoundAccessTokensRequired", zOptional(zBool())),
	zf("disabled", zOptional(zBool())),
	zf("metadata", zOptional(zNullable(zRecord(zUnknown())))),
}

func requiredIdentifierFields() []zField {
	out := append([]zField(nil), resourceBodyFields...)
	out[0] = zf("identifier", zString(minLen(1, "")))
	return out
}

func clientIDBody() validate.Schema {
	return toValidate(zObject("strip", nil, zf("client_id", zString())))
}

// ---- plugin ----

// New creates the oauth-provider plugin. Invalid options make betterauth.New fail.
func New(options Options) *betterauth.Plugin {
	o, optErr := resolveOptions(options)
	if optErr != nil {
		o = &resolved{Options: options}
		o.Scopes = DefaultOAuthScopes
		o.GrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	var authorizeEP *betterauth.Endpoint
	// authorize re-runs /oauth2/authorize for continuations (consent, continue, sign-in)
	// with the configured hooks, like upstream's dispatchAuthEndpoint.
	authorize := func(ctx *betterauth.EndpointContext, settings authorizeSettings, query *jsonx.Object) (any, error) {
		if authorizeEP == nil {
			return authorizeEndpoint(ctx, o, settings, query)
		}
		return betterauth.OAuthProviderDispatch(ctx, authorizeEP, objectToMap(query), func(child *betterauth.EndpointContext) (any, error) {
			return authorizeEndpoint(child, o, settings, query)
		})
	}
	p := &betterauth.Plugin{
		ID:      "oauth-provider",
		Version: Version,
		Options: o,
		Schema:  Schema(options.Schema),
	}
	p.OnRequest = func(r *http.Request, ac *betterauth.AuthContext) (*http.Request, *betterauth.Response, error) {
		return nil, handleIssuerMetadataRequest(r, ac, o), nil
	}
	p.Init = func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
		if optErr != nil {
			return nil, optErr
		}
		so := ac.Options.Session
		if ac.Options.SecondaryStorage != nil && (so == nil || !so.StoreSessionInDatabase) {
			return nil, errors.New("OAuth Provider requires `session.storeSessionInDatabase: true` when using secondaryStorage")
		}
		if err := seedResources(contextBackground(), ac, o); err != nil && err != errSeedDeferred {
			return nil, err
		}
		enforce, source := resolveEnforcePerClient(o)
		ac.Logger.Info("oauth-provider: enforcePerClientResources resolved to " + boolString(enforce) + " (" + source + ")")
		if !o.DisableJwtPlugin {
			jo, err := jwtOptions(ac)
			if err != nil {
				return nil, err
			}
			issuer := jwtIssuer(jo)
			if issuer == "" {
				issuer = ac.BaseURL
			}
			dynamic := jwtIssuer(jo) == "" && ac.Options.DynamicBaseURL != nil
			if _, err := parseURL(issuer); err != nil && (!dynamic || issuer != "") {
				return nil, errors.New("Invalid URL")
			}
		}
		return &betterauth.PluginInit{DatabaseHooks: &betterauth.DatabaseHooks{
			Session: betterauth.DBModelHooks{Delete: sessionDeleteHooks(o)},
		}}, nil
	}
	p.Hooks = betterauth.PluginHooks{
		Before: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool {
				return validate.Truthy(bodyMap(ctx)["oauth_query"])
			},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				q, _ := bodyMap(ctx)["oauth_query"].(string)
				if !VerifyOAuthQueryParams(q, ctx.Auth.Secret) {
					return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "invalid_signature"))
				}
				issuedAt := getSignedQueryIssuedAt(q)
				params := parseSearchParams(q)
				cleared := params.getString(postLoginClearedParam)
				params.delete("sig")
				params.delete("exp")
				params.delete(signedQueryIssuedAtParam)
				params.delete(postLoginClearedParam)
				setOAuthProviderState(ctx, &OAuthProviderState{Query: params.String(), SignedQueryIssuedAt: issuedAt,
					PostLoginClearedForSession: cleared})
				if ctx.Path == "/sign-in/social" {
					sc := map[string]any{"query": params.String()}
					if issuedAt != nil {
						sc["signedQueryIssuedAtMs"] = float64(issuedAt.UnixMilli())
					}
					betterauth.AddOAuthServerContext(ctx.Context(), sc)
				}
				return nil, nil
			},
		}},
		After: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool {
				return sessionTokenFromSetCookie(ctx) != ""
			},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				return afterSignIn(ctx, o, authorize)
			},
		}},
	}
	p.Endpoints = endpoints(o, authorize)
	for _, ep := range p.Endpoints {
		if ep.Key == "oauth2Authorize" {
			authorizeEP = ep
		}
	}
	p.RateLimit = rateLimits(o)
	return p
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func sessionTokenFromSetCookie(ctx *betterauth.EndpointContext) string {
	name := ctx.Auth.AuthCookies.SessionToken.Name
	value := ""
	for _, sc := range ctx.ResponseHeaders.Values("Set-Cookie") {
		n, v, _ := betterauth.ParseSetCookie(sc)
		if n == name {
			value = v
		}
	}
	if value == "" {
		return ""
	}
	return strings.Split(value, ".")[0]
}

func afterSignIn(ctx *betterauth.EndpointContext, o *resolved, authorize authorizeCaller) (any, error) {
	token := sessionTokenFromSetCookie(ctx)
	if token == "" {
		return nil, nil
	}
	state := GetOAuthProviderState(ctx)
	var serverContext map[string]any
	if st := betterauth.GetOAuthState(ctx.Context()); st != nil {
		serverContext = st.ServerContext
	}
	query := ""
	if state != nil && state.Query != "" {
		query = state.Query
	} else if serverContext != nil {
		query, _ = serverContext["query"].(string)
	}
	if query == "" {
		return nil, nil
	}
	session, err := ctx.Auth.InternalAdapter.FindSession(ctx.Context(), token)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, nil
	}
	ctx.Session = session
	var h http.Header
	if ctx.Request != nil {
		h = ctx.Request.Header
	}
	mode := ""
	accept := ""
	if h != nil {
		mode = strings.ToLower(h.Get("Sec-Fetch-Mode"))
		accept = strings.ToLower(h.Get("Accept"))
	}
	navigation := mode == "navigate" || (mode == "" && (strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")))
	if !navigation {
		setAcceptJSON(ctx)
	}
	var issuedAt *time.Time
	if state != nil && state.SignedQueryIssuedAt != nil {
		issuedAt = state.SignedQueryIssuedAt
	} else if serverContext != nil {
		issuedAt = serverContextIssuedAt(serverContext["signedQueryIssuedAtMs"])
	}
	q := removePromptFromQuery(parseSearchParams(query), "login")
	if isSessionFreshForSignedQuery(session.Session.CreatedAt, issuedAt) {
		q = removeMaxAgeFromQuery(q)
	}
	return authorize(ctx, authorizeSettings{}, searchParamsToQuery(q))
}

func serverContextIssuedAt(v any) *time.Time {
	var ms float64
	switch t := v.(type) {
	case float64:
		ms = t
	case int64:
		ms = float64(t)
	case int:
		ms = float64(t)
	case string:
		ms = jsNumber(t)
	default:
		return nil
	}
	if ms != ms || ms <= 0 {
		return nil
	}
	tm := time.UnixMilli(int64(ms))
	return &tm
}

func handleIssuerMetadataRequest(r *http.Request, ac *betterauth.AuthContext, o *resolved) *betterauth.Response {
	reqPath := r.URL.EscapedPath()
	if ac.Options.Advanced != nil && ac.Options.Advanced.SkipTrailingSlashes {
		reqPath = strings.TrimRight(reqPath, "/")
		if reqPath == "" {
			reqPath = "/"
		}
	}
	issuer := ac.BaseURL
	if !o.DisableJwtPlugin {
		if jo, err := jwtOptions(ac); err == nil && jwtIssuer(jo) != "" {
			issuer = jwtIssuer(jo)
		}
	}
	issuerPath := ""
	if u, err := parseURL(issuer); err == nil {
		issuerPath = strings.TrimSuffix(u.EscapedPath(), "/")
	} else if u, err := parseURL(ac.BaseURL); err == nil {
		issuerPath = strings.TrimSuffix(u.EscapedPath(), "/")
	}
	isAS := reqPath == "/.well-known/oauth-authorization-server"+issuerPath || reqPath == issuerPath+"/.well-known/oauth-authorization-server"
	isOIDC := o.hasScope("openid") && reqPath == issuerPath+"/.well-known/openid-configuration"
	if !isAS && !isOIDC {
		return nil
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h := http.Header{}
		h.Set("Allow", "GET, HEAD")
		return &betterauth.Response{Status: 405, Header: h}
	}
	ctx := &betterauth.EndpointContext{Auth: ac, Request: r, Headers: r.Header}
	var doc *jsonx.Object
	var err error
	if isAS && !o.hasScope("openid") {
		doc, err = oauthAuthorizationServerMetadata(ctx, o)
	} else {
		doc, err = oidcServerMetadata(ctx, o)
	}
	if err != nil {
		ac.Logger.Error("oauth-provider metadata error", err)
		return &betterauth.Response{Status: 500, Header: http.Header{}}
	}
	res := MetadataResponse(doc, nil)
	if r.Method == http.MethodHead {
		res.Body = nil
	}
	return res
}

func rateLimits(o *resolved) []betterauth.PluginRateLimit {
	var rl RateLimitOptions
	if o.RateLimit != nil {
		rl = *o.RateLimit
	}
	var out []betterauth.PluginRateLimit
	add := func(r *RateLimitRule, path string, window, max int) {
		if r != nil && r.Disabled {
			return
		}
		if r != nil {
			window, max = r.Window, r.Max
		}
		out = append(out, betterauth.PluginRateLimit{Window: time.Duration(window) * time.Second, Max: max,
			PathMatcher: func(p string) bool { return p == path }})
	}
	add(rl.Token, "/oauth2/token", 60, 20)
	add(rl.Authorize, "/oauth2/authorize", 60, 30)
	add(rl.Introspect, "/oauth2/introspect", 60, 100)
	add(rl.Revoke, "/oauth2/revoke", 60, 30)
	add(rl.Register, "/oauth2/register", 60, 5)
	add(rl.UserInfo, "/oauth2/userinfo", 60, 60)
	return out
}

var formOnly = []string{"application/x-www-form-urlencoded"}

func endpoints(o *resolved, authorize authorizeCaller) []*betterauth.Endpoint {
	h := func(f func(ctx *betterauth.EndpointContext, o *resolved) (any, error)) func(*betterauth.EndpointContext) (any, error) {
		return func(ctx *betterauth.EndpointContext) (any, error) { return f(ctx, o) }
	}
	return []*betterauth.Endpoint{
		{Key: "getOAuthServerConfig", Path: "/.well-known/oauth-authorization-server", Methods: []string{"GET"}, ServerOnly: true,
			Metadata: map[string]any{"SERVER_ONLY": true},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if o.hasScope("openid") {
					return oidcServerMetadata(ctx, o)
				}
				return oauthAuthorizationServerMetadata(ctx, o)
			}},
		{Key: "getOpenIdConfig", Path: "/.well-known/openid-configuration", Methods: []string{"GET"}, ServerOnly: true,
			Metadata: map[string]any{"SERVER_ONLY": true},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if !o.hasScope("openid") {
					return nil, apiErr("NOT_FOUND")
				}
				return oidcServerMetadata(ctx, o)
			}},
		{Key: "oauth2Authorize", Path: "/oauth2/authorize", Methods: []string{"GET", "POST"}, AllowedMediaTypes: formOnly,
			Metadata: openapiMeta("oauth2Authorize", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				raw := requestQueryObject(ctx)
				if b := bodyValue(ctx); !isUndef(b) {
					if _, issues := zParse(zObject("loose", nil), b); len(issues) > 0 {
						code, desc := mapIssuesToOAuthError(issues, nil, "")
						return authorizeRedirectOnError(ctx, o, raw, code, desc)
					}
				}
				query := raw
				if ctx.Method == "POST" {
					query = requestBodyObject(ctx)
				}
				return authorizeEndpoint(ctx, o, authorizeSettings{isAuthorize: true}, query)
			}},
		{Key: "oauth2Consent", Path: "/oauth2/consent", Methods: []string{"POST"}, Body: toValidate(consentBody),
			Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: openapiMeta("oauth2Consent", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) { return consentEndpoint(ctx, o, authorize) }},
		{Key: "oauth2Continue", Path: "/oauth2/continue", Methods: []string{"POST"}, Body: toValidate(continueBody),
			Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: openapiMeta("oauth2Continue", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) { return continueEndpoint(ctx, authorize) }},
		{Key: "oauth2Token", Path: "/oauth2/token", Methods: []string{"POST"}, AllowedMediaTypes: formOnly,
			Metadata: openapiMeta("oauth2Token", map[string]any{"openapiBodySchema": toValidate(tokenBody)}),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if _, err := validateOAuthBody(ctx, tokenBody, tokenFieldErrors, ""); err != nil {
					return nil, err
				}
				setNoStore(ctx)
				if rep := extractRepeatedResourceFromForm(ctx); len(rep) > 1 {
					bodyMap(ctx)["resource"] = stringsToAny(rep)
				}
				return tokenEndpoint(ctx, o)
			}},
		{Key: "oauth2Introspect", Path: "/oauth2/introspect", Methods: []string{"POST"}, AllowedMediaTypes: formOnly,
			Metadata: openapiMeta("oauth2Introspect", map[string]any{"openapiBodySchema": toValidate(introspectBody)}),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if _, err := validateOAuthBody(ctx, introspectBody, nil, ""); err != nil {
					return nil, err
				}
				setNoStore(ctx)
				return introspectEndpoint(ctx, o)
			}},
		{Key: "oauth2Revoke", Path: "/oauth2/revoke", Methods: []string{"POST"}, AllowedMediaTypes: formOnly,
			Metadata: openapiMeta("oauth2Revoke", map[string]any{"openapiBodySchema": toValidate(introspectBody)}),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if _, err := validateOAuthBody(ctx, introspectBody, nil, ""); err != nil {
					return nil, err
				}
				return revokeEndpoint(ctx, o)
			}},
		{Key: "oauth2UserInfo", Path: "/oauth2/userinfo", Methods: []string{"GET", "POST"}, NoStore: true, AllowedMediaTypes: formOnly,
			Body: toValidate(userInfoBody), Metadata: openapiMeta("oauth2UserInfo", nil), Handler: h(userInfoEndpoint)},
		{Key: "oauth2EndSession", Path: "/oauth2/end-session", Methods: []string{"GET", "POST"},
			AllowedMediaTypes: []string{"application/x-www-form-urlencoded", "application/json"},
			Metadata:          openapiMeta("oauth2EndSession", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if _, err := validateOAuthBody(ctx, logoutRequestSchema, nil, ""); err != nil {
					return nil, err
				}
				if _, err := validateOAuthQuery(ctx, logoutRequestSchema, nil, ""); err != nil {
					return nil, err
				}
				setNoStore(ctx)
				return rpInitiatedLogoutEndpoint(ctx, o)
			}},
		{Key: "oauth2EndSessionConfirmation", Path: "/oauth2/end-session/confirm", Methods: []string{"POST"},
			AllowedMediaTypes: formOnly, Metadata: map[string]any{"scope": "http"},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				if _, err := validateOAuthBody(ctx, logoutConfirmBody, nil, ""); err != nil {
					return nil, err
				}
				setNoStore(ctx)
				return completeConfirmedLogout(ctx, o)
			}},
		{Key: "registerOAuthClient", Path: "/oauth2/register", Methods: []string{"POST"},
			Metadata: openapiMeta("registerOAuthClient", map[string]any{"openapiBodySchema": toValidate(clientRegistrationRequestSchema)}),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				body, err := validateOAuthBody(ctx, clientRegistrationRequestSchema, registerFieldErrors, "invalid_client_metadata")
				if err != nil {
					return nil, err
				}
				setNoStore(ctx)
				if body == nil {
					body = jsonx.NewObject()
				}
				return registerEndpoint(ctx, o, body)
			}},
		{Key: "adminCreateOAuthClient", Path: "/admin/oauth2/create-client", Methods: []string{"POST"}, NoStore: true, ServerOnly: true,
			Body: toValidate(zObject("strip", nil, clientMetadataFields(true)...)), Metadata: openapiMeta("adminCreateOAuthClient", map[string]any{"SERVER_ONLY": true}),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) { return createOAuthClientEndpoint(ctx, o, true) }},
		{Key: "createOAuthClient", Path: "/oauth2/create-client", Methods: []string{"POST"}, NoStore: true,
			Use:  []betterauth.Middleware{betterauth.SessionMiddleware},
			Body: toValidate(zObject("strip", nil, clientMetadataFields(false)...)), Metadata: openapiMeta("createOAuthClient", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) { return createOAuthClientEndpoint(ctx, o, false) }},
		{Key: "getOAuthClient", Path: "/oauth2/get-client", Methods: []string{"GET"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Query: clientIDBody(), Metadata: openapiMeta("getOAuthClient", nil), Handler: h(getClientEndpoint)},
		{Key: "getOAuthClientPublic", Path: "/oauth2/public-client", Methods: []string{"GET"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Query: clientIDBody(), Metadata: openapiMeta("getOAuthClientPublic", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				return getClientPublicEndpoint(ctx, o, ctx.QueryString("client_id"))
			}},
		{Key: "getOAuthClientPublicPrelogin", Path: "/oauth2/public-client-prelogin", Methods: []string{"POST"},
			Use: []betterauth.Middleware{func(ctx *betterauth.EndpointContext) error {
				if !o.AllowPublicClientPrelogin {
					return apiErr("BAD_REQUEST")
				}
				if !VerifyOAuthQueryParams(bodyStr(ctx, "oauth_query"), ctx.Auth.Secret) {
					return betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("error", "invalid_signature"))
				}
				return nil
			}},
			Body:     toValidate(zObject("strip", nil, zf("client_id", zString()), zf("oauth_query", zOptional(zString())))),
			Metadata: openapiMeta("getOAuthClientPublicPrelogin", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				return getClientPublicEndpoint(ctx, o, bodyStr(ctx, "client_id"))
			}},
		{Key: "getOAuthClients", Path: "/oauth2/get-clients", Methods: []string{"GET"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Metadata: openapiMeta("getOAuthClients", nil), Handler: h(getClientsEndpoint)},
		{Key: "adminUpdateOAuthClient", Path: "/admin/oauth2/update-client", Methods: []string{"PATCH"}, ServerOnly: true,
			Body:     toValidate(zObject("strip", nil, zf("client_id", zString()), zf("update", zObject("strip", nil, updateFields(true)...)))),
			Metadata: openapiMeta("adminUpdateOAuthClient", map[string]any{"SERVER_ONLY": true}),
			Handler:  func(ctx *betterauth.EndpointContext) (any, error) { return updateClientEndpoint(ctx, o, true) }},
		{Key: "updateOAuthClient", Path: "/oauth2/update-client", Methods: []string{"POST"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Body:     toValidate(zObject("strip", nil, zf("client_id", zString()), zf("update", zObject("strip", nil, updateFields(false)...)))),
			Metadata: openapiMeta("updateOAuthClient", nil),
			Handler:  func(ctx *betterauth.EndpointContext) (any, error) { return updateClientEndpoint(ctx, o, false) }},
		{Key: "rotateClientSecret", Path: "/oauth2/client/rotate-secret", Methods: []string{"POST"}, NoStore: true,
			Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Body: clientIDBody(),
			Metadata: openapiMeta("rotateClientSecret", nil), Handler: h(rotateClientSecretEndpoint)},
		{Key: "deleteOAuthClient", Path: "/oauth2/delete-client", Methods: []string{"POST"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Body: clientIDBody(), Metadata: openapiMeta("deleteOAuthClient", nil), Handler: h(deleteClientEndpoint)},
		{Key: "getOAuthConsent", Path: "/oauth2/get-consent", Methods: []string{"GET"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Query: toValidate(zObject("strip", nil, zf("id", zString()))), Metadata: openapiMeta("getOAuthConsent", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) { return getConsentEndpoint(ctx) }},
		{Key: "getOAuthConsents", Path: "/oauth2/get-consents", Methods: []string{"GET"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Metadata: openapiMeta("getOAuthConsents", nil),
			Handler:  func(ctx *betterauth.EndpointContext) (any, error) { return getConsentsEndpoint(ctx) }},
		{Key: "updateOAuthConsent", Path: "/oauth2/update-consent", Methods: []string{"POST"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Body:     toValidate(zObject("strip", nil, zf("id", zString()), zf("update", zObject("strip", nil, zf("scopes", zArray(zString(), 0)))))),
			Metadata: openapiMeta("updateOAuthConsent", nil), Handler: h(updateConsentEndpoint)},
		{Key: "deleteOAuthConsent", Path: "/oauth2/delete-consent", Methods: []string{"POST"}, Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Body: toValidate(zObject("strip", nil, zf("id", zString()))), Metadata: openapiMeta("deleteOAuthConsent", nil),
			Handler: func(ctx *betterauth.EndpointContext) (any, error) { return deleteConsentEndpoint(ctx) }},
		{Key: "adminCreateOAuthResource", Path: "/admin/oauth2/resources", Methods: []string{"POST"}, ServerOnly: true,
			Body: toValidate(zObject("strip", nil, requiredIdentifierFields()...)), Metadata: map[string]any{"SERVER_ONLY": true},
			Handler: h(createResourceEndpoint)},
		{Key: "adminListOAuthResources", Path: "/admin/oauth2/resources", Methods: []string{"GET"}, ServerOnly: true,
			Metadata: map[string]any{"SERVER_ONLY": true}, Handler: h(listResourcesEndpoint)},
		{Key: "adminGetOAuthResource", Path: "/admin/oauth2/resources/:identifier", Methods: []string{"GET"}, ServerOnly: true,
			Metadata: map[string]any{"SERVER_ONLY": true}, Handler: h(getResourceEndpoint)},
		{Key: "adminUpdateOAuthResource", Path: "/admin/oauth2/resources/:identifier", Methods: []string{"PATCH"}, ServerOnly: true,
			Body: toValidate(zObject("strip", nil, resourceBodyFields...)), Metadata: map[string]any{"SERVER_ONLY": true},
			Handler: h(updateResourceEndpoint)},
		{Key: "adminDeleteOAuthResource", Path: "/admin/oauth2/resources/:identifier", Methods: []string{"DELETE"}, ServerOnly: true,
			Metadata: map[string]any{"SERVER_ONLY": true}, Handler: h(deleteResourceEndpoint)},
		{Key: "adminLinkClientResource", Path: "/admin/oauth2/resources/:identifier/clients/:client_id", Methods: []string{"POST"}, ServerOnly: true,
			Metadata: map[string]any{"SERVER_ONLY": true}, Handler: h(linkClientResourceEndpoint)},
		{Key: "adminUnlinkClientResource", Path: "/admin/oauth2/resources/:identifier/clients/:client_id", Methods: []string{"DELETE"}, ServerOnly: true,
			Metadata: map[string]any{"SERVER_ONLY": true}, Handler: h(unlinkClientResourceEndpoint)},
	}
}

func contextBackground() context.Context { return context.Background() }

// setNoStore adds the noStore headers once the request validated (better-call applies
// metadata.noStore after input validation).
func setNoStore(ctx *betterauth.EndpointContext) {
	ctx.SetHeader("Cache-Control", "no-store")
	ctx.SetHeader("Pragma", "no-cache")
}
