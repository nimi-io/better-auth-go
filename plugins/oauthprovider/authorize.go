package oauthprovider

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of packages/oauth-provider/src/authorize.ts.

// oauthStateKey is the request-state key of the OAuth provider state (oAuthState).
type oauthStateKey struct{}

// OAuthProviderState is the per-request OAuth provider state (getOAuthProviderState):
// the authorization query being processed and the signed-query metadata.
type OAuthProviderState struct {
	Query                      string
	SignedQueryIssuedAt        *time.Time
	PostLoginClearedForSession string
}

// GetOAuthProviderState returns the request's OAuth provider state (nil when unset).
func GetOAuthProviderState(ctx *betterauth.EndpointContext) *OAuthProviderState {
	v, _ := betterauth.RequestStateGet(ctx.Context(), oauthStateKey{})
	s, _ := v.(*OAuthProviderState)
	return s
}

func setOAuthProviderState(ctx *betterauth.EndpointContext, s *OAuthProviderState) {
	betterauth.RequestStateSet(ctx.Context(), oauthStateKey{}, s)
}

// authorizeSettings are AuthorizeEndpointSettings.
type authorizeSettings struct {
	isAuthorize bool
	postLogin   bool
}

func formatErrorURL(rawURL, errCode, description, state, iss, mode string) string {
	p := newSearchParams()
	p.append("error", errCode)
	p.append("error_description", description)
	if state != "" {
		p.append("state", state)
	}
	if iss != "" {
		p.append("iss", iss)
	}
	if mode == "fragment" {
		return rawURL + "#" + p.String()
	}
	out, err := appendQueryParams(rawURL, p)
	if err != nil {
		return rawURL
	}
	return out
}

var implicitResponseType = regexp.MustCompile(`\b(token|id_token)\b`)

func deriveResponseMode(raw *jsonx.Object) string {
	rm := objString(raw, "response_mode")
	if rm == "fragment" || rm == "query" {
		return rm
	}
	if rt := objString(raw, "response_type"); rt != "" && implicitResponseType.MatchString(rt) {
		return "fragment"
	}
	return "query"
}

func objString(o *jsonx.Object, k string) string {
	if o == nil {
		return ""
	}
	v, _ := o.Get(k)
	s, _ := v.(string)
	return s
}

// redirectResult is the {redirect: true, url} response.
func redirectResult(u string) *jsonx.Object { return jsonx.O("redirect", true, "url", u) }

// isBrowserFetchRequest reports Sec-Fetch-Mode: cors.
func isBrowserFetchRequest(ctx *betterauth.EndpointContext) bool {
	return ctx.Request != nil && ctx.Request.Header.Get("Sec-Fetch-Mode") == "cors"
}

// handleRedirect answers fetch / JSON requests with {redirect, url} and navigations with
// a 302.
func handleRedirect(ctx *betterauth.EndpointContext, uri string) (any, error) {
	acceptJSON := strings.Contains(ctx.GetHeader("Accept"), "application/json")
	if isBrowserFetchRequest(ctx) || acceptJSON {
		return redirectResult(uri), nil
	}
	return nil, ctx.Redirect(uri)
}

// validateIssuerURL forces https for non-loopback issuers and strips query / fragment.
func validateIssuerURL(issuer string) string {
	u, err := parseURL(issuer)
	if err != nil {
		return issuer
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Host) {
		u.Scheme = "https"
		if p := u.Port(); p == "443" {
			u.Host = u.Hostname()
		}
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return strings.TrimSuffix(u.String(), "/")
}

// GetIssuer returns the authorization server issuer identifier (getIssuer): the jwt
// plugin issuer (or base URL), normalised by validateIssuerUrl.
func GetIssuer(ctx *betterauth.EndpointContext) string {
	o, err := pluginOptions(ctx.Auth)
	if err != nil {
		return validateIssuerURL(ctx.Auth.BaseURL)
	}
	return getIssuer(ctx, o)
}

func getIssuer(ctx *betterauth.EndpointContext, o *resolved) string {
	return validateIssuerURL(o.issuerOrBase(ctx))
}

func getErrorURL(ctx *betterauth.EndpointContext, errCode, description string) string {
	base := ctx.Auth.BaseURL + "/error"
	if e := ctx.Auth.Options.OnAPIError; e != nil && e.ErrorURL != "" {
		base = e.ErrorURL
	}
	return formatErrorURL(base, errCode, description, "", "", "query")
}

var digitsOnly = regexp.MustCompile(`^\d*$`)

// stripLoopbackRedirectPort removes the port of an http loopback redirect URI ("" when
// the URI is not an http loopback URI).
func stripLoopbackRedirectPort(uri string) (string, bool) {
	u, err := parseURL(uri)
	if err != nil {
		return "", false
	}
	host := u.Hostname()
	if !(isLoopbackIP(host) || host == "localhost") || u.Scheme != "http" {
		return "", false
	}
	sep := strings.Index(uri, "://")
	if sep < 0 {
		return "", false
	}
	start := sep + 3
	end := len(uri)
	if i := strings.IndexAny(uri[start:], "/?#"); i >= 0 {
		end = start + i
	}
	authority := uri[start:end]
	var portStart int
	if strings.HasPrefix(authority, "[") {
		closing := strings.Index(authority, "]")
		if closing < 0 {
			return "", false
		}
		if closing+1 >= len(authority) || authority[closing+1] != ':' {
			return uri, true
		}
		portStart = closing + 1
	} else {
		portStart = strings.LastIndex(authority, ":")
		if portStart < 0 {
			return uri, true
		}
	}
	if !digitsOnly.MatchString(authority[portStart+1:]) {
		return "", false
	}
	at := start + portStart
	return uri[:at] + uri[end:], true
}

func findRegisteredRedirectURI(registered []string, requested string) string {
	if len(registered) == 0 || requested == "" {
		return ""
	}
	u, err := parseURL(requested)
	if err != nil {
		return ""
	}
	if strings.Contains(requested, "#") || urlHasCredentials(u) {
		return ""
	}
	withoutPort, ok := stripLoopbackRedirectPort(requested)
	for _, r := range registered {
		if r == requested {
			return r
		}
		if !ok {
			continue
		}
		if rp, rok := stripLoopbackRedirectPort(r); rok && rp == withoutPort {
			return r
		}
	}
	return ""
}

func isSafeCustomRedirectURI(uri string) bool {
	if _, issues := zParse(safeURL(), uri); len(issues) > 0 {
		return false
	}
	u, err := parseURL(uri)
	return err == nil && !urlHasCredentials(u)
}

func resolveTrustedRedirectURI(ctx *betterauth.EndpointContext, o *resolved, clientID, redirectURI string) string {
	if clientID == "" || redirectURI == "" {
		return ""
	}
	client, err := getClient(ctx, o, clientID)
	if err != nil || client == nil || client.IsDisabled() {
		return ""
	}
	matched := findRegisteredRedirectURI(client.RedirectURIs, redirectURI)
	if o.ValidateRedirectURI != nil {
		if !isSafeCustomRedirectURI(redirectURI) {
			return ""
		}
		ok, err := o.ValidateRedirectURI(redirectURI, client.RedirectURIs, matched != "")
		if err != nil || !ok {
			return ""
		}
		return redirectURI
	}
	if matched != "" {
		return redirectURI
	}
	return ""
}

// authorizeRedirectOnError redirects authorization errors to the client when its redirect
// URI is trusted, otherwise to the error page.
func authorizeRedirectOnError(ctx *betterauth.EndpointContext, o *resolved, raw *jsonx.Object, errCode, description string) (any, error) {
	trusted := resolveTrustedRedirectURI(ctx, o, objString(raw, "client_id"), objString(raw, "redirect_uri"))
	if trusted != "" {
		return handleRedirect(ctx, formatErrorURL(trusted, errCode, description, objString(raw, "state"),
			getIssuer(ctx, o), deriveResponseMode(raw)))
	}
	return handleRedirect(ctx, getErrorURL(ctx, errCode, description))
}

func redirectWithPromptNoneError(ctx *betterauth.EndpointContext, o *resolved, query *jsonx.Object, errCode, description string) (any, error) {
	return handleRedirect(ctx, formatErrorURL(objString(query, "redirect_uri"), errCode, description,
		objString(query, "state"), getIssuer(ctx, o), "query"))
}

// serializeAuthorizationQuery converts a query object into URLSearchParams.
func serializeAuthorizationQuery(q *jsonx.Object) *searchParams {
	p := newSearchParams()
	if q == nil {
		return p
	}
	for _, k := range q.Keys() {
		v, _ := q.Get(k)
		if v == nil || isUndef(v) || v == jsonx.Undefined {
			continue
		}
		switch t := v.(type) {
		case []any:
			for _, x := range t {
				p.append(k, jsString(x))
			}
		case []string:
			for _, x := range t {
				p.append(k, x)
			}
		case *jsonx.Object:
			if k == "claims" {
				b, _ := jsonx.Marshal(t)
				p.set(k, string(b))
			} else {
				p.set(k, "[object Object]")
			}
		case map[string]any:
			if k == "claims" {
				b, _ := jsonx.Marshal(toObject(t))
				p.set(k, string(b))
			} else {
				p.set(k, "[object Object]")
			}
		default:
			p.set(k, jsString(t))
		}
	}
	return p
}

// jsString is String(v) for JSON values.
func jsString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return jsonx.FormatNumber(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if x == nil {
				parts[i] = ""
			} else {
				parts[i] = jsString(x)
			}
		}
		return strings.Join(parts, ",")
	case *jsonx.Object, map[string]any:
		return "[object Object]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// requestQueryObject returns the HTTP query in request order (searchParamsToQuery) or the
// API query (keys sorted).
func requestQueryObject(ctx *betterauth.EndpointContext) *jsonx.Object {
	if ctx.Request != nil && ctx.Request.URL != nil && len(ctx.Query) > 0 {
		q := searchParamsToQuery(parseSearchParams(ctx.Request.URL.RawQuery))
		if q.Len() == len(ctx.Query) {
			return q
		}
	}
	return mapToObject(ctx.Query)
}

// requestBodyObject returns the urlencoded body in request order, or the body map.
func requestBodyObject(ctx *betterauth.EndpointContext) *jsonx.Object {
	if form := requestForm(ctx); form != nil {
		out := jsonx.NewObject()
		for _, p := range form.list {
			out.Set(p.k, p.v)
		}
		if out.Len() == len(bodyMap(ctx)) {
			return out
		}
	}
	return mapToObject(bodyMap(ctx))
}

func mapToObject(m map[string]any) *jsonx.Object {
	o := jsonx.NewObject()
	for _, k := range sortedKeys(m) {
		o.Set(k, m[k])
	}
	return o
}

// authorizeEndpoint processes an authorization request (authorizeEndpoint). query is the
// authorization request (ctx.query upstream).
func authorizeEndpoint(ctx *betterauth.EndpointContext, o *resolved, settings authorizeSettings, query *jsonx.Object) (any, error) {
	if !contains(o.GrantTypes, "authorization_code") {
		return nil, apiErr("NOT_FOUND")
	}
	if ctx.Request == nil {
		return nil, oauthErr("UNAUTHORIZED", "invalid_request", "request not found")
	}
	if query == nil {
		query = jsonx.NewObject()
	}
	redirectErr := func(code, desc string) (any, error) {
		return authorizeRedirectOnError(ctx, o, query, code, desc)
	}
	reqObj, hasReqObj := query.Get("request")
	reqURI, hasReqURI := query.Get("request_uri")
	_, reqObjStr := reqObj.(string)
	reqURIStr, reqURIIsStr := reqURI.(string)
	hasReqObj = hasReqObj && reqObjStr
	hasReqURI = hasReqURI && reqURIIsStr
	if hasReqObj && hasReqURI {
		return redirectErr("invalid_request", "request and request_uri cannot be used together")
	}
	if hasReqObj {
		return redirectErr("request_not_supported", "request object not supported")
	}
	if hasReqURI {
		clientID := objString(query, "client_id")
		if clientID == "" {
			return redirectErr("invalid_request", "client_id is required")
		}
		if o.RequestURIResolver == nil {
			return redirectErr("request_uri_not_supported", "request_uri not supported")
		}
		resolvedParams, err := o.RequestURIResolver(RequestURIInput{RequestURI: reqURIStr, ClientID: clientID, Ctx: ctx})
		if err != nil {
			return nil, err
		}
		if resolvedParams == nil {
			return redirectErr("invalid_request_uri", "request_uri is invalid or expired")
		}
		urlClientID, _ := query.Get("client_id")
		query = resolvedParams.Clone()
		if v, ok := urlClientID.(string); ok && v != "" {
			query.Set("client_id", v)
		} else if urlClientID != nil && urlClientID != "" {
			query.Set("client_id", urlClientID)
		}
	}
	parsed, issues := zParse(authorizationQuerySchema, query)
	if len(issues) > 0 {
		code, desc := mapIssuesToOAuthError(issues, map[string]fieldErrorCodes{
			"response_type": {Invalid: "unsupported_response_type"},
			"resource":      {Invalid: "invalid_target"},
		}, "")
		return redirectErr(code, desc)
	}
	query = parsed.(*jsonx.Object)
	setOAuthProviderState(ctx, &OAuthProviderState{Query: serializeAuthorizationQuery(query).String()})
	if !query.Has("response_type") {
		return redirectErr("invalid_request", "response_type is required")
	}
	prompt := objString(query, "prompt")
	var promptSet map[string]bool
	if prompt != "" {
		promptSet = parsePrompt(prompt)
	}
	promptNone := promptSet["none"]
	if promptSet["select_account"] && (o.SelectAccount == nil || o.SelectAccount.Page == "") {
		return handleRedirect(ctx, getErrorURL(ctx, "unsupported_prompt_select_account", "unsupported prompt type"))
	}
	if objString(query, "response_type") != "code" {
		return handleRedirect(ctx, getErrorURL(ctx, "unsupported_response_type", "unsupported response type"))
	}
	client, err := getClient(ctx, o, objString(query, "client_id"))
	if err != nil {
		return nil, err
	}
	if client == nil {
		return handleRedirect(ctx, getErrorURL(ctx, "invalid_client", "client_id is required"))
	}
	if client.IsDisabled() {
		return handleRedirect(ctx, getErrorURL(ctx, "client_disabled", "client is disabled"))
	}
	if !clientAllowsGrant(client, "authorization_code") {
		return handleRedirect(ctx, getErrorURL(ctx, "unauthorized_client", "client is not authorized to use the authorization_code grant"))
	}
	redirectURI := objString(query, "redirect_uri")
	valid := false
	if redirectURI != "" {
		def := findRegisteredRedirectURI(client.RedirectURIs, redirectURI) != ""
		if o.ValidateRedirectURI != nil && isSafeCustomRedirectURI(redirectURI) {
			ok, err := o.ValidateRedirectURI(redirectURI, client.RedirectURIs, def)
			valid = err == nil && ok
		} else if o.ValidateRedirectURI == nil {
			valid = def
		}
	}
	if !valid {
		return handleRedirect(ctx, getErrorURL(ctx, "invalid_redirect", "invalid redirect uri"))
	}
	state := objString(query, "state")
	clientError := func(code, desc string) (any, error) {
		return handleRedirect(ctx, formatErrorURL(redirectURI, code, desc, state, getIssuer(ctx, o), "query"))
	}
	var requestedScopes []string
	if query.Has("scope") {
		for _, s := range strings.Split(objString(query, "scope"), " ") {
			if s != "" {
				requestedScopes = append(requestedScopes, s)
			}
		}
		if requestedScopes == nil {
			requestedScopes = []string{}
		}
		valid := client.Scopes
		if valid == nil {
			valid = o.Scopes
		}
		var invalid []string
		for _, s := range requestedScopes {
			if !contains(valid, s) {
				invalid = append(invalid, s)
			}
		}
		if len(invalid) > 0 {
			return clientError("invalid_scope", "The following scopes are invalid: "+strings.Join(invalid, ", "))
		}
	} else {
		requestedScopes = client.Scopes
		if requestedScopes == nil {
			requestedScopes = o.Scopes
		}
		query.Set("scope", strings.Join(requestedScopes, " "))
	}
	openid := contains(requestedScopes, "openid")
	claimsV, hasClaims := query.Get("claims")
	if hasClaims && !openid {
		return clientError("invalid_request", "openid scope must be requested when using the claims parameter")
	}
	if openid && hasClaims && !isValidOIDCClaimsRequest(claimsV) {
		return clientError("invalid_request", "claims must be a valid Claims request object")
	}
	if openid && hasClaims && !canSatisfyEssentialACRRequest(claimsV, level0ACR) {
		return clientError("access_denied", "essential acr requirement cannot be met")
	}
	var claimsArg any
	if hasClaims {
		claimsArg = claimsV
	}
	requestedUserInfoClaims := getRequestedUserInfoClaims(claimsArg, o.supportedClaims())
	resourceV, hasResource := query.Get("resource")
	if hasResource {
		if _, err := resolveResourcePolicy(ctx, o, resourceV, client.ClientID, requestedScopes); err != nil {
			e, ok := betterauth.AsAPIError(err)
			if !ok {
				return nil, err
			}
			code := errorBodyString(e, "error")
			if code == "" {
				code = "invalid_target"
			}
			desc := errorBodyString(e, "error_description")
			if desc == "" {
				desc = "requested resource invalid"
			}
			return clientError(code, desc)
		}
	}
	nonce := objString(query, "nonce")
	if reason := isPKCERequired(client, requestedScopes, nonce); reason != "" {
		if objString(query, "code_challenge") == "" || objString(query, "code_challenge_method") == "" {
			return clientError("invalid_request", reason)
		}
	}
	challenge, method := objString(query, "code_challenge"), objString(query, "code_challenge_method")
	if challenge != "" || method != "" {
		if challenge == "" || method == "" {
			return clientError("invalid_request", "code_challenge and code_challenge_method must both be provided")
		}
		if method != "S256" {
			return clientError("invalid_request", "invalid code_challenge method, only S256 is supported")
		}
	}
	requestedResources := toResourceList(resourceV)
	if requestedResources == nil {
		requestedResources = []string{}
	}
	session, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	maxAgeV, hasMaxAge := query.Get("max_age")
	maxAge, _ := maxAgeV.(float64)
	hasSatisfiedMaxAge := session != nil && hasMaxAge && isWithinMaxAge(session.Session.CreatedAt, maxAge, time.Now())
	staleForMaxAge := session != nil && hasMaxAge && !hasSatisfiedMaxAge
	if session == nil || staleForMaxAge || promptSet["login"] || promptSet["create"] {
		if promptNone {
			return redirectWithPromptNoneError(ctx, o, query, "login_required", "authentication required")
		}
		typ := "login"
		if promptSet["create"] {
			typ = "create"
		}
		return redirectWithPromptCode(ctx, o, query, typ, "", "")
	}
	if hasSatisfiedMaxAge {
		query = query.Clone()
		query.Delete("max_age")
	}
	if settings.isAuthorize && promptSet["select_account"] {
		return redirectWithPromptCode(ctx, o, query, "select_account", "", "")
	}
	usc := UserSessionContext{Ctx: ctx, Headers: ctx.Request.Header, User: session.User, Session: session.Session, Scopes: requestedScopes}
	if settings.isAuthorize && o.SelectAccount != nil && o.SelectAccount.ShouldRedirect != nil {
		redirect, err := o.SelectAccount.ShouldRedirect(usc)
		if err != nil {
			return nil, err
		}
		if redirect {
			if promptNone {
				return redirectWithPromptNoneError(ctx, o, query, "account_selection_required", "End-User account selection is required")
			}
			return redirectWithPromptCode(ctx, o, query, "select_account", "", "")
		}
	}
	if o.Signup != nil && o.Signup.ShouldRedirect != nil {
		redirect, page, err := o.Signup.ShouldRedirect(usc)
		if err != nil {
			return nil, err
		}
		if redirect || page != "" {
			if promptNone {
				return redirectWithPromptNoneError(ctx, o, query, "interaction_required", "End-User interaction is required")
			}
			return redirectWithPromptCode(ctx, o, query, "create", page, "")
		}
	}
	if !settings.postLogin && o.PostLogin != nil {
		redirect := false
		if o.PostLogin.ShouldRedirect != nil {
			redirect, err = o.PostLogin.ShouldRedirect(usc)
			if err != nil {
				return nil, err
			}
		}
		if redirect {
			if promptNone {
				return redirectWithPromptNoneError(ctx, o, query, "interaction_required", "End-User interaction is required")
			}
			return redirectWithPromptCode(ctx, o, query, "post_login", "", "")
		}
	}
	if promptSet["consent"] {
		return redirectWithPromptCode(ctx, o, query, "consent", "", session.Session.ID)
	}
	referenceID := ""
	if o.PostLogin != nil && o.PostLogin.ConsentReferenceID != nil {
		referenceID, err = o.PostLogin.ConsentReferenceID(usc)
		if err != nil {
			return nil, err
		}
	}
	codeInput := authorizationCodeInput{query: query, clientID: client.ClientID, userID: session.User.ID,
		sessionID: session.Session.ID, authTime: session.Session.CreatedAt.UnixMilli(), referenceID: referenceID,
		resource: requestedResources}
	if isTrue(client.SkipConsent) {
		return redirectWithAuthorizationCode(ctx, o, codeInput)
	}
	consent, err := findConsent(ctx, client.ClientID, session.User.ID, referenceID)
	if err != nil {
		return nil, err
	}
	needsConsent := consent == nil
	if consent != nil {
		for _, s := range requestedScopes {
			if !contains(consent.Scopes, s) {
				needsConsent = true
			}
		}
		for _, c := range requestedUserInfoClaims {
			if !contains(consent.RequestedUserInfoClaims, c) {
				needsConsent = true
			}
		}
	}
	if needsConsent {
		if promptNone {
			return redirectWithPromptNoneError(ctx, o, query, "consent_required", "End-User consent is required")
		}
		return redirectWithPromptCode(ctx, o, query, "consent", "", session.Session.ID)
	}
	for _, r := range requestedResources {
		if !contains(consent.Resources, r) {
			if promptNone {
				return redirectWithPromptNoneError(ctx, o, query, "consent_required", "End-User consent is required")
			}
			return redirectWithPromptCode(ctx, o, query, "consent", "", session.Session.ID)
		}
	}
	return redirectWithAuthorizationCode(ctx, o, codeInput)
}

func isWithinMaxAge(createdAt time.Time, maxAgeSeconds float64, now time.Time) bool {
	if maxAgeSeconds == 0 {
		return false
	}
	return float64(now.UnixMilli()-createdAt.UnixMilli()) <= maxAgeSeconds*1000
}

type authorizationCodeInput struct {
	query       *jsonx.Object
	clientID    string
	userID      string
	sessionID   string
	authTime    int64
	referenceID string
	resource    []string
}

func redirectWithAuthorizationCode(ctx *betterauth.EndpointContext, o *resolved, in authorizationCodeInput) (any, error) {
	code := bacrypto.RandomString(32, "a-z", "A-Z", "0-9")
	iat := time.Now().Unix()
	exp := iat + int64(o.codeExpiresIn())
	identifier, err := storeToken(o, code, TokenTypeAuthorizationCode)
	if err != nil {
		return nil, err
	}
	value := jsonx.O("type", "authorization_code", "query", in.query, "userId", in.userID, "sessionId", in.sessionID)
	if in.referenceID != "" {
		value.Set("referenceId", in.referenceID)
	}
	value.Set("authTime", in.authTime)
	if in.resource != nil {
		value.Set("resource", stringsToAny(in.resource))
	}
	raw, err := jsonx.Marshal(value)
	if err != nil {
		return nil, err
	}
	at := time.Unix(iat, 0)
	if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(ctx.Context(), identifier, string(raw), time.Unix(exp, 0),
		map[string]any{"createdAt": at, "updatedAt": at}); err != nil {
		return nil, err
	}
	kv := []string{"code", code}
	if s := objString(in.query, "state"); s != "" {
		kv = append(kv, "state", s)
	}
	kv = append(kv, "iss", getIssuer(ctx, o))
	target, err := setSearchParams(objString(in.query, "redirect_uri"), kv...)
	if err != nil {
		return nil, err
	}
	return handleRedirect(ctx, target)
}

// redirectWithPromptCode redirects to the login / consent / account pages with a signed
// copy of the authorization request.
func redirectWithPromptCode(ctx *betterauth.EndpointContext, o *resolved, query *jsonx.Object, typ, page, sessionID string) (any, error) {
	cleared := ""
	if typ == "consent" && o.PostLogin != nil {
		cleared = sessionID
	}
	params := signParams(ctx, o, query, cleared)
	path := o.LoginPage
	switch typ {
	case "select_account":
		if o.SelectAccount != nil && o.SelectAccount.Page != "" {
			path = o.SelectAccount.Page
		}
	case "post_login":
		if o.PostLogin == nil || o.PostLogin.Page == "" {
			return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error_description", "postLogin should have been defined"))
		}
		path = o.PostLogin.Page
	case "consent":
		path = o.ConsentPage
	case "create":
		if o.Signup != nil && o.Signup.Page != "" {
			path = o.Signup.Page
		}
	}
	if page != "" {
		path = page
	}
	return handleRedirect(ctx, path+"?"+params)
}

func signParams(ctx *betterauth.EndpointContext, o *resolved, query *jsonx.Object, postLoginCleared string) string {
	issuedAt := time.Now().UnixMilli()
	exp := issuedAt/1000 + int64(o.codeExpiresIn())
	p := serializeAuthorizationQuery(query)
	p.set("exp", strconv.FormatInt(exp, 10))
	p.set(signedQueryIssuedAtParam, strconv.FormatInt(issuedAt, 10))
	p.delete("sig")
	p.delete(postLoginClearedParam)
	if postLoginCleared != "" {
		p.set(postLoginClearedParam, postLoginCleared)
	}
	setSignedOAuthQueryParameterNames(p)
	sig := bacrypto.MakeSignature(canonicalizeOAuthQueryParams(p).String(), ctx.Auth.Secret)
	p.set("sig", sig)
	return p.String()
}
