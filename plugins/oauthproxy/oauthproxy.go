// Package oauthproxy ports Better Auth's oauth-proxy plugin
// (packages/better-auth/src/plugins/oauth-proxy): OAuth sign-in for preview / development
// deployments whose callback URL is not registered with the provider. The provider calls
// back the production deployment, which exchanges the code and forwards an encrypted
// profile to the originating deployment (/callback/:id/oauth-proxy).
package oauthproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/validate"
)

// Options configure the plugin (OAuthProxyOptions).
type Options struct {
	// CurrentURL is the URL of the current (preview) deployment; inferred from the request
	// (when it is a trusted origin), the platform environment or the base URL otherwise.
	CurrentURL string
	// ProductionURL is the URL registered with the OAuth providers.
	ProductionURL string
	// MaxAge is the maximum age of a forwarded profile payload (default 60s).
	MaxAge time.Duration
	// Secret encrypts the proxy payloads; it must be shared by all deployments when their
	// BETTER_AUTH_SECRET differs. SecretConfig is the rotation-aware form.
	Secret       string
	SecretConfig *bacrypto.Secret
}

func (o Options) maxAge() float64 {
	if o.MaxAge > 0 {
		return o.MaxAge.Seconds()
	}
	return 60
}

func (o Options) key(ac *betterauth.AuthContext, purpose bacrypto.EncryptionPurpose) bacrypto.Secret {
	base := ac.SecretConfig
	if o.SecretConfig != nil {
		base = *o.SecretConfig
	} else if o.Secret != "" {
		base = bacrypto.PlainSecret(o.Secret)
	}
	return bacrypto.DerivePurposeKey(base, purpose)
}

func stripTrailingSlash(u string) string { return strings.TrimRight(u, "/") }

func getOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func vendorBaseURL() string {
	if v := os.Getenv("VERCEL_URL"); v != "" {
		return "https://" + v
	}
	for _, k := range []string{"NETLIFY_URL", "RENDER_URL", "AWS_LAMBDA_FUNCTION_NAME", "GOOGLE_CLOUD_FUNCTION_NAME", "AZURE_FUNCTION_NAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// requestURL is the full URL of the incoming request (Request.url).
func requestURL(r *http.Request) string {
	if r == nil {
		return ""
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

func resolveCurrentURL(ctx *betterauth.EndpointContext, o Options) *url.URL {
	if o.CurrentURL != "" {
		if u, err := url.Parse(o.CurrentURL); err == nil {
			return u
		}
	}
	if ru := requestURL(ctx.Request); ru != "" {
		if origin := getOrigin(ru); origin != "" && ctx.Auth.IsTrustedOrigin(origin, false) {
			if u, err := url.Parse(ru); err == nil {
				return u
			}
		}
	}
	target := ctx.Auth.BaseURL
	if v := vendorBaseURL(); v != "" && getOrigin(v) != "" {
		target = v
	}
	u, _ := url.Parse(target)
	if u == nil {
		u = &url.URL{}
	}
	return u
}

func checkSkipProxy(ctx *betterauth.EndpointContext, o Options) bool {
	if ctx.Request != nil && ctx.Request.Header.Get("x-skip-oauth-proxy") != "" {
		return true
	}
	productionURL := o.ProductionURL
	if productionURL == "" {
		productionURL = os.Getenv("BETTER_AUTH_URL")
	}
	if productionURL == "" {
		productionURL = ctx.Auth.BaseURL
	}
	if productionURL == "" {
		return false
	}
	currentURL := o.CurrentURL
	if currentURL == "" {
		currentURL = requestURL(ctx.Request)
	}
	if currentURL == "" {
		currentURL = vendorBaseURL()
	}
	if currentURL == "" {
		return false
	}
	return getOrigin(productionURL) == getOrigin(currentURL)
}

func originOf(u *url.URL) string {
	if u == nil || u.Scheme == "" {
		return "null"
	}
	return u.Scheme + "://" + u.Host
}

func basePath(ac *betterauth.AuthContext) string {
	if ac.Options.BasePath != "" {
		return ac.Options.BasePath
	}
	return "/api/auth"
}

var querySchema = validate.Object(
	validate.F("callbackURL", validate.String()),
	validate.F("profile", validate.Optional(validate.String())),
)

func signInMatcher(ctx *betterauth.EndpointContext) bool {
	return strings.HasPrefix(ctx.Path, "/sign-in/social") || ctx.Path == "/link-social"
}

func callbackMatcher(ctx *betterauth.EndpointContext) bool { return ctx.Path == "/callback/:id" }

// New creates the oauth-proxy plugin (oAuthProxy).
func New(o Options) *betterauth.Plugin {
	completion := &betterauth.Endpoint{
		Key: "oAuthProxyCompletion", Path: "/callback/:id/oauth-proxy", Methods: []string{"GET"}, OperationID: "oauthProxyCompletion",
		Query: querySchema, Use: []betterauth.Middleware{betterauth.OriginCheck(func(ctx *betterauth.EndpointContext) []string {
			return []string{ctx.QueryString("callbackURL")}
		})},
		Metadata: map[string]any{"scope": "http"},
		Handler:  func(ctx *betterauth.EndpointContext) (any, error) { return complete(ctx, o) },
	}
	proxy := &betterauth.Endpoint{
		Key: "oAuthProxy", Path: "/oauth-proxy-callback", Methods: []string{"GET"}, OperationID: "oauthProxyCallback",
		Query: querySchema, Use: completion.Use,
		Metadata: map[string]any{"openapi": map[string]any{
			"operationId": "oauthProxyCallback", "deprecated": true, "description": "OAuth Proxy Callback",
			"parameters": []any{
				map[string]any{"in": "query", "name": "callbackURL", "required": true, "description": "The URL to redirect to after the proxy"},
				map[string]any{"in": "query", "name": "profile", "required": false, "description": "Encrypted OAuth profile data"},
			},
			"responses": map[string]any{"302": map[string]any{"description": "Redirect", "headers": map[string]any{
				"Location": map[string]any{"description": "The URL to redirect to", "schema": map[string]any{"type": "string"}}}}},
		}},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			ctx.Params = map[string]string{"id": "oauth-proxy"}
			return complete(ctx, o)
		},
	}
	return &betterauth.Plugin{
		ID:        "oauth-proxy",
		Options:   o,
		Endpoints: []*betterauth.Endpoint{proxy, completion},
		Hooks: betterauth.PluginHooks{
			Before: []betterauth.Hook{
				{Matcher: signInMatcher, Handler: func(ctx *betterauth.EndpointContext) (any, error) { return beforeSignIn(ctx, o) }},
				{Matcher: callbackMatcher, Handler: func(ctx *betterauth.EndpointContext) (any, error) { return beforeCallback(ctx, o) }},
			},
			After: []betterauth.Hook{
				{Matcher: signInMatcher, Handler: func(ctx *betterauth.EndpointContext) (any, error) { return afterSignIn(ctx, o) }},
				{Matcher: callbackMatcher, Handler: func(ctx *betterauth.EndpointContext) (any, error) { return afterCallback(ctx, o) }},
			},
		},
	}
}

func beforeSignIn(ctx *betterauth.EndpointContext, o Options) (any, error) {
	if checkSkipProxy(ctx, o) {
		return nil, nil
	}
	body := ctx.BodyMap()
	providerID, _ := body["provider"].(string)
	if providerID == "" {
		return nil, nil
	}
	ac := ctx.Auth
	current := resolveCurrentURL(ctx, o)
	original := ac.BaseURL
	if cb, ok := body["callbackURL"].(string); ok && cb != "" {
		original = cb
	}
	if o.ProductionURL != "" {
		ac.BaseURL = stripTrailingSlash(o.ProductionURL) + basePath(ac)
	}
	body["callbackURL"] = stripTrailingSlash(originOf(current)) + basePath(ac) + "/callback/" + providerID +
		"/oauth-proxy?callbackURL=" + betterauth.EncodeURIComponent(original)
	return nil, nil
}

type statePackage struct {
	State        string `json:"state"`
	StateCookie  string `json:"stateCookie"`
	IsOAuthProxy bool   `json:"isOAuthProxy"`
}

func parseObject(s string) (map[string]any, bool) {
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		return nil, false
	}
	obj, ok := v.(*jsonx.Object)
	if !ok {
		return nil, false
	}
	return obj.Map(), true
}

func beforeCallback(ctx *betterauth.EndpointContext, o Options) (any, error) {
	ac := ctx.Auth
	params := map[string]any{}
	for k, v := range ctx.BodyMap() {
		params[k] = v
	}
	for k, v := range ctx.Query {
		if s, ok := v.([]any); ok && len(s) > 0 {
			v = s[0]
		}
		params[k] = v
	}
	state, _ := params["state"].(string)
	if state == "" {
		return nil, nil
	}
	dec, err := bacrypto.SymmetricDecrypt(o.key(ac, bacrypto.PurposeOAuthProxyPackage), state)
	if err != nil {
		ac.Logger.Debug("OAuth proxy: could not decrypt state package, falling back to regular callback")
		return nil, nil
	}
	pm, ok := parseObject(dec)
	if !ok {
		ac.Logger.Debug("OAuth proxy: could not decrypt state package, falling back to regular callback")
		return nil, nil
	}
	pkg := statePackage{}
	pkg.State, _ = pm["state"].(string)
	pkg.StateCookie, _ = pm["stateCookie"].(string)
	pkg.IsOAuthProxy = validate.Truthy(pm["isOAuthProxy"])
	if !pkg.IsOAuthProxy || pkg.State == "" || pkg.StateCookie == "" {
		ac.Logger.Warn("Invalid OAuth proxy state package")
		return nil, nil
	}
	for _, k := range []string{"code", "error", "user"} {
		if v, ok := params[k]; ok && v != nil {
			if _, isStr := v.(string); !isStr {
				ac.Logger.Warn("Invalid OAuth callback query")
				return nil, nil
			}
		}
	}
	code, _ := params["code"].(string)
	errParam, _ := params["error"].(string)
	userData, _ := params["user"].(string)
	plain, err := bacrypto.SymmetricDecrypt(o.key(ac, bacrypto.PurposeOAuthProxyState), pkg.StateCookie)
	if err != nil {
		ac.Logger.Error("Failed to decrypt OAuth proxy state cookie:", err)
		return nil, nil
	}
	sd, ok := parseObject(plain)
	if !ok {
		ac.Logger.Error("Failed to decrypt OAuth proxy state cookie:", "invalid JSON")
		return nil, nil
	}
	str := func(k string) string { s, _ := sd[k].(string); return s }
	errorURL := str("errorURL")
	if errorURL == "" && ac.Options.OnAPIError != nil {
		errorURL = ac.Options.OnAPIError.ErrorURL
	}
	if errorURL == "" {
		errorURL = ac.BaseURL + "/error"
	}
	fail := func(c string) error { return betterauth.OAuthProxyRedirectOnError(ctx, errorURL, c, "") }
	if v, ok := sd["oauthState"]; ok && v != pkg.State {
		ac.Logger.Error("OAuth proxy state binding mismatch")
		return nil, fail("state_mismatch")
	}
	if errParam != "" {
		return nil, fail(errParam)
	}
	if code == "" {
		ac.Logger.Warn("OAuth callback missing authorization code")
		return nil, fail("no_code")
	}
	providerID := ctx.Params["id"]
	p := ac.FindProvider(providerID)
	if p == nil {
		ac.Logger.Warn("OAuth provider not found", map[string]any{"providerId": providerID})
		return nil, fail("oauth_provider_not_found")
	}
	tokens, err := p.ValidateAuthorizationCode(ctx.Context(), oauth2.CodeParams{Code: code, CodeVerifier: str("codeVerifier"),
		RedirectURI: ac.BaseURL + oauth2.CallbackPath(p)})
	if err != nil {
		ac.Logger.Error("Failed to validate authorization code", err)
		return nil, fail("invalid_code")
	}
	if tokens == nil {
		return nil, fail("invalid_code")
	}
	params2 := oauth2.UserInfoParams{Tokens: *tokens}
	if userData != "" {
		if um, ok := parseObject(userData); ok {
			u := &struct {
				Name  *oauth2.AppleUserName
				Email string
			}{}
			u.Email, _ = um["email"].(string)
			if n, ok := um["name"].(map[string]any); ok {
				u.Name = &oauth2.AppleUserName{}
				u.Name.FirstName, _ = n["firstName"].(string)
				u.Name.LastName, _ = n["lastName"].(string)
			}
			params2.User = u
		}
	}
	info, err := p.GetUserInfo(ctx.Context(), params2)
	if err != nil || info == nil {
		ac.Logger.Error("Unable to get user info from provider")
		return nil, fail("unable_to_get_user_info")
	}
	if info.User.Email == "" {
		ac.Logger.Error("Provider did not return email")
		return nil, fail("email_not_found")
	}
	accountID, err := betterauth.ResolveOAuthAccountKey(ctx.Context(), p, tokens, info.Data)
	if err != nil {
		ac.Logger.Error("Unable to derive provider account identity", map[string]any{"providerId": p.ID(), "error": err})
		return nil, fail("unable_to_get_user_info")
	}
	proxyCallback, err := url.Parse(str("callbackURL"))
	if err != nil || proxyCallback.Scheme == "" {
		return nil, betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "Invalid URL")
	}
	finalCallbackURL := proxyCallback.Query().Get("callbackURL")
	if finalCallbackURL == "" {
		finalCallbackURL = str("callbackURL")
	}
	userInfo := jsonx.O("id", accountID, "email", info.User.Email, "name", info.User.Name)
	if info.User.Image != "" {
		userInfo.Set("image", info.User.Image)
	}
	userInfo.Set("emailVerified", info.User.EmailVerified)
	account := jsonx.O("providerId", p.ID(), "accountId", accountID)
	for _, kv := range [][2]string{{"accessToken", tokens.AccessToken}, {"refreshToken", tokens.RefreshToken}, {"idToken", tokens.IDToken}} {
		if kv[1] != "" {
			account.Set(kv[0], kv[1])
		}
	}
	if tokens.AccessTokenExpiresAt != nil {
		account.Set("accessTokenExpiresAt", jsonx.ISOTime(*tokens.AccessTokenExpiresAt))
	}
	if tokens.RefreshTokenExpiresAt != nil {
		account.Set("refreshTokenExpiresAt", jsonx.ISOTime(*tokens.RefreshTokenExpiresAt))
	}
	scopes := tokens.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	account.Set("scope", strings.Join(scopes, ","))
	payload := jsonx.O("userInfo", userInfo, "profile", info.Data, "scopes", scopes, "account", account,
		"state", pkg.State, "callbackURL", finalCallbackURL)
	if v := str("newUserURL"); v != "" {
		payload.Set("newUserURL", v)
	}
	if v := str("errorURL"); v != "" {
		payload.Set("errorURL", v)
	}
	s := oauth2.SettingsOf(p)
	requestSignUp, _ := sd["requestSignUp"].(bool)
	payload.Set("disableSignUp", (s.DisableImplicitSignUp && !requestSignUp) || s.DisableSignUp)
	payload.Set("timestamp", float64(time.Now().UnixMilli()))
	raw, err := jsonx.Marshal(payload)
	if err != nil {
		return nil, err
	}
	enc, err := bacrypto.SymmetricEncrypt(o.key(ac, bacrypto.PurposeOAuthProxyProfile), string(raw))
	if err != nil {
		return nil, err
	}
	q := newSearchParams(proxyCallback.RawQuery)
	q.set("profile", enc)
	proxyCallback.RawQuery = q.encode()
	return nil, ctx.Redirect(proxyCallback.String())
}

func returnedURL(v any) (string, bool) {
	switch t := v.(type) {
	case *jsonx.Object:
		u, ok := t.Get("url")
		if !ok {
			return "", false
		}
		s, ok := u.(string)
		return s, ok
	case map[string]any:
		u, ok := t["url"]
		if !ok {
			return "", false
		}
		s, ok := u.(string)
		return s, ok
	}
	return "", false
}

func withURL(v any, u string) any {
	switch t := v.(type) {
	case *jsonx.Object:
		o := jsonx.NewObject()
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			o.Set(k, x)
		}
		o.Set("url", u)
		return o
	case map[string]any:
		m := map[string]any{}
		for k, x := range t {
			m[k] = x
		}
		m["url"] = u
		return m
	}
	return v
}

func afterSignIn(ctx *betterauth.EndpointContext, o Options) (any, error) {
	if checkSkipProxy(ctx, o) {
		return nil, nil
	}
	ac := ctx.Auth
	providerURL, ok := returnedURL(ctx.Returned)
	if !ok || providerURL == "" {
		return nil, nil
	}
	oauthURL, err := url.Parse(providerURL)
	if err != nil {
		return nil, nil
	}
	q := newSearchParams(oauthURL.RawQuery)
	original := q.get("state")
	if original == "" {
		return nil, nil
	}
	plaintext := ""
	if ac.OAuthConfig.StoreStateStrategy == "cookie" {
		name := ac.CreateAuthCookie("oauth_state", nil).Name
		for _, sc := range ctx.ResponseHeaders.Values("Set-Cookie") {
			n, v, _ := betterauth.ParseSetCookie(sc)
			if n == name && v != "" {
				dec, err := bacrypto.SymmetricDecrypt(bacrypto.DerivePurposeKey(ac.SecretConfig, bacrypto.PurposeOAuthStateCookie), v)
				if err != nil {
					ac.Logger.Error("Failed to prepare OAuth proxy state:", err)
					return nil, nil
				}
				plaintext = dec
			}
		}
	} else {
		v, err := ac.InternalAdapter.FindVerificationValue(ctx.Context(), "auth-state:"+original)
		if err != nil {
			ac.Logger.Error("Failed to prepare OAuth proxy state:", err)
			return nil, nil
		}
		if v != nil {
			plaintext = v.Value
		}
	}
	if plaintext == "" {
		ac.Logger.Warn("No OAuth state found for proxy")
		return nil, nil
	}
	stateCookie, err := bacrypto.SymmetricEncrypt(o.key(ac, bacrypto.PurposeOAuthProxyState), plaintext)
	if err != nil {
		ac.Logger.Error("Failed to prepare OAuth proxy state:", err)
		return nil, nil
	}
	pkg, _ := json.Marshal(statePackage{State: original, StateCookie: stateCookie, IsOAuthProxy: true})
	enc, err := bacrypto.SymmetricEncrypt(o.key(ac, bacrypto.PurposeOAuthProxyPackage), string(pkg))
	if err != nil {
		ac.Logger.Error("Failed to prepare OAuth proxy state:", err)
		return nil, nil
	}
	q.set("state", enc)
	oauthURL.RawQuery = q.encode()
	return withURL(ctx.Returned, oauthURL.String()), nil
}

func afterCallback(ctx *betterauth.EndpointContext, o Options) (any, error) {
	loc := ctx.ResponseHeaders.Get("Location")
	if (!strings.Contains(loc, "/oauth-proxy?callbackURL") && !strings.Contains(loc, "/oauth-proxy-callback?callbackURL")) || !strings.HasPrefix(loc, "http") {
		return nil, nil
	}
	ac := ctx.Auth
	productionURL := o.ProductionURL
	if productionURL == "" {
		productionURL = ac.Options.BaseURL
	}
	if productionURL == "" {
		productionURL = ac.BaseURL
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return nil, nil
	}
	if originOf(lu) == getOrigin(productionURL) {
		next := lu.Query().Get("callbackURL")
		if next == "" {
			return nil, nil
		}
		ctx.ResponseHeaders.Set("Location", next)
		return nil, nil
	}
	ac.Logger.Warn("OAuth proxy: cross-origin callback reached after hook unexpectedly")
	return nil, nil
}

// ---- passthrough completion ----

var isoDate = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(?:Z|([+-])(\d{2}):(\d{2}))$`)

type payload struct {
	userInfo      oauth2.UserInfo
	account       betterauth.OAuthAccountData
	accountScope  *string
	profile       map[string]any
	scopes        []string
	hasScopes     bool
	state         string
	callbackURL   string
	newUserURL    string
	errorURL      string
	disableSignUp bool
}

func optStr(m map[string]any, k string) (string, bool) {
	v, ok := m[k]
	if !ok || v == nil {
		return "", true
	}
	s, isStr := v.(string)
	return s, isStr
}

func optDate(m map[string]any, k string) (*time.Time, bool) {
	v, ok := m[k]
	if !ok || v == nil {
		return nil, true
	}
	s, isStr := v.(string)
	if !isStr || !isoDate.MatchString(s) {
		return nil, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, false
	}
	return &t, true
}

// parsePayload validates the decrypted profile (passthroughPayloadSchema).
func parsePayload(raw string) (*payload, bool) {
	m, ok := parseObject(raw)
	if !ok {
		return nil, false
	}
	p := &payload{}
	ui, ok := m["userInfo"].(map[string]any)
	if !ok {
		return nil, false
	}
	if _, ok := ui["id"].(string); !ok {
		return nil, false
	}
	email, ok := ui["email"].(string)
	if !ok {
		return nil, false
	}
	name, ok := ui["name"].(string)
	if !ok {
		return nil, false
	}
	ev := false
	if v, present := ui["emailVerified"]; present && v != nil {
		b, isBool := v.(bool)
		if !isBool {
			return nil, false
		}
		ev = b
	}
	image, ok := optStr(ui, "image")
	if !ok {
		return nil, false
	}
	p.userInfo = oauth2.UserInfo{Name: name, Email: strings.ToLower(email), Image: image, EmailVerified: ev}
	for k, v := range ui {
		switch k {
		case "id", "email", "name", "image", "emailVerified", "createdAt", "updatedAt":
		default:
			if p.userInfo.Extra == nil {
				p.userInfo.Extra = map[string]any{}
			}
			p.userInfo.Extra[k] = v
		}
	}
	acc, ok := m["account"].(map[string]any)
	if !ok {
		return nil, false
	}
	pid, ok1 := acc["providerId"].(string)
	aid, ok2 := acc["accountId"].(string)
	if !ok1 || !ok2 {
		return nil, false
	}
	a := betterauth.OAuthAccountData{ProviderID: pid, AccountID: aid}
	for _, f := range []struct {
		k   string
		dst *string
	}{{"accessToken", &a.AccessToken}, {"refreshToken", &a.RefreshToken}, {"idToken", &a.IDToken}, {"scope", &a.Scope}, {"password", new(string)}} {
		s, ok := optStr(acc, f.k)
		if !ok {
			return nil, false
		}
		*f.dst = s
	}
	if v, ok := acc["scope"].(string); ok {
		p.accountScope = &v
	}
	if a.AccessTokenExpiresAt, ok = optDate(acc, "accessTokenExpiresAt"); !ok {
		return nil, false
	}
	if a.RefreshTokenExpiresAt, ok = optDate(acc, "refreshTokenExpiresAt"); !ok {
		return nil, false
	}
	p.account = a
	if v, present := m["profile"]; present && v != nil {
		pr, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		p.profile = pr
	}
	if v, present := m["scopes"]; present && v != nil {
		arr, ok := v.([]any)
		if !ok {
			return nil, false
		}
		p.hasScopes = true
		p.scopes = []string{}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			p.scopes = append(p.scopes, s)
		}
	}
	if p.state, ok = m["state"].(string); !ok || p.state == "" {
		return nil, false
	}
	if p.callbackURL, ok = m["callbackURL"].(string); !ok || p.callbackURL == "" {
		return nil, false
	}
	if p.newUserURL, ok = optStr(m, "newUserURL"); !ok {
		return nil, false
	}
	if p.errorURL, ok = optStr(m, "errorURL"); !ok {
		return nil, false
	}
	if v, present := m["disableSignUp"]; present && v != nil {
		b, isBool := v.(bool)
		if !isBool {
			return nil, false
		}
		p.disableSignUp = b
	}
	if _, ok := m["timestamp"].(float64); !ok {
		return nil, false
	}
	return p, true
}

func complete(ctx *betterauth.EndpointContext, o Options) (any, error) {
	ac := ctx.Auth
	baseURLStr := ac.Options.BaseURL
	if baseURLStr == "" {
		baseURLStr = getOrigin(ac.BaseURL)
	}
	defaultErrorURL := ""
	if ac.Options.OnAPIError != nil {
		defaultErrorURL = ac.Options.OnAPIError.ErrorURL
	}
	if defaultErrorURL == "" {
		defaultErrorURL = stripTrailingSlash(baseURLStr) + "/api/auth/error"
	}
	redirectErr := func(target, code, desc string) error {
		return betterauth.OAuthProxyRedirectOnError(ctx, target, code, desc)
	}
	encrypted := ctx.QueryString("profile")
	if encrypted == "" {
		ac.Logger.Error("OAuth proxy callback missing profile data")
		return nil, redirectErr(defaultErrorURL, "missing_profile", "")
	}
	dec, err := bacrypto.SymmetricDecrypt(o.key(ac, bacrypto.PurposeOAuthProxyProfile), encrypted)
	if err != nil {
		ac.Logger.Error("Failed to decrypt OAuth proxy profile", err)
		return nil, redirectErr(defaultErrorURL, "invalid_profile", "")
	}
	p, ok := parsePayload(dec)
	if !ok {
		ac.Logger.Error("Failed to parse OAuth proxy payload")
		return nil, redirectErr(defaultErrorURL, "invalid_payload", "")
	}
	m, _ := parseObject(dec)
	errorURL := p.errorURL
	if errorURL == "" {
		errorURL = defaultErrorURL
	}
	if strings.HasPrefix(ctx.Path, "/callback/") && ctx.Params["id"] != p.account.ProviderID {
		ac.Logger.Warn("OAuth proxy callback provider mismatch")
		return nil, redirectErr(errorURL, "provider_mismatch", "")
	}
	ts, _ := m["timestamp"].(float64)
	age := (float64(time.Now().UnixMilli()) - ts) / 1000
	if age > o.maxAge() || age < -10 {
		ac.Logger.Error("OAuth proxy payload expired or invalid")
		return nil, redirectErr(errorURL, "payload_expired", "")
	}
	sd, err := betterauth.ParseGenericState(ctx, p.state, "", betterauth.Bool(true))
	if err != nil {
		ac.Logger.Warn("OAuth proxy state missing or invalid", err)
		return nil, redirectErr(errorURL, "state_mismatch", "")
	}
	betterauth.OAuthProxySetOAuthState(ctx.Context(), sd)
	if sd.Link != nil {
		scopes := p.scopes
		if !p.hasScopes && p.accountScope != nil {
			scopes = strings.Split(*p.accountScope, ",")
		}
		profile := p.profile
		if profile == nil {
			profile = map[string]any{}
		}
		res, err := betterauth.LinkOAuthAccount(ctx, *sd.Link, p.userInfo, p.account, profile, scopes)
		if err != nil {
			return nil, err
		}
		if !res.Linked {
			return nil, redirectErr(errorURL, res.ErrorCode, res.ErrorMessage)
		}
		return nil, ctx.Redirect(p.callbackURL)
	}
	res, err := betterauth.HandleOAuthUserInfo(ctx, betterauth.HandleOAuthUserInfoOptions{
		UserInfo: p.userInfo, Account: p.account, CallbackURL: p.callbackURL, DisableSignUp: p.disableSignUp,
		Source: betterauth.UserInfoSource{Method: "oauth", ProviderID: p.account.ProviderID, Profile: p.profile},
	})
	if err != nil {
		if e, ok := betterauth.AsAPIError(err); ok && e.Code() != "" && !betterauth.IsRedirect(err) {
			return nil, redirectErr(errorURL, e.Code(), e.Message())
		}
		return nil, err
	}
	if res.Error != "" {
		ac.Logger.Error("OAuth proxy callback error", res.Error)
		return nil, redirectErr(errorURL, strings.Join(strings.Split(res.Error, " "), "_"), "")
	}
	if res.Data == nil {
		ac.Logger.Error("OAuth proxy callback missing session data")
		return nil, redirectErr(errorURL, "user_creation_failed", "")
	}
	if err := betterauth.SetSessionCookie(ctx, res.Data, nil, nil); err != nil {
		return nil, err
	}
	final := p.callbackURL
	if res.IsRegister && p.newUserURL != "" {
		final = p.newUserURL
	}
	return nil, ctx.Redirect(final)
}

// ---- URLSearchParams emulation ----

type searchParams struct {
	keys []string
	vals map[string][]string
}

func newSearchParams(raw string) *searchParams {
	p := &searchParams{vals: map[string][]string{}}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		if _, ok := p.vals[k]; !ok {
			p.keys = append(p.keys, k)
		}
		p.vals[k] = append(p.vals[k], v)
	}
	return p
}

func (p *searchParams) get(k string) string {
	if v := p.vals[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (p *searchParams) set(k, v string) {
	if _, ok := p.vals[k]; !ok {
		p.keys = append(p.keys, k)
	}
	p.vals[k] = []string{v}
}

func (p *searchParams) encode() string {
	var parts []string
	for _, k := range p.keys {
		for _, v := range p.vals[k] {
			parts = append(parts, oauth2.FormEncode(k)+"="+oauth2.FormEncode(v))
		}
	}
	return strings.Join(parts, "&")
}
