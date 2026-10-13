package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/logout.ts: OpenID Connect back-channel logout and
// RP-initiated logout (end_session_endpoint).

const (
	backchannelLogoutEventURI    = "http://schemas.openid.net/event/backchannel-logout"
	logoutTokenJWTType           = "logout+jwt"
	logoutTokenLifetimeSeconds   = 120
	backchannelDispatchTimeout   = 5 * time.Second
	logoutConfirmationTTLSeconds = 5 * 60
	logoutConfirmationSuffix     = ".oauth_logout_confirmation"
)

// BackchannelHTTPClient delivers back-channel logout tokens (redirects are refused).
var BackchannelHTTPClient = &http.Client{
	Timeout: backchannelDispatchTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect")
	},
}

type backchannelTarget struct {
	client *SchemaClient
	sub    string
}

type backchannelPlan struct {
	accessTokenIDs  []any
	refreshTokenIDs []any
	sessionID       string
	targets         []backchannelTarget
}

func prepareBackchannelLogoutPlan(ctx *betterauth.EndpointContext, c context.Context, o *resolved, sessionID, userID string) *backchannelPlan {
	if userID == "" {
		return nil
	}
	log := ctx.Auth.Logger
	plan, err := func() (*backchannelPlan, error) {
		where := []adapter.Where{{Field: "sessionId", Value: sessionID}}
		access, err := ctx.Auth.Adapter.FindMany(c, adapter.FindManyInput{Model: modelAccessToken, Where: where})
		if err != nil {
			return nil, err
		}
		refresh, err := ctx.Auth.Adapter.FindMany(c, adapter.FindManyInput{Model: modelRefreshToken, Where: where})
		if err != nil {
			return nil, err
		}
		var ids []string
		for _, t := range access {
			ids = append(ids, recStr(t, "clientId"))
		}
		for _, t := range refresh {
			ids = append(ids, recStr(t, "clientId"))
		}
		ids = uniqueStrings(ids)
		if len(ids) == 0 {
			return nil, nil
		}
		clients, err := ctx.Auth.Adapter.FindMany(c, adapter.FindManyInput{Model: modelClient,
			Where: []adapter.Where{{Field: "clientId", Operator: adapter.In, Value: stringsToAny(ids)}}})
		if err != nil {
			return nil, err
		}
		p := &backchannelPlan{sessionID: sessionID, accessTokenIDs: []any{}, refreshTokenIDs: []any{}}
		for _, t := range access {
			if t["revoked"] == nil {
				p.accessTokenIDs = append(p.accessTokenIDs, recStr(t, "id"))
			}
		}
		for _, t := range refresh {
			if t["revoked"] == nil && !contains(recStrings(t, "scopes"), "offline_access") {
				p.refreshTokenIDs = append(p.refreshTokenIDs, recStr(t, "id"))
			}
		}
		if !o.DisableJwtPlugin {
			for _, r := range clients {
				cl := ClientFromRecord(r)
				if cl.BackchannelLogoutURI == "" || cl.IsDisabled() {
					continue
				}
				sub, err := resolveSubjectIdentifier(userID, cl, o)
				if err != nil {
					log.Warn("back-channel logout: unable to resolve subject for client "+cl.ClientID, err)
					continue
				}
				p.targets = append(p.targets, backchannelTarget{client: cl, sub: sub})
			}
		}
		return p, nil
	}()
	if err != nil {
		log.Error("back-channel logout planning failed", err)
		return nil
	}
	return plan
}

func applyBackchannelLogoutPlan(ctx *betterauth.EndpointContext, c context.Context, o *resolved, plan *backchannelPlan) {
	revokedAt := time.Now()
	if len(plan.accessTokenIDs) > 0 {
		if _, err := ctx.Auth.Adapter.UpdateMany(c, modelAccessToken,
			[]adapter.Where{{Field: "id", Operator: adapter.In, Value: plan.accessTokenIDs}},
			adapter.Record{"revoked": revokedAt}); err != nil {
			ctx.Auth.Logger.Error("back-channel logout: token revocation update failed", err)
		}
	}
	if len(plan.refreshTokenIDs) > 0 {
		if _, err := ctx.Auth.Adapter.UpdateMany(c, modelRefreshToken,
			[]adapter.Where{{Field: "id", Operator: adapter.In, Value: plan.refreshTokenIDs}},
			adapter.Record{"revoked": revokedAt}); err != nil {
			ctx.Auth.Logger.Error("back-channel logout: token revocation update failed", err)
		}
	}
	if len(plan.targets) > 0 {
		deliverBackchannelLogoutTokens(ctx, c, plan)
	}
}

func deliverBackchannelLogoutTokens(ctx *betterauth.EndpointContext, c context.Context, plan *backchannelPlan) {
	log := ctx.Auth.Logger
	jo, err := jwtOptions(ctx.Auth)
	if err != nil {
		log.Error("Back-channel logout failed after session deletion", err)
		return
	}
	iss := jwtIssuer(jo)
	if iss == "" {
		iss = ctx.Auth.BaseURL
	}
	iat := time.Now().Unix()
	exp := iat + logoutTokenLifetimeSeconds
	var key *jwt.ResolvedSigningKey
	if jo.JWT == nil || jo.JWT.Sign == nil {
		key, err = jwt.ResolveSigningKey(ctx, jo, nil)
		if err != nil {
			log.Error("Back-channel logout failed after session deletion", err)
			return
		}
	}
	var wg sync.WaitGroup
	for _, t := range plan.targets {
		t := t
		jti := bacrypto.RandomString(32, "a-z", "A-Z", "0-9")
		payload := jsonx.O("iss", iss, "aud", t.client.ClientID, "sub", t.sub, "sid", plan.sessionID,
			"iat", iat, "exp", exp, "jti", jti, "events", jsonx.O(backchannelLogoutEventURI, jsonx.NewObject()))
		token, err := jwt.SignJWT(ctx, jwt.SignConfig{Options: jo, Payload: payload, Header: &jwt.Header{Typ: logoutTokenJWTType}, ResolvedKey: key})
		if err != nil {
			log.Warn("back-channel logout to client "+t.client.ClientID+" failed", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := "logout_token=" + formEncode(token)
			rc, cancel := context.WithTimeout(context.WithoutCancel(c), backchannelDispatchTimeout)
			defer cancel()
			req, err := http.NewRequestWithContext(rc, http.MethodPost, t.client.BackchannelLogoutURI, strings.NewReader(body))
			if err != nil {
				log.Warn("back-channel logout to client "+t.client.ClientID+" failed", err)
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			res, err := BackchannelHTTPClient.Do(req)
			if err != nil {
				log.Warn("back-channel logout to client "+t.client.ClientID+" failed", err)
				return
			}
			res.Body.Close()
			if res.StatusCode != 200 && res.StatusCode != 204 {
				log.Warn(fmt.Sprintf("back-channel logout to client %s returned %d", t.client.ClientID, res.StatusCode))
			}
		}()
	}
	wg.Wait()
}

// backchannelPlans keeps the plans prepared in session delete "before" hooks until the
// matching "after" hook (keyed by endpoint context and session id).
type backchannelPlans struct {
	mu sync.Mutex
	m  map[*betterauth.EndpointContext]map[string]*backchannelPlan
}

func (b *backchannelPlans) put(ctx *betterauth.EndpointContext, sessionID string, p *backchannelPlan) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[*betterauth.EndpointContext]map[string]*backchannelPlan{}
	}
	if b.m[ctx] == nil {
		b.m[ctx] = map[string]*backchannelPlan{}
	}
	b.m[ctx][sessionID] = p
}

func (b *backchannelPlans) take(ctx *betterauth.EndpointContext, sessionID string) *backchannelPlan {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.m[ctx]
	if m == nil {
		return nil
	}
	p := m[sessionID]
	delete(m, sessionID)
	if len(m) == 0 {
		delete(b.m, ctx)
	}
	return p
}

func sessionDeleteHooks(o *resolved) betterauth.DBOperationHooks {
	plans := &backchannelPlans{}
	return betterauth.DBOperationHooks{
		Before: func(c context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
			ec := betterauth.EndpointContextFrom(c)
			if ec == nil {
				return nil, nil
			}
			plan := prepareBackchannelLogoutPlan(ec, c, o, recStr(data, "id"), recStr(data, "userId"))
			if plan == nil {
				return nil, nil
			}
			plans.put(ec, recStr(data, "id"), plan)
			return nil, nil
		},
		After: func(c context.Context, data adapter.Record) error {
			ec := betterauth.EndpointContextFrom(c)
			if ec == nil {
				return nil
			}
			plan := plans.take(ec, recStr(data, "id"))
			if plan == nil {
				return nil
			}
			ec.Auth.RunInBackgroundOrAwait(func() error {
				applyBackchannelLogoutPlan(ec, c, o, plan)
				return nil
			})
			return nil
		},
	}
}

// ---- RP-initiated logout ----

type logoutRequest struct {
	IDTokenHint           *string
	ClientID              string
	PostLogoutRedirectURI string
	State                 *string
}

type logoutConfirmation struct {
	SessionID             string
	ClientID              string
	PostLogoutRedirectURI string
	State                 *string
	RedirectInvalid       *bool
	ExpiresAt             float64
}

func escapeHTML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

func isBrowserNavigation(ctx *betterauth.EndpointContext) bool {
	var h http.Header
	if ctx.Request != nil {
		h = ctx.Request.Header
	} else {
		h = ctx.Headers
	}
	if h == nil || h.Get("Sec-Fetch-Mode") == "cors" {
		return false
	}
	accept := h.Get("Accept")
	return h.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(accept, "text/html") ||
		strings.Contains(accept, "application/xhtml+xml")
}

func logoutPage(title, body string, status int) *betterauth.Response {
	h := http.Header{}
	h.Set("cache-control", "no-store")
	h.Set("content-security-policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("content-type", "text/html; charset=utf-8")
	h.Set("pragma", "no-cache")
	h.Set("x-content-type-options", "nosniff")
	html := `<!doctype html><html><head><meta charset="utf-8"><title>` + escapeHTML(title) + `</title></head><body>` + body + `</body></html>`
	return &betterauth.Response{Status: status, Header: h, Body: []byte(html)}
}

func logoutConfirmationPath(ctx *betterauth.EndpointContext) string {
	return strings.TrimSuffix(ctx.Auth.BaseURL, "/") + "/oauth2/end-session/confirm"
}

func logoutConfirmationCookiePath(ctx *betterauth.EndpointContext) string {
	u, err := parseURL(logoutConfirmationPath(ctx))
	if err != nil {
		return "/oauth2/end-session/confirm"
	}
	return u.EscapedPath()
}

func logoutConfirmationPage(ctx *betterauth.EndpointContext) *betterauth.Response {
	action := logoutConfirmationPath(ctx)
	return logoutPage("Confirm logout", `<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method="post" data-oidc-logout-confirmation action="`+
		escapeHTML(action)+`"><button type="submit" name="action" value="confirm">Confirm logout</button></form></main>`, 200)
}

func logoutSuccessPage(note string) *betterauth.Response {
	msg := "Logged out."
	if note != "" {
		msg = "Logged out. " + escapeHTML(note)
	}
	return logoutPage("Logged out", `<main><p data-oidc-logout-state="logged-out">`+msg+`</p></main>`, 200)
}

func logoutErrorPage(description string, status int) *betterauth.Response {
	return logoutPage("Logout error", `<main><h1>Logout error</h1><p data-oidc-logout-state="error">`+escapeHTML(description)+`</p></main>`, status)
}

func logoutProtocolError(ctx *betterauth.EndpointContext, status, code, description string) (any, error) {
	if isBrowserNavigation(ctx) {
		sc := 500
		switch status {
		case "BAD_REQUEST":
			sc = 400
		case "UNAUTHORIZED":
			sc = 401
		}
		return logoutErrorPage(description, sc), nil
	}
	return nil, betterauth.NewAPIError(status, jsonx.O("error", code, "error_description", description))
}

func logoutCookieName(ctx *betterauth.EndpointContext) string {
	return ctx.Auth.AuthCookies.SessionToken.Name + logoutConfirmationSuffix
}

func logoutCookieOptions(ctx *betterauth.EndpointContext, maxAge int) betterauth.CookieOptions {
	o := ctx.Auth.AuthCookies.SessionToken.Attributes
	o.HTTPOnly = true
	o.MaxAge = betterauth.Int(maxAge)
	o.Path = logoutConfirmationCookiePath(ctx)
	o.SameSite = "lax"
	return o
}

func setLogoutConfirmationState(ctx *betterauth.EndpointContext, sessionID string, c logoutConfirmation) {
	state := jsonx.NewObject()
	if sessionID != "" {
		state.Set("sessionId", sessionID)
	}
	if c.ClientID != "" {
		state.Set("clientId", c.ClientID)
	}
	if c.PostLogoutRedirectURI != "" {
		state.Set("postLogoutRedirectUri", c.PostLogoutRedirectURI)
	}
	if c.State != nil {
		state.Set("state", *c.State)
	}
	if c.RedirectInvalid != nil {
		state.Set("redirectInvalid", *c.RedirectInvalid)
	}
	state.Set("expiresAt", time.Now().UnixMilli()+logoutConfirmationTTLSeconds*1000)
	b, _ := jsonx.Marshal(state)
	ctx.SetSignedCookie(logoutCookieName(ctx), string(b), ctx.Auth.Secret, logoutCookieOptions(ctx, logoutConfirmationTTLSeconds))
}

func getLogoutConfirmationState(ctx *betterauth.EndpointContext) *logoutConfirmation {
	value, ok := ctx.GetSignedCookie(logoutCookieName(ctx), ctx.Auth.Secret)
	if !ok {
		return nil
	}
	pv, err := jsonx.Parse([]byte(value))
	if err != nil {
		return nil
	}
	r, ok := pv.(*jsonx.Object)
	if !ok {
		return nil
	}
	nonEmpty := func(k string) (string, bool, bool) {
		v, has := r.Get(k)
		if !has {
			return "", false, true
		}
		s, isStr := v.(string)
		return s, true, isStr && s != ""
	}
	sid, hasSID, okSID := nonEmpty("sessionId")
	cid, hasCID, okCID := nonEmpty("clientId")
	uri, hasURI, okURI := nonEmpty("postLogoutRedirectUri")
	if (hasSID && !okSID) || (hasCID && !okCID) || (hasURI && !okURI) {
		return nil
	}
	out := &logoutConfirmation{SessionID: sid, ClientID: cid, PostLogoutRedirectURI: uri}
	if v, has := r.Get("state"); has {
		s, isStr := v.(string)
		if !isStr {
			return nil
		}
		out.State = &s
	}
	if v, has := r.Get("redirectInvalid"); has {
		b, isBool := v.(bool)
		if !isBool {
			return nil
		}
		out.RedirectInvalid = &b
	}
	if hasURI && !hasCID {
		return nil
	}
	exp, isNum := mustGetObj(r, "expiresAt").(float64)
	if !isNum {
		return nil
	}
	out.ExpiresAt = exp
	return out
}

func mustGetObj(o *jsonx.Object, k string) any { v, _ := o.Get(k); return v }

func clearLogoutConfirmationState(ctx *betterauth.EndpointContext) {
	ctx.SetCookie(logoutCookieName(ctx), "", logoutCookieOptions(ctx, 0))
}

func getCurrentBrowserSession(ctx *betterauth.EndpointContext) (*betterauth.Session, error) {
	token, ok := ctx.GetSignedCookie(ctx.Auth.AuthCookies.SessionToken.Name, ctx.Auth.Secret)
	if !ok || token == "" {
		return nil, nil
	}
	s, err := ctx.Auth.InternalAdapter.FindSession(ctx.Context(), token)
	if err != nil {
		ctx.Auth.Logger.Error("Failed to read the current logout session", err)
		return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error", "server_error", "error_description", "Unable to read the current session"))
	}
	if s == nil {
		return nil, nil
	}
	return s.Session, nil
}

func findHintedSession(ctx *betterauth.EndpointContext, sessionID string) (adapter.Record, error) {
	r, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "session",
		Where: []adapter.Where{{Field: "id", Value: sessionID}}})
	if err != nil {
		ctx.Auth.Logger.Error("Failed to read the hinted logout session", err)
		return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error", "server_error", "error_description", "Unable to read the hinted session"))
	}
	return r, nil
}

func deleteLogoutSession(ctx *betterauth.EndpointContext, token string) error {
	if token == "" {
		return betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error", "server_error", "error_description", "Unable to complete logout"))
	}
	if err := ctx.Auth.InternalAdapter.DeleteSession(ctx.Context(), token); err != nil {
		ctx.Auth.Logger.Error("Failed to delete the logout session", err)
		return betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error", "server_error", "error_description", "Unable to complete logout"))
	}
	return nil
}

func getLogoutClient(ctx *betterauth.EndpointContext, o *resolved, clientID string) (*SchemaClient, error) {
	c, err := getClient(ctx, o, clientID)
	if err != nil {
		if _, ok := betterauth.AsAPIError(err); !ok || true {
			ctx.Auth.Logger.Error("Failed to resolve the logout client", err)
			return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("error", "server_error", "error_description", "Unable to resolve the logout client"))
		}
	}
	return c, nil
}

func logoutAudiences(v any) []string {
	var vals []any
	if arr, ok := v.([]any); ok {
		vals = arr
	} else {
		vals = []any{v}
	}
	var out []string
	for _, x := range vals {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func hintClientID(p *jsonx.Object) string {
	aud, _ := p.Get("aud")
	if s, ok := aud.(string); ok && s != "" {
		return s
	}
	if s := objString(p, "azp"); s != "" {
		return s
	}
	if a := logoutAudiences(aud); len(a) == 1 {
		return a[0]
	}
	return ""
}

func resolveHintClient(ctx *betterauth.EndpointContext, o *resolved, hint, clientID string) (*SchemaClient, error) {
	if clientID != "" {
		return getLogoutClient(ctx, o, clientID)
	}
	decoded, err := oauthcore.DecodeJWT(hint)
	if err != nil {
		return nil, nil
	}
	if c := hintClientID(decoded); c != "" {
		return getLogoutClient(ctx, o, c)
	}
	return nil, nil
}

func verifyLogoutHint(ctx *betterauth.EndpointContext, o *resolved, hint string, client *SchemaClient) *jsonx.Object {
	var payload *jsonx.Object
	if o.DisableJwtPlugin {
		if client.ClientSecret == "" {
			return nil
		}
		secret, err := decryptStoredClientSecret(ctx, o.storeClientSecretMode(), client.ClientSecret)
		if err != nil {
			return nil
		}
		v, err := oauthcore.CompactVerify(hint, oauthcore.StaticKey([]byte(secret)), nil)
		if err != nil {
			return nil
		}
		pv, err := jsonx.Parse(v.RawPayload)
		if err != nil {
			return nil
		}
		payload, _ = pv.(*jsonx.Object)
	} else {
		jo, err := jwtOptions(ctx.Auth)
		if err != nil {
			return nil
		}
		jwksURL := ""
		if jo.JWKS != nil && jo.JWKS.RemoteURL != "" {
			jwksURL = jo.JWKS.RemoteURL
		} else {
			path := "/jwks"
			if jo.JWKS != nil && jo.JWKS.JWKSPath != "" {
				path = jo.JWKS.JWKSPath
			}
			jwksURL = ctx.Auth.BaseURL + path
		}
		jwks, err := oauthcore.GetJWKS(ctx.Context(), hint, oauthcore.JWKSFetch{URL: jwksURL})
		if err != nil {
			return nil
		}
		keys, err := oauthcore.LocalJWKSet(jwks)
		if err != nil {
			return nil
		}
		v, err := oauthcore.CompactVerify(hint, keys, nil)
		if err != nil {
			return nil
		}
		pv, err := jsonx.Parse(v.RawPayload)
		if err != nil {
			return nil
		}
		payload, _ = pv.(*jsonx.Object)
	}
	if payload == nil {
		return nil
	}
	if objString(payload, "iss") != getIssuer(ctx, o) {
		return nil
	}
	aud, _ := payload.Get("aud")
	if !contains(logoutAudiences(aud), client.ClientID) {
		return nil
	}
	if objString(payload, "sid") == "" || objString(payload, "sub") == "" {
		return nil
	}
	return payload
}

func registeredLogoutRedirect(client *SchemaClient, requested string, state *string) (string, bool) {
	if requested == "" {
		return "", false
	}
	if !contains(client.PostLogoutRedirectURIs, requested) {
		return "", true
	}
	if state == nil || *state == "" {
		return requested, false
	}
	out, err := setSearchParams(requested, "state", *state)
	if err != nil {
		return "", true
	}
	return out, false
}

func logoutConfirmationContext(client *SchemaClient, req logoutRequest) logoutConfirmation {
	if req.PostLogoutRedirectURI == "" {
		return logoutConfirmation{}
	}
	if _, invalid := registeredLogoutRedirect(client, req.PostLogoutRedirectURI, req.State); invalid {
		return logoutConfirmation{RedirectInvalid: boolPtr(true)}
	}
	return logoutConfirmation{ClientID: client.ClientID, PostLogoutRedirectURI: req.PostLogoutRedirectURI, State: req.State}
}

func confirmedLogoutRedirect(ctx *betterauth.EndpointContext, o *resolved, s *logoutConfirmation) (string, bool, error) {
	if s.RedirectInvalid != nil && *s.RedirectInvalid {
		return "", true, nil
	}
	if s.ClientID == "" || s.PostLogoutRedirectURI == "" {
		return "", false, nil
	}
	c, err := getLogoutClient(ctx, o, s.ClientID)
	if err != nil {
		return "", false, err
	}
	if c == nil || c.IsDisabled() || !isTrue(c.EnableEndSession) {
		return "", true, nil
	}
	uri, invalid := registeredLogoutRedirect(c, s.PostLogoutRedirectURI, s.State)
	return uri, invalid, nil
}

func confirmationRequired(ctx *betterauth.EndpointContext, current *betterauth.Session, c logoutConfirmation) (any, error) {
	if current == nil {
		if isBrowserNavigation(ctx) {
			setLogoutConfirmationState(ctx, "", c)
			return logoutConfirmationPage(ctx), nil
		}
		return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_request", "No active session is available for logout")
	}
	if !isBrowserNavigation(ctx) {
		return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_request", "User confirmation is required to complete logout")
	}
	setLogoutConfirmationState(ctx, current.ID, c)
	return logoutConfirmationPage(ctx), nil
}

const unregisteredRedirectNote = "The requested post-logout redirect was not registered."

func finishLogout(ctx *betterauth.EndpointContext, uri string, invalid bool) (any, error) {
	if uri != "" {
		return handleRedirect(ctx, uri)
	}
	if isBrowserNavigation(ctx) {
		note := ""
		if invalid {
			note = unregisteredRedirectNote
		}
		return logoutSuccessPage(note), nil
	}
	return betterauth.Null, nil
}

func completeConfirmedLogout(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	state := getLogoutConfirmationState(ctx)
	current, err := getCurrentBrowserSession(ctx)
	if err != nil {
		return nil, err
	}
	if state == nil || state.ExpiresAt <= float64(time.Now().UnixMilli()) {
		return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_request", "The logout confirmation is invalid or expired")
	}
	uri, invalid, err := confirmedLogoutRedirect(ctx, o, state)
	if err != nil {
		return nil, err
	}
	if current == nil {
		clearLogoutConfirmationState(ctx)
		if uri != "" {
			return handleRedirect(ctx, uri)
		}
		if isBrowserNavigation(ctx) {
			note := ""
			if invalid {
				note = unregisteredRedirectNote
			}
			return logoutSuccessPage(note), nil
		}
		return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_request", "No active session is available for logout")
	}
	if state.SessionID != "" && state.SessionID != current.ID {
		return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_request", "The logout confirmation is invalid or expired")
	}
	if err := deleteLogoutSession(ctx, current.Token); err != nil {
		return nil, err
	}
	betterauth.DeleteSessionCookie(ctx, false)
	clearLogoutConfirmationState(ctx)
	return finishLogout(ctx, uri, invalid)
}

func readLogoutRequest(ctx *betterauth.EndpointContext) logoutRequest {
	var r logoutRequest
	apply := func(m map[string]any) {
		if v, ok := m["id_token_hint"].(string); ok {
			r.IDTokenHint = &v
		}
		if v, ok := m["client_id"].(string); ok {
			r.ClientID = v
		}
		if v, ok := m["post_logout_redirect_uri"].(string); ok {
			r.PostLogoutRedirectURI = v
		}
		if v, ok := m["state"].(string); ok {
			r.State = &v
		}
	}
	apply(ctx.Query)
	apply(bodyMap(ctx))
	return r
}

// rpInitiatedLogoutEndpoint handles GET/POST /oauth2/end-session.
func rpInitiatedLogoutEndpoint(ctx *betterauth.EndpointContext, o *resolved) (any, error) {
	req := readLogoutRequest(ctx)
	current, err := getCurrentBrowserSession(ctx)
	if err != nil {
		return nil, err
	}
	if req.IDTokenHint == nil {
		var conf logoutConfirmation
		if req.ClientID != "" {
			c, err := getLogoutClient(ctx, o, req.ClientID)
			if err != nil {
				return nil, err
			}
			if c == nil {
				return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_client", "The logout client does not exist")
			}
			if c.IsDisabled() {
				return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_client", "The logout client is disabled")
			}
			if !isTrue(c.EnableEndSession) {
				return logoutProtocolError(ctx, "UNAUTHORIZED", "invalid_client", "The client is not allowed to initiate logout")
			}
			conf = logoutConfirmationContext(c, req)
		}
		return confirmationRequired(ctx, current, conf)
	}
	client, err := resolveHintClient(ctx, o, *req.IDTokenHint, req.ClientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		if current != nil && isBrowserNavigation(ctx) {
			return confirmationRequired(ctx, current, logoutConfirmation{})
		}
		return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_client", "The logout client does not exist")
	}
	if client.IsDisabled() {
		return logoutProtocolError(ctx, "BAD_REQUEST", "invalid_client", "The logout client is disabled")
	}
	if !isTrue(client.EnableEndSession) {
		return logoutProtocolError(ctx, "UNAUTHORIZED", "invalid_client", "The client is not allowed to initiate logout")
	}
	payload := verifyLogoutHint(ctx, o, *req.IDTokenHint, client)
	if payload == nil {
		if current != nil && isBrowserNavigation(ctx) {
			var conf logoutConfirmation
			if req.ClientID != "" {
				conf = logoutConfirmationContext(client, req)
			}
			return confirmationRequired(ctx, current, conf)
		}
		return logoutProtocolError(ctx, "UNAUTHORIZED", "invalid_token", "The id_token_hint is invalid")
	}
	sessionID := objString(payload, "sid")
	hinted, err := findHintedSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	matches := current != nil && current.ID == sessionID
	if current != nil && !matches {
		return confirmationRequired(ctx, current, logoutConfirmationContext(client, req))
	}
	uri, invalid := registeredLogoutRedirect(client, req.PostLogoutRedirectURI, req.State)
	token := ""
	switch {
	case hinted != nil:
		token = recStr(hinted, "token")
	case matches:
		token = current.Token
	}
	if hinted != nil || matches {
		if err := deleteLogoutSession(ctx, token); err != nil {
			return nil, err
		}
	}
	if matches {
		betterauth.DeleteSessionCookie(ctx, false)
	}
	clearLogoutConfirmationState(ctx)
	return finishLogout(ctx, uri, invalid)
}

var _ = jose.ErrInvalid
