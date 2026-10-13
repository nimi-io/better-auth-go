package oauthprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of packages/oauth-provider/src/logout.test.ts.

// ---- shared helpers (prefix lo) ----

// loAdapter wraps the database adapter to observe or fail operations (stands in for
// vi.spyOn on the adapter / internal adapter).
type loAdapter struct {
	adapter.Adapter
	mu                sync.Mutex
	countFindOne      bool
	findOneModels     []string
	findManyModels    []string
	trackUpdateMany   bool
	updateManyModels  []string
	failSessionDelete bool
}

func (a *loAdapter) Custom() adapter.CustomAdapter {
	if c, ok := a.Adapter.(interface{ Custom() adapter.CustomAdapter }); ok {
		return c.Custom()
	}
	return nil
}

func (a *loAdapter) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	a.mu.Lock()
	if a.countFindOne {
		a.findOneModels = append(a.findOneModels, in.Model)
	}
	a.mu.Unlock()
	return a.Adapter.FindOne(ctx, in)
}

func (a *loAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	a.mu.Lock()
	if a.countFindOne {
		a.findManyModels = append(a.findManyModels, in.Model)
	}
	a.mu.Unlock()
	return a.Adapter.FindMany(ctx, in)
}

func (a *loAdapter) UpdateMany(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (int64, error) {
	a.mu.Lock()
	if a.trackUpdateMany {
		a.updateManyModels = append(a.updateManyModels, model)
	}
	a.mu.Unlock()
	return a.Adapter.UpdateMany(ctx, model, where, update)
}

func (a *loAdapter) sessionDeleteFails(model string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.failSessionDelete && model == "session"
}

func (a *loAdapter) Delete(ctx context.Context, model string, where []adapter.Where) error {
	if a.sessionDeleteFails(model) {
		return errors.New("adapter failure")
	}
	return a.Adapter.Delete(ctx, model, where)
}

func (a *loAdapter) DeleteMany(ctx context.Context, model string, where []adapter.Where) (int64, error) {
	if a.sessionDeleteFails(model) {
		return 0, errors.New("adapter failure")
	}
	return a.Adapter.DeleteMany(ctx, model, where)
}

func (a *loAdapter) ConsumeOne(ctx context.Context, model string, where []adapter.Where) (adapter.Record, error) {
	if a.sessionDeleteFails(model) {
		return nil, errors.New("adapter failure")
	}
	return a.Adapter.ConsumeOne(ctx, model, where)
}

func (a *loAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return a.Adapter.Transaction(ctx, func(c context.Context, _ adapter.Adapter) error { return fn(c, a) })
}

// loNewEnv builds an env whose adapter is wrapped by a loAdapter.
func loNewEnv(t *testing.T, opts Options, eo envOptions) (*testEnv, *loAdapter) {
	t.Helper()
	wrapper := &loAdapter{}
	prev := eo.mutate
	eo.mutate = func(c *betterauth.Config) {
		if prev != nil {
			prev(c)
		}
		inner := c.Database
		c.Database = func(ao adapter.Options) (adapter.Adapter, error) {
			a, err := inner(ao)
			if err != nil {
				return nil, err
			}
			wrapper.Adapter = a
			return wrapper, nil
		}
	}
	return newEnv(t, opts, eo), wrapper
}

// loSessionActive mirrors `await auth.api.getSession({ headers }) !== null`.
func loSessionActive(env *testEnv, h http.Header) bool {
	env.t.Helper()
	res, err := env.call("getSession", betterauth.CallInput{Headers: h})
	if err != nil {
		env.t.Fatalf("getSession: %d %v", err.StatusCode, errBody(err))
	}
	m := decodeMap(env.t, res)
	return m != nil && m["session"] != nil
}

func loSessionID(env *testEnv, h http.Header) string {
	env.t.Helper()
	res, err := env.call("getSession", betterauth.CallInput{Headers: h})
	if err != nil {
		env.t.Fatalf("getSession: %v", errBody(err))
	}
	m := decodeMap(env.t, res)
	if m == nil {
		return ""
	}
	s, _ := m["session"].(map[string]any)
	id, _ := s["id"].(string)
	return id
}

func loSessionToken(env *testEnv, h http.Header) string {
	env.t.Helper()
	res, err := env.call("getSession", betterauth.CallInput{Headers: h})
	if err != nil {
		env.t.Fatalf("getSession: %v", errBody(err))
	}
	m := decodeMap(env.t, res)
	s, _ := m["session"].(map[string]any)
	tok, _ := s["token"].(string)
	if tok == "" {
		env.t.Fatalf("Expected an active test session")
	}
	return tok
}

func loStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// loAuthorizeRedirect runs /oauth2/authorize and returns the redirect location.
func loAuthorizeRedirect(env *testEnv, headers http.Header, clientID, redirectURI, state string, scopes []string, challenge string) string {
	env.t.Helper()
	res := env.do("GET", authorizeURL("response_type", "code", "client_id", clientID, "state", state,
		"scope", strings.Join(scopes, " "), "redirect_uri", redirectURI, "code_challenge", challenge,
		"code_challenge_method", "S256"), nil, headers)
	loc := res.location()
	if loc == "" {
		if m := res.json(); m != nil {
			loc, _ = m["url"].(string)
		}
	}
	return loc
}

// loExchangeCode posts the authorization code with client_secret_post credentials.
func loExchangeCode(env *testEnv, code, verifier, redirectURI, clientID, secret string) map[string]any {
	env.t.Helper()
	res := env.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {redirectURI}, "client_id": {clientID}, "client_secret": {secret}}, nil)
	if res.status != 200 {
		env.t.Fatalf("token: %d %s", res.status, res.body)
	}
	return res.json()
}

// loIssueTokens runs the authorization code flow and returns the token response.
func loIssueTokens(env *testEnv, headers http.Header, client map[string]any, redirectURI string, scopes []string) map[string]any {
	env.t.Helper()
	verifier, challenge := pkcePair()
	loc := loAuthorizeRedirect(env, headers, loStr(client, "client_id"), redirectURI, "123", scopes, challenge)
	u, err := url.Parse(loc)
	if err != nil || u.Query().Get("code") == "" {
		env.t.Fatalf("no authorization code in %q", loc)
	}
	return loExchangeCode(env, u.Query().Get("code"), verifier, redirectURI, loStr(client, "client_id"), loStr(client, "client_secret"))
}

// ---- describe("oauth logout") ----

type loLogoutSuite struct {
	t                 *testing.T
	env               *testEnv
	ad                *loAdapter
	headers           http.Header
	oauthClient       map[string]any
	redirectURI       string
	logoutRedirectURI string
	scopes            []string
}

const loCSP = "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func loNewLogoutSuite(t *testing.T, disableJwtPlugin bool) *loLogoutSuite {
	scopes := []string{"openid", "email", "profile", "offline_access"}
	env, ad := loNewEnv(t, Options{LoginPage: "/login", ConsentPage: "/consent", AllowDynamicClientRegistration: true,
		Scopes: scopes, DisableJwtPlugin: disableJwtPlugin}, envOptions{mutate: func(c *betterauth.Config) {
		if !disableJwtPlugin {
			// advanced.disableOriginCheck: false (only the main describe sets it upstream)
			if c.Advanced == nil {
				c.Advanced = &betterauth.AdvancedConfig{}
			}
			c.Advanced.DisableOriginCheck = betterauth.Bool(false)
		}
	}})
	s := &loLogoutSuite{t: t, env: env, ad: ad, scopes: scopes,
		redirectURI:       "http://localhost:5000/api/auth/callback/test",
		logoutRedirectURI: "http://localhost:5000/api/auth/callback/logout"}
	s.headers = env.signInWithTestUser()
	s.headers.Set("Origin", testBaseURL)
	resp := env.adminCreateClient(s.headers, map[string]any{
		"redirect_uris":              []any{s.redirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
		"enable_end_session":         true,
	})
	if resp["client_id"] == nil || resp["user_id"] == nil || resp["client_secret"] == nil {
		t.Fatalf("client: %v", resp)
	}
	if uris, _ := resp["redirect_uris"].([]any); len(uris) != 1 || uris[0] != s.redirectURI {
		t.Fatalf("redirect_uris: %v", resp["redirect_uris"])
	}
	if resp["enable_end_session"] != true {
		t.Fatalf("enable_end_session: %v", resp["enable_end_session"])
	}
	s.oauthClient = resp
	// beforeEach: fresh session
	s.headers = env.signInWithTestUser()
	s.headers.Set("Origin", testBaseURL)
	return s
}

type loEndSessionInput struct {
	method               string
	query                map[string]string
	body                 map[string]string
	accept               string
	excludeSessionCookie bool
	origin               string
}

func (s *loLogoutSuite) requestEndSession(in loEndSessionInput) *response {
	s.t.Helper()
	method := in.method
	if method == "" {
		method = "GET"
	}
	q := url.Values{}
	for k, v := range in.query {
		q.Set(k, v)
	}
	path := "/oauth2/end-session"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	h := s.headers.Clone()
	if in.excludeSessionCookie {
		h.Del("Cookie")
	}
	accept := in.accept
	if accept == "" {
		accept = "text/html"
	}
	h.Set("Accept", accept)
	var body any
	if in.body != nil {
		form := url.Values{}
		for k, v := range in.body {
			form.Set(k, v)
		}
		body = form.Encode()
		h.Set("Content-Type", "application/x-www-form-urlencoded")
		origin := in.origin
		if origin == "" {
			origin = testBaseURL
		}
		h.Set("Origin", origin)
	}
	return s.env.do(method, path, body, h)
}

func (s *loLogoutSuite) requestConfirmation(accept, origin string) *response {
	s.t.Helper()
	h := s.headers.Clone()
	if accept == "" {
		accept = "text/html"
	}
	if origin == "" {
		origin = testBaseURL
	}
	h.Set("Accept", accept)
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Set("Origin", origin)
	return s.env.do("POST", "/oauth2/end-session/confirm", url.Values{"action": {"confirm"}}.Encode(), h)
}

func (s *loLogoutSuite) captureResponseCookies(res *response) {
	s.headers = mergeCookies(s.headers, res.header)
}

func loConfirmationCookie(t *testing.T, res *response) (string, string, string) {
	t.Helper()
	for _, sc := range res.header.Values("Set-Cookie") {
		name, value, _ := betterauth.ParseSetCookie(sc)
		if strings.HasSuffix(name, ".oauth_logout_confirmation") {
			return name, value, sc
		}
	}
	t.Fatalf("confirmation cookie was not set")
	return "", "", ""
}

func loReplaceCookie(h http.Header, name, value string) {
	var parts []string
	replaced := false
	for _, c := range betterauth.ParseCookies(h.Get("Cookie")) {
		v := c.Value
		if c.Name == name {
			v, replaced = value, true
		}
		parts = append(parts, c.Name+"="+url.QueryEscape(v))
	}
	if !replaced {
		parts = append(parts, name+"="+url.QueryEscape(value))
	}
	h.Set("Cookie", strings.Join(parts, "; "))
}

func (s *loLogoutSuite) expectConfirmationHeaders(res *response) {
	s.t.Helper()
	if got := res.header.Get("Cache-Control"); got != "no-store" {
		s.t.Fatalf("cache-control: %q", got)
	}
	if got := res.header.Get("Content-Security-Policy"); got != loCSP {
		s.t.Fatalf("csp: %q", got)
	}
}

func (s *loLogoutSuite) completeBrowserConfirmation(query map[string]string) (*response, *response) {
	s.t.Helper()
	confirmation := s.requestEndSession(loEndSessionInput{query: query, accept: "text/html"})
	s.captureResponseCookies(confirmation)
	if confirmation.status != 200 {
		s.t.Fatalf("confirmation: %d %s", confirmation.status, confirmation.body)
	}
	s.expectConfirmationHeaders(confirmation)
	if !strings.Contains(string(confirmation.body), "Confirm logout") {
		s.t.Fatalf("body: %s", confirmation.body)
	}
	return confirmation, s.requestConfirmation("text/html", "")
}

func (s *loLogoutSuite) issueTokens(client map[string]any, headers http.Header) map[string]any {
	s.t.Helper()
	if client == nil {
		client = s.oauthClient
	}
	if headers == nil {
		headers = s.headers
	}
	return loIssueTokens(s.env, headers, client, s.redirectURI, s.scopes)
}

func (s *loLogoutSuite) createLogoutRedirectClient() map[string]any {
	s.t.Helper()
	resp := s.env.adminCreateClient(s.headers, map[string]any{
		"redirect_uris":              []any{s.redirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"enable_end_session":         true,
		"skip_consent":               true,
		"post_logout_redirect_uris":  []any{s.logoutRedirectURI},
	})
	if resp["client_id"] == nil || resp["client_secret"] == nil {
		s.t.Fatalf("logout redirect client registration failed")
	}
	return resp
}

// clientEndSession mirrors client.oauth2.endSession({ query }) (a plain fetch without
// cookies or an html Accept header).
func (s *loLogoutSuite) clientEndSession(query map[string]string) *response {
	s.t.Helper()
	q := url.Values{}
	for k, v := range query {
		q.Set(k, v)
	}
	return s.env.do("GET", "/oauth2/end-session?"+q.Encode(), nil, nil)
}

func loBody(r *response) string { return string(r.body) }

func loExpectContains(t *testing.T, body, sub string) {
	t.Helper()
	if !strings.Contains(body, sub) {
		t.Fatalf("expected body to contain %q, got %s", sub, body)
	}
}

func loExpectNotContains(t *testing.T, body, sub string) {
	t.Helper()
	if strings.Contains(body, sub) {
		t.Fatalf("expected body not to contain %q, got %s", sub, body)
	}
}

// loUnsecuredJWT mirrors jose's UnsecuredJWT(...).encode().
func loUnsecuredJWT(payload map[string]any) string {
	raw, _ := jsonx.Marshal(payload)
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(raw) + "."
}

func (s *loLogoutSuite) runAuthFlow(t *testing.T, client map[string]any) map[string]any {
	t.Helper()
	verifier, challenge := pkcePair()
	loc := loAuthorizeRedirect(s.env, s.headers, loStr(client, "client_id"), s.redirectURI, "123", s.scopes, challenge)
	if !strings.Contains(loc, s.redirectURI) || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=123") {
		t.Fatalf("callback: %q", loc)
	}
	u, _ := url.Parse(loc)
	tokens := loExchangeCode(s.env, u.Query().Get("code"), verifier, s.redirectURI, loStr(client, "client_id"), loStr(client, "client_secret"))
	if tokens["access_token"] == nil || tokens["id_token"] == nil || tokens["refresh_token"] == nil {
		t.Fatalf("tokens: %v", tokens)
	}
	if tokens["scope"] != strings.Join(s.scopes, " ") {
		t.Fatalf("scope: %v", tokens["scope"])
	}
	return tokens
}

func TestLo_OAuthLogout(t *testing.T) {
	t.Run("should fail with invalid id_token_hint", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		res := s.clientEndSession(map[string]string{"id_token_hint": ""})
		if res.status < 400 || res.status >= 500 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
	})

	t.Run("requires confirmation before deleting the session without a hint", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
		confirmation, completed := s.completeBrowserConfirmation(nil)
		loExpectContains(t, loBody(confirmation), `<form method="post" data-oidc-logout-confirmation`)
		loExpectContains(t, loBody(confirmation), `name="action" value="confirm"`)
		if completed.status != 200 {
			t.Fatalf("completed: %d %s", completed.status, completed.body)
		}
		s.expectConfirmationHeaders(completed)
		loExpectContains(t, loBody(completed), `data-oidc-logout-state="logged-out"`)
		loExpectContains(t, loBody(completed), "Logged out")
		if completed.location() != "" {
			t.Fatalf("location: %q", completed.location())
		}
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("does not delete on an initial no-hint POST", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		res := s.requestEndSession(loEndSessionInput{method: "POST", body: map[string]string{}, accept: "text/html"})
		if res.status != 200 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		loExpectContains(t, loBody(res), "data-oidc-logout-confirmation")
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("confirms a no-hint form POST when the initial navigation omits the session cookie", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		sessionHeaders := s.headers.Clone()
		initial := s.requestEndSession(loEndSessionInput{method: "POST", body: map[string]string{}, accept: "text/html",
			excludeSessionCookie: true, origin: "https://rp.example"})
		if initial.status != 200 {
			t.Fatalf("status %d %s", initial.status, initial.body)
		}
		loExpectContains(t, loBody(initial), `<form method="post" data-oidc-logout-confirmation`)
		loExpectNotContains(t, loBody(initial), `data-oidc-logout-state="logged-out"`)
		if !loSessionActive(s.env, sessionHeaders) {
			t.Fatal("expected session")
		}
		s.captureResponseCookies(initial)
		completed := s.requestConfirmation("text/html", "")
		if completed.status != 200 {
			t.Fatalf("completed: %d %s", completed.status, completed.body)
		}
		loExpectContains(t, loBody(completed), `data-oidc-logout-state="logged-out"`)
		if loSessionActive(s.env, sessionHeaders) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("does not delete when the confirmation state is missing or tampered", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		confirmation := s.requestEndSession(loEndSessionInput{accept: "text/html"})
		loExpectContains(t, loBody(confirmation), "data-oidc-logout-confirmation")
		missing := s.requestConfirmation("text/html", "")
		if missing.status < 400 {
			t.Fatalf("missing state: %d", missing.status)
		}
		s.expectConfirmationHeaders(missing)
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
		s.captureResponseCookies(confirmation)
		name, _, _ := loConfirmationCookie(t, confirmation)
		loReplaceCookie(s.headers, name, "tampered")
		tampered := s.requestConfirmation("text/html", "")
		if tampered.status < 400 {
			t.Fatalf("tampered state: %d", tampered.status)
		}
		if got := tampered.header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("cache-control: %q", got)
		}
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("rejects confirmation state bound to a different current session", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		confirmation := s.requestEndSession(loEndSessionInput{accept: "text/html"})
		s.captureResponseCookies(confirmation)
		_, _, setCookie := loConfirmationCookie(t, confirmation)
		other := s.env.signInWithTestUser()
		sc := http.Header{}
		sc.Add("Set-Cookie", setCookie)
		other = mergeCookies(other, sc)
		other.Set("Origin", testBaseURL)
		original := s.headers
		s.headers = other
		res := s.requestConfirmation("text/html", "")
		s.headers = original
		if res.status < 400 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		if !loSessionActive(s.env, original) || !loSessionActive(s.env, other) {
			t.Fatal("expected both sessions to remain")
		}
	})

	t.Run("rejects a cross-origin confirmation POST", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		confirmation := s.requestEndSession(loEndSessionInput{accept: "text/html"})
		s.captureResponseCookies(confirmation)
		res := s.requestConfirmation("text/html", "https://attacker.example")
		if res.status != 403 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("does not redirect or delete for a redirect request without a hint", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{"post_logout_redirect_uri": s.logoutRedirectURI}, accept: "text/html"})
		if res.status != 200 || res.location() != "" {
			t.Fatalf("status %d %q", res.status, res.location())
		}
		loExpectContains(t, loBody(res), "data-oidc-logout-confirmation")
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("redirects after confirming a no-hint request for an identified client", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		rc := s.createLogoutRedirectClient()
		confirmation := s.requestEndSession(loEndSessionInput{query: map[string]string{
			"client_id": loStr(rc, "client_id"), "post_logout_redirect_uri": s.logoutRedirectURI, "state": "confirmed-state",
		}, accept: "text/html"})
		s.captureResponseCookies(confirmation)
		if confirmation.status != 200 || confirmation.location() != "" {
			t.Fatalf("confirmation: %d %q %s", confirmation.status, confirmation.location(), confirmation.body)
		}
		loExpectContains(t, loBody(confirmation), "data-oidc-logout-confirmation")
		completed := s.requestConfirmation("text/html", "")
		if completed.status != 302 {
			t.Fatalf("completed: %d %s", completed.status, completed.body)
		}
		if completed.location() != s.logoutRedirectURI+"?state=confirmed-state" {
			t.Fatalf("location: %q", completed.location())
		}
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("revalidates a no-hint redirect before completing confirmation", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		rc := s.createLogoutRedirectClient()
		confirmation := s.requestEndSession(loEndSessionInput{query: map[string]string{
			"client_id": loStr(rc, "client_id"), "post_logout_redirect_uri": s.logoutRedirectURI, "state": "stale-registration-state",
		}, accept: "text/html"})
		s.captureResponseCookies(confirmation)
		if confirmation.status != 200 || confirmation.location() != "" {
			t.Fatalf("confirmation: %d %q", confirmation.status, confirmation.location())
		}
		s.env.update("oauthClient", adapter.Record{"postLogoutRedirectUris": []any{}}, eq("clientId", loStr(rc, "client_id")))
		completed := s.requestConfirmation("text/html", "")
		if completed.status != 200 || completed.location() != "" {
			t.Fatalf("completed: %d %q %s", completed.status, completed.location(), completed.body)
		}
		loExpectContains(t, loBody(completed), `data-oidc-logout-state="logged-out"`)
		loExpectContains(t, loBody(completed), "The requested post-logout redirect was not registered.")
		loExpectNotContains(t, loBody(completed), "stale-registration-state")
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("requires confirmation for a state-only request", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{"state": "opaque-state"}, accept: "text/html"})
		if res.status != 200 || res.location() != "" {
			t.Fatalf("status %d %q", res.status, res.location())
		}
		loExpectContains(t, loBody(res), "data-oidc-logout-confirmation")
		loExpectNotContains(t, loBody(res), "opaque-state")
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("rejects alg=none hints as controlled errors", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		hint := loUnsecuredJWT(map[string]any{"sid": "not-a-session", "iss": testAuthBase, "aud": loStr(s.oauthClient, "client_id")})
		res := s.clientEndSession(map[string]string{"id_token_hint": hint})
		if res.status < 400 || res.status >= 500 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("offers confirmation for an invalid hint without an unsafe redirect", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{
			"id_token_hint": "not-a-jwt", "post_logout_redirect_uri": "https://evil.example/logout",
		}, accept: "text/html"})
		if res.status != 200 || res.location() != "" {
			t.Fatalf("status %d %q", res.status, res.location())
		}
		loExpectContains(t, loBody(res), "data-oidc-logout-confirmation")
		loExpectNotContains(t, loBody(res), "evil.example")
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("does not fan out client lookups across unverified hint audiences", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		auds := make([]any, 100)
		for i := range auds {
			auds[i] = "unknown-client-" + strconv.Itoa(i)
		}
		hint := loUnsecuredJWT(map[string]any{"sid": "not-a-session", "sub": "test-user", "iss": testAuthBase, "aud": auds})
		s.ad.mu.Lock()
		s.ad.countFindOne, s.ad.findOneModels = true, nil
		s.ad.mu.Unlock()
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{"id_token_hint": hint}, accept: "text/html"})
		s.ad.mu.Lock()
		s.ad.countFindOne = false
		models := s.ad.findOneModels
		s.ad.mu.Unlock()
		if res.status != 200 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		loExpectContains(t, loBody(res), "data-oidc-logout-confirmation")
		for _, m := range models {
			if m == modelClient {
				t.Fatalf("unexpected client lookup: %v", models)
			}
		}
	})

	t.Run("resolves a valid multi-audience logout hint through azp", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		tokens := s.issueTokens(nil, nil)
		payload := decodeJWTPayload(t, loStr(tokens, "id_token"))
		clientID := loStr(s.oauthClient, "client_id")
		payload["aud"] = []any{clientID, "https://other-audience.example"}
		payload["azp"] = clientID
		signed := s.env.mustCall("signJWT", betterauth.CallInput{Body: map[string]any{"payload": payload}})
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{"id_token_hint": loStr(signed, "token")}, accept: "text/html"})
		if res.status != 200 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		loExpectContains(t, loBody(res), `data-oidc-logout-state="logged-out"`)
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("should not allow registration of rp-initiated clients, specifically enable_end_session", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		res := s.env.do("POST", "/oauth2/register", map[string]any{
			"redirect_uris":             []any{s.redirectURI},
			"application_type":          "native",
			"post_logout_redirect_uris": []any{s.logoutRedirectURI},
			"enable_end_session":        true,
		}, s.headers)
		m := res.json()
		if res.status != 200 && res.status != 201 {
			t.Fatalf("register: %d %s", res.status, res.body)
		}
		if m["client_id"] == nil || m["user_id"] == nil || m["client_secret"] == nil {
			t.Fatalf("register: %v", m)
		}
		if uris, _ := m["redirect_uris"].([]any); len(uris) != 1 || uris[0] != s.redirectURI {
			t.Fatalf("redirect_uris: %v", m["redirect_uris"])
		}
		if uris, _ := m["post_logout_redirect_uris"].([]any); len(uris) != 1 || uris[0] != s.logoutRedirectURI {
			t.Fatalf("post_logout_redirect_uris: %v", m["post_logout_redirect_uris"])
		}
		if _, ok := m["enable_end_session"]; ok {
			t.Fatalf("enable_end_session should be undefined: %v", m["enable_end_session"])
		}
	})

	t.Run("should fail for clients without enable_end_session access", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		resp := s.env.adminCreateClient(s.headers, map[string]any{
			"redirect_uris":              []any{s.redirectURI},
			"application_type":           "native",
			"token_endpoint_auth_method": "client_secret_post",
			"skip_consent":               true,
		})
		if resp["client_id"] == nil || resp["user_id"] == nil || resp["client_secret"] == nil {
			t.Fatalf("client: %v", resp)
		}
		if _, ok := resp["enable_end_session"]; ok {
			t.Fatalf("enable_end_session: %v", resp["enable_end_session"])
		}
		tokens := s.runAuthFlow(t, resp)
		if _, ok := decodeJWTPayload(t, loStr(tokens, "id_token"))["sid"]; ok {
			t.Fatal("sid should be undefined")
		}
		res := s.clientEndSession(map[string]string{"id_token_hint": loStr(tokens, "id_token")})
		if res.status != 401 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
	})

	t.Run("should pass for clients with enable_end_session access", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		loPassWithEndSession(t, s)
	})

	t.Run("supports a valid hint in a form POST", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		tokens := s.issueTokens(nil, nil)
		res := s.requestEndSession(loEndSessionInput{method: "POST", body: map[string]string{"id_token_hint": loStr(tokens, "id_token")}, accept: "application/json"})
		if res.status != 200 || res.location() != "" {
			t.Fatalf("status %d %q %s", res.status, res.location(), res.body)
		}
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("supports a valid hint through the generated client", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		tokens := s.issueTokens(nil, nil)
		// client.oauth2.endSession({ id_token_hint }) sends the hint as a JSON body.
		res := s.env.do("POST", "/oauth2/end-session", map[string]any{"id_token_hint": loStr(tokens, "id_token")}, nil)
		if res.status != 302 && (res.status != 200 || strings.TrimSpace(loBody(res)) != "null") {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("logs out a valid hinted session without browser cookies", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		tokens := s.issueTokens(nil, nil)
		res := s.env.do("GET", "/oauth2/end-session?id_token_hint="+url.QueryEscape(loStr(tokens, "id_token")), nil,
			http.Header{"Accept": {"application/json"}})
		if res.status != 200 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("requires confirmation when a valid hint conflicts with the current session", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		other := s.env.signInWithTestUser()
		otherTokens := s.issueTokens(nil, other)
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{"id_token_hint": loStr(otherTokens, "id_token")}, accept: "text/html"})
		s.captureResponseCookies(res)
		if res.status != 200 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		loExpectContains(t, loBody(res), "data-oidc-logout-confirmation")
		if !loSessionActive(s.env, s.headers) || !loSessionActive(s.env, other) {
			t.Fatal("expected both sessions to remain")
		}
	})

	t.Run("rejects a bad signed hint without deleting the session", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		tokens := s.issueTokens(nil, nil)
		parts := strings.Split(loStr(tokens, "id_token"), ".")
		replacement := "A"
		if strings.HasPrefix(parts[2], "A") {
			replacement = "B"
		}
		bad := parts[0] + "." + parts[1] + "." + replacement + parts[2][1:]
		res := s.clientEndSession(map[string]string{"id_token_hint": bad})
		if res.status < 400 || res.status >= 500 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("logs out and suppresses an unregistered post-logout redirect", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		rc := s.createLogoutRedirectClient()
		tokens := s.issueTokens(rc, nil)
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{
			"id_token_hint": loStr(tokens, "id_token"), "post_logout_redirect_uri": "https://evil.example/logout",
		}, accept: "text/html"})
		if res.status != 200 || res.location() != "" {
			t.Fatalf("status %d %q", res.status, res.location())
		}
		loExpectContains(t, loBody(res), `data-oidc-logout-state="logged-out"`)
		loExpectContains(t, loBody(res), "Logged out")
		loExpectNotContains(t, loBody(res), "evil.example")
		loExpectNotContains(t, loBody(res), "attacker")
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("logs out and suppresses a query-added post-logout redirect", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		rc := s.createLogoutRedirectClient()
		tokens := s.issueTokens(rc, nil)
		res := s.requestEndSession(loEndSessionInput{query: map[string]string{
			"id_token_hint": loStr(tokens, "id_token"), "post_logout_redirect_uri": s.logoutRedirectURI + "?attacker=1",
		}, accept: "text/html"})
		if res.status != 200 || res.location() != "" {
			t.Fatalf("status %d %q", res.status, res.location())
		}
		loExpectContains(t, loBody(res), `data-oidc-logout-state="logged-out"`)
		loExpectContains(t, loBody(res), "Logged out")
		loExpectNotContains(t, loBody(res), "attacker")
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
	})

	t.Run("surfaces session deletion failures without redirecting as successful", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		tokens := s.issueTokens(nil, nil)
		s.ad.mu.Lock()
		s.ad.failSessionDelete = true
		s.ad.mu.Unlock()
		res := s.clientEndSession(map[string]string{"id_token_hint": loStr(tokens, "id_token")})
		s.ad.mu.Lock()
		s.ad.failSessionDelete = false
		s.ad.mu.Unlock()
		if res.status < 500 || res.status >= 600 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
	})

	t.Run("should pass with redirection", func(t *testing.T) {
		s := loNewLogoutSuite(t, false)
		loPassWithRedirection(t, s, true)
	})
}

func loPassWithEndSession(t *testing.T, s *loLogoutSuite) {
	t.Helper()
	tokens := s.runAuthFlow(t, s.oauthClient)
	sid, _ := decodeJWTPayload(t, loStr(tokens, "id_token"))["sid"].(string)
	if sid == "" {
		t.Fatal("sid should be defined")
	}
	if got := loSessionID(s.env, s.headers); got != sid {
		t.Fatalf("session id %q != sid %q", got, sid)
	}
	res := s.clientEndSession(map[string]string{"id_token_hint": loStr(tokens, "id_token")})
	if res.status != 200 || strings.TrimSpace(loBody(res)) != "null" {
		t.Fatalf("logout: %d %s", res.status, res.body)
	}
	after := s.env.do("GET", "/get-session", nil, s.headers)
	if after.status != 200 || strings.TrimSpace(loBody(after)) != "null" {
		t.Fatalf("session after: %d %s", after.status, after.body)
	}
}

func loPassWithRedirection(t *testing.T, s *loLogoutSuite, withState bool) {
	t.Helper()
	resp := s.env.adminCreateClient(s.headers, map[string]any{
		"redirect_uris":              []any{s.redirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"enable_end_session":         true,
		"skip_consent":               true,
		"post_logout_redirect_uris":  []any{s.logoutRedirectURI},
	})
	if resp["client_id"] == nil || resp["user_id"] == nil || resp["client_secret"] == nil || resp["enable_end_session"] != true {
		t.Fatalf("client: %v", resp)
	}
	if uris, _ := resp["post_logout_redirect_uris"].([]any); len(uris) != 1 || uris[0] != s.logoutRedirectURI {
		t.Fatalf("post_logout_redirect_uris: %v", resp["post_logout_redirect_uris"])
	}
	tokens := s.runAuthFlow(t, resp)
	if sid, _ := decodeJWTPayload(t, loStr(tokens, "id_token"))["sid"].(string); sid == "" {
		t.Fatal("sid should be defined")
	}
	q := map[string]string{"id_token_hint": loStr(tokens, "id_token"), "post_logout_redirect_uri": s.logoutRedirectURI}
	if withState {
		q["state"] = "123"
	}
	res := s.clientEndSession(q)
	if res.status != 302 {
		t.Fatalf("status %d %s", res.status, res.body)
	}
	if withState {
		if !strings.Contains(res.location(), s.logoutRedirectURI) || !strings.Contains(res.location(), "state=123") {
			t.Fatalf("location %q", res.location())
		}
	} else if res.location() != s.logoutRedirectURI {
		t.Fatalf("location %q", res.location())
	}
}

func TestLo_OAuthLogoutConfirmationWithCustomBasePath(t *testing.T) {
	t.Run("uses the custom base path for confirmation navigation and cookies", func(t *testing.T) {
		basePath := "/custom/auth"
		env := newEnv(t, Options{LoginPage: "/login", ConsentPage: "/consent", Scopes: []string{"openid"}},
			envOptions{mutate: func(c *betterauth.Config) { c.BasePath = basePath }})
		h := env.signInWithTestUser()
		h.Set("Accept", "text/html")
		res := env.do("GET", testBaseURL+basePath+"/oauth2/end-session", nil, h)
		confirmationURL := testBaseURL + basePath + "/oauth2/end-session/confirm"
		if res.status != 200 {
			t.Fatalf("status %d %s", res.status, res.body)
		}
		loExpectContains(t, loBody(res), `action="`+confirmationURL+`"`)
		found := false
		for _, sc := range res.header.Values("Set-Cookie") {
			name, _, attrs := betterauth.ParseSetCookie(sc)
			if strings.HasSuffix(name, ".oauth_logout_confirmation") {
				found = true
				if attrs["path"] != basePath+"/oauth2/end-session/confirm" {
					t.Fatalf("cookie path %q (%s)", attrs["path"], sc)
				}
			}
		}
		if !found {
			t.Fatal("confirmation cookie was not set")
		}
		// auth.api.oauth2EndSessionConfirmation exists.
		if _, err := env.auth.API.Call(context.Background(), "oauth2EndSessionConfirmation", betterauth.CallInput{}); err != nil {
			if _, ok := betterauth.AsAPIError(err); !ok {
				t.Fatalf("oauth2EndSessionConfirmation: %v", err)
			}
		}
	})
}

func TestLo_OAuthLogoutDisableJwtPlugin(t *testing.T) {
	t.Run("should pass for clients with enable_end_session access", func(t *testing.T) {
		s := loNewLogoutSuite(t, true)
		loPassWithEndSession(t, s)
	})
	t.Run("should pass with redirection", func(t *testing.T) {
		s := loNewLogoutSuite(t, true)
		loPassWithRedirection(t, s, false)
	})
}
