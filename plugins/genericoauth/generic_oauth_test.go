package genericoauth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

// Port of packages/better-auth/src/plugins/generic-oauth/generic-oauth.test.ts.

const (
	providerID   = "test"
	clientID     = "test-client-id"
	clientSecret = "test-client-secret"
)

// setupIdP starts the mock OpenID provider with the describe-level default userinfo
// response (server.service.on("beforeUserinfo")).
func setupIdP(t *testing.T) *mockIdP {
	t.Helper()
	idp := newIdP(t)
	idp.onUserinfo(func(b *map[string]any, s *int) {
		*b = map[string]any{"email": "oauth2@test.com", "name": "OAuth2 Test", "sub": "oauth2",
			"picture": "https://test.com/picture.png", "email_verified": true}
		*s = 200
	}, false)
	return idp
}

func discoveryConfig(id string) Config {
	return Config{ProviderID: id, DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret, PKCE: ptrBool(true)}
}

// mainInst is the describe-level instance: provider "test", user-create hook marking emails
// verified and a pre-created oauth2@test.com user.
func mainInst(t *testing.T) *inst {
	t.Helper()
	in := newInst(t, func(c *betterauth.Config) {
		emailVerifiedOnCreate(c)
		genericPlugin(discoveryConfig(providerID))(c)
	})
	if _, err := in.ctx().InternalAdapter.CreateUser(context.Background(), adapter.Record{"email": "oauth2@test.com", "name": "OAuth2 Test"}, betterauth.UserInfoSource{Method: "test"}); err != nil {
		t.Fatal(err)
	}
	return in
}

func signInBody(provider string, extra ...any) map[string]any {
	b := map[string]any{"provider": provider, "callbackURL": "http://localhost:3000/dashboard"}
	for i := 0; i+1 < len(extra); i += 2 {
		b[extra[i].(string)] = extra[i+1]
	}
	return b
}

func TestShouldDiscoverEndSessionEndpointForProviderLogout(t *testing.T) {
	srv := oauth2test.New(t)
	calls := 0
	srv.Handle("idp.example.com/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeJSON(w, 200, map[string]any{"issuer": "https://idp.example.com", "authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint": "https://idp.example.com/token", "end_session_endpoint": "https://idp.example.com/logout"})
	})
	in := newInst(t, genericPlugin(Config{ProviderID: "discovery-logout", DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration",
		ClientID: "client-id", ClientSecret: "client-secret"}))
	es, ok := oauth2.AsEndSessioner(in.provider("discovery-logout"))
	if !ok {
		t.Fatal("expected end session support")
	}
	u, err := es.CreateEndSessionURL(context.Background(), oauth2.EndSessionParams{IDToken: "id-token"})
	if err != nil || u == nil {
		t.Fatalf("logout url: %v %v", u, err)
	}
	mustEqual(t, u.String(), "https://idp.example.com/logout?id_token_hint=id-token")
	mustEqual(t, calls, 1)
	mustEqual(t, srv.Requests[0].URL.String(), "https://idp.example.com/.well-known/openid-configuration")
}

func TestShouldDeleteStateCookieWithPathAttribute(t *testing.T) {
	setupIdP(t)
	in := mainInst(t)
	c := in.client()
	_, u := c.signInSocial(signInBody("test"))
	f := c.simulateOAuthFlow(u)
	_, attrs, ok := f.res.setCookie("better-auth.state")
	if !ok {
		t.Fatalf("no state cookie in %v", f.res.Header.Values("Set-Cookie"))
	}
	mustEqual(t, attrs["max-age"], "0")
	mustEqual(t, attrs["path"], "/")
}

func TestShouldCompleteFullSignInFlowAndReturnCorrectSessionData(t *testing.T) {
	setupIdP(t)
	in := mainInst(t)
	c := in.client()
	res, u := c.signInSocial(signInBody("test", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, res.JSON(t)["redirect"], any(true))
	f := c.simulateOAuthFlow(u)
	mustEqual(t, f.callbackURL, "http://localhost:3000/dashboard")
	s := c.session()
	if s == nil {
		t.Fatal("expected session")
	}
	user := sessionUser(s)
	mustEqual(t, user["email"], any("oauth2@test.com"))
	mustEqual(t, user["name"], any("OAuth2 Test"))
	mustEqual(t, s["session"].(map[string]any)["userId"], user["id"])
	accs := in.accounts(user["id"].(string))
	if len(accs) != 1 || accs[0].ProviderID != "test" || accs[0].AccountID != "oauth2" {
		t.Fatalf("accounts: %+v", accs)
	}
}

func TestShouldRedirectToTheProviderAndHandleTheResponseForANewUser(t *testing.T) {
	idp := setupIdP(t)
	in := mainInst(t)
	idp.userinfoOnce(map[string]any{"email": "oauth2-2@test.com", "name": "OAuth2 Test 2", "sub": "oauth2-2",
		"picture": "https://test.com/picture.png", "email_verified": true})
	c := in.client()
	res, u := c.signInSocial(signInBody("test", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, res.JSON(t)["redirect"], any(true))
	f := c.simulateOAuthFlow(u)
	mustEqual(t, f.callbackURL, "http://localhost:3000/new_user")
	s := c.session()
	uid := sessionUser(s)["id"].(string)
	a := in.accounts(uid)[0]
	if a.ProviderID != providerID || a.AccountID != "oauth2-2" || a.UserID != uid || strp(a.AccessToken) == "" ||
		strp(a.RefreshToken) == "" || a.AccessTokenExpiresAt == nil || a.RefreshTokenExpiresAt != nil || a.Scope == nil || strp(a.IDToken) == "" {
		t.Fatalf("account: %+v", a)
	}
}

func TestEncodesCallbackURLInTheVerifyEmailLinkForANewUnverifiedOAuthUser(t *testing.T) {
	idp := setupIdP(t)
	captured := ""
	in := newInst(t, func(c *betterauth.Config) {
		c.EmailVerification = &betterauth.EmailVerificationConfig{SendOnSignUp: betterauth.Bool(true),
			SendVerificationEmail: func(_ context.Context, d betterauth.EmailData, _ *http.Request) error {
				captured = d.URL
				return nil
			}}
		genericPlugin(discoveryConfig("test-encode-callback"))(c)
	})
	idp.userinfoOnce(map[string]any{"email": "encode-callback@test.com", "name": "Encode Callback", "sub": "encode-callback", "email_verified": false})
	cb := "http://localhost:3000/welcome?ref=oauth&plan=pro"
	c := in.client()
	_, u := c.signInSocial(map[string]any{"provider": "test-encode-callback", "callbackURL": cb})
	c.simulateOAuthFlow(u)
	if captured == "" {
		t.Fatal("no verification email")
	}
	mustEqual(t, queryParam(t, captured, "callbackURL"), cb)
}

func TestShouldResolveGetAccessTokenAfterFirstTimeGenericOAuthSignInStoreAccountCookieJWE(t *testing.T) {
	idp := setupIdP(t)
	in := newInst(t, func(c *betterauth.Config) {
		c.Advanced = &betterauth.AdvancedConfig{UseSecureCookies: betterauth.Bool(true)}
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, Strategy: "jwe"}}
		c.Account = &betterauth.AccountConfig{StoreAccountCookie: betterauth.Bool(true)}
		genericPlugin(discoveryConfig("test-store-account"))(c)
	})
	name := in.ctx().AuthCookies.AccountData.Name
	idp.userinfoOnce(map[string]any{"email": "first-time-generic-oauth@test.com", "name": "First Time SSO", "sub": "first-time-sso",
		"picture": "https://test.com/picture.png", "email_verified": true})
	c := in.client()
	_, u := c.signInSocial(signInBody("test-store-account", "newUserCallbackURL", "http://localhost:3000/new_user"))
	f := c.simulateOAuthFlow(u)
	v, attrs, ok := f.res.setCookie(name)
	if !ok || v == "" || !strings.HasPrefix(v, "ey") {
		t.Fatalf("account cookie: %q %v", v, f.res.Header.Values("Set-Cookie"))
	}
	if _, ok := attrs["httponly"]; !ok {
		t.Fatal("expected httponly")
	}
	if _, ok := attrs["secure"]; !ok {
		t.Fatal("expected secure")
	}
	mustEqual(t, strings.ToLower(attrs["samesite"]), "lax")
	if attrs["max-age"] == "" || attrs["max-age"] == "0" {
		t.Fatalf("max-age %q", attrs["max-age"])
	}
	payload := bacrypto.SymmetricDecodeJWT(v, in.ctx().SecretConfig, "better-auth-account")
	if payload == nil {
		t.Fatal("could not decode account cookie")
	}
	pm := payload.Map()
	mustEqual(t, pm["providerId"], any("test-store-account"))
	if s, _ := pm["accessToken"].(string); s == "" {
		t.Fatal("expected accessToken in account cookie")
	}
	res := c.post("/get-access-token", map[string]any{"useAccountCookie": true})
	if res.Status != 200 {
		t.Fatalf("get-access-token: %d %s", res.Status, res.Body)
	}
	if s, _ := res.JSON(t)["accessToken"].(string); s == "" {
		t.Fatal("expected access token")
	}
}

func TestKeepsImplicitLinksUsableAcrossStatelessInstances(t *testing.T) {
	idp := setupIdP(t)
	providerA, providerB := "test-implicit-link-a", "test-implicit-link-b"
	shared := "implicit-link-stateless@test.com"
	mutate := func(c *betterauth.Config) {
		c.Secret = "stateless-implicit-link-secret-with-32-chars"
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, Strategy: "jwe"}}
		c.Account = &betterauth.AccountConfig{StoreStateStrategy: "cookie", StoreAccountCookie: betterauth.Bool(true)}
		genericPlugin(discoveryConfig(providerA), discoveryConfig(providerB))(c)
	}
	first := newInst(t, mutate, instOpts{noDatabase: true})
	if first.auth.Options().Database != nil {
		t.Fatal("expected no database")
	}
	type result struct {
		f      flowResult
		c      *client
		userID string
	}
	complete := func(provider, accountID string) result {
		idp.userinfoOnce(map[string]any{"email": shared, "name": "Implicit Link User", "sub": accountID, "email_verified": true})
		c := first.client()
		_, u := c.signInSocial(map[string]any{"provider": provider, "callbackURL": "http://localhost:3000/dashboard", "newUserCallbackURL": "http://localhost:3000/new-user"})
		if u == "" {
			t.Fatal("expected an OAuth authorization URL")
		}
		f := c.simulateOAuthFlow(u)
		s := c.session()
		if s == nil {
			t.Fatal("expected a session after OAuth callback")
		}
		return result{f: f, c: c, userID: sessionUser(s)["id"].(string)}
	}
	a := complete(providerA, "implicit-link-account-a")
	mustEqual(t, a.f.callbackURL, "http://localhost:3000/new-user")
	b := complete(providerB, "implicit-link-account-b")
	mustEqual(t, b.f.callbackURL, "http://localhost:3000/dashboard")
	mustEqual(t, b.userID, a.userID)
	name := first.ctx().AuthCookies.AccountData.Name
	v, _, ok := b.f.res.setCookie(name)
	if !ok || v == "" {
		t.Fatal("implicit link must set an account cookie")
	}
	linked := bacrypto.SymmetricDecodeJWT(v, first.ctx().SecretConfig, "better-auth-account")
	if linked == nil {
		t.Fatal("decode linked account")
	}
	lm := linked.Map()
	at, _ := lm["accessToken"].(string)
	if at == "" {
		t.Fatal("linked account cookie must carry a token")
	}
	mustEqual(t, lm["providerId"], any(providerB))
	mustEqual(t, lm["accountId"], any("implicit-link-account-b"))
	mustEqual(t, lm["userId"], any(a.userID))

	second := newInst(t, mutate, instOpts{noDatabase: true})
	if accs := second.accounts(a.userID); len(accs) != 0 {
		t.Fatalf("expected no stored accounts, got %d", len(accs))
	}
	c2 := second.client()
	for _, k := range b.c.order {
		if v, ok := b.c.cookies[k]; ok {
			c2.setCookieValue(k, v)
		}
	}
	res := c2.post("/get-access-token", map[string]any{"useAccountCookie": true})
	if res.Status != 200 {
		t.Fatalf("get-access-token: %d %s", res.Status, res.Body)
	}
	mustEqual(t, res.JSON(t)["accessToken"], any(at))
}

// expireAccount moves the stored access token expiry into the past (vi.setSystemTime).
func expireAccount(t *testing.T, in *inst, accountID string) {
	t.Helper()
	if _, err := in.ctx().InternalAdapter.UpdateAccount(context.Background(), accountID, adapter.Record{"accessTokenExpiresAt": time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func listFirstAccountID(t *testing.T, c *client) string {
	t.Helper()
	res := c.get("/list-accounts")
	if res.Status != 200 {
		t.Fatalf("list-accounts: %d %s", res.Status, res.Body)
	}
	var arr []map[string]any
	if err := jsonUnmarshal(res.Body, &arr); err != nil || len(arr) == 0 {
		t.Fatalf("list-accounts: %s", res.Body)
	}
	return arr[0]["id"].(string)
}

func omitExpiresIn(count *int) responseHook {
	return func(body map[string]any, r *oauth2test.Request) {
		if _, ok := body["access_token"]; ok {
			delete(body, "expires_in")
			if r.Form.Get("grant_type") == "refresh_token" {
				*count++
			}
		}
	}
}

func TestRefreshesOnceTheAccessTokenExpiresInWindowPassesWhenTheProviderOmitsExpiresIn(t *testing.T) {
	idp := setupIdP(t)
	refreshCount := 0
	idp.onResponse(omitExpiresIn(&refreshCount))
	idp.userinfoOnce(map[string]any{"email": "exp-fallback@test.com", "name": "Expires In Fallback", "sub": "exp-fallback", "email_verified": true})
	cfg := discoveryConfig("exp-fallback")
	cfg.AccessTokenExpiresIn = time.Hour
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("exp-fallback", "newUserCallbackURL", "http://localhost:3000/new_user"))
	c.simulateOAuthFlow(u)
	accountID := listFirstAccountID(t, c)
	fresh := c.post("/get-access-token", map[string]any{"accountId": accountID})
	if s, _ := fresh.JSON(t)["accessToken"].(string); s == "" {
		t.Fatalf("expected token: %s", fresh.Body)
	}
	mustEqual(t, refreshCount, 0)
	expireAccount(t, in, accountID)
	refreshed := c.post("/get-access-token", map[string]any{"accountId": accountID})
	if s, _ := refreshed.JSON(t)["accessToken"].(string); s == "" {
		t.Fatalf("expected token: %s", refreshed.Body)
	}
	mustEqual(t, refreshCount, 1)
}

func TestDoesNotRefreshAProviderThatOmitsExpiresInWhenAccessTokenExpiresInIsUnset(t *testing.T) {
	idp := setupIdP(t)
	refreshCount := 0
	idp.onResponse(omitExpiresIn(&refreshCount))
	idp.userinfoOnce(map[string]any{"email": "exp-none@test.com", "name": "No Fallback", "sub": "exp-none", "email_verified": true})
	in := newInst(t, genericPlugin(discoveryConfig("exp-none")))
	c := in.client()
	_, u := c.signInSocial(signInBody("exp-none", "newUserCallbackURL", "http://localhost:3000/new_user"))
	c.simulateOAuthFlow(u)
	accountID := listFirstAccountID(t, c)
	acc := in.accounts(sessionUser(c.session())["id"].(string))[0]
	if acc.AccessTokenExpiresAt != nil {
		t.Fatalf("expected unknown expiry, got %v", acc.AccessTokenExpiresAt)
	}
	res := c.post("/get-access-token", map[string]any{"accountId": accountID})
	if s, _ := res.JSON(t)["accessToken"].(string); s == "" {
		t.Fatalf("expected token: %s", res.Body)
	}
	mustEqual(t, refreshCount, 0)
}

func TestAppliesAccessTokenExpiresInToACustomGetTokenResult(t *testing.T) {
	idp := setupIdP(t)
	refreshCount := 0
	idp.onResponse(func(_ map[string]any, r *oauth2test.Request) {
		if r.Form.Get("grant_type") == "refresh_token" {
			refreshCount++
		}
	})
	cfg := discoveryConfig("exp-gettoken")
	cfg.AccessTokenExpiresIn = time.Hour
	cfg.AccountSubject = func(_ context.Context, _ *oauth2.Tokens, p map[string]any) (any, error) {
		if p["id"] == nil {
			return "", nil
		}
		return p["id"], nil
	}
	cfg.GetToken = func(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "gettoken-initial", RefreshToken: "gettoken-refresh"}, nil
	}
	cfg.GetUserInfo = func(context.Context, *oauth2.Tokens) (map[string]any, error) {
		return map[string]any{"id": "exp-gettoken-user", "email": "exp-gettoken@test.com", "name": "GetToken User", "emailVerified": true}, nil
	}
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("exp-gettoken", "newUserCallbackURL", "http://localhost:3000/new_user"))
	c.simulateOAuthFlow(u)
	accountID := listFirstAccountID(t, c)
	fresh := c.post("/get-access-token", map[string]any{"accountId": accountID})
	mustEqual(t, fresh.JSON(t)["accessToken"], any("gettoken-initial"))
	mustEqual(t, refreshCount, 0)
	expireAccount(t, in, accountID)
	refreshed := c.post("/get-access-token", map[string]any{"accountId": accountID})
	if s, _ := refreshed.JSON(t)["accessToken"].(string); s == "" {
		t.Fatalf("expected token: %s", refreshed.Body)
	}
	mustEqual(t, refreshCount, 1)
}

func TestForwardsRefreshTokenParamsInclDynamicCtxProtectedKeysToTheTokenEndpointOnRefresh(t *testing.T) {
	idp := setupIdP(t)
	var captured []map[string]string
	idp.onResponse(func(_ map[string]any, r *oauth2test.Request) {
		if r.Form.Get("grant_type") == "refresh_token" {
			m := map[string]string{}
			for k := range r.Form {
				m[k] = r.Form.Get(k)
			}
			captured = append(captured, m)
		}
	})
	dynamicScope := "urn:zitadel:iam:org:id:org-A"
	type seen struct {
		providerID string
		hasCtx     bool
		header     string
	}
	var ctxSeen []seen
	mk := func(id string) Config {
		c := discoveryConfig(id)
		c.AccessTokenExpiresIn = time.Hour
		return c
	}
	ctxCfg := mk("refresh-params-ctx")
	ctxCfg.RefreshTokenParamsFunc = func(_ context.Context, rc *oauth2.RefreshContext) (map[string]string, error) {
		header := ""
		if rc != nil && rc.Headers != nil {
			header = rc.Headers.Get("x-active-org")
		}
		ctxSeen = append(ctxSeen, seen{"refresh-params-ctx", rc != nil, header})
		if header != "" {
			return map[string]string{"scope": "urn:zitadel:iam:org:id:" + header}, nil
		}
		return nil, nil
	}
	staticCfg := mk("refresh-params-static")
	staticCfg.RefreshTokenParams = map[string]string{"audience": "https://api.example.com"}
	dynCfg := mk("refresh-params-dynamic")
	dynCfg.RefreshTokenParamsFunc = func(context.Context, *oauth2.RefreshContext) (map[string]string, error) {
		return map[string]string{"scope": dynamicScope}, nil
	}
	noopCfg := mk("refresh-params-noop")
	noopCfg.RefreshTokenParamsFunc = func(context.Context, *oauth2.RefreshContext) (map[string]string, error) { return nil, nil }
	protCfg := mk("refresh-params-protected")
	protCfg.RefreshTokenParams = map[string]string{"grant_type": "client_credentials", "refresh_token": "should-not-replace",
		"__proto__": "polluted", "constructor": "polluted", "prototype": "polluted", "audience": "https://api.example.com"}
	in := newInst(t, genericPlugin(ctxCfg, staticCfg, dynCfg, noopCfg, protCfg))
	type acct struct {
		c  *client
		id string
	}
	signIn := func(id string) acct {
		idp.userinfoOnce(map[string]any{"email": id + "@test.com", "name": id, "sub": id, "email_verified": true})
		c := in.client()
		_, u := c.signInSocial(signInBody(id, "newUserCallbackURL", "http://localhost:3000/new_user"))
		c.simulateOAuthFlow(u)
		return acct{c, listFirstAccountID(t, c)}
	}
	ctxA, staticA, dynA, noopA, protA := signIn("refresh-params-ctx"), signIn("refresh-params-static"), signIn("refresh-params-dynamic"), signIn("refresh-params-noop"), signIn("refresh-params-protected")
	refresh := func(a acct, mutate ...func(*http.Request)) {
		t.Helper()
		expireAccount(t, in, a.id)
		res := a.c.post("/get-access-token", map[string]any{"accountId": a.id}, mutate...)
		if s, _ := res.JSON(t)["accessToken"].(string); s == "" {
			t.Fatalf("refresh: %d %s", res.Status, res.Body)
		}
	}
	refresh(ctxA, func(r *http.Request) { r.Header.Set("x-active-org", "org-from-header") })
	refresh(staticA)
	refresh(dynA)
	dynamicScope = "urn:zitadel:iam:org:id:org-B"
	refresh(dynA)
	refresh(noopA)
	refresh(protA)
	if len(captured) != 6 {
		t.Fatalf("captured %d refresh bodies", len(captured))
	}
	ctxBody, staticBody, dynBodyA, dynBodyB, noopBody, protBody := captured[0], captured[1], captured[2], captured[3], captured[4], captured[5]
	mustEqual(t, ctxBody["scope"], "urn:zitadel:iam:org:id:org-from-header")
	if len(ctxSeen) != 1 || ctxSeen[0] != (seen{"refresh-params-ctx", true, "org-from-header"}) {
		t.Fatalf("ctxSeen: %+v", ctxSeen)
	}
	mustEqual(t, staticBody["audience"], "https://api.example.com")
	mustEqual(t, staticBody["grant_type"], "refresh_token")
	mustEqual(t, dynBodyA["scope"], "urn:zitadel:iam:org:id:org-A")
	mustEqual(t, dynBodyB["scope"], "urn:zitadel:iam:org:id:org-B")
	mustEqual(t, noopBody["grant_type"], "refresh_token")
	if noopBody["refresh_token"] == "" {
		t.Fatal("expected refresh_token")
	}
	if _, ok := noopBody["audience"]; ok {
		t.Fatal("unexpected audience")
	}
	if _, ok := noopBody["scope"]; ok {
		t.Fatal("unexpected scope")
	}
	mustEqual(t, protBody["grant_type"], "refresh_token")
	if protBody["refresh_token"] == "should-not-replace" {
		t.Fatal("refresh_token was replaced")
	}
	for _, k := range []string{"__proto__", "constructor", "prototype"} {
		if _, ok := protBody[k]; ok {
			t.Fatalf("unexpected %s", k)
		}
	}
	mustEqual(t, protBody["audience"], "https://api.example.com")
}

func TestShouldRedirectToTheProviderAndHandleTheResponseAfterLinked(t *testing.T) {
	setupIdP(t)
	in := mainInst(t)
	// first sign-in links the pre-created user, the second finds the linked account
	for i := 0; i < 2; i++ {
		c := in.client()
		_, u := c.signInSocial(signInBody("test", "newUserCallbackURL", "http://localhost:3000/new_user"))
		mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/dashboard")
	}
}

func TestShouldHandleInvalidProviderID(t *testing.T) {
	setupIdP(t)
	in := mainInst(t)
	res, _ := in.client().signInSocial(signInBody("invalid-provider", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustEqual(t, res.Status, 404)
}

func TestShouldHandleServerErrorDuringOAuthFlow(t *testing.T) {
	idp := setupIdP(t)
	in := mainInst(t)
	idp.onUserinfo(func(b *map[string]any, s *int) {
		*b = map[string]any{"email": "oauth2@test.com", "name": "OAuth2 Test", "sub": "oauth2", "picture": "https://test.com/picture.png", "email_verified": true}
		*s = 500
	}, true)
	c := in.client()
	_, u := c.signInSocial(signInBody("test", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, c.simulateOAuthFlow(u).callbackURL, "?error=")
}

func TestShouldWorkWithCustomRedirectURI(t *testing.T) {
	setupIdP(t)
	cfg := discoveryConfig("test2")
	cfg.RedirectURI = "http://localhost:3000/api/auth/callback/test2"
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("test2", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
}

func TestShouldNotCreateUserWhenSignUpsAreDisabled(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"email": "oauth2-signup-disabled@test.com", "name": "OAuth2 Test Signup Disabled", "sub": "oauth2-signup-disabled",
		"picture": "https://test.com/picture.png", "email_verified": true})
	cfg := discoveryConfig("test2")
	cfg.DisableImplicitSignUp = true
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("test2", "errorCallbackURL", "http://localhost:3000/error"))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/error?error=signup_disabled")
}

func TestBlocksTheSessionWithErrorEmailNotVerifiedWhenRequireEmailVerificationIsSet(t *testing.T) {
	idp := setupIdP(t)
	cfg := discoveryConfig("test-require-verify")
	cfg.RequireEmailVerification = true
	in := newInst(t, genericPlugin(cfg))
	idp.userinfoOnce(map[string]any{"email": "generic-unverified@test.com", "name": "Generic Unverified", "sub": "generic-unverified", "email_verified": false})
	c := in.client()
	_, u := c.signInSocial(signInBody("test-require-verify", "errorCallbackURL", "http://localhost:3000/error"))
	f := c.simulateOAuthFlow(u)
	mustContain(t, f.callbackURL, "error=email_not_verified")
	mustNotContain(t, strings.Join(f.res.Header.Values("Set-Cookie"), "\n"), "better-auth.session_token=")
}

func TestShouldCreateUserWhenSignUpsAreDisabledAndSignUpIsRequested(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"email": "oauth2-signup-disabled-and-requested@test.com", "name": "OAuth2 Test Signup Disabled And Requested",
		"sub": "oauth2-signup-disabled-and-requested", "picture": "https://test.com/picture.png", "email_verified": true})
	cfg := discoveryConfig("test2")
	cfg.DisableImplicitSignUp = true
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("test2", "errorCallbackURL", "http://localhost:3000/error", "requestSignUp", true))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/dashboard")
}

func TestShouldRedirectToCrossOriginErrorCallbackURLWhenASessionHookThrowsAPIError(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"email": "hook-reject@test.com", "name": "Hook Reject User", "sub": "hook-reject",
		"picture": "https://test.com/picture.png", "email_verified": true})
	in := newInst(t, func(c *betterauth.Config) {
		c.TrustedOrigins = []string{"https://frontend.example.com"}
		genericPlugin(discoveryConfig("test-hook-reject"))(c)
		emailVerifiedOnCreate(c)
		c.DatabaseHooks.Session.Create.Before = func(context.Context, adapter.Record) (*betterauth.DBHookResult, error) {
			return nil, betterauth.ErrFrom("FORBIDDEN", betterauth.ErrorCode{Code: "HOOK_REJECTED", Message: "Session hook rejected this user"})
		}
	}, instOpts{disableTestUser: true})
	c := in.client()
	_, u := c.signInSocial(map[string]any{"provider": "test-hook-reject", "callbackURL": "https://frontend.example.com/dashboard",
		"errorCallbackURL": "https://frontend.example.com/auth-error"})
	cb := c.simulateOAuthFlow(u).callbackURL
	mustContain(t, cb, "https://frontend.example.com/auth-error?")
	mustEqual(t, queryParam(t, cb, "error"), "HOOK_REJECTED")
	mustEqual(t, queryParam(t, cb, "error_description"), "Session hook rejected this user")
}

func TestShouldPassAuthorizationHeadersInOAuth2Callback(t *testing.T) {
	idp := setupIdP(t)
	var received http.Header
	idp.onTokenSigning(func(_ map[string]any, r *oauth2test.Request) { received = r.Header }, true)
	cfg := discoveryConfig("test3")
	cfg.AuthorizationHeaders = map[string]string{"X-Custom-Header": "test-value"}
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("test3", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	c.simulateOAuthFlow(u)
	if received == nil {
		t.Fatal("token endpoint not called")
	}
	mustEqual(t, received.Get("x-custom-header"), "test-value")
}

func TestShouldDeleteOAuthUserWithVerificationFlowWithoutPassword(t *testing.T) {
	setupIdP(t)
	token := ""
	cfg := discoveryConfig("test")
	cfg.PKCE = nil
	in := newInst(t, func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{DeleteUser: &betterauth.DeleteUserConfig{Enabled: true,
			SendDeleteAccountVerification: func(_ context.Context, d betterauth.EmailData, _ *http.Request) error {
				token = d.Token
				return nil
			}}}
		genericPlugin(cfg)(c)
	})
	c := in.client()
	res, u := c.signInSocial(signInBody("test", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, res.JSON(t)["redirect"], any(true))
	c.simulateOAuthFlow(u)
	if c.session() == nil {
		t.Fatal("expected session")
	}
	del := c.post("/delete-user", map[string]any{})
	mustEqual(t, del.JSON(t)["success"], any(true))
	mustEqual(t, len(token), 32)
	cb := c.post("/delete-user", map[string]any{"token": token})
	mustEqual(t, cb.JSON(t)["success"], any(true))
	if c.session() != nil {
		t.Fatal("expected no session")
	}
}

func TestShouldHandleNumericAccountIDsCorrectlyAndPreventDuplicateAccounts(t *testing.T) {
	idp := setupIdP(t)
	profile := map[string]any{"email": "numeric-id-test@test.com", "name": "Numeric ID Test User", "sub": float64(123456789),
		"picture": "https://test.com/picture.png", "email_verified": true}
	idp.userinfoOnce(profile)
	in := newInst(t, genericPlugin(discoveryConfig("numeric-test")))
	c := in.client()
	_, u := c.signInSocial(signInBody("numeric-test", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
	s := c.session()
	if s == nil {
		t.Fatal("expected session")
	}
	uid := sessionUser(s)["id"].(string)
	accs := in.accounts(uid)
	if len(accs) != 1 || accs[0].ProviderID != "numeric-test" || accs[0].AccountID != "123456789" || accs[0].UserID != uid {
		t.Fatalf("accounts: %+v", accs)
	}
	idp.userinfoOnce(profile)
	_, u = c.signInSocial(signInBody("numeric-test"))
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/dashboard")
	mustEqual(t, sessionUser(c.session())["id"], any(uid))
	accs = in.accounts(uid)
	if len(accs) != 1 || accs[0].AccountID != "123456789" {
		t.Fatalf("accounts: %+v", accs)
	}
}

func TestRejectsSignInWhenTheProviderOmitsAnAccountIDPreventingAccountCollisions(t *testing.T) {
	idp := setupIdP(t)
	in := newInst(t, func(c *betterauth.Config) {
		emailVerifiedOnCreate(c)
		genericPlugin(discoveryConfig("no-sub-test"))(c)
	})
	without := func(email, name string) {
		idp.userinfoOnce(map[string]any{"email": email, "name": name, "picture": "https://test.com/picture.png", "email_verified": true})
	}
	without("first-no-sub@test.com", "First No Sub")
	c1 := in.client()
	_, u := c1.signInSocial(signInBody("no-sub-test", "newUserCallbackURL", "http://localhost:3000/new_user"))
	f1 := c1.simulateOAuthFlow(u)
	mustContain(t, f1.callbackURL, "/error?error=")
	mustNotContain(t, f1.callbackURL, "/dashboard")
	mustNotContain(t, f1.callbackURL, "/new_user")
	if c1.session() != nil {
		t.Fatal("expected no session")
	}
	if n := len(in.accountsByProvider("no-sub-test")); n != 0 {
		t.Fatalf("expected no accounts, got %d", n)
	}
	without("second-no-sub@test.com", "Second No Sub")
	c2 := in.client()
	_, u = c2.signInSocial(signInBody("no-sub-test"))
	mustContain(t, c2.simulateOAuthFlow(u).callbackURL, "/error?error=")
	if c2.session() != nil {
		t.Fatal("expected no session")
	}
}

func explicitEndpoints(id string) Config {
	return Config{ProviderID: id, AuthorizationURL: idpBase + "/authorize", TokenURL: idpBase + "/token",
		ClientID: clientID, ClientSecret: clientSecret, PKCE: ptrBool(true)}
}

func TestRejectsSignInWhenACustomGetUserInfoReturnsAnEmptyID(t *testing.T) {
	setupIdP(t)
	cfg := explicitEndpoints("empty-id-test")
	cfg.GetUserInfo = func(context.Context, *oauth2.Tokens) (map[string]any, error) {
		return map[string]any{"id": "", "email": "empty-id@test.com", "name": "Empty Id", "emailVerified": true}, nil
	}
	in := newInst(t, func(c *betterauth.Config) { emailVerifiedOnCreate(c); genericPlugin(cfg)(c) })
	c := in.client()
	_, u := c.signInSocial(signInBody("empty-id-test"))
	mustContain(t, c.simulateOAuthFlow(u).callbackURL, "error=unable_to_get_user_info")
	if c.session() != nil {
		t.Fatal("expected no session")
	}
	if n := len(in.accountsByProvider("empty-id-test")); n != 0 {
		t.Fatalf("accounts %d", n)
	}
}

func TestDoesNotSwitchAPlainOAuthAccountFromIDToSub(t *testing.T) {
	setupIdP(t)
	cfg := explicitEndpoints("empty-id-with-sub-test")
	cfg.GetUserInfo = func(context.Context, *oauth2.Tokens) (map[string]any, error) {
		return map[string]any{"id": "", "sub": "custom-sub-id", "email": "custom-sub@test.com", "name": "Custom Sub", "emailVerified": true}, nil
	}
	in := newInst(t, func(c *betterauth.Config) { emailVerifiedOnCreate(c); genericPlugin(cfg)(c) })
	c := in.client()
	_, u := c.signInSocial(signInBody("empty-id-with-sub-test", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, c.simulateOAuthFlow(u).callbackURL, "error=unable_to_get_user_info")
	if c.session() != nil {
		t.Fatal("expected no session")
	}
	if n := len(in.accountsByProvider("empty-id-with-sub-test")); n != 0 {
		t.Fatalf("accounts %d", n)
	}
}

// signInNewUser runs a full flow with the given userinfo body and returns the session user id
// and its accounts.
func signInNewUser(t *testing.T, idp *mockIdP, in *inst, provider string, body map[string]any) (string, []*betterauth.Account) {
	t.Helper()
	if body != nil {
		idp.userinfoOnce(body)
	}
	c := in.client()
	_, u := c.signInSocial(signInBody(provider, "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
	s := c.session()
	if s == nil {
		t.Fatal("expected session")
	}
	uid := sessionUser(s)["id"].(string)
	return uid, in.accounts(uid)
}

func TestCompletesSignInWhenAccountSubjectDerivesIdentityFromANonStandardProfileField(t *testing.T) {
	idp := setupIdP(t)
	cfg := discoveryConfig("derived-id-test")
	cfg.AccountSubject = func(_ context.Context, _ *oauth2.Tokens, p map[string]any) (any, error) {
		return optString(p["username"]), nil
	}
	cfg.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"email": p["email"], "name": p["name"], "emailVerified": truthy(p["email_verified"])}, nil
	}
	in := newInst(t, genericPlugin(cfg))
	_, accs := signInNewUser(t, idp, in, "derived-id-test", map[string]any{"username": "derived-id-user", "email": "derived-id@test.com",
		"name": "Derived Id User", "picture": "https://test.com/picture.png", "email_verified": true})
	if len(accs) != 1 || accs[0].ProviderID != "derived-id-test" || accs[0].AccountID != "derived-id-user" {
		t.Fatalf("accounts %+v", accs)
	}
}

func TestUsesTheOIDCSubWhenTheUserinfoIDFieldIsEmpty(t *testing.T) {
	idp := setupIdP(t)
	in := newInst(t, genericPlugin(discoveryConfig("sub-over-empty-id-test")))
	_, accs := signInNewUser(t, idp, in, "sub-over-empty-id-test", map[string]any{"sub": "abc", "id": "", "email": "sub-over-empty-id@test.com",
		"name": "Sub Over Empty Id", "picture": "https://test.com/picture.png", "email_verified": true})
	if len(accs) != 1 || accs[0].AccountID != "abc" {
		t.Fatalf("accounts %+v", accs)
	}
}

func TestUsesTheOIDCSubWhenTheUserinfoIDFieldIsNull(t *testing.T) {
	idp := setupIdP(t)
	in := newInst(t, genericPlugin(discoveryConfig("sub-over-null-id-test")))
	_, accs := signInNewUser(t, idp, in, "sub-over-null-id-test", map[string]any{"sub": "null-id-sub", "id": nil, "email": "sub-over-null-id@test.com",
		"name": "Sub Over Null Id", "picture": "https://test.com/picture.png", "email_verified": true})
	if len(accs) != 1 || accs[0].AccountID != "null-id-sub" {
		t.Fatalf("accounts %+v", accs)
	}
}

func TestUsesTheOIDCSubAsTheAccountSubjectWhenUserinfoAlsoHasAnIDField(t *testing.T) {
	idp := setupIdP(t)
	in := newInst(t, genericPlugin(discoveryConfig("id-over-sub-test")))
	_, accs := signInNewUser(t, idp, in, "id-over-sub-test", map[string]any{"sub": "subject-1", "id": "raw-id-1", "email": "id-over-sub@test.com",
		"name": "Id Over Sub", "picture": "https://test.com/picture.png", "email_verified": true})
	if len(accs) != 1 || accs[0].AccountID != "subject-1" {
		t.Fatalf("accounts %+v", accs)
	}
}

func TestLinksProviderAliasesAsSeparateAccountsOfOneUserWhenMutableProfileFieldsChange(t *testing.T) {
	idp := setupIdP(t)
	web := Config{ProviderID: "workforce-web", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret}
	mobile := web
	mobile.ProviderID = "workforce-mobile"
	in := newInst(t, genericPlugin(web, mobile))
	signIn := func(provider, profileID, name string) string {
		idp.userinfoOnce(map[string]any{"sub": "workforce-subject", "id": profileID, "email": "employee@workforce.test", "name": name, "email_verified": true})
		c := in.client()
		_, u := c.signInSocial(map[string]any{"provider": provider, "callbackURL": "http://localhost:3000/dashboard", "newUserCallbackURL": "http://localhost:3000/new-user"})
		c.simulateOAuthFlow(u)
		s := c.session()
		if s == nil {
			t.Fatal("expected session")
		}
		return sessionUser(s)["id"].(string)
	}
	first := signIn("workforce-web", "mutable-profile-id-1", "Employee One")
	second := signIn("workforce-mobile", "mutable-profile-id-2", "Employee Two")
	mustEqual(t, second, first)
	accs := in.accounts(first)
	got := map[string]bool{}
	for _, a := range accs {
		got[a.ProviderID] = true
		if a.AccountID != "workforce-subject" {
			t.Fatalf("account id %s", a.AccountID)
		}
	}
	if len(accs) != 2 || !got["workforce-web"] || !got["workforce-mobile"] {
		t.Fatalf("accounts %+v", accs)
	}
}

func TestKeepsDifferentOIDCSubjectsSeparateWhenAMutableIDFieldIsReused(t *testing.T) {
	idp := setupIdP(t)
	in := newInst(t, genericPlugin(Config{ProviderID: "subject-boundary", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret}))
	signIn := func(subject, email string) string {
		idp.userinfoOnce(map[string]any{"subject": subject, "sub": subject, "id": "reused-profile-id", "email": email, "name": subject, "email_verified": true})
		c := in.client()
		_, u := c.signInSocial(signInBody("subject-boundary"))
		c.simulateOAuthFlow(u)
		s := c.session()
		if s == nil {
			t.Fatal("expected session")
		}
		return sessionUser(s)["id"].(string)
	}
	a := signIn("subject-a", "subject-a@workforce.test")
	b := signIn("subject-b", "subject-b@workforce.test")
	if a == b {
		t.Fatal("expected different users")
	}
	mustEqual(t, in.accounts(a)[0].AccountID, "subject-a")
	mustEqual(t, in.accounts(b)[0].AccountID, "subject-b")
}

func TestShouldHandleCustomGetUserInfoReturningNumericID(t *testing.T) {
	setupIdP(t)
	cfg := explicitEndpoints("custom-numeric")
	cfg.GetUserInfo = func(context.Context, *oauth2.Tokens) (map[string]any, error) {
		return map[string]any{"id": float64(987654321), "email": "custom-numeric@test.com", "name": "Custom Numeric User",
			"emailVerified": true, "image": "https://test.com/avatar.png"}, nil
	}
	in := newInst(t, genericPlugin(cfg))
	_, accs := signInNewUser(t, nil, in, "custom-numeric", nil)
	mustEqual(t, accs[0].AccountID, "987654321")
}

func TestShouldHandleAccountSubjectReturningANumericSubject(t *testing.T) {
	idp := setupIdP(t)
	cfg := discoveryConfig("map-profile-numeric")
	cfg.AccountSubject = func(_ context.Context, _ *oauth2.Tokens, p map[string]any) (any, error) { return p["user_id"], nil }
	cfg.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"email": p["email"], "name": p["name"], "emailVerified": truthy(p["email_verified"])}, nil
	}
	in := newInst(t, genericPlugin(cfg))
	_, accs := signInNewUser(t, idp, in, "map-profile-numeric", map[string]any{"email": "map-profile-numeric@test.com", "name": "Map Profile Numeric User",
		"sub": "string-sub-id", "user_id": float64(111222333), "picture": "https://test.com/picture.png", "email_verified": true})
	mustEqual(t, accs[0].AccountID, "111222333")
}

func TestShouldHandleStravaOAuthWithCustomMapProfileToUser(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"id": float64(12345678), "firstname": "John", "lastname": "Doe",
		"profile": "https://example.com/strava-avatar.jpg", "email_verified": true})
	in := newInst(t, genericPlugin(Config{ProviderID: "strava", AuthorizationURL: idpBase + "/authorize", TokenURL: idpBase + "/token",
		UserInfoURL: idpBase + "/userinfo", ClientID: "STRAVA_CLIENT_ID", ClientSecret: "STRAVA_CLIENT_SECRET",
		Scopes: []string{"read", "activity:read_all"}, PKCE: ptrBool(true),
		MapProfileToUser: func(p map[string]any) (map[string]any, error) {
			return map[string]any{"email": optString(p["id"]) + "@strava.local", "name": optString(p["firstname"]) + " " + optString(p["lastname"]),
				"image": p["profile"], "emailVerified": true}, nil
		}}))
	c := in.client()
	_, u := c.signInSocial(signInBody("strava", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	mustContain(t, u, "scope=read+activity")
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
	user := sessionUser(c.session())
	mustEqual(t, user["email"], any("12345678@strava.local"))
	mustEqual(t, user["name"], any("John Doe"))
	mustEqual(t, user["image"], any("https://example.com/strava-avatar.jpg"))
	a := in.accounts(user["id"].(string))[0]
	if a.ProviderID != "strava" || a.AccountID != "12345678" || a.UserID != user["id"] {
		t.Fatalf("account %+v", a)
	}
}

func TestRedirectsWithEmailNotFoundWhenBothTheProviderAndMapProfileToUserOmitEmail(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"sub": "no-email-no-synthesis", "name": "No Email User"})
	in := newInst(t, genericPlugin(discoveryConfig("no-email-unresolved")))
	c := in.client()
	_, u := c.signInSocial(signInBody("no-email-unresolved"))
	mustContain(t, c.simulateOAuthFlow(u).callbackURL, "error=email_not_found")
}

func TestShouldWorkWithCookieBasedStateStorage(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"email": "oauth2-cookie-state@test.com", "name": "OAuth2 Cookie State", "sub": "oauth2-cookie-state",
		"picture": "https://test.com/picture.png", "email_verified": true})
	in := newInst(t, func(c *betterauth.Config) {
		genericPlugin(discoveryConfig("test-cookie"))(c)
		c.Account = &betterauth.AccountConfig{StoreStateStrategy: "cookie"}
	})
	c := in.client()
	_, u := c.signInSocial(signInBody("test-cookie", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
	user := sessionUser(c.session())
	mustEqual(t, user["email"], any("oauth2-cookie-state@test.com"))
	mustEqual(t, user["name"], any("OAuth2 Cookie State"))
}

func TestShouldRejectCookieBackedOAuthWhenCallbackStateDoesNotMatchTheIssuedState(t *testing.T) {
	setupIdP(t)
	cfg := discoveryConfig("test-cookie-csrf")
	cfg.PKCE = ptrBool(false)
	in := newInst(t, func(c *betterauth.Config) {
		genericPlugin(cfg)(c)
		c.Account = &betterauth.AccountConfig{StoreStateStrategy: "cookie"}
	})
	c := in.client()
	_, u := c.signInSocial(signInBody("test-cookie-csrf"))
	if u == "" {
		t.Fatal("expected url")
	}
	res := c.get("/callback/test-cookie-csrf?code=dummy&state=attacker-controlled-state")
	mustEqual(t, res.Status, 302)
	mustContain(t, res.location(), "state_mismatch")
	if c.session() != nil {
		t.Fatal("expected no session")
	}
}

func TestShouldRedirectToTheErrorPageWhenAGETCallbackArrivesWithoutState(t *testing.T) {
	setupIdP(t)
	in := mainInst(t)
	res := in.client().get("/callback/" + providerID + "?code=dummy")
	mustEqual(t, res.Status, 302)
	mustContain(t, res.location(), "state_not_found")
}

func TestShouldAwaitAsyncMapProfileToUser(t *testing.T) {
	in := newInst(t, genericPlugin(Config{ProviderID: "test-async", ClientID: clientID, ClientSecret: clientSecret,
		GetUserInfo: func(context.Context, *oauth2.Tokens) (map[string]any, error) {
			return map[string]any{"id": "test-user-id", "email": "test@example.com", "name": "Test User", "emailVerified": true}, nil
		},
		MapProfileToUser: func(map[string]any) (map[string]any, error) {
			return map[string]any{"customField": "async-custom-data"}, nil
		}}))
	r, err := in.provider("test-async").GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "test-access-token"}})
	if err != nil || r == nil {
		t.Fatalf("GetUserInfo: %v %v", r, err)
	}
	mustEqual(t, r.User.Extra["customField"], any("async-custom-data"))
}

func TestKeepsProviderSubInRawDataWhenThePlainOAuthIDIsEmpty(t *testing.T) {
	in := newInst(t, genericPlugin(Config{ProviderID: "test-wrapper-sub", ClientID: clientID, ClientSecret: clientSecret,
		GetUserInfo: func(context.Context, *oauth2.Tokens) (map[string]any, error) {
			return map[string]any{"id": "", "sub": "wrapped-sub", "email": "wrapped-sub@test.com", "name": "Wrapped Sub", "emailVerified": true}, nil
		}}))
	r, err := in.provider("test-wrapper-sub").GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "test-access-token"}})
	if err != nil || r == nil {
		t.Fatalf("GetUserInfo: %v %v", r, err)
	}
	mustEqual(t, r.Data["sub"], any("wrapped-sub"))
	if _, ok := r.User.Extra["id"]; ok {
		t.Fatal("user must not carry id")
	}
}
