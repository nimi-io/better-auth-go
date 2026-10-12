package betterauth

// Port of better-auth/src/api/routes/account.test.ts — storeAccountCookie / token-refresh
// cases of describe("account"), describe("account selector validation"),
// describe("token routes cookie cache revocation") and
// describe("account resolution in stateless mode").
//
// Upstream obtains the account_data cookie from the /callback/:id round-trip (phase 2).
// The "...Adapted" tests keep the upstream assertions but seed the account row and inject
// the signed account_data cookie directly (the way the upstream "does not select a signed
// account cookie" test does), so the get-access-token / refresh-token / cookie semantics
// are exercised without the callback.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/oauth2"
)

func pacAccountCookieValue(t *testing.T, env *testEnv, acc *Account) string {
	t.Helper()
	ac := env.auth.Context()
	v, err := bacrypto.SymmetricEncodeJWT(accountCookieObject(acc), ac.SecretConfig, "better-auth-account", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func pacInjectAccountCookie(t *testing.T, env *testEnv, c *testClient, acc *Account) {
	t.Helper()
	pacSetCookies(c, &http.Cookie{Name: env.auth.Context().AuthCookies.AccountData.Name, Value: pacAccountCookieValue(t, env, acc)})
}

func pacDecodeAccountCookie(t *testing.T, env *testEnv, value string) map[string]any {
	t.Helper()
	ac := env.auth.Context()
	o := bacrypto.SymmetricDecodeJWT(value, ac.SecretConfig, "better-auth-account")
	if o == nil {
		t.Fatalf("account cookie could not be decoded")
	}
	return o.Map()
}

// ---- callback-dependent upstream cases (phase 2) ----

func TestPortAccountCookieStoredAfterOAuthFlow(t *testing.T) {
	t.Skip("phase 2: requires /sign-in/social + /callback/google; see TestPortAccountCookieUseAccountCookieAdapted")
}

func TestPortAccountCookieSelectedAccountCookie(t *testing.T) {
	t.Skip("phase 2: requires /sign-in/social + /callback/google; see TestPortAccountCookieUseAccountCookieAdapted")
}

func TestPortAccountCookieLocalAccountIDFromDatabase(t *testing.T) {
	t.Skip("phase 2: requires /sign-in/social + /callback/google; see TestPortAccountCookieLocalAccountIDFromDatabaseAdapted")
}

func TestPortAccountCookieStaleCookieOtherUser(t *testing.T) {
	t.Skip("phase 2: requires /sign-in/social + /callback/google; see TestPortAccountCookieStaleCookieOtherUserAdapted")
}

func TestPortAccountPersistRefreshedIDTokenInDatabase(t *testing.T) {
	t.Skip("phase 2: requires /sign-in/social + /callback/google; see TestPortAccountPersistRefreshedIDTokenInDatabaseAdapted")
}

func TestPortAccountPersistRefreshedIDTokenInCookieStateless(t *testing.T) {
	t.Skip("phase 2: stateless (database: undefined) session can only be created by /sign-in/social + /callback/google")
}

func TestPortAccountCognitoPreserveRefreshToken(t *testing.T) {
	t.Skip("phase 2: stateless cognito sign-in requires /sign-in/social + /callback/cognito and a cognito provider; see TestPortAccountPreserveRefreshTokenAdapted")
}

func TestPortAccountCookieNotChunkedUnder4KB(t *testing.T) {
	t.Skip("phase 2: asserts the Set-Cookie of /callback/google")
}

func TestPortAccountCookieChunkedOver4KB(t *testing.T) {
	t.Skip("phase 2: asserts the Set-Cookie of /callback/google")
}

func TestPortAccountCookieEncryptedPayload(t *testing.T) {
	t.Skip("phase 2: asserts the Set-Cookie of /callback/google; the payload encryption is checked in TestPortAccountPreserveRefreshTokenAdapted")
}

func TestPortAccountCookieReLoginUpdateAccountOnSignInFalse(t *testing.T) {
	t.Skip("phase 2: requires /sign-in/social + /callback/google")
}

func TestPortAccountCookieRefreshedWithSession(t *testing.T) {
	t.Skip("phase 2: requires /sign-in/social + /callback/google; see TestPortAccountCookieRefreshedWithSessionAdapted")
}

func TestPortAccountCookieRefreshedStateless(t *testing.T) {
	t.Skip("phase 2: stateless session requires /sign-in/social + /callback/google")
}

func TestPortAccountStatelessGetAccessTokenMismatchedCookie(t *testing.T) {
	t.Skip("phase 2: describe(\"account resolution in stateless mode\") needs genericOAuth + /sign-in/social + /callback/idp")
}

func TestPortAccountStatelessAccountInfoMismatchedCookie(t *testing.T) {
	t.Skip("phase 2: describe(\"account resolution in stateless mode\") needs genericOAuth + /sign-in/social + /callback/idp")
}

func TestPortAccountStatelessRefreshMismatchedCookie(t *testing.T) {
	t.Skip("phase 2: describe(\"account resolution in stateless mode\") needs genericOAuth + /sign-in/social + /callback/idp")
}

func TestPortAccountStatelessSessionRefreshPreservesCookie(t *testing.T) {
	t.Skip("phase 2: describe(\"account resolution in stateless mode\") needs genericOAuth + /sign-in/social + /callback/idp")
}

// ---- adapted storeAccountCookie cases ----

// Adapted from "should store account data cookie after oauth flow and retrieve it through
// getAccessToken" and "should use the selected account cookie in getAccessToken".
func TestPortAccountCookieUseAccountCookieAdapted(t *testing.T) {
	var spy *pacSpyAdapter
	env, _ := pacIsolatedGoogle(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
	}, pacWithSpy(&spy))
	c, user := pacSignInWithTestUser(t, env)
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "1234567890",
		"accessToken": "test", "refreshToken": "test"})
	pacInjectAccountCookie(t, env, c, acc)
	spy.reset()
	res := c.post("/get-access-token", map[string]any{"useAccountCookie": true})
	if res.Status != 200 {
		t.Fatalf("expected no error, got %d %s", res.Status, res.Body)
	}
	if res.JSON(t)["accessToken"] != "test" {
		t.Fatalf("unexpected access token %s", res.Body)
	}
	if calls := spy.calls(); len(calls) != 0 {
		t.Fatalf("findAccounts must not be called on the cookie path, got %v", calls)
	}
}

// Adapted from "should resolve a local account ID from the database instead of the account cookie".
func TestPortAccountCookieLocalAccountIDFromDatabaseAdapted(t *testing.T) {
	var spy *pacSpyAdapter
	env, _ := pacIsolatedGoogle(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
	}, pacWithSpy(&spy))
	c, user := pacSignInWithTestUser(t, env)
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "1234567890",
		"accessToken": "test", "refreshToken": "test"})
	pacInjectAccountCookie(t, env, c, acc)
	var google map[string]any
	for _, a := range pacListAccounts(t, c) {
		if a["providerId"] == "google" {
			google = a
		}
	}
	if google == nil || google["id"] == google["accountId"] {
		t.Fatalf("google account should exist with id != accountId: %#v", google)
	}
	spy.reset()
	res := c.post("/get-access-token", map[string]any{"accountId": google["id"]})
	if res.Status != 200 || res.JSON(t)["accessToken"] != "test" {
		t.Fatalf("unexpected response %d %s", res.Status, res.Body)
	}
	found := false
	for _, a := range spy.calls() {
		if a == google["userId"] {
			found = true
		}
	}
	if !found {
		t.Fatalf("findAccounts must be called with %v, got %v", google["userId"], spy.calls())
	}
}

// Adapted from "should not refresh with a stale account cookie belonging to another user".
func TestPortAccountCookieStaleCookieOtherUserAdapted(t *testing.T) {
	env, g := pacIsolatedGoogle(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
	})
	g.refreshFn = func(string) (*oauth2.Tokens, error) {
		// the provider does not rotate the refresh token
		return &oauth2.Tokens{AccessToken: "rotated-access-token"}, nil
	}
	// The first user's google account and account_data cookie (from the OAuth sign-in upstream).
	c, first := pacSignInWithTestUser(t, env)
	firstAcc := pacCreateAccount(t, env, adapter.Record{"userId": first["id"], "providerId": "google", "accountId": "first-google-sub",
		"accessToken": "first-access-token", "refreshToken": "first-refresh-token"})
	pacInjectAccountCookie(t, env, c, firstAcc)

	c.signUp("stale-cookie-second@test.com", "password123456", "Second User")
	s := c.session()
	if s == nil {
		t.Fatal("second user should be signed in")
	}
	second, _ := s["user"].(map[string]any)
	if second["email"] != "stale-cookie-second@test.com" {
		t.Fatalf("unexpected session user %v", second["email"])
	}
	secondAcc := pacCreateAccount(t, env, adapter.Record{"userId": second["id"], "providerId": "google", "accountId": "second-google-sub",
		"accessToken": "second-access-token", "refreshToken": "second-refresh-token", "scope": "email"})

	res := c.post("/refresh-token", map[string]any{"accountId": secondAcc.ID})
	calls := g.refreshCallsCopy()
	if len(calls) == 0 || calls[len(calls)-1] != "second-refresh-token" {
		t.Fatalf("refresh must use the second user's token, got %v", calls)
	}
	if res.Status == 200 && res.JSON(t)["refreshToken"] == "first-refresh-token" {
		t.Fatalf("refresh returned the first user's token: %s", res.Body)
	}
	for _, a := range pacFindAccounts(t, env, pacStr(second["id"])) {
		if a.ProviderID == "google" {
			if a.RefreshToken == nil || *a.RefreshToken != "second-refresh-token" {
				t.Fatalf("second user's refresh token overwritten: %v", a.RefreshToken)
			}
		}
	}
}

// Adapted from "should persist refreshed idToken in database during getAccessToken
// auto-refresh": the account row is seeded as the callback would have stored it (token
// expiring in 1s) instead of being created through the callback.
func TestPortAccountPersistRefreshedIDTokenInDatabaseAdapted(t *testing.T) {
	env, g := pacIsolatedGoogle(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(false)}
	})
	const oldIDToken, newIDToken = "old-id-token", "new-id-token"
	g.refreshFn = func(string) (*oauth2.Tokens, error) {
		exp := time.Now().Add(3600 * time.Second)
		return &oauth2.Tokens{AccessToken: "refreshed-access-token", RefreshToken: "refreshed-refresh-token",
			AccessTokenExpiresAt: &exp, IDToken: newIDToken}, nil
	}
	c, user := pacSignInWithTestUser(t, env)
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "persist-id-token-db",
		"accessToken": "initial-access-token", "refreshToken": "initial-refresh-token",
		"accessTokenExpiresAt": time.Now().Add(time.Second), "idToken": oldIDToken})
	var googleID any
	for _, a := range pacListAccounts(t, c) {
		if a["providerId"] == "google" {
			googleID = a["id"]
		}
	}
	if googleID == nil {
		t.Fatal("google account should be listed")
	}
	first := c.post("/get-access-token", map[string]any{"accountId": googleID})
	if first.Status != 200 || first.JSON(t)["idToken"] != newIDToken {
		t.Fatalf("first get-access-token: %d %s", first.Status, first.Body)
	}
	second := c.post("/get-access-token", map[string]any{"accountId": googleID})
	if second.Status != 200 || second.JSON(t)["idToken"] != newIDToken {
		t.Fatalf("second get-access-token: %d %s", second.Status, second.Body)
	}
	if n := len(g.refreshCallsCopy()); n != 1 {
		t.Fatalf("refresh calls = %d, want 1", n)
	}
	rec, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "account",
		Where: []adapter.Where{{Field: "providerId", Value: "google"}}})
	if err != nil || rec == nil {
		t.Fatalf("account not found: %v", err)
	}
	if rec["idToken"] != newIDToken {
		t.Fatalf("idToken = %v, want %s", rec["idToken"], newIDToken)
	}
}

// Adapted from "should preserve the Cognito refresh token when getAccessToken auto-refresh
// receives no replacement" (and the "should encrypt account cookie payload" assertions):
// run with a database + storeAccountCookie and an injected account_data cookie.
func TestPortAccountPreserveRefreshTokenAdapted(t *testing.T) {
	env, g := pacIsolatedGoogle(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
	})
	const refreshedIDToken = "refreshed-cognito-id-token"
	g.refreshFn = func(string) (*oauth2.Tokens, error) {
		exp := time.Now().Add(3600 * time.Second)
		return &oauth2.Tokens{AccessToken: "refreshed-cognito-access-token", AccessTokenExpiresAt: &exp,
			IDToken: refreshedIDToken, TokenType: "Bearer"}, nil
	}
	c, user := pacSignInWithTestUser(t, env)
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "cognito-user-sub",
		"accessToken": "initial-cognito-access-token", "refreshToken": "cognito-refresh-token",
		"accessTokenExpiresAt": time.Now().Add(time.Second), "idToken": "initial-cognito-id-token"})
	pacInjectAccountCookie(t, env, c, acc)
	cookieName := env.auth.Context().AuthCookies.AccountData.Name

	res := c.post("/get-access-token", map[string]any{"useAccountCookie": true})
	if res.Status != 200 {
		t.Fatalf("get-access-token: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if m["accessToken"] != "refreshed-cognito-access-token" || m["idToken"] != refreshedIDToken {
		t.Fatalf("unexpected response %s", res.Body)
	}
	if calls := g.refreshCallsCopy(); len(calls) != 1 || calls[0] != "cognito-refresh-token" {
		t.Fatalf("refresh grants = %v", calls)
	}
	cookie, ok := res.cookie(cookieName)
	if !ok || cookie == "" {
		t.Fatalf("expected refreshed account cookie, got %v", res.Header.Values("Set-Cookie"))
	}
	if !strings.HasPrefix(cookie, "ey") {
		t.Fatalf("account cookie must be an encrypted JWT, got %q", cookie)
	}
	dec := pacDecodeAccountCookie(t, env, cookie)
	if dec["accessToken"] != "refreshed-cognito-access-token" || dec["idToken"] != refreshedIDToken || dec["refreshToken"] != "cognito-refresh-token" {
		t.Fatalf("unexpected cookie payload %#v", dec)
	}

	rt := c.post("/refresh-token", map[string]any{"useAccountCookie": true})
	if rt.Status != 200 {
		t.Fatalf("refresh-token: %d %s", rt.Status, rt.Body)
	}
	if rt.JSON(t)["refreshToken"] != "cognito-refresh-token" {
		t.Fatalf("unexpected refreshToken %s", rt.Body)
	}
	if calls := g.refreshCallsCopy(); len(calls) != 2 || calls[0] != "cognito-refresh-token" || calls[1] != "cognito-refresh-token" {
		t.Fatalf("refresh grants = %v", calls)
	}
}

// Adapted from "should refresh account_data cookie when session is refreshed".
func TestPortAccountCookieRefreshedWithSessionAdapted(t *testing.T) {
	expiresIn := 7 * 24 * time.Hour
	updateAge := 10 * time.Second
	env, _ := pacIsolatedGoogle(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
		c.Session = &SessionConfig{ExpiresIn: expiresIn, UpdateAge: &updateAge,
			CookieCache: &CookieCacheConfig{Enabled: true, Strategy: "jwe"}}
	})
	ac := env.auth.Context()
	c, user := pacSignInWithTestUser(t, env)
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "1234567890",
		"accessToken": "test", "refreshToken": "test"})
	pacInjectAccountCookie(t, env, c, acc)
	s := c.session()
	sess, _ := s["session"].(map[string]any)
	token := pacStr(sess["token"])
	if token == "" {
		t.Fatal("missing session token")
	}
	past := time.Now().Add(expiresIn - updateAge - time.Second)
	if _, err := ac.Adapter.Update(context.Background(), "session", []adapter.Where{{Field: "token", Value: token}},
		adapter.Record{"expiresAt": past}); err != nil {
		t.Fatal(err)
	}
	res := c.get("/get-session?disableCookieCache=true")
	if res.Status != 200 {
		t.Fatalf("get-session: %d %s", res.Status, res.Body)
	}
	if v, ok := res.cookie(ac.AuthCookies.SessionData.Name); !ok || v == "" {
		t.Fatalf("expected refreshed session_data cookie, got %v", pacSetCookieNames(res.Header))
	}
	if v, ok := res.cookie(ac.AuthCookies.AccountData.Name); !ok || v == "" {
		t.Fatalf("expected refreshed account_data cookie, got %v", pacSetCookieNames(res.Header))
	}
}

// ---- describe("account selector validation") ----

func pacSelectorInstance(t *testing.T) (*testEnv, *testClient) {
	t.Helper()
	env := pacNewInstance(t, nil)
	c, _ := pacSignInWithTestUser(t, env)
	return env, c
}

func TestPortAccountSelectorRejectsBothSelectors(t *testing.T) {
	_, c := pacSelectorInstance(t)
	body := map[string]any{"accountId": "account-id", "useAccountCookie": true}
	got := []int{
		c.post("/get-access-token", body).Status,
		c.post("/refresh-token", body).Status,
		c.get("/account-info?accountId=account-id&useAccountCookie=true").Status,
	}
	for i, s := range got {
		if s != 400 {
			t.Fatalf("expected [400 400 400], got %v (index %d)", got, i)
		}
	}
}

func TestPortAccountSelectorRejectsMissingSelector(t *testing.T) {
	_, c := pacSelectorInstance(t)
	got := []int{
		c.post("/get-access-token", map[string]any{}).Status,
		c.post("/refresh-token", map[string]any{}).Status,
		c.get("/account-info").Status,
	}
	for i, s := range got {
		if s != 400 {
			t.Fatalf("expected [400 400 400], got %v (index %d)", got, i)
		}
	}
}

func TestPortAccountSelectorIgnoresCookieWhenStorageDisabled(t *testing.T) {
	env, _ := pacIsolatedGoogle(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(false)}
	})
	c, user := pacSignInWithTestUser(t, env)
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google",
		"accountId": "stale-google-subject", "accessToken": "stale-access-token"})
	pacInjectAccountCookie(t, env, c, acc)
	res := c.post("/get-access-token", map[string]any{"useAccountCookie": true})
	pacExpectErrorBody(t, res, 400, ErrAccountNotFound.Code, ErrAccountNotFound.Message)
}

// ---- describe("token routes cookie cache revocation") ----

func TestPortAccountGetAccessTokenFailsClosedAfterRevocation(t *testing.T) {
	env := pacNewInstance(t, nil, func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true, MaxAge: 60 * time.Second}}
	})
	c, _ := pacSignInWithTestUser(t, env)
	s := c.session()
	sess, _ := s["session"].(map[string]any)
	token := pacStr(sess["token"])
	u, _ := url.Parse(env.server.URL)
	hasData := false
	for _, ck := range c.jar.Cookies(u) {
		if strings.Contains(ck.Name, "session_data") {
			hasData = true
		}
	}
	if !hasData {
		t.Fatal("expected a session_data cookie")
	}
	if err := env.auth.Context().InternalAdapter.DeleteSession(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	res := c.post("/get-access-token", map[string]any{"useAccountCookie": true})
	if res.Status != 401 {
		t.Fatalf("expected 401, got %d %s", res.Status, res.Body)
	}
	bypass := c.post("/get-access-token?disableCookieCache=", map[string]any{"useAccountCookie": true})
	if bypass.Status != 401 {
		t.Fatalf("expected 401, got %d %s", bypass.Status, bypass.Body)
	}
}
