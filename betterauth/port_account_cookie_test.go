package betterauth

// Port of better-auth/src/api/routes/account.test.ts — storeAccountCookie / token-refresh
// cases of describe("account"), describe("account selector validation"),
// describe("token routes cookie cache revocation") and
// describe("account resolution in stateless mode").
//
// Upstream obtains the account_data cookie from the /callback/:id round-trip, ported
// below with the real Google provider. The additional "...Adapted" tests keep the
// upstream assertions but seed the account row and inject the signed account_data cookie
// directly (the way the upstream "does not select a signed
// account cookie" test does), so the get-access-token / refresh-token / cookie semantics
// are exercised without the callback.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/cognito"
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

// ---- callback-dependent upstream cases ----
//
// These drive the real /sign-in/social + /callback/google round-trip with the Google
// provider; its token endpoint is answered by oauth2test (the msw handlers upstream).

func pacCallbackGoogleEnv(t *testing.T, extra ...func(c *Config)) (*testEnv, *oauth2test.Server) {
	t.Helper()
	m := oauth2test.New(t)
	return poEnv(t, []oauth2.Provider{poGoogle(nil)}, extra), m
}

func pacStoreAccountCookie(c *Config) {
	if c.Account == nil {
		c.Account = &AccountConfig{}
	}
	c.Account.StoreAccountCookie = Bool(true)
}

// pacGoogleSignIn runs signIn.social + /callback/google (callbackURL "/callback") on c and
// expects a 302 to the callback URL.
func pacGoogleSignIn(t *testing.T, c *testClient) *testResponse {
	t.Helper()
	state := poStartGoogle(t, c, "/callback")
	res := c.get("/callback/google?state=" + url.QueryEscape(state) + "&code=test")
	if res.Status != 302 || !strings.Contains(res.Header.Get("Location"), "/callback") {
		t.Fatalf("callback: %d %q %s", res.Status, res.Header.Get("Location"), res.Body)
	}
	return res
}

func pacExpectAccessToken(t *testing.T, res *testResponse, field, want string) {
	t.Helper()
	if res.Status != 200 {
		t.Fatalf("expected no error, got %d %s", res.Status, res.Body)
	}
	if got := res.JSON(t)[field]; got != want {
		t.Fatalf("%s = %v, want %s", field, got, want)
	}
}

func TestPortAccountCookieStoredAfterOAuthFlow(t *testing.T) {
	env, m := pacCallbackGoogleEnv(t, pacStoreAccountCookie)
	name := env.auth.Context().AuthCookies.AccountData.Name
	poAccountGoogleToken(m, "oauth-test@test.com")
	c := env.client()
	res := pacGoogleSignIn(t, c)
	if v, ok := poLastSetCookie(res.Header, name); !ok || v == "" {
		t.Fatalf("expected %s cookie, got %v", name, pacSetCookieNames(res.Header))
	}
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"useAccountCookie": true}), "accessToken", "test")
}

func TestPortAccountCookieSelectedAccountCookie(t *testing.T) {
	var spy *pacSpyAdapter
	env, m := pacCallbackGoogleEnv(t, pacStoreAccountCookie, pacWithSpy(&spy))
	poAccountGoogleToken(m, "account-cookie-match@test.com")
	c := env.client()
	pacGoogleSignIn(t, c)
	spy.reset()
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"useAccountCookie": true}), "accessToken", "test")
	if calls := spy.calls(); len(calls) != 0 {
		t.Fatalf("findAccounts must not be called on the cookie path, got %v", calls)
	}
}

func TestPortAccountCookieLocalAccountIDFromDatabase(t *testing.T) {
	var spy *pacSpyAdapter
	env, m := pacCallbackGoogleEnv(t, pacStoreAccountCookie, pacWithSpy(&spy))
	poAccountGoogleToken(m, "account-cookie-accountid@test.com")
	c := env.client()
	pacGoogleSignIn(t, c)
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
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"accountId": google["id"]}), "accessToken", "test")
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

func TestPortAccountCookieStaleCookieOtherUser(t *testing.T) {
	env, m := pacCallbackGoogleEnv(t, pacStoreAccountCookie)
	var mu sync.Mutex
	refreshedWith := ""
	poGoogleTokenByGrant(m, func(form url.Values) map[string]any {
		if form.Get("grant_type") == "refresh_token" {
			mu.Lock()
			refreshedWith = form.Get("refresh_token")
			mu.Unlock()
			// the provider does not rotate the refresh token
			return map[string]any{"access_token": "rotated-access-token"}
		}
		p := poAccountGoogleProfile("stale-cookie-first@test.com")
		p["name"], p["sub"], p["given_name"], p["family_name"] = "First User", "first-google-sub", "First", "User"
		return map[string]any{"access_token": "first-access-token", "refresh_token": "first-refresh-token", "id_token": poSignJWT(p)}
	})
	// The first user signs in with Google, storing their account_data cookie.
	c := env.client()
	pacGoogleSignIn(t, c)

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
	mu.Lock()
	got := refreshedWith
	mu.Unlock()
	if got != "second-refresh-token" {
		t.Fatalf("refresh must use the second user's token, got %q", got)
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

// pacIDTokenPair signs the old/new id tokens of the "persist refreshed idToken" tests.
func pacIDTokenPair(email, sub, oldJTI, newJTI string) (string, string) {
	now := time.Now().Unix()
	mk := func(exp int64, jti string) string {
		p := poAccountGoogleProfile(email)
		p["exp"], p["sub"], p["iat"], p["nbf"], p["jti"] = now+exp, sub, now, now, jti
		return poSignJWT(p)
	}
	return mk(3600, oldJTI), mk(7200, newJTI)
}

func TestPortAccountPersistRefreshedIDTokenInDatabase(t *testing.T) {
	env, m := pacCallbackGoogleEnv(t, func(c *Config) { c.Account = &AccountConfig{StoreAccountCookie: Bool(false)} })
	oldIDToken, newIDToken := pacIDTokenPair("persist-id-token-db@test.com", "persist-id-token-db", "old-id-token", "new-id-token")
	var refreshCalls atomic.Int32
	poGoogleTokenByGrant(m, func(form url.Values) map[string]any {
		if form.Get("grant_type") == "refresh_token" {
			refreshCalls.Add(1)
			return map[string]any{"access_token": "refreshed-access-token", "refresh_token": "refreshed-refresh-token",
				"expires_in": 3600, "id_token": newIDToken}
		}
		return map[string]any{"access_token": "initial-access-token", "refresh_token": "initial-refresh-token",
			"expires_in": 1, "id_token": oldIDToken}
	})
	c := env.client()
	pacGoogleSignIn(t, c)
	var googleID any
	for _, a := range pacListAccounts(t, c) {
		if a["providerId"] == "google" {
			googleID = a["id"]
		}
	}
	if googleID == nil {
		t.Fatal("google account should be listed")
	}
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"accountId": googleID}), "idToken", newIDToken)
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"accountId": googleID}), "idToken", newIDToken)
	if n := refreshCalls.Load(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1", n)
	}
	rec, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "account",
		Where: []adapter.Where{{Field: "providerId", Value: "google"}}})
	if err != nil || rec == nil {
		t.Fatalf("account not found: %v", err)
	}
	if rec["idToken"] != newIDToken {
		t.Fatalf("idToken = %v, want the refreshed id token", rec["idToken"])
	}
}

func TestPortAccountPersistRefreshedIDTokenInCookieStateless(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){func(c *Config) {
		c.Database = nil
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
	}}, poInstanceOpts{disableTestUser: true})
	name := env.auth.Context().AuthCookies.AccountData.Name
	oldIDToken, newIDToken := pacIDTokenPair("persist-id-token-cookie@test.com", "persist-id-token-cookie", "old-cookie-id-token", "new-cookie-id-token")
	var refreshCalls atomic.Int32
	poGoogleTokenByGrant(m, func(form url.Values) map[string]any {
		if form.Get("grant_type") == "refresh_token" {
			refreshCalls.Add(1)
			return map[string]any{"access_token": "refreshed-cookie-access-token", "refresh_token": "refreshed-cookie-refresh-token",
				"expires_in": 3600, "id_token": newIDToken}
		}
		return map[string]any{"access_token": "initial-cookie-access-token", "refresh_token": "initial-cookie-refresh-token",
			"expires_in": 1, "id_token": oldIDToken}
	})
	c := env.client()
	pacGoogleSignIn(t, c)
	first := c.post("/get-access-token", map[string]any{"useAccountCookie": true})
	pacExpectAccessToken(t, first, "idToken", newIDToken)
	refreshed, ok := poLastSetCookie(first.Header, name)
	if !ok || refreshed == "" {
		t.Fatalf("expected a refreshed %s cookie, got %v", name, pacSetCookieNames(first.Header))
	}
	if dec := pacDecodeAccountCookie(t, env, refreshed); dec["idToken"] != newIDToken {
		t.Fatalf("account cookie idToken = %v", dec["idToken"])
	}
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"useAccountCookie": true}), "idToken", newIDToken)
	if refreshCalls.Load() == 0 {
		t.Fatal("expected at least one refresh grant")
	}
}

// @see https://github.com/better-auth/better-auth/issues/8562
func TestPortAccountCognitoPreserveRefreshToken(t *testing.T) {
	const cognitoDomain = "test.auth.us-east-1.amazoncognito.com"
	const cognitoIssuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_testpool"
	signCognitoIDToken := func(jti string) string {
		now := time.Now().Unix()
		return poSignJWT(map[string]any{"email": "cognito-refresh@test.com", "email_verified": true, "name": "Cognito User",
			"exp": now + 3600, "sub": "cognito-user-sub", "iat": now, "aud": "cognito-client", "iss": cognitoIssuer, "jti": jti})
	}
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{cognito.New(cognito.Options{
		ProviderOptions: oauth2.ProviderOptions{ClientID: "cognito-client", ClientSecret: "cognito-secret"},
		Domain:          cognitoDomain, Region: "us-east-1", UserPoolID: "us-east-1_testpool",
	})}, []func(c *Config){func(c *Config) {
		c.Database = nil
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
	}}, poInstanceOpts{disableTestUser: true})
	name := env.auth.Context().AuthCookies.AccountData.Name
	initialIDToken, refreshedIDToken := signCognitoIDToken("initial-cognito-id-token"), signCognitoIDToken("refreshed-cognito-id-token")
	var mu sync.Mutex
	var grants []string
	m.Handle("POST "+cognitoDomain+"/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "application/json")
		if form.Get("grant_type") == "refresh_token" {
			mu.Lock()
			grants = append(grants, form.Get("refresh_token"))
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "refreshed-cognito-access-token", "expires_in": 3600,
				"id_token": refreshedIDToken, "token_type": "Bearer"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "initial-cognito-access-token", "expires_in": 1,
			"id_token": initialIDToken, "refresh_token": "cognito-refresh-token", "token_type": "Bearer"})
	})
	grantsCopy := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, grants...)
	}

	c := env.client()
	res := c.post("/sign-in/social", map[string]any{"provider": "cognito", "callbackURL": "/callback"})
	if res.Status != 200 {
		t.Fatalf("signIn.social: %d %s", res.Status, res.Body)
	}
	sm := res.JSON(t)
	if !strings.Contains(pacStr(sm["url"]), cognitoDomain) || sm["redirect"] != true {
		t.Fatalf("signIn.social: unexpected response %s", res.Body)
	}
	u, _ := url.Parse(pacStr(sm["url"]))
	cb := c.get("/callback/cognito?state=" + url.QueryEscape(u.Query().Get("state")) + "&code=test")
	if cb.Status != 302 {
		t.Fatalf("callback: %d %q %s", cb.Status, cb.Header.Get("Location"), cb.Body)
	}

	at := c.post("/get-access-token", map[string]any{"useAccountCookie": true})
	if at.Status != 200 {
		t.Fatalf("get-access-token: %d %s", at.Status, at.Body)
	}
	am := at.JSON(t)
	if am["accessToken"] != "refreshed-cognito-access-token" || am["idToken"] != refreshedIDToken {
		t.Fatalf("unexpected response %s", at.Body)
	}
	if g := grantsCopy(); len(g) != 1 || g[0] != "cognito-refresh-token" {
		t.Fatalf("refresh grants = %v", g)
	}
	refreshed, ok := poLastSetCookie(at.Header, name)
	if !ok || refreshed == "" {
		t.Fatalf("expected a refreshed %s cookie, got %v", name, pacSetCookieNames(at.Header))
	}
	dec := pacDecodeAccountCookie(t, env, refreshed)
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
	if g := grantsCopy(); len(g) != 2 || g[0] != "cognito-refresh-token" || g[1] != "cognito-refresh-token" {
		t.Fatalf("refresh grants = %v", g)
	}
}

func pacChunkedEnv(t *testing.T, fields ...db.Field) (*testEnv, *oauth2test.Server) {
	return pacCallbackGoogleEnv(t, func(c *Config) {
		c.Secret = "better-auth.secret"
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true), ModelConfig: ModelConfig{AdditionalFields: fields}}
	})
}

func pacAccountDataChunks(h http.Header) (chunks, single bool) {
	for _, n := range pacSetCookieNames(h) {
		if strings.Contains(n, "account_data.0") || strings.Contains(n, "account_data.1") {
			chunks = true
		}
		if strings.HasSuffix(n, "account_data") {
			single = true
		}
	}
	return
}

func TestPortAccountCookieNotChunkedUnder4KB(t *testing.T) {
	env, m := pacChunkedEnv(t)
	poAccountGoogleToken(m, "oauth-test@test.com")
	c := env.client()
	res := pacGoogleSignIn(t, c)
	chunks, single := pacAccountDataChunks(res.Header)
	if chunks || !single {
		t.Fatalf("hasChunks=%v hasSingleAccountData=%v (%v)", chunks, single, pacSetCookieNames(res.Header))
	}
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"useAccountCookie": true}), "accessToken", "test")
}

func TestPortAccountCookieChunkedOver4KB(t *testing.T) {
	env, m := pacChunkedEnv(t, db.Field{Name: "largeField", Type: db.TypeString, DefaultValue: strings.Repeat("x", 5000)})
	poAccountGoogleToken(m, "oauth-test@test.com")
	c := env.client()
	res := pacGoogleSignIn(t, c)
	if chunks, _ := pacAccountDataChunks(res.Header); !chunks {
		t.Fatalf("expected chunked account_data cookies, got %v", pacSetCookieNames(res.Header))
	}
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"useAccountCookie": true}), "accessToken", "test")
}

func TestPortAccountCookieEncryptedPayload(t *testing.T) {
	env, m := pacChunkedEnv(t)
	poAccountGoogleToken(m, "oauth-test@test.com")
	res := pacGoogleSignIn(t, env.client())
	v, ok := poLastSetCookie(res.Header, "better-auth.account_data")
	if !ok || !strings.HasPrefix(v, "ey") {
		t.Fatalf("account_data must be an encrypted JWT, got %q (%v)", v, pacSetCookieNames(res.Header))
	}
	dec := pacDecodeAccountCookie(t, env, v)
	if dec["accessToken"] != "test" || dec["refreshToken"] != "test" || dec["providerId"] != "google" {
		t.Fatalf("unexpected cookie payload %#v", dec)
	}
}

func TestPortAccountCookieReLoginUpdateAccountOnSignInFalse(t *testing.T) {
	env, m := pacCallbackGoogleEnv(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true), UpdateAccountOnSignIn: Bool(false)}
	})
	name := env.auth.Context().AuthCookies.AccountData.Name
	poAccountGoogleToken(m, "re-login-test@test.com")
	c := env.client()
	pacGoogleSignIn(t, c)
	pacExpectAccessToken(t, c.post("/get-access-token", map[string]any{"useAccountCookie": true}), "accessToken", "test")
	c.post("/sign-out", map[string]any{})

	c2 := env.client()
	res := pacGoogleSignIn(t, c2)
	if v, ok := poLastSetCookie(res.Header, name); !ok || v == "" {
		t.Fatalf("account cookie must be set on re-login, got %v", pacSetCookieNames(res.Header))
	}
	pacExpectAccessToken(t, c2.post("/get-access-token", map[string]any{"useAccountCookie": true}), "accessToken", "test")
}

func TestPortAccountCookieRefreshedWithSession(t *testing.T) {
	expiresIn := 7 * 24 * time.Hour
	updateAge := 10 * time.Second
	env, m := pacCallbackGoogleEnv(t, func(c *Config) {
		c.Account = &AccountConfig{StoreAccountCookie: Bool(true)}
		c.Session = &SessionConfig{ExpiresIn: expiresIn, UpdateAge: &updateAge,
			CookieCache: &CookieCacheConfig{Enabled: true, Strategy: "jwe"}}
	})
	ac := env.auth.Context()
	poAccountGoogleToken(m, "refresh-account-cookie-test@test.com")
	c := env.client()
	res := pacGoogleSignIn(t, c)
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.AccountData.Name); v == "" {
		t.Fatalf("initial account cookie not set: %v", pacSetCookieNames(res.Header))
	}
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.SessionData.Name); v == "" {
		t.Fatalf("initial session cookie not set: %v", pacSetCookieNames(res.Header))
	}
	s := c.session()
	if s == nil {
		t.Fatal("expected a session")
	}
	token := pacStr(s["session"].(map[string]any)["token"])
	past := time.Now().Add(expiresIn - updateAge - time.Second)
	if token != "" {
		if _, err := ac.Adapter.Update(context.Background(), "session", []adapter.Where{{Field: "token", Value: token}},
			adapter.Record{"expiresAt": past}); err != nil {
			t.Fatal(err)
		}
	}
	res = c.get("/get-session?disableCookieCache=true")
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.SessionData.Name); v == "" {
		t.Fatalf("expected refreshed session_data cookie, got %v", pacSetCookieNames(res.Header))
	}
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.AccountData.Name); v == "" {
		t.Fatalf("expected refreshed account_data cookie, got %v", pacSetCookieNames(res.Header))
	}
}

// Upstream advances fake timers by 241s against maxAge 300 / refreshCache.updateAge 60. Go
// has no injectable clock, so (like psStatelessRefresh) the refresh window is made
// reachable with updateAge 299s and a 1.1s sleep.
func TestPortAccountCookieRefreshedStateless(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){func(c *Config) {
		c.Database = nil
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true, Strategy: "jwe", MaxAge: 300 * time.Second,
			RefreshCache: &RefreshCacheConfig{Enabled: true, UpdateAge: Duration(299 * time.Second)}}}
	}}, poInstanceOpts{disableTestUser: true})
	ac := env.auth.Context()
	if ac.Options.Account == nil || ac.Options.Account.StoreAccountCookie == nil || !*ac.Options.Account.StoreAccountCookie {
		t.Fatal("storeAccountCookie should default to true in stateless mode")
	}
	poAccountGoogleToken(m, "stateless-refresh-test@test.com")
	c := env.client()
	res := pacGoogleSignIn(t, c)
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.AccountData.Name); v == "" {
		t.Fatalf("initial account cookie not set: %v", pacSetCookieNames(res.Header))
	}
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.SessionData.Name); v == "" {
		t.Fatalf("initial session cookie not set: %v", pacSetCookieNames(res.Header))
	}
	s := c.session()
	if s == nil {
		t.Fatal("expected a session")
	}
	if token := pacStr(s["session"].(map[string]any)["token"]); token != "" {
		_ = ac.InternalAdapter.DeleteSession(context.Background(), token)
	}
	time.Sleep(1100 * time.Millisecond)
	res = c.get("/get-session")
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.SessionData.Name); v == "" {
		t.Fatalf("expected refreshed session_data cookie, got %v", pacSetCookieNames(res.Header))
	}
	if v, _ := poLastSetCookie(res.Header, ac.AuthCookies.AccountData.Name); v == "" {
		t.Fatalf("expected refreshed account_data cookie, got %v", pacSetCookieNames(res.Header))
	}
}

const pacGenericOAuthSkip = "ported to plugins/genericoauth/stateless_account_test.go: describe(\"account resolution in stateless mode\") signs in through a discovery-based genericOAuth provider (betterauth cannot import plugins)"

func TestPortAccountStatelessGetAccessTokenMismatchedCookie(t *testing.T) {
	t.Skip(pacGenericOAuthSkip)
}

func TestPortAccountStatelessAccountInfoMismatchedCookie(t *testing.T) {
	t.Skip(pacGenericOAuthSkip)
}

func TestPortAccountStatelessRefreshMismatchedCookie(t *testing.T) {
	t.Skip(pacGenericOAuthSkip)
}

func TestPortAccountStatelessSessionRefreshPreservesCookie(t *testing.T) {
	t.Skip(pacGenericOAuthSkip)
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
