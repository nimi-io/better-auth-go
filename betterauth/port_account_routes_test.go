package betterauth

// Port of better-auth/src/api/routes/account.test.ts — describe("account").
//
// Upstream runs the "account" describe block as one shared instance whose state flows
// from test to test (accounts linked through the /callback/google round-trip are counted
// by later tests). The Go ports below are independent: each test seeds the rows the
// upstream predecessor tests would have produced (documented per test). The callback
// round-trip itself is phase 2 and is skipped where it is the subject of the test.

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// pacMainInstance mirrors the shared getTestInstance of describe("account"): google with
// a verifyIdToken mock, allowDifferentEmails and encryptOAuthTokens.
func pacMainInstance(t *testing.T) (*testEnv, *pacProvider) {
	t.Helper()
	g := pacGoogle()
	env := pacNewInstance(t, []*pacProvider{g}, func(c *Config) {
		c.Account = &AccountConfig{
			AccountLinking:     &AccountLinkingConfig{AllowDifferentEmails: true},
			EncryptOAuthTokens: true,
		}
	})
	return env, g
}

func pacIsolatedGoogle(t *testing.T, mutates ...func(*Config)) (*testEnv, *pacProvider) {
	t.Helper()
	g := pacGoogle()
	return pacNewInstance(t, []*pacProvider{g}, mutates...), g
}

func TestPortAccountListAllAccounts(t *testing.T) {
	env, _ := pacMainInstance(t)
	c, _ := pacSignInWithTestUser(t, env)
	if n := len(pacListAccounts(t, c)); n != 1 {
		t.Fatalf("expected 1 account, got %d", n)
	}
}

func TestPortAccountLinkFirstAccount(t *testing.T) {
	env, _ := pacMainInstance(t)
	c, _ := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback"})
	if res.Status != 200 {
		t.Fatalf("link-social: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if !strings.Contains(pacStr(m["url"]), "google.com") || m["redirect"] != true {
		t.Fatalf("unexpected link-social response: %s", res.Body)
	}
	if _, ok := res.cookie("better-auth.state"); !ok {
		t.Fatalf("expected better-auth.state cookie, got %v", res.Header.Values("Set-Cookie"))
	}
	u, _ := url.Parse(pacStr(m["url"]))
	if u.Query().Get("state") == "" {
		t.Fatal("expected state in authorization URL")
	}
	t.Skip("phase 2: /callback/google round-trip (account creation + list-accounts == 2) not implemented")
}

func TestPortAccountEncryptAccessAndRefreshToken(t *testing.T) {
	t.Skip("phase 2: upstream relies on the account created by the /callback/google round-trip; see TestPortAccountEncryptTokensViaIDTokenLink for the adapted id-token variant")
}

// Adapted from "should encrypt access token and refresh token": the google account is
// linked through the id-token flow (with accessToken "test") instead of the callback.
func TestPortAccountEncryptTokensViaIDTokenLink(t *testing.T) {
	env, g := pacMainInstance(t)
	g.verifyOnce = []bool{true}
	g.userInfoOnce = []*oauth2.UserInfoResult{{
		User: oauth2.UserInfo{Name: "First Last", Email: pacTestEmail, EmailVerified: true},
		Data: map[string]any{"sub": "1234567890", "email": pacTestEmail},
	}}
	c, _ := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback",
		"idToken": map[string]any{"token": "id-token", "accessToken": "test", "refreshToken": "test"}})
	if res.Status != 200 {
		t.Fatalf("link-social: %d %s", res.Status, res.Body)
	}
	rec, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "account",
		Where: []adapter.Where{{Field: "providerId", Value: "google"}}})
	if err != nil || rec == nil {
		t.Fatalf("google account not found: %v", err)
	}
	if rec["accessToken"] == "test" || rec["accessToken"] == nil {
		t.Fatalf("expected encrypted accessToken, got %v", rec["accessToken"])
	}
	if rec["refreshToken"] == "test" || rec["refreshToken"] == nil {
		t.Fatalf("expected encrypted refreshToken, got %v", rec["refreshToken"])
	}
	c2, _ := pacSignInWithTestUser(t, env)
	var googleID string
	for _, a := range pacListAccounts(t, c2) {
		if a["providerId"] == "google" {
			googleID = pacStr(a["id"])
		}
	}
	if googleID == "" {
		t.Fatal("google account should be listed")
	}
	at := c2.post("/get-access-token", map[string]any{"accountId": googleID})
	if at.Status != 200 || at.JSON(t)["accessToken"] != "test" {
		t.Fatalf("expected accessToken test, got %d %s", at.Status, at.Body)
	}
}

func TestPortAccountSelectLinkedAccountByLocalID(t *testing.T) {
	env, _ := pacIsolatedGoogle(t)
	c, user := pacSignInWithTestUser(t, env)
	stored := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google",
		"accountId": "local-account-selector-subject", "accessToken": "local-account-selector-token"})
	var found map[string]any
	for _, a := range pacListAccounts(t, c) {
		if a["id"] == stored.ID {
			found = a
		}
	}
	if found == nil {
		t.Fatal("google account should be listed")
	}
	if found["accountId"] != "local-account-selector-subject" {
		t.Fatalf("accountId = %v", found["accountId"])
	}
	if found["id"] == found["accountId"] {
		t.Fatal("id must differ from accountId")
	}
	res := c.post("/get-access-token", map[string]any{"accountId": found["id"]})
	if res.Status != 200 {
		t.Fatalf("expected no error, got %d %s", res.Status, res.Body)
	}
	if res.JSON(t)["accessToken"] != "local-account-selector-token" {
		t.Fatalf("unexpected access token: %s", res.Body)
	}
}

func TestPortAccountEmptyStoredScope(t *testing.T) {
	env, _ := pacIsolatedGoogle(t)
	c, user := pacSignInWithTestUser(t, env)
	stored := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google",
		"accountId": "empty-scope-google-account", "accessToken": "access-token", "scope": ""})
	var found map[string]any
	for _, a := range pacListAccounts(t, c) {
		if a["accountId"] == "empty-scope-google-account" {
			found = a
		}
	}
	if found == nil {
		t.Fatal("account not listed")
	}
	if sc, ok := found["scopes"].([]any); !ok || len(sc) != 0 {
		t.Fatalf("expected scopes [], got %#v", found["scopes"])
	}
	res := c.post("/get-access-token", map[string]any{"accountId": stored.ID})
	if res.Status != 200 {
		t.Fatalf("get-access-token: %d %s", res.Status, res.Body)
	}
	if sc, ok := res.JSON(t)["scopes"].([]any); !ok || len(sc) != 0 {
		t.Fatalf("expected scopes [], got %s", res.Body)
	}
}

// Not upstream: list-accounts scope parsing for a comma separated scope string.
func TestPortAccountListAccountsParsesScopes(t *testing.T) {
	env, _ := pacIsolatedGoogle(t)
	c, user := pacSignInWithTestUser(t, env)
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google",
		"accountId": "scoped", "accessToken": "a", "scope": "email, profile,,openid"})
	for _, a := range pacListAccounts(t, c) {
		if a["accountId"] != "scoped" {
			continue
		}
		sc, _ := a["scopes"].([]any)
		if len(sc) != 3 || sc[0] != "email" || sc[1] != "profile" || sc[2] != "openid" {
			t.Fatalf("unexpected scopes %#v", a["scopes"])
		}
		if _, ok := a["scope"]; ok {
			t.Fatalf("raw scope must not be exposed: %#v", a)
		}
		return
	}
	t.Fatal("account not listed")
}

func pacAssertAccountInfo(t *testing.T, m map[string]any, acc *Account) {
	t.Helper()
	u, ok := m["user"].(map[string]any)
	if !ok {
		t.Fatalf("missing user: %#v", m)
	}
	if _, ok := u["email"].(string); !ok {
		t.Fatalf("user.email must be a string: %#v", u)
	}
	a, _ := m["account"].(map[string]any)
	if a == nil || a["id"] != acc.ID || a["providerId"] != acc.ProviderID || a["accountId"] != acc.AccountID {
		t.Fatalf("unexpected account: %#v", m["account"])
	}
	if _, ok := m["data"].(map[string]any); !ok {
		t.Fatalf("data must be an object: %#v", m["data"])
	}
}

func TestPortAccountInfoByLocalAccountID(t *testing.T) {
	env, g := pacIsolatedGoogle(t)
	g.userInfoFn = func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "Provider User", Email: "provider-user@example.com", EmailVerified: true},
			Data: map[string]any{"sub": "provider-subject"}}, nil
	}
	c, user := pacSignInWithTestUser(t, env)
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google",
		"accountId": "provider-subject", "accessToken": "provider-access-token"})
	res := c.get("/account-info?accountId=" + url.QueryEscape(acc.ID))
	if res.Status != 200 {
		t.Fatalf("account-info: %d %s", res.Status, res.Body)
	}
	pacAssertAccountInfo(t, res.JSON(t), acc)
}

func TestPortAccountInfoProviderCannotResolve(t *testing.T) {
	env, g := pacIsolatedGoogle(t)
	g.userInfoFn = func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) { return nil, nil }
	c, user := pacSignInWithTestUser(t, env)
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google",
		"accountId": "unavailable-provider-subject", "accessToken": "provider-access-token"})
	res := c.get("/account-info?accountId=" + url.QueryEscape(acc.ID))
	pacExpectErrorBody(t, res, 401, ErrFailedToGetUserInfo.Code, ErrFailedToGetUserInfo.Message)
}

func TestPortAccountInfoServerSideUserIDWithoutHeaders(t *testing.T) {
	env, g := pacIsolatedGoogle(t)
	user := pacCreateUser(t, env, "Server-side Account User", "account-info-server-side@test.com")
	acc := pacCreateAccount(t, env, adapter.Record{"userId": user.ID, "providerId": "google",
		"accountId": "server-side-provider-subject", "accessToken": "server-side-access-token"})
	g.userInfoFn = func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "Provider User", Email: user.Email, EmailVerified: true},
			Data: map[string]any{"sub": acc.AccountID}}, nil
	}
	res, err := env.auth.API.Call(context.Background(), "accountInfo", CallInput{
		Query: map[string]any{"accountId": acc.ID, "userId": acc.UserID}})
	if err != nil {
		t.Fatalf("accountInfo: %v", err)
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		t.Fatal(err)
	}
	pacAssertAccountInfo(t, m, acc)
}

func TestPortAccountInfoRejectHTTPWithoutSession(t *testing.T) {
	env, _ := pacMainInstance(t)
	_, user := pacSignInWithTestUser(t, env)
	c := env.client() // no session
	res := c.get("/account-info?accountId=any-account-id&userId=" + url.QueryEscape(pacStr(user["id"])))
	if res.Status != 401 {
		t.Fatalf("expected 401, got %d %s", res.Status, res.Body)
	}
}

func TestPortAccountInfoNotResolveOtherUsersAccount(t *testing.T) {
	env, g := pacIsolatedGoogle(t)
	other := pacCreateUser(t, env, "Other User", "other-account-info@example.com")
	otherAcc := pacCreateAccount(t, env, adapter.Record{"userId": other.ID, "providerId": "google",
		"accountId": "other-user-google-subject", "accessToken": "other-access-token"})
	c, _ := pacSignInWithTestUser(t, env)
	res := c.get("/account-info?accountId=" + url.QueryEscape(otherAcc.ID))
	if m := res.JSON(t); m["message"] != ErrAccountNotFound.Message {
		t.Fatalf("expected %q, got %d %s", ErrAccountNotFound.Message, res.Status, res.Body)
	}
	if n := g.userInfoCallCount(); n != 0 {
		t.Fatalf("getUserInfo must not be called, got %d calls", n)
	}
}

func TestPortAccountInfoSubjectCollisionAcrossIssuers(t *testing.T) {
	g, gh := pacGoogle(), pacGithub()
	env := pacNewInstance(t, []*pacProvider{g, gh}, func(c *Config) {
		c.Account = &AccountConfig{AccountLinking: &AccountLinkingConfig{AllowDifferentEmails: true}}
	})
	c, user := pacSignInWithTestUser(t, env)
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google",
		"accountId": "shared-provider-account-id", "accessToken": "google-access-token"})
	ghAcc := pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "github",
		"accountId": "shared-provider-account-id", "accessToken": "github-access-token"})
	gh.userInfoOnce = []*oauth2.UserInfoResult{{
		User: oauth2.UserInfo{Name: pacStr(user["name"]), Email: pacStr(user["email"]), EmailVerified: user["emailVerified"] == true},
		Data: map[string]any{"source": "github"},
	}}
	res := c.get("/account-info?accountId=" + url.QueryEscape(ghAcc.ID))
	if res.Status != 200 {
		t.Fatalf("expected no error, got %d %s", res.Status, res.Body)
	}
	data, _ := res.JSON(t)["data"].(map[string]any)
	if data["source"] != "github" {
		t.Fatalf("unexpected data: %s", res.Body)
	}
	found := false
	for _, call := range gh.userInfoCalls {
		if call.AccessToken == "github-access-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("github getUserInfo not called with github-access-token: %#v", gh.userInfoCalls)
	}
}

func TestPortAccountInfoServerSideOwnership(t *testing.T) {
	gh := pacGithub()
	env := pacNewInstance(t, []*pacProvider{gh})
	selected := pacCreateUser(t, env, "Server Side User", "server-side-disambiguate@example.com")
	other := pacCreateUser(t, env, "Other Server Side User", "other-server-side@example.com")
	otherAcc := pacCreateAccount(t, env, adapter.Record{"userId": other.ID, "providerId": "github",
		"accountId": "other-server-side-subject", "accessToken": "github-access-token"})
	_, err := env.auth.API.Call(context.Background(), "accountInfo", CallInput{
		Query: map[string]any{"accountId": otherAcc.ID, "userId": selected.ID}})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %v", err)
	}
	if apiErr.Message() != ErrAccountNotFound.Message {
		t.Fatalf("expected %q, got %q", ErrAccountNotFound.Message, apiErr.Message())
	}
	if n := gh.userInfoCallCount(); n != 0 {
		t.Fatalf("getUserInfo must not be called, got %d", n)
	}
}

func TestPortAccountInfoCredentialAccount(t *testing.T) {
	env, _ := pacMainInstance(t)
	c, _ := pacSignInWithTestUser(t, env)
	var credID string
	for _, a := range pacListAccounts(t, c) {
		if a["providerId"] == "credential" {
			credID = pacStr(a["id"])
		}
	}
	if credID == "" {
		t.Fatal("credential account should be listed")
	}
	res := c.get("/account-info?accountId=" + url.QueryEscape(credID))
	pacExpectErrorBody(t, res, 400, "", "Account is not associated with a configured social provider.")
}

func TestPortAccountLinkSocialCustomScopes(t *testing.T) {
	env, _ := pacMainInstance(t)
	c, _ := pacSignInWithTestUser(t, env)
	custom := "https://www.googleapis.com/auth/drive.readonly"
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback", "scopes": []string{custom}})
	if res.Status != 200 {
		t.Fatalf("link-social: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if !strings.Contains(pacStr(m["url"]), "google.com") || m["redirect"] != true {
		t.Fatalf("unexpected response %s", res.Body)
	}
	u, _ := url.Parse(pacStr(m["url"]))
	if !strings.Contains(u.Query().Get("scope"), custom) {
		t.Fatalf("scope %q does not contain %q", u.Query().Get("scope"), custom)
	}
}

func TestPortAccountLinkSocialAdditionalParamsAndLoginHint(t *testing.T) {
	env, _ := pacMainInstance(t)
	c, _ := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback",
		"loginHint": "user@example.com", "additionalParams": map[string]any{"access_type": "offline", "prompt": "consent"}})
	if res.Status != 200 {
		t.Fatalf("link-social: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if !strings.Contains(pacStr(m["url"]), "google.com") || m["redirect"] != true {
		t.Fatalf("unexpected response %s", res.Body)
	}
	q, _ := url.Parse(pacStr(m["url"]))
	if q.Query().Get("access_type") != "offline" || q.Query().Get("prompt") != "consent" || q.Query().Get("login_hint") != "user@example.com" {
		t.Fatalf("unexpected query %v", q.Query())
	}
}

func TestPortAccountLinkSocialRejectReservedAdditionalParams(t *testing.T) {
	env, _ := pacMainInstance(t)
	c, _ := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback",
		"additionalParams": map[string]any{"state": "attacker-controlled"}})
	if res.Status != 400 {
		t.Fatalf("expected 400, got %d %s", res.Status, res.Body)
	}
}

func TestPortAccountLinkSocialIDTokenNonce(t *testing.T) {
	env, g := pacMainInstance(t)
	g.setRequiresIDTokenNonce(true)
	c, _ := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback"})
	if res.Status != 200 {
		t.Fatalf("expected no error, got %d %s", res.Status, res.Body)
	}
	if len(g.authURLCalls) != 1 || g.authURLCalls[0].IDTokenNonce == "" {
		t.Fatalf("createAuthorizationURL must be called with an idTokenNonce: %#v", g.authURLCalls)
	}
}

func TestPortAccountLinkSecondAccountSameProvider(t *testing.T) {
	env, _ := pacMainInstance(t)
	c, _ := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback"})
	if res.Status != 200 {
		t.Fatalf("link-social: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if !strings.Contains(pacStr(m["url"]), "google.com") || m["redirect"] != true {
		t.Fatalf("unexpected response %s", res.Body)
	}
	t.Skip("phase 2: /callback/google round-trip (re-linking the same google subject keeps 2 accounts) not implemented")
}

// Upstream state before this test: credential + the google account (sub "1234567890")
// created by the earlier callback round-trips. It is seeded directly here.
func TestPortAccountLinkThirdAccountWithIDToken(t *testing.T) {
	env, g := pacMainInstance(t)
	_, user := pacSignInWithTestUser(t, env)
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "1234567890",
		"accessToken": "test", "refreshToken": "test"})
	g.verifyOnce = []bool{true}
	profile := map[string]any{"id": "0987654321", "name": "test2", "email": "test2@gmail.com", "sub": "test2", "emailVerified": true}
	g.userInfoOnce = []*oauth2.UserInfoResult{{
		User: oauth2.UserInfo{Name: "test2", Email: "test2@gmail.com", EmailVerified: true,
			Extra: map[string]any{"id": "0987654321", "sub": "test2"}},
		Data: profile,
	}}
	c, _ := pacSignInWithTestUser(t, env)
	c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/callback", "idToken": map[string]any{"token": "test"}})
	if n := g.verifyCallCount(); n != 1 {
		t.Fatalf("verifyIdToken calls = %d, want 1", n)
	}
	if n := g.userInfoCallCount(); n != 1 {
		t.Fatalf("getUserInfo calls = %d, want 1", n)
	}
	c3, _ := pacSignInWithTestUser(t, env)
	if n := len(pacListAccounts(t, c3)); n != 3 {
		t.Fatalf("expected 3 accounts, got %d", n)
	}
}

func TestPortAccountLinkInvalidAccountSubject(t *testing.T) {
	env, g := pacIsolatedGoogle(t)
	g.verifyFn = func(string, string) (bool, error) { return true, nil }
	g.subjectFn = func(*oauth2.Tokens, map[string]any) (string, error) { return "", nil }
	g.userInfoFn = func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "Invalid Subject User", Email: "invalid-subject@example.com", EmailVerified: true},
			Data: map[string]any{"sub": "ignored-provider-subject"}}, nil
	}
	c, user := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "idToken": map[string]any{"token": "verified-id-token"}})
	pacExpectErrorBody(t, res, 401, ErrFailedToGetUserInfo.Code, ErrFailedToGetUserInfo.Message)
	accs := pacFindAccounts(t, env, pacStr(user["id"]))
	if len(accs) != 1 || accs[0].ProviderID != "credential" {
		t.Fatalf("expected only the credential account, got %d", len(accs))
	}
}

func TestPortAccountLinkMissingEmailBeforeInvalidAccountKey(t *testing.T) {
	env, g := pacIsolatedGoogle(t)
	g.verifyFn = func(string, string) (bool, error) { return true, nil }
	g.subjectFn = func(*oauth2.Tokens, map[string]any) (string, error) { return "", nil }
	g.userInfoFn = func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "Missing Email User", EmailVerified: true},
			Data: map[string]any{"sub": "ignored-provider-subject"}}, nil
	}
	c, _ := pacSignInWithTestUser(t, env)
	res := c.post("/link-social", map[string]any{"provider": "google", "idToken": map[string]any{"token": "verified-id-token"}})
	pacExpectErrorBody(t, res, 401, ErrUserEmailNotFound.Code, ErrUserEmailNotFound.Message)
}

func TestPortAccountProviderAliasesNoCrossUserLinking(t *testing.T) {
	g := pacGoogle()
	g.verifyFn = func(string, string) (bool, error) { return true, nil }
	accountID := "shared-direct-link-subject"
	g.userInfoFn = func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "Shared Social User", Email: "shared-social@example.com", EmailVerified: true},
			Data: map[string]any{"sub": accountID}}, nil
	}
	mobile := g.alias("google-mobile", "Google Mobile")
	env := pacNewInstance(t, []*pacProvider{g, mobile}, func(c *Config) {
		c.Account = &AccountConfig{AccountLinking: &AccountLinkingConfig{AllowDifferentEmails: true}}
	})
	c1, user1 := pacSignInWithTestUser(t, env)
	idt := map[string]any{"token": "verified-id-token"}
	first := c1.post("/link-social", map[string]any{"idToken": idt, "provider": "google"})
	if first.Status != 200 {
		t.Fatalf("first link: %d %s", first.Status, first.Body)
	}
	alias := c1.post("/link-social", map[string]any{"idToken": idt, "provider": "google-mobile"})
	if alias.Status != 200 {
		t.Fatalf("alias link: %d %s", alias.Status, alias.Body)
	}
	if m := alias.JSON(t); m["status"] != true || m["redirect"] != false {
		t.Fatalf("unexpected alias response %s", alias.Body)
	}
	var providers []string
	for _, a := range pacFindAccounts(t, env, pacStr(user1["id"])) {
		if a.AccountID == accountID {
			providers = append(providers, a.ProviderID)
		}
	}
	sort.Strings(providers)
	if strings.Join(providers, ",") != "google,google-mobile" {
		t.Fatalf("expected [google google-mobile], got %v", providers)
	}
	c2 := env.client()
	c2.signUp("second-direct-link@example.com", "password123456", "Second User")
	s2 := c2.session()
	if s2 == nil {
		t.Fatal("second user should be signed in")
	}
	user2, _ := s2["user"].(map[string]any)
	conflict := c2.post("/link-social", map[string]any{"idToken": idt, "provider": "google-mobile"})
	if conflict.Status != 409 {
		t.Fatalf("expected 409, got %d %s", conflict.Status, conflict.Body)
	}
	if m := conflict.JSON(t); m["message"] != ErrSocialAccountAlreadyLinked.Message {
		t.Fatalf("unexpected message %s", conflict.Body)
	}
	for _, a := range pacFindAccounts(t, env, pacStr(user2["id"])) {
		if a.AccountID == accountID {
			t.Fatal("second user must not get the shared account")
		}
	}
}

// Upstream state before this test: credential + google (callback) + google (id token).
func TestPortAccountUnlinkAccount(t *testing.T) {
	env, _ := pacMainInstance(t)
	_, user := pacSignInWithTestUser(t, env)
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "1234567890"})
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "test2"})
	c, _ := pacSignInWithTestUser(t, env)
	prev := pacListAccounts(t, c)
	if len(prev) != 3 {
		t.Fatalf("expected 3 accounts, got %d", len(prev))
	}
	res := c.post("/unlink-account", map[string]any{"accountId": prev[1]["id"]})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("unlink: %d %s", res.Status, res.Body)
	}
	if n := len(pacListAccounts(t, c)); n != 2 {
		t.Fatalf("expected 2 accounts, got %d", n)
	}
}

// Upstream state before this test: credential + one google account.
func TestPortAccountFailUnlinkLastAccount(t *testing.T) {
	env, _ := pacMainInstance(t)
	_, user := pacSignInWithTestUser(t, env)
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "1234567890"})
	c, _ := pacSignInWithTestUser(t, env)
	prev := pacListAccounts(t, c)
	if _, err := env.auth.Context().Adapter.DeleteMany(context.Background(), "account",
		[]adapter.Where{{Field: "providerId", Value: "google"}}); err != nil {
		t.Fatal(err)
	}
	res := c.post("/unlink-account", map[string]any{"accountId": prev[0]["id"]})
	if m := res.JSON(t); m["message"] != ErrFailedToUnlinkLastAccount.Message {
		t.Fatalf("expected %q, got %d %s", ErrFailedToUnlinkLastAccount.Message, res.Status, res.Body)
	}
}

// Upstream state before this test: only the credential account remains, so the upstream
// test returns early after the provider-count check. The literal logic is ported; the
// seeded google rows make the per-row path run when the first listed account has
// siblings of the same provider.
func TestPortAccountUnlinkOnlySelectedRow(t *testing.T) {
	env, _ := pacMainInstance(t)
	_, user := pacSignInWithTestUser(t, env)
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "a1"})
	pacCreateAccount(t, env, adapter.Record{"userId": user["id"], "providerId": "google", "accountId": "a2"})
	c, _ := pacSignInWithTestUser(t, env)
	prev := pacListAccounts(t, c)
	if len(prev) == 0 {
		t.Fatal("expected accounts")
	}
	toUnlink := prev[0]
	same := 0
	for _, a := range prev {
		if a["providerId"] == toUnlink["providerId"] {
			same++
		}
	}
	if same <= 1 {
		return
	}
	res := c.post("/unlink-account", map[string]any{"accountId": toUnlink["id"]})
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("unlink: %d %s", res.Status, res.Body)
	}
	after := pacListAccounts(t, c)
	if len(after) != len(prev)-1 {
		t.Fatalf("expected %d accounts, got %d", len(prev)-1, len(after))
	}
	for _, a := range after {
		if a["id"] == toUnlink["id"] {
			t.Fatal("unlinked account still listed")
		}
	}
}

func TestPortAccountUnlinkProviderAccountsIndividually(t *testing.T) {
	env, _ := pacMainInstance(t)
	_, user := pacSignInWithTestUser(t, env)
	for _, id := range []string{"123", "345"} {
		if _, err := env.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "account",
			Data: adapter.Record{"providerId": "google", "accountId": id, "userId": user["id"]}}); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := pacSignInWithTestUser(t, env)
	var google []map[string]any
	for _, a := range pacListAccounts(t, c) {
		if a["providerId"] == "google" {
			google = append(google, a)
		}
	}
	if len(google) <= 1 {
		t.Fatalf("expected >1 google accounts, got %d", len(google))
	}
	for i := 0; i < len(google)-1; i++ {
		res := c.post("/unlink-account", map[string]any{"accountId": google[i]["id"]})
		if res.Status != 200 || res.JSON(t)["status"] != true {
			t.Fatalf("unlink %d: %d %s", i, res.Status, res.Body)
		}
	}
	remaining := 0
	for _, a := range pacListAccounts(t, c) {
		if a["providerId"] == "google" {
			remaining++
		}
	}
	if remaining != 1 {
		t.Fatalf("expected 1 remaining google account, got %d", remaining)
	}
}

func TestPortAccountValidateUserInfoRejectsLinking(t *testing.T) {
	t.Skip("phase 2: describe(\"validateUserInfo account linking\") requires the /callback/google round-trip")
}
