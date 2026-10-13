package genericoauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

// Port of describe("account resolution in stateless mode") from
// packages/better-auth/src/api/routes/account.test.ts. The cases sign in through a
// discovery-based genericOAuth provider, so they live here (betterauth cannot import plugins).

const statelessIDP = "https://idp.stateless.test"

func statelessIdP(t *testing.T) {
	t.Helper()
	srv := oauth2test.New(t)
	srv.JSON("idp.stateless.test/.well-known/openid-configuration", 200, map[string]any{
		"authorization_endpoint": statelessIDP + "/authorize", "token_endpoint": statelessIDP + "/token",
		"userinfo_endpoint": statelessIDP + "/userinfo", "jwks_uri": statelessIDP + "/jwks"})
	srv.Handle("POST idp.stateless.test/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			writeJSON(w, 200, map[string]any{"token_type": "Bearer", "access_token": "idp-refreshed-access-token",
				"refresh_token": "idp-rotated-refresh-token", "expires_in": 3600, "scope": "openid profile email"})
			return
		}
		writeJSON(w, 200, map[string]any{"token_type": "Bearer", "access_token": "idp-access-token", "refresh_token": "idp-refresh-token",
			"expires_in": 3600, "scope": "openid profile email"})
	})
}

func makeStatelessAuth(t *testing.T) *inst {
	t.Helper()
	ua := time.Hour
	return newInst(t, func(c *betterauth.Config) {
		c.Secret = "stateless-test-secret-stateless-test-secret"
		c.TrustedOrigins = []string{"http://localhost:3000"}
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, Strategy: "jwe", MaxAge: time.Minute,
			RefreshCache: &betterauth.RefreshCacheConfig{Enabled: true, UpdateAge: &ua}}}
		c.Account = &betterauth.AccountConfig{StoreStateStrategy: "cookie", StoreAccountCookie: betterauth.Bool(true)}
		genericPlugin(Config{ProviderID: "idp", ClientID: "client-id", ClientSecret: "client-secret", Scopes: []string{"openid", "profile", "email"},
			DiscoveryURL: statelessIDP + "/.well-known/openid-configuration",
			GetUserInfo: func(_ context.Context, tok *oauth2.Tokens) (map[string]any, error) {
				return map[string]any{"id": "shared-idp-user", "email": "user@stateless.test", "name": "Stateless User", "emailVerified": true,
					"accessTokenSeen": tok.AccessToken}, nil
			}})(c)
	}, instOpts{noDatabase: true})
}

func statelessSignIn(t *testing.T, in *inst) (*client, string) {
	t.Helper()
	c := in.client()
	res := c.post("/sign-in/social", map[string]any{"provider": "idp", "callbackURL": "/", "disableRedirect": true})
	u, _ := res.JSON(t)["url"].(string)
	state := queryParam(t, u, "state")
	if state == "" {
		t.Fatal("expected an OAuth state to be issued")
	}
	c.get("/callback/idp?code=test-code&state=" + url.QueryEscape(state))
	s := c.session()
	if s == nil {
		t.Fatal("expected OAuth sign-in to create a session")
	}
	return c, sessionUser(s)["id"].(string)
}

// signInOnTwoInstances returns a jar holding A's session with B's account cookie.
func signInOnTwoInstances(t *testing.T) (mixed *client, accountCookie, sessionUserID string) {
	t.Helper()
	authA := makeStatelessAuth(t)
	a, aID := statelessSignIn(t, authA)
	b, bID := statelessSignIn(t, makeStatelessAuth(t))
	if aID == bID {
		t.Fatal("expected different users")
	}
	name := authA.ctx().AuthCookies.AccountData.Name
	m := a.clone()
	for _, k := range append([]string(nil), m.order...) {
		if strings.HasPrefix(k, name) {
			delete(m.cookies, k)
		}
	}
	for _, k := range b.order {
		if v, ok := b.cookies[k]; ok && strings.HasPrefix(k, name) {
			m.setCookieValue(k, v)
		}
	}
	return m, name, aID
}

func onInstance(c *client, in *inst) *client {
	n := in.client()
	for _, k := range c.order {
		if v, ok := c.cookies[k]; ok {
			n.setCookieValue(k, v)
		}
	}
	return n
}

func TestResolvesGetAccessTokenWithAValidAccountCookieWhoseUserIDDiffersFromTheSessionUser(t *testing.T) {
	statelessIdP(t)
	mixed, _, uid := signInOnTwoInstances(t)
	c := onInstance(mixed, makeStatelessAuth(t))
	res := c.post("/get-access-token", map[string]any{"useAccountCookie": true, "userId": uid})
	mustEqual(t, res.JSON(t)["accessToken"], any("idp-access-token"))
}

func TestResolvesAccountInfoWithAValidAccountCookieWhoseUserIDDiffersFromTheSessionUser(t *testing.T) {
	statelessIdP(t)
	mixed, _, uid := signInOnTwoInstances(t)
	in := makeStatelessAuth(t)
	h := http.Header{}
	h.Set("Cookie", mixed.cookieHeader())
	h.Set("Host", "localhost:3000")
	r, err := in.auth.API.Call(context.Background(), "accountInfo", betterauth.CallInput{Headers: h,
		Query: map[string]any{"useAccountCookie": true, "userId": uid}})
	if err != nil {
		t.Fatalf("accountInfo: %v", err)
	}
	b, _ := r.JSON()
	info := decodeJSON(t, string(b))
	acc, _ := info["account"].(map[string]any)
	if acc == nil {
		t.Fatalf("expected accountInfo to resolve from the account cookie: %s", b)
	}
	mustEqual(t, acc["accountId"], any("shared-idp-user"))
	mustEqual(t, acc["providerId"], any("idp"))
	data, _ := info["data"].(map[string]any)
	mustEqual(t, data["accessTokenSeen"], any("idp-access-token"))
}

func TestRefreshesAValidAccountCookieWhoseUserIDDiffersFromTheSessionUser(t *testing.T) {
	statelessIdP(t)
	mixed, _, uid := signInOnTwoInstances(t)
	c := onInstance(mixed, makeStatelessAuth(t))
	res := c.post("/refresh-token", map[string]any{"useAccountCookie": true, "userId": uid})
	m := res.JSON(t)
	mustEqual(t, m["accessToken"], any("idp-refreshed-access-token"))
	mustEqual(t, m["refreshToken"], any("idp-rotated-refresh-token"))
}

func TestPreservesAValidMismatchedAccountCookieDuringStatelessSessionRefresh(t *testing.T) {
	statelessIdP(t)
	mixed, name, _ := signInOnTwoInstances(t)
	c := onInstance(mixed, makeStatelessAuth(t))
	res := c.get("/get-session")
	mustEqual(t, res.Status, 200)
	v, attrs, ok := res.setCookie(name)
	if !ok || v == "" || attrs["max-age"] == "0" {
		t.Fatalf("account cookie %q %v (%v)", v, attrs, res.Header.Values("Set-Cookie"))
	}
}
