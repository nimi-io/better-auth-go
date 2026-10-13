package oauthproxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/apple"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// Port of packages/better-auth/src/plugins/oauth-proxy/oauth-proxy.test.ts.

func signHS(t *testing.T, claims map[string]any) string {
	t.Helper()
	o := jsonx.NewObject()
	for _, k := range sortedKeys(claims) {
		o.Set(k, claims[k])
	}
	tok, err := bacrypto.SignJWT(o, betterauth.DefaultSecret, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func sortedKeys(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func testIDToken(t *testing.T) string {
	return signHS(t, map[string]any{"email": "user@email.com", "email_verified": true, "name": "First Last",
		"picture": "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw", "sub": "1234567890", "aud": "test", "azp": "test",
		"iss": "test", "locale": "en", "jti": "test", "given_name": "First", "family_name": "Last"})
}

// googleIdP mocks https://oauth2.googleapis.com/token (msw handlers).
func googleIdP(t *testing.T) *oauth2test.Server {
	t.Helper()
	srv := oauth2test.New(t)
	tok := testIDToken(t)
	srv.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{"access_token": "test", "refresh_token": "test", "id_token": tok,
		"expires_in": 3600, "refresh_token_expires_in": 86400})
	return srv
}

func at(base string) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.BaseURL = base }
}

func with(fs ...func(c *betterauth.Config)) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		for _, f := range fs {
			f(c)
		}
	}
}

func proxy(o Options) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.Plugins = append(c.Plugins, New(o)) }
}

func secret(s string) func(c *betterauth.Config) { return func(c *betterauth.Config) { c.Secret = s } }

func noDB(c *betterauth.Config) { c.Database = nil }

func startGoogle(t *testing.T, c *client) string {
	t.Helper()
	res, u := c.signInSocial(map[string]any{"provider": "google", "callbackURL": "/dashboard"})
	if u == "" {
		t.Fatalf("sign-in: %d %s", res.Status, res.Body)
	}
	return queryParam(t, u, "state")
}

func decryptWith(t *testing.T, key bacrypto.Secret, purpose bacrypto.EncryptionPurpose, data string) map[string]any {
	t.Helper()
	dec, err := bacrypto.SymmetricDecrypt(bacrypto.DerivePurposeKey(key, purpose), data)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return decodeJSON(t, dec)
}

func encryptPayload(t *testing.T, key bacrypto.Secret, payload any) string {
	t.Helper()
	raw, _ := jsonx.Marshal(payload)
	enc, err := bacrypto.SymmetricEncrypt(bacrypto.DerivePurposeKey(key, bacrypto.PurposeOAuthProxyProfile), string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestPackagesDatabaseStateAfterVerificationIdentifiersAreNamespaced(t *testing.T) {
	googleIdP(t)
	ps := "shared-proxy-purpose-test-secret"
	in := newInst(t, with(at("http://preview.example.com"), proxy(Options{ProductionURL: "http://localhost:3000", Secret: ps})))
	state := startGoogle(t, in.client())
	pkg := decryptWith(t, bacrypto.PlainSecret(ps), bacrypto.PurposeOAuthProxyPackage, state)
	mustEqual(t, pkg["isOAuthProxy"], any(true))
	v, err := in.ctx().InternalAdapter.FindVerificationValue(context.Background(), "auth-state:"+pkg["state"].(string))
	if err != nil || v == nil {
		t.Fatalf("verification %v %v", v, err)
	}
}

func TestRejectsProfileInputEncryptedForAnotherPurpose(t *testing.T) {
	for _, path := range []string{"/callback/google/oauth-proxy", "/oauth-proxy-callback"} {
		for _, source := range []string{"state-cookie", "pre-upgrade"} {
			t.Run("rejects profile input on "+path+" encrypted for "+source, func(t *testing.T) {
				in := newInst(t, proxy(Options{}))
				key := in.ctx().SecretConfig
				if source == "state-cookie" {
					key = bacrypto.DerivePurposeKey(key, bacrypto.PurposeOAuthStateCookie)
				}
				enc, _ := bacrypto.SymmetricEncrypt(key, `{"callbackURL":"/dashboard"}`)
				res := in.client().get(path + "?callbackURL=%2Fdashboard&profile=" + url.QueryEscape(enc))
				mustContain(t, res.location(), "error=invalid_profile")
			})
		}
	}
}

// invalidIdentityProvider cannot derive a stable account identity.
type invalidIdentityProvider struct{}

func (invalidIdentityProvider) ID() string   { return "invalid-account-identity" }
func (invalidIdentityProvider) Name() string { return "Invalid account identity" }
func (invalidIdentityProvider) CreateAuthorizationURL(_ context.Context, p oauth2.AuthorizationURLParams) (*url.URL, error) {
	return url.Parse("https://idp.example.com/authorize?state=" + p.State)
}
func (invalidIdentityProvider) ValidateAuthorizationCode(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
	return &oauth2.Tokens{AccessToken: "access-token"}, nil
}
func (invalidIdentityProvider) GetUserInfo(context.Context, oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
	return &oauth2.UserInfoResult{User: oauth2.UserInfo{Email: "user@example.com", EmailVerified: true}, Data: map[string]any{}}, nil
}
func (invalidIdentityProvider) AccountSubject(context.Context, *oauth2.Tokens, map[string]any) (string, error) {
	return "", nil
}

func TestRedirectsWhenAProviderCannotDeriveAStableAccountIdentity(t *testing.T) {
	in := newInst(t, with(func(c *betterauth.Config) {
		c.Plugins = append(c.Plugins, &betterauth.Plugin{ID: "invalid-account-identity-provider", Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			ac.SocialProviders = append([]oauth2.Provider{invalidIdentityProvider{}}, ac.SocialProviders...)
			return nil, nil
		}})
	}, proxy(Options{CurrentURL: "http://preview.example.com"})))
	c := in.client()
	_, u := c.signInSocial(map[string]any{"provider": "invalid-account-identity", "callbackURL": "/dashboard"})
	state := queryParam(t, u, "state")
	res := c.get("/callback/invalid-account-identity?code=test&state=" + url.QueryEscape(state))
	if res.location() == "" {
		t.Fatal("expected redirect")
	}
	mustEqual(t, queryParam(t, res.location(), "error"), "unable_to_get_user_info")
}

// ---- account linking ----

func accountLinkingFlow(t *testing.T) (complete func(accessToken, scope string) (authRedirect, finalRedirect, tokenRedirect string), preview *inst, userID string, pc *client) {
	srv := oauth2test.New(t)
	proxySecret := "shared-oauth-proxy-secret"
	gp := func(c *betterauth.Config) {
		c.SocialProviders = []oauth2.Provider{googleProvider(func(o *google.Options) {
			o.VerifyIDToken = func(context.Context, string, string) (bool, error) { return true, nil }
		})}
	}
	preview = newInst(t, with(at("http://preview.example.com"), secret("preview-main-secret"), gp,
		proxy(Options{ProductionURL: "http://localhost:3000", Secret: proxySecret}), func(c *betterauth.Config) {
			c.Account = &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{AllowDifferentEmails: true}}
		}))
	production := newInst(t, with(at("http://localhost:3000"), secret("production-main-secret"), gp, proxy(Options{Secret: proxySecret})), instOpts{disableTestUser: true})
	pc, userID = preview.signInWithTestUser()
	tok := testIDToken(t)
	complete = func(accessToken, scope string) (string, string, string) {
		tokenRedirect := ""
		srv.Handle("POST oauth2.googleapis.com/token", func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			tokenRedirect = r.Form.Get("redirect_uri")
			writeJSONResp(w, map[string]any{"access_token": accessToken, "refresh_token": "test", "id_token": tok, "expires_in": 3600,
				"refresh_token_expires_in": 86400, "scope": scope})
		})
		res := pc.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/settings"})
		u, _ := res.JSON(t)["url"].(string)
		if u == "" {
			t.Fatalf("link-social: %d %s", res.Status, res.Body)
		}
		state := queryParam(t, u, "state")
		cb := production.client().get("/callback/google?code=test&state=" + url.QueryEscape(state))
		loc := cb.location()
		if loc == "" {
			t.Fatal("Proxy callback URL is missing")
		}
		fin := pc.get(loc)
		return queryParam(t, u, "redirect_uri"), fin.location(), tokenRedirect
	}
	return
}

func TestAccountLinking(t *testing.T) {
	t.Run("creates and updates the provider account for the initiating user", func(t *testing.T) {
		complete, preview, uid, _ := accountLinkingFlow(t)
		sessions := func() []string {
			ss, _ := preview.ctx().InternalAdapter.ListSessions(context.Background(), uid, false)
			var ids []string
			for _, s := range ss {
				ids = append(ids, s.ID)
			}
			return ids
		}
		before := sessions()
		authR, fin, tokR := complete("initial-access-token", "openid profile")
		mustEqual(t, authR, "http://localhost:3000/api/auth/callback/google")
		mustEqual(t, tokR, authR)
		mustEqual(t, fin, "/settings")
		var g *betterauth.Account
		for _, a := range preview.accounts(uid) {
			if a.ProviderID == "google" {
				g = a
			}
		}
		if g == nil || strp(g.Scope) != "openid,profile" {
			t.Fatalf("google account %+v", g)
		}
		_, fin2, _ := complete("updated-access-token", "https://www.googleapis.com/auth/drive.readonly")
		mustEqual(t, fin2, "/settings")
		var gs []*betterauth.Account
		for _, a := range preview.accounts(uid) {
			if a.ProviderID == "google" {
				gs = append(gs, a)
			}
		}
		if len(gs) != 1 || strp(gs[0].AccessToken) != "updated-access-token" {
			t.Fatalf("accounts %+v", gs)
		}
		sc := strings.Split(strp(gs[0].Scope), ",")
		sort.Strings(sc)
		mustEqual(t, strings.Join(sc, " "), "https://www.googleapis.com/auth/drive.readonly openid profile")
		mustEqual(t, strings.Join(sessions(), ","), strings.Join(before, ","))
	})
	t.Run("links an account directly with an ID token", func(t *testing.T) {
		in := newInst(t, with(at("http://preview.example.com"), func(c *betterauth.Config) {
			c.SocialProviders = []oauth2.Provider{googleProvider(func(o *google.Options) {
				o.VerifyIDToken = func(context.Context, string, string) (bool, error) { return true, nil }
			})}
			c.Account = &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{AllowDifferentEmails: true}}
		}, proxy(Options{ProductionURL: "http://localhost:3000"})))
		c, uid := in.signInWithTestUser()
		res := c.post("/link-social", map[string]any{"provider": "google", "idToken": map[string]any{"token": testIDToken(t)}})
		if res.Status != 200 {
			t.Fatalf("link: %d %s", res.Status, res.Body)
		}
		m := res.JSON(t)
		mustEqual(t, m["status"], any(true))
		mustEqual(t, m["redirect"], any(false))
		found := false
		for _, a := range in.accounts(uid) {
			found = found || a.ProviderID == "google"
		}
		if !found {
			t.Fatal("expected google account")
		}
	})
}

func TestShouldRedirectToProxyURLWithProfileDataPassthrough(t *testing.T) {
	googleIdP(t)
	in := newInst(t, proxy(Options{CurrentURL: "http://preview-localhost:3000"}))
	c := in.client()
	state := startGoogle(t, c)
	loc := in.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
	mustContain(t, loc, "http://preview-localhost:3000/api/auth/callback/google/oauth-proxy")
	mustContain(t, loc, "callbackURL")
	if queryParam(t, loc, "profile") == "" {
		t.Fatal("expected profile")
	}
}

func TestShouldntRedirectToProxyURLOnSameOrigin(t *testing.T) {
	googleIdP(t)
	in := newInst(t, proxy(Options{}))
	c := in.client()
	state := startGoogle(t, c)
	loc := c.get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
	mustNotContain(t, loc, "/api/auth/callback/google/oauth-proxy")
	mustContain(t, loc, "/dashboard")
}

func TestShouldProxyToTheOriginalRequestURL(t *testing.T) {
	googleIdP(t)
	in := newInst(t, with(at("https://myapp.com"), proxy(Options{ProductionURL: "https://login.myapp.com"})))
	state := startGoogle(t, in.client())
	loc := in.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
	mustContain(t, loc, "https://myapp.com/api/auth/callback/google/oauth-proxy?callbackURL=%2Fdashboard")
	if queryParam(t, loc, "profile") == "" {
		t.Fatal("expected profile")
	}
}

func TestShouldRequireStateCookieIfItsNotInProxyURL(t *testing.T) {
	googleIdP(t)
	in := newInst(t, with(at("https://myapp.com"), proxy(Options{ProductionURL: "https://myapp.com"})))
	state := startGoogle(t, in.client())
	mustContain(t, in.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location(), "state_mismatch")
}

func TestShouldntRedirectToProxyURLOnSameOriginWithProductionURL(t *testing.T) {
	googleIdP(t)
	in := newInst(t, with(at("https://myapp.com"), proxy(Options{ProductionURL: "https://myapp.com"})))
	c := in.client()
	state := startGoogle(t, c)
	loc := c.get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
	mustNotContain(t, loc, "/api/auth/callback/google/oauth-proxy")
	mustContain(t, loc, "/dashboard")
}

// ---- stateless mode (cookie-based) ----

func TestStatelessModeCookieBased(t *testing.T) {
	t.Run("should encrypt state package for cross-origin OAuth", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, with(noDB, proxy(Options{CurrentURL: "http://preview-localhost:3000"})))
		state := startGoogle(t, in.client())
		if len(state) <= 50 {
			t.Fatalf("state %q", state)
		}
	})
	t.Run("should handle OAuth callback with encrypted state package", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, with(noDB, proxy(Options{CurrentURL: "http://preview-localhost:3000"})))
		state := startGoogle(t, in.client())
		loc := in.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
		mustContain(t, loc, "/callback/google/oauth-proxy")
		mustContain(t, loc, "callbackURL")
		mustContain(t, loc, "profile")
	})
	t.Run("should decrypt state package correctly", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, with(noDB, proxy(Options{CurrentURL: "http://preview-localhost:3000"})))
		state := startGoogle(t, in.client())
		pkg := decryptWith(t, bacrypto.PlainSecret(in.ctx().Secret), bacrypto.PurposeOAuthProxyPackage, state)
		for _, k := range []string{"state", "stateCookie", "isOAuthProxy"} {
			if _, ok := pkg[k]; !ok {
				t.Fatalf("missing %s", k)
			}
		}
		mustEqual(t, pkg["isOAuthProxy"], any(true))
	})
	t.Run("should work on same origin without proxy", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, with(noDB, proxy(Options{ProductionURL: "http://localhost:3000"})))
		c := in.client()
		state := startGoogle(t, c)
		if len(state) >= 50 {
			t.Fatalf("state %q", state)
		}
		loc := c.get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
		mustNotContain(t, loc, "/callback/google/oauth-proxy")
		mustContain(t, loc, "/dashboard")
	})
}

// ---- passthrough mode ----

func profileFrom(t *testing.T, loc string) (profile, callbackURL string) {
	t.Helper()
	if !strings.Contains(loc, "profile=") {
		t.Fatalf("no profile in %q", loc)
	}
	return queryParam(t, loc, "profile"), queryParam(t, loc, "callbackURL")
}

func proxyCallbackPath(t *testing.T, cb, profile string) string {
	return "/oauth-proxy-callback?callbackURL=" + url.QueryEscape(cb) + "&profile=" + url.QueryEscape(profile)
}

func previewProduction(t *testing.T, prodMutate, prevMutate func(c *betterauth.Config)) (*inst, *inst) {
	production := newInst(t, with(at("http://localhost:3000"), proxy(Options{}), prodMutate), instOpts{disableTestUser: true})
	preview := newInst(t, with(at("http://preview.example.com"), proxy(Options{ProductionURL: "http://localhost:3000"}), prevMutate), instOpts{disableTestUser: true})
	return production, preview
}

func nop(*betterauth.Config) {}

func TestPassthroughMode(t *testing.T) {
	t.Run("should include profile data in passthrough payload", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, proxy(Options{CurrentURL: "http://preview.example.com"}))
		state := startGoogle(t, in.client())
		prof, _ := profileFrom(t, in.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location())
		p := decryptWith(t, bacrypto.PlainSecret(in.ctx().Secret), bacrypto.PurposeOAuthProxyProfile, prof)
		ui := p["userInfo"].(map[string]any)
		mustEqual(t, ui["email"], any("user@email.com"))
		acc := p["account"].(map[string]any)
		mustEqual(t, acc["providerId"], any("google"))
		mustEqual(t, acc["accountId"], any("1234567890"))
		if p["state"] == nil || p["timestamp"] == nil {
			t.Fatal("missing state/timestamp")
		}
	})
	t.Run("recovers cookie-strategy state when the proxy secret differs from the env secret", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, with(secret("env-secret-not-shared"), func(c *betterauth.Config) {
			c.Account = &betterauth.AccountConfig{StoreStateStrategy: "cookie"}
		}, proxy(Options{CurrentURL: "http://preview.example.com", Secret: "shared-proxy-secret"})))
		state := startGoogle(t, in.client())
		profileFrom(t, in.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location())
	})
	t.Run("should create user/session on preview from profile data", func(t *testing.T) {
		googleIdP(t)
		production, preview := previewProduction(t, nop, nop)
		state := startGoogle(t, preview.client())
		prof, cb := profileFrom(t, production.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location())
		mustEqual(t, len(production.listUsers()), 0)
		mustEqual(t, len(preview.listUsers()), 0)
		mustContain(t, preview.client().get(proxyCallbackPath(t, cb, prof)).location(), "/dashboard")
		users := preview.listUsers()
		if len(users) != 1 || users[0].Email != "user@email.com" {
			t.Fatalf("users %+v", users)
		}
		accs := preview.accounts(users[0].ID)
		if len(accs) != 1 || accs[0].ProviderID != "google" {
			t.Fatalf("accounts %+v", accs)
		}
		ss, _ := preview.ctx().InternalAdapter.ListSessions(context.Background(), users[0].ID, false)
		mustEqual(t, len(ss), 1)
	})
	t.Run("runs callback hooks with restored OAuth state", func(t *testing.T) {
		googleIdP(t)
		type call struct {
			newSession    bool
			path          string
			providerID    string
			serverContext map[string]any
		}
		var calls []call
		production, preview := previewProduction(t, nop, func(c *betterauth.Config) {
			c.Hooks = &betterauth.HooksConfig{
				Before: func(ctx *betterauth.EndpointContext) (any, error) {
					if ctx.Path == "/sign-in/social" {
						betterauth.AddOAuthServerContext(ctx.Context(), map[string]any{"callbackObserver": true})
					}
					return nil, nil
				},
				After: func(ctx *betterauth.EndpointContext) (any, error) {
					if !strings.HasPrefix(ctx.Path, "/callback") {
						return nil, nil
					}
					st := betterauth.GetOAuthState(ctx.Context())
					var sc map[string]any
					if st != nil {
						sc = st.ServerContext
					}
					calls = append(calls, call{ctx.NewSession() != nil, ctx.Path, ctx.Params["id"], sc})
					return nil, nil
				},
			}
		})
		state := startGoogle(t, preview.client())
		loc := production.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
		profileFrom(t, loc)
		u, _ := url.Parse(loc)
		mustContain(t, preview.client().get(strings.Replace(u.Path, "/api/auth", "", 1)+"?"+u.RawQuery).location(), "/dashboard")
		if len(calls) != 1 || !calls[0].newSession || calls[0].path != "/callback/:id/oauth-proxy" || calls[0].providerID != "google" ||
			calls[0].serverContext["callbackObserver"] != true {
			t.Fatalf("calls %+v", calls)
		}
	})
	t.Run("rejects mismatched callback providers", func(t *testing.T) {
		googleIdP(t)
		production, preview := previewProduction(t, nop, nop)
		state := startGoogle(t, preview.client())
		loc := production.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
		profileFrom(t, loc)
		u, _ := url.Parse(loc)
		p := strings.Replace(strings.Replace(u.Path, "/api/auth", "", 1), "/callback/google/", "/callback/github/", 1)
		res := preview.client().get(p + "?" + u.RawQuery)
		mustEqual(t, queryParam(t, res.location(), "error"), "provider_mismatch")
		mustEqual(t, len(preview.listUsers()), 0)
	})
	t.Run("should forward result.error verbatim instead of collapsing to user_creation_failed", func(t *testing.T) {
		googleIdP(t)
		production, preview := previewProduction(t, func(c *betterauth.Config) {
			c.SocialProviders = []oauth2.Provider{googleProvider(func(o *google.Options) { o.DisableSignUp = true })}
		}, nop)
		state := startGoogle(t, preview.client())
		prof, cb := profileFrom(t, production.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location())
		loc := preview.client().get(proxyCallbackPath(t, cb, prof)).location()
		mustEqual(t, queryParam(t, loc, "error"), "signup_disabled")
	})
	expired := func(t *testing.T, maxAge time.Duration, ageMs int64) {
		in := newInst(t, proxy(Options{CurrentURL: "http://preview.example.com", MaxAge: maxAge}))
		enc := encryptPayload(t, bacrypto.PlainSecret(in.ctx().Secret), map[string]any{
			"userInfo": map[string]any{"id": "123", "email": "user@email.com", "name": "Test User", "emailVerified": true},
			"account":  map[string]any{"providerId": "google", "accountId": "123", "accessToken": "test"},
			"state":    "test-state", "callbackURL": "/dashboard", "timestamp": float64(time.Now().UnixMilli() - ageMs)})
		mustContain(t, in.client().get("/oauth-proxy-callback?callbackURL=%2Fdashboard&profile="+url.QueryEscape(enc)).location(), "error=payload_expired")
	}
	t.Run("should reject expired profile payloads", func(t *testing.T) { expired(t, 60*time.Second, 120000) })
	t.Run("should use custom maxAge setting", func(t *testing.T) { expired(t, 5*time.Second, 10000) })
	t.Run("should work with database mode + UUID", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, with(proxy(Options{CurrentURL: "http://preview.example.com"}), func(c *betterauth.Config) {
			c.Advanced = &betterauth.AdvancedConfig{Database: &betterauth.DatabaseAdvancedConfig{GenerateID: adapter.IDUUID}}
		}))
		state := startGoogle(t, in.client())
		prof, _ := profileFrom(t, in.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location())
		p := decryptWith(t, bacrypto.PlainSecret(in.ctx().Secret), bacrypto.PurposeOAuthProxyProfile, prof)
		if p["userInfo"] == nil {
			t.Fatal("missing userInfo")
		}
		mustEqual(t, p["account"].(map[string]any)["providerId"], any("google"))
	})
	t.Run("should reject payloads with missing required fields", func(t *testing.T) {
		in := newInst(t, proxy(Options{CurrentURL: "http://preview.example.com"}))
		valid := func() map[string]any {
			return map[string]any{
				"userInfo": map[string]any{"id": "123", "email": "user@email.com", "name": "Test User", "emailVerified": true},
				"account":  map[string]any{"providerId": "google", "accountId": "123", "accessToken": "test"},
				"state":    "test-state", "callbackURL": "/dashboard", "timestamp": float64(time.Now().UnixMilli())}
		}
		expect := func(p any) {
			t.Helper()
			enc := encryptPayload(t, bacrypto.PlainSecret(in.ctx().Secret), p)
			mustContain(t, in.client().get("/oauth-proxy-callback?callbackURL=%2Fdashboard&profile="+url.QueryEscape(enc)).location(), "error=invalid_payload")
		}
		expect(nil)
		for _, mod := range []func(m map[string]any){
			func(m map[string]any) { m["callbackURL"] = "" },
			func(m map[string]any) { m["state"] = "" },
			func(m map[string]any) { delete(m, "timestamp") },
			func(m map[string]any) { delete(m, "userInfo") },
			func(m map[string]any) { m["timestamp"] = "not-a-number" },
		} {
			v := valid()
			mod(v)
			expect(v)
		}
	})
	t.Run("should use dedicated secret instead of global secret", func(t *testing.T) {
		googleIdP(t)
		ded := "oauth-proxy-dedicated-secret-key"
		production := newInst(t, with(at("http://localhost:3000"), proxy(Options{Secret: ded})), instOpts{disableTestUser: true})
		preview := newInst(t, with(at("http://preview.example.com"), proxy(Options{ProductionURL: "http://localhost:3000", Secret: ded})), instOpts{disableTestUser: true})
		state := startGoogle(t, preview.client())
		prof, cb := profileFrom(t, production.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location())
		dec, err := bacrypto.SymmetricDecrypt(bacrypto.DerivePurposeKey(bacrypto.PlainSecret(ded), bacrypto.PurposeOAuthProxyProfile), prof)
		if err != nil || !strings.Contains(dec, "user@email.com") {
			t.Fatalf("decrypt %v", err)
		}
		if _, err := bacrypto.SymmetricDecrypt(bacrypto.PlainSecret(production.ctx().Secret), prof); err == nil {
			t.Fatal("expected global secret to fail")
		}
		mustContain(t, preview.client().get(proxyCallbackPath(t, cb, prof)).location(), "/dashboard")
		users := preview.listUsers()
		if len(users) != 1 || users[0].Email != "user@email.com" {
			t.Fatalf("users %+v", users)
		}
		found := false
		for _, a := range preview.accounts(users[0].ID) {
			found = found || (a.ProviderID == "google" && a.AccountID == "1234567890")
		}
		if !found {
			t.Fatal("expected google account")
		}
	})
	t.Run("should reject a profile payload whose OAuth state was never issued", func(t *testing.T) {
		preview := newInst(t, with(at("http://preview.example.com"), proxy(Options{})), instOpts{disableTestUser: true})
		if _, err := preview.ctx().InternalAdapter.CreateUser(context.Background(), adapter.Record{"id": "existing-user-id", "email": "user@email.com",
			"name": "Existing User", "emailVerified": true}, betterauth.UserInfoSource{Method: "test"}); err != nil {
			t.Fatal(err)
		}
		enc := encryptPayload(t, bacrypto.PlainSecret(preview.ctx().Secret), map[string]any{
			"userInfo": map[string]any{"id": "google-user-id", "email": "user@email.com", "name": "New Name", "emailVerified": true},
			"account":  map[string]any{"providerId": "google", "accountId": "google-user-id", "accessToken": "test123"},
			"state":    "test-state", "callbackURL": "/dashboard", "timestamp": float64(time.Now().UnixMilli())})
		res := preview.client().get("/oauth-proxy-callback?callbackURL=/dashboard&profile=" + url.QueryEscape(enc))
		mustEqual(t, res.Status, 302)
		mustContain(t, res.location(), "error=state_mismatch")
		users := preview.listUsers()
		if len(users) != 1 || users[0].Email != "user@email.com" {
			t.Fatalf("users %+v", users)
		}
		mustEqual(t, len(preview.accounts(users[0].ID)), 0)
	})
}

// ---- database mode state cleanup ----

func TestDatabaseModeStateCleanup(t *testing.T) {
	t.Run("should not fail when state cookie is missing during proxy callback cleanup", func(t *testing.T) {
		googleIdP(t)
		in := newInst(t, with(at("http://localhost:3000"), proxy(Options{CurrentURL: "http://preview.example.com", ProductionURL: "http://localhost:3000"})), instOpts{disableTestUser: true})
		state := startGoogle(t, in.client())
		prof, cb := profileFrom(t, in.client().get("/callback/google?code=test&state="+url.QueryEscape(state)).location())
		if cb == "" {
			t.Fatal("expected callbackURL")
		}
		loc := in.client().get(proxyCallbackPath(t, cb, prof)).location()
		mustNotContain(t, loc, "error=")
		mustContain(t, loc, "/dashboard")
		users := in.listUsers()
		if len(users) != 1 || users[0].Email != "user@email.com" {
			t.Fatalf("users %+v", users)
		}
	})
	t.Run("should reject the callback when the OAuth state is not found in the database", func(t *testing.T) {
		in := newInst(t, proxy(Options{CurrentURL: "http://preview.example.com"}), instOpts{disableTestUser: true})
		enc := encryptPayload(t, bacrypto.PlainSecret(in.ctx().Secret), map[string]any{
			"userInfo": map[string]any{"id": "123", "email": "test@email.com", "name": "Test User", "emailVerified": true},
			"account":  map[string]any{"providerId": "google", "accountId": "123", "accessToken": "test"},
			"state":    "non-existent-state-id", "callbackURL": "/dashboard", "timestamp": float64(time.Now().UnixMilli())})
		mustContain(t, in.client().get("/oauth-proxy-callback?callbackURL=/dashboard&profile="+url.QueryEscape(enc)).location(), "error=state_mismatch")
		mustEqual(t, len(in.listUsers()), 0)
	})
}

// ---- secret configuration ----

func TestSecretConfiguration(t *testing.T) {
	t.Run("should fail when preview and production have different secrets (no shared secret)", func(t *testing.T) {
		googleIdP(t)
		preview := newInst(t, with(at("http://preview.example.com"), secret("preview-secret-key-that-is-different"), proxy(Options{ProductionURL: "http://localhost:3000"})), instOpts{disableTestUser: true})
		production := newInst(t, with(at("http://localhost:3000"), secret("production-secret-key-that-is-different"), proxy(Options{})), instOpts{disableTestUser: true})
		state := startGoogle(t, preview.client())
		loc := production.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
		if !strings.Contains(loc, "error=") || !(strings.Contains(loc, "state") || strings.Contains(loc, "please_restart")) {
			t.Fatalf("location %q", loc)
		}
	})
	t.Run("should work correctly when a shared secret is configured", func(t *testing.T) {
		googleIdP(t)
		shared := "shared-oauth-proxy-secret-for-all-envs"
		preview := newInst(t, with(at("http://preview.example.com"), secret("preview-main-secret"), proxy(Options{ProductionURL: "http://localhost:3000", Secret: shared})), instOpts{disableTestUser: true})
		production := newInst(t, with(at("http://localhost:3000"), secret("production-main-secret"), proxy(Options{Secret: shared})), instOpts{disableTestUser: true})
		state := startGoogle(t, preview.client())
		loc := production.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
		mustContain(t, loc, "preview.example.com")
		mustContain(t, loc, "/callback/google/oauth-proxy")
		prof, cb := profileFrom(t, loc)
		fin := preview.client().get(proxyCallbackPath(t, cb, prof)).location()
		mustNotContain(t, fin, "error=")
		mustContain(t, fin, "/dashboard")
		users := preview.listUsers()
		if len(users) != 1 || users[0].Email != "user@email.com" {
			t.Fatalf("users %+v", users)
		}
		mustContain(t, preview.client().get(proxyCallbackPath(t, cb, prof)).location(), "error=state_mismatch")
	})
}

// ---- cookie state strategy ----

func TestCookieStateStrategyShouldValidateTheStateCookieDuringProxyCallback(t *testing.T) {
	googleIdP(t)
	ps := "shared-oauth-proxy-secret-for-stateless"
	preview := newInst(t, with(at("http://preview.example.com"), noDB, secret("preview-main-secret-for-stateless"), proxy(Options{ProductionURL: "http://localhost:3000", Secret: ps})), instOpts{disableTestUser: true})
	production := newInst(t, with(at("http://localhost:3000"), noDB, secret("production-main-secret-for-stateless"), proxy(Options{Secret: ps})), instOpts{disableTestUser: true})
	pc := preview.client()
	state := startGoogle(t, pc)
	loc := production.client().get("/callback/google?code=test&state=" + url.QueryEscape(state)).location()
	mustContain(t, loc, "/callback/google/oauth-proxy")
	prof, cb := profileFrom(t, loc)
	mustContain(t, preview.client().get(proxyCallbackPath(t, cb, prof)).location(), "error=state_mismatch")
	mustEqual(t, len(preview.listUsers()), 0)
	fin := pc.get(proxyCallbackPath(t, cb, prof)).location()
	mustNotContain(t, fin, "error=")
	mustContain(t, fin, "/dashboard")
	users := preview.listUsers()
	if len(users) != 1 || users[0].Email != "user@email.com" {
		t.Fatalf("users %+v", users)
	}
}

func TestShouldReadCodeFromPOSTBodyForFormPostResponseMode(t *testing.T) {
	googleIdP(t)
	in := newInst(t, with(noDB, proxy(Options{CurrentURL: "http://preview-localhost:3000"})))
	state := startGoogle(t, in.client())
	body := url.Values{"code": {"test"}, "state": {state}}.Encode()
	res := in.client().do("POST", "/callback/google", body, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") })
	loc := res.location()
	mustNotContain(t, loc, "error=no_code")
	mustNotContain(t, loc, "error=invalid")
	mustContain(t, loc, "/callback/google/oauth-proxy")
	mustContain(t, loc, "profile")
}

func TestShouldPreserveAppleUserDataFromAFormPostCallback(t *testing.T) {
	srv := oauth2test.New(t)
	appleIDT := signHS(t, map[string]any{"sub": "apple-user-id", "email": "jane@privaterelay.appleid.com", "email_verified": true,
		"is_private_email": true, "real_user_status": 2})
	srv.JSON("POST appleid.apple.com/auth/token", 200, map[string]any{"access_token": "apple-access-token", "id_token": appleIDT, "token_type": "Bearer", "expires_in": 3600})
	in := newInst(t, with(noDB, func(c *betterauth.Config) {
		c.SocialProviders = []oauth2.Provider{apple.New(apple.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test-apple-client", ClientSecret: "test-apple-secret"}})}
	}, proxy(Options{CurrentURL: "http://preview-localhost:3000"})))
	res, u := in.client().signInSocial(map[string]any{"provider": "apple", "callbackURL": "/dashboard"})
	if u == "" {
		t.Fatalf("sign-in %d %s", res.Status, res.Body)
	}
	state := queryParam(t, u, "state")
	body := url.Values{"code": {"apple-test-code"}, "state": {state}, "id_token": {appleIDT},
		"user": {`{"name":{"firstName":"Jane","lastName":"Doe"},"email":"jane@privaterelay.appleid.com"}`}}.Encode()
	loc := in.client().do("POST", "/callback/apple", body, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }).location()
	prof := queryParam(t, loc, "profile")
	if prof == "" {
		t.Fatalf("location %q", loc)
	}
	p := decryptWith(t, bacrypto.PlainSecret(in.ctx().Secret), bacrypto.PurposeOAuthProxyProfile, prof)
	mustEqual(t, p["userInfo"].(map[string]any)["name"], any("Jane Doe"))
}

// ---- oauth-proxy current URL trust ----

func TestOAuthProxyCurrentURLTrust(t *testing.T) {
	run := func(t *testing.T, mutate func(c *betterauth.Config), host string) string {
		googleIdP(t)
		in := newInst(t, with(at("https://myapp.com"), proxy(Options{ProductionURL: "https://login.myapp.com"}), mutate))
		res := in.client().do("POST", host+"/api/auth/sign-in/social", map[string]any{"provider": "google", "callbackURL": "/dashboard"})
		u, _ := res.JSON(t)["url"].(string)
		state := queryParam(t, u, "state")
		return in.client().get("https://login.myapp.com/api/auth/callback/google?code=test&state=" + url.QueryEscape(state)).location()
	}
	t.Run("does not use an untrusted request origin as the proxy callback receiver", func(t *testing.T) {
		loc := run(t, nop, "https://untrusted.example")
		if loc == "" {
			t.Fatal("expected location")
		}
		mustNotContain(t, loc, "untrusted.example")
		mustContain(t, loc, "https://myapp.com/api/auth/callback/google/oauth-proxy")
	})
	t.Run("uses an explicitly trusted request origin as the proxy callback receiver", func(t *testing.T) {
		loc := run(t, func(c *betterauth.Config) { c.TrustedOrigins = []string{"https://preview.myapp.com"} }, "https://preview.myapp.com")
		mustContain(t, loc, "https://preview.myapp.com/api/auth/callback/google/oauth-proxy")
	})
	t.Run("falls back to the base URL when the platform vendor value is not a URL", func(t *testing.T) {
		t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "my-lambda-function")
		loc := run(t, nop, "https://untrusted.example")
		mustContain(t, loc, "https://myapp.com/api/auth/callback/google/oauth-proxy")
	})
}

var _ = errors.New

func writeJSONResp(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := jsonx.Marshal(body)
	_, _ = w.Write(b)
}
