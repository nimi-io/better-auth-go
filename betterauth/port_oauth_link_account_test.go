package betterauth

// Port of better-auth/src/oauth2/link-account.test.ts.
//
// Upstream mocks the provider HTTP APIs with msw; here oauth2test routes the real google /
// github / discord providers' outbound requests to in-test handlers. The google token
// endpoint answers with an HS256 id_token signed with DEFAULT_SECRET exactly like upstream
// (Google's getUserInfo only decodes it). Each upstream describe's shared getTestInstance
// becomes a per-test instance (poEnv) with the same options; tests that relied on rows
// left by a previous test in the same describe do not exist in this file.
//
// Spies on ctx.internalAdapter / ctx.adapter are expressed with poAdapter, a wrapper around
// the configured database adapter (InternalAdapter is a concrete type in Go).

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/discord"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// poDefaultSecret is DEFAULT_SECRET (utils/constants.ts).
const poDefaultSecret = "better-auth-secret-12345678901234567890"

// poSignJWT mirrors signJWT(payload, DEFAULT_SECRET) (HS256).
func poSignJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": "HS256"})
	p, _ := json.Marshal(claims)
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	mac := hmac.New(sha256.New, []byte(poDefaultSecret))
	mac.Write([]byte(signing))
	return signing + "." + enc.EncodeToString(mac.Sum(nil))
}

// poGoogleProfile is the full GoogleProfile used by most upstream token handlers.
func poGoogleProfile(email string, verified bool, sub, name, picture string) map[string]any {
	return map[string]any{
		"email": email, "email_verified": verified, "name": name, "picture": picture,
		"exp": 1234567890, "sub": sub, "iat": 1234567890, "aud": "test", "azp": "test", "nbf": 1234567890,
		"iss": "test", "locale": "en", "jti": "test", "given_name": "Test", "family_name": "User",
	}
}

// poMockGoogleToken registers the https://oauth2.googleapis.com/token handler.
func poMockGoogleToken(m *oauth2test.Server, profile map[string]any, body map[string]any) {
	out := map[string]any{"id_token": poSignJWT(profile)}
	for k, v := range body {
		out[k] = v
	}
	m.JSON("POST oauth2.googleapis.com/token", 200, out)
}

func poGoogleTokens() map[string]any {
	return map[string]any{"access_token": "test_access_token", "refresh_token": "test_refresh_token"}
}

func poGoogle(mutate func(o *google.Options)) oauth2.Provider {
	o := google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}
	if mutate != nil {
		mutate(&o)
	}
	return google.New(o)
}

func poVerifyTrue(context.Context, string, string) (bool, error) { return true, nil }

// ---- adapter spy ----

type poUpdateCall struct {
	Model  string
	Update adapter.Record
}

type poAdapter struct {
	adapter.Adapter
	mu       sync.Mutex
	updates  []poUpdateCall
	onCreate func(ctx context.Context, in adapter.CreateInput) (adapter.Record, error, bool)
	onUpdate func(ctx context.Context, model string, rec adapter.Record, err error) (adapter.Record, error)
}

func (p *poAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if p.onCreate != nil {
		if r, err, handled := p.onCreate(ctx, in); handled {
			return r, err
		}
	}
	return p.Adapter.Create(ctx, in)
}

func (p *poAdapter) Update(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (adapter.Record, error) {
	p.mu.Lock()
	cp := adapter.Record{}
	for k, v := range update {
		cp[k] = v
	}
	p.updates = append(p.updates, poUpdateCall{Model: model, Update: cp})
	hook := p.onUpdate
	p.mu.Unlock()
	rec, err := p.Adapter.Update(ctx, model, where, update)
	if hook != nil {
		return hook(ctx, model, rec, err)
	}
	return rec, err
}

func (p *poAdapter) userUpdates() []adapter.Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []adapter.Record
	for _, u := range p.updates {
		if u.Model == "user" {
			out = append(out, u.Update)
		}
	}
	return out
}

func poWrapAdapter(dst **poAdapter) func(c *Config) {
	return func(c *Config) {
		inner := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := inner(o)
			if err != nil {
				return nil, err
			}
			w := &poAdapter{Adapter: a}
			*dst = w
			return w, nil
		}
	}
}

// ---- logger spy ----

type poLogEntry struct {
	Level string
	Msg   string
	Args  []any
}

type poLogger struct {
	mu      sync.Mutex
	entries []poLogEntry
}

func (l *poLogger) add(level, msg string, args []any) {
	l.mu.Lock()
	l.entries = append(l.entries, poLogEntry{level, msg, args})
	l.mu.Unlock()
}
func (l *poLogger) Debug(msg string, args ...any) { l.add("debug", msg, args) }
func (l *poLogger) Info(msg string, args ...any)  { l.add("info", msg, args) }
func (l *poLogger) Warn(msg string, args ...any)  { l.add("warn", msg, args) }
func (l *poLogger) Error(msg string, args ...any) { l.add("error", msg, args) }

// ---- instance helpers (getTestInstance) ----

type poInstanceOpts struct{ disableTestUser bool }

// poEnv mirrors getTestInstance(options): the given social providers replace the
// defaults, email+password enabled, rate limit disabled, fast test hasher and the
// test@test.com user unless disabled.
func poEnv(t *testing.T, providers []oauth2.Provider, mutates []func(c *Config), opts ...poInstanceOpts) *testEnv {
	t.Helper()
	var o poInstanceOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	env := newTestEnv(t, func(c *Config) {
		c.SocialProviders = providers
		c.RateLimit = &RateLimitConfig{Enabled: Bool(false)}
		for _, m := range mutates {
			if m != nil {
				m(c)
			}
		}
		if c.EmailAndPassword != nil && c.EmailAndPassword.Password == nil {
			c.EmailAndPassword.Password = paTestPassword()
		}
	})
	if !o.disableTestUser {
		env.client().signUp(pacTestEmail, pacTestPassword, pacTestName)
	}
	return env
}

func poAccountLinking(al *AccountLinkingConfig) func(c *Config) {
	return func(c *Config) {
		if c.Account == nil {
			c.Account = &AccountConfig{}
		}
		c.Account.AccountLinking = al
	}
}

func poUserFields(fields ...db.Field) func(c *Config) {
	return func(c *Config) {
		if c.User == nil {
			c.User = &UserConfig{}
		}
		c.User.AdditionalFields = append(c.User.AdditionalFields, fields...)
	}
}

func poCookieCache() func(c *Config) {
	return func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true, MaxAge: 300 * time.Second}}
	}
}

// poSignUp signs a user up on c and returns its id.
func poSignUp(t *testing.T, c *testClient, email, password, name string) string {
	t.Helper()
	res := c.signUp(email, password, name)
	u, _ := res.JSON(t)["user"].(map[string]any)
	id := pacStr(u["id"])
	if id == "" {
		t.Fatalf("sign-up returned no user id: %s", res.Body)
	}
	return id
}

// poSocialState runs client.signIn.social and returns the state of the authorization URL.
func poSocialState(t *testing.T, c *testClient, body map[string]any) string {
	t.Helper()
	state, _ := startSocial(t, c, body)
	return state
}

// poCallback runs client.$fetch("/callback/<provider>", {query: {state, code}}).
func poCallback(t *testing.T, c *testClient, provider, state string) *testResponse {
	t.Helper()
	return c.get("/callback/" + provider + "?state=" + url.QueryEscape(state) + "&code=test_code")
}

// poSignInSocial = signIn.social + callback on a fresh client; returns the client and
// the callback response.
func poSignInSocial(t *testing.T, env *testEnv, provider string, body map[string]any) (*testClient, *testResponse) {
	t.Helper()
	c := env.client()
	if body == nil {
		body = map[string]any{}
	}
	body["provider"] = provider
	if _, ok := body["callbackURL"]; !ok {
		body["callbackURL"] = "/"
	}
	state := poSocialState(t, c, body)
	return c, poCallback(t, c, provider, state)
}

// poLinkSocial = client.linkSocial({provider, callbackURL}) + callback on the signed-in c.
func poLinkSocial(t *testing.T, c *testClient, provider, callbackURL string) *testResponse {
	t.Helper()
	res := c.post("/link-social", map[string]any{"provider": provider, "callbackURL": callbackURL})
	if res.Status != 200 {
		t.Fatalf("linkSocial: expected no error, got %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	u, err := url.Parse(pacStr(m["url"]))
	if err != nil || m["redirect"] != true {
		t.Fatalf("linkSocial: unexpected response %s", res.Body)
	}
	if provider == "google" && !strings.Contains(m["url"].(string), "google.com") {
		t.Fatalf("linkSocial: url should contain google.com: %s", m["url"])
	}
	return poCallback(t, c, provider, u.Query().Get("state"))
}

func poLocation(res *testResponse) string { return res.Header.Get("Location") }

func poFindUser(t *testing.T, env *testEnv, field string, value any) adapter.Record {
	t.Helper()
	rec, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user",
		Where: []adapter.Where{{Field: field, Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func poAccountsOf(t *testing.T, env *testEnv, userID any) []adapter.Record {
	t.Helper()
	rows, err := env.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "account",
		Where: []adapter.Where{{Field: "userId", Value: userID}}})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func poFindProviderAccount(rows []adapter.Record, providerID string) adapter.Record {
	for _, r := range rows {
		if r["providerId"] == providerID {
			return r
		}
	}
	return nil
}

func poCreateUser(t *testing.T, env *testEnv, data adapter.Record) adapter.Record {
	t.Helper()
	in := adapter.CreateInput{Model: "user", Data: data}
	if _, ok := data["id"]; ok {
		in.ForceAllowID = true
	}
	rec, err := env.auth.Context().Adapter.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("adapter.create(user): %v", err)
	}
	return rec
}

func poSetEmailVerified(t *testing.T, env *testEnv, userID string) {
	t.Helper()
	if _, err := env.auth.Context().Adapter.Update(context.Background(), "user",
		[]adapter.Where{{Field: "id", Value: userID}}, adapter.Record{"emailVerified": true}); err != nil {
		t.Fatal(err)
	}
}

func poExpectRedirect(t *testing.T, res *testResponse) string {
	t.Helper()
	if res.Status != 302 {
		t.Fatalf("expected 302, got %d %s", res.Status, res.Body)
	}
	return poLocation(res)
}

// ======================================================================
// describe("oauth2 - email verification on link")
// ======================================================================

func poEmailVerificationOnLinkEnv(t *testing.T) *testEnv {
	return poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){
		func(c *Config) {
			c.EmailAndPassword = &EmailAndPasswordConfig{Enabled: true, RequireEmailVerification: true}
		},
		poAccountLinking(&AccountLinkingConfig{Enabled: Bool(true), TrustedProviders: []string{"google"}}),
	})
}

// poLinkGoogleAccount mirrors linkGoogleAccount(): signIn.social + callback with the
// mockEmail / mockEmailVerified profile.
func poLinkGoogleAccount(t *testing.T, env *testEnv, m *oauth2test.Server, email string, verified bool) string {
	t.Helper()
	poMockGoogleToken(m, poGoogleProfile(email, verified, "google_oauth_sub_1234567890", "Test User", "https://example.com/photo.jpg"), poGoogleTokens())
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	return poExpectRedirect(t, res)
}

// @see https://github.com/better-auth/better-auth/security/advisories/GHSA-g38m-r43w-p2q7
func TestPortOAuthLinkRejectImplicitLinkUnverifiedLocal(t *testing.T) {
	m := oauth2test.New(t)
	env := poEmailVerificationOnLinkEnv(t)
	const testEmail = "unverified-local@example.com"
	userID := poSignUp(t, env.client(), testEmail, "password123", "Test User")
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != false {
		t.Fatalf("initial emailVerified = %v", u["emailVerified"])
	}
	loc := poLinkGoogleAccount(t, env, m, testEmail, true)
	if !strings.Contains(loc, "error=account_not_linked") {
		t.Fatalf("redirect %q should contain error=account_not_linked", loc)
	}
	if poFindProviderAccount(poAccountsOf(t, env, userID), "google") != nil {
		t.Fatal("google account must not be linked")
	}
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != false {
		t.Fatalf("emailVerified = %v, want false", u["emailVerified"])
	}
}

func TestPortOAuthLinkPreserveEmailVerifiedWhenLocalVerified(t *testing.T) {
	m := oauth2test.New(t)
	env := poEmailVerificationOnLinkEnv(t)
	const testEmail = "verified-local@example.com"
	userID := poSignUp(t, env.client(), testEmail, "password123", "Test User")
	poSetEmailVerified(t, env, userID)
	poLinkGoogleAccount(t, env, m, testEmail, true)
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != true {
		t.Fatalf("emailVerified = %v, want true", u["emailVerified"])
	}
	if poFindProviderAccount(poAccountsOf(t, env, userID), "google") == nil {
		t.Fatal("google account should be linked")
	}
}

func TestPortOAuthLinkNotUpdateEmailVerifiedWhenProviderUnverified(t *testing.T) {
	m := oauth2test.New(t)
	env := poEmailVerificationOnLinkEnv(t)
	const testEmail = "unverified@example.com"
	userID := poSignUp(t, env.client(), testEmail, "password123", "Unverified User")
	poLinkGoogleAccount(t, env, m, testEmail, false)
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != false {
		t.Fatalf("emailVerified = %v, want false", u["emailVerified"])
	}
}

func TestPortOAuthLinkNotUpdateEmailVerifiedWhenEmailsDiffer(t *testing.T) {
	m := oauth2test.New(t)
	env := poEmailVerificationOnLinkEnv(t)
	userID := poSignUp(t, env.client(), "user@example.com", "password123", "Test User")
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != false {
		t.Fatalf("initial emailVerified = %v", u["emailVerified"])
	}
	poLinkGoogleAccount(t, env, m, "different@gmail.com", true)
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != false {
		t.Fatalf("emailVerified = %v, want false", u["emailVerified"])
	}
}

func TestPortOAuthLinkAlreadyVerifiedEmails(t *testing.T) {
	m := oauth2test.New(t)
	env := poEmailVerificationOnLinkEnv(t)
	const testEmail = "already-verified@example.com"
	userID := poSignUp(t, env.client(), testEmail, "password123", "Verified User")
	poSetEmailVerified(t, env, userID)
	poLinkGoogleAccount(t, env, m, testEmail, true)
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != true {
		t.Fatalf("emailVerified = %v, want true", u["emailVerified"])
	}
}

// ======================================================================
// describe("oauth2 - account linking with case insensitive email")
// @see https://github.com/better-auth/better-auth/issues/7806
// ======================================================================

func poCaseInsensitiveEnv(t *testing.T) *testEnv {
	return poEnv(t, []oauth2.Provider{poGoogle(func(o *google.Options) { o.VerifyIDToken = poVerifyTrue })},
		[]func(c *Config){poAccountLinking(&AccountLinkingConfig{Enabled: Bool(true), TrustedProviders: []string{"google"}})})
}

func TestPortOAuthLinkCaseInsensitiveEmailCallback(t *testing.T) {
	m := oauth2test.New(t)
	env := poCaseInsensitiveEnv(t)
	c := env.client()
	userID := poSignUp(t, c, "casing-test@example.com", "password123", "Test User")
	poMockGoogleToken(m, poGoogleProfile("Casing-Test@Example.com", true, "google_oauth_sub_casing", "Test User", "https://example.com/photo.jpg"), poGoogleTokens())
	loc := poLocation(poLinkSocial(t, c, "google", "/settings"))
	if strings.Contains(loc, "error") || !strings.Contains(loc, "/settings") {
		t.Fatalf("redirect = %q", loc)
	}
	if poFindProviderAccount(poAccountsOf(t, env, userID), "google") == nil {
		t.Fatal("google account should be linked")
	}
}

func TestPortOAuthLinkCaseInsensitiveEmailIDToken(t *testing.T) {
	env := poCaseInsensitiveEnv(t)
	c := env.client()
	userID := poSignUp(t, c, "casing-test2@example.com", "password123", "Test User")
	idToken := poSignJWT(poGoogleProfile("Casing-Test2@Example.com", true, "google_oauth_sub_casing_id_token", "Test User", "https://example.com/photo.jpg"))
	res := c.post("/link-social", map[string]any{"provider": "google", "callbackURL": "/settings", "idToken": map[string]any{"token": idToken}})
	if res.Status != 200 || len(res.Body) == 0 {
		t.Fatalf("linkSocial: %d %s", res.Status, res.Body)
	}
	if poFindProviderAccount(poAccountsOf(t, env, userID), "google") == nil {
		t.Fatal("google account should be linked")
	}
}

// ======================================================================
// describe("oauth2 - account linking without trustedProviders")
// ======================================================================

func poUntrustedEnv(t *testing.T) *testEnv {
	return poEnv(t, []oauth2.Provider{poGoogle(nil)},
		[]func(c *Config){poAccountLinking(&AccountLinkingConfig{Enabled: Bool(true), TrustedProviders: []string{}})})
}

func poMinimalGoogleProfile(email string, verified bool, sub, name string) map[string]any {
	return map[string]any{"email": email, "email_verified": verified, "name": name, "sub": sub,
		"iat": 1234567890, "exp": 1234567890, "aud": "test", "iss": "test"}
}

func TestPortOAuthLinkDenyUntrustedUnverified(t *testing.T) {
	m := oauth2test.New(t)
	env := poUntrustedEnv(t)
	const testEmail = "untrusted@example.com"
	poCreateUser(t, env, adapter.Record{"id": "existing-user-id", "email": testEmail, "name": "Existing User",
		"emailVerified": true, "createdAt": time.Now(), "updatedAt": time.Now()})
	poMockGoogleToken(m, poMinimalGoogleProfile(testEmail, false, "google_untrusted_123", "Test User"), poGoogleTokens())
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	if loc := poLocation(res); !strings.Contains(loc, "error=account_not_linked") {
		t.Fatalf("redirect %q should contain error=account_not_linked", loc)
	}
	if poFindProviderAccount(poAccountsOf(t, env, "existing-user-id"), "google") != nil {
		t.Fatal("google account must not be linked")
	}
}

func TestPortOAuthLinkAllowUntrustedWhenVerified(t *testing.T) {
	m := oauth2test.New(t)
	env := poUntrustedEnv(t)
	const testEmail = "verified-provider@example.com"
	poCreateUser(t, env, adapter.Record{"id": "existing-user-verified", "email": testEmail, "name": "Existing User",
		"emailVerified": true, "createdAt": time.Now(), "updatedAt": time.Now()})
	poMockGoogleToken(m, poMinimalGoogleProfile(testEmail, true, "google_verified_456", "Test User"), poGoogleTokens())
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/dashboard"})
	if loc := poLocation(res); strings.Contains(loc, "error=account_not_linked") {
		t.Fatalf("redirect %q must not contain error=account_not_linked", loc)
	}
	u := poFindUser(t, env, "email", testEmail)
	if u == nil {
		t.Fatal("user should exist")
	}
	if poFindProviderAccount(poAccountsOf(t, env, u["id"]), "google") == nil {
		t.Fatal("google account should be linked")
	}
}

// ======================================================================
// describe("oauth2 - disableImplicitLinking")
// ======================================================================

func poDisableImplicitEnv(t *testing.T) *testEnv {
	return poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){poAccountLinking(&AccountLinkingConfig{
		Enabled: Bool(true), DisableImplicitLinking: true, TrustedProviders: []string{"google"}})})
}

func TestPortOAuthLinkDisableImplicitBlocksTrusted(t *testing.T) {
	m := oauth2test.New(t)
	env := poDisableImplicitEnv(t)
	const testEmail = "implicit-block@example.com"
	poCreateUser(t, env, adapter.Record{"id": "implicit-block-user", "email": testEmail, "name": "Existing User",
		"emailVerified": true, "createdAt": time.Now(), "updatedAt": time.Now()})
	poMockGoogleToken(m, poMinimalGoogleProfile(testEmail, true, "google_implicit_block_123", "Test User"), poGoogleTokens())
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	if loc := poLocation(res); !strings.Contains(loc, "error=account_not_linked") {
		t.Fatalf("redirect %q should contain error=account_not_linked", loc)
	}
	if poFindProviderAccount(poAccountsOf(t, env, "implicit-block-user"), "google") != nil {
		t.Fatal("google account must not be linked")
	}
}

func TestPortOAuthLinkDisableImplicitAllowsNewUser(t *testing.T) {
	m := oauth2test.New(t)
	env := poDisableImplicitEnv(t)
	const newUserEmail = "new-user-implicit@example.com"
	poMockGoogleToken(m, poMinimalGoogleProfile(newUserEmail, true, "google_new_user_implicit_456", "New User"), poGoogleTokens())
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/dashboard"})
	if loc := poLocation(res); strings.Contains(loc, "error") {
		t.Fatalf("redirect %q must not contain error", loc)
	}
	if poFindUser(t, env, "email", newUserEmail) == nil {
		t.Fatal("user should be created")
	}
}

func TestPortOAuthLinkDisableImplicitAllowsExplicitLinkSocial(t *testing.T) {
	m := oauth2test.New(t)
	env := poDisableImplicitEnv(t)
	c := env.client()
	const testEmail = "explicit-link@example.com"
	userID := poSignUp(t, c, testEmail, "password123", "Test User")
	poMockGoogleToken(m, poMinimalGoogleProfile(testEmail, true, "google_explicit_link_789", "Test User"), poGoogleTokens())
	loc := poLocation(poLinkSocial(t, c, "google", "/settings"))
	if strings.Contains(loc, "error") || !strings.Contains(loc, "/settings") {
		t.Fatalf("redirect = %q", loc)
	}
	if poFindProviderAccount(poAccountsOf(t, env, userID), "google") == nil {
		t.Fatal("google account should be linked")
	}
}

// ======================================================================
// describe("oauth2 - updateUserInfoOnLink via callback")
// @see https://github.com/better-auth/better-auth/issues/8742
// ======================================================================

func TestPortOAuthLinkUpdateUserInfoOnLinkCallback(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){poAccountLinking(&AccountLinkingConfig{
		Enabled: Bool(true), TrustedProviders: []string{"google"}, UpdateUserInfoOnLink: true})})
	c := env.client()
	const testEmail = "update-on-link@example.com"
	userID := poSignUp(t, c, testEmail, "password123", "Original Name")
	u := poFindUser(t, env, "id", userID)
	if u["name"] != "Original Name" || u["image"] != nil {
		t.Fatalf("initial user %v", u)
	}
	p := poGoogleProfile(testEmail, true, "google_update_on_link_123", "Updated Name From Google", "https://example.com/avatar.jpg")
	p["given_name"], p["family_name"] = "Updated", "Name From Google"
	poMockGoogleToken(m, p, poGoogleTokens())
	poExpectRedirect(t, poLinkSocial(t, c, "google", "/settings"))
	u = poFindUser(t, env, "id", userID)
	if u["name"] != "Updated Name From Google" || u["image"] != "https://example.com/avatar.jpg" {
		t.Fatalf("user not updated: %v", u)
	}
}

func TestPortOAuthLinkNoUpdateUserInfoWhenUnset(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){poAccountLinking(&AccountLinkingConfig{
		Enabled: Bool(true), TrustedProviders: []string{"google"}})})
	c := env.client()
	const testEmail = "no-update-on-link@example.com"
	userID := poSignUp(t, c, testEmail, "password123", "Should Not Change")
	poMockGoogleToken(m, poGoogleProfile(testEmail, true, "google_no_update_456", "Google Name", "https://example.com/photo.jpg"), poGoogleTokens())
	poExpectRedirect(t, poLinkSocial(t, c, "google", "/settings"))
	u := poFindUser(t, env, "id", userID)
	if u["name"] != "Should Not Change" || u["image"] != nil {
		t.Fatalf("user must not be updated: %v", u)
	}
}

// ======================================================================
// describe("oauth2 - updateUserInfoOnLink on implicit sign-in link")
// @see https://github.com/better-auth/better-auth/issues/8742
// ======================================================================

func poLowerTransform(v any) (any, error) {
	if s, ok := v.(string); ok {
		return strings.ToLower(s), nil
	}
	return v, nil
}

func poMinLen3(v any) (any, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("Invalid input: expected string")
	}
	if len(s) < 3 {
		return nil, errors.New("Too small: expected string to have >=3 characters")
	}
	return s, nil
}

func poImplicitLinkEnv(t *testing.T, spy **poAdapter) *testEnv {
	t.Helper()
	g := poGoogle(func(o *google.Options) {
		o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
			return map[string]any{"googleSub": p["sub"], "profileCode": p["sub"], "validatedProfileCode": p["sub"],
				"serverManagedField": "elevated"}, nil
		}
	})
	muts := []func(c *Config){
		poUserFields(
			db.Field{Name: "googleSub", Type: db.TypeString},
			db.Field{Name: "profileCode", Type: db.TypeString, TransformInput: poLowerTransform},
			db.Field{Name: "validatedProfileCode", Type: db.TypeString, Validator: poMinLen3},
			db.Field{Name: "serverManagedField", Type: db.TypeString, Input: Bool(false)},
		),
		poAccountLinking(&AccountLinkingConfig{Enabled: Bool(true), TrustedProviders: []string{"google"}, UpdateUserInfoOnLink: true}),
		poCookieCache(),
	}
	if spy != nil {
		muts = append(muts, poWrapAdapter(spy))
	}
	return poEnv(t, []oauth2.Provider{g}, muts)
}

// poSignInAndLink mirrors signInAndLink(email, sub); returns the client holding the
// callback cookies.
func poSignInAndLink(t *testing.T, env *testEnv, m *oauth2test.Server, email, sub string) *testClient {
	t.Helper()
	poMockGoogleToken(m, map[string]any{"sub": sub, "email": email, "email_verified": true,
		"name": "Updated Name From Google", "picture": "https://example.com/avatar.jpg"},
		map[string]any{"access_token": "test_token"})
	c, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	poExpectRedirect(t, res)
	return c
}

func TestPortOAuthLinkImplicitReturnsFreshNameAndImage(t *testing.T) {
	m := oauth2test.New(t)
	env := poImplicitLinkEnv(t, nil)
	const testEmail = "implicit-link@example.com"
	poCreateUser(t, env, adapter.Record{"email": testEmail, "name": "Original Name", "emailVerified": true})
	c := poSignInAndLink(t, env, m, testEmail, "google_implicit_name")
	s := c.session()
	if s == nil {
		t.Fatal("expected a session")
	}
	u := s["user"].(map[string]any)
	if u["name"] != "Updated Name From Google" || u["image"] != "https://example.com/avatar.jpg" {
		t.Fatalf("session user %v", u)
	}
}

func TestPortOAuthLinkImplicitSyncsMappedFields(t *testing.T) {
	m := oauth2test.New(t)
	var spy *poAdapter
	env := poImplicitLinkEnv(t, &spy)
	const testEmail = "implicit-link-mapped@example.com"
	poCreateUser(t, env, adapter.Record{"email": testEmail, "name": "Original Name", "emailVerified": true})
	poSignInAndLink(t, env, m, testEmail, "GOOGLE_IMPLICIT_MAPPED")
	found := false
	for _, u := range spy.userUpdates() {
		if u["googleSub"] == "GOOGLE_IMPLICIT_MAPPED" && u["profileCode"] == "google_implicit_mapped" {
			found = true
		}
	}
	if !found {
		t.Fatalf("updateUser must be called with googleSub/profileCode, calls: %v", spy.userUpdates())
	}
	u := poFindUser(t, env, "email", testEmail)
	if u["googleSub"] != "GOOGLE_IMPLICIT_MAPPED" || u["profileCode"] != "google_implicit_mapped" {
		t.Fatalf("user %v", u)
	}
}

func TestPortOAuthLinkImplicitIgnoresInputFalse(t *testing.T) {
	m := oauth2test.New(t)
	env := poImplicitLinkEnv(t, nil)
	const testEmail = "implicit-link-input-false@example.com"
	poCreateUser(t, env, adapter.Record{"email": testEmail, "name": "Original Name", "emailVerified": true})
	poSignInAndLink(t, env, m, testEmail, "google_link_input_false")
	u := poFindUser(t, env, "email", testEmail)
	if u["googleSub"] != "google_link_input_false" {
		t.Fatalf("googleSub = %v", u["googleSub"])
	}
	if u["serverManagedField"] != nil {
		t.Fatalf("serverManagedField = %v, want null", u["serverManagedField"])
	}
}

func TestPortOAuthLinkImplicitContinuesOnInvalidMappedFields(t *testing.T) {
	m := oauth2test.New(t)
	env := poImplicitLinkEnv(t, nil)
	const testEmail = "implicit-link-invalid-profile@example.com"
	poCreateUser(t, env, adapter.Record{"email": testEmail, "name": "Original Name", "emailVerified": true})
	c := poSignInAndLink(t, env, m, testEmail, "x")
	s := c.session()
	if s == nil {
		t.Fatal("expected a session")
	}
	su := s["user"].(map[string]any)
	if su["email"] != testEmail || su["name"] != "Original Name" {
		t.Fatalf("session user %v", su)
	}
	if poFindProviderAccount(poAccountsOf(t, env, su["id"]), "google") == nil {
		t.Fatal("google account should be linked")
	}
	if u := poFindUser(t, env, "email", testEmail); u["validatedProfileCode"] != nil {
		t.Fatalf("validatedProfileCode = %v, want null", u["validatedProfileCode"])
	}
}

// ======================================================================
// describe("oauth2 - first sign-in provisioning applies user input rules")
// ======================================================================

func TestPortOAuthLinkFirstSignInIgnoresInputFalse(t *testing.T) {
	m := oauth2test.New(t)
	g := poGoogle(func(o *google.Options) {
		o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
			return map[string]any{"googleSub": p["sub"], "profileCode": "PROVIDER-CODE",
				"serverManagedField": "elevated", "serverManagedDefault": "admin"}, nil
		}
	})
	env := poEnv(t, []oauth2.Provider{g}, []func(c *Config){poUserFields(
		db.Field{Name: "googleSub", Type: db.TypeString},
		db.Field{Name: "profileCode", Type: db.TypeString, TransformInput: poLowerTransform},
		db.Field{Name: "serverManagedField", Type: db.TypeString, Input: Bool(false)},
		db.Field{Name: "serverManagedDefault", Type: db.TypeString, DefaultValue: "member", Input: Bool(false)},
	)})
	const testEmail = "implicit-create-input-false@example.com"
	poMockGoogleToken(m, map[string]any{"sub": "google_create_input_false", "email": testEmail, "email_verified": true,
		"name": "Created From Google"}, map[string]any{"access_token": "test_token"})
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	poExpectRedirect(t, res)
	u := poFindUser(t, env, "email", testEmail)
	if u == nil {
		t.Fatal("user should be created")
	}
	if u["googleSub"] != "google_create_input_false" || u["profileCode"] != "provider-code" {
		t.Fatalf("mapped input fields: googleSub=%v profileCode=%v", u["googleSub"], u["profileCode"])
	}
	if u["serverManagedField"] != nil {
		t.Fatalf("serverManagedField = %v, want null", u["serverManagedField"])
	}
	if u["serverManagedDefault"] != "member" {
		t.Fatalf("serverManagedDefault = %v, want member", u["serverManagedDefault"])
	}
}

// ======================================================================
// describe("oauth2 - override user info on sign-in")
// ======================================================================

func poOverrideEnv(t *testing.T, spy **poAdapter) *testEnv {
	t.Helper()
	g := poGoogle(func(o *google.Options) {
		o.OverrideUserInfoOnSignIn = true
		o.MapProfileToUser = func(map[string]any) (map[string]any, error) {
			return map[string]any{"serverManagedField": "elevated"}, nil
		}
	})
	muts := []func(c *Config){
		poUserFields(db.Field{Name: "serverManagedField", Type: db.TypeString, Input: Bool(false)}),
		poAccountLinking(&AccountLinkingConfig{Enabled: Bool(true), TrustedProviders: []string{"google"}}),
		poCookieCache(),
	}
	if spy != nil {
		muts = append(muts, poWrapAdapter(spy))
	}
	return poEnv(t, []oauth2.Provider{g}, muts)
}

func poOverrideSignIn(t *testing.T, env *testEnv, m *oauth2test.Server, email, sub string) *testClient {
	t.Helper()
	poMockGoogleToken(m, map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "Updated Name"},
		map[string]any{"access_token": "test_token"})
	c, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	poExpectRedirect(t, res)
	return c
}

func TestPortOAuthLinkOverrideUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	var spy *poAdapter
	env := poOverrideEnv(t, &spy)
	const testEmail = "override@example.com"
	poCreateUser(t, env, adapter.Record{"email": testEmail, "name": "Initial Name", "emailVerified": true})
	// Simulate DB latency on user updates.
	spy.onUpdate = func(_ context.Context, model string, rec adapter.Record, err error) (adapter.Record, error) {
		if model == "user" {
			time.Sleep(100 * time.Millisecond)
		}
		return rec, err
	}
	c := poOverrideSignIn(t, env, m, testEmail, "google_123")
	s := c.session()
	if s == nil || s["user"].(map[string]any)["name"] != "Updated Name" {
		t.Fatalf("session %v", s)
	}
}

func TestPortOAuthLinkOverridePreservesUserWhenUpdateNull(t *testing.T) {
	m := oauth2test.New(t)
	var spy *poAdapter
	env := poOverrideEnv(t, &spy)
	const testEmail = "override-null@example.com"
	poCreateUser(t, env, adapter.Record{"email": testEmail, "name": "Initial Name", "emailVerified": true})
	spy.onUpdate = func(_ context.Context, model string, rec adapter.Record, err error) (adapter.Record, error) {
		if model == "user" {
			return nil, err
		}
		return rec, err
	}
	c := poOverrideSignIn(t, env, m, testEmail, "google_null_update")
	s := c.session()
	if s == nil || s["user"].(map[string]any)["email"] != testEmail {
		t.Fatalf("session %v", s)
	}
}

func TestPortOAuthLinkOverrideIgnoresInputFalse(t *testing.T) {
	m := oauth2test.New(t)
	env := poOverrideEnv(t, nil)
	const testEmail = "override-input-false@example.com"
	poCreateUser(t, env, adapter.Record{"email": testEmail, "name": "Initial Name", "emailVerified": true})
	poOverrideSignIn(t, env, m, testEmail, "google_override_input_false")
	u := poFindUser(t, env, "email", testEmail)
	if u["name"] != "Updated Name" {
		t.Fatalf("name = %v", u["name"])
	}
	if u["serverManagedField"] != nil {
		t.Fatalf("serverManagedField = %v, want null", u["serverManagedField"])
	}
}

// ======================================================================
// describe("oauth2 - sign-up account creation rollback")
// ======================================================================

func TestPortOAuthLinkSignUpRollback(t *testing.T) {
	m := oauth2test.New(t)
	var spy *poAdapter
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){
		func(c *Config) {
			c.EmailAndPassword = nil
			c.Account = &AccountConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{
				{Name: "requiredAccountField", Type: db.TypeString, Required: db.True}}}}
		},
		poWrapAdapter(&spy),
	}, poInstanceOpts{disableTestUser: true})
	// The upstream sqlite database rejects the account row through its NOT NULL constraint;
	// the in-memory adapter has no constraints, so the wrapper enforces it.
	spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
		if in.Model == "account" && in.Data["requiredAccountField"] == nil {
			return nil, errors.New("NOT NULL constraint failed: account.requiredAccountField"), true
		}
		return nil, nil, false
	}
	const testEmail = "oauth-rollback@example.com"
	poMockGoogleToken(m, map[string]any{"sub": "google_rollback", "email": testEmail, "email_verified": true,
		"name": "Rollback User"}, map[string]any{"access_token": "test_token"})
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	if loc := poExpectRedirect(t, res); !strings.Contains(loc, "error=unable_to_create_user") {
		t.Fatalf("redirect %q should contain error=unable_to_create_user", loc)
	}
	if u := poFindUser(t, env, "email", testEmail); u != nil {
		t.Fatalf("user row must be rolled back: %v", u)
	}
}

// ======================================================================
// describe("oauth2 - link-social uses issuer-scoped account lookup")
// @see https://github.com/better-auth/better-auth/issues/8906
// ======================================================================

func TestPortOAuthLinkIssuerScopedLookup(t *testing.T) {
	const sharedAccountID = "99999"
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{
		poGoogle(nil),
		github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}}),
	}, []func(c *Config){poAccountLinking(&AccountLinkingConfig{Enabled: Bool(true), TrustedProviders: []string{"google", "github"}})})

	// User A signs up through Google with the shared provider account ID.
	const userAEmail = "user-a@example.com"
	poMockGoogleToken(m, map[string]any{"sub": sharedAccountID, "email": userAEmail, "email_verified": true,
		"name": "Test User", "iat": 0, "exp": 9999999999, "aud": "test", "iss": "https://accounts.google.com"},
		map[string]any{"access_token": "google-access-token"})
	cA, _ := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	sA := cA.session()
	if sA == nil || sA["user"].(map[string]any)["email"] != userAEmail {
		t.Fatalf("session A %v", sA)
	}
	userAID := sA["user"].(map[string]any)["id"]

	// User B: separate email/password account.
	const userBEmail = "user-b@example.com"
	cB := env.client()
	poSignUp(t, cB, userBEmail, "password123", "User B")

	m.JSON("POST github.com/login/oauth/access_token", 200, map[string]any{"access_token": "github-access-token"})
	m.JSON("GET api.github.com/user", 200, map[string]any{"id": 99999, "login": "user-b-gh", "name": "user-b-gh", "email": userBEmail})
	m.JSON("GET api.github.com/user/emails", 200, []map[string]any{{"email": userBEmail, "primary": true, "verified": true}})

	loc := poLocation(poLinkSocial(t, cB, "github", "/settings"))
	if strings.Contains(loc, "error") || !strings.Contains(loc, "/settings") {
		t.Fatalf("redirect = %q", loc)
	}
	sB := cB.session()
	if sB == nil {
		t.Fatal("user B should be signed in")
	}
	userBID := sB["user"].(map[string]any)["id"]
	gh := poFindProviderAccount(poAccountsOf(t, env, userBID), "github")
	if gh == nil || gh["accountId"] != sharedAccountID || gh["userId"] != userBID {
		t.Fatalf("github account %v", gh)
	}
	g := poFindProviderAccount(poAccountsOf(t, env, userAID), "google")
	if g == nil || g["userId"] != userAID {
		t.Fatalf("google account of user A %v", g)
	}
}

// ======================================================================
// describe("oauth2 - ambiguous account identity")
// ======================================================================

func TestPortOAuthLinkAmbiguousAccountIdentity(t *testing.T) {
	env := poEnv(t, []oauth2.Provider{poGoogle(func(o *google.Options) { o.VerifyIDToken = poVerifyTrue })}, nil,
		poInstanceOpts{disableTestUser: true})
	ia := env.auth.Context().InternalAdapter
	for _, name := range []string{"first", "second"} {
		u, err := ia.CreateUser(context.Background(), adapter.Record{"name": name, "email": name + "@ambiguous-account.test"},
			UserInfoSource{Method: "test"})
		if err != nil || u == nil {
			t.Fatalf("createUser: %v", err)
		}
		if _, err := ia.CreateAccount(context.Background(), adapter.Record{"userId": u.ID, "providerId": "google", "accountId": "shared-subject"}); err != nil {
			t.Fatalf("createAccount: %v", err)
		}
	}
	token := poSignJWT(map[string]any{"sub": "shared-subject", "email": "second@ambiguous-account.test", "email_verified": true,
		"name": "Second", "iss": "https://accounts.google.com", "aud": "test"})
	res := env.client().post("/sign-in/social", map[string]any{"provider": "google", "idToken": map[string]any{"token": token}})
	if res.Status != 302 {
		t.Fatalf("expected 302, got %d %s", res.Status, res.Body)
	}
	if loc := poLocation(res); !strings.Contains(loc, "error=internal_server_error") {
		t.Fatalf("redirect %q should contain error=internal_server_error", loc)
	}
	sessions, err := env.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "session"})
	if err != nil || len(sessions) != 0 {
		t.Fatalf("sessions = %v (%v), want none", sessions, err)
	}
}

// ======================================================================
// describe("oauth2 - orphaned account identity")
// ======================================================================

func TestPortOAuthLinkOrphanedAccountIdentity(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poGoogle(func(o *google.Options) { o.VerifyIDToken = poVerifyTrue })},
		[]func(c *Config){poAccountLinking(&AccountLinkingConfig{Enabled: Bool(false)})})
	const email = "orphaned-account@example.com"
	const accountID = "orphaned-google-subject"
	userID := poSignUp(t, env.client(), email, "password123", "Existing User")
	// The in-memory adapter has no foreign keys (upstream disables them for this insert).
	if _, err := env.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "account", Data: adapter.Record{
		"providerId": "google", "accountId": accountID, "userId": "missing-account-owner",
		"createdAt": time.Now(), "updatedAt": time.Now()}}); err != nil {
		t.Fatal(err)
	}
	p := poGoogleProfile(email, true, accountID, "Existing User", "https://example.com/photo.jpg")
	p["iss"], p["given_name"] = "https://accounts.google.com", "Existing"
	poMockGoogleToken(m, p, map[string]any{"access_token": "google-access-token"})
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	if loc := poExpectRedirect(t, res); !strings.Contains(loc, "error=unable_to_link_account") {
		t.Fatalf("redirect %q should contain error=unable_to_link_account", loc)
	}
	if poFindProviderAccount(poAccountsOf(t, env, userID), "google") != nil {
		t.Fatal("google account must not be linked to the email owner")
	}
}

// ======================================================================
// describe("oauth2 - providers without email")
// @see https://github.com/better-auth/better-auth/issues/9124
// ======================================================================

var poDiscordTokenResponse = map[string]any{"access_token": "discord-access-token", "refresh_token": "discord-refresh-token",
	"token_type": "Bearer", "expires_in": 3600, "scope": "identify email"}

func poMockDiscordToken(m *oauth2test.Server, id, username string, email any) {
	m.JSON("POST discord.com/api/oauth2/token", 200, poDiscordTokenResponse)
	m.JSON("GET discord.com/api/users/@me", 200, map[string]any{
		"id": id, "username": username, "discriminator": "0", "global_name": username, "avatar": nil,
		"mfa_enabled": false, "banner": nil, "accent_color": nil, "locale": "en-US", "verified": email != nil,
		"email": email, "flags": 0, "premium_type": 0, "public_flags": 0, "display_name": username,
		"avatar_decoration": nil, "banner_color": nil,
	})
}

func poDiscord(mapper func(map[string]any) (map[string]any, error)) *oauth2.GenericProvider {
	return discord.New(discord.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test", MapProfileToUser: mapper}})
}

// poSubjectSpy wraps a provider to record accountSubject calls (vi.fn(originalAccountSubject)).
type poSubjectSpy struct {
	*oauth2.GenericProvider
	mu    sync.Mutex
	calls []poSubjectCall
}

func (s *poSubjectSpy) AccountSubject(ctx context.Context, tokens *oauth2.Tokens, profile map[string]any) (string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, poSubjectCall{tokens, profile})
	s.mu.Unlock()
	return s.GenericProvider.AccountSubject(ctx, tokens, profile)
}

// @see https://github.com/better-auth/better-auth/issues/9454
func TestPortOAuthLinkDiscordMappedIDIgnored(t *testing.T) {
	m := oauth2test.New(t)
	inner := poDiscord(func(map[string]any) (map[string]any, error) {
		return map[string]any{"id": "mapped-profile-id"}, nil
	})
	spy := &poSubjectSpy{GenericProvider: inner}
	env := poEnv(t, []oauth2.Provider{spy}, nil)
	const accountID = "920138789012345000"
	const email = "mapped-id@example.com"
	poMockDiscordToken(m, accountID, "mapped-id", email)

	info, err := inner.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "discord-access-token"}})
	if err != nil || info == nil {
		t.Fatalf("getUserInfo: %v", err)
	}
	if info.Data["id"] != accountID {
		t.Fatalf("providerInfo.data.id = %v", info.Data["id"])
	}
	// Upstream also asserts providerInfo.user.id == "mapped-profile-id"; the Go UserInfo has
	// no id field (BuildUserInfo never takes the id from mapProfileToUser), so the mapped id
	// cannot surface as an identity source by construction.

	c, res := poSignInSocial(t, env, "discord", map[string]any{"callbackURL": "/"})
	poExpectRedirect(t, res)
	spy.mu.Lock()
	called := false
	for _, call := range spy.calls {
		if call.Profile["id"] == accountID {
			called = true
		}
	}
	spy.mu.Unlock()
	if !called {
		t.Fatalf("accountSubject must be called with the raw profile id %s", accountID)
	}
	s := c.session()
	if s == nil || s["user"].(map[string]any)["email"] != email {
		t.Fatalf("session %v", s)
	}
	acc, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "account",
		Where: []adapter.Where{{Field: "accountId", Value: accountID}, {Field: "providerId", Value: "discord"}}})
	if err != nil || acc == nil {
		t.Fatalf("discord account not found (%v)", err)
	}
}

func TestPortOAuthLinkDiscordPlaceholderEmail(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poDiscord(func(p map[string]any) (map[string]any, error) {
		email := p["email"]
		if email == nil {
			email = fmt.Sprint(p["id"]) + "@discord.placeholder.invalid"
		}
		return map[string]any{"email": email}, nil
	})}, nil)
	const discordID = "920138789012345001"
	poMockDiscordToken(m, discordID, "phoneonly", nil)
	_, res := poSignInSocial(t, env, "discord", map[string]any{"callbackURL": "/"})
	if loc := poLocation(res); strings.Contains(loc, "error") {
		t.Fatalf("redirect %q must not contain error", loc)
	}
	placeholder := discordID + "@discord.placeholder.invalid"
	u := poFindUser(t, env, "email", placeholder)
	if u == nil || u["email"] != placeholder {
		t.Fatalf("user %v", u)
	}
	acc := poFindProviderAccount(poAccountsOf(t, env, u["id"]), "discord")
	if acc == nil || acc["accountId"] != discordID {
		t.Fatalf("discord account %v", acc)
	}
}

func TestPortOAuthLinkDiscordNullEmailRejected(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poDiscord(nil)}, nil)
	poMockDiscordToken(m, "920138789012345002", "phoneonly2", nil)
	_, res := poSignInSocial(t, env, "discord", map[string]any{"callbackURL": "/"})
	if loc := poLocation(res); !strings.Contains(loc, "error=email_not_found") {
		t.Fatalf("redirect %q should contain error=email_not_found", loc)
	}
}

// ======================================================================
// describe("oauth2 - accountLinking.requireLocalEmailVerified: false opt-out")
// ======================================================================

func TestPortOAuthLinkRequireLocalEmailVerifiedOptOut(t *testing.T) {
	m := oauth2test.New(t)
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){poAccountLinking(&AccountLinkingConfig{
		Enabled: Bool(true), TrustedProviders: []string{"google"}, RequireLocalEmailVerified: Bool(false)})})
	const email = "opt-out@example.com"
	userID := poSignUp(t, env.client(), email, "password123", "Opt Out User")
	p := poGoogleProfile(email, true, "google_opt_out_sub", "Test User", "")
	p["exp"], p["iat"], p["nbf"] = 1, 1, 1
	poMockGoogleToken(m, p, map[string]any{"access_token": "t", "refresh_token": "r"})
	_, res := poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	poExpectRedirect(t, res)
	if poFindProviderAccount(poAccountsOf(t, env, userID), "google") == nil {
		t.Fatal("google account should be linked")
	}
	if u := poFindUser(t, env, "id", userID); u["emailVerified"] != true {
		t.Fatalf("emailVerified = %v, want true", u["emailVerified"])
	}
}

// ======================================================================
// describe("oauth2 - per-provider requireEmailVerification gate")
// @see https://github.com/better-auth/better-auth/issues/9486
// ======================================================================

type poGateConfig struct {
	requireEmailVerification              bool
	emailPasswordRequireEmailVerification bool
	sendOnSignUp                          *bool
	sendOnSignIn                          bool
	withoutSendVerificationEmail          bool
}

type poGate struct {
	env   *testEnv
	m     *oauth2test.Server
	sends atomic.Int32
}

func poGateSetup(t *testing.T, cfg poGateConfig) *poGate {
	t.Helper()
	g := &poGate{m: oauth2test.New(t)}
	g.env = poEnv(t, []oauth2.Provider{poGoogle(func(o *google.Options) {
		o.RequireEmailVerification = cfg.requireEmailVerification
	})}, []func(c *Config){func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{Enabled: true, RequireEmailVerification: cfg.emailPasswordRequireEmailVerification}
		ev := &EmailVerificationConfig{SendOnSignUp: cfg.sendOnSignUp, SendOnSignIn: cfg.sendOnSignIn}
		if !cfg.withoutSendVerificationEmail {
			ev.SendVerificationEmail = func(context.Context, EmailData, *http.Request) error {
				g.sends.Add(1)
				return nil
			}
		}
		c.EmailVerification = ev
	}}, poInstanceOpts{disableTestUser: true})
	return g
}

// signInViaCallback returns the redirect location and whether the callback response set
// a better-auth.session_token cookie.
func (g *poGate) signInViaCallback(t *testing.T, email string, verified bool, sub string) (string, bool) {
	t.Helper()
	poMockGoogleToken(g.m, poMinimalGoogleProfile(email, verified, sub, "OAuth User"), poGoogleTokens())
	_, res := poSignInSocial(t, g.env, "google", map[string]any{"callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"})
	loc := poExpectRedirect(t, res)
	_, hasToken := res.cookie("better-auth.session_token")
	return loc, hasToken
}

func TestPortOAuthLinkGateBlocksNewUnverified(t *testing.T) {
	g := poGateSetup(t, poGateConfig{requireEmailVerification: true})
	const email = "gate-new-unverified@example.com"
	loc, token := g.signInViaCallback(t, email, false, "gate_new_unverified")
	if !strings.Contains(loc, "error=email_not_verified") {
		t.Fatalf("redirect %q should contain error=email_not_verified", loc)
	}
	if token {
		t.Fatal("session token must not be set")
	}
	if n := g.sends.Load(); n != 1 {
		t.Fatalf("sendVerificationEmail calls = %d, want 1", n)
	}
	if u := poFindUser(t, g.env, "email", email); u == nil || u["emailVerified"] != false {
		t.Fatalf("user %v", u)
	}
}

func TestPortOAuthLinkGateAllowsNewVerified(t *testing.T) {
	g := poGateSetup(t, poGateConfig{requireEmailVerification: true, sendOnSignUp: Bool(true)})
	loc, token := g.signInViaCallback(t, "gate-new-verified@example.com", true, "gate_new_verified")
	if !strings.Contains(loc, "/welcome") || strings.Contains(loc, "error") {
		t.Fatalf("redirect = %q", loc)
	}
	if !token {
		t.Fatal("session token should be set")
	}
	if n := g.sends.Load(); n != 0 {
		t.Fatalf("sendVerificationEmail calls = %d, want 0", n)
	}
}

func TestPortOAuthLinkGateResendsReturningUnverified(t *testing.T) {
	g := poGateSetup(t, poGateConfig{requireEmailVerification: true, sendOnSignIn: true})
	g.signInViaCallback(t, "gate-returning@example.com", false, "gate_returning")
	g.sends.Store(0)
	loc, token := g.signInViaCallback(t, "gate-returning@example.com", false, "gate_returning")
	if !strings.Contains(loc, "error=email_not_verified") {
		t.Fatalf("redirect %q should contain error=email_not_verified", loc)
	}
	if token {
		t.Fatal("session token must not be set")
	}
	if n := g.sends.Load(); n != 1 {
		t.Fatalf("sendVerificationEmail calls = %d, want 1", n)
	}
}

func TestPortOAuthLinkGateNotFromEmailPasswordFlag(t *testing.T) {
	g := poGateSetup(t, poGateConfig{emailPasswordRequireEmailVerification: true})
	loc, token := g.signInViaCallback(t, "gate-credential-only@example.com", false, "gate_credential_only")
	if strings.Contains(loc, "error") {
		t.Fatalf("redirect %q must not contain error", loc)
	}
	if !token {
		t.Fatal("session token should be set")
	}
}

func TestPortOAuthLinkGateReturningVerifiedNoResend(t *testing.T) {
	g := poGateSetup(t, poGateConfig{requireEmailVerification: true, sendOnSignIn: true})
	if _, token := g.signInViaCallback(t, "gate-returning-verified@example.com", true, "gate_returning_verified"); !token {
		t.Fatal("first sign-in should set a session token")
	}
	loc, token := g.signInViaCallback(t, "gate-returning-verified@example.com", true, "gate_returning_verified")
	if !strings.Contains(loc, "/dashboard") || strings.Contains(loc, "error") {
		t.Fatalf("redirect = %q", loc)
	}
	if !token {
		t.Fatal("session token should be set")
	}
	if n := g.sends.Load(); n != 0 {
		t.Fatalf("sendVerificationEmail calls = %d, want 0", n)
	}
}

func TestPortOAuthLinkGateReturningUnverifiedNoResend(t *testing.T) {
	g := poGateSetup(t, poGateConfig{requireEmailVerification: true})
	g.signInViaCallback(t, "gate-returning-no-resend@example.com", false, "gate_returning_no_resend")
	g.sends.Store(0)
	loc, token := g.signInViaCallback(t, "gate-returning-no-resend@example.com", false, "gate_returning_no_resend")
	if !strings.Contains(loc, "error=email_not_verified") {
		t.Fatalf("redirect %q should contain error=email_not_verified", loc)
	}
	if token {
		t.Fatal("session token must not be set")
	}
	if n := g.sends.Load(); n != 0 {
		t.Fatalf("sendVerificationEmail calls = %d, want 0", n)
	}
}

func TestPortOAuthLinkGateBlocksWithoutSender(t *testing.T) {
	g := poGateSetup(t, poGateConfig{requireEmailVerification: true, withoutSendVerificationEmail: true})
	loc, token := g.signInViaCallback(t, "gate-no-send@example.com", false, "gate_no_send")
	if !strings.Contains(loc, "error=email_not_verified") {
		t.Fatalf("redirect %q should contain error=email_not_verified", loc)
	}
	if token {
		t.Fatal("session token must not be set")
	}
}

// ======================================================================
// describe("oauth2 - account-linking logs use the configured logger")
// @see https://github.com/better-auth/better-auth/issues/9959
// ======================================================================

func TestPortOAuthLinkFailedLinkUsesConfiguredLogger(t *testing.T) {
	m := oauth2test.New(t)
	log := &poLogger{}
	var spy *poAdapter
	env := poEnv(t, []oauth2.Provider{poGoogle(nil)}, []func(c *Config){
		poAccountLinking(&AccountLinkingConfig{Enabled: Bool(true), TrustedProviders: []string{"google"}}),
		func(c *Config) { c.Logger = log },
		poWrapAdapter(&spy),
	})
	const email = "logger-link-fail@example.com"
	userID := poSignUp(t, env.client(), email, "password123", "Logger Test User")
	// Pre-verify so the link passes the gate and reaches linkAccount.
	poSetEmailVerified(t, env, userID)
	// Force the link to throw once (linkAccount.mockRejectedValueOnce(new Error("boom"))).
	var armed atomic.Bool
	armed.Store(true)
	spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
		if in.Model == "account" && armed.CompareAndSwap(true, false) {
			return nil, errors.New("boom"), true
		}
		return nil, nil, false
	}
	p := poGoogleProfile(email, true, "google_logger_link_fail", "Logger Test User", "https://example.com/photo.jpg")
	p["given_name"] = "Logger"
	poMockGoogleToken(m, p, poGoogleTokens())
	poSignInSocial(t, env, "google", map[string]any{"callbackURL": "/"})
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, e := range log.entries {
		if e.Level == "error" && e.Msg == "Unable to link account" && len(e.Args) > 0 && e.Args[0] != nil {
			return
		}
	}
	t.Fatalf("expected log(\"error\", \"Unable to link account\", <error>), got %+v", log.entries)
}

// ---- helpers shared with the un-skipped /callback/:id cases of account.test.ts ----

// poLastSetCookie returns the last Set-Cookie value for name (parseSetCookieHeader keeps
// the last occurrence of a cookie name).
func poLastSetCookie(h http.Header, name string) (string, bool) {
	val, found := "", false
	for _, sc := range h.Values("Set-Cookie") {
		if n, v, _ := ParseSetCookie(sc); n == name {
			val, found = v, true
		}
	}
	return val, found
}

// poAccountGoogleProfile is the GoogleProfile of account.test.ts's default token handler.
func poAccountGoogleProfile(email string) map[string]any {
	return map[string]any{
		"email": email, "email_verified": true, "name": "First Last",
		"picture": "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw", "exp": 1234567890, "sub": "1234567890",
		"iat": 1234567890, "aud": "test", "azp": "test", "nbf": 1234567890, "iss": "test", "locale": "en",
		"jti": "test", "given_name": "First", "family_name": "Last",
	}
}

// poAccountGoogleToken registers account.test.ts's default google token handler
// ({access_token: "test", refresh_token: "test", id_token}).
func poAccountGoogleToken(m *oauth2test.Server, email string) {
	poMockGoogleToken(m, poAccountGoogleProfile(email), map[string]any{"access_token": "test", "refresh_token": "test"})
}

// poGoogleTokenByGrant registers a google token handler answering per grant_type.
func poGoogleTokenByGrant(m *oauth2test.Server, fn func(form url.Values) map[string]any) {
	m.Handle("POST oauth2.googleapis.com/token", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fn(form))
	})
}

// poStartGoogle runs client.signIn.social({provider: "google", callbackURL}) on c and
// asserts the {url: /google.com/, redirect: true} response; returns the state.
func poStartGoogle(t *testing.T, c *testClient, callbackURL string) string {
	t.Helper()
	res := c.post("/sign-in/social", map[string]any{"provider": "google", "callbackURL": callbackURL})
	if res.Status != 200 {
		t.Fatalf("signIn.social: %d %s", res.Status, res.Body)
	}
	m := res.JSON(t)
	if !strings.Contains(pacStr(m["url"]), "google.com") || m["redirect"] != true {
		t.Fatalf("signIn.social: unexpected response %s", res.Body)
	}
	u, err := url.Parse(pacStr(m["url"]))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

// poPacGoogleUserInfo makes a pacProvider answer getUserInfo like Google decoding the
// id_token of account.test.ts's default token handler for the given email.
func poPacGoogleUserInfo(email string) func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
	return func(oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
		p := poAccountGoogleProfile(email)
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "First Last", Email: email, EmailVerified: true,
			Image: pacStr(p["picture"])}, Data: p}, nil
	}
}
