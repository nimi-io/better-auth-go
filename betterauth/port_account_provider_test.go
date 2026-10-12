package betterauth

// Shared helpers for the port of better-auth/src/api/routes/account.test.ts.
//
// pacProvider is a configurable mock OAuth provider standing in for the msw-mocked
// Google / GitHub providers upstream. Its defaults mirror the upstream mocks:
//   - CreateAuthorizationURL builds a provider authorization URL (accounts.google.com for
//     "google") with the standard params and drops reserved additionalParams, like
//     core/src/oauth2/create-authorization-url.ts.
//   - ValidateAuthorizationCode / RefreshAccessToken return {access_token:"test",
//     refresh_token:"test"} like the default msw token handler.
//   - VerifyIDToken returns false unless configured (the upstream vi.fn() mock resolves
//     undefined, and an unconfigured Google JWKS verification fails closed).
//   - GetUserInfo returns nil unless configured (vi.spyOn(..).mockResolvedValue(...)).
//   - AccountSubject returns String(profile[subjectKey]) ("sub" for google, "id" for github).
// Every call is recorded so tests can assert toHaveBeenCalled / toHaveBeenCalledWith.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/oauth2"
)

const (
	pacTestEmail    = "test@test.com"
	pacTestPassword = "test123456"
	pacTestName     = "test user"
)

var pacReservedAuthorizationParams = map[string]bool{"state": true, "client_id": true, "redirect_uri": true,
	"response_type": true, "code_challenge": true, "code_challenge_method": true, "nonce": true, "scope": true}

type pacVerifyCall struct{ Token, Nonce string }

type pacProvider struct {
	id            string
	name          string
	authEndpoint  string
	defaultScopes []string
	subjectKey    string

	mu       sync.Mutex
	settings oauth2.ProviderSettings

	verifyFn   func(token, nonce string) (bool, error)
	userInfoFn func(p oauth2.UserInfoParams) (*oauth2.UserInfoResult, error)
	refreshFn  func(refreshToken string) (*oauth2.Tokens, error)
	subjectFn  func(tokens *oauth2.Tokens, profile map[string]any) (string, error)
	// verifyOnce / userInfoOnce emulate mockResolvedValueOnce.
	verifyOnce   []bool
	userInfoOnce []*oauth2.UserInfoResult

	verifyCalls   []pacVerifyCall
	userInfoCalls []oauth2.UserInfoParams
	authURLCalls  []oauth2.AuthorizationURLParams
	refreshCalls  []string
}

func pacGoogle() *pacProvider {
	return &pacProvider{id: "google", name: "Google", authEndpoint: "https://accounts.google.com/o/oauth2/auth",
		defaultScopes: []string{"email", "profile", "openid"}, subjectKey: "sub"}
}

func pacGithub() *pacProvider {
	return &pacProvider{id: "github", name: "GitHub", authEndpoint: "https://github.com/login/oauth/authorize",
		defaultScopes: []string{"read:user", "user:email"}, subjectKey: "id"}
}

// alias returns a copy of p with another id/name that shares p's behaviour (the
// `{...googleProvider, id: "google-mobile"}` spread upstream).
func (p *pacProvider) alias(id, name string) *pacProvider {
	return &pacProvider{id: id, name: name, authEndpoint: p.authEndpoint, defaultScopes: p.defaultScopes,
		subjectKey: p.subjectKey, settings: p.settings, verifyFn: p.verifyFn, userInfoFn: p.userInfoFn,
		refreshFn: p.refreshFn, subjectFn: p.subjectFn}
}

func (p *pacProvider) ID() string   { return p.id }
func (p *pacProvider) Name() string { return p.name }

func (p *pacProvider) ProviderSettings() *oauth2.ProviderSettings {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.settings
	return &s
}

func (p *pacProvider) setRequiresIDTokenNonce(v bool) {
	p.mu.Lock()
	p.settings.RequiresIDTokenNonce = v
	p.mu.Unlock()
}

func (p *pacProvider) CreateAuthorizationURL(_ context.Context, a oauth2.AuthorizationURLParams) (*url.URL, error) {
	p.mu.Lock()
	p.authURLCalls = append(p.authURLCalls, a)
	p.mu.Unlock()
	u, err := url.Parse(p.authEndpoint)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "test")
	q.Set("state", a.State)
	scopes := append(append([]string{}, p.defaultScopes...), a.Scopes...)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("redirect_uri", a.RedirectURI)
	if a.CodeVerifier != "" {
		q.Set("code_challenge", "challenge-"+a.CodeVerifier[:8])
		q.Set("code_challenge_method", "S256")
	}
	if a.LoginHint != "" {
		q.Set("login_hint", a.LoginHint)
	}
	if a.IDTokenNonce != "" {
		q.Set("nonce", a.IDTokenNonce)
	}
	for k, v := range a.AdditionalParams {
		if pacReservedAuthorizationParams[k] {
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func (p *pacProvider) ValidateAuthorizationCode(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
	return &oauth2.Tokens{AccessToken: "test", RefreshToken: "test"}, nil
}

func (p *pacProvider) GetUserInfo(_ context.Context, in oauth2.UserInfoParams) (*oauth2.UserInfoResult, error) {
	p.mu.Lock()
	p.userInfoCalls = append(p.userInfoCalls, in)
	if len(p.userInfoOnce) > 0 {
		r := p.userInfoOnce[0]
		p.userInfoOnce = p.userInfoOnce[1:]
		p.mu.Unlock()
		return r, nil
	}
	fn := p.userInfoFn
	p.mu.Unlock()
	if fn == nil {
		return nil, nil
	}
	return fn(in)
}

func (p *pacProvider) AccountSubject(_ context.Context, tokens *oauth2.Tokens, profile map[string]any) (string, error) {
	if p.subjectFn != nil {
		return p.subjectFn(tokens, profile)
	}
	v, ok := profile[p.subjectKey]
	if !ok || v == nil {
		return "undefined", nil
	}
	return fmt.Sprint(v), nil
}

func (p *pacProvider) RefreshAccessToken(_ context.Context, refreshToken string, _ *oauth2.RefreshContext) (*oauth2.Tokens, error) {
	p.mu.Lock()
	p.refreshCalls = append(p.refreshCalls, refreshToken)
	fn := p.refreshFn
	p.mu.Unlock()
	if fn == nil {
		return &oauth2.Tokens{AccessToken: "test", RefreshToken: "test"}, nil
	}
	return fn(refreshToken)
}

func (p *pacProvider) VerifyIDToken(_ context.Context, token, nonce string) (bool, error) {
	p.mu.Lock()
	p.verifyCalls = append(p.verifyCalls, pacVerifyCall{token, nonce})
	if len(p.verifyOnce) > 0 {
		r := p.verifyOnce[0]
		p.verifyOnce = p.verifyOnce[1:]
		p.mu.Unlock()
		return r, nil
	}
	fn := p.verifyFn
	p.mu.Unlock()
	if fn == nil {
		return false, nil
	}
	return fn(token, nonce)
}

func (p *pacProvider) userInfoCallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.userInfoCalls)
}

func (p *pacProvider) verifyCallCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.verifyCalls)
}

func (p *pacProvider) refreshCallsCopy() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.refreshCalls...)
}

var (
	_ oauth2.Provider        = (*pacProvider)(nil)
	_ oauth2.Refresher       = (*pacProvider)(nil)
	_ oauth2.IDTokenVerifier = (*pacProvider)(nil)
	_ oauth2.Settings        = (*pacProvider)(nil)
)

// ---- adapter spy ----

// pacSpyAdapter counts FindMany calls on the account model filtered by userId, i.e.
// internalAdapter.findAccounts(userId) (vi.spyOn(ctx.internalAdapter, "findAccounts")).
type pacSpyAdapter struct {
	adapter.Adapter
	mu               sync.Mutex
	findAccountsArgs []any
}

func (s *pacSpyAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	if in.Model == "account" && len(in.Where) == 1 && in.Where[0].Field == "userId" {
		s.mu.Lock()
		s.findAccountsArgs = append(s.findAccountsArgs, in.Where[0].Value)
		s.mu.Unlock()
	}
	return s.Adapter.FindMany(ctx, in)
}

func (s *pacSpyAdapter) reset() {
	s.mu.Lock()
	s.findAccountsArgs = nil
	s.mu.Unlock()
}

func (s *pacSpyAdapter) calls() []any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]any{}, s.findAccountsArgs...)
}

// pacWithSpy wraps the configured database with a pacSpyAdapter.
func pacWithSpy(spy **pacSpyAdapter) func(c *Config) {
	return func(c *Config) {
		inner := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := inner(o)
			if err != nil {
				return nil, err
			}
			s := &pacSpyAdapter{Adapter: a}
			*spy = s
			return s, nil
		}
	}
}

// ---- instance helpers (getTestInstance / signInWithTestUser) ----

// pacNewInstance builds an instance with the given providers and creates the default
// test user, like getTestInstance.
func pacNewInstance(t *testing.T, providers []*pacProvider, mutates ...func(c *Config)) *testEnv {
	t.Helper()
	env := newTestEnv(t, func(c *Config) {
		for _, p := range providers {
			c.SocialProviders = append(c.SocialProviders, p)
		}
		for _, m := range mutates {
			if m != nil {
				m(c)
			}
		}
	})
	if env.auth.Context().Options.Database != nil {
		env.client().signUp(pacTestEmail, pacTestPassword, pacTestName)
	}
	return env
}

// pacSignInWithTestUser signs the default test user in on a fresh client.
func pacSignInWithTestUser(t *testing.T, env *testEnv) (*testClient, map[string]any) {
	t.Helper()
	c := env.client()
	res := c.post("/sign-in/email", map[string]any{"email": pacTestEmail, "password": pacTestPassword})
	if res.Status != 200 {
		t.Fatalf("sign-in failed: %d %s", res.Status, res.Body)
	}
	s := c.session()
	if s == nil {
		t.Fatal("no session after sign-in")
	}
	u, _ := s["user"].(map[string]any)
	return c, u
}

func pacJSONArray(t *testing.T, res *testResponse) []map[string]any {
	t.Helper()
	var arr []map[string]any
	if err := json.Unmarshal(res.Body, &arr); err != nil {
		t.Fatalf("decode array %q: %v", res.Body, err)
	}
	return arr
}

func pacListAccounts(t *testing.T, c *testClient) []map[string]any {
	t.Helper()
	res := c.get("/list-accounts")
	if res.Status != 200 {
		t.Fatalf("list-accounts: %d %s", res.Status, res.Body)
	}
	return pacJSONArray(t, res)
}

func pacCreateAccount(t *testing.T, env *testEnv, rec adapter.Record) *Account {
	t.Helper()
	acc, err := env.auth.Context().InternalAdapter.CreateAccount(context.Background(), rec)
	if err != nil || acc == nil {
		t.Fatalf("createAccount: %v", err)
	}
	return acc
}

func pacCreateUser(t *testing.T, env *testEnv, name, email string) *User {
	t.Helper()
	u, err := env.auth.Context().InternalAdapter.CreateUser(context.Background(),
		adapter.Record{"name": name, "email": email}, UserInfoSource{Method: "test"})
	if err != nil || u == nil {
		t.Fatalf("createUser: %v", err)
	}
	return u
}

func pacFindAccounts(t *testing.T, env *testEnv, userID string) []*Account {
	t.Helper()
	accs, err := env.auth.Context().InternalAdapter.FindAccounts(context.Background(), userID)
	if err != nil {
		t.Fatalf("findAccounts: %v", err)
	}
	return accs
}

func pacSetCookies(c *testClient, cookies ...*http.Cookie) {
	u, _ := url.Parse(c.env.server.URL)
	c.jar.SetCookies(u, cookies)
}

// pacSetCookieNames returns all cookie names in Set-Cookie headers.
func pacSetCookieNames(h http.Header) []string {
	var out []string
	for _, sc := range h.Values("Set-Cookie") {
		n, _, _ := ParseSetCookie(sc)
		out = append(out, n)
	}
	return out
}

func pacStr(v any) string {
	s, _ := v.(string)
	return s
}

func pacExpectErrorBody(t *testing.T, res *testResponse, status int, code, message string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("expected status %d, got %d: %s", status, res.Status, res.Body)
	}
	m := res.JSON(t)
	if code != "" && m["code"] != code {
		t.Fatalf("expected code %q, got %v (%s)", code, m["code"], res.Body)
	}
	if message != "" && m["message"] != message {
		t.Fatalf("expected message %q, got %v (%s)", message, m["message"], res.Body)
	}
}
