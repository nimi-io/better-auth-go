package sso

// Port of oidc-user-resolution-http-e2e.test.ts (@better-auth/sso 1.7.7). The upstream
// suite runs against node:sqlite with native transactions; the Go port uses the memory
// adapter (native snapshot transactions) and a real httptest server.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// o1NoTxAdapter runs transaction callbacks without a transaction (no native support).
type o1NoTxAdapter struct{ adapter.Adapter }

func (a o1NoTxAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return fn(ctx, a)
}

// o1IdP is the shared identity provider state of the upstream suite.
type o1IdP struct {
	*mockOIDC
	mu                 sync.Mutex
	subject            string
	email              string
	emailVerified      bool
	userInfoSubject    string
	omitIDToken        bool
	beforeTokenSigning func()
}

func newO1IdP(t *testing.T) *o1IdP {
	p := &o1IdP{mockOIDC: newMockOIDC(t), subject: "directory-user-1", email: "idp.employee@example.com", emailVerified: true}
	p.BeforeUserinfo = func(r *mockResponse, _ *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		sub := p.subject
		if p.userInfoSubject != "" {
			sub = p.userInfoSubject
		}
		r.Body = map[string]any{"sub": sub, "email": p.email, "name": "Directory Employee", "email_verified": p.emailVerified}
		r.StatusCode = 200
	}
	p.BeforeTokenSigning = func(payload map[string]any, _ *http.Request) {
		p.mu.Lock()
		hook := p.beforeTokenSigning
		p.mu.Unlock()
		if hook != nil {
			hook()
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		payload["sub"] = p.subject
		payload["email"] = p.email
		payload["name"] = "Directory Employee"
		payload["email_verified"] = p.emailVerified
	}
	p.BeforeResponse = func(r *mockResponse, _ *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.omitIDToken {
			if m, ok := r.Body.(map[string]any); ok {
				delete(m, "id_token")
			}
		}
	}
	return p
}

// reset mirrors the upstream afterEach.
func (p *o1IdP) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userInfoSubject = ""
	p.emailVerified = true
	p.omitIDToken = false
	p.beforeTokenSigning = nil
}

func (p *o1IdP) set(subject, email string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subject, p.email = subject, email
}

func (p *o1IdP) provider(providerID string) DefaultSSOProvider {
	return DefaultSSOProvider{Domain: "example.com", ProviderID: providerID, OIDCConfig: p.oidcConfig()}
}

func (p *o1IdP) oidcConfig() *OIDCConfig {
	return &OIDCConfig{Issuer: p.URL, ClientID: "workforce-client", ClientSecret: "workforce-secret", PKCE: false,
		DiscoveryEndpoint: p.URL + "/.well-known/openid-configuration"}
}

type o1Instance struct {
	*testEnv
	origin string
}

// o1CreateInstance mirrors createInstance: providers nil means [provider()].
func o1CreateInstance(t *testing.T, idp *o1IdP, opts Options, mutate func(c *betterauth.Config), providers []DefaultSSOProvider) *o1Instance {
	t.Helper()
	if providers == nil {
		providers = []DefaultSSOProvider{idp.provider("workforce")}
	}
	opts.DefaultSSO = providers
	env := newEnv(t, opts, envConfig{noTestUser: true, mutate: func(c *betterauth.Config) {
		c.TrustedOrigins = []string{idp.URL}
		if mutate != nil {
			mutate(c)
		}
	}})
	return &o1Instance{testEnv: env, origin: env.server.URL}
}

func (in *o1Instance) createUser(t *testing.T, data adapter.Record) adapter.Record {
	t.Helper()
	now := time.Now()
	rec := adapter.Record{"createdAt": now, "updatedAt": now}
	for k, v := range data {
		rec[k] = v
	}
	_, force := rec["id"]
	u, err := in.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "user", Data: rec, ForceAllowID: force})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func (in *o1Instance) findUser(t *testing.T, id string) adapter.Record {
	t.Helper()
	u, err := in.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: id}}})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (in *o1Instance) count(model string) int { return len(in.rows(model)) }

type o1SignInResult struct {
	callback *result
	cookies  http.Header
}

func (r o1SignInResult) location() string { return r.callback.location() }

func (r o1SignInResult) setCookies() string {
	return strings.Join(r.callback.Headers.Values("Set-Cookie"), ";")
}

func (r o1SignInResult) param(t *testing.T, base, name string) string {
	t.Helper()
	b, _ := url.Parse(base)
	u, err := b.Parse(r.location())
	if err != nil {
		t.Fatalf("bad location %q", r.location())
	}
	return u.Query().Get(name)
}

// completeSignIn mirrors the upstream helper.
func (in *o1Instance) completeSignIn(t *testing.T, providerID string) o1SignInResult {
	t.Helper()
	signIn := in.do("POST", in.origin+"/api/auth/sign-in/sso", http.Header{"Origin": {in.origin}},
		map[string]any{"providerId": providerID, "callbackURL": in.origin + "/employee"})
	if signIn.Status != 200 {
		t.Fatalf("sign-in status %d %s", signIn.Status, signIn.Raw)
	}
	cookies := cookieHeaders(signIn.Headers)
	authURL, _ := signIn.m()["url"].(string)
	res, err := noRedirectClient.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	callbackURL := res.Header.Get("Location")
	if callbackURL == "" {
		t.Fatal("OIDC provider did not return a callback")
	}
	cb := in.do("GET", callbackURL, cookies, nil)
	return o1SignInResult{callback: cb, cookies: mergeCookies(cookies, cb.Headers)}
}

// o1FailingStorage is the secondary storage whose active-session mirroring fails.
type o1FailingStorage struct {
	mu       sync.Mutex
	values   map[string]string
	setCalls int
}

func (s *o1FailingStorage) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	return v, ok, nil
}

func (s *o1FailingStorage) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setCalls++
	if strings.HasPrefix(key, "active-sessions-") {
		return errors.New("secondary storage unavailable")
	}
	s.values[key] = value
	return nil
}

func (s *o1FailingStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func (s *o1FailingStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	delete(s.values, key)
	return v, ok, nil
}

func (s *o1FailingStorage) Increment(_ context.Context, key string, _ time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, _ := strconv.ParseInt(s.values[key], 10, 64)
	n++
	s.values[key] = strconv.FormatInt(n, 10)
	return n, nil
}

func TestOIDCUserResolutionHTTP(t *testing.T) {
	t.Run("SSO OIDC user resolution HTTP", func(t *testing.T) {
		idp := newO1IdP(t)
		run := func(name string, fn func(t *testing.T)) {
			t.Run(name, func(t *testing.T) {
				defer idp.reset()
				fn(t)
			})
		}

		run("links the exact selected user without email fallback and resolves returning sign-ins", func(t *testing.T) {
			idp.set("directory-user-1", "distinct-provider@example.com")
			firstProviderEmail := "distinct-provider@example.com"
			subject := "directory-user-1"
			var mu sync.Mutex
			selectedUserID := ""
			var inputs []UserResolutionInput
			var databases []adapter.Adapter
			var validationActions []string
			in := o1CreateInstance(t, idp, Options{
				DisableImplicitSignUp: true,
				ResolveUser: func(_ context.Context, input UserResolutionInput, rc UserResolutionContext) (UserResolution, error) {
					mu.Lock()
					defer mu.Unlock()
					inputs = append(inputs, input)
					databases = append(databases, rc.Adapter)
					return UserResolution{Action: "link", UserID: selectedUserID, Profile: "preserve"}, nil
				},
			}, func(c *betterauth.Config) {
				c.Account = &betterauth.AccountConfig{StoreAccountCookie: betterauth.Bool(true)}
				c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, _ map[string]any, src betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
					mu.Lock()
					validationActions = append(validationActions, src.Action)
					mu.Unlock()
					return nil, nil
				}}
				c.DatabaseHooks = &betterauth.DatabaseHooks{Account: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
					After: func(context.Context, adapter.Record) error { return errors.New("committed account after-hook failure") },
				}}}
			}, nil)
			selected := in.createUser(t, adapter.Record{"email": "provisioned@example.com", "emailVerified": false,
				"name": "Provisioned Employee", "image": "https://directory.example/avatar.png"})
			selectedUserID, _ = selected["id"].(string)

			first := in.completeSignIn(t, "workforce")
			o1Eq(t, "location", first.location(), in.origin+"/employee")
			o1Contains(t, first.setCookies(), "account_data=")
			o1Contains(t, first.setCookies(), "session_token=")
			idp.set(subject, "changed-by-provider@example.com")
			in.completeSignIn(t, "workforce")

			if len(inputs) != 2 {
				t.Fatalf("inputs: %d", len(inputs))
			}
			i0 := inputs[0]
			o1Eq(t, "protocol", i0.Protocol, "oidc")
			o1Eq(t, "providerId", i0.ProviderID, "workforce")
			o1Eq(t, "accountKey.issuer", i0.AccountKey.Issuer, idp.URL)
			o1Eq(t, "accountKey.accountId", i0.AccountKey.AccountID, subject)
			o1Eq(t, "providerUser.email", i0.ProviderUser.Email, firstProviderEmail)
			o1Eq(t, "providerClaims.sub", i0.ProviderClaims["sub"], subject)
			o1Eq(t, "verifiedIdTokenClaims.iss", i0.VerifiedIDTokenClaims["iss"], idp.URL)
			o1Eq(t, "verifiedIdTokenClaims.sub", i0.VerifiedIDTokenClaims["sub"], subject)
			o1Eq(t, "providerReference.providerId", i0.ProviderReference.ProviderID, "workforce")
			o1Eq(t, "providerReference.source.type", i0.ProviderReference.Source.Type, "configured")
			if i0.ProviderReference.AuthenticationConfigurationFingerprint == "" {
				t.Errorf("expected authenticationConfigurationFingerprint")
			}
			if len(databases) != 2 || databases[0] == nil || databases[1] == nil {
				t.Errorf("databases: %v", databases)
			}
			o1Eq(t, "validationActions", validationActions, []string{"link-account", "sign-in"})
			users := in.rows("user")
			if len(users) != 1 {
				t.Fatalf("users: %v", users)
			}
			o1Match(t, "user", users[0], map[string]any{"id": selectedUserID, "email": "provisioned@example.com", "emailVerified": false,
				"name": "Provisioned Employee", "image": "https://directory.example/avatar.png"})
			accounts := in.rows("account")
			if len(accounts) != 1 {
				t.Fatalf("accounts: %v", accounts)
			}
			o1Match(t, "account", accounts[0], map[string]any{"accountId": subject, "providerId": "workforce", "userId": selectedUserID})
		})

		run("preserves an unverified selected profile on a same-email first link", func(t *testing.T) {
			idp.set("preserved-profile-user", "same-email@example.com")
			selectedUserID := ""
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				return UserResolution{Action: "link", UserID: selectedUserID, Profile: "preserve"}, nil
			}}, nil, nil)
			selected := in.createUser(t, adapter.Record{"email": "same-email@example.com", "emailVerified": false,
				"name": "SCIM Name", "image": "https://directory.example/scim.png"})
			selectedUserID, _ = selected["id"].(string)
			o1Eq(t, "location", in.completeSignIn(t, "workforce").location(), in.origin+"/employee")
			o1Match(t, "user", map[string]any(in.findUser(t, selectedUserID)), map[string]any{"email": "same-email@example.com", "emailVerified": false,
				"name": "SCIM Name", "image": "https://directory.example/scim.png"})
		})

		run("updates an explicitly selected user from the provider profile", func(t *testing.T) {
			idp.set("provider-profile-user", "provider-profile@example.com")
			selectedUserID := ""
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				return UserResolution{Action: "link", UserID: selectedUserID, Profile: "update"}, nil
			}}, nil, nil)
			selected := in.createUser(t, adapter.Record{"email": "old-profile@example.com", "emailVerified": false, "name": "Old Profile", "image": nil})
			selectedUserID, _ = selected["id"].(string)
			o1Eq(t, "location", in.completeSignIn(t, "workforce").location(), in.origin+"/employee")
			o1Match(t, "user", map[string]any(in.findUser(t, selectedUserID)), map[string]any{"email": "provider-profile@example.com",
				"emailVerified": false, "name": "Directory Employee"})
		})

		run("rejects missing selected users and account ownership conflicts", func(t *testing.T) {
			subject := "selected-user-conflict"
			idp.set(subject, "selected-user-conflict@example.com")
			var mu sync.Mutex
			selectedUserID := "missing-user"
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				mu.Lock()
				defer mu.Unlock()
				return UserResolution{Action: "link", UserID: selectedUserID, Profile: "preserve"}, nil
			}}, nil, nil)

			missing := in.completeSignIn(t, "workforce")
			o1Eq(t, "error", missing.param(t, in.origin, "error"), "user_not_found")

			owner := in.createUser(t, adapter.Record{"email": "owner@example.com", "emailVerified": true, "name": "Owner", "image": nil})
			selected := in.createUser(t, adapter.Record{"email": "selected@example.com", "emailVerified": true, "name": "Selected", "image": nil})
			ownerID, _ := owner["id"].(string)
			// Upstream also passes issuer; the Go account schema keys accounts by
			// providerId + accountId.
			if _, err := in.auth.Context().InternalAdapter.CreateAccount(context.Background(), adapter.Record{
				"accountId": subject, "providerId": "workforce", "userId": ownerID}); err != nil {
				t.Fatalf("createAccount: %v", err)
			}
			mu.Lock()
			selectedUserID, _ = selected["id"].(string)
			mu.Unlock()

			conflict := in.completeSignIn(t, "workforce")
			o1Eq(t, "error", conflict.param(t, in.origin, "error"), "account_ownership_conflict")
			o1Eq(t, "sessions", in.count("session"), 0)

			// PRAGMA foreign_keys = OFF; DELETE FROM "user" WHERE "id" = owner.id
			if err := in.auth.Context().Adapter.Delete(context.Background(), "user", []adapter.Where{{Field: "id", Value: ownerID}}); err != nil {
				t.Fatal(err)
			}
			orphaned := in.completeSignIn(t, "workforce")
			o1Eq(t, "error", orphaned.param(t, in.origin, "error"), "unable to link account")
			o1Eq(t, "sessions", in.count("session"), 0)
		})

		run("rolls back resolver and authentication writes without publishing side effects", func(t *testing.T) {
			idp.set("rollback-user", "rollback@example.com")
			idp.mu.Lock()
			idp.emailVerified = false
			idp.mu.Unlock()
			var mu sync.Mutex
			markerUserID := ""
			rejectSessionCreation := true
			sendCalls := 0
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(ctx context.Context, _ UserResolutionInput, rc UserResolutionContext) (UserResolution, error) {
				if _, err := rc.Adapter.Update(ctx, "user", []adapter.Where{{Field: "id", Value: markerUserID}}, adapter.Record{"name": "must roll back"}); err != nil {
					return UserResolution{}, err
				}
				return UserResolution{Action: "continue"}, nil
			}}, func(c *betterauth.Config) {
				c.Account = &betterauth.AccountConfig{StoreAccountCookie: betterauth.Bool(true)}
				c.EmailVerification = &betterauth.EmailVerificationConfig{SendOnSignUp: betterauth.Bool(true),
					SendVerificationEmail: func(context.Context, betterauth.EmailData, *http.Request) error {
						mu.Lock()
						sendCalls++
						mu.Unlock()
						return nil
					}}
				c.DatabaseHooks = &betterauth.DatabaseHooks{Session: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
					Before: func(context.Context, adapter.Record) (*betterauth.DBHookResult, error) {
						mu.Lock()
						defer mu.Unlock()
						if rejectSessionCreation {
							return &betterauth.DBHookResult{Abort: true}, nil
						}
						return nil, nil
					},
				}}}
			}, nil)
			marker := in.createUser(t, adapter.Record{"email": "marker@example.com", "emailVerified": true, "name": "marker", "image": nil})
			markerUserID, _ = marker["id"].(string)

			signIn := in.completeSignIn(t, "workforce")
			o1Eq(t, "error", signIn.param(t, in.origin, "error"), "unable to create session")
			o1NotContains(t, signIn.setCookies(), "account_data=")
			o1NotContains(t, signIn.setCookies(), "session_token=")
			o1Eq(t, "accounts", in.count("account"), 0)
			o1Eq(t, "sessions", in.count("session"), 0)
			o1Eq(t, "sendVerificationEmail calls", sendCalls, 0)
			o1Match(t, "marker", map[string]any(in.findUser(t, markerUserID)), map[string]any{"name": "marker"})

			mu.Lock()
			rejectSessionCreation = false
			mu.Unlock()
			committed := in.completeSignIn(t, "workforce")
			o1Eq(t, "location", committed.location(), in.origin+"/employee")
			o1Eq(t, "sendVerificationEmail calls", sendCalls, 1)
		})

		run("keeps case-distinct OIDC subjects as different account keys", func(t *testing.T) {
			idp.set("CaseSensitiveSubject", "case-sensitive@example.com")
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				return UserResolution{Action: "continue"}, nil
			}}, nil, nil)
			o1Eq(t, "location", in.completeSignIn(t, "workforce").location(), in.origin+"/employee")
			idp.set("casesensitivesubject", "case-sensitive-lower@example.com")
			o1Eq(t, "location", in.completeSignIn(t, "workforce").location(), in.origin+"/employee")
			var ids []string
			for _, a := range in.rows("account") {
				s, _ := a["accountId"].(string)
				ids = append(ids, s)
			}
			if len(ids) != 2 || !((ids[0] == "CaseSensitiveSubject" && ids[1] == "casesensitivesubject") ||
				(ids[1] == "CaseSensitiveSubject" && ids[0] == "casesensitivesubject")) {
				t.Errorf("accountIds: %v", ids)
			}
		})

		run("rejects a persisted provider replacement between token exchange and finalization", func(t *testing.T) {
			idp.set("provider-replacement-user", "provider-replacement@example.com")
			resolverCalls := 0
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				resolverCalls++
				return UserResolution{Action: "continue"}, nil
			}}, nil, []DefaultSSOProvider{})
			// UPDATE "user" SET "id" = 'default': create the owner with that id directly.
			in.createUser(t, adapter.Record{"id": "default", "email": "provider-owner@example.com", "emailVerified": true, "name": "Provider Owner", "image": nil})
			a := in.auth.Context().Adapter
			cfgJSON := o1JSON(t, idp.oidcConfig())
			row, err := a.Create(context.Background(), adapter.CreateInput{Model: "ssoProvider", Data: adapter.Record{
				"issuer": idp.URL, "domain": "example.com", "oidcConfig": cfgJSON, "samlConfig": nil,
				"userId": "default", "providerId": "workforce", "organizationId": nil}})
			if err != nil {
				t.Fatalf("create provider: %v", err)
			}
			idp.mu.Lock()
			idp.beforeTokenSigning = func() {
				// UPDATE "ssoProvider" SET "id" = 'replacement-provider-row' WHERE "providerId" = 'workforce'
				ctx := context.Background()
				if err := a.Delete(ctx, "ssoProvider", []adapter.Where{{Field: "providerId", Value: "workforce"}}); err != nil {
					t.Errorf("delete provider: %v", err)
				}
				rec := adapter.Record{}
				for k, v := range row {
					rec[k] = v
				}
				rec["id"] = "replacement-provider-row"
				if _, err := a.Create(ctx, adapter.CreateInput{Model: "ssoProvider", Data: rec, ForceAllowID: true}); err != nil {
					t.Errorf("recreate provider: %v", err)
				}
			}
			idp.mu.Unlock()

			signIn := in.completeSignIn(t, "workforce")
			o1Eq(t, "error", signIn.param(t, in.origin, "error"), "SSO_PROVIDER_CHANGED")
			o1Eq(t, "resolverCalls", resolverCalls, 0)
			o1Eq(t, "accounts", in.count("account"), 0)
		})

		run("returns committed session cookies when secondary mirroring fails", func(t *testing.T) {
			idp.set("secondary-storage-failure-user", "secondary-storage-failure@example.com")
			storage := &o1FailingStorage{values: map[string]string{}}
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				return UserResolution{Action: "continue"}, nil
			}}, func(c *betterauth.Config) {
				c.SecondaryStorage = storage
				c.Session = &betterauth.SessionConfig{StoreSessionInDatabase: true}
			}, nil)
			signIn := in.completeSignIn(t, "workforce")
			o1Eq(t, "location", signIn.location(), in.origin+"/employee")
			o1Contains(t, signIn.setCookies(), "session_token=")
			o1Eq(t, "sessions", in.count("session"), 1)
			storage.mu.Lock()
			calls := storage.setCalls
			storage.mu.Unlock()
			if calls == 0 {
				t.Errorf("expected secondary storage set to be called")
			}
		})

		run("rejects missing ID Tokens and UserInfo subject mismatches before resolution", func(t *testing.T) {
			idp.set("verified-token-user", "verified-token@example.com")
			resolverCalls := 0
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				resolverCalls++
				return UserResolution{Action: "continue"}, nil
			}}, nil, nil)
			idp.mu.Lock()
			idp.omitIDToken = true
			idp.mu.Unlock()
			missing := in.completeSignIn(t, "workforce")
			o1Eq(t, "error_description", missing.param(t, in.origin, "error_description"), "id_token_required_for_user_resolution")
			idp.mu.Lock()
			idp.omitIDToken = false
			idp.userInfoSubject = "different-userinfo-subject"
			idp.mu.Unlock()
			mismatch := in.completeSignIn(t, "workforce")
			o1Eq(t, "error_description", mismatch.param(t, in.origin, "error_description"), "id_token_userinfo_subject_mismatch")
			idp.mu.Lock()
			idp.userInfoSubject = ""
			idp.mu.Unlock()
			o1Eq(t, "resolverCalls", resolverCalls, 0)
		})

		run("fails before resolution when native transactions are unavailable", func(t *testing.T) {
			idp.set("unsupported-transaction-user", "unsupported-transaction@example.com")
			resolverCalls := 0
			in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				resolverCalls++
				return UserResolution{Action: "continue"}, nil
			}}, func(c *betterauth.Config) {
				// adapterConfig.transaction = false
				inner := memory.New()
				c.Database = func(o adapter.Options) (adapter.Adapter, error) {
					a, err := inner(o)
					if err != nil {
						return nil, err
					}
					return o1NoTxAdapter{a}, nil
				}
			}, nil)
			signIn := in.completeSignIn(t, "workforce")
			o1Eq(t, "error", signIn.param(t, in.origin, "error"), "SSO_USER_RESOLUTION_REQUIRES_NATIVE_TRANSACTIONS")
			o1Eq(t, "resolverCalls", resolverCalls, 0)
		})

		for _, c := range []struct{ hookModel, expectedError string }{
			{"account", "account_hook_binding_conflict"},
			{"session", "session_hook_user_conflict"},
		} {
			run("rejects "+c.hookModel+" hook attempts to rewrite the selected binding", func(t *testing.T) {
				idp.set(c.hookModel+"-hook-rewrite-user", c.hookModel+"-hook-rewrite@example.com")
				var mu sync.Mutex
				selectedUserID, otherUserID := "", ""
				before := func(context.Context, adapter.Record) (*betterauth.DBHookResult, error) {
					mu.Lock()
					defer mu.Unlock()
					return &betterauth.DBHookResult{Data: adapter.Record{"userId": otherUserID}}, nil
				}
				hooks := &betterauth.DatabaseHooks{}
				if c.hookModel == "account" {
					hooks.Account.Create.Before = before
				} else {
					hooks.Session.Create.Before = before
				}
				in := o1CreateInstance(t, idp, Options{ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
					mu.Lock()
					defer mu.Unlock()
					return UserResolution{Action: "link", UserID: selectedUserID, Profile: "preserve"}, nil
				}}, func(cfg *betterauth.Config) { cfg.DatabaseHooks = hooks }, nil)
				selected := in.createUser(t, adapter.Record{"email": "selected@example.com", "emailVerified": true, "name": "selected-user", "image": nil})
				other := in.createUser(t, adapter.Record{"email": "other@example.com", "emailVerified": true, "name": "other-user", "image": nil})
				mu.Lock()
				selectedUserID, _ = selected["id"].(string)
				otherUserID, _ = other["id"].(string)
				mu.Unlock()

				signIn := in.completeSignIn(t, "workforce")
				o1Eq(t, "error", signIn.param(t, in.origin, "error"), c.expectedError)
				o1Eq(t, "accounts", in.count("account"), 0)
				o1Eq(t, "sessions", in.count("session"), 0)
			})
		}
	})
}

func o1JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
