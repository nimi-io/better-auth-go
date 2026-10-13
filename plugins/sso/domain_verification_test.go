package sso

// Ports of domain-verification.test.ts and domain-verification-concurrency.test.ts.

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/organization"
)

// m1TXT is the node:dns resolveTxt mock (lookupTXT replacement).
type m1TXT struct {
	mu    sync.Mutex
	calls []string
	impl  func(name string) ([]string, error)
}

// m1MockTXT installs a lookupTXT mock for the duration of the test.
func m1MockTXT(t *testing.T) *m1TXT {
	t.Helper()
	m := &m1TXT{impl: func(string) ([]string, error) { return nil, nil }}
	prev := lookupTXT
	lookupTXT = func(_ context.Context, name string) ([]string, error) {
		m.mu.Lock()
		m.calls = append(m.calls, name)
		impl := m.impl
		m.mu.Unlock()
		return impl(name)
	}
	t.Cleanup(func() { lookupTXT = prev })
	return m
}

// resolved mirrors mockResolvedValue (records are [][]string; entries are joined).
func (m *m1TXT) resolved(records ...[]string) {
	var out []string
	for _, r := range records {
		out = append(out, strings.Join(r, ""))
	}
	m.set(func(string) ([]string, error) { return out, nil })
}

func (m *m1TXT) set(f func(name string) ([]string, error)) {
	m.mu.Lock()
	m.impl = f
	m.mu.Unlock()
}

func (m *m1TXT) calledWith(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.calls {
		if c == name {
			return true
		}
	}
	return false
}

// m1Deferred blocks DNS resolution until released (createDeferred pair).
type m1Deferred struct {
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	records  []string
	count    int
	startAt  int
	startOne sync.Once
}

// m1BlockTXT makes lookupTXT block; started closes once startAt calls have begun.
func m1BlockTXT(m *m1TXT, startAt int) *m1Deferred {
	d := &m1Deferred{started: make(chan struct{}), release: make(chan struct{}), startAt: startAt}
	m.set(func(string) ([]string, error) {
		d.mu.Lock()
		d.count++
		if d.count >= d.startAt {
			d.startOne.Do(func() { close(d.started) })
		}
		d.mu.Unlock()
		<-d.release
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.records, nil
	})
	return d
}

func (d *m1Deferred) wait(t *testing.T) {
	t.Helper()
	select {
	case <-d.started:
	case <-time.After(10 * time.Second):
		t.Fatal("DNS lookup never started")
	}
}

func (d *m1Deferred) resolve(records ...[]string) {
	d.mu.Lock()
	for _, r := range records {
		d.records = append(d.records, strings.Join(r, ""))
	}
	d.mu.Unlock()
	d.once.Do(func() { close(d.release) })
}

type m1User struct{ email, password, name string }

var m1TestUser = m1User{email: "test@email.com", password: "password", name: "Test User"}

type m1DVEnv struct {
	*testEnv
}

// m1NewDVEnv mirrors createTestAuth (sso with domain verification + organization).
func m1NewDVEnv(t *testing.T, opts Options, mutate func(c *betterauth.Config)) *m1DVEnv {
	t.Helper()
	dv := DomainVerificationOptions{}
	if opts.DomainVerification != nil {
		dv = *opts.DomainVerification
	}
	dv.Enabled = true
	opts.DomainVerification = &dv
	env := newEnv(t, opts, envConfig{noTestUser: true, mutate: mutate,
		extraPlugins: []*betterauth.Plugin{organization.New(organization.Options{})}})
	return &m1DVEnv{env}
}

func (e *m1DVEnv) createOrganization(name string, headers http.Header) string {
	e.t.Helper()
	r := e.mustAPI("createOrganization", headers, map[string]any{"name": name, "slug": name}, nil)
	id, _ := r.m()["id"].(string)
	return id
}

// getAuthHeaders signs the user up (ignoring duplicates), optionally adds it to the
// organization as a member, and signs it in.
func (e *m1DVEnv) getAuthHeaders(u m1User, orgID string) http.Header {
	e.t.Helper()
	_, err := e.auth.API.Call(context.Background(), "signUpEmail", betterauth.CallInput{
		Body: map[string]any{"email": u.email, "password": u.password, "name": u.name}})
	if err == nil && orgID != "" {
		uid := m1UserID(e.testEnv, u.email)
		e.mustAPI("addMember", http.Header{}, map[string]any{"userId": uid, "role": "member", "organizationId": orgID}, nil)
	}
	return e.signIn(u.email, u.password)
}

func m1UserID(e *testEnv, email string) string {
	e.t.Helper()
	u, err := e.auth.Context().InternalAdapter.FindUserByEmail(context.Background(), email, false)
	if err != nil || u == nil {
		e.t.Fatalf("user %s not found: %v", email, err)
	}
	return u.User.ID
}

func (e *m1DVEnv) registerSSOProvider(headers http.Header, orgID string) map[string]any {
	e.t.Helper()
	body := map[string]any{
		"providerId": "saml-provider-1",
		"issuer":     "http://hello.com:8081",
		"domain":     "http://hello.com:8081",
		"samlConfig": map[string]any{
			"entryPoint":  "http://idp.com:",
			"cert":        "the-cert",
			"idpMetadata": map[string]any{"entityID": "http://idp.com"},
			"spMetadata":  map[string]any{},
		},
	}
	if orgID != "" {
		body["organizationId"] = orgID
	}
	return e.mustAPI("registerSSOProvider", headers, body, nil).m()
}

// m1ExpireVerification moves a verification value's expiry into the past (fake timers
// advanced by a week upstream).
func m1ExpireVerification(e *testEnv, identifier string) {
	e.t.Helper()
	_, err := e.auth.Context().Adapter.UpdateMany(context.Background(), "verification",
		[]adapter.Where{{Field: "identifier", Value: identifier}}, adapter.Record{"expiresAt": time.Now().Add(-time.Minute)})
	if err != nil {
		e.t.Fatal(err)
	}
}

func m1ExpectStatus(t *testing.T, r *result, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Raw)
	}
}

func m1ExpectJSON(t *testing.T, r *result, want map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(r.m(), want) {
		t.Fatalf("body = %s, want %v", r.Raw, want)
	}
}

// m1MatchObject mirrors toMatchObject for flat keys.
func m1MatchObject(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if wm, ok := v.(map[string]any); ok {
			gm, _ := got[k].(map[string]any)
			if gm == nil {
				t.Fatalf("%s: got %v, want object %v (full %v)", k, got[k], v, got)
			}
			m1MatchObject(t, gm, wm)
			continue
		}
		if !reflect.DeepEqual(got[k], v) {
			t.Fatalf("%s = %#v, want %#v (full %v)", k, got[k], v, got)
		}
	}
}

func m1Post(e *testEnv, path string, headers http.Header, body map[string]any) *result {
	e.t.Helper()
	return e.do("POST", path, headers, body)
}

var m1StaleProviderError = map[string]any{
	"code":    "SSO_PROVIDER_CHANGED",
	"message": "SSO provider changed while domain verification was in progress. Reload the provider and try again",
}

func TestMiscDomainVerification(t *testing.T) {
	other := m1User{name: "other", email: "other@test.com", password: "password"}
	forbidden := map[string]any{"message": "You don't have access to this provider"}

	t.Run("POST /sso/request-domain-verification", func(t *testing.T) {
		t.Run("should return unauthorized when session is missing", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			r := m1Post(e.testEnv, "/sso/request-domain-verification", nil, map[string]any{"providerId": "the-provider"})
			m1ExpectStatus(t, r, 401)
		})

		t.Run("should return not found when no provider is found", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			r := m1Post(e.testEnv, "/sso/request-domain-verification", h, map[string]any{"providerId": "unknown"})
			m1ExpectStatus(t, r, 404)
			m1ExpectJSON(t, r, map[string]any{"message": "Provider not found"})
		})

		t.Run("should return the existing active verification token", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			h2 := e.getAuthHeaders(m1TestUser, "")
			r := m1Post(e.testEnv, "/sso/request-domain-verification", h2, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 201)
			m1ExpectJSON(t, r, map[string]any{"domainVerificationToken": p["domainVerificationToken"]})
		})

		t.Run("should return forbidden if user does not own the provider", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			nh := e.getAuthHeaders(other, "")
			r := m1Post(e.testEnv, "/sso/request-domain-verification", nh, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 403)
			m1ExpectJSON(t, r, forbidden)
		})

		t.Run("should return forbidden if user does not belong to the provider organization", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			orgA := e.createOrganization("org-a", h)
			orgB := e.createOrganization("org-b", h)
			p := e.registerSSOProvider(h, orgA)
			nh := e.getAuthHeaders(other, orgB)
			r := m1Post(e.testEnv, "/sso/request-domain-verification", nh, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 403)
			m1ExpectJSON(t, r, forbidden)
		})

		t.Run("should return a new domain verification token", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			m1ExpireVerification(e.testEnv, "_better-auth-token-saml-provider-1")
			nh := e.getAuthHeaders(m1TestUser, "")
			r := m1Post(e.testEnv, "/sso/request-domain-verification", nh, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 201)
			if s, _ := r.m()["domainVerificationToken"].(string); s == "" {
				t.Fatalf("body %s", r.Raw)
			}
		})

		t.Run("allows a non-creator org admin to request verification for an org-owned provider", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			owner := e.getAuthHeaders(m1TestUser, "")
			org := e.createOrganization("org-with-admin", owner)
			p := e.registerSSOProvider(owner, org)
			admin := e.getAuthHeaders(m1User{name: "Org Admin", email: "org-admin@test.com", password: "password"}, "")
			s := e.session(admin)
			e.mustAPI("addMember", owner, map[string]any{"userId": s.User.ID, "role": "admin", "organizationId": org}, nil)
			r := m1Post(e.testEnv, "/sso/request-domain-verification", admin, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 201)
			if s, _ := r.m()["domainVerificationToken"].(string); s == "" {
				t.Fatalf("body %s", r.Raw)
			}
		})

		t.Run("should fail to create a new token on an already verified domain", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			dns.resolved([]string{"_better-auth-token-saml-provider-1=" + p["domainVerificationToken"].(string)})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 204)
			r2 := m1Post(e.testEnv, "/sso/request-domain-verification", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r2, 409)
			m1ExpectJSON(t, r2, map[string]any{"message": "Domain has already been verified", "code": "DOMAIN_VERIFIED"})
		})
	})

	t.Run("POST /sso/verify-domain", func(t *testing.T) {
		t.Run("should return unauthorized when session is missing", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			r := m1Post(e.testEnv, "/sso/verify-domain", nil, map[string]any{"providerId": "the-provider"})
			m1ExpectStatus(t, r, 401)
		})

		t.Run("should return not found when no provider is found", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": "unknown"})
			m1ExpectStatus(t, r, 404)
			m1ExpectJSON(t, r, map[string]any{"message": "Provider not found"})
		})

		t.Run("should return not found when no pending verification is found", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			m1ExpireVerification(e.testEnv, "_better-auth-token-saml-provider-1")
			nh := e.getAuthHeaders(m1TestUser, "")
			r := m1Post(e.testEnv, "/sso/verify-domain", nh, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 404)
			m1ExpectJSON(t, r, map[string]any{"message": "No pending domain verification exists", "code": "NO_PENDING_VERIFICATION"})
		})

		t.Run("should return bad gateway when unable to verify domain", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			dns.resolved([]string{"google-site-verification=the-token"})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 502)
			m1ExpectJSON(t, r, map[string]any{"message": "Unable to verify domain ownership for hello.com. Try again later", "code": "DOMAIN_VERIFICATION_FAILED"})
		})

		t.Run("should return bad gateway when the TXT record only contains the verification token as a substring", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			tok := p["domainVerificationToken"].(string)
			dns.resolved([]string{"prefix-" + tok + "-suffix"}, []string{"_better-auth-token-saml-provider-1=" + tok + "-suffix"})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 502)
			m1ExpectJSON(t, r, map[string]any{"message": "Unable to verify domain ownership for hello.com. Try again later", "code": "DOMAIN_VERIFICATION_FAILED"})
		})

		t.Run("should return forbidden if user does not own the provider", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			nh := e.getAuthHeaders(other, "")
			r := m1Post(e.testEnv, "/sso/verify-domain", nh, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 403)
			m1ExpectJSON(t, r, forbidden)
		})

		t.Run("should return forbidden if user does not belong to the provider organization", func(t *testing.T) {
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			orgA := e.createOrganization("org-a", h)
			orgB := e.createOrganization("org-b", h)
			p := e.registerSSOProvider(h, orgA)
			nh := e.getAuthHeaders(other, orgB)
			r := m1Post(e.testEnv, "/sso/verify-domain", nh, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 403)
			m1ExpectJSON(t, r, forbidden)
		})

		t.Run("should verify a provider domain ownership", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			if p["domain"] != "http://hello.com:8081" || p["domainVerified"] != false {
				t.Fatalf("provider %v", p)
			}
			tok, ok := p["domainVerificationToken"].(string)
			if !ok {
				t.Fatalf("token %v", p["domainVerificationToken"])
			}
			dns.resolved([]string{"google-site-verification=the-token"},
				[]string{"v=spf1 ip4:50.242.118.232/29 include:_spf.google.com include:mail.zendesk.com ~all"},
				[]string{"_better-auth-token-saml-provider-1=", tok})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 204)
			if !dns.calledWith("_better-auth-token-saml-provider-1.hello.com") {
				t.Fatalf("calls %v", dns.calls)
			}
		})

		t.Run("rejects a stale proof after a domain update with the memory adapter", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			d := m1BlockTXT(dns, 1)
			done := make(chan *result, 1)
			go func() {
				done <- m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			}()
			d.wait(t)
			up := m1Post(e.testEnv, "/sso/update-provider", h, map[string]any{"providerId": p["providerId"], "domain": "changed.example"})
			m1ExpectStatus(t, up, 200)
			d.resolve([]string{p["domainVerificationToken"].(string)})
			r := <-done
			m1ExpectStatus(t, r, 409)
			m1ExpectJSON(t, r, m1StaleProviderError)
			got := e.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": p["providerId"]})
			m1MatchObject(t, got.m(), map[string]any{"domain": "changed.example", "domainVerified": false})
		})

		t.Run("verifies a provider registered before domain verification was enabled", func(t *testing.T) {
			dns := m1MockTXT(t)
			shared := memory.NewDB()
			useShared := func(c *betterauth.Config) { c.Database = memory.New(shared) }
			legacy := newEnv(t, Options{}, envConfig{noTestUser: true, mutate: useShared})
			legacy.signUp(m1TestUser.email, m1TestUser.password, m1TestUser.name)
			lh := legacy.signIn(m1TestUser.email, m1TestUser.password)
			legacy.mustAPI("registerSSOProvider", lh, map[string]any{
				"providerId": "pre-upgrade-provider",
				"issuer":     "http://hello.com:8081",
				"domain":     "http://hello.com:8081",
				"samlConfig": map[string]any{
					"entryPoint":  "http://idp.com:",
					"cert":        "the-cert",
					"callbackUrl": "http://hello.com:8081/api/sso/saml2/callback",
					"idpMetadata": map[string]any{"entityID": "http://idp.com"},
					"spMetadata":  map[string]any{},
				},
			}, nil)
			rows := shared.Rows("ssoProvider")
			if len(rows) != 1 {
				t.Fatalf("rows %v", rows)
			}
			if _, has := rows[0]["domainVerified"]; has {
				t.Fatalf("precondition: domainVerified stored: %v", rows[0])
			}

			e := newEnv(t, Options{DomainVerification: &DomainVerificationOptions{Enabled: true}}, envConfig{noTestUser: true, mutate: useShared})
			h := e.signIn(m1TestUser.email, m1TestUser.password)
			req := e.mustAPI("requestDomainVerification", h, map[string]any{"providerId": "pre-upgrade-provider"}, nil)
			tok, _ := req.m()["domainVerificationToken"].(string)
			dns.resolved([]string{tok})
			r := m1Post(e, "/sso/verify-domain", h, map[string]any{"providerId": "pre-upgrade-provider"})
			m1ExpectStatus(t, r, 204)
			got := e.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "pre-upgrade-provider"})
			m1MatchObject(t, got.m(), map[string]any{"domainVerified": true})
		})

		t.Run("should verify a provider domain ownership (custom token verification prefix)", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{DomainVerification: &DomainVerificationOptions{TokenPrefix: "auth-prefix"}}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			dns.resolved([]string{"google-site-verification=the-token"},
				[]string{"v=spf1 ip4:50.242.118.232/29 include:_spf.google.com include:mail.zendesk.com ~all"},
				[]string{"_auth-prefix-saml-provider-1=" + p["domainVerificationToken"].(string)})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 204)
			if !dns.calledWith("_auth-prefix-saml-provider-1.hello.com") {
				t.Fatalf("calls %v", dns.calls)
			}
		})

		t.Run("should verify a provider domain ownership with a bare domain", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			e.mustAPI("registerSSOProvider", h, map[string]any{
				"providerId": "bare-domain-provider",
				"issuer":     "http://hello.com:8081",
				"domain":     "hello.com",
				"samlConfig": map[string]any{
					"entryPoint":  "http://idp.com:",
					"cert":        "the-cert",
					"idpMetadata": map[string]any{"entityID": "http://idp.com"},
					"spMetadata":  map[string]any{},
				},
			}, nil)
			req := m1Post(e.testEnv, "/sso/request-domain-verification", h, map[string]any{"providerId": "bare-domain-provider"})
			m1ExpectStatus(t, req, 201)
			tok, _ := req.m()["domainVerificationToken"].(string)
			dns.resolved([]string{"_better-auth-token-bare-domain-provider=" + tok})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": "bare-domain-provider"})
			m1ExpectStatus(t, r, 204)
			if !dns.calledWith("_better-auth-token-bare-domain-provider.hello.com") {
				t.Fatalf("calls %v", dns.calls)
			}
		})

		t.Run("should return bad request when provider ID exceeds DNS label limit", func(t *testing.T) {
			long := strings.Repeat("a", 50)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			e.mustAPI("registerSSOProvider", h, map[string]any{
				"providerId": long,
				"issuer":     "http://hello.com:8081",
				"domain":     "http://hello.com:8081",
				"samlConfig": map[string]any{
					"entryPoint":  "http://idp.com:",
					"cert":        "the-cert",
					"idpMetadata": map[string]any{"entityID": "http://idp.com"},
					"spMetadata":  map[string]any{},
				},
			}, nil)
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": long})
			m1ExpectStatus(t, r, 400)
			m1ExpectJSON(t, r, map[string]any{"message": "Verification identifier exceeds the DNS label limit of 63 characters", "code": "IDENTIFIER_TOO_LONG"})
		})

		t.Run("should fail to verify an already verified domain", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			dns.resolved([]string{"_better-auth-token-saml-provider-1=" + p["domainVerificationToken"].(string)})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 204)
			r2 := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r2, 409)
			m1ExpectJSON(t, r2, map[string]any{"message": "Domain has already been verified", "code": "DOMAIN_VERIFIED"})
		})

		t.Run("does not verify a URL-like multi-domain provider unless every later-accepted domain is owned", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			e.mustAPI("registerSSOProvider", h, map[string]any{
				"providerId": "multi-domain-provider",
				"issuer":     "https://idp.example.com",
				"domain":     "https://attacker.com/path,victim.com",
				"samlConfig": map[string]any{
					"entryPoint":  "http://idp.com:",
					"cert":        "the-cert",
					"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
					"callbackUrl": "http://hello.com:8081/api/sso/saml2/callback",
					"spMetadata":  map[string]any{},
				},
			}, nil)
			req := m1Post(e.testEnv, "/sso/request-domain-verification", h, map[string]any{"providerId": "multi-domain-provider"})
			tok, _ := req.m()["domainVerificationToken"].(string)
			dns.set(func(name string) ([]string, error) {
				if name == "_better-auth-token-multi-domain-provider.attacker.com" {
					return []string{"_better-auth-token-multi-domain-provider=" + tok}, nil
				}
				return []string{}, nil
			})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": "multi-domain-provider"})
			m1ExpectStatus(t, r, 502)
			m1ExpectJSON(t, r, map[string]any{"message": "Unable to verify domain ownership for victim.com. Try again later", "code": "DOMAIN_VERIFICATION_FAILED"})
			if !dns.calledWith("_better-auth-token-multi-domain-provider.victim.com") {
				t.Fatalf("calls %v", dns.calls)
			}
		})

		t.Run("verifies a multi-domain provider when every listed domain is owned", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, nil)
			h := e.getAuthHeaders(m1TestUser, "")
			e.mustAPI("registerSSOProvider", h, map[string]any{
				"providerId": "owned-multi-domain",
				"issuer":     "https://idp.company.example",
				"domain":     "company.com,subsidiary.com",
				"samlConfig": map[string]any{
					"entryPoint":  "http://idp.com:",
					"cert":        "the-cert",
					"idpMetadata": map[string]any{"entityID": "https://idp.company.example"},
					"callbackUrl": "http://hello.com:8081/api/sso/saml2/callback",
					"spMetadata":  map[string]any{},
				},
			}, nil)
			req := m1Post(e.testEnv, "/sso/request-domain-verification", h, map[string]any{"providerId": "owned-multi-domain"})
			tok, _ := req.m()["domainVerificationToken"].(string)
			dns.resolved([]string{tok})
			r := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": "owned-multi-domain"})
			m1ExpectStatus(t, r, 204)
			if !dns.calledWith("_better-auth-token-owned-multi-domain.company.com") || !dns.calledWith("_better-auth-token-owned-multi-domain.subsidiary.com") {
				t.Fatalf("calls %v", dns.calls)
			}
		})
	})

	t.Run("with secondaryStorage (no storeInDatabase)", func(t *testing.T) {
		t.Run("should request and verify domain verification via secondary storage", func(t *testing.T) {
			dns := m1MockTXT(t)
			e := m1NewDVEnv(t, Options{}, func(c *betterauth.Config) { c.SecondaryStorage = betterauth.NewMemoryStorage() })
			h := e.getAuthHeaders(m1TestUser, "")
			p := e.registerSSOProvider(h, "")
			tok, ok := p["domainVerificationToken"].(string)
			if !ok {
				t.Fatalf("token %v", p)
			}
			r := m1Post(e.testEnv, "/sso/request-domain-verification", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, r, 201)
			m1ExpectJSON(t, r, map[string]any{"domainVerificationToken": tok})
			dns.resolved([]string{"_better-auth-token-saml-provider-1=" + tok})
			v := m1Post(e.testEnv, "/sso/verify-domain", h, map[string]any{"providerId": p["providerId"]})
			m1ExpectStatus(t, v, 204)
		})
	})
}

// ---- domain-verification-concurrency.test.ts ----

type m1Harness struct {
	e *testEnv
	h http.Header
}

func m1NewHarness(t *testing.T) *m1Harness {
	t.Helper()
	e := newEnv(t, Options{DomainVerification: &DomainVerificationOptions{Enabled: true}})
	return &m1Harness{e: e, h: e.signInTestUser()}
}

func (m *m1Harness) request(method, path string, body map[string]any) *result {
	m.e.t.Helper()
	if body == nil {
		return m.e.do(method, path, m.h, nil)
	}
	return m.e.do(method, path, m.h, body)
}

func (m *m1Harness) registerProvider(t *testing.T, providerID, domain, audience, issuer string) map[string]any {
	t.Helper()
	if issuer == "" {
		issuer = "https://idp.example"
	}
	saml := map[string]any{
		"entryPoint":  issuer + "/sso",
		"cert":        "test-certificate",
		"callbackUrl": "http://localhost:3000/api/auth/sso/saml2/sp/acs/" + providerID,
		"idpMetadata": map[string]any{"entityID": issuer},
		"spMetadata":  map[string]any{},
	}
	if audience != "" {
		saml["audience"] = audience
	}
	r := m.request("POST", "/sso/register", map[string]any{"providerId": providerID, "issuer": issuer, "domain": domain, "samlConfig": saml})
	m1ExpectStatus(t, r, 200)
	return r.m()
}

func (m *m1Harness) getProvider(providerID string) (*result, map[string]any) {
	r := m.request("GET", "/sso/get-provider?providerId="+providerID, nil)
	if r.Status == 200 {
		return r, r.m()
	}
	return r, nil
}

func TestMiscDomainVerificationConcurrency(t *testing.T) {
	t.Run("domain verification concurrency", func(t *testing.T) {
		t.Run("rejects a DNS proof after the provider domain changes", func(t *testing.T) {
			dns := m1MockTXT(t)
			m := m1NewHarness(t)
			providerID, attacker, victim := "domain-update-race", "attacker.example", "victim.example"
			p := m.registerProvider(t, providerID, attacker, "", "")
			d := m1BlockTXT(dns, 1)
			done := make(chan *result, 1)
			go func() { done <- m.request("POST", "/sso/verify-domain", map[string]any{"providerId": providerID}) }()
			d.wait(t)
			up := m.request("POST", "/sso/update-provider", map[string]any{"providerId": providerID, "domain": victim})
			m1ExpectStatus(t, up, 200)
			d.resolve([]string{p["domainVerificationToken"].(string)})
			r := <-done
			m1ExpectStatus(t, r, 409)
			m1ExpectJSON(t, r, m1StaleProviderError)
			if !dns.calledWith("_better-auth-token-" + providerID + "." + attacker) {
				t.Fatalf("calls %v", dns.calls)
			}
			_, got := m.getProvider(providerID)
			m1MatchObject(t, got, map[string]any{"domain": victim, "domainVerified": false})
		})

		t.Run("keeps a later domain update unverified after verification completes", func(t *testing.T) {
			dns := m1MockTXT(t)
			m := m1NewHarness(t)
			providerID := "verify-before-update"
			p := m.registerProvider(t, providerID, "original.example", "", "")
			dns.resolved([]string{p["domainVerificationToken"].(string)})
			r := m.request("POST", "/sso/verify-domain", map[string]any{"providerId": providerID})
			m1ExpectStatus(t, r, 204)
			up := m.request("POST", "/sso/update-provider", map[string]any{"providerId": providerID, "domain": "changed.example"})
			m1ExpectStatus(t, up, 200)
			_, got := m.getProvider(providerID)
			m1MatchObject(t, got, map[string]any{"domain": "changed.example", "domainVerified": false})
		})

		t.Run("rejects a DNS proof after the provider is deleted", func(t *testing.T) {
			dns := m1MockTXT(t)
			m := m1NewHarness(t)
			providerID := "delete-race"
			p := m.registerProvider(t, providerID, "delete.example", "", "")
			d := m1BlockTXT(dns, 1)
			done := make(chan *result, 1)
			go func() { done <- m.request("POST", "/sso/verify-domain", map[string]any{"providerId": providerID}) }()
			d.wait(t)
			del := m.request("POST", "/sso/delete-provider", map[string]any{"providerId": providerID})
			m1ExpectStatus(t, del, 200)
			d.resolve([]string{p["domainVerificationToken"].(string)})
			r := <-done
			m1ExpectStatus(t, r, 409)
			m1ExpectJSON(t, r, m1StaleProviderError)
			gr, _ := m.getProvider(providerID)
			m1ExpectStatus(t, gr, 404)
		})

		t.Run("does not apply an old proof to a replacement with the same provider ID", func(t *testing.T) {
			dns := m1MockTXT(t)
			m := m1NewHarness(t)
			providerID := "replacement-race"
			orig := m.registerProvider(t, providerID, "original.example", "", "")
			d := m1BlockTXT(dns, 1)
			done := make(chan *result, 1)
			go func() { done <- m.request("POST", "/sso/verify-domain", map[string]any{"providerId": providerID}) }()
			d.wait(t)
			del := m.request("POST", "/sso/delete-provider", map[string]any{"providerId": providerID})
			m1ExpectStatus(t, del, 200)
			rep := m.registerProvider(t, providerID, "replacement.example", "", "https://replacement-idp.example")
			if rep["domainVerified"] != false {
				t.Fatalf("replacement %v", rep)
			}
			d.resolve([]string{orig["domainVerificationToken"].(string)})
			r := <-done
			m1ExpectStatus(t, r, 409)
			m1ExpectJSON(t, r, m1StaleProviderError)
			_, got := m.getProvider(providerID)
			m1MatchObject(t, got, map[string]any{"domain": "replacement.example", "domainVerified": false})
		})

		t.Run("verifies the domain when two simultaneous requests prove the same domain", func(t *testing.T) {
			dns := m1MockTXT(t)
			m := m1NewHarness(t)
			providerID, domain := "simultaneous-verification", "simultaneous.example"
			p := m.registerProvider(t, providerID, domain, "", "")
			d := m1BlockTXT(dns, 2)
			first, second := make(chan *result, 1), make(chan *result, 1)
			go func() { first <- m.request("POST", "/sso/verify-domain", map[string]any{"providerId": providerID}) }()
			go func() { second <- m.request("POST", "/sso/verify-domain", map[string]any{"providerId": providerID}) }()
			d.wait(t)
			d.resolve([]string{p["domainVerificationToken"].(string)})
			r1, r2 := <-first, <-second
			if r1.Status != 204 || r2.Status != 204 {
				t.Fatalf("statuses [%d %d] (%s / %s), want [204 204]", r1.Status, r2.Status, r1.Raw, r2.Raw)
			}
			_, got := m.getProvider(providerID)
			m1MatchObject(t, got, map[string]any{"domain": domain, "domainVerified": true})
		})

		t.Run("allows an unrelated provider update while DNS verification is in flight", func(t *testing.T) {
			dns := m1MockTXT(t)
			m := m1NewHarness(t)
			providerID, domain := "unrelated-update", "unchanged.example"
			p := m.registerProvider(t, providerID, domain, "original-audience", "")
			d := m1BlockTXT(dns, 1)
			done := make(chan *result, 1)
			go func() { done <- m.request("POST", "/sso/verify-domain", map[string]any{"providerId": providerID}) }()
			d.wait(t)
			up := m.request("POST", "/sso/update-provider", map[string]any{"providerId": providerID, "samlConfig": map[string]any{"audience": "updated-audience"}})
			m1ExpectStatus(t, up, 200)
			d.resolve([]string{p["domainVerificationToken"].(string)})
			r := <-done
			m1ExpectStatus(t, r, 204)
			_, got := m.getProvider(providerID)
			m1MatchObject(t, got, map[string]any{"domain": domain, "domainVerified": true,
				"samlConfig": map[string]any{"audience": "updated-audience"}})
		})
	})
}
