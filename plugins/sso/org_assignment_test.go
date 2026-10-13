package sso

// Ports of linking/org-assignment.test.ts and linking/org-assignment.security.test.ts.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/plugins/organization"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// m1OrgCtx mirrors createTestContext: sso (+domain verification) and organization on a
// memory database whose rows are seeded directly.
type m1OrgCtx struct {
	e *testEnv
}

func m1NewOrgCtx(t *testing.T, domainVerificationEnabled bool) *m1OrgCtx {
	t.Helper()
	opts := Options{}
	if domainVerificationEnabled {
		opts.DomainVerification = &DomainVerificationOptions{Enabled: true}
	}
	e := newEnv(t, opts, envConfig{noTestUser: true, extraPlugins: []*betterauth.Plugin{organization.New(organization.Options{})}})
	return &m1OrgCtx{e: e}
}

func (c *m1OrgCtx) insert(model string, data adapter.Record) {
	c.e.t.Helper()
	if _, err := c.e.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: model, Data: data, ForceAllowID: true}); err != nil {
		c.e.t.Fatalf("insert %s: %v", model, err)
	}
}

func (c *m1OrgCtx) members() []map[string]any { return c.e.rows("member") }

func (c *m1OrgCtx) membersOf(userID string) []map[string]any {
	var out []map[string]any
	for _, m := range c.members() {
		if m["userId"] == userID {
			out = append(out, m)
		}
	}
	return out
}

// endpointCtx is the (partial) GenericEndpointContext passed to the helpers.
func (c *m1OrgCtx) endpointCtx() *betterauth.EndpointContext {
	return &betterauth.EndpointContext{Auth: c.e.auth.Context()}
}

func m1CreateUser(over adapter.Record) adapter.Record {
	u := adapter.Record{"id": "user-1", "email": "alice@example.com", "name": "Alice", "emailVerified": true,
		"createdAt": time.Now(), "updatedAt": time.Now()}
	for k, v := range over {
		u[k] = v
	}
	return u
}

func m1CreateOrg(over adapter.Record) adapter.Record {
	o := adapter.Record{"id": "org-1", "name": "Test Org", "slug": "test-org", "createdAt": time.Now()}
	for k, v := range over {
		o[k] = v
	}
	return o
}

func m1CreateProvider(over adapter.Record) adapter.Record {
	p := adapter.Record{"id": "provider-1", "providerId": "test-provider", "issuer": "https://idp.example.com",
		"domain": "example.com", "domainVerified": false, "organizationId": "org-1", "userId": "user-1"}
	for k, v := range over {
		if v == nil {
			delete(p, k)
			continue
		}
		p[k] = v
	}
	return p
}

func m1ToUser(r adapter.Record) *betterauth.User {
	u := &betterauth.User{}
	u.ID, _ = r["id"].(string)
	u.Email, _ = r["email"].(string)
	u.Name, _ = r["name"].(string)
	u.EmailVerified, _ = r["emailVerified"].(bool)
	return u
}

// byDomain is assignOrganizationByDomain.
func (c *m1OrgCtx) byDomain(user adapter.Record, enabled bool) error {
	_, err := assignOrganization(c.endpointCtx(), assignOptions{reason: "verified-domain", user: m1ToUser(user), domainVerification: enabled})
	return err
}

func m1Len(t *testing.T, got []map[string]any, n int) {
	t.Helper()
	if len(got) != n {
		t.Fatalf("len = %d, want %d: %v", len(got), n, got)
	}
}

// m1FailingAdapter fails the next FindMany (vi.spyOn(...).mockRejectedValueOnce).
type m1FailingAdapter struct {
	adapter.Adapter
	failed bool
}

func (a *m1FailingAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	if !a.failed {
		a.failed = true
		return nil, errors.New("provider lookup failed")
	}
	return a.Adapter.FindMany(ctx, in)
}

func TestMiscAssignOrganizationByDomain(t *testing.T) {
	t.Run("assignOrganizationByDomain", func(t *testing.T) {
		t.Run("should NOT assign user to org when provider domain is unverified", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": false}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.membersOf("user-1"), 0)
		})

		t.Run("should assign user to org when provider domain is verified", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true, "organizationId": "org-1"}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m := c.membersOf("user-1")
			m1Len(t, m, 1)
			if m[0]["organizationId"] != "org-1" || m[0]["role"] != "member" {
				t.Fatalf("member %v", m[0])
			}
		})

		t.Run("should assign user when a verified provider's normalized domain set includes the email domain", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domain": "https://attacker.com/path,victim.com", "domainVerified": true, "organizationId": "org-1"}))
			u := m1CreateUser(adapter.Record{"email": "alice@victim.com"})
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m := c.membersOf("user-1")
			m1Len(t, m, 1)
			if m[0]["organizationId"] != "org-1" {
				t.Fatalf("member %v", m[0])
			}
		})

		t.Run("should find a matching verified provider beyond the default adapter page", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			for i := 0; i < 100; i++ {
				c.insert("ssoProvider", m1CreateProvider(adapter.Record{
					"id": fmt.Sprintf("unrelated-provider-%d", i), "providerId": fmt.Sprintf("unrelated-provider-%d", i),
					"domain": fmt.Sprintf("unrelated-%d.example", i), "domainVerified": true, "organizationId": nil}))
			}
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"id": "zz-matching-provider", "providerId": "zz-matching-provider",
				"domainVerified": true, "organizationId": "org-1"}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m := c.members()
			m1Len(t, m, 1)
			if m[0]["organizationId"] != "org-1" {
				t.Fatalf("member %v", m[0])
			}
		})

		t.Run("should NOT assign user when the email domain is malformed", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domain": "victim.com", "domainVerified": true, "organizationId": "org-1"}))
			u := m1CreateUser(adapter.Record{"email": "alice@https://victim.com/path"})
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.membersOf("user-1"), 0)
		})

		t.Run("should NOT assign user when email domain does not match any provider", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true}))
			u := m1CreateUser(adapter.Record{"email": "alice@other-domain.com"})
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.membersOf("user-1"), 0)
		})

		t.Run("should NOT assign user when provider has no organizationId", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true, "organizationId": nil}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.membersOf("user-1"), 0)
		})

		t.Run("should NOT assign user when provider has no domainVerified field (verification enabled)", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": nil, "organizationId": "org-1"}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.membersOf("user-1"), 0)
		})

		t.Run("should NOT assign user when domain verification is disabled", func(t *testing.T) {
			c := m1NewOrgCtx(t, false)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": nil, "organizationId": "org-1"}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			if err := c.byDomain(u, false); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.membersOf("user-1"), 0)
		})

		t.Run("should NOT assign user when already a member of the org", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true, "organizationId": "org-1"}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			c.insert("member", adapter.Record{"id": "member-1", "organizationId": "org-1", "userId": "user-1", "role": "admin", "createdAt": time.Now()})
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m := c.membersOf("user-1")
			m1Len(t, m, 1)
			if m[0]["role"] != "admin" {
				t.Fatalf("member %v", m[0])
			}
		})

		for _, order := range [][]string{{"unverified", "verified"}, {"verified", "unverified"}} {
			name := fmt.Sprintf("should only find the verified provider when multiple providers claim the same domain (%s)", m1FormatOrder(order))
			t.Run(name, func(t *testing.T) {
				c := m1NewOrgCtx(t, true)
				c.insert("organization", m1CreateOrg(adapter.Record{"id": "legit-org", "name": "Legit Org", "slug": "legit-org"}))
				c.insert("organization", m1CreateOrg(adapter.Record{"id": "attacker-org", "name": "Attacker Org", "slug": "attacker-org"}))
				providers := map[string]adapter.Record{
					"unverified": m1CreateProvider(adapter.Record{"id": "attacker-provider", "providerId": "attacker-provider",
						"issuer": "https://attacker.com", "domainVerified": false, "organizationId": "attacker-org"}),
					"verified": m1CreateProvider(adapter.Record{"id": "legit-provider", "providerId": "legit-provider",
						"domainVerified": true, "organizationId": "legit-org"}),
				}
				for _, k := range order {
					c.insert("ssoProvider", providers[k])
				}
				u := m1CreateUser(nil)
				c.insert("user", u)
				if err := c.byDomain(u, true); err != nil {
					t.Fatal(err)
				}
				m := c.membersOf("user-1")
				m1Len(t, m, 1)
				if m[0]["organizationId"] != "legit-org" {
					t.Fatalf("member %v", m[0])
				}
			})
		}

		for _, order := range [][]string{{"first", "second"}, {"second", "first"}} {
			name := fmt.Sprintf("should NOT assign user when verified providers map one domain to different organizations (%s)", m1FormatOrder(order))
			t.Run(name, func(t *testing.T) {
				c := m1NewOrgCtx(t, true)
				c.insert("organization", m1CreateOrg(adapter.Record{"id": "first-org", "name": "First Org", "slug": "first-org"}))
				c.insert("organization", m1CreateOrg(adapter.Record{"id": "second-org", "name": "Second Org", "slug": "second-org"}))
				providers := map[string]adapter.Record{
					"first": m1CreateProvider(adapter.Record{"id": "first-provider", "providerId": "first-provider",
						"domainVerified": true, "organizationId": "first-org"}),
					"second": m1CreateProvider(adapter.Record{"id": "second-provider", "providerId": "second-provider",
						"domainVerified": true, "organizationId": "second-org"}),
				}
				for _, k := range order {
					c.insert("ssoProvider", providers[k])
				}
				u := m1CreateUser(nil)
				c.insert("user", u)
				if err := c.byDomain(u, true); err != nil {
					t.Fatal(err)
				}
				m1Len(t, c.membersOf("user-1"), 0)
			})
		}

		t.Run("should assign once when verified providers map one domain to the same organization", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"id": "second-provider", "providerId": "second-provider", "domainVerified": true, "organizationId": "org-1"}))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"id": "first-provider", "providerId": "first-provider", "domainVerified": true, "organizationId": "org-1"}))
			u := m1CreateUser(nil)
			c.insert("user", u)
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m := c.members()
			m1Len(t, m, 1)
			if m[0]["organizationId"] != "org-1" {
				t.Fatalf("member %v", m[0])
			}
		})

		t.Run("should require the canonical stored user email to be verified", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true, "organizationId": "org-1"}))
			callbackUser := m1CreateUser(adapter.Record{"emailVerified": true})
			c.insert("user", m1CreateUser(adapter.Record{"emailVerified": false}))
			if err := c.byDomain(callbackUser, true); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.members(), 0)
		})

		t.Run("should use a freshly verified canonical user instead of stale callback state", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true, "organizationId": "org-1"}))
			callbackUser := m1CreateUser(adapter.Record{"emailVerified": false})
			c.insert("user", m1CreateUser(adapter.Record{"emailVerified": true}))
			if err := c.byDomain(callbackUser, true); err != nil {
				t.Fatal(err)
			}
			m := c.membersOf("user-1")
			m1Len(t, m, 1)
			if m[0]["organizationId"] != "org-1" {
				t.Fatalf("member %v", m[0])
			}
		})

		t.Run("should skip automatic membership while an invitation is pending", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			u := m1CreateUser(nil)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("user", u)
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true, "organizationId": "org-1"}))
			c.insert("invitation", adapter.Record{"id": "invitation-1", "email": u["email"], "organizationId": "org-1", "inviterId": "inviter-1",
				"role": "admin", "status": "pending", "expiresAt": time.Now().Add(time.Minute)})
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m1Len(t, c.members(), 0)
			inv := c.e.rows("invitation")
			m1Len(t, inv, 1)
			if inv[0]["id"] != "invitation-1" || inv[0]["status"] != "pending" || inv[0]["role"] != "admin" || inv[0]["email"] != u["email"] {
				t.Fatalf("invitation %v", inv[0])
			}
		})

		t.Run("should ignore an expired pending invitation", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			u := m1CreateUser(nil)
			c.insert("organization", m1CreateOrg(nil))
			c.insert("user", u)
			c.insert("ssoProvider", m1CreateProvider(adapter.Record{"domainVerified": true, "organizationId": "org-1"}))
			c.insert("invitation", adapter.Record{"id": "expired-invitation", "email": u["email"], "organizationId": "org-1", "inviterId": "inviter-1",
				"role": "admin", "status": "pending", "expiresAt": time.Now().Add(-time.Minute)})
			if err := c.byDomain(u, true); err != nil {
				t.Fatal(err)
			}
			m := c.members()
			m1Len(t, m, 1)
			if m[0]["organizationId"] != "org-1" {
				t.Fatalf("member %v", m[0])
			}
		})

		t.Run("should surface adapter failures instead of treating them as ineligibility", func(t *testing.T) {
			c := m1NewOrgCtx(t, true)
			u := m1CreateUser(nil)
			c.insert("user", u)
			ac := *c.e.auth.Context()
			ac.Adapter = &m1FailingAdapter{Adapter: ac.Adapter}
			_, err := assignOrganization(&betterauth.EndpointContext{Auth: &ac}, assignOptions{reason: "verified-domain", user: m1ToUser(u), domainVerification: true})
			if err == nil || !strings.Contains(err.Error(), "provider lookup failed") {
				t.Fatalf("err = %v, want provider lookup failed", err)
			}
		})
	})
}

func m1FormatOrder(order []string) string {
	// vitest formats $insertionOrder arrays as [ 'a', 'b' ].
	q := make([]string, len(order))
	for i, o := range order {
		q[i] = "'" + o + "'"
	}
	return "[ " + strings.Join(q, ", ") + " ]"
}

func TestMiscAssignOrganizationFromProvider(t *testing.T) {
	t.Run("assignOrganizationFromProvider", func(t *testing.T) {
		for _, providerType := range []string{"oidc", "saml"} {
			t.Run("should preserve direct "+providerType+" organization provisioning without domain verification", func(t *testing.T) {
				c := m1NewOrgCtx(t, false)
				u := m1CreateUser(nil)
				org := m1CreateOrg(adapter.Record{"name": "Enterprise", "slug": "enterprise"})
				prov := m1CreateProvider(adapter.Record{"providerId": "enterprise-provider", "userId": "owner-1", "domainVerified": nil, "organizationId": org["id"]})
				c.insert("user", u)
				c.insert("organization", org)
				c.insert("ssoProvider", prov)
				provider, _, _ := providerFromRecord(prov)
				_, err := assignOrganization(c.endpointCtx(), assignOptions{reason: "provider-bound", user: m1ToUser(u), provider: provider,
					profile: &normalizedProfile{ProviderType: providerType, ProviderID: "enterprise-provider", AccountID: "enterprise-account",
						Email: u["email"].(string), EmailVerified: true}})
				if err != nil {
					t.Fatal(err)
				}
				m := c.members()
				m1Len(t, m, 1)
				if m[0]["organizationId"] != org["id"] || m[0]["role"] != "member" || m[0]["userId"] != "user-1" {
					t.Fatalf("member %v", m[0])
				}
			})
		}
	})
}

// ---- org-assignment.security.test.ts ----

const (
	m1TestDomain = "verified-corp.test"
	m1TestEmail  = "employee@" + m1TestDomain
)

type m1SecInstance struct {
	e    *testEnv
	mock *oauth2test.Server
}

// m1MockGoogleToken mocks the Google token endpoint with an id token for TEST_EMAIL.
func m1MockGoogleToken(t *testing.T, emailVerified bool, subject string) *oauth2test.Server {
	t.Helper()
	mock := oauth2test.New(t)
	idToken := mock.IDToken(map[string]any{"aud": "test", "azp": "test", "email": m1TestEmail, "email_verified": emailVerified,
		"iss": "https://accounts.google.com", "name": "Verified Employee", "sub": subject})
	mock.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{"access_token": "test-access-token", "expires_in": 3600,
		"id_token": idToken, "token_type": "Bearer"})
	return mock
}

func m1NewSecInstance(t *testing.T, mock *oauth2test.Server) *m1SecInstance {
	t.Helper()
	e := newEnv(t, Options{DomainVerification: &DomainVerificationOptions{Enabled: true}}, envConfig{
		extraPlugins: []*betterauth.Plugin{organization.New(organization.Options{})},
		mutate: func(c *betterauth.Config) {
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}})}
		},
	})
	return &m1SecInstance{e: e, mock: mock}
}

// registerOrganizationProvider creates the target organization and an SSO provider
// claiming TEST_DOMAIN for it.
func (s *m1SecInstance) registerOrganizationProvider(t *testing.T, domainVerified bool) string {
	t.Helper()
	h := s.e.signInTestUser()
	org := s.e.mustAPI("createOrganization", h, map[string]any{"name": "Target Organization", "slug": "target-organization"}, nil)
	orgID, _ := org.m()["id"].(string)
	if orgID == "" {
		t.Fatal("Target organization was not created")
	}
	s.e.mustAPI("registerSSOProvider", h, map[string]any{
		"domain": m1TestDomain, "issuer": "https://idp.example.test", "organizationId": orgID, "providerId": "target-provider",
		"samlConfig": map[string]any{
			"audience": "target-provider", "callbackUrl": "http://localhost:3000/api/auth/sso/callback", "cert": "test-certificate",
			"entryPoint": "https://idp.example.test/sso", "idpMetadata": map[string]any{"entityID": "https://idp.example.test"},
			"spMetadata": map[string]any{}, "wantAssertionsSigned": true,
		},
	}, nil)
	if domainVerified {
		if _, err := s.e.auth.Context().Adapter.Update(context.Background(), "ssoProvider",
			[]adapter.Where{{Field: "providerId", Value: "target-provider"}}, adapter.Record{"domainVerified": true}); err != nil {
			t.Fatal(err)
		}
	}
	return orgID
}

func m1StateOf(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	st := u.Query().Get("state")
	if st == "" {
		t.Fatal("OAuth state was not created")
	}
	return st
}

// signInWithGoogle drives a full Google sign-in and returns the resulting user row.
func (s *m1SecInstance) signInWithGoogle(t *testing.T) map[string]any {
	t.Helper()
	res := s.e.do("POST", "/sign-in/social", nil, map[string]any{"callbackURL": "/signed-in", "provider": "google"})
	authURL, _ := res.m()["url"].(string)
	if authURL == "" {
		t.Fatalf("Google authorization URL was not created: %s", res.Raw)
	}
	state := m1StateOf(t, authURL)
	cb := s.e.do("GET", "/callback/google?code=test-authorization-code&state="+url.QueryEscape(state), cookieHeaders(res.Headers), nil)
	if cb.Status != 302 {
		t.Fatalf("callback status %d %s", cb.Status, cb.Raw)
	}
	u := s.findOne("user", []adapter.Where{{Field: "email", Value: m1TestEmail}})
	if u == nil {
		t.Fatalf("Google sign-in did not produce a user for %s", m1TestEmail)
	}
	return u
}

// linkGoogleToExistingUser signs up a verified email-password user and links Google.
func (s *m1SecInstance) linkGoogleToExistingUser(t *testing.T) (http.Header, string) {
	t.Helper()
	res, err := s.e.auth.API.Call(context.Background(), "signUpEmail", betterauth.CallInput{
		Body: map[string]any{"email": m1TestEmail, "name": "Existing User", "password": "test-password"}})
	if err != nil {
		t.Fatalf("Existing user was not created: %v", err)
	}
	h := cookieHeaders(res.Headers)
	userID := m1UserID(s.e, m1TestEmail)
	if _, err := s.e.auth.Context().Adapter.Update(context.Background(), "user", []adapter.Where{{Field: "id", Value: userID}},
		adapter.Record{"emailVerified": true}); err != nil {
		t.Fatal(err)
	}
	link := s.e.do("POST", "/link-social", h, map[string]any{"callbackURL": "/settings", "provider": "google"})
	authURL, _ := link.m()["url"].(string)
	if authURL == "" {
		t.Fatalf("Google account-link URL was not created: %s", link.Raw)
	}
	h = mergeCookies(h, link.Headers)
	state := m1StateOf(t, authURL)
	s.e.do("GET", "/callback/google?code=test-link-code&state="+url.QueryEscape(state), h, nil)
	return h, userID
}

func (s *m1SecInstance) findOne(model string, where []adapter.Where) adapter.Record {
	r, err := s.e.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: model, Where: where})
	if err != nil {
		s.e.t.Fatal(err)
	}
	return r
}

func (s *m1SecInstance) membership(orgID, userID string) adapter.Record {
	return s.findOne("member", []adapter.Where{{Field: "organizationId", Value: orgID}, {Field: "userId", Value: userID}})
}

func TestMiscOrgAssignmentSecurity(t *testing.T) {
	t.Run("SSO verified-domain organization assignment", func(t *testing.T) {
		t.Run("does not auto-join a social-login user through an unverified SSO domain claim", func(t *testing.T) {
			s := m1NewSecInstance(t, m1MockGoogleToken(t, true, "unverified-domain"))
			target := s.registerOrganizationProvider(t, false)
			u := s.signInWithGoogle(t)
			if m := s.membership(target, u["id"].(string)); m != nil {
				t.Fatalf("unexpected membership %v", m)
			}
		})

		t.Run("auto-joins a verified social-login user through a verified SSO domain", func(t *testing.T) {
			s := m1NewSecInstance(t, m1MockGoogleToken(t, true, "verified-social"))
			target := s.registerOrganizationProvider(t, true)
			u := s.signInWithGoogle(t)
			if m := s.membership(target, u["id"].(string)); m == nil {
				t.Fatal("expected membership")
			}
		})

		t.Run("does not auto-join when the social provider does not verify the email", func(t *testing.T) {
			s := m1NewSecInstance(t, m1MockGoogleToken(t, false, "unverified-social"))
			target := s.registerOrganizationProvider(t, true)
			u := s.signInWithGoogle(t)
			if u["emailVerified"] != false {
				t.Fatalf("emailVerified = %v", u["emailVerified"])
			}
			if m := s.membership(target, u["id"].(string)); m != nil {
				t.Fatalf("unexpected membership %v", m)
			}
		})

		t.Run("does not auto-join while a social account is linked to an existing user", func(t *testing.T) {
			s := m1NewSecInstance(t, m1MockGoogleToken(t, true, "linked-social"))
			target := s.registerOrganizationProvider(t, true)
			_, userID := s.linkGoogleToExistingUser(t)
			if a := s.findOne("account", []adapter.Where{{Field: "providerId", Value: "google"}, {Field: "userId", Value: userID}}); a == nil {
				t.Fatal("google account was not linked")
			}
			if m := s.membership(target, userID); m != nil {
				t.Fatalf("unexpected membership %v", m)
			}
		})

		t.Run("auto-joins the linked user on their next social sign-in", func(t *testing.T) {
			s := m1NewSecInstance(t, m1MockGoogleToken(t, true, "linked-social"))
			target := s.registerOrganizationProvider(t, true)
			h, userID := s.linkGoogleToExistingUser(t)
			s.e.do("POST", "/sign-out", h, map[string]any{})
			s.signInWithGoogle(t)
			if m := s.membership(target, userID); m == nil {
				t.Fatal("expected membership")
			}
		})
	})
}
