package sso

// Port of upstream providers.test.ts (lines 1213-end): the "POST /sso/update-provider",
// "ssoProvider additionalFields", "POST /sso/delete-provider" and "POST /sso/register"
// describes of "SSO provider read endpoints", plus "SSO providerId namespace collisions".

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/internal/testdb"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/plugins/organization"
	"github.com/nimi-io/better-auth-go/providers/google"
	_ "modernc.org/sqlite"
)

const p2TestCert = `MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcm9markup
temporary cert for testing`

const p2ValidCustomSPMetadata = `
	<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
		<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
			<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
		</SPSSODescriptor>
	</EntityDescriptor>
`

var p2InvalidCustomSPMetadata = []struct{ name, metadata string }{
	{"malformed XML", "<EntityDescriptor><SPSSODescriptor>"},
	{"a missing entity ID", `
			<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
				<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</SPSSODescriptor>
			</EntityDescriptor>
		`},
	{"a missing POST assertion consumer service", `
			<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
				<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://service.example.com/saml/acs" />
				</SPSSODescriptor>
			</EntityDescriptor>
		`},
	{"an invalid WantAssertionsSigned lexical value", `
			<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
				<SPSSODescriptor WantAssertionsSigned="TRUE" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</SPSSODescriptor>
			</EntityDescriptor>
		`},
	{"an unqualified metadata tree", `
			<EntityDescriptor entityID="https://service.example.com/saml">
				<SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</SPSSODescriptor>
			</EntityDescriptor>
		`},
	{"a foreign metadata root with a namespace decoy", `
			<foreign:EntityDescriptor xmlns:foreign="urn:example:foreign" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://service.example.com/saml">
				<md:EntityDescriptor entityID="https://service.example.com/saml">
					<md:SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
						<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
					</md:SPSSODescriptor>
				</md:EntityDescriptor>
			</foreign:EntityDescriptor>
		`},
	{"a foreign service-provider descriptor", `
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
				<foreign:SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</foreign:SPSSODescriptor>
			</md:EntityDescriptor>
		`},
	{"a valid descriptor followed by a foreign descriptor", `
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
				<md:SPSSODescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</md:SPSSODescriptor>
				<foreign:SPSSODescriptor WantAssertionsSigned="true">
					<foreign:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attacker.example.com/saml/acs" />
				</foreign:SPSSODescriptor>
			</md:EntityDescriptor>
		`},
	{"a foreign POST endpoint before a valid endpoint", `
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
				<md:SPSSODescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<foreign:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://attacker.example.com/saml/acs" />
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		`},
	{"a foreign NameID format before a valid format", `
			<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:foreign="urn:example:foreign" entityID="https://service.example.com/saml">
				<md:SPSSODescriptor WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<foreign:NameIDFormat>urn:example:attacker</foreign:NameIDFormat>
					<md:NameIDFormat>urn:example:valid</md:NameIDFormat>
					<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />
				</md:SPSSODescriptor>
			</md:EntityDescriptor>
		`},
}

func p2CustomIdPMetadata(signingCertificate string) string {
	return `
		<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
			<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
				<KeyDescriptor use="signing">
					<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
						<ds:X509Data>
							<ds:X509Certificate>` + signingCertificate + `</ds:X509Certificate>
						</ds:X509Data>
					</ds:KeyInfo>
				</KeyDescriptor>
				<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso" />
			</IDPSSODescriptor>
		</EntityDescriptor>
	`
}

// ---- adapter wrapper ----

type p2TxMarker struct{}

// p2Adapter wraps the auth adapter: it can disable native transactions (the upstream
// `adapterConfig.transaction = false` toggle) and run a hook before every ssoProvider
// update issued inside a transaction (interceptSSOProviderLockUpdate).
type p2Adapter struct {
	adapter.Adapter
	mu           sync.Mutex
	nonNative    bool
	onLockUpdate func()
}

func (w *p2Adapter) setNonNative() {
	w.mu.Lock()
	w.nonNative = true
	w.mu.Unlock()
}

func (w *p2Adapter) setLockHook(fn func()) {
	w.mu.Lock()
	w.onLockUpdate = fn
	w.mu.Unlock()
}

func (w *p2Adapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	w.mu.Lock()
	nonNative := w.nonNative
	w.mu.Unlock()
	if nonNative {
		return fn(ctx, w)
	}
	return w.Adapter.Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error {
		return fn(context.WithValue(txCtx, p2TxMarker{}, true), w)
	})
}

func (w *p2Adapter) Update(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (adapter.Record, error) {
	w.mu.Lock()
	hook := w.onLockUpdate
	w.mu.Unlock()
	if model == "ssoProvider" && hook != nil && ctx.Value(p2TxMarker{}) != nil {
		hook()
	}
	return w.Adapter.Update(ctx, model, where, update)
}

// PlanMigrations delegates to the wrapped adapter's migrator.
func (w *p2Adapter) PlanMigrations(ctx context.Context, schema *db.Schema) (*adapter.MigrationPlan, error) {
	m, ok := adapter.AsMigrator(w.Adapter)
	if !ok {
		return nil, adapter.ErrMigrationsNotSupported
	}
	return m.PlanMigrations(ctx, schema)
}

func p2WrapFactory(inner adapter.Factory, w *p2Adapter) adapter.Factory {
	return func(opts adapter.Options) (adapter.Adapter, error) {
		a, err := inner(opts)
		if err != nil {
			return nil, err
		}
		w.Adapter = a
		return w, nil
	}
}

// ---- createTestAuth ----

type p2Auth struct {
	*testEnv
	w *p2Adapter
}

// p2CreateTestAuth mirrors createTestAuth (memory adapter, no default user).
func p2CreateTestAuth(t *testing.T, includeOrgPlugin, enableDomainVerification bool, o Options) *p2Auth {
	t.Helper()
	if enableDomainVerification {
		o.DomainVerification = &DomainVerificationOptions{Enabled: true}
	}
	var extra []*betterauth.Plugin
	if includeOrgPlugin {
		extra = append(extra, organization.New(organization.Options{}))
	}
	w := &p2Adapter{}
	env := newEnv(t, o, envConfig{noTestUser: true, extraPlugins: extra, mutate: func(c *betterauth.Config) {
		c.Database = p2WrapFactory(c.Database, w)
	}})
	return &p2Auth{testEnv: env, w: w}
}

func (a *p2Auth) getAuthHeaders(email, password, name string) http.Header {
	a.t.Helper()
	a.signUp(email, password, name)
	return a.signIn(email, password)
}

func (a *p2Auth) userID(email string) string {
	a.t.Helper()
	for _, u := range a.rows("user") {
		if u["email"] == email {
			return fmt.Sprint(u["id"])
		}
	}
	a.t.Fatalf("user %s not found", email)
	return ""
}

func (a *p2Auth) createOrganization(name string, headers http.Header) string {
	a.t.Helper()
	r := a.mustAPI("createOrganization", headers, map[string]any{"name": name, "slug": name}, nil)
	id, _ := r.m()["id"].(string)
	if id == "" {
		a.t.Fatalf("createOrganization: %s", r.Raw)
	}
	return id
}

func (a *p2Auth) addMember(userID, orgID, role string, headers http.Header) {
	a.t.Helper()
	a.mustAPI("addMember", headers, map[string]any{"userId": userID, "role": role, "organizationId": orgID}, nil)
}

func p2SAMLBody(providerID, orgID string, extra map[string]any) map[string]any {
	body := map[string]any{
		"providerId": providerID,
		"issuer":     "https://idp.example.com",
		"domain":     "example.com",
		"samlConfig": map[string]any{
			"entryPoint":           "https://idp.example.com/sso",
			"cert":                 p2TestCert,
			"audience":             "my-audience",
			"wantAssertionsSigned": true,
			"idpMetadata":          map[string]any{"entityID": "https://idp.example.com"},
			"spMetadata":           map[string]any{},
		},
	}
	if orgID != "" {
		body["organizationId"] = orgID
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// registerSAMLProvider returns the raw result (callers decide whether it must succeed).
func (a *p2Auth) registerSAMLProvider(headers http.Header, providerID, orgID string, extra map[string]any) *result {
	a.t.Helper()
	return a.api("registerSSOProvider", headers, p2SAMLBody(providerID, orgID, extra), nil)
}

func (a *p2Auth) mustRegisterSAML(headers http.Header, providerID, orgID string, extra map[string]any) *result {
	a.t.Helper()
	r := a.registerSAMLProvider(headers, providerID, orgID, extra)
	if r.Err != nil {
		a.t.Fatalf("registerSSOProvider %s: %d %s", providerID, r.Status, r.Raw)
	}
	return r
}

func (a *p2Auth) createOIDCProviderData(userID, providerID, clientID, orgID string) {
	a.t.Helper()
	cfg, _ := json.Marshal(map[string]any{
		"clientId":          clientID,
		"clientSecret":      "super-secret-value",
		"discoveryEndpoint": "https://idp.example.com/.well-known",
		"pkce":              true,
	})
	data := adapter.Record{
		"id": "oidc-" + providerID, "providerId": providerID, "issuer": "https://idp.example.com",
		"domain": "example.com", "userId": userID, "oidcConfig": string(cfg),
	}
	if orgID != "" {
		data["organizationId"] = orgID
	}
	if _, err := a.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "ssoProvider", Data: data, ForceAllowID: true}); err != nil {
		a.t.Fatal(err)
	}
}

func (a *p2Auth) pushAccount(data adapter.Record) {
	a.t.Helper()
	if _, ok := data["createdAt"]; !ok {
		data["createdAt"] = time.Now()
	}
	if _, ok := data["updatedAt"]; !ok {
		data["updatedAt"] = time.Now()
	}
	if _, err := a.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: "account", Data: data, ForceAllowID: true}); err != nil {
		a.t.Fatal(err)
	}
}

func (a *p2Auth) providerRows() []map[string]any { return a.rows("ssoProvider") }

func (a *p2Auth) update(headers http.Header, body map[string]any) *result {
	a.t.Helper()
	return a.api("updateSSOProvider", headers, body, nil)
}

func (a *p2Auth) mustUpdate(headers http.Header, body map[string]any) *result {
	a.t.Helper()
	r := a.update(headers, body)
	if r.Err != nil {
		a.t.Fatalf("updateSSOProvider: %d %s", r.Status, r.Raw)
	}
	return r
}

func p2Get(m map[string]any, path ...string) any {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		v, ok := mm[k]
		if !ok {
			return nil
		}
		cur = v
	}
	return cur
}

func p2Has(m map[string]any, path ...string) bool {
	cur := m
	for i, k := range path {
		v, ok := cur[k]
		if !ok {
			return false
		}
		if i == len(path)-1 {
			return true
		}
		cur, ok = v.(map[string]any)
		if !ok {
			return false
		}
	}
	return false
}

func p2ExpectStatus(t *testing.T, r *result, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Raw)
	}
}

func p2ExpectError(t *testing.T, r *result, status int, code, message string) {
	t.Helper()
	if r.Err == nil {
		t.Fatalf("expected error %d, got success: %s", status, r.Raw)
	}
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s %s)", r.Status, status, r.code(), r.message())
	}
	if code != "" && r.code() != code {
		t.Fatalf("code = %q, want %q (message %q)", r.code(), code, r.message())
	}
	if message != "" && r.message() != message {
		t.Fatalf("message = %q, want %q", r.message(), message)
	}
}

// p2BoundaryRecorder records the update guard's isAuthenticationBoundaryChange.
type p2BoundaryRecorder struct {
	mu         sync.Mutex
	set        bool
	boundary   bool
	serialized string
}

func (b *p2BoundaryRecorder) guard(_ context.Context, in ProviderMutationGuardInput, _ ProviderMutationGuardContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if in.Action == "update" {
		b.set = true
		b.boundary = in.IsAuthenticationBoundaryChange
	}
	raw, _ := json.Marshal(in)
	b.serialized = string(raw)
	return nil
}

func (b *p2BoundaryRecorder) expect(t *testing.T, want bool) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.set {
		t.Fatalf("guard was not called for update")
	}
	if b.boundary != want {
		t.Fatalf("isAuthenticationBoundaryChange = %v, want %v", b.boundary, want)
	}
}

// ---- SQL-backed environments ----

// p2NewSQLEnv builds an env on a SQL database with migrations applied (getHttpTestInstance
// with transactions), then signs up the default test user.
func p2NewSQLEnv(t *testing.T, conn *sql.DB, o Options, w *p2Adapter, mutate func(c *betterauth.Config)) *testEnv {
	t.Helper()
	env := newEnv(t, o, envConfig{noTestUser: true, mutate: func(c *betterauth.Config) {
		c.Database = p2WrapFactory(sqladapter.New(conn, sqladapter.Config{Transaction: betterauth.Bool(true)}), w)
		if mutate != nil {
			mutate(c)
		}
	}})
	if err := env.auth.RunMigrations(context.Background()); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return env
}

// p2StartOIDCIdentityProvider mirrors startOIDCIdentityProvider.
func p2StartOIDCIdentityProvider(t *testing.T, subject string) *mockOIDC {
	idp := newMockOIDC(t)
	idp.BeforeUserinfo = func(r *mockResponse, _ *http.Request) {
		r.Body = map[string]any{"sub": subject, "email": "employee@example.com", "name": "Directory Employee", "email_verified": true}
		r.StatusCode = 200
	}
	idp.BeforeTokenSigning = func(p map[string]any, _ *http.Request) {
		p["sub"] = subject
		p["email"] = "employee@example.com"
		p["name"] = "Directory Employee"
		p["email_verified"] = true
	}
	return idp
}

// p2CompleteOIDCSignIn mirrors completeOIDCSignIn.
func p2CompleteOIDCSignIn(env *testEnv, providerID string) oidcFlowResult {
	origin := env.server.URL
	res := env.do("POST", "/sign-in/sso", nil, map[string]any{"providerId": providerID, "callbackURL": origin + "/employee"})
	authURL, _ := res.m()["url"].(string)
	if authURL == "" {
		env.t.Errorf("sign-in/sso: %d %s", res.Status, res.Raw)
		return oidcFlowResult{}
	}
	return env.simulateOAuthFlow(authURL, cookieHeaders(res.Headers))
}

func p2Chan() (chan struct{}, func()) {
	ch := make(chan struct{})
	var once sync.Once
	return ch, func() { once.Do(func() { close(ch) }) }
}

func p2Wait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// p2LockObserver mirrors createProviderLockAttemptObserver.
type p2LockObserver struct {
	mu                   sync.Mutex
	count                int
	first, second        chan struct{}
	resolveF, resolveSec func()
}

func newP2LockObserver() *p2LockObserver {
	o := &p2LockObserver{}
	o.first, o.resolveF = p2Chan()
	o.second, o.resolveSec = p2Chan()
	return o
}

func (o *p2LockObserver) record() {
	o.mu.Lock()
	o.count++
	n := o.count
	o.mu.Unlock()
	if n == 1 {
		o.resolveF()
	}
	if n == 2 {
		o.resolveSec()
	}
}

func p2SessionUserID(t *testing.T, env *testEnv, h http.Header) string {
	t.Helper()
	s := env.session(h)
	if s == nil || s.User == nil {
		t.Fatal("no session")
	}
	return s.User.ID
}

// ---- tests ----

func TestProviders2UpdateProvider(t *testing.T) {
	ctx := context.Background()

	for _, action := range []string{"update", "delete"} {
		t.Run(fmt.Sprintf("does not %s a same-alias Postgres replacement when the authorized row disappears before locking", action), func(t *testing.T) {
			conn := testdb.Postgres(t)
			var guardMu sync.Mutex
			guardCalls := 0
			w := &p2Adapter{}
			env := p2NewSQLEnv(t, conn, Options{GuardProviderMutation: func(context.Context, ProviderMutationGuardInput, ProviderMutationGuardContext) error {
				guardMu.Lock()
				guardCalls++
				guardMu.Unlock()
				return nil
			}}, w, nil)
			env.signUp(testEmail, testPassword, testName)
			owner := env.signInTestUser()
			ownerID := p2SessionUserID(t, env, owner)
			a := env.auth.Context().Adapter
			authorized, err := a.Create(ctx, adapter.CreateInput{Model: "ssoProvider", Data: adapter.Record{
				"issuer": "https://identity.example.com", "domain": "example.com",
				"oidcConfig": `{"issuer":"https://identity.example.com","clientId":"workforce-client","clientSecret":"workforce-secret"}`,
				"samlConfig": nil, "userId": ownerID, "providerId": "replaced-provider", "organizationId": nil,
			}})
			if err != nil {
				t.Fatal(err)
			}
			replacement := adapter.Record{}
			for k, v := range authorized {
				replacement[k] = v
			}
			replacement["id"] = "same-alias-replacement"
			replacement["domain"] = "replacement.example.com"
			replaced := false
			w.setLockHook(func() {
				if replaced {
					return
				}
				replaced = true
				bg := context.Background()
				if err := a.Delete(bg, "ssoProvider", []adapter.Where{{Field: "id", Value: authorized["id"]}}); err != nil {
					t.Error(err)
				}
				if _, err := a.Create(bg, adapter.CreateInput{Model: "ssoProvider", Data: replacement, ForceAllowID: true}); err != nil {
					t.Error(err)
				}
				if _, err := a.Create(bg, adapter.CreateInput{Model: "account", Data: adapter.Record{
					"id": "replacement-account", "userId": replacement["userId"], "providerId": replacement["providerId"],
					"accountId": "replacement-subject", "createdAt": time.Now(), "updatedAt": time.Now(),
				}, ForceAllowID: true}); err != nil {
					t.Error(err)
				}
			})
			var r *result
			if action == "update" {
				r = env.api("updateSSOProvider", owner, map[string]any{"providerId": authorized["providerId"], "domain": "mutated.example.com"}, nil)
			} else {
				r = env.api("deleteSSOProvider", owner, map[string]any{"providerId": authorized["providerId"]}, nil)
			}
			p2ExpectError(t, r, 404, "", "")
			guardMu.Lock()
			if guardCalls != 0 {
				t.Fatalf("guardCalls = %d", guardCalls)
			}
			guardMu.Unlock()
			got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "id", Value: "same-alias-replacement"}}})
			if err != nil || got == nil || got["providerId"] != replacement["providerId"] || got["domain"] != "replacement.example.com" {
				t.Fatalf("replacement = %v (%v)", got, err)
			}
			acc, err := a.FindOne(ctx, adapter.FindOneInput{Model: "account", Where: []adapter.Where{{Field: "id", Value: "replacement-account"}}})
			if err != nil || acc == nil || acc["providerId"] != replacement["providerId"] || acc["accountId"] != "replacement-subject" {
				t.Fatalf("account = %v (%v)", acc, err)
			}
		})
	}

	t.Run("runs the provider mutation guard inside the update transaction before writing", func(t *testing.T) {
		var observedProviderID string
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: func(ctx context.Context, in ProviderMutationGuardInput, gc ProviderMutationGuardContext) error {
			rec, _ := gc.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "id", Value: in.Provider.ID}}})
			if rec != nil {
				observedProviderID, _ = rec["providerId"].(string)
			}
			if _, err := gc.Adapter.Update(ctx, "ssoProvider", []adapter.Where{{Field: "id", Value: in.Provider.ID}}, adapter.Record{"domain": "must-rollback.example.com"}); err != nil {
				return err
			}
			return fmt.Errorf("reject")
		}})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "guarded-update", "", nil)
		r := env.update(headers, map[string]any{"providerId": "guarded-update", "domain": "updated.example.com"})
		p2ExpectError(t, r, 409, "SSO_PROVIDER_MUTATION_REJECTED", "SSO provider mutation is not allowed")
		if observedProviderID != "guarded-update" {
			t.Fatalf("observedProviderId = %q", observedProviderID)
		}
		for _, row := range env.providerRows() {
			if row["providerId"] == "guarded-update" && row["domain"] != "example.com" {
				t.Fatalf("domain = %v", row["domain"])
			}
		}
	})

	t.Run("classifies OIDC secret rotation outside the authentication boundary without exposing secrets", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.createOIDCProviderData(env.userID("owner@example.com"), "secret-rotation", "workforce-client", "")
		env.mustUpdate(headers, map[string]any{"providerId": "secret-rotation", "oidcConfig": map[string]any{"clientSecret": "rotated-secret-value"}})
		rec.expect(t, false)
		for _, s := range []string{"super-secret-value", "rotated-secret-value", "clientSecret"} {
			if strings.Contains(rec.serialized, s) {
				t.Fatalf("guard input exposes %q: %s", s, rec.serialized)
			}
		}
	})

	t.Run("classifies the signed-assertion policy as an authentication-boundary change", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "signature-policy-change", "", nil)
		env.mustUpdate(headers, map[string]any{"providerId": "signature-policy-change", "samlConfig": map[string]any{"wantAssertionsSigned": false}})
		rec.expect(t, true)
	})

	t.Run("classifies an overlapping manual IdP signing-certificate rotation as an authentication-boundary change", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "certificate-rotation", "", nil)
		env.mustUpdate(headers, map[string]any{"providerId": "certificate-rotation", "samlConfig": map[string]any{"cert": []any{p2TestCert, "rotated-signing-certificate"}}})
		rec.expect(t, true)
		if strings.Contains(rec.serialized, p2TestCert) || strings.Contains(rec.serialized, "rotated-signing-certificate") {
			t.Fatalf("guard input exposes certificates: %s", rec.serialized)
		}
	})

	t.Run("classifies IdP metadata certificate replacement as an authentication-boundary change", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "metadata-certificate-replacement", "", map[string]any{"samlConfig": map[string]any{
			"entryPoint": "https://idp.example.com/sso", "wantAssertionsSigned": true,
			"idpMetadata": map[string]any{"metadata": p2CustomIdPMetadata("original-signing-certificate")},
			"spMetadata":  map[string]any{},
		}})
		env.mustUpdate(headers, map[string]any{"providerId": "metadata-certificate-replacement", "samlConfig": map[string]any{
			"idpMetadata": map[string]any{"metadata": p2CustomIdPMetadata("replacement-signing-certificate")},
		}})
		rec.expect(t, true)
	})

	t.Run("classifies an SP private-key rotation outside the authentication boundary without exposing it", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "sp-private-key-rotation", "", nil)
		env.mustUpdate(headers, map[string]any{"providerId": "sp-private-key-rotation", "samlConfig": map[string]any{
			"spMetadata": map[string]any{"privateKey": "rotated-sp-private-key"},
		}})
		rec.expect(t, false)
		if strings.Contains(rec.serialized, "rotated-sp-private-key") {
			t.Fatalf("guard input exposes key: %s", rec.serialized)
		}
	})

	customMetadataBody := func(metadata string) map[string]any {
		return map[string]any{"samlConfig": map[string]any{
			"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "wantAssertionsSigned": false,
			"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
			"spMetadata":  map[string]any{"metadata": metadata},
		}}
	}

	for _, tc := range []struct{ name, metadata string }{
		{"entity ID", strings.Replace(p2ValidCustomSPMetadata, "https://service.example.com/saml", "https://replacement.example.com/saml", 1)},
		{"POST assertion consumer service", strings.Replace(p2ValidCustomSPMetadata, "https://service.example.com/saml/acs", "https://service.example.com/replacement-acs", 1)},
	} {
		t.Run("classifies a custom SP metadata "+tc.name+" change as an authentication-boundary change", func(t *testing.T) {
			rec := &p2BoundaryRecorder{}
			env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
			headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
			env.mustRegisterSAML(headers, "custom-metadata-boundary", "", customMetadataBody(p2ValidCustomSPMetadata))
			env.mustUpdate(headers, map[string]any{"providerId": "custom-metadata-boundary", "samlConfig": map[string]any{"spMetadata": map[string]any{"metadata": tc.metadata}}})
			rec.expect(t, true)
		})
	}

	t.Run("treats unparseable stored SP metadata as an authentication-boundary change instead of throwing", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "legacy-metadata-boundary", "", customMetadataBody(p2ValidCustomSPMetadata))
		row := env.providerRows()[0]
		var stored map[string]any
		if err := json.Unmarshal([]byte(fmt.Sprint(row["samlConfig"])), &stored); err != nil {
			t.Fatal(err)
		}
		stored["spMetadata"].(map[string]any)["metadata"] = "<EntityDescriptor><SPSSODescriptor>"
		raw, _ := json.Marshal(stored)
		if _, err := env.auth.Context().Adapter.Update(ctx, "ssoProvider", []adapter.Where{{Field: "id", Value: row["id"]}}, adapter.Record{"samlConfig": string(raw)}); err != nil {
			t.Fatal(err)
		}
		r := env.update(headers, map[string]any{"providerId": "legacy-metadata-boundary", "samlConfig": map[string]any{"spMetadata": map[string]any{"metadata": p2ValidCustomSPMetadata}}})
		p2ExpectStatus(t, r, 200)
		rec.expect(t, true)
	})

	t.Run("classifies the effective custom SP NameIDFormat as an authentication-boundary change", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		metadata := strings.Replace(p2ValidCustomSPMetadata, "<AssertionConsumerService", "<NameIDFormat>urn:example:name-id:original</NameIDFormat><AssertionConsumerService", 1)
		env.mustRegisterSAML(headers, "custom-name-id-boundary", "", customMetadataBody(metadata))
		env.mustUpdate(headers, map[string]any{"providerId": "custom-name-id-boundary", "samlConfig": map[string]any{"spMetadata": map[string]any{
			"metadata": strings.Replace(metadata, "urn:example:name-id:original", "urn:example:name-id:replacement", 1),
		}}})
		rec.expect(t, true)
	})

	t.Run("classifies an additional POST ACS with the same selected final ACS as an authentication-boundary change", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "custom-multiple-acs-boundary", "", customMetadataBody(p2ValidCustomSPMetadata))
		withEarlier := strings.Replace(p2ValidCustomSPMetadata, "<AssertionConsumerService",
			`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/earlier-acs" /><AssertionConsumerService`, 1)
		env.mustUpdate(headers, map[string]any{"providerId": "custom-multiple-acs-boundary", "samlConfig": map[string]any{"spMetadata": map[string]any{"metadata": withEarlier}}})
		rec.expect(t, true)
	})

	t.Run("classifies reordered custom POST ACS endpoints as an authentication-boundary change", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		originalAcs := `<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/acs" />`
		additionalAcs := `<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.example.com/saml/additional-acs" />`
		metadata := strings.Replace(p2ValidCustomSPMetadata, originalAcs, additionalAcs+originalAcs, 1)
		env.mustRegisterSAML(headers, "custom-acs-order-boundary", "", customMetadataBody(metadata))
		env.mustUpdate(headers, map[string]any{"providerId": "custom-acs-order-boundary", "samlConfig": map[string]any{"spMetadata": map[string]any{
			"metadata": strings.Replace(metadata, additionalAcs+originalAcs, originalAcs+additionalAcs, 1),
		}}})
		rec.expect(t, true)
	})

	t.Run("does not classify a raw identifierFormat change when custom metadata overrides it", func(t *testing.T) {
		rec := &p2BoundaryRecorder{}
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: rec.guard})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		metadata := strings.Replace(p2ValidCustomSPMetadata, "<AssertionConsumerService", "<NameIDFormat>urn:example:name-id:metadata</NameIDFormat><AssertionConsumerService", 1)
		body := customMetadataBody(metadata)
		body["samlConfig"].(map[string]any)["identifierFormat"] = "urn:example:name-id:raw-original"
		env.mustRegisterSAML(headers, "custom-name-id-override", "", body)
		env.mustUpdate(headers, map[string]any{"providerId": "custom-name-id-override", "samlConfig": map[string]any{"identifierFormat": "urn:example:name-id:raw-replacement"}})
		rec.expect(t, false)
	})

	t.Run("rejects a guarded update when the adapter has no native transaction", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: func(context.Context, ProviderMutationGuardInput, ProviderMutationGuardContext) error { return nil }})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "fallback-update", "", nil)
		env.w.setNonNative()
		r := env.update(headers, map[string]any{"providerId": "fallback-update", "domain": "updated.example.com"})
		p2ExpectError(t, r, 501, "SSO_PROVIDER_MUTATION_GUARD_REQUIRES_NATIVE_TRANSACTIONS", "")
	})

	t.Run("should return 401 when not authenticated", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		r := env.update(nil, map[string]any{"providerId": "test", "domain": "new-domain.com"})
		p2ExpectStatus(t, r, 401)
	})

	t.Run("should return 404 when provider not found", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		headers := env.getAuthHeaders("test@example.com", "password123", "Test User")
		r := env.update(headers, map[string]any{"providerId": "nonexistent", "domain": "new-domain.com"})
		p2ExpectStatus(t, r, 404)
	})

	t.Run("should return 403 when user does not own provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(ownerHeaders, "other-provider", "", nil)
		otherHeaders := env.getAuthHeaders("other@example.com", "password123", "Other User")
		r := env.update(otherHeaders, map[string]any{"providerId": "other-provider", "domain": "new-domain.com"})
		p2ExpectStatus(t, r, 403)
	})

	t.Run("should update domain and reset domainVerified to false", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, true, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-saml-provider", "domain": "new-domain.com"}).m()
		if updated["domain"] != "new-domain.com" {
			t.Fatalf("domain = %v", updated["domain"])
		}
		if updated["domainVerified"] != false {
			t.Fatalf("domainVerified = %v", updated["domainVerified"])
		}
	})

	t.Run("should perform partial update on SAML provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-saml-provider", "samlConfig": map[string]any{
			"audience": "new-audience", "wantAssertionsSigned": false,
		}}).m()
		if v := p2Get(updated, "samlConfig", "audience"); v != "new-audience" {
			t.Fatalf("audience = %v", v)
		}
		if v := p2Get(updated, "samlConfig", "wantAssertionsSigned"); v != false {
			t.Fatalf("wantAssertionsSigned = %v", v)
		}
		if v := p2Get(updated, "samlConfig", "entryPoint"); v != "https://idp.example.com/sso" {
			t.Fatalf("entryPoint = %v", v)
		}
	})

	for _, tc := range p2InvalidCustomSPMetadata {
		t.Run("rejects custom SP metadata with "+tc.name+" before updating the provider", func(t *testing.T) {
			guardCalls := 0
			env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: func(context.Context, ProviderMutationGuardInput, ProviderMutationGuardContext) error {
				guardCalls++
				return nil
			}})
			headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
			env.mustRegisterSAML(headers, "invalid-metadata-update", "", nil)
			storedBefore := env.providerRows()[0]["samlConfig"]
			r := env.update(headers, map[string]any{"providerId": "invalid-metadata-update", "samlConfig": map[string]any{
				"wantAssertionsSigned": false, "spMetadata": map[string]any{"metadata": tc.metadata},
			}})
			p2ExpectError(t, r, 400, "SAML_INVALID_SP_METADATA", "Invalid SAML service provider metadata")
			rows := env.providerRows()
			if len(rows) != 1 || rows[0]["samlConfig"] != storedBefore {
				t.Fatalf("provider changed: %v", rows)
			}
			if guardCalls != 0 {
				t.Fatalf("guardCalls = %d", guardCalls)
			}
		})
	}

	t.Run("rejects oversized custom SP metadata before updating the provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{SAML: &SAMLOptions{MaxMetadataSize: 32}})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "oversized-metadata-update", "", nil)
		storedBefore := env.providerRows()[0]["samlConfig"]
		r := env.update(headers, map[string]any{"providerId": "oversized-metadata-update", "samlConfig": map[string]any{
			"wantAssertionsSigned": false, "spMetadata": map[string]any{"metadata": strings.Repeat("x", 33)},
		}})
		p2ExpectError(t, r, 400, "", "SP metadata exceeds maximum allowed size (32 bytes)")
		rows := env.providerRows()
		if len(rows) != 1 || rows[0]["samlConfig"] != storedBefore {
			t.Fatalf("provider changed: %v", rows)
		}
	})

	t.Run("should clear a provider-level IdP-initiated callback URL", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustAPI("registerSSOProvider", headers, map[string]any{
			"providerId": "my-saml-provider", "issuer": "https://idp.example.com", "domain": "example.com",
			"samlConfig": map[string]any{
				"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "idpInitiatedCallbackUrl": "/dashboard",
				"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
			},
		}, nil)
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-saml-provider", "samlConfig": map[string]any{"idpInitiatedCallbackUrl": nil}}).m()
		if p2Has(updated, "samlConfig", "idpInitiatedCallbackUrl") {
			t.Fatalf("idpInitiatedCallbackUrl still returned: %v", updated["samlConfig"])
		}
		var stored map[string]any
		_ = json.Unmarshal([]byte(fmt.Sprint(env.providerRows()[0]["samlConfig"])), &stored)
		if _, ok := stored["idpInitiatedCallbackUrl"]; ok {
			t.Fatalf("stored idpInitiatedCallbackUrl = %v", stored["idpInitiatedCallbackUrl"])
		}
	})

	t.Run("should perform partial update on OIDC provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.createOIDCProviderData(env.userID("owner@example.com"), "my-oidc-provider", "client123", "")
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-oidc-provider", "oidcConfig": map[string]any{
			"scopes": []any{"openid", "email", "profile", "custom"}, "pkce": false,
		}}).m()
		if v := p2Get(updated, "oidcConfig", "scopes"); !reflect.DeepEqual(v, []any{"openid", "email", "profile", "custom"}) {
			t.Fatalf("scopes = %v", v)
		}
		if v := p2Get(updated, "oidcConfig", "pkce"); v != false {
			t.Fatalf("pkce = %v", v)
		}
	})

	t.Run("should update issuer", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-saml-provider", "issuer": "https://new-issuer.example.com"}).m()
		if updated["issuer"] != "https://new-issuer.example.com" {
			t.Fatalf("issuer = %v", updated["issuer"])
		}
	})

	t.Run("rejects issuer updates when linked account rows exist", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		env.pushAccount(adapter.Record{"id": "linked-saml-account", "userId": env.userID("owner@example.com"), "providerId": "my-saml-provider", "accountId": "saml-account-id"})
		r := env.update(headers, map[string]any{"providerId": "my-saml-provider", "issuer": "https://new-issuer.example.com"})
		p2ExpectStatus(t, r, 409)
	})

	t.Run("allows same-value issuer updates when linked account rows exist", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		env.pushAccount(adapter.Record{"id": "linked-saml-account", "userId": env.userID("owner@example.com"), "providerId": "my-saml-provider", "accountId": "saml-account-id"})
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-saml-provider", "issuer": "https://idp.example.com"}).m()
		if updated["issuer"] != "https://idp.example.com" {
			t.Fatalf("issuer = %v", updated["issuer"])
		}
	})

	t.Run("rejects OIDC client id updates when linked account rows exist", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		uid := env.userID("owner@example.com")
		env.createOIDCProviderData(uid, "my-oidc-provider", "client123", "")
		env.pushAccount(adapter.Record{"id": "linked-oidc-account", "userId": uid, "providerId": "my-oidc-provider", "accountId": "oidc-account-id"})
		r := env.update(headers, map[string]any{"providerId": "my-oidc-provider", "oidcConfig": map[string]any{"clientId": "new-client-id"}})
		p2ExpectStatus(t, r, 409)
	})

	t.Run("allows OIDC secret rotation with same identity fields when linked account rows exist", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		uid := env.userID("owner@example.com")
		env.createOIDCProviderData(uid, "my-oidc-provider", "client123", "")
		env.pushAccount(adapter.Record{"id": "linked-oidc-account", "userId": uid, "providerId": "my-oidc-provider", "accountId": "oidc-account-id"})
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-oidc-provider", "oidcConfig": map[string]any{
			"clientId": "client123", "clientSecret": "rotated-secret-value", "discoveryEndpoint": "https://idp.example.com/.well-known",
		}}).m()
		if v := p2Get(updated, "oidcConfig", "clientIdLastFour"); v != "****t123" {
			t.Fatalf("clientIdLastFour = %v", v)
		}
	})

	t.Run("allows OIDC client secret updates when linked account rows exist", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		uid := env.userID("owner@example.com")
		env.createOIDCProviderData(uid, "my-oidc-provider", "client123", "")
		env.pushAccount(adapter.Record{"id": "linked-oidc-account", "userId": uid, "providerId": "my-oidc-provider", "accountId": "oidc-account-id"})
		updated := env.mustUpdate(headers, map[string]any{"providerId": "my-oidc-provider", "oidcConfig": map[string]any{"clientSecret": "new-secret"}}).m()
		if v := p2Get(updated, "oidcConfig", "clientIdLastFour"); v != "****t123" {
			t.Fatalf("clientIdLastFour = %v", v)
		}
	})

	t.Run("should return 400 when issuer is invalid URL", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		r := env.update(headers, map[string]any{"providerId": "my-saml-provider", "issuer": "invalid-url"})
		p2ExpectStatus(t, r, 400)
	})

	t.Run("should return 400 when SAML callbackUrl contains a fragment", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		r := env.api("registerSSOProvider", headers, map[string]any{
			"providerId": "fragment-callback-provider", "issuer": "https://idp.example.com", "domain": "example.com",
			"samlConfig": map[string]any{
				"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert,
				"callbackUrl": "http://localhost:3000/dashboard#saml", "spMetadata": map[string]any{},
			},
		}, nil)
		p2ExpectStatus(t, r, 400)
	})

	t.Run("should return 400 when no fields provided", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		r := env.update(headers, map[string]any{"providerId": "my-saml-provider"})
		p2ExpectStatus(t, r, 400)
	})

	t.Run("should allow org admin to update org provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		org := env.createOrganization("test-org", ownerHeaders)
		env.mustRegisterSAML(ownerHeaders, "org-provider", org, nil)
		adminHeaders := env.getAuthHeaders("admin@example.com", "password123", "Admin")
		env.addMember(env.userID("admin@example.com"), org, "admin", ownerHeaders)
		updated := env.mustUpdate(adminHeaders, map[string]any{"providerId": "org-provider", "domain": "new-domain.com"}).m()
		if updated["domain"] != "new-domain.com" {
			t.Fatalf("domain = %v", updated["domain"])
		}
	})

	t.Run("should return 403 when org member tries to update org provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		org := env.createOrganization("test-org", ownerHeaders)
		env.mustRegisterSAML(ownerHeaders, "org-provider", org, nil)
		memberHeaders := env.getAuthHeaders("member@example.com", "password123", "Member")
		env.addMember(env.userID("member@example.com"), org, "member", ownerHeaders)
		r := env.update(memberHeaders, map[string]any{"providerId": "org-provider", "domain": "new-domain.com"})
		p2ExpectStatus(t, r, 403)
	})

	t.Run("should return 400 when trying to update SAML config for OIDC provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.createOIDCProviderData(env.userID("owner@example.com"), "my-oidc-provider", "client123", "")
		r := env.update(headers, map[string]any{"providerId": "my-oidc-provider", "samlConfig": map[string]any{
			"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "spMetadata": map[string]any{},
		}})
		p2ExpectStatus(t, r, 400)
	})

	t.Run("should return 400 when trying to update OIDC config for SAML provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		r := env.update(headers, map[string]any{"providerId": "my-saml-provider", "oidcConfig": map[string]any{
			"clientId": "new-client-id", "clientSecret": "new-secret",
		}})
		p2ExpectStatus(t, r, 400)
	})
}

func p2AdditionalFieldsOptions() Options {
	return Options{Schema: &SchemaOptions{AdditionalFields: []db.Field{
		{Name: "displayName", Type: db.TypeString, Required: db.True},
		{Name: "internalCode", Type: db.TypeString, Required: db.False, Returned: db.Bool(false)},
		{Name: "source", Type: db.TypeString, Required: db.False, Input: db.Bool(false), DefaultValue: "system"},
	}}}
}

func p2ExpectPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		t.Helper()
		r := recover()
		if r == nil {
			t.Fatalf("expected panic %q", want)
		}
		msg := fmt.Sprint(r)
		if err, ok := r.(error); ok {
			msg = err.Error()
		}
		if !strings.Contains(msg, want) {
			t.Fatalf("panic = %q, want %q", msg, want)
		}
	}()
	fn()
}

func TestProviders2AdditionalFields(t *testing.T) {
	t.Run("should require configured additional fields on register", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, p2AdditionalFieldsOptions())
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		r := env.api("registerSSOProvider", headers, map[string]any{
			"providerId": "missing-display-name", "issuer": "https://idp.example.com", "domain": "example.com",
			"samlConfig": map[string]any{
				"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert,
				"callbackUrl": "http://localhost:3000/api/sso/callback", "spMetadata": map[string]any{},
			},
		}, nil)
		p2ExpectStatus(t, r, 400)
	})

	t.Run("should store and return visible additional fields", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, p2AdditionalFieldsOptions())
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		registered := env.mustRegisterSAML(headers, "okta", "", map[string]any{"displayName": "Okta", "internalCode": "secret"}).m()
		check := func(what string, m map[string]any) {
			t.Helper()
			if m["displayName"] != "Okta" || m["source"] != "system" {
				t.Fatalf("%s: displayName=%v source=%v", what, m["displayName"], m["source"])
			}
			if _, ok := m["internalCode"]; ok {
				t.Fatalf("%s: internalCode returned", what)
			}
		}
		check("registered", registered)
		row := env.providerRows()[0]
		if row["displayName"] != "Okta" || row["internalCode"] != "secret" || row["source"] != "system" {
			t.Fatalf("stored row = %v", row)
		}
		listed := env.mustAPI("listSSOProviders", headers, nil, nil).m()
		providers, _ := listed["providers"].([]any)
		if len(providers) == 0 {
			t.Fatalf("listed = %v", listed)
		}
		first, _ := providers[0].(map[string]any)
		check("listed", first)
		fetched := env.mustAPI("getSSOProvider", headers, nil, map[string]any{"providerId": "okta"}).m()
		check("fetched", fetched)
	})

	t.Run("should reject additional field keys that collide with built-in provider fields", func(t *testing.T) {
		p2ExpectPanic(t, `ssoProvider additional field "providerId" conflicts with a built-in field`, func() {
			p2CreateTestAuth(t, false, false, Options{Schema: &SchemaOptions{AdditionalFields: []db.Field{
				{Name: "providerId", Type: db.TypeString, Required: db.False},
			}}})
		})
	})

	t.Run("should reject additional field keys that collide with returned provider fields", func(t *testing.T) {
		p2ExpectPanic(t, `ssoProvider additional field "type" conflicts with a returned provider field`, func() {
			p2CreateTestAuth(t, false, false, Options{Schema: &SchemaOptions{AdditionalFields: []db.Field{
				{Name: "type", Type: db.TypeString, Required: db.False},
			}}})
		})
	})

	t.Run("should reject additional fields that map to built-in provider columns", func(t *testing.T) {
		p2ExpectPanic(t, `ssoProvider additional field "displayName" maps to built-in field "providerId"`, func() {
			p2CreateTestAuth(t, false, false, Options{Schema: &SchemaOptions{AdditionalFields: []db.Field{
				{Name: "displayName", Type: db.TypeString, Required: db.False, FieldName: "providerId"},
			}}})
		})
	})

	t.Run("should reject input false additional fields on register", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, p2AdditionalFieldsOptions())
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		r := env.registerSAMLProvider(headers, "okta", "", map[string]any{"displayName": "Okta", "source": "client"})
		if r.Err == nil || !strings.Contains(r.message(), "source is not allowed to be set") {
			t.Fatalf("expected rejection, got %d %s", r.Status, r.Raw)
		}
		if n := len(env.providerRows()); n != 0 {
			t.Fatalf("providers = %d", n)
		}
	})

	t.Run("should update additional fields", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, p2AdditionalFieldsOptions())
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "okta", "", map[string]any{"displayName": "Okta"})
		updated := env.mustUpdate(headers, map[string]any{"providerId": "okta", "displayName": "Okta Workforce"}).m()
		if updated["displayName"] != "Okta Workforce" {
			t.Fatalf("displayName = %v", updated["displayName"])
		}
	})

	t.Run("should reject input false additional fields on update", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, p2AdditionalFieldsOptions())
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "okta", "", map[string]any{"displayName": "Okta"})
		r := env.update(headers, map[string]any{"providerId": "okta", "source": "client"})
		if r.Err == nil || !strings.Contains(r.message(), "source is not allowed to be set") {
			t.Fatalf("expected rejection, got %d %s", r.Status, r.Raw)
		}
	})

	t.Run("should infer sso provider additional fields", func(t *testing.T) {
		t.Skip("TS-only: type-level inference check (expectTypeOf on auth.$Infer.SSOProvider)")
	})
}

func TestProviders2DeleteProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("runs the provider mutation guard after locking the exact row and before deleting accounts", func(t *testing.T) {
		type observation struct {
			action, recordID, providerID  string
			providerExists, accountExists bool
		}
		var observed *observation
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: func(ctx context.Context, in ProviderMutationGuardInput, gc ProviderMutationGuardContext) error {
			o := &observation{action: in.Action, providerID: in.Provider.ProviderID}
			if in.ProviderReference.Source.Type == "persisted" {
				o.recordID = in.ProviderReference.Source.RecordID
			}
			p, _ := gc.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "id", Value: in.Provider.ID}}})
			o.providerExists = p != nil
			acc, _ := gc.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: in.Provider.ProviderID}}})
			o.accountExists = acc != nil
			observed = o
			return fmt.Errorf("application detail must not escape")
		}})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "guarded-provider", "", nil)
		var provider map[string]any
		for _, row := range env.providerRows() {
			if row["providerId"] == "guarded-provider" {
				provider = row
			}
		}
		env.pushAccount(adapter.Record{"id": "guarded-account", "userId": provider["userId"], "providerId": provider["providerId"], "accountId": "subject"})
		r := env.api("deleteSSOProvider", headers, map[string]any{"providerId": provider["providerId"]}, nil)
		p2ExpectError(t, r, 409, "SSO_PROVIDER_MUTATION_REJECTED", "SSO provider mutation is not allowed")
		want := &observation{action: "delete", recordID: fmt.Sprint(provider["id"]), providerID: fmt.Sprint(provider["providerId"]), providerExists: true, accountExists: true}
		if observed == nil || *observed != *want {
			t.Fatalf("observed = %+v, want %+v", observed, want)
		}
		if strings.Contains(string(r.Raw), "application detail must not escape") || strings.Contains(r.message(), "application detail") {
			t.Fatalf("guard detail escaped: %s", r.Raw)
		}
		found := false
		for _, row := range env.providerRows() {
			if row["id"] == provider["id"] && reflect.DeepEqual(row, provider) {
				found = true
			}
		}
		if !found {
			t.Fatal("provider row changed or deleted")
		}
		accFound := false
		for _, a := range env.rows("account") {
			if a["id"] == "guarded-account" {
				accFound = true
			}
		}
		if !accFound {
			t.Fatal("account deleted")
		}
	})

	t.Run("rejects a guarded delete when the adapter has no native transaction", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{GuardProviderMutation: func(context.Context, ProviderMutationGuardInput, ProviderMutationGuardContext) error { return nil }})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "fallback-delete", "", nil)
		env.w.setNonNative()
		r := env.api("deleteSSOProvider", headers, map[string]any{"providerId": "fallback-delete"}, nil)
		p2ExpectError(t, r, 501, "SSO_PROVIDER_MUTATION_GUARD_REQUIRES_NATIVE_TRANSACTIONS", "")
	})

	t.Run("serializes a concurrent account link before deleting the provider and its account", func(t *testing.T) {
		conn, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		conn.SetMaxOpenConns(1)
		t.Cleanup(func() { conn.Close() })
		env := p2NewSQLEnv(t, conn, Options{}, &p2Adapter{}, nil)
		env.signUp("race-owner@example.com", "password123", "Race Owner")
		headers := env.signIn("race-owner@example.com", "password123")
		if headers.Get("Cookie") == "" {
			t.Fatal("expected cookie")
		}
		env.mustAPI("registerSSOProvider", headers, map[string]any{
			"providerId": "concurrent-provider", "issuer": "https://idp.example.com", "domain": "example.com",
			"samlConfig": map[string]any{
				"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "audience": "my-audience",
				"wantAssertionsSigned": true, "idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
				"spMetadata": map[string]any{},
			},
		}, nil)
		ac := env.auth.Context()
		a := ac.Adapter
		rec, err := a.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "providerId", Value: "concurrent-provider"}}})
		if err != nil || rec == nil {
			t.Fatalf("Expected the persisted SSO provider (%v)", err)
		}
		samlCfg, err := safeJSONParse[SAMLConfig](fmt.Sprint(rec["samlConfig"]))
		if err != nil {
			t.Fatal(err)
		}
		provider := &SSOProvider{ID: fmt.Sprint(rec["id"]), ProviderID: fmt.Sprint(rec["providerId"]), Issuer: fmt.Sprint(rec["issuer"]),
			UserID: fmt.Sprint(rec["userId"]), SAMLConfig: samlCfg}

		release, releaseAccountLink := p2Chan()
		locked, reportProviderLocked := p2Chan()
		linkDone := make(chan error, 1)
		go func() {
			linkDone <- ac.RunWithTransaction(ctx, func(txCtx context.Context) error {
				if err := lockSSOProviderForAccountLink(txCtx, a, provider); err != nil {
					reportProviderLocked()
					return err
				}
				reportProviderLocked()
				<-release
				_, err := a.Create(txCtx, adapter.CreateInput{Model: "account", Data: adapter.Record{
					"id": "concurrent-account", "accountId": "saml-subject", "providerId": provider.ProviderID,
					"userId": provider.UserID, "createdAt": time.Now(), "updatedAt": time.Now(),
				}, ForceAllowID: true})
				return err
			})
		}()
		p2Wait(t, locked, "provider lock")

		deletion := make(chan *result, 1)
		go func() {
			deletion <- env.api("deleteSSOProvider", headers, map[string]any{"providerId": provider.ProviderID}, nil)
		}()
		time.Sleep(50 * time.Millisecond)
		select {
		case r := <-deletion:
			t.Fatalf("deletion settled before the account link committed: %d %s", r.Status, r.Raw)
		default:
		}
		releaseAccountLink()
		if err := <-linkDone; err != nil {
			t.Fatalf("account link: %v", err)
		}
		var r *result
		select {
		case r = <-deletion:
		case <-time.After(15 * time.Second):
			t.Fatal("deletion did not finish")
		}
		if r.Err != nil || r.m()["success"] != true || len(r.m()) != 1 {
			t.Fatalf("deletion = %d %s", r.Status, r.Raw)
		}
		got, err := a.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "id", Value: provider.ID}}})
		if err != nil || got != nil {
			t.Fatalf("provider still exists: %v (%v)", got, err)
		}
		accs, err := a.FindMany(ctx, adapter.FindManyInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: provider.ProviderID}}})
		if err != nil || len(accs) != 0 {
			t.Fatalf("accounts = %v (%v)", accs, err)
		}
	})

	pgOIDCSetup := func(t *testing.T, subject string, o Options, w *p2Adapter) (*testEnv, *mockOIDC, http.Header) {
		conn := testdb.Postgres(t)
		idp := p2StartOIDCIdentityProvider(t, subject)
		env := p2NewSQLEnv(t, conn, o, w, func(c *betterauth.Config) {
			c.Account = &betterauth.AccountConfig{StoreAccountCookie: betterauth.Bool(true)}
			c.TrustedOrigins = []string{idp.URL}
		})
		env.signUp(testEmail, testPassword, testName)
		return env, idp, env.signInTestUser()
	}
	createEmployeeAndProvider := func(t *testing.T, env *testEnv, idp *mockOIDC, ownerID, providerID string) (employeeID string, provider adapter.Record) {
		a := env.auth.Context().Adapter
		now := time.Now()
		emp, err := a.Create(ctx, adapter.CreateInput{Model: "user", Data: adapter.Record{
			"email": "employee@example.com", "emailVerified": true, "name": "Directory Employee", "image": nil, "createdAt": now, "updatedAt": now,
		}})
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := json.Marshal(map[string]any{
			"issuer": idp.URL, "clientId": "workforce-client", "clientSecret": "workforce-secret", "pkce": false,
			"discoveryEndpoint": idp.URL + "/.well-known/openid-configuration",
		})
		provider, err = a.Create(ctx, adapter.CreateInput{Model: "ssoProvider", Data: adapter.Record{
			"issuer": idp.URL, "domain": "example.com", "oidcConfig": string(cfg), "samlConfig": nil,
			"userId": ownerID, "providerId": providerID, "organizationId": nil,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(emp["id"]), provider
	}

	t.Run("waits for a Postgres OIDC account link before deleting its exact provider and account", func(t *testing.T) {
		resolutionEntered, resolveEntered := p2Chan()
		releaseResolution, resolveRelease := p2Chan()
		lockAttempts := newP2LockObserver()
		var mu sync.Mutex
		deletionGuardEntered := false
		employeeID := ""
		w := &p2Adapter{}
		env, idp, owner := pgOIDCSetup(t, "postgres-link-first", Options{
			DisableImplicitSignUp: true,
			GuardProviderMutation: func(_ context.Context, in ProviderMutationGuardInput, _ ProviderMutationGuardContext) error {
				if in.Action == "delete" {
					mu.Lock()
					deletionGuardEntered = true
					mu.Unlock()
				}
				return nil
			},
			ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				resolveEntered()
				<-releaseResolution
				mu.Lock()
				defer mu.Unlock()
				return UserResolution{Action: "link", UserID: employeeID, Profile: "preserve"}, nil
			},
		}, w)
		w.setLockHook(lockAttempts.record)
		empID, provider := createEmployeeAndProvider(t, env, idp, p2SessionUserID(t, env, owner), "postgres-link-first")
		mu.Lock()
		employeeID = empID
		mu.Unlock()
		pid := fmt.Sprint(provider["providerId"])

		signIn := make(chan oidcFlowResult, 1)
		go func() { signIn <- p2CompleteOIDCSignIn(env, pid) }()
		p2Wait(t, lockAttempts.first, "first lock attempt")
		p2Wait(t, resolutionEntered, "resolution")
		deletion := make(chan *result, 1)
		go func() { deletion <- env.api("deleteSSOProvider", owner, map[string]any{"providerId": pid}, nil) }()
		p2Wait(t, lockAttempts.second, "second lock attempt")
		mu.Lock()
		entered := deletionGuardEntered
		mu.Unlock()
		if entered {
			t.Fatal("deletion guard entered before the account link committed")
		}
		resolveRelease()
		auth := <-signIn
		if auth.Status != 302 {
			t.Fatalf("callback status = %d", auth.Status)
		}
		r := <-deletion
		if r.Err != nil || r.m()["success"] != true {
			t.Fatalf("deletion = %d %s", r.Status, r.Raw)
		}
		a := env.auth.Context().Adapter
		if got, _ := a.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "id", Value: provider["id"]}}}); got != nil {
			t.Fatalf("provider still exists: %v", got)
		}
		if accs, _ := a.FindMany(ctx, adapter.FindManyInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: pid}}}); len(accs) != 0 {
			t.Fatalf("accounts = %v", accs)
		}
	})

	t.Run("rejects a Postgres OIDC callback waiting behind provider deletion", func(t *testing.T) {
		deletionGuardEntered, resolveGuardEntered := p2Chan()
		releaseDeletion, resolveReleaseDeletion := p2Chan()
		lockAttempts := newP2LockObserver()
		var mu sync.Mutex
		resolverCalled := false
		employeeID := ""
		w := &p2Adapter{}
		env, idp, owner := pgOIDCSetup(t, "postgres-delete-first", Options{
			DisableImplicitSignUp: true,
			GuardProviderMutation: func(_ context.Context, in ProviderMutationGuardInput, _ ProviderMutationGuardContext) error {
				if in.Action != "delete" {
					return nil
				}
				resolveGuardEntered()
				<-releaseDeletion
				return nil
			},
			ResolveUser: func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				mu.Lock()
				defer mu.Unlock()
				resolverCalled = true
				return UserResolution{Action: "link", UserID: employeeID, Profile: "preserve"}, nil
			},
		}, w)
		w.setLockHook(lockAttempts.record)
		empID, provider := createEmployeeAndProvider(t, env, idp, p2SessionUserID(t, env, owner), "postgres-delete-first")
		mu.Lock()
		employeeID = empID
		mu.Unlock()
		pid := fmt.Sprint(provider["providerId"])

		deletion := make(chan *result, 1)
		go func() { deletion <- env.api("deleteSSOProvider", owner, map[string]any{"providerId": pid}, nil) }()
		p2Wait(t, lockAttempts.first, "first lock attempt")
		p2Wait(t, deletionGuardEntered, "deletion guard")
		signIn := make(chan oidcFlowResult, 1)
		go func() { signIn <- p2CompleteOIDCSignIn(env, pid) }()
		p2Wait(t, lockAttempts.second, "second lock attempt")
		mu.Lock()
		called := resolverCalled
		mu.Unlock()
		if called {
			t.Fatal("resolver called before deletion committed")
		}
		resolveReleaseDeletion()
		r := <-deletion
		if r.Err != nil || r.m()["success"] != true {
			t.Fatalf("deletion = %d %s", r.Status, r.Raw)
		}
		auth := <-signIn
		if auth.Status != 302 {
			t.Fatalf("callback status = %d", auth.Status)
		}
		if !strings.Contains(auth.CallbackURL, "error=SSO_PROVIDER_CHANGED") {
			t.Fatalf("callback location = %q", auth.CallbackURL)
		}
		mu.Lock()
		called = resolverCalled
		mu.Unlock()
		if called {
			t.Fatal("resolver called")
		}
		a := env.auth.Context().Adapter
		if accs, _ := a.FindMany(ctx, adapter.FindManyInput{Model: "account", Where: []adapter.Where{{Field: "providerId", Value: pid}}}); len(accs) != 0 {
			t.Fatalf("accounts = %v", accs)
		}
		if sess, _ := a.FindMany(ctx, adapter.FindManyInput{Model: "session", Where: []adapter.Where{{Field: "userId", Value: empID}}}); len(sess) != 0 {
			t.Fatalf("sessions = %v", sess)
		}
	})

	t.Run("should return 401 when not authenticated", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		r := env.api("deleteSSOProvider", nil, map[string]any{"providerId": "test"}, nil)
		p2ExpectStatus(t, r, 401)
	})

	t.Run("should return 404 when provider not found", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		headers := env.getAuthHeaders("test@example.com", "password123", "Test User")
		r := env.api("deleteSSOProvider", headers, map[string]any{"providerId": "nonexistent"}, nil)
		p2ExpectStatus(t, r, 404)
	})

	t.Run("should return 403 when user does not own provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(ownerHeaders, "other-provider", "", nil)
		otherHeaders := env.getAuthHeaders("other@example.com", "password123", "Other User")
		r := env.api("deleteSSOProvider", otherHeaders, map[string]any{"providerId": "other-provider"}, nil)
		p2ExpectStatus(t, r, 403)
	})

	t.Run("should delete provider successfully", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		r := env.mustAPI("deleteSSOProvider", headers, map[string]any{"providerId": "my-saml-provider"}, nil)
		if r.m()["success"] != true {
			t.Fatalf("delete = %s", r.Raw)
		}
		g := env.api("getSSOProvider", headers, nil, map[string]any{"providerId": "my-saml-provider"})
		p2ExpectStatus(t, g, 404)
	})

	t.Run("should allow org admin to delete org provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		org := env.createOrganization("test-org", ownerHeaders)
		env.mustRegisterSAML(ownerHeaders, "org-provider", org, nil)
		adminHeaders := env.getAuthHeaders("admin@example.com", "password123", "Admin")
		env.addMember(env.userID("admin@example.com"), org, "admin", ownerHeaders)
		r := env.mustAPI("deleteSSOProvider", adminHeaders, map[string]any{"providerId": "org-provider"}, nil)
		if r.m()["success"] != true {
			t.Fatalf("delete = %s", r.Raw)
		}
	})

	t.Run("should return 403 when org member tries to delete org provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		org := env.createOrganization("test-org", ownerHeaders)
		env.mustRegisterSAML(ownerHeaders, "org-provider", org, nil)
		memberHeaders := env.getAuthHeaders("member@example.com", "password123", "Member")
		env.addMember(env.userID("member@example.com"), org, "member", ownerHeaders)
		r := env.api("deleteSSOProvider", memberHeaders, map[string]any{"providerId": "org-provider"}, nil)
		p2ExpectStatus(t, r, 403)
	})

	t.Run("deletes linked account rows when the provider is deleted", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		env.mustRegisterSAML(headers, "my-saml-provider", "", nil)
		env.pushAccount(adapter.Record{"id": "account-1", "userId": env.userID("owner@example.com"), "providerId": "my-saml-provider",
			"accountId": "saml-account-id", "accessToken": "token", "refreshToken": "refresh"})
		env.mustAPI("deleteSSOProvider", headers, map[string]any{"providerId": "my-saml-provider"}, nil)
		hasSAML, hasCredential := false, false
		for _, a := range env.rows("account") {
			switch a["providerId"] {
			case "my-saml-provider":
				hasSAML = true
			case "credential":
				hasCredential = true
			}
		}
		if hasSAML || !hasCredential {
			t.Fatalf("saml account present=%v credential present=%v", hasSAML, hasCredential)
		}
	})
}

func TestProviders2Register(t *testing.T) {
	registerBody := func(providerID string, saml map[string]any) map[string]any {
		return map[string]any{"providerId": providerID, "issuer": "https://idp.example.com", "domain": "example.com", "samlConfig": saml}
	}

	for _, tc := range p2InvalidCustomSPMetadata {
		t.Run("rejects custom SP metadata with "+tc.name+" before creating the provider", func(t *testing.T) {
			env := p2CreateTestAuth(t, false, false, Options{})
			headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
			r := env.api("registerSSOProvider", headers, registerBody("invalid-metadata-register", map[string]any{
				"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "wantAssertionsSigned": false,
				"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
				"spMetadata":  map[string]any{"metadata": tc.metadata},
			}), nil)
			p2ExpectError(t, r, 400, "SAML_INVALID_SP_METADATA", "Invalid SAML service provider metadata")
			if n := len(env.providerRows()); n != 0 {
				t.Fatalf("providers = %d", n)
			}
		})
	}

	t.Run("rejects oversized custom SP metadata before creating the provider", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{SAML: &SAMLOptions{MaxMetadataSize: 32}})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		r := env.api("registerSSOProvider", headers, registerBody("oversized-metadata-register", map[string]any{
			"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "wantAssertionsSigned": false,
			"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
			"spMetadata":  map[string]any{"metadata": strings.Repeat("x", 33)},
		}), nil)
		p2ExpectError(t, r, 400, "", "SP metadata exceeds maximum allowed size (32 bytes)")
		if n := len(env.providerRows()); n != 0 {
			t.Fatalf("providers = %d", n)
		}
	})

	t.Run("accepts usable custom SP metadata as the effective signed-assertion policy", func(t *testing.T) {
		env := p2CreateTestAuth(t, false, false, Options{})
		headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		r := env.api("registerSSOProvider", headers, registerBody("effective-metadata-policy", map[string]any{
			"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "wantAssertionsSigned": false,
			"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
			"spMetadata":  map[string]any{"metadata": p2ValidCustomSPMetadata},
		}), nil)
		p2ExpectStatus(t, r, 200)
		if n := len(env.providerRows()); n != 1 {
			t.Fatalf("providers = %d", n)
		}
	})

	for _, tc := range []struct {
		value  string
		policy bool
	}{{"1", true}, {"0", false}} {
		t.Run("registers XML Schema numeric WantAssertionsSigned="+tc.value+" metadata", func(t *testing.T) {
			env := p2CreateTestAuth(t, false, false, Options{})
			headers := env.getAuthHeaders("owner@example.com", "password123", "Owner")
			r := env.api("registerSSOProvider", headers, registerBody("numeric-metadata-policy-"+tc.value, map[string]any{
				"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "wantAssertionsSigned": tc.policy,
				"idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
				"spMetadata": map[string]any{"metadata": strings.Replace(p2ValidCustomSPMetadata,
					`WantAssertionsSigned="true"`, `WantAssertionsSigned="`+tc.value+`"`, 1)},
			}), nil)
			p2ExpectStatus(t, r, 200)
			if n := len(env.providerRows()); n != 1 {
				t.Fatalf("providers = %d", n)
			}
		})
	}

	orgSAML := func() map[string]any {
		return map[string]any{
			"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert, "audience": "my-audience",
			"wantAssertionsSigned": true, "idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
			"spMetadata": map[string]any{},
		}
	}

	t.Run("should reject registration from non-admin org members", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		org := env.createOrganization("test-org", ownerHeaders)
		memberHeaders := env.getAuthHeaders("member@example.com", "password123", "Member")
		env.addMember(env.userID("member@example.com"), org, "member", ownerHeaders)
		body := registerBody("org-saml-provider", orgSAML())
		body["organizationId"] = org
		r := env.api("registerSSOProvider", memberHeaders, body, nil)
		p2ExpectStatus(t, r, 403)
	})

	t.Run("should allow registration from org admins", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		org := env.createOrganization("test-org", ownerHeaders)
		adminHeaders := env.getAuthHeaders("admin@example.com", "password123", "Admin")
		env.addMember(env.userID("admin@example.com"), org, "admin", ownerHeaders)
		body := registerBody("org-saml-provider", orgSAML())
		body["organizationId"] = org
		r := env.api("registerSSOProvider", adminHeaders, body, nil)
		p2ExpectStatus(t, r, 200)
	})

	t.Run("should reject registration when user is not a member of the organization", func(t *testing.T) {
		env := p2CreateTestAuth(t, true, false, Options{})
		ownerHeaders := env.getAuthHeaders("owner@example.com", "password123", "Owner")
		org := env.createOrganization("test-org", ownerHeaders)
		outsiderHeaders := env.getAuthHeaders("outsider@example.com", "password123", "Outsider")
		body := registerBody("org-saml-provider", orgSAML())
		body["organizationId"] = org
		r := env.api("registerSSOProvider", outsiderHeaders, body, nil)
		p2ExpectStatus(t, r, 400)
	})
}

func TestProviders2NamespaceCollisions(t *testing.T) {
	setup := func(t *testing.T, o Options) (*testEnv, http.Header) {
		env := newEnv(t, o, envConfig{noTestUser: true, mutate: func(c *betterauth.Config) {
			c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}})}
			c.Account = &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{
				Enabled: betterauth.Bool(true), TrustedProviders: []string{"github"},
			}}
		}})
		env.signUp("user@example.com", "password123", "User")
		return env, env.signIn("user@example.com", "password123")
	}
	registerBody := func(providerID string) map[string]any {
		return map[string]any{
			"providerId": providerID, "issuer": "https://idp.example.com", "domain": "example.com",
			"samlConfig": map[string]any{
				"entryPoint": "https://idp.example.com/sso", "cert": p2TestCert,
				"callbackUrl": "http://localhost:3000/api/sso/callback", "audience": "my-audience",
				"wantAssertionsSigned": true, "idpMetadata": map[string]any{"entityID": "https://idp.example.com"},
				"spMetadata": map[string]any{},
			},
		}
	}

	t.Run("rejects a providerId that collides with a configured social provider", func(t *testing.T) {
		env, headers := setup(t, Options{})
		p2ExpectStatus(t, env.api("registerSSOProvider", headers, registerBody("google"), nil), 422)
	})

	t.Run("rejects a providerId that collides with a trustedProviders entry", func(t *testing.T) {
		env, headers := setup(t, Options{})
		p2ExpectStatus(t, env.api("registerSSOProvider", headers, registerBody("github"), nil), 422)
	})

	t.Run("rejects the reserved 'credential' providerId", func(t *testing.T) {
		env, headers := setup(t, Options{})
		p2ExpectStatus(t, env.api("registerSSOProvider", headers, registerBody("credential"), nil), 422)
	})

	t.Run("rejects a providerId that collides with a default SSO provider", func(t *testing.T) {
		env, headers := setup(t, Options{DefaultSSO: []DefaultSSOProvider{{
			Domain: "example.com", ProviderID: "default-sso",
			SAMLConfig: &SAMLConfig{
				Issuer: "https://sp.example.com/saml", EntryPoint: "https://idp.example.com/sso", Cert: Cert(p2TestCert),
				CallbackURL: "http://localhost:3000/api/sso/callback",
				IdpMetadata: &SAMLIdentityProviderMetadata{EntityID: "https://idp.example.com"},
				SpMetadata:  &SAMLServiceProviderMetadata{},
			},
		}}})
		p2ExpectStatus(t, env.api("registerSSOProvider", headers, registerBody("default-sso"), nil), 422)
	})

	t.Run("allows a non-colliding providerId", func(t *testing.T) {
		env, headers := setup(t, Options{})
		p2ExpectStatus(t, env.api("registerSSOProvider", headers, registerBody("okta-corp"), nil), 200)
	})
}
