package scim

// Port of upstream scim-dynamic-authentication.test.ts ("SCIM dynamic connection
// authentication").

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const dynAuthUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

const dynAuthCredentialModel = "testSCIMCredential"

// dynAuthCredentialPlugin is dynamicCredentialPlugin: an application-owned credential table.
var dynAuthCredentialPlugin = &betterauth.Plugin{
	ID: "scim-dynamic-authentication-test",
	Schema: []db.PluginTable{{Key: dynAuthCredentialModel, Fields: []db.Field{
		{Name: "tokenHash", Type: db.TypeString, Required: db.True, Unique: true},
		{Name: "connectionId", Type: db.TypeString, Required: db.True},
		{Name: "provisioningDomainId", Type: db.TypeString, Required: db.True},
		{Name: "credentialId", Type: db.TypeString, Required: db.True},
		{Name: "scopes", Type: db.TypeString, Required: db.True},
		{Name: "status", Type: db.TypeString, Required: db.True},
		{Name: "expiresAt", Type: db.TypeDate, Required: db.False},
		{Name: "lastAuthenticatedAt", Type: db.TypeDate, Required: db.False},
	}}},
}

func dynAuthHashToken(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// dynAuthOverride is a VerificationOverride: a fixed verifier result or error.
type dynAuthOverride struct {
	result *BearerTokenVerification
	err    error
}

type dynAuthInstanceOptions struct {
	connections             []ConnectionOptions
	overrides               map[string]dynAuthOverride
	afterCredentialAccepted func(credential adapter.Record)
}

type dynAuthInstance struct {
	*testEnv
	mu           sync.Mutex
	capabilities []string
}

func (d *dynAuthInstance) verifierCapabilities() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.capabilities
}

// dynAuthDatabaseCapabilities lists the methods of the verifier's database capability
// (Object.keys(context.database) upstream).
func dynAuthDatabaseCapabilities(v FindOneUpdater) []string {
	t := reflect.TypeOf((*FindOneUpdater)(nil)).Elem()
	_ = v
	var out []string
	for i := 0; i < t.NumMethod(); i++ {
		name := t.Method(i).Name
		out = append(out, strings.ToLower(name[:1])+name[1:])
	}
	sort.Strings(out)
	return out
}

func dynAuthCreateInstance(t *testing.T, o dynAuthInstanceOptions) *dynAuthInstance {
	t.Helper()
	inst := &dynAuthInstance{}
	verify := func(in BearerTokenVerificationInput, vc BearerTokenVerificationContext) (*BearerTokenVerification, error) {
		caps := dynAuthDatabaseCapabilities(vc.Database)
		inst.mu.Lock()
		inst.capabilities = caps
		inst.mu.Unlock()
		if ov, ok := o.overrides[in.Token]; ok {
			return ov.result, ov.err
		}
		cred, err := vc.Database.FindOne(vc.Context, adapter.FindOneInput{Model: dynAuthCredentialModel,
			Where: []adapter.Where{{Field: "tokenHash", Value: dynAuthHashToken(in.Token)}}})
		if err != nil {
			return nil, err
		}
		if cred == nil {
			return nil, nil
		}
		if cred["status"] != "active" {
			return nil, nil
		}
		exp, hasExp := cred["expiresAt"].(time.Time)
		if hasExp && !exp.After(time.Now()) {
			return nil, nil
		}
		if o.afterCredentialAccepted != nil {
			o.afterCredentialAccepted(cred)
		}
		if _, err := vc.Database.Update(vc.Context, dynAuthCredentialModel,
			[]adapter.Where{{Field: "id", Value: cred["id"]}}, adapter.Record{"lastAuthenticatedAt": time.Now()}); err != nil {
			return nil, err
		}
		var scopes []Scope
		if err := json.Unmarshal([]byte(cred["scopes"].(string)), &scopes); err != nil {
			return nil, err
		}
		v := &BearerTokenVerification{
			Connection: &VerifiedConnection{ID: cred["connectionId"].(string),
				ProvisioningDomainID: cred["provisioningDomainId"].(string)},
			CredentialID: cred["credentialId"].(string),
			Scopes:       scopes,
		}
		if hasExp {
			v.ExpiresAt = &exp
		}
		return v, nil
	}
	inst.testEnv = newEnv(t, Options{
		Connections:    o.connections,
		Authentication: &AuthenticationOptions{VerifyBearerToken: verify},
	}, envOptions{sqlite: true, extraPlugins: []*betterauth.Plugin{dynAuthCredentialPlugin}})
	return inst
}

type dynAuthCredentialInput struct {
	token, connectionID, provisioningDomainID, credentialID string
	scopes                                                  []string
	expiresAt                                               *time.Time
}

func dynAuthAddCredential(e *testEnv, in dynAuthCredentialInput) adapter.Record {
	e.t.Helper()
	credID := in.credentialID
	if credID == "" {
		credID = in.connectionID + "-credential"
	}
	scopes := in.scopes
	if scopes == nil {
		scopes = []string{"scim.users.read", "scim.users.write", "scim.groups.read", "scim.groups.write"}
	}
	enc, _ := json.Marshal(scopes)
	data := adapter.Record{
		"tokenHash": dynAuthHashToken(in.token), "connectionId": in.connectionID,
		"provisioningDomainId": in.provisioningDomainID, "credentialId": credID,
		"scopes": string(enc), "status": "active",
	}
	if in.expiresAt != nil {
		data["expiresAt"] = *in.expiresAt
	}
	r, err := e.db().Create(context.Background(), adapter.CreateInput{Model: dynAuthCredentialModel, Data: data})
	if err != nil {
		e.t.Fatalf("create credential: %v", err)
	}
	return r
}

func dynAuthCreateUser(e *testEnv, token string, userName, externalID string) *response {
	body := map[string]any{"schemas": []any{dynAuthUserSchema}, "userName": userName}
	if externalID != "" {
		body["externalId"] = externalID
	}
	return e.scim("POST", scimUsersURL, token, body)
}

func dynAuthListUsers(e *testEnv, token string) *response {
	return e.scim("GET", scimUsersURL, token, nil)
}

func dynAuthUpdateCredential(t *testing.T, e *testEnv, id any, update adapter.Record) {
	t.Helper()
	if _, err := e.db().Update(context.Background(), dynAuthCredentialModel,
		[]adapter.Where{{Field: "id", Value: id}}, update); err != nil {
		t.Fatalf("update credential: %v", err)
	}
}

func dynAuthWait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func dynAuthExpectUnauthorized(t *testing.T, r *response, label string) {
	t.Helper()
	if r.Status != 401 {
		t.Errorf("%s: status = %d, want 401 (%s)", label, r.Status, r.text())
	}
	if got := r.Header.Get("WWW-Authenticate"); got != `Bearer realm="SCIM"` {
		t.Errorf("%s: www-authenticate = %q", label, got)
	}
}

func dynAuthExpectEmpty(t *testing.T, e *testEnv, models ...string) {
	t.Helper()
	for _, m := range models {
		if rs := e.rows(m); len(rs) != 0 {
			t.Errorf("%s rows = %v, want none", m, rs)
		}
	}
}

func dynAuthExpectSingleBinding(t *testing.T, e *testEnv, want map[string]any) []adapter.Record {
	t.Helper()
	rs := e.rows("scimConnectionBinding")
	if len(rs) != 1 {
		t.Fatalf("bindings = %v, want 1", rs)
	}
	for k, v := range want {
		if got := rs[0][k]; !dynAuthLooseEqual(got, v) {
			t.Errorf("binding[%s] = %#v, want %#v", k, got, v)
		}
	}
	return rs
}

func dynAuthLooseEqual(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func TestDynAuthSCIMDynamicConnectionAuthentication(t *testing.T) {
	t.Run("allows a dynamic-only connection resolver", func(t *testing.T) {
		_, err := NewE(Options{Connections: []ConnectionOptions{}})
		if err == nil || err.Error() != "The scim plugin requires a provisioning connection, bearer token verifier, or managed connection catalog." {
			t.Fatalf("err = %v", err)
		}
		if _, err := NewE(Options{Authentication: &AuthenticationOptions{
			VerifyBearerToken: func(BearerTokenVerificationInput, BearerTokenVerificationContext) (*BearerTokenVerification, error) {
				return nil, nil
			}}}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects malformed authentication options at construction", func(t *testing.T) {
		// Go cannot distinguish `authentication: null` from an absent option; both the
		// `{}` and `null` cases map to an AuthenticationOptions without a verifier.
		const expected = "SCIM authentication requires a callable verifyBearerToken."
		missingVerifier := &AuthenticationOptions{}
		cases := []Options{
			{Authentication: missingVerifier},
			{Connections: []ConnectionOptions{{ID: "dynamic-only", Credentials: []BearerCredential{}}}, Authentication: &AuthenticationOptions{}},
			{Connections: []ConnectionOptions{{ID: "static-connection", Credentials: []BearerCredential{
				{Type: "bearer", ID: "static-credential", Token: "static-token"}}}}, Authentication: missingVerifier},
		}
		for i, o := range cases {
			_, err := NewE(o)
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Errorf("case %d: err = %v", i, err)
			}
		}
	})

	t.Run("resolves application-owned credentials and isolates equal external IDs over HTTP", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "tenant-a-token", connectionID: "dynamic-tenant-a", provisioningDomainID: "workspace-a"})
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "tenant-b-token", connectionID: "dynamic-tenant-b", provisioningDomainID: "workspace-b"})

		tenantA := dynAuthCreateUser(e, "tenant-a-token", "employee-a@example.com", "shared-directory-user")
		tenantB := dynAuthCreateUser(e, "tenant-b-token", "employee-b@example.com", "shared-directory-user")
		tenantAUsers := dynAuthListUsers(e, "tenant-a-token")
		tenantBUsers := dynAuthListUsers(e, "tenant-b-token")
		tenantBID, _ := tenantB.json()["id"].(string)
		tenantAID, _ := tenantA.json()["id"].(string)
		crossTenantPatch := e.scim("PATCH", scimUsersURL+"/"+tenantBID, "tenant-a-token", map[string]any{
			"schemas":    []any{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}},
		})
		tenantBResource := e.scim("GET", scimUsersURL+"/"+tenantBID, "tenant-b-token", nil)

		if tenantA.Status != 201 || tenantB.Status != 201 {
			t.Fatalf("create statuses = %d %d (%s / %s)", tenantA.Status, tenantB.Status, tenantA.text(), tenantB.text())
		}
		if tenantAUsers.Status != 200 || tenantBUsers.Status != 200 {
			t.Fatalf("list statuses = %d %d", tenantAUsers.Status, tenantBUsers.Status)
		}
		if crossTenantPatch.Status != 404 {
			t.Errorf("cross-tenant patch = %d, want 404", crossTenantPatch.Status)
		}
		if tenantBResource.Status != 200 || tenantBResource.json()["active"] != true {
			t.Errorf("tenant B resource = %d %s", tenantBResource.Status, tenantBResource.text())
		}
		for _, c := range []struct {
			list      *response
			id, other string
			label     string
		}{{tenantAUsers, tenantAID, tenantBID, "A"}, {tenantBUsers, tenantBID, tenantAID, "B"}} {
			body := c.list.json()
			if body["totalResults"] != float64(1) {
				t.Errorf("%s totalResults = %v", c.label, body["totalResults"])
			}
			res, _ := body["Resources"].([]any)
			if len(res) != 1 {
				t.Fatalf("%s Resources = %v", c.label, res)
			}
			r0 := res[0].(map[string]any)
			if r0["id"] != c.id || r0["externalId"] != "shared-directory-user" {
				t.Errorf("%s resource = %v", c.label, r0)
			}
			for _, r := range res {
				if r.(map[string]any)["id"] == c.other {
					t.Errorf("%s list contains other tenant user", c.label)
				}
			}
		}

		bindings := e.rows("scimConnectionBinding")
		scimUsers := e.rows("scimUser")
		subjects := e.rows("scimSubject")
		accounts := e.rows("account")
		credentials := e.rows(dynAuthCredentialModel)
		if len(bindings) != 2 {
			t.Fatalf("bindings = %v", bindings)
		}
		wantBindings := map[string]string{"dynamic-tenant-a": "workspace-a", "dynamic-tenant-b": "workspace-b"}
		for _, b := range bindings {
			if wantBindings[b["connectionId"].(string)] != b["provisioningDomainId"] {
				t.Errorf("unexpected binding %v", b)
			}
		}
		if len(scimUsers) != 2 {
			t.Fatalf("scimUsers = %v", scimUsers)
		}
		userIDs := map[any]bool{}
		scimIDs := map[any]bool{}
		for _, u := range scimUsers {
			if wantBindings[u["connectionId"].(string)] != u["provisioningDomainId"] || u["externalId"] != "shared-directory-user" {
				t.Errorf("unexpected scimUser %v", u)
			}
			userIDs[u["userId"]] = true
			scimIDs[u["id"]] = true
		}
		if len(userIDs) != 2 {
			t.Errorf("distinct userIds = %d", len(userIDs))
		}
		if len(subjects) != 2 {
			t.Fatalf("subjects = %v", subjects)
		}
		subjectUsers := map[any]bool{}
		profileSources := map[any]bool{}
		for _, s := range subjects {
			subjectUsers[s["userId"]] = true
			profileSources[s["profileSourceId"]] = true
		}
		if len(subjectUsers) != 2 {
			t.Errorf("distinct subject userIds = %d", len(subjectUsers))
		}
		for id := range scimIDs {
			if !profileSources[id] {
				t.Errorf("profileSourceId missing scimUser %v", id)
			}
		}
		if len(accounts) != 0 {
			t.Errorf("accounts = %v", accounts)
		}
		if len(credentials) != 2 {
			t.Fatalf("credentials = %v", credentials)
		}
		for _, c := range credentials {
			if _, ok := c["lastAuthenticatedAt"].(time.Time); !ok {
				t.Errorf("credential lastAuthenticatedAt = %#v", c["lastAuthenticatedAt"])
			}
		}
		if got := inst.verifierCapabilities(); !reflect.DeepEqual(got, []string{"findOne", "update"}) {
			t.Errorf("verifier capabilities = %v", got)
		}
	})

	t.Run("rejects unknown, malformed, ambiguous, and static-colliding resolutions before writes", func(t *testing.T) {
		valid := func(v BearerTokenVerification) *BearerTokenVerification {
			if v.CredentialID == "" {
				v.CredentialID = "dynamic-credential"
			}
			if v.Scopes == nil {
				v.Scopes = []Scope{ScopeUsersRead}
			}
			return &v
		}
		zero := time.Time{}
		expired := time.Now().Add(-60 * time.Second)
		overrides := map[string]dynAuthOverride{
			"malformed-token": {result: valid(BearerTokenVerification{Connection: &VerifiedConnection{ID: " dynamic-tenant ", ProvisioningDomainID: "workspace"}})},
			"ambiguous-token": {result: valid(BearerTokenVerification{ConnectionID: strPtr("configured-tenant"),
				Connection: &VerifiedConnection{ID: "dynamic-tenant", ProvisioningDomainID: "workspace"}})},
			"missing-domain-token": {result: valid(BearerTokenVerification{Connection: &VerifiedConnection{ID: "dynamic-tenant"}})},
			"invalid-credential-token": {result: valid(BearerTokenVerification{Connection: &VerifiedConnection{ID: "dynamic-tenant", ProvisioningDomainID: "workspace"},
				CredentialID: " invalid-credential "})},
			"empty-scopes-token": {result: valid(BearerTokenVerification{Connection: &VerifiedConnection{ID: "dynamic-tenant", ProvisioningDomainID: "workspace"},
				Scopes: []Scope{}})},
			// expiresAt: "tomorrow" (an invalid Date) is modelled as a non-nil zero time.
			"invalid-expiry-token": {result: valid(BearerTokenVerification{Connection: &VerifiedConnection{ID: "dynamic-tenant", ProvisioningDomainID: "workspace"},
				ExpiresAt: &zero})},
			"expired-result-token": {result: valid(BearerTokenVerification{Connection: &VerifiedConnection{ID: "dynamic-tenant", ProvisioningDomainID: "workspace"},
				ExpiresAt: &expired})},
			"unknown-configured-token": {result: valid(BearerTokenVerification{ConnectionID: strPtr("missing-configured-tenant")})},
			"missing-connection-token": {result: valid(BearerTokenVerification{})},
			"colliding-token":          {result: valid(BearerTokenVerification{Connection: &VerifiedConnection{ID: "configured-tenant", ProvisioningDomainID: "dynamic-workspace"}})},
		}
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{
			connections: []ConnectionOptions{{ID: "configured-tenant", Credentials: []BearerCredential{}}},
			overrides:   overrides,
		})
		e := inst.testEnv
		for _, token := range []string{"unknown-token", "malformed-token", "ambiguous-token", "missing-domain-token",
			"invalid-credential-token", "empty-scopes-token", "invalid-expiry-token", "expired-result-token",
			"unknown-configured-token", "missing-connection-token", "colliding-token"} {
			dynAuthExpectUnauthorized(t, dynAuthListUsers(e, token), token)
		}
		dynAuthExpectEmpty(t, e, "scimConnectionBinding", "scimUser", "user")
	})

	t.Run("checks dynamic credential scopes and expiry before binding or provisioning", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "read-only-token", connectionID: "read-only-tenant",
			provisioningDomainID: "read-only-workspace", scopes: []string{"scim.users.read"}})
		past := time.Now().Add(-60 * time.Second)
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "expired-token", connectionID: "expired-tenant",
			provisioningDomainID: "expired-workspace", expiresAt: &past})

		insufficient := dynAuthCreateUser(e, "read-only-token", "read-only@example.com", "")
		expiredRes := dynAuthCreateUser(e, "expired-token", "expired@example.com", "")
		if insufficient.Status != 403 {
			t.Errorf("insufficient scope = %d, want 403", insufficient.Status)
		}
		dynAuthExpectUnauthorized(t, expiredRes, "expired")
		dynAuthExpectEmpty(t, e, "scimConnectionBinding", "scimUser", "user")
		cred, err := e.db().FindOne(context.Background(), adapter.FindOneInput{Model: dynAuthCredentialModel,
			Where: []adapter.Where{{Field: "tokenHash", Value: dynAuthHashToken("expired-token")}}})
		if err != nil || cred == nil {
			t.Fatalf("find expired credential: %v %v", cred, err)
		}
		if cred["lastAuthenticatedAt"] != nil {
			t.Errorf("lastAuthenticatedAt = %v, want nil", cred["lastAuthenticatedAt"])
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("applies dynamic credential revocation prospectively to real HTTP requests", func(t *testing.T) {
		accepted := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{afterCredentialAccepted: func(adapter.Record) {
			first := false
			once.Do(func() { first = true; close(accepted) })
			if first {
				<-release
			}
		}})
		e := inst.testEnv
		cred := dynAuthAddCredential(e, dynAuthCredentialInput{token: "prospective-revocation-token",
			connectionID: "prospective-revocation-tenant", provisioningDomainID: "prospective-revocation-workspace"})

		done := make(chan *response, 1)
		go func() {
			done <- dynAuthCreateUser(e, "prospective-revocation-token", "accepted-before-revocation@example.com", "")
		}()
		dynAuthWait(t, accepted, "credential acceptance")
		dynAuthUpdateCredential(t, e, cred["id"], adapter.Record{"status": "revoked"})
		close(release)
		var acceptedResult *response
		select {
		case acceptedResult = <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for accepted request")
		}
		later := dynAuthListUsers(e, "prospective-revocation-token")

		if acceptedResult.Status != 201 {
			t.Errorf("accepted = %d %s", acceptedResult.Status, acceptedResult.text())
		}
		dynAuthExpectUnauthorized(t, later, "later")
		dynAuthExpectSingleBinding(t, e, map[string]any{"connectionId": "prospective-revocation-tenant",
			"provisioningDomainId": "prospective-revocation-workspace"})
		users := e.rows("scimUser")
		if len(users) != 1 || users[0]["userName"] != "accepted-before-revocation@example.com" {
			t.Errorf("scimUsers = %v", users)
		}
	})

	t.Run("preserves the first dynamic connection-to-domain binding on remap attempts", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		cred := dynAuthAddCredential(e, dynAuthCredentialInput{token: "remap-token", connectionID: "dynamic-remap-tenant",
			provisioningDomainID: "original-workspace"})
		first := dynAuthListUsers(e, "remap-token")
		dynAuthUpdateCredential(t, e, cred["id"], adapter.Record{"provisioningDomainId": "different-workspace"})
		remapped := dynAuthListUsers(e, "remap-token")
		if first.Status != 200 {
			t.Errorf("first = %d", first.Status)
		}
		if remapped.Status != 409 {
			t.Errorf("remapped = %d, want 409", remapped.Status)
		}
		dynAuthExpectSingleBinding(t, e, map[string]any{"connectionId": "dynamic-remap-tenant",
			"provisioningDomainId": "original-workspace", "decommissionStatus": "active"})
	})

	t.Run("rejects a resolved dynamic connection after terminal decommissioning", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "decommissioned-token", connectionID: "dynamic-decommissioned-tenant",
			provisioningDomainID: "decommissioned-workspace"})
		created := dynAuthCreateUser(e, "decommissioned-token", "decommissioned@example.com", "")
		decommissioned := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{
			"connectionId": "dynamic-decommissioned-tenant"}})
		rejected := dynAuthListUsers(e, "decommissioned-token")
		if created.Status != 201 {
			t.Errorf("created = %d", created.Status)
		}
		if decommissioned["status"] != "complete" {
			t.Errorf("decommission status = %v", decommissioned["status"])
		}
		dynAuthExpectUnauthorized(t, rejected, "rejected")
		dynAuthExpectSingleBinding(t, e, map[string]any{"connectionId": "dynamic-decommissioned-tenant",
			"provisioningDomainId": "decommissioned-workspace", "decommissionStatus": "complete"})
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("permanently decommissions a dynamic connection before its first request", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "never-used-decommissioned-token",
			connectionID: "never-used-decommissioned-tenant", provisioningDomainID: "never-used-decommissioned-workspace"})
		res, ae := e.call("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{
			"connectionId": "never-used-decommissioned-tenant", "provisioningDomainId": "never-used-decommissioned-workspace"}})
		if ae != nil {
			t.Fatalf("decommission: %v", ae)
		}
		rejected := dynAuthListUsers(e, "never-used-decommissioned-token")

		obj, ok := res.Data.(*jsonx.Object)
		if !ok {
			t.Fatalf("decommission result = %#v", res.Data)
		}
		wantKeys := []string{"connectionId", "provisioningDomainId", "status", "decommissionedAt", "completedAt",
			"retryAfter", "reconciledUsers", "batches"}
		if got := obj.Keys(); !reflect.DeepEqual(got, wantKeys) {
			t.Errorf("result keys = %v", got)
		}
		m := obj.Map()
		if m["connectionId"] != "never-used-decommissioned-tenant" || m["provisioningDomainId"] != "never-used-decommissioned-workspace" ||
			m["status"] != "complete" || m["retryAfter"] != nil || !dynAuthLooseEqual(m["reconciledUsers"], 0) ||
			!dynAuthLooseEqual(m["batches"], 0) {
			t.Errorf("result = %v", m)
		}
		for _, k := range []string{"decommissionedAt", "completedAt"} {
			if _, ok := m[k].(time.Time); !ok {
				t.Errorf("%s = %#v, want Date", k, m[k])
			}
		}
		dynAuthExpectUnauthorized(t, rejected, "rejected")
		dynAuthExpectSingleBinding(t, e, map[string]any{"connectionId": "never-used-decommissioned-tenant",
			"provisioningDomainId": "never-used-decommissioned-workspace", "decommissionStatus": "complete",
			"decommissionReconciledUserCount": 0, "decommissionBatchCount": 0})
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("keeps a never-used terminal binding idempotent and immutable", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		body := map[string]any{"connectionId": "idempotent-tombstone-tenant", "provisioningDomainId": "idempotent-tombstone-workspace"}
		first := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: body})
		repeated := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: body})
		before := e.rows("scimConnectionBinding")
		_, err := e.callErr("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{
			"connectionId": "idempotent-tombstone-tenant", "provisioningDomainId": "different-workspace"}})
		if err == nil || !strings.Contains(err.Error(), "is already bound to provisioning domain") {
			t.Errorf("mismatch err = %v", err)
		}
		if !reflect.DeepEqual(repeated, first) {
			t.Errorf("repeated = %v, first = %v", repeated, first)
		}
		if after := e.rows("scimConnectionBinding"); !reflect.DeepEqual(after, before) {
			t.Errorf("binding changed: %v -> %v", before, after)
		}
		if len(before) != 1 {
			t.Fatalf("bindings = %v", before)
		}
		if before[0]["connectionId"] != "idempotent-tombstone-tenant" || before[0]["provisioningDomainId"] != "idempotent-tombstone-workspace" ||
			before[0]["decommissionStatus"] != "complete" {
			t.Errorf("binding = %v", before[0])
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("preserves the missing-binding error for legacy decommission calls", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		_, err := e.callErr("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{
			"connectionId": "legacy-never-used-tenant"}})
		if err == nil || !strings.Contains(err.Error(), `SCIM connection "legacy-never-used-tenant" has no persisted binding.`) {
			t.Errorf("err = %v", err)
		}
		dynAuthExpectEmpty(t, e, "scimConnectionBinding")
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("does not mutate an active binding when decommissioning names another domain", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "active-domain-mismatch-token",
			connectionID: "active-domain-mismatch-tenant", provisioningDomainID: "active-domain-mismatch-workspace"})
		if r := dynAuthListUsers(e, "active-domain-mismatch-token"); r.Status != 200 {
			t.Fatalf("first list = %d", r.Status)
		}
		before := e.rows("scimConnectionBinding")
		_, err := e.callErr("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{
			"connectionId": "active-domain-mismatch-tenant", "provisioningDomainId": "different-workspace"}})
		if err == nil || !strings.Contains(err.Error(), "is already bound to provisioning domain") {
			t.Errorf("err = %v", err)
		}
		if after := e.rows("scimConnectionBinding"); !reflect.DeepEqual(after, before) {
			t.Errorf("binding changed: %v -> %v", before, after)
		}
		if r := dynAuthListUsers(e, "active-domain-mismatch-token"); r.Status != 200 {
			t.Errorf("second list = %d", r.Status)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("converges authentication racing a never-used tombstone", func(t *testing.T) {
		accepted := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{afterCredentialAccepted: func(adapter.Record) {
			once.Do(func() { close(accepted) })
			<-release
		}})
		e := inst.testEnv
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "tombstone-race-token", connectionID: "tombstone-race-tenant",
			provisioningDomainID: "tombstone-race-workspace"})
		done := make(chan *response, 1)
		go func() { done <- dynAuthListUsers(e, "tombstone-race-token") }()
		dynAuthWait(t, accepted, "credential acceptance")
		decommissioned := e.mustCall("decommissionSCIMConnection", betterauth.CallInput{Body: map[string]any{
			"connectionId": "tombstone-race-tenant", "provisioningDomainId": "tombstone-race-workspace"}})
		close(release)
		var rejected *response
		select {
		case rejected = <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for authentication")
		}
		if decommissioned["status"] != "complete" {
			t.Errorf("status = %v", decommissioned["status"])
		}
		if rejected.Status != 401 {
			t.Errorf("rejected = %d, want 401", rejected.Status)
		}
		dynAuthExpectSingleBinding(t, e, map[string]any{"connectionId": "tombstone-race-tenant",
			"provisioningDomainId": "tombstone-race-workspace", "decommissionStatus": "complete"})
	})

	t.Run("converges parallel first use on one dynamic binding", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{})
		e := inst.testEnv
		dynAuthAddCredential(e, dynAuthCredentialInput{token: "parallel-token", connectionID: "dynamic-parallel-tenant",
			provisioningDomainID: "parallel-workspace"})
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		for i := range statuses {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				statuses[i] = dynAuthListUsers(e, "parallel-token").Status
			}(i)
		}
		wg.Wait()
		if !reflect.DeepEqual(statuses, []int{200, 200}) {
			t.Errorf("statuses = %v", statuses)
		}
		dynAuthExpectSingleBinding(t, e, map[string]any{"connectionId": "dynamic-parallel-tenant",
			"provisioningDomainId": "parallel-workspace"})
	})

	t.Run("preserves verifier infrastructure failures as server errors", func(t *testing.T) {
		inst := dynAuthCreateInstance(t, dynAuthInstanceOptions{overrides: map[string]dynAuthOverride{
			"infrastructure-error-token": {err: errors.New("dynamic credential store unavailable")},
		}})
		e := inst.testEnv
		r := dynAuthListUsers(e, "infrastructure-error-token")
		if r.Status != 500 {
			t.Errorf("status = %d, want 500 (%s)", r.Status, r.text())
		}
		if got := r.Header.Get("WWW-Authenticate"); got != "" {
			t.Errorf("www-authenticate = %q, want none", got)
		}
		dynAuthExpectEmpty(t, e, "scimConnectionBinding")
	})
}
