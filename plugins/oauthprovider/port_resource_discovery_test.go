package oauthprovider

import (
	"context"
	"errors"
	"reflect"
	"regexp"
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

// Port of resource-discovery.test.ts.

type rsTxKey struct{}

func rsInTx(ctx context.Context) bool { v, _ := ctx.Value(rsTxKey{}).(bool); return v }

// rsSpyAdapter stands in for vi.spyOn(adapter, "transaction" / "create" / "update"):
// Create / Update hooks run only for calls made inside a transaction (the TS tests spy on
// the transaction adapter).
type rsSpyAdapter struct {
	adapter.Adapter
	mu       sync.Mutex
	onTx     func(ctx context.Context, run func() error) error
	onCreate func(ctx context.Context, in adapter.CreateInput) (adapter.Record, error, bool)
	onUpdate func(ctx context.Context, model string) (error, bool)
}

func (s *rsSpyAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	run := func() error {
		return s.Adapter.Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
			return fn(context.WithValue(txCtx, rsTxKey{}, true), tx)
		})
	}
	if s.onTx != nil {
		return s.onTx(ctx, run)
	}
	return run()
}

func (s *rsSpyAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if s.onCreate != nil && rsInTx(ctx) {
		if r, err, handled := s.onCreate(ctx, in); handled {
			return r, err
		}
	}
	return s.Adapter.Create(ctx, in)
}

func (s *rsSpyAdapter) Update(ctx context.Context, model string, where []adapter.Where, update adapter.Record) (adapter.Record, error) {
	if s.onUpdate != nil && rsInTx(ctx) {
		if err, handled := s.onUpdate(ctx, model); handled {
			return nil, err
		}
	}
	return s.Adapter.Update(ctx, model, where, update)
}

// rsSpy installs a spy adapter on the auth context (restored at cleanup).
func rsSpy(t *testing.T, env *testEnv) *rsSpyAdapter {
	ac := env.auth.Context()
	orig := ac.Adapter
	s := &rsSpyAdapter{Adapter: orig}
	ac.Adapter = s
	t.Cleanup(func() { ac.Adapter = orig })
	return s
}

// rsUniqueErr mimics Object.assign(new Error(msg), { code: "23505" }).
type rsUniqueErr struct{ msg string }

func (e *rsUniqueErr) Error() string    { return e.msg }
func (e *rsUniqueErr) SQLState() string { return "23505" }

func rsCtx(env *testEnv) *betterauth.EndpointContext {
	return &betterauth.EndpointContext{Auth: env.auth.Context(), Headers: map[string][]string{}}
}

func rsMetadata(clientID, name string, redirect string) *jsonx.Object {
	m := jsonx.O("client_id", clientID)
	if name != "" {
		m.Set("client_name", name)
	}
	m.Set("redirect_uris", []any{redirect})
	m.Set("token_endpoint_auth_method", "none")
	return m
}

func rsRegisterCIMD(t *testing.T, env *testEnv, in RegisterClientMetadataDocumentInput) *ClientRegistrationResult {
	t.Helper()
	r, err := RegisterClientMetadataDocument(rsCtx(env), in)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return r
}

func rsManagedClientRow(clientID, name, redirect string) adapter.Record {
	now := time.Now()
	return adapter.Record{"clientId": clientID, "clientDiscoveryId": nil, "name": name, "redirectUris": []any{redirect},
		"tokenEndpointAuthMethod": "none", "applicationType": "web", "grantTypes": []any{"authorization_code"},
		"responseTypes": []any{"code"}, "createdAt": now, "updatedAt": now}
}

func rsOpts(env *testEnv) *resolved {
	o, _ := pluginOptions(env.auth.Context())
	return o
}

func rsLinkIDs(env *testEnv, model, clientID string) []string {
	var out []string
	for _, l := range env.findMany(model, eq("clientId", clientID)) {
		out = append(out, recStr(l, "resourceId"))
	}
	return out
}

func rsExpectManaged(t *testing.T, r adapter.Record, name, redirect string) {
	t.Helper()
	if r == nil || r["clientDiscoveryId"] != nil || r["name"] != name || !reflect.DeepEqual(recStrings(r, "redirectUris"), []string{redirect}) {
		t.Fatal(r)
	}
}

func TestRs_DCRResourcesField(t *testing.T) {
	t.Run("unions registration defaults with explicit resources and dedupes the final links", func(t *testing.T) {
		def, req := "https://api.example.com/default", "https://api.example.com/requested"
		env := rsBoot(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true,
			Resources: []ResourceInput{{Identifier: def}, {Identifier: req}}, ClientRegistrationDefaultResources: []string{def, def},
			ClientRegistrationAllowedResources: []string{req}}, nil)
		r := env.mustCall("registerOAuthClient", betterauth.CallInput{Body: map[string]any{
			"redirect_uris": []any{"https://app.example.com/callback"}, "resources": []any{req, def, req}}})
		if !reflect.DeepEqual(r["resources"], []any{def, req}) {
			t.Fatal(r["resources"])
		}
		ids := rsLinkIDs(env, modelClientResource, r["client_id"].(string))
		sort.Strings(ids)
		want := []string{def, req}
		sort.Strings(want)
		if !reflect.DeepEqual(ids, want) {
			t.Fatal(ids)
		}
	})
	t.Run("rejects explicit resources outside the effective registration allowlist", func(t *testing.T) {
		def, dis := "https://api.example.com/default-only", "https://api.example.com/configured-but-disallowed"
		env := rsBoot(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true,
			Resources: []ResourceInput{{Identifier: def}, {Identifier: dis}}, ClientRegistrationDefaultResources: []string{def}}, nil)
		_, err := env.call("registerOAuthClient", betterauth.CallInput{Body: map[string]any{
			"redirect_uris": []any{"https://app.example.com/callback"}, "resources": []any{dis}}})
		rsExpectBodyError(t, err, "invalid_target")
	})
	t.Run("rejects registration resource policies that name unconfigured resources", func(t *testing.T) {
		env := newEnv(t, Options{Resources: []ResourceInput{{Identifier: "https://api.example.com/configured"}},
			ClientRegistrationAllowedResources: []string{"https://api.example.com/not-configured"}}, envOptions{expectInitError: true})
		if env.initErr == nil || !regexp.MustCompile(`not-configured.*not found in resources`).MatchString(env.initErr.Error()) {
			t.Fatal(env.initErr)
		}
	})
	t.Run("registers a client with valid resources and creates link rows", func(t *testing.T) {
		res := "https://api.example.com/dcr-link"
		env := rsBoot(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true,
			Resources: []ResourceInput{{Identifier: res}}, ClientRegistrationAllowedResources: []string{res}}, nil)
		r := env.mustCall("registerOAuthClient", betterauth.CallInput{Body: map[string]any{
			"redirect_uris": []any{"https://app.example.com/callback"}, "resources": []any{res}}})
		cid, _ := r["client_id"].(string)
		if cid == "" || !reflect.DeepEqual(r["resources"], []any{res}) {
			t.Fatal(r)
		}
		if ids := rsLinkIDs(env, modelClientResource, cid); !reflect.DeepEqual(ids, []string{res}) {
			t.Fatal(ids)
		}
		stored := env.findOne(modelClient, eq("clientId", cid))
		md, _ := ParseClientMetadata(stored["metadata"])
		if md != nil && md.Has("resources") {
			t.Fatal(stored["metadata"])
		}
	})
	t.Run("rejects an explicit resource when no registration resources are allowed", func(t *testing.T) {
		env := rsBoot(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true,
			Resources: []ResourceInput{{Identifier: "https://api.example.com/exists"}}}, nil)
		_, err := env.call("registerOAuthClient", betterauth.CallInput{Body: map[string]any{
			"redirect_uris": []any{"https://app.example.com/callback"}, "resources": []any{"https://api.example.com/exists"}}})
		rsExpectBodyError(t, err, "invalid_target")
	})
	t.Run("rejects registration when one requested resource is disabled", func(t *testing.T) {
		res := "https://api.example.com/disabled-test"
		env := rsBoot(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true,
			Resources: []ResourceInput{{Identifier: res}}, ClientRegistrationAllowedResources: []string{res}}, nil)
		env.update(modelResource, adapter.Record{"disabled": true}, eq("identifier", res))
		_, err := env.call("registerOAuthClient", betterauth.CallInput{Body: map[string]any{
			"redirect_uris": []any{"https://app.example.com/callback"}, "resources": []any{res}}})
		rsExpectBodyError(t, err, "invalid_target")
	})
	t.Run("registration without resources still works (no behavior change)", func(t *testing.T) {
		env := rsBoot(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true}, nil)
		r := env.mustCall("registerOAuthClient", betterauth.CallInput{Body: map[string]any{
			"redirect_uris": []any{"https://app.example.com/callback"}}})
		if r["client_id"] == nil {
			t.Fatal(r)
		}
		if _, ok := r["resources"]; ok {
			t.Fatal(r["resources"])
		}
	})
}

func TestRs_ManagedClientRegistrationResources(t *testing.T) {
	t.Run("links server-owned defaults during managed client creation", func(t *testing.T) {
		def := "https://api.example.com/managed-default"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: def}}, ClientRegistrationDefaultResources: []string{def}}, nil)
		h := env.signInWithTestUser()
		r := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{"https://app.example.com/callback"}})
		if !reflect.DeepEqual(r["resources"], []any{def}) {
			t.Fatal(r["resources"])
		}
		links := env.findMany(modelClientResource, eq("clientId", r["client_id"]))
		if len(links) != 1 || links[0]["clientId"] != r["client_id"] || links[0]["resourceId"] != def {
			t.Fatal(links)
		}
	})
	t.Run("rolls back the client when a resource link cannot be inserted", func(t *testing.T) {
		name := "transaction-rollback-client"
		def := "https://api.example.com/rollback-default"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: def}}, ClientRegistrationDefaultResources: []string{def}}, nil)
		h := env.signInWithTestUser()
		spy := rsSpy(t, env)
		spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
			if in.Model == modelClientResource {
				return nil, errors.New("forced resource-link insertion failure"), true
			}
			return nil, nil, false
		}
		_, err := env.auth.API.Call(context.Background(), "adminCreateOAuthClient", betterauth.CallInput{Headers: h,
			Body: map[string]any{"client_name": name, "redirect_uris": []any{"https://app.example.com/callback"}}})
		if err == nil || !strings.Contains(rsErrText(err), "forced resource-link insertion failure") {
			t.Fatalf("got %v", err)
		}
		if r := env.findOne(modelClient, eq("name", name)); r != nil {
			t.Fatal(r)
		}
	})
}

// rsErrText returns the error message including a wrapped cause.
func rsErrText(err error) string {
	s := err.Error()
	if e, ok := betterauth.AsAPIError(err); ok && e.Cause != nil {
		s += " " + e.Cause.Error()
	}
	return s
}

func TestRs_TrustedClientCacheProvenance(t *testing.T) {
	t.Run("does not cache a discovery-owned client when its ID is trusted", func(t *testing.T) {
		cid := "https://client.example.com/trusted-discovery.json"
		d := &ClientDiscovery{ID: "trusted-test-discovery", Matches: func(c string) bool { return c == cid },
			Resolve: func(_ *betterauth.EndpointContext, _ string, existing *SchemaClient) (*SchemaClient, error) {
				return existing, nil
			}}
		env := rsBoot(t, Options{CachedTrustedClients: []string{cid}, Extensions: []*Extension{{ClientDiscovery: []*ClientDiscovery{d}}}}, nil)
		o := rsOpts(env)
		md := rsMetadata(cid, "Trusted Discovery Client", "https://client.example.com/callback")
		rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: d.ID, Metadata: md})
		c, err := getClient(rsCtx(env), o, cid)
		if err != nil || c == nil || c.ClientDiscoveryID != d.ID {
			t.Fatal(c, err)
		}
		o.Extensions = nil
		c, err = getClient(rsCtx(env), o, cid)
		if err != nil || c != nil {
			t.Fatal(c, err)
		}
	})
	t.Run("isolates trusted client cache entries between provider options", func(t *testing.T) {
		cid := "https://client.example.com/provider-isolation.json"
		d := &ClientDiscovery{ID: "provider-one-discovery", Matches: func(c string) bool { return c == cid },
			Resolve: func(_ *betterauth.EndpointContext, _ string, existing *SchemaClient) (*SchemaClient, error) {
				return existing, nil
			}}
		one := rsBoot(t, Options{CachedTrustedClients: []string{cid}, Extensions: []*Extension{{ClientDiscovery: []*ClientDiscovery{d}}}}, nil)
		rsRegisterCIMD(t, one, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: d.ID,
			Metadata: rsMetadata(cid, "Provider One Client", "https://one.example.com/callback")})
		c, err := getClient(rsCtx(one), rsOpts(one), cid)
		if err != nil || c == nil || c.Name != "Provider One Client" {
			t.Fatal(c, err)
		}
		two := rsBoot(t, Options{CachedTrustedClients: []string{cid}}, nil)
		row := rsManagedClientRow(cid, "Provider Two Client", "https://two.example.com/callback")
		if _, err := two.db.Create(context.Background(), adapter.CreateInput{Model: modelClient, Data: row}); err != nil {
			t.Fatal(err)
		}
		c, err = getClient(rsCtx(two), rsOpts(two), cid)
		if err != nil || c == nil || c.Name != "Provider Two Client" {
			t.Fatal(c, err)
		}
	})
}

func TestRs_CanonicalClientMetadataDocumentRegistration(t *testing.T) {
	const discID = "test-client-discovery"
	t.Run("fails closed when the persisted client discovery is not installed", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/orphaned-discovery.json"
		rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: "removed-client-discovery",
			Metadata: rsMetadata(cid, "", "https://client.example.com/callback")})
		c, err := getClient(rsCtx(env), rsOpts(env), cid)
		if err != nil || c != nil {
			t.Fatal(c, err)
		}
	})
	t.Run("preserves omitted application type as null while validating a loopback redirect", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/metadata.json"
		r := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "", "http://127.0.0.1:5198/callback")})
		if r.Client.ApplicationType != "" || r.Client.ClientDiscoveryID != discID {
			t.Fatal(r.Client)
		}
		stored := env.findOne(modelClient, eq("clientId", cid))
		if stored["applicationType"] != nil || stored["clientDiscoveryId"] != discID {
			t.Fatal(stored)
		}
	})
	t.Run("persists through the configured oauthClient model", func(t *testing.T) {
		model := "customCimdOAuthClient"
		env := rsBoot(t, Options{Schema: SchemaOptions{"oauthClient": db.ModelOptions{ModelName: model}}}, nil)
		var created []string
		spy := rsSpy(t, env)
		spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
			created = append(created, in.Model)
			return nil, nil, false
		}
		cid := "https://client.example.com/custom-metadata.json"
		rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "", "https://app.example.com/callback")})
		if r := env.findOne(model, eq("clientId", cid)); r == nil || r["clientId"] != cid {
			t.Fatal(r)
		}
		// Go passes logical model keys to the adapter, which maps them to the configured
		// model name.
		if !rsContains(created, modelClient) || env.db.Schema().Table(modelClient).ModelName != model {
			t.Fatal(created)
		}
	})
	t.Run("atomically refreshes custom client and resource models without duplicating links", func(t *testing.T) {
		clientModel, linkModel := "customCimdOAuthClient", "customCimdOAuthClientResource"
		res := "https://api.example.com/cimd"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: res}}, ClientRegistrationDefaultResources: []string{res},
			Schema: SchemaOptions{"oauthClient": db.ModelOptions{ModelName: clientModel}, "oauthClientResource": db.ModelOptions{ModelName: linkModel}}}, nil)
		cid := "https://client.example.com/refresh.json"
		rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Before Refresh", "https://client.example.com/callback")})
		env.update(clientModel, adapter.Record{"disabled": true, "skipConsent": true, "enableEndSession": true}, eq("clientId", cid))
		operator := env.findOne(clientModel, eq("clientId", cid))
		if operator == nil {
			t.Fatal("created client was not persisted")
		}
		refreshed := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			ExistingClient: ClientFromRecord(operator), Metadata: rsMetadata(cid, "After Refresh", "https://client.example.com/callback")})
		c := refreshed.Client
		if refreshed.Created || c.Name != "After Refresh" || !isTrue(c.Disabled) || !isTrue(c.SkipConsent) || !isTrue(c.EnableEndSession) {
			t.Fatal(refreshed.Created, c)
		}
		if ids := rsLinkIDs(env, linkModel, cid); !reflect.DeepEqual(ids, []string{res}) {
			t.Fatal(ids)
		}
	})
	t.Run("converges a stale fixed-ID creator after a unique-constraint race", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/concurrent.json"
		rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "First Writer", "https://client.example.com/callback")})
		r := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Concurrent Writer", "https://client.example.com/callback")})
		if r.Created || r.Client.Name != "Concurrent Writer" {
			t.Fatal(r.Created, r.Client.Name)
		}
	})
	t.Run("does not take over a managed client after a fixed-ID registration race", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/managed-race.json"
		if _, err := env.db.Create(context.Background(), adapter.CreateInput{Model: modelClient,
			Data: rsManagedClientRow(cid, "Managed Client", "https://managed.example.com/callback")}); err != nil {
			t.Fatal(err)
		}
		cause := &rsUniqueErr{"unique constraint on managed client"}
		spy := rsSpy(t, env)
		spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
			if in.Model == modelClient {
				return nil, cause, true
			}
			return nil, nil, false
		}
		_, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Discovered Client", "https://discovered.example.com/callback")})
		if err != cause {
			t.Fatalf("expected the collision cause, got %v", err)
		}
		rsExpectManaged(t, env.findOne(modelClient, eq("clientId", cid)), "Managed Client", "https://managed.example.com/callback")
	})
	t.Run("rejects a managed client supplied to the discovery refresh seam", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/managed-refresh.json"
		managed, err := env.db.Create(context.Background(), adapter.CreateInput{Model: modelClient,
			Data: rsManagedClientRow(cid, "Managed Client", "https://managed.example.com/callback")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			ExistingClient: ClientFromRecord(managed), Metadata: rsMetadata(cid, "Discovered Client", "https://discovered.example.com/callback")}); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("does not overwrite a managed replacement from a stale discovery refresh", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/stale-refresh.json"
		disc := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Discovered Client", "https://discovered.example.com/callback")})
		if err := env.db.Delete(context.Background(), modelClient, []adapter.Where{eq("clientId", cid)}); err != nil {
			t.Fatal(err)
		}
		if _, err := env.db.Create(context.Background(), adapter.CreateInput{Model: modelClient,
			Data: rsManagedClientRow(cid, "Managed Replacement", "https://managed.example.com/callback")}); err != nil {
			t.Fatal(err)
		}
		_, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			ExistingClient: disc.Client, Metadata: rsMetadata(cid, "Stale Refresh", "https://stale.example.com/callback")})
		e, _ := betterauth.AsAPIError(err)
		if errBody(e)["error_description"] != "client no longer exists" {
			t.Fatalf("got %v", err)
		}
		rsExpectManaged(t, env.findOne(modelClient, eq("clientId", cid)), "Managed Replacement", "https://managed.example.com/callback")
	})
	t.Run("converges a metadata refresh only after the exact raced link is committed", func(t *testing.T) {
		res := "https://api.example.com/concurrent-link"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		cid := "https://client.example.com/concurrent-link.json"
		created := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Before Link Race", "https://client.example.com/callback")})
		rsOpts(env).ClientRegistrationDefaultResources = []string{res}
		spy := rsSpy(t, env)
		attempts := 0
		failLinks := false
		spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
			if failLinks && in.Model == modelClientResource {
				return nil, &rsUniqueErr{"unique constraint on client resource"}, true
			}
			return nil, nil, false
		}
		spy.onTx = func(ctx context.Context, run func() error) error {
			attempts++
			if attempts > 1 {
				return run()
			}
			failLinks = true
			err := run()
			failLinks = false
			if err != nil {
				if _, cerr := spy.Adapter.Create(context.Background(), adapter.CreateInput{Model: modelClientResource,
					Data: adapter.Record{"clientId": cid, "resourceId": res, "createdAt": time.Now()}}); cerr != nil {
					t.Fatal(cerr)
				}
			}
			return err
		}
		r := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			ExistingClient: created.Client, Metadata: rsMetadata(cid, "After Link Race", "https://client.example.com/callback")})
		if attempts != 2 || r.Created || r.Client.Name != "After Link Race" {
			t.Fatal(attempts, r.Created, r.Client.Name)
		}
		if ids := rsLinkIDs(env, modelClientResource, cid); !reflect.DeepEqual(ids, []string{res}) {
			t.Fatal(ids)
		}
	})
	t.Run("rethrows an unproven link-row unique cause without retrying", func(t *testing.T) {
		res := "https://api.example.com/unproven-link"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		cid := "https://client.example.com/unproven-link.json"
		created := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Before Unproven Link", "https://client.example.com/callback")})
		rsOpts(env).ClientRegistrationDefaultResources = []string{res}
		cause := &rsUniqueErr{"unique constraint without committed link"}
		spy := rsSpy(t, env)
		attempts := 0
		spy.onTx = func(ctx context.Context, run func() error) error { attempts++; return run() }
		spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
			if in.Model == modelClientResource {
				return nil, cause, true
			}
			return nil, nil, false
		}
		_, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			ExistingClient: created.Client, Metadata: rsMetadata(cid, "After Unproven Link", "https://client.example.com/callback")})
		if err != cause || attempts != 1 {
			t.Fatal(err, attempts)
		}
		if r := env.findOne(modelClientResource, eq("clientId", cid), eq("resourceId", res)); r != nil {
			t.Fatal(r)
		}
	})
	t.Run("preserves an unrelated unique error thrown by client update", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/update-unique.json"
		created := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Before Update Failure", "https://client.example.com/callback")})
		cause := &rsUniqueErr{"unique constraint from unrelated update field"}
		spy := rsSpy(t, env)
		attempts := 0
		once := false
		spy.onTx = func(ctx context.Context, run func() error) error { attempts++; once = true; return run() }
		spy.onUpdate = func(_ context.Context, _ string) (error, bool) {
			if once {
				once = false
				return cause, true
			}
			return nil, false
		}
		_, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			ExistingClient: created.Client, Metadata: rsMetadata(cid, "After Update Failure", "https://client.example.com/callback")})
		if err != cause || attempts != 1 {
			t.Fatal(err, attempts)
		}
	})
	t.Run("preserves an unrelated unique error thrown by the transaction", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/transaction-unique.json"
		md := rsMetadata(cid, "Transaction Failure", "https://client.example.com/callback")
		rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID, Metadata: md})
		cause := &rsUniqueErr{"unique constraint from transaction"}
		spy := rsSpy(t, env)
		attempts := 0
		spy.onTx = func(ctx context.Context, run func() error) error {
			attempts++
			if attempts == 1 {
				return cause
			}
			return run()
		}
		_, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID, Metadata: md})
		if err != cause || attempts != 1 {
			t.Fatal(err, attempts)
		}
	})
	t.Run("does not mask a non-unique persistence failure when the fixed ID already exists", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		cid := "https://client.example.com/non-unique-failure.json"
		md := rsMetadata(cid, "Existing Client", "https://client.example.com/callback")
		rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID, Metadata: md})
		spy := rsSpy(t, env)
		once := false
		spy.onTx = func(ctx context.Context, run func() error) error { once = true; return run() }
		spy.onCreate = func(_ context.Context, _ adapter.CreateInput) (adapter.Record, error, bool) {
			if once {
				once = false
				return nil, errors.New("storage unavailable"), true
			}
			return nil, nil, false
		}
		_, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID, Metadata: md})
		if err == nil || !strings.Contains(err.Error(), "storage unavailable") {
			t.Fatal(err)
		}
	})
	t.Run("rolls back a metadata replacement when a new default resource link fails", func(t *testing.T) {
		orig, added := "https://api.example.com/original", "https://api.example.com/added"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: orig}, {Identifier: added}},
			ClientRegistrationDefaultResources: []string{orig}}, nil)
		cid := "https://client.example.com/atomic-refresh.json"
		created := rsRegisterCIMD(t, env, RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			Metadata: rsMetadata(cid, "Before Atomic Refresh", "https://client.example.com/callback")})
		rsOpts(env).ClientRegistrationDefaultResources = []string{orig, added}
		spy := rsSpy(t, env)
		spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
			if in.Model == modelClientResource && in.Data["resourceId"] == added {
				return nil, errors.New("forced refresh-link failure"), true
			}
			return nil, nil, false
		}
		_, err := RegisterClientMetadataDocument(rsCtx(env), RegisterClientMetadataDocumentInput{ClientID: cid, ClientDiscoveryID: discID,
			ExistingClient: created.Client, Metadata: rsMetadata(cid, "After Atomic Refresh", "https://client.example.com/callback")})
		if err == nil || !strings.Contains(err.Error(), "forced refresh-link failure") {
			t.Fatal(err)
		}
		if r := env.findOne(modelClient, eq("clientId", cid)); r == nil || r["name"] != "Before Atomic Refresh" {
			t.Fatal(r)
		}
		if ids := rsLinkIDs(env, modelClientResource, cid); !reflect.DeepEqual(ids, []string{orig}) {
			t.Fatal(ids)
		}
	})
}

func TestRs_CanonicalDynamicClientRegistration(t *testing.T) {
	t.Run("persists through the configured oauthClient model", func(t *testing.T) {
		model := "customDcrOAuthClient"
		env := rsBoot(t, Options{AllowDynamicClientRegistration: true, AllowUnauthenticatedClientRegistration: true,
			Schema: SchemaOptions{"oauthClient": db.ModelOptions{ModelName: model}}}, nil)
		var created []string
		spy := rsSpy(t, env)
		spy.onCreate = func(_ context.Context, in adapter.CreateInput) (adapter.Record, error, bool) {
			created = append(created, in.Model)
			return nil, nil, false
		}
		r := env.mustCall("registerOAuthClient", betterauth.CallInput{Body: map[string]any{"redirect_uris": []any{"https://app.example.com/callback"}}})
		if s := env.findOne(model, eq("clientId", r["client_id"])); s == nil || s["clientId"] != r["client_id"] {
			t.Fatal(s)
		}
		if !rsContains(created, modelClient) || env.db.Schema().Table(modelClient).ModelName != model {
			t.Fatal(created)
		}
	})
}
