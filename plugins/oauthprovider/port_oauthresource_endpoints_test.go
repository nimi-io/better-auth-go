package oauthprovider

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Port of oauthResource/endpoints.test.ts.

type rsInstance struct {
	*testEnv
	h http.Header
}

func rsBootSignedIn(t *testing.T, opts Options) *rsInstance {
	t.Helper()
	env := rsBoot(t, opts, nil)
	return &rsInstance{testEnv: env, h: env.signInWithTestUser()}
}

func (i *rsInstance) createResource(body map[string]any) map[string]any {
	i.t.Helper()
	return i.mustCall("adminCreateOAuthResource", betterauth.CallInput{Headers: i.h, Body: body})
}

func (i *rsInstance) callID(key, identifier string, body map[string]any) (map[string]any, *betterauth.APIError) {
	i.t.Helper()
	in := betterauth.CallInput{Headers: i.h, Params: map[string]string{"identifier": identifier}}
	if body != nil {
		in.Body = body
	}
	res, err := i.call(key, in)
	if err != nil {
		return nil, err
	}
	return decodeMap(i.t, res), nil
}

func (i *rsInstance) link(key, identifier, clientID string) (map[string]any, *betterauth.APIError) {
	i.t.Helper()
	res, err := i.call(key, betterauth.CallInput{Headers: i.h, Params: map[string]string{"identifier": identifier, "client_id": clientID}})
	if err != nil {
		return nil, err
	}
	return decodeMap(i.t, res), nil
}

func (i *rsInstance) seedClient(model, clientID string) {
	i.t.Helper()
	now := time.Now()
	if _, err := i.db.Create(i.ctx(), adapter.CreateInput{Model: model, Data: adapter.Record{"clientId": clientID,
		"redirectUris": []any{"https://example.com/callback"}, "createdAt": now, "updatedAt": now}}); err != nil {
		i.t.Fatal(err)
	}
}

func rsExpectBodyError(t *testing.T, err *betterauth.APIError, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s", code)
	}
	if b := errBody(err); b["error"] != code {
		t.Fatalf("expected error %s, got %v", code, b)
	}
}

func TestRs_ResourceAdminCRUD(t *testing.T) {
	t.Run("create + read round-trips", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		created := i.createResource(map[string]any{"identifier": "https://api.example.com/created", "name": "Created Resource", "accessTokenTtl": 300})
		if created["identifier"] != "https://api.example.com/created" {
			t.Fatal(created)
		}
		fetched, err := i.callID("adminGetOAuthResource", "https://api.example.com/created", nil)
		if err != nil || fetched["name"] != "Created Resource" || fetched["accessTokenTtl"] != float64(300) {
			t.Fatal(fetched, errBody(err))
		}
	})
	t.Run("rejects identifiers that aren't absolute URIs", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		_, err := i.call("adminCreateOAuthResource", betterauth.CallInput{Headers: i.h, Body: map[string]any{"identifier": "not-a-uri"}})
		rsExpectBodyError(t, err, "invalid_target")
	})
	t.Run("rejects identifiers with a fragment", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		_, err := i.call("adminCreateOAuthResource", betterauth.CallInput{Headers: i.h, Body: map[string]any{"identifier": "https://api.example.com/x#fragment"}})
		rsExpectBodyError(t, err, "invalid_target")
	})
	t.Run("rejects duplicate identifiers", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": "https://api.example.com/dup"})
		_, err := i.call("adminCreateOAuthResource", betterauth.CallInput{Headers: i.h, Body: map[string]any{"identifier": "https://api.example.com/dup"}})
		rsExpectBodyError(t, err, "invalid_request")
	})
	t.Run("update only touches specified fields", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		id := "https://api.example.com/update-me"
		i.createResource(map[string]any{"identifier": id, "name": "Original", "accessTokenTtl": 600, "allowedScopes": []any{"read"}})
		updated, err := i.callID("adminUpdateOAuthResource", id, map[string]any{"accessTokenTtl": 60})
		if err != nil || updated == nil || updated["accessTokenTtl"] != float64(60) {
			t.Fatal(updated, errBody(err))
		}
		fetched, _ := i.callID("adminGetOAuthResource", id, nil)
		if fetched["accessTokenTtl"] != float64(60) || fetched["name"] != "Original" || !reflect.DeepEqual(fetched["allowedScopes"], []any{"read"}) {
			t.Fatal(fetched)
		}
	})
	t.Run("update on a missing identifier returns 404", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		_, err := i.callID("adminUpdateOAuthResource", "https://api.example.com/missing", map[string]any{"accessTokenTtl": 120})
		rsExpectBodyError(t, err, "not_found")
	})
	t.Run("delete removes the row and 404s on subsequent reads", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		id := "https://api.example.com/delete-me"
		i.createResource(map[string]any{"identifier": id})
		if _, err := i.callID("adminDeleteOAuthResource", id, nil); err != nil {
			t.Fatal(errBody(err))
		}
		_, err := i.callID("adminGetOAuthResource", id, nil)
		rsExpectBodyError(t, err, "not_found")
	})
	t.Run("list returns all resources", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": "https://api.example.com/a"})
		i.createResource(map[string]any{"identifier": "https://api.example.com/b"})
		res, err := i.call("adminListOAuthResources", betterauth.CallInput{Headers: i.h})
		if err != nil {
			t.Fatal(errBody(err))
		}
		var list []map[string]any
		if e := res.Decode(&list); e != nil {
			t.Fatal(e)
		}
		var ids []string
		for _, r := range list {
			s, _ := r["identifier"].(string)
			ids = append(ids, s)
		}
		if !rsContains(ids, "https://api.example.com/a") || !rsContains(ids, "https://api.example.com/b") {
			t.Fatal(ids)
		}
	})
}

func TestRs_ResourcePrivilegesGate(t *testing.T) {
	t.Run("blocks create when resourcePrivileges returns false", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{ResourcePrivileges: func(c PrivilegeContext) (bool, error) { return c.Action != "create", nil }})
		_, err := i.call("adminCreateOAuthResource", betterauth.CallInput{Headers: i.h, Body: map[string]any{"identifier": "https://api.example.com/gated"}})
		if err == nil || err.Status != "UNAUTHORIZED" {
			t.Fatal(err)
		}
	})
	t.Run("allows actions the callback approves", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{ResourcePrivileges: func(c PrivilegeContext) (bool, error) {
			return c.Action == "create" || c.Action == "read", nil
		}})
		i.createResource(map[string]any{"identifier": "https://api.example.com/approved"})
		if r, err := i.callID("adminGetOAuthResource", "https://api.example.com/approved", nil); err != nil || r == nil {
			t.Fatal(errBody(err))
		}
	})
	t.Run("blocks list independently of read", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{ResourcePrivileges: func(c PrivilegeContext) (bool, error) { return c.Action != "list", nil }})
		_, err := i.call("adminListOAuthResources", betterauth.CallInput{Headers: i.h})
		if err == nil || err.Status != "UNAUTHORIZED" {
			t.Fatal(err)
		}
	})
}

func TestRs_ClientResourceLinking(t *testing.T) {
	links := func(i *rsInstance, field, v string) []adapter.Record {
		return i.findMany(modelClientResource, eq(field, v))
	}
	t.Run("link creates the join row and unlink removes it", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.seedClient(modelClient, "test-client")
		id := "https://api.example.com/linked"
		i.createResource(map[string]any{"identifier": id})
		if _, err := i.link("adminLinkClientResource", id, "test-client"); err != nil {
			t.Fatal(errBody(err))
		}
		l := links(i, "clientId", "test-client")
		if len(l) != 1 || l[0]["resourceId"] != id {
			t.Fatal(l)
		}
		if _, err := i.link("adminUnlinkClientResource", id, "test-client"); err != nil {
			t.Fatal(errBody(err))
		}
		if l := links(i, "clientId", "test-client"); len(l) != 0 {
			t.Fatal(l)
		}
	})
	t.Run("link is idempotent on repeat calls", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.seedClient(modelClient, "idempotent-client")
		id := "https://api.example.com/idempotent"
		i.createResource(map[string]any{"identifier": id})
		if _, err := i.link("adminLinkClientResource", id, "idempotent-client"); err != nil {
			t.Fatal(errBody(err))
		}
		second, err := i.link("adminLinkClientResource", id, "idempotent-client")
		if err != nil || second["alreadyLinked"] != true {
			t.Fatal(second, errBody(err))
		}
	})
	t.Run("link rejects an unknown resource", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.seedClient(modelClient, "client-x")
		_, err := i.link("adminLinkClientResource", "https://api.example.com/nope", "client-x")
		rsExpectBodyError(t, err, "not_found")
	})
	t.Run("link rejects an unknown client", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": "https://api.example.com/orphan"})
		_, err := i.link("adminLinkClientResource", "https://api.example.com/orphan", "no-such-client")
		rsExpectBodyError(t, err, "not_found")
	})
	t.Run("concurrent link attempts for the same pair produce exactly one row", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.seedClient(modelClient, "race-client")
		id := "https://api.example.com/race"
		i.createResource(map[string]any{"identifier": id})
		var wg sync.WaitGroup
		errs := make([]error, 5)
		for n := 0; n < 5; n++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				_, err := i.auth.API.Call(i.ctx(), "adminLinkClientResource", betterauth.CallInput{Headers: i.h,
					Params: map[string]string{"identifier": id, "client_id": "race-client"}})
				errs[n] = err
			}(n)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		l := links(i, "clientId", "race-client")
		if len(l) != 1 || l[0]["resourceId"] != id {
			t.Fatal(l)
		}
	})
	t.Run("link resolves the client through a custom oauthClient model name", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{Schema: SchemaOptions{"oauthClient": db.ModelOptions{ModelName: "customOauthClient"}}})
		i.seedClient("customOauthClient", "remapped-client")
		id := "https://api.example.com/remapped"
		i.createResource(map[string]any{"identifier": id})
		if _, err := i.link("adminLinkClientResource", id, "remapped-client"); err != nil {
			t.Fatal(errBody(err))
		}
		l := links(i, "clientId", "remapped-client")
		if len(l) != 1 || l[0]["resourceId"] != id {
			t.Fatal(l)
		}
	})
}

func TestRs_ResourceAdminSigningAlgorithmValidation(t *testing.T) {
	t.Run("rejects bad signingAlgorithm at create time, not at sign time", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		if _, err := i.call("adminCreateOAuthResource", betterauth.CallInput{Headers: i.h,
			Body: map[string]any{"identifier": "https://api.example.com/bad-alg", "signingAlgorithm": "HS256"}}); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("rejects unknown signingAlgorithm at create time", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		if _, err := i.call("adminCreateOAuthResource", betterauth.CallInput{Headers: i.h,
			Body: map[string]any{"identifier": "https://api.example.com/bogus-alg", "signingAlgorithm": "not-an-alg"}}); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("accepts every supported JWS asymmetric algorithm", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		for _, alg := range []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"} {
			r := i.createResource(map[string]any{"identifier": "https://api.example.com/alg-" + strings.ToLower(alg), "signingAlgorithm": alg})
			if r == nil {
				t.Fatal(alg)
			}
		}
	})
	t.Run("rejects bad signingAlgorithm at update time too", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": "https://api.example.com/upd-alg"})
		if _, err := i.callID("adminUpdateOAuthResource", "https://api.example.com/upd-alg", map[string]any{"signingAlgorithm": "HS256"}); err == nil {
			t.Fatal("expected rejection")
		}
	})
}

func TestRs_PathParamDecoding(t *testing.T) {
	const raw = "https://api.example.com/path-decode"
	enc := url.QueryEscape(raw) // encodeURIComponent for this value
	t.Run("read endpoint decodes a percent-encoded URI identifier", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": raw, "name": "Path Decode"})
		r, err := i.callID("adminGetOAuthResource", enc, nil)
		if err != nil || r["identifier"] != raw || r["name"] != "Path Decode" {
			t.Fatal(r, errBody(err))
		}
	})
	t.Run("update endpoint decodes a percent-encoded URI identifier", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": raw, "accessTokenTtl": 600})
		if _, err := i.callID("adminUpdateOAuthResource", enc, map[string]any{"accessTokenTtl": 90}); err != nil {
			t.Fatal(errBody(err))
		}
		r, _ := i.callID("adminGetOAuthResource", raw, nil)
		if r["accessTokenTtl"] != float64(90) {
			t.Fatal(r)
		}
	})
	t.Run("delete endpoint decodes a percent-encoded URI identifier", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": raw})
		if _, err := i.callID("adminDeleteOAuthResource", enc, nil); err != nil {
			t.Fatal(errBody(err))
		}
		_, err := i.callID("adminGetOAuthResource", raw, nil)
		rsExpectBodyError(t, err, "not_found")
	})
	t.Run("link / unlink endpoints decode both percent-encoded path segments", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		i.createResource(map[string]any{"identifier": raw})
		client := i.adminCreateClient(i.h, map[string]any{"redirect_uris": []any{"https://app.example.com/cb"}})
		cid := client["client_id"].(string)
		if _, err := i.link("adminLinkClientResource", enc, url.QueryEscape(cid)); err != nil {
			t.Fatal(errBody(err))
		}
		after := i.findMany(modelClientResource, eq("resourceId", raw))
		if len(after) != 1 || after[0]["clientId"] != cid {
			t.Fatal(after)
		}
		if _, err := i.link("adminUnlinkClientResource", enc, url.QueryEscape(cid)); err != nil {
			t.Fatal(errBody(err))
		}
		if after := i.findMany(modelClientResource, eq("resourceId", raw)); len(after) != 0 {
			t.Fatal(after)
		}
	})
	t.Run("falls back to raw identifier when decodeURIComponent throws (malformed escape)", func(t *testing.T) {
		i := rsBootSignedIn(t, Options{})
		_, err := i.callID("adminGetOAuthResource", "%ZZ-not-valid", nil)
		rsExpectBodyError(t, err, "not_found")
	})
}
