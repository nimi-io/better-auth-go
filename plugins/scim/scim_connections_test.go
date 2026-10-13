package scim

// Port of upstream scim-connections.test.ts.

import (
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

const connectionsUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// connectionsNoNativeTx is withoutNativeTransactions(memoryAdapter(data)).
type connectionsNoNativeTx struct{ adapter.Adapter }

func (connectionsNoNativeTx) SupportsNativeTransactions() bool { return false }

func connectionsEnv(t *testing.T, conns ...ConnectionOptions) *testEnv {
	t.Helper()
	return newEnv(t, Options{Connections: conns})
}

func connectionsCreateUser(e *testEnv, token string, body map[string]any) map[string]any {
	e.t.Helper()
	b := map[string]any{"schemas": []any{connectionsUserSchema}}
	for k, v := range body {
		b[k] = v
	}
	return e.mustCall("createSCIMUser", betterauth.CallInput{Body: b, Headers: bearer(token)})
}

func connectionsFindRow(rows []adapter.Record, id any) adapter.Record {
	for _, r := range rows {
		if r["id"] == id {
			return r
		}
	}
	return nil
}

func connectionsHasRow(rows []adapter.Record, id any) bool {
	return connectionsFindRow(rows, id) != nil
}

func TestConnections(t *testing.T) {
	t.Run("rejects ambiguous connection identifiers and bearer credentials", func(t *testing.T) {
		_, err := NewE(Options{Connections: []ConnectionOptions{{
			ID:          " workforce ",
			Credentials: []BearerCredential{{Type: "bearer", ID: "valid-token", Token: "valid-token"}},
		}}})
		if err == nil || !strings.Contains(err.Error(), "SCIM connection ids must be trimmed") {
			t.Fatalf("err = %v", err)
		}
		_, err = NewE(Options{Connections: []ConnectionOptions{{
			ID:          "workforce",
			Credentials: []BearerCredential{{Type: "bearer", ID: "invalid-token", Token: "invalid token"}},
		}}})
		if err == nil || !strings.Contains(err.Error(), "SCIM bearer tokens cannot be empty or contain whitespace") {
			t.Fatalf("err = %v", err)
		}
		// scim() throws: New panics with the same error.
		func() {
			defer func() {
				r := recover()
				if r == nil || !strings.Contains(r.(error).Error(), "SCIM connection ids must be trimmed") {
					t.Fatalf("panic = %v", r)
				}
			}()
			New(Options{Connections: []ConnectionOptions{{
				ID:          " workforce ",
				Credentials: []BearerCredential{{Type: "bearer", ID: "valid-token", Token: "valid-token"}},
			}}})
		}()
	})

	t.Run("provisions a connection-owned SCIM resource without an organization or account", func(t *testing.T) {
		e := connectionsEnv(t, staticConnection("workforce", "test-scim-token"))
		created := connectionsCreateUser(e, "test-scim-token", map[string]any{
			"userName": "ada@example.com",
			"name":     map[string]any{"formatted": "Ada Lovelace"},
		})
		retrieved := e.mustCall("getSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": created["id"].(string)}, Headers: bearer("test-scim-token"),
		})
		scimUser := connectionsFindRow(e.mem.Rows("scimUser"), created["id"])
		httpContractMustMatch(t, retrieved, map[string]any{"id": created["id"], "userName": "ada@example.com"})
		if scimUser == nil || scimUser["connectionId"] != "workforce" {
			t.Fatalf("scimUser = %v", scimUser)
		}
		if uid, ok := scimUser["userId"].(string); !ok || uid == "" || uid == created["id"] {
			t.Fatalf("scimUser.userId = %#v (created id %v)", scimUser["userId"], created["id"])
		}
		if n := len(e.mem.Rows("account")); n != 0 {
			t.Fatalf("accounts = %d", n)
		}
	})

	t.Run("deactivates a SCIM User without deleting the global Better Auth User", func(t *testing.T) {
		e := connectionsEnv(t, staticConnection("workforce", "test-scim-token"))
		created := connectionsCreateUser(e, "test-scim-token", map[string]any{"userName": "grace@example.com"})
		id := created["id"].(string)
		e.mustCall("patchSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id},
			Body: map[string]any{
				"schemas":    []any{httpContractPatchSchema},
				"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}},
			},
			Headers: bearer("test-scim-token"),
		})
		retrieved := e.mustCall("getSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id}, Headers: bearer("test-scim-token"),
		})
		scimUser := connectionsFindRow(e.mem.Rows("scimUser"), id)
		if retrieved["active"] != false {
			t.Fatalf("retrieved.active = %v", retrieved["active"])
		}
		if scimUser == nil || scimUser["active"] != false {
			t.Fatalf("scimUser = %v", scimUser)
		}
		if !connectionsHasRow(e.mem.Rows("user"), scimUser["userId"]) {
			t.Fatal("Better Auth user was deleted")
		}
	})

	t.Run("lists only SCIM Users owned by the authenticated connection", func(t *testing.T) {
		e := connectionsEnv(t,
			staticConnection("workforce-a", "connection-a-token"),
			staticConnection("workforce-b", "connection-b-token"))
		a := connectionsCreateUser(e, "connection-a-token", map[string]any{"userName": "ada@connection-a.test"})
		b := connectionsCreateUser(e, "connection-b-token", map[string]any{"userName": "grace@connection-b.test"})
		listed := e.mustCall("listSCIMUsers", betterauth.CallInput{Headers: bearer("connection-a-token")})
		httpContractMustMatch(t, listed, map[string]any{
			"totalResults": 1,
			"Resources":    []any{map[string]any{"id": a["id"]}},
		})
		for _, r := range listed["Resources"].([]any) {
			if r.(map[string]any)["id"] == b["id"] {
				t.Fatal("listed a user owned by another connection")
			}
		}
	})

	t.Run("replaces a SCIM User while preserving its connection-owned identity", func(t *testing.T) {
		e := connectionsEnv(t, staticConnection("workforce", "test-scim-token"))
		created := connectionsCreateUser(e, "test-scim-token", map[string]any{
			"userName":   "ada@example.com",
			"name":       map[string]any{"formatted": "Ada Lovelace"},
			"externalId": "directory-user-1",
		})
		id := created["id"].(string)
		originalLink := connectionsFindRow(e.mem.Rows("scimUser"), id)
		if originalLink == nil {
			t.Fatal("Expected a SCIM User link")
		}
		replaced := e.mustCall("replaceSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id},
			Body: map[string]any{
				"schemas":    []any{connectionsUserSchema},
				"userName":   "augusta@example.com",
				"name":       map[string]any{"formatted": "Augusta Ada King"},
				"externalId": "directory-user-2",
				"active":     false,
			},
			Headers: bearer("test-scim-token"),
		})
		retrieved := e.mustCall("getSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id}, Headers: bearer("test-scim-token"),
		})
		updatedLink := connectionsFindRow(e.mem.Rows("scimUser"), id)
		if replaced["id"] != id {
			t.Fatalf("replaced id = %v", replaced["id"])
		}
		httpContractMustMatch(t, retrieved, map[string]any{
			"id":         id,
			"userName":   "augusta@example.com",
			"name":       map[string]any{"formatted": "Augusta Ada King"},
			"externalId": "directory-user-2",
			"active":     false,
			"emails":     []any{map[string]any{"primary": true, "value": "augusta@example.com"}},
		})
		httpContractMustMatch(t, map[string]any(updatedLink), map[string]any{
			"id":           id,
			"connectionId": "workforce",
			"userId":       originalLink["userId"],
			"userName":     "augusta@example.com",
			"externalId":   "directory-user-2",
			"active":       false,
		})
		if n := len(e.mem.Rows("account")); n != 0 {
			t.Fatalf("accounts = %d", n)
		}
	})

	t.Run("deletes only the SCIM User link and preserves the Better Auth User", func(t *testing.T) {
		e := connectionsEnv(t, staticConnection("workforce", "test-scim-token"))
		created := connectionsCreateUser(e, "test-scim-token", map[string]any{"userName": "katherine@example.com"})
		id := created["id"].(string)
		link := connectionsFindRow(e.mem.Rows("scimUser"), id)
		if link == nil {
			t.Fatal("Expected a SCIM User link")
		}
		if _, ae := e.call("deleteSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id}, Headers: bearer("test-scim-token"),
		}); ae != nil {
			t.Fatalf("delete: %d %v", ae.StatusCode, errBody(ae))
		}
		if connectionsHasRow(e.mem.Rows("scimUser"), id) {
			t.Fatal("SCIM user link still present")
		}
		_, ae := e.call("getSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id}, Headers: bearer("test-scim-token"),
		})
		if ae == nil {
			t.Fatal("expected a rejection")
		}
		wantBody := map[string]any{
			"detail":  "SCIM User not found",
			"schemas": []any{httpContractErrorSchema},
			"status":  "404",
		}
		if got := errBody(ae); !reflect.DeepEqual(got, wantBody) {
			t.Fatalf("body = %v", got)
		}
		if !connectionsHasRow(e.mem.Rows("user"), link["userId"]) {
			t.Fatal("Better Auth user was deleted")
		}
		if n := len(e.mem.Rows("account")); n != 0 {
			t.Fatalf("accounts = %d", n)
		}
		// Upstream: error.message === "SCIM User not found" (createSCIMError sets
		// error.message = detail). Go's APIError.Error() reads body.message (core), so the
		// SCIM detail carries the message.
		if d := getStr(ae.Body, "detail"); d != "SCIM User not found" {
			t.Fatalf("detail = %q", d)
		}
	})

	t.Run("filters and paginates the connection-owned User collection", func(t *testing.T) {
		e := connectionsEnv(t, staticConnection("workforce", "test-scim-token"))
		connectionsCreateUser(e, "test-scim-token", map[string]any{"userName": "ada@example.com"})
		second := connectionsCreateUser(e, "test-scim-token", map[string]any{"userName": "grace@example.com"})
		connectionsCreateUser(e, "test-scim-token", map[string]any{"userName": "katherine@example.com"})
		list := func(q map[string]any) map[string]any {
			return e.mustCall("listSCIMUsers", betterauth.CallInput{Query: q, Headers: bearer("test-scim-token")})
		}
		existingMatch := list(map[string]any{"filter": `userName eq "grace@example.com"`})
		nonexistentMatch := list(map[string]any{"filter": `userName eq "missing@example.com"`})
		secondPage := list(map[string]any{"startIndex": 2, "count": 1})
		rows := e.mem.Rows("scimUser")
		sort.SliceStable(rows, func(i, j int) bool { return rows[i]["orderKey"].(string) < rows[j]["orderKey"].(string) })
		expectedSecondPageID := rows[1]["id"]

		httpContractMustMatch(t, existingMatch, map[string]any{"totalResults": 1, "startIndex": 1, "itemsPerPage": 1})
		httpContractMustMatch(t, existingMatch["Resources"], []any{map[string]any{"id": second["id"]}})
		wantEmpty := map[string]any{
			"schemas":      []any{httpContractListSchema},
			"totalResults": float64(0),
			"startIndex":   float64(1),
			"itemsPerPage": float64(0),
			"Resources":    []any{},
		}
		if !reflect.DeepEqual(nonexistentMatch, wantEmpty) {
			t.Fatalf("nonexistent match = %v", nonexistentMatch)
		}
		httpContractMustMatch(t, secondPage, map[string]any{"totalResults": 3, "startIndex": 2, "itemsPerPage": 1})
		httpContractMustMatch(t, secondPage["Resources"], []any{map[string]any{"id": expectedSecondPageID}})
		keys := map[any]bool{}
		for _, r := range rows {
			keys[r["orderKey"]] = true
		}
		if len(keys) != 3 {
			t.Fatalf("distinct order keys = %d", len(keys))
		}
	})

	t.Run("accepts overlapping bearer credentials and rejects an expired credential", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		e := connectionsEnv(t, ConnectionOptions{ID: "workforce", Credentials: []BearerCredential{
			{Type: "bearer", ID: "rotating-token-a", Token: "rotating-token-a"},
			{Type: "bearer", ID: "rotating-token-b", Token: "rotating-token-b", ExpiresAt: &future},
		}})
		created := connectionsCreateUser(e, "rotating-token-a", map[string]any{"userName": "ada@example.com"})
		id := created["id"].(string)
		retrieved := e.mustCall("getSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": id}, Headers: bearer("rotating-token-b"),
		})
		res := e.request("GET", scimUsersURL+"/"+id, nil, map[string]string{"Authorization": "Bearer rotating-token-b"})
		if retrieved["id"] != id {
			t.Fatalf("retrieved id = %v", retrieved["id"])
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/scim+json" {
			t.Fatalf("content-type = %q", ct)
		}
		if row := connectionsFindRow(e.mem.Rows("scimUser"), id); row == nil || row["connectionId"] != "workforce" {
			t.Fatalf("scimUser row = %v", row)
		}

		past := time.Now().Add(-time.Minute)
		expired := connectionsEnv(t, ConnectionOptions{ID: "expired-workforce", Credentials: []BearerCredential{
			{Type: "bearer", ID: "expired-token", Token: "expired-token", ExpiresAt: &past},
		}})
		expiredRes := expired.request("GET", scimUsersURL, nil, map[string]string{"Authorization": "Bearer expired-token"})
		if expiredRes.Status != 401 {
			t.Fatalf("status = %d", expiredRes.Status)
		}
		if got := expiredRes.Header.Get("WWW-Authenticate"); got != `Bearer realm="SCIM"` {
			t.Fatalf("www-authenticate = %q", got)
		}
	})

	t.Run("authenticates verified OAuth bearer principals and enforces their scopes", func(t *testing.T) {
		type verified struct{ method, path, token string }
		var (
			mu       sync.Mutex
			requests []verified
		)
		workforce := "workforce"
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{{ID: "workforce", Credentials: []BearerCredential{}}},
			Authentication: &AuthenticationOptions{
				VerifyBearerToken: func(in BearerTokenVerificationInput, _ BearerTokenVerificationContext) (*BearerTokenVerification, error) {
					mu.Lock()
					requests = append(requests, verified{in.Method, in.Path, in.Token})
					mu.Unlock()
					if in.Token == "malformed-oauth-token" {
						return &BearerTokenVerification{
							ConnectionID: &workforce, CredentialID: "oauth-client-1", Scopes: []Scope{"administrator"},
						}, nil
					}
					if in.Token != "oauth-write-token" {
						return nil, nil
					}
					return &BearerTokenVerification{
						ConnectionID: &workforce, CredentialID: "oauth-client-1", Scopes: []Scope{ScopeUsersWrite},
					}, nil
				},
			},
		})
		created := connectionsCreateUser(e, "oauth-write-token", map[string]any{"userName": "oauth@example.com"})
		listRes := e.request("GET", scimUsersURL, nil, map[string]string{"Authorization": "Bearer oauth-write-token"})
		malformedRes := e.request("GET", scimUsersURL, nil, map[string]string{"Authorization": "Bearer malformed-oauth-token"})
		if created["userName"] != "oauth@example.com" {
			t.Fatalf("created = %v", created)
		}
		if listRes.Status != http.StatusForbidden {
			t.Fatalf("list status = %d", listRes.Status)
		}
		if malformedRes.Status != http.StatusUnauthorized {
			t.Fatalf("malformed status = %d", malformedRes.Status)
		}
		want := []verified{
			{"POST", "/scim/v2/Users", "oauth-write-token"},
			{"GET", "/scim/v2/Users", "oauth-write-token"},
			{"GET", "/scim/v2/Users", "malformed-oauth-token"},
		}
		mu.Lock()
		defer mu.Unlock()
		if !reflect.DeepEqual(requests, want) {
			t.Fatalf("verified requests = %+v", requests)
		}
	})

	t.Run("rejects provisioning before any write when the adapter lacks native transactions", func(t *testing.T) {
		store := memory.NewDB()
		inner := memory.New(store)
		_, err := betterauth.New(betterauth.Config{
			BaseURL:   testBaseURL,
			Secret:    testAuthSecret,
			Logger:    betterauth.NopLogger{},
			RateLimit: &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
			Database: func(opts adapter.Options) (adapter.Adapter, error) {
				a, err := inner(opts)
				if err != nil {
					return nil, err
				}
				return connectionsNoNativeTx{a}, nil
			},
			Plugins: []*betterauth.Plugin{New(Options{Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")}})},
		})
		if err == nil || !strings.Contains(err.Error(), "native transaction support") {
			t.Fatalf("err = %v", err)
		}
		for _, m := range []string{"scimConnectionBinding", "user", "scimSubject", "scimUser"} {
			if n := len(store.Rows(m)); n != 0 {
				t.Fatalf("%s rows = %d", m, n)
			}
		}
	})
}
