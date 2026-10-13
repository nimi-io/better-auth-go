package scim

// Port of upstream scim-managed-connections.test.ts ("SCIM managed connections").

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const managedConnSecret = "managed-test-secret-at-least-32-characters"

var managedConnAllScopes = []any{"scim.users.read", "scim.users.write", "scim.groups.read", "scim.groups.write"}

var managedConnEndpoints = []string{
	"createSCIMManagedConnection",
	"listSCIMManagedConnections",
	"getSCIMManagedConnection",
	"rotateSCIMManagedCredential",
	"revokeSCIMManagedCredential",
	"decommissionSCIMManagedConnection",
	"listSCIMManagedConnectionEvents",
}

var managedConnRequestSeq atomic.Int64

func managedConnCreationRequestID() string {
	return fmt.Sprintf("managed-connection-test-request-%d", managedConnRequestSeq.Add(1))
}

type managedConnInstanceOptions struct {
	maxActiveCredentials         *int
	lastUsedWriteIntervalSeconds *int
	connections                  []ConnectionOptions
	verifyBearerToken            func(BearerTokenVerificationInput, BearerTokenVerificationContext) (*BearerTokenVerification, error)
	projection                   *Projection
}

func managedConnOptions(o managedConnInstanceOptions) Options {
	opts := Options{
		Connections: o.connections,
		ManagedConnections: &ManagedConnectionOptions{CredentialHashSecret: managedConnSecret,
			MaxActiveCredentials: o.maxActiveCredentials, LastUsedWriteIntervalSeconds: o.lastUsedWriteIntervalSeconds},
		Projection: o.projection,
	}
	if o.verifyBearerToken != nil {
		opts.Authentication = &AuthenticationOptions{VerifyBearerToken: o.verifyBearerToken}
	}
	return opts
}

func managedConnCreateInstance(t *testing.T, o managedConnInstanceOptions) *testEnv {
	t.Helper()
	return newEnv(t, managedConnOptions(o), envOptions{sqlite: true})
}

func managedConnDay() time.Time { return time.Now().Add(24 * time.Hour) }

// managedConnCall invokes a server-only managed endpoint with ctx and returns the result
// object (time values preserved) or the error.
func managedConnCall(ctx context.Context, e *testEnv, key string, body map[string]any) (*jsonx.Object, error) {
	res, err := e.auth.API.Call(ctx, key, betterauth.CallInput{Body: body})
	if err != nil {
		return nil, err
	}
	obj, ok := res.Data.(*jsonx.Object)
	if !ok {
		return nil, fmt.Errorf("%s: unexpected result %#v", key, res.Data)
	}
	return obj, nil
}

func managedConnMust(t *testing.T, e *testEnv, key string, body map[string]any) *jsonx.Object {
	t.Helper()
	obj, err := managedConnCall(context.Background(), e, key, body)
	if err != nil {
		if ae, ok := betterauth.AsAPIError(err); ok {
			t.Fatalf("%s: %d %s", key, ae.StatusCode, string(jsonx.MustMarshal(ae.Body)))
		}
		t.Fatalf("%s: %v", key, err)
	}
	return obj
}

func managedConnCreateBody(domain string, scopes []any, expiresAt time.Time) map[string]any {
	return map[string]any{"creationRequestId": managedConnCreationRequestID(), "provisioningDomainId": domain,
		"actorId": "admin-acme", "scopes": scopes, "expiresAt": expiresAt}
}

func managedConnObj(o *jsonx.Object, path ...string) *jsonx.Object {
	cur := o
	for _, p := range path {
		v, _ := cur.Get(p)
		next, ok := v.(*jsonx.Object)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func managedConnStr(o *jsonx.Object, path ...string) string {
	if o == nil {
		return ""
	}
	last := path[len(path)-1]
	parent := managedConnObj(o, path[:len(path)-1]...)
	if parent == nil {
		return ""
	}
	v, _ := parent.Get(last)
	s, _ := v.(string)
	return s
}

func managedConnList(o *jsonx.Object, key string) []*jsonx.Object {
	v, _ := o.Get(key)
	arr, _ := v.([]any)
	out := make([]*jsonx.Object, 0, len(arr))
	for _, x := range arr {
		xo, _ := x.(*jsonx.Object)
		out = append(out, xo)
	}
	return out
}

// managedConnNormalize converts a value to plain JSON-like data with dates as epoch
// milliseconds (JS Date equality) so toEqual comparisons are faithful.
func managedConnNormalize(v any) any {
	switch x := v.(type) {
	case *jsonx.Object:
		m := map[string]any{}
		for _, k := range x.Keys() {
			val, _ := x.Get(k)
			m[k] = managedConnNormalize(val)
		}
		return m
	case map[string]any:
		m := map[string]any{}
		for k, val := range x {
			m[k] = managedConnNormalize(val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = managedConnNormalize(val)
		}
		return out
	case []*jsonx.Object:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = managedConnNormalize(val)
		}
		return out
	case time.Time:
		return fmt.Sprintf("Date(%d)", x.UnixMilli())
	case *time.Time:
		if x == nil {
			return nil
		}
		return fmt.Sprintf("Date(%d)", x.UnixMilli())
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case float64:
		return x
	}
	return v
}

func managedConnEqual(a, b any) bool {
	return reflect.DeepEqual(managedConnNormalize(a), managedConnNormalize(b))
}

func managedConnStatus(err error) int {
	if ae, ok := betterauth.AsAPIError(err); ok {
		return ae.StatusCode
	}
	return 0
}

// managedConnErrMessage is error.message: SCIM errors (createSCIMError) set the message to
// their detail, which the Go APIError keeps only in body.detail.
func managedConnErrMessage(err error) string {
	if ae, ok := betterauth.AsAPIError(err); ok && ae.Body != nil && ae.Message() == "" {
		if d, ok := ae.Body.Get("detail"); ok {
			if s, ok := d.(string); ok {
				return s
			}
		}
	}
	return err.Error()
}

func managedConnEventTypes(o *jsonx.Object) []string {
	var out []string
	for _, ev := range managedConnList(o, "events") {
		out = append(out, managedConnStr(ev, "type"))
	}
	return out
}

func managedConnCreateUser(e *testEnv, token, userName string) *response {
	return e.scim("POST", scimUsersURL, token, map[string]any{
		"schemas": []any{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": userName})
}

func managedConnListUsers(e *testEnv, token string) *response {
	return e.scim("GET", scimUsersURL, token, nil)
}

func managedConnFindCredential(t *testing.T, e *testEnv, credentialID string) adapter.Record {
	t.Helper()
	r, err := e.db().FindOne(context.Background(), adapter.FindOneInput{Model: "scimManagedCredential",
		Where: []adapter.Where{{Field: "credentialId", Value: credentialID}}})
	if err != nil {
		t.Fatalf("find credential: %v", err)
	}
	return r
}

func managedConnUpdateCredential(t *testing.T, e *testEnv, credentialID string, update adapter.Record) {
	t.Helper()
	if _, err := e.db().Update(context.Background(), "scimManagedCredential",
		[]adapter.Where{{Field: "credentialId", Value: credentialID}}, update); err != nil {
		t.Fatalf("update credential: %v", err)
	}
}

func managedConnRefBody(created *jsonx.Object) map[string]any {
	return map[string]any{"connectionId": managedConnStr(created, "connection", "connectionId"),
		"provisioningDomainId": managedConnStr(created, "connection", "provisioningDomainId")}
}

func managedConnWith(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// managedConnAdapter wraps the auth adapter to intercept native transactions (the
// upstream tests monkey-patch context.adapter.transaction).
type managedConnAdapter struct {
	adapter.Adapter
	transactionCalls atomic.Int64
	// failTransaction, when set, replaces every native transaction with this error.
	failTransaction error
	// failEventCreate fails scimManagedConnectionEvent creates inside native transactions.
	failEventCreate bool
}

type managedConnTxKey struct{}

func (a *managedConnAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	a.transactionCalls.Add(1)
	if a.failTransaction != nil {
		return a.failTransaction
	}
	return a.Adapter.Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		return fn(context.WithValue(txCtx, managedConnTxKey{}, true), tx)
	})
}

func (a *managedConnAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if a.failEventCreate && ctx.Value(managedConnTxKey{}) == true && in.Model == "scimManagedConnectionEvent" {
		return nil, errors.New("simulated managed event failure")
	}
	return a.Adapter.Create(ctx, in)
}

func managedConnInstallAdapter(t *testing.T, e *testEnv, w *managedConnAdapter) func() {
	t.Helper()
	ac := e.auth.Context()
	original := ac.Adapter
	w.Adapter = original
	ac.Adapter = w
	return func() { ac.Adapter = original }
}

type managedConnSettled struct {
	obj *jsonx.Object
	err error
}

func managedConnAllSettled(e *testEnv, calls ...func() (*jsonx.Object, error)) []managedConnSettled {
	out := make([]managedConnSettled, len(calls))
	var wg sync.WaitGroup
	for i, c := range calls {
		wg.Add(1)
		go func(i int, c func() (*jsonx.Object, error)) {
			defer wg.Done()
			o, err := c()
			out[i] = managedConnSettled{o, err}
		}(i, c)
	}
	wg.Wait()
	return out
}

func managedConnCaller(e *testEnv, key string, body map[string]any) func() (*jsonx.Object, error) {
	return func() (*jsonx.Object, error) { return managedConnCall(context.Background(), e, key, body) }
}

func TestManagedConnSCIMManagedConnections(t *testing.T) {
	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("creates, lists, and gets a tenant-scoped connection without storing its token", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{})
		expiresAt := managedConnDay()
		raw := "  " + managedConnCreationRequestID() + "  "
		creationRequestID := strings.TrimSpace(raw)

		created := managedConnMust(t, e, "createSCIMManagedConnection", map[string]any{"creationRequestId": raw,
			"provisioningDomainId": "organization-acme", "actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": expiresAt})
		listed := managedConnMust(t, e, "listSCIMManagedConnections", map[string]any{"provisioningDomainId": "organization-acme"})
		connectionID := managedConnStr(created, "connection", "connectionId")
		fetched := managedConnMust(t, e, "getSCIMManagedConnection", map[string]any{"connectionId": connectionID,
			"provisioningDomainId": "organization-acme"})
		otherTenant := managedConnMust(t, e, "listSCIMManagedConnections", map[string]any{"provisioningDomainId": "organization-other"})
		events := managedConnMust(t, e, "listSCIMManagedConnectionEvents", map[string]any{"connectionId": connectionID,
			"provisioningDomainId": "organization-acme"})
		rows := e.rows("scimManagedCredential")

		if !regexp.MustCompile(`^ba_scim_connection_[A-Za-z0-9_-]+$`).MatchString(connectionID) {
			t.Errorf("connectionId = %q", connectionID)
		}
		if got := managedConnStr(created, "connection", "creationRequestId"); got != creationRequestID {
			t.Errorf("creationRequestId = %q, want %q", got, creationRequestID)
		}
		credentialID := managedConnStr(created, "credential", "credentialId")
		if !regexp.MustCompile(`^ba_scim_credential_[A-Za-z0-9_-]+$`).MatchString(credentialID) {
			t.Errorf("credentialId = %q", credentialID)
		}
		token := managedConnStr(created, "token")
		if !regexp.MustCompile(`^` + regexp.QuoteMeta(credentialID) + `\.[A-Za-z0-9_-]+$`).MatchString(token) {
			t.Errorf("token = %q", token)
		}
		cred := managedConnObj(created, "credential")
		credM := managedConnNormalize(cred).(map[string]any)
		if credM["status"] != "active" || !managedConnEqual(credM["scopes"], managedConnAllScopes) ||
			!managedConnEqual(credM["expiresAt"], expiresAt) || credM["createdBy"] != "admin-acme" {
			t.Errorf("credential = %v", credM)
		}
		if !managedConnEqual(listed, map[string]any{"connections": []any{managedConnObj(created, "connection")}}) {
			t.Errorf("listed = %v", managedConnNormalize(listed))
		}
		if !managedConnEqual(managedConnObj(fetched, "connection"), managedConnObj(created, "connection")) {
			t.Errorf("fetched connection = %v", managedConnNormalize(managedConnObj(fetched, "connection")))
		}
		if !managedConnEqual(managedConnList(fetched, "credentials"), []any{cred}) {
			t.Errorf("fetched credentials = %v vs %v", managedConnNormalize(managedConnList(fetched, "credentials")), credM)
		}
		evs := managedConnList(events, "events")
		if len(evs) != 2 {
			t.Errorf("events = %v", managedConnNormalize(events))
		}
		for _, ev := range evs {
			if ev.Has("creationRequestId") {
				t.Errorf("event has creationRequestId: %v", managedConnNormalize(ev))
			}
		}
		if !managedConnEqual(otherTenant, map[string]any{"connections": []any{}}) {
			t.Errorf("other tenant = %v", managedConnNormalize(otherTenant))
		}
		if len(rows) != 1 {
			t.Fatalf("credential rows = %v", rows)
		}
		r := rows[0]
		if r["credentialId"] != credentialID || r["hashVersion"] != "v1" || r["status"] != "active" {
			t.Errorf("row = %v", r)
		}
		if _, ok := r["token"]; ok {
			t.Errorf("row has token")
		}
		if _, ok := r["secret"]; ok {
			t.Errorf("row has secret")
		}
		digest, ok := r["tokenDigest"].(string)
		if !ok {
			t.Errorf("tokenDigest = %#v", r["tokenDigest"])
		}
		parts := strings.Split(token, ".")
		if strings.Contains(digest, parts[len(parts)-1]) {
			t.Errorf("tokenDigest contains the secret")
		}
		pl := New(managedConnOptions(managedConnInstanceOptions{}))
		for _, name := range managedConnEndpoints {
			var found *betterauth.Endpoint
			for _, ep := range pl.Endpoints {
				if ep.Key == name {
					found = ep
				}
			}
			if found == nil || found.Handler == nil {
				t.Errorf("%s is not an endpoint", name)
				continue
			}
			if found.Path != "" || !found.ServerOnly {
				t.Errorf("%s must not carry a routable path (path=%q serverOnly=%v)", name, found.Path, found.ServerOnly)
			}
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("joins an ambient transaction for create, rotate, and revoke", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{})
		ac := e.auth.Context()
		expiresAt := managedConnDay()
		createBody := managedConnCreateBody("organization-acme", managedConnAllScopes, expiresAt)

		err := ac.RunWithTransaction(context.Background(), func(tx context.Context) error {
			if _, err := managedConnCall(tx, e, "createSCIMManagedConnection", createBody); err != nil {
				return err
			}
			return errors.New("rollback managed create")
		})
		if err == nil || !strings.Contains(err.Error(), "rollback managed create") {
			t.Fatalf("err = %v", err)
		}
		for _, m := range []string{"scimManagedConnection", "scimManagedCredential", "scimManagedConnectionEvent"} {
			if rs := e.rows(m); len(rs) != 0 {
				t.Errorf("%s = %v, want none", m, rs)
			}
		}

		created := managedConnMust(t, e, "createSCIMManagedConnection", createBody)
		ref := managedConnRefBody(created)
		baseline := managedConnMust(t, e, "getSCIMManagedConnection", ref)
		baselineEvents := managedConnMust(t, e, "listSCIMManagedConnectionEvents", ref)

		err = ac.RunWithTransaction(context.Background(), func(tx context.Context) error {
			rotated, err := managedConnCall(tx, e, "rotateSCIMManagedCredential", managedConnWith(ref,
				map[string]any{"actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": expiresAt}))
			if err != nil {
				return err
			}
			if s := managedConnStr(rotated, "credential", "status"); s != "active" {
				t.Errorf("rotated status = %q", s)
			}
			return errors.New("rollback managed rotation")
		})
		if err == nil || !strings.Contains(err.Error(), "rollback managed rotation") {
			t.Fatalf("err = %v", err)
		}
		if got := managedConnMust(t, e, "getSCIMManagedConnection", ref); !managedConnEqual(got, baseline) {
			t.Errorf("state after rotation rollback = %v", managedConnNormalize(got))
		}
		if got := managedConnMust(t, e, "listSCIMManagedConnectionEvents", ref); !managedConnEqual(got, baselineEvents) {
			t.Errorf("events after rotation rollback = %v", managedConnNormalize(got))
		}

		err = ac.RunWithTransaction(context.Background(), func(tx context.Context) error {
			revoked, err := managedConnCall(tx, e, "revokeSCIMManagedCredential", managedConnWith(ref, map[string]any{
				"credentialId": managedConnStr(created, "credential", "credentialId"), "actorId": "admin-acme"}))
			if err != nil {
				return err
			}
			creds := managedConnList(revoked, "credentials")
			if len(creds) != 1 || managedConnStr(creds[0], "status") != "revoked" {
				t.Errorf("revoked credentials = %v", managedConnNormalize(creds))
			}
			return errors.New("rollback managed revocation")
		})
		if err == nil || !strings.Contains(err.Error(), "rollback managed revocation") {
			t.Fatalf("err = %v", err)
		}
		if got := managedConnMust(t, e, "getSCIMManagedConnection", ref); !managedConnEqual(got, baseline) {
			t.Errorf("state after revocation rollback = %v", managedConnNormalize(got))
		}
		if got := managedConnMust(t, e, "listSCIMManagedConnectionEvents", ref); !managedConnEqual(got, baselineEvents) {
			t.Errorf("events after revocation rollback = %v", managedConnNormalize(got))
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10592
	t.Run("joins an ambient transaction for decommission without deadlocking", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{})
		ac := e.auth.Context()
		created := managedConnMust(t, e, "createSCIMManagedConnection", managedConnCreateBody("organization-acme", managedConnAllScopes, managedConnDay()))
		ref := managedConnRefBody(created)
		baseline := managedConnMust(t, e, "getSCIMManagedConnection", ref)
		baselineEvents := managedConnMust(t, e, "listSCIMManagedConnectionEvents", ref)
		decommissionBody := managedConnWith(ref, map[string]any{"actorId": "admin-acme"})

		done := make(chan error, 1)
		go func() {
			done <- ac.RunWithTransaction(context.Background(), func(tx context.Context) error {
				d, err := managedConnCall(tx, e, "decommissionSCIMManagedConnection", decommissionBody)
				if err != nil {
					return err
				}
				if s := managedConnStr(d, "connection", "status"); s != "decommissioned" {
					return fmt.Errorf("unexpected status %q", s)
				}
				return errors.New("rollback managed decommission")
			})
		}()
		var err error
		select {
		case err = <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("decommission inside an ambient transaction deadlocked")
		}
		if err == nil || !strings.Contains(err.Error(), "rollback managed decommission") {
			t.Fatalf("err = %v", err)
		}
		if got := managedConnMust(t, e, "getSCIMManagedConnection", ref); !managedConnEqual(got, baseline) {
			t.Errorf("state after rollback = %v", managedConnNormalize(got))
		}
		if got := managedConnMust(t, e, "listSCIMManagedConnectionEvents", ref); !managedConnEqual(got, baselineEvents) {
			t.Errorf("events after rollback = %v", managedConnNormalize(got))
		}
		d := managedConnMust(t, e, "decommissionSCIMManagedConnection", decommissionBody)
		if s := managedConnStr(d, "connection", "status"); s != "decommissioned" {
			t.Errorf("status = %q", s)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("uses the native adapter transaction when no ambient transaction exists", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{})
		w := &managedConnAdapter{failEventCreate: true}
		restore := managedConnInstallAdapter(t, e, w)
		_, err := managedConnCall(context.Background(), e, "createSCIMManagedConnection",
			managedConnCreateBody("organization-acme", managedConnAllScopes, managedConnDay()))
		restore()
		if err == nil || !strings.Contains(err.Error(), "simulated managed event failure") {
			t.Errorf("err = %v", err)
		}
		if n := w.transactionCalls.Load(); n != 1 {
			t.Errorf("transaction calls = %d, want 1", n)
		}
		for _, m := range []string{"scimManagedConnection", "scimManagedCredential", "scimManagedConnectionEvent"} {
			if rs := e.rows(m); len(rs) != 0 {
				t.Errorf("%s = %v, want none", m, rs)
			}
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("requires a bounded creation request ID and atomically rejects duplicate creation", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{})
		expiresAt := managedConnDay()
		validBody := map[string]any{"creationRequestId": "managed-duplicate-request", "provisioningDomainId": "organization-acme",
			"actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": expiresAt}

		missing := managedConnWith(validBody, nil)
		delete(missing, "creationRequestId")
		if _, err := managedConnCall(context.Background(), e, "createSCIMManagedConnection", missing); managedConnStatus(err) != 400 {
			t.Errorf("missing creationRequestId: err = %v", err)
		}
		for _, id := range []string{"too-short", strings.Repeat("😎", 8), strings.Repeat("x", 256), "                "} {
			_, err := managedConnCall(context.Background(), e, "createSCIMManagedConnection",
				managedConnWith(validBody, map[string]any{"creationRequestId": id}))
			if managedConnStatus(err) != 400 {
				t.Errorf("creationRequestId %q: err = %v", id, err)
			}
		}

		results := managedConnAllSettled(e,
			managedConnCaller(e, "createSCIMManagedConnection", validBody),
			managedConnCaller(e, "createSCIMManagedConnection", validBody))
		var fulfilled, rejected []managedConnSettled
		for _, r := range results {
			if r.err == nil {
				fulfilled = append(fulfilled, r)
			} else {
				rejected = append(rejected, r)
			}
		}
		connections := e.rows("scimManagedConnection")
		credentials := e.rows("scimManagedCredential")
		events := e.rows("scimManagedConnectionEvent")
		if len(fulfilled) != 1 || len(rejected) != 1 {
			t.Fatalf("fulfilled=%d rejected=%d (%v)", len(fulfilled), len(rejected), rejected)
		}
		ae, ok := betterauth.AsAPIError(rejected[0].err)
		if !ok || ae.StatusCode != 409 || ae.Code() != "SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT" {
			t.Errorf("rejected = %v", rejected[0].err)
		}
		if ok && ae.Body != nil && ae.Body.Has("token") {
			t.Errorf("rejection carries a token")
		}
		if len(connections) != 1 || connections[0]["creationRequestId"] != "managed-duplicate-request" {
			t.Errorf("connections = %v", connections)
		}
		if len(credentials) != 1 {
			t.Errorf("credentials = %v", credentials)
		}
		createdEvents := 0
		for _, ev := range events {
			if ev["type"] == "connection.created" {
				createdEvents++
			}
		}
		if createdEvents != 1 || len(events) != 2 {
			t.Errorf("events = %v", events)
		}

		unrelated := errors.New("unrelated adapter failure")
		w := &managedConnAdapter{failTransaction: unrelated}
		restore := managedConnInstallAdapter(t, e, w)
		_, err := managedConnCall(context.Background(), e, "createSCIMManagedConnection",
			managedConnWith(validBody, map[string]any{"creationRequestId": "unrelated-error-request-id"}))
		restore()
		if err != unrelated {
			t.Errorf("err = %#v, want the unrelated adapter error itself", err)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("authenticates generated tokens, overlaps rotation, revokes immediately, and throttles last-used writes", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{lastUsedWriteIntervalSeconds: intPtr(3600)})
		expiresAt := managedConnDay()
		created := managedConnMust(t, e, "createSCIMManagedConnection", managedConnCreateBody("organization-acme", managedConnAllScopes, expiresAt))
		token := managedConnStr(created, "token")
		credentialID := managedConnStr(created, "credential", "credentialId")
		ref := managedConnRefBody(created)

		provisioned := managedConnCreateUser(e, token, "managed@example.com")
		afterFirst := managedConnFindCredential(t, e, credentialID)
		listedWithOld := managedConnListUsers(e, token)
		afterSecond := managedConnFindCredential(t, e, credentialID)
		rotated := managedConnMust(t, e, "rotateSCIMManagedCredential", managedConnWith(ref,
			map[string]any{"actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": expiresAt}))
		rotatedToken := managedConnStr(rotated, "token")
		oldDuringOverlap := managedConnListUsers(e, token)
		newDuringOverlap := managedConnListUsers(e, rotatedToken)
		revoked := managedConnMust(t, e, "revokeSCIMManagedCredential", managedConnWith(ref,
			map[string]any{"credentialId": credentialID, "actorId": "admin-acme"}))
		oldAfterRevoke := managedConnListUsers(e, token)
		newAfterRevoke := managedConnListUsers(e, rotatedToken)
		events := managedConnMust(t, e, "listSCIMManagedConnectionEvents", ref)

		if provisioned.Status != 201 {
			t.Errorf("provisioned = %d %s", provisioned.Status, provisioned.text())
		}
		if listedWithOld.Status != 200 {
			t.Errorf("listedWithOld = %d", listedWithOld.Status)
		}
		first, ok := afterFirst["lastUsedAt"].(time.Time)
		if !ok {
			t.Errorf("lastUsedAt after first use = %#v", afterFirst["lastUsedAt"])
		}
		if second, _ := afterSecond["lastUsedAt"].(time.Time); !second.Equal(first) {
			t.Errorf("lastUsedAt after second use = %v, want %v", afterSecond["lastUsedAt"], first)
		}
		if rotatedToken == token {
			t.Errorf("rotated token equals original")
		}
		if oldDuringOverlap.Status != 200 || newDuringOverlap.Status != 200 {
			t.Errorf("overlap statuses = %d %d", oldDuringOverlap.Status, newDuringOverlap.Status)
		}
		statuses := map[string]string{}
		for _, c := range managedConnList(revoked, "credentials") {
			statuses[managedConnStr(c, "credentialId")] = managedConnStr(c, "status")
		}
		if statuses[credentialID] != "revoked" || statuses[managedConnStr(rotated, "credential", "credentialId")] != "active" {
			t.Errorf("revoked credentials = %v", statuses)
		}
		if oldAfterRevoke.Status != 401 {
			t.Errorf("oldAfterRevoke = %d", oldAfterRevoke.Status)
		}
		if newAfterRevoke.Status != 200 {
			t.Errorf("newAfterRevoke = %d", newAfterRevoke.Status)
		}
		want := []string{"connection.created", "credential.issued", "credential.rotated", "credential.revoked"}
		if got := managedConnEventTypes(events); !reflect.DeepEqual(got, want) {
			t.Errorf("event types = %v", got)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("decommissions managed credentials before canonical reconciliation and remains retry-safe", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{})
		created := managedConnMust(t, e, "createSCIMManagedConnection", managedConnCreateBody("organization-acme", managedConnAllScopes, managedConnDay()))
		token := managedConnStr(created, "token")
		ref := managedConnRefBody(created)
		if r := managedConnCreateUser(e, token, "decommission@example.com"); r.Status != 201 {
			t.Fatalf("create user = %d %s", r.Status, r.text())
		}
		body := managedConnWith(ref, map[string]any{"actorId": "admin-acme"})
		first := managedConnMust(t, e, "decommissionSCIMManagedConnection", body)
		repeated := managedConnMust(t, e, "decommissionSCIMManagedConnection", body)
		rejected := managedConnListUsers(e, token)
		events := managedConnMust(t, e, "listSCIMManagedConnectionEvents", ref)
		binding, err := e.db().FindOne(context.Background(), adapter.FindOneInput{Model: "scimConnectionBinding",
			Where: []adapter.Where{{Field: "connectionId", Value: ref["connectionId"]}}})
		if err != nil {
			t.Fatal(err)
		}

		if s := managedConnStr(first, "connection", "status"); s != "decommissioned" {
			t.Errorf("first status = %q", s)
		}
		creds := managedConnList(first, "credentials")
		if len(creds) != 1 || managedConnStr(creds[0], "status") != "decommissioned" {
			t.Errorf("first credentials = %v", managedConnNormalize(creds))
		}
		if s := managedConnStr(first, "decommission", "status"); s != "complete" {
			t.Errorf("decommission status = %q", s)
		}
		if !managedConnEqual(managedConnObj(repeated, "connection"), managedConnObj(first, "connection")) {
			t.Errorf("repeated connection = %v", managedConnNormalize(managedConnObj(repeated, "connection")))
		}
		if rejected.Status != 401 {
			t.Errorf("rejected = %d", rejected.Status)
		}
		want := []string{"connection.created", "credential.issued", "connection.decommissioning", "connection.decommissioned"}
		if got := managedConnEventTypes(events); !reflect.DeepEqual(got, want) {
			t.Errorf("event types = %v", got)
		}
		if binding == nil || binding["connectionId"] != ref["connectionId"] || binding["provisioningDomainId"] != "organization-acme" ||
			binding["decommissionStatus"] != "complete" {
			t.Errorf("binding = %v", binding)
		}
		_, err = managedConnCall(context.Background(), e, "rotateSCIMManagedCredential", managedConnWith(ref,
			map[string]any{"actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": managedConnDay()}))
		if managedConnStatus(err) != 409 {
			t.Errorf("rotate after decommission: err = %v", err)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("uses tenant-qualified not-found behavior and atomically enforces active credential slots", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{maxActiveCredentials: intPtr(2)})
		expiresAt := managedConnDay()
		created := managedConnMust(t, e, "createSCIMManagedConnection", managedConnCreateBody("organization-acme", managedConnAllScopes, expiresAt))
		ref := managedConnRefBody(created)
		rotateBody := managedConnWith(ref, map[string]any{"actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": expiresAt})
		rotations := managedConnAllSettled(e,
			managedConnCaller(e, "rotateSCIMManagedCredential", rotateBody),
			managedConnCaller(e, "rotateSCIMManagedCredential", rotateBody))
		credentials, err := e.db().FindMany(context.Background(), adapter.FindManyInput{Model: "scimManagedCredential",
			Where: []adapter.Where{{Field: "status", Value: "active"}, {Field: "expiresAt", Value: time.Now(), Operator: adapter.Gt}}})
		if err != nil {
			t.Fatal(err)
		}
		_, wrongDomain := managedConnCall(context.Background(), e, "getSCIMManagedConnection", map[string]any{
			"connectionId": ref["connectionId"], "provisioningDomainId": "organization-other"})
		_, unknown := managedConnCall(context.Background(), e, "getSCIMManagedConnection", map[string]any{
			"connectionId": "ba_scim_connection_missing", "provisioningDomainId": "organization-other"})

		ok, failed := 0, 0
		for _, r := range rotations {
			if r.err == nil {
				ok++
			} else {
				failed++
			}
		}
		if ok != 1 || failed != 1 {
			t.Errorf("rotations fulfilled=%d rejected=%d (%v)", ok, failed, rotations)
		}
		if len(credentials) != 2 {
			t.Errorf("live credentials = %v", credentials)
		}
		slots := map[any]bool{}
		for _, c := range credentials {
			slots[c["activeSlotKey"]] = true
		}
		if len(slots) != 2 {
			t.Errorf("distinct slots = %v", slots)
		}
		for name, err := range map[string]error{"wrongDomain": wrongDomain, "unknown": unknown} {
			ae, ok := betterauth.AsAPIError(err)
			if !ok || ae.StatusCode != 404 || ae.Message() != "Managed SCIM connection not found" {
				t.Errorf("%s: err = %v", name, err)
			}
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("keeps the managed bearer namespace catalog-only while preserving static-first dispatch", func(t *testing.T) {
		var verifierCalls atomic.Int64
		staticToken := "ba_scim_credential_static-credential.static-secret"
		e := managedConnCreateInstance(t, managedConnInstanceOptions{
			connections: []ConnectionOptions{{ID: "static-connection", Credentials: []BearerCredential{
				{Type: "bearer", ID: "static-credential", Token: staticToken}}}},
			verifyBearerToken: func(in BearerTokenVerificationInput, _ BearerTokenVerificationContext) (*BearerTokenVerification, error) {
				verifierCalls.Add(1)
				if in.Token != "application-token" {
					return nil, nil
				}
				return &BearerTokenVerification{
					Connection:   &VerifiedConnection{ID: "ba_scim_connection_application-collision", ProvisioningDomainID: "organization-acme"},
					CredentialID: "application-credential",
					Scopes:       AllScopes,
				}, nil
			},
		})
		staticResponse := managedConnListUsers(e, staticToken)
		unknownManaged := managedConnListUsers(e, "ba_scim_credential_unknown.unknown-secret")
		applicationCollision := managedConnListUsers(e, "application-token")
		if staticResponse.Status != 200 {
			t.Errorf("static = %d %s", staticResponse.Status, staticResponse.text())
		}
		if unknownManaged.Status != 401 {
			t.Errorf("unknown managed = %d", unknownManaged.Status)
		}
		if n := verifierCalls.Load(); n != 1 {
			t.Errorf("verifier calls = %d, want 1", n)
		}
		if applicationCollision.Status != 401 {
			t.Errorf("application collision = %d", applicationCollision.Status)
		}
		_, err := NewE(Options{
			Connections: []ConnectionOptions{{ID: "ba_scim_connection_static-collision", Credentials: []BearerCredential{
				{Type: "bearer", ID: "credential", Token: "ordinary-static-token"}}}},
			ManagedConnections: &ManagedConnectionOptions{CredentialHashSecret: managedConnSecret},
		})
		if err == nil || !strings.Contains(err.Error(), "cannot use the reserved") {
			t.Errorf("err = %v", err)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("enforces explicit future expiry and exact scopes at issuance and request time", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{})
		_, err := managedConnCall(context.Background(), e, "createSCIMManagedConnection",
			managedConnCreateBody("organization-acme", managedConnAllScopes, time.Now().Add(-time.Millisecond)))
		if managedConnStatus(err) != 400 {
			t.Errorf("past expiry: err = %v", err)
		}
		created := managedConnMust(t, e, "createSCIMManagedConnection",
			managedConnCreateBody("organization-acme", []any{"scim.users.read"}, managedConnDay()))
		token := managedConnStr(created, "token")
		readAllowed := managedConnListUsers(e, token)
		writeDenied := managedConnCreateUser(e, token, "scope-denied@example.com")
		managedConnUpdateCredential(t, e, managedConnStr(created, "credential", "credentialId"),
			adapter.Record{"expiresAt": time.Now().Add(-time.Millisecond)})
		expired := managedConnListUsers(e, token)
		if readAllowed.Status != 200 {
			t.Errorf("read = %d", readAllowed.Status)
		}
		if writeDenied.Status != 403 {
			t.Errorf("write = %d", writeDenied.Status)
		}
		if expired.Status != 401 {
			t.Errorf("expired = %d", expired.Status)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("reclaims expired slots and never exceeds the cap during rotate-revoke races", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{maxActiveCredentials: intPtr(2)})
		expiresAt := managedConnDay()
		created := managedConnMust(t, e, "createSCIMManagedConnection", managedConnCreateBody("organization-acme", managedConnAllScopes, expiresAt))
		ref := managedConnRefBody(created)
		rotateBody := managedConnWith(ref, map[string]any{"actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": expiresAt})
		second := managedConnMust(t, e, "rotateSCIMManagedCredential", rotateBody)
		originalID := managedConnStr(created, "credential", "credentialId")
		managedConnUpdateCredential(t, e, originalID, adapter.Record{"expiresAt": time.Now().Add(-time.Millisecond)})
		replacement := managedConnMust(t, e, "rotateSCIMManagedCredential", rotateBody)
		managedConnAllSettled(e,
			managedConnCaller(e, "revokeSCIMManagedCredential", managedConnWith(ref, map[string]any{
				"credentialId": managedConnStr(second, "credential", "credentialId"), "actorId": "admin-acme"})),
			managedConnCaller(e, "rotateSCIMManagedCredential", rotateBody))
		credentials := e.rows("scimManagedCredential")
		now := time.Now()
		var live []adapter.Record
		var original adapter.Record
		for _, c := range credentials {
			if exp, ok := c["expiresAt"].(time.Time); ok && c["status"] == "active" && exp.After(now) {
				live = append(live, c)
			}
			if c["credentialId"] == originalID {
				original = c
			}
		}
		if managedConnStr(replacement, "token") == managedConnStr(created, "token") {
			t.Errorf("replacement token equals original")
		}
		if original == nil || original["status"] != "expired" {
			t.Errorf("original = %v", original)
		}
		if original != nil && original["activeSlotKey"] != originalID+":inactive" {
			t.Errorf("original activeSlotKey = %v", original["activeSlotKey"])
		}
		if len(live) > 2 {
			t.Errorf("live credentials = %d", len(live))
		}
		slots := map[any]bool{}
		for _, c := range live {
			slots[c["activeSlotKey"]] = true
		}
		if len(slots) != len(live) {
			t.Errorf("duplicate live slots: %v", live)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("enforces a reduced active credential cap across existing slot layouts", func(t *testing.T) {
		e := managedConnCreateInstance(t, managedConnInstanceOptions{maxActiveCredentials: intPtr(2)})
		expiresAt := managedConnDay()
		created := managedConnMust(t, e, "createSCIMManagedConnection", managedConnCreateBody("organization-acme", managedConnAllScopes, expiresAt))
		ref := managedConnRefBody(created)
		rotateBody := managedConnWith(ref, map[string]any{"actorId": "admin-acme", "scopes": managedConnAllScopes, "expiresAt": expiresAt})
		second := managedConnMust(t, e, "rotateSCIMManagedCredential", rotateBody)
		connection, err := e.db().FindOne(context.Background(), adapter.FindOneInput{Model: "scimManagedConnection",
			Where: []adapter.Where{{Field: "connectionId", Value: ref["connectionId"]}}})
		if err != nil {
			t.Fatal(err)
		}
		recordID, ok := connection["id"].(string)
		if !ok {
			t.Fatalf("connection id = %#v", connection["id"])
		}
		managedConnUpdateCredential(t, e, managedConnStr(created, "credential", "credentialId"),
			adapter.Record{"activeSlotKey": recordID + ":active:3"})
		managedConnUpdateCredential(t, e, managedConnStr(second, "credential", "credentialId"),
			adapter.Record{"activeSlotKey": recordID + ":active:4"})

		_, err = managedConnCall(context.Background(), e, "rotateSCIMManagedCredential", rotateBody)
		ae, isAPI := betterauth.AsAPIError(err)
		if !isAPI || ae.StatusCode != 409 || ae.Message() != "Managed SCIM connection has the maximum number of active credentials" {
			t.Errorf("err = %v", err)
		}
		active, err := e.db().FindMany(context.Background(), adapter.FindManyInput{Model: "scimManagedCredential",
			Where: []adapter.Where{{Field: "status", Value: "active"}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(active) != 2 {
			t.Errorf("active = %v", active)
		}
	})

	// @see https://github.com/better-auth/better-auth/pull/10475
	t.Run("keeps credentials disabled after a canonical decommission failure and completes on retry", func(t *testing.T) {
		var failDecommission atomic.Bool
		e := managedConnCreateInstance(t, managedConnInstanceOptions{projection: &Projection{
			ReconcileUser: func(ProjectedUserState, DatabaseContext) error {
				if failDecommission.Load() {
					return errors.New("simulated projection interruption")
				}
				return nil
			},
		}})
		created := managedConnMust(t, e, "createSCIMManagedConnection", managedConnCreateBody("organization-acme", managedConnAllScopes, managedConnDay()))
		token := managedConnStr(created, "token")
		ref := managedConnRefBody(created)
		if r := managedConnCreateUser(e, token, "retry@example.com"); r.Status != 201 {
			t.Fatalf("create user = %d %s", r.Status, r.text())
		}
		failDecommission.Store(true)
		body := managedConnWith(ref, map[string]any{"actorId": "admin-acme"})
		_, err := managedConnCall(context.Background(), e, "decommissionSCIMManagedConnection", body)
		if err == nil || !strings.Contains(managedConnErrMessage(err), "SCIM projection reconciliation failed") {
			t.Errorf("err = %v", err)
		}
		interrupted := managedConnMust(t, e, "getSCIMManagedConnection", ref)
		rejected := managedConnListUsers(e, token)
		failDecommission.Store(false)
		retried := managedConnMust(t, e, "decommissionSCIMManagedConnection", body)

		if s := managedConnStr(interrupted, "connection", "status"); s != "decommissioning" {
			t.Errorf("interrupted status = %q", s)
		}
		creds := managedConnList(interrupted, "credentials")
		if len(creds) != 1 || managedConnStr(creds[0], "status") != "decommissioned" {
			t.Errorf("interrupted credentials = %v", managedConnNormalize(creds))
		}
		if rejected.Status != 401 {
			t.Errorf("rejected = %d", rejected.Status)
		}
		if s := managedConnStr(retried, "connection", "status"); s != "decommissioned" {
			t.Errorf("retried status = %q", s)
		}
		if s := managedConnStr(retried, "decommission", "status"); s != "complete" {
			t.Errorf("retried decommission = %q", s)
		}
	})

	t.Run("rejects unsafe managed catalog configuration before startup", func(t *testing.T) {
		cases := []struct {
			opts ManagedConnectionOptions
			want string
		}{
			{ManagedConnectionOptions{CredentialHashSecret: "too-short"},
				"SCIM managed credentialHashSecret must contain at least 32 characters."},
			{ManagedConnectionOptions{CredentialHashSecret: managedConnSecret, MaxActiveCredentials: intPtr(0)},
				"SCIM managed maxActiveCredentials must be an integer between 1 and 100."},
			{ManagedConnectionOptions{CredentialHashSecret: managedConnSecret, LastUsedWriteIntervalSeconds: intPtr(-1)},
				"SCIM managed lastUsedWriteIntervalSeconds must be a non-negative integer."},
		}
		for _, c := range cases {
			o := c.opts
			_, err := NewE(Options{ManagedConnections: &o})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		}
	})
}
