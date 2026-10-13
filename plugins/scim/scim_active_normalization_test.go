package scim

// Port of upstream scim-active-normalization.test.ts.

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const (
	activeNormUserSchema           = "urn:ietf:params:scim:schemas:core:2.0:User"
	activeNormPatchSchema          = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	activeNormToken                = "active-normalization-token"
	activeNormEnterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

func activeNormObj(t *testing.T, s string) *jsonx.Object {
	t.Helper()
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return v.(*jsonx.Object)
}

func activeNormJSON(v any) string { return string(jsonx.MustMarshal(v)) }

func activeNormExpectEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	if g, w := activeNormJSON(got), activeNormJSON(want); g != w {
		t.Fatalf("%s:\n got %s\nwant %s", label, g, w)
	}
}

var activeNormStringBooleans = []struct {
	value    string
	expected bool
}{
	{"true", true}, {"True", true}, {"TRUE", true}, {"tRuE", true},
	{"false", false}, {"False", false}, {"FALSE", false}, {"fAlSe", false},
}

func TestActiveNorm_ActiveIngressHelper(t *testing.T) {
	for _, tc := range activeNormStringBooleans {
		t.Run("normalizes the exact case-insensitive string "+tc.value+" at POST and PUT boundaries", func(t *testing.T) {
			for _, method := range []string{"POST", "PUT"} {
				body := jsonx.O("schemas", []any{activeNormUserSchema}, "userName", "boundary@example.com", "active", tc.value)
				normalized := normalizeUserEntraCompatibilityBody(method, body)
				if no, ok := normalized.(*jsonx.Object); ok && no == body {
					t.Fatalf("%s: normalized is the same object", method)
				}
				activeNormExpectEqual(t, method, normalized,
					jsonx.O("schemas", []any{activeNormUserSchema}, "userName", "boundary@example.com", "active", tc.expected))
				if v, _ := body.Get("active"); v != tc.value {
					t.Fatalf("%s: input mutated: %v", method, v)
				}
			}
		})
	}

	nearMisses := []struct {
		name  string
		value func() any
	}{
		{"true", func() any { return true }},
		{"false", func() any { return false }},
		{`" true"`, func() any { return " true" }},
		{`"true "`, func() any { return "true " }},
		{`" false "`, func() any { return " false " }},
		{`""`, func() any { return "" }},
		{`"yes"`, func() any { return "yes" }},
		{`"1"`, func() any { return "1" }},
		{`"0"`, func() any { return "0" }},
		{"1", func() any { return float64(1) }},
		{"0", func() any { return float64(0) }},
		{"null", func() any { return nil }},
		{"[]", func() any { return []any{} }},
		{"[true]", func() any { return []any{true} }},
		{"{}", func() any { return jsonx.NewObject() }},
		{"{value:true}", func() any { return jsonx.O("value", true) }},
	}
	for _, nm := range nearMisses {
		t.Run("leaves the rejected near-miss unchanged at POST and PUT boundaries/"+nm.name, func(t *testing.T) {
			for _, method := range []string{"POST", "PUT"} {
				body := jsonx.O("schemas", []any{activeNormUserSchema}, "userName", "boundary@example.com", "active", nm.value())
				if got := normalizeUserEntraCompatibilityBody(method, body); got != any(body) {
					t.Fatalf("%s: body was copied: %s", method, activeNormJSON(got))
				}
			}
		})
	}

	t.Run("copies only User active containers whose values change", func(t *testing.T) {
		untouched := jsonx.O("op", "replace", "path", "displayName", "value", "False")
		first := jsonx.O("op", "replace", "path", "active", "value", "False")
		body := jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{first, untouched})
		normalized := normalizeUserEntraCompatibilityBody("PATCH", body)
		no, ok := normalized.(*jsonx.Object)
		if !ok || no == body {
			t.Fatal("expected a copied body")
		}
		activeNormExpectEqual(t, "normalized", normalized, jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{
			jsonx.O("op", "replace", "path", "active", "value", false), untouched,
		}))
		ops := objGet(no, "Operations").([]any)
		if ops[1] != any(untouched) {
			t.Fatal("untouched operation was copied")
		}
		if v, _ := first.Get("value"); v != "False" {
			t.Fatalf("input mutated: %v", v)
		}
		only := jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{untouched})
		activeNormExpectEqual(t, "untouched only", normalizeUserEntraCompatibilityBody("PATCH", only),
			jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{untouched}))
	})

	// See https://github.com/better-auth/better-auth/pull/10475
	t.Run("rewrites only changed User bodies while preserving request transport", func(t *testing.T) {
		plugin := New(Options{Connections: []ConnectionOptions{staticConnection("request-normalization", "request-normalization-token")}})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req := httptest.NewRequest("POST", "https://example.com/api/auth/scim/v2/Users",
			strings.NewReader(`{"schemas":["`+activeNormUserSchema+`"],"userName":"rewritten@example.com","active":"False"}`)).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer request-normalization-token")
		req.Header.Set("Content-Length", "999")
		req.Header.Set("Content-Type", MediaType)
		req.Header.Set("X-Request-Marker", "preserved")
		nr, resp, err := plugin.OnRequest(req, nil)
		if err != nil || resp != nil || nr == nil {
			t.Fatalf("Expected a normalized SCIM User request (req=%v resp=%v err=%v)", nr, resp, err)
		}
		if nr.Method != "POST" {
			t.Fatalf("method = %s", nr.Method)
		}
		if got := nr.Header.Get("Authorization"); got != "Bearer request-normalization-token" {
			t.Fatalf("authorization = %q", got)
		}
		if got := nr.Header.Get("X-Request-Marker"); got != "preserved" {
			t.Fatalf("x-request-marker = %q", got)
		}
		if _, ok := nr.Header["Content-Length"]; ok {
			t.Fatal("content-length header was preserved")
		}
		raw, _ := io.ReadAll(nr.Body)
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded["active"] != false {
			t.Fatalf("body = %s", raw)
		}
		if nr.Context().Err() != nil {
			t.Fatal("signal already aborted")
		}
		cancel()
		if nr.Context().Err() == nil {
			t.Fatal("signal not propagated to the rewritten request")
		}

		// The runtime-boundary Request-like object case (a plain object exposing clone())
		// has no Go equivalent; an *http.Request is always the native type.

		unchanged := httptest.NewRequest("POST", "https://example.com/api/auth/scim/v2/Users",
			strings.NewReader(`{"schemas":["`+activeNormUserSchema+`"],"userName":"native@example.com","active":false}`))
		unchanged.Header.Set("Content-Type", MediaType)
		if nr, resp, err := plugin.OnRequest(unchanged, nil); nr != nil || resp != nil || err != nil {
			t.Fatalf("unchanged User: req=%v resp=%v err=%v", nr, resp, err)
		}

		group := httptest.NewRequest("POST", "https://example.com/api/auth/scim/v2/Groups",
			strings.NewReader(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"False","active":"False"}`))
		group.Header.Set("Content-Type", MediaType)
		if nr, resp, err := plugin.OnRequest(group, nil); nr != nil || resp != nil || err != nil {
			t.Fatalf("group: req=%v resp=%v err=%v", nr, resp, err)
		}
	})
}

func TestActiveNorm_PrimaryIngressHelper(t *testing.T) {
	for _, tc := range activeNormStringBooleans {
		t.Run("normalizes the exact case-insensitive string "+tc.value+" for every multi-valued primary at POST and PUT boundaries", func(t *testing.T) {
			for _, method := range []string{"POST", "PUT"} {
				body := jsonx.O(
					"schemas", []any{activeNormUserSchema},
					"userName", "primary-boundary@example.com",
					"emails", []any{jsonx.O("value", "primary-boundary@example.com", "type", "work", "primary", tc.value)},
					"phoneNumbers", []any{jsonx.O("value", "+1-555-0100", "primary", tc.value)},
					"addresses", []any{jsonx.O("formatted", "1 Infinite Loop", "primary", tc.value)},
					"roles", []any{jsonx.O("value", "engineer", "primary", tc.value)},
					"entitlements", []any{jsonx.O("value", "license", "primary", tc.value)},
				)
				normalized, ok := normalizeUserEntraCompatibilityBody(method, body).(*jsonx.Object)
				if !ok || normalized == body {
					t.Fatalf("%s: expected a copied body", method)
				}
				for _, attr := range []string{"emails", "phoneNumbers", "addresses", "roles", "entitlements"} {
					entry := objGet(normalized, attr).([]any)[0].(*jsonx.Object)
					if v, _ := entry.Get("primary"); v != tc.expected {
						t.Fatalf("%s %s.primary = %#v", method, attr, v)
					}
				}
				orig := objGet(body, "emails").([]any)[0].(*jsonx.Object)
				if v, _ := orig.Get("primary"); v != tc.value {
					t.Fatalf("input mutated: %v", v)
				}
			}
		})
	}

	nearMisses := []struct {
		name  string
		value func() any
	}{
		{"true", func() any { return true }},
		{"false", func() any { return false }},
		{`" true"`, func() any { return " true" }},
		{`"true "`, func() any { return "true " }},
		{`" false "`, func() any { return " false " }},
		{`""`, func() any { return "" }},
		{`"yes"`, func() any { return "yes" }},
		{`"1"`, func() any { return "1" }},
		{`"0"`, func() any { return "0" }},
		{"1", func() any { return float64(1) }},
		{"0", func() any { return float64(0) }},
		{"null", func() any { return nil }},
		{"[]", func() any { return []any{} }},
		{"{}", func() any { return jsonx.NewObject() }},
	}
	for _, nm := range nearMisses {
		t.Run("leaves the rejected near-miss primary value unchanged at POST and PUT boundaries/"+nm.name, func(t *testing.T) {
			for _, method := range []string{"POST", "PUT"} {
				body := jsonx.O("schemas", []any{activeNormUserSchema}, "userName", "primary-near-miss@example.com",
					"emails", []any{jsonx.O("value", "primary-near-miss@example.com", "primary", nm.value())})
				if got := normalizeUserEntraCompatibilityBody(method, body); got != any(body) {
					t.Fatalf("%s: body was copied: %s", method, activeNormJSON(got))
				}
			}
		})
	}

	t.Run("copies only the multi-valued entries whose primary value changes", func(t *testing.T) {
		untouched := jsonx.O("value", "untouched@example.com", "type", "home", "primary", true)
		changed := jsonx.O("value", "changed@example.com", "type", "work", "primary", "True")
		body := jsonx.O("schemas", []any{activeNormUserSchema}, "userName", "copy-on-write@example.com",
			"emails", []any{changed, untouched})
		normalized, ok := normalizeUserEntraCompatibilityBody("POST", body).(*jsonx.Object)
		if !ok || normalized == body {
			t.Fatal("expected a copied body")
		}
		emails := objGet(normalized, "emails").([]any)
		activeNormExpectEqual(t, "emails[0]", emails[0], jsonx.O("value", "changed@example.com", "type", "work", "primary", true))
		if emails[1] != any(untouched) {
			t.Fatal("untouched email was copied")
		}
		if v, _ := changed.Get("primary"); v != "True" {
			t.Fatalf("input mutated: %v", v)
		}
	})

	patchCases := []struct{ name, in, want string }{
		{"normalizes a filtered-path value targeting the primary sub-attribute directly",
			`{"op":"replace","path":"emails[type eq \"work\"].primary","value":"true"}`,
			`{"op":"replace","path":"emails[type eq \"work\"].primary","value":true}`},
		{"normalizes a filtered-path value with whitespace around the filter and dot",
			`{"op":"replace","path":"roles [ type eq \"engineer\" ] . primary","value":"true"}`,
			`{"op":"replace","path":"roles [ type eq \"engineer\" ] . primary","value":true}`},
		{"normalizes primary inside a filtered-path element replace value",
			`{"op":"replace","path":"addresses[type eq \"work\"]","value":{"formatted":"1 Infinite Loop","primary":"true"}}`,
			`{"op":"replace","path":"addresses[type eq \"work\"]","value":{"formatted":"1 Infinite Loop","primary":true}}`},
		{"normalizes primary inside an unfiltered attribute-path array replace value",
			`{"op":"replace","path":"roles","value":[{"value":"engineer","primary":"true"}]}`,
			`{"op":"replace","path":"roles","value":[{"value":"engineer","primary":true}]}`},
		{"normalizes a direct unfiltered primary sub-attribute path target",
			`{"op":"replace","path":"emails.primary","value":"false"}`,
			`{"op":"replace","path":"emails.primary","value":false}`},
		{"normalizes active and multi-valued primary fields inside a pathless full-resource PATCH value",
			`{"op":"replace","value":{"active":"true","emails":[{"value":"a@example.com","primary":"true"}],"addresses":[{"formatted":"1 Infinite Loop","primary":"TRUE"}]}}`,
			`{"op":"replace","value":{"active":true,"emails":[{"value":"a@example.com","primary":true}],"addresses":[{"formatted":"1 Infinite Loop","primary":true}]}}`},
		{"leaves an untouched PATCH operation unchanged",
			`{"op":"replace","path":"displayName","value":"False"}`,
			`{"op":"replace","path":"displayName","value":"False"}`},
	}
	for _, pc := range patchCases {
		t.Run(pc.name, func(t *testing.T) {
			wrap := func(op string) string {
				return `{"schemas":["` + activeNormPatchSchema + `"],"Operations":[` + op + `]}`
			}
			body := activeNormObj(t, wrap(pc.in))
			activeNormExpectEqual(t, "normalized", normalizeUserEntraCompatibilityBody("PATCH", body), activeNormObj(t, wrap(pc.want)))
		})
	}
}

// --- HTTP helpers --------------------------------------------------------------------

type activeNormInstance struct {
	e *testEnv
}

// activeNormCreateInstance is createTestInstance (SQLite with native transactions).
func activeNormCreateInstance(t *testing.T, onProjected func(ProjectedUserState)) *activeNormInstance {
	t.Helper()
	opts := Options{Connections: []ConnectionOptions{{
		ID:          "active-normalization",
		Credentials: []BearerCredential{{Type: "bearer", ID: "active-normalization-token", Token: activeNormToken}},
	}}}
	if onProjected != nil {
		opts.Projection = &Projection{ReconcileUser: func(state ProjectedUserState, _ DatabaseContext) error {
			onProjected(state)
			return nil
		}}
	}
	return &activeNormInstance{e: newEnv(t, opts, envOptions{sqlite: true})}
}

func (in *activeNormInstance) do(method, path string, body any) *response {
	in.e.t.Helper()
	h := map[string]string{"Accept": MediaType, "Authorization": "Bearer " + activeNormToken, "Content-Type": MediaType}
	return in.e.request(method, path, body, h)
}

func activeNormUserURL(id string) string { return scimUsersURL + "/" + url.PathEscape(id) }

func (in *activeNormInstance) persistentState() map[string][]adapter.Record {
	out := map[string][]adapter.Record{}
	for _, m := range []string{"user", "session", "scimConnectionBinding", "scimSubject", "scimUser", "scimGroup",
		"scimGroupMember", "scimProjectionGrant", "scimIdentityTombstone"} {
		out[m] = in.e.rows(m)
	}
	return out
}

func (in *activeNormInstance) findSCIMUser(t *testing.T, id string) adapter.Record {
	t.Helper()
	r, err := in.e.db().FindOne(context.Background(), adapter.FindOneInput{Model: "scimUser", Where: []adapter.Where{{Field: "id", Value: id}}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (in *activeNormInstance) createUser(t *testing.T, active bool, userName string) map[string]any {
	t.Helper()
	res := in.do("POST", scimUsersURL, jsonx.O(
		"schemas", []any{activeNormUserSchema},
		"externalId", "directory-"+userName,
		"userName", userName,
		"displayName", "Provisioned User",
		"emails", []any{jsonx.O("value", userName, "type", "work", "primary", true)},
		"active", active,
	))
	if res.Status != 201 {
		t.Fatalf("create user: %d %s", res.Status, res.text())
	}
	return res.json()
}

func activeNormExpectMutationError(t *testing.T, res *response, scimType string) {
	t.Helper()
	if res.Status != 400 {
		t.Fatalf("status = %d %s", res.Status, res.text())
	}
	if ct := res.Header.Get("Content-Type"); ct != MediaType {
		t.Fatalf("content-type = %q", ct)
	}
	b := res.json()
	schemas, _ := b["schemas"].([]any)
	if len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" || b["status"] != "400" || b["scimType"] != scimType {
		t.Fatalf("body = %s, want scimType %s", res.text(), scimType)
	}
}

func activeNormExpectState(t *testing.T, label string, got, want map[string][]adapter.Record) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: persistent state changed\n got %v\nwant %v", label, got, want)
	}
}

func TestActiveNorm_ActiveHTTPNormalization(t *testing.T) {
	// See https://github.com/better-auth/better-auth/pull/10390
	scenarios := []struct {
		scenario       string
		active         string
		expected       bool
		expectedStatus int
	}{
		{"create", "False", false, 201},
		{"replace", "True", true, 200},
		{"path-patch", "false", false, 200},
		{"pathless-patch", "TRUE", true, 200},
		{"schema-qualified-patch", "FaLsE", false, 200},
	}
	for _, sc := range scenarios {
		t.Run("normalizes "+sc.scenario+" string active values at the real HTTP ingress", func(t *testing.T) {
			in := activeNormCreateInstance(t, nil)
			userName := sc.scenario + "@example.com"
			var userID string
			var res *response
			resource := func() *jsonx.Object {
				return jsonx.O(
					"schemas", []any{activeNormUserSchema},
					"externalId", "entra-"+sc.scenario,
					"userName", userName,
					"displayName", "Entra Active User",
					"emails", []any{jsonx.O("value", userName, "type", "work", "primary", true)},
					"active", sc.active,
				)
			}
			if sc.scenario == "create" {
				res = in.do("POST", scimUsersURL, resource())
				userID, _ = res.json()["id"].(string)
			} else {
				user := in.createUser(t, !sc.expected, userName)
				userID = user["id"].(string)
				if sc.scenario == "replace" {
					res = in.do("PUT", activeNormUserURL(userID), resource())
				} else {
					var op *jsonx.Object
					switch sc.scenario {
					case "pathless-patch":
						op = jsonx.O("op", "replace", "value", jsonx.O("active", sc.active))
					case "schema-qualified-patch":
						op = jsonx.O("op", "replace", "path", activeNormUserSchema+":active", "value", sc.active)
					default:
						op = jsonx.O("op", "replace", "path", "active", "value", sc.active)
					}
					res = in.do("PATCH", activeNormUserURL(userID), jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{op}))
				}
			}
			if res.Status != sc.expectedStatus {
				t.Fatalf("status = %d %s", res.Status, res.text())
			}
			got := in.do("GET", activeNormUserURL(userID), nil)
			if got.Status != 200 {
				t.Fatalf("GET status = %d", got.Status)
			}
			if a, ok := got.json()["active"].(bool); !ok || a != sc.expected {
				t.Fatalf("resource.active = %#v", got.json()["active"])
			}
			persisted := in.findSCIMUser(t, userID)
			if a, ok := persisted["active"].(bool); !ok || a != sc.expected {
				t.Fatalf("persisted.active = %#v", persisted["active"])
			}
		})
	}

	t.Run("preserves native Boolean provider requests and Boolean schema discovery", func(t *testing.T) {
		in := activeNormCreateInstance(t, nil)
		res := in.do("POST", scimUsersURL, jsonx.O(
			"schemas", []any{activeNormUserSchema},
			"externalId", "00u-okta-directory-user",
			"userName", "okta.user@example.com",
			"name", jsonx.O("givenName", "Okta", "familyName", "User"),
			"displayName", "Okta User",
			"emails", []any{jsonx.O("value", "okta.user@example.com", "type", "work", "primary", true)},
			"active", true,
		))
		if res.Status != 201 {
			t.Fatalf("status = %d %s", res.Status, res.text())
		}
		body := res.json()
		if a, ok := body["active"].(bool); !ok || !a {
			t.Fatalf("resource.active = %#v", body["active"])
		}
		persisted := in.findSCIMUser(t, body["id"].(string))
		if a, ok := persisted["active"].(bool); !ok || !a {
			t.Fatalf("persisted.active = %#v", persisted["active"])
		}

		schemasRes := in.e.request("GET", "/api/auth/scim/v2/Schemas", nil, map[string]string{"Accept": MediaType})
		if schemasRes.Status != 200 {
			t.Fatalf("Schemas status = %d", schemasRes.Status)
		}
		var found map[string]any
		for _, r := range schemasRes.json()["Resources"].([]any) {
			rm := r.(map[string]any)
			if rm["id"] != activeNormUserSchema {
				continue
			}
			for _, a := range rm["attributes"].([]any) {
				if am := a.(map[string]any); am["name"] == "active" {
					found = am
				}
			}
		}
		if found == nil || found["type"] != "boolean" {
			t.Fatalf("active attribute = %v", found)
		}
	})

	t.Run("rejects invalid active values across every User mutation shape without persistence", func(t *testing.T) {
		in := activeNormCreateInstance(t, nil)
		if r := in.do("GET", scimUsersURL, nil); r.Status != 200 {
			t.Fatalf("establish binding: %d %s", r.Status, r.text())
		}
		before := in.persistentState()
		rejected := in.do("POST", scimUsersURL, jsonx.O("schemas", []any{activeNormUserSchema},
			"userName", "invalid-create@example.com", "active", " false"))
		activeNormExpectMutationError(t, rejected, "invalidValue")
		activeNormExpectState(t, "create", in.persistentState(), before)

		created := in.createUser(t, true, "invalid-mutations@example.com")
		userURL := activeNormUserURL(created["id"].(string))
		invalid := []struct {
			method string
			body   *jsonx.Object
		}{
			{"PUT", jsonx.O("schemas", []any{activeNormUserSchema}, "userName", "invalid-mutations@example.com", "active", float64(1))},
			{"PATCH", jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{jsonx.O("op", "replace", "path", "active", "value", nil)})},
			{"PATCH", jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{jsonx.O("op", "replace", "value", jsonx.O("active", jsonx.O("value", false)))})},
		}
		for _, req := range invalid {
			before := in.persistentState()
			res := in.do(req.method, userURL, req.body)
			activeNormExpectMutationError(t, res, "invalidValue")
			activeNormExpectState(t, req.method+" "+activeNormJSON(req.body), in.persistentState(), before)
		}
	})

	t.Run("rolls back an earlier normalized active operation when a later PATCH operation fails", func(t *testing.T) {
		var mu sync.Mutex
		var projected []ProjectedUserState
		in := activeNormCreateInstance(t, func(s ProjectedUserState) {
			mu.Lock()
			defer mu.Unlock()
			s.Sources = append([]IdentitySource(nil), s.Sources...)
			s.Grants = append([]ProjectedRoleGrant(nil), s.Grants...)
			projected = append(projected, s)
		})
		snapshot := func() []ProjectedUserState {
			mu.Lock()
			defer mu.Unlock()
			return append([]ProjectedUserState(nil), projected...)
		}
		created := in.createUser(t, true, "atomic-active@example.com")
		id := created["id"].(string)
		persistedUser := in.findSCIMUser(t, id)
		if persistedUser == nil {
			t.Fatal("Expected persisted SCIM User")
		}
		sessionAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		if _, err := in.e.db().Create(context.Background(), adapter.CreateInput{Model: "session", Data: adapter.Record{
			"token":     "active-normalization-session-token",
			"userId":    persistedUser["userId"],
			"expiresAt": time.Date(2030, 2, 1, 0, 0, 0, 0, time.UTC),
			"createdAt": sessionAt,
			"updatedAt": sessionAt,
		}}); err != nil {
			t.Fatal(err)
		}
		before := in.persistentState()
		projectedBefore := snapshot()
		resourceBefore := in.do("GET", activeNormUserURL(id), nil).json()

		res := in.do("PATCH", activeNormUserURL(id), jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{
			jsonx.O("op", "replace", "path", "active", "value", "False"),
			jsonx.O("op", "replace", "path", "id", "value", "must-not-be-applied"),
		}))
		activeNormExpectMutationError(t, res, "mutability")
		activeNormExpectState(t, "patch", in.persistentState(), before)
		if got := snapshot(); !reflect.DeepEqual(got, projectedBefore) {
			t.Fatalf("projected states changed: %+v, want %+v", got, projectedBefore)
		}
		resourceAfter := in.do("GET", activeNormUserURL(id), nil).json()
		if !reflect.DeepEqual(resourceAfter, resourceBefore) {
			t.Fatalf("resource changed: %v, want %v", resourceAfter, resourceBefore)
		}
		if resourceAfter["active"] != true {
			t.Fatalf("active = %v", resourceAfter["active"])
		}
	})
}

func TestActiveNorm_PrimaryHTTPNormalization(t *testing.T) {
	entries := []struct {
		attribute string
		entry     *jsonx.Object
	}{
		{"emails", jsonx.O("value", "primary-http@example.com", "type", "work", "primary", "true")},
		{"addresses", jsonx.O("formatted", "1 Infinite Loop", "type", "work", "primary", "true")},
		{"roles", jsonx.O("value", "engineer", "primary", "true")},
		{"phoneNumbers", jsonx.O("value", "+1-555-0100", "type", "work", "primary", "true")},
		{"entitlements", jsonx.O("value", "license", "primary", "true")},
	}
	for _, tc := range entries {
		t.Run("normalizes a string primary for "+tc.attribute+" at the real HTTP create ingress", func(t *testing.T) {
			in := activeNormCreateInstance(t, nil)
			userName := tc.attribute + "-primary@example.com"
			body := jsonx.O(
				"schemas", []any{activeNormUserSchema},
				"userName", userName,
				"displayName", "Entra Primary User",
				"emails", []any{jsonx.O("value", userName, "type", "work", "primary", true)},
			)
			// [attribute]: [entry] overrides emails in place (same key position).
			body.Set(tc.attribute, []any{tc.entry})
			res := in.do("POST", scimUsersURL, body)
			if res.Status != 201 {
				t.Fatalf("status = %d %s", res.Status, res.text())
			}
			entry := res.json()[tc.attribute].([]any)[0].(map[string]any)
			if p, ok := entry["primary"].(bool); !ok || !p {
				t.Fatalf("%s[0].primary = %#v", tc.attribute, entry["primary"])
			}
		})
	}

	// Mirrors the exact payload shape sent by Microsoft's SCIM Validator, which encodes every
	// multi-valued `primary` sub-attribute as a string Boolean and the Enterprise User
	// `manager` as a bare string.
	t.Run("creates a user from the Microsoft SCIM Validator's exact string-primary payload", func(t *testing.T) {
		in := activeNormCreateInstance(t, nil)
		res := in.do("POST", scimUsersURL, jsonx.O(
			"schemas", []any{activeNormUserSchema, activeNormEnterpriseUserSchema},
			"userName", "validator-primary@example.com",
			"displayName", "Validator Primary User",
			"active", "true",
			"emails", []any{jsonx.O("value", "validator-primary@example.com", "type", "work", "primary", "true")},
			"addresses", []any{jsonx.O("formatted", "1 Infinite Loop, Cupertino, CA", "type", "work", "primary", "true")},
			"roles", []any{jsonx.O("value", "engineer", "primary", "true")},
			activeNormEnterpriseUserSchema, jsonx.O("manager", "validator-manager-id"),
		))
		if res.Status != 201 {
			t.Fatalf("status = %d %s", res.Status, res.text())
		}
		r := res.json()
		if a, ok := r["active"].(bool); !ok || !a {
			t.Fatalf("active = %#v", r["active"])
		}
		for _, attr := range []string{"emails", "addresses", "roles"} {
			e := r[attr].([]any)[0].(map[string]any)
			if p, ok := e["primary"].(bool); !ok || !p {
				t.Fatalf("%s[0].primary = %#v", attr, e["primary"])
			}
		}
		ent, _ := r[activeNormEnterpriseUserSchema].(map[string]any)
		if !reflect.DeepEqual(ent["manager"], map[string]any{"value": "validator-manager-id"}) {
			t.Fatalf("manager = %#v", ent["manager"])
		}
		persisted := in.findSCIMUser(t, r["id"].(string))
		if a, ok := persisted["active"].(bool); !ok || !a {
			t.Fatalf("persisted.active = %#v", persisted["active"])
		}
	})

	for _, pc := range []struct{ name, userName, path string }{
		{"normalizes a string primary through a filtered PATCH path at the real HTTP ingress",
			"patch-primary@example.com", `roles[type eq "primary-role"].primary`},
		{"normalizes a string primary through a whitespace-padded filtered PATCH path",
			"patch-primary-whitespace@example.com", `roles [ type eq "primary-role" ] . primary`},
	} {
		t.Run(pc.name, func(t *testing.T) {
			in := activeNormCreateInstance(t, nil)
			created := in.createUser(t, true, pc.userName)
			userURL := activeNormUserURL(created["id"].(string))
			addRole := in.do("PATCH", userURL, jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{
				jsonx.O("op", "add", "path", "roles", "value", []any{jsonx.O("value", "engineer", "type", "primary-role", "primary", false)}),
			}))
			if addRole.Status != 200 {
				t.Fatalf("add role: %d %s", addRole.Status, addRole.text())
			}
			res := in.do("PATCH", userURL, jsonx.O("schemas", []any{activeNormPatchSchema}, "Operations", []any{
				jsonx.O("op", "replace", "path", pc.path, "value", "true"),
			}))
			if res.Status != 200 {
				t.Fatalf("status = %d %s", res.Status, res.text())
			}
			resource := in.do("GET", userURL, nil).json()
			var role map[string]any
			for _, r := range resource["roles"].([]any) {
				if rm := r.(map[string]any); rm["type"] == "primary-role" {
					role = rm
				}
			}
			if p, ok := role["primary"].(bool); !ok || !p {
				t.Fatalf("primary role = %#v", role)
			}
		})
	}
}
