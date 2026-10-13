package scim

// Port of upstream scim-enterprise-user.test.ts
// ("SCIM classic Enterprise User provisioning").

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const (
	entUserCoreSchema       = "urn:ietf:params:scim:schemas:core:2.0:User"
	entUserEnterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	entUserPatchSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	entUserGraphUserSchema  = "urn:ietf:params:scim:schemas:extension:Microsoft:Entra:2.0:User"
	entUserLegacyGroup      = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
	entUserWorkforce        = "workforce-token"
	entUserPartners         = "partners-token"
)

// entUserJ expands placeholders in a JSON template: %CORE%, %ENT%, %PATCH%, %BASE% plus
// the extra "%NAME%", "value" pairs.
func entUserJ(tpl string, kv ...string) string {
	pairs := []string{
		"%CORE%", entUserCoreSchema,
		"%ENT%", entUserEnterpriseSchema,
		"%PATCH%", entUserPatchSchema,
		"%BASE%", testBaseURL,
	}
	pairs = append(pairs, kv...)
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// entUserPlain converts a value (JSON string, []byte, *jsonx.Object, maps...) to plain
// encoding/json values.
func entUserPlain(t *testing.T, v any) any {
	t.Helper()
	var b []byte
	switch x := v.(type) {
	case string:
		b = []byte(x)
	case []byte:
		b = x
	default:
		var err error
		b, err = jsonx.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode %q: %v", string(b), err)
	}
	return out
}

func entUserShow(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// entUserEqual is toEqual (deep equality, key order ignored). want may be a JSON string.
func entUserEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	g, w := entUserPlain(t, got), entUserPlain(t, want)
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("%s:\n got  %s\n want %s", label, entUserShow(g), entUserShow(w))
	}
}

// entUserMatches implements vitest toMatchObject semantics on plain values.
func entUserMatches(got, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, wv := range w {
			gv, ok := g[k]
			if !ok || !entUserMatches(gv, wv) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !entUserMatches(g[i], w[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(got, want)
	}
}

// entUserMatch is toMatchObject. want may be a JSON string.
func entUserMatch(t *testing.T, label string, got, want any) {
	t.Helper()
	g, w := entUserPlain(t, got), entUserPlain(t, want)
	if !entUserMatches(g, w) {
		t.Fatalf("%s: object does not match\n got  %s\n want %s", label, entUserShow(g), entUserShow(w))
	}
}

// entUserGet walks plain maps by key.
func entUserGet(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func entUserHas(v any, key string) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, has := m[key]
	return has
}

// entUserEnc is encodeURIComponent.
func entUserEnc(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

type entUserFixture struct {
	*testEnv
	mu       sync.Mutex
	resolved []*jsonx.Object
}

// newEntUserFixture is createEnterpriseFixture.
func newEntUserFixture(t *testing.T) *entUserFixture {
	f := &entUserFixture{}
	f.testEnv = newEnv(t, Options{
		Connections: []ConnectionOptions{
			staticConnection("workforce", entUserWorkforce),
			staticConnection("partners", entUserPartners),
		},
		Identity: &Identity{
			ResolveUser: func(in IdentityResolutionInput, _ DatabaseContext) (*IdentityResolution, error) {
				f.mu.Lock()
				f.resolved = append(f.resolved, in.Resource.Resource)
				f.mu.Unlock()
				return &IdentityResolution{Action: "create"}, nil
			},
		},
	})
	return f
}

// do sends a SCIM request; path is relative to /api/auth; token "" omits auth; body ""
// sends no body.
func (f *entUserFixture) do(method, path, token, body string) (*response, map[string]any) {
	f.t.Helper()
	var b any
	if body != "" {
		b = body
	}
	res := f.request(method, "/api/auth"+path, b, scimHeaders(token, body != ""))
	var m map[string]any
	_ = json.Unmarshal(res.Body, &m)
	return res, m
}

func (f *entUserFixture) expectStatus(label string, res *response, status int) {
	f.t.Helper()
	if res.Status != status {
		f.t.Fatalf("%s: status = %d, want %d; body %s", label, res.Status, status, res.text())
	}
}

// rawRows returns the raw memory rows of a model (the upstream `data.<model>`).
func (f *entUserFixture) rawRows(model string) []adapter.Record {
	return f.mem.Rows(model)
}

func (f *entUserFixture) scimUserRow(id string) adapter.Record {
	f.t.Helper()
	for _, r := range f.rawRows("scimUser") {
		if r["id"] == id {
			return r
		}
	}
	f.t.Fatalf("scimUser row %s not found", id)
	return nil
}

func entUserStr(v any) string {
	s, _ := v.(string)
	return s
}

func entUserPath(id string) string { return "/scim/v2/Users/" + entUserEnc(id) }

func TestEntUser_DiscoverPersistReplaceTenantScope(t *testing.T) {
	// it("discovers, persists, replaces, and tenant-scopes a Microsoft-style User through HTTP")
	f := newEntUserFixture(t)
	schemasRes, schemas := f.do("GET", "/scim/v2/Schemas", "", "")
	entSchemaRes, entSchema := f.do("GET", "/scim/v2/Schemas/"+entUserEnc(entUserEnterpriseSchema), "", "")
	rtRes, rt := f.do("GET", "/scim/v2/ResourceTypes/User", "", "")
	f.expectStatus("schemas", schemasRes, 200)
	f.expectStatus("enterprise schema", entSchemaRes, 200)
	f.expectStatus("resource type", rtRes, 200)
	entUserMatch(t, "schemas", schemas, `{"totalResults":3}`)
	var ids []string
	for _, r := range schemas["Resources"].([]any) {
		ids = append(ids, entUserStr(entUserGet(r, "id")))
	}
	if !strings.Contains(strings.Join(ids, "\n"), entUserEnterpriseSchema) {
		t.Fatalf("schema ids %v do not contain enterprise schema", ids)
	}
	if entSchema["id"] != entUserEnterpriseSchema {
		t.Fatalf("enterprise schema id = %v", entSchema["id"])
	}
	names := map[string]bool{}
	for _, a := range entSchema["attributes"].([]any) {
		names[entUserStr(entUserGet(a, "name"))] = true
	}
	if !names["employeeNumber"] || !names["manager"] {
		t.Fatalf("enterprise schema attributes %v", names)
	}
	entUserMatch(t, "resource type", rt, entUserJ(`{"id":"User","schema":"%CORE%","schemaExtensions":[{"schema":"%ENT%","required":false}]}`))

	enterpriseName := `{
		"formatted": "Ms. Barbara Jane Jensen III",
		"familyName": "Jensen",
		"givenName": "Barbara",
		"middleName": "Jane",
		"honorificPrefix": "Ms.",
		"honorificSuffix": "III"
	}`
	emails := `[{"value": "bjensen@example.com", "type": "work", "primary": true}]`
	phones := `[{"value": "+1-555-555-8377", "type": "work", "primary": true}]`
	addresses := `[{
		"formatted": "100 Universal City Plaza\nHollywood, CA 91608 USA",
		"streetAddress": "100 Universal City Plaza",
		"locality": "Hollywood",
		"region": "CA",
		"postalCode": "91608",
		"country": "USA",
		"type": "work",
		"primary": true
	}]`
	roles := `[{"value": "Tour Guide", "primary": true}]`
	entitlements := `[{"value": "Universal Studios", "primary": true}]`
	vars := []string{"%NAME%", enterpriseName, "%EMAILS%", emails, "%PHONES%", phones,
		"%ADDRESSES%", addresses, "%ROLES%", roles, "%ENTITLEMENTS%", entitlements}
	enterpriseBody := entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"userName": "bjensen@example.com",
		"externalId": "701984",
		"name": %NAME%,
		"displayName": "Babs Jensen",
		"title": "Tour Guide",
		"userType": "Employee",
		"preferredLanguage": "en-US",
		"locale": "en-US",
		"timezone": "America/Los_Angeles",
		"active": true,
		"emails": %EMAILS%,
		"phoneNumbers": %PHONES%,
		"addresses": %ADDRESSES%,
		"roles": %ROLES%,
		"entitlements": %ENTITLEMENTS%,
		"%ENT%": {
			"employeeNumber": "701984",
			"costCenter": "4130",
			"organization": "Universal Studios",
			"division": "Theme Park",
			"department": "Tour Operations",
			"manager": [{
				"value": "26118915",
				"$ref": "%BASE%/api/auth/scim/v2/Users/26118915",
				"displayName": "John Smith"
			}]
		}
	}`, vars...)
	createRes, created := f.do("POST", "/scim/v2/Users", entUserWorkforce, enterpriseBody)
	f.expectStatus("create", createRes, 201)
	entUserMatch(t, "created", created, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"externalId": "701984",
		"userName": "bjensen@example.com",
		"name": %NAME%,
		"title": "Tour Guide",
		"userType": "Employee",
		"preferredLanguage": "en-US",
		"locale": "en-US",
		"timezone": "America/Los_Angeles",
		"phoneNumbers": %PHONES%,
		"addresses": %ADDRESSES%,
		"roles": %ROLES%,
		"entitlements": %ENTITLEMENTS%,
		"%ENT%": {
			"employeeNumber": "701984",
			"costCenter": "4130",
			"organization": "Universal Studios",
			"division": "Theme Park",
			"department": "Tour Operations",
			"manager": {"value": "26118915", "$ref": "%BASE%/api/auth/scim/v2/Users/26118915"}
		}
	}`, vars...))
	if entUserHas(entUserGet(created, entUserEnterpriseSchema, "manager"), "displayName") {
		t.Fatalf("created manager has displayName")
	}
	if len(f.resolved) != 1 {
		t.Fatalf("resolvedUsers = %d, want 1", len(f.resolved))
	}
	entUserMatch(t, "resolvedUsers[0]", f.resolved[0], entUserJ(`{
		"title": "Tour Guide",
		"phoneNumbers": %PHONES%,
		"enterprise": {"employeeNumber": "701984", "manager": {"value": "26118915"}}
	}`, vars...))
	createdID := entUserStr(created["id"])

	getRes, got := f.do("GET", entUserPath(createdID), entUserWorkforce, "")
	f.expectStatus("get", getRes, 200)
	entUserMatch(t, "get", got, created)

	extRes, ext := f.do("GET", entUserPath(createdID)+"?attributes="+entUserEnc(entUserEnterpriseSchema), entUserWorkforce, "")
	f.expectStatus("entire extension", extRes, 200)
	var keys []string
	for k := range ext {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	wantKeys := []string{entUserEnterpriseSchema, "id", "schemas"}
	sort.Strings(wantKeys)
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("entire extension keys = %v, want %v", keys, wantKeys)
	}
	entUserMatch(t, "entire extension", ext[entUserEnterpriseSchema], entUserJ(`{
		"department": "Tour Operations",
		"manager": {"value": "26118915", "$ref": "%BASE%/api/auth/scim/v2/Users/26118915"}
	}`))

	depRes, dep := f.do("GET", entUserPath(createdID)+"?attributes="+entUserEnc(strings.ToUpper(entUserEnterpriseSchema)+":department"), entUserWorkforce, "")
	f.expectStatus("department", depRes, 200)
	entUserEqual(t, "department", dep, entUserJ(`{"schemas":["%CORE%","%ENT%"],"id":"%ID%","%ENT%":{"department":"Tour Operations"}}`, "%ID%", createdID))

	mlRes, ml := f.do("GET", "/scim/v2/Users?attributes="+entUserEnc(entUserEnterpriseSchema+":manager.value"), entUserWorkforce, "")
	f.expectStatus("manager list", mlRes, 200)
	entUserMatch(t, "manager list", ml, entUserJ(`{"totalResults":1,"Resources":[{"schemas":["%CORE%","%ENT%"],"id":"%ID%","%ENT%":{"manager":{"value":"26118915"}}}]}`, "%ID%", createdID))

	exRes, ex := f.do("GET", entUserPath(createdID)+"?excludedAttributes="+entUserEnc(entUserEnterpriseSchema+":manager.value"), entUserWorkforce, "")
	f.expectStatus("excluded manager value", exRes, 200)
	entUserEqual(t, "excluded manager value", entUserGet(ex, entUserEnterpriseSchema, "manager"), entUserJ(`{"$ref":"%BASE%/api/auth/scim/v2/Users/26118915"}`))

	var workforceRow adapter.Record
	for _, r := range f.rawRows("scimUser") {
		if r["connectionId"] == "workforce" {
			workforceRow = r
		}
	}
	if workforceRow == nil {
		t.Fatal("Expected workforce SCIM User")
	}
	workforceID := entUserStr(workforceRow["id"])
	entUserMatch(t, "serializedAttributes", entUserStr(workforceRow["serializedAttributes"]), entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"name": %NAME%,
		"phoneNumbers": %PHONES%,
		"enterprise": {"employeeNumber": "701984", "manager": {"value": "26118915"}}
	}`, vars...))
	entUserMatch(t, "workforceRow", workforceRow, `{"formattedName":"Ms. Barbara Jane Jensen III","givenName":"Barbara","familyName":"Jensen"}`)
	entUserEqual(t, "serializedEmails", entUserStr(workforceRow["serializedEmails"]), emails)
	if n := len(f.rawRows("account")); n != 0 {
		t.Fatalf("accounts = %d, want 0", n)
	}
	users := f.rawRows("user")
	if len(users) != 1 {
		t.Fatalf("users = %d, want 1", len(users))
	}
	entUserMatch(t, "user[0]", users[0], map[string]any{"id": workforceRow["userId"], "email": "bjensen@example.com", "name": "Babs Jensen"})
	if strings.Contains(string(jsonx.MustMarshal(users)), "employeeNumber") {
		t.Fatal("user rows contain employeeNumber")
	}

	// Corrupt the mirrored columns directly.
	if _, err := f.db().Update(context.Background(), "scimUser", []adapter.Where{{Field: "id", Value: workforceID}}, adapter.Record{
		"formattedName": "corrupt mirror", "givenName": "corrupt mirror", "familyName": nil, "serializedEmails": "[]",
	}); err != nil {
		t.Fatal(err)
	}
	cRes, c := f.do("GET", entUserPath(createdID), entUserWorkforce, "")
	f.expectStatus("canonical after mirror corruption", cRes, 200)
	entUserMatch(t, "canonical after mirror corruption", c, entUserJ(`{"name":%NAME%,"emails":%EMAILS%,"%ENT%":{"department":"Tour Operations"}}`, vars...))

	pRes, p := f.do("PATCH", entUserPath(createdID)+"?attributes="+entUserEnc(entUserEnterpriseSchema+":department"), entUserWorkforce,
		entUserJ(`{"schemas":["%PATCH%"],"Operations":[{"op":"replace","path":"displayName","value":"Barbara J. Jensen"}]}`))
	f.expectStatus("patch", pRes, 200)
	entUserEqual(t, "patch", p, entUserJ(`{"schemas":["%CORE%","%ENT%"],"id":"%ID%","%ENT%":{"department":"Tour Operations"}}`, "%ID%", createdID))
	patchedRow := f.scimUserRow(workforceID)
	entUserMatch(t, "patched row", patchedRow, `{"formattedName":"Ms. Barbara Jane Jensen III","givenName":"Barbara","familyName":"Jensen"}`)
	entUserEqual(t, "patched serializedEmails", entUserStr(patchedRow["serializedEmails"]), emails)
	entUserMatch(t, "patched serializedAttributes", entUserStr(patchedRow["serializedAttributes"]), entUserJ(`{"enterprise":{"department":"Tour Operations","manager":{"value":"26118915","$ref":"%BASE%/api/auth/scim/v2/Users/26118915"}}}`))

	wrongRes, _ := f.do("GET", entUserPath(createdID), entUserPartners, "")
	f.expectStatus("wrong tenant", wrongRes, 404)

	partnerRes, partner := f.do("POST", "/scim/v2/Users", entUserPartners,
		entUserJ(`{"schemas":["%CORE%","%ENT%"],"userName":"partner-bjensen@example.com","externalId":"701984"}`))
	f.expectStatus("partner create", partnerRes, 201)
	entUserMatch(t, "partner", partner, entUserJ(`{"schemas":["%CORE%","%ENT%"],"externalId":"701984"}`))
	if entUserHas(partner, entUserEnterpriseSchema) {
		t.Fatal("partner has enterprise extension")
	}
	pgRes, pg := f.do("GET", entUserPath(entUserStr(partner["id"])), entUserPartners, "")
	f.expectStatus("partner get", pgRes, 200)
	entUserEqual(t, "declared-only partner schemas", pg["schemas"], entUserJ(`["%CORE%","%ENT%"]`))
	if entUserHas(pg, entUserEnterpriseSchema) {
		t.Fatal("declared-only partner has enterprise extension")
	}
	foundWorkforce, foundPartners := false, false
	for _, r := range f.rawRows("scimUser") {
		if r["externalId"] == "701984" {
			foundWorkforce = foundWorkforce || r["connectionId"] == "workforce"
			foundPartners = foundPartners || r["connectionId"] == "partners"
		}
	}
	if !foundWorkforce || !foundPartners {
		t.Fatalf("scimUser rows missing tenant-scoped externalIds: %s", jsonx.MustMarshal(f.rawRows("scimUser")))
	}

	rRes, r := f.do("PUT", entUserPath(createdID), entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%"],
		"userName": "bjensen@example.com",
		"externalId": "701984",
		"displayName": "Barbara Jensen",
		"name": {"formatted": "Barbara Jensen", "givenName": "Barbara", "familyName": "Jensen"},
		"emails": [{"value": "bjensen@example.com", "type": "work", "primary": true}],
		"active": true
	}`))
	f.expectStatus("replace", rRes, 200)
	entUserMatch(t, "replaced", r, entUserJ(`{"schemas":["%CORE%"],"displayName":"Barbara Jensen","name":{"formatted":"Barbara Jensen","givenName":"Barbara","familyName":"Jensen"}}`))
	for _, k := range []string{entUserEnterpriseSchema, "title", "phoneNumbers"} {
		if entUserHas(r, k) {
			t.Fatalf("replaced has %s", k)
		}
	}
	entUserEqual(t, "replaced serializedAttributes", entUserStr(f.scimUserRow(workforceID)["serializedAttributes"]), entUserJ(`{
		"schemas": ["%CORE%"],
		"name": {"formatted": "Barbara Jensen", "givenName": "Barbara", "familyName": "Jensen"},
		"emails": [{"value": "bjensen@example.com", "type": "work", "primary": true}]
	}`))
}

func TestEntUser_ManagerReferenceDiscardsReadOnlyDisplayName(t *testing.T) {
	// it("accepts an RFC manager reference while discarding client readOnly displayName data")
	f := newEntUserFixture(t)
	res, created := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"userName": "reference-only-manager@example.com",
		"%ENT%": {"manager": {"$ref": "%BASE%/api/auth/scim/v2/Users/manager", "displayName": "Client supplied display value"}}
	}`))
	f.expectStatus("create", res, 201)
	ref := entUserJ(`{"$ref":"%BASE%/api/auth/scim/v2/Users/manager"}`)
	entUserEqual(t, "created manager", entUserGet(created, entUserEnterpriseSchema, "manager"), ref)
	if len(f.resolved) == 0 {
		t.Fatal("resolver not called")
	}
	entUserEqual(t, "resolved manager", entUserGet(entUserPlain(t, f.resolved[0]), "enterprise", "manager"), ref)
	rows := f.rawRows("scimUser")
	attrs := entUserStr(rows[0]["serializedAttributes"])
	entUserMatch(t, "serializedAttributes", attrs, entUserJ(`{"enterprise":{"manager":{"$ref":"%BASE%/api/auth/scim/v2/Users/manager"}}}`))
	if strings.Contains(attrs, "displayName") {
		t.Fatalf("serializedAttributes contains displayName: %s", attrs)
	}
}

func TestEntUser_PatchCoreAndEnterpriseThroughEntraAndRFCPaths(t *testing.T) {
	// it("patches core and Enterprise User attributes through Entra and RFC path shapes")
	f := newEntUserFixture(t)
	mRes, manager := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{"schemas":["%CORE%"],"userName":"manager@example.com","displayName":"Priya Shah"}`))
	f.expectStatus("manager", mRes, 201)
	managerID := entUserStr(manager["id"])
	rRes, report := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%"],
		"userName": "report@example.com",
		"displayName": "Jordan Lee",
		"name": {"formatted": "Jordan Quinn Lee", "givenName": "Jordan", "middleName": "Quinn", "familyName": "Lee"},
		"title": "Analyst",
		"phoneNumbers": [{"value": "+1-555-0100", "type": "work", "primary": true}]
	}`))
	f.expectStatus("report", rRes, 201)
	reportID := entUserStr(report["id"])
	ids := []string{"%ID%", reportID, "%MID%", managerID}

	attrs := strings.Join([]string{
		"title", "name", "phoneNumbers", "addresses",
		entUserEnterpriseSchema + ":department",
		entUserEnterpriseSchema + ":costCenter",
		entUserEnterpriseSchema + ":division",
		entUserEnterpriseSchema + ":manager",
	}, ",")
	pRes, patched := f.do("PATCH", entUserPath(reportID)+"?attributes="+entUserEnc(attrs), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [
			{"op": "Replace", "path": "%ENT%:manager", "value": "%MID%"},
			{"op": "Replace", "value": {"title": "Senior Analyst", "%ENT%:department": "Finance"}},
			{"op": "Add", "path": "addresses", "value": [{
				"streetAddress": "1 Finance Way", "locality": "Seattle", "region": "WA",
				"postalCode": "98101", "country": "US", "type": "work", "primary": true
			}]},
			{"op": "Replace", "path": "phoneNumbers[type eq \"work\"].value", "value": "+1-555-0199"},
			{"op": "Add", "path": "phoneNumbers", "value": [{"value": "+1-555-0177", "type": "mobile", "primary": true}]},
			{"op": "Replace", "path": "name", "value": {"givenName": "Jordana"}},
			{"op": "Replace", "path": "%ENT%:costCenter", "value": "CC-204"},
			{"op": "Replace", "path": "%ENT%", "value": {"division": "Financial Planning"}},
			{"op": "Add", "path": "manager", "value": [{
				"value": "%MID%",
				"$ref": "%BASE%/api/auth/scim/v2/Users/%MID%",
				"displayName": "Client supplied manager name"
			}]}
		]
	}`, ids...))
	f.expectStatus("patch", pRes, 200)
	entUserEqual(t, "patched report", patched, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"id": "%ID%",
		"title": "Senior Analyst",
		"name": {"formatted": "Jordan Quinn Lee", "givenName": "Jordana", "middleName": "Quinn", "familyName": "Lee"},
		"phoneNumbers": [
			{"value": "+1-555-0199", "type": "work", "primary": false},
			{"value": "+1-555-0177", "type": "mobile", "primary": true}
		],
		"addresses": [{
			"streetAddress": "1 Finance Way", "locality": "Seattle", "region": "WA",
			"postalCode": "98101", "country": "US", "type": "work", "primary": true
		}],
		"%ENT%": {
			"department": "Finance",
			"costCenter": "CC-204",
			"division": "Financial Planning",
			"manager": {"value": "%MID%", "$ref": "%BASE%/api/auth/scim/v2/Users/%MID%"}
		}
	}`, ids...))
	persisted := entUserStr(f.scimUserRow(reportID)["serializedAttributes"])
	entUserMatch(t, "persisted", persisted, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"title": "Senior Analyst",
		"phoneNumbers": [
			{"value": "+1-555-0199", "type": "work", "primary": false},
			{"value": "+1-555-0177", "type": "mobile", "primary": true}
		],
		"addresses": [{"streetAddress": "1 Finance Way", "locality": "Seattle", "type": "work"}],
		"enterprise": {
			"department": "Finance",
			"costCenter": "CC-204",
			"division": "Financial Planning",
			"manager": {"value": "%MID%", "$ref": "%BASE%/api/auth/scim/v2/Users/%MID%"}
		},
		"name": {"formatted": "Jordan Quinn Lee", "givenName": "Jordana", "middleName": "Quinn", "familyName": "Lee"}
	}`, ids...))
	if strings.Contains(persisted, "displayName") {
		t.Fatalf("persisted contains displayName: %s", persisted)
	}

	mvRes, mv := f.do("PATCH", entUserPath(reportID)+"?attributes="+entUserEnc(entUserEnterpriseSchema+":manager"), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [
			{"op": "Replace", "path": "manager.value", "value": "%MID%"},
			{"op": "Replace", "path": "manager.$ref", "value": "%BASE%/api/auth/scim/v2/Users/%MID%"}
		]
	}`, ids...))
	f.expectStatus("manager value", mvRes, 200)
	entUserEqual(t, "manager value", mv, entUserJ(`{"schemas":["%CORE%","%ENT%"],"id":"%ID%","%ENT%":{"manager":{"value":"%MID%","$ref":"%BASE%/api/auth/scim/v2/Users/%MID%"}}}`, ids...))

	roRes, ro := f.do("PATCH", entUserPath(reportID), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Replace", "path": "manager.displayName", "value": "Must not persist"}]
	}`))
	f.expectStatus("read-only manager", roRes, 400)
	entUserMatch(t, "read-only manager", ro, `{"scimType":"mutability"}`)
	if strings.Contains(entUserStr(f.scimUserRow(reportID)["serializedAttributes"]), "Must not persist") {
		t.Fatal("read-only manager displayName persisted")
	}

	rmAttrs := strings.Join([]string{"title", "phoneNumbers", "addresses", entUserEnterpriseSchema}, ",")
	rmRes, rm := f.do("PATCH", entUserPath(reportID)+"?attributes="+entUserEnc(rmAttrs), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [
			{"op": "Remove", "path": "title"},
			{"op": "Remove", "path": "addresses[type eq \"work\"]"},
			{"op": "Remove", "path": "%ENT%:department"},
			{"op": "Remove", "path": "manager"}
		]
	}`))
	f.expectStatus("remove", rmRes, 200)
	entUserEqual(t, "remove", rm, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"id": "%ID%",
		"phoneNumbers": [
			{"value": "+1-555-0199", "type": "work", "primary": false},
			{"value": "+1-555-0177", "type": "mobile", "primary": true}
		],
		"%ENT%": {"costCenter": "CC-204", "division": "Financial Planning"}
	}`, ids...))

	mmRes, mm := f.do("PATCH", entUserPath(reportID)+"?attributes="+entUserEnc(entUserEnterpriseSchema+":manager"), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Replace", "path": "manager.value", "value": "%MID%"}]
	}`, ids...))
	f.expectStatus("missing manager value", mmRes, 200)
	entUserEqual(t, "missing manager value", mm, entUserJ(`{"schemas":["%CORE%","%ENT%"],"id":"%ID%","%ENT%":{"manager":{"value":"%MID%"}}}`, ids...))

	muRes, mu := f.do("PATCH", entUserPath(reportID)+"?attributes=phoneNumbers", entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [
			{"op": "Remove", "path": "phoneNumbers"},
			{"op": "Replace", "path": "phoneNumbers.value", "value": "+1-555-0188"}
		]
	}`))
	f.expectStatus("missing unfiltered subattribute", muRes, 200)
	entUserEqual(t, "missing unfiltered subattribute", mu, entUserJ(`{"schemas":["%CORE%","%ENT%"],"id":"%ID%","phoneNumbers":[{"value":"+1-555-0188"}]}`, ids...))

	before := entUserStr(f.scimUserRow(reportID)["serializedAttributes"])
	rjRes, rj := f.do("PATCH", entUserPath(reportID), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [
			{"op": "Replace", "path": "title", "value": "Must not persist"},
			{"op": "Replace", "path": "urn:ietf:params:scim:schemas:extension:Microsoft:Entra:2.0:User:department", "value": "Unsupported"}
		]
	}`))
	f.expectStatus("rejected", rjRes, 400)
	entUserMatch(t, "rejected", rj, `{"scimType":"invalidPath"}`)
	if after := entUserStr(f.scimUserRow(reportID)["serializedAttributes"]); after != before {
		t.Fatalf("rejected PATCH mutated resource:\n before %s\n after  %s", before, after)
	}
}

func TestEntUser_EntraFullMultiOpReplaceAttributes(t *testing.T) {
	// it("applies Microsoft Entra's full multi-op Replace Attributes PATCH shape")
	f := newEntUserFixture(t)
	cRes, user := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"userName": "replace-attributes@example.com",
		"displayName": "Replace Attributes",
		"name": {"givenName": "Replace", "familyName": "Attributes"},
		"emails": [{"value": "replace-attributes@example.com", "type": "work", "primary": true}],
		"phoneNumbers": [{"value": "+1-555-0100", "type": "work", "primary": true}],
		"addresses": [{
			"formatted": "1 Old Way", "streetAddress": "1 Old Way", "locality": "Redmond", "region": "WA",
			"postalCode": "98052", "country": "US", "type": "work", "primary": true
		}],
		"roles": [{"value": "engineer", "display": "Engineer", "primary": true}],
		"%ENT%": {"employeeNumber": "1"}
	}`))
	f.expectStatus("create", cRes, 201)
	attrs := strings.Join([]string{
		"displayName", "title", "userType", "preferredLanguage", "locale", "timezone",
		"emails", "phoneNumbers", "addresses", "roles", entUserEnterpriseSchema + ":employeeNumber",
	}, ",")
	pRes, patched := f.do("PATCH", entUserPath(entUserStr(user["id"]))+"?attributes="+entUserEnc(attrs), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [
			{"op": "Replace", "path": "emails[primary eq true].value", "value": "replaced@example.com"},
			{"op": "Replace", "path": "phoneNumbers[primary eq true].value", "value": "+1-555-0199"},
			{"op": "Replace", "path": "addresses[primary eq true].formatted", "value": "2 New Way"},
			{"op": "Replace", "path": "addresses[primary eq true].streetAddress", "value": "2 New Way"},
			{"op": "Replace", "path": "addresses[primary eq true].locality", "value": "Bellevue"},
			{"op": "Replace", "path": "addresses[primary eq true].region", "value": "WA"},
			{"op": "Replace", "path": "addresses[primary eq true].postalCode", "value": "98004"},
			{"op": "Replace", "path": "addresses[primary eq true].country", "value": "US"},
			{"op": "Replace", "path": "roles[primary eq true].value", "value": "senior-engineer"},
			{"op": "Replace", "path": "roles[primary eq true].display", "value": "Senior Engineer"},
			{"op": "Replace", "path": "displayName", "value": ["Replaced Attributes"]},
			{"op": "Replace", "path": "title", "value": ["Senior Engineer"]},
			{"op": "Replace", "path": "userType", "value": ["Employee"]},
			{"op": "Replace", "path": "preferredLanguage", "value": ["en-US"]},
			{"op": "Replace", "path": "locale", "value": ["en-US"]},
			{"op": "Replace", "path": "timezone", "value": ["America/Los_Angeles"]},
			{"op": "Replace", "path": "%ENT%:employeeNumber", "value": ["99999"]}
		]
	}`))
	f.expectStatus("patch", pRes, 200)
	entUserMatch(t, "patched", patched, entUserJ(`{
		"displayName": "Replaced Attributes",
		"title": "Senior Engineer",
		"userType": "Employee",
		"preferredLanguage": "en-US",
		"locale": "en-US",
		"timezone": "America/Los_Angeles",
		"emails": [{"value": "replaced@example.com", "primary": true}],
		"phoneNumbers": [{"value": "+1-555-0199", "primary": true}],
		"addresses": [{
			"formatted": "2 New Way", "streetAddress": "2 New Way", "locality": "Bellevue", "region": "WA",
			"postalCode": "98004", "country": "US", "primary": true
		}],
		"roles": [{"value": "senior-engineer", "display": "Senior Engineer", "primary": true}],
		"%ENT%": {"employeeNumber": "99999"}
	}`))
}

func TestEntUser_EntraFlatKeyPathlessReplaceWithPrimaryFilters(t *testing.T) {
	// it("applies Entra's captured flat-key pathless replace alongside primary filters")
	f := newEntUserFixture(t)
	_, user := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"userName": "flat-key-replace@example.com",
		"name": {"formatted": "Original"},
		"emails": [{"value": "flat-key-replace@example.com", "primary": true}],
		"phoneNumbers": [{"value": "+1-555-0100", "primary": true}],
		"addresses": [{"formatted": "1 Old Way", "primary": true}],
		"roles": [{"value": "engineer", "display": "Engineer", "primary": true}],
		"entitlements": [{"value": "vpn", "display": "VPN", "primary": true}],
		"%ENT%": {"manager": "manager-id"}
	}`))
	pRes, patched := f.do("PATCH", entUserPath(entUserStr(user["id"])), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [
			{"op": "replace", "path": "emails[primary eq true].value", "value": "flat-key-replaced@example.com"},
			{"op": "replace", "path": "phoneNumbers[primary eq true].value", "value": "+1-555-0199"},
			{"op": "replace", "path": "roles[primary eq true].value", "value": "senior-engineer"},
			{"op": "replace", "path": "entitlements[primary eq true].value", "value": "vpn-admin"},
			{"op": "replace", "value": {
				"displayName": "Flat Key Replace",
				"name.formatted": "Replaced",
				"name.givenName": "First",
				"%ENT%:employeeNumber": "99999"
			}}
		]
	}`))
	f.expectStatus("patch", pRes, 200)
	want := entUserJ(`{
		"displayName": "Flat Key Replace",
		"name": {"formatted": "Replaced", "givenName": "First"},
		"emails": [{"value": "flat-key-replaced@example.com", "primary": true}],
		"phoneNumbers": [{"value": "+1-555-0199", "primary": true}],
		"roles": [{"value": "senior-engineer", "primary": true}],
		"entitlements": [{"value": "vpn-admin", "primary": true}],
		"%ENT%": {"employeeNumber": "99999", "manager": {"value": "manager-id"}}
	}`)
	entUserMatch(t, "patched", patched, want)

	_, list := f.do("GET", "/scim/v2/Users?filter="+entUserEnc(`userName eq "flat-key-replace@example.com"`), entUserWorkforce, "")
	resources, _ := list["Resources"].([]any)
	if len(resources) != 1 {
		t.Fatalf("Resources = %s", entUserShow(list))
	}
	entUserMatch(t, "listed", resources[0], want)
}

func TestEntUser_QuotedStringPrimaryFilter(t *testing.T) {
	// it("resolves the quoted string-literal primary filter variant")
	f := newEntUserFixture(t)
	_, user := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%"],
		"userName": "quoted-primary-filter@example.com",
		"roles": [{"value": "engineer", "primary": true}]
	}`))
	pRes, patched := f.do("PATCH", entUserPath(entUserStr(user["id"]))+"?attributes=roles", entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Replace", "path": "roles[primary eq \"true\"].value", "value": "senior-engineer"}]
	}`))
	f.expectStatus("patch", pRes, 200)
	entUserEqual(t, "roles", patched["roles"], `[{"value":"senior-engineer","primary":true}]`)
}

func TestEntUser_PrimaryFilteredReplaceCreatesTarget(t *testing.T) {
	// it("creates a primary-filtered replace target when no value is currently primary")
	f := newEntUserFixture(t)
	_, user := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%"],
		"userName": "no-primary-match@example.com",
		"roles": [{"value": "engineer", "primary": false}]
	}`))
	pRes, patched := f.do("PATCH", entUserPath(entUserStr(user["id"])), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Replace", "path": "roles[primary eq true].value", "value": "senior-engineer"}]
	}`))
	f.expectStatus("patch", pRes, 200)
	entUserEqual(t, "roles", patched["roles"], `[{"value":"engineer","primary":false},{"value":"senior-engineer","primary":true}]`)
}

func TestEntUser_CascadeEmptiedManagerOnSubattributeRemoval(t *testing.T) {
	// it("cascades an emptied manager object out of the Enterprise extension on subattribute removal")
	f := newEntUserFixture(t)
	_, user := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"userName": "manager-value-remove@example.com",
		"%ENT%": {"manager": "manager-id"}
	}`))
	id := entUserStr(user["id"])
	pRes, patched := f.do("PATCH", entUserPath(id)+"?attributes=userName", entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Remove", "path": "%ENT%:manager.value"}]
	}`))
	f.expectStatus("patch", pRes, 200)
	entUserEqual(t, "schemas", patched["schemas"], entUserJ(`["%CORE%"]`))
	if entUserHas(patched, entUserEnterpriseSchema) {
		t.Fatal("patched has enterprise extension")
	}
	_, got := f.do("GET", entUserPath(id), entUserWorkforce, "")
	if entUserHas(got, entUserEnterpriseSchema) {
		t.Fatal("resource has enterprise extension")
	}
	if attrs := entUserPlain(t, entUserStr(f.scimUserRow(id)["serializedAttributes"])); entUserHas(attrs, "enterprise") {
		t.Fatalf("serializedAttributes has enterprise: %s", entUserShow(attrs))
	}
}

func TestEntUser_ClearManagerOnEmptyStringReplace(t *testing.T) {
	// it("clears manager on Microsoft Entra's replace-with-empty-string PATCH")
	f := newEntUserFixture(t)
	_, user := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"userName": "manager-empty-string-remove@example.com",
		"%ENT%": {"manager": "manager-id"}
	}`))
	id := entUserStr(user["id"])
	pRes, patched := f.do("PATCH", entUserPath(id), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "replace", "path": "%ENT%:manager", "value": ""}]
	}`))
	f.expectStatus("patch", pRes, 200)
	entUserEqual(t, "patched schemas", patched["schemas"], entUserJ(`["%CORE%"]`))
	if entUserHas(patched, entUserEnterpriseSchema) {
		t.Fatal("patched has enterprise extension")
	}
	_, fetched := f.do("GET", entUserPath(id), entUserWorkforce, "")
	entUserEqual(t, "fetched schemas", fetched["schemas"], entUserJ(`["%CORE%"]`))
	if entUserHas(fetched, entUserEnterpriseSchema) {
		t.Fatal("fetched has enterprise extension")
	}
}

func TestEntUser_BareEnterpriseSubAttributeProjection(t *testing.T) {
	// it("resolves a bare Enterprise User sub-attribute name in the attributes projection")
	f := newEntUserFixture(t)
	_, user := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"userName": "bare-attribute-projection@example.com",
		"roles": [{"value": "engineer", "primary": true}],
		"%ENT%": {"manager": "manager-id"}
	}`))
	id := entUserStr(user["id"])
	_, projected := f.do("GET", entUserPath(id)+"?attributes="+entUserEnc("userName,roles,manager"), entUserWorkforce, "")
	entUserEqual(t, "projected", projected, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"id": "%ID%",
		"userName": "bare-attribute-projection@example.com",
		"roles": [{"value": "engineer", "primary": true}],
		"%ENT%": {"manager": {"value": "manager-id"}}
	}`, "%ID%", id))
}

func TestEntUser_PathlessEnterpriseRootObject(t *testing.T) {
	// it("applies a pathless Enterprise User root object with canonical persistence and response")
	f := newEntUserFixture(t)
	mRes, manager := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{"schemas":["%CORE%"],"userName":"pathless-manager@example.com","displayName":"Pathless Manager"}`))
	f.expectStatus("manager", mRes, 201)
	rRes, report := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{"schemas":["%CORE%"],"userName":"pathless-report@example.com","displayName":"Pathless Report"}`))
	f.expectStatus("report", rRes, 201)
	ids := []string{"%ID%", entUserStr(report["id"]), "%MID%", entUserStr(manager["id"])}
	pRes, patched := f.do("PATCH", entUserPath(entUserStr(report["id"]))+"?attributes="+entUserEnc(entUserEnterpriseSchema), entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Replace", "value": {"%ENT%": {
			"employeeNumber": "E-204", "department": "Finance", "manager": {"value": "%MID%"}
		}}}]
	}`, ids...))
	f.expectStatus("patch", pRes, 200)
	entUserMatch(t, "patched", patched, entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"id": "%ID%",
		"%ENT%": {"employeeNumber": "E-204", "department": "Finance", "manager": {"value": "%MID%"}}
	}`, ids...))
	entUserMatch(t, "persisted", entUserStr(f.scimUserRow(entUserStr(report["id"]))["serializedAttributes"]), entUserJ(`{
		"schemas": ["%CORE%", "%ENT%"],
		"enterprise": {"employeeNumber": "E-204", "department": "Finance", "manager": {"value": "%MID%"}}
	}`, ids...))
}

func TestEntUser_RequiresExactlyPatchOpSchema(t *testing.T) {
	// it("requires exactly the PatchOp schema on User PATCH without mutating rejected resources")
	f := newEntUserFixture(t)
	cRes, created := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{"schemas":["%CORE%"],"userName":"patch-message-schema@example.com","title":"Original title"}`))
	f.expectStatus("create", cRes, 201)
	id := entUserStr(created["id"])
	read := func() string { return entUserStr(f.scimUserRow(id)["serializedAttributes"]) }
	before := read()
	for _, unsupported := range []string{entUserGraphUserSchema, entUserLegacyGroup} {
		res, body := f.do("PATCH", entUserPath(id), entUserWorkforce, entUserJ(`{
			"schemas": ["%PATCH%", "%UNSUPPORTED%"],
			"Operations": [{"op": "Replace", "path": "title", "value": "Must not persist"}]
		}`, "%UNSUPPORTED%", unsupported))
		f.expectStatus(unsupported, res, 400)
		entUserMatch(t, unsupported, body, `{"scimType":"invalidValue"}`)
		if read() != before {
			t.Fatalf("%s: rejected PATCH mutated resource", unsupported)
		}
	}
	aRes, accepted := f.do("PATCH", entUserPath(id)+"?attributes=title", entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Replace", "path": "title", "value": "Accepted title"}]
	}`))
	f.expectStatus("accepted", aRes, 200)
	entUserMatch(t, "accepted", accepted, entUserJ(`{"schemas":["%CORE%"],"id":"%ID%","title":"Accepted title"}`, "%ID%", id))
	entUserMatch(t, "persisted", read(), `{"title":"Accepted title"}`)
}

func TestEntUser_DemotesExistingPrimaryValues(t *testing.T) {
	// it("demotes existing primary values for every structured core attribute over HTTP")
	f := newEntUserFixture(t)
	cRes, created := f.do("POST", "/scim/v2/Users", entUserWorkforce, entUserJ(`{
		"schemas": ["%CORE%"],
		"userName": "primary-values@example.com",
		"phoneNumbers": [{"value": "+1-555-0100", "type": "work", "primary": true}],
		"addresses": [{"locality": "Seattle", "type": "work", "primary": true}],
		"roles": [{"value": "analyst", "type": "work", "primary": true}],
		"entitlements": [{"value": "standard", "type": "work", "primary": true}]
	}`))
	f.expectStatus("create", cRes, 201)
	pRes, patched := f.do("PATCH", entUserPath(entUserStr(created["id"]))+"?attributes=phoneNumbers,addresses,roles,entitlements", entUserWorkforce, entUserJ(`{
		"schemas": ["%PATCH%"],
		"Operations": [{"op": "Add", "value": {
			"phoneNumbers": [{"value": "+1-555-0199", "type": "mobile", "primary": true}],
			"addresses": [{"locality": "Vancouver", "type": "home", "primary": true}],
			"roles": [{"value": "manager", "type": "project", "primary": true}],
			"entitlements": [{"value": "premium", "type": "license", "primary": true}]
		}}]
	}`))
	f.expectStatus("patch", pRes, 200)
	entUserMatch(t, "patched", patched, `{
		"phoneNumbers": [
			{"value": "+1-555-0100", "type": "work", "primary": false},
			{"value": "+1-555-0199", "type": "mobile", "primary": true}
		],
		"addresses": [
			{"locality": "Seattle", "type": "work", "primary": false},
			{"locality": "Vancouver", "type": "home", "primary": true}
		],
		"roles": [
			{"value": "analyst", "type": "work", "primary": false},
			{"value": "manager", "type": "project", "primary": true}
		],
		"entitlements": [
			{"value": "standard", "type": "work", "primary": false},
			{"value": "premium", "type": "license", "primary": true}
		]
	}`)
}

func TestEntUser_TypedEnterpriseCallbackData(t *testing.T) {
	// it("exposes typed Enterprise User and manager callback data")
	t.Skip("TS-only: compile-time expectTypeOf assertions on SCIMCanonicalManager/SCIMEnterpriseUser; the Go port exposes the canonical resource as *jsonx.Object (CanonicalUser.Resource)")
}
