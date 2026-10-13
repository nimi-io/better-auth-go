package scim

// Port of scim-okta-conformance.test.ts: Okta's SCIM 2.0 SPEC and CRUD conformance
// suites. Upstream runs against a real HTTP listener (getHttpTestInstance) backed by
// node:sqlite; here requests go through auth.Handler() on an in-memory SQLite database.

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const (
	oktaUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	oktaPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	oktaListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	oktaErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	oktaMediaType   = "application/scim+json"
	oktaToken       = "okta-conformance-token"
)

type oktaName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type oktaEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary *bool  `json:"primary,omitempty"`
}

type oktaUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	Name        *oktaName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      *bool       `json:"active"`
	Emails      []oktaEmail `json:"emails,omitempty"`
}

type oktaList struct {
	Schemas      []string   `json:"schemas"`
	TotalResults *float64   `json:"totalResults"`
	StartIndex   *float64   `json:"startIndex"`
	ItemsPerPage *float64   `json:"itemsPerPage"`
	Resources    []oktaUser `json:"Resources"`
}

type oktaError struct {
	Schemas []string `json:"schemas"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail"`
}

func oktaHeaders(authorization string) map[string]string {
	return map[string]string{
		"Accept":        oktaMediaType,
		"Authorization": authorization,
		"Content-Type":  oktaMediaType,
	}
}

func oktaDefaultHeaders() map[string]string { return oktaHeaders("Bearer " + oktaToken) }

func oktaNewEnv(t *testing.T) *testEnv {
	t.Helper()
	return newEnv(t, Options{Connections: []ConnectionOptions{{
		ID:          "okta-conformance",
		Credentials: []BearerCredential{{Type: "bearer", ID: "okta-conformance-token", Token: oktaToken}},
	}}}, envOptions{sqlite: true})
}

func oktaDecode[T any](t *testing.T, r *response) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatalf("decode %q: %v", r.text(), err)
	}
	return v
}

func oktaFilterURL(filter string) string {
	return scimUsersURL + "?" + url.Values{"filter": {filter}}.Encode()
}

func oktaIsTrue(b *bool) bool  { return b != nil && *b }
func oktaIsFalse(b *bool) bool { return b != nil && !*b }

func TestOktaSPEC(t *testing.T) {
	// describe("Okta SCIM 2.0 SPEC test")
	e := oktaNewEnv(t)

	seededUserName := "morgan.chen@example.com"
	seededGivenName := "Morgan"
	seededFamilyName := "Chen"

	randomUsername := "jordan.rivera@example.com"
	randomUsernameCaps := strings.ToUpper(randomUsername)
	randomGivenName := "Jordan"
	randomFamilyName := "Rivera"
	randomEmail := "jordan.rivera.primary@example.com"
	var idUserOne string

	// beforeAll: seed one User.
	seed := e.request("POST", scimUsersURL, map[string]any{
		"schemas":     []string{oktaUserSchema},
		"userName":    seededUserName,
		"name":        map[string]any{"givenName": seededGivenName, "familyName": seededFamilyName},
		"emails":      []any{map[string]any{"value": seededUserName, "type": "work", "primary": true}},
		"displayName": seededGivenName + " " + seededFamilyName,
		"active":      true,
	}, oktaDefaultHeaders())
	if seed.Status != 201 {
		t.Fatalf("seed status = %d: %s", seed.Status, seed.text())
	}
	seededUserID := oktaDecode[oktaUser](t, seed).ID

	t.Run("R1 — Required Test: Test Users endpoint", func(t *testing.T) {
		res := e.request("GET", scimUsersURL+"?count=1&startIndex=1", nil, oktaDefaultHeaders())
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		body := oktaDecode[oktaList](t, res)
		if !slices.Contains(body.Schemas, oktaListSchema) {
			t.Fatalf("schemas = %v", body.Schemas)
		}
		if body.ItemsPerPage == nil || body.StartIndex == nil || body.TotalResults == nil {
			t.Fatalf("list numbers missing: %s", res.text())
		}
		if len(body.Resources) == 0 {
			t.Fatalf("no resources")
		}
		r := body.Resources[0]
		if r.ID == "" || r.Name == nil || r.Name.FamilyName == "" || r.Name.GivenName == "" || r.UserName == "" ||
			!oktaIsTrue(r.Active) || len(r.Emails) == 0 || r.Emails[0].Value == "" {
			t.Fatalf("resource = %s", res.text())
		}
	})

	t.Run("R2 — Required Test: Get Users/{id}", func(t *testing.T) {
		res := e.request("GET", scimUsersURL+"/"+seededUserID, nil, oktaDefaultHeaders())
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaUser](t, res)
		if b.ID != seededUserID || b.Name == nil || b.Name.FamilyName == "" || b.Name.GivenName == "" || b.UserName == "" ||
			!oktaIsTrue(b.Active) || len(b.Emails) == 0 || b.Emails[0].Value == "" {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("R3 — Required Test: Test invalid User by username", func(t *testing.T) {
		res := e.request("GET", oktaFilterURL(`userName eq "nonexistent-user@example.invalid"`), nil, oktaDefaultHeaders())
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaList](t, res)
		if !slices.Contains(b.Schemas, oktaListSchema) || b.TotalResults == nil || *b.TotalResults != 0 {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("R4 — Required Test: Test invalid User by ID", func(t *testing.T) {
		res := e.request("GET", scimUsersURL+"/00000000000000000000", nil, oktaDefaultHeaders())
		if res.Status != 404 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaError](t, res)
		if b.Detail == "" || !slices.Contains(b.Schemas, oktaErrorSchema) {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("R5 — Required Test: Make sure random user doesn't exist", func(t *testing.T) {
		res := e.request("GET", oktaFilterURL(`userName eq "`+randomUsername+`"`), nil, oktaDefaultHeaders())
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaList](t, res)
		if b.TotalResults == nil || *b.TotalResults != 0 || !slices.Contains(b.Schemas, oktaListSchema) {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("R6 — Required Test: Create Okta user with realistic values", func(t *testing.T) {
		res := e.request("POST", scimUsersURL, map[string]any{
			"schemas":     []string{oktaUserSchema},
			"userName":    randomUsername,
			"name":        map[string]any{"givenName": randomGivenName, "familyName": randomFamilyName},
			"emails":      []any{map[string]any{"primary": true, "value": randomEmail, "type": "work"}},
			"displayName": randomGivenName + " " + randomFamilyName,
			"active":      true,
		}, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + oktaToken,
			"Accept":        "application/scim+json; charset=utf-8",
		})
		if res.Status != 201 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaUser](t, res)
		if !oktaIsTrue(b.Active) || b.ID == "" || b.Name == nil || b.Name.FamilyName != randomFamilyName ||
			b.Name.GivenName != randomGivenName || !slices.Contains(b.Schemas, oktaUserSchema) || b.UserName != randomUsername {
			t.Fatalf("body = %s", res.text())
		}
		idUserOne = b.ID
	})

	t.Run("R7 — Required Test: Verify that user was created", func(t *testing.T) {
		res := e.request("GET", scimUsersURL+"/"+idUserOne, nil, oktaDefaultHeaders())
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaUser](t, res)
		if b.UserName != randomUsername || b.Name == nil || b.Name.FamilyName != randomFamilyName || b.Name.GivenName != randomGivenName {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("R8 — Required Test: Expect failure when recreating user with same values", func(t *testing.T) {
		res := e.request("POST", scimUsersURL, map[string]any{
			"schemas":     []string{oktaUserSchema},
			"userName":    randomUsername,
			"name":        map[string]any{"givenName": randomGivenName, "familyName": randomFamilyName},
			"emails":      []any{map[string]any{"primary": true, "value": randomUsername, "type": "work"}},
			"displayName": randomGivenName + " " + randomFamilyName,
			"active":      true,
		}, map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + oktaToken,
			"Accept":        "application/scim+json; charset=utf-8",
		})
		if res.Status != 409 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
	})

	t.Run("R9 — Required Test: Username Case Sensitivity Check", func(t *testing.T) {
		res := e.request("GET", oktaFilterURL(`userName eq "`+randomUsernameCaps+`"`), nil, oktaDefaultHeaders())
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaList](t, res)
		if b.TotalResults == nil || *b.TotalResults != 1 || len(b.Resources) == 0 || b.Resources[0].UserName != randomUsername {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("R10 — Optional Test: Verify Groups endpoint", func(t *testing.T) {
		res := e.request("GET", scimGroupsURL, nil, oktaDefaultHeaders())
		if res.Status != 200 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		m := res.json()
		resources, isArr := m["Resources"].([]any)
		if m["totalResults"] == float64(0) {
			if !isArr || len(resources) != 0 {
				t.Fatalf("Resources = %#v", m["Resources"])
			}
		} else if !isArr {
			t.Fatalf("Resources not an array: %s", res.text())
		}
	})

	t.Run("R11 — Required Test: Check status 401", func(t *testing.T) {
		res := e.request("GET", oktaFilterURL(`userName eq "`+randomUsernameCaps+`"`), nil, oktaHeaders("non-token"))
		if res.Status != 401 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaError](t, res)
		if b.Detail == "" || b.Status != "401" || !slices.Contains(b.Schemas, oktaErrorSchema) {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("R12 — Required Test: Check status 404", func(t *testing.T) {
		res := e.request("GET", scimUsersURL+"/00919288221112222", nil, oktaDefaultHeaders())
		if res.Status != 404 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaError](t, res)
		if b.Detail == "" || b.Status != "404" || !slices.Contains(b.Schemas, oktaErrorSchema) {
			t.Fatalf("body = %s", res.text())
		}
	})

	t.Run("rejects HTTP Basic credentials (Basic Auth is not a supported scheme)", func(t *testing.T) {
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("okta:okta-conformance-token"))
		res := e.request("GET", scimUsersURL, nil, oktaHeaders(basic))
		if res.Status != 401 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		b := oktaDecode[oktaError](t, res)
		if b.Status != "401" || !slices.Contains(b.Schemas, oktaErrorSchema) {
			t.Fatalf("body = %s", res.text())
		}
	})
}

func TestOktaCRUDNetWireSequence(t *testing.T) {
	// describe("Okta SCIM 2.0 CRUD test net wire sequence")
	t.Run("creates, reads, replaces, deactivates, reactivates, and deactivates a user", func(t *testing.T) {
		e := oktaNewEnv(t)
		h := oktaDefaultHeaders()
		userName := "riley.okta.test@atko.com"

		// 1. POST /Users with an unsolicited password placeholder.
		createRes := e.request("POST", scimUsersURL, map[string]any{
			"schemas":      []string{oktaUserSchema},
			"userName":     userName,
			"name":         map[string]any{"givenName": "Riley", "familyName": "Okta"},
			"emails":       []any{map[string]any{"value": userName, "type": "work", "primary": true}},
			"displayName":  "Riley Okta",
			"title":        "Engineer",
			"phoneNumbers": []any{map[string]any{"value": "415.123.4567"}},
			"password":     "N3verSt0red!",
			"active":       true,
		}, h)
		if createRes.Status != 201 {
			t.Fatalf("create status = %d: %s", createRes.Status, createRes.text())
		}
		createdRaw := createRes.json()
		if _, has := createdRaw["password"]; has {
			t.Fatalf("created has password: %s", createRes.text())
		}
		createdID, _ := createdRaw["id"].(string)

		// 2. Existence check by filter.
		filterRes := e.request("GET", oktaFilterURL(`userName eq "`+userName+`"`), nil, h)
		if filterRes.Status != 200 {
			t.Fatalf("filter status = %d", filterRes.Status)
		}
		filtered := oktaDecode[oktaList](t, filterRes)
		if len(filtered.Resources) != 1 || filtered.Resources[0].ID != createdID {
			t.Fatalf("filtered = %s", filterRes.text())
		}

		// 3. PUT full-resource read-modify-write.
		beforePut := e.request("GET", scimUsersURL+"/"+createdID, nil, h).json()
		name, _ := beforePut["name"].(map[string]any)
		newName := map[string]any{}
		for k, v := range name {
			newName[k] = v
		}
		newName["givenName"] = "Rileyupdate"
		beforePut["name"] = newName
		putRes := e.request("PUT", scimUsersURL+"/"+createdID, beforePut, h)
		if putRes.Status != 200 {
			t.Fatalf("put status = %d: %s", putRes.Status, putRes.text())
		}
		if pb := oktaDecode[oktaUser](t, putRes); pb.Name == nil || pb.Name.GivenName != "Rileyupdate" {
			t.Fatalf("put body = %s", putRes.text())
		}

		patch := func(active bool) *response {
			return e.request("PATCH", scimUsersURL+"/"+createdID, map[string]any{
				"schemas":    []string{oktaPatchSchema},
				"Operations": []any{map[string]any{"op": "replace", "value": map[string]any{"active": active}}},
			}, h)
		}
		// 4. Deactivate.
		r := patch(false)
		if r.Status != 200 || !oktaIsFalse(oktaDecode[oktaUser](t, r).Active) {
			t.Fatalf("deactivate = %d %s", r.Status, r.text())
		}
		// 5. Reactivate.
		r = patch(true)
		if r.Status != 200 || !oktaIsTrue(oktaDecode[oktaUser](t, r).Active) {
			t.Fatalf("reactivate = %d %s", r.Status, r.text())
		}
		// 6. Second deactivate.
		r = patch(false)
		if r.Status != 200 || !oktaIsFalse(oktaDecode[oktaUser](t, r).Active) {
			t.Fatalf("second deactivate = %d %s", r.Status, r.text())
		}
	})
}
