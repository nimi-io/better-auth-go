package scim

// Port of scim-google-conformance.test.ts (Google Workspace/Cloud Identity automated
// provisioning client).

import (
	"encoding/json"
	"net/url"
	"testing"
)

const (
	googleSCIMToken      = "google-conformance-token"
	googleUserSchema     = "urn:ietf:params:scim:schemas:core:2.0:User"
	googlePatchSchema    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	googleSCIMMediaType  = "application/scim+json"
	googleDefaultAuthHdr = "Bearer " + googleSCIMToken
)

func googleHeaders(authorization string) map[string]string {
	return map[string]string{
		"Accept":        googleSCIMMediaType,
		"Authorization": authorization,
		"Content-Type":  googleSCIMMediaType,
	}
}

func googleNewEnv(t *testing.T) *testEnv {
	t.Helper()
	return newEnv(t, Options{Connections: []ConnectionOptions{{
		ID:          "google-conformance",
		Credentials: []BearerCredential{{Type: "bearer", ID: "google-conformance-token", Token: googleSCIMToken}},
	}}}, envOptions{sqlite: true})
}

func googleDecode[T any](t *testing.T, r *response) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatalf("decode %q: %v", r.text(), err)
	}
	return v
}

type googleUser struct {
	ID       string `json:"id"`
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
}

type googleGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

type googleSchemaAttribute struct {
	Name          string                  `json:"name"`
	Type          string                  `json:"type"`
	MultiValued   bool                    `json:"multiValued"`
	Required      bool                    `json:"required"`
	Mutability    string                  `json:"mutability"`
	SubAttributes []googleSchemaAttribute `json:"subAttributes"`
}

func googleHasSub(a googleSchemaAttribute, name string) bool {
	for _, s := range a.SubAttributes {
		if s.Name == name {
			return true
		}
	}
	return false
}

func TestGoogleConformance(t *testing.T) {
	t.Run("R1 — bearer/access token auth, admin-pasted, no OAuth flow", func(t *testing.T) {
		t.Run("accepts the connection's bearer token", func(t *testing.T) {
			e := googleNewEnv(t)
			res := e.request("GET", scimUsersURL, nil, googleHeaders(googleDefaultAuthHdr))
			if res.Status != 200 {
				t.Fatalf("status = %d: %s", res.Status, res.text())
			}
		})

		t.Run("rejects a missing or invalid token with 401", func(t *testing.T) {
			e := googleNewEnv(t)
			missing := e.request("GET", scimUsersURL, nil, googleHeaders(""))
			stale := e.request("GET", scimUsersURL, nil, googleHeaders("Bearer revoked-or-unknown-token"))
			if missing.Status != 401 {
				t.Fatalf("missing status = %d", missing.Status)
			}
			if stale.Status != 401 {
				t.Fatalf("stale status = %d", stale.Status)
			}
			if got := stale.json()["status"]; got != "401" {
				t.Fatalf("stale body status = %#v", got)
			}
		})
	})

	t.Run("R3 — deprovisioning: suspend and hard-delete are independent paths", func(t *testing.T) {
		t.Run("hard-deletes a still-active user with no prior deactivation call", func(t *testing.T) {
			e := googleNewEnv(t)
			created := googleDecode[googleUser](t, e.request("POST", scimUsersURL, map[string]any{
				"schemas":  []string{googleUserSchema},
				"userName": "deleted-from-google@example.com",
				"active":   true,
			}, googleHeaders(googleDefaultAuthHdr)))
			if !created.Active {
				t.Fatalf("created.active = false")
			}
			del := e.request("DELETE", scimUsersURL+"/"+created.ID, nil, googleHeaders(googleDefaultAuthHdr))
			if del.Status != 204 {
				t.Fatalf("delete status = %d: %s", del.Status, del.text())
			}
			after := e.request("GET", scimUsersURL+"/"+created.ID, nil, googleHeaders(googleDefaultAuthHdr))
			if after.Status != 404 {
				t.Fatalf("after delete status = %d", after.Status)
			}
		})

		t.Run("cleans up group membership on a DELETE arriving long after an earlier suspend", func(t *testing.T) {
			e := googleNewEnv(t)
			h := googleHeaders(googleDefaultAuthHdr)
			created := googleDecode[googleUser](t, e.request("POST", scimUsersURL, map[string]any{
				"schemas":  []string{googleUserSchema},
				"userName": "delayed-deprovision@example.com",
				"active":   true,
			}, h))
			group := googleDecode[googleGroup](t, e.request("POST", scimGroupsURL, map[string]any{
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
				"displayName": "Suspended then deleted",
				"members":     []any{map[string]any{"value": created.ID}},
			}, h))

			suspend := e.request("PATCH", scimUsersURL+"/"+created.ID, map[string]any{
				"schemas":    []string{googlePatchSchema},
				"Operations": []any{map[string]any{"op": "replace", "value": map[string]any{"active": false}}},
			}, h)
			if suspend.Status != 200 {
				t.Fatalf("suspend status = %d: %s", suspend.Status, suspend.text())
			}
			del := e.request("DELETE", scimUsersURL+"/"+created.ID, nil, h)
			if del.Status != 204 {
				t.Fatalf("delete status = %d: %s", del.Status, del.text())
			}
			after := e.request("GET", scimUsersURL+"/"+created.ID, nil, h)
			if after.Status != 404 {
				t.Fatalf("after delete status = %d", after.Status)
			}
			gres := e.request("GET", scimGroupsURL+"/"+group.ID, nil, h)
			m := gres.json()
			members, ok := m["members"].([]any)
			if !ok || len(members) != 0 {
				t.Fatalf("group members = %#v (%s)", m["members"], gres.text())
			}
		})
	})

	t.Run("R5 — attribute mapping is built live from the receiving app's discovered schema", func(t *testing.T) {
		t.Run("discovers a complete, accurately-flagged User attribute list", func(t *testing.T) {
			e := googleNewEnv(t)
			res := e.request("GET", "/api/auth/scim/v2/Schemas/"+url.QueryEscape(googleUserSchema), nil, googleHeaders(googleDefaultAuthHdr))
			if res.Status != 200 {
				t.Fatalf("status = %d: %s", res.Status, res.text())
			}
			schema := googleDecode[struct {
				ID         string                  `json:"id"`
				Attributes []googleSchemaAttribute `json:"attributes"`
			}](t, res)
			byName := map[string]googleSchemaAttribute{}
			for _, a := range schema.Attributes {
				byName[a.Name] = a
			}
			userName := byName["userName"]
			if !userName.Required || userName.Type != "string" {
				t.Fatalf("userName = %#v", userName)
			}
			active := byName["active"]
			if active.Type != "boolean" || active.Mutability != "readWrite" {
				t.Fatalf("active = %#v", active)
			}
			emails := byName["emails"]
			if !emails.MultiValued || !googleHasSub(emails, "value") || !googleHasSub(emails, "primary") {
				t.Fatalf("emails = %#v", emails)
			}
			name := byName["name"]
			if name.Type != "complex" || !googleHasSub(name, "givenName") || !googleHasSub(name, "familyName") {
				t.Fatalf("name = %#v", name)
			}
		})
	})
}
