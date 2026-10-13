package scim

// Port of upstream scim-entra-conformance.test.ts
// ("SCIM User PATCH against Microsoft Entra ID attribute mappings").

import (
	"encoding/json"
	"testing"
)

const entraConfToken = "entra-token"

// newEntraConfFixture is createEntraFixture.
func newEntraConfFixture(t *testing.T) *testEnv {
	return newEnv(t, Options{
		Connections: []ConnectionOptions{staticConnection("workforce", entraConfToken)},
		Identity: &Identity{
			ResolveUser: func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
				return &IdentityResolution{Action: "create"}, nil
			},
		},
	})
}

func entraConfDecode(r *response) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}

// entraConfCreateUser is createUser: POST /scim/v2/Users with the core User schema
// prepended to the given JSON members (a "{...}" object without schemas).
func entraConfCreateUser(t *testing.T, e *testEnv, members string) map[string]any {
	t.Helper()
	body := entUserJ(`{"schemas":["%CORE%"],` + members[1:])
	res := e.scim("POST", scimUsersURL, entraConfToken, body)
	if res.Status != 201 {
		t.Fatalf("create: status %d, body %s", res.Status, res.text())
	}
	return entraConfDecode(res)
}

// entraConfPatchUser is patchUser.
func entraConfPatchUser(t *testing.T, e *testEnv, id, operations string) (*response, map[string]any) {
	t.Helper()
	res := e.scim("PATCH", scimUsersURL+"/"+entUserEnc(id), entraConfToken,
		entUserJ(`{"schemas":["%PATCH%"],"Operations":`+operations+`}`))
	return res, entraConfDecode(res)
}

func entraConfExpectStatus(t *testing.T, res *response, status int) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("status = %d, want %d; body %s", res.Status, status, res.text())
	}
}

func TestEntraConf_UserPatchAttributeMappings(t *testing.T) {
	t.Run("creates a filtered phone number and keeps the operations bundled with it", func(t *testing.T) {
		e := newEntraConfFixture(t)
		user := entraConfCreateUser(t, e, `{"userName":"bundled-phone@example.com","name":{"givenName":"Ada","familyName":"Lovelace"}}`)
		res, patched := entraConfPatchUser(t, e, entUserStr(user["id"]), `[
			{"op": "Replace", "path": "phoneNumbers[type eq \"work\"].value", "value": "+1-555-0100"},
			{"op": "Replace", "path": "name.familyName", "value": "King"}
		]`)
		entraConfExpectStatus(t, res, 200)
		entUserEqual(t, "phoneNumbers", patched["phoneNumbers"], `[{"value":"+1-555-0100","type":"work"}]`)
		if got := entUserGet(patched, "name", "familyName"); got != "King" {
			t.Fatalf("name.familyName = %v, want King", got)
		}
	})

	t.Run("creates a filtered address sub-attribute", func(t *testing.T) {
		e := newEntraConfFixture(t)
		user := entraConfCreateUser(t, e, `{"userName":"missing-address@example.com"}`)
		res, patched := entraConfPatchUser(t, e, entUserStr(user["id"]), `[
			{"op": "Replace", "path": "addresses[type eq \"work\"].postalCode", "value": "94105"}
		]`)
		entraConfExpectStatus(t, res, 200)
		entUserEqual(t, "addresses", patched["addresses"], `[{"type":"work","postalCode":"94105"}]`)
	})

	t.Run("creates filtered roles and entitlements", func(t *testing.T) {
		e := newEntraConfFixture(t)
		user := entraConfCreateUser(t, e, `{"userName":"missing-role@example.com"}`)
		res, patched := entraConfPatchUser(t, e, entUserStr(user["id"]), `[
			{"op": "Replace", "path": "roles[type eq \"work\"].value", "value": "engineer"},
			{"op": "Replace", "path": "entitlements[type eq \"work\"].value", "value": "vpn"}
		]`)
		entraConfExpectStatus(t, res, 200)
		entUserEqual(t, "roles", patched["roles"], `[{"value":"engineer","type":"work"}]`)
		entUserEqual(t, "entitlements", patched["entitlements"], `[{"value":"vpn","type":"work"}]`)
	})

	t.Run("creates a filtered email without moving the primary address", func(t *testing.T) {
		e := newEntraConfFixture(t)
		user := entraConfCreateUser(t, e, `{"userName":"primary-email@example.com","emails":[{"value":"primary-email@example.com","type":"work","primary":true}]}`)
		res, patched := entraConfPatchUser(t, e, entUserStr(user["id"]), `[
			{"op": "Replace", "path": "emails[type eq \"other\"].value", "value": "other-email@example.com"}
		]`)
		entraConfExpectStatus(t, res, 200)
		entUserEqual(t, "emails", patched["emails"], `[
			{"value":"primary-email@example.com","type":"work","primary":true},
			{"value":"other-email@example.com","type":"other","primary":false}
		]`)
	})

	t.Run("creates a single primary value for a quoted primary filter", func(t *testing.T) {
		e := newEntraConfFixture(t)
		user := entraConfCreateUser(t, e, `{"userName":"quoted-primary@example.com","roles":[{"value":"engineer","primary":false}]}`)
		res, patched := entraConfPatchUser(t, e, entUserStr(user["id"]), `[
			{"op": "Replace", "path": "roles[primary eq \"true\"].value", "value": "senior-engineer"}
		]`)
		entraConfExpectStatus(t, res, 200)
		entUserEqual(t, "roles", patched["roles"], `[{"value":"engineer","primary":false},{"value":"senior-engineer","primary":true}]`)
		primaries := 0
		roles, _ := patched["roles"].([]any)
		for _, r := range roles {
			if entUserGet(r, "primary") == true {
				primaries++
			}
		}
		if primaries != 1 {
			t.Fatalf("primary roles = %d, want 1", primaries)
		}
	})

	t.Run("updates a populated filtered phone number in place", func(t *testing.T) {
		e := newEntraConfFixture(t)
		user := entraConfCreateUser(t, e, `{"userName":"populated-phone@example.com","phoneNumbers":[{"value":"+1-555-0100","type":"work"}]}`)
		res, patched := entraConfPatchUser(t, e, entUserStr(user["id"]), `[
			{"op": "Replace", "path": "phoneNumbers[type eq \"work\"].value", "value": "+1-555-0199"}
		]`)
		entraConfExpectStatus(t, res, 200)
		entUserEqual(t, "phoneNumbers", patched["phoneNumbers"], `[{"value":"+1-555-0199","type":"work"}]`)
	})

	t.Run("rejects a remove operation without a path", func(t *testing.T) {
		e := newEntraConfFixture(t)
		user := entraConfCreateUser(t, e, `{"userName":"pathless-remove@example.com"}`)
		res, body := entraConfPatchUser(t, e, entUserStr(user["id"]), `[
			{"op": "Remove", "value": {"displayName": "Ada"}}
		]`)
		entraConfExpectStatus(t, res, 400)
		if body["scimType"] != "noTarget" {
			t.Fatalf("scimType = %v, want noTarget", body["scimType"])
		}
	})
}
