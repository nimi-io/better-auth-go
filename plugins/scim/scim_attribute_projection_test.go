package scim

// Port of upstream scim-attribute-projection.test.ts
// ("SCIM core-schema-qualified attribute projection").

import (
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

type apFixture struct {
	e       *testEnv
	headers map[string][]string
	user    map[string]any
	group   map[string]any
}

func apNewFixture(t *testing.T) *apFixture {
	t.Helper()
	e := newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")}})
	return &apFixture{e: e, headers: bearer("test-scim-token")}
}

func apCreateUserAndGroup(t *testing.T) *apFixture {
	t.Helper()
	f := apNewFixture(t)
	f.user = f.e.mustCall("createSCIMUser", betterauth.CallInput{Headers: f.headers, Body: map[string]any{
		"schemas":     []any{SchemaUser},
		"userName":    "ada@example.com",
		"displayName": "Ada Lovelace",
		"name":        map[string]any{"givenName": "Ada", "familyName": "Lovelace"},
	}})
	f.group = f.e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: f.headers, Body: map[string]any{
		"schemas":     []any{SchemaGroup},
		"displayName": "Engineering",
		"members":     []any{map[string]any{"value": f.user["id"]}},
	}})
	return f
}

func apString(v any) string { s, _ := v.(string); return s }

func TestAttributeProjection_CoreSchemaQualified(t *testing.T) {
	t.Run("projects included and excluded User attributes on an item", func(t *testing.T) {
		f := apCreateUserAndGroup(t)
		id := apString(f.user["id"])
		included := f.e.mustCall("getSCIMUser", betterauth.CallInput{Headers: f.headers, Params: map[string]string{"userId": id},
			Query: map[string]any{"attributes": SchemaUser + ":userName," + SchemaUser + ":name.givenName"}})
		excluded := f.e.mustCall("getSCIMUser", betterauth.CallInput{Headers: f.headers, Params: map[string]string{"userId": id},
			Query: map[string]any{"excludedAttributes": SchemaUser + ":displayName," + SchemaUser + ":name.familyName"}})
		rapEqual(t, included, map[string]any{"schemas": []any{SchemaUser}, "id": id, "userName": "ada@example.com", "name": map[string]any{"givenName": "Ada"}})
		if _, ok := excluded["displayName"]; ok {
			t.Fatal("displayName not excluded")
		}
		name, _ := excluded["name"].(map[string]any)
		if _, ok := name["familyName"]; ok {
			t.Fatal("name.familyName not excluded")
		}
		rapMatchObject(t, name, `{"givenName":"Ada"}`)
	})

	t.Run("projects included and excluded User attributes in a collection", func(t *testing.T) {
		f := apCreateUserAndGroup(t)
		included := f.e.mustCall("listSCIMUsers", betterauth.CallInput{Headers: f.headers, Query: map[string]any{"attributes": SchemaUser + ":displayName"}})
		excluded := f.e.mustCall("listSCIMUsers", betterauth.CallInput{Headers: f.headers, Query: map[string]any{"excludedAttributes": SchemaUser + ":name"}})
		rapEqual(t, included["Resources"], []any{map[string]any{"schemas": []any{SchemaUser}, "id": f.user["id"], "displayName": "Ada Lovelace"}})
		first := excluded["Resources"].([]any)[0].(map[string]any)
		if _, ok := first["name"]; ok {
			t.Fatal("name not excluded")
		}
		rapMatchObject(t, first, map[string]any{"id": f.user["id"], "userName": "ada@example.com", "displayName": "Ada Lovelace"})
	})

	t.Run("projects included and excluded Group attributes on an item", func(t *testing.T) {
		f := apCreateUserAndGroup(t)
		gid := apString(f.group["id"])
		included := f.e.mustCall("getSCIMGroup", betterauth.CallInput{Headers: f.headers, Params: map[string]string{"groupId": gid},
			Query: map[string]any{"attributes": SchemaGroup + ":displayName," + SchemaGroup + ":members.value"}})
		excluded := f.e.mustCall("getSCIMGroup", betterauth.CallInput{Headers: f.headers, Params: map[string]string{"groupId": gid},
			Query: map[string]any{"excludedAttributes": SchemaGroup + ":members"}})
		rapEqual(t, included, map[string]any{"schemas": []any{SchemaGroup}, "id": gid, "displayName": "Engineering",
			"members": []any{map[string]any{"value": f.user["id"]}}})
		if _, ok := excluded["members"]; ok {
			t.Fatal("members not excluded")
		}
		if excluded["displayName"] != "Engineering" {
			t.Fatalf("displayName = %v", excluded["displayName"])
		}
	})

	t.Run("projects included and excluded Group attributes in a collection", func(t *testing.T) {
		f := apCreateUserAndGroup(t)
		included := f.e.mustCall("listSCIMGroups", betterauth.CallInput{Headers: f.headers, Query: map[string]any{"attributes": SchemaGroup + ":members.value"}})
		excluded := f.e.mustCall("listSCIMGroups", betterauth.CallInput{Headers: f.headers, Query: map[string]any{"excludedAttributes": SchemaGroup + ":displayName"}})
		rapEqual(t, included["Resources"], []any{map[string]any{"schemas": []any{SchemaGroup}, "id": f.group["id"],
			"members": []any{map[string]any{"value": f.user["id"]}}}})
		first := excluded["Resources"].([]any)[0].(map[string]any)
		if _, ok := first["displayName"]; ok {
			t.Fatal("displayName not excluded")
		}
		members, _ := first["members"].([]any)
		if len(members) != 1 {
			t.Fatalf("members = %v", first["members"])
		}
		rapMatchObject(t, members[0], map[string]any{"value": f.user["id"]})
	})

	t.Run("projects Group creation and replacement responses", func(t *testing.T) {
		f := apNewFixture(t)
		user := f.e.mustCall("createSCIMUser", betterauth.CallInput{Headers: f.headers, Body: map[string]any{"schemas": []any{SchemaUser}, "userName": "ada@example.com"}})
		created := f.e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: f.headers, Query: map[string]any{"attributes": "displayName"}, Body: map[string]any{
			"schemas": []any{SchemaGroup}, "displayName": "Engineering", "members": []any{map[string]any{"value": user["id"]}},
		}})
		replaced := f.e.mustCall("replaceSCIMGroup", betterauth.CallInput{Headers: f.headers, Params: map[string]string{"groupId": apString(created["id"])},
			Query: map[string]any{"excludedAttributes": "members"}, Body: map[string]any{
				"schemas": []any{SchemaGroup}, "displayName": "Platform Engineering", "members": []any{map[string]any{"value": user["id"]}},
			}})
		rapEqual(t, created, map[string]any{"schemas": []any{SchemaGroup}, "id": created["id"], "displayName": "Engineering"})
		rapMatchObject(t, replaced, map[string]any{"schemas": []any{SchemaGroup}, "id": created["id"], "displayName": "Platform Engineering"})
		if _, ok := replaced["members"]; ok {
			t.Fatal("members not excluded")
		}
	})

	t.Run("returns projected resources when PATCH requests response attributes", func(t *testing.T) {
		f := apCreateUserAndGroup(t)
		uid, gid := apString(f.user["id"]), apString(f.group["id"])
		h := map[string]string{"Authorization": "Bearer test-scim-token", "Content-Type": MediaType}
		patch := func(value string) map[string]any {
			return map[string]any{"schemas": []any{SchemaPatchOp}, "Operations": []any{
				map[string]any{"op": "replace", "path": "displayName", "value": value},
			}}
		}
		userRes := f.e.request("PATCH", scimUsersURL+"/"+uid+"?attributes=displayName", patch("Augusta Ada King"), h)
		groupRes := f.e.request("PATCH", scimGroupsURL+"/"+gid+"?excludedAttributes=members", patch("Platform Engineering"), h)

		if userRes.Status != 200 {
			t.Fatalf("user status = %d %s", userRes.Status, userRes.text())
		}
		if !strings.Contains(userRes.Header.Get("Location"), "/Users/"+uid) {
			t.Fatalf("user location = %q", userRes.Header.Get("Location"))
		}
		rapEqual(t, userRes.json(), map[string]any{"schemas": []any{SchemaUser}, "id": uid, "displayName": "Augusta Ada King"})
		if groupRes.Status != 200 {
			t.Fatalf("group status = %d %s", groupRes.Status, groupRes.text())
		}
		if !strings.Contains(groupRes.Header.Get("Location"), "/Groups/"+gid) {
			t.Fatalf("group location = %q", groupRes.Header.Get("Location"))
		}
		groupBody := groupRes.json()
		rapMatchObject(t, groupBody, map[string]any{"schemas": []any{SchemaGroup}, "id": gid, "displayName": "Platform Engineering"})
		if _, ok := groupBody["members"]; ok {
			t.Fatal("members not excluded")
		}
	})
}
