package scim

// Port of upstream scim-groups-v2.test.ts ("SCIM connection-owned Groups").

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

const (
	gv2Token        = "test-scim-token"
	gv2TokenA       = "connection-a-token"
	gv2TokenB       = "connection-b-token"
	gv2UserSchema   = "urn:ietf:params:scim:schemas:core:2.0:User"
	gv2GroupSchema  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	gv2PatchSchema  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	gv2ErrorSchema  = "urn:ietf:params:scim:api:messages:2.0:Error"
	gv2ListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
)

// gv2Env is an instance with the single "workforce" connection.
func gv2Env(t *testing.T) *testEnv {
	t.Helper()
	return newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("workforce", gv2Token)}})
}

// gv2TwoConnectionEnv has connections "workforce-a" and "workforce-b".
func gv2TwoConnectionEnv(t *testing.T) *testEnv {
	t.Helper()
	return newEnv(t, Options{Connections: []ConnectionOptions{
		staticConnection("workforce-a", gv2TokenA),
		staticConnection("workforce-b", gv2TokenB),
	}})
}

func gv2Call(e *testEnv, key, token string, in betterauth.CallInput) map[string]any {
	e.t.Helper()
	in.Headers = bearer(token)
	return e.mustCall(key, in)
}

func gv2CallErr(e *testEnv, key, token string, in betterauth.CallInput) *betterauth.APIError {
	e.t.Helper()
	in.Headers = bearer(token)
	_, ae := e.call(key, in)
	if ae == nil {
		e.t.Fatalf("%s: expected an error", key)
	}
	return ae
}

func gv2CreateUser(e *testEnv, token string, body map[string]any) map[string]any {
	e.t.Helper()
	body["schemas"] = []any{gv2UserSchema}
	return gv2Call(e, "createSCIMUser", token, betterauth.CallInput{Body: body})
}

func gv2CreateGroup(e *testEnv, token string, body map[string]any) map[string]any {
	e.t.Helper()
	body["schemas"] = []any{gv2GroupSchema}
	return gv2Call(e, "createSCIMGroup", token, betterauth.CallInput{Body: body})
}

func gv2GetGroup(e *testEnv, token, id string) map[string]any {
	e.t.Helper()
	return gv2Call(e, "getSCIMGroup", token, betterauth.CallInput{Params: map[string]string{"groupId": id}})
}

func gv2PatchGroup(e *testEnv, token, id string, ops ...any) map[string]any {
	e.t.Helper()
	if ops == nil {
		ops = []any{}
	}
	return gv2Call(e, "patchSCIMGroup", token, betterauth.CallInput{
		Params: map[string]string{"groupId": id},
		Body:   map[string]any{"schemas": []any{gv2PatchSchema}, "Operations": ops},
	})
}

func gv2Members(id ...string) []any {
	out := []any{}
	for _, v := range id {
		out = append(out, map[string]any{"value": v})
	}
	return out
}

func gv2Where(rows []adapter.Record, field string, value any) []adapter.Record {
	var out []adapter.Record
	for _, r := range rows {
		if fmt.Sprint(r[field]) == fmt.Sprint(value) {
			out = append(out, r)
		}
	}
	return out
}

func gv2Find(rows []adapter.Record, field string, value any) adapter.Record {
	if m := gv2Where(rows, field, value); len(m) > 0 {
		return m[0]
	}
	return nil
}

func gv2Strings(rows []adapter.Record, field string) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, fmt.Sprint(r[field]))
	}
	return out
}

func gv2Num(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case int32:
		return float64(n)
	}
	return -1
}

func gv2Time(t *testing.T, v any) time.Time {
	t.Helper()
	switch x := v.(type) {
	case time.Time:
		return x
	case string:
		p, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			t.Fatalf("parse time %q: %v", x, err)
		}
		return p
	}
	t.Fatalf("not a time: %#v", v)
	return time.Time{}
}

func gv2ResourceIDs(list map[string]any) []string {
	out := []string{}
	res, _ := list["Resources"].([]any)
	for _, r := range res {
		out = append(out, fmt.Sprint(r.(map[string]any)["id"]))
	}
	return out
}

func gv2MemberValues(group map[string]any) []string {
	out := []string{}
	ms, _ := group["members"].([]any)
	for _, m := range ms {
		out = append(out, fmt.Sprint(m.(map[string]any)["value"]))
	}
	return out
}

func gv2SortedEqual(a, b []string) bool {
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(x, y)
}

func gv2ExpectEmpty(t *testing.T, e *testEnv, models ...string) {
	t.Helper()
	for _, m := range models {
		if rows := e.rows(m); len(rows) != 0 {
			t.Fatalf("%s rows = %v, want none", m, rows)
		}
	}
}

func TestScimGroupsV2(t *testing.T) {
	t.Run("creates a Group whose membership references a SCIM User resource", func(t *testing.T) {
		e := gv2Env(t)
		createdUser := gv2CreateUser(e, gv2Token, map[string]any{
			"userName": "ada@example.com",
			"name":     map[string]any{"formatted": "Ada Lovelace"},
		})
		userID := createdUser["id"].(string)
		userLink := gv2Find(e.rows("scimUser"), "id", userID)
		if userLink == nil {
			t.Fatal("Expected a SCIM User link")
		}
		createdGroup := gv2CreateGroup(e, gv2Token, map[string]any{
			"externalId":  "directory-engineering",
			"displayName": "Engineering",
			"members":     gv2Members(userID),
		})
		groupID := createdGroup["id"].(string)
		retrieved := gv2GetGroup(e, gv2Token, groupID)
		groupRow := gv2Find(e.rows("scimGroup"), "id", groupID)
		membership := gv2Find(e.rows("scimGroupMember"), "groupId", groupID)

		if groupID == "directory-engineering" {
			t.Fatal("group id must not be the externalId")
		}
		if groupRow == nil || groupRow["connectionId"] != "workforce" || groupRow["externalId"] != "directory-engineering" ||
			groupRow["displayName"] != "Engineering" {
			t.Fatalf("group row = %v", groupRow)
		}
		if membership == nil || membership["scimUserId"] != userID {
			t.Fatalf("membership = %v", membership)
		}
		if membership["scimUserId"] == userLink["userId"] {
			t.Fatal("membership must reference the SCIM User, not the auth user")
		}
		if _, ok := membership["userId"]; ok {
			t.Fatalf("membership has userId: %v", membership)
		}
		members, _ := retrieved["members"].([]any)
		if len(members) != 1 {
			t.Fatalf("members = %v", retrieved["members"])
		}
		m := members[0].(map[string]any)
		ref, _ := m["$ref"].(string)
		if m["value"] != userID || !strings.Contains(ref, "/scim/v2/Users/"+url.PathEscape(userID)) ||
			m["display"] != "Ada Lovelace" || m["type"] != "User" {
			t.Fatalf("member = %v", m)
		}
		gv2ExpectEmpty(t, e, "account", "scimProjectionGrant")
	})

	t.Run("advances Group metadata when User deletion removes membership", func(t *testing.T) {
		e := gv2Env(t)
		user := gv2CreateUser(e, gv2Token, map[string]any{"userName": "deleted-member@example.com"})
		userID := user["id"].(string)
		group := gv2CreateGroup(e, gv2Token, map[string]any{"displayName": "Deletion metadata", "members": gv2Members(userID)})
		groupID := group["id"].(string)
		persisted := gv2Find(e.rows("scimGroup"), "id", groupID)
		if persisted == nil {
			t.Fatal("Expected a SCIM Group row")
		}
		previousRevision := gv2Num(persisted["revision"])
		if _, err := e.db().Update(context.Background(), "scimGroup", []adapter.Where{{Field: "id", Value: groupID}},
			adapter.Record{"updatedAt": time.UnixMilli(0).UTC()}); err != nil {
			t.Fatal(err)
		}

		gv2Call(e, "deleteSCIMUser", gv2Token, betterauth.CallInput{Params: map[string]string{"userId": userID}})

		retrieved := gv2GetGroup(e, gv2Token, groupID)
		updated := gv2Find(e.rows("scimGroup"), "id", groupID)
		meta, _ := retrieved["meta"].(map[string]any)
		if meta == nil || meta["lastModified"] == nil {
			t.Fatal("Expected SCIM Group last-modified metadata")
		}
		if ms, _ := retrieved["members"].([]any); ms == nil || len(ms) != 0 {
			t.Fatalf("members = %#v, want []", retrieved["members"])
		}
		if gv2Time(t, meta["lastModified"]).UnixMilli() <= 0 {
			t.Fatalf("lastModified = %v", meta["lastModified"])
		}
		if gv2Num(updated["revision"]) != previousRevision+1 {
			t.Fatalf("revision = %v, want %v", updated["revision"], previousRevision+1)
		}
	})

	t.Run("lists only Groups owned by the authenticated connection", func(t *testing.T) {
		e := gv2TwoConnectionEnv(t)
		a := gv2CreateGroup(e, gv2TokenA, map[string]any{"displayName": "Engineering A", "members": []any{}})
		b := gv2CreateGroup(e, gv2TokenB, map[string]any{"displayName": "Engineering B", "members": []any{}})

		listed := gv2Call(e, "listSCIMGroups", gv2TokenA, betterauth.CallInput{})

		if !reflect.DeepEqual(listed["schemas"], []any{gv2ListResponse}) || gv2Num(listed["totalResults"]) != 1 {
			t.Fatalf("listed = %v", listed)
		}
		ids := gv2ResourceIDs(listed)
		if !reflect.DeepEqual(ids, []string{a["id"].(string)}) {
			t.Fatalf("ids = %v", ids)
		}
		for _, id := range ids {
			if id == b["id"] {
				t.Fatal("listed a Group of another connection")
			}
		}
	})

	t.Run("rejects a cross-connection Group member add atomically", func(t *testing.T) {
		e := gv2TwoConnectionEnv(t)
		memberA := gv2CreateUser(e, gv2TokenA, map[string]any{"userName": "member-a@example.com"})
		memberB := gv2CreateUser(e, gv2TokenB, map[string]any{"userName": "member-b@example.com"})
		group := gv2CreateGroup(e, gv2TokenA, map[string]any{"displayName": "Engineering A", "members": gv2Members(memberA["id"].(string))})
		groupID := group["id"].(string)
		membershipsBefore := gv2Where(e.rows("scimGroupMember"), "groupId", groupID)
		before := gv2Find(e.rows("scimGroup"), "id", groupID)
		if before == nil {
			t.Fatal("Expected connection A Group")
		}
		stateBefore := []any{before["displayName"], gv2Num(before["revision"]), gv2Time(t, before["updatedAt"]).UnixMilli()}

		res := e.request("PATCH", scimGroupsURL+"/"+url.PathEscape(groupID), map[string]any{
			"schemas": []any{gv2PatchSchema},
			"Operations": []any{
				map[string]any{"op": "replace", "path": "displayName", "value": "Must not persist"},
				map[string]any{"op": "add", "path": "members", "value": gv2Members(memberB["id"].(string))},
			},
		}, map[string]string{"Authorization": "Bearer " + gv2TokenA, "Content-Type": "application/scim+json"})

		if res.Status != 400 {
			t.Fatalf("status = %d %s", res.Status, res.text())
		}
		body := res.json()
		if !reflect.DeepEqual(body["schemas"], []any{gv2ErrorSchema}) || body["status"] != "400" || body["scimType"] != "invalidValue" {
			t.Fatalf("body = %v", body)
		}
		if after := gv2Where(e.rows("scimGroupMember"), "groupId", groupID); !reflect.DeepEqual(after, membershipsBefore) {
			t.Fatalf("memberships = %v, want %v", after, membershipsBefore)
		}
		after := gv2Find(e.rows("scimGroup"), "id", groupID)
		if after == nil {
			t.Fatal("Expected connection A Group after PATCH")
		}
		stateAfter := []any{after["displayName"], gv2Num(after["revision"]), gv2Time(t, after["updatedAt"]).UnixMilli()}
		if !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatalf("group state = %v, want %v", stateAfter, stateBefore)
		}
	})

	t.Run("replaces a Group and its connection-owned membership set", func(t *testing.T) {
		e := gv2Env(t)
		memberA := gv2CreateUser(e, gv2Token, map[string]any{"userName": "ada@example.com"})
		memberB := gv2CreateUser(e, gv2Token, map[string]any{"userName": "grace@example.com"})
		created := gv2CreateGroup(e, gv2Token, map[string]any{
			"externalId": "directory-engineering", "displayName": "Engineering", "members": gv2Members(memberA["id"].(string)),
		})
		groupID := created["id"].(string)

		replaced := gv2Call(e, "replaceSCIMGroup", gv2Token, betterauth.CallInput{
			Params: map[string]string{"groupId": groupID},
			Body: map[string]any{"schemas": []any{gv2GroupSchema}, "displayName": "Product Engineering",
				"members": gv2Members(memberB["id"].(string))},
		})
		retrieved := gv2GetGroup(e, gv2Token, groupID)
		groupRow := gv2Find(e.rows("scimGroup"), "id", groupID)
		memberships := gv2Where(e.rows("scimGroupMember"), "groupId", groupID)

		if replaced["id"] != groupID {
			t.Fatalf("replaced id = %v", replaced["id"])
		}
		if _, ok := replaced["externalId"]; ok {
			t.Fatalf("replaced has externalId: %v", replaced)
		}
		if groupRow == nil || groupRow["connectionId"] != "workforce" || groupRow["displayName"] != "Product Engineering" {
			t.Fatalf("group row = %v", groupRow)
		}
		if groupRow["externalId"] != nil {
			t.Fatalf("externalId = %v, want null", groupRow["externalId"])
		}
		if len(memberships) != 1 || memberships[0]["scimUserId"] != memberB["id"] {
			t.Fatalf("memberships = %v", memberships)
		}
		if !reflect.DeepEqual(retrieved, replaced) {
			t.Fatalf("retrieved = %v\nreplaced = %v", retrieved, replaced)
		}
		gv2ExpectEmpty(t, e, "scimProjectionGrant")
	})

	t.Run("deletes a Group without deleting its provisioned User or policy state", func(t *testing.T) {
		e := gv2Env(t)
		createdUser := gv2CreateUser(e, gv2Token, map[string]any{"userName": "ada@example.com"})
		userID := createdUser["id"].(string)
		userLink := gv2Find(e.rows("scimUser"), "id", userID)
		if userLink == nil {
			t.Fatal("Expected a SCIM User link")
		}
		group := gv2CreateGroup(e, gv2Token, map[string]any{"displayName": "Engineering", "members": gv2Members(userID)})
		groupID := group["id"].(string)
		accountsBefore := e.rows("account")
		policyBefore := e.rows("scimProjectionGrant")

		gv2Call(e, "deleteSCIMGroup", gv2Token, betterauth.CallInput{Params: map[string]string{"groupId": groupID}})

		if gv2Find(e.rows("scimGroup"), "id", groupID) != nil {
			t.Fatal("group row still present")
		}
		if gv2Find(e.rows("scimGroupMember"), "groupId", groupID) != nil {
			t.Fatal("membership rows still present")
		}
		link := gv2Find(e.rows("scimUser"), "id", userID)
		if link == nil || link["userId"] != userLink["userId"] {
			t.Fatalf("scimUser = %v", link)
		}
		if gv2Find(e.rows("user"), "id", userLink["userId"]) == nil {
			t.Fatal("auth user deleted")
		}
		ae := gv2CallErr(e, "getSCIMGroup", gv2Token, betterauth.CallInput{Params: map[string]string{"groupId": groupID}})
		wantBody := map[string]any{"detail": "SCIM Group not found", "schemas": []any{gv2ErrorSchema}, "status": "404"}
		if got := errBody(ae); !reflect.DeepEqual(got, wantBody) {
			t.Fatalf("body = %v, want %v", got, wantBody)
		}
		if got := e.rows("scimProjectionGrant"); len(got) != len(policyBefore) {
			t.Fatalf("projection grants = %v, want %v", got, policyBefore)
		}
		if got := e.rows("account"); !reflect.DeepEqual(got, accountsBefore) {
			t.Fatalf("accounts = %v, want %v", got, accountsBefore)
		}
		// Upstream: rejects.toThrowError(objectContaining({ message: "SCIM Group not found" })).
		// Go's APIError.Error() reads body.message (core), so the detail carries the message.
		if d := getStr(ae.Body, "detail"); d != "SCIM Group not found" {
			t.Fatalf("detail = %q", d)
		}
	})

	t.Run("applies ordered Okta-style Group membership PATCH operations", func(t *testing.T) {
		e := gv2Env(t)
		memberA := gv2CreateUser(e, gv2Token, map[string]any{"userName": "ada@example.com"})["id"].(string)
		memberB := gv2CreateUser(e, gv2Token, map[string]any{"userName": "grace@example.com"})["id"].(string)
		groupID := gv2CreateGroup(e, gv2Token, map[string]any{"displayName": "Engineering", "members": gv2Members(memberA)})["id"].(string)

		gv2PatchGroup(e, gv2Token, groupID,
			map[string]any{"op": "replace", "path": gv2GroupSchema + ":displayName", "value": "Qualified Engineering"},
			map[string]any{"op": "add", "path": gv2GroupSchema + ":members", "value": gv2Members(memberB)},
		)
		afterAdd := gv2GetGroup(e, gv2Token, groupID)
		membershipsAfterAdd := gv2Strings(gv2Where(e.rows("scimGroupMember"), "groupId", groupID), "scimUserId")

		gv2PatchGroup(e, gv2Token, groupID,
			map[string]any{"op": "remove", "path": fmt.Sprintf(`%s:members[value eq "%s"]`, gv2GroupSchema, memberA)},
		)
		afterRemove := gv2GetGroup(e, gv2Token, groupID)
		membershipsAfterRemove := gv2Strings(gv2Where(e.rows("scimGroupMember"), "groupId", groupID), "scimUserId")
		if afterAdd["members"] == nil || afterRemove["members"] == nil {
			t.Fatal("Expected Group members in the default representation")
		}

		if v := gv2MemberValues(afterAdd); !gv2SortedEqual(v, []string{memberA, memberB}) {
			t.Fatalf("afterAdd members = %v", v)
		}
		if afterAdd["displayName"] != "Qualified Engineering" {
			t.Fatalf("displayName = %v", afterAdd["displayName"])
		}
		if !gv2SortedEqual(membershipsAfterAdd, []string{memberA, memberB}) {
			t.Fatalf("memberships after add = %v", membershipsAfterAdd)
		}
		if v := gv2MemberValues(afterRemove); !reflect.DeepEqual(v, []string{memberB}) {
			t.Fatalf("afterRemove members = %v", v)
		}
		if afterRemove["displayName"] != "Qualified Engineering" {
			t.Fatalf("displayName = %v", afterRemove["displayName"])
		}
		if !reflect.DeepEqual(membershipsAfterRemove, []string{memberB}) {
			t.Fatalf("memberships after remove = %v", membershipsAfterRemove)
		}
	})

	t.Run("removes Entra-style Group members from a value list", func(t *testing.T) {
		e := gv2Env(t)
		memberA := gv2CreateUser(e, gv2Token, map[string]any{"userName": "ada@example.com"})["id"].(string)
		memberB := gv2CreateUser(e, gv2Token, map[string]any{"userName": "grace@example.com"})["id"].(string)
		groupID := gv2CreateGroup(e, gv2Token, map[string]any{"displayName": "Engineering", "members": gv2Members(memberA, memberB)})["id"].(string)

		gv2PatchGroup(e, gv2Token, groupID, map[string]any{"op": "remove", "path": "members", "value": gv2Members(memberA)})
		afterRemove := gv2GetGroup(e, gv2Token, groupID)
		memberships := gv2Strings(gv2Where(e.rows("scimGroupMember"), "groupId", groupID), "scimUserId")
		if afterRemove["members"] == nil {
			t.Fatal("Expected Group members in the default representation")
		}
		if v := gv2MemberValues(afterRemove); !reflect.DeepEqual(v, []string{memberB}) {
			t.Fatalf("members = %v", v)
		}
		if !reflect.DeepEqual(memberships, []string{memberB}) {
			t.Fatalf("memberships = %v", memberships)
		}
	})

	t.Run("patches Group attributes without conflating them with membership policy", func(t *testing.T) {
		e := gv2Env(t)
		groupID := gv2CreateGroup(e, gv2Token, map[string]any{"externalId": "directory-engineering", "displayName": "Engineering"})["id"].(string)

		gv2PatchGroup(e, gv2Token, groupID,
			map[string]any{"op": "replace", "value": map[string]any{"id": groupID, "displayName": "Platform"}},
			map[string]any{"op": "remove", "path": "externalId"},
		)
		patched := gv2GetGroup(e, gv2Token, groupID)
		groupRow := gv2Find(e.rows("scimGroup"), "id", groupID)

		if patched["id"] != groupID || patched["displayName"] != "Platform" {
			t.Fatalf("patched = %v", patched)
		}
		if ms, ok := patched["members"].([]any); !ok || len(ms) != 0 {
			t.Fatalf("members = %#v, want []", patched["members"])
		}
		if _, ok := patched["externalId"]; ok {
			t.Fatalf("patched has externalId: %v", patched)
		}
		if groupRow == nil || groupRow["displayName"] != "Platform" {
			t.Fatalf("group row = %v", groupRow)
		}
		if groupRow["externalId"] != nil {
			t.Fatalf("externalId = %v, want null", groupRow["externalId"])
		}
		gv2ExpectEmpty(t, e, "scimProjectionGrant")
	})

	// @see https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups
	t.Run("applies Microsoft Entra's array-wrapped Group Replace Attributes PATCH", func(t *testing.T) {
		e := gv2Env(t)
		groupID := gv2CreateGroup(e, gv2Token, map[string]any{"externalId": "directory-engineering", "displayName": "Engineering"})["id"].(string)

		gv2PatchGroup(e, gv2Token, groupID,
			map[string]any{"op": "Replace", "path": "displayName", "value": []any{"Platform"}},
			map[string]any{"op": "Replace", "path": "externalId", "value": []any{"directory-platform"}},
		)
		patched := gv2GetGroup(e, gv2Token, groupID)
		if patched["id"] != groupID || patched["displayName"] != "Platform" || patched["externalId"] != "directory-platform" {
			t.Fatalf("patched = %v", patched)
		}
	})

	// @see https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups
	t.Run("accepts an empty Operations array as a no-op Group PATCH", func(t *testing.T) {
		e := gv2Env(t)
		groupID := gv2CreateGroup(e, gv2Token, map[string]any{"displayName": "No Op Group"})["id"].(string)

		gv2PatchGroup(e, gv2Token, groupID)

		if got := gv2GetGroup(e, gv2Token, groupID); got["displayName"] != "No Op Group" {
			t.Fatalf("group = %v", got)
		}
	})

	t.Run("enforces connection-scoped, case-insensitive Group displayName uniqueness", func(t *testing.T) {
		e := gv2Env(t)
		gv2CreateGroup(e, gv2Token, map[string]any{"displayName": "Engineering"})
		platformID := gv2CreateGroup(e, gv2Token, map[string]any{"displayName": "Platform"})["id"].(string)

		ae := gv2CallErr(e, "createSCIMGroup", gv2Token, betterauth.CallInput{
			Body: map[string]any{"schemas": []any{gv2GroupSchema}, "displayName": "engineering"},
		})
		if b := errBody(ae); b["status"] != "409" || b["scimType"] != "uniqueness" {
			t.Fatalf("create body = %v", b)
		}
		ae = gv2CallErr(e, "patchSCIMGroup", gv2Token, betterauth.CallInput{
			Params: map[string]string{"groupId": platformID},
			Body: map[string]any{"schemas": []any{gv2PatchSchema}, "Operations": []any{
				map[string]any{"op": "replace", "path": "displayName", "value": "ENGINEERING"},
			}},
		})
		if b := errBody(ae); b["status"] != "409" || b["scimType"] != "uniqueness" {
			t.Fatalf("patch body = %v", b)
		}
		if row := gv2Find(e.rows("scimGroup"), "id", platformID); row == nil || row["displayName"] != "Platform" {
			t.Fatalf("platform row = %v", row)
		}
	})

	t.Run("filters, paginates, and projects the connection-owned Group collection", func(t *testing.T) {
		e := gv2TwoConnectionEnv(t)
		member := gv2CreateUser(e, gv2TokenA, map[string]any{"userName": "ada@example.com"})["id"].(string)
		engineering := gv2CreateGroup(e, gv2TokenA, map[string]any{"displayName": "Engineering", "members": gv2Members(member)})["id"].(string)
		gv2CreateGroup(e, gv2TokenA, map[string]any{"displayName": "Finance", "members": []any{}})
		gv2CreateGroup(e, gv2TokenA, map[string]any{"displayName": "Support", "members": []any{}})
		other := gv2CreateGroup(e, gv2TokenB, map[string]any{"displayName": "Engineering", "members": []any{}})["id"].(string)

		filtered := gv2Call(e, "listSCIMGroups", gv2TokenA, betterauth.CallInput{Query: map[string]any{"filter": `displayName eq "Engineering"`}})
		secondPage := gv2Call(e, "listSCIMGroups", gv2TokenA, betterauth.CallInput{Query: map[string]any{"startIndex": 2, "count": 1}})
		withoutMembers := gv2Call(e, "listSCIMGroups", gv2TokenA, betterauth.CallInput{Query: map[string]any{
			"filter": `displayName eq "Engineering"`, "excludedAttributes": "members",
		}})
		ownGroups := gv2Where(e.rows("scimGroup"), "connectionId", "workforce-a")
		sort.Slice(ownGroups, func(i, j int) bool {
			return fmt.Sprint(ownGroups[i]["orderKey"]) < fmt.Sprint(ownGroups[j]["orderKey"])
		})
		expectedSecondPageID := fmt.Sprint(ownGroups[1]["id"])

		if gv2Num(filtered["totalResults"]) != 1 || gv2Num(filtered["startIndex"]) != 1 || gv2Num(filtered["itemsPerPage"]) != 1 {
			t.Fatalf("filtered = %v", filtered)
		}
		if ids := gv2ResourceIDs(filtered); !reflect.DeepEqual(ids, []string{engineering}) || ids[0] == other {
			t.Fatalf("filtered ids = %v", ids)
		}
		if gv2Num(secondPage["totalResults"]) != 3 || gv2Num(secondPage["startIndex"]) != 2 || gv2Num(secondPage["itemsPerPage"]) != 1 {
			t.Fatalf("secondPage = %v", secondPage)
		}
		if ids := gv2ResourceIDs(secondPage); !reflect.DeepEqual(ids, []string{expectedSecondPageID}) {
			t.Fatalf("secondPage ids = %v, want %v", ids, expectedSecondPageID)
		}
		found := false
		for _, r := range e.rows("scimGroupMember") {
			if r["groupId"] == engineering && r["scimUserId"] == member {
				found = true
			}
		}
		if !found {
			t.Fatal("expected the Engineering membership row")
		}
		res, _ := withoutMembers["Resources"].([]any)
		if len(res) != 1 {
			t.Fatalf("withoutMembers = %v", withoutMembers)
		}
		if _, ok := res[0].(map[string]any)["members"]; ok {
			t.Fatalf("resource has members: %v", res[0])
		}
	})
}
