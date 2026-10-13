package scim

// Port of upstream scim-user-patch.test.ts.

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const (
	userPatchTPatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	userPatchTUserSchema    = "urn:ietf:params:scim:schemas:core:2.0:User"
)

type userPatchTCtx struct {
	e                *testEnv
	identityResolved *int32
}

// userPatchTNew is createTestContext.
func userPatchTNew(t *testing.T) *userPatchTCtx {
	t.Helper()
	var count int32
	e := newEnv(t, Options{
		Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")},
		Identity: &Identity{ResolveUser: func(IdentityResolutionInput, DatabaseContext) (*IdentityResolution, error) {
			atomic.AddInt32(&count, 1)
			return &IdentityResolution{Action: "create"}, nil
		}},
	})
	return &userPatchTCtx{e: e, identityResolved: &count}
}

func (c *userPatchTCtx) resolutionCount() int32 { return atomic.LoadInt32(c.identityResolved) }

func userPatchTObj(t *testing.T, s string) *jsonx.Object {
	t.Helper()
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		t.Fatalf("not an object: %s", s)
	}
	return o
}

func userPatchTPlain(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return v
}

func (c *userPatchTCtx) create(t *testing.T, body string) map[string]any {
	t.Helper()
	return c.e.mustCall("createSCIMUser", betterauth.CallInput{Body: userPatchTObj(t, body), Headers: bearer("test-scim-token")})
}

func (c *userPatchTCtx) get(t *testing.T, id string) map[string]any {
	t.Helper()
	return c.e.mustCall("getSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": id}, Headers: bearer("test-scim-token")})
}

// patch sends a PatchOp body with the given Operations JSON.
func (c *userPatchTCtx) patch(t *testing.T, id, operations string) *betterauth.APIError {
	t.Helper()
	body := userPatchTObj(t, `{"schemas":["`+userPatchTPatchOpSchema+`"],"Operations":`+operations+`}`)
	_, ae := c.e.call("patchSCIMUser", betterauth.CallInput{Params: map[string]string{"userId": id}, Body: body, Headers: bearer("test-scim-token")})
	return ae
}

func (c *userPatchTCtx) mustPatch(t *testing.T, id, operations string) {
	t.Helper()
	if ae := c.patch(t, id, operations); ae != nil {
		t.Fatalf("patch %s: %d %s", operations, ae.StatusCode, string(jsonx.MustMarshal(ae.Body)))
	}
}

// persisted is getPersistedUser (raw memory rows).
func (c *userPatchTCtx) persisted(t *testing.T, scimUserID string) (adapter.Record, adapter.Record) {
	t.Helper()
	var su adapter.Record
	for _, r := range c.e.mem.Rows("scimUser") {
		if r["id"] == scimUserID {
			su = r
		}
	}
	if su == nil {
		t.Fatal("Expected a persisted SCIM User")
	}
	for _, r := range c.e.mem.Rows("user") {
		if r["id"] == su["userId"] {
			return su, r
		}
	}
	t.Fatal("Expected a backing Better Auth User")
	return nil, nil
}

// userPatchTMatch is a recursive toMatchObject.
func userPatchTMatch(t *testing.T, label string, got any, want any) {
	t.Helper()
	if !userPatchTMatches(got, want) {
		t.Fatalf("%s: got %s, want to match %s", label, jsonx.MustMarshal(got), jsonx.MustMarshal(want))
	}
}

func userPatchTMatches(got, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			if ar, ok := got.(adapter.Record); ok {
				g = ar
			} else {
				return false
			}
		}
		for k, wv := range w {
			gv, ok := g[k]
			if !ok && wv != nil {
				return false
			}
			if !userPatchTMatches(gv, wv) {
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
			if !userPatchTMatches(g[i], w[i]) {
				return false
			}
		}
		return true
	case nil:
		return got == nil
	default:
		return reflect.DeepEqual(got, want)
	}
}

func userPatchTEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got %s, want %s", label, jsonx.MustMarshal(got), jsonx.MustMarshal(want))
	}
}

func userPatchTExpectSCIMType(t *testing.T, ae *betterauth.APIError, status int, scimType string) {
	t.Helper()
	if ae == nil {
		t.Fatalf("expected %d %s error, got success", status, scimType)
	}
	b := errBody(ae)
	if ae.StatusCode != status || b["scimType"] != scimType {
		t.Fatalf("error = %d %v, want %d scimType=%s", ae.StatusCode, b, status, scimType)
	}
}

// See https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups#update-user-multi-valued-properties
func TestUserPatchT_ProviderCompatibility(t *testing.T) {
	t.Run("applies ordered Entra-style replacements to the canonical and backing Users", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"ada.login@example.com",
			"name":{"formatted":"Ada Lovelace"},
			"emails":[{"value":"ada.primary@example.com","type":"work","primary":true}],
			"externalId":"directory-user-1"}`)
		id := created["id"].(string)
		origSU, origUser := c.persisted(t, id)

		c.mustPatch(t, id, `[
			{"op":"Replace","path":"userName","value":"augusta.login@example.com"},
			{"op":"Replace","path":"name.formatted","value":"Augusta Ada King"},
			{"op":"Replace","path":"emails[type eq \"work\"].value","value":"augusta.primary@example.com"}]`)

		retrieved := c.get(t, id)
		su, user := c.persisted(t, id)
		userPatchTMatch(t, "retrieved", retrieved, map[string]any{
			"id":          id,
			"userName":    "augusta.login@example.com",
			"name":        map[string]any{"formatted": "Augusta Ada King"},
			"displayName": "Augusta Ada King",
			"externalId":  "directory-user-1",
			"emails":      []any{map[string]any{"primary": true, "value": "augusta.primary@example.com"}},
		})
		userPatchTMatch(t, "scimUser", map[string]any(su), map[string]any{
			"id":           id,
			"connectionId": "workforce",
			"userId":       origSU["userId"],
			"userName":     "augusta.login@example.com",
			"primaryEmail": "augusta.primary@example.com",
			"displayName":  "Augusta Ada King",
			"externalId":   "directory-user-1",
		})
		userPatchTMatch(t, "user", map[string]any(user), map[string]any{
			"id":    origUser["id"],
			"email": "augusta.primary@example.com",
			"name":  "Augusta Ada King",
		})
	})

	t.Run("replaces the value subattribute on every selected email record", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"multi-email@example.com",
			"emails":[{"value":"home@example.com","type":"home","primary":true},{"value":"work@example.com","type":"work"}]}`)
		id := created["id"].(string)

		c.mustPatch(t, id, `[{"op":"replace","path":"emails.value","value":"shared@example.com"}]`)

		retrieved := c.get(t, id)
		su, user := c.persisted(t, id)
		userPatchTEqual(t, "emails", retrieved["emails"], userPatchTPlain(t, `[
			{"value":"shared@example.com","type":"home","primary":true},
			{"value":"shared@example.com","type":"work","primary":false}]`))
		userPatchTEqual(t, "primaryEmail", su["primaryEmail"], "shared@example.com")
		userPatchTEqual(t, "user.email", user["email"], "shared@example.com")
	})

	t.Run("creates a missing work email for add and replace and treats a missing filtered removal as a no-op", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"typed-email@example.com",
			"emails":[{"value":"home@example.com","type":"home","primary":true}]}`)
		id := created["id"].(string)

		c.mustPatch(t, id, `[{"op":"add","path":"emails[type eq \"work\"].value","value":"work@example.com"}]`)
		userPatchTEqual(t, "withWorkEmail", c.get(t, id)["emails"], userPatchTPlain(t, `[
			{"value":"home@example.com","type":"home","primary":true},
			{"value":"work@example.com","type":"work","primary":false}]`))

		c.mustPatch(t, id, `[{"op":"remove","path":"emails[type eq \"work\"].value"}]`)
		c.mustPatch(t, id, `[{"op":"replace","path":"emails[type eq \"work\"].value","value":"replacement@example.com"}]`)
		userPatchTEqual(t, "withReplacedWorkEmail", c.get(t, id)["emails"], userPatchTPlain(t, `[
			{"value":"home@example.com","type":"home","primary":true},
			{"value":"replacement@example.com","type":"work","primary":false}]`))

		c.mustPatch(t, id, `[{"op":"remove","path":"emails[type eq \"work\"].value"}]`)
		su, _ := c.persisted(t, id)
		updatedAtAfterRemoval := su["updatedAt"]
		c.mustPatch(t, id, `[{"op":"remove","path":"emails[type eq \"work\"].value"}]`)
		su, _ = c.persisted(t, id)
		userPatchTEqual(t, "updatedAt", su["updatedAt"], updatedAtAfterRemoval)
	})

	t.Run("adds, replaces, and removes a non-work typed email through the filtered path", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"home-email@example.com",
			"emails":[{"value":"work@example.com","type":"work","primary":true}]}`)
		id := created["id"].(string)

		c.mustPatch(t, id, `[{"op":"add","path":"emails[type eq \"home\"].value","value":"home@example.com"}]`)
		userPatchTEqual(t, "withHomeEmail", c.get(t, id)["emails"], userPatchTPlain(t, `[
			{"value":"work@example.com","type":"work","primary":true},
			{"value":"home@example.com","type":"home","primary":false}]`))

		c.mustPatch(t, id, `[{"op":"replace","path":"emails[type eq \"home\"].value","value":"home-updated@example.com"}]`)
		userPatchTEqual(t, "withReplacedHomeEmail", c.get(t, id)["emails"], userPatchTPlain(t, `[
			{"value":"work@example.com","type":"work","primary":true},
			{"value":"home-updated@example.com","type":"home","primary":false}]`))

		c.mustPatch(t, id, `[{"op":"remove","path":"emails[type eq \"home\"].value"}]`)
		userPatchTEqual(t, "finalResource", c.get(t, id)["emails"], userPatchTPlain(t, `[
			{"value":"work@example.com","type":"work","primary":true}]`))
	})

	t.Run("appends email tuples and treats duplicate additions as a no-op", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"append-email@example.com",
			"emails":[{"value":"home@example.com","type":"home","primary":true}]}`)
		id := created["id"].(string)

		c.mustPatch(t, id, `[{"op":"add","path":"emails","value":[{"value":"work@example.com","type":"work"}]}]`)
		userPatchTEqual(t, "appended", c.get(t, id)["emails"], userPatchTPlain(t, `[
			{"value":"home@example.com","type":"home","primary":true},
			{"value":"work@example.com","type":"work","primary":false}]`))
		su, user := c.persisted(t, id)
		userPatchTEqual(t, "user.email", user["email"], "home@example.com")

		updatedAtAfterAppend := su["updatedAt"]
		c.mustPatch(t, id, `[{"op":"add","value":{"emails":[
			{"value":"WORK@example.com","type":"WORK"},
			{"value":"work@example.com","type":"work"}]}}]`)
		su, _ = c.persisted(t, id)
		userPatchTEqual(t, "updatedAt", su["updatedAt"], updatedAtAfterAppend)
	})

	t.Run("makes a newly appended explicit primary email authoritative", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"new-primary@example.com",
			"emails":[{"value":"old-primary@example.com","type":"home","primary":true}]}`)
		id := created["id"].(string)

		c.mustPatch(t, id, `[{"op":"add","path":"emails","value":[{"value":"new-primary@example.com","type":"work","primary":true}]}]`)
		userPatchTEqual(t, "emails", c.get(t, id)["emails"], userPatchTPlain(t, `[
			{"value":"old-primary@example.com","type":"home","primary":false},
			{"value":"new-primary@example.com","type":"work","primary":true}]`))
		_, user := c.persisted(t, id)
		userPatchTEqual(t, "user.email", user["email"], "new-primary@example.com")
	})

	t.Run("rejects duplicate email types atomically across HTTP PATCH shapes", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"patch-type-collision@example.com",
			"emails":[{"value":"home@example.com","type":"home","primary":true},{"value":"work@example.com","type":"work"}]}`)
		id := created["id"].(string)
		resourcePath := scimUsersURL + "/" + url.PathEscape(id)
		resourceBefore := c.get(t, id)
		suBefore, userBefore := c.persisted(t, id)
		serializedBefore := suBefore["serializedAttributes"]
		callbackCountBefore := c.resolutionCount()
		operationSets := []string{
			`[{"op":"add","path":"emails","value":[{"value":"second-work@example.com","type":"Work"}]}]`,
			`[{"op":"replace","path":"emails","value":[
				{"value":"home@example.com","type":"home","primary":true},
				{"value":"first-work@example.com","type":"Work"},
				{"value":"second-work@example.com","type":"work"}]}]`,
			`[{"op":"add","value":{"emails":[{"value":"pathless-work@example.com","type":"Work"}]}}]`,
		}
		for _, ops := range operationSets {
			res := c.e.scim("PATCH", resourcePath, "test-scim-token",
				`{"schemas":["`+userPatchTPatchOpSchema+`"],"Operations":`+ops+`}`)
			if res.Status != 400 {
				t.Fatalf("%s: status = %d %s", ops, res.Status, res.text())
			}
			if res.json()["scimType"] != "invalidValue" {
				t.Fatalf("%s: body = %s", ops, res.text())
			}
			userPatchTEqual(t, "resource", c.get(t, id), resourceBefore)
			suAfter, userAfter := c.persisted(t, id)
			userPatchTEqual(t, "serializedAttributes", suAfter["serializedAttributes"], serializedBefore)
			userPatchTEqual(t, "user", userAfter, userBefore)
			if got := c.resolutionCount(); got != callbackCountBefore {
				t.Fatalf("identity resolution count = %d, want %d", got, callbackCountBefore)
			}
		}
	})

	t.Run("rejects an email replacement with a duplicate type and value tuple", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"duplicate-email@example.com",
			"emails":[{"value":"home@example.com","type":"home","primary":true},{"value":"work@example.com","type":"work"}]}`)
		id := created["id"].(string)
		resourceBefore := c.get(t, id)
		suBefore, userBefore := c.persisted(t, id)

		ae := c.patch(t, id, `[{"op":"replace","path":"emails","value":[
			{"value":"home@example.com","type":"home","primary":true},
			{"value":"duplicate@example.com"},
			{"value":"duplicate@example.com"}]}]`)
		userPatchTExpectSCIMType(t, ae, 400, "invalidValue")

		userPatchTEqual(t, "resource", c.get(t, id), resourceBefore)
		suAfter, userAfter := c.persisted(t, id)
		userPatchTEqual(t, "serializedAttributes", suAfter["serializedAttributes"], suBefore["serializedAttributes"])
		userPatchTEqual(t, "user.email", userAfter["email"], userBefore["email"])
	})

	t.Run("rejects emails.value replacements that collapse distinct email tuples", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"tuple-collision@example.com",
			"emails":[{"value":"primary-work@example.com","primary":true},{"value":"secondary-work@example.com"}]}`)
		id := created["id"].(string)
		resourceBefore := c.get(t, id)

		ae := c.patch(t, id, `[{"op":"replace","path":"emails.value","value":"collision@example.com"}]`)
		userPatchTExpectSCIMType(t, ae, 400, "invalidValue")
		userPatchTEqual(t, "resource", c.get(t, id), resourceBefore)
	})

	t.Run("preserves explicitly supplied formatted and display names when patching one name part", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"explicit-name@example.com",
			"displayName":"Ada Lovelace",
			"name":{"formatted":"Ada Lovelace","givenName":"Ada","familyName":"Lovelace"}}`)
		id := created["id"].(string)

		c.mustPatch(t, id, `[{"op":"replace","path":"name.givenName","value":"Augusta"}]`)
		userPatchTMatch(t, "resource", c.get(t, id), map[string]any{
			"displayName": "Ada Lovelace",
			"name":        map[string]any{"formatted": "Ada Lovelace", "givenName": "Augusta", "familyName": "Lovelace"},
		})
	})

	t.Run("rejects whitespace inside a simple PATCH attribute path", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"path-whitespace@example.com"}`)
		id := created["id"].(string)

		ae := c.patch(t, id, `[{"op":"replace","path":"user Name","value":"unexpected@example.com"}]`)
		userPatchTExpectSCIMType(t, ae, 400, "invalidPath")
	})

	t.Run("rejects a PATCH attribute path with a trailing empty segment", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"path-trailing-dot@example.com",
			"name":{"formatted":"Original Name"}}`)
		id := created["id"].(string)

		ae := c.patch(t, id, `[{"op":"replace","path":"name.","value":{"formatted":"Unexpected Name"}}]`)
		userPatchTExpectSCIMType(t, ae, 400, "invalidPath")
		userPatchTMatch(t, "name", c.get(t, id)["name"], map[string]any{"formatted": "Original Name"})
	})

	t.Run("atomically applies pathless object updates and removes externalId", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"initial.login@example.com",
			"name":{"formatted":"Initial Name"},
			"emails":[{"value":"initial.primary@example.com","primary":true}],
			"externalId":"directory-user-2"}`)
		id := created["id"].(string)
		origSU, origUser := c.persisted(t, id)

		c.mustPatch(t, id, `[
			{"op":"replace","value":{"userName":"pathless.login@example.com","name":{"formatted":"Pathless Replacement"},"active":false}},
			{"op":"add","value":{"emails":[{"value":"pathless.primary@example.com","primary":true}]}},
			{"op":"remove","path":"externalId"}]`)

		retrieved := c.get(t, id)
		su, user := c.persisted(t, id)
		userPatchTMatch(t, "retrieved", retrieved, map[string]any{
			"id":          id,
			"userName":    "pathless.login@example.com",
			"name":        map[string]any{"formatted": "Pathless Replacement"},
			"displayName": "Pathless Replacement",
			"active":      false,
			"emails": []any{
				map[string]any{"primary": false, "value": "initial.primary@example.com"},
				map[string]any{"primary": true, "value": "pathless.primary@example.com"},
			},
		})
		if _, ok := retrieved["externalId"]; ok {
			t.Fatalf("retrieved has externalId: %v", retrieved["externalId"])
		}
		userPatchTMatch(t, "scimUser", map[string]any(su), map[string]any{
			"id":           id,
			"connectionId": "workforce",
			"userId":       origSU["userId"],
			"userName":     "pathless.login@example.com",
			"primaryEmail": "pathless.primary@example.com",
			"displayName":  "Pathless Replacement",
			"active":       false,
		})
		// externalId: null, externalIdKey: null
		for _, k := range []string{"externalId", "externalIdKey"} {
			if v, ok := su[k]; !ok || v != nil {
				t.Fatalf("scimUser.%s = %v (present=%v), want null", k, v, ok)
			}
		}
		userPatchTMatch(t, "user", map[string]any(user), map[string]any{
			"id":    origUser["id"],
			"email": "pathless.primary@example.com",
			"name":  "Pathless Replacement",
		})
	})

	t.Run("rejects pathless remove operations with noTarget", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"pathless-remove@example.com"}`)
		id := created["id"].(string)

		ae := c.patch(t, id, `[{"op":"remove"}]`)
		userPatchTExpectSCIMType(t, ae, 400, "noTarget")
	})

	t.Run("rejects a read-only path without applying any operation", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"unchanged.login@example.com",
			"name":{"formatted":"Unchanged Name"},
			"emails":[{"value":"unchanged.primary@example.com","primary":true}],
			"externalId":"directory-user-3"}`)
		id := created["id"].(string)
		resourceBefore := c.get(t, id)
		suBefore, userBefore := c.persisted(t, id)
		canonicalKeys := []string{"userName", "userNameKey", "primaryEmail", "displayName", "externalId", "externalIdKey", "active", "updatedAt"}
		backingKeys := []string{"email", "name", "updatedAt"}
		pick := func(r adapter.Record, keys []string) map[string]any {
			out := map[string]any{}
			for _, k := range keys {
				out[k] = r[k]
			}
			return out
		}

		ae := c.patch(t, id, `[
			{"op":"replace","path":"userName","value":"must-not-persist.login@example.com"},
			{"op":"replace","path":"name.formatted","value":"Must Not Persist"},
			{"op":"replace","path":"id","value":"read-only-mutation"},
			{"op":"replace","path":"emails[type eq \"work\"].value","value":"must-not-persist.primary@example.com"}]`)

		userPatchTEqual(t, "resource", c.get(t, id), resourceBefore)
		suAfter, userAfter := c.persisted(t, id)
		userPatchTEqual(t, "canonical", pick(suAfter, canonicalKeys), pick(suBefore, canonicalKeys))
		userPatchTEqual(t, "backing", pick(userAfter, backingKeys), pick(userBefore, backingKeys))
		if ae == nil {
			t.Fatal("expected a mutability error")
		}
		userPatchTMatch(t, "patchError.body", errBody(ae), map[string]any{
			"schemas":  []any{"urn:ietf:params:scim:api:messages:2.0:Error"},
			"status":   "400",
			"scimType": "mutability",
		})
	})
}

func TestUserPatchT_PreSerializedAttributesRows(t *testing.T) {
	t.Run("serves GET, PUT, and PATCH for a scimUser row persisted before serializedAttributes existed", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"legacy.login@example.com",
			"name":{"formatted":"Legacy Employee","givenName":"Legacy","familyName":"Employee"},
			"emails":[{"value":"legacy.primary@example.com","primary":true}]}`)
		id := created["id"].(string)

		forgetSerializedAttributes := func() {
			t.Helper()
			if _, err := c.e.db().Update(context.Background(), "scimUser",
				[]adapter.Where{{Field: "id", Value: id}}, adapter.Record{"serializedAttributes": nil}); err != nil {
				t.Fatal(err)
			}
		}
		serialized := func() any {
			su, _ := c.persisted(t, id)
			return su["serializedAttributes"]
		}
		truthy := func(v any) bool {
			s, ok := v.(string)
			return ok && s != ""
		}

		forgetSerializedAttributes()
		userPatchTMatch(t, "retrieved", c.get(t, id), map[string]any{
			"userName": "legacy.login@example.com",
			"name":     map[string]any{"formatted": "Legacy Employee", "givenName": "Legacy", "familyName": "Employee"},
			"emails":   []any{map[string]any{"value": "legacy.primary@example.com", "primary": true}},
		})
		if truthy(serialized()) {
			t.Fatalf("GET persisted serializedAttributes = %v", serialized())
		}

		forgetSerializedAttributes()
		replaced := c.e.mustCall("replaceSCIMUser", betterauth.CallInput{
			Params:  map[string]string{"userId": id},
			Headers: bearer("test-scim-token"),
			Body: userPatchTObj(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"legacy.login@example.com",
				"name":{"formatted":"Legacy Employee Renewed","givenName":"Legacy","familyName":"Employee"},
				"emails":[{"value":"legacy.primary@example.com","primary":true}]}`),
		})
		userPatchTMatch(t, "replaced.name", replaced["name"], map[string]any{"formatted": "Legacy Employee Renewed"})
		if !truthy(serialized()) {
			t.Fatal("PUT did not persist serializedAttributes")
		}

		forgetSerializedAttributes()
		c.mustPatch(t, id, `[{"op":"replace","path":"title","value":"Archivist"}]`)
		userPatchTEqual(t, "title", c.get(t, id)["title"], "Archivist")
		if !truthy(serialized()) {
			t.Fatal("PATCH did not persist serializedAttributes")
		}
	})

	// See https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups
	t.Run("accepts an empty Operations array as a no-op PATCH", func(t *testing.T) {
		c := userPatchTNew(t)
		created := c.create(t, `{"schemas":["`+userPatchTUserSchema+`"],"userName":"no-op-patch@example.com","displayName":"No Op"}`)
		id := created["id"].(string)

		c.mustPatch(t, id, `[]`)
		userPatchTMatch(t, "resource", c.get(t, id), map[string]any{"displayName": "No Op"})
	})
}
