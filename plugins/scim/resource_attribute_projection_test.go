package scim

// Port of upstream resource-attribute-projection.test.ts ("projectSCIMResourceAttributes").

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/nimi-io/better-auth-go/jsonx"
)

const rapUserResourceJSON = `{
	"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
	"id": "scim-user-1",
	"externalId": "directory-user-1",
	"userName": "ada@example.com",
	"displayName": "Ada Lovelace",
	"name": {"formatted": "Ada Lovelace", "givenName": "Ada", "familyName": "Lovelace"},
	"emails": [
		{"value": "ada@example.com", "primary": true, "type": "work"},
		{"primary": false, "type": "other"}
	],
	"meta": {
		"resourceType": "User",
		"location": "https://example.com/scim/v2/Users/scim-user-1",
		"version": "v1"
	}
}`

func rapObject(t *testing.T, s string) *jsonx.Object {
	t.Helper()
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*jsonx.Object)
}

func rapPlain(t *testing.T, v any) any {
	t.Helper()
	var b []byte
	if s, ok := v.(string); ok {
		b = []byte(s)
	} else {
		var err error
		b, err = jsonx.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// rapEqual is toEqual: deep equality ignoring key order. want may be a JSON string.
func rapEqual(t *testing.T, got, want any) {
	t.Helper()
	g, w := rapPlain(t, got), rapPlain(t, want)
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("got %s\nwant %s", jsonx.MustMarshal(got), jsonx.MustMarshal(w))
	}
}

func rapProj(mode string, paths ...string) attributeProjection {
	p := attributeProjection{mode: mode}
	if mode == "default" {
		return p
	}
	p.attributes = map[string]bool{}
	for _, x := range paths {
		if !p.attributes[x] {
			p.attributes[x] = true
			p.order = append(p.order, x)
		}
	}
	return p
}

func rapGet(o *jsonx.Object, k string) any {
	v, _ := o.Get(k)
	return v
}

func TestResourceAttributeProjection(t *testing.T) {
	t.Run("preserves schemas and id for an included attribute projection", func(t *testing.T) {
		resource := rapObject(t, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"scim-user-1","userName":"ada@example.com","displayName":"Ada Lovelace"}`)
		got := projectResourceAttributes(resource, rapProj("include", "displayname"))
		rapEqual(t, got, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"scim-user-1","displayName":"Ada Lovelace"}`)
	})

	t.Run("returns a shallow copy for the default projection", func(t *testing.T) {
		user := rapObject(t, rapUserResourceJSON)
		got := projectResourceAttributes(user, rapProj("default"))
		rapEqual(t, got, rapUserResourceJSON)
		if got == user {
			t.Fatal("expected a copy")
		}
	})

	t.Run("preserves mandatory attributes even when excluded explicitly", func(t *testing.T) {
		user := rapObject(t, rapUserResourceJSON)
		got := projectResourceAttributes(user, rapProj("exclude", "schemas", "id", "displayname"))
		rapEqual(t, rapGet(got, "schemas"), []any{"urn:ietf:params:scim:schemas:core:2.0:User"})
		if rapGet(got, "id") != "scim-user-1" {
			t.Fatalf("id = %v", rapGet(got, "id"))
		}
		if got.Has("displayName") {
			t.Fatal("displayName should be excluded")
		}
	})

	t.Run("includes dotted object and multi-valued subattributes", func(t *testing.T) {
		user := rapObject(t, rapUserResourceJSON)
		got := projectResourceAttributes(user, rapProj("include", "name.givenname", "emails.value", "meta.location"))
		rapEqual(t, got, `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"id": "scim-user-1",
			"name": {"givenName": "Ada"},
			"emails": [{"value": "ada@example.com"}],
			"meta": {"location": "https://example.com/scim/v2/Users/scim-user-1"}
		}`)
	})

	t.Run("excludes dotted attributes while preserving sibling values", func(t *testing.T) {
		user := rapObject(t, rapUserResourceJSON)
		got := projectResourceAttributes(user, rapProj("exclude", "name.formatted", "emails.value", "meta.location"))
		rapEqual(t, rapGet(got, "name"), `{"givenName":"Ada","familyName":"Lovelace"}`)
		rapEqual(t, rapGet(got, "emails"), `[{"primary":true,"type":"work"},{"primary":false,"type":"other"}]`)
		rapEqual(t, rapGet(got, "meta"), `{"resourceType":"User","version":"v1"}`)
		first := rapGet(user, "emails").([]any)[0].(*jsonx.Object)
		if rapGet(first, "value") != "ada@example.com" {
			t.Fatal("source resource was mutated")
		}
	})

	t.Run("treats a selected top-level attribute as the complete value", func(t *testing.T) {
		user := rapObject(t, rapUserResourceJSON)
		got := projectResourceAttributes(user, rapProj("include", "name", "name.givenname"))
		rapEqual(t, rapGet(got, "name"), rapGet(user, "name"))
	})

	t.Run("matches resource key spelling case-insensitively", func(t *testing.T) {
		user := rapObject(t, rapUserResourceJSON)
		// Upstream passes the raw set {"USERNAME", "NAME.FAMILYNAME"}.
		got := projectResourceAttributes(user, rapProj("include", "USERNAME", "NAME.FAMILYNAME"))
		if rapGet(got, "userName") != "ada@example.com" {
			t.Fatalf("userName = %v", rapGet(got, "userName"))
		}
		name, _ := rapGet(got, "name").(*jsonx.Object)
		if name == nil || rapGet(name, "familyName") != "Lovelace" {
			t.Fatalf("name = %s", jsonx.MustMarshal(rapGet(got, "name")))
		}
	})

	t.Run("accepts projection output directly from the collection query parser", func(t *testing.T) {
		user := rapObject(t, rapUserResourceJSON)
		q, qerr := parseCollectionQuery("User", queryInputFrom(map[string]any{"attributes": "userName,name.givenName"}))
		if qerr != nil {
			t.Fatal(qerr.detail)
		}
		got := projectResourceAttributes(user, q.projection)
		rapEqual(t, got, `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"id": "scim-user-1",
			"userName": "ada@example.com",
			"name": {"givenName": "Ada"}
		}`)
	})

	t.Run("retains mandatory fields in the projected result type", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf type-level assertions")
	})
}

// rapMatchObject is vitest toMatchObject: objects match as subsets (recursively), arrays
// must have equal length with element-wise matching, other values must be deep-equal.
// want may be a JSON string. Shared by the other SCIM test files ported alongside this one.
func rapMatchObject(t *testing.T, got, want any) {
	t.Helper()
	g, w := rapPlain(t, got), rapPlain(t, want)
	if path, ok := rapMatches(g, w, "$"); !ok {
		t.Fatalf("toMatchObject mismatch at %s\ngot  %s\nwant %s", path, jsonx.MustMarshal(g), jsonx.MustMarshal(w))
	}
}

func rapMatches(g, w any, path string) (string, bool) {
	switch wv := w.(type) {
	case map[string]any:
		gv, ok := g.(map[string]any)
		if !ok {
			return path, false
		}
		for k, x := range wv {
			y, ok := gv[k]
			if !ok {
				return path + "." + k, false
			}
			if p, ok := rapMatches(y, x, path+"."+k); !ok {
				return p, false
			}
		}
		return "", true
	case []any:
		gv, ok := g.([]any)
		if !ok || len(gv) != len(wv) {
			return path, false
		}
		for i := range wv {
			if p, ok := rapMatches(gv[i], wv[i], path+"["+jsonx.FormatNumber(float64(i))+"]"); !ok {
				return p, false
			}
		}
		return "", true
	default:
		if !reflect.DeepEqual(g, w) {
			return path, false
		}
		return "", true
	}
}
