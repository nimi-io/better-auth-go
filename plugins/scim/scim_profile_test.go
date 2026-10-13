package scim

// Port of upstream scim-profile.test.ts ("SCIM canonical User profiles").

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func TestProfile_SCIMCanonicalUserProfiles(t *testing.T) {
	t.Run("round-trips provider-standard names, displayName, and typed emails", func(t *testing.T) {
		e := newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")}})
		headers := bearer("test-scim-token")

		created := e.mustCall("createSCIMUser", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"schemas":     []any{SchemaUser},
			"userName":    "Ada.Login@Example.com",
			"displayName": "Countess of Lovelace",
			"name": map[string]any{
				"formatted":  "Augusta Ada King, Countess of Lovelace",
				"givenName":  "Augusta Ada",
				"familyName": "King",
			},
			"emails": []any{
				map[string]any{"value": "ada.shared@example.com", "type": "home", "primary": true},
				map[string]any{"value": "ada.shared@example.com", "type": "work"},
				map[string]any{"value": "ada.alias@example.com", "type": "other"},
			},
		}})
		id, _ := created["id"].(string)
		retrieved := e.mustCall("getSCIMUser", betterauth.CallInput{Headers: headers, Params: map[string]string{"userId": id}})

		rapMatchObject(t, retrieved, map[string]any{
			"schemas":     []any{SchemaUser},
			"id":          id,
			"userName":    "Ada.Login@Example.com",
			"displayName": "Countess of Lovelace",
			"name": map[string]any{
				"formatted":  "Augusta Ada King, Countess of Lovelace",
				"givenName":  "Augusta Ada",
				"familyName": "King",
			},
			"emails": []any{
				map[string]any{"value": "ada.shared@example.com", "type": "home", "primary": true},
				map[string]any{"value": "ada.shared@example.com", "type": "work", "primary": false},
				map[string]any{"value": "ada.alias@example.com", "type": "other", "primary": false},
			},
		})

		scimUsers := e.rows("scimUser")
		if len(scimUsers) == 0 {
			t.Fatal("Expected the persisted SCIM User")
		}
		serialized, _ := scimUsers[0]["serializedAttributes"].(string)
		var attrs map[string]any
		if err := json.Unmarshal([]byte(serialized), &attrs); err != nil {
			t.Fatalf("serializedAttributes %q: %v", serialized, err)
		}
		rapMatchObject(t, attrs, map[string]any{"emails": retrieved["emails"]})
		rapMatchObject(t, map[string]any(e.rows("user")[0]), map[string]any{
			"email": "ada.shared@example.com",
			"name":  "Countess of Lovelace",
		})

		if _, err := e.db().Update(context.Background(), "scimUser",
			[]adapter.Where{{Field: "id", Value: scimUsers[0]["id"]}},
			adapter.Record{"serializedAttributes": "corrupt"}); err != nil {
			t.Fatal(err)
		}
		_, ae := e.call("getSCIMUser", betterauth.CallInput{Headers: headers, Params: map[string]string{"userId": id}})
		if ae == nil {
			t.Fatal("expected error")
		}
		if ae.StatusCode != 500 {
			t.Fatalf("status = %d", ae.StatusCode)
		}
		rapMatchObject(t, errBody(ae), `{"detail":"Stored SCIM User attribute state is invalid"}`)
	})
}
