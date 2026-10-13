package scim

// Port of upstream scim-provisioning-domain.test.ts.

import (
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// provisioningDomainAuth is createAuth(provisioningDomainId) over a shared memory store.
func provisioningDomainAuth(t *testing.T, store *memory.DB, provisioningDomainID string) *testEnv {
	t.Helper()
	return newEnv(t, Options{Connections: []ConnectionOptions{{
		ID:                   "workforce",
		ProvisioningDomainID: provisioningDomainID,
		Credentials:          []BearerCredential{{Type: "bearer", ID: "test-scim-token", Token: "test-scim-token"}},
	}}}, envOptions{mutate: func(cfg *betterauth.Config) { cfg.Database = memory.New(store) }})
}

func provisioningDomainExpect409(t *testing.T, ae *betterauth.APIError) {
	t.Helper()
	if ae == nil || ae.StatusCode != 409 {
		t.Fatalf("expected statusCode 409, got %+v", ae)
	}
}

func TestProvisioningDomain(t *testing.T) {
	headers := bearer("test-scim-token")

	t.Run("rejects configuration drift instead of moving persisted resources", func(t *testing.T) {
		store := memory.NewDB()
		original := provisioningDomainAuth(t, store, "workspace-original")
		user := original.mustCall("createSCIMUser", betterauth.CallInput{
			Body:    map[string]any{"schemas": []any{httpContractUserSchema}, "userName": "ada@example.com"},
			Headers: headers,
		})
		group := original.mustCall("createSCIMGroup", betterauth.CallInput{
			Body:    map[string]any{"schemas": []any{httpContractGroupSchema}, "displayName": "Engineering"},
			Headers: headers,
		})
		drifted := provisioningDomainAuth(t, store, "workspace-drifted")

		_, ae := drifted.call("getSCIMUser", betterauth.CallInput{
			Params: map[string]string{"userId": user["id"].(string)}, Headers: headers,
		})
		provisioningDomainExpect409(t, ae)
		_, ae = drifted.call("getSCIMGroup", betterauth.CallInput{
			Params: map[string]string{"groupId": group["id"].(string)}, Headers: headers,
		})
		provisioningDomainExpect409(t, ae)
		if got := store.Rows("scimUser")[0]["provisioningDomainId"]; got != "workspace-original" {
			t.Fatalf("scimUser domain = %v", got)
		}
		if got := store.Rows("scimGroup")[0]["provisioningDomainId"]; got != "workspace-original" {
			t.Fatalf("scimGroup domain = %v", got)
		}
	})

	for _, tc := range [][2]string{{"Group", "User"}, {"User", "Group"}} {
		originalResource, driftedResource := tc[0], tc[1]
		t.Run("rejects domain drift after provisioning only a "+originalResource+" before creating a "+driftedResource, func(t *testing.T) {
			store := memory.NewDB()
			original := provisioningDomainAuth(t, store, "workspace-original")
			if originalResource == "Group" {
				original.mustCall("createSCIMGroup", betterauth.CallInput{
					Body:    map[string]any{"schemas": []any{httpContractGroupSchema}, "displayName": "Engineering"},
					Headers: headers,
				})
			} else {
				original.mustCall("createSCIMUser", betterauth.CallInput{
					Body:    map[string]any{"schemas": []any{httpContractUserSchema}, "userName": "ada@example.com"},
					Headers: headers,
				})
			}
			drifted := provisioningDomainAuth(t, store, "workspace-drifted")
			var ae *betterauth.APIError
			if driftedResource == "User" {
				_, ae = drifted.call("createSCIMUser", betterauth.CallInput{
					Body:    map[string]any{"schemas": []any{httpContractUserSchema}, "userName": "grace@example.com"},
					Headers: headers,
				})
			} else {
				_, ae = drifted.call("createSCIMGroup", betterauth.CallInput{
					Body:    map[string]any{"schemas": []any{httpContractGroupSchema}, "displayName": "Finance"},
					Headers: headers,
				})
			}
			provisioningDomainExpect409(t, ae)
			bindings := store.Rows("scimConnectionBinding")
			if len(bindings) != 1 || bindings[0]["connectionId"] != "workforce" ||
				bindings[0]["provisioningDomainId"] != "workspace-original" {
				t.Fatalf("bindings = %v", bindings)
			}
			wantUsers, wantGroups := 0, 0
			if originalResource == "User" {
				wantUsers = 1
			} else {
				wantGroups = 1
			}
			if n := len(store.Rows("scimUser")); n != wantUsers {
				t.Fatalf("scimUser rows = %d, want %d", n, wantUsers)
			}
			if n := len(store.Rows("scimGroup")); n != wantGroups {
				t.Fatalf("scimGroup rows = %d, want %d", n, wantGroups)
			}
		})
	}
}
