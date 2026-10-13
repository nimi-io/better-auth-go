package organization

// Ports of upstream client.test.ts and organization-client-declaration.test.ts. Both are
// mostly client/type-level; the server-observable part is ported.

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func TestClientOrganization(t *testing.T) {
	t.Run("should infer additional fields", func(t *testing.T) {
		t.Skip("TS-only: client type inference of organization additionalFields (inferOrgAdditionalFields<typeof auth>)")
	})
	t.Run("should infer filed when schema is provided", func(t *testing.T) {
		t.Skip("TS-only: client type inference of organization additionalFields from an explicit schema")
	})
}

func TestClientRefreshesActiveOrganizationAfterSignIn(t *testing.T) {
	t.Run("refreshes the active organization after sign-in sets it in a session hook", func(t *testing.T) {
		// The nanostores activeOrganization atom refresh is client-only; the server-observable
		// part (a session.create.before hook setting activeOrganizationId on sign-in, picked up
		// by getFullOrganization) is ported.
		initialOrganizationID := ""
		e := newEnv(t, Options{}, envConfig{mutate: func(c *betterauth.Config) {
			c.DatabaseHooks = &betterauth.DatabaseHooks{Session: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				Before: func(ctx context.Context, session adapter.Record) (*betterauth.DBHookResult, error) {
					data := adapter.Record{}
					for k, v := range session {
						data[k] = v
					}
					if initialOrganizationID != "" {
						data["activeOrganizationId"] = initialOrganizationID
					}
					return &betterauth.DBHookResult{Data: data}, nil
				},
			}}}
		}})
		headers := e.signInTestUser()
		org := e.createOrg(headers, "Test Workspace", "test-workspace")
		if org == nil {
			t.Fatal("Organization was not created")
		}
		initialOrganizationID = s(org["id"])

		r := e.post("/sign-in/email", nil, map[string]any{"email": testEmail, "password": testPassword})
		expectOK(t, r)
		newHeaders := cookieHeaders(r.Headers)
		full := e.mustAPI("getFullOrganization", newHeaders, nil, nil).m()
		if full == nil || full["id"] != initialOrganizationID {
			t.Fatalf("full organization = %v", full)
		}
	})
}

func TestClientDeclarationEmit(t *testing.T) {
	t.Run("should not produce TS2742 when organizationClient uses additionalFields", func(t *testing.T) {
		t.Skip("TS-only: TypeScript declaration emit (tsc TS2742) of the organization client")
	})
	t.Run("should not produce TS2742 when organizationClient is used without additionalFields", func(t *testing.T) {
		t.Skip("TS-only: TypeScript declaration emit (tsc TS2742) of the organization client")
	})
}
