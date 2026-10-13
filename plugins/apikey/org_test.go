package apikey

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/access"
	"github.com/nimi-io/better-auth-go/plugins/organization"
)

func orgPlugin(o organization.Options) *betterauth.Plugin {
	if o.SendInvitationEmail == nil {
		o.SendInvitationEmail = func(*organization.Ctx, organization.InvitationEmailData, *http.Request) error { return nil }
	}
	return organization.New(o)
}

func (i *instance) createOrg(headers http.Header, name, slug string) string {
	i.t.Helper()
	return str(i.mustCall("createOrganization", map[string]any{"name": name, "slug": slug}, headers)["id"])
}

// addMemberViaInvitation signs a new user up, invites and accepts (createUserAndInvite).
func (i *instance) addMemberViaInvitation(ownerHeaders http.Header, orgID, role string) http.Header {
	i.t.Helper()
	email := fmt.Sprintf("%s-%d-%d@test.com", role, time.Now().UnixNano(), rand.IntN(1e9))
	i.signUp(email, "password123", role+" User")
	inv := i.mustCall("createInvitation", map[string]any{"organizationId": orgID, "email": email, "role": role}, ownerHeaders)
	s := i.signIn(email, "password123")
	i.mustCall("acceptInvitation", map[string]any{"invitationId": inv["id"]}, s.headers)
	return s.headers
}

var userAndOrgConfigs = Options{Configurations: []Configuration{
	{ConfigID: "user-keys", DefaultPrefix: "usr_", References: ReferencesUser},
	{ConfigID: "org-keys", DefaultPrefix: "org_", References: ReferencesOrganization},
}}

// describe("organization-owned API keys") nested in describe("api-key").
func TestAPIKeyOrganizationOwnedAPIKeys(t *testing.T) {
	inst := newInstance(t, userAndOrgConfigs, nil, orgPlugin(organization.Options{}))

	t.Run("should create organization-owned API key", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Test Org", "test-org")
		k := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
		eq(t, k["configId"], "org-keys")
		eq(t, k["referenceId"], orgID)
		eq(t, k["prefix"], "org_")
	})

	t.Run("should create user-owned API key", func(t *testing.T) {
		s := inst.signInWithTestUser()
		k := inst.createKey(map[string]any{"configId": "user-keys", "userId": s.userID}, nil)
		eq(t, k["configId"], "user-keys")
		eq(t, k["referenceId"], s.userID)
		eq(t, k["prefix"], "usr_")
	})

	t.Run("should fail to create org key without organizationId", func(t *testing.T) {
		s := inst.signInWithTestUser()
		_, e := inst.call("createApiKey", map[string]any{"configId": "org-keys", "userId": s.userID}, nil)
		if e == nil || e.Code() != ErrOrganizationIDRequired.Code {
			t.Fatalf("expected ORGANIZATION_ID_REQUIRED, got %v", e)
		}
	})

	t.Run("should verify organization-owned API key", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Verify Org", "verify-org")
		k := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
		r := inst.verify(map[string]any{"key": k["key"], "configId": "org-keys"})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["configId"], "org-keys")
		eq(t, obj(r["key"])["referenceId"], orgID)
	})

	t.Run("should list only user-owned keys when no organizationId provided", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "List Org", "list-org")
		inst.createKey(map[string]any{"configId": "user-keys", "userId": s.userID}, nil)
		inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
		r := expectOK(t, inst.clientList("", s.headers))
		for _, k := range r["apiKeys"].([]any) {
			eq(t, obj(k)["configId"], "user-keys")
			eq(t, obj(k)["referenceId"], s.userID)
		}
	})

	t.Run("should list organization-owned keys when organizationId is provided", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "List Org Keys", "list-org-keys")
		uk := inst.createKey(map[string]any{"configId": "user-keys", "userId": s.userID}, nil)
		inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID, "name": "org-key-1"}, s.headers)
		inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID, "name": "org-key-2"}, s.headers)
		r := inst.mustCall("listApiKeys", nil, s.headers, map[string]any{"organizationId": orgID})
		keys := r["apiKeys"].([]any)
		eq(t, len(keys), 2)
		for _, k := range keys {
			eq(t, obj(k)["configId"], "org-keys")
			eq(t, obj(k)["referenceId"], orgID)
			if obj(k)["id"] == uk["id"] {
				t.Fatal("user key listed")
			}
		}
	})

	t.Run("should filter organization keys by configId", func(t *testing.T) {
		in := newInstance(t, Options{Configurations: []Configuration{
			{ConfigID: "org-public", DefaultPrefix: "pub_", References: ReferencesOrganization},
			{ConfigID: "org-internal", DefaultPrefix: "int_", References: ReferencesOrganization},
		}}, nil, orgPlugin(organization.Options{}))
		s := in.signInWithTestUser()
		orgID := in.createOrg(s.headers, "Filter Org", "filter-org")
		in.createKey(map[string]any{"configId": "org-public", "organizationId": orgID}, s.headers)
		in.createKey(map[string]any{"configId": "org-internal", "organizationId": orgID}, s.headers)
		r := in.mustCall("listApiKeys", nil, s.headers, map[string]any{"organizationId": orgID, "configId": "org-public"})
		keys := r["apiKeys"].([]any)
		eq(t, len(keys), 1)
		eq(t, obj(keys[0])["configId"], "org-public")
	})

	t.Run("should allow organization owners to manage API keys", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Owner Access Org", "owner-access-org")
		r := expectOK(t, inst.clientList(q("organizationId", orgID), s.headers))
		notNil(t, r["apiKeys"])
	})

	t.Run("should deny non-members from accessing organization API keys", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Non Member Org", "non-member-org")
		email := fmt.Sprintf("non-member-%d@test.com", time.Now().UnixNano())
		inst.signUp(email, "password123", "Non Member User")
		nm := inst.signIn(email, "password123")
		res := inst.clientList(q("organizationId", orgID), nm.headers)
		if res.Status != 401 && res.Status != 403 {
			t.Fatalf("expected 401 or 403, got %d", res.Status)
		}
	})

	t.Run("should not allow session mocking for org-owned keys", func(t *testing.T) {
		in := newInstance(t, Options{Configurations: []Configuration{
			{ConfigID: "org-keys", DefaultPrefix: "org_", References: ReferencesOrganization, EnableSessionForAPIKeys: true},
		}}, nil, orgPlugin(organization.Options{}))
		s := in.signInWithTestUser()
		orgID := in.createOrg(s.headers, "Session Org", "session-org")
		k := in.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
		h := http.Header{}
		h.Set("x-api-key", str(k["key"]))
		_, err := in.auth.API.GetSession(t.Context(), h)
		e, ok := betterauth.AsAPIError(err)
		if !ok || e.Code() != ErrInvalidReferenceIDFromAPIKey.Code {
			t.Fatalf("expected INVALID_REFERENCE_ID_FROM_API_KEY, got %v", err)
		}
	})

	t.Run("should allow session mocking for user-owned keys only", func(t *testing.T) {
		in := newInstance(t, Options{Configurations: []Configuration{
			{ConfigID: "user-keys", DefaultPrefix: "usr_", References: ReferencesUser, EnableSessionForAPIKeys: true},
		}}, nil, orgPlugin(organization.Options{}))
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"configId": "user-keys", "userId": s.userID}, nil)
		h := http.Header{}
		h.Set("x-api-key", str(k["key"]))
		sess, err := in.auth.API.GetSession(t.Context(), h)
		if err != nil || sess == nil {
			t.Fatalf("expected session: %v", err)
		}
		eq(t, sess.User.ID, s.userID)
	})

	t.Run("should handle mixed user and org keys in same instance", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Mixed Org", "mixed-org")
		uk := inst.createKey(map[string]any{"configId": "user-keys", "userId": s.userID}, nil)
		ok := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
		r := inst.verify(map[string]any{"key": uk["key"], "configId": "user-keys"})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["referenceId"], s.userID)
		r = inst.verify(map[string]any{"key": ok["key"], "configId": "org-keys"})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["referenceId"], orgID)
	})

	t.Run("should get org-owned key by id from server", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Get Org", "get-org")
		k := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID, "name": "my-org-key"}, s.headers)
		r, e := inst.getKey(str(k["id"]), "org-keys", s.headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, r["id"], k["id"])
		eq(t, r["configId"], "org-keys")
		eq(t, r["referenceId"], orgID)
		eq(t, r["name"], "my-org-key")
	})

	t.Run("should delete org-owned key", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Delete Org", "delete-org")
		k := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
		d := inst.mustCall("deleteApiKey", map[string]any{"keyId": k["id"], "configId": "org-keys"}, s.headers)
		eq(t, d["success"], true)
		eq(t, inst.verify(map[string]any{"key": k["key"], "configId": "org-keys"})["valid"], false)
	})

	t.Run("should update org-owned key", func(t *testing.T) {
		s := inst.signInWithTestUser()
		orgID := inst.createOrg(s.headers, "Update Org", "update-org")
		k := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID, "name": "original-name"}, s.headers)
		u := inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "name": "updated-name", "enabled": false, "configId": "org-keys"}, s.headers)
		eq(t, u["name"], "updated-name")
		eq(t, u["enabled"], false)
		eq(t, u["configId"], "org-keys")
		eq(t, u["referenceId"], orgID)
	})
}

// Port of packages/api-key/src/org-api-key.test.ts.
func TestOrganizationAPIKeys(t *testing.T) {
	slug := func(p string) string { return fmt.Sprintf("%s-%d", p, time.Now().UnixNano()) }

	t.Run("basic organization ownership", func(t *testing.T) {
		inst := newInstance(t, userAndOrgConfigs, nil, orgPlugin(organization.Options{}))

		t.Run("organization owner should have full CRUD access to API keys", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Owner CRUD Org", slug("owner-crud"))
			c := expectOK(t, inst.clientCreate(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers))
			eq(t, c["referenceId"], orgID)
			eq(t, c["configId"], "org-keys")
			l := expectOK(t, inst.clientList(q("organizationId", orgID), s.headers))
			if len(l["apiKeys"].([]any)) == 0 {
				t.Fatal("expected keys")
			}
			g := expectOK(t, inst.clientGet(q("id", str(c["id"]), "configId", "org-keys"), s.headers))
			eq(t, g["id"], c["id"])
			u := expectOK(t, inst.clientUpdate(map[string]any{"keyId": c["id"], "configId": "org-keys", "name": "Updated Key"}, s.headers))
			eq(t, u["name"], "Updated Key")
			expectOK(t, inst.clientDelete(map[string]any{"keyId": c["id"], "configId": "org-keys"}, s.headers))
		})

		t.Run("non-member should be denied access to organization API keys", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Non Member Org", slug("non-member"))
			ok := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
			email := fmt.Sprintf("non-member-%d@test.com", time.Now().UnixNano())
			inst.signUp(email, "password123", "Non Member")
			nm := inst.signIn(email, "password123").headers
			expectStatus(t, inst.clientList(q("organizationId", orgID), nm), 403, ErrUserNotMemberOfOrganization.Code)
			expectStatus(t, inst.clientCreate(map[string]any{"configId": "org-keys", "organizationId": orgID}, nm), 403, "")
			expectStatus(t, inst.clientGet(q("id", str(ok["id"]), "configId", "org-keys"), nm), 403, "")
			expectStatus(t, inst.clientUpdate(map[string]any{"keyId": ok["id"], "configId": "org-keys", "name": "Hacked"}, nm), 403, "")
			expectStatus(t, inst.clientDelete(map[string]any{"keyId": ok["id"], "configId": "org-keys"}, nm), 403, "")
		})

		t.Run("member without apiKey permissions should be denied (default roles)", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Default Roles Org", slug("default-roles"))
			mh := inst.addMemberViaInvitation(s.headers, orgID, "member")
			expectStatus(t, inst.clientList(q("organizationId", orgID), mh), 403, ErrInsufficientAPIKeyPermissions.Code)
		})

		t.Run("should correctly separate user and org keys when listing", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Separate Keys Org", slug("separate"))
			uk := inst.createKey(map[string]any{"configId": "user-keys", "userId": s.userID}, nil)
			ok := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
			userIDs := listIDs(expectOK(t, inst.clientList("", s.headers)))
			orgIDs := listIDs(expectOK(t, inst.clientList(q("organizationId", orgID), s.headers)))
			has := func(ids []string, id any) bool {
				for _, x := range ids {
					if x == str(id) {
						return true
					}
				}
				return false
			}
			eq(t, has(userIDs, uk["id"]), true)
			eq(t, has(userIDs, ok["id"]), false)
			eq(t, has(orgIDs, ok["id"]), true)
			eq(t, has(orgIDs, uk["id"]), false)
		})

		t.Run("verify API key should work for organization-owned keys", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Verify Org", slug("verify"))
			k := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
			r := inst.verify(map[string]any{"key": k["key"], "configId": "org-keys"})
			eq(t, r["valid"], true)
			eq(t, obj(r["key"])["configId"], "org-keys")
			eq(t, obj(r["key"])["referenceId"], orgID)
		})
	})

	t.Run("custom apiKey permissions in roles", func(t *testing.T) {
		stmts := access.Statements{"apiKey": {"create", "read", "update", "delete"}}
		for k, v := range organization.DefaultStatements {
			stmts[k] = v
		}
		ac := access.New(stmts)
		with := func(base access.Role, extra access.Statements) access.Role {
			s := access.Statements{}
			for k, v := range base.Statements {
				s[k] = v
			}
			for k, v := range extra {
				s[k] = v
			}
			return ac.NewRole(s)
		}
		all := access.Statements{"apiKey": {"create", "read", "update", "delete"}}
		roles := map[string]access.Role{
			"owner":      with(organization.OwnerAC, all),
			"admin":      with(organization.AdminAC, all),
			"member":     with(organization.MemberAC, access.Statements{"apiKey": {"read"}}),
			"restricted": with(organization.MemberAC, nil),
		}
		inst := newInstance(t, Options{Configurations: []Configuration{
			{ConfigID: "org-keys", DefaultPrefix: "org_", References: ReferencesOrganization},
		}}, nil, orgPlugin(organization.Options{AC: ac, Roles: roles}))

		t.Run("admin role should have full apiKey CRUD permissions", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Admin Test Org", slug("admin-test"))
			ah := inst.addMemberViaInvitation(s.headers, orgID, "admin")
			c := expectOK(t, inst.clientCreate(map[string]any{"configId": "org-keys", "organizationId": orgID}, ah))
			notNil(t, c["id"])
			l := expectOK(t, inst.clientList(q("organizationId", orgID), ah))
			if len(l["apiKeys"].([]any)) == 0 {
				t.Fatal("expected keys")
			}
			u := expectOK(t, inst.clientUpdate(map[string]any{"keyId": c["id"], "configId": "org-keys", "name": "Admin Updated"}, ah))
			eq(t, u["name"], "Admin Updated")
			expectOK(t, inst.clientDelete(map[string]any{"keyId": c["id"], "configId": "org-keys"}, ah))
		})

		t.Run("member role with read-only permission should be limited", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Member Read Org", slug("member-read"))
			ok := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
			mh := inst.addMemberViaInvitation(s.headers, orgID, "member")
			l := expectOK(t, inst.clientList(q("organizationId", orgID), mh))
			if len(l["apiKeys"].([]any)) == 0 {
				t.Fatal("expected keys")
			}
			expectOK(t, inst.clientGet(q("id", str(ok["id"]), "configId", "org-keys"), mh))
			expectStatus(t, inst.clientCreate(map[string]any{"configId": "org-keys", "organizationId": orgID}, mh), 403, ErrInsufficientAPIKeyPermissions.Code)
			expectStatus(t, inst.clientUpdate(map[string]any{"keyId": ok["id"], "configId": "org-keys", "name": "Hacked"}, mh), 403, "")
			expectStatus(t, inst.clientDelete(map[string]any{"keyId": ok["id"], "configId": "org-keys"}, mh), 403, "")
		})

		t.Run("restricted role with no apiKey permissions should be fully denied", func(t *testing.T) {
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Restricted Org", slug("restricted"))
			ok := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
			rh := inst.addMemberViaInvitation(s.headers, orgID, "restricted")
			expectStatus(t, inst.clientList(q("organizationId", orgID), rh), 403, "")
			expectStatus(t, inst.clientGet(q("id", str(ok["id"]), "configId", "org-keys"), rh), 403, "")
			expectStatus(t, inst.clientCreate(map[string]any{"configId": "org-keys", "organizationId": orgID}, rh), 403, "")
			expectStatus(t, inst.clientUpdate(map[string]any{"keyId": ok["id"], "configId": "org-keys", "name": "Hacked"}, rh), 403, "")
			expectStatus(t, inst.clientDelete(map[string]any{"keyId": ok["id"], "configId": "org-keys"}, rh), 403, "")
		})
	})

	t.Run("edge cases", func(t *testing.T) {
		t.Run("should return error when organization plugin is not installed", func(t *testing.T) {
			inst := newInstance(t, Options{Configurations: []Configuration{
				{ConfigID: "org-keys", DefaultPrefix: "org_", References: ReferencesOrganization},
			}}, nil)
			s := inst.signInWithTestUser()
			res := inst.clientCreate(map[string]any{"configId": "org-keys", "organizationId": "fake-org-id"}, s.headers)
			eq(t, res.Status, 500)
		})

		t.Run("should not allow accessing org key with wrong configId", func(t *testing.T) {
			inst := newInstance(t, userAndOrgConfigs, nil, orgPlugin(organization.Options{}))
			s := inst.signInWithTestUser()
			orgID := inst.createOrg(s.headers, "Wrong Config Org", slug("wrong-config"))
			ok := inst.createKey(map[string]any{"configId": "org-keys", "organizationId": orgID}, s.headers)
			eq(t, inst.clientGet(q("id", str(ok["id"]), "configId", "user-keys"), s.headers).Status, 404)
		})
	})
}
