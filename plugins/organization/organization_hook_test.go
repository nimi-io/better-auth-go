package organization

// Port of upstream organization-hook.test.ts ("organization creation in database hooks").

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// ohkCreateOrg is auth.api.createOrganization called from inside a database hook (a server
// call: no headers, explicit userId).
func ohkCreateOrg(ctx context.Context, e *testEnv, body map[string]any) (map[string]any, error) {
	res, err := e.auth.API.Call(ctx, "createOrganization", betterauth.CallInput{Body: body})
	if err != nil {
		return nil, err
	}
	b, err := res.JSON()
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func ohkRows(e *testEnv, model string, keep func(adapter.Record) bool) []adapter.Record {
	var out []adapter.Record
	for _, r := range e.db.Rows(model) {
		if keep == nil || keep(r) {
			out = append(out, r)
		}
	}
	return out
}

func TestOrgHookDatabaseHooks(t *testing.T) {
	t.Run("should create organization in user creation after hook within transaction", func(t *testing.T) {
		var e *testEnv
		hookCalled := false
		var orgCreated map[string]any
		var errInHook error
		e = newEnv(t, Options{}, envConfig{mutate: func(c *betterauth.Config) {
			c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				After: func(ctx context.Context, user adapter.Record) error {
					if user["email"] != "test-hook@example.com" {
						return nil
					}
					hookCalled = true
					id := s(user["id"])
					org, err := ohkCreateOrg(ctx, e, map[string]any{
						"name": s(user["email"]) + "'s Organization", "slug": "org-" + id[:8], "userId": id,
					})
					if err != nil {
						errInHook = err
						return err
					}
					orgCreated = org
					return nil
				},
			}}}
		}})
		r := e.post("/sign-up/email", nil, map[string]any{"email": "test-hook@example.com", "password": "password123", "name": "Test Hook User"})
		expectOK(t, r)
		user, _ := r.m()["user"].(map[string]any)
		if user == nil || user["email"] != "test-hook@example.com" {
			t.Fatalf("result = %v", r.Data)
		}
		if !hookCalled || errInHook != nil || orgCreated == nil {
			t.Fatalf("hookCalled=%v err=%v org=%v", hookCalled, errInHook, orgCreated)
		}
		if orgCreated["name"] != "test-hook@example.com's Organization" || !strings.HasPrefix(s(orgCreated["slug"]), "org-") {
			t.Fatalf("org = %v", orgCreated)
		}
		orgs := ohkRows(e, "organization", func(o adapter.Record) bool { return strings.HasPrefix(s(o["slug"]), "org-") })
		if len(orgs) == 0 || orgs[0]["name"] != "test-hook@example.com's Organization" {
			t.Fatalf("orgs = %v", orgs)
		}
		members := ohkRows(e, "member", func(m adapter.Record) bool { return m["organizationId"] == orgCreated["id"] })
		if len(members) != 1 {
			t.Fatalf("members = %v", members)
		}
		if members[0]["userId"] != user["id"] || members[0]["organizationId"] != orgCreated["id"] || members[0]["role"] != "owner" {
			t.Fatalf("member = %v", members[0])
		}
	})

	t.Run("keeps the committed user and surfaces a post-commit hook failure as the sign-up response", func(t *testing.T) {
		var e *testEnv
		firstUserCreated := false
		e = newEnv(t, Options{}, envConfig{mutate: func(c *betterauth.Config) {
			c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				After: func(ctx context.Context, user adapter.Record) error {
					if !strings.Contains(s(user["email"]), "-hook@") {
						return nil
					}
					if _, err := ohkCreateOrg(ctx, e, map[string]any{
						"name": "Test Org", "slug": "duplicate-test-org", "userId": user["id"],
					}); err != nil {
						return err
					}
					firstUserCreated = true
					return nil
				},
			}}}
		}})
		r1 := e.post("/sign-up/email", nil, map[string]any{"email": "user1-hook@example.com", "password": "password123", "name": "User 1"})
		expectOK(t, r1)
		if u, _ := r1.m()["user"].(map[string]any); u == nil || u["email"] != "user1-hook@example.com" {
			t.Fatalf("r1 = %v", r1.Data)
		}
		if !firstUserCreated {
			t.Fatal("first user hook did not run")
		}
		r2 := e.post("/sign-up/email", nil, map[string]any{"email": "user2-hook@example.com", "password": "password123", "name": "User 2"})
		if r2.Err == nil || r2.code() != "ORGANIZATION_ALREADY_EXISTS" {
			t.Fatalf("r2 = %d %s %v", r2.Status, r2.code(), r2.Data)
		}
		if orgs := ohkRows(e, "organization", func(o adapter.Record) bool { return o["slug"] == "duplicate-test-org" }); len(orgs) != 1 {
			t.Fatalf("orgs = %v", orgs)
		}
		if users := ohkRows(e, "user", func(u adapter.Record) bool { return u["email"] == "user2-hook@example.com" }); len(users) != 1 {
			t.Fatalf("users = %v", users)
		}
	})

	t.Run("should work with multiple async operations in the hook", func(t *testing.T) {
		var e *testEnv
		completed := 0
		foundUser := false
		e = newEnv(t, Options{}, envConfig{mutate: func(c *betterauth.Config) {
			c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				After: func(ctx context.Context, user adapter.Record) error {
					if user["email"] != "async-hook@example.com" {
						return nil
					}
					time.Sleep(10 * time.Millisecond)
					completed++
					if ec := betterauth.EndpointContextFrom(ctx); ec != nil && ec.Auth != nil && ec.Auth.InternalAdapter != nil {
						u, err := ec.Auth.InternalAdapter.FindUserByID(ctx, s(user["id"]))
						foundUser = err == nil && u != nil
					}
					id := s(user["id"])
					if _, err := ohkCreateOrg(ctx, e, map[string]any{
						"name": "Async Org for " + s(user["name"]), "slug": "async-" + id[:8], "userId": id,
					}); err != nil {
						return err
					}
					time.Sleep(10 * time.Millisecond)
					completed++
					return nil
				},
			}}}
		}})
		r := e.post("/sign-up/email", nil, map[string]any{"email": "async-hook@example.com", "password": "password123", "name": "Async User"})
		expectOK(t, r)
		if u, _ := r.m()["user"].(map[string]any); u == nil || u["email"] != "async-hook@example.com" {
			t.Fatalf("result = %v", r.Data)
		}
		if completed != 2 || !foundUser {
			t.Fatalf("completed=%d foundUser=%v", completed, foundUser)
		}
		orgs := ohkRows(e, "organization", func(o adapter.Record) bool { return strings.Contains(s(o["slug"]), "async-") })
		var asyncOrg adapter.Record
		for _, o := range orgs {
			if strings.Contains(s(o["name"]), "Async Org") {
				asyncOrg = o
			}
		}
		if asyncOrg == nil || asyncOrg["name"] != "Async Org for Async User" {
			t.Fatalf("orgs = %v", orgs)
		}
	})

	t.Run("should work when creating organization from before hook", func(t *testing.T) {
		var e *testEnv
		orgID := ""
		e = newEnv(t, Options{}, envConfig{mutate: func(c *betterauth.Config) {
			c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				Before: func(ctx context.Context, user adapter.Record) (*betterauth.DBHookResult, error) {
					data := adapter.Record{}
					for k, v := range user {
						data[k] = v
					}
					data["image"] = "prepared-in-before-hook"
					return &betterauth.DBHookResult{Data: data}, nil
				},
				After: func(ctx context.Context, user adapter.Record) error {
					if user["email"] != "before-hook@example.com" {
						return nil
					}
					id := s(user["id"])
					org, err := ohkCreateOrg(ctx, e, map[string]any{
						"name": "Before-After Org", "slug": "before-after-" + id[:8], "userId": id,
					})
					if err != nil {
						return err
					}
					orgID = s(org["id"])
					return nil
				},
			}}}
		}})
		r := e.post("/sign-up/email", nil, map[string]any{"email": "before-hook@example.com", "password": "password123", "name": "Before Hook User"})
		expectOK(t, r)
		if u, _ := r.m()["user"].(map[string]any); u == nil || u["image"] != "prepared-in-before-hook" {
			t.Fatalf("result = %v", r.Data)
		}
		if orgID == "" {
			t.Fatal("orgId is null")
		}
		orgs := ohkRows(e, "organization", func(o adapter.Record) bool { return o["id"] == orgID })
		if len(orgs) != 1 || orgs[0]["name"] != "Before-After Org" {
			t.Fatalf("orgs = %v", orgs)
		}
	})
}
