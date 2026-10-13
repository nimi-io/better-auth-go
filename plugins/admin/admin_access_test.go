package admin

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// Port of admin.test.ts — describe("access control").
func TestAdminAccessControl(t *testing.T) {
	ac := access.New(access.Statements{
		"user":  {"create", "read", "update", "delete", "list", "bulk-delete", "set-role"},
		"order": {"create", "read", "update", "delete", "update-many"},
	})
	roles := map[string]access.Role{
		"admin":   ac.NewRole(access.Statements{"user": {"create", "read", "update", "delete", "list", "set-role"}, "order": {"create", "read", "update", "delete"}}),
		"user":    ac.NewRole(access.Statements{"user": {"read"}, "order": {"read"}}),
		"support": ac.NewRole(access.Statements{"user": {"update"}, "order": {"update"}}),
		"creator": ac.NewRole(access.Statements{"user": {"create"}, "order": {}}),
	}
	opts := Options{AC: ac, Roles: roles}
	e := newEnv(t, func(c *betterauth.Config) {
		c.Plugins = []*betterauth.Plugin{New(opts)}
		c.DatabaseHooks = nameRoleHook(map[string]string{"Admin": "admin", "Support": "support", "Creator": "creator"}, nil)
	}, instanceOpts{testUser: testUser{Name: "Admin"}})
	headers, user := e.signInTestUser()
	userID := user["id"].(string)

	t.Run("should not allow role updates via update-user without user:set-role", func(t *testing.T) {
		supportHeaders := newJar()
		s := e.signUp("support@test.com", "password", "Support", supportHeaders)
		id := s["user"].(map[string]any)["id"]
		ok := e.post("/admin/update-user", map[string]any{"userId": id, "data": map[string]any{"name": "Support Updated"}}, supportHeaders).data(t)
		if ok["name"] != "Support Updated" {
			t.Fatalf("%v", ok)
		}
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": id, "data": map[string]any{"role": "admin"}}, supportHeaders), 403, "")
	})
	t.Run("should reject non-existent roles via update-user", func(t *testing.T) {
		target := e.signUp("role-target@test.com", "password", "Role Target", newJar())
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": target["user"].(map[string]any)["id"], "data": map[string]any{"role": "non-existent-role"}}, headers), 400, "")
	})
	t.Run("should allow role updates via update-user for valid roles with user:set-role", func(t *testing.T) {
		target := e.signUp("role-valid-target@test.com", "password", "Role Valid Target", newJar())
		res := e.post("/admin/update-user", map[string]any{"userId": target["user"].(map[string]any)["id"], "data": map[string]any{"role": "support"}}, headers).data(t)
		if res["role"] != "support" {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should require user:set-role to assign roles via create-user", func(t *testing.T) {
		creatorHeaders := newJar()
		e.signUp("creator@test.com", "password", "Creator", creatorHeaders)
		ok := e.post("/admin/create-user", map[string]any{"name": "Created User", "email": "created-by-creator@test.com", "password": "password"}, creatorHeaders).data(t)
		if ok["user"].(map[string]any)["role"] != "user" {
			t.Fatalf("%v", ok)
		}
		expectStatus(t, e.post("/admin/create-user", map[string]any{"name": "Role Requested User", "email": "role-requested@test.com", "password": "password", "role": "admin"}, creatorHeaders), 403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
		expectStatus(t, e.post("/admin/create-user", map[string]any{"name": "Role Requested User", "email": "role-requested2@test.com", "password": "password", "data": map[string]any{"role": "admin"}}, creatorHeaders), 403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
	})
	t.Run("should reject non-existent roles via create-user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/create-user", map[string]any{"name": "Bad Role User", "email": "bad-role@test.com", "password": "password", "data": map[string]any{"role": "non-existent-role"}}, headers), 400, "")
	})
	t.Run("should apply a validated data.role for callers with user:set-role", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"name": "Data Role User", "email": "data-role@test.com", "password": "password", "data": map[string]any{"role": "support"}}, headers).data(t)
		if res["user"].(map[string]any)["role"] != "support" {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should require user:ban to update ban fields via update-user", func(t *testing.T) {
		h := newJar()
		s := e.signUp("support-ban@test.com", "password", "Support", h)
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": s["user"].(map[string]any)["id"], "data": map[string]any{"banned": true, "banReason": "self-served ban"}}, h), 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
	})
	t.Run("should require user:set-email to update email fields via update-user", func(t *testing.T) {
		h := newJar()
		s := e.signUp("support-email@test.com", "password", "Support", h)
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": s["user"].(map[string]any)["id"], "data": map[string]any{"email": "new-address@example.com", "emailVerified": true}}, h), 403, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL")
	})
	t.Run("should validate on the client", func(t *testing.T) {
		// adminClient().checkRolePermission is hasPermission({role, options, permissions}).
		check := func(role string, p map[string][]string) bool {
			return HasPermission(HasPermissionInput{Role: role, Options: &opts, Permissions: p})
		}
		if !check("admin", map[string][]string{"order": {"create"}}) {
			t.Fatal("admin order:create")
		}
		if !check("admin", map[string][]string{"order": {"create"}, "user": {"read"}}) {
			t.Fatal("admin order:create user:read")
		}
		if check("user", map[string][]string{"user": {"create"}}) {
			t.Fatal("user user:create")
		}
		if check("user", map[string][]string{"order": {"create"}, "user": {"create"}}) {
			t.Fatal("user order:create user:create")
		}
	})
	perm := func(t *testing.T, body map[string]any) bool {
		t.Helper()
		return e.mustCall("userHasPermission", body, nil, nil)["success"].(bool)
	}
	t.Run("should validate using userId", func(t *testing.T) {
		if !perm(t, map[string]any{"userId": userID, "permissions": map[string]any{"user": []any{"create"}}}) {
			t.Fatal("user:create")
		}
		if !perm(t, map[string]any{"userId": userID, "permissions": map[string]any{"user": []any{"create"}, "order": []any{"create"}}}) {
			t.Fatal("user:create order:create")
		}
		if perm(t, map[string]any{"userId": userID, "permissions": map[string]any{"order": []any{"update-many"}}}) {
			t.Fatal("order:update-many")
		}
		if perm(t, map[string]any{"userId": userID, "permissions": map[string]any{"user": []any{"bulk-delete"}, "order": []any{"update-many"}}}) {
			t.Fatal("bulk-delete")
		}
	})
	t.Run("should validate using role", func(t *testing.T) {
		if !perm(t, map[string]any{"role": "admin", "permissions": map[string]any{"user": []any{"create"}}}) {
			t.Fatal("admin user:create")
		}
		if !perm(t, map[string]any{"role": "admin", "permissions": map[string]any{"user": []any{"create"}, "order": []any{"create"}}}) {
			t.Fatal("admin user:create order:create")
		}
		if perm(t, map[string]any{"role": "user", "permissions": map[string]any{"order": []any{"update"}}}) {
			t.Fatal("user order:update")
		}
		if perm(t, map[string]any{"role": "user", "permissions": map[string]any{"order": []any{"update"}, "user": []any{"update"}}}) {
			t.Fatal("user order:update user:update")
		}
	})
	t.Run("should prioritize role over userId when both are provided", func(t *testing.T) {
		id := e.signUp("rolepriority@test.com", "password", "Role Priority Test User", nil)["user"].(map[string]any)["id"]
		if !perm(t, map[string]any{"userId": id, "role": "admin", "permissions": map[string]any{"user": []any{"create"}}}) {
			t.Fatal("role admin")
		}
		if perm(t, map[string]any{"userId": id, "role": "user", "permissions": map[string]any{"user": []any{"create"}}}) {
			t.Fatal("role user")
		}
	})
	t.Run("should check permissions correctly for banned user with role provided", func(t *testing.T) {
		id := e.signUp("bannedwithRole@test.com", "password", "Banned Role Test User", nil)["user"].(map[string]any)["id"]
		e.post("/admin/ban-user", map[string]any{"userId": id, "banReason": "Testing role priority"}, headers)
		if !perm(t, map[string]any{"userId": id, "role": "admin", "permissions": map[string]any{"user": []any{"create"}}}) {
			t.Fatal("with role")
		}
		if perm(t, map[string]any{"userId": id, "permissions": map[string]any{"user": []any{"create"}}}) {
			t.Fatal("without role")
		}
		e.post("/admin/unban-user", map[string]any{"userId": id}, headers)
	})
	t.Run("shouldn't allow to list users", func(t *testing.T) {
		h, _ := e.signInTestUser()
		res := e.get("/admin/list-users", q("limit", "10"), h).data(t)
		if len(users(t, res)) == 0 {
			t.Fatalf("%v", res)
		}
		uh := newJar()
		e.signUp("test2@test.com", "password", "Test User", uh)
		expectStatus(t, e.get("/admin/list-users", q("limit", "2"), uh), 403, "")
	})
	t.Run("should not allow to set multiple non existent user role", func(t *testing.T) {
		created := e.post("/admin/create-user", map[string]any{"name": "Test User mr", "email": "testmr@test.com", "password": "test", "role": []string{"user"}}, headers).data(t)
		u := created["user"].(map[string]any)
		if u["role"] != "user" {
			t.Fatalf("%v", u)
		}
		expectStatus(t, e.post("/admin/set-role", map[string]any{"userId": u["id"], "role": []string{"user", "non-user"}}, headers), 400, ErrNotAllowedToSetNonExistentValue.Code)
		e.post("/admin/remove-user", map[string]any{"userId": u["id"]}, headers)
	})
	t.Run("should not allow to set non existent user role", func(t *testing.T) {
		created := e.post("/admin/create-user", map[string]any{"name": "Test User mr", "email": "testmr@test.com", "password": "test", "role": "user"}, headers).data(t)
		u := created["user"].(map[string]any)
		if u["role"] != "user" {
			t.Fatalf("%v", u)
		}
		expectStatus(t, e.post("/admin/set-role", map[string]any{"userId": u["id"], "role": "non-user"}, headers), 400, ErrNotAllowedToSetNonExistentValue.Code)
		e.post("/admin/remove-user", map[string]any{"userId": u["id"]}, headers)
	})
	t.Run("should throw error when assigning non-existent admin roles", func(t *testing.T) {
		defer func() {
			r := recover()
			err, ok := r.(error)
			if !ok || !strings.Contains(err.Error(), "Invalid admin roles: non-existent-role") {
				t.Fatalf("expected panic, got %v", r)
			}
		}()
		New(Options{AdminRoles: []string{"non-existent-role"}})
	})
	t.Run("should properly type custom roles in createUser", func(t *testing.T) {
		created := e.post("/admin/create-user", map[string]any{"name": "Test User with Support Role", "email": "support-role@test.com", "password": "test", "role": "support"}, headers).data(t)
		u := created["user"].(map[string]any)
		if u["role"] != "support" {
			t.Fatalf("%v", u)
		}
		e.post("/admin/remove-user", map[string]any{"userId": u["id"]}, headers)
	})
}

// Port of admin.test.ts — describe("edge cases: userId validation").
func TestAdminUserIDValidationEdgeCases(t *testing.T) {
	e := newEnv(t, func(c *betterauth.Config) {
		c.Advanced = &betterauth.AdvancedConfig{Database: &betterauth.DatabaseAdvancedConfig{GenerateID: adapter.IDSerial}}
		c.Plugins = []*betterauth.Plugin{New(Options{BannedUserMessage: "Custom banned user message"})}
		c.DatabaseHooks = nameRoleHook(map[string]string{"Admin": "admin"}, func(adapter.Record) adapter.Record {
			return adapter.Record{"emailVerified": true}
		})
	}, instanceOpts{testUser: testUser{Name: "Admin"}})
	adminHeaders, _ := e.signInTestUser()

	t.Run("should allow admin to check permissions with useNumberId", func(t *testing.T) {
		res := e.post("/admin/has-permission", map[string]any{"role": "admin", "permissions": map[string]any{"user": []any{"create"}}}, adminHeaders).data(t)
		if res["success"] != true {
			t.Fatalf("%v", res)
		}
	})
	expectErr := func(t *testing.T, body map[string]any, msg string) {
		t.Helper()
		_, err := e.call("userHasPermission", body, nil, nil)
		var apiErr *betterauth.APIError
		if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message(), msg) {
			t.Fatalf("expected %q, got %v", msg, err)
		}
	}
	t.Run("should return correct error when userId is missing and not call DB with undefined", func(t *testing.T) {
		expectErr(t, map[string]any{"permissions": map[string]any{"user": []any{"list"}}}, "user id or role is required")
	})
	t.Run("should return user not found when userId is empty string", func(t *testing.T) {
		expectErr(t, map[string]any{"userId": "", "permissions": map[string]any{"user": []any{"list"}}}, "user id or role is required")
	})
	t.Run("should not crash if userId is 'NaN'", func(t *testing.T) {
		expectErr(t, map[string]any{"userId": "NaN", "permissions": map[string]any{"user": []any{"list"}}}, "user not found")
	})
}

// Port of admin.test.ts — describe("Admin plugin id-token sign-in").
func TestAdminIDTokenSignIn(t *testing.T) {
	const clientID = "admin-idtoken-client.googleusercontent.com"
	mock := oauth2test.New(t)
	mock.ServeJWKS("GET www.googleapis.com/oauth2/v3/certs")

	t.Run("should return BANNED_USER 403 JSON for id-token sign-in by banned user", func(t *testing.T) {
		e := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{BannedUserMessage: "Custom banned user message"})}
			c.SocialProviders = nil
			c.SocialProviders = append(c.SocialProviders, googleProvider(clientID, "test-secret"))
			c.DatabaseHooks = &betterauth.DatabaseHooks{User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
				Before: func(context.Context, adapter.Record) (*betterauth.DBHookResult, error) {
					return &betterauth.DBHookResult{Data: adapter.Record{"emailVerified": true, "banned": true}}, nil
				},
			}}}
		}, instanceOpts{disableTestUser: true})
		tok := mock.IDToken(map[string]any{
			"email": "banned-idtoken@test.com", "email_verified": true, "name": "Banned ID Token User",
			"sub": "banned-google-sub", "iss": "https://accounts.google.com", "aud": clientID,
		})
		res := e.post("/sign-in/social", map[string]any{"provider": "google", "idToken": map[string]any{"token": tok}}, nil)
		expectStatus(t, res, 403, "BANNED_USER")
		if res.message() != "Custom banned user message" {
			t.Fatalf("%s", res.Body)
		}
	})
}

// Port of admin.test.ts — describe("admin createUser validateUserInfo provisioning gate").
func TestAdminCreateUserValidateUserInfo(t *testing.T) {
	e := newEnv(t, func(c *betterauth.Config) {
		c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, user map[string]any, source betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
			if source.Method != "admin" {
				return nil, nil
			}
			if source.Action != "create-user" {
				t.Errorf("action = %q", source.Action)
			}
			if email, _ := user["email"].(string); strings.HasSuffix(email, "@blocked.com") {
				return &betterauth.ValidateUserInfoResult{Error: "admin_create_blocked", ErrorDescription: "This email domain is not allowed"}, nil
			}
			return nil, nil
		}}
		c.Plugins = []*betterauth.Plugin{New(Options{})}
		c.DatabaseHooks = nameRoleHook(map[string]string{"Admin": "admin"}, nil)
	}, instanceOpts{testUser: testUser{Name: "Admin"}})
	adminHeaders, _ := e.signInTestUser()

	t.Run("rejects an admin-created user when validateUserInfo returns error", func(t *testing.T) {
		expectStatus(t, e.post("/admin/create-user", map[string]any{"name": "Blocked User", "email": "new@blocked.com", "password": "password", "role": "user"}, adminHeaders), 403, "admin_create_blocked")
	})
	t.Run("allows an admin-created user that passes validation", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"name": "Allowed User", "email": "ok@allowed.com", "password": "password", "role": "user"}, adminHeaders).data(t)
		if res["user"].(map[string]any)["email"] != "ok@allowed.com" {
			t.Fatalf("%v", res)
		}
	})
}

// Port of admin.test.ts — describe("admin authorization is revocation-aware with cookie cache").
func TestAdminRevocationAwareWithCookieCache(t *testing.T) {
	preload := &betterauth.Plugin{ID: "preload-cached-session", Hooks: betterauth.PluginHooks{Before: []betterauth.Hook{{
		Matcher: func(ctx *betterauth.EndpointContext) bool { return strings.HasPrefix(ctx.Path, "/admin/") },
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			_, err := betterauth.GetSessionFromCtx(ctx, nil)
			return nil, err
		},
	}}}}
	e := newEnv(t, func(c *betterauth.Config) {
		c.Plugins = []*betterauth.Plugin{preload, New(Options{})}
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, MaxAge: 300 * time.Second}}
		c.DatabaseHooks = nameRoleHook(map[string]string{"Admin": "admin"}, func(adapter.Record) adapter.Record {
			return adapter.Record{"emailVerified": true}
		})
	}, instanceOpts{testUser: testUser{Name: "Admin"}})
	rootHeaders, _ := e.signInTestUser()

	t.Run("should reject privileged calls from a demoted admin holding a cached admin snapshot", func(t *testing.T) {
		attackerID := e.signUp("attacker-demote@test.com", "password", "Admin", nil)["user"].(map[string]any)["id"]
		victimID := e.signUp("victim-demote@test.com", "password", "Victim", nil)["user"].(map[string]any)["id"]
		attacker, _ := e.signIn("attacker-demote@test.com", "password")
		demote := e.post("/admin/set-role", map[string]any{"userId": attackerID, "role": "user"}, rootHeaders).data(t)
		if demote["user"].(map[string]any)["role"] != "user" {
			t.Fatalf("%v", demote)
		}
		cached := e.get("/get-session", nil, attacker.clone()).data(t)
		if cached["user"].(map[string]any)["role"] != "admin" {
			t.Fatalf("cached role %v", cached["user"])
		}
		expectStatus(t, e.post("/admin/set-role", map[string]any{"userId": attackerID, "role": "admin"}, attacker.clone()), 403, "")
		pc := e.post("/admin/has-permission", map[string]any{"permissions": map[string]any{"user": []any{"set-role"}}}, attacker.clone()).data(t)
		if pc["success"] != false {
			t.Fatalf("%v", pc)
		}
		expectStatus(t, e.post("/admin/impersonate-user", map[string]any{"userId": victimID}, attacker.clone()), 403, "")
		live := e.get("/get-session", q("disableCookieCache", "true"), attacker.clone()).data(t)
		if live["user"].(map[string]any)["role"] != "user" {
			t.Fatalf("live role %v", live["user"])
		}
	})
	t.Run("should reject a banned admin within the cookie-cache window", func(t *testing.T) {
		attackerID := e.signUp("attacker-ban@test.com", "password", "Admin", nil)["user"].(map[string]any)["id"]
		attacker, _ := e.signIn("attacker-ban@test.com", "password")
		ban := e.post("/admin/ban-user", map[string]any{"userId": attackerID}, rootHeaders).data(t)
		if ban["user"].(map[string]any)["banned"] != true {
			t.Fatalf("%v", ban)
		}
		expectStatus(t, e.get("/admin/list-users", q("limit", "10"), attacker), 401, "")
	})
}

// Port of admin.test.ts — describe("admin create-user password length").
func TestAdminCreateUserPasswordLength(t *testing.T) {
	var hashCalls atomic.Int32
	e := newEnv(t, func(c *betterauth.Config) {
		c.EmailAndPassword = &betterauth.EmailAndPasswordConfig{Enabled: true, Password: &betterauth.PasswordConfig{
			Hash: func(pw string) (string, error) {
				hashCalls.Add(1)
				return "hashed:" + pw, nil
			},
			Verify: func(hash, pw string) (bool, error) { return hash == "hashed:"+pw, nil },
		}}
		c.Plugins = []*betterauth.Plugin{New(Options{})}
	}, instanceOpts{})

	t.Run("should reject a password longer than maxPasswordLength before hashing", func(t *testing.T) {
		hashCalls.Store(0)
		_, err := e.call("createUser", map[string]any{"email": "long-password@test.com", "password": strings.Repeat("x", 129), "name": "Long Password"}, nil, nil)
		var apiErr *betterauth.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != "BAD_REQUEST" || apiErr.Code() != "PASSWORD_TOO_LONG" {
			t.Fatalf("err = %v", err)
		}
		if hashCalls.Load() != 0 {
			t.Fatal("hash must not be called")
		}
	})
}
