package admin

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// Port of plugins/admin/admin.test.ts — describe("Admin plugin"). The cases share one
// instance and run in order, like the upstream suite.
func TestAdminPlugin(t *testing.T) {
	mock := oauth2test.New(t)
	googleToken := func() {
		mock.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{
			"access_token": "test", "refresh_token": "test",
			"id_token": mock.IDToken(map[string]any{
				"email": "user@email.com", "email_verified": true, "name": "First Last",
				"picture": "https://lh3.googleusercontent.com/a-/AOh14GjQ4Z7Vw", "sub": "1234567890",
				"aud": "test", "azp": "test", "iss": "test", "locale": "en", "given_name": "First", "family_name": "Last",
			}),
		})
	}
	googleToken()

	e := newEnv(t, func(c *betterauth.Config) {
		c.TrustedOrigins = []string{"https://frontend.example.com"}
		c.Plugins = []*betterauth.Plugin{New(Options{
			BannedUserMessageFunc: func(_ context.Context, u *betterauth.User) (string, error) {
				if r, _ := u.Get("banReason").(string); r != "" {
					return "Banned: " + r, nil
				}
				return "Custom banned user message", nil
			},
		})}
		c.DatabaseHooks = nameRoleHook(map[string]string{"Admin": "admin"}, func(adapter.Record) adapter.Record {
			return adapter.Record{"emailVerified": true}
		})
	}, instanceOpts{testUser: testUser{Name: "Admin"}})
	adminHeaders, _ := e.signInTestUser()

	var newUser map[string]any
	newUserID := func() string {
		if newUser == nil {
			return ""
		}
		s, _ := newUser["id"].(string)
		return s
	}
	nonAdmin := e.signUp("user@test.com", "password", "Test User", nil)
	nonAdminID := nonAdmin["user"].(map[string]any)["id"].(string)
	userHeaders, _ := e.signIn("user@test.com", "password")

	t.Run("should allow admin to get user", func(t *testing.T) {
		res := e.get("/admin/get-user", q("id", nonAdminID), adminHeaders)
		if res.data(t)["email"] != "user@test.com" {
			t.Fatalf("%s", res.Body)
		}
	})
	t.Run("should not allow non-admin to get user", func(t *testing.T) {
		expectStatus(t, e.get("/admin/get-user", q("id", nonAdminID), userHeaders), 403, "YOU_ARE_NOT_ALLOWED_TO_GET_USER")
	})
	t.Run("should allow admin to create users", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"name": "Test User", "email": "user@email.com", "password": "test", "role": "user"}, adminHeaders)
		newUser = res.data(t)["user"].(map[string]any)
		if newUser["role"] != "user" {
			t.Fatalf("role %v", newUser["role"])
		}
	})
	t.Run("should allow admin to create users without password", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"name": "Passwordless User", "email": "passwordless@email.com", "role": "user"}, adminHeaders)
		u := res.data(t)["user"].(map[string]any)
		if u["email"] != "passwordless@email.com" || u["name"] != "Passwordless User" || u["role"] != "user" {
			t.Fatalf("%v", u)
		}
		if r := e.post("/sign-in/email", map[string]any{"email": "passwordless@email.com", "password": "anypassword"}, nil); r.Status == 200 {
			t.Fatal("passwordless user must not sign in with a password")
		}
		e.post("/admin/remove-user", map[string]any{"userId": u["id"]}, adminHeaders)
	})
	t.Run("should allow admin to create user with multiple roles", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"name": "Test User mr", "email": "testmr@test.com", "password": "test", "role": []string{"user", "admin"}}, adminHeaders)
		u := res.data(t)["user"].(map[string]any)
		list := e.get("/admin/list-users", q("filterField", "role", "filterOperator", "contains", "filterValue", "admin"), adminHeaders).data(t)
		if n := len(users(t, list)); n != 2 {
			t.Fatalf("users = %d", n)
		}
		if u["role"] != "user,admin" {
			t.Fatalf("role %v", u["role"])
		}
		e.post("/admin/remove-user", map[string]any{"userId": u["id"]}, adminHeaders)
	})
	t.Run("should not allow non-admin to create users", func(t *testing.T) {
		expectStatus(t, e.post("/admin/create-user", map[string]any{"name": "Test User", "email": "test2@test.com", "password": "test", "role": "user"}, userHeaders), 403, "")
	})
	t.Run("should allow admin to list users", func(t *testing.T) {
		if n := len(users(t, e.get("/admin/list-users", q("limit", "2"), adminHeaders).data(t))); n != 2 {
			t.Fatalf("users = %d", n)
		}
	})
	t.Run("should list users with search query", func(t *testing.T) {
		res := e.get("/admin/list-users", q("filterField", "role", "filterOperator", "eq", "filterValue", "admin"), adminHeaders).data(t)
		if res["total"] != float64(1) {
			t.Fatalf("total %v", res["total"])
		}
	})
	t.Run("should not allow non-admin to list users", func(t *testing.T) {
		expectStatus(t, e.get("/admin/list-users", q("limit", "2"), userHeaders), 403, "")
	})
	t.Run("should allow admin to count users", func(t *testing.T) {
		res := e.get("/admin/list-users", q("limit", "2"), adminHeaders).data(t)
		if len(users(t, res)) != 2 || res["total"] != float64(3) {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should allow to sort users by name", func(t *testing.T) {
		res := e.get("/admin/list-users", q("sortBy", "name", "sortDirection", "desc"), adminHeaders).data(t)
		if users(t, res)[0]["name"] != "Test User" {
			t.Fatalf("%v", res)
		}
		res2 := e.get("/admin/list-users", q("sortBy", "name", "sortDirection", "asc"), adminHeaders).data(t)
		if users(t, res2)[0]["name"] != "Admin" {
			t.Fatalf("%v", res2)
		}
	})
	t.Run("should allow offset and limit", func(t *testing.T) {
		res := e.get("/admin/list-users", q("limit", "1", "offset", "1"), adminHeaders).data(t)
		us := users(t, res)
		if len(us) != 1 || us[0]["name"] != "Test User" {
			t.Fatalf("%v", res)
		}
		if res["limit"] != float64(1) || res["offset"] != float64(1) {
			t.Fatalf("limit/offset %v", res)
		}
	})
	t.Run("should allow to search users by name", func(t *testing.T) {
		res := e.get("/admin/list-users", q("searchValue", "Admin", "searchField", "name", "searchOperator", "contains"), adminHeaders).data(t)
		if len(users(t, res)) != 1 {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should allow to filter users by role", func(t *testing.T) {
		e.get("/admin/list-users", q("filterValue", "admin", "filterField", "role", "filterOperator", "eq"), adminHeaders).data(t)
	})
	t.Run("should apply filter when filterValue is defined", func(t *testing.T) {
		temp := e.signUp("falsy-filter-test@test.com", "password", "Falsy Filter Test", nil)
		tempID := temp["user"].(map[string]any)["id"].(string)
		all := e.get("/admin/list-users", nil, adminHeaders).data(t)
		totalBefore := all["total"].(float64)
		if totalBefore < 2 {
			t.Fatalf("total %v", totalBefore)
		}
		e.mustCall("banUser", map[string]any{"userId": tempID}, nil, adminHeaders.header())
		res := e.mustCall("listUsers", nil, map[string]any{"filterField": "banned", "filterOperator": "eq", "filterValue": false}, adminHeaders.header())
		us := users(t, res)
		if float64(len(us)) != totalBefore-1 {
			t.Fatalf("users %d, before %v", len(us), totalBefore)
		}
		for _, u := range us {
			if u["banned"] != false || u["id"] == tempID {
				t.Fatalf("%v", u)
			}
		}
		e.mustCall("unbanUser", map[string]any{"userId": tempID}, nil, adminHeaders.header())
	})
	t.Run("should filter users by id with ne operator", func(t *testing.T) {
		all := e.get("/admin/list-users", nil, adminHeaders).data(t)
		first := users(t, all)[0]["id"].(string)
		res := e.get("/admin/list-users", q("filterValue", first, "filterField", "id", "filterOperator", "ne"), adminHeaders).data(t)
		us := users(t, res)
		if float64(len(us)) != all["total"].(float64)-1 {
			t.Fatalf("%d vs %v", len(us), all["total"])
		}
		for _, u := range us {
			if u["id"] == first {
				t.Fatal("first user returned")
			}
		}
	})
	t.Run("should filter users by _id with ne operator", func(t *testing.T) {
		all := e.get("/admin/list-users", nil, adminHeaders).data(t)
		first := users(t, all)[0]["id"].(string)
		res := e.get("/admin/list-users", q("filterValue", first, "filterField", "_id", "filterOperator", "ne"), adminHeaders).data(t)
		us := users(t, res)
		if float64(len(us)) != all["total"].(float64)-1 {
			t.Fatalf("%d vs %v", len(us), all["total"])
		}
		for _, u := range us {
			if u["id"] == first {
				t.Fatal("first user returned")
			}
		}
	})
	t.Run("should allow to combine search and filter", func(t *testing.T) {
		res := e.get("/admin/list-users", q("filterValue", "admin", "filterField", "role", "filterOperator", "eq",
			"searchValue", "test", "searchField", "email", "searchOperator", "contains"), adminHeaders).data(t)
		us := users(t, res)
		if len(us) != 1 || us[0]["email"] != "test@test.com" {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should allow to set user role", func(t *testing.T) {
		res := e.post("/admin/set-role", map[string]any{"userId": newUserID(), "role": "admin"}, adminHeaders).data(t)
		if res["user"].(map[string]any)["role"] != "admin" {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should allow to set multiple user roles", func(t *testing.T) {
		created := e.post("/admin/create-user", map[string]any{"name": "Test User mr", "email": "testmr@test.com", "password": "test", "role": "user"}, adminHeaders).data(t)
		cu := created["user"].(map[string]any)
		if cu["role"] != "user" {
			t.Fatalf("%v", cu)
		}
		res := e.post("/admin/set-role", map[string]any{"userId": cu["id"], "role": []string{"user", "admin"}}, adminHeaders).data(t)
		if res["user"].(map[string]any)["role"] != "user,admin" {
			t.Fatalf("%v", res)
		}
		e.post("/admin/remove-user", map[string]any{"userId": cu["id"]}, adminHeaders)
	})
	t.Run("should not allow non-admin to set user role", func(t *testing.T) {
		expectStatus(t, e.post("/admin/set-role", map[string]any{"userId": newUserID(), "role": "admin"}, userHeaders), 403, "")
	})
	t.Run("should allow to ban user", func(t *testing.T) {
		res := e.post("/admin/ban-user", map[string]any{"userId": newUserID()}, adminHeaders).data(t)
		if res["user"].(map[string]any)["banned"] != true {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should not allow non-admin to ban user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/ban-user", map[string]any{"userId": newUserID()}, userHeaders), 403, "")
	})
	t.Run("should allow to ban user with reason and expiration", func(t *testing.T) {
		res := e.post("/admin/ban-user", map[string]any{"userId": newUserID(), "banReason": "Test reason", "banExpiresIn": 60 * 60 * 24}, adminHeaders).data(t)
		u := res["user"].(map[string]any)
		if u["banned"] != true || u["banReason"] != "Test reason" || u["banExpires"] == nil {
			t.Fatalf("%v", u)
		}
	})
	t.Run("should not allow banned user to sign in", func(t *testing.T) {
		expectStatus(t, e.post("/sign-in/email", map[string]any{"email": "user@email.com", "password": "test"}, nil), 403, "BANNED_USER")
	})
	socialCallback := func(t *testing.T, body map[string]any) *url.URL {
		t.Helper()
		j := newJar()
		res := e.post("/sign-in/social", body, j)
		u, err := url.Parse(res.data(t)["url"].(string))
		if err != nil {
			t.Fatal(err)
		}
		cb := e.get("/callback/google", q("state", u.Query().Get("state"), "code", "test"), j)
		if cb.Status != 302 {
			t.Fatalf("callback: %d %s", cb.Status, cb.Body)
		}
		loc, err := url.Parse(cb.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return loc
	}
	t.Run("should not allow banned user to sign in with social provider", func(t *testing.T) {
		loc := socialCallback(t, map[string]any{"provider": "google"})
		if !strings.Contains(loc.String(), "error=BANNED_USER") {
			t.Fatalf("location %s", loc)
		}
	})
	t.Run("should redirect banned social sign-in to a cross-origin errorCallbackURL", func(t *testing.T) {
		errorCallbackURL := "https://frontend.example.com/auth-error"
		loc := socialCallback(t, map[string]any{"provider": "google", "errorCallbackURL": errorCallbackURL})
		if loc.Scheme+"://"+loc.Host != "https://frontend.example.com" || loc.Scheme+"://"+loc.Host+loc.Path != errorCallbackURL {
			t.Fatalf("location %s", loc)
		}
		if loc.Query().Get("error") != "BANNED_USER" || loc.Query().Get("error_description") != "Banned: Test reason" {
			t.Fatalf("location %s", loc)
		}
	})
	t.Run("should resolve async banned user message", func(t *testing.T) {
		res := e.post("/sign-in/email", map[string]any{"email": "user@email.com", "password": "test"}, nil)
		if res.message() != "Banned: Test reason" {
			t.Fatalf("%s", res.Body)
		}
	})
	t.Run("should allow banned user to sign in if ban expired", func(t *testing.T) {
		// upstream advances fake timers by the 24h ban; here the stored expiry is moved into the past.
		e.updateRaw("user", []adapter.Where{{Field: "id", Value: newUserID()}}, adapter.Record{"banExpires": time.Now().Add(-time.Second)})
		res := e.post("/sign-in/email", map[string]any{"email": "user@email.com", "password": "test"}, nil)
		if res.data(t)["user"] == nil {
			t.Fatalf("%s", res.Body)
		}
	})
	t.Run("should clear the expired expiration when banning again without a duration", func(t *testing.T) {
		created := e.post("/admin/create-user", map[string]any{"name": "Reban User", "email": "reban@email.com", "password": "test", "role": "user"}, adminHeaders).data(t)
		userID := created["user"].(map[string]any)["id"].(string)
		e.post("/admin/ban-user", map[string]any{"userId": userID, "banExpiresIn": 60 * 60}, adminHeaders).data(t)
		// upstream advances fake timers by 2h past the 1h ban.
		e.updateRaw("user", []adapter.Where{{Field: "id", Value: userID}}, adapter.Record{"banExpires": time.Now().Add(-time.Hour)})
		res := e.post("/admin/ban-user", map[string]any{"userId": userID}, adminHeaders).data(t)
		u := res["user"].(map[string]any)
		if u["banned"] != true {
			t.Fatalf("%v", u)
		}
		if v, ok := u["banExpires"]; !ok || v != nil {
			t.Fatalf("banExpires %v", u)
		}
		expectStatus(t, e.post("/sign-in/email", map[string]any{"email": "reban@email.com", "password": "test"}, nil), 403, "")
	})
	t.Run("should allow to unban user", func(t *testing.T) {
		res := e.post("/admin/unban-user", map[string]any{"userId": newUserID()}, adminHeaders).data(t)
		u := res["user"].(map[string]any)
		if u["banned"] != false || u["banExpires"] != nil || u["banReason"] != nil {
			t.Fatalf("%v", u)
		}
		for _, k := range []string{"banExpires", "banReason"} {
			if _, ok := u[k]; !ok {
				t.Fatalf("%s should be null, got absent", k)
			}
		}
	})
	t.Run("should not allow non-admin to unban user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/unban-user", map[string]any{"userId": newUserID()}, userHeaders), 403, "")
	})
	t.Run("should allow admin to list user sessions", func(t *testing.T) {
		res := e.post("/admin/list-user-sessions", map[string]any{"userId": newUserID()}, adminHeaders).data(t)
		if n := len(res["sessions"].([]any)); n != 1 {
			t.Fatalf("sessions = %d", n)
		}
	})
	t.Run("should return 404 from unbanUser when the target user does not exist", func(t *testing.T) {
		expectStatus(t, e.post("/admin/unban-user", map[string]any{"userId": "nonexistent-user-id"}, adminHeaders), 404, "USER_NOT_FOUND")
	})
	t.Run("should return 404 from banUser when the target user does not exist", func(t *testing.T) {
		expectStatus(t, e.post("/admin/ban-user", map[string]any{"userId": "nonexistent-user-id"}, adminHeaders), 404, "USER_NOT_FOUND")
	})
	t.Run("should return 404 from setRole when the target user does not exist", func(t *testing.T) {
		expectStatus(t, e.post("/admin/set-role", map[string]any{"userId": "nonexistent-user-id", "role": "admin"}, adminHeaders), 404, "USER_NOT_FOUND")
	})
	t.Run("should return 404 from admin.updateUser when the target user does not exist", func(t *testing.T) {
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": "nonexistent-user-id", "data": map[string]any{"name": "John Doe"}}, adminHeaders), 404, "USER_NOT_FOUND")
	})
	t.Run("should not allow non-admin to list user sessions", func(t *testing.T) {
		expectStatus(t, e.post("/admin/list-user-sessions", map[string]any{"userId": newUserID()}, userHeaders), 403, "")
	})

	impersonateHeaders := newJar()
	t.Run("should allow admins to impersonate user", func(t *testing.T) {
		// upstream reads the user id back through a bearer-token get-session (bearer plugin);
		// the sign-up response carries the same id.
		signed := e.signUp("impersonate@mail.com", "password", "Impersonate User", nil)
		uid := signed["user"].(map[string]any)["id"]
		res := e.doTo("POST", "/admin/impersonate-user", map[string]any{"userId": uid}, adminHeaders, impersonateHeaders, nil).data(t)
		if res["session"] == nil || res["user"].(map[string]any)["id"] != uid {
			t.Fatalf("%v", res)
		}
		if res["session"].(map[string]any)["impersonatedBy"] == nil {
			t.Fatalf("impersonatedBy missing: %v", res["session"])
		}
		s := e.get("/get-session", nil, impersonateHeaders).data(t)
		if s["user"].(map[string]any)["id"] != uid {
			t.Fatalf("impersonated session %v", s)
		}
	})
	t.Run("should revalidate useSession after admin impersonation", func(t *testing.T) {
		t.Skip("TS client only: exercises the nanostores useSession atom of the browser client")
	})
	t.Run("should not allow non-admin to impersonate user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/impersonate-user", map[string]any{"userId": newUserID()}, userHeaders), 403, "")
	})
	t.Run("should not allow to impersonate admins without impersonate-admins permission", func(t *testing.T) {
		u := e.signUp("impersonate-admin@mail.com", "password", "Impersonate Admin User", nil)
		uid := u["user"].(map[string]any)["id"]
		e.post("/admin/set-role", map[string]any{"userId": uid, "role": "admin"}, adminHeaders).data(t)
		expectStatus(t, e.post("/admin/impersonate-user", map[string]any{"userId": uid}, adminHeaders), 403, "YOU_CANNOT_IMPERSONATE_ADMINS")
	})
	t.Run("should allow impersonating admins with impersonate-admins permission", func(t *testing.T) {
		ac := access.New(access.Statements{
			"user":    {"create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "get", "update"},
			"session": {"list", "revoke", "delete"},
		})
		superAdmin := ac.NewRole(access.Statements{
			"user":    {"create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "get", "update"},
			"session": {"list", "revoke", "delete"},
		})
		regularAdmin := ac.NewRole(access.Statements{
			"user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "get", "update"},
			"session": {"list", "revoke", "delete"},
		})
		userRole := ac.NewRole(access.Statements{"user": {}, "session": {}})
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{AC: ac, Roles: map[string]access.Role{
				"super-admin": superAdmin, "admin": regularAdmin, "user": userRole,
			}})}
			c.DatabaseHooks = nameRoleHook(map[string]string{"Super Admin": "super-admin"}, nil)
		}, instanceOpts{testUser: testUser{Name: "Super Admin"}})
		superHeaders, _ := e2.signInTestUser()
		target := e2.signUp("target-admin-perm@test.com", "password", "Target Admin Perm", nil)["user"].(map[string]any)
		e2.post("/admin/set-role", map[string]any{"userId": target["id"], "role": "admin"}, superHeaders).data(t)
		res := e2.post("/admin/impersonate-user", map[string]any{"userId": target["id"]}, superHeaders).data(t)
		if res["session"] == nil || res["user"].(map[string]any)["id"] != target["id"] {
			t.Fatalf("%v", res)
		}
		regular := e2.signUp("regular-admin-perm@test.com", "password", "Regular Admin Perm", nil)["user"].(map[string]any)
		e2.post("/admin/set-role", map[string]any{"userId": regular["id"], "role": "admin"}, superHeaders).data(t)
		regularHeaders, _ := e2.signIn("regular-admin-perm@test.com", "password")
		expectStatus(t, e2.post("/admin/impersonate-user", map[string]any{"userId": target["id"]}, regularHeaders), 403, "")
	})
	t.Run("should allow impersonating admins with legacy allowImpersonatingAdmins option", func(t *testing.T) {
		e2 := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{AllowImpersonatingAdmins: true})}
			c.DatabaseHooks = nameRoleHook(map[string]string{"Admin": "admin"}, nil)
		}, instanceOpts{testUser: testUser{Name: "Admin"}})
		h, _ := e2.signInTestUser()
		target := e2.signUp("target-admin-legacy@test.com", "password", "Target Admin Legacy", nil)["user"].(map[string]any)
		e2.post("/admin/set-role", map[string]any{"userId": target["id"], "role": "admin"}, h).data(t)
		res := e2.post("/admin/impersonate-user", map[string]any{"userId": target["id"]}, h).data(t)
		if res["session"] == nil || res["user"].(map[string]any)["id"] != target["id"] {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should filter impersonated sessions", func(t *testing.T) {
		h, _ := e.signIn("impersonate@mail.com", "password")
		var list []any
		res := e.get("/list-sessions", nil, h)
		if res.Status != 200 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
		if err := jsonUnmarshal(res.Body, &list); err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 {
			t.Fatalf("sessions = %d: %s", len(list), res.Body)
		}
	})
	t.Run("should allow admin to stop impersonating", func(t *testing.T) {
		res := e.doTo("POST", "/admin/stop-impersonating", map[string]any{}, impersonateHeaders, impersonateHeaders, nil).data(t)
		if res["session"] == nil {
			t.Fatalf("%v", res)
		}
		after := e.get("/admin/list-users", q("filterField", "role", "filterOperator", "eq", "filterValue", "admin"), impersonateHeaders).data(t)
		if len(users(t, after)) <= 1 {
			t.Fatalf("%v", after)
		}
	})
	t.Run("should allow admin to revoke user session", func(t *testing.T) {
		_, signIn := e.signIn("impersonate@mail.com", "password")
		uid := signIn["user"].(map[string]any)["id"]
		sessions := e.post("/admin/list-user-sessions", map[string]any{"userId": uid}, adminHeaders).data(t)["sessions"].([]any)
		if len(sessions) != 3 {
			t.Fatalf("sessions = %d", len(sessions))
		}
		res := e.post("/admin/revoke-user-session", map[string]any{"sessionToken": sessions[0].(map[string]any)["token"]}, adminHeaders).data(t)
		if res["success"] != true {
			t.Fatalf("%v", res)
		}
		sessions2 := e.post("/admin/list-user-sessions", map[string]any{"userId": uid}, adminHeaders).data(t)["sessions"].([]any)
		if len(sessions2) != 2 {
			t.Fatalf("sessions = %d", len(sessions2))
		}
	})
	t.Run("should not allow non-admin to revoke user sessions", func(t *testing.T) {
		expectStatus(t, e.post("/admin/revoke-user-sessions", map[string]any{"userId": newUserID()}, userHeaders), 403, "")
	})
	t.Run("should allow admin to revoke user sessions", func(t *testing.T) {
		res := e.post("/admin/revoke-user-sessions", map[string]any{"userId": newUserID()}, adminHeaders).data(t)
		if res["success"] != true {
			t.Fatalf("%v", res)
		}
		sessions := e.post("/admin/list-user-sessions", map[string]any{"userId": newUserID()}, adminHeaders).data(t)["sessions"].([]any)
		if len(sessions) != 0 {
			t.Fatalf("sessions = %d", len(sessions))
		}
	})
	t.Run("should list with me", func(t *testing.T) {
		res := e.get("/admin/list-users", q("sortBy", "createdAt", "sortDirection", "desc", "filterField", "role", "filterOperator", "ne", "filterValue", "user"), adminHeaders).data(t)
		us := users(t, res)
		if len(us) < 2 {
			t.Fatalf("%v", res)
		}
		for _, u := range us {
			if u["role"] == "user" {
				t.Fatalf("%v", u)
			}
		}
	})
	t.Run("should allow admin to set user password", func(t *testing.T) {
		res := e.post("/admin/set-user-password", map[string]any{"userId": newUserID(), "newPassword": "newPassword"}, adminHeaders).data(t)
		if res["status"] != true {
			t.Fatalf("%v", res)
		}
		e.post("/sign-in/email", map[string]any{"email": "user@email.com", "password": "newPassword"}, nil).data(t)
	})
	t.Run("should not allow admin to set user password with empty userId", func(t *testing.T) {
		res := e.post("/admin/set-user-password", map[string]any{"userId": "", "newPassword": "newPassword"}, adminHeaders)
		expectStatus(t, res, 400, "VALIDATION_ERROR")
		if res.message() != "[body.userId] userId cannot be empty" {
			t.Fatalf("%s", res.Body)
		}
	})
	t.Run("should not allow admin to set user password with empty new password", func(t *testing.T) {
		res := e.post("/admin/set-user-password", map[string]any{"userId": newUserID(), "newPassword": ""}, adminHeaders)
		expectStatus(t, res, 400, "VALIDATION_ERROR")
		if res.message() != "[body.newPassword] newPassword cannot be empty" {
			t.Fatalf("%s", res.Body)
		}
	})
	t.Run("should not allow admin to set user password with a short new password", func(t *testing.T) {
		res := e.post("/admin/set-user-password", map[string]any{"userId": newUserID(), "newPassword": "1234567"}, adminHeaders)
		expectStatus(t, res, 400, "PASSWORD_TOO_SHORT")
		if res.message() != "Password too short" {
			t.Fatalf("%s", res.Body)
		}
	})
	t.Run("should not allow admin to set user password with a long new password", func(t *testing.T) {
		res := e.post("/admin/set-user-password", map[string]any{"userId": newUserID(), "newPassword": strings.Repeat("a", 129)}, adminHeaders)
		expectStatus(t, res, 400, "PASSWORD_TOO_LONG")
		if res.message() != "Password too long" {
			t.Fatalf("%s", res.Body)
		}
	})
	t.Run("should not allow non-admin to set user password", func(t *testing.T) {
		expectStatus(t, e.post("/admin/set-user-password", map[string]any{"userId": newUserID(), "newPassword": "newPassword"}, userHeaders), 403, "")
	})
	t.Run("should create a credential account when setting password for a user without one", func(t *testing.T) {
		created := e.post("/admin/create-user", map[string]any{"name": "No Credential User", "email": "no-credential@email.com", "role": "user"}, adminHeaders).data(t)
		userID := created["user"].(map[string]any)["id"].(string)
		if userID == "" {
			t.Fatal("no id")
		}
		if r := e.post("/sign-in/email", map[string]any{"email": "no-credential@email.com", "password": "newPassword"}, nil); r.Status == 200 {
			t.Fatal("sign-in should fail before a password is set")
		}
		res := e.post("/admin/set-user-password", map[string]any{"userId": userID, "newPassword": "newPassword"}, adminHeaders).data(t)
		if res["status"] != true {
			t.Fatalf("%v", res)
		}
		post := e.post("/sign-in/email", map[string]any{"email": "no-credential@email.com", "password": "newPassword"}, nil).data(t)
		if post["user"].(map[string]any)["id"] != userID {
			t.Fatalf("%v", post)
		}
		acc, err := e.auth.Context().InternalAdapter.FindCredentialAccount(context.Background(), userID)
		if err != nil || acc == nil || acc.UserID != userID || acc.ProviderID != "credential" || acc.AccountID != userID {
			t.Fatalf("credential account %+v %v", acc, err)
		}
		e.post("/admin/remove-user", map[string]any{"userId": userID}, adminHeaders).data(t)
	})
	t.Run("should return USER_NOT_FOUND when setting password for a non-existent user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/set-user-password", map[string]any{"userId": "non-existent-user-id", "newPassword": "newPassword"}, adminHeaders), 404, "USER_NOT_FOUND")
	})
	t.Run("should allow admin to delete user", func(t *testing.T) {
		res := e.post("/admin/remove-user", map[string]any{"userId": newUserID()}, adminHeaders).data(t)
		if res["success"] != true {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should not allow non-admin to delete user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/remove-user", map[string]any{"userId": newUserID()}, userHeaders), 403, "")
	})
	t.Run("should allow creating users from server", func(t *testing.T) {
		res := e.mustCall("createUser", map[string]any{"email": "test2@test.com", "password": "password", "name": "Test User"}, nil, nil)
		u := res["user"].(map[string]any)
		if u["email"] != "test2@test.com" || u["name"] != "Test User" || u["role"] != "user" {
			t.Fatalf("%v", u)
		}
	})
	t.Run("should allow admin to update user", func(t *testing.T) {
		res := e.post("/admin/update-user", map[string]any{"userId": nonAdminID, "data": map[string]any{
			"name": "Updated Name", "customField": "custom value", "role": []string{"member", "user"},
		}}, adminHeaders).data(t)
		if res["name"] != "Updated Name" || res["role"] != "member,user" {
			t.Fatalf("%v", res)
		}
	})
	t.Run("should not allow non-admin to update user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": nonAdminID, "data": map[string]any{"name": "Unauthorized Update"}}, userHeaders), 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS")
	})
	t.Run("should not allow updating password through update-user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": nonAdminID, "data": map[string]any{"password": "new-password"}}, adminHeaders), 400, "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER")
	})
	t.Run("should revoke sessions when banning a user via update-user", func(t *testing.T) {
		target := e.signUp("ban-via-update@test.com", "password", "Ban Via Update", newJar())
		targetID := target["user"].(map[string]any)["id"]
		res := e.post("/admin/update-user", map[string]any{"userId": targetID, "data": map[string]any{"banned": true, "banReason": "Violation"}}, adminHeaders).data(t)
		if res["banned"] != true {
			t.Fatalf("%v", res)
		}
		sessions := e.post("/admin/list-user-sessions", map[string]any{"userId": targetID}, adminHeaders).data(t)["sessions"].([]any)
		if len(sessions) != 0 {
			t.Fatalf("sessions = %d", len(sessions))
		}
	})
	t.Run("should not allow admins to ban themselves via update-user", func(t *testing.T) {
		s := e.get("/get-session", nil, adminHeaders).data(t)
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": s["user"].(map[string]any)["id"], "data": map[string]any{"banned": true}}, adminHeaders), 400, "YOU_CANNOT_BAN_YOURSELF")
	})
	t.Run("should reject email updates that collide with another user", func(t *testing.T) {
		expectStatus(t, e.post("/admin/update-user", map[string]any{"userId": nonAdminID, "data": map[string]any{"email": "ban-via-update@test.com"}}, adminHeaders), 400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
	})
	t.Run("should allow admin to update user email and normalize it", func(t *testing.T) {
		res := e.post("/admin/update-user", map[string]any{"userId": nonAdminID, "data": map[string]any{"email": "Updated-Email@Test.com", "emailVerified": false}}, adminHeaders).data(t)
		if res["email"] != "updated-email@test.com" || res["emailVerified"] != false {
			t.Fatalf("%v", res)
		}
	})
}
