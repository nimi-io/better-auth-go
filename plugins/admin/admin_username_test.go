package admin

import (
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/username"
)

// Port of plugins/admin/admin-username.test.ts — describe("admin + username plugin interaction").
func TestAdminUsernameInteraction(t *testing.T) {
	e := newEnv(t, func(c *betterauth.Config) {
		c.Plugins = []*betterauth.Plugin{username.New(username.Options{}), New(Options{BannedUserMessage: "Custom banned user message"})}
		c.DatabaseHooks = nameRoleHook(map[string]string{"Admin": "admin"}, nil)
	}, instanceOpts{testUser: testUser{Name: "Admin"}})
	adminHeaders, _ := e.signInTestUser()

	t.Run("should normalize username when creating user via admin endpoint", func(t *testing.T) {
		res := e.mustCall("createUser", map[string]any{"email": "testuser1@example.com", "password": "some-secure-password",
			"name": "James Smith", "role": "user", "data": map[string]any{"username": "JamesSmith"}}, nil, nil)
		if u := res["user"].(map[string]any); u["username"] != "jamessmith" {
			t.Fatalf("%v", u)
		}
	})
	t.Run("should reject duplicate username when creating user via admin endpoint", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"email": "testuser2@example.com", "password": "some-secure-password",
			"name": "James Smith 2", "role": "user", "data": map[string]any{"username": "JamesSmith"}}, adminHeaders)
		if res.code(t) != username.ErrUsernameIsAlreadyTaken.Code {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("should auto-populate displayUsername when creating user via admin endpoint", func(t *testing.T) {
		res := e.mustCall("createUser", map[string]any{"email": "testuser3@example.com", "password": "some-secure-password",
			"name": "Test User 3", "role": "user", "data": map[string]any{"username": "TestUser3"}}, nil, nil)
		u := res["user"].(map[string]any)
		if u["username"] != "testuser3" || u["displayUsername"] != "TestUser3" {
			t.Fatalf("%v", u)
		}
	})
	t.Run("should validate username format when creating user via admin endpoint", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"email": "testuser4@example.com", "password": "some-secure-password",
			"name": "Test User 4", "role": "user", "data": map[string]any{"username": "Invalid Username!"}}, adminHeaders)
		if res.code(t) != username.ErrInvalidUsername.Code {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("should validate username length when creating user via admin endpoint", func(t *testing.T) {
		res := e.post("/admin/create-user", map[string]any{"email": "testuser5@example.com", "password": "some-secure-password",
			"name": "Test User 5", "role": "user", "data": map[string]any{"username": "ab"}}, adminHeaders)
		if res.code(t) != username.ErrUsernameTooShort.Code {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
}
