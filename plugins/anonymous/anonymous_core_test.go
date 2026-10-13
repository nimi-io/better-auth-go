package anonymous

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

// Core tests that need the anonymous plugin. They live here because betterauth cannot
// import plugins (import cycle); the betterauth test skips with a pointer here.

// Port of db/secondary-storage.test.ts — describe("secondary storage - /delete-anonymous-user
// cleans up sessions") (GHSA-2vg6-77g8-24mp).
func TestPortDBSecondaryStorage_DeleteAnonymousUserCleansUpSessions(t *testing.T) {
	store := betterauth.NewMemoryStorage()
	e := newEnv(t, func(c *betterauth.Config) {
		c.Plugins = []*betterauth.Plugin{New(Options{})}
		c.SecondaryStorage = store
	}, instanceOpts{})

	t.Run("should clear secondary storage sessions when an anonymous user calls /delete-anonymous-user", func(t *testing.T) {
		h := newJar()
		e.post("/sign-in/anonymous", nil, h).data(t)
		s := e.get("/get-session", nil, h).data(t)
		token := s["session"].(map[string]any)["token"].(string)
		if _, ok, _ := store.Get(context.Background(), token); !ok {
			t.Fatal("session missing from secondary storage")
		}
		e.mustCall("deleteAnonymousUser", nil, nil, h.header())
		if _, ok, _ := store.Get(context.Background(), token); ok {
			t.Fatal("session still in secondary storage")
		}
		if res := e.get("/get-session", nil, h); string(res.Body) != "null" {
			t.Fatalf("session after delete: %s", res.Body)
		}
	})
}

// Additional coverage of /delete-anonymous-user (no dedicated upstream case).
func TestDeleteAnonymousUser(t *testing.T) {
	t.Run("deletes the anonymous user and clears the session cookie", func(t *testing.T) {
		e := newEnv(t, func(c *betterauth.Config) { c.Plugins = []*betterauth.Plugin{New(Options{})} }, instanceOpts{})
		h := newJar()
		id := e.post("/sign-in/anonymous", nil, h).data(t)["user"].(map[string]any)["id"].(string)
		res := e.post("/delete-anonymous-user", nil, h).data(t)
		if res["success"] != true || e.findUser(id) != nil {
			t.Fatalf("%v", res)
		}
		if _, ok := h.cookies["better-auth.session_token"]; ok {
			t.Fatal("session cookie not cleared")
		}
	})
	t.Run("rejects non-anonymous users", func(t *testing.T) {
		e := newEnv(t, func(c *betterauth.Config) { c.Plugins = []*betterauth.Plugin{New(Options{})} }, instanceOpts{})
		h, _ := e.signInTestUser()
		expectStatus(t, e.post("/delete-anonymous-user", nil, h), 403, "USER_IS_NOT_ANONYMOUS")
	})
	t.Run("rejects when disabled", func(t *testing.T) {
		e := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{DisableDeleteAnonymousUser: true})}
		}, instanceOpts{})
		h := newJar()
		e.post("/sign-in/anonymous", nil, h).data(t)
		expectStatus(t, e.post("/delete-anonymous-user", nil, h), 400, "DELETE_ANONYMOUS_USER_DISABLED")
	})
	t.Run("requires a session", func(t *testing.T) {
		e := newEnv(t, func(c *betterauth.Config) { c.Plugins = []*betterauth.Plugin{New(Options{})} }, instanceOpts{})
		expectStatus(t, e.post("/delete-anonymous-user", nil, nil), 401, "")
	})
	t.Run("uses emailDomainName", func(t *testing.T) {
		e := newEnv(t, func(c *betterauth.Config) {
			c.Plugins = []*betterauth.Plugin{New(Options{EmailDomainName: "example.org"})}
		}, instanceOpts{})
		email := e.post("/sign-in/anonymous", nil, nil).data(t)["user"].(map[string]any)["email"].(string)
		if len(email) < 5 || email[:5] != "temp-" || email[len(email)-12:] != "@example.org" {
			t.Fatalf("email %q", email)
		}
	})
}
