package admin

import (
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

// has-permission body validation (z.object(...).and(z.xor([...]))) wording.
func TestHasPermissionBodyValidation(t *testing.T) {
	e := newEnv(t, func(c *betterauth.Config) { c.Plugins = append(c.Plugins, New(Options{})) }, instanceOpts{disableTestUser: true})
	for _, c := range []struct {
		name string
		body map[string]any
		msg  string
	}{
		{"none", map[string]any{}, "[body] Invalid input"},
		{"both", map[string]any{"permission": map[string]any{"user": []any{"list"}}, "permissions": map[string]any{"user": []any{"list"}}}, "[body] Invalid input: more than one option matched"},
		{"singular", map[string]any{"role": "admin", "permission": map[string]any{"user": []any{"list"}}}, "invalid permission check. no permission(s) were passed."},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := e.post("/admin/has-permission", c.body, nil)
			if res.Status != 400 || res.message() != c.msg {
				t.Fatalf("%d %s", res.Status, res.Body)
			}
		})
	}
}
