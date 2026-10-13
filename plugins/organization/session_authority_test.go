package organization

// Port of describe("updateSession plugin authority fields") from
// better-auth/src/api/routes/session-api.test.ts. It lives here rather than in betterauth/
// because the core test package cannot import plugins (import cycle).

import (
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/admin"
)

func TestSessionAuthorityUpdateSessionPluginAuthorityFields(t *testing.T) {
	e := newEnv(t, Options{Teams: &TeamsOptions{Enabled: true}}, envConfig{extraPlugins: []*betterauth.Plugin{admin.New(admin.Options{})}})
	for _, field := range []string{"activeOrganizationId", "activeTeamId", "impersonatedBy"} {
		t.Run("should reject forging the "+field+" session field", func(t *testing.T) {
			h := e.signInTestUser()
			r := e.post("/update-session", h, map[string]any{field: "forged-value"})
			if r.Status != 400 {
				t.Fatalf("status = %d %v", r.Status, r.Data)
			}
		})
	}
}
