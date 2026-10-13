package betterauth

import "github.com/nimi-io/better-auth-go/jsonx"

// NewAPIKeySessionResult builds a get-session payload for sw rendered as `rendered`. The
// api-key plugin answers /get-session from a before hook with the session it derives
// from an API key; returning a *SessionResult keeps API.GetSession, ResolveSession and
// GetSessionFromCtx working for such sessions.
func NewAPIKeySessionResult(sw *SessionWithUser, rendered *jsonx.Object) *SessionResult {
	return &SessionResult{SessionWithUser: sw, json: rendered}
}
