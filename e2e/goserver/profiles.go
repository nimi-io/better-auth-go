package main

import (
	"context"
	"net/http"

	"github.com/nimi-io/better-auth-go/betterauth"
)

// profileEnv is passed to plugin profiles.
type profileEnv struct {
	BaseURL string
	// Mail records messages (emails, OTPs, SMS) for /__test/email; tests read the latest
	// one by recipient and type. Put OTP codes in Token.
	Mail *mailbox
	// Capture returns a sender that records EmailData under the given type.
	Capture func(typ string) func(ctx context.Context, d betterauth.EmailData, r *http.Request) error
}

// profiles holds plugin profiles; each profile_<name>.go registers one in init().
// e2e/servers/profiles/<name>.mjs configures the TypeScript server identically.
var profiles = map[string]func(cfg *betterauth.Config, env profileEnv){}

// testHandlers are extra /__test/* endpoints registered by profiles.
var testHandlers = map[string]func(w http.ResponseWriter, r *http.Request, auth *betterauth.Auth){}

// Record stores a message for /__test/email.
func (m *mailbox) Record(typ, to, url, token string) {
	m.add(email{Type: typ, To: to, URL: url, Token: token})
}
