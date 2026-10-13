// Package onetimetoken is the one-time token plugin
// (packages/better-auth/src/plugins/one-time-token): short-lived, single-use tokens that
// can be exchanged for the session that generated them (e.g. cross-domain hand-off).
package onetimetoken

import (
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// StoreToken selects how tokens are stored in the verification table. The zero value
// stores the plain token.
type StoreToken struct {
	// Mode is "plain" (default) or "hashed" (SHA-256, base64url). Ignored when Hash is set.
	Mode string
	// Hash is a custom hasher ({ type: "custom-hasher", hash } upstream).
	Hash func(token string) (string, error)
}

// Options configures the plugin (OneTimeTokenOptions).
type Options struct {
	// ExpiresIn is the token lifetime (default 3 minutes).
	ExpiresIn time.Duration
	// DisableClientRequest only allows generating tokens from server-side API calls.
	DisableClientRequest bool
	// GenerateToken overrides token generation (default 32 random characters).
	GenerateToken func(session *betterauth.SessionWithUser, ctx *betterauth.EndpointContext) (string, error)
	// DisableSetSessionCookie stops /one-time-token/verify from setting the session cookie.
	DisableSetSessionCookie bool
	StoreToken              StoreToken
	// SetOttHeaderOnNewSession adds a "set-ott" response header with a fresh token
	// whenever a new session is created.
	SetOttHeaderOnNewSession bool
}

// DefaultKeyHasher hashes a token with SHA-256 and encodes it as unpadded base64url.
func DefaultKeyHasher(token string) string {
	return bacrypto.Base64URLNoPad(bacrypto.SHA256([]byte(token)))
}

func (o *Options) storeToken(token string) (string, error) {
	if o.StoreToken.Hash != nil {
		return o.StoreToken.Hash(token)
	}
	if o.StoreToken.Mode == "hashed" {
		return DefaultKeyHasher(token), nil
	}
	return token, nil
}

func (o *Options) generateToken(ctx *betterauth.EndpointContext, s *betterauth.SessionWithUser) (string, error) {
	var token string
	if o.GenerateToken != nil {
		t, err := o.GenerateToken(s, ctx)
		if err != nil {
			return "", err
		}
		token = t
	} else {
		token = bacrypto.RandomString(32)
	}
	expiresIn := 3 * time.Minute
	if o.ExpiresIn != 0 {
		expiresIn = o.ExpiresIn
	}
	stored, err := o.storeToken(token)
	if err != nil {
		return "", err
	}
	if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(ctx.Context(), "one-time-token:"+stored, s.Session.Token, time.Now().Add(expiresIn), nil); err != nil {
		return "", err
	}
	return token, nil
}

// New creates the one-time token plugin (oneTimeToken).
func New(opts Options) *betterauth.Plugin {
	o := &opts
	return &betterauth.Plugin{
		ID: "one-time-token",
		Endpoints: []*betterauth.Endpoint{
			{
				Key: "generateOneTimeToken", Path: "/one-time-token/generate", Methods: []string{"GET"},
				Use: []betterauth.Middleware{betterauth.SessionMiddleware},
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					if o.DisableClientRequest && ctx.Request != nil {
						return nil, betterauth.ErrMessage("BAD_REQUEST", "Client requests are disabled")
					}
					token, err := o.generateToken(ctx, ctx.Session)
					if err != nil {
						return nil, err
					}
					return jsonx.O("token", token), nil
				},
			},
			{
				Key: "verifyOneTimeToken", Path: "/one-time-token/verify", Methods: []string{"POST"},
				Body: validate.Object(validate.F("token", validate.String())),
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					a := ctx.Auth
					stored, err := o.storeToken(ctx.BodyString("token"))
					if err != nil {
						return nil, err
					}
					v, err := a.InternalAdapter.ConsumeVerificationValue(ctx.Context(), "one-time-token:"+stored)
					if err != nil {
						return nil, err
					}
					if v == nil {
						return nil, betterauth.ErrMessage("BAD_REQUEST", "Invalid token")
					}
					s, err := a.InternalAdapter.FindSession(ctx.Context(), v.Value)
					if err != nil {
						return nil, err
					}
					if s == nil {
						return nil, betterauth.ErrMessage("BAD_REQUEST", "Session not found")
					}
					if !o.DisableSetSessionCookie {
						if err := betterauth.SetSessionCookie(ctx, s, nil, nil); err != nil {
							return nil, err
						}
					}
					if s.Session.ExpiresAt.Before(time.Now()) {
						return nil, betterauth.ErrMessage("BAD_REQUEST", "Session expired")
					}
					return jsonx.O("session", a.SessionOutput(s.Session), "user", a.UserOutput(s.User)), nil
				},
			},
		},
		Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(*betterauth.EndpointContext) bool { return true },
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				ns := ctx.NewSession()
				if ns == nil || !o.SetOttHeaderOnNewSession {
					return nil, nil
				}
				var headers []string
				seen := map[string]bool{}
				for _, h := range strings.Split(ctx.ResponseHeaders.Get("Access-Control-Expose-Headers"), ",") {
					h = strings.TrimSpace(h)
					if h != "" && !seen[h] {
						seen[h] = true
						headers = append(headers, h)
					}
				}
				if !seen["set-ott"] {
					headers = append(headers, "set-ott")
				}
				token, err := o.generateToken(ctx, ns)
				if err != nil {
					return nil, err
				}
				ctx.SetHeader("set-ott", token)
				ctx.SetHeader("Access-Control-Expose-Headers", strings.Join(headers, ", "))
				return nil, nil
			},
		}}},
		Options: o,
	}
}
