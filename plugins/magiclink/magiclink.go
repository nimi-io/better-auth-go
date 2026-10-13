// Package magiclink is the magic link plugin (packages/better-auth/src/plugins/magic-link):
// passwordless sign-in through a single-use link sent by email.
package magiclink

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// SendMagicLinkData is passed to Options.SendMagicLink.
type SendMagicLinkData struct {
	Email string
	URL   string
	Token string
	// Metadata is the optional metadata sent with the sign-in request (nil when absent).
	Metadata map[string]any
}

// StoreToken selects how tokens are stored in the verification table. The zero value
// stores the plain token.
type StoreToken struct {
	// Mode is "plain" (default) or "hashed" (SHA-256, base64url). Ignored when Hash is set.
	Mode string
	// Hash is a custom hasher ({ type: "custom-hasher", hash } upstream).
	Hash func(token string) (string, error)
}

// RateLimit overrides the plugin rate limit (default 5 requests per 60 seconds).
type RateLimit struct {
	Window time.Duration
	Max    int
}

// Options configures the plugin (MagicLinkOptions).
type Options struct {
	// ExpiresIn is the token lifetime (default 5 minutes).
	ExpiresIn time.Duration
	// AllowedAttempts is ignored: tokens are consumed atomically on the first verification.
	// Any value other than 0 or 1 logs a warning.
	AllowedAttempts int
	// SendMagicLink delivers the link (required). ctx is the current endpoint context.
	SendMagicLink func(ctx *betterauth.EndpointContext, data SendMagicLinkData) error
	// DisableSignUp prevents creating users from magic links.
	DisableSignUp bool
	RateLimit     *RateLimit
	// GenerateToken overrides token generation (default 32 random letters).
	GenerateToken func(email string) (string, error)
	StoreToken    StoreToken
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

func identifier(stored string) string { return "magic-link:" + stored }

// parseRecord validates a stored verification value: a strict object
// {type: "magic-link", email, name?}.
func parseRecord(value string) (email, name string, ok bool) {
	var m map[string]any
	if err := json.Unmarshal([]byte(value), &m); err != nil || m == nil {
		return "", "", false
	}
	for k := range m {
		switch k {
		case "type", "email", "name":
		default:
			return "", "", false
		}
	}
	if m["type"] != "magic-link" {
		return "", "", false
	}
	email, _ = m["email"].(string)
	if !validate.IsEmail(email) {
		return "", "", false
	}
	if v, has := m["name"]; has {
		s, isStr := v.(string)
		if !isStr {
			return "", "", false
		}
		name = s
	}
	return email, name, true
}

var signInBody = validate.Object(
	validate.F("email", validate.Email()),
	validate.F("name", validate.Optional(validate.String())),
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("newUserCallbackURL", validate.Optional(validate.String())),
	validate.F("errorCallbackURL", validate.Optional(validate.String())),
	validate.F("metadata", validate.Optional(validate.Record(validate.Any()))),
)

var verifyQuery = validate.Object(
	validate.F("token", validate.String()),
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("errorCallbackURL", validate.Optional(validate.String())),
	validate.F("newUserCallbackURL", validate.Optional(validate.String())),
)

// New creates the magic link plugin (magicLink).
func New(opts Options) *betterauth.Plugin {
	o := &opts
	if o.AllowedAttempts != 0 && o.AllowedAttempts != 1 {
		fmt.Fprintln(os.Stderr, "[better-auth/magic-link] `allowedAttempts` is ignored: tokens are consumed atomically on the first verification call. Any value other than `1` has no effect; remove the option to silence this warning.")
	}
	window, max := 60*time.Second, 5
	if o.RateLimit != nil {
		if o.RateLimit.Window > 0 {
			window = o.RateLimit.Window
		}
		if o.RateLimit.Max > 0 {
			max = o.RateLimit.Max
		}
	}
	return &betterauth.Plugin{
		ID:        "magic-link",
		Endpoints: []*betterauth.Endpoint{signInEndpoint(o), verifyEndpoint(o)},
		RateLimit: []betterauth.PluginRateLimit{{Window: window, Max: max, PathMatcher: func(p string) bool {
			return hasPrefix(p, "/sign-in/magic-link") || hasPrefix(p, "/magic-link/verify")
		}}},
		Options: o,
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func signInEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "signInMagicLink", Path: "/sign-in/magic-link", Methods: []string{"POST"},
		RequireHeaders: true,
		Use:            []betterauth.Middleware{betterauth.FormCSRFMiddleware},
		Body:           signInBody,
		Metadata:       metaSignIn,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			a := ctx.Auth
			body := ctx.BodyMap()
			email := ctx.BodyString("email")
			var token string
			if o.GenerateToken != nil {
				t, err := o.GenerateToken(email)
				if err != nil {
					return nil, err
				}
				token = t
			} else {
				token = bacrypto.RandomStringFrom(32, bacrypto.AlphaLower, bacrypto.AlphaUpper)
			}
			stored, err := o.storeToken(token)
			if err != nil {
				return nil, err
			}
			var name any = jsonx.Undefined
			if n, ok := body["name"].(string); ok {
				name = n
			}
			value, err := jsonx.Stringify(jsonx.O("type", "magic-link", "email", email, "name", name))
			if err != nil {
				return nil, err
			}
			expiresIn := o.ExpiresIn
			if expiresIn == 0 {
				expiresIn = 5 * time.Minute
			}
			if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), identifier(stored), value, time.Now().Add(expiresIn), nil); err != nil {
				return nil, err
			}
			base, err := url.Parse(a.BaseURL)
			if err != nil {
				return nil, err
			}
			pathname := base.EscapedPath()
			if pathname == "/" {
				pathname = ""
			}
			basePath := ""
			if pathname == "" {
				basePath = a.Options.BasePath
			}
			origin := base.Scheme + "://" + base.Host
			u, err := betterauth.MagicLinkResolveURL(pathname+basePath+"/magic-link/verify", origin)
			if err != nil {
				return nil, err
			}
			cb := ctx.BodyString("callbackURL")
			if cb == "" {
				cb = "/"
			}
			kv := []string{"token", token, "callbackURL", cb}
			if v := ctx.BodyString("newUserCallbackURL"); v != "" {
				kv = append(kv, "newUserCallbackURL", v)
			}
			if v := ctx.BodyString("errorCallbackURL"); v != "" {
				kv = append(kv, "errorCallbackURL", v)
			}
			if u, err = betterauth.MagicLinkSetSearchParams(u, kv...); err != nil {
				return nil, err
			}
			var metadata map[string]any
			if m, ok := body["metadata"].(map[string]any); ok {
				metadata = m
			}
			if err := o.SendMagicLink(ctx, SendMagicLinkData{Email: email, URL: u, Token: token, Metadata: metadata}); err != nil {
				return nil, err
			}
			return jsonx.O("status", true), nil
		},
	}
}

// decodedQuery returns decodeURIComponent(query[key]) or fallback when absent.
func decodedQuery(ctx *betterauth.EndpointContext, key, fallback string) (string, error) {
	v := ctx.QueryString(key)
	if v == "" {
		return fallback, nil
	}
	return betterauth.DecodeURIComponent(v)
}

func originCheckQuery(key string) betterauth.Middleware {
	return func(ctx *betterauth.EndpointContext) error {
		v, err := decodedQuery(ctx, key, "/")
		if err != nil {
			return err
		}
		return betterauth.OriginCheck(func(*betterauth.EndpointContext) []string { return []string{v} })(ctx)
	}
}

func verifyEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "magicLinkVerify", Path: "/magic-link/verify", Methods: []string{"GET"},
		Query:          verifyQuery,
		Use:            []betterauth.Middleware{originCheckQuery("callbackURL"), originCheckQuery("newUserCallbackURL"), originCheckQuery("errorCallbackURL")},
		RequireHeaders: true,
		Metadata:       metaVerify,
		Handler:        func(ctx *betterauth.EndpointContext) (any, error) { return verify(ctx, o) },
	}
}

func verify(ctx *betterauth.EndpointContext, o *Options) (any, error) {
	a := ctx.Auth
	ia := a.InternalAdapter
	c := ctx.Context()
	token := ctx.QueryString("token")
	cbRaw, err := decodedQuery(ctx, "callbackURL", "/")
	if err != nil {
		return nil, err
	}
	callbackURL, err := betterauth.MagicLinkResolveURL(cbRaw, a.BaseURL)
	if err != nil {
		return nil, err
	}
	errRaw, err := decodedQuery(ctx, "errorCallbackURL", callbackURL)
	if err != nil {
		return nil, err
	}
	errorCallbackURL, err := betterauth.MagicLinkResolveURL(errRaw, a.BaseURL)
	if err != nil {
		return nil, err
	}
	redirectWithError := func(code, description string) error {
		kv := []string{"error", code}
		if description != "" {
			kv = append(kv, "error_description", description)
		}
		u, err := betterauth.MagicLinkSetSearchParams(errorCallbackURL, kv...)
		if err != nil {
			return err
		}
		return ctx.Redirect(u)
	}
	newRaw, err := decodedQuery(ctx, "newUserCallbackURL", callbackURL)
	if err != nil {
		return nil, err
	}
	newUserCallbackURL, err := betterauth.MagicLinkResolveURL(newRaw, a.BaseURL)
	if err != nil {
		return nil, err
	}
	stored, err := o.storeToken(token)
	if err != nil {
		return nil, err
	}
	id := identifier(stored)
	pending, err := ia.FindVerificationValue(c, id)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, redirectWithError("INVALID_TOKEN", "")
	}
	if _, _, ok := parseRecord(pending.Value); !ok {
		return nil, redirectWithError("INVALID_TOKEN", "")
	}
	consumed, err := ia.ConsumeVerificationValue(c, id)
	if err != nil {
		return nil, err
	}
	if consumed == nil {
		return nil, redirectWithError("INVALID_TOKEN", "")
	}
	email, name, ok := parseRecord(consumed.Value)
	if !ok {
		return nil, redirectWithError("INVALID_TOKEN", "")
	}
	isNewUser := false
	var user *betterauth.User
	found, err := ia.FindUserByEmail(c, email, false)
	if err != nil {
		return nil, err
	}
	if found != nil {
		user = found.User
	}
	if user == nil {
		if o.DisableSignUp {
			return nil, redirectWithError("new_user_signup_disabled", "")
		}
		created, err := ia.CreateUser(c, map[string]any{"email": email, "emailVerified": true, "name": name, "image": nil}, betterauth.UserInfoSource{Method: "magic-link"})
		if err != nil {
			if e, ok := betterauth.AsAPIError(err); ok && e.Code() != "" {
				return nil, redirectWithError(e.Code(), e.Message())
			}
			return nil, err
		}
		isNewUser = true
		user = created
		if user == nil {
			return nil, redirectWithError("failed_to_create_user", "")
		}
	}
	if !user.EmailVerified {
		promoted, err := betterauth.RevokeUnprovenAccountAccess(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if promoted == nil {
			return nil, redirectWithError("user_not_found", "")
		}
		user = promoted
	}
	session, err := ia.CreateSession(c, user.ID, nil)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, redirectWithError("failed_to_create_session", "")
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, nil, nil); err != nil {
		return nil, err
	}
	if ctx.QueryString("callbackURL") == "" {
		return jsonx.O("token", session.Token, "user", a.UserOutput(user), "session", a.SessionOutput(session)), nil
	}
	if isNewUser {
		return nil, ctx.Redirect(newUserCallbackURL)
	}
	return nil, ctx.Redirect(callbackURL)
}

var (
	metaSignIn = map[string]any{"openapi": jsonx.O(
		"operationId", "signInWithMagicLink",
		"description", "Sign in with magic link",
		"responses", jsonx.O("200", jsonx.O("description", "Success", "content", jsonx.O("application/json", jsonx.O("schema",
			jsonx.O("type", "object", "properties", jsonx.O("status", jsonx.O("type", "boolean"))))))),
	)}
	metaVerify = map[string]any{"openapi": jsonx.O(
		"operationId", "verifyMagicLink",
		"description", "Verify magic link",
		"responses", jsonx.O("200", jsonx.O("description", "Success", "content", jsonx.O("application/json", jsonx.O("schema",
			jsonx.O("type", "object", "properties", jsonx.O(
				"session", jsonx.O("$ref", "#/components/schemas/Session"),
				"user", jsonx.O("$ref", "#/components/schemas/User"),
			)))))),
	)}
)
