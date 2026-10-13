// Package twofactor ports the Better Auth two-factor plugin (TOTP, email/SMS OTP, backup
// codes and trusted devices). Data written to the database (encrypted TOTP secrets, backup
// code blobs, verification rows and signed cookies) is byte-compatible with the
// TypeScript implementation, so both can share one database.
package twofactor

import (
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// ID is the plugin id.
const ID = "two-factor"

type plugin struct {
	opts Options
}

// New returns the two-factor plugin.
func New(opts Options) *betterauth.Plugin {
	p := &plugin{opts: opts}
	var endpoints []*betterauth.Endpoint
	endpoints = append(endpoints, p.totpEndpoints()...)
	endpoints = append(endpoints, p.otpEndpoints()...)
	endpoints = append(endpoints, p.backupCodeEndpoints()...)
	endpoints = append(endpoints, p.enableEndpoint(), p.disableEndpoint())
	optsCopy := p.opts
	return &betterauth.Plugin{
		ID:        ID,
		Version:   betterauth.Version,
		Endpoints: endpoints,
		Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool {
				return ctx.Path == "/sign-in/email" || ctx.Path == "/sign-in/username" || ctx.Path == "/sign-in/phone-number"
			},
			Handler: p.signInHook,
		}}},
		Schema: p.opts.schema(),
		RateLimit: []betterauth.PluginRateLimit{{
			Window: 10 * time.Second, Max: 3,
			PathMatcher: func(path string) bool { return strings.HasPrefix(path, "/two-factor/") },
		}},
		ErrorCodes: ErrorCodes,
		Options:    &optsCopy,
	}
}

// ---- helpers ----

func findTwoFactor(ctx *betterauth.EndpointContext, userID string) (adapter.Record, error) {
	return ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{
		Model: twoFactorModel, Where: []adapter.Where{{Field: "userId", Value: userID}},
	})
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := toFloat(v); ok {
		return f != 0
	}
	return true
}

// isFalse is `value === false` for a stored boolean.
func isFalse(v any) bool {
	switch t := v.(type) {
	case bool:
		return !t
	case nil:
		return false
	}
	if f, ok := toFloat(v); ok {
		return f == 0
	}
	return false
}

// isTrue is `value === true` for a stored boolean.
func isTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case nil:
		return false
	}
	if f, ok := toFloat(v); ok {
		return f == 1
	}
	return false
}

type rotated struct {
	User    *betterauth.User
	Session *betterauth.Session
}

// rotateSession sets user.twoFactorEnabled, replaces the current session with a new one
// (copying its fields) and writes the session cookie.
func (p *plugin) rotateSession(ctx *betterauth.EndpointContext, old *betterauth.Session, enabled bool) (*rotated, error) {
	a := ctx.Auth
	userID := ctx.Session.User.ID
	if old != nil {
		userID = old.UserID
	}
	updated, err := a.InternalAdapter.UpdateUser(ctx.Context(), userID, adapter.Record{"twoFactorEnabled": enabled})
	if err != nil {
		return nil, err
	}
	var override adapter.Record
	if old != nil {
		override = old.Record()
	}
	s, err := a.InternalAdapter.CreateSession(ctx.Context(), updated.ID, &betterauth.CreateSessionOptions{Override: override})
	if err != nil {
		return nil, err
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: s, User: updated}, nil, nil); err != nil {
		return nil, err
	}
	if old != nil {
		if err := a.InternalAdapter.DeleteSession(ctx.Context(), old.Token); err != nil {
			return nil, err
		}
	}
	return &rotated{User: updated, Session: s}, nil
}

func (p *plugin) passwordField() validate.Schema {
	s := validate.Describe(validate.String(), "User password")
	if p.opts.AllowPasswordless {
		return validate.Optional(s)
	}
	return s
}

// ---- enable / disable ----

func (p *plugin) enableEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "enableTwoFactor", Path: "/two-factor/enable", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("password", p.passwordField()),
			validate.F("method", validate.Default(validate.Enum("otp", "totp"), "totp")),
			validate.F("issuer", validate.Optional(validate.Describe(validate.String(), "Custom issuer for the TOTP URI"))),
		),
		Use:      []betterauth.Middleware{betterauth.SessionMiddleware},
		Metadata: enableMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			a := ctx.Auth
			user := ctx.Session.User
			method := ctx.BodyString("method")
			if err := requirePasswordIfNeeded(ctx, user.ID, p.opts.AllowPasswordless); err != nil {
				return nil, err
			}
			if method == "otp" && !p.opts.sendOTPConfigured() {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrOTPNotConfigured)
			}
			if method == "totp" && p.opts.totpDisabled() {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTOTPNotConfigured)
			}
			if method == "otp" {
				if _, err := p.rotateSession(ctx, ctx.Session.Session, true); err != nil {
					return nil, err
				}
				return jsonx.O("method", "otp"), nil
			}
			existing, err := findTwoFactor(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			if existing != nil && !isFalse(existing["verified"]) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTOTPAlreadyEnabled)
			}
			codes, err := generateBackupCodes(a.SecretConfig, p.opts.BackupCodeOptions)
			if err != nil {
				return nil, err
			}
			secret := RandomTOTPSecret()
			encrypted, err := bacrypto.SymmetricEncrypt(a.SecretConfig, secret)
			if err != nil {
				return nil, err
			}
			if p.opts.SkipVerificationOnEnable {
				if _, err := p.rotateSession(ctx, ctx.Session.Session, true); err != nil {
					return nil, err
				}
			}
			data := adapter.Record{"secret": encrypted, "backupCodes": codes.encoded, "verified": p.opts.SkipVerificationOnEnable}
			if existing != nil {
				if _, err := a.Adapter.Update(ctx.Context(), twoFactorModel, []adapter.Where{{Field: "id", Value: existing["id"]}}, data); err != nil {
					return nil, err
				}
			} else {
				data["userId"] = user.ID
				if _, err := a.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: twoFactorModel, Data: data}); err != nil {
					return nil, err
				}
			}
			digits := DefaultOTPDigits
			period := 0
			if t := p.opts.TOTPOptions; t != nil {
				if t.Digits != 0 {
					digits = t.Digits
				}
				period = t.Period
			}
			issuer := ctx.BodyString("issuer")
			if issuer == "" {
				issuer = p.opts.Issuer
			}
			if issuer == "" {
				issuer = a.AppName
			}
			uri := CreateOTP(secret, digits, period).URL(issuer, user.Email)
			return jsonx.O("method", "totp", "totpURI", uri, "backupCodes", stringsToAny(codes.codes)), nil
		},
	}
}

func (p *plugin) disableEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "disableTwoFactor", Path: "/two-factor/disable", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("password", p.passwordField())),
		Use:      []betterauth.Middleware{betterauth.SensitiveSessionMiddleware},
		Metadata: disableMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			a := ctx.Auth
			user := ctx.Session.User
			if err := requirePasswordIfNeeded(ctx, user.ID, p.opts.AllowPasswordless); err != nil {
				return nil, err
			}
			updated, err := a.InternalAdapter.UpdateUser(ctx.Context(), user.ID, adapter.Record{"twoFactorEnabled": false})
			if err != nil {
				return nil, err
			}
			if err := a.Adapter.Delete(ctx.Context(), twoFactorModel, []adapter.Where{{Field: "userId", Value: updated.ID}}); err != nil {
				return nil, err
			}
			old := ctx.Session.Session
			s, err := a.InternalAdapter.CreateSession(ctx.Context(), updated.ID, &betterauth.CreateSessionOptions{Override: old.Record()})
			if err != nil {
				return nil, err
			}
			if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: s, User: updated}, nil, nil); err != nil {
				return nil, err
			}
			if err := a.InternalAdapter.DeleteSession(ctx.Context(), old.Token); err != nil {
				return nil, err
			}
			trustCookie := a.CreateAuthCookie(TrustDeviceCookieName, &betterauth.CookieOptions{MaxAge: betterauth.Int(p.opts.trustDeviceMaxAge())})
			if value, ok := ctx.GetSignedCookie(trustCookie.Name, a.Secret); ok {
				parts := strings.Split(value, "!")
				if len(parts) > 1 && parts[1] != "" {
					if err := a.InternalAdapter.DeleteVerificationByIdentifier(ctx.Context(), parts[1]); err != nil {
						return nil, err
					}
				}
				betterauth.ExpireCookie(ctx, trustCookie)
			}
			return jsonx.O("status", true), nil
		},
	}
}

// ---- sign-in interception ----

func (p *plugin) signInHook(ctx *betterauth.EndpointContext) (any, error) {
	data := ctx.NewSession()
	if data == nil || data.User == nil || data.Session == nil {
		return nil, nil
	}
	if !truthy(data.User.Get("twoFactorEnabled")) {
		return nil, nil
	}
	a := ctx.Auth
	userID := data.User.ID
	trustMaxAge := p.opts.trustDeviceMaxAge()
	trustCookie := a.CreateAuthCookie(TrustDeviceCookieName, &betterauth.CookieOptions{MaxAge: betterauth.Int(trustMaxAge)})
	if value, ok := ctx.GetSignedCookie(trustCookie.Name, a.Secret); ok {
		parts := strings.Split(value, "!")
		if len(parts) > 1 && parts[0] != "" && parts[1] != "" {
			token, trustIdentifier := parts[0], parts[1]
			if token == hmacToken(a.Secret, userID+"!"+trustIdentifier) {
				rec, err := a.InternalAdapter.FindVerificationValue(ctx.Context(), trustIdentifier)
				if err != nil {
					return nil, err
				}
				if rec != nil && rec.Value == userID && rec.ExpiresAt.After(time.Now()) {
					if err := a.InternalAdapter.DeleteVerificationByIdentifier(ctx.Context(), trustIdentifier); err != nil {
						return nil, err
					}
					newIdentifier := "trust-device-" + bacrypto.RandomString(32)
					newToken := hmacToken(a.Secret, userID+"!"+newIdentifier)
					if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), newIdentifier, userID,
						time.Now().Add(time.Duration(trustMaxAge)*time.Second), nil); err != nil {
						return nil, err
					}
					ctx.SetSignedCookie(trustCookie.Name, newToken+"!"+newIdentifier, a.Secret, trustCookie.Attributes)
					return nil, nil
				}
			}
		}
		betterauth.ExpireCookie(ctx, trustCookie)
	}
	betterauth.DeleteSessionCookie(ctx, true)
	if err := a.InternalAdapter.DeleteSession(ctx.Context(), data.Session.Token); err != nil {
		return nil, err
	}
	ctx.SetNewSession(nil)
	maxAge := p.opts.twoFactorCookieMaxAge()
	twoFactorCookie := a.CreateAuthCookie(TwoFactorCookieName, &betterauth.CookieOptions{MaxAge: betterauth.Int(maxAge)})
	identifier := "2fa-" + bacrypto.RandomString(20)
	expiresAt := time.Now().Add(time.Duration(maxAge) * time.Second)
	if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), identifier, userID, expiresAt, nil); err != nil {
		return nil, err
	}
	if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), "2fa-attempts-"+identifier, "0", expiresAt, nil); err != nil {
		return nil, err
	}
	ctx.SetSignedCookie(twoFactorCookie.Name, identifier, a.Secret, twoFactorCookie.Attributes)
	methods := []any{}
	if !p.opts.totpDisabled() {
		row, err := findTwoFactor(ctx, userID)
		if err != nil {
			return nil, err
		}
		if row != nil && !isFalse(row["verified"]) {
			methods = append(methods, "totp")
		}
	}
	if p.opts.sendOTPConfigured() {
		methods = append(methods, "otp")
	}
	return jsonx.O("twoFactorRedirect", true, "twoFactorMethods", methods), nil
}
