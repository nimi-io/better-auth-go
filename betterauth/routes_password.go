package betterauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func redirectWithQuery(a *AuthContext, callbackURL string, fallbackError bool, kv ...string) string {
	base := callbackURL
	var u string
	var err error
	if base != "" {
		u, err = resolveURL(base, a.BaseURL)
	} else if fallbackError {
		u = a.BaseURL + "/error"
	}
	if err != nil {
		u = a.BaseURL + "/error"
	}
	out, err := setSearchParams(u, kv...)
	if err != nil {
		return u
	}
	return out
}

func requestPasswordResetEndpoint() *Endpoint {
	return &Endpoint{
		Key: "requestPasswordReset", Path: "/request-password-reset", Methods: []string{"POST"},
		Body: validate.Object(validate.F("email", validate.Email()), validate.F("redirectTo", validate.Optional(validate.String()))),
		Use:  []Middleware{OriginCheck(func(c *EndpointContext) []string { return []string{c.BodyString("redirectTo")} })},
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			ep := a.Options.EmailAndPassword
			if ep == nil || ep.SendResetPassword == nil {
				a.Logger.Error("Reset password isn't enabled.Please pass an emailAndPassword.sendResetPassword function in your auth config!")
				return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "RESET_PASSWORD_DISABLED", Message: "Reset password isn't enabled"})
			}
			msg := jsonx.O("status", true, "message", "If this email exists in our system, check your email for the reset link")
			email, redirectTo := ctx.BodyString("email"), ctx.BodyString("redirectTo")
			user, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), email, true)
			if err != nil {
				return nil, err
			}
			if user == nil {
				bacrypto.GenerateID(24)
				_, _ = a.InternalAdapter.FindVerificationValue(ctx.Context(), "dummy-verification-token")
				a.Logger.Warn("Reset Password: User not found")
				return msg, nil
			}
			expiresIn := time.Hour
			if ep.ResetPasswordTokenExpiresIn > 0 {
				expiresIn = ep.ResetPasswordTokenExpiresIn
			}
			token := bacrypto.GenerateID(24)
			if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), "reset-password:"+token, user.User.ID, time.Now().Add(expiresIn), nil); err != nil {
				return nil, err
			}
			cb := ""
			if redirectTo != "" {
				cb = EncodeURIComponent(redirectTo)
			}
			u := a.BaseURL + "/reset-password/" + token + "?callbackURL=" + cb
			usr := user.User
			a.RunInBackgroundOrAwait(func() error {
				return ep.SendResetPassword(context.WithoutCancel(ctx.Context()), EmailData{User: usr, URL: u, Token: token}, ctx.Request)
			})
			return msg, nil
		},
	}
}

func requestPasswordResetCallbackEndpoint() *Endpoint {
	return &Endpoint{
		Key: "requestPasswordResetCallback", Path: "/reset-password/:token", Methods: []string{"GET"}, OperationID: "resetPasswordCallback",
		Query: validate.Object(validate.F("callbackURL", validate.String())),
		Use:   []Middleware{OriginCheck(func(c *EndpointContext) []string { return []string{c.QueryString("callbackURL")} })},
		Handler: func(ctx *EndpointContext) (any, error) {
			token := ctx.Params["token"]
			cb := ctx.QueryString("callbackURL")
			if token == "" || cb == "" {
				return nil, ctx.Redirect(redirectWithQuery(ctx.Auth, cb, true, "error", "INVALID_TOKEN"))
			}
			v, err := ctx.Auth.InternalAdapter.FindVerificationValue(ctx.Context(), "reset-password:"+token)
			if err != nil {
				return nil, err
			}
			if v == nil || v.ExpiresAt.Before(time.Now()) {
				return nil, ctx.Redirect(redirectWithQuery(ctx.Auth, cb, true, "error", "INVALID_TOKEN"))
			}
			return nil, ctx.Redirect(redirectWithQuery(ctx.Auth, cb, false, "token", token))
		},
	}
}

func resetPasswordEndpoint() *Endpoint {
	return &Endpoint{
		Key: "resetPassword", Path: "/reset-password", Methods: []string{"POST"}, OperationID: "resetPassword",
		Query: validate.Optional(validate.Object(validate.F("token", validate.Optional(validate.String())))),
		Body:  validate.Object(validate.F("newPassword", validate.String()), validate.F("token", validate.Optional(validate.String()))),
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			token := ctx.BodyString("token")
			if token == "" {
				token = ctx.QueryString("token")
			}
			if token == "" {
				return nil, ErrFrom("BAD_REQUEST", ErrInvalidToken)
			}
			newPassword := ctx.BodyString("newPassword")
			if err := assertPasswordNotTooShort(ctx, newPassword); err != nil {
				return nil, err
			}
			if err := assertPasswordNotTooLong(ctx, newPassword); err != nil {
				return nil, err
			}
			v, err := a.InternalAdapter.ConsumeVerificationValue(ctx.Context(), "reset-password:"+token)
			if err != nil {
				return nil, err
			}
			if v == nil {
				return nil, ErrFrom("BAD_REQUEST", ErrInvalidToken)
			}
			user, err := a.InternalAdapter.FindUserByID(ctx.Context(), v.Value)
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, ErrFrom("BAD_REQUEST", ErrUserNotFound)
			}
			hashed, err := a.Password.Hash(newPassword)
			if err != nil {
				return nil, err
			}
			acc, err := a.InternalAdapter.FindCredentialAccount(ctx.Context(), user.ID)
			if err != nil {
				return nil, err
			}
			if acc == nil {
				if _, err := a.InternalAdapter.CreateAccount(ctx.Context(), adapter.Record{"userId": user.ID, "providerId": "credential", "accountId": user.ID, "password": hashed}); err != nil {
					return nil, err
				}
			} else if err := a.InternalAdapter.UpdatePassword(ctx.Context(), user.ID, hashed); err != nil {
				return nil, err
			}
			if ep := a.Options.EmailAndPassword; ep != nil && ep.OnPasswordReset != nil {
				if err := ep.OnPasswordReset(ctx.Context(), user, ctx.Request); err != nil {
					return nil, err
				}
			}
			if ep := a.Options.EmailAndPassword; ep != nil && ep.RevokeSessionsOnPasswordReset {
				if err := a.InternalAdapter.DeleteUserSessions(ctx.Context(), user.ID); err != nil {
					return nil, err
				}
			}
			return statusTrue(), nil
		},
	}
}

// validatePassword checks a password against the user's credential account.
func validatePassword(ctx *EndpointContext, password, userID string) (bool, error) {
	if err := assertPasswordNotTooLong(ctx, password); err != nil {
		return false, err
	}
	acc, err := ctx.Auth.InternalAdapter.FindCredentialAccount(ctx.Context(), userID)
	if err != nil {
		return false, err
	}
	if acc == nil || acc.Password == nil || *acc.Password == "" {
		return false, nil
	}
	return ctx.Auth.Password.Verify(*acc.Password, password)
}

func verifyPasswordEndpoint() *Endpoint {
	return &Endpoint{
		Key: "verifyPassword", Path: "/verify-password", Methods: []string{"POST"},
		Body: validate.Object(validate.F("password", validate.String())),
		Use:  []Middleware{SensitiveSessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			ok, err := validatePassword(ctx, ctx.BodyString("password"), ctx.Session.User.ID)
			if err != nil {
				if _, isAPI := AsAPIError(err); isAPI {
					return nil, err
				}
			}
			if !ok {
				return nil, ErrFrom("BAD_REQUEST", ErrInvalidPassword)
			}
			return statusTrue(), nil
		},
	}
}

// ---- email verification ----

func sendVerificationEmailFn(ctx *EndpointContext, user *User) error {
	a := ctx.Auth
	ev := a.Options.EmailVerification
	if ev == nil || ev.SendVerificationEmail == nil {
		a.Logger.Error("Verification email isn't enabled.")
		return ErrFrom("BAD_REQUEST", ErrVerificationEmailNotEnabled)
	}
	token, err := CreateEmailVerificationToken(a.Secret, user.Email, "", a.verificationExpiresIn(), nil)
	if err != nil {
		return err
	}
	cb := "/"
	if v := ctx.BodyString("callbackURL"); v != "" {
		cb = v
	}
	u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + EncodeURIComponent(cb)
	return ev.SendVerificationEmail(ctx.Context(), EmailData{User: user, URL: u, Token: token}, ctx.Request)
}

// SendVerificationEmail sends the verification email for user (exported for plugins).
func SendVerificationEmail(ctx *EndpointContext, user *User) error {
	return sendVerificationEmailFn(ctx, user)
}

func sendVerificationEmailEndpoint() *Endpoint {
	return &Endpoint{
		Key: "sendVerificationEmail", Path: "/send-verification-email", Methods: []string{"POST"}, OperationID: "sendVerificationEmail",
		Body: validate.Object(validate.F("email", validate.Email()), validate.F("callbackURL", validate.Optional(validate.String()))),
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			if ev := a.Options.EmailVerification; ev == nil || ev.SendVerificationEmail == nil {
				a.Logger.Error("Verification email isn't enabled.")
				return nil, ErrFrom("BAD_REQUEST", ErrVerificationEmailNotEnabled)
			}
			email := ctx.BodyString("email")
			session, err := GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if session == nil {
				start := time.Now()
				user, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), email, false)
				if err != nil {
					return nil, err
				}
				var sendErr error
				if user == nil || user.User.EmailVerified {
					_, _ = CreateEmailVerificationToken(a.Secret, email, "", a.verificationExpiresIn(), nil)
				} else {
					sendErr = sendVerificationEmailFn(ctx, user.User)
				}
				if remaining := 500*time.Millisecond - time.Since(start); remaining > 0 {
					time.Sleep(remaining)
				}
				if sendErr != nil {
					return nil, sendErr
				}
				return statusTrue(), nil
			}
			if !equalFoldASCII(session.User.Email, email) {
				return nil, ErrFrom("BAD_REQUEST", ErrEmailMismatch)
			}
			if session.User.EmailVerified {
				return nil, ErrFrom("BAD_REQUEST", ErrEmailAlreadyVerified)
			}
			if err := sendVerificationEmailFn(ctx, session.User); err != nil {
				return nil, err
			}
			return statusTrue(), nil
		},
	}
}

func equalFoldASCII(a, b string) bool { return strings.ToLower(a) == strings.ToLower(b) }

func verifyEmailEndpoint() *Endpoint {
	return &Endpoint{
		Key: "verifyEmail", Path: "/verify-email", Methods: []string{"GET"}, OperationID: "verifyEmail",
		Query:   validate.Object(validate.F("token", validate.String()), validate.F("callbackURL", validate.Optional(validate.String()))),
		Use:     []Middleware{OriginCheck(func(c *EndpointContext) []string { return []string{c.QueryString("callbackURL")} })},
		Handler: verifyEmail,
	}
}

func verifyEmail(ctx *EndpointContext) (any, error) {
	a := ctx.Auth
	cb := ctx.QueryString("callbackURL")
	redirectOnError := func(code ErrorCode) error {
		if cb != "" {
			u, err := appendQueryParams(cb, url.Values{"error": {code.Code}}, []string{"error"})
			if err != nil {
				return err
			}
			return ctx.Redirect(u)
		}
		return ErrFrom("UNAUTHORIZED", code)
	}
	payload, err := bacrypto.VerifyJWT(ctx.QueryString("token"), a.Secret, bacrypto.VerifyJWTOptions{Algorithms: []string{"HS256"}})
	if err != nil {
		if errors.Is(err, bacrypto.ErrJWTExpired) {
			return nil, redirectOnError(ErrTokenExpired)
		}
		return nil, redirectOnError(ErrInvalidToken)
	}
	emailV, _ := payload.Get("email")
	email, ok := emailV.(string)
	if !ok || !validate.IsEmail(email) {
		return nil, errors.New("invalid email verification token payload")
	}
	updateTo, _ := payloadString(payload, "updateTo")
	requestType, _ := payloadString(payload, "requestType")
	user, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), email, false)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, redirectOnError(ErrUserNotFound)
	}
	if updateTo != "" {
		session, err := GetSessionFromCtx(ctx, nil)
		if err != nil {
			return nil, err
		}
		if session != nil && session.User.Email != email {
			return nil, redirectOnError(ErrInvalidUser)
		}
		updateCB := EncodeURIComponent("/")
		if cb != "" {
			updateCB = EncodeURIComponent(cb)
		}
		switch requestType {
		case "change-email-confirmation":
			newToken, err := CreateEmailVerificationToken(a.Secret, email, updateTo, a.verificationExpiresIn(), jsonx.O("requestType", "change-email-verification"))
			if err != nil {
				return nil, err
			}
			u := a.BaseURL + "/verify-email?token=" + newToken + "&callbackURL=" + updateCB
			if ev := a.Options.EmailVerification; ev != nil && ev.SendVerificationEmail != nil {
				target := user.User.Clone()
				target.Email = updateTo
				a.RunInBackgroundOrAwait(func() error {
					return ev.SendVerificationEmail(context.WithoutCancel(ctx.Context()), EmailData{User: target, URL: u, Token: newToken}, ctx.Request)
				})
			}
			if cb != "" {
				return nil, ctx.Redirect(cb)
			}
			return statusTrue(), nil
		case "change-email-verification":
			active := session
			if active == nil {
				ns, err := a.InternalAdapter.CreateSession(ctx.Context(), user.User.ID, nil)
				if err != nil {
					return nil, err
				}
				if ns == nil {
					return nil, ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToCreateSession)
				}
				active = &SessionWithUser{Session: ns, User: user.User}
			}
			updated, err := a.InternalAdapter.UpdateUserByEmail(ctx.Context(), email, adapter.Record{"email": updateTo, "emailVerified": true})
			if err != nil {
				return nil, err
			}
			if ev := a.Options.EmailVerification; ev != nil && ev.AfterEmailVerification != nil {
				if err := ev.AfterEmailVerification(ctx.Context(), updated, ctx.Request); err != nil {
					return nil, err
				}
			}
			nu := active.User.Clone()
			nu.Email, nu.EmailVerified = updateTo, true
			if err := SetSessionCookie(ctx, &SessionWithUser{Session: active.Session, User: nu}, nil, nil); err != nil {
				return nil, err
			}
			if cb != "" {
				return nil, ctx.Redirect(cb)
			}
			return jsonx.O("status", true, "user", a.UserOutput(updated)), nil
		default:
			active := session
			if active == nil {
				ns, err := a.InternalAdapter.CreateSession(ctx.Context(), user.User.ID, nil)
				if err != nil {
					return nil, err
				}
				if ns == nil {
					return nil, ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToCreateSession)
				}
				active = &SessionWithUser{Session: ns, User: user.User}
			}
			updated, err := a.InternalAdapter.UpdateUserByEmail(ctx.Context(), email, adapter.Record{"email": updateTo, "emailVerified": false})
			if err != nil {
				return nil, err
			}
			newToken, err := CreateEmailVerificationToken(a.Secret, updateTo, "", time.Hour, nil)
			if err != nil {
				return nil, err
			}
			if ev := a.Options.EmailVerification; ev != nil && ev.SendVerificationEmail != nil {
				u := a.BaseURL + "/verify-email?token=" + newToken + "&callbackURL=" + updateCB
				a.RunInBackgroundOrAwait(func() error {
					return ev.SendVerificationEmail(context.WithoutCancel(ctx.Context()), EmailData{User: updated, URL: u, Token: newToken}, ctx.Request)
				})
			}
			nu := active.User.Clone()
			nu.Email, nu.EmailVerified = updateTo, false
			if err := SetSessionCookie(ctx, &SessionWithUser{Session: active.Session, User: nu}, nil, nil); err != nil {
				return nil, err
			}
			if cb != "" {
				return nil, ctx.Redirect(cb)
			}
			return jsonx.O("status", true, "user", a.UserOutput(updated)), nil
		}
	}
	if user.User.EmailVerified {
		if cb != "" {
			return nil, ctx.Redirect(cb)
		}
		return jsonx.O("status", true, "user", nil), nil
	}
	ev := a.Options.EmailVerification
	if ev != nil && ev.BeforeEmailVerification != nil {
		if err := ev.BeforeEmailVerification(ctx.Context(), user.User, ctx.Request); err != nil {
			return nil, err
		}
	}
	updated, err := a.InternalAdapter.UpdateUserByEmail(ctx.Context(), email, adapter.Record{"emailVerified": true})
	if err != nil {
		return nil, err
	}
	if ev != nil && ev.AfterEmailVerification != nil {
		if err := ev.AfterEmailVerification(ctx.Context(), updated, ctx.Request); err != nil {
			return nil, err
		}
	}
	if ev != nil && ev.AutoSignInAfterVerification {
		current, err := GetSessionFromCtx(ctx, nil)
		if err != nil {
			return nil, err
		}
		if current == nil || current.User.Email != email {
			s, err := a.InternalAdapter.CreateSession(ctx.Context(), user.User.ID, nil)
			if err != nil {
				return nil, err
			}
			if s == nil {
				return nil, ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToCreateSession)
			}
			nu := user.User.Clone()
			nu.EmailVerified = true
			if err := SetSessionCookie(ctx, &SessionWithUser{Session: s, User: nu}, nil, nil); err != nil {
				return nil, err
			}
		} else {
			nu := current.User.Clone()
			nu.EmailVerified = true
			if err := SetSessionCookie(ctx, &SessionWithUser{Session: current.Session, User: nu}, nil, nil); err != nil {
				return nil, err
			}
		}
	}
	if cb != "" {
		return nil, ctx.Redirect(cb)
	}
	return jsonx.O("status", true, "user", nil), nil
}

func payloadString(o *jsonx.Object, key string) (string, bool) {
	v, ok := o.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
