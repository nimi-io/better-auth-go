package betterauth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func updateUserEndpoint() *Endpoint {
	return &Endpoint{
		Key: "updateUser", Path: "/update-user", Methods: []string{"POST"}, OperationID: "updateUser",
		Body: validate.Record(validate.Any()), Use: []Middleware{SessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			body := ctx.BodyMap()
			if body == nil {
				return nil, ErrFrom("BAD_REQUEST", ErrBodyMustBeAnObject)
			}
			if truthy(body["email"]) {
				return nil, ErrFrom("BAD_REQUEST", ErrEmailCanNotBeUpdated)
			}
			name, hasName := body["name"]
			image, hasImage := body["image"]
			rest := map[string]any{}
			for k, v := range body {
				if k != "name" && k != "image" {
					rest[k] = v
				}
			}
			additional, err := a.ParseUserInput(rest, "update")
			if err != nil {
				return nil, err
			}
			if !hasImage && !hasName && len(additional) == 0 {
				return nil, ErrMessage("BAD_REQUEST", "No fields to update")
			}
			upd := adapter.Record{}
			if hasName {
				upd["name"] = name
			}
			if hasImage {
				upd["image"] = image
			}
			for k, v := range additional {
				upd[k] = v
			}
			user, err := a.InternalAdapter.UpdateUser(ctx.Context(), ctx.Session.User.ID, upd)
			if err != nil {
				return nil, err
			}
			if user == nil || user.ID == "" {
				user = UserFromRecord(mergeRecord(ctx.Session.User.Record(), upd))
			}
			if err := SetSessionCookie(ctx, &SessionWithUser{Session: ctx.Session.Session, User: user}, nil, nil); err != nil {
				return nil, err
			}
			return statusTrue(), nil
		},
	}
}

func changePasswordEndpoint() *Endpoint {
	return &Endpoint{
		Key: "changePassword", Path: "/change-password", Methods: []string{"POST"}, OperationID: "changePassword",
		Body: validate.Object(validate.F("newPassword", validate.String()), validate.F("currentPassword", validate.String()),
			validate.F("revokeOtherSessions", validate.Optional(validate.Boolean()))),
		Use: []Middleware{SensitiveSessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			newPassword, currentPassword := ctx.BodyString("newPassword"), ctx.BodyString("currentPassword")
			if err := assertPasswordNotTooShort(ctx, newPassword); err != nil {
				return nil, err
			}
			if err := assertPasswordNotTooLong(ctx, newPassword); err != nil {
				return nil, err
			}
			if err := assertPasswordNotTooLong(ctx, currentPassword); err != nil {
				return nil, err
			}
			user := ctx.Session.User
			acc, err := a.InternalAdapter.FindCredentialAccount(ctx.Context(), user.ID)
			if err != nil {
				return nil, err
			}
			if acc == nil || acc.Password == nil || *acc.Password == "" {
				return nil, ErrFrom("BAD_REQUEST", ErrCredentialAccountNotFound)
			}
			hash, err := a.Password.Hash(newPassword)
			if err != nil {
				return nil, err
			}
			ok, err := a.Password.Verify(*acc.Password, currentPassword)
			if err != nil || !ok {
				return nil, ErrFrom("BAD_REQUEST", ErrInvalidPassword)
			}
			if _, err := a.InternalAdapter.UpdateAccount(ctx.Context(), acc.ID, adapter.Record{"password": hash}); err != nil {
				return nil, err
			}
			var token any
			if b := ctx.BodyBool("revokeOtherSessions"); b != nil && *b {
				if err := a.InternalAdapter.DeleteUserSessions(ctx.Context(), user.ID); err != nil {
					return nil, err
				}
				ns, err := a.InternalAdapter.CreateSession(ctx.Context(), user.ID, nil)
				if err != nil {
					return nil, err
				}
				if ns == nil {
					return nil, ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToGetSession)
				}
				if err := SetSessionCookie(ctx, &SessionWithUser{Session: ns, User: user}, nil, nil); err != nil {
					return nil, err
				}
				token = ns.Token
			}
			return jsonx.O("token", token, "user", a.UserOutput(user)), nil
		},
	}
}

func setPasswordEndpoint() *Endpoint {
	return &Endpoint{
		Key: "setPassword", ServerOnly: true, Methods: []string{"POST"},
		Body: validate.Object(validate.F("newPassword", validate.String())),
		Use:  []Middleware{SensitiveSessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			newPassword := ctx.BodyString("newPassword")
			if err := assertPasswordNotTooShort(ctx, newPassword); err != nil {
				return nil, err
			}
			if err := assertPasswordNotTooLong(ctx, newPassword); err != nil {
				return nil, err
			}
			uid := ctx.Session.User.ID
			acc, err := a.InternalAdapter.FindCredentialAccount(ctx.Context(), uid)
			if err != nil {
				return nil, err
			}
			hash, err := a.Password.Hash(newPassword)
			if err != nil {
				return nil, err
			}
			if acc == nil {
				if _, err := a.InternalAdapter.LinkAccount(ctx.Context(), adapter.Record{"userId": uid, "providerId": "credential", "accountId": uid, "password": hash}); err != nil {
					return nil, err
				}
				return statusTrue(), nil
			}
			if acc.Password == nil || *acc.Password == "" {
				if _, err := a.InternalAdapter.UpdateAccount(ctx.Context(), acc.ID, adapter.Record{"password": hash}); err != nil {
					return nil, err
				}
				return statusTrue(), nil
			}
			return nil, ErrFrom("BAD_REQUEST", ErrPasswordAlreadySet)
		},
	}
}

func (a *AuthContext) deleteUserConfig() *DeleteUserConfig {
	if a.Options.User == nil {
		return nil
	}
	return a.Options.User.DeleteUser
}

func deleteUserEndpoint() *Endpoint {
	return &Endpoint{
		Key: "deleteUser", Path: "/delete-user", Methods: []string{"POST"},
		Use: []Middleware{SensitiveSessionMiddleware},
		Body: validate.Object(validate.F("callbackURL", validate.Optional(validate.String())),
			validate.F("password", validate.Optional(validate.String())), validate.F("token", validate.Optional(validate.String()))),
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			du := a.deleteUserConfig()
			if du == nil || !du.Enabled {
				a.Logger.Error("Delete user is disabled. Enable it in the options")
				return nil, ErrStatus("NOT_FOUND")
			}
			session := ctx.Session
			if pw := ctx.BodyString("password"); pw != "" {
				if err := assertPasswordNotTooLong(ctx, pw); err != nil {
					return nil, err
				}
				acc, err := a.InternalAdapter.FindCredentialAccount(ctx.Context(), session.User.ID)
				if err != nil {
					return nil, err
				}
				if acc == nil || acc.Password == nil || *acc.Password == "" {
					return nil, ErrFrom("BAD_REQUEST", ErrCredentialAccountNotFound)
				}
				ok, err := a.Password.Verify(*acc.Password, pw)
				if err != nil || !ok {
					return nil, ErrFrom("BAD_REQUEST", ErrInvalidPassword)
				}
			}
			if tok := ctx.BodyString("token"); tok != "" {
				child := *ctx
				child.Query = map[string]any{"token": tok}
				if _, err := deleteUserCallbackHandler(&child); err != nil {
					return nil, err
				}
				ctx.ResponseHeaders = child.ResponseHeaders
				return jsonx.O("success", true, "message", "User deleted"), nil
			}
			if du.SendDeleteAccountVerification != nil {
				token := bacrypto.RandomString(32, bacrypto.Digits, bacrypto.AlphaLower)
				exp := 24 * time.Hour
				if du.DeleteTokenExpiresIn > 0 {
					exp = du.DeleteTokenExpiresIn
				}
				if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), "delete-account-"+token, session.User.ID, time.Now().Add(exp), nil); err != nil {
					return nil, err
				}
				cb := ctx.BodyString("callbackURL")
				if cb == "" {
					cb = "/"
				}
				u := a.BaseURL + "/delete-user/callback?token=" + token + "&callbackURL=" + EncodeURIComponent(cb)
				user := session.User
				a.RunInBackgroundOrAwait(func() error {
					return du.SendDeleteAccountVerification(context.WithoutCancel(ctx.Context()), EmailData{User: user, URL: u, Token: token}, ctx.Request)
				})
				return jsonx.O("success", true, "message", "Verification email sent"), nil
			}
			if ctx.BodyString("password") == "" && a.SessionConfig.FreshAge != 0 {
				if time.Since(session.Session.CreatedAt) >= a.SessionConfig.FreshAge {
					return nil, ErrFrom("BAD_REQUEST", ErrSessionExpired)
				}
			}
			if du.BeforeDelete != nil {
				if err := du.BeforeDelete(ctx.Context(), session.User, ctx.Request); err != nil {
					return nil, err
				}
			}
			if err := a.InternalAdapter.DeleteUser(ctx.Context(), session.User.ID); err != nil {
				return nil, err
			}
			if err := a.InternalAdapter.DeleteUserSessions(ctx.Context(), session.User.ID); err != nil {
				return nil, err
			}
			DeleteSessionCookie(ctx, false)
			if du.AfterDelete != nil {
				if err := du.AfterDelete(ctx.Context(), session.User, ctx.Request); err != nil {
					return nil, err
				}
			}
			return jsonx.O("success", true, "message", "User deleted"), nil
		},
	}
}

func deleteUserCallbackHandler(ctx *EndpointContext) (any, error) {
	a := ctx.Auth
	du := a.deleteUserConfig()
	if du == nil || !du.Enabled {
		a.Logger.Error("Delete user is disabled. Enable it in the options")
		return nil, ErrFrom("NOT_FOUND", ErrorCode{Code: "NOT_FOUND", Message: "Not found"})
	}
	session, err := GetSessionFromCtx(ctx, &GetSessionOptions{DisableCookieCache: a.stateful})
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrFrom("NOT_FOUND", ErrFailedToGetUserInfo)
	}
	v, err := a.InternalAdapter.ConsumeVerificationValue(ctx.Context(), "delete-account-"+ctx.QueryString("token"))
	if err != nil {
		return nil, err
	}
	if v == nil || v.Value != session.User.ID {
		return nil, ErrFrom("NOT_FOUND", ErrInvalidToken)
	}
	if du.BeforeDelete != nil {
		if err := du.BeforeDelete(ctx.Context(), session.User, ctx.Request); err != nil {
			return nil, err
		}
	}
	if err := a.InternalAdapter.DeleteUser(ctx.Context(), session.User.ID); err != nil {
		return nil, err
	}
	if err := a.InternalAdapter.DeleteUserSessions(ctx.Context(), session.User.ID); err != nil {
		return nil, err
	}
	if err := a.InternalAdapter.DeleteAccounts(ctx.Context(), session.User.ID); err != nil {
		return nil, err
	}
	DeleteSessionCookie(ctx, false)
	if du.AfterDelete != nil {
		if err := du.AfterDelete(ctx.Context(), session.User, ctx.Request); err != nil {
			return nil, err
		}
	}
	if cb := ctx.QueryString("callbackURL"); cb != "" {
		return nil, ctx.Redirect(cb)
	}
	return jsonx.O("success", true, "message", "User deleted"), nil
}

func deleteUserCallbackEndpoint() *Endpoint {
	return &Endpoint{
		Key: "deleteUserCallback", Path: "/delete-user/callback", Methods: []string{"GET"},
		Query:   validate.Object(validate.F("token", validate.String()), validate.F("callbackURL", validate.Optional(validate.String()))),
		Use:     []Middleware{OriginCheck(func(c *EndpointContext) []string { return []string{c.QueryString("callbackURL")} })},
		Handler: deleteUserCallbackHandler,
	}
}

func changeEmailEndpoint() *Endpoint {
	return &Endpoint{
		Key: "changeEmail", Path: "/change-email", Methods: []string{"POST"},
		Body: validate.Object(validate.F("newEmail", validate.Email()), validate.F("callbackURL", validate.Optional(validate.String()))),
		Use:  []Middleware{SensitiveSessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			uc := a.Options.User
			if uc == nil || uc.ChangeEmail == nil || !uc.ChangeEmail.Enabled {
				a.Logger.Error("Change email is disabled.")
				return nil, ErrFrom("BAD_REQUEST", ErrChangeEmailDisabled)
			}
			user := ctx.Session.User
			newEmail := strings.ToLower(ctx.BodyString("newEmail"))
			if newEmail == user.Email {
				a.Logger.Warn("Email is the same")
				return nil, ErrMessage("BAD_REQUEST", "Email is the same")
			}
			canUpdateWithout := !user.EmailVerified && uc.ChangeEmail.UpdateEmailWithoutVerification
			var sendVerification func(context.Context, EmailData, *http.Request) error
			if ev := a.Options.EmailVerification; ev != nil {
				sendVerification = ev.SendVerificationEmail
			}
			canSendConfirmation := sendVerification != nil && user.EmailVerified && uc.ChangeEmail.SendChangeEmailConfirmation != nil
			if !canUpdateWithout && !canSendConfirmation && sendVerification == nil {
				a.Logger.Error("Verification email isn't enabled.")
				return nil, ErrMessage("BAD_REQUEST", "Verification email isn't enabled")
			}
			cb := ctx.BodyString("callbackURL")
			if cb == "" {
				cb = "/"
			}
			existing, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), newEmail, false)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				_, _ = CreateEmailVerificationToken(a.Secret, user.Email, newEmail, a.verificationExpiresIn(), nil)
				a.Logger.Info("Change email attempt for existing email")
				return statusTrue(), nil
			}
			if canUpdateWithout {
				if _, err := a.InternalAdapter.UpdateUser(ctx.Context(), user.ID, adapter.Record{"email": newEmail}); err != nil {
					return nil, err
				}
				nu := user.Clone()
				nu.Email = newEmail
				if err := SetSessionCookie(ctx, &SessionWithUser{Session: ctx.Session.Session, User: nu}, nil, nil); err != nil {
					return nil, err
				}
				if sendVerification != nil {
					token, err := CreateEmailVerificationToken(a.Secret, newEmail, "", a.verificationExpiresIn(), nil)
					if err != nil {
						return nil, err
					}
					u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + EncodeURIComponent(cb)
					a.RunInBackgroundOrAwait(func() error {
						return sendVerification(context.WithoutCancel(ctx.Context()), EmailData{User: nu, URL: u, Token: token}, ctx.Request)
					})
				}
				return statusTrue(), nil
			}
			if canSendConfirmation {
				token, err := CreateEmailVerificationToken(a.Secret, user.Email, newEmail, a.verificationExpiresIn(), jsonx.O("requestType", "change-email-confirmation"))
				if err != nil {
					return nil, err
				}
				u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + EncodeURIComponent(cb)
				send := uc.ChangeEmail.SendChangeEmailConfirmation
				a.RunInBackgroundOrAwait(func() error {
					return send(context.WithoutCancel(ctx.Context()), ChangeEmailData{User: user, NewEmail: newEmail, URL: u, Token: token}, ctx.Request)
				})
				return statusTrue(), nil
			}
			if sendVerification == nil {
				a.Logger.Error("Verification email isn't enabled.")
				return nil, ErrMessage("BAD_REQUEST", "Verification email isn't enabled")
			}
			token, err := CreateEmailVerificationToken(a.Secret, user.Email, newEmail, a.verificationExpiresIn(), jsonx.O("requestType", "change-email-verification"))
			if err != nil {
				return nil, err
			}
			u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + EncodeURIComponent(cb)
			nu := user.Clone()
			nu.Email = newEmail
			a.RunInBackgroundOrAwait(func() error {
				return sendVerification(context.WithoutCancel(ctx.Context()), EmailData{User: nu, URL: u, Token: token}, ctx.Request)
			})
			return statusTrue(), nil
		},
	}
}
