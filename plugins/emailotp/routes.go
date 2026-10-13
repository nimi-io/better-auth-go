package emailotp

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func successTrue() *jsonx.Object { return jsonx.O("success", true) }

func typeEnum() validate.Schema { return validate.Enum(otpTypes...) }

func sendOTP(ctx *betterauth.EndpointContext, o *Options, email, otp, typ string) {
	ctx.Auth.RunInBackgroundOrAwait(func() error {
		return o.SendVerificationOTP(ctx, SendVerificationOTPData{Email: email, OTP: otp, Type: typ})
	})
}

func invalidEmail() error { return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidEmail) }

// sendVerificationOTPAction is the shared body of /email-otp/send-verification-otp.
func sendVerificationOTPAction(ctx *betterauth.EndpointContext, o *Options, rawEmail, typ string) (any, error) {
	if o.SendVerificationOTP == nil {
		ctx.Auth.Logger.Error("send email verification is not implemented")
		return nil, betterauth.ErrMessage("BAD_REQUEST", "send email verification is not implemented")
	}
	email := strings.ToLower(rawEmail)
	if !validate.IsEmail(email) {
		return nil, invalidEmail()
	}
	if typ == TypeChangeEmail {
		ctx.Auth.Logger.Error("Use the /email-otp/request-email-change endpoint to send OTP for changing email")
		return nil, betterauth.ErrMessage("BAD_REQUEST", "Invalid OTP type")
	}
	identifier := ToOTPIdentifier(typ, email)
	otp, err := resolveOTP(ctx, o, email, typ)
	if err != nil {
		return nil, err
	}
	shouldSend := typ == TypeSignIn && !o.DisableSignUp
	user, err := ctx.Auth.InternalAdapter.FindUserByEmail(ctx.Context(), email, false)
	if err != nil {
		return nil, err
	}
	if user == nil && !shouldSend {
		if err := ctx.Auth.InternalAdapter.DeleteVerificationByIdentifier(ctx.Context(), identifier); err != nil {
			return nil, err
		}
		return successTrue(), nil
	}
	sendOTP(ctx, o, email, otp, typ)
	return successTrue(), nil
}

func sendVerificationOTPEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "sendVerificationOTP", Path: "/email-otp/send-verification-otp", Methods: []string{"POST"},
		Use:      []betterauth.Middleware{betterauth.FormCSRFMiddleware},
		Body:     validate.Object(validate.F("email", validate.String()), validate.F("type", typeEnum())),
		Metadata: metaSendVerificationOTP,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			return sendVerificationOTPAction(ctx, o, ctx.BodyString("email"), ctx.BodyString("type"))
		},
	}
}

func createVerificationOTPEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "createVerificationOTP", Methods: []string{"POST"}, ServerOnly: true,
		Body:     validate.Object(validate.F("email", validate.String()), validate.F("type", typeEnum())),
		Metadata: metaCreateVerificationOTP,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			email := strings.ToLower(ctx.BodyString("email"))
			typ := ctx.BodyString("type")
			return createOTPValue(ctx, o, email, typ, ToOTPIdentifier(typ, email))
		},
	}
}

func getVerificationOTPEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getVerificationOTP", Methods: []string{"GET"}, ServerOnly: true,
		Query:    validate.Object(validate.F("email", validate.String()), validate.F("type", typeEnum())),
		Metadata: metaGetVerificationOTP,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			email := strings.ToLower(ctx.QueryString("email"))
			v, err := ctx.Auth.InternalAdapter.FindVerificationValue(ctx.Context(), ToOTPIdentifier(ctx.QueryString("type"), email))
			if err != nil {
				return nil, err
			}
			if v == nil || v.ExpiresAt.Before(time.Now()) {
				return jsonx.O("otp", nil), nil
			}
			s := o.StoreOTP
			if s.isHashed() || s.Hash != nil {
				return nil, betterauth.ErrMessage("BAD_REQUEST", "OTP is hashed, cannot return the plain text OTP")
			}
			stored, _ := SplitAtLastColon(v.Value)
			otp := stored
			if s.isEncrypted() {
				if otp, err = bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, stored); err != nil {
					return nil, err
				}
			}
			if s.Hash == nil && s.Decrypt != nil {
				if otp, err = s.Decrypt(stored); err != nil {
					return nil, err
				}
			}
			return jsonx.O("otp", otp), nil
		},
	}
}

func checkVerificationOTPEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "checkVerificationOTP", Path: "/email-otp/check-verification-otp", Methods: []string{"POST"},
		Body: validate.Object(validate.F("email", validate.String()), validate.F("type", typeEnum()),
			validate.F("otp", validate.String())),
		Metadata: metaCheckVerificationOTP,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			ia := ctx.Auth.InternalAdapter
			c := ctx.Context()
			email := strings.ToLower(ctx.BodyString("email"))
			if !validate.IsEmail(email) {
				return nil, invalidEmail()
			}
			identifier := ToOTPIdentifier(ctx.BodyString("type"), email)
			v, err := ia.FindVerificationValue(c, identifier)
			if err != nil {
				return nil, err
			}
			if v == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
			}
			if v.ExpiresAt.Before(time.Now()) {
				if err := ia.DeleteVerificationByIdentifier(c, identifier); err != nil {
					return nil, err
				}
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrOTPExpired)
			}
			value, attempts := SplitAtLastColon(v.Value)
			if attempts != "" {
				if n, ok := jsParseInt(attempts); ok && n >= o.allowedAttempts() {
					if err := ia.DeleteVerificationByIdentifier(c, identifier); err != nil {
						return nil, err
					}
					return nil, betterauth.ErrFrom("FORBIDDEN", ErrTooManyAttempts)
				}
			}
			ok, err := verifyStoredOTP(ctx, o, value, ctx.BodyString("otp"))
			if err != nil {
				return nil, err
			}
			if !ok {
				a := attempts
				if a == "" {
					a = "0"
				}
				next := "NaN"
				if n, ok := jsParseInt(a); ok {
					next = itoa(n + 1)
				}
				if _, err := ia.UpdateVerificationByIdentifier(c, identifier, adapter.Record{"value": value + ":" + next}); err != nil {
					return nil, err
				}
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
			}
			user, err := ia.FindUserByEmail(c, email, false)
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrUserNotFound)
			}
			return successTrue(), nil
		},
	}
}

func verifyEmailOTPEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "verifyEmailOTP", Path: "/email-otp/verify-email", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("email", validate.String()), validate.F("otp", validate.String())),
		Metadata: metaVerifyEmailOTP,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			a := ctx.Auth
			ia := a.InternalAdapter
			c := ctx.Context()
			email := strings.ToLower(ctx.BodyString("email"))
			if !validate.IsEmail(email) {
				return nil, invalidEmail()
			}
			if err := atomicVerifyOTP(ctx, o, ToOTPIdentifier(TypeEmailVerification, email), ctx.BodyString("otp")); err != nil {
				return nil, err
			}
			user, err := ia.FindUserByEmail(c, email, false)
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrUserNotFound)
			}
			ev := a.Options.EmailVerification
			if ev != nil && ev.BeforeEmailVerification != nil {
				if err := ev.BeforeEmailVerification(c, user.User, ctx.Request); err != nil {
					return nil, err
				}
			}
			updated, err := ia.UpdateUser(c, user.User.ID, adapter.Record{"email": email, "emailVerified": true})
			if err != nil {
				return nil, err
			}
			if updated == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrUserNotFound)
			}
			if ev != nil && ev.AfterEmailVerification != nil {
				if err := ev.AfterEmailVerification(c, updated, ctx.Request); err != nil {
					return nil, err
				}
			}
			if ev != nil && ev.AutoSignInAfterVerification {
				session, err := ia.CreateSession(c, updated.ID, nil)
				if err != nil {
					return nil, err
				}
				if session == nil {
					return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", betterauth.ErrFailedToCreateSession)
				}
				if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: updated}, nil, nil); err != nil {
					return nil, err
				}
				return jsonx.O("status", true, "token", session.Token, "user", a.UserOutput(updated)), nil
			}
			current, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if current != nil && updated.EmailVerified && current.User.ID == updated.ID {
				_, drm := ctx.GetSignedCookie(a.AuthCookies.DontRememberToken.Name, a.Secret)
				nu := current.User.Clone()
				nu.EmailVerified = true
				if err := betterauth.EmailOTPSetCookieCache(ctx, &betterauth.SessionWithUser{Session: current.Session, User: nu}, drm); err != nil {
					return nil, err
				}
			}
			return jsonx.O("status", true, "token", nil, "user", a.UserOutput(updated)), nil
		},
	}
}

var signInEmailOTPBody = validate.And(validate.Object(
	validate.F("email", validate.String()),
	validate.F("otp", validate.String()),
	validate.F("name", validate.Optional(validate.String())),
	validate.F("image", validate.Optional(validate.String())),
), validate.Record(validate.Any()))

func signInEmailOTPEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "signInEmailOTP", Path: "/sign-in/email-otp", Methods: []string{"POST"},
		Body:     signInEmailOTPBody,
		Metadata: metaSignInEmailOTP,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			a := ctx.Auth
			ia := a.InternalAdapter
			c := ctx.Context()
			body := ctx.BodyMap()
			email := strings.ToLower(ctx.BodyString("email"))
			if err := atomicVerifyOTP(ctx, o, ToOTPIdentifier(TypeSignIn, email), ctx.BodyString("otp")); err != nil {
				return nil, err
			}
			found, err := ia.FindUserByEmail(c, email, false)
			if err != nil {
				return nil, err
			}
			if found == nil {
				if o.DisableSignUp {
					return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
				}
				rest := map[string]any{}
				for k, v := range body {
					switch k {
					case "email", "otp", "name", "image":
					default:
						rest[k] = v
					}
				}
				additional, err := a.ParseUserInput(rest, "create")
				if err != nil {
					return nil, err
				}
				data := adapter.Record{}
				for k, v := range additional {
					data[k] = v
				}
				data["email"] = email
				data["emailVerified"] = true
				data["name"] = ctx.BodyString("name")
				if img, ok := body["image"]; ok {
					data["image"] = img
				} else {
					data["image"] = nil
				}
				created, err := ia.CreateUser(c, data, betterauth.UserInfoSource{Method: "email-otp"})
				if err != nil {
					return nil, err
				}
				if created == nil {
					return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", betterauth.ErrFailedToCreateUser)
				}
				return signIn(ctx, created)
			}
			user := found.User
			if !user.EmailVerified {
				promoted, err := betterauth.RevokeUnprovenAccountAccess(ctx, user.ID)
				if err != nil {
					return nil, err
				}
				if promoted == nil {
					return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
				}
				user = promoted
			}
			return signIn(ctx, user)
		},
	}
}

func signIn(ctx *betterauth.EndpointContext, user *betterauth.User) (any, error) {
	session, err := ctx.Auth.InternalAdapter.CreateSession(ctx.Context(), user.ID, nil)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", betterauth.ErrFailedToCreateSession)
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, nil, nil); err != nil {
		return nil, err
	}
	return jsonx.O("token", session.Token, "user", ctx.Auth.UserOutput(user)), nil
}

func requestPasswordReset(ctx *betterauth.EndpointContext, o *Options) (any, error) {
	email := strings.ToLower(ctx.BodyString("email"))
	identifier := ToOTPIdentifier(TypeForgetPassword, email)
	otp, err := resolveOTP(ctx, o, email, TypeForgetPassword)
	if err != nil {
		return nil, err
	}
	user, err := ctx.Auth.InternalAdapter.FindUserByEmail(ctx.Context(), email, false)
	if err != nil {
		return nil, err
	}
	if user == nil {
		if err := ctx.Auth.InternalAdapter.DeleteVerificationByIdentifier(ctx.Context(), identifier); err != nil {
			return nil, err
		}
		return successTrue(), nil
	}
	sendOTP(ctx, o, email, otp, TypeForgetPassword)
	return successTrue(), nil
}

func requestPasswordResetEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "requestPasswordResetEmailOTP", Path: "/email-otp/request-password-reset", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("email", validate.String())),
		Metadata: metaRequestPasswordReset,
		Handler:  func(ctx *betterauth.EndpointContext) (any, error) { return requestPasswordReset(ctx, o) },
	}
}

func forgetPasswordEndpoint(o *Options) *betterauth.Endpoint {
	var once sync.Once
	return &betterauth.Endpoint{
		Key: "forgetPasswordEmailOTP", Path: "/forget-password/email-otp", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("email", validate.String())),
		Metadata: metaForgetPassword,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			once.Do(func() {
				ctx.Auth.Logger.Warn(`[Deprecation] The "/forget-password/email-otp" endpoint is deprecated. ` +
					`Please use "/email-otp/request-password-reset" instead. ` +
					"This endpoint will be removed in the next major version.")
			})
			return requestPasswordReset(ctx, o)
		},
	}
}

func resetPasswordEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "resetPasswordEmailOTP", Path: "/email-otp/reset-password", Methods: []string{"POST"},
		Body: validate.Object(validate.F("email", validate.String()), validate.F("otp", validate.String()),
			validate.F("password", validate.String())),
		Metadata: metaResetPassword,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			a := ctx.Auth
			ia := a.InternalAdapter
			c := ctx.Context()
			email := strings.ToLower(ctx.BodyString("email"))
			password := ctx.BodyString("password")
			if n := jsonx.EncodeUTF16Length(password); n < a.Password.MinLength {
				a.Logger.Warn("Password is too short")
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooShort)
			} else if n > a.Password.MaxLength {
				a.Logger.Warn("Password is too long")
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooLong)
			}
			if err := atomicVerifyOTP(ctx, o, ToOTPIdentifier(TypeForgetPassword, email), ctx.BodyString("otp")); err != nil {
				return nil, err
			}
			found, err := ia.FindUserByEmail(c, email, false)
			if err != nil {
				return nil, err
			}
			if found == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrUserNotFound)
			}
			user := found.User
			hash, err := a.Password.Hash(password)
			if err != nil {
				return nil, err
			}
			acc, err := ia.FindCredentialAccount(c, user.ID)
			if err != nil {
				return nil, err
			}
			if acc == nil {
				if _, err := ia.CreateAccount(c, adapter.Record{"userId": user.ID, "providerId": "credential", "accountId": user.ID, "password": hash}); err != nil {
					return nil, err
				}
			} else if err := ia.UpdatePassword(c, user.ID, hash); err != nil {
				return nil, err
			}
			ep := a.Options.EmailAndPassword
			if ep != nil && ep.OnPasswordReset != nil {
				if err := ep.OnPasswordReset(c, user, ctx.Request); err != nil {
					return nil, err
				}
			}
			if !user.EmailVerified {
				if _, err := ia.UpdateUser(c, user.ID, adapter.Record{"emailVerified": true}); err != nil {
					return nil, err
				}
			}
			if ep != nil && ep.RevokeSessionsOnPasswordReset {
				if err := ia.DeleteUserSessions(c, user.ID); err != nil {
					return nil, err
				}
			}
			return successTrue(), nil
		},
	}
}

func changeEmailDisabled(ctx *betterauth.EndpointContext, o *Options) error {
	if o.ChangeEmail == nil || !o.ChangeEmail.Enabled {
		ctx.Auth.Logger.Error("Change email with OTP is disabled.")
		return betterauth.ErrMessage("BAD_REQUEST", "Change email with OTP is disabled")
	}
	return nil
}

func requestEmailChangeEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "requestEmailChangeEmailOTP", Path: "/email-otp/request-email-change", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("newEmail", validate.String()), validate.F("otp", validate.Optional(validate.String()))),
		Use:      []betterauth.Middleware{betterauth.SensitiveSessionMiddleware},
		Metadata: metaRequestEmailChange,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if err := changeEmailDisabled(ctx, o); err != nil {
				return nil, err
			}
			ia := ctx.Auth.InternalAdapter
			c := ctx.Context()
			email := strings.ToLower(ctx.Session.User.Email)
			newEmail := strings.ToLower(ctx.BodyString("newEmail"))
			if !validate.IsEmail(newEmail) {
				return nil, invalidEmail()
			}
			if newEmail == email {
				ctx.Auth.Logger.Error("Email is the same")
				return nil, betterauth.ErrMessage("BAD_REQUEST", "Email is the same")
			}
			providedOTP := ctx.BodyString("otp")
			if o.ChangeEmail.VerifyCurrentEmail {
				if providedOTP == "" {
					return nil, betterauth.ErrMessage("BAD_REQUEST", "OTP is required to verify current email")
				}
				if err := atomicVerifyOTP(ctx, o, ToOTPIdentifier(TypeEmailVerification, email), providedOTP); err != nil {
					return nil, err
				}
			} else if providedOTP != "" {
				ctx.Auth.Logger.Warn("OTP provided but not required for verifying current email. " +
					"If you want to require OTP verification for current email, " +
					"please set the changeEmail.verifyCurrentEmail option to true in the configuration")
			}
			identifier := ToOTPIdentifier(TypeChangeEmail, email+"-"+newEmail)
			otp, err := createOTPValue(ctx, o, newEmail, TypeChangeEmail, identifier)
			if err != nil {
				return nil, err
			}
			existing, err := ia.FindUserByEmail(c, newEmail, false)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				if err := ia.DeleteVerificationByIdentifier(c, identifier); err != nil {
					return nil, err
				}
				return successTrue(), nil
			}
			sendOTP(ctx, o, newEmail, otp, TypeChangeEmail)
			return successTrue(), nil
		},
	}
}

func changeEmailEndpoint(o *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "changeEmailEmailOTP", Path: "/email-otp/change-email", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("newEmail", validate.String()), validate.F("otp", validate.String())),
		Use:      []betterauth.Middleware{betterauth.SensitiveSessionMiddleware},
		Metadata: metaChangeEmail,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if err := changeEmailDisabled(ctx, o); err != nil {
				return nil, err
			}
			a := ctx.Auth
			ia := a.InternalAdapter
			c := ctx.Context()
			session := ctx.Session
			email := strings.ToLower(session.User.Email)
			newEmail := strings.ToLower(ctx.BodyString("newEmail"))
			if !validate.IsEmail(newEmail) {
				return nil, invalidEmail()
			}
			if newEmail == email {
				a.Logger.Error("Email is the same")
				return nil, betterauth.ErrMessage("BAD_REQUEST", "Email is the same")
			}
			if err := atomicVerifyOTP(ctx, o, ToOTPIdentifier(TypeChangeEmail, email+"-"+newEmail), ctx.BodyString("otp")); err != nil {
				return nil, err
			}
			current, err := ia.FindUserByEmail(c, email, false)
			if err != nil {
				return nil, err
			}
			if current == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrUserNotFound)
			}
			taken, err := ia.FindUserByEmail(c, newEmail, false)
			if err != nil {
				return nil, err
			}
			if taken != nil {
				return nil, betterauth.ErrMessage("BAD_REQUEST", "Email already in use")
			}
			ev := a.Options.EmailVerification
			if ev != nil && ev.BeforeEmailVerification != nil {
				if err := ev.BeforeEmailVerification(c, current.User, ctx.Request); err != nil {
					return nil, err
				}
			}
			updated, err := ia.UpdateUser(c, current.User.ID, adapter.Record{"email": newEmail, "emailVerified": true})
			if err != nil {
				return nil, err
			}
			if ev != nil && ev.AfterEmailVerification != nil {
				if err := ev.AfterEmailVerification(c, updated, ctx.Request); err != nil {
					return nil, err
				}
			}
			nu := session.User.Clone()
			nu.Email, nu.EmailVerified = newEmail, true
			if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session.Session, User: nu}, nil, nil); err != nil {
				return nil, err
			}
			return successTrue(), nil
		},
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// sendFromEmailVerification is the emailVerification.sendVerificationEmail override
// (overrideDefaultEmailVerification).
func sendFromEmailVerification(o *Options, initCtx *betterauth.AuthContext) func(c context.Context, d betterauth.EmailData, r *http.Request) error {
	return func(c context.Context, d betterauth.EmailData, r *http.Request) error {
		ec := betterauth.EndpointContextFrom(c)
		if ec == nil {
			ec = &betterauth.EndpointContext{Auth: initCtx, Request: r}
			ec.SetContext(c)
		}
		// Run as a direct endpoint call: errors are logged, never returned.
		ec.Auth.RunInBackgroundOrAwait(func() error {
			_, err := sendVerificationOTPAction(ec, o, d.User.Email, TypeEmailVerification)
			return err
		})
		return nil
	}
}
