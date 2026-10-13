// Package phonenumber adds phone number OTP sign-in/verification and password reset
// (packages/better-auth/src/plugins/phone-number).
package phonenumber

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Error codes (PHONE_NUMBER_ERROR_CODES).
var (
	ErrInvalidPhoneNumber           = betterauth.ErrorCode{Code: "INVALID_PHONE_NUMBER", Message: "Invalid phone number"}
	ErrPhoneNumberExist             = betterauth.ErrorCode{Code: "PHONE_NUMBER_EXIST", Message: "Phone number already exists"}
	ErrPhoneNumberNotExist          = betterauth.ErrorCode{Code: "PHONE_NUMBER_NOT_EXIST", Message: "phone number isn't registered"}
	ErrInvalidPhoneNumberOrPassword = betterauth.ErrorCode{Code: "INVALID_PHONE_NUMBER_OR_PASSWORD", Message: "Invalid phone number or password"}
	ErrUnexpectedError              = betterauth.ErrorCode{Code: "UNEXPECTED_ERROR", Message: "Unexpected error"}
	ErrOTPNotFound                  = betterauth.ErrorCode{Code: "OTP_NOT_FOUND", Message: "OTP not found"}
	ErrOTPExpired                   = betterauth.ErrorCode{Code: "OTP_EXPIRED", Message: "OTP expired"}
	ErrInvalidOTP                   = betterauth.ErrorCode{Code: "INVALID_OTP", Message: "Invalid OTP"}
	ErrPhoneNumberNotVerified       = betterauth.ErrorCode{Code: "PHONE_NUMBER_NOT_VERIFIED", Message: "Phone number not verified"}
	ErrPhoneNumberCannotBeUpdated   = betterauth.ErrorCode{Code: "PHONE_NUMBER_CANNOT_BE_UPDATED", Message: "Phone number cannot be updated"}
	ErrSendOTPNotImplemented        = betterauth.ErrorCode{Code: "SEND_OTP_NOT_IMPLEMENTED", Message: "sendOTP not implemented"}
	ErrTooManyAttempts              = betterauth.ErrorCode{Code: "TOO_MANY_ATTEMPTS", Message: "Too many attempts"}
)

// ErrorCodes lists the plugin error codes ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{ErrInvalidPhoneNumber, ErrPhoneNumberExist, ErrPhoneNumberNotExist,
	ErrInvalidPhoneNumberOrPassword, ErrUnexpectedError, ErrOTPNotFound, ErrOTPExpired, ErrInvalidOTP,
	ErrPhoneNumberNotVerified, ErrPhoneNumberCannotBeUpdated, ErrSendOTPNotImplemented, ErrTooManyAttempts}

// OTPData is passed to the OTP callbacks.
type OTPData struct {
	PhoneNumber string
	Code        string
}

// VerificationData is passed to CallbackOnVerification.
type VerificationData struct {
	PhoneNumber string
	User        *betterauth.User
}

// SignUpOnVerification creates a user when an unknown phone number is verified.
type SignUpOnVerification struct {
	GetTempEmail func(phoneNumber string) string
	// GetTempName defaults to the phone number.
	GetTempName func(phoneNumber string) string
}

// SchemaOptions renames the plugin fields (InferOptionSchema / mergeSchema).
type SchemaOptions struct {
	ModelName string
	// Fields maps "phoneNumber" / "phoneNumberVerified" to column names.
	Fields map[string]string
}

// Options configures the plugin (PhoneNumberOptions).
type Options struct {
	// OTPLength defaults to 6.
	OTPLength int
	// SendOTP delivers the code (required for /phone-number/send-otp).
	SendOTP func(data OTPData, ctx *betterauth.EndpointContext) error
	// VerifyOTP replaces the built-in OTP check (e.g. an external SMS verification API).
	VerifyOTP func(data OTPData, ctx *betterauth.EndpointContext) (bool, error)
	// SendPasswordResetOTP delivers password reset codes.
	SendPasswordResetOTP func(data OTPData, ctx *betterauth.EndpointContext) error
	// ExpiresIn is the OTP lifetime (default 300s).
	ExpiresIn time.Duration
	// PhoneNumberValidator rejects invalid numbers with INVALID_PHONE_NUMBER.
	PhoneNumberValidator func(phoneNumber string) bool
	// RequireVerification blocks password sign-in for unverified numbers (and sends an OTP).
	RequireVerification    bool
	CallbackOnVerification func(data VerificationData, ctx *betterauth.EndpointContext) error
	SignUpOnVerification   *SignUpOnVerification
	Schema                 *SchemaOptions
	// AllowedAttempts defaults to 3.
	AllowedAttempts *int
}

// OpenAPI metadata, extracted verbatim from the upstream route definitions.
const (
	signInOpenAPI       = `{"summary":"Sign in with phone number","description":"Use this endpoint to sign in with phone number","responses":{"200":{"description":"Success","content":{"application/json":{"schema":{"type":"object","properties":{"user":{"$ref":"#/components/schemas/User"},"session":{"$ref":"#/components/schemas/Session"}}}}}},"400":{"description":"Invalid phone number or password"}}}`
	sendOTPOpenAPI      = `{"summary":"Send OTP to phone number","description":"Use this endpoint to send OTP to phone number","responses":{"200":{"description":"Success","content":{"application/json":{"schema":{"type":"object","properties":{"message":{"type":"string"}}}}}}}}`
	verifyOpenAPI       = `{"summary":"Verify phone number","description":"Use this endpoint to verify phone number","responses":{"200":{"description":"Phone number verified successfully","content":{"application/json":{"schema":{"type":"object","properties":{"status":{"type":"boolean","description":"Indicates if the verification was successful","enum":[true]},"token":{"type":"string","nullable":true,"description":"Session token if session is created, null if disableSession is true or no session is created"},"user":{"type":"object","nullable":true,"properties":{"id":{"type":"string","description":"Unique identifier of the user"},"email":{"type":"string","format":"email","nullable":true,"description":"User's email address"},"emailVerified":{"type":"boolean","nullable":true,"description":"Whether the email is verified"},"name":{"type":"string","nullable":true,"description":"User's name"},"image":{"type":"string","format":"uri","nullable":true,"description":"User's profile image URL"},"phoneNumber":{"type":"string","description":"User's phone number"},"phoneNumberVerified":{"type":"boolean","description":"Whether the phone number is verified"},"createdAt":{"type":"string","format":"date-time","description":"Timestamp when the user was created"},"updatedAt":{"type":"string","format":"date-time","description":"Timestamp when the user was last updated"}},"required":["id","phoneNumber","phoneNumberVerified","createdAt","updatedAt"],"description":"User object with phone number details, null if no user is created or found"}},"required":["status"]}}}},"400":{"description":"Invalid OTP"}}}`
	requestResetOpenAPI = `{"description":"Request OTP for password reset via phone number","responses":{"200":{"description":"OTP sent successfully for password reset","content":{"application/json":{"schema":{"type":"object","properties":{"status":{"type":"boolean","description":"Indicates if the OTP was sent successfully","enum":[true]}},"required":["status"]}}}}}}`
	resetOpenAPI        = `{"description":"Reset password using phone number OTP","responses":{"200":{"description":"Password reset successfully","content":{"application/json":{"schema":{"type":"object","properties":{"status":{"type":"boolean","description":"Indicates if the password was reset successfully","enum":[true]}},"required":["status"]}}}}}}`
)

func mustParse(s string) any {
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		panic(err)
	}
	return v
}

type plugin struct {
	opts      Options
	expiresIn time.Duration
	otpLength int
}

func (p *plugin) allowedAttempts() int {
	if p.opts.AllowedAttempts != nil {
		return *p.opts.AllowedAttempts
	}
	return 3
}

func generateOTP(size int) string { return bacrypto.RandomString(size, "0-9") }

func jsLen(s string) int { return jsonx.EncodeUTF16Length(s) }

func assertPasswordNotTooShort(ctx *betterauth.EndpointContext, pw string) error {
	if jsLen(pw) < ctx.Auth.Password.MinLength {
		ctx.Auth.Logger.Warn("Password is too short")
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooShort)
	}
	return nil
}

func assertPasswordNotTooLong(ctx *betterauth.EndpointContext, pw string) error {
	if jsLen(pw) > ctx.Auth.Password.MaxLength {
		ctx.Auth.Logger.Warn("Password is too long")
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooLong)
	}
	return nil
}

func findUserByPhone(ctx *betterauth.EndpointContext, phone string) (*betterauth.User, error) {
	rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "phoneNumber", Value: phone}}})
	if err != nil || rec == nil {
		return nil, err
	}
	return betterauth.UserFromRecord(rec), nil
}

func (p *plugin) validatePhone(phone string) error {
	if p.opts.PhoneNumberValidator != nil && !p.opts.PhoneNumberValidator(phone) {
		return betterauth.ErrFrom("BAD_REQUEST", ErrInvalidPhoneNumber)
	}
	return nil
}

var signInBody = validate.Object(
	validate.F("phoneNumber", validate.Describe(validate.String(), `Phone number to sign in. Eg: "+1234567890"`)),
	validate.F("password", validate.Describe(validate.String(), `Password to use for sign in.`)),
	validate.F("rememberMe", validate.Optional(validate.Describe(validate.Boolean(), `Remember the session. Eg: true`))),
)

func (p *plugin) signIn(ctx *betterauth.EndpointContext) (any, error) {
	a := ctx.Auth
	phone := ctx.BodyString("phoneNumber")
	password := ctx.BodyString("password")
	if err := p.validatePhone(phone); err != nil {
		return nil, err
	}
	if err := assertPasswordNotTooLong(ctx, password); err != nil {
		return nil, err
	}
	user, err := findUserByPhone(ctx, phone)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidPhoneNumberOrPassword)
	}
	if p.opts.RequireVerification && !adapter.ToBool(user.Additional["phoneNumberVerified"]) {
		otp := generateOTP(p.otpLength)
		if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), phone, otp, time.Now().Add(p.expiresIn), nil); err != nil {
			return nil, err
		}
		if p.opts.SendOTP != nil {
			a.RunInBackgroundOrAwait(func() error { return p.opts.SendOTP(OTPData{PhoneNumber: phone, Code: otp}, ctx) })
		}
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrPhoneNumberNotVerified)
	}
	account, err := a.InternalAdapter.FindCredentialAccount(ctx.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		a.Logger.Warn("Credential account not found")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidPhoneNumberOrPassword)
	}
	if account.Password == nil || *account.Password == "" {
		a.Logger.Warn("Password not found")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrUnexpectedError)
	}
	ok, err := a.Password.Verify(*account.Password, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		a.Logger.Warn("Invalid password")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidPhoneNumberOrPassword)
	}
	rememberMe := ctx.BodyBool("rememberMe")
	dontRemember := rememberMe != nil && !*rememberMe
	session, err := a.InternalAdapter.CreateSession(ctx.Context(), user.ID, &betterauth.CreateSessionOptions{DontRememberMe: dontRemember})
	if err != nil {
		return nil, err
	}
	if session == nil {
		a.Logger.Error("Failed to create session")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", betterauth.ErrFailedToCreateSession)
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, betterauth.Bool(dontRemember), nil); err != nil {
		return nil, err
	}
	return jsonx.O("token", session.Token, "user", a.UserOutput(user)), nil
}

var sendOTPBody = validate.Object(validate.F("phoneNumber", validate.Describe(validate.String(), `Phone number to send OTP. Eg: "+1234567890"`)))

func (p *plugin) sendOTP(ctx *betterauth.EndpointContext) (any, error) {
	a := ctx.Auth
	if p.opts.SendOTP == nil {
		a.Logger.Warn("sendOTP not implemented")
		return nil, betterauth.ErrFrom("NOT_IMPLEMENTED", ErrSendOTPNotImplemented)
	}
	phone := ctx.BodyString("phoneNumber")
	if err := p.validatePhone(phone); err != nil {
		return nil, err
	}
	code := generateOTP(p.otpLength)
	if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), phone, code+":0", time.Now().Add(p.expiresIn), nil); err != nil {
		return nil, err
	}
	data := OTPData{PhoneNumber: phone, Code: code}
	if adv := a.Options.Advanced; adv != nil && adv.BackgroundTasks != nil {
		// The JavaScript promise starts running before it is handed to the background
		// handler, so a throwing handler does not prevent delivery.
		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- nil
					a.Logger.Error("Failed to run background task:", r)
				}
			}()
			done <- p.opts.SendOTP(data, ctx)
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.Logger.Error("Failed to run background task:", r)
				}
			}()
			a.RunInBackground(func() {
				if err := <-done; err != nil {
					a.Logger.Error("Failed to run background task:", err)
				}
			})
		}()
	} else if err := p.opts.SendOTP(data, ctx); err != nil {
		return nil, err
	}
	return jsonx.O("message", "code sent"), nil
}

func (p *plugin) verifyAndConsume(ctx *betterauth.EndpointContext, phone, code string) error {
	if p.opts.VerifyOTP != nil {
		ok, err := p.opts.VerifyOTP(OTPData{PhoneNumber: phone, Code: code}, ctx)
		if err != nil {
			return err
		}
		if !ok {
			return betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
		}
		return ctx.Auth.InternalAdapter.DeleteVerificationByIdentifier(ctx.Context(), phone)
	}
	return p.verifyOTP(ctx, phone, code)
}

// parseAttempts mirrors parseVerificationAttempts (Number(value ?? 0), safe integers > 0).
func parseAttempts(v string, present bool) int {
	if !present {
		return 0
	}
	s := strings.TrimSpace(v)
	if s == "" || strings.ContainsRune(s, '_') {
		return 0
	}
	var f float64
	if i, err := strconv.ParseInt(s, 0, 64); err == nil && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") ||
		strings.HasPrefix(s, "0o") || strings.HasPrefix(s, "0O") || strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B")) {
		f = float64(i)
	} else {
		parsed, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0
		}
		f = parsed
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > 9007199254740991 || f <= 0 {
		return 0
	}
	return int(f)
}

func splitValue(v string) (otp, attempts string, hasAttempts bool) {
	parts := strings.Split(v, ":")
	otp = parts[0]
	if len(parts) > 1 {
		return otp, parts[1], true
	}
	return otp, "", false
}

// verifyOTP mirrors verifyPhoneNumberOTP.
func (p *plugin) verifyOTP(ctx *betterauth.EndpointContext, identifier, provided string) error {
	ia := ctx.Auth.InternalAdapter
	existing, err := ia.FindVerificationValue(ctx.Context(), identifier)
	if err != nil {
		return err
	}
	if existing == nil {
		return betterauth.ErrFrom("BAD_REQUEST", ErrOTPNotFound)
	}
	if existing.ExpiresAt.Before(time.Now()) {
		if err := ia.DeleteVerificationByIdentifier(ctx.Context(), identifier); err != nil {
			return err
		}
		return betterauth.ErrFrom("BAD_REQUEST", ErrOTPExpired)
	}
	allowed := p.allowedAttempts()
	_, raw, has := splitValue(existing.Value)
	if parseAttempts(raw, has) >= allowed {
		if err := ia.DeleteVerificationByIdentifier(ctx.Context(), identifier); err != nil {
			return err
		}
		return betterauth.ErrFrom("FORBIDDEN", ErrTooManyAttempts)
	}
	consumed, err := ia.ConsumeVerificationValue(ctx.Context(), identifier)
	if err != nil {
		return err
	}
	if consumed == nil {
		return betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
	}
	otp, raw, has := splitValue(consumed.Value)
	attempts := parseAttempts(raw, has)
	if attempts >= allowed {
		return betterauth.ErrFrom("FORBIDDEN", ErrTooManyAttempts)
	}
	if otp != provided {
		if _, err := ia.CreateVerificationValue(ctx.Context(), identifier, otp+":"+strconv.Itoa(attempts+1), consumed.ExpiresAt, nil); err != nil {
			return err
		}
		return betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
	}
	return nil
}

var consumeBody = validate.Object(
	validate.F("phoneNumber", validate.Describe(validate.String(), `Phone number to verify. Eg: "+1234567890"`)),
	validate.F("code", validate.Describe(validate.String(), `OTP code. Eg: "123456"`)),
)

var verifyBody = validate.And(validate.Object(
	validate.F("phoneNumber", validate.Describe(validate.String(), `Phone number to verify. Eg: "+1234567890"`)),
	validate.F("code", validate.Describe(validate.String(), `OTP code. Eg: "123456"`)),
	validate.F("disableSession", validate.Optional(validate.Describe(validate.Boolean(), `Disable session creation after verification. Eg: false`))),
	validate.F("updatePhoneNumber", validate.Optional(validate.Describe(validate.Boolean(), `Check if there is a session and update the phone number. Eg: true`))),
), validate.Record(validate.Any()))

func (p *plugin) verify(ctx *betterauth.EndpointContext) (any, error) {
	a := ctx.Auth
	phone := ctx.BodyString("phoneNumber")
	if err := p.verifyAndConsume(ctx, phone, ctx.BodyString("code")); err != nil {
		return nil, err
	}
	if b := ctx.BodyBool("updatePhoneNumber"); b != nil && *b {
		session, err := betterauth.GetSessionFromCtx(ctx, nil)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, betterauth.ErrFrom("UNAUTHORIZED", betterauth.ErrUserNotFound)
		}
		existing, err := a.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "phoneNumber", Value: phone}}})
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrPhoneNumberExist)
		}
		user, err := a.InternalAdapter.UpdateUser(ctx.Context(), session.User.ID, adapter.Record{"phoneNumber": phone, "phoneNumberVerified": true})
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", betterauth.ErrFailedToUpdateUser)
		}
		if p.opts.CallbackOnVerification != nil {
			if err := p.opts.CallbackOnVerification(VerificationData{PhoneNumber: phone, User: user}, ctx); err != nil {
				return nil, err
			}
		}
		return jsonx.O("status", true, "token", session.Session.Token, "user", a.UserOutput(user)), nil
	}
	user, err := findUserByPhone(ctx, phone)
	if err != nil {
		return nil, err
	}
	if user == nil {
		if su := p.opts.SignUpOnVerification; su != nil {
			rest := map[string]any{}
			for k, v := range ctx.BodyMap() {
				switch k {
				case "phoneNumber", "code", "disableSession", "updatePhoneNumber":
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
			data["email"] = su.GetTempEmail(phone)
			if su.GetTempName != nil {
				data["name"] = su.GetTempName(phone)
			} else {
				data["name"] = phone
			}
			data["phoneNumber"] = phone
			data["phoneNumberVerified"] = true
			user, err = a.InternalAdapter.CreateUser(ctx.Context(), data, betterauth.UserInfoSource{Method: "phone-number"})
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", betterauth.ErrFailedToCreateUser)
			}
		}
	} else {
		user, err = a.InternalAdapter.UpdateUser(ctx.Context(), user.ID, adapter.Record{"phoneNumberVerified": true})
		if err != nil {
			return nil, err
		}
	}
	if user == nil {
		return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", betterauth.ErrFailedToUpdateUser)
	}
	if p.opts.CallbackOnVerification != nil {
		if err := p.opts.CallbackOnVerification(VerificationData{PhoneNumber: phone, User: user}, ctx); err != nil {
			return nil, err
		}
	}
	if b := ctx.BodyBool("disableSession"); b == nil || !*b {
		session, err := a.InternalAdapter.CreateSession(ctx.Context(), user.ID, nil)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", betterauth.ErrFailedToCreateSession)
		}
		if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, nil, nil); err != nil {
			return nil, err
		}
		return jsonx.O("status", true, "token", session.Token, "user", a.UserOutput(user)), nil
	}
	return jsonx.O("status", true, "token", nil, "user", a.UserOutput(user)), nil
}

var requestResetBody = validate.Object(validate.F("phoneNumber", validate.String()))

func (p *plugin) requestPasswordReset(ctx *betterauth.EndpointContext) (any, error) {
	a := ctx.Auth
	phone := ctx.BodyString("phoneNumber")
	user, err := findUserByPhone(ctx, phone)
	if err != nil {
		return nil, err
	}
	code := generateOTP(p.otpLength)
	if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), phone+"-request-password-reset", code+":0", time.Now().Add(p.expiresIn), nil); err != nil {
		return nil, err
	}
	if user == nil {
		return jsonx.O("status", true), nil
	}
	if p.opts.SendPasswordResetOTP != nil {
		a.RunInBackgroundOrAwait(func() error {
			return p.opts.SendPasswordResetOTP(OTPData{PhoneNumber: phone, Code: code}, ctx)
		})
	}
	return jsonx.O("status", true), nil
}

var resetBody = validate.Object(
	validate.F("otp", validate.Describe(validate.String(), `The one time password to reset the password. Eg: "123456"`)),
	validate.F("phoneNumber", validate.Describe(validate.String(), `The phone number to the account which intends to reset the password for. Eg: "+1234567890"`)),
	validate.F("newPassword", validate.Describe(validate.String(), `The new password. Eg: "new-and-secure-password"`)),
)

func (p *plugin) resetPassword(ctx *betterauth.EndpointContext) (any, error) {
	a := ctx.Auth
	phone := ctx.BodyString("phoneNumber")
	if err := p.verifyOTP(ctx, phone+"-request-password-reset", ctx.BodyString("otp")); err != nil {
		return nil, err
	}
	user, err := findUserByPhone(ctx, phone)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrUnexpectedError)
	}
	newPassword := ctx.BodyString("newPassword")
	if err := assertPasswordNotTooShort(ctx, newPassword); err != nil {
		return nil, err
	}
	if err := assertPasswordNotTooLong(ctx, newPassword); err != nil {
		return nil, err
	}
	hashed, err := a.Password.Hash(newPassword)
	if err != nil {
		return nil, err
	}
	account, err := a.InternalAdapter.FindCredentialAccount(ctx.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	if account == nil {
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
	return jsonx.O("status", true), nil
}

func (p *plugin) schema() []db.PluginTable {
	col := func(name string) string {
		if p.opts.Schema != nil {
			return p.opts.Schema.Fields[name]
		}
		return ""
	}
	t := db.PluginTable{Key: "user", Fields: []db.Field{
		{Name: "phoneNumber", Type: db.TypeString, Required: db.False, Unique: true, Sortable: true, Returned: db.True, FieldName: col("phoneNumber")},
		{Name: "phoneNumberVerified", Type: db.TypeBoolean, Required: db.False, Returned: db.True, Input: db.False, FieldName: col("phoneNumberVerified")},
	}}
	if p.opts.Schema != nil {
		t.ModelName = p.opts.Schema.ModelName
	}
	return []db.PluginTable{t}
}

// New creates the phone number plugin.
func New(opts Options) *betterauth.Plugin {
	p := &plugin{opts: opts, expiresIn: opts.ExpiresIn, otpLength: opts.OTPLength}
	if p.expiresIn <= 0 {
		p.expiresIn = 300 * time.Second
	}
	if p.otpLength <= 0 {
		p.otpLength = 6
	}
	hooks := &betterauth.DatabaseHooks{}
	hooks.User.Update.Before = func(_ context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
		if v, ok := data["phoneNumber"]; ok && v == nil {
			out := adapter.Record{}
			for k, v := range data {
				out[k] = v
			}
			out["phoneNumberVerified"] = false
			return &betterauth.DBHookResult{Data: out}, nil
		}
		return nil, nil
	}
	return &betterauth.Plugin{
		ID:      "phone-number",
		Version: "1.7.7",
		Init: func(*betterauth.AuthContext) (*betterauth.PluginInit, error) {
			return &betterauth.PluginInit{DatabaseHooks: hooks}, nil
		},
		Hooks: betterauth.PluginHooks{Before: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool {
				if ctx.Path != "/update-user" {
					return false
				}
				body, ok := ctx.Body.(map[string]any)
				if !ok {
					// `"phoneNumber" in ctx.body` throws for non-object bodies upstream.
					panic("TypeError: Cannot use 'in' operator to search for 'phoneNumber'")
				}
				v, has := body["phoneNumber"]
				return has && v != nil
			},
			Handler: func(*betterauth.EndpointContext) (any, error) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrPhoneNumberCannotBeUpdated)
			},
		}}},
		Endpoints: []*betterauth.Endpoint{
			{Key: "signInPhoneNumber", Path: "/sign-in/phone-number", Methods: []string{"POST"}, Body: signInBody,
				Handler: p.signIn, Metadata: map[string]any{"openapi": mustParse(signInOpenAPI)}},
			{Key: "sendPhoneNumberOTP", Path: "/phone-number/send-otp", Methods: []string{"POST"}, Body: sendOTPBody,
				Handler: p.sendOTP, Metadata: map[string]any{"openapi": mustParse(sendOTPOpenAPI)}},
			{Key: "consumePhoneNumberOTP", ServerOnly: true, Methods: []string{"POST"}, Body: consumeBody,
				Metadata: map[string]any{"scope": "server"},
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					if err := p.verifyAndConsume(ctx, ctx.BodyString("phoneNumber"), ctx.BodyString("code")); err != nil {
						return nil, err
					}
					return jsonx.O("status", true), nil
				}},
			{Key: "verifyPhoneNumber", Path: "/phone-number/verify", Methods: []string{"POST"}, Body: verifyBody,
				Handler: p.verify, Metadata: map[string]any{"openapi": mustParse(verifyOpenAPI)}},
			{Key: "requestPasswordResetPhoneNumber", Path: "/phone-number/request-password-reset", Methods: []string{"POST"},
				Body: requestResetBody, Handler: p.requestPasswordReset, Metadata: map[string]any{"openapi": mustParse(requestResetOpenAPI)}},
			{Key: "resetPasswordPhoneNumber", Path: "/phone-number/reset-password", Methods: []string{"POST"},
				Body: resetBody, Handler: p.resetPassword, Metadata: map[string]any{"openapi": mustParse(resetOpenAPI)}},
		},
		Schema: p.schema(),
		RateLimit: []betterauth.PluginRateLimit{{Window: 60 * time.Second, Max: 10,
			PathMatcher: func(path string) bool { return strings.HasPrefix(path, "/phone-number") }}},
		ErrorCodes: ErrorCodes,
		Options:    opts,
	}
}
