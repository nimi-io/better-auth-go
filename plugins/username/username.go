// Package username adds username sign-in and username/displayUsername user fields
// (packages/better-auth/src/plugins/username).
package username

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Error codes (USERNAME_ERROR_CODES).
var (
	ErrInvalidUsernameOrPassword = betterauth.ErrorCode{Code: "INVALID_USERNAME_OR_PASSWORD", Message: "Invalid username or password"}
	ErrEmailNotVerified          = betterauth.ErrorCode{Code: "EMAIL_NOT_VERIFIED", Message: "Email not verified"}
	ErrUnexpectedError           = betterauth.ErrorCode{Code: "UNEXPECTED_ERROR", Message: "Unexpected error"}
	ErrUsernameIsAlreadyTaken    = betterauth.ErrorCode{Code: "USERNAME_IS_ALREADY_TAKEN", Message: "Username is already taken. Please try another."}
	ErrUsernameTooShort          = betterauth.ErrorCode{Code: "USERNAME_TOO_SHORT", Message: "Username is too short"}
	ErrUsernameTooLong           = betterauth.ErrorCode{Code: "USERNAME_TOO_LONG", Message: "Username is too long"}
	ErrInvalidUsername           = betterauth.ErrorCode{Code: "INVALID_USERNAME", Message: "Username is invalid"}
	ErrInvalidDisplayUsername    = betterauth.ErrorCode{Code: "INVALID_DISPLAY_USERNAME", Message: "Display username is invalid"}
	ErrUsernameIsImmutable       = betterauth.ErrorCode{Code: "USERNAME_IS_IMMUTABLE", Message: "Username cannot be updated"}
)

// ErrorCodes lists the plugin error codes ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{ErrInvalidUsernameOrPassword, ErrEmailNotVerified, ErrUnexpectedError,
	ErrUsernameIsAlreadyTaken, ErrUsernameTooShort, ErrUsernameTooLong, ErrInvalidUsername,
	ErrInvalidDisplayUsername, ErrUsernameIsImmutable}

// Validation orders.
const (
	PreNormalization  = "pre-normalization"
	PostNormalization = "post-normalization"
)

// ValidationOrder selects whether values are validated before or after normalization.
type ValidationOrder struct {
	// Username is "pre-normalization" (default) or "post-normalization".
	Username string
	// DisplayUsername is "pre-normalization" (default) or "post-normalization".
	DisplayUsername string
}

// SchemaOptions renames the plugin fields (InferOptionSchema / mergeSchema).
type SchemaOptions struct {
	// ModelName overrides the user model name.
	ModelName string
	// Fields maps logical field names ("username", "displayUsername") to column names.
	Fields map[string]string
}

// Options configures the plugin (UsernameOptions).
type Options struct {
	Schema *SchemaOptions
	// MinUsernameLength defaults to 3; MaxUsernameLength to 30.
	MinUsernameLength int
	MaxUsernameLength int
	// UsernameValidator replaces the default /^[a-zA-Z0-9_.]+$/ check.
	UsernameValidator func(username string) bool
	// DisplayUsernameValidator validates displayUsername (no validation by default).
	DisplayUsernameValidator func(displayUsername string) bool
	// UsernameNormalization replaces the default lower-casing.
	UsernameNormalization func(username string) string
	// DisableUsernameNormalization stores usernames as given (usernameNormalization: false).
	DisableUsernameNormalization bool
	// DisplayUsernameNormalization normalizes displayUsername (none by default).
	DisplayUsernameNormalization func(displayUsername string) string
	ValidationOrder              ValidationOrder
	// ImmutableUsername rejects changing a username once set.
	ImmutableUsername bool
	// DisplayUsername controls the displayUsername field (default true).
	DisplayUsername *bool
}

var defaultUsernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

func defaultUsernameValidator(username string) bool { return defaultUsernameRe.MatchString(username) }

var signInUsernameBody = validate.Object(
	validate.F("username", validate.Describe(validate.String(), "The username of the user")),
	validate.F("password", validate.Describe(validate.String(), "The password of the user")),
	validate.F("rememberMe", validate.Optional(validate.Describe(validate.Boolean(), "Remember the user session"))),
	validate.F("callbackURL", validate.Optional(validate.Describe(validate.String(), "URL to redirect to after sign in (also used as the redirect target for email verification when required)"))),
)

var isUsernameAvailableBody = validate.Object(
	validate.F("username", validate.Describe(validate.String(), "The username to check")),
)

const signInOpenAPI = `{"summary":"Sign in with username","description":"Sign in with username","responses":{"200":{"description":"Success","content":{"application/json":{"schema":{"type":"object","properties":{"redirect":{"type":"boolean","description":"Whether the client should follow the Location header. True when callbackURL was provided."},"token":{"type":"string","description":"Session token for the authenticated session"},"url":{"type":"string","nullable":true,"description":"The callbackURL echoed back so the client can redirect."},"user":{"$ref":"#/components/schemas/User"}},"required":["redirect","token","user"]}}}},"422":{"description":"Unprocessable Entity. Validation error","content":{"application/json":{"schema":{"type":"object","properties":{"message":{"type":"string"}}}}}}}}`

func mustParse(s string) any {
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		panic(err)
	}
	return v
}

type plugin struct {
	opts                   Options
	includeDisplayUsername bool
	min, max               int
	validator              func(string) bool
}

func (p *plugin) normalize(username string) string {
	if p.opts.DisableUsernameNormalization {
		return username
	}
	if p.opts.UsernameNormalization != nil {
		return p.opts.UsernameNormalization(username)
	}
	return strings.ToLower(username)
}

func (p *plugin) normalizeDisplay(displayUsername string) string {
	if p.opts.DisplayUsernameNormalization != nil {
		return p.opts.DisplayUsernameNormalization(displayUsername)
	}
	return displayUsername
}

func jsLen(s string) int { return jsonx.EncodeUTF16Length(s) }

// validateValue returns the error code for an invalid username (validateUsernameValue).
func (p *plugin) validateValue(username string) *betterauth.ErrorCode {
	v := username
	if p.opts.ValidationOrder.Username == PostNormalization {
		v = p.normalize(username)
	}
	if jsLen(v) < p.min {
		return &ErrUsernameTooShort
	}
	if jsLen(v) > p.max {
		return &ErrUsernameTooLong
	}
	if !p.validator(v) {
		return &ErrInvalidUsername
	}
	return nil
}

func findUserByUsername(ctx context.Context, ac *betterauth.AuthContext, username string) (*betterauth.User, error) {
	rec, err := ac.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "username", Value: username}}})
	if err != nil || rec == nil {
		return nil, err
	}
	return betterauth.UserFromRecord(rec), nil
}

// validateUsername is used by the database hooks for non-HTTP writes.
func (p *plugin) validateUsername(ctx context.Context, ac *betterauth.AuthContext, username string, displayUsername *string, currentUserID string) error {
	if code := p.validateValue(username); code != nil {
		return betterauth.ErrFrom("BAD_REQUEST", *code)
	}
	existing, err := findUserByUsername(ctx, ac, p.normalize(username))
	if err != nil {
		return err
	}
	if existing != nil && (currentUserID == "" || existing.ID != currentUserID) {
		return betterauth.ErrFrom("BAD_REQUEST", ErrUsernameIsAlreadyTaken)
	}
	if displayUsername != nil && *displayUsername != "" && p.opts.DisplayUsernameValidator != nil {
		d := *displayUsername
		if p.opts.ValidationOrder.DisplayUsername == PostNormalization {
			d = p.normalizeDisplay(d)
		}
		if !p.opts.DisplayUsernameValidator(d) {
			return betterauth.ErrFrom("BAD_REQUEST", ErrInvalidDisplayUsername)
		}
	}
	return nil
}

var pathsWithHTTPHookValidation = []string{"/sign-up/email", "/update-user"}

// hookValues extracts username/displayUsername from a record being written.
func hookValues(data adapter.Record) (username string, hasUsername bool, display *string) {
	if v, ok := data["username"]; ok {
		if s, ok := v.(string); ok && s != "" {
			username, hasUsername = s, true
		}
	}
	if v, ok := data["displayUsername"]; ok {
		if s, ok := v.(string); ok {
			display = &s
		}
	}
	return
}

func skipValidation(ctx context.Context) bool {
	ec := betterauth.EndpointContextFrom(ctx)
	return ec != nil && slices.Contains(pathsWithHTTPHookValidation, ec.Path)
}

func copyRecord(r adapter.Record) adapter.Record {
	out := adapter.Record{}
	for k, v := range r {
		out[k] = v
	}
	return out
}

func (p *plugin) init(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
	hooks := &betterauth.DatabaseHooks{}
	hooks.User.Create.Before = func(ctx context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
		username, has, display := hookValues(data)
		out := copyRecord(data)
		if has {
			if !skipValidation(ctx) {
				if err := p.validateUsername(ctx, ac, username, display, ""); err != nil {
					return nil, err
				}
			}
			out["username"] = p.normalize(username)
			if p.includeDisplayUsername {
				if display != nil && *display != "" {
					out["displayUsername"] = p.normalizeDisplay(*display)
				} else {
					out["displayUsername"] = username
				}
			}
			return &betterauth.DBHookResult{Data: out}, nil
		}
		if p.includeDisplayUsername && display != nil && *display != "" {
			out["displayUsername"] = p.normalizeDisplay(*display)
		}
		return &betterauth.DBHookResult{Data: out}, nil
	}
	hooks.User.Update.Before = func(ctx context.Context, data adapter.Record) (*betterauth.DBHookResult, error) {
		username, has, display := hookValues(data)
		out := copyRecord(data)
		if has {
			if !skipValidation(ctx) {
				current := ""
				if ec := betterauth.EndpointContextFrom(ctx); ec != nil && ec.Session != nil && ec.Session.User != nil {
					current = ec.Session.User.ID
				}
				if current == "" {
					current, _ = data["id"].(string)
				}
				if err := p.validateUsername(ctx, ac, username, display, current); err != nil {
					return nil, err
				}
			}
			out["username"] = p.normalize(username)
		}
		if p.includeDisplayUsername && display != nil && *display != "" {
			out["displayUsername"] = p.normalizeDisplay(*display)
		}
		return &betterauth.DBHookResult{Data: out}, nil
	}
	return &betterauth.PluginInit{DatabaseHooks: hooks}, nil
}

func assertPasswordNotTooLong(ctx *betterauth.EndpointContext, pw string) error {
	if jsLen(pw) > ctx.Auth.Password.MaxLength {
		ctx.Auth.Logger.Warn("Password is too long")
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooLong)
	}
	return nil
}

func (p *plugin) signIn(ctx *betterauth.EndpointContext) (any, error) {
	a := ctx.Auth
	bodyUsername := ctx.BodyString("username")
	password := ctx.BodyString("password")
	if bodyUsername == "" || password == "" {
		a.Logger.Warn("Username or password not found")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidUsernameOrPassword)
	}
	username := bodyUsername
	if p.opts.ValidationOrder.Username == PreNormalization {
		username = p.normalize(bodyUsername)
	}
	if jsLen(username) < p.min {
		a.Logger.Warn("Username too short")
		return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", ErrUsernameTooShort)
	}
	if jsLen(username) > p.max {
		a.Logger.Warn("Username too long")
		return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", ErrUsernameTooLong)
	}
	if !p.validator(username) {
		return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", ErrInvalidUsername)
	}
	if err := assertPasswordNotTooLong(ctx, password); err != nil {
		return nil, err
	}
	user, err := findUserByUsername(ctx.Context(), a, p.normalize(username))
	if err != nil {
		return nil, err
	}
	if user == nil {
		_, _ = a.Password.Hash(password)
		a.Logger.Warn("User not found")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidUsernameOrPassword)
	}
	account, err := a.InternalAdapter.FindCredentialAccount(ctx.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidUsernameOrPassword)
	}
	if account.Password == nil || *account.Password == "" {
		a.Logger.Warn("Password not found")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidUsernameOrPassword)
	}
	ok, err := a.Password.Verify(*account.Password, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		a.Logger.Warn("Invalid password")
		return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidUsernameOrPassword)
	}
	callbackURL := ctx.BodyString("callbackURL")
	if ep := a.Options.EmailAndPassword; ep != nil && ep.RequireEmailVerification && !user.EmailVerified {
		ev := a.Options.EmailVerification
		if ev == nil || ev.SendVerificationEmail == nil {
			return nil, betterauth.ErrFrom("FORBIDDEN", ErrEmailNotVerified)
		}
		if ev.SendOnSignIn {
			token, err := betterauth.CreateEmailVerificationToken(a.Secret, user.Email, "", ev.ExpiresIn, nil)
			if err != nil {
				return nil, err
			}
			cb := callbackURL
			if cb == "" {
				cb = "/"
			}
			u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + betterauth.EncodeURIComponent(cb)
			a.RunInBackgroundOrAwait(func() error {
				return ev.SendVerificationEmail(context.WithoutCancel(ctx.Context()), betterauth.EmailData{User: user, URL: u, Token: token}, ctx.Request)
			})
		}
		return nil, betterauth.ErrFrom("FORBIDDEN", ErrEmailNotVerified)
	}
	rememberMe := ctx.BodyBool("rememberMe")
	dontRemember := rememberMe != nil && !*rememberMe
	session, err := a.InternalAdapter.CreateSession(ctx.Context(), user.ID, &betterauth.CreateSessionOptions{DontRememberMe: dontRemember})
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", betterauth.ErrFailedToCreateSession)
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, betterauth.Bool(dontRemember), nil); err != nil {
		return nil, err
	}
	if callbackURL != "" {
		ctx.SetHeader("Location", callbackURL)
	}
	var urlVal any = jsonx.Undefined
	if _, ok := ctx.BodyMap()["callbackURL"]; ok {
		urlVal = callbackURL
	}
	return jsonx.O("redirect", callbackURL != "", "token", session.Token, "url", urlVal, "user", a.UserOutput(user)), nil
}

func (p *plugin) isAvailable(ctx *betterauth.EndpointContext) (any, error) {
	username := ctx.BodyString("username")
	if username == "" {
		return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", ErrInvalidUsername)
	}
	if jsLen(username) < p.min {
		return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", ErrUsernameTooShort)
	}
	if jsLen(username) > p.max {
		return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", ErrUsernameTooLong)
	}
	if !p.validator(username) {
		return nil, betterauth.ErrFrom("UNPROCESSABLE_ENTITY", ErrInvalidUsername)
	}
	user, err := findUserByUsername(ctx.Context(), ctx.Auth, p.normalize(username))
	if err != nil {
		return nil, err
	}
	return jsonx.O("available", user == nil), nil
}

// hookCopyDisplayToUsername uses a valid displayUsername as the username when only the
// display name is given on sign-up.
func (p *plugin) hookCopyDisplayToUsername(ctx *betterauth.EndpointContext) (any, error) {
	body := ctx.BodyMap()
	if body == nil {
		return nil, nil
	}
	display, ok := body["displayUsername"].(string)
	if _, hasUsername := body["username"]; !ok || hasUsername {
		return nil, nil
	}
	if p.validateValue(display) == nil {
		body["username"] = display
	}
	return nil, nil
}

func (p *plugin) hookValidate(ctx *betterauth.EndpointContext) (any, error) {
	body := ctx.BodyMap()
	if body == nil {
		return nil, nil
	}
	if username, ok := body["username"].(string); ok {
		if code := p.validateValue(username); code != nil {
			return nil, betterauth.ErrFrom("BAD_REQUEST", *code)
		}
		normalized := p.normalize(username)
		var session *betterauth.SessionWithUser
		if ctx.Path == "/update-user" {
			s, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			session = s
		}
		if ctx.Path == "/update-user" && p.opts.ImmutableUsername {
			var current any
			if session != nil {
				current = session.User.Additional["username"]
			}
			cs, isString := current.(string)
			if jsTruthy(current) && (!isString || cs != normalized) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrUsernameIsImmutable)
			}
		}
		existing, err := findUserByUsername(ctx.Context(), ctx.Auth, normalized)
		if err != nil {
			return nil, err
		}
		if ctx.Path == "/sign-up/email" && existing != nil {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrUsernameIsAlreadyTaken)
		}
		if ctx.Path == "/update-user" && existing != nil {
			if session == nil || existing.ID != session.User.ID {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrUsernameIsAlreadyTaken)
			}
		}
	}
	if !p.includeDisplayUsername {
		return nil, nil
	}
	if display, ok := body["displayUsername"].(string); ok {
		if p.opts.ValidationOrder.DisplayUsername == PostNormalization {
			display = p.normalizeDisplay(display)
		}
		if p.opts.DisplayUsernameValidator != nil && !p.opts.DisplayUsernameValidator(display) {
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidDisplayUsername)
		}
	}
	return nil, nil
}

func (p *plugin) hookDefaultDisplayUsername(ctx *betterauth.EndpointContext) (any, error) {
	if !p.includeDisplayUsername {
		return nil, nil
	}
	body := ctx.BodyMap()
	if body == nil {
		return nil, nil
	}
	if jsTruthy(body["username"]) && !jsTruthy(body["displayUsername"]) {
		body["displayUsername"] = body["username"]
	}
	return nil, nil
}

func jsTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	}
	return !validate.IsUndefined(v)
}

func (p *plugin) schema() []db.PluginTable {
	transform := func(norm func(string) string) func(any) (any, error) {
		return func(v any) (any, error) {
			if s, ok := v.(string); ok {
				return norm(s), nil
			}
			return v, nil
		}
	}
	fieldName := func(name string) string {
		if p.opts.Schema != nil {
			return p.opts.Schema.Fields[name]
		}
		return ""
	}
	fields := []db.Field{{
		Name: "username", Type: db.TypeString, Required: db.False, Sortable: true, Unique: true,
		Returned: db.True, TransformInput: transform(p.normalize), FieldName: fieldName("username"),
	}}
	if p.includeDisplayUsername {
		fields = append(fields, db.Field{
			Name: "displayUsername", Type: db.TypeString, Required: db.False,
			TransformInput: transform(p.normalizeDisplay), FieldName: fieldName("displayUsername"),
		})
	}
	t := db.PluginTable{Key: "user", Fields: fields}
	if p.opts.Schema != nil {
		t.ModelName = p.opts.Schema.ModelName
	}
	return []db.PluginTable{t}
}

func pathIs(paths ...string) func(*betterauth.EndpointContext) bool {
	return func(ctx *betterauth.EndpointContext) bool { return slices.Contains(paths, ctx.Path) }
}

// New creates the username plugin.
func New(opts Options) *betterauth.Plugin {
	p := &plugin{opts: opts, includeDisplayUsername: opts.DisplayUsername == nil || *opts.DisplayUsername,
		min: opts.MinUsernameLength, max: opts.MaxUsernameLength, validator: opts.UsernameValidator}
	if p.min == 0 {
		p.min = 3
	}
	if p.max == 0 {
		p.max = 30
	}
	if p.validator == nil {
		p.validator = defaultUsernameValidator
	}
	return &betterauth.Plugin{
		ID:      "username",
		Version: "1.7.7",
		Init:    p.init,
		Endpoints: []*betterauth.Endpoint{
			{
				Key: "signInUsername", Path: "/sign-in/username", Methods: []string{"POST"},
				Body: signInUsernameBody, Handler: p.signIn,
				Metadata: map[string]any{"openapi": mustParse(signInOpenAPI)},
			},
			{
				Key: "isUsernameAvailable", Path: "/is-username-available", Methods: []string{"POST"},
				Body: isUsernameAvailableBody, Handler: p.isAvailable,
			},
		},
		Schema: p.schema(),
		Hooks: betterauth.PluginHooks{Before: []betterauth.Hook{
			{Matcher: pathIs("/sign-up/email"), Handler: p.hookCopyDisplayToUsername},
			{Matcher: pathIs("/sign-up/email", "/update-user"), Handler: p.hookValidate},
			{Matcher: pathIs("/sign-up/email"), Handler: p.hookDefaultDisplayUsername},
		}},
		ErrorCodes: ErrorCodes,
		Options:    opts,
	}
}
