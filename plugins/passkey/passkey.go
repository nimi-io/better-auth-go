// Package passkey implements WebAuthn passkey registration and sign-in (packages/passkey,
// @better-auth/passkey). Options returned to the browser match @simplewebauthn/server's
// output so the official passkeyClient works unchanged; stored credentials use the same
// encoding (publicKey = base64 of the COSE key) so TypeScript and Go servers can share
// a database.
package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Version is the upstream package version this port follows.
const Version = "1.7.7"

// maxAgeInSeconds is the lifetime of a WebAuthn challenge (MAX_AGE_IN_SECONDS).
const maxAgeInSeconds = 60 * 5

// Error codes (PASSKEY_ERROR_CODES).
var (
	ErrChallengeNotFound                     = betterauth.ErrorCode{Code: "CHALLENGE_NOT_FOUND", Message: "Challenge not found"}
	ErrYouAreNotAllowedToRegisterThisPasskey = betterauth.ErrorCode{Code: "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", Message: "You are not allowed to register this passkey"}
	ErrFailedToVerifyRegistration            = betterauth.ErrorCode{Code: "FAILED_TO_VERIFY_REGISTRATION", Message: "Failed to verify registration"}
	ErrPasskeyNotFound                       = betterauth.ErrorCode{Code: "PASSKEY_NOT_FOUND", Message: "Passkey not found"}
	ErrAuthenticationFailed                  = betterauth.ErrorCode{Code: "AUTHENTICATION_FAILED", Message: "Authentication failed"}
	ErrUnableToCreateSession                 = betterauth.ErrorCode{Code: "UNABLE_TO_CREATE_SESSION", Message: "Unable to create session"}
	ErrUserNotFound                          = betterauth.ErrorCode{Code: "USER_NOT_FOUND", Message: "User not found"}
	ErrFailedToUpdatePasskey                 = betterauth.ErrorCode{Code: "FAILED_TO_UPDATE_PASSKEY", Message: "Failed to update passkey"}
	ErrPreviouslyRegistered                  = betterauth.ErrorCode{Code: "PREVIOUSLY_REGISTERED", Message: "Previously registered"}
	ErrRegistrationCancelled                 = betterauth.ErrorCode{Code: "REGISTRATION_CANCELLED", Message: "Registration cancelled"}
	ErrAuthCancelled                         = betterauth.ErrorCode{Code: "AUTH_CANCELLED", Message: "Auth cancelled"}
	ErrUnknownError                          = betterauth.ErrorCode{Code: "UNKNOWN_ERROR", Message: "Unknown error"}
	ErrSessionRequired                       = betterauth.ErrorCode{Code: "SESSION_REQUIRED", Message: "Passkey registration requires an authenticated session"}
	ErrResolveUserRequired                   = betterauth.ErrorCode{Code: "RESOLVE_USER_REQUIRED", Message: "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false"}
	ErrResolvedUserInvalid                   = betterauth.ErrorCode{Code: "RESOLVED_USER_INVALID", Message: "Resolved user is invalid"}
)

// ErrorCodes lists the plugin error codes ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{
	ErrChallengeNotFound, ErrYouAreNotAllowedToRegisterThisPasskey, ErrFailedToVerifyRegistration,
	ErrPasskeyNotFound, ErrAuthenticationFailed, ErrUnableToCreateSession, ErrUserNotFound,
	ErrFailedToUpdatePasskey, ErrPreviouslyRegistered, ErrRegistrationCancelled, ErrAuthCancelled,
	ErrUnknownError, ErrSessionRequired, ErrResolveUserRequired, ErrResolvedUserInvalid,
}

// RegistrationUser is the WebAuthn user a passkey is registered for (PasskeyRegistrationUser).
type RegistrationUser struct {
	ID          string
	Name        string
	DisplayName string
}

// ExtensionsResolver returns WebAuthn extension inputs for a ceremony
// (PasskeyExtensionsResolver). Use StaticExtensions for a fixed object.
type ExtensionsResolver func(ctx *betterauth.EndpointContext) (*jsonx.Object, error)

// StaticExtensions returns a resolver for a fixed extensions object.
func StaticExtensions(o *jsonx.Object) ExtensionsResolver {
	return func(*betterauth.EndpointContext) (*jsonx.Object, error) { return o, nil }
}

// AfterRegistrationArgs are passed to RegistrationOptions.AfterVerification.
type AfterRegistrationArgs struct {
	Ctx          *betterauth.EndpointContext
	Verification *VerifiedRegistrationResponse
	User         RegistrationUser
	// ClientData is the RegistrationResponseJSON sent by the browser.
	ClientData any
	// Context is the context passed to generate-register-options (nil when absent).
	Context *string
}

// AfterRegistrationResult may override the passkey owner or provide a fallback name.
type AfterRegistrationResult struct {
	UserID string
	Name   string
}

// RegistrationOptions configures registration (PasskeyRegistrationOptions).
type RegistrationOptions struct {
	// RequireSession defaults to true. When false, ResolveUser identifies the user for
	// passkey-first registration.
	RequireSession *bool
	ResolveUser    func(ctx *betterauth.EndpointContext, context *string) (*RegistrationUser, error)
	// AfterVerification runs after the attestation is verified, before the passkey is
	// stored. It may return a userId to link the passkey to and/or a name.
	AfterVerification func(args AfterRegistrationArgs) (*AfterRegistrationResult, error)
	Extensions        ExtensionsResolver
}

// AfterAuthenticationArgs are passed to AuthenticationOptions.AfterVerification.
type AfterAuthenticationArgs struct {
	Ctx          *betterauth.EndpointContext
	Verification *VerifiedAuthenticationResponse
	ClientData   map[string]any
}

// AuthenticationOptions configures authentication (PasskeyAuthenticationOptions).
type AuthenticationOptions struct {
	Extensions        ExtensionsResolver
	AfterVerification func(args AfterAuthenticationArgs) error
}

// AdvancedOptions are advanced options.
type AdvancedOptions struct {
	// WebAuthnChallengeCookie defaults to "better-auth-passkey".
	WebAuthnChallengeCookie string
}

// SchemaOptions renames the passkey model and its fields (InferOptionSchema / mergeSchema).
type SchemaOptions struct {
	ModelName string
	Fields    map[string]string
}

// Options configures the plugin (PasskeyOptions).
type Options struct {
	// RPID defaults to the hostname of the configured baseURL ("localhost" without one).
	RPID string
	// RPName defaults to the app name.
	RPName string
	// Origin lists the expected origins; empty uses the request Origin header.
	Origin []string
	// AuthenticatorSelection is merged over {residentKey: "preferred", userVerification: "preferred"}.
	AuthenticatorSelection *AuthenticatorSelection
	Advanced               AdvancedOptions
	Schema                 *SchemaOptions
	Registration           *RegistrationOptions
	Authentication         *AuthenticationOptions
}

// Passkey is a stored passkey.
type Passkey struct {
	ID           string
	Name         string
	PublicKey    string
	UserID       string
	CredentialID string
	Counter      float64
	DeviceType   string
	BackedUp     bool
	Transports   *string
	CreatedAt    time.Time
	AAGUID       string
	// Record is the raw stored row.
	Record adapter.Record
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int32:
		return float64(t)
	case int64:
		return float64(t)
	case uint32:
		return float64(t)
	case uint64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	}
	return 0
}

func passkeyFromRecord(r adapter.Record) *Passkey {
	if r == nil {
		return nil
	}
	p := &Passkey{Record: r, ID: str(r["id"]), Name: str(r["name"]), PublicKey: str(r["publicKey"]),
		UserID: str(r["userId"]), CredentialID: str(r["credentialID"]), Counter: num(r["counter"]),
		DeviceType: str(r["deviceType"]), AAGUID: str(r["aaguid"])}
	p.BackedUp, _ = r["backedUp"].(bool)
	if t, ok := r["transports"].(string); ok {
		p.Transports = &t
	}
	p.CreatedAt, _ = adapter.ToTime(r["createdAt"])
	return p
}

// passkeyFields is the schema field order (used for JSON output).
var passkeyFields = []string{"name", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp", "transports", "createdAt", "aaguid"}

// passkeyOutput renders a stored row in schema order; missing fields are null.
func passkeyOutput(r adapter.Record) *jsonx.Object {
	o := jsonx.NewObject()
	if v, ok := r["id"]; ok {
		o.Set("id", v)
	}
	seen := map[string]bool{"id": true}
	for _, k := range passkeyFields {
		seen[k] = true
		// Never-written optional columns are null (as SQL-backed TypeScript deployments
		// return them) rather than absent.
		o.Set(k, r[k])
	}
	for k, v := range r {
		if !seen[k] {
			o.Set(k, v)
		}
	}
	return o
}

func passkeySchema(o *SchemaOptions) []db.PluginTable {
	col := func(name string) string {
		if o != nil && o.Fields != nil {
			return o.Fields[name]
		}
		return ""
	}
	t := db.PluginTable{
		Key: "passkey",
		Fields: []db.Field{
			{Name: "name", Type: db.TypeString, Required: db.False, FieldName: col("name")},
			{Name: "publicKey", Type: db.TypeString, Required: db.True, FieldName: col("publicKey")},
			{Name: "userId", Type: db.TypeString, References: &db.Reference{Model: "user", Field: "id"}, Required: db.True, Index: true, FieldName: col("userId")},
			{Name: "credentialID", Type: db.TypeString, Required: db.True, Index: true, FieldName: col("credentialID")},
			{Name: "counter", Type: db.TypeNumber, Required: db.True, FieldName: col("counter")},
			{Name: "deviceType", Type: db.TypeString, Required: db.True, FieldName: col("deviceType")},
			{Name: "backedUp", Type: db.TypeBoolean, Required: db.True, FieldName: col("backedUp")},
			{Name: "transports", Type: db.TypeString, Required: db.False, FieldName: col("transports")},
			{Name: "createdAt", Type: db.TypeDate, Required: db.False, FieldName: col("createdAt")},
			{Name: "aaguid", Type: db.TypeString, Required: db.False, FieldName: col("aaguid")},
		},
	}
	if o != nil {
		t.ModelName = o.ModelName
	}
	return []db.PluginTable{t}
}

// getRpID is utils.getRpID: options.rpID, else the hostname of the configured baseURL.
func getRpID(opts *Options, cfg *betterauth.Config) (string, error) {
	if opts.RPID != "" {
		return opts.RPID, nil
	}
	if cfg == nil || cfg.BaseURL == "" || cfg.DynamicBaseURL != nil {
		return "localhost", nil
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme == "" {
		return "", betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "Invalid URL")
	}
	h := strings.ToLower(u.Hostname())
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h, nil
}

// jsTrim is String.prototype.trim.
func jsTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == 0xFEFF })
}

// splitTransports is `transports?.split(",")`: nil when the column is null.
func splitTransports(t *string) []string {
	if t == nil {
		return nil
	}
	return strings.Split(*t, ",")
}

// challengeValue is the stored challenge (StoredChallengeValue).
type challengeValue struct {
	Type              string `json:"type,omitempty"`
	ExpectedChallenge string `json:"expectedChallenge"`
	UserData          struct {
		ID          string `json:"id"`
		Name        string `json:"name,omitempty"`
		DisplayName string `json:"displayName,omitempty"`
	} `json:"userData"`
	Context *string `json:"context,omitempty"`
}

type plugin struct {
	opts           Options
	requireSession bool
	cookieName     string
}

// New creates the passkey plugin.
func New(opts Options) *betterauth.Plugin {
	if opts.Advanced.WebAuthnChallengeCookie == "" {
		opts.Advanced.WebAuthnChallengeCookie = "better-auth-passkey"
	}
	p := &plugin{opts: opts, requireSession: true, cookieName: opts.Advanced.WebAuthnChallengeCookie}
	if opts.Registration != nil && opts.Registration.RequireSession != nil {
		p.requireSession = *opts.Registration.RequireSession
	}
	o := &p.opts
	return &betterauth.Plugin{
		ID:      "passkey",
		Version: Version,
		Endpoints: []*betterauth.Endpoint{
			p.generateRegistrationOptionsEndpoint(),
			p.generateAuthenticationOptionsEndpoint(),
			p.verifyRegistrationEndpoint(),
			p.verifyAuthenticationEndpoint(),
			listPasskeysEndpoint(),
			deletePasskeyEndpoint(),
			updatePasskeyEndpoint(),
		},
		Schema:     passkeySchema(opts.Schema),
		ErrorCodes: ErrorCodes,
		Options:    o,
	}
}

func resolveExtensions(r ExtensionsResolver, ctx *betterauth.EndpointContext) (*jsonx.Object, error) {
	if r == nil {
		return nil, nil
	}
	return r(ctx)
}

func sessionName(u *betterauth.User) string {
	if u.Email != "" {
		return u.Email
	}
	return u.ID
}

func (p *plugin) resolveRegistrationUser(ctx *betterauth.EndpointContext) (*RegistrationUser, error) {
	if p.requireSession {
		s := ctx.Session
		if s == nil || s.User == nil || s.User.ID == "" {
			return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrSessionRequired)
		}
		n := sessionName(s.User)
		return &RegistrationUser{ID: s.User.ID, Name: n, DisplayName: n}, nil
	}
	s, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if s != nil && s.User != nil && s.User.ID != "" {
		n := sessionName(s.User)
		return &RegistrationUser{ID: s.User.ID, Name: n, DisplayName: n}, nil
	}
	if p.opts.Registration == nil || p.opts.Registration.ResolveUser == nil {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrResolveUserRequired)
	}
	var c *string
	if ctx.HasQuery("context") {
		v := ctx.QueryString("context")
		c = &v
	}
	u, err := p.opts.Registration.ResolveUser(ctx, c)
	if err != nil {
		return nil, err
	}
	if u == nil || u.ID == "" || u.Name == "" {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrResolvedUserInvalid)
	}
	return u, nil
}

func (p *plugin) setChallenge(ctx *betterauth.EndpointContext, value any) error {
	token := bacrypto.RandomString(32)
	c := ctx.Auth.CreateAuthCookie(p.cookieName, nil)
	attrs := c.Attributes
	attrs.MaxAge = betterauth.Int(maxAgeInSeconds)
	ctx.SetSignedCookie(c.Name, token, ctx.Auth.Secret, attrs)
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = ctx.Auth.InternalAdapter.CreateVerificationValue(ctx.Context(), token, string(raw),
		time.Now().Add(maxAgeInSeconds*time.Second), nil)
	return err
}

// consumeChallenge reads the challenge cookie and consumes the stored challenge.
func (p *plugin) consumeChallenge(ctx *betterauth.EndpointContext, ceremony string) (*challengeValue, error) {
	c := ctx.Auth.CreateAuthCookie(p.cookieName, nil)
	token, ok := ctx.GetSignedCookie(c.Name, ctx.Auth.Secret)
	if !ok || token == "" {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrChallengeNotFound)
	}
	v, err := ctx.Auth.InternalAdapter.ConsumeVerificationValue(ctx.Context(), token)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrChallengeNotFound)
	}
	var cv challengeValue
	if err := json.Unmarshal([]byte(v.Value), &cv); err != nil {
		return nil, err
	}
	if cv.Type != ceremony {
		return nil, betterauth.ErrFrom("BAD_REQUEST", ErrChallengeNotFound)
	}
	return &cv, nil
}

func (p *plugin) userPasskeys(ctx *betterauth.EndpointContext, userID string) ([]*Passkey, error) {
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "passkey",
		Where: []adapter.Where{{Field: "userId", Value: userID}}})
	if err != nil {
		return nil, err
	}
	out := make([]*Passkey, 0, len(rows))
	for _, r := range rows {
		out = append(out, passkeyFromRecord(r))
	}
	return out, nil
}

func (p *plugin) authenticatorSelection(ctx *betterauth.EndpointContext) *jsonx.Object {
	sel := jsonx.O("residentKey", "preferred", "userVerification", "preferred")
	if a := p.opts.AuthenticatorSelection; a != nil {
		if a.AuthenticatorAttachment != "" {
			sel.Set("authenticatorAttachment", a.AuthenticatorAttachment)
		}
		if a.RequireResidentKey != nil {
			sel.Set("requireResidentKey", *a.RequireResidentKey)
		}
		if a.ResidentKey != "" {
			sel.Set("residentKey", a.ResidentKey)
		}
		if a.UserVerification != "" {
			sel.Set("userVerification", a.UserVerification)
		}
	}
	if att := ctx.QueryString("authenticatorAttachment"); att != "" {
		sel.Set("authenticatorAttachment", att)
	}
	return sel
}

func (p *plugin) generateRegistrationOptionsEndpoint() *betterauth.Endpoint {
	var use []betterauth.Middleware
	if p.requireSession {
		use = []betterauth.Middleware{betterauth.FreshSessionMiddleware}
	}
	return &betterauth.Endpoint{
		Key: "generatePasskeyRegistrationOptions", Path: "/passkey/generate-register-options", Methods: []string{"GET"},
		Use: use,
		Query: validate.Optional(validate.Object(
			validate.F("authenticatorAttachment", validate.Optional(validate.Enum("platform", "cross-platform"))),
			validate.F("name", validate.Optional(validate.String())),
			validate.F("context", validate.Optional(validate.String())),
		)),
		Metadata: map[string]any{"openapi": mustParse(generateRegisterOptionsOpenAPI)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			user, err := p.resolveRegistrationUser(ctx)
			if err != nil {
				return nil, err
			}
			passkeys, err := p.userPasskeys(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			var regExt ExtensionsResolver
			if p.opts.Registration != nil {
				regExt = p.opts.Registration.Extensions
			}
			ext, err := resolveExtensions(regExt, ctx)
			if err != nil {
				return nil, err
			}
			rpID, err := getRpID(&p.opts, ctx.Auth.Options)
			if err != nil {
				return nil, err
			}
			rpName := p.opts.RPName
			if rpName == "" {
				rpName = ctx.Auth.AppName
			}
			userName := ctx.QueryString("name")
			if userName == "" {
				userName = user.Name
			}
			if userName == "" {
				userName = user.ID
			}
			displayName := user.DisplayName
			if displayName == "" {
				displayName = user.Name
			}
			if displayName == "" {
				displayName = user.ID
			}
			exclude := make([]CredentialDescriptor, 0, len(passkeys))
			for _, pk := range passkeys {
				exclude = append(exclude, CredentialDescriptor{ID: pk.CredentialID, Transports: splitTransports(pk.Transports)})
			}
			options, err := GenerateRegistrationOptions(GenerateRegistrationOptionsInput{
				RPName:                 rpName,
				RPID:                   rpID,
				UserID:                 []byte(bacrypto.RandomStringFrom(32, bacrypto.AlphaLower, bacrypto.Digits)),
				UserName:               userName,
				UserDisplayName:        displayName,
				AttestationType:        "none",
				ExcludeCredentials:     exclude,
				AuthenticatorSelection: p.authenticatorSelection(ctx),
				Extensions:             ext,
			})
			if err != nil {
				return nil, err
			}
			cv := challengeValue{Type: "registration", ExpectedChallenge: str(mustGet(options, "challenge"))}
			cv.UserData.ID = user.ID
			cv.UserData.Name = user.Name
			cv.UserData.DisplayName = user.DisplayName
			cv.Context = nil
			if ctx.HasQuery("context") {
				c := ctx.QueryString("context")
				cv.Context = &c
			}
			if err := p.setChallenge(ctx, storedRegistrationChallenge(cv)); err != nil {
				return nil, err
			}
			return options, nil
		},
	}
}

// storedRegistrationChallenge serialises the registration challenge with `context: null`
// when absent (JSON.stringify of { ..., context: ctx.query?.context ?? null }).
func storedRegistrationChallenge(cv challengeValue) *jsonx.Object {
	ud := jsonx.O("id", cv.UserData.ID)
	if cv.UserData.Name != "" {
		ud.Set("name", cv.UserData.Name)
	}
	if cv.UserData.DisplayName != "" {
		ud.Set("displayName", cv.UserData.DisplayName)
	}
	var c any
	if cv.Context != nil {
		c = *cv.Context
	}
	return jsonx.O("type", cv.Type, "expectedChallenge", cv.ExpectedChallenge, "userData", ud, "context", c)
}

func mustGet(o *jsonx.Object, k string) any {
	v, _ := o.Get(k)
	return v
}

func (p *plugin) generateAuthenticationOptionsEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "generatePasskeyAuthenticationOptions", Path: "/passkey/generate-authenticate-options", Methods: []string{"GET"},
		Metadata: map[string]any{"openapi": mustParse(generateAuthenticateOptionsOpenAPI)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			var passkeys []*Passkey
			if s != nil && s.User != nil {
				if passkeys, err = p.userPasskeys(ctx, s.User.ID); err != nil {
					return nil, err
				}
			}
			rpID, err := getRpID(&p.opts, ctx.Auth.Options)
			if err != nil {
				return nil, err
			}
			var authExt ExtensionsResolver
			if p.opts.Authentication != nil {
				authExt = p.opts.Authentication.Extensions
			}
			ext, err := resolveExtensions(authExt, ctx)
			if err != nil {
				return nil, err
			}
			in := GenerateAuthenticationOptionsInput{RPID: rpID, UserVerification: "preferred", Extensions: ext}
			if len(passkeys) > 0 {
				in.AllowCredentials = make([]CredentialDescriptor, 0, len(passkeys))
				for _, pk := range passkeys {
					in.AllowCredentials = append(in.AllowCredentials, CredentialDescriptor{ID: pk.CredentialID, Transports: splitTransports(pk.Transports)})
				}
			}
			options, err := GenerateAuthenticationOptions(in)
			if err != nil {
				return nil, err
			}
			userID := ""
			if s != nil && s.User != nil {
				userID = s.User.ID
			}
			data := jsonx.O("type", "authentication", "expectedChallenge", mustGet(options, "challenge"), "userData", jsonx.O("id", userID))
			if err := p.setChallenge(ctx, data); err != nil {
				return nil, err
			}
			return options, nil
		},
	}
}

// expectedOrigins is `options.origin || ctx.headers.get("origin") || ""`.
func (p *plugin) expectedOrigins(ctx *betterauth.EndpointContext) []string {
	if len(p.opts.Origin) > 0 {
		return p.opts.Origin
	}
	if o := ctx.GetHeader("origin"); o != "" {
		return []string{o}
	}
	return nil
}

// verifiers are swapped by tests (the upstream tests mock @simplewebauthn/server).
var (
	verifyRegistration   = VerifyRegistrationResponse
	verifyAuthentication = VerifyAuthenticationResponse
)

// nonOptionalAny is z.any() as an object member: undefined is rejected.
var nonOptionalAny = validate.Custom(func(v any, path []any) (any, []validate.Issue) {
	if validate.IsUndefined(v) {
		return nil, []validate.Issue{validate.NewIssue(path, "invalid_type", "Invalid input: expected nonoptional, received undefined")}
	}
	return v, nil
})

// trimmedString is z.string().trim() (optionally .min(1)): the value is trimmed before
// the length check.
func trimmedString(min int) validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		withPath := func(out any, issues []validate.Issue) (any, []validate.Issue) {
			for i := range issues {
				issues[i].Path = path
			}
			return out, issues
		}
		s, ok := v.(string)
		if !ok {
			return withPath(validate.Validate(validate.String(), v))
		}
		s = jsTrim(s)
		if min > 0 {
			return withPath(validate.Validate(validate.String().Min(min), s))
		}
		return s, nil
	})
}

func joinTransports(resp any) (string, error) {
	m, _ := resp.(map[string]any)
	r, _ := m["response"].(map[string]any)
	t, ok := r["transports"]
	if !ok || t == nil {
		return "", nil
	}
	arr, ok := t.([]any)
	if !ok {
		return "", betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "transports is not an array")
	}
	parts := make([]string, len(arr))
	for i, x := range arr {
		switch y := x.(type) {
		case nil:
			parts[i] = ""
		case string:
			parts[i] = y
		default:
			parts[i], _ = jsonx.Stringify(y)
		}
	}
	return strings.Join(parts, ","), nil
}

type registrationResult struct {
	passkey adapter.Record
	session *betterauth.Session
	user    *betterauth.User
}

func (p *plugin) verifyRegistrationEndpoint() *betterauth.Endpoint {
	var use []betterauth.Middleware
	if p.requireSession {
		use = []betterauth.Middleware{betterauth.FreshSessionMiddleware}
	}
	return &betterauth.Endpoint{
		Key: "verifyPasskeyRegistration", Path: "/passkey/verify-registration", Methods: []string{"POST"},
		Use: use,
		Body: validate.Object(
			validate.F("response", nonOptionalAny),
			validate.F("name", validate.Optional(trimmedString(0))),
			validate.F("createSession", validate.Optional(validate.Boolean())),
		),
		Metadata: map[string]any{"openapi": mustParse(verifyRegistrationOpenAPI)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			origins := p.expectedOrigins(ctx)
			if len(origins) == 0 {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrFailedToVerifyRegistration)
			}
			resp := ctx.BodyMap()["response"]
			cv, err := p.consumeChallenge(ctx, "registration")
			if err != nil {
				return nil, err
			}
			var session *betterauth.SessionWithUser
			if p.requireSession {
				session = ctx.Session
			} else if session, err = betterauth.GetSessionFromCtx(ctx, nil); err != nil {
				return nil, err
			}
			sessionUserID := ""
			if session != nil && session.User != nil {
				sessionUserID = session.User.ID
			}
			if sessionUserID != "" && cv.UserData.ID != sessionUserID {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrYouAreNotAllowedToRegisterThisPasskey)
			}
			fail := func(err error) (any, error) {
				if _, ok := betterauth.AsAPIError(err); ok {
					return nil, err
				}
				ctx.Auth.Logger.Error("Failed to verify registration", err)
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToVerifyRegistration)
			}
			rpID, err := getRpID(&p.opts, ctx.Auth.Options)
			if err != nil {
				return fail(err)
			}
			verification, err := verifyRegistration(VerifyRegistrationInput{
				Response:          resp,
				ExpectedChallenge: cv.ExpectedChallenge,
				ExpectedOrigin:    origins,
				ExpectedRPID:      []string{rpID},
			})
			if err != nil {
				return fail(err)
			}
			if verification == nil || !verification.Verified || verification.RegistrationInfo == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrFailedToVerifyRegistration)
			}
			info := verification.RegistrationInfo
			createSession := false
			if b := ctx.BodyBool("createSession"); b != nil {
				createSession = *b
			}
			persist := func() (*registrationResult, error) {
				resolved := RegistrationUser{ID: cv.UserData.ID, Name: cv.UserData.Name, DisplayName: cv.UserData.DisplayName}
				if resolved.Name == "" {
					resolved.Name = cv.UserData.ID
				}
				target := resolved.ID
				name := ctx.BodyString("name")
				if p.opts.Registration != nil && p.opts.Registration.AfterVerification != nil {
					res, err := p.opts.Registration.AfterVerification(AfterRegistrationArgs{
						Ctx: ctx, Verification: verification, User: resolved, ClientData: resp, Context: cv.Context,
					})
					if err != nil {
						return nil, err
					}
					if res != nil && res.UserID != "" {
						if sessionUserID != "" && res.UserID != sessionUserID {
							return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrYouAreNotAllowedToRegisterThisPasskey)
						}
						target = res.UserID
					}
					if name == "" && res != nil {
						name = jsTrim(res.Name)
					}
				}
				if target == "" {
					return nil, betterauth.ErrFrom("BAD_REQUEST", ErrResolvedUserInvalid)
				}
				var user *betterauth.User
				if createSession {
					u, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), target)
					if err != nil {
						return nil, err
					}
					if u == nil {
						return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrUserNotFound)
					}
					user = u
				}
				transports, err := joinTransports(resp)
				if err != nil {
					return nil, err
				}
				data := adapter.Record{
					"userId":       target,
					"credentialID": info.Credential.ID,
					"publicKey":    base64.StdEncoding.EncodeToString(info.Credential.PublicKey),
					"counter":      int64(info.Credential.Counter),
					"deviceType":   info.CredentialDeviceType,
					"transports":   transports,
					"backedUp":     info.CredentialBackedUp,
					"createdAt":    time.Now(),
					"aaguid":       info.AAGUID,
				}
				if name != "" {
					data["name"] = name
				}
				row, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: "passkey", Data: data})
				if err != nil {
					return nil, err
				}
				if user == nil {
					return &registrationResult{passkey: row}, nil
				}
				s, err := ctx.Auth.InternalAdapter.CreateSession(ctx.Context(), target, &betterauth.CreateSessionOptions{DeferSecondaryStorageWrites: true})
				if err != nil {
					return nil, err
				}
				if s == nil {
					return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrUnableToCreateSession)
				}
				return &registrationResult{passkey: row, session: s, user: user}, nil
			}
			var reg *registrationResult
			if createSession {
				err = ctx.Transaction(func() error {
					var e error
					reg, e = persist()
					return e
				})
			} else {
				reg, err = persist()
			}
			if err != nil {
				return fail(err)
			}
			out := passkeyOutput(reg.passkey)
			if reg.session != nil && reg.user != nil {
				if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: reg.session, User: reg.user}, nil, nil); err != nil {
					return fail(err)
				}
				out.Set("session", ctx.Auth.SessionOutput(reg.session))
				out.Set("user", ctx.Auth.UserOutput(reg.user))
			}
			return out, nil
		},
	}
}

func (p *plugin) verifyAuthenticationEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "verifyPasskeyAuthentication", Path: "/passkey/verify-authentication", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("response", validate.Record(validate.Any()))),
		Metadata: map[string]any{"openapi": mustParse(verifyAuthenticationOpenAPI)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			origins := p.expectedOrigins(ctx)
			if len(origins) == 0 {
				return nil, betterauth.ErrMessage("BAD_REQUEST", "origin missing")
			}
			resp, _ := ctx.BodyMap()["response"].(map[string]any)
			cv, err := p.consumeChallenge(ctx, "authentication")
			if err != nil {
				return nil, err
			}
			_ = cv
			row, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "passkey",
				Where: []adapter.Where{{Field: "credentialID", Value: resp["id"]}}})
			if err != nil {
				return nil, err
			}
			if row == nil {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrPasskeyNotFound)
			}
			pk := passkeyFromRecord(row)
			fail := func(err error) (any, error) {
				if _, ok := betterauth.AsAPIError(err); ok {
					return nil, err
				}
				ctx.Auth.Logger.Error("Failed to verify authentication", err)
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrAuthenticationFailed)
			}
			rpID, err := getRpID(&p.opts, ctx.Auth.Options)
			if err != nil {
				return fail(err)
			}
			publicKey, err := bacrypto.DecodeBase64Loose(pk.PublicKey)
			if err != nil {
				return fail(err)
			}
			verification, err := verifyAuthentication(VerifyAuthenticationInput{
				Response:          resp,
				ExpectedChallenge: cv.ExpectedChallenge,
				ExpectedOrigin:    origins,
				ExpectedRPID:      []string{rpID},
				Credential: CredentialRecord{ID: pk.CredentialID, PublicKey: publicKey,
					Counter: uint32(pk.Counter), Transports: splitTransports(pk.Transports)},
			})
			if err != nil {
				return fail(err)
			}
			if verification == nil || !verification.Verified {
				return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrAuthenticationFailed)
			}
			if p.opts.Authentication != nil && p.opts.Authentication.AfterVerification != nil {
				if err := p.opts.Authentication.AfterVerification(AfterAuthenticationArgs{Ctx: ctx, Verification: verification, ClientData: resp}); err != nil {
					return fail(err)
				}
			}
			if _, err := ctx.Auth.Adapter.Update(ctx.Context(), "passkey", []adapter.Where{{Field: "id", Value: pk.ID}},
				adapter.Record{"counter": int64(verification.AuthenticationInfo.NewCounter)}); err != nil {
				return fail(err)
			}
			s, err := ctx.Auth.InternalAdapter.CreateSession(ctx.Context(), pk.UserID, nil)
			if err != nil {
				return fail(err)
			}
			if s == nil {
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrUnableToCreateSession)
			}
			user, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), pk.UserID)
			if err != nil {
				return fail(err)
			}
			if user == nil {
				return nil, betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "User not found")
			}
			if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: s, User: user}, nil, nil); err != nil {
				return fail(err)
			}
			return jsonx.O("session", ctx.Auth.SessionOutput(s), "user", ctx.Auth.UserOutput(user)), nil
		},
	}
}

// requireResourceOwnership mirrors the better-auth middleware of the same name for a
// body-sourced id owned through userId.
func requireResourceOwnership(model string, notFound betterauth.ErrorCode, forbidden *betterauth.ErrorCode) betterauth.Middleware {
	return func(ctx *betterauth.EndpointContext) error {
		s := ctx.Session
		if s == nil || s.User == nil || s.User.ID == "" {
			return betterauth.ErrStatus("UNAUTHORIZED")
		}
		id := ctx.BodyMap()["id"]
		if !jsTruthy(id) {
			return betterauth.ErrMessage("BAD_REQUEST", "Missing required parameter: id")
		}
		row, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: model,
			Where: []adapter.Where{{Field: "id", Value: id}}})
		if err != nil {
			return err
		}
		if row == nil {
			return betterauth.ErrFrom("NOT_FOUND", notFound)
		}
		if owner, _ := row["userId"].(string); owner != s.User.ID {
			if forbidden != nil {
				return betterauth.ErrFrom("UNAUTHORIZED", *forbidden)
			}
			return betterauth.ErrStatus("UNAUTHORIZED")
		}
		ctx.Set("verifiedResource", row)
		return nil
	}
}

func listPasskeysEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listPasskeys", Path: "/passkey/list-user-passkeys", Methods: []string{"GET"},
		Use:      []betterauth.Middleware{betterauth.SessionMiddleware},
		Metadata: map[string]any{"openapi": mustParse(listPasskeysOpenAPI)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "passkey",
				Where: []adapter.Where{{Field: "userId", Value: ctx.Session.User.ID}}})
			if err != nil {
				return nil, err
			}
			out := make([]any, 0, len(rows))
			for _, r := range rows {
				out = append(out, passkeyOutput(r))
			}
			return out, nil
		},
	}
}

func deletePasskeyEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "deletePasskey", Path: "/passkey/delete-passkey", Methods: []string{"POST"},
		Body: validate.Object(validate.F("id", validate.String())),
		Use: []betterauth.Middleware{betterauth.SessionMiddleware,
			requireResourceOwnership("passkey", ErrPasskeyNotFound, nil)},
		Metadata: map[string]any{"openapi": mustParse(deletePasskeyOpenAPI)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if err := ctx.Auth.Adapter.Delete(ctx.Context(), "passkey", []adapter.Where{{Field: "id", Value: ctx.BodyString("id")}}); err != nil {
				return nil, err
			}
			return jsonx.O("status", true), nil
		},
	}
}

func updatePasskeyEndpoint() *betterauth.Endpoint {
	forbidden := ErrYouAreNotAllowedToRegisterThisPasskey
	return &betterauth.Endpoint{
		Key: "updatePasskey", Path: "/passkey/update-passkey", Methods: []string{"POST"},
		Body: validate.Object(validate.F("id", validate.String()), validate.F("name", trimmedString(1))),
		Use: []betterauth.Middleware{betterauth.SessionMiddleware,
			requireResourceOwnership("passkey", ErrPasskeyNotFound, &forbidden)},
		Metadata: map[string]any{"openapi": mustParse(updatePasskeyOpenAPI)},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			row, err := ctx.Auth.Adapter.Update(ctx.Context(), "passkey", []adapter.Where{{Field: "id", Value: ctx.BodyString("id")}},
				adapter.Record{"name": ctx.BodyString("name")})
			if err != nil {
				return nil, err
			}
			if row == nil {
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToUpdatePasskey)
			}
			return jsonx.O("passkey", passkeyOutput(row)), nil
		},
	}
}

// FindPasskeys returns the passkeys of a user (a convenience for server code).
func FindPasskeys(ctx context.Context, auth *betterauth.Auth, userID string) ([]*Passkey, error) {
	rows, err := auth.Context().Adapter.FindMany(ctx, adapter.FindManyInput{Model: "passkey",
		Where: []adapter.Where{{Field: "userId", Value: userID}}})
	if err != nil {
		return nil, err
	}
	out := make([]*Passkey, 0, len(rows))
	for _, r := range rows {
		out = append(out, passkeyFromRecord(r))
	}
	return out, nil
}
