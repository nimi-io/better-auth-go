package twofactor

import (
	"encoding/json"
	"fmt"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func (o *BackupCodeOptions) storage() string {
	if o == nil || o.StoreBackupCodes == "" {
		return StoreEncrypted
	}
	return o.StoreBackupCodes
}

func (o *BackupCodeOptions) custom() bool {
	return o != nil && o.StoreBackupCodes == "" && o.Encrypt != nil && o.Decrypt != nil
}

// GenerateBackupCodeList returns amount codes of length characters with a dash after the
// fifth character (generateBackupCodesFn).
func GenerateBackupCodeList(opts *BackupCodeOptions) []string {
	amount, length := 10, 10
	if opts != nil {
		if opts.Amount != 0 {
			amount = opts.Amount
		}
		if opts.Length != 0 {
			length = opts.Length
		}
	}
	out := make([]string, amount)
	for i := range out {
		code := bacrypto.RandomString(length, bacrypto.AlphaLower, bacrypto.Digits, bacrypto.AlphaUpper)
		if len(code) > 5 {
			out[i] = code[:5] + "-" + code[5:]
		} else {
			out[i] = code + "-"
		}
	}
	return out
}

// EncodeBackupCodes serialises codes for storage (JSON, encrypted by default) exactly like
// encodeBackupCodes upstream.
func EncodeBackupCodes(codes []string, key bacrypto.Secret, opts *BackupCodeOptions) (string, error) {
	arr := make([]any, len(codes))
	for i, c := range codes {
		arr[i] = c
	}
	raw, err := jsonx.Stringify(arr)
	if err != nil {
		return "", err
	}
	if opts.custom() {
		return opts.Encrypt(raw)
	}
	if opts.storage() == StoreEncrypted {
		return bacrypto.SymmetricEncrypt(key, raw)
	}
	return raw, nil
}

// DecodeBackupCodes reverses EncodeBackupCodes (getBackupCodes). It returns nil codes when
// the stored value is not a JSON array of strings; decryption errors are returned.
func DecodeBackupCodes(stored string, key bacrypto.Secret, opts *BackupCodeOptions) ([]string, error) {
	raw := stored
	var err error
	switch {
	case opts.custom():
		raw, err = opts.Decrypt(stored)
	case opts.storage() == StoreEncrypted:
		raw, err = bacrypto.SymmetricDecrypt(key, stored)
	}
	if err != nil {
		return nil, err
	}
	var codes []string
	if json.Unmarshal([]byte(raw), &codes) != nil || codes == nil {
		return nil, nil
	}
	return codes, nil
}

type generatedCodes struct {
	codes   []string
	encoded string
}

func generateBackupCodes(key bacrypto.Secret, opts *BackupCodeOptions) (*generatedCodes, error) {
	var codes []string
	if opts != nil && opts.CustomBackupCodesGenerate != nil {
		codes = opts.CustomBackupCodesGenerate()
	} else {
		codes = GenerateBackupCodeList(opts)
	}
	enc, err := EncodeBackupCodes(codes, key, opts)
	if err != nil {
		return nil, err
	}
	return &generatedCodes{codes: codes, encoded: enc}, nil
}

func stringsToAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func (p *plugin) backupCodeEndpoints() []*betterauth.Endpoint {
	opts := p.opts.BackupCodeOptions
	allowPasswordless := p.opts.AllowPasswordless
	if opts != nil && opts.AllowPasswordless != nil {
		allowPasswordless = *opts.AllowPasswordless
	}
	verify := &betterauth.Endpoint{
		Key: "verifyBackupCode", Path: "/two-factor/verify-backup-code", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("code", validate.Describe(validate.String(), `A backup code to verify. Eg: "123456"`)),
			validate.F("disableSession", validate.Optional(validate.Describe(validate.Boolean(), "If true, the session cookie will not be set."))),
			validate.F("trustDevice", validate.Optional(validate.Describe(validate.Boolean(), "If true, the device will be trusted for 30 days. It'll be refreshed on every sign in request within this time. Eg: true"))),
		),
		Metadata: verifyBackupCodeMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			v, err := p.verifyTwoFactor(ctx)
			if err != nil {
				return nil, err
			}
			isSignIn := v.isSignIn()
			row, err := findTwoFactor(ctx, v.user.ID)
			if err != nil {
				return nil, err
			}
			if row == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrBackupCodesNotEnabled)
			}
			if isSignIn {
				if err := p.assertNotLocked(ctx, row); err != nil {
					return nil, err
				}
			}
			var att *attempt
			if isSignIn {
				if att, err = v.beginAttempt(DefaultTwoFactorAllowedAttempts); err != nil {
					return nil, err
				}
			}
			code := ctx.BodyString("code")
			stored, _ := row["backupCodes"].(string)
			codes, err := DecodeBackupCodes(stored, ctx.Auth.SecretConfig, opts)
			if err != nil {
				att.undo()
				return nil, err
			}
			found := false
			var remaining []string
			if codes != nil {
				remaining = []string{}
				for _, c := range codes {
					if c == code {
						found = true
					} else {
						remaining = append(remaining, c)
					}
				}
			}
			if !found || remaining == nil {
				att.fail()
				if isSignIn {
					if err := p.recordFailure(ctx, row); err != nil {
						return nil, err
					}
				}
				return nil, betterauth.ErrFrom("UNAUTHORIZED", ErrInvalidBackupCode)
			}
			encoded, err := EncodeBackupCodes(remaining, ctx.Auth.SecretConfig, opts)
			if err != nil {
				return nil, err
			}
			updated, err := ctx.Auth.Adapter.IncrementOne(ctx.Context(), adapter.IncrementInput{
				Model: twoFactorModel,
				Where: []adapter.Where{
					{Field: "id", Value: row["id"]},
					{Field: "backupCodes", Value: stored},
				},
				Increment: map[string]float64{},
				Set:       adapter.Record{"backupCodes": encoded},
			})
			if err != nil {
				return nil, err
			}
			if updated == nil {
				return nil, betterauth.ErrMessage("CONFLICT", "Failed to verify backup code. Please try again.")
			}
			if isSignIn {
				if err := p.resetFailures(ctx, row); err != nil {
					return nil, err
				}
			}
			if b := ctx.BodyBool("disableSession"); b == nil || !*b {
				return v.valid(ctx)
			}
			var token any = jsonx.Undefined
			if v.session.Session != nil {
				token = v.session.Session.Token
			}
			return jsonx.O("token", token, "user", ctx.Auth.UserOutput(v.user)), nil
		},
	}
	passwordField := validate.Describe(validate.String(), "The users password.")
	if allowPasswordless {
		passwordField = validate.Optional(passwordField)
	}
	generate := &betterauth.Endpoint{
		Key: "generateBackupCodes", Path: "/two-factor/generate-backup-codes", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("password", passwordField)),
		Use:      []betterauth.Middleware{betterauth.SessionMiddleware},
		Metadata: generateBackupCodesMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			user := ctx.Session.User
			if !truthy(user.Get("twoFactorEnabled")) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTwoFactorNotEnabled)
			}
			req, err := shouldRequirePassword(ctx, user.ID, allowPasswordless)
			if err != nil {
				return nil, err
			}
			if req {
				if ctx.BodyString("password") == "" {
					return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidPassword)
				}
				if err := checkPassword(ctx, user.ID); err != nil {
					return nil, err
				}
			}
			row, err := findTwoFactor(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			if row == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTwoFactorNotEnabled)
			}
			gen, err := generateBackupCodes(ctx.Auth.SecretConfig, opts)
			if err != nil {
				return nil, err
			}
			if _, err := ctx.Auth.Adapter.Update(ctx.Context(), twoFactorModel, []adapter.Where{{Field: "id", Value: row["id"]}},
				adapter.Record{"backupCodes": gen.encoded}); err != nil {
				return nil, err
			}
			return jsonx.O("status", true, "backupCodes", stringsToAny(gen.codes)), nil
		},
	}
	view := &betterauth.Endpoint{
		Key: "viewBackupCodes", ServerOnly: true, Methods: []string{"POST"},
		Body: validate.Object(validate.F("userId", validate.Describe(validate.Any(), `The user ID to view all backup codes. Eg: "user-id"`))),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			userID := coerceString(ctx.BodyMap()["userId"])
			row, err := findTwoFactor(ctx, userID)
			if err != nil {
				return nil, err
			}
			if row == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrBackupCodesNotEnabled)
			}
			stored, _ := row["backupCodes"].(string)
			codes, err := DecodeBackupCodes(stored, ctx.Auth.SecretConfig, opts)
			if err != nil {
				return nil, err
			}
			if codes == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidBackupCode)
			}
			return jsonx.O("status", true, "backupCodes", stringsToAny(codes)), nil
		},
	}
	return []*betterauth.Endpoint{verify, generate, view}
}

// coerceString is z.coerce.string(): String(value).
func coerceString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case float64:
		return jsonx.FormatNumber(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	if validate.IsUndefined(v) {
		return "undefined"
	}
	return fmt.Sprint(v)
}
