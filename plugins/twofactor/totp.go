package twofactor

import (
	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func (p *plugin) totpDigitsPeriod() (int, int) {
	digits, period := DefaultOTPDigits, DefaultTOTPPeriod
	if t := p.opts.TOTPOptions; t != nil {
		if t.Digits != 0 {
			digits = t.Digits
		}
		if t.Period != 0 {
			period = t.Period
		}
	}
	return digits, period
}

func totpNotConfigured(ctx *betterauth.EndpointContext) error {
	ctx.Auth.Logger.Error("totp isn't configured. please pass totp option on two factor plugin to enable totp")
	return betterauth.NewAPIError("BAD_REQUEST", jsonx.O("message", "totp isn't configured", "code", "TOTP_NOT_CONFIGURED"))
}

func (p *plugin) totpEndpoints() []*betterauth.Endpoint {
	disabled := p.opts.totpDisabled()
	digits, period := p.totpDigitsPeriod()
	allowPasswordless := p.opts.AllowPasswordless
	if t := p.opts.TOTPOptions; t != nil && t.AllowPasswordless != nil {
		allowPasswordless = *t.AllowPasswordless
	}
	passwordField := validate.Describe(validate.String(), "User password")
	if allowPasswordless {
		passwordField = validate.Optional(passwordField)
	}
	trustDeviceField := validate.F("trustDevice", validate.Optional(validate.Describe(validate.Boolean(), "If true, the device will be trusted for 30 days. It'll be refreshed on every sign in request within this time. Eg: true")))

	generate := &betterauth.Endpoint{
		Key: "generateTOTP", ServerOnly: true, Methods: []string{"POST"},
		Body:     validate.Object(validate.F("secret", validate.Describe(validate.String(), "The secret to generate the TOTP code"))),
		Metadata: generateTOTPMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if disabled {
				return nil, totpNotConfigured(ctx)
			}
			code, err := CreateOTP(ctx.BodyString("secret"), digits, period).TOTP()
			if err != nil {
				return nil, err
			}
			return jsonx.O("code", code), nil
		},
	}
	getURI := &betterauth.Endpoint{
		Key: "getTOTPURI", Path: "/two-factor/get-totp-uri", Methods: []string{"POST"},
		Use:      []betterauth.Middleware{betterauth.SessionMiddleware},
		Body:     validate.Object(validate.F("password", passwordField)),
		Metadata: getTOTPURIMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if disabled {
				return nil, totpNotConfigured(ctx)
			}
			user := ctx.Session.User
			row, err := findTwoFactor(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			if row == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTOTPNotEnabled)
			}
			stored, _ := row["secret"].(string)
			secret, err := bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, stored)
			if err != nil {
				return nil, err
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
			// totpOptions has no issuer upstream, so the URI always uses the app name here.
			return jsonx.O("totpURI", CreateOTP(secret, digits, period).URL(ctx.Auth.AppName, user.Email)), nil
		},
	}
	verify := &betterauth.Endpoint{
		Key: "verifyTOTP", Path: "/two-factor/verify-totp", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("code", validate.Describe(validate.String(), "The otp code to verify. Eg: \"012345\"")), trustDeviceField),
		Metadata: verifyTOTPMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if disabled {
				return nil, totpNotConfigured(ctx)
			}
			v, err := p.verifyTwoFactor(ctx)
			if err != nil {
				return nil, err
			}
			user := v.user
			isSignIn := v.isSignIn()
			row, err := findTwoFactor(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			if row == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTOTPNotEnabled)
			}
			verified := row["verified"]
			if isSignIn && isFalse(verified) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTOTPNotEnabled)
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
			stored, _ := row["secret"].(string)
			secret, err := bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, stored)
			if err != nil {
				att.undo()
				return nil, err
			}
			ok, err := CreateOTP(secret, digits, period).Verify(ctx.BodyString("code"))
			if err != nil {
				att.undo()
				return nil, err
			}
			if !ok {
				att.fail()
				if isSignIn {
					if err := p.recordFailure(ctx, row); err != nil {
						return nil, err
					}
				}
				return nil, invalid(ErrInvalidCode)
			}
			if isSignIn {
				if err := p.resetFailures(ctx, row); err != nil {
					return nil, err
				}
			}
			if !isTrue(verified) {
				if !truthy(user.Get("twoFactorEnabled")) {
					if _, err := p.rotateSession(ctx, v.session.Session, true); err != nil {
						return nil, err
					}
				}
				if _, err := ctx.Auth.Adapter.Update(ctx.Context(), twoFactorModel, []adapter.Where{{Field: "id", Value: row["id"]}},
					adapter.Record{"verified": true}); err != nil {
					return nil, err
				}
			}
			return v.valid(ctx)
		},
	}
	return []*betterauth.Endpoint{generate, getURI, verify}
}
