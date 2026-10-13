package twofactor

import (
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// DefaultKeyHasher is SHA-256 + base64url without padding (utils.ts defaultKeyHasher).
func DefaultKeyHasher(token string) string {
	return bacrypto.Base64URLNoPad(bacrypto.SHA256([]byte(token)))
}

type otpConfig struct {
	opts    *OTPOptions
	digits  int
	period  time.Duration
	allowed int
}

func newOTPConfig(o *OTPOptions) otpConfig {
	c := otpConfig{opts: o, digits: 6, period: 3 * time.Minute, allowed: 5}
	if o != nil {
		if o.Digits != 0 {
			c.digits = o.Digits
		}
		if o.Period != 0 {
			c.period = time.Duration(o.Period) * time.Minute
		}
		if o.AllowedAttempts != 0 {
			c.allowed = o.AllowedAttempts
		}
	}
	return c
}

func (c otpConfig) mode() string {
	if c.opts == nil {
		return StorePlain
	}
	return c.opts.StoreOTP
}

// store transforms a code before it is persisted (storeOTP).
func (c otpConfig) store(ctx *betterauth.EndpointContext, otp string) (string, error) {
	switch {
	case c.mode() == StoreHashed:
		return DefaultKeyHasher(otp), nil
	case c.mode() == "" && c.opts.Hash != nil:
		return c.opts.Hash(otp)
	case c.mode() == "" && c.opts.Encrypt != nil:
		return c.opts.Encrypt(otp)
	case c.mode() == StoreEncrypted:
		return bacrypto.SymmetricEncrypt(ctx.Auth.SecretConfig, otp)
	}
	return otp, nil
}

// compare returns the stored and the input value in comparable form
// (decryptOrHashForComparison).
func (c otpConfig) compare(ctx *betterauth.EndpointContext, stored, input string) (string, string, error) {
	switch {
	case c.mode() == StoreHashed:
		return stored, DefaultKeyHasher(input), nil
	case c.mode() == StoreEncrypted:
		d, err := bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, stored)
		return d, input, err
	case c.mode() == "" && c.opts.Encrypt != nil && c.opts.Decrypt != nil:
		d, err := c.opts.Decrypt(stored)
		return d, input, err
	case c.mode() == "" && c.opts.Hash != nil:
		h, err := c.opts.Hash(input)
		return stored, h, err
	}
	return stored, input, nil
}

func (p *plugin) otpEndpoints() []*betterauth.Endpoint {
	cfg := newOTPConfig(p.opts.OTPOptions)
	trustDeviceField := validate.F("trustDevice", validate.Describe(validate.Optional(validate.Boolean()), "If true, the device will be trusted for 30 days. It'll be refreshed on every sign in request within this time. Eg: true"))
	send := &betterauth.Endpoint{
		Key: "sendTwoFactorOTP", Path: "/two-factor/send-otp", Methods: []string{"POST"},
		Body:     validate.Optional(validate.Object(trustDeviceField)),
		Metadata: sendOTPMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !p.opts.sendOTPConfigured() {
				ctx.Auth.Logger.Error("send otp isn't configured. Please configure the send otp function on otp options.")
				return nil, betterauth.NewAPIError("BAD_REQUEST", jsonx.O("message", "otp isn't configured", "code", "OTP_NOT_CONFIGURED"))
			}
			v, err := p.verifyTwoFactor(ctx)
			if err != nil {
				return nil, err
			}
			code := bacrypto.RandomStringFrom(cfg.digits, bacrypto.Digits)
			stored, err := cfg.store(ctx, code)
			if err != nil {
				return nil, err
			}
			if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(ctx.Context(), "2fa-otp-"+v.key, stored+":0",
				time.Now().Add(cfg.period), nil); err != nil {
				return nil, err
			}
			send := p.opts.OTPOptions.SendOTP
			user := v.user
			ctx.Auth.RunInBackgroundOrAwait(func() error {
				if err := send(ctx.Context(), OTPData{User: user, OTP: code}, ctx); err != nil {
					ctx.Auth.Logger.Error("Failed to send two-factor OTP", err)
				}
				return nil
			})
			return jsonx.O("status", true), nil
		},
	}
	verify := &betterauth.Endpoint{
		Key: "verifyTwoFactorOTP", Path: "/two-factor/verify-otp", Methods: []string{"POST"},
		Body:     validate.Object(validate.F("code", validate.Describe(validate.String(), "The otp code to verify. Eg: \"012345\"")), trustDeviceField),
		Metadata: verifyOTPMetadata(),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			v, err := p.verifyTwoFactor(ctx)
			if err != nil {
				return nil, err
			}
			isSignIn := v.isSignIn()
			var row adapter.Record
			if isSignIn {
				if row, err = findTwoFactor(ctx, v.user.ID); err != nil {
					return nil, err
				}
				if row != nil {
					if err := p.assertNotLocked(ctx, row); err != nil {
						return nil, err
					}
				}
			}
			ia := ctx.Auth.InternalAdapter
			consumed, err := ia.ConsumeVerificationValue(ctx.Context(), "2fa-otp-"+v.key)
			if err != nil {
				return nil, err
			}
			if consumed == nil {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrOTPHasExpired)
			}
			parts := strings.Split(consumed.Value, ":")
			otp := parts[0]
			attempts := 0
			if len(parts) > 1 {
				attempts = parseIntPrefix(parts[1])
			}
			if attempts >= cfg.allowed {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTooManyAttemptsRequestNewCode)
			}
			storedValue, inputValue, err := cfg.compare(ctx, otp, ctx.BodyString("code"))
			if err != nil {
				return nil, err
			}
			if bacrypto.ConstantTimeEqual([]byte(storedValue), []byte(inputValue)) {
				if row != nil {
					if err := p.resetFailures(ctx, row); err != nil {
						return nil, err
					}
				}
				if !truthy(v.user.Get("twoFactorEnabled")) {
					if v.session.Session == nil {
						return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrFailedToCreateSession)
					}
					res, err := p.rotateSession(ctx, v.session.Session, true)
					if err != nil {
						return nil, err
					}
					return jsonx.O("token", res.Session.Token, "user", ctx.Auth.UserOutput(res.User)), nil
				}
				return v.valid(ctx)
			}
			if _, err := ia.CreateVerificationValue(ctx.Context(), "2fa-otp-"+v.key, otp+":"+strconv.Itoa(attempts+1),
				consumed.ExpiresAt, nil); err != nil {
				return nil, err
			}
			if row != nil {
				if err := p.recordFailure(ctx, row); err != nil {
					return nil, err
				}
			}
			return nil, invalid(ErrInvalidCode)
		},
	}
	return []*betterauth.Endpoint{send, verify}
}

// parseIntPrefix mirrors parseInt(s, 10) || 0.
func parseIntPrefix(s string) int {
	s = strings.TrimLeft(s, " \t\n\r")
	neg := false
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		neg = s[0] == '-'
		s = s[1:]
	}
	n := 0
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n > 1<<40 {
			break
		}
	}
	if neg {
		return -n
	}
	return n
}
