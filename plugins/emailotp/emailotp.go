package emailotp

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// New creates the email OTP plugin (emailOTP).
func New(opts Options) *betterauth.Plugin {
	o := &opts
	window, max := 60*time.Second, 3
	if o.RateLimit != nil {
		if o.RateLimit.Window > 0 {
			window = o.RateLimit.Window
		}
		if o.RateLimit.Max > 0 {
			max = o.RateLimit.Max
		}
	}
	var rateLimits []betterauth.PluginRateLimit
	for _, p := range []string{
		"/email-otp/send-verification-otp", "/email-otp/check-verification-otp", "/email-otp/verify-email",
		"/sign-in/email-otp", "/email-otp/request-password-reset", "/email-otp/reset-password",
		"/forget-password/email-otp", "/email-otp/request-email-change", "/email-otp/change-email",
	} {
		path := p
		rateLimits = append(rateLimits, betterauth.PluginRateLimit{Window: window, Max: max,
			PathMatcher: func(s string) bool { return s == path }})
	}
	return &betterauth.Plugin{
		ID: "email-otp",
		Init: func(ctx *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			if !o.OverrideDefaultEmailVerification {
				return nil, nil
			}
			return &betterauth.PluginInit{ApplyDefaults: func(cfg *betterauth.Config) {
				ev := betterauth.EmailVerificationConfig{}
				if cfg.EmailVerification != nil {
					ev = *cfg.EmailVerification
				}
				// defu(options, pluginOptions): the user's own sender wins.
				if ev.SendVerificationEmail == nil {
					ev.SendVerificationEmail = sendFromEmailVerification(o, ctx)
				}
				cfg.EmailVerification = &ev
			}}, nil
		},
		Endpoints: []*betterauth.Endpoint{
			sendVerificationOTPEndpoint(o),
			createVerificationOTPEndpoint(o),
			getVerificationOTPEndpoint(o),
			checkVerificationOTPEndpoint(o),
			verifyEmailOTPEndpoint(o),
			signInEmailOTPEndpoint(o),
			requestPasswordResetEndpoint(o),
			forgetPasswordEndpoint(o),
			resetPasswordEndpoint(o),
			requestEmailChangeEndpoint(o),
			changeEmailEndpoint(o),
		},
		Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool {
				return strings.HasPrefix(ctx.Path, "/sign-up") && o.SendVerificationOnSignUp && !o.OverrideDefaultEmailVerification
			},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				email := responseUserEmail(ctx.Returned)
				if email == "" {
					return nil, nil
				}
				otp, err := createOTPValue(ctx, o, email, TypeEmailVerification, ToOTPIdentifier(TypeEmailVerification, email))
				if err != nil {
					return nil, err
				}
				sendOTP(ctx, o, email, otp, TypeEmailVerification)
				return nil, nil
			},
		}}},
		RateLimit:  rateLimits,
		ErrorCodes: ErrorCodes,
		Options:    o,
	}
}

// responseUserEmail reads response.user.email from an endpoint result (getEndpointResponse).
func responseUserEmail(returned any) string {
	switch returned.(type) {
	case nil, *betterauth.APIError:
		return ""
	}
	var raw []byte
	if r, ok := returned.(*betterauth.Response); ok {
		raw = r.Body
	} else {
		b, err := jsonx.Marshal(returned)
		if err != nil {
			return ""
		}
		raw = b
	}
	var out struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return ""
	}
	return out.User.Email
}
