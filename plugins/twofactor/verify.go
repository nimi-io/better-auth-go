package twofactor

import (
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// attempt is the per-challenge attempt slot returned by beginAttempt.
type attempt struct {
	recordFailure func()
	restore       func()
}

func (a *attempt) fail() {
	if a != nil {
		a.recordFailure()
	}
}

func (a *attempt) undo() {
	if a != nil {
		a.restore()
	}
}

// verification is the result of verifyTwoFactor.
type verification struct {
	// session is the active session (nil Session during a sign-in challenge).
	session *betterauth.SessionWithUser
	user    *betterauth.User
	key     string
	// valid completes the verification and builds the response.
	valid        func(ctx *betterauth.EndpointContext) (any, error)
	beginAttempt func(allowed int) (*attempt, error)
}

func (v *verification) isSignIn() bool { return v.session.Session == nil }

func invalid(code betterauth.ErrorCode) error { return betterauth.ErrFrom("UNAUTHORIZED", code) }

func hmacToken(secret, data string) string {
	return bacrypto.Base64URLNoPad(bacrypto.HMACSHA256([]byte(secret), []byte(data)))
}

// verifyTwoFactor resolves either the signed-in session or the pending sign-in challenge
// (verify-two-factor.ts).
func (p *plugin) verifyTwoFactor(ctx *betterauth.EndpointContext) (*verification, error) {
	a := ctx.Auth
	session, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if session != nil {
		return &verification{
			session: session,
			user:    session.User,
			key:     session.User.ID + "!" + session.Session.ID,
			valid: func(ctx *betterauth.EndpointContext) (any, error) {
				return jsonx.O("token", session.Session.Token, "user", ctx.Auth.UserOutput(session.User)), nil
			},
			beginAttempt: func(int) (*attempt, error) {
				return &attempt{recordFailure: func() {}, restore: func() {}}, nil
			},
		}, nil
	}
	twoFactorCookie := a.CreateAuthCookie(TwoFactorCookieName, nil)
	signed, ok := ctx.GetSignedCookie(twoFactorCookie.Name, a.Secret)
	if !ok {
		return nil, invalid(ErrInvalidTwoFactorCookie)
	}
	token, err := a.InternalAdapter.FindVerificationValue(ctx.Context(), signed)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, invalid(ErrInvalidTwoFactorCookie)
	}
	user, err := a.InternalAdapter.FindUserByID(ctx.Context(), token.Value)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, invalid(ErrInvalidTwoFactorCookie)
	}
	_, dontRememberMe := ctx.GetSignedCookie(a.AuthCookies.DontRememberToken.Name, a.Secret)
	v := &verification{
		session: &betterauth.SessionWithUser{User: user},
		user:    user,
		key:     signed,
	}
	v.valid = func(ctx *betterauth.EndpointContext) (any, error) {
		a := ctx.Auth
		consumed, err := a.InternalAdapter.ConsumeVerificationValue(ctx.Context(), signed)
		if err != nil {
			return nil, err
		}
		if consumed == nil || consumed.Value != user.ID {
			betterauth.ExpireCookie(ctx, twoFactorCookie)
			return nil, invalid(ErrInvalidTwoFactorCookie)
		}
		s, err := a.InternalAdapter.CreateSession(ctx.Context(), consumed.Value, &betterauth.CreateSessionOptions{DontRememberMe: dontRememberMe})
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("message", "failed to create session", "code", "FAILED_TO_CREATE_SESSION"))
		}
		if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: s, User: user}, nil, nil); err != nil {
			return nil, err
		}
		betterauth.ExpireCookie(ctx, twoFactorCookie)
		if b := ctx.BodyBool("trustDevice"); b != nil && *b {
			maxAge := p.opts.trustDeviceMaxAge()
			trustCookie := a.CreateAuthCookie(TrustDeviceCookieName, &betterauth.CookieOptions{MaxAge: betterauth.Int(maxAge)})
			trustIdentifier := "trust-device-" + bacrypto.RandomString(32)
			tok := hmacToken(a.Secret, user.ID+"!"+trustIdentifier)
			if _, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), trustIdentifier, user.ID,
				time.Now().Add(time.Duration(maxAge)*time.Second), nil); err != nil {
				return nil, err
			}
			ctx.SetSignedCookie(trustCookie.Name, tok+"!"+trustIdentifier, a.Secret, trustCookie.Attributes)
			betterauth.ExpireCookie(ctx, a.AuthCookies.DontRememberToken)
		}
		return jsonx.O("token", s.Token, "user", a.UserOutput(user)), nil
	}
	v.beginAttempt = func(allowed int) (*attempt, error) {
		identifier := "2fa-attempts-" + signed
		consumed, err := a.InternalAdapter.ConsumeVerificationValue(ctx.Context(), identifier)
		if err != nil {
			consumed = nil
		}
		if consumed == nil {
			return nil, invalid(ErrInvalidTwoFactorCookie)
		}
		attempts := allowed
		if n, ok := parseNonNegativeInt(consumed.Value); ok {
			attempts = n
		}
		if attempts >= allowed {
			if _, err := a.InternalAdapter.ConsumeVerificationValue(ctx.Context(), signed); err != nil {
				betterauth.ExpireCookie(ctx, twoFactorCookie)
				return nil, betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("message", "Failed to invalidate two-factor challenge", "code", "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE"))
			}
			betterauth.ExpireCookie(ctx, twoFactorCookie)
			return nil, betterauth.ErrFrom("BAD_REQUEST", ErrTooManyAttemptsRequestNewCode)
		}
		rearm := func(count int) {
			_, _ = a.InternalAdapter.CreateVerificationValue(ctx.Context(), identifier, strconv.Itoa(count), token.ExpiresAt, nil)
		}
		return &attempt{
			recordFailure: func() { rearm(attempts + 1) },
			restore:       func() { rearm(attempts) },
		}, nil
	}
	return v, nil
}

// parseNonNegativeInt mirrors Number(value) followed by Number.isInteger && >= 0.
func parseNonNegativeInt(s string) (int, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, true // Number("") === 0
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil || f < 0 || f != float64(int64(f)) || f > 1e15 {
		return 0, false
	}
	return int(f), true
}

// ---- account lockout ----

// lockedUntil returns the lock expiry stored on a twoFactor row.
func lockedUntil(row adapter.Record) (time.Time, bool) {
	v := row["lockedUntil"]
	if v == nil {
		return time.Time{}, false
	}
	t, ok := adapter.ToTime(v)
	if !ok || t.IsZero() {
		return time.Time{}, false
	}
	return t, true
}

func (p *plugin) assertNotLocked(ctx *betterauth.EndpointContext, row adapter.Record) error {
	cfg := p.opts.lockout()
	if !cfg.enabled {
		return nil
	}
	until, ok := lockedUntil(row)
	if !ok {
		return nil
	}
	if until.After(time.Now()) {
		return betterauth.ErrFrom("TOO_MANY_REQUESTS", ErrAccountTemporarilyLocked)
	}
	_, err := ctx.Auth.Adapter.IncrementOne(ctx.Context(), adapter.IncrementInput{
		Model: twoFactorModel,
		Where: []adapter.Where{
			{Field: "id", Value: row["id"]},
			{Field: "lockedUntil", Operator: adapter.Lte, Value: time.Now()},
		},
		Increment: map[string]float64{},
		Set:       adapter.Record{"failedVerificationCount": 0, "lockedUntil": nil},
	})
	return err
}

func (p *plugin) recordFailure(ctx *betterauth.EndpointContext, row adapter.Record) error {
	cfg := p.opts.lockout()
	if !cfg.enabled {
		return nil
	}
	ad := ctx.Auth.Adapter
	updated, err := ad.IncrementOne(ctx.Context(), adapter.IncrementInput{
		Model:     twoFactorModel,
		Where:     []adapter.Where{{Field: "id", Value: row["id"]}},
		Increment: map[string]float64{"failedVerificationCount": 1},
	})
	if err != nil {
		return err
	}
	count := 0.0
	if updated != nil {
		count, _ = toFloat(updated["failedVerificationCount"])
	}
	if count >= float64(cfg.maxFailed) {
		_, err = ad.IncrementOne(ctx.Context(), adapter.IncrementInput{
			Model: twoFactorModel,
			Where: []adapter.Where{
				{Field: "id", Value: row["id"]},
				{Field: "failedVerificationCount", Operator: adapter.Gte, Value: cfg.maxFailed},
			},
			Increment: map[string]float64{},
			Set:       adapter.Record{"lockedUntil": time.Now().Add(cfg.duration)},
		})
	}
	return err
}

func (p *plugin) resetFailures(ctx *betterauth.EndpointContext, row adapter.Record) error {
	if !p.opts.lockout().enabled {
		return nil
	}
	_, err := ctx.Auth.Adapter.Update(ctx.Context(), twoFactorModel, []adapter.Where{{Field: "id", Value: row["id"]}},
		adapter.Record{"failedVerificationCount": 0, "lockedUntil": nil})
	return err
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}
