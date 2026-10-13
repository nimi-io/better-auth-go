package betterauth

// Exported helpers used by the email-otp, magic-link and one-time-token plugins
// (plugins/emailotp, plugins/magiclink, plugins/onetimetoken).

import (
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

// EmailOTPSetCookieCache refreshes only the session data cookie (setCookieCache upstream),
// without touching the session token cookie.
func EmailOTPSetCookieCache(ctx *EndpointContext, s *SessionWithUser, dontRememberMe bool) error {
	return setCookieCache(ctx, s, dontRememberMe)
}

// MagicLinkResolveURL resolves ref against base like `new URL(ref, base).toString()`.
func MagicLinkResolveURL(ref, base string) (string, error) {
	return resolveURL(ref, base)
}

// MagicLinkSetSearchParams sets query parameters on an absolute URL like
// `url.searchParams.set(k, v)` (kv are key/value pairs, applied in order).
func MagicLinkSetSearchParams(rawURL string, kv ...string) (string, error) {
	return setSearchParams(rawURL, kv...)
}

const (
	revokeUnprovenLockExpiresIn = 5 * time.Second
	revokeUnprovenLockWait      = 2 * time.Second
	revokeUnprovenLockPoll      = 250 * time.Millisecond
)

// RevokeUnprovenAccountAccess promotes an unverified user whose email ownership has just
// been proven (OTP / magic link): it deletes every linked account (including credential
// passwords set by someone who never proved ownership), revokes all sessions and marks the
// email verified. A short verification-row lock serialises concurrent calls
// (db/revoke-unproven-account-access.ts).
func RevokeUnprovenAccountAccess(ctx *EndpointContext, userID string) (*User, error) {
	ia := ctx.Auth.InternalAdapter
	c := ctx.Context()
	lockID := "revoke-unproven-account-access:" + userID
	acquired, err := ia.ReserveVerificationValue(c, lockID, userID, time.Now().Add(revokeUnprovenLockExpiresIn))
	if err != nil {
		if !strings.Contains(err.Error(), "requires database-backed verification storage") {
			return nil, err
		}
		acquired = true
	}
	if !acquired {
		deadline := time.Now().Add(revokeUnprovenLockWait)
		for time.Now().Before(deadline) {
			lock, err := ia.FindVerificationValue(c, lockID)
			if err != nil {
				return nil, err
			}
			if lock == nil {
				break
			}
			if !lock.ExpiresAt.After(time.Now()) {
				if err := ia.DeleteVerificationByIdentifier(c, lockID); err != nil {
					return nil, err
				}
				break
			}
			time.Sleep(revokeUnprovenLockPoll)
		}
		return ia.FindUserByID(c, userID)
	}
	defer func() { _ = ia.DeleteVerificationByIdentifier(c, lockID) }()
	user, err := ia.FindUserByID(c, userID)
	if err != nil || user == nil || user.EmailVerified {
		return user, err
	}
	accounts, err := ia.FindAccounts(c, userID)
	if err != nil {
		return nil, err
	}
	for _, acc := range accounts {
		if err := ia.DeleteAccount(c, acc.ID); err != nil {
			return nil, err
		}
	}
	if err := ia.DeleteUserSessions(c, userID); err != nil {
		return nil, err
	}
	return ia.UpdateUser(c, userID, adapter.Record{"emailVerified": true})
}
