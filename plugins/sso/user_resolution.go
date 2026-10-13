package sso

import (
	"context"
	"errors"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func resolutionFailure() *betterauth.APIError {
	return apiErr("INTERNAL_SERVER_ERROR", "code", "SSO_USER_RESOLUTION_FAILED", "message", "Unable to resolve the SSO user")
}

func isValidResolution(r UserResolution) bool {
	switch r.Action {
	case "continue":
		return true
	case "link":
		return strings.TrimSpace(r.UserID) != "" && (r.Profile == "preserve" || r.Profile == "update")
	case "reject":
		return strings.TrimSpace(r.Code) != ""
	}
	return false
}

type errorLogger interface {
	Error(msg string, args ...any)
}

func safeLog(l errorLogger, msg string) {
	defer func() { _ = recover() }()
	l.Error(msg)
}

// resolveSSOUser runs the ResolveUser hook and validates its decision.
func resolveSSOUser(ctx context.Context, fn func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error),
	in UserResolutionInput, db adapter.Adapter, logger errorLogger) (res UserResolution, err error) {
	defer func() {
		if r := recover(); r != nil {
			safeLog(logger, "SSO user resolution failed")
			err = resolutionFailure()
		}
	}()
	res, err = fn(ctx, in, UserResolutionContext{Adapter: db})
	if err != nil {
		safeLog(logger, "SSO user resolution failed")
		return UserResolution{}, resolutionFailure()
	}
	if !isValidResolution(res) {
		safeLog(logger, "SSO user resolver returned an invalid decision")
		return UserResolution{}, resolutionFailure()
	}
	return res, nil
}

// supportsNativeTransactions reports whether the adapter runs callbacks in a real
// transaction (a transactional context is passed to the callback).
func supportsNativeTransactions(ctx context.Context, a adapter.Adapter) bool {
	native := false
	_ = a.Transaction(ctx, func(txCtx context.Context, _ adapter.Adapter) error {
		native = txCtx != ctx
		return nil
	})
	return native
}

func assertNativeTransactionSupport(ctx context.Context, a adapter.Adapter, code, message string) error {
	if supportsNativeTransactions(ctx, a) {
		return nil
	}
	return apiErr("NOT_IMPLEMENTED", "code", code, "message", message)
}

func assertSSOUserResolutionNativeTransactionSupport(ctx context.Context, a adapter.Adapter) error {
	return assertNativeTransactionSupport(ctx, a, "SSO_USER_RESOLUTION_REQUIRES_NATIVE_TRANSACTIONS",
		"SSO user resolution requires a database adapter with native transaction support")
}

// assertSSOUserResolutionSessionStorage requires database-backed sessions when secondary
// storage is configured.
func assertSSOUserResolutionSessionStorage(cfg *betterauth.Config) error {
	if cfg.SecondaryStorage == nil || (cfg.Session != nil && cfg.Session.StoreSessionInDatabase && !cfg.Session.PreserveSessionInDatabase) {
		return nil
	}
	return apiErr("NOT_IMPLEMENTED", "code", "SSO_USER_RESOLUTION_REQUIRES_DATABASE_SESSIONS",
		"message", "SSO user resolution requires database-backed sessions with database fallback")
}

// ssoAuthenticationFailure carries a failed authentication result out of the transaction.
type ssoAuthenticationFailure struct {
	result *betterauth.SSOHandleOAuthUserInfoResult
}

func (e *ssoAuthenticationFailure) Error() string { return "SSO authentication failed" }

func requireSuccessfulSSOAuthentication(r *betterauth.SSOHandleOAuthUserInfoResult) (*betterauth.SSOHandleOAuthUserInfoResult, error) {
	if r.Error == "" {
		return r, nil
	}
	return nil, &ssoAuthenticationFailure{result: r}
}

func getFailedSSOAuthenticationResult(err error) *betterauth.SSOHandleOAuthUserInfoResult {
	var f *ssoAuthenticationFailure
	if errors.As(err, &f) {
		return f.result
	}
	return nil
}
