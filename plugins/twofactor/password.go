package twofactor

import (
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// The helpers below port utils/password.ts using exported core APIs.

func assertPasswordNotTooLong(ctx *betterauth.EndpointContext, pw string) error {
	if jsonx.EncodeUTF16Length(pw) > ctx.Auth.Password.MaxLength {
		ctx.Auth.Logger.Warn("Password is too long")
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooLong)
	}
	return nil
}

// shouldRequirePassword: a password is required unless allowPasswordless is set and the user
// has no credential password.
func shouldRequirePassword(ctx *betterauth.EndpointContext, userID string, allowPasswordless bool) (bool, error) {
	if !allowPasswordless {
		return true, nil
	}
	acc, err := ctx.Auth.InternalAdapter.FindCredentialAccount(ctx.Context(), userID)
	if err != nil {
		return false, err
	}
	return acc != nil && acc.Password != nil && *acc.Password != "", nil
}

// validatePassword reports whether password matches the user's credential password.
func validatePassword(ctx *betterauth.EndpointContext, password, userID string) (bool, error) {
	if err := assertPasswordNotTooLong(ctx, password); err != nil {
		return false, err
	}
	acc, err := ctx.Auth.InternalAdapter.FindCredentialAccount(ctx.Context(), userID)
	if err != nil {
		return false, err
	}
	if acc == nil || acc.Password == nil || *acc.Password == "" {
		return false, nil
	}
	return ctx.Auth.Password.Verify(*acc.Password, password)
}

// checkPassword is ctx.context.password.checkPassword: it reads body.password and fails with
// INVALID_PASSWORD whether the password is wrong or the credential row is missing.
func checkPassword(ctx *betterauth.EndpointContext, userID string) error {
	password, isString := ctx.BodyMap()["password"].(string)
	if isString {
		if err := assertPasswordNotTooLong(ctx, password); err != nil {
			return err
		}
	}
	acc, err := ctx.Auth.InternalAdapter.FindCredentialAccount(ctx.Context(), userID)
	if err != nil {
		return err
	}
	if acc == nil || acc.Password == nil || *acc.Password == "" || password == "" {
		if password != "" {
			_, _ = ctx.Auth.Password.Hash(password)
		}
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidPassword)
	}
	ok, err := ctx.Auth.Password.Verify(*acc.Password, password)
	if err != nil {
		return err
	}
	if !ok {
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidPassword)
	}
	return nil
}

// requirePasswordIfNeeded is the enable/disable password gate.
func requirePasswordIfNeeded(ctx *betterauth.EndpointContext, userID string, allowPasswordless bool) error {
	req, err := shouldRequirePassword(ctx, userID, allowPasswordless)
	if err != nil {
		return err
	}
	if !req {
		return nil
	}
	password := ctx.BodyString("password")
	if password == "" {
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidPassword)
	}
	ok, err := validatePassword(ctx, password, userID)
	if err != nil {
		return err
	}
	if !ok {
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidPassword)
	}
	return nil
}
