package betterauth

import (
	"context"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Helpers exported for the sso plugin (packages/sso). They expose existing core behaviour
// (parseState, parseInputData) and the full upstream handleOAuthUserInfo signature, whose
// selectedUser / deferNonDatabaseWrites / requireExactAccountBinding options the SSO user
// resolution hooks rely on.

// SSOSelectedUser binds an authentication to an existing user (handleOAuthUserInfo
// selectedUser). Profile is "preserve" or "update".
type SSOSelectedUser struct {
	UserID  string
	Profile string
}

// SSOHandleOAuthUserInfoOptions extend HandleOAuthUserInfoOptions with the options the SSO
// plugin passes upstream.
type SSOHandleOAuthUserInfoOptions struct {
	HandleOAuthUserInfoOptions
	// SelectedUser links the account to this user instead of the email match.
	SelectedUser *SSOSelectedUser
	// DeferNonDatabaseWrites defers the account cookie, verification e-mails and secondary
	// storage session writes until the surrounding transaction commits.
	DeferNonDatabaseWrites bool
	// RequireExactAccountBinding rejects database hooks that change the selected binding.
	RequireExactAccountBinding bool
}

// SSOHandleOAuthUserInfoResult is the outcome of SSOHandleOAuthUserInfo.
type SSOHandleOAuthUserInfoResult struct {
	HandleOAuthUserInfoResult
	// AccountCookie is the deferred account cookie (DeferNonDatabaseWrites only).
	AccountCookie *Account
}

func ssoConflict(code, message string) *APIError {
	return NewAPIError("CONFLICT", jsonx.O("code", code, "message", message))
}

func ssoProfileRecord(info oauth2.UserInfo) map[string]any {
	m := map[string]any{}
	for k, v := range info.Extra {
		m[k] = v
	}
	return m
}

// SSOHandleOAuthUserInfo signs in or registers a user from provider data with the full
// upstream handleOAuthUserInfo semantics (selectedUser, deferNonDatabaseWrites and
// requireExactAccountBinding).
func SSOHandleOAuthUserInfo(ctx *EndpointContext, o SSOHandleOAuthUserInfoOptions) (*SSOHandleOAuthUserInfoResult, error) {
	a := ctx.Auth
	info, acc := o.UserInfo, o.Account
	source := o.Source
	if source.Method == "" {
		source = UserInfoSource{Method: "oauth", ProviderID: acc.ProviderID}
	}
	requireExact := o.SelectedUser != nil || o.RequireExactAccountBinding
	var pendingCookie *Account
	fail := func(msg string, isRegister bool) (*SSOHandleOAuthUserInfoResult, error) {
		return &SSOHandleOAuthUserInfoResult{HandleOAuthUserInfoResult: HandleOAuthUserInfoResult{Error: msg, IsRegister: isRegister}}, nil
	}
	dbError := func(err error) error {
		a.Logger.Error("Better auth was unable to query your database.\nError: ", err)
		u, _ := appendQueryParams(a.defaultErrorURL(), map[string][]string{"error": {"internal_server_error"}}, []string{"error"})
		return ctx.Redirect(u)
	}
	email := strings.ToLower(info.Email)
	owner, err := a.InternalAdapter.FindAccountOwnerByKey(ctx.Context(), acc.ProviderID, acc.AccountID)
	if err != nil {
		return nil, dbError(err)
	}
	if owner != nil && owner.Kind == "orphaned" {
		a.Logger.Error("OAuth account references a missing user. Repair the account before retrying authentication.")
		return fail("unable to link account", false)
	}
	var dbUser *User
	var linked *Account
	var accounts []*Account
	switch {
	case owner != nil:
		if o.SelectedUser != nil && owner.User.ID != o.SelectedUser.UserID {
			return nil, ssoConflict("account_ownership_conflict", "Account is already linked to another user")
		}
		dbUser, linked, accounts = owner.User, owner.Account, []*Account{owner.Account}
	case o.SelectedUser != nil:
		u, err := a.InternalAdapter.FindUserByID(ctx.Context(), o.SelectedUser.UserID)
		if err != nil {
			return nil, dbError(err)
		}
		if u == nil {
			return nil, NewAPIError("NOT_FOUND", jsonx.O("code", "user_not_found", "message", "User not found"))
		}
		dbUser = u
	default:
		m, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), email, true)
		if err != nil {
			return nil, dbError(err)
		}
		if m != nil {
			dbUser, accounts = m.User, m.Accounts
		}
	}
	user := dbUser
	isRegister := user == nil
	setCookie := func(acct *Account) error {
		if !a.storeAccountCookie() || acct == nil {
			return nil
		}
		if o.DeferNonDatabaseWrites {
			pendingCookie = acct
			return nil
		}
		return SetAccountCookie(ctx, acct)
	}
	if dbUser != nil {
		if linked == nil {
			for _, x := range accounts {
				if x.ProviderID == acc.ProviderID && x.AccountID == acc.AccountID {
					linked = x
				}
			}
		}
		if linked == nil {
			al := a.accountLinking()
			trusted := o.IsTrustedProvider || ((o.TrustProviderByName == nil || *o.TrustProviderByName) && contains(a.TrustedProviders, acc.ProviderID))
			requireLocal := true
			if al != nil && al.RequireLocalEmailVerified != nil {
				requireLocal = *al.RequireLocalEmailVerified
			}
			if o.SelectedUser == nil && ((!trusted && !info.EmailVerified) || (requireLocal && !dbUser.EmailVerified) ||
				(al != nil && al.Enabled != nil && !*al.Enabled) || (al != nil && al.DisableImplicitLinking)) {
				if isTestOrDev() {
					a.Logger.Warn("User already exist but account isn't linked to " + acc.ProviderID + ". To read more about how account linking works in Better Auth see https://www.better-auth.com/docs/concepts/users-accounts#account-linking.")
				}
				return fail("account not linked", false)
			}
			if a.Options.User != nil && a.Options.User.ValidateUserInfo != nil {
				u := userInfoRecord(info)
				u["id"] = dbUser.ID
				u["email"] = email
				src := source
				src.Action = "link-account"
				if err := assertValidUserInfo(ctx, u, src); err != nil {
					return nil, err
				}
			}
			tokens, err := a.tokenFields(acc)
			if err != nil {
				return nil, err
			}
			rec := adapter.Record{"providerId": acc.ProviderID, "accountId": acc.AccountID, "userId": dbUser.ID}
			for k, v := range tokens {
				rec[k] = v
			}
			setIfPresent(rec, "scope", acc.Scope)
			created, err := a.InternalAdapter.LinkAccount(ctx.Context(), rec)
			if err != nil {
				if _, ok := AsAPIError(err); ok {
					return nil, err
				}
				a.Logger.Error("Unable to link account", err)
				return fail("unable to link account", false)
			}
			if created == nil {
				return fail("unable to link account", false)
			}
			if requireExact && (created.AccountID != acc.AccountID || created.ProviderID != acc.ProviderID || created.UserID != dbUser.ID) {
				return nil, ssoConflict("account_hook_binding_conflict", "Account hook changed the selected authentication binding")
			}
			if err := setCookie(created); err != nil {
				return nil, err
			}
			if o.SelectedUser == nil && info.EmailVerified && !dbUser.EmailVerified && email == dbUser.Email {
				if _, err := a.InternalAdapter.UpdateUser(ctx.Context(), dbUser.ID, adapter.Record{"emailVerified": true}); err != nil {
					return nil, err
				}
			}
			if o.SelectedUser == nil {
				if u := ApplyUpdateUserInfoOnLink(ctx, dbUser.ID, info); u != nil {
					user = u
				}
			}
		} else {
			if a.Options.User != nil && a.Options.User.ValidateUserInfo != nil {
				u := userInfoRecord(info)
				u["id"] = dbUser.ID
				u["email"] = email
				src := source
				src.Action = "sign-in"
				if err := assertValidUserInfo(ctx, u, src); err != nil {
					return nil, err
				}
			}
			fresh := adapter.Record{}
			if ac := a.Options.Account; ac == nil || ac.UpdateAccountOnSignIn == nil || *ac.UpdateAccountOnSignIn {
				tokens, err := a.tokenFields(acc)
				if err != nil {
					return nil, err
				}
				fresh["providerId"] = acc.ProviderID
				for k, v := range tokens {
					fresh[k] = v
				}
			}
			if a.storeAccountCookie() {
				if err := setCookie(AccountFromRecord(mergeRecord(linked.Record(), fresh))); err != nil {
					return nil, err
				}
			}
			if len(fresh) > 0 {
				updated, err := a.InternalAdapter.UpdateAccount(ctx.Context(), linked.ID, fresh)
				if err != nil {
					return nil, err
				}
				if updated == nil {
					return fail("unable to update account", false)
				}
				if requireExact && (updated.AccountID != acc.AccountID || updated.ProviderID != acc.ProviderID || updated.UserID != dbUser.ID) {
					return nil, ssoConflict("account_hook_binding_conflict", "Account hook changed the selected authentication binding")
				}
				if o.DeferNonDatabaseWrites && pendingCookie != nil {
					pendingCookie = updated
				}
			}
			if o.SelectedUser == nil && info.EmailVerified && !dbUser.EmailVerified && email == dbUser.Email {
				if _, err := a.InternalAdapter.UpdateUser(ctx.Context(), dbUser.ID, adapter.Record{"emailVerified": true}); err != nil {
					return nil, err
				}
			}
		}
		doUpdate := o.OverrideUserInfo
		if o.SelectedUser != nil {
			doUpdate = o.SelectedUser.Profile == "update"
		}
		if doUpdate {
			additional, err := a.ParseAdditionalUserInputFromProfile(ssoProfileRecord(info), "update")
			if err != nil {
				return nil, err
			}
			upd := adapter.Record{}
			if info.Name != "" {
				upd["name"] = info.Name
			}
			if info.Image != "" {
				upd["image"] = info.Image
			}
			for k, v := range additional {
				upd[k] = v
			}
			upd["email"] = email
			if email == dbUser.Email {
				upd["emailVerified"] = dbUser.EmailVerified || info.EmailVerified
			} else {
				upd["emailVerified"] = info.EmailVerified
			}
			updated, err := a.InternalAdapter.UpdateUser(ctx.Context(), dbUser.ID, upd)
			if err != nil {
				return nil, err
			}
			if updated == nil {
				a.Logger.Warn("Could not update user info during OAuth sign in; preserving existing user for session.")
			}
			if o.SelectedUser != nil && updated != nil && updated.ID != o.SelectedUser.UserID {
				return nil, ssoConflict("user_hook_selection_conflict", "User hook changed the selected user")
			}
			if updated != nil {
				user = updated
			}
		}
	} else {
		if o.DisableSignUp {
			return fail("signup disabled", false)
		}
		additional, err := a.ParseAdditionalUserInputFromProfile(ssoProfileRecord(info), "create")
		if err != nil {
			if _, ok := AsAPIError(err); ok {
				return nil, err
			}
			return fail("unable to create user", false)
		}
		tokens, err := a.tokenFields(acc)
		if err != nil {
			return nil, err
		}
		var createdUser *User
		var createdAcc *Account
		err = ctx.Transaction(func() error {
			data := adapter.Record{}
			if info.Name != "" {
				data["name"] = info.Name
			} else {
				data["name"] = ""
			}
			if info.Image != "" {
				data["image"] = info.Image
			} else {
				data["image"] = nil
			}
			for k, v := range additional {
				data[k] = v
			}
			data["email"] = email
			data["emailVerified"] = info.EmailVerified
			u, err := a.InternalAdapter.CreateUser(ctx.Context(), data, source)
			if err != nil {
				return err
			}
			if u == nil {
				return ErrFrom("BAD_REQUEST", ErrFailedToCreateUser)
			}
			rec := adapter.Record{"providerId": acc.ProviderID, "accountId": acc.AccountID, "userId": u.ID}
			for k, v := range tokens {
				rec[k] = v
			}
			setIfPresent(rec, "scope", acc.Scope)
			createdAcc, err = a.InternalAdapter.CreateAccount(ctx.Context(), rec)
			if err != nil {
				return err
			}
			createdUser = u
			return nil
		})
		if err != nil {
			if _, ok := AsAPIError(err); ok {
				return nil, err
			}
			a.Logger.Error("Unable to create OAuth user", err)
			return fail("unable to create user", false)
		}
		if requireExact && createdAcc == nil {
			// Upstream reads createdAccount.accountId of the aborted (null) account and throws
			// a TypeError, which ends in "unable to create user" (and rolls back the caller).
			a.Logger.Error("Unable to create OAuth user", "account creation was aborted")
			return fail("unable to create user", false)
		}
		if requireExact && (createdAcc.AccountID != acc.AccountID || createdAcc.ProviderID != acc.ProviderID || createdAcc.UserID != createdUser.ID) {
			return nil, ssoConflict("account_hook_binding_conflict", "Account hook changed the selected authentication binding")
		}
		user = createdUser
		if err := setCookie(createdAcc); err != nil {
			return nil, err
		}
	}
	if user == nil {
		return fail("unable to create user", false)
	}
	requireVerification := false
	if p := a.FindProvider(acc.ProviderID); p != nil {
		requireVerification = oauth2.SettingsOf(p).RequireEmailVerification
	}
	sendOnSignUp := requireVerification
	if ev := a.Options.EmailVerification; ev != nil && ev.SendOnSignUp != nil {
		sendOnSignUp = *ev.SendOnSignUp
	}
	dispatch := func() {
		u, cb := user, o.CallbackURL
		if o.DeferNonDatabaseWrites {
			_ = a.QueueAfterTransactionHook(ctx.Context(), func(context.Context) error {
				dispatchOAuthVerificationEmail(ctx, u, cb)
				return nil
			}, nil)
			return
		}
		dispatchOAuthVerificationEmail(ctx, u, cb)
	}
	if isRegister && !user.EmailVerified && sendOnSignUp {
		dispatch()
	}
	if requireVerification && !user.EmailVerified {
		if !isRegister && a.Options.EmailVerification != nil && a.Options.EmailVerification.SendOnSignIn {
			dispatch()
		}
		return fail(OAuthErrEmailNotVerified, isRegister)
	}
	session, err := a.InternalAdapter.CreateSession(ctx.Context(), user.ID, &CreateSessionOptions{DeferSecondaryStorageWrites: o.DeferNonDatabaseWrites})
	if err != nil {
		return nil, err
	}
	if session == nil {
		return fail("unable to create session", false)
	}
	expected := user.ID
	if o.SelectedUser != nil {
		expected = o.SelectedUser.UserID
	}
	if requireExact && session.UserID != expected {
		return nil, ssoConflict("session_hook_user_conflict", "Session hook changed the selected user")
	}
	return &SSOHandleOAuthUserInfoResult{
		HandleOAuthUserInfoResult: HandleOAuthUserInfoResult{Data: &SessionWithUser{Session: session, User: user}, IsRegister: isRegister},
		AccountCookie:             pendingCookie,
	}, nil
}

// SSOParseState parses the OAuth state of a callback like the core parseState: failures
// redirect to the error URL with the state error code, a missing errorURL defaults to the
// configured error page and the state is stored for GetOAuthState.
func SSOParseState(ctx *EndpointContext) (*StateData, error) {
	a := ctx.Auth
	state := ctx.QueryString("state")
	if state == "" {
		state = ctx.BodyString("state")
	}
	errorURL := a.defaultErrorURL()
	sd, err := ParseGenericState(ctx, state, "", nil)
	if err != nil {
		a.Logger.Error("Failed to parse state", err)
		code := "internal_server_error"
		target := errorURL
		if se, ok := err.(*StateError); ok {
			code = se.Code
			if code == "state_security_mismatch" {
				code = "state_mismatch"
			}
			if se.ErrorURL != "" {
				target = se.ErrorURL
			}
		}
		return nil, errorRedirect(ctx, target, code, "")
	}
	if sd.ErrorURL == "" {
		sd.ErrorURL = errorURL
	}
	RequestStateSet(ctx.Context(), oauthStateKey{}, sd)
	return sd, nil
}

// SSOParseGenericState parses a state created with OAuthPopupGenerateState (parseGenericState
// with skipStateCookieCheck), used for SAML RelayState.
func SSOParseGenericState(ctx *EndpointContext, state, cookieName string, skipStateCookieCheck bool) (*StateData, error) {
	return ParseGenericState(ctx, state, cookieName, &skipStateCookieCheck)
}

// SSOParseInputData validates plugin additional-field input (db/schema parseInputData).
func SSOParseInputData(data map[string]any, fields []db.Field, action string) (map[string]any, error) {
	if data == nil {
		data = map[string]any{}
	}
	return parseInputData(data, fields, action)
}

// SSOIsTestOrDev reports whether NODE_ENV is test/development (isDevelopment / isTest).
func SSOIsTestOrDev() bool { return isTestOrDev() }

// SSOAdditionalParamsSchema is additionalAuthorizationParamsSchema (a string record without
// reserved OAuth parameters).
var SSOAdditionalParamsSchema = additionalParamsSchema

// SSOAdditionalParamsOrder returns the request-body key order of additionalParams.
func SSOAdditionalParamsOrder(ctx *EndpointContext) []string { return additionalParamsOrder(ctx) }
