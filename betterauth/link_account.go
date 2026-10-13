package betterauth

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// OAuth callback error codes (OAUTH_CALLBACK_ERROR_CODES).
const (
	OAuthErrNoCode                   = "no_code"
	OAuthErrProviderNotFound         = "oauth_provider_not_found"
	OAuthErrIssuerMissing            = "issuer_missing"
	OAuthErrIssuerMismatch           = "issuer_mismatch"
	OAuthErrInvalidCode              = "invalid_code"
	OAuthErrNonceBindingMissing      = "nonce_binding_missing"
	OAuthErrUnableToGetUserInfo      = "unable_to_get_user_info"
	OAuthErrNoCallbackURL            = "no_callback_url"
	OAuthErrUnableToLinkAccount      = "unable_to_link_account"
	OAuthErrEmailDoesNotMatch        = "email_does_not_match"
	OAuthErrAccountLinkedToOtherUser = "account_already_linked_to_different_user"
	OAuthErrEmailNotFound            = "email_not_found"
	OAuthErrEmailNotVerified         = "email_not_verified"
)

const handlingProvidersDocsURL = "https://www.better-auth.com/docs/concepts/oauth#handling-providers-without-email"

func missingEmailLogMessage(providerID, source string) string {
	subject := `Provider "` + providerID + `"`
	if source == "generic" {
		subject = `Generic OAuth provider "` + providerID + `"`
	}
	where := ""
	if source == "id_token" {
		where = " in the id token"
	}
	return subject + " did not return an email" + where + ". Either request the provider's email scope, or create a placeholder via `mapProfileToUser`. See " + handlingProvidersDocsURL
}

// OAuthAccountData are the account fields obtained from a provider.
type OAuthAccountData struct {
	ProviderID            string
	AccountID             string
	AccessToken           string
	RefreshToken          string
	IDToken               string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	// Scope is the comma-joined granted scopes ("" when unknown).
	Scope string
}

// AccountDataFromTokens builds OAuthAccountData from tokens.
func AccountDataFromTokens(providerID, accountID string, t *oauth2.Tokens) OAuthAccountData {
	d := OAuthAccountData{ProviderID: providerID, AccountID: accountID}
	if t != nil {
		d.AccessToken, d.RefreshToken, d.IDToken = t.AccessToken, t.RefreshToken, t.IDToken
		d.AccessTokenExpiresAt, d.RefreshTokenExpiresAt = t.AccessTokenExpiresAt, t.RefreshTokenExpiresAt
		d.Scope = strings.Join(t.Scopes, ",")
	}
	return d
}

func setIfPresent(rec adapter.Record, key string, v any) {
	switch t := v.(type) {
	case nil:
		return
	case string:
		if t == "" {
			return
		}
	case *time.Time:
		if t == nil {
			return
		}
		rec[key] = *t
		return
	}
	rec[key] = v
}

// tokenFields returns encrypted/filtered token fields (undefined values dropped).
func (a *AuthContext) tokenFields(d OAuthAccountData) (adapter.Record, error) {
	rec := adapter.Record{}
	at, err := a.SetTokenUtil(d.AccessToken)
	if err != nil {
		return nil, err
	}
	rt, err := a.SetTokenUtil(d.RefreshToken)
	if err != nil {
		return nil, err
	}
	setIfPresent(rec, "accessToken", at)
	setIfPresent(rec, "refreshToken", rt)
	setIfPresent(rec, "idToken", d.IDToken)
	setIfPresent(rec, "accessTokenExpiresAt", d.AccessTokenExpiresAt)
	setIfPresent(rec, "refreshTokenExpiresAt", d.RefreshTokenExpiresAt)
	return rec, nil
}

func userInfoRecord(info oauth2.UserInfo) map[string]any {
	m := map[string]any{}
	for k, v := range info.Extra {
		m[k] = v
	}
	if info.Name != "" {
		m["name"] = info.Name
	}
	m["email"] = info.Email
	if info.Image != "" {
		m["image"] = info.Image
	}
	m["emailVerified"] = info.EmailVerified
	return m
}

// LinkOAuthAccountResult reports a link attempt.
type LinkOAuthAccountResult struct {
	Linked       bool
	ErrorCode    string
	ErrorMessage string
}

// LinkOAuthAccount links a provider account to an existing user (linkOAuthAccount).
func LinkOAuthAccount(ctx *EndpointContext, link StateLink, info oauth2.UserInfo, acc OAuthAccountData, profile map[string]any, scopes []string) (LinkOAuthAccountResult, error) {
	a := ctx.Auth
	if a.Options.User != nil && a.Options.User.ValidateUserInfo != nil {
		u := userInfoRecord(info)
		u["id"] = link.UserID
		if err := assertValidUserInfo(ctx, u, UserInfoSource{Action: "link-account", Method: "oauth", ProviderID: acc.ProviderID, Profile: profile}); err != nil {
			if e, ok := AsAPIError(err); ok && e.Code() != "" {
				return LinkOAuthAccountResult{ErrorCode: e.Code(), ErrorMessage: e.Message()}, nil
			}
			return LinkOAuthAccountResult{}, err
		}
	}
	trusted := contains(a.TrustedProviders, acc.ProviderID)
	al := a.accountLinking()
	if (!trusted && !info.EmailVerified) || (al != nil && al.Enabled != nil && !*al.Enabled) {
		a.Logger.Error("Unable to link account - untrusted provider")
		return LinkOAuthAccountResult{ErrorCode: OAuthErrUnableToLinkAccount}, nil
	}
	if !strings.EqualFold(info.Email, link.Email) && (al == nil || !al.AllowDifferentEmails) {
		return LinkOAuthAccountResult{ErrorCode: OAuthErrEmailDoesNotMatch}, nil
	}
	existing, err := a.InternalAdapter.FindAccountByKey(ctx.Context(), acc.ProviderID, acc.AccountID)
	if err != nil {
		return LinkOAuthAccountResult{}, err
	}
	tokens, err := a.tokenFields(acc)
	if err != nil {
		return LinkOAuthAccountResult{}, err
	}
	if existing != nil {
		if existing.UserID != link.UserID {
			return LinkOAuthAccountResult{ErrorCode: OAuthErrAccountLinkedToOtherUser}, nil
		}
		stored := ""
		if existing.Scope != nil {
			stored = *existing.Scope
		}
		upd := adapter.Record{"providerId": acc.ProviderID}
		for k, v := range tokens {
			upd[k] = v
		}
		if merged := oauth2.MergeScopes(stored, scopes); merged != "" {
			upd["scope"] = merged
		}
		if _, err := a.InternalAdapter.UpdateAccount(ctx.Context(), existing.ID, upd); err != nil {
			return LinkOAuthAccountResult{}, err
		}
	} else {
		rec := adapter.Record{"userId": link.UserID, "providerId": acc.ProviderID, "accountId": acc.AccountID}
		for k, v := range tokens {
			rec[k] = v
		}
		if scopes != nil {
			rec["scope"] = strings.Join(scopes, ",")
		} else if acc.Scope != "" {
			rec["scope"] = acc.Scope
		}
		created, err := a.InternalAdapter.CreateAccount(ctx.Context(), rec)
		if err != nil {
			return LinkOAuthAccountResult{}, err
		}
		if created == nil {
			return LinkOAuthAccountResult{ErrorCode: OAuthErrUnableToLinkAccount}, nil
		}
	}
	ApplyUpdateUserInfoOnLink(ctx, link.UserID, info)
	return LinkOAuthAccountResult{Linked: true}, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// HandleOAuthUserInfoOptions configure HandleOAuthUserInfo.
type HandleOAuthUserInfoOptions struct {
	UserInfo         oauth2.UserInfo
	Account          OAuthAccountData
	CallbackURL      string
	DisableSignUp    bool
	OverrideUserInfo bool
	// IsTrustedProvider treats the provider as trusted for implicit linking.
	IsTrustedProvider bool
	// TrustProviderByName=false ignores accountLinking.trustedProviders.
	TrustProviderByName *bool
	Source              UserInfoSource
}

// HandleOAuthUserInfoResult is the outcome of HandleOAuthUserInfo.
type HandleOAuthUserInfoResult struct {
	Error      string
	Data       *SessionWithUser
	IsRegister bool
}

// HandleOAuthUserInfo signs in or registers a user from provider data
// (handleOAuthUserInfo upstream).
func HandleOAuthUserInfo(ctx *EndpointContext, o HandleOAuthUserInfoOptions) (*HandleOAuthUserInfoResult, error) {
	a := ctx.Auth
	info, acc := o.UserInfo, o.Account
	source := o.Source
	if source.Method == "" {
		source = UserInfoSource{Method: "oauth", ProviderID: acc.ProviderID}
	}
	errorURL := a.BaseURL + "/error"
	if a.Options.OnAPIError != nil && a.Options.OnAPIError.ErrorURL != "" {
		errorURL = a.Options.OnAPIError.ErrorURL
	}
	dbError := func(err error) error {
		a.Logger.Error("Better auth was unable to query your database.\nError: ", err)
		u, _ := appendQueryParams(errorURL, url.Values{"error": {"internal_server_error"}}, []string{"error"})
		return ctx.Redirect(u)
	}
	owner, err := a.InternalAdapter.FindAccountOwnerByKey(ctx.Context(), acc.ProviderID, acc.AccountID)
	if err != nil {
		return nil, dbError(err)
	}
	if owner != nil && owner.Kind == "orphaned" {
		a.Logger.Error("OAuth account references a missing user. Repair the account before retrying authentication.")
		return &HandleOAuthUserInfoResult{Error: "unable to link account"}, nil
	}
	var dbUser *User
	var linked *Account
	var accounts []*Account
	if owner != nil {
		dbUser, linked, accounts = owner.User, owner.Account, []*Account{owner.Account}
	} else {
		m, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), strings.ToLower(info.Email), true)
		if err != nil {
			return nil, dbError(err)
		}
		if m != nil {
			dbUser, accounts = m.User, m.Accounts
		}
	}
	user := dbUser
	isRegister := user == nil
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
			if (!trusted && !info.EmailVerified) || (requireLocal && !dbUser.EmailVerified) ||
				(al != nil && al.Enabled != nil && !*al.Enabled) || (al != nil && al.DisableImplicitLinking) {
				if isTestOrDev() {
					a.Logger.Warn("User already exist but account isn't linked to " + acc.ProviderID + ". To read more about how account linking works in Better Auth see https://www.better-auth.com/docs/concepts/users-accounts#account-linking.")
				}
				return &HandleOAuthUserInfoResult{Error: "account not linked"}, nil
			}
			if a.Options.User != nil && a.Options.User.ValidateUserInfo != nil {
				u := userInfoRecord(info)
				u["id"] = dbUser.ID
				u["email"] = strings.ToLower(info.Email)
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
				return &HandleOAuthUserInfoResult{Error: "unable to link account"}, nil
			}
			if created == nil {
				return &HandleOAuthUserInfoResult{Error: "unable to link account"}, nil
			}
			if a.storeAccountCookie() {
				if err := SetAccountCookie(ctx, created); err != nil {
					return nil, err
				}
			}
			if info.EmailVerified && !dbUser.EmailVerified && strings.ToLower(info.Email) == dbUser.Email {
				if _, err := a.InternalAdapter.UpdateUser(ctx.Context(), dbUser.ID, adapter.Record{"emailVerified": true}); err != nil {
					return nil, err
				}
			}
			if u := ApplyUpdateUserInfoOnLink(ctx, dbUser.ID, info); u != nil {
				user = u
			}
		} else {
			if a.Options.User != nil && a.Options.User.ValidateUserInfo != nil {
				u := userInfoRecord(info)
				u["id"] = dbUser.ID
				u["email"] = strings.ToLower(info.Email)
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
				cookieAcc := AccountFromRecord(mergeRecord(linked.Record(), fresh))
				if err := SetAccountCookie(ctx, cookieAcc); err != nil {
					return nil, err
				}
			}
			if len(fresh) > 0 {
				updated, err := a.InternalAdapter.UpdateAccount(ctx.Context(), linked.ID, fresh)
				if err != nil {
					return nil, err
				}
				if updated == nil {
					return &HandleOAuthUserInfoResult{Error: "unable to update account"}, nil
				}
			}
			if info.EmailVerified && !dbUser.EmailVerified && strings.ToLower(info.Email) == dbUser.Email {
				if _, err := a.InternalAdapter.UpdateUser(ctx.Context(), dbUser.ID, adapter.Record{"emailVerified": true}); err != nil {
					return nil, err
				}
			}
		}
		if o.OverrideUserInfo {
			additional, err := a.ParseAdditionalUserInputFromProfile(info.Extra, "update")
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
			upd["email"] = strings.ToLower(info.Email)
			if strings.ToLower(info.Email) == dbUser.Email {
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
			} else {
				user = updated
			}
		}
	} else {
		if o.DisableSignUp {
			return &HandleOAuthUserInfoResult{Error: "signup disabled"}, nil
		}
		additional, err := a.ParseAdditionalUserInputFromProfile(info.Extra, "create")
		if err != nil {
			if _, ok := AsAPIError(err); ok {
				return nil, err
			}
			return &HandleOAuthUserInfoResult{Error: "unable to create user"}, nil
		}
		tokens, err := a.tokenFields(acc)
		if err != nil {
			return nil, err
		}
		var createdUser *User
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
			data["email"] = strings.ToLower(info.Email)
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
			createdAcc, err := a.InternalAdapter.CreateAccount(ctx.Context(), rec)
			if err != nil {
				return err
			}
			createdUser = u
			if a.storeAccountCookie() && createdAcc != nil {
				return SetAccountCookie(ctx, createdAcc)
			}
			return nil
		})
		if err != nil {
			if _, ok := AsAPIError(err); ok {
				return nil, err
			}
			a.Logger.Error("Unable to create OAuth user", err)
			return &HandleOAuthUserInfoResult{Error: "unable to create user"}, nil
		}
		user = createdUser
	}
	if user == nil {
		return &HandleOAuthUserInfoResult{Error: "unable to create user"}, nil
	}
	requireVerification := false
	if p := a.FindProvider(acc.ProviderID); p != nil {
		requireVerification = oauth2.SettingsOf(p).RequireEmailVerification
	}
	sendOnSignUp := requireVerification
	if ev := a.Options.EmailVerification; ev != nil && ev.SendOnSignUp != nil {
		sendOnSignUp = *ev.SendOnSignUp
	}
	if isRegister && !user.EmailVerified && sendOnSignUp {
		dispatchOAuthVerificationEmail(ctx, user, o.CallbackURL)
	}
	if requireVerification && !user.EmailVerified {
		if !isRegister && a.Options.EmailVerification != nil && a.Options.EmailVerification.SendOnSignIn {
			dispatchOAuthVerificationEmail(ctx, user, o.CallbackURL)
		}
		return &HandleOAuthUserInfoResult{Error: OAuthErrEmailNotVerified, IsRegister: isRegister}, nil
	}
	session, err := a.InternalAdapter.CreateSession(ctx.Context(), user.ID, nil)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return &HandleOAuthUserInfoResult{Error: "unable to create session"}, nil
	}
	return &HandleOAuthUserInfoResult{Data: &SessionWithUser{Session: session, User: user}, IsRegister: isRegister}, nil
}

func dispatchOAuthVerificationEmail(ctx *EndpointContext, user *User, callbackURL string) {
	a := ctx.Auth
	ev := a.Options.EmailVerification
	if ev == nil || ev.SendVerificationEmail == nil {
		return
	}
	token, err := CreateEmailVerificationToken(a.Secret, user.Email, "", a.verificationExpiresIn(), nil)
	if err != nil {
		a.Logger.Error("Failed to send OAuth verification email", err)
		return
	}
	if callbackURL == "" {
		callbackURL = "/"
	}
	u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + EncodeURIComponent(callbackURL)
	a.RunInBackgroundOrAwait(func() error {
		err := ev.SendVerificationEmail(context.WithoutCancel(ctx.Context()), EmailData{User: user, URL: u, Token: token}, ctx.Request)
		if err != nil {
			a.Logger.Error("Failed to send OAuth verification email", err)
		}
		return nil
	})
}
