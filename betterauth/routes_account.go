package betterauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/validate"
)

func parseStoredScopes(scope *string) []any {
	out := []any{}
	if scope == nil || *scope == "" {
		return out
	}
	for _, s := range strings.Split(*scope, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// FindProvider returns the configured social provider with id.
func (a *AuthContext) FindProvider(id string) oauth2.Provider {
	for _, p := range a.SocialProviders {
		if p.ID() == id {
			return p
		}
	}
	return nil
}

func listAccountsEndpoint() *Endpoint {
	return &Endpoint{
		Key: "listUserAccounts", Path: "/list-accounts", Methods: []string{"GET"},
		Use: []Middleware{SessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			accounts, err := ctx.Auth.InternalAdapter.FindAccounts(ctx.Context(), ctx.Session.User.ID)
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, acc := range accounts {
				o := ctx.Auth.AccountOutput(acc)
				o.Delete("scope")
				o.Set("scopes", parseStoredScopes(acc.Scope))
				out = append(out, o)
			}
			return out, nil
		},
	}
}

var reservedParamsMessage = "additionalParams cannot include reserved OAuth parameters: " + strings.Join(oauth2.ReservedAuthorizationParams, ", ")

// additionalParamsSchema is additionalAuthorizationParamsSchema: a string record that may
// not contain reserved OAuth parameters.
var additionalParamsSchema = validate.Optional(validate.Custom(func(v any, path []any) (any, []validate.Issue) {
	out, issues := validate.Validate(validate.Record(validate.String()), v)
	if len(issues) > 0 {
		for i := range issues {
			issues[i].Path = append(append([]any(nil), path...), issues[i].Path...)
		}
		return nil, issues
	}
	if m, ok := out.(map[string]any); ok {
		for k := range m {
			for _, r := range oauth2.ReservedAuthorizationParams {
				if k == r {
					return nil, []validate.Issue{validate.NewIssue(path, "custom", reservedParamsMessage)}
				}
			}
		}
	}
	return out, nil
}))

var linkSocialBody = validate.Object(
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("provider", validate.String()),
	validate.F("idToken", validate.Optional(validate.Object(
		validate.F("token", validate.String()),
		validate.F("nonce", validate.Optional(validate.String())),
		validate.F("accessToken", validate.Optional(validate.String())),
		validate.F("refreshToken", validate.Optional(validate.String())),
	))),
	validate.F("requestSignUp", validate.Optional(validate.Boolean())),
	validate.F("scopes", validate.Optional(validate.Array(validate.String()))),
	validate.F("errorCallbackURL", validate.Optional(validate.String())),
	validate.F("disableRedirect", validate.Optional(validate.Boolean())),
	validate.F("loginHint", validate.Optional(validate.String())),
	validate.F("additionalParams", additionalParamsSchema),
	validate.F("additionalData", validate.Optional(validate.Record(validate.Any()))),
)

func stringList(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}

// additionalParamsOrder recovers the key order of body.additionalParams from the raw JSON
// request body (insertion order; oauth2.OrderedKeys applies JS enumeration rules). It returns nil for server-side calls (no request body).
func additionalParamsOrder(ctx *EndpointContext) []string {
	r := ctx.Request
	if r == nil || r.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) == 0 {
		return nil
	}
	v, err := jsonx.Parse(raw)
	if err != nil {
		return nil
	}
	obj, ok := v.(*jsonx.Object)
	if !ok {
		return nil
	}
	ap, _ := obj.Get("additionalParams")
	params, ok := ap.(*jsonx.Object)
	if !ok {
		return nil
	}
	return params.Keys()
}

// ApplyUpdateUserInfoOnLink updates the user with provider profile data when
// account.accountLinking.updateUserInfoOnLink is enabled.
func ApplyUpdateUserInfoOnLink(ctx *EndpointContext, userID string, info oauth2.UserInfo) *User {
	a := ctx.Auth
	if a.Options.Account == nil || a.Options.Account.AccountLinking == nil || !a.Options.Account.AccountLinking.UpdateUserInfoOnLink {
		return nil
	}
	profile := map[string]any{}
	for k, v := range info.Extra {
		profile[k] = v
	}
	additional, err := a.ParseAdditionalUserInputFromProfile(profile, "update")
	if err != nil {
		a.Logger.Warn("Could not update user info on account link", err)
		return nil
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
	u, err := a.InternalAdapter.UpdateUser(ctx.Context(), userID, upd)
	if err != nil {
		a.Logger.Warn("Could not update user info on account link", err)
		return nil
	}
	return u
}

// ErrAccountSubjectInvalid is returned when a provider's account subject is empty,
// "undefined" or "null" (BetterAuthError OAUTH_ACCOUNT_SUBJECT_INVALID).
var ErrAccountSubjectInvalid = errors.New("OAUTH_ACCOUNT_SUBJECT_INVALID")

// ResolveOAuthAccountKey returns the stable provider account id established by a provider
// response (resolveOAuthAccountKey).
func ResolveOAuthAccountKey(ctx context.Context, p oauth2.Provider, tokens *oauth2.Tokens, profile map[string]any) (string, error) {
	id, err := p.AccountSubject(ctx, tokens, profile)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(id) == "" || id == "undefined" || id == "null" {
		return "", ErrAccountSubjectInvalid
	}
	return id, nil
}

// ResolveAccountID resolves the account id at a direct HTTP boundary
// (resolveOAuthAccountKeyForAPI): every failure becomes UNAUTHORIZED FAILED_TO_GET_USER_INFO.
func ResolveAccountID(ctx *EndpointContext, p oauth2.Provider, tokens *oauth2.Tokens, profile map[string]any) (string, error) {
	id, err := ResolveOAuthAccountKey(ctx.Context(), p, tokens, profile)
	if err != nil {
		return "", ErrFrom("UNAUTHORIZED", ErrFailedToGetUserInfo)
	}
	return id, nil
}

func linkSocialEndpoint() *Endpoint {
	return &Endpoint{
		Key: "linkSocialAccount", Path: "/link-social", Methods: []string{"POST"}, RequireHeaders: true,
		Body: linkSocialBody, Use: []Middleware{SessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			session := ctx.Session
			body := ctx.BodyMap()
			providerID := ctx.BodyString("provider")
			p := a.FindProvider(providerID)
			if p == nil {
				a.Logger.Error("Provider not found. Make sure to add the provider in your auth config", providerID)
				return nil, ErrFrom("NOT_FOUND", ErrProviderNotFound)
			}
			if idt, ok := body["idToken"].(map[string]any); ok {
				if !oauth2.SupportsIDTokenSignIn(p) {
					return nil, ErrFrom("NOT_FOUND", ErrIDTokenNotSupported)
				}
				token, _ := idt["token"].(string)
				nonce, _ := idt["nonce"].(string)
				accessToken, _ := idt["accessToken"].(string)
				refreshToken, _ := idt["refreshToken"].(string)
				verifier, _ := oauth2.AsIDTokenVerifier(p)
				valid, err := verifier.VerifyIDToken(ctx.Context(), token, nonce)
				if err != nil || !valid {
					a.Logger.Warn("Invalid id token", providerID)
					return nil, ErrFrom("UNAUTHORIZED", ErrInvalidToken)
				}
				tokens := &oauth2.Tokens{IDToken: token, AccessToken: accessToken, RefreshToken: refreshToken}
				info, err := p.GetUserInfo(ctx.Context(), oauth2.UserInfoParams{Tokens: *tokens})
				if err != nil || info == nil {
					a.Logger.Error("Failed to get user info", providerID)
					return nil, ErrFrom("UNAUTHORIZED", ErrFailedToGetUserInfo)
				}
				if info.User.Email == "" {
					return nil, ErrFrom("UNAUTHORIZED", ErrUserEmailNotFound)
				}
				accountID, err := ResolveAccountID(ctx, p, tokens, info.Data)
				if err != nil {
					return nil, err
				}
				linked, err := a.InternalAdapter.FindAccountByKey(ctx.Context(), p.ID(), accountID)
				if err != nil {
					return nil, err
				}
				encAccess, err := a.SetTokenUtil(accessToken)
				if err != nil {
					return nil, err
				}
				encRefresh, err := a.SetTokenUtil(refreshToken)
				if err != nil {
					return nil, err
				}
				if linked != nil && linked.UserID == session.User.ID {
					upd := adapter.Record{"providerId": p.ID(), "idToken": token}
					if encAccess != nil {
						upd["accessToken"] = encAccess
					}
					if encRefresh != nil {
						upd["refreshToken"] = encRefresh
					}
					if _, err := a.InternalAdapter.UpdateAccount(ctx.Context(), linked.ID, upd); err != nil {
						return nil, err
					}
					ApplyUpdateUserInfoOnLink(ctx, session.User.ID, info.User)
					return jsonx.O("url", "", "status", true, "redirect", false), nil
				}
				if linked != nil {
					return nil, ErrFrom("CONFLICT", ErrSocialAccountAlreadyLinked)
				}
				trusted := false
				for _, t := range a.TrustedProviders {
					if t == p.ID() {
						trusted = true
					}
				}
				al := a.accountLinking()
				if (!trusted && !info.User.EmailVerified) || (al != nil && al.Enabled != nil && !*al.Enabled) {
					return nil, ErrFrom("UNAUTHORIZED", ErrorCode{Code: "LINKING_NOT_ALLOWED", Message: "Account not linked - linking not allowed"})
				}
				if !strings.EqualFold(info.User.Email, session.User.Email) && (al == nil || !al.AllowDifferentEmails) {
					return nil, ErrFrom("UNAUTHORIZED", ErrorCode{Code: "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED", Message: "Account not linked - different emails not allowed"})
				}
				rec := adapter.Record{"userId": session.User.ID, "providerId": p.ID(), "accountId": accountID, "idToken": token}
				if encAccess != nil {
					rec["accessToken"] = encAccess
				}
				if encRefresh != nil {
					rec["refreshToken"] = encRefresh
				}
				if _, err := a.InternalAdapter.CreateAccount(ctx.Context(), rec); err != nil {
					return nil, ErrFrom("EXPECTATION_FAILED", ErrorCode{Code: "LINKING_FAILED", Message: "Account not linked - unable to create account"})
				}
				ApplyUpdateUserInfoOnLink(ctx, session.User.ID, info.User)
				return jsonx.O("url", "", "status", true, "redirect", false), nil
			}
			nonce := GenerateIDTokenNonce(p)
			additional, _ := body["additionalData"].(map[string]any)
			state, verifier, err := GenerateState(ctx, &GenerateStateOptions{
				Link:           &StateLink{UserID: session.User.ID, Email: session.User.Email},
				AdditionalData: additional, IDTokenNonce: nonce,
			})
			if err != nil {
				return nil, err
			}
			u, err := p.CreateAuthorizationURL(ctx.Context(), oauth2.AuthorizationURLParams{
				State: state, CodeVerifier: verifier, IDTokenNonce: nonce,
				RedirectURI: a.BaseURL + oauth2.CallbackPath(p), Scopes: stringList(body["scopes"]),
				LoginHint: ctx.BodyString("loginHint"), AdditionalParams: stringMap(body["additionalParams"]),
				AdditionalParamsOrder: additionalParamsOrder(ctx),
			})
			if err != nil {
				return nil, err
			}
			redirect := true
			if b := ctx.BodyBool("disableRedirect"); b != nil && *b {
				redirect = false
			}
			if redirect {
				ctx.SetHeader("Location", u.String())
			}
			return jsonx.O("url", u.String(), "redirect", redirect), nil
		},
	}
}

func (a *AuthContext) accountLinking() *AccountLinkingConfig {
	if a.Options.Account == nil {
		return nil
	}
	return a.Options.Account.AccountLinking
}

func unlinkAccountEndpoint() *Endpoint {
	return &Endpoint{
		Key: "unlinkAccount", Path: "/unlink-account", Methods: []string{"POST"},
		Body: validate.Object(validate.F("accountId", validate.String())), Use: []Middleware{FreshSessionMiddleware},
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			accounts, err := a.InternalAdapter.FindAccounts(ctx.Context(), ctx.Session.User.ID)
			if err != nil {
				return nil, err
			}
			al := a.accountLinking()
			if len(accounts) == 1 && (al == nil || !al.AllowUnlinkingAll) {
				return nil, ErrFrom("BAD_REQUEST", ErrFailedToUnlinkLastAccount)
			}
			id := ctx.BodyString("accountId")
			for _, acc := range accounts {
				if acc.ID == id {
					if err := a.InternalAdapter.DeleteAccount(ctx.Context(), acc.ID); err != nil {
						return nil, err
					}
					return statusTrue(), nil
				}
			}
			return nil, ErrFrom("BAD_REQUEST", ErrAccountNotFound)
		},
	}
}

func resolveUserID(ctx *EndpointContext, userID string) (string, error) {
	s, err := GetSessionFromCtx(ctx, &GetSessionOptions{DisableCookieCache: ctx.Auth.stateful})
	if err != nil {
		return "", err
	}
	if s == nil && (ctx.Request != nil || ctx.Headers != nil) {
		return "", ErrStatus("UNAUTHORIZED")
	}
	if s != nil && s.User.ID != "" {
		return s.User.ID, nil
	}
	if userID == "" {
		return "", ErrFrom("BAD_REQUEST", ErrorCode{Code: "USER_ID_OR_SESSION_REQUIRED", Message: "Either userId or session is required"})
	}
	return userID, nil
}

var accountSelectionSchema = validate.Union(
	validate.StrictObject(validate.F("accountId", validate.String()), validate.F("userId", validate.Optional(validate.String()))),
	validate.StrictObject(validate.F("useAccountCookie", validate.Literal(true)), validate.F("userId", validate.Optional(validate.String()))),
)

type accountSelection struct {
	accountID        string
	useAccountCookie bool
	userID           string
}

func selectionFrom(m map[string]any) accountSelection {
	s := accountSelection{}
	s.accountID, _ = m["accountId"].(string)
	s.useAccountCookie, _ = m["useAccountCookie"].(bool)
	s.userID, _ = m["userId"].(string)
	return s
}

func matchesAccountSelection(ctx *EndpointContext, acc *Account, uid string, sel accountSelection) bool {
	matchesUser := ctx.Auth.Options.Database == nil || acc.UserID == uid
	return matchesUser && (sel.accountID == "" || acc.ID == sel.accountID)
}

func resolveUserAccount(ctx *EndpointContext, uid string, sel accountSelection) (*Account, *Account, error) {
	if sel.accountID != "" {
		accounts, err := ctx.Auth.InternalAdapter.FindAccounts(ctx.Context(), uid)
		if err != nil {
			return nil, nil, err
		}
		for _, acc := range accounts {
			if acc.ID == sel.accountID {
				return acc, nil, nil
			}
		}
	} else if ctx.Auth.storeAccountCookie() {
		if c := GetAccountCookie(ctx); c != nil && matchesAccountSelection(ctx, c, uid, sel) {
			return c, c, nil
		}
	}
	return nil, nil, ErrFrom("BAD_REQUEST", ErrAccountNotFound)
}

func timePtrOrUndefined(t *time.Time) any {
	if t == nil {
		return jsonx.Undefined
	}
	return *t
}

func getValidAccessToken(ctx *EndpointContext, uid string, sel accountSelection, acc *Account) (*jsonx.Object, error) {
	a := ctx.Auth
	if acc == nil {
		var err error
		acc, _, err = resolveUserAccount(ctx, uid, sel)
		if err != nil {
			return nil, err
		}
	}
	if !matchesAccountSelection(ctx, acc, uid, sel) {
		return nil, ErrFrom("BAD_REQUEST", ErrAccountNotFound)
	}
	p := a.FindProvider(acc.ProviderID)
	if p == nil {
		return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "PROVIDER_NOT_SUPPORTED", Message: "Provider " + acc.ProviderID + " is not supported."})
	}
	fail := ErrFrom("BAD_REQUEST", ErrorCode{Code: "FAILED_TO_GET_ACCESS_TOKEN", Message: "Failed to get a valid access token"})
	var newTokens *oauth2.Tokens
	expired := acc.AccessTokenExpiresAt != nil && time.Until(*acc.AccessTokenExpiresAt) < 5*time.Second
	refresher, canRefresh := oauth2.AsRefresher(p)
	if acc.RefreshToken != nil && *acc.RefreshToken != "" && expired && canRefresh {
		rt, err := a.DecryptOAuthToken(*acc.RefreshToken)
		if err != nil {
			return nil, fail
		}
		newTokens, err = refresher.RefreshAccessToken(ctx.Context(), rt, &oauth2.RefreshContext{Headers: ctx.Headers, Request: ctx.Request})
		if err != nil || newTokens == nil {
			return nil, fail
		}
		encAccess, err := a.SetTokenUtil(newTokens.AccessToken)
		if err != nil {
			return nil, fail
		}
		upd := adapter.Record{"accessToken": encAccess, "accessTokenExpiresAt": timeOrNil(newTokens.AccessTokenExpiresAt)}
		if newTokens.RefreshToken != "" {
			enc, err := a.SetTokenUtil(newTokens.RefreshToken)
			if err != nil {
				return nil, fail
			}
			upd["refreshToken"] = enc
		} else {
			upd["refreshToken"] = *acc.RefreshToken
		}
		if newTokens.RefreshTokenExpiresAt != nil {
			upd["refreshTokenExpiresAt"] = *newTokens.RefreshTokenExpiresAt
		} else {
			upd["refreshTokenExpiresAt"] = timeOrNil(acc.RefreshTokenExpiresAt)
		}
		if newTokens.IDToken != "" {
			upd["idToken"] = newTokens.IDToken
		} else {
			upd["idToken"] = strPtrVal(acc.IDToken)
		}
		var updated *Account
		if acc.ID != "" {
			updated, err = a.InternalAdapter.UpdateAccount(ctx.Context(), acc.ID, upd)
			if err != nil {
				return nil, fail
			}
		}
		if a.storeAccountCookie() {
			merged := updated
			if merged == nil {
				merged = AccountFromRecord(mergeRecord(acc.Record(), upd))
			}
			if err := SetAccountCookie(ctx, merged); err != nil {
				return nil, fail
			}
		}
	}
	var expiresAt *time.Time
	if newTokens != nil && newTokens.AccessTokenExpiresAt != nil {
		expiresAt = newTokens.AccessTokenExpiresAt
	} else if acc.AccessTokenExpiresAt != nil {
		expiresAt = acc.AccessTokenExpiresAt
	}
	accessToken := ""
	if newTokens != nil && newTokens.AccessToken != "" {
		accessToken = newTokens.AccessToken
	} else {
		raw := ""
		if acc.AccessToken != nil {
			raw = *acc.AccessToken
		}
		dec, err := a.DecryptOAuthToken(raw)
		if err != nil {
			return nil, fail
		}
		accessToken = dec
	}
	var idToken any = jsonx.Undefined
	if newTokens != nil && newTokens.IDToken != "" {
		idToken = newTokens.IDToken
	} else if acc.IDToken != nil {
		idToken = *acc.IDToken
	}
	return jsonx.O("accessToken", accessToken, "accessTokenExpiresAt", timePtrOrUndefined(expiresAt),
		"scopes", parseStoredScopes(acc.Scope), "idToken", idToken), nil
}

func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func getAccessTokenEndpoint() *Endpoint {
	return &Endpoint{
		Key: "getAccessToken", Path: "/get-access-token", Methods: []string{"POST"}, Body: accountSelectionSchema,
		Handler: func(ctx *EndpointContext) (any, error) {
			sel := selectionFrom(ctx.BodyMap())
			uid, err := resolveUserID(ctx, sel.userID)
			if err != nil {
				return nil, err
			}
			return getValidAccessToken(ctx, uid, sel, nil)
		},
	}
}

func refreshTokenEndpoint() *Endpoint {
	return &Endpoint{
		Key: "refreshToken", Path: "/refresh-token", Methods: []string{"POST"}, Body: accountSelectionSchema,
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			sel := selectionFrom(ctx.BodyMap())
			uid, err := resolveUserID(ctx, sel.userID)
			if err != nil {
				return nil, err
			}
			acc, cookieAcc, err := resolveUserAccount(ctx, uid, sel)
			if err != nil {
				return nil, err
			}
			p := a.FindProvider(acc.ProviderID)
			if p == nil {
				return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "PROVIDER_NOT_SUPPORTED", Message: "Provider " + acc.ProviderID + " is not supported."})
			}
			refresher, ok := oauth2.AsRefresher(p)
			if !ok {
				return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "TOKEN_REFRESH_NOT_SUPPORTED", Message: "Provider " + acc.ProviderID + " does not support token refreshing."})
			}
			if acc.RefreshToken == nil || *acc.RefreshToken == "" {
				return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "REFRESH_TOKEN_NOT_FOUND", Message: "Refresh token not found"})
			}
			fail := ErrFrom("BAD_REQUEST", ErrorCode{Code: "FAILED_TO_REFRESH_ACCESS_TOKEN", Message: "Failed to refresh access token"})
			rt, err := a.DecryptOAuthToken(*acc.RefreshToken)
			if err != nil {
				return nil, fail
			}
			tokens, err := refresher.RefreshAccessToken(ctx.Context(), rt, &oauth2.RefreshContext{Headers: ctx.Headers, Request: ctx.Request})
			if err != nil || tokens == nil {
				return nil, fail
			}
			var resolvedRefresh any = *acc.RefreshToken
			if tokens.RefreshToken != "" {
				if resolvedRefresh, err = a.SetTokenUtil(tokens.RefreshToken); err != nil {
					return nil, fail
				}
			}
			resolvedRefreshExp := acc.RefreshTokenExpiresAt
			if tokens.RefreshTokenExpiresAt != nil {
				resolvedRefreshExp = tokens.RefreshTokenExpiresAt
			}
			encAccess, err := a.SetTokenUtil(tokens.AccessToken)
			if err != nil {
				return nil, fail
			}
			idToken := strPtrVal(acc.IDToken)
			if tokens.IDToken != "" {
				idToken = tokens.IDToken
			}
			upd := adapter.Record{"accessToken": encAccess, "refreshToken": resolvedRefresh,
				"accessTokenExpiresAt": timeOrNil(tokens.AccessTokenExpiresAt), "refreshTokenExpiresAt": timeOrNil(resolvedRefreshExp), "idToken": idToken}
			var updated *Account
			if acc.ID != "" {
				if updated, err = a.InternalAdapter.UpdateAccount(ctx.Context(), acc.ID, upd); err != nil {
					return nil, fail
				}
			}
			if cookieAcc != nil && cookieAcc.ID == acc.ID && a.storeAccountCookie() {
				merged := updated
				if merged == nil {
					merged = AccountFromRecord(mergeRecord(cookieAcc.Record(), upd))
				}
				if err := SetAccountCookie(ctx, merged); err != nil {
					return nil, fail
				}
			}
			scope := acc.Scope
			if updated != nil && updated.Scope != nil {
				scope = updated.Scope
			}
			refreshOut := tokens.RefreshToken
			if refreshOut == "" {
				refreshOut = rt
			}
			var scopeOut any = jsonx.Undefined
			if scope != nil {
				scopeOut = *scope
			}
			return jsonx.O("accessToken", tokens.AccessToken, "refreshToken", refreshOut,
				"accessTokenExpiresAt", timePtrOrUndefined(tokens.AccessTokenExpiresAt),
				"refreshTokenExpiresAt", timePtrOrUndefined(resolvedRefreshExp), "scope", scopeOut,
				"idToken", nilToUndefined(idToken), "providerId", acc.ProviderID, "accountId", acc.ID), nil
		},
	}
}

func nilToUndefined(v any) any {
	if v == nil || v == "" {
		return jsonx.Undefined
	}
	return v
}

func accountInfoEndpoint() *Endpoint {
	return &Endpoint{
		Key: "accountInfo", Path: "/account-info", Methods: []string{"GET"}, Query: accountSelectionSchema,
		Handler: func(ctx *EndpointContext) (any, error) {
			a := ctx.Auth
			sel := selectionFrom(ctx.Query)
			uid, err := resolveUserID(ctx, sel.userID)
			if err != nil {
				return nil, err
			}
			acc, _, err := resolveUserAccount(ctx, uid, sel)
			if err != nil {
				return nil, err
			}
			p := a.FindProvider(acc.ProviderID)
			if p == nil {
				return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "PROVIDER_NOT_CONFIGURED", Message: "Account is not associated with a configured social provider."})
			}
			tokens, err := getValidAccessToken(ctx, uid, sel, acc)
			if err != nil {
				return nil, err
			}
			at, _ := tokens.Get("accessToken")
			accessToken, _ := at.(string)
			if accessToken == "" {
				return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "ACCESS_TOKEN_NOT_FOUND", Message: "Access token not found"})
			}
			t := oauth2.Tokens{AccessToken: accessToken}
			if v, ok := tokens.Get("idToken"); ok {
				t.IDToken, _ = v.(string)
			}
			if v, ok := tokens.Get("accessTokenExpiresAt"); ok {
				if tm, ok := v.(time.Time); ok {
					t.AccessTokenExpiresAt = &tm
				}
			}
			info, err := p.GetUserInfo(ctx.Context(), oauth2.UserInfoParams{Tokens: t})
			if err != nil || info == nil {
				return nil, ErrFrom("UNAUTHORIZED", ErrFailedToGetUserInfo)
			}
			return jsonx.O("user", userInfoObject(info.User), "data", info.Data,
				"account", jsonx.O("id", acc.ID, "providerId", acc.ProviderID, "accountId", acc.AccountID)), nil
		},
	}
}

func userInfoObject(u oauth2.UserInfo) *jsonx.Object {
	o := jsonx.NewObject()
	if u.Name != "" {
		o.Set("name", u.Name)
	}
	if u.Email != "" {
		o.Set("email", u.Email)
	}
	if u.Image != "" {
		o.Set("image", u.Image)
	}
	o.Set("emailVerified", u.EmailVerified)
	for k, v := range u.Extra {
		o.Set(k, v)
	}
	return o
}

var errNoProvider = errors.New("provider not found")
