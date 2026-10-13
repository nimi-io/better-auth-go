package betterauth

import (
	"errors"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/validate"
)

var socialSignInBody = validate.Object(
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("newUserCallbackURL", validate.Optional(validate.String())),
	validate.F("errorCallbackURL", validate.Optional(validate.String())),
	validate.F("provider", validate.String()),
	validate.F("disableRedirect", validate.Optional(validate.Boolean())),
	validate.F("idToken", validate.Optional(validate.Object(
		validate.F("token", validate.String()),
		validate.F("nonce", validate.Optional(validate.String())),
		validate.F("accessToken", validate.Optional(validate.String())),
		validate.F("refreshToken", validate.Optional(validate.String())),
		validate.F("expiresAt", validate.Optional(validate.Number())),
		validate.F("user", validate.Optional(validate.Object(
			validate.F("name", validate.Optional(validate.Object(
				validate.F("firstName", validate.Optional(validate.String())),
				validate.F("lastName", validate.Optional(validate.String())),
			))),
			validate.F("email", validate.Optional(validate.String())),
		))),
	))),
	validate.F("scopes", validate.Optional(validate.Array(validate.String()))),
	validate.F("requestSignUp", validate.Optional(validate.Boolean())),
	validate.F("loginHint", validate.Optional(validate.String())),
	validate.F("additionalParams", additionalParamsSchema),
	validate.F("additionalData", validate.Optional(validate.Record(validate.Any()))),
)

func appleUserFrom(v any) *struct {
	Name  *oauth2.AppleUserName
	Email string
} {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := &struct {
		Name  *oauth2.AppleUserName
		Email string
	}{}
	out.Email, _ = m["email"].(string)
	if n, ok := m["name"].(map[string]any); ok {
		out.Name = &oauth2.AppleUserName{}
		out.Name.FirstName, _ = n["firstName"].(string)
		out.Name.LastName, _ = n["lastName"].(string)
	}
	return out
}

func disableSignUpFor(p oauth2.Provider, requestSignUp bool) bool {
	s := oauth2.SettingsOf(p)
	return (s.DisableImplicitSignUp && !requestSignUp) || s.DisableSignUp
}

func signInSocialEndpoint() *Endpoint {
	return &Endpoint{
		Key: "signInSocial", Path: "/sign-in/social", Methods: []string{"POST"}, OperationID: "socialSignIn",
		Body: socialSignInBody, Handler: signInSocial,
	}
}

func signInSocial(ctx *EndpointContext) (any, error) {
	a := ctx.Auth
	body := ctx.BodyMap()
	providerID := ctx.BodyString("provider")
	p := a.FindProvider(providerID)
	if p == nil {
		a.Logger.Error("Provider not found. Make sure to add the provider in your auth config", providerID)
		return nil, ErrFrom("NOT_FOUND", ErrProviderNotFound)
	}
	requestSignUp := false
	if b := ctx.BodyBool("requestSignUp"); b != nil {
		requestSignUp = *b
	}
	if idt, ok := body["idToken"].(map[string]any); ok {
		verifier, ok := oauth2.AsIDTokenVerifier(p)
		if !ok {
			a.Logger.Error("Provider does not support id token verification", providerID)
			return nil, ErrFrom("NOT_FOUND", ErrIDTokenNotSupported)
		}
		token, _ := idt["token"].(string)
		nonce, _ := idt["nonce"].(string)
		valid, err := verifier.VerifyIDToken(ctx.Context(), token, nonce)
		if err != nil || !valid {
			a.Logger.Warn("Invalid id token", providerID)
			return nil, ErrFrom("UNAUTHORIZED", ErrInvalidToken)
		}
		accessToken, _ := idt["accessToken"].(string)
		refreshToken, _ := idt["refreshToken"].(string)
		tokens := oauth2.Tokens{IDToken: token, AccessToken: accessToken, RefreshToken: refreshToken}
		info, err := p.GetUserInfo(ctx.Context(), oauth2.UserInfoParams{Tokens: tokens, User: appleUserFrom(idt["user"])})
		if err != nil || info == nil {
			a.Logger.Error("Failed to get user info", providerID)
			return nil, ErrFrom("UNAUTHORIZED", ErrFailedToGetUserInfo)
		}
		if info.User.Email == "" {
			a.Logger.Error(missingEmailLogMessage(providerID, "id_token"))
			return nil, ErrFrom("UNAUTHORIZED", ErrUserEmailNotFound)
		}
		accountID, err := ResolveAccountID(ctx, p, &tokens, info.Data)
		if err != nil {
			return nil, err
		}
		acc := OAuthAccountData{ProviderID: p.ID(), AccountID: accountID, AccessToken: accessToken, IDToken: token}
		res, err := HandleOAuthUserInfo(ctx, HandleOAuthUserInfoOptions{
			UserInfo: info.User, Account: acc, CallbackURL: ctx.BodyString("callbackURL"),
			DisableSignUp: disableSignUpFor(p, requestSignUp),
			Source:        UserInfoSource{Method: "oauth", ProviderID: p.ID(), Profile: info.Data},
		})
		if err != nil {
			return nil, err
		}
		if res.Error != "" {
			if res.Error == OAuthErrEmailNotVerified {
				return nil, ErrFrom("FORBIDDEN", ErrEmailNotVerified)
			}
			return nil, ErrFrom("UNAUTHORIZED", ErrorCode{Code: "OAUTH_LINK_ERROR", Message: res.Error})
		}
		if err := SetSessionCookie(ctx, res.Data, nil, nil); err != nil {
			return nil, err
		}
		return jsonx.O("redirect", false, "token", res.Data.Session.Token, "url", jsonx.Undefined,
			"user", a.UserOutput(res.Data.User)), nil
	}
	nonce := GenerateIDTokenNonce(p)
	additional, _ := body["additionalData"].(map[string]any)
	state, verifier, err := GenerateState(ctx, &GenerateStateOptions{AdditionalData: additional, IDTokenNonce: nonce})
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
}

var callbackSchema = validate.Object(
	validate.F("code", validate.Optional(validate.String())),
	validate.F("error", validate.Optional(validate.String())),
	validate.F("device_id", validate.Optional(validate.String())),
	validate.F("error_description", validate.Optional(validate.String())),
	validate.F("state", validate.Optional(validate.String())),
	validate.F("user", validate.Optional(validate.String())),
	validate.F("iss", validate.Optional(validate.String())),
)

var callbackKeys = []string{"code", "error", "device_id", "error_description", "state", "user", "iss"}

func callbackEndpoint() *Endpoint {
	return &Endpoint{
		Key: "callbackOAuth", Path: "/callback/:id", Methods: []string{"GET", "POST"}, OperationID: "handleOAuthCallback",
		Body: validate.Optional(callbackSchema), Query: validate.Optional(callbackSchema),
		AllowedMediaTypes: []string{"application/x-www-form-urlencoded", "application/json"},
		Handler:           callbackOAuth,
	}
}

func (a *AuthContext) defaultErrorURL() string {
	if a.Options.OnAPIError != nil && a.Options.OnAPIError.ErrorURL != "" {
		return a.Options.OnAPIError.ErrorURL
	}
	return a.BaseURL + "/error"
}

func errorRedirect(ctx *EndpointContext, base, code, description string) error {
	params := url.Values{"error": {code}}
	order := []string{"error"}
	if description != "" {
		params.Set("error_description", description)
		order = append(order, "error_description")
	}
	u, err := appendQueryParams(base, params, order)
	if err != nil {
		return err
	}
	return ctx.Redirect(u)
}

func callbackOAuth(ctx *EndpointContext) (any, error) {
	a := ctx.Auth
	defaultErrorURL := a.defaultErrorURL()
	if ctx.Method == "POST" {
		merged := map[string]any{}
		for _, src := range []map[string]any{ctx.BodyMap(), ctx.Query} {
			for k, v := range src {
				merged[k] = v
			}
		}
		var order []string
		params := url.Values{}
		for _, k := range callbackKeys {
			if v, ok := merged[k].(string); ok {
				params.Set(k, v)
				order = append(order, k)
			}
		}
		return nil, ctx.Redirect(a.BaseURL + "/callback/" + ctx.Params["id"] + "?" + encodeSearchParams(params, order))
	}
	q := func(k string) string { return ctx.QueryString(k) }
	code, state, iss := q("code"), q("state"), q("iss")
	if state == "" && code != "" {
		if p := a.FindProvider(ctx.Params["id"]); p != nil && oauth2.SettingsOf(p).AllowIDPInitiated {
			nonce := GenerateIDTokenNonce(p)
			st, verifier, err := GenerateState(ctx, &GenerateStateOptions{IDTokenNonce: nonce})
			if err != nil {
				return nil, err
			}
			u, err := p.CreateAuthorizationURL(ctx.Context(), oauth2.AuthorizationURLParams{
				State: st, CodeVerifier: verifier, IDTokenNonce: nonce, RedirectURI: a.BaseURL + oauth2.CallbackPath(p)})
			if err != nil {
				return nil, err
			}
			return nil, ctx.Redirect(u.String())
		}
	}
	if state == "" {
		a.Logger.Error("State not found", q("error"))
		return nil, errorRedirect(ctx, defaultErrorURL, "state_not_found", "")
	}
	sd, err := ParseGenericState(ctx, state, "", nil)
	if err != nil {
		a.Logger.Error("Failed to parse state", err)
		code := "internal_server_error"
		target := defaultErrorURL
		var se *StateError
		if errors.As(err, &se) {
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
		sd.ErrorURL = defaultErrorURL
	}
	RequestStateSet(ctx.Context(), oauthStateKey{}, sd)
	fail := func(code, desc string) error { return errorRedirect(ctx, sd.ErrorURL, code, desc) }
	if e := q("error"); e != "" {
		return nil, fail(e, q("error_description"))
	}
	if code == "" {
		a.Logger.Warn("Code not found")
		return nil, fail(OAuthErrNoCode, "")
	}
	p := a.FindProvider(ctx.Params["id"])
	if p == nil {
		a.Logger.Warn("OAuth provider not found", ctx.Params["id"])
		return nil, fail(OAuthErrProviderNotFound, "")
	}
	settings := oauth2.SettingsOf(p)
	if iss != "" && settings.Issuer != "" && iss != settings.Issuer {
		a.Logger.Error("OAuth issuer mismatch")
		return nil, fail(OAuthErrIssuerMismatch, "")
	}
	if settings.RequiresIDTokenNonce && sd.IDTokenNonce == "" {
		a.Logger.Error("OAuth id_token nonce binding required but no expected nonce was found in state")
		return nil, fail(OAuthErrNonceBindingMissing, "")
	}
	tokens, err := p.ValidateAuthorizationCode(ctx.Context(), oauth2.CodeParams{
		Code: code, CodeVerifier: sd.CodeVerifier, DeviceID: q("device_id"), RedirectURI: a.BaseURL + oauth2.CallbackPath(p)})
	if err != nil {
		a.Logger.Error("", err)
		return nil, fail(OAuthErrInvalidCode, "")
	}
	if tokens == nil {
		return nil, fail(OAuthErrInvalidCode, "")
	}
	var user *struct {
		Name  *oauth2.AppleUserName
		Email string
	}
	if raw := q("user"); raw != "" {
		if v, err := jsonx.Parse([]byte(raw)); err == nil {
			if o, ok := v.(*jsonx.Object); ok {
				user = appleUserFrom(o.Map())
			}
		}
	}
	info, err := p.GetUserInfo(ctx.Context(), oauth2.UserInfoParams{Tokens: *tokens, ExpectedIDTokenNonce: sd.IDTokenNonce, User: user})
	if err != nil || info == nil {
		a.Logger.Error("Unable to get user info")
		return nil, fail(OAuthErrUnableToGetUserInfo, "")
	}
	accountID, err := ResolveOAuthAccountKey(ctx.Context(), p, tokens, info.Data)
	if err != nil {
		a.Logger.Error("Unable to derive provider account identity", map[string]any{"providerId": p.ID(), "error": err})
		return nil, fail(OAuthErrUnableToGetUserInfo, "")
	}
	if sd.CallbackURL == "" {
		a.Logger.Error("No callback URL found")
		return nil, fail(OAuthErrNoCallbackURL, "")
	}
	acc := AccountDataFromTokens(p.ID(), accountID, tokens)
	if sd.Link != nil {
		res, err := LinkOAuthAccount(ctx, *sd.Link, info.User, acc, info.Data, tokens.Scopes)
		if err != nil {
			return nil, err
		}
		if !res.Linked {
			return nil, fail(res.ErrorCode, res.ErrorMessage)
		}
		return nil, ctx.Redirect(sd.CallbackURL)
	}
	if info.User.Email == "" {
		a.Logger.Error(missingEmailLogMessage(p.ID(), ""))
		return nil, fail(OAuthErrEmailNotFound, "")
	}
	requestSignUp := sd.RequestSignUp != nil && *sd.RequestSignUp
	res, err := HandleOAuthUserInfo(ctx, HandleOAuthUserInfoOptions{
		UserInfo: info.User, Account: acc, CallbackURL: sd.CallbackURL,
		DisableSignUp:    disableSignUpFor(p, requestSignUp),
		OverrideUserInfo: settings.OverrideUserInfoOnSignIn,
		Source:           UserInfoSource{Method: "oauth", ProviderID: p.ID(), Profile: info.Data},
	})
	if err != nil {
		if e, ok := AsAPIError(err); ok && e.Code() != "" && !IsRedirect(err) {
			return nil, fail(e.Code(), e.Message())
		}
		return nil, err
	}
	if res.Error != "" {
		code := strings.Join(strings.Split(res.Error, " "), "_")
		a.Logger.Error(code)
		return nil, fail(code, "")
	}
	if err := SetSessionCookie(ctx, res.Data, nil, nil); err != nil {
		return nil, err
	}
	target := sd.CallbackURL
	if res.IsRegister && sd.NewUserURL != "" {
		target = sd.NewUserURL
	}
	return nil, ctx.Redirect(target)
}
