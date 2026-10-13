package betterauth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/validate"
)

func assertPasswordNotTooShort(ctx *EndpointContext, pw string) error {
	if jsLen(pw) < ctx.Auth.Password.MinLength {
		ctx.Auth.Logger.Warn("Password is too short")
		return ErrFrom("BAD_REQUEST", ErrPasswordTooShort)
	}
	return nil
}

func assertPasswordNotTooLong(ctx *EndpointContext, pw string) error {
	if jsLen(pw) > ctx.Auth.Password.MaxLength {
		ctx.Auth.Logger.Warn("Password is too long")
		return ErrFrom("BAD_REQUEST", ErrPasswordTooLong)
	}
	return nil
}

func jsLen(s string) int { return jsonx.EncodeUTF16Length(s) }

// CreateEmailVerificationToken signs an email verification JWT (createEmailVerificationToken).
func CreateEmailVerificationToken(secret, email, updateTo string, expiresIn time.Duration, extra *jsonx.Object) (string, error) {
	p := jsonx.O("email", strings.ToLower(email))
	if updateTo != "" {
		p.Set("updateTo", strings.ToLower(updateTo))
	}
	if extra != nil {
		for _, k := range extra.Keys() {
			v, _ := extra.Get(k)
			p.Set(k, v)
		}
	}
	if expiresIn == 0 {
		expiresIn = time.Hour
	}
	return bacrypto.SignJWT(p, secret, expiresIn)
}

func (a *AuthContext) verificationExpiresIn() time.Duration {
	if ev := a.Options.EmailVerification; ev != nil && ev.ExpiresIn > 0 {
		return ev.ExpiresIn
	}
	return time.Hour
}

var signUpBody = validate.And(validate.Object(
	validate.F("name", validate.String()),
	validate.F("email", validate.Email()),
	validate.F("password", validate.String().NonEmpty()),
	validate.F("image", validate.Optional(validate.String())),
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("rememberMe", validate.Optional(validate.Boolean())),
), validate.Record(validate.Any()))

func signUpEmailEndpoint() *Endpoint {
	return &Endpoint{
		Key: "signUpEmail", Path: "/sign-up/email", Methods: []string{"POST"}, OperationID: "signUpWithEmailAndPassword",
		Use: []Middleware{FormCSRFMiddleware}, Body: signUpBody,
		AllowedMediaTypes: []string{"application/x-www-form-urlencoded", "application/json"},
		Handler: func(ctx *EndpointContext) (any, error) {
			var out any
			err := ctx.Transaction(func() error {
				var err error
				out, err = signUpEmail(ctx)
				return err
			})
			return out, err
		},
	}
}

func signUpEmail(ctx *EndpointContext) (any, error) {
	a := ctx.Auth
	ep := a.Options.EmailAndPassword
	if ep == nil || !ep.Enabled || ep.DisableSignUp {
		return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "EMAIL_PASSWORD_SIGN_UP_DISABLED", Message: "Email and password sign up is not enabled"})
	}
	body := ctx.BodyMap()
	name, _ := body["name"].(string)
	email, _ := body["email"].(string)
	password, pwOK := body["password"].(string)
	var image any
	if v, ok := body["image"]; ok {
		image = v
	}
	rest := map[string]any{}
	for k, v := range body {
		switch k {
		case "name", "email", "password", "image", "callbackURL", "rememberMe":
		default:
			rest[k] = v
		}
	}
	if !validate.IsEmail(email) {
		return nil, ErrFrom("BAD_REQUEST", ErrInvalidEmail)
	}
	if !pwOK || password == "" {
		return nil, ErrFrom("BAD_REQUEST", ErrInvalidPassword)
	}
	if err := assertPasswordNotTooShort(ctx, password); err != nil {
		return nil, err
	}
	if err := assertPasswordNotTooLong(ctx, password); err != nil {
		return nil, err
	}
	autoSignInDisabled := ep.AutoSignIn != nil && !*ep.AutoSignIn
	genericDuplicate := ep.RequireEmailVerification || autoSignInDisabled
	skipAutoSignIn := autoSignInDisabled || genericDuplicate
	additional, err := a.ParseUserInput(rest, "create")
	if err != nil {
		return nil, err
	}
	normalized := strings.ToLower(email)
	rememberMe := ctx.BodyBool("rememberMe")
	dontRemember := rememberMe != nil && !*rememberMe

	syntheticResponse := func() any {
		now := time.Now()
		id, ok := a.GenerateID("user")
		if !ok || id == "" {
			id = bacrypto.GenerateID()
		}
		var img any = image
		if img == nil {
			img = nil
		}
		core := map[string]any{"name": name, "email": normalized, "emailVerified": false, "image": img, "createdAt": now, "updatedAt": now}
		var synthetic *jsonx.Object
		if ep.CustomSyntheticUser != nil {
			addl := map[string]any{}
			if a.Options.User != nil {
				for _, f := range a.Options.User.AdditionalFields {
					if v, ok := additional[f.Name]; ok {
						addl[f.Name] = v
					}
				}
			}
			synthetic = a.buildSyntheticUserOutput(ep.CustomSyntheticUser(SyntheticUserParams{CoreFields: core, AdditionalFields: addl, ID: id}))
		} else {
			data := map[string]any{}
			for k, v := range core {
				data[k] = v
			}
			for k, v := range additional {
				data[k] = v
			}
			data["id"] = id
			synthetic = a.buildSyntheticUserOutput(data)
		}
		hidden := a.outputHidden("user")
		for k := range hidden {
			synthetic.Delete(k)
		}
		return jsonx.O("token", nil, "user", synthetic)
	}

	existing, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), normalized, false)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		a.Logger.Info("Sign-up attempt for existing email: " + email)
		if genericDuplicate {
			if _, err := a.Password.Hash(password); err != nil {
				return nil, err
			}
			if ep.OnExistingUserSignUp != nil {
				u := existing.User
				a.RunInBackgroundOrAwait(func() error { return ep.OnExistingUserSignUp(context.WithoutCancel(ctx.Context()), u, ctx.Request) })
			}
			return syntheticResponse(), nil
		}
		return nil, ErrFrom("UNPROCESSABLE_ENTITY", ErrUserAlreadyExistsUseAnotherEmail)
	}
	hash, err := a.Password.Hash(password)
	if err != nil {
		return nil, err
	}
	// Always write image (null when omitted) so the real user's JSON is shaped exactly like
	// the synthetic duplicate-sign-up response (no account enumeration via key presence).
	data := adapter.Record{"email": normalized, "name": name, "image": image}
	for k, v := range additional {
		data[k] = v
	}
	data["emailVerified"] = false
	created, err := a.InternalAdapter.CreateUser(ctx.Context(), data, UserInfoSource{Method: "email-password"})
	if err != nil {
		var e *APIError
		if errors.As(err, &e) {
			if e.StatusCode == 403 && genericDuplicate {
				return syntheticResponse(), nil
			}
			return nil, err
		}
		a.Logger.Error("Failed to create user", err)
		return nil, ErrFrom("UNPROCESSABLE_ENTITY", ErrFailedToCreateUser)
	}
	if created == nil {
		return nil, ErrFrom("UNPROCESSABLE_ENTITY", ErrFailedToCreateUser)
	}
	if _, err := a.InternalAdapter.LinkAccount(ctx.Context(), adapter.Record{
		"userId": created.ID, "providerId": "credential", "accountId": created.ID, "password": hash,
	}); err != nil {
		return nil, err
	}
	shouldSend := ep.RequireEmailVerification
	if ev := a.Options.EmailVerification; ev != nil && ev.SendOnSignUp != nil {
		shouldSend = *ev.SendOnSignUp
	}
	if shouldSend {
		token, err := CreateEmailVerificationToken(a.Secret, created.Email, "", a.verificationExpiresIn(), nil)
		if err != nil {
			return nil, err
		}
		cb := "/"
		if v, ok := body["callbackURL"].(string); ok && v != "" {
			cb = v
		}
		u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + EncodeURIComponent(cb)
		if ev := a.Options.EmailVerification; ev != nil && ev.SendVerificationEmail != nil {
			user := created
			a.RunInBackgroundOrAwait(func() error {
				return ev.SendVerificationEmail(context.WithoutCancel(ctx.Context()), EmailData{User: user, URL: u, Token: token}, ctx.Request)
			})
		}
	}
	if skipAutoSignIn {
		return jsonx.O("token", nil, "user", a.UserOutput(created)), nil
	}
	session, err := a.InternalAdapter.CreateSession(ctx.Context(), created.ID, &CreateSessionOptions{DontRememberMe: dontRemember})
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrFrom("BAD_REQUEST", ErrFailedToCreateSession)
	}
	if err := SetSessionCookie(ctx, &SessionWithUser{Session: session, User: created}, Bool(dontRemember), nil); err != nil {
		return nil, err
	}
	return jsonx.O("token", session.Token, "user", a.UserOutput(created)), nil
}

var signInEmailBody = validate.Object(
	validate.F("email", validate.String()),
	validate.F("password", validate.String()),
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("rememberMe", validate.Default(validate.Boolean(), true)),
)

func signInEmailEndpoint() *Endpoint {
	return &Endpoint{
		Key: "signInEmail", Path: "/sign-in/email", Methods: []string{"POST"}, OperationID: "signInEmail",
		Use: []Middleware{FormCSRFMiddleware}, Body: signInEmailBody,
		AllowedMediaTypes: []string{"application/x-www-form-urlencoded", "application/json"},
		Handler:           signInEmail,
	}
}

func signInEmail(ctx *EndpointContext) (any, error) {
	a := ctx.Auth
	if ep := a.Options.EmailAndPassword; ep == nil || !ep.Enabled {
		a.Logger.Error("Email and password is not enabled. Make sure to enable it in the options on you `auth.ts` file. Check `https://better-auth.com/docs/authentication/email-password` for more!")
		return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "EMAIL_PASSWORD_DISABLED", Message: "Email and password is not enabled"})
	}
	email := ctx.BodyString("email")
	password := ctx.BodyString("password")
	if !validate.IsEmail(email) {
		return nil, ErrFrom("BAD_REQUEST", ErrInvalidEmail)
	}
	if err := assertPasswordNotTooLong(ctx, password); err != nil {
		return nil, err
	}
	rec, err := a.InternalAdapter.FindUserByEmail(ctx.Context(), strings.ToLower(email), true)
	if err != nil {
		return nil, err
	}
	var cred *Account
	if rec != nil {
		for _, acc := range rec.Accounts {
			if acc.ProviderID == "credential" && acc.AccountID == rec.User.ID {
				cred = acc
				break
			}
		}
	}
	if rec == nil || cred == nil {
		_, _ = a.Password.Hash(password)
		a.Logger.Warn("User not found")
		return nil, ErrFrom("UNAUTHORIZED", ErrInvalidEmailOrPassword)
	}
	user := rec.User
	if cred.Password == nil || *cred.Password == "" {
		_, _ = a.Password.Hash(password)
		a.Logger.Warn("Password not found")
		return nil, ErrFrom("UNAUTHORIZED", ErrInvalidEmailOrPassword)
	}
	ok, err := a.Password.Verify(*cred.Password, password)
	if err != nil || !ok {
		a.Logger.Warn("Invalid password")
		return nil, ErrFrom("UNAUTHORIZED", ErrInvalidEmailOrPassword)
	}
	if a.Options.EmailAndPassword.RequireEmailVerification && !user.EmailVerified {
		ev := a.Options.EmailVerification
		if ev == nil || ev.SendVerificationEmail == nil {
			return nil, ErrFrom("FORBIDDEN", ErrEmailNotVerified)
		}
		if ev.SendOnSignIn {
			token, err := CreateEmailVerificationToken(a.Secret, user.Email, "", a.verificationExpiresIn(), nil)
			if err != nil {
				return nil, err
			}
			cb := "/"
			if v := ctx.BodyString("callbackURL"); v != "" {
				cb = v
			}
			u := a.BaseURL + "/verify-email?token=" + token + "&callbackURL=" + EncodeURIComponent(cb)
			a.RunInBackgroundOrAwait(func() error {
				return ev.SendVerificationEmail(context.WithoutCancel(ctx.Context()), EmailData{User: user, URL: u, Token: token}, ctx.Request)
			})
		}
		return nil, ErrFrom("FORBIDDEN", ErrEmailNotVerified)
	}
	rememberMe := ctx.BodyBool("rememberMe")
	dontRemember := rememberMe != nil && !*rememberMe
	session, err := a.InternalAdapter.CreateSession(ctx.Context(), user.ID, &CreateSessionOptions{DontRememberMe: dontRemember})
	if err != nil {
		return nil, err
	}
	if session == nil {
		a.Logger.Error("Failed to create session")
		return nil, ErrFrom("UNAUTHORIZED", ErrFailedToCreateSession)
	}
	if err := SetSessionCookie(ctx, &SessionWithUser{Session: session, User: user}, Bool(dontRemember), nil); err != nil {
		return nil, err
	}
	cb := ctx.BodyString("callbackURL")
	if cb != "" {
		ctx.SetHeader("Location", cb)
	}
	var urlVal any = jsonx.Undefined
	if cb != "" {
		urlVal = cb
	}
	return jsonx.O("redirect", cb != "", "token", session.Token, "url", urlVal, "user", a.UserOutput(user)), nil
}

var signOutBody = validate.Optional(validate.Object(
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("disableRedirect", validate.Optional(validate.Boolean())),
	validate.F("state", validate.Optional(validate.String())),
))

func signOutEndpoint() *Endpoint {
	return &Endpoint{
		Key: "signOut", Path: "/sign-out", Methods: []string{"POST"}, OperationID: "signOut",
		Body: signOutBody, RequireHeaders: true, Handler: signOut,
	}
}

func signOut(ctx *EndpointContext) (any, error) {
	a := ctx.Auth
	token, has := ctx.GetSignedCookie(a.AuthCookies.SessionToken.Name, a.Secret)
	var current *SessionWithUser
	if has {
		s, err := a.InternalAdapter.FindSession(ctx.Context(), token)
		if err != nil {
			a.Logger.Error("Failed to read session from database", err)
		}
		current = s
		if err := a.InternalAdapter.DeleteSession(ctx.Context(), token); err != nil {
			a.Logger.Error("Failed to delete session from database", err)
		}
	}
	DeleteSessionCookie(ctx, false)
	logoutURL := providerLogoutURL(ctx, current)
	if logoutURL != "" {
		redirect := true
		if b := ctx.BodyBool("disableRedirect"); b != nil && *b {
			redirect = false
		}
		if redirect {
			ctx.SetHeader("Location", logoutURL)
		}
		return jsonx.O("success", true, "url", logoutURL, "redirect", redirect), nil
	}
	return jsonx.O("success", true), nil
}

func providerLogoutURL(ctx *EndpointContext, current *SessionWithUser) string {
	a := ctx.Auth
	if current == nil {
		return ""
	}
	accounts, err := a.InternalAdapter.FindAccounts(ctx.Context(), current.User.ID)
	if err != nil {
		a.Logger.Error("Failed to create provider logout URL", err)
		return ""
	}
	byID := map[string]oauth2.Provider{}
	for _, p := range a.SocialProviders {
		byID[p.ID()] = p
	}
	var logout []*Account
	for _, acc := range accounts {
		if p, ok := byID[acc.ProviderID]; ok {
			if _, ok := oauth2.AsEndSessioner(p); ok {
				logout = append(logout, acc)
			}
		}
	}
	if len(logout) == 0 {
		return ""
	}
	for i := 1; i < len(logout); i++ {
		for j := i; j > 0 && logout[j].UpdatedAt.After(logout[j-1].UpdatedAt); j-- {
			logout[j], logout[j-1] = logout[j-1], logout[j]
		}
	}
	postLogout := ""
	if cb := ctx.BodyString("callbackURL"); cb != "" {
		if r, err := resolveURL(cb, a.BaseURL); err == nil {
			postLogout = r
		}
	}
	seen := map[string]bool{}
	for _, acc := range logout {
		if seen[acc.ProviderID] {
			continue
		}
		seen[acc.ProviderID] = true
		es, _ := oauth2.AsEndSessioner(byID[acc.ProviderID])
		idToken := ""
		if acc.IDToken != nil {
			idToken = *acc.IDToken
		}
		u, err := es.CreateEndSessionURL(ctx.Context(), oauth2.EndSessionParams{IDToken: idToken, PostLogoutRedirectURI: postLogout, State: ctx.BodyString("state")})
		if err != nil {
			a.Logger.Error("Failed to create logout URL for provider \""+acc.ProviderID+"\"", err)
			continue
		}
		if u != nil {
			return u.String()
		}
	}
	return ""
}
