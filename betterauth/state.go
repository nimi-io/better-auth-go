package betterauth

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// StateLink is the account-linking part of the OAuth state.
type StateLink struct {
	Email  string
	UserID string
}

// StateData is the OAuth state persisted between sign-in and callback.
type StateData struct {
	CallbackURL   string
	CodeVerifier  string
	ErrorURL      string
	NewUserURL    string
	ExpiresAt     int64 // epoch ms
	OAuthState    string
	Link          *StateLink
	RequestSignUp *bool
	IDTokenNonce  string
	ServerContext map[string]any
	// Additional holds additionalData and unknown keys.
	Additional *jsonx.Object
}

func (s *StateData) toObject() *jsonx.Object {
	o := jsonx.NewObject()
	// Internal fields are always written from the typed fields below (upstream assigns them
	// after spreading additionalData), so a client cannot smuggle link, errorURL,
	// serverContext, ... through additionalData.
	if s.Additional != nil {
		for _, k := range s.Additional.Keys() {
			if internalStateKeys[k] {
				continue
			}
			v, _ := s.Additional.Get(k)
			o.Set(k, v)
		}
	}
	o.Set("callbackURL", s.CallbackURL)
	o.Set("codeVerifier", s.CodeVerifier)
	if s.ErrorURL != "" {
		o.Set("errorURL", s.ErrorURL)
	}
	if s.NewUserURL != "" {
		o.Set("newUserURL", s.NewUserURL)
	}
	if s.Link != nil {
		o.Set("link", jsonx.O("userId", s.Link.UserID, "email", s.Link.Email))
	}
	if len(s.ServerContext) > 0 {
		o.Set("serverContext", s.ServerContext)
	}
	o.Set("expiresAt", float64(s.ExpiresAt))
	if s.RequestSignUp != nil {
		o.Set("requestSignUp", *s.RequestSignUp)
	}
	if s.IDTokenNonce != "" {
		o.Set("idTokenNonce", s.IDTokenNonce)
	}
	if s.OAuthState != "" {
		o.Set("oauthState", s.OAuthState)
	}
	return o
}

var internalStateKeys = map[string]bool{"callbackURL": true, "codeVerifier": true, "errorURL": true,
	"newUserURL": true, "expiresAt": true, "oauthState": true, "link": true, "requestSignUp": true,
	"idTokenNonce": true, "serverContext": true}

// parseStateData validates stored state (stateDataSchema).
func parseStateData(raw string) (*StateData, error) {
	v, err := jsonx.Parse([]byte(raw))
	if err != nil {
		return nil, err
	}
	o, ok := v.(*jsonx.Object)
	if !ok {
		return nil, errors.New("state is not an object")
	}
	s := &StateData{Additional: jsonx.NewObject()}
	getStr := func(k string, required bool) (string, error) {
		x, ok := o.Get(k)
		if !ok {
			if required {
				return "", errors.New(k + " is required")
			}
			return "", nil
		}
		str, ok := x.(string)
		if !ok {
			return "", errors.New(k + " must be a string")
		}
		return str, nil
	}
	if s.CallbackURL, err = getStr("callbackURL", true); err != nil {
		return nil, err
	}
	if s.CodeVerifier, err = getStr("codeVerifier", true); err != nil {
		return nil, err
	}
	if s.ErrorURL, err = getStr("errorURL", false); err != nil {
		return nil, err
	}
	if s.NewUserURL, err = getStr("newUserURL", false); err != nil {
		return nil, err
	}
	if s.OAuthState, err = getStr("oauthState", false); err != nil {
		return nil, err
	}
	if s.IDTokenNonce, err = getStr("idTokenNonce", false); err != nil {
		return nil, err
	}
	exp, ok := o.Get("expiresAt")
	ef, isNum := exp.(float64)
	if !ok || !isNum {
		return nil, errors.New("expiresAt must be a number")
	}
	s.ExpiresAt = int64(ef)
	if l, ok := o.Get("link"); ok {
		lo, ok := l.(*jsonx.Object)
		if !ok {
			return nil, errors.New("invalid link")
		}
		e, _ := lo.Get("email")
		u, _ := lo.Get("userId")
		es, ok := e.(string)
		if !ok || u == nil {
			return nil, errors.New("invalid link")
		}
		s.Link = &StateLink{Email: es, UserID: str(u)}
	}
	if r, ok := o.Get("requestSignUp"); ok {
		b, ok := r.(bool)
		if !ok {
			return nil, errors.New("invalid requestSignUp")
		}
		s.RequestSignUp = &b
	}
	if sc, ok := o.Get("serverContext"); ok {
		so, ok := sc.(*jsonx.Object)
		if !ok {
			return nil, errors.New("invalid serverContext")
		}
		s.ServerContext = so.Map()
	}
	for _, k := range o.Keys() {
		if !internalStateKeys[k] {
			v, _ := o.Get(k)
			s.Additional.Set(k, v)
		}
	}
	return s, nil
}

// StateError is returned when OAuth state validation fails.
type StateError struct {
	Code     string
	Message  string
	ErrorURL string
}

func (e *StateError) Error() string { return e.Message }

type oauthStateKey struct{}
type oauthServerContextKey struct{}

// GetOAuthState returns the OAuth state parsed for the current request (getOAuthState).
func GetOAuthState(ctx context.Context) *StateData {
	v, _ := RequestStateGet(ctx, oauthStateKey{})
	s, _ := v.(*StateData)
	return s
}

// AddOAuthServerContext stores server-only values to be persisted with the OAuth state.
func AddOAuthServerContext(ctx context.Context, values map[string]any) {
	cur, _ := RequestStateGet(ctx, oauthServerContextKey{})
	m, _ := cur.(map[string]any)
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for k, v := range values {
		out[k] = v
	}
	RequestStateSet(ctx, oauthServerContextKey{}, out)
}

// GenerateStateOptions customise GenerateState.
type GenerateStateOptions struct {
	Link           *StateLink
	AdditionalData map[string]any
	CodeVerifier   string
	IDTokenNonce   string
}

// GenerateState creates and persists OAuth state (generateState).
func GenerateState(ctx *EndpointContext, o *GenerateStateOptions) (state, codeVerifier string, err error) {
	if o == nil {
		o = &GenerateStateOptions{}
	}
	a := ctx.Auth
	callbackURL := ctx.BodyString("callbackURL")
	if callbackURL == "" {
		callbackURL = a.Options.BaseURL
	}
	if callbackURL == "" {
		return "", "", ErrFrom("BAD_REQUEST", ErrCallbackURLRequired)
	}
	codeVerifier = o.CodeVerifier
	if codeVerifier == "" {
		codeVerifier = bacrypto.RandomString(128)
	}
	sd := &StateData{
		CallbackURL: callbackURL, CodeVerifier: codeVerifier, ErrorURL: ctx.BodyString("errorCallbackURL"),
		NewUserURL: ctx.BodyString("newUserCallbackURL"), Link: o.Link,
		ExpiresAt: time.Now().Add(10 * time.Minute).UnixMilli(), RequestSignUp: ctx.BodyBool("requestSignUp"),
		IDTokenNonce: o.IDTokenNonce, Additional: jsonx.NewObject(),
	}
	if v, ok := RequestStateGet(ctx.Context(), oauthServerContextKey{}); ok {
		if m, _ := v.(map[string]any); len(m) > 0 {
			sd.ServerContext = m
		}
	}
	for k, v := range o.AdditionalData {
		if !internalStateKeys[k] {
			sd.Additional.Set(k, v)
		}
	}
	RequestStateSet(ctx.Context(), oauthStateKey{}, sd)
	state, err = generateGenericState(ctx, sd, "")
	if err != nil {
		a.Logger.Error("Failed to create verification", err)
		return "", "", ErrFrom("INTERNAL_SERVER_ERROR", ErrorCode{Code: "", Message: "Unable to create verification"})
	}
	return state, codeVerifier, nil
}

func generateGenericState(ctx *EndpointContext, sd *StateData, cookieName string) (string, error) {
	a := ctx.Auth
	state := bacrypto.RandomString(32)
	payload := *sd
	payload.OAuthState = state
	if a.OAuthConfig.StoreStateStrategy == "cookie" {
		if cookieName == "" {
			cookieName = "oauth_state"
		}
		enc, err := bacrypto.SymmetricEncrypt(bacrypto.DerivePurposeKey(a.SecretConfig, bacrypto.PurposeOAuthStateCookie), string(jsonx.MustMarshal(payload.toObject())))
		if err != nil {
			return "", err
		}
		c := a.CreateAuthCookie(cookieName, &CookieOptions{MaxAge: Int(600)})
		ctx.SetCookie(c.Name, enc, c.Attributes)
		return state, nil
	}
	if cookieName == "" {
		cookieName = "state"
	}
	c := a.CreateAuthCookie(cookieName, &CookieOptions{MaxAge: Int(300)})
	ctx.SetSignedCookie(c.Name, state, a.Secret, c.Attributes)
	v, err := a.InternalAdapter.CreateVerificationValue(ctx.Context(), "auth-state:"+state,
		string(jsonx.MustMarshal(payload.toObject())), time.Now().Add(10*time.Minute), nil)
	if err != nil {
		return "", err
	}
	if v == nil {
		return "", &StateError{Code: "state_generation_error", Message: "Unable to create verification. Make sure the database adapter is properly working and there is a verification table in the database"}
	}
	return state, nil
}

// ParseGenericState validates the OAuth state from the callback (parseGenericState).
func ParseGenericState(ctx *EndpointContext, state, cookieName string, skipStateCookieCheck *bool) (*StateData, error) {
	a := ctx.Auth
	if state == "" {
		return nil, &StateError{Code: "state_not_found", Message: "State not found in OAuth callback"}
	}
	var sd *StateData
	if a.OAuthConfig.StoreStateStrategy == "cookie" {
		if cookieName == "" {
			cookieName = "oauth_state"
		}
		c := a.CreateAuthCookie(cookieName, nil)
		enc := ctx.GetCookie(c.Name)
		if enc == "" {
			return nil, &StateError{Code: "state_mismatch", Message: "State mismatch: auth state cookie not found"}
		}
		dec, err := bacrypto.SymmetricDecrypt(bacrypto.DerivePurposeKey(a.SecretConfig, bacrypto.PurposeOAuthStateCookie), enc)
		if err == nil {
			sd, err = parseStateData(dec)
		}
		if err != nil {
			return nil, &StateError{Code: "state_invalid", Message: "State invalid: Failed to decrypt or parse auth state"}
		}
		if sd.OAuthState == "" || sd.OAuthState != state {
			return nil, &StateError{Code: "state_security_mismatch", Message: "State mismatch: OAuth state parameter does not match stored state", ErrorURL: sd.ErrorURL}
		}
		ExpireCookie(ctx, c)
	} else {
		v, err := a.InternalAdapter.FindVerificationValue(ctx.Context(), "auth-state:"+state)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, &StateError{Code: "state_mismatch", Message: "State mismatch: verification not found"}
		}
		sd, err = parseStateData(v.Value)
		if err != nil {
			return nil, err
		}
		if sd.OAuthState != "" && sd.OAuthState != state {
			return nil, &StateError{Code: "state_security_mismatch", Message: "State mismatch: OAuth state parameter does not match stored state", ErrorURL: sd.ErrorURL}
		}
		if cookieName == "" {
			cookieName = "state"
		}
		c := a.CreateAuthCookie(cookieName, nil)
		cookieVal, _ := ctx.GetSignedCookie(c.Name, a.Secret)
		skip := a.OAuthConfig.SkipStateCookieCheck
		if skipStateCookieCheck != nil {
			skip = *skipStateCookieCheck
		}
		if !skip && (cookieVal == "" || cookieVal != state) {
			return nil, &StateError{Code: "state_security_mismatch", Message: "State mismatch: State not persisted correctly", ErrorURL: sd.ErrorURL}
		}
		ExpireCookie(ctx, c)
		if err := a.InternalAdapter.DeleteVerificationByIdentifier(ctx.Context(), "auth-state:"+state); err != nil {
			return nil, err
		}
	}
	if sd.ExpiresAt < time.Now().UnixMilli() {
		return nil, &StateError{Code: "state_mismatch", Message: "Invalid state: request expired", ErrorURL: sd.ErrorURL}
	}
	return sd, nil
}

// GenerateIDTokenNonce returns a nonce when the provider requires one.
func GenerateIDTokenNonce(p oauth2.Provider) string {
	if oauth2.SettingsOf(p).RequiresIDTokenNonce {
		return bacrypto.RandomString(32)
	}
	return ""
}

// ---- token encryption (oauth2/utils.ts) ----

var hexOnly = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func isLikelyEncrypted(token string) bool {
	if strings.HasPrefix(token, "$ba$") {
		return true
	}
	return len(token)%2 == 0 && hexOnly.MatchString(token)
}

func (a *AuthContext) encryptTokens() bool {
	return a.Options.Account != nil && a.Options.Account.EncryptOAuthTokens
}

// DecryptOAuthToken decrypts a stored OAuth token when encryptOAuthTokens is enabled.
func (a *AuthContext) DecryptOAuthToken(token string) (string, error) {
	if token == "" || !a.encryptTokens() || !isLikelyEncrypted(token) {
		return token, nil
	}
	return bacrypto.SymmetricDecrypt(a.SecretConfig, token)
}

// SetTokenUtil encrypts an OAuth token for storage when encryptOAuthTokens is enabled.
// Empty tokens are returned as nil.
func (a *AuthContext) SetTokenUtil(token string) (any, error) {
	if token == "" {
		return nil, nil
	}
	if a.encryptTokens() {
		return bacrypto.SymmetricEncrypt(a.SecretConfig, token)
	}
	return token, nil
}
