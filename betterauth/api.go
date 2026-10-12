package betterauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// API calls endpoints directly from Go (auth.api upstream). Errors are returned as
// *APIError. Use Call for any endpoint (including plugin endpoints) or the typed helpers.
type API struct {
	auth *Auth
}

// CallInput is the input of a direct API call.
type CallInput struct {
	// Headers are the incoming request headers (cookies, authorization, ...).
	Headers http.Header
	// Request, when set, makes the call behave like an HTTP request (origin checks still
	// only run for HTTP requests through the handler).
	Request *http.Request
	// Body is any JSON-encodable value (map, struct, *jsonx.Object).
	Body   any
	Query  map[string]any
	Params map[string]string
	// Method overrides the endpoint method (e.g. "POST" for get-session).
	Method string
}

// CallResult is the result of a direct API call.
type CallResult struct {
	// Data is the raw handler result (often *jsonx.Object).
	Data any
	// Headers are the response headers (Set-Cookie, Location, ...).
	Headers http.Header
	Status  int
}

// JSON returns the result encoded as JSON.
func (r *CallResult) JSON() ([]byte, error) {
	switch r.Data {
	case nil, Null:
		return []byte("null"), nil
	}
	return jsonx.Marshal(r.Data)
}

// Decode decodes the JSON result into v.
func (r *CallResult) Decode(v any) error {
	b, err := r.JSON()
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func normalizeBody(body any) (any, error) {
	switch body.(type) {
	case nil:
		return validate.Undefined, nil
	case map[string]any:
		return body, nil
	}
	b, err := jsonx.Marshal(body)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Call invokes the endpoint registered under key ("signUpEmail", "getSession", ...).
func (api *API) Call(ctx context.Context, key string, in CallInput) (*CallResult, error) {
	a := api.auth
	ep := a.endpoint(key)
	if ep == nil {
		return nil, fmt.Errorf("betterauth: unknown endpoint %q", key)
	}
	body, err := normalizeBody(in.Body)
	if err != nil {
		return nil, err
	}
	var ac *AuthContext
	needsCallbacks := a.cfg.TrustedOriginsFunc != nil || (a.cfg.Account != nil && a.cfg.Account.AccountLinking != nil && a.cfg.Account.AccountLinking.TrustedProvidersFunc != nil)
	if in.Request != nil || a.cfg.DynamicBaseURL != nil || (needsCallbacks && in.Headers != nil) {
		ac, err = a.requestContext(in.Request, in.Headers)
		if err != nil {
			return nil, ErrMessage("INTERNAL_SERVER_ERROR", "Dynamic baseURL could not be resolved for this direct auth.api call. Pass `headers: request.headers` (or `request`) to the call, or add `fallback` to your baseURL config.")
		}
	} else {
		ac = a.ctx.clone()
	}
	headers := in.Headers
	if headers == nil && in.Request != nil {
		headers = in.Request.Header
	}
	res, err := a.dispatch(ctx, ep, callInput{Request: in.Request, Headers: headers, Body: body, Query: in.Query,
		Params: in.Params, Method: in.Method, Auth: ac})
	if err != nil {
		return nil, err
	}
	if e, ok := res.Response.(*APIError); ok {
		c := *e
		c.Headers = mergeHeaders(newHeader(), res.Headers)
		return &CallResult{Headers: res.Headers, Status: e.StatusCode}, &c
	}
	if raw, ok := res.Response.(*Response); ok {
		return &CallResult{Data: raw, Headers: mergeHeaders(mergeHeaders(newHeader(), res.Headers), raw.Header), Status: raw.Status}, nil
	}
	status := res.Status
	if status == 0 {
		status = 200
	}
	return &CallResult{Data: res.Response, Headers: res.Headers, Status: status}, nil
}

// GetSession returns the session for the given request headers (nil when signed out).
func (api *API) GetSession(ctx context.Context, headers http.Header) (*SessionWithUser, error) {
	if headers == nil {
		headers = http.Header{}
	}
	res, err := api.Call(ctx, "getSession", CallInput{Headers: headers})
	if err != nil {
		return nil, err
	}
	if sr, ok := res.Data.(*SessionResult); ok {
		return sr.SessionWithUser, nil
	}
	return nil, nil
}

// SignUpEmailInput is the body of sign-up/email.
type SignUpEmailInput struct {
	Name        string         `json:"name"`
	Email       string         `json:"email"`
	Password    string         `json:"password"`
	Image       string         `json:"image,omitempty"`
	CallbackURL string         `json:"callbackURL,omitempty"`
	RememberMe  *bool          `json:"rememberMe,omitempty"`
	Additional  map[string]any `json:"-"`
}

func (in SignUpEmailInput) body() map[string]any {
	m := map[string]any{"name": in.Name, "email": in.Email, "password": in.Password}
	if in.Image != "" {
		m["image"] = in.Image
	}
	if in.CallbackURL != "" {
		m["callbackURL"] = in.CallbackURL
	}
	if in.RememberMe != nil {
		m["rememberMe"] = *in.RememberMe
	}
	for k, v := range in.Additional {
		m[k] = v
	}
	return m
}

// SignUpEmail signs a user up with email and password.
func (api *API) SignUpEmail(ctx context.Context, in SignUpEmailInput, headers http.Header) (*CallResult, error) {
	return api.Call(ctx, "signUpEmail", CallInput{Body: in.body(), Headers: headers})
}

// SignInEmail signs a user in with email and password.
func (api *API) SignInEmail(ctx context.Context, email, password string, rememberMe *bool, headers http.Header) (*CallResult, error) {
	body := map[string]any{"email": email, "password": password}
	if rememberMe != nil {
		body["rememberMe"] = *rememberMe
	}
	return api.Call(ctx, "signInEmail", CallInput{Body: body, Headers: headers})
}

// SignOut signs the current session out.
func (api *API) SignOut(ctx context.Context, headers http.Header) (*CallResult, error) {
	return api.Call(ctx, "signOut", CallInput{Headers: headers})
}

// SetPassword sets a password for a user without one (server-only endpoint).
func (api *API) SetPassword(ctx context.Context, newPassword string, headers http.Header) (*CallResult, error) {
	return api.Call(ctx, "setPassword", CallInput{Body: map[string]any{"newPassword": newPassword}, Headers: headers})
}

// ListSessions lists the active sessions of the current user.
func (api *API) ListSessions(ctx context.Context, headers http.Header) (*CallResult, error) {
	return api.Call(ctx, "listSessions", CallInput{Headers: headers})
}

// RevokeSession revokes a session by token.
func (api *API) RevokeSession(ctx context.Context, token string, headers http.Header) (*CallResult, error) {
	return api.Call(ctx, "revokeSession", CallInput{Body: map[string]any{"token": token}, Headers: headers})
}

// UpdateUser updates the current user.
func (api *API) UpdateUser(ctx context.Context, fields map[string]any, headers http.Header) (*CallResult, error) {
	return api.Call(ctx, "updateUser", CallInput{Body: fields, Headers: headers})
}

// ChangePassword changes the current user's password.
func (api *API) ChangePassword(ctx context.Context, current, next string, revokeOtherSessions bool, headers http.Header) (*CallResult, error) {
	return api.Call(ctx, "changePassword", CallInput{Body: map[string]any{"currentPassword": current, "newPassword": next, "revokeOtherSessions": revokeOtherSessions}, Headers: headers})
}
