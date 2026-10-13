// Package oauthpopup ports Better Auth's experimental oauth-popup plugin
// (packages/better-auth/src/plugins/oauth-popup): the OAuth flow runs in a popup and the
// callback renders a completion page that posts the session token (or the error) back to
// the opener with postMessage. Pair it with the bearer plugin.
package oauthpopup

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/validate"
)

// Constants (constants.ts).
const (
	MessageType     = "better-auth:oauth-popup"
	DataElementID   = "better-auth-oauth-popup"
	MarkerCookie    = "oauth_popup"
	TokenStorageKey = "better-auth.popup_token"
	ScriptCSPHash   = "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ="
)

// CompleteScript is the inline completion script; its sha256 is pinned in ScriptCSPHash.
const CompleteScript = `(function () {
	var el = document.getElementById("better-auth-oauth-popup");
	if (!el) return;
	var payload;
	try {
		payload = JSON.parse(el.textContent || "");
	} catch (e) {
		return;
	}
	var target = window.opener || window.parent;
	if (target && target !== window) {
		try {
			target.postMessage(
				{
					type: payload.type,
					nonce: payload.nonce,
					token: payload.token,
					redirectTo: payload.redirectTo,
					error: payload.error,
				},
				payload.targetOrigin,
			);
		} catch (e) {}
	}
	window.close();
})();
`

// Error codes (OAUTH_POPUP_ERROR_CODES).
var (
	ErrPopupSignInFailed = betterauth.ErrorCode{Code: "POPUP_SIGN_IN_FAILED", Message: "Popup sign-in failed"}
	ErrPopupBlocked      = betterauth.ErrorCode{Code: "POPUP_BLOCKED", Message: "Sign-in popup was blocked by the browser"}
	ErrPopupClosed       = betterauth.ErrorCode{Code: "POPUP_CLOSED", Message: "Sign-in popup was closed before completing"}
	ErrPopupTimeout      = betterauth.ErrorCode{Code: "POPUP_TIMEOUT", Message: "Sign-in popup timed out"}
)

func inlineJSON(v any) string {
	b, _ := jsonx.Marshal(v)
	r := strings.NewReplacer("<", "\\u003c", "\u2028", "\\u2028", "\u2029", "\\u2029")
	return r.Replace(string(b))
}

type popupError struct {
	code, description string
}

type message struct {
	nonce, token, redirectTo string
	err                      *popupError
}

func renderCompletion(c *betterauth.EndpointContext, popupOrigin string, m message) *betterauth.Response {
	if m.token != "" && !c.Auth.HasPlugin("bearer") {
		c.Auth.Logger.Warn("OAuth popup hands the session token back via postMessage, but the `bearer` plugin is not registered, so an embedded (cross-site iframe) app cannot authenticate with it. Add bearer() to your auth `plugins`.")
	}
	data := jsonx.O("type", MessageType, "targetOrigin", popupOrigin, "nonce", m.nonce)
	if m.token != "" {
		data.Set("token", m.token)
	}
	if m.redirectTo != "" {
		data.Set("redirectTo", m.redirectTo)
	}
	if m.err != nil {
		e := jsonx.O("code", m.err.code)
		if m.err.description != "" {
			e.Set("description", m.err.description)
		}
		data.Set("error", e)
	}
	html := "<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Completing sign-in</title></head>\n<body>\n" +
		"<script type=\"application/json\" id=\"" + DataElementID + "\">" + inlineJSON(data) + "</script>\n" +
		"<script>" + CompleteScript + "</script>\n</body>\n</html>"
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src '"+ScriptCSPHash+"'; base-uri 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	return &betterauth.Response{Status: 200, Header: h, Body: []byte(html)}
}

var startQuery = validate.Object(
	validate.F("provider", validate.String()),
	validate.F("popupOrigin", validate.String()),
	validate.F("popupNonce", validate.Optional(validate.String())),
	validate.F("callbackURL", validate.Optional(validate.String())),
	validate.F("errorCallbackURL", validate.Optional(validate.String())),
	validate.F("newUserCallbackURL", validate.Optional(validate.String())),
	validate.F("scopes", validate.Optional(validate.String())),
	validate.F("requestSignUp", validate.Optional(validate.String())),
	validate.F("additionalData", validate.Optional(validate.String())),
)

var internalStateKeys = map[string]bool{"callbackURL": true, "codeVerifier": true, "errorURL": true,
	"newUserURL": true, "expiresAt": true, "oauthState": true, "link": true, "requestSignUp": true,
	"idTokenNonce": true, "serverContext": true}

func start(c *betterauth.EndpointContext) (any, error) {
	a := c.Auth
	q := c.QueryString
	popupOrigin := q("popupOrigin")
	if !a.IsTrustedOrigin(popupOrigin, false) {
		a.Logger.Error(fmt.Sprintf("OAuth popup origin is not a trusted origin. Add %s to trustedOrigins.", popupOrigin))
		return nil, betterauth.ErrFrom("FORBIDDEN", betterauth.ErrInvalidOrigin)
	}
	fail := func(code, desc string) (any, error) {
		return renderCompletion(c, popupOrigin, message{nonce: q("popupNonce"), err: &popupError{code, desc}}), nil
	}
	for _, v := range [][2]string{{"callbackURL", "invalid_callback_url"}, {"errorCallbackURL", "invalid_error_callback_url"},
		{"newUserCallbackURL", "invalid_new_user_callback_url"}} {
		u := q(v[0])
		if u == "" || a.IsTrustedOrigin(u, true) {
			continue
		}
		a.Logger.Error("Invalid redirect URL: " + u)
		return fail(v[1], "Untrusted URL: "+u)
	}
	p := a.FindProvider(q("provider"))
	if p == nil {
		return fail("provider_not_found", "Unknown provider: "+q("provider"))
	}
	callbackURL := q("callbackURL")
	if callbackURL == "" {
		callbackURL = a.BaseURL
	}
	u, err := func() (*url.URL, error) {
		verifier := bacrypto.RandomString(128)
		nonce := betterauth.GenerateIDTokenNonce(p)
		sd := &betterauth.StateData{CallbackURL: callbackURL, CodeVerifier: verifier, IDTokenNonce: nonce,
			ErrorURL: q("errorCallbackURL"), NewUserURL: q("newUserCallbackURL"),
			ExpiresAt: time.Now().Add(10 * time.Minute).UnixMilli(), Additional: jsonx.NewObject()}
		if q("requestSignUp") == "true" {
			sd.RequestSignUp = betterauth.Bool(true)
		}
		if raw := q("additionalData"); raw != "" {
			if v, err := jsonx.Parse([]byte(raw)); err == nil {
				if o, ok := v.(*jsonx.Object); ok {
					for _, k := range o.Keys() {
						if !internalStateKeys[k] {
							x, _ := o.Get(k)
							sd.Additional.Set(k, x)
						}
					}
				}
			}
		}
		betterauth.OAuthProxySetOAuthState(c.Context(), sd)
		state, err := betterauth.OAuthPopupGenerateState(c, sd, "")
		if err != nil {
			return nil, err
		}
		marker := a.CreateAuthCookie(MarkerCookie, &betterauth.CookieOptions{MaxAge: betterauth.Int(600)})
		mv, _ := json.Marshal(map[string]string{"popupOrigin": popupOrigin, "popupNonce": q("popupNonce")})
		c.SetSignedCookie(marker.Name, string(mv), a.Secret, marker.Attributes)
		var scopes []string
		if s := q("scopes"); s != "" {
			scopes = strings.Split(s, ",")
		}
		return p.CreateAuthorizationURL(c.Context(), oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier,
			IDTokenNonce: nonce, RedirectURI: a.BaseURL + "/callback/" + p.ID(), Scopes: scopes})
	}()
	if err != nil {
		a.Logger.Error("OAuth popup failed to start", err)
		return fail("popup_sign_in_failed", "Failed to start the OAuth flow.")
	}
	return nil, c.Redirect(u.String())
}

func afterCallback(c *betterauth.EndpointContext) (any, error) {
	redirectTo := c.ResponseHeaders.Get("Location")
	if redirectTo == "" {
		return nil, nil
	}
	a := c.Auth
	cookie := a.CreateAuthCookie(MarkerCookie, nil)
	marker, ok := c.GetSignedCookie(cookie.Name, a.Secret)
	if !ok {
		return nil, nil
	}
	betterauth.ExpireCookie(c, cookie)
	var parsed struct {
		PopupOrigin string `json:"popupOrigin"`
		PopupNonce  string `json:"popupNonce"`
	}
	if err := json.Unmarshal([]byte(marker), &parsed); err != nil {
		return nil, nil
	}
	token := ""
	for _, sc := range c.ResponseHeaders.Values("Set-Cookie") {
		n, v, _ := betterauth.ParseSetCookie(sc)
		if n == a.AuthCookies.SessionToken.Name {
			token = v
			break
		}
	}
	if token != "" {
		return renderCompletion(c, parsed.PopupOrigin, message{nonce: parsed.PopupNonce, token: token, redirectTo: redirectTo}), nil
	}
	base, err := url.Parse(a.BaseURL)
	if err != nil {
		return nil, nil
	}
	ref, err := url.Parse(redirectTo)
	if err != nil {
		return nil, nil
	}
	qv := base.ResolveReference(ref).Query()
	code := qv.Get("error")
	if code == "" {
		return nil, nil
	}
	return renderCompletion(c, parsed.PopupOrigin, message{nonce: parsed.PopupNonce, err: &popupError{code, qv.Get("error_description")}}), nil
}

// New creates the oauth-popup plugin (oauthPopup).
func New() *betterauth.Plugin {
	return &betterauth.Plugin{
		ID:         "oauth-popup",
		ErrorCodes: []betterauth.ErrorCode{ErrPopupSignInFailed, ErrPopupBlocked, ErrPopupClosed, ErrPopupTimeout},
		Endpoints: []*betterauth.Endpoint{{
			Key: "oauthPopupStart", Path: "/oauth-popup/start", Methods: []string{"GET"}, Query: startQuery,
			Metadata: map[string]any{"scope": "server"}, Handler: start,
		}},
		Hooks: betterauth.PluginHooks{After: []betterauth.Hook{{
			Matcher: func(c *betterauth.EndpointContext) bool {
				return strings.HasPrefix(c.Path, "/callback/") || strings.HasPrefix(c.Path, "/oauth2/callback/")
			},
			Handler: afterCallback,
		}}},
	}
}
