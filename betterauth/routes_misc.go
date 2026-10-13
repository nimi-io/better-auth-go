package betterauth

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// coreEndpoints returns the built-in endpoints in upstream registration order
// (ok and error are appended after plugin endpoints).
func coreEndpoints() []*Endpoint {
	return []*Endpoint{
		signInSocialEndpoint(),
		callbackEndpoint(),
		getSessionEndpoint(),
		signOutEndpoint(),
		signUpEmailEndpoint(),
		signInEmailEndpoint(),
		resetPasswordEndpoint(),
		verifyPasswordEndpoint(),
		verifyEmailEndpoint(),
		sendVerificationEmailEndpoint(),
		changeEmailEndpoint(),
		changePasswordEndpoint(),
		setPasswordEndpoint(),
		updateSessionEndpoint(),
		updateUserEndpoint(),
		deleteUserEndpoint(),
		requestPasswordResetEndpoint(),
		requestPasswordResetCallbackEndpoint(),
		listSessionsEndpoint(),
		revokeSessionEndpoint(),
		revokeSessionsEndpoint(),
		revokeOtherSessionsEndpoint(),
		linkSocialEndpoint(),
		listAccountsEndpoint(),
		deleteUserCallbackEndpoint(),
		unlinkAccountEndpoint(),
		refreshTokenEndpoint(),
		getAccessTokenEndpoint(),
		accountInfoEndpoint(),
	}
}

func okEndpoint() *Endpoint {
	return &Endpoint{Key: "ok", Path: "/ok", Methods: []string{"GET"},
		Handler: func(*EndpointContext) (any, error) { return jsonx.O("ok", true), nil }}
}

var errorCodeRe = regexp.MustCompile(`^['A-Za-z0-9_-]+$`)

func sanitizeHTML(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	// & not already part of an entity
	ent := regexp.MustCompile(`^(amp;|lt;|gt;|quot;|#39;|#x[0-9a-fA-F]+;|#[0-9]+;)`)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '&' && !ent.MatchString(s[i+1:]) {
			b.WriteString("&amp;")
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func pageVal(c *ErrorPageCustomization, group, key, def string) string {
	if c == nil {
		return def
	}
	var m map[string]string
	switch group {
	case "colors":
		m = c.Colors
	case "size":
		m = c.Size
	case "font":
		m = c.Font
	}
	if v := m[key]; v != "" {
		return v
	}
	return def
}

func pageFlag(c *ErrorPageCustomization, name string) bool {
	if c == nil {
		return false
	}
	switch name {
	case "disableBackgroundGrid":
		return c.DisableBackgroundGrid
	case "disableCornerDecorations":
		return c.DisableCornerDecorations
	case "disableTitleBorder":
		return c.DisableTitleBorder
	}
	return false
}

func errorEndpoint() *Endpoint {
	return &Endpoint{Key: "error", Path: "/error", Methods: []string{"GET"},
		Handler: func(ctx *EndpointContext) (any, error) {
			var q url.Values
			if ctx.Request != nil {
				q = ctx.Request.URL.Query()
			} else {
				q = url.Values{}
				for k, v := range ctx.Query {
					if s, ok := v.(string); ok {
						q.Set(k, s)
					}
				}
			}
			code := q.Get("error")
			if code == "" {
				code = "UNKNOWN"
			}
			desc := q.Get("error_description")
			safeCode := code
			if !errorCodeRe.MatchString(code) {
				safeCode = "UNKNOWN"
			}
			safeDesc := ""
			if desc != "" {
				safeDesc = sanitizeHTML(desc)
			}
			params := url.Values{"error": {safeCode}}
			order := []string{"error"}
			if desc != "" {
				params.Set("error_description", desc)
				order = append(order, "error_description")
			}
			opts := ctx.Auth.Options.OnAPIError
			if opts != nil && opts.ErrorURL != "" {
				loc, err := appendQueryParams(opts.ErrorURL, params, order)
				if err != nil {
					return nil, err
				}
				h := http.Header{}
				h.Set("Location", loc)
				return &Response{Status: 302, Header: h}, nil
			}
			var custom *ErrorPageCustomization
			if opts != nil {
				custom = opts.CustomizeDefaultErrorPage
			}
			if isProduction() && custom == nil {
				h := http.Header{}
				h.Set("Location", "/?"+encodeSearchParams(params, order))
				return &Response{Status: 302, Header: h}, nil
			}
			h := http.Header{}
			h.Set("Content-Type", "text/html")
			return &Response{Status: 200, Header: h, Body: []byte(renderErrorPage(custom, safeCode, safeDesc))}, nil
		}}
}
