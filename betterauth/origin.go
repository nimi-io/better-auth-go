package betterauth

import (
	"strings"
)

func (a *AuthContext) disableCSRFSet() bool {
	return a.Options.Advanced != nil && a.Options.Advanced.DisableCSRFCheck != nil
}

func shouldSkipCSRFForBackwardCompat(ctx *EndpointContext) bool {
	return ctx.Auth.SkipOriginCheck && !ctx.Auth.disableCSRFSet()
}

func shouldSkipOriginCheck(ctx *EndpointContext) bool {
	if ctx.Auth.SkipOriginCheck {
		return true
	}
	if len(ctx.Auth.SkipOriginCheckPaths) > 0 && ctx.Request != nil {
		basePath := ""
		if u, err := parseJSURL(ctx.Auth.BaseURL); err == nil {
			basePath = u.Path
		}
		current := normalizePathname(requestURL(ctx.Request), basePath)
		for _, p := range ctx.Auth.SkipOriginCheckPaths {
			np := strings.TrimRight(p, "/")
			if current == np || strings.HasPrefix(current, np+"/") {
				return true
			}
		}
	}
	return false
}

func invalidURLError(label string) *APIError {
	switch label {
	case "origin":
		return ErrFrom("FORBIDDEN", ErrInvalidOrigin)
	case "callbackURL":
		return ErrFrom("FORBIDDEN", ErrInvalidCallbackURL)
	case "redirectURL":
		return ErrFrom("FORBIDDEN", ErrInvalidRedirectURL)
	case "errorCallbackURL":
		return ErrFrom("FORBIDDEN", ErrInvalidErrorCallbackURL)
	case "newUserCallbackURL":
		return ErrFrom("FORBIDDEN", ErrInvalidNewUserCallbackURL)
	}
	return ErrMessage("FORBIDDEN", "Invalid "+label)
}

func validateURLLabel(ctx *EndpointContext, v any, label string, strict bool) error {
	if v == nil || v == "" {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		if !strict {
			return nil
		}
		return ErrMessage("BAD_REQUEST", "Invalid "+label+": expected a string")
	}
	if !ctx.Auth.IsTrustedOrigin(s, label != "origin") {
		ctx.Auth.Logger.Error("Invalid " + label + ": " + s)
		ctx.Auth.Logger.Info("If it's a valid URL, please add "+s+" to trustedOrigins in your auth config\n",
			"Current list of trustedOrigins: "+strings.Join(ctx.Auth.TrustedOrigins, ","))
		return invalidURLError(label)
	}
	return nil
}

func bodyField(body any, key string) any {
	if m, ok := body.(map[string]any); ok {
		return m[key]
	}
	return nil
}

// originCheckMiddleware is the router-level CSRF/URL check applied to every request.
func originCheckMiddleware(ctx *EndpointContext) error {
	if ctx.Request == nil {
		return nil
	}
	switch ctx.Request.Method {
	case "GET", "OPTIONS", "HEAD":
		return nil
	}
	if err := validateOrigin(ctx, false); err != nil {
		return err
	}
	if shouldSkipOriginCheck(ctx) {
		return nil
	}
	callbackURL := bodyField(ctx.Body, "callbackURL")
	if callbackURL == nil || callbackURL == "" {
		if q, ok := ctx.Query["callbackURL"]; ok {
			callbackURL = q
		}
	}
	checks := []struct {
		v     any
		label string
	}{
		{callbackURL, "callbackURL"},
		{bodyField(ctx.Body, "redirectTo"), "redirectURL"},
		{bodyField(ctx.Body, "errorCallbackURL"), "errorCallbackURL"},
		{bodyField(ctx.Body, "newUserCallbackURL"), "newUserCallbackURL"},
	}
	for _, c := range checks {
		if err := validateURLLabel(ctx, c.v, c.label, true); err != nil {
			return err
		}
	}
	return nil
}

// OriginCheck returns an endpoint middleware validating the URLs returned by getValue
// against the trusted origins (originCheck upstream).
func OriginCheck(getValue func(ctx *EndpointContext) []string) Middleware {
	return func(ctx *EndpointContext) error {
		if ctx.Request == nil || shouldSkipOriginCheck(ctx) {
			return nil
		}
		for _, u := range getValue(ctx) {
			if u == "" {
				continue
			}
			if err := validateURLLabel(ctx, u, "callbackURL", false); err != nil {
				return err
			}
		}
		return nil
	}
}

func validateOrigin(ctx *EndpointContext, force bool) error {
	if ctx.Request == nil {
		return nil
	}
	h := ctx.Request.Header
	origin := h.Get("Origin")
	originHeader := origin
	if originHeader == "" {
		originHeader = h.Get("Referer")
	}
	useCookies := len(h.Values("Cookie")) > 0
	if ctx.Auth.SkipCSRFCheck {
		return nil
	}
	if shouldSkipCSRFForBackwardCompat(ctx) {
		if adv := ctx.Auth.Options.Advanced; adv != nil && adv.DisableOriginCheck != nil && *adv.DisableOriginCheck {
			ctx.Auth.auth.deprecationOnce.Do(func() {
				ctx.Auth.Logger.Warn("[Deprecation] disableOriginCheck: true currently also disables CSRF checks. " +
					"In a future version, disableOriginCheck will ONLY disable URL validation. " +
					"To keep CSRF disabled, add disableCSRFCheck: true to your config.")
			})
		}
		return nil
	}
	if shouldSkipOriginCheck(ctx) {
		return nil
	}
	if !force && !useCookies {
		return nil
	}
	toValidate := originHeader
	if origin == "null" && h.Get("Sec-Fetch-Site") == "same-origin" {
		trusted := ctx.Auth.Options.Advanced != nil && ctx.Auth.Options.Advanced.TrustedProxyHeaders
		if base, err := getBaseURL("", ctx.Auth.Options.BasePath, ctx.Request, false, trusted); err == nil && base != "" {
			if o := getOrigin(base); o != "" {
				toValidate = o
			}
		}
	}
	if toValidate == "" || toValidate == "null" {
		return ErrFrom("FORBIDDEN", ErrMissingOrNullOrigin)
	}
	for _, o := range ctx.Auth.TrustedOrigins {
		if matchesOriginPattern(toValidate, o, false) {
			return nil
		}
	}
	ctx.Auth.Logger.Error("Invalid origin: " + toValidate)
	return ErrFrom("FORBIDDEN", ErrInvalidOrigin)
}

// FormCSRFMiddleware protects form-capable endpoints (sign-in/sign-up) against cross-site
// form posts (formCsrfMiddleware).
func FormCSRFMiddleware(ctx *EndpointContext) error {
	req := ctx.Request
	if req == nil || ctx.Auth.SkipCSRFCheck || shouldSkipCSRFForBackwardCompat(ctx) {
		return nil
	}
	h := req.Header
	if len(h.Values("Cookie")) > 0 {
		return validateOrigin(ctx, false)
	}
	site, mode, dest := h.Get("Sec-Fetch-Site"), h.Get("Sec-Fetch-Mode"), h.Get("Sec-Fetch-Dest")
	if strings.TrimSpace(site) != "" || strings.TrimSpace(mode) != "" || strings.TrimSpace(dest) != "" {
		if site == "cross-site" && mode == "navigate" {
			ctx.Auth.Logger.Error("Blocked cross-site navigation login attempt (CSRF protection)")
			return ErrFrom("FORBIDDEN", ErrCrossSiteNavigationLoginBlocked)
		}
		return validateOrigin(ctx, true)
	}
	if h.Get("Origin") != "" || h.Get("Referer") != "" {
		return validateOrigin(ctx, true)
	}
	return nil
}
