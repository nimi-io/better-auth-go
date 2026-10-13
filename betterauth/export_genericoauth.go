package betterauth

import (
	"context"
	"net/url"
)

// Helpers exported for the OAuth plugin group (generic-oauth, oauth-proxy, oauth-popup,
// one-tap). They expose existing core internals without changing their behaviour.

// OAuthProxySetOAuthState stores sd as the OAuth state of the current request
// (setOAuthState upstream), so GetOAuthState and callback hooks can read it.
func OAuthProxySetOAuthState(ctx context.Context, sd *StateData) {
	RequestStateSet(ctx, oauthStateKey{}, sd)
}

// OAuthProxyRedirectOnError returns the redirect to errorURL with ?error=code (and
// error_description when description is non-empty), appended to any existing query
// (redirectOnError upstream).
func OAuthProxyRedirectOnError(ctx *EndpointContext, errorURL, code, description string) error {
	return errorRedirect(ctx, errorURL, code, description)
}

// OAuthProxyAppendQueryParams appends params (in order) to u (appendQueryParams).
func OAuthProxyAppendQueryParams(u string, params url.Values, order []string) (string, error) {
	return appendQueryParams(u, params, order)
}

// OAuthPopupGenerateState persists sd (with a fresh OAuth state value) using the configured
// state strategy and returns the state (generateGenericState upstream).
func OAuthPopupGenerateState(ctx *EndpointContext, sd *StateData, cookieName string) (string, error) {
	return generateGenericState(ctx, sd, cookieName)
}
