package sso

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
	"github.com/nimi-io/better-auth-go/validate"
)

// ---- relay state (saml-state.ts) ----

func generateRelayState(ctx *betterauth.EndpointContext, ref ProviderReference) (string, error) {
	callbackURL := ctx.BodyString("callbackURL")
	if callbackURL == "" {
		return "", badRequest("callbackURL is required")
	}
	sd := &betterauth.StateData{
		CallbackURL:   callbackURL,
		CodeVerifier:  bacrypto.RandomString(128),
		ErrorURL:      ctx.BodyString("errorCallbackURL"),
		NewUserURL:    ctx.BodyString("newUserCallbackURL"),
		ExpiresAt:     time.Now().Add(10 * time.Minute).UnixMilli(),
		RequestSignUp: ctx.BodyBool("requestSignUp"),
		ServerContext: map[string]any{SSOProviderStateKey: ref.toServerContext()},
		Additional:    jsonx.NewObject(),
	}
	state, err := betterauth.OAuthPopupGenerateState(ctx, sd, "relay_state")
	if err != nil {
		ctx.Auth.Logger.Error("Failed to create verification for relay state", err)
		return "", apiErr("INTERNAL_SERVER_ERROR", "message", "State error: Unable to create verification for relay state", "cause", jsonx.NewObject())
	}
	return state, nil
}

func parseRelayState(ctx *betterauth.EndpointContext, relayState string) (*betterauth.StateData, error) {
	sd, err := betterauth.SSOParseGenericState(ctx, relayState, "relay_state", true)
	if err != nil {
		ctx.Auth.Logger.Error("Failed to parse relay state", err)
		return nil, apiErr("BAD_REQUEST", "message", "State error: failed to validate relay state", "cause", jsonx.NewObject())
	}
	if sd.ErrorURL == "" {
		sd.ErrorURL = errorPageURL(ctx)
	}
	return sd, nil
}

// ---- redirects ----

type trustedFn func(u string, allowRelative bool) bool

func getSafeRedirectCandidate(u, callbackPathname, appOrigin string, trusted trustedFn) string {
	if u == "" {
		return ""
	}
	if strings.HasPrefix(u, "/") {
		if !isSafeSAMLRedirectPath(u) {
			return ""
		}
		base, _ := url.Parse(appOrigin)
		ref, err := url.Parse(u)
		if err != nil {
			return ""
		}
		abs := base.ResolveReference(ref)
		if originOf(abs) != appOrigin || abs.Path == callbackPathname {
			return ""
		}
		return u
	}
	abs, err := url.Parse(u)
	if err != nil || abs.Scheme == "" || (abs.Host == "" && abs.Opaque == "") {
		return ""
	}
	if originOf(abs) != appOrigin && !trusted(u, false) {
		return ""
	}
	if originOf(abs) == appOrigin && pathOrRoot(abs) == callbackPathname {
		return ""
	}
	return u
}

func pathOrRoot(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func originOf(u *url.URL) string {
	host := strings.ToLower(u.Host)
	if (u.Scheme == "http" && strings.HasSuffix(host, ":80")) || (u.Scheme == "https" && strings.HasSuffix(host, ":443")) {
		host = host[:strings.LastIndex(host, ":")]
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

func appOriginOf(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	return originOf(u)
}

// GetSafeRedirectURL returns the first safe redirect candidate or the app origin.
func GetSafeRedirectURL(candidates []string, callbackPath, appOrigin string, trusted func(u string, allowRelative bool) bool) string {
	cp, _ := url.Parse(callbackPath)
	pathname := "/"
	if cp != nil {
		pathname = pathOrRoot(cp)
	}
	for _, c := range candidates {
		if s := getSafeRedirectCandidate(c, pathname, appOrigin, trusted); s != "" {
			return s
		}
	}
	return appOrigin
}

func buildSAMLRedirectURL(u string, kv ...string) string {
	isRelative := strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//")
	base, _ := url.Parse("http://better-auth.local")
	ref, err := url.Parse(u)
	if err == nil {
		parsed := base.ResolveReference(ref)
		q := parsed.Query()
		var keys []string
		for i := 0; i+1 < len(kv); i += 2 {
			q.Set(kv[i], kv[i+1])
			keys = append(keys, kv[i])
		}
		// keep existing order, then new keys (URLSearchParams.set semantics)
		parsed.RawQuery = orderedQuery(parsed.RawQuery, kv)
		_ = q
		_ = keys
		if isRelative {
			s := parsed.EscapedPath()
			if parsed.RawQuery != "" {
				s += "?" + parsed.RawQuery
			}
			if parsed.Fragment != "" {
				s += "#" + parsed.EscapedFragment()
			}
			return s
		}
		return parsed.String()
	}
	hash := ""
	if i := strings.Index(u, "#"); i >= 0 {
		u, hash = u[:i], u[i:]
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + encodeParams(kv) + hash
}

func encodeParams(kv []string) string {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, oauth2.FormEncode(kv[i])+"="+oauth2.FormEncode(kv[i+1]))
	}
	return strings.Join(parts, "&")
}

// orderedQuery applies URLSearchParams.set for each pair onto raw.
func orderedQuery(raw string, kv []string) string {
	type pair struct{ k, v string }
	var pairs []pair
	if raw != "" {
		for _, part := range strings.Split(raw, "&") {
			if part == "" {
				continue
			}
			k, v, _ := strings.Cut(part, "=")
			dk, _ := url.QueryUnescape(k)
			dv, _ := url.QueryUnescape(v)
			pairs = append(pairs, pair{dk, dv})
		}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		k, v := kv[i], kv[i+1]
		idx := -1
		var out []pair
		for _, p := range pairs {
			if p.k == k {
				if idx == -1 {
					idx = len(out)
					out = append(out, pair{k, v})
				}
				continue
			}
			out = append(out, p)
		}
		if idx == -1 {
			out = append(out, pair{k, v})
		}
		pairs = out
	}
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = oauth2.FormEncode(p.k) + "=" + oauth2.FormEncode(p.v)
	}
	return strings.Join(parts, "&")
}

func samlRedirectCandidates(relayCallback string, cfg *SAMLConfig, o *SAMLOptions) []string {
	var c []string
	c = append(c, relayCallback)
	if cfg != nil {
		c = append(c, cfg.IdpInitiatedCallbackURL)
	} else {
		c = append(c, "")
	}
	c = append(c, o.IdpInitiatedCallbackURL)
	if cfg != nil {
		c = append(c, cfg.CallbackURL)
	}
	return c
}

func errorRedirectURL(base, errCode, desc string) string {
	if u, err := url.Parse(base); err == nil && u.Scheme != "" && u.Host != "" {
		u.RawQuery = orderedQuery(u.RawQuery, []string{"error", errCode, "error_description", desc})
		return u.String()
	}
	hash := ""
	if i := strings.Index(base, "#"); i >= 0 {
		base, hash = base[:i], base[i:]
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "error=" + betterauth.EncodeURIComponent(errCode) + "&error_description=" + betterauth.EncodeURIComponent(desc) + hash
}

// ---- response validation ----

func (p *plugin) validateInResponseTo(ctx *betterauth.EndpointContext, ex samlify.Extract, providerID, redirectURL string) (*ProviderReference, error) {
	s := p.o.saml()
	if s.EnableInResponseToValidation != nil && !*s.EnableInResponseToValidation {
		return nil, nil
	}
	inResponseTo := ex.Response["inResponseTo"]
	if inResponseTo != "" {
		consumed, err := ctx.Auth.InternalAdapter.ConsumeVerificationValue(ctx.Context(), AuthnRequestKeyPrefix+inResponseTo)
		if err != nil {
			return nil, err
		}
		var stored map[string]any
		if consumed != nil {
			if v, err := jsonx.Parse([]byte(consumed.Value)); err == nil {
				if o, ok := v.(*jsonx.Object); ok {
					stored = o.Map()
				}
			}
		}
		if stored == nil {
			ctx.Auth.Logger.Error("SAML InResponseTo validation failed: unknown or expired request ID", map[string]any{"inResponseTo": inResponseTo, "providerId": providerID})
			return nil, ctx.Redirect(errorRedirectURL(redirectURL, "invalid_saml_response", "Unknown or expired request ID"))
		}
		if stored["providerId"] != providerID {
			ctx.Auth.Logger.Error("SAML InResponseTo validation failed: provider mismatch", map[string]any{"inResponseTo": inResponseTo})
			return nil, ctx.Redirect(errorRedirectURL(redirectURL, "invalid_saml_response", "Provider mismatch"))
		}
		ref := parseProviderReference(stored["providerReference"])
		if ref == nil {
			ctx.Auth.Logger.Error("SAML InResponseTo validation failed: provider reference missing or invalid", map[string]any{"inResponseTo": inResponseTo})
			return nil, ctx.Redirect(errorRedirectURL(redirectURL, "invalid_state", "SSO provider reference missing or invalid"))
		}
		return ref, nil
	}
	if !s.AllowIdpInitiated {
		ctx.Auth.Logger.Error("SAML IdP-initiated SSO rejected: InResponseTo missing and allowIdpInitiated is false", map[string]any{"providerId": providerID})
		return nil, ctx.Redirect(errorRedirectURL(redirectURL, "unsolicited_response", "IdP-initiated SSO not allowed"))
	}
	return nil, nil
}

func validateAudience(ctx *betterauth.EndpointContext, ex samlify.Extract, expected, providerID, redirectURL string) error {
	if expected == "" {
		ctx.Auth.Logger.Warn("Could not determine SP entity ID for audience validation; skipping", map[string]any{"providerId": providerID})
		return nil
	}
	if len(ex.Audience) == 0 {
		ctx.Auth.Logger.Error("SAML assertion missing AudienceRestriction but audience is configured — rejecting", map[string]any{"providerId": providerID})
		return ctx.Redirect(errorRedirectURL(redirectURL, "invalid_saml_response", "Audience restriction missing"))
	}
	if !inList(ex.Audience, expected) {
		ctx.Auth.Logger.Error("SAML audience mismatch: assertion was issued for a different service provider", map[string]any{"expected": expected, "providerId": providerID})
		return ctx.Redirect(errorRedirectURL(redirectURL, "invalid_saml_response", "Audience mismatch"))
	}
	return nil
}

func extractAssertionID(samlContent string) string {
	parsed, err := parseXMLObject(samlContent)
	if err != nil {
		return ""
	}
	resp := parsed.vals["Response"]
	if resp == nil {
		return ""
	}
	a := nodeChild(resp, "Assertion")
	if arr, ok := a.([]any); ok {
		if len(arr) == 0 {
			return ""
		}
		a = arr[0]
	}
	return nodeAttr(a, "ID")
}

// processSAMLResponse runs the ACS pipeline and returns the redirect URL.
func (p *plugin) processSAMLResponse(ctx *betterauth.EndpointContext, samlResponse, relayStateParam, providerID, callbackPath string, onErrorRedirect func(string)) (string, error) {
	o := p.o
	so := o.saml()
	c := ctx.Context()
	appOrigin := appOriginOf(ctx.Auth.BaseURL)
	maxSize := so.MaxResponseSize
	if maxSize == 0 {
		maxSize = DefaultMaxSAMLResponseSize
	}
	if len(samlResponse) > maxSize {
		return "", badRequest(fmt.Sprintf("SAML response exceeds maximum allowed size (%d bytes)", maxSize))
	}
	samlResponse = stripWhitespace(samlResponse)
	var relay *betterauth.StateData
	relayFailed := false
	if relayStateParam != "" {
		r, err := parseRelayState(ctx, relayStateParam)
		if err != nil {
			relayFailed = true
		} else {
			relay = r
		}
	}
	provider, err := findSAMLProvider(c, providerID, o, ctx.Auth.Adapter)
	if err != nil {
		return "", err
	}
	if provider == nil || provider.SAMLConfig == nil {
		return "", apiErr("NOT_FOUND", "message", "No SAML provider found")
	}
	if o.domainVerificationEnabled() && !isTrue(provider.DomainVerified) {
		return "", apiErr("UNAUTHORIZED", "message", "Provider domain has not been verified")
	}
	cfg := provider.SAMLConfig
	sp, err := createSP(cfg, ctx.Auth.BaseURL, providerID, &createSPOptions{clockSkew: so.ClockSkew})
	if err != nil {
		return "", err
	}
	idp, err := createIdP(cfg)
	if err != nil {
		return "", err
	}
	trusted := func(u string, allow bool) bool { return ctx.Auth.IsTrustedOrigin(u, allow) }
	relayCallback, relayError := "", ""
	if relay != nil {
		relayCallback, relayError = relay.CallbackURL, relay.ErrorURL
	}
	candidates := samlRedirectCandidates(relayCallback, cfg, so)
	redirectURL := GetSafeRedirectURL(candidates, callbackPath, appOrigin, trusted)
	errorURL := GetSafeRedirectURL([]string{relayError, redirectURL}, callbackPath, appOrigin, trusted)
	if onErrorRedirect != nil {
		onErrorRedirect(errorURL)
	}
	var stateRef *ProviderReference
	if relay != nil {
		stateRef = parseProviderReference(relay.ServerContext[SSOProviderStateKey])
	}
	if err := validateSingleAssertion(samlResponse); err != nil {
		return "", err
	}
	parsed, perr := sp.ParseLoginResponse(idp, samlResponse)
	if perr != nil {
		ctx.Auth.Logger.Error("SAML response validation failed")
		return "", badRequest("Invalid SAML response")
	}
	ex := parsed.Extract
	if err := validateSAMLAlgorithms(parsed.SigAlg, parsed.SAMLContent, so.Algorithms); err != nil {
		return "", err
	}
	var cond *SAMLConditions
	if ex.Conditions != nil {
		cond = &SAMLConditions{NotBefore: ex.Conditions["notBefore"], NotOnOrAfter: ex.Conditions["notOnOrAfter"]}
	}
	if err := ValidateSAMLTimestamp(cond, TimestampValidationOptions{ClockSkew: so.ClockSkew, RequireTimestamps: so.RequireTimestamps, Logger: ctx.Auth.Logger}); err != nil {
		return "", err
	}
	acs, _ := sp.Meta.GetAssertionConsumerService("post")
	audiences := []string{sp.Meta.GetEntityID(), cfg.Audience}
	recipients := append([]string{callbackPath, ctx.Auth.BaseURL + "/sso/saml2/sp/acs/" + providerID}, getSAMLPostAssertionConsumerServiceURLs(cfg.sp().Metadata)...)
	recipients = append(recipients, acs)
	policy, err := deriveSAMLServiceProviderPolicy(cfg)
	bindingContent := parsed.SAMLContent
	if err == nil {
		if hasSAMLEncryptedAssertion(bindingContent) {
			bindingContent, _, err = samlify.DecryptAssertion(sp, bindingContent)
		}
		if err == nil && policy.WantAssertionsSigned {
			err = verifySAMLAssertionSignature(bindingContent, idp.Meta)
		}
		if err == nil {
			err = validateSAMLResponseBinding(bindingContent, audiences, recipients)
		}
	}
	if err != nil {
		if ae, ok := betterauth.AsAPIError(err); ok {
			ctx.Auth.Logger.Error("SAML response binding validation failed", map[string]any{"providerId": providerID, "code": ae.Code()})
			return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, "error", "invalid_saml_response", "error_description", or(ae.Message(), "Invalid SAML response")))
		}
		ctx.Auth.Logger.Error("SAML response binding validation failed", map[string]any{"providerId": providerID})
		return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, "error", "invalid_saml_response", "error_description", "SAML response binding could not be validated"))
	}
	reqRef, err := p.validateInResponseTo(ctx, ex, providerID, errorURL)
	if err != nil {
		return "", err
	}
	if relayFailed {
		return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, "error", "invalid_state", "error_description", "invalid_or_expired_relay_state"))
	}
	if relay != nil && stateRef == nil {
		return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, "error", "invalid_state", "error_description", "sso_provider_reference_missing_or_invalid"))
	}
	if stateRef != nil && reqRef != nil && !sameProviderReference(stateRef, reqRef) {
		return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, "error", "invalid_state", "error_description", "sso_provider_reference_mismatch"))
	}
	ref := stateRef
	if ref == nil {
		ref = reqRef
	}
	if ref == nil {
		r := computeProviderReference(provider)
		ref = &r
	}
	if !isCurrentProviderReference(provider, ref) {
		return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, "error", "invalid_state", "error_description", "sso_provider_changed_during_authentication"))
	}
	if err := validateAudience(ctx, ex, or(cfg.Audience, sp.Meta.GetEntityID()), providerID, errorURL); err != nil {
		return "", err
	}
	issuer := idp.Meta.GetEntityID()
	if assertionID := extractAssertionID(bindingContent); assertionID != "" {
		skew := int64(DefaultClockSkewMS)
		if so.ClockSkew != nil {
			skew = *so.ClockSkew
		}
		expires := time.Now().Add(DefaultAssertionTTL * time.Millisecond)
		if na := ex.Conditions["notOnOrAfter"]; na != "" {
			if t, ok := samlify.ParseJSDate(na); ok {
				expires = t.Add(time.Duration(skew) * time.Millisecond)
			}
		}
		val := jsonx.O("assertionId", assertionID, "issuer", issuer, "providerId", providerID, "usedAt", float64(time.Now().UnixMilli()), "expiresAt", float64(expires.UnixMilli()))
		reserved, err := ctx.Auth.InternalAdapter.ReserveVerificationValue(c, UsedAssertionKeyPrefix+assertionID, string(jsonx.MustMarshal(val)), expires)
		if err != nil {
			return "", err
		}
		if !reserved {
			ctx.Auth.Logger.Error("SAML assertion replay detected: assertion ID already used", map[string]any{"assertionId": assertionID, "issuer": issuer, "providerId": providerID})
			return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, "error", "replay_detected", "error_description", "SAML assertion has already been used"))
		}
	} else {
		ctx.Auth.Logger.Warn("Could not extract assertion ID for replay protection", map[string]any{"providerId": providerID})
	}
	attributes := ex.Attributes
	if attributes == nil {
		attributes = map[string]any{}
	}
	providerAttributes := map[string]any{}
	for k, v := range attributes {
		providerAttributes[k] = v
	}
	mapping := cfg.Mapping
	if mapping == nil {
		mapping = &SAMLMapping{}
	}
	attr := func(key string) string {
		switch t := attributes[key].(type) {
		case string:
			return t
		case []string:
			if len(t) > 0 {
				return t[0]
			}
		}
		return ""
	}
	nameID := ex.NameID.Value
	userInfo := map[string]any{}
	extra := map[string]any{}
	for k, a := range mapping.ExtraFields {
		var v any = attributes[a]
		if _, ok := attributes[a]; !ok {
			v = nil
		}
		userInfo[k] = v
		extra[k] = v
	}
	email := strings.ToLower(or(attr(or(mapping.Email, "email")), nameID))
	var nameParts []string
	for _, s := range []string{attr(or(mapping.FirstName, "givenName")), attr(or(mapping.LastName, "surname"))} {
		if s != "" {
			nameParts = append(nameParts, s)
		}
	}
	name := or(strings.Join(nameParts, " "), or(attr(or(mapping.Name, "displayName")), nameID))
	emailVerified := false
	if o.TrustEmailVerified && mapping.EmailVerified != "" {
		emailVerified = parseProviderEmailVerified(attr(mapping.EmailVerified))
	}
	userInfo["id"] = nameID
	userInfo["email"] = email
	userInfo["name"] = name
	userInfo["emailVerified"] = emailVerified
	if nameID == "" || email == "" {
		names := make([]string, 0, len(attributes))
		for k := range attributes {
			names = append(names, k)
		}
		ctx.Auth.Logger.Error("Missing essential user info from SAML response", map[string]any{"providerId": providerID, "attributeNames": names})
		return "", badRequest("Unable to extract user ID or email from SAML response")
	}
	providerUser := ProviderUserProfile{Email: email, Name: or(name, email), EmailVerified: emailVerified, Extra: extra}
	if img, ok := extra["image"].(string); ok {
		providerUser.Image = img
	}
	trustedProvider := isTrue(provider.DomainVerified) && validateEmailDomain(email, provider.Domain)
	callbackURL := ctx.Auth.BaseURL
	for _, cnd := range candidates {
		if cnd != "" {
			callbackURL = redirectURL
			break
		}
	}
	falseV := false
	result, err := p.authenticate(ctx, provider, func(tx context.Context) (*SSOProvider, error) {
		return findSAMLProvider(tx, providerID, o, ctx.Auth.Adapter)
	}, ref, func() UserResolutionInput {
		return UserResolutionInput{Protocol: "saml", ProviderID: provider.ProviderID, AccountKey: AccountKey{Issuer: issuer, AccountID: nameID},
			ProviderUser: providerUser, ProviderReference: *ref, ProviderAttributes: providerAttributes}
	}, betterauth.HandleOAuthUserInfoOptions{
		UserInfo:            oauth2.UserInfo{Name: providerUser.Name, Email: email, Image: providerUser.Image, EmailVerified: emailVerified, Extra: extra},
		Account:             betterauth.OAuthAccountData{ProviderID: providerID, AccountID: nameID},
		CallbackURL:         callbackURL,
		DisableSignUp:       o.DisableImplicitSignUp,
		Source:              betterauth.UserInfoSource{Method: "sso-saml", ProviderID: providerID, Profile: attributes},
		IsTrustedProvider:   trustedProvider,
		TrustProviderByName: &falseV,
	})
	if err != nil {
		if ae, ok := betterauth.AsAPIError(err); ok && ae.Code() != "" && !betterauth.IsRedirect(err) {
			kv := []string{"error", ae.Code()}
			if ae.Message() != "" {
				kv = append(kv, "error_description", ae.Message())
			}
			return "", ctx.Redirect(buildSAMLRedirectURL(errorURL, kv...))
		}
		return "", err
	}
	if result.Error != "" {
		return "", ctx.Redirect(buildSAMLRedirectURL(callbackURL, "error", strings.Join(strings.Split(result.Error, " "), "_")))
	}
	session, user := result.Data.Session, result.Data.User
	if o.ProvisionUser != nil && (result.IsRegister || o.ProvisionUserOnEveryLogin) {
		if err := o.ProvisionUser(c, ProvisionUserData{User: user, UserInfo: userInfo, Provider: provider}); err != nil {
			return "", err
		}
	}
	if _, err := assignOrganization(ctx, assignOptions{reason: "provider-bound", user: user, provider: provider, provisioning: o.OrganizationProvisioning,
		profile: &normalizedProfile{ProviderType: "saml", ProviderID: providerID, AccountID: nameID, Email: email, EmailVerified: emailVerified, RawAttributes: attributes}}); err != nil {
		return "", err
	}
	if result.AccountCookie != nil {
		if err := betterauth.SetAccountCookie(ctx, result.AccountCookie); err != nil {
			return "", err
		}
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, nil, nil); err != nil {
		return "", err
	}
	if so.EnableSingleLogout && nameID != "" {
		key := SAMLSessionKeyPrefix + providerID + ":" + nameID
		rec := jsonx.O("sessionId", session.ID, "sessionToken", session.Token, "providerId", providerID, "nameID", nameID)
		if si := ex.SessionIndex["sessionIndex"]; si != "" {
			rec.Set("sessionIndex", si)
		}
		if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(c, key, string(jsonx.MustMarshal(rec)), session.ExpiresAt, nil); err != nil {
			ctx.Auth.Logger.Warn("Failed to create SAML session record", err)
		}
		if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(c, SAMLSessionByIDPrefix+session.ID, key, session.ExpiresAt, nil); err != nil {
			ctx.Auth.Logger.Warn("Failed to create SAML session lookup record", err)
		}
	}
	return redirectURL, nil
}

// ---- ACS ----

var formMediaTypes = []string{"application/x-www-form-urlencoded", "application/json"}

func (p *plugin) acsEndpoint() *betterauth.Endpoint {
	meta := endpointMeta("acsEndpoint", true)
	meta["allowedMediaTypes"] = formMediaTypes
	return &betterauth.Endpoint{
		Key: "acsEndpoint", Path: "/sso/saml2/sp/acs/:providerId", Methods: []string{"GET", "POST"},
		Body:              opt(validate.Object(validate.F("SAMLResponse", validate.String()), validate.F("RelayState", opt(validate.String())))),
		Query:             opt(validate.Object(validate.F("RelayState", opt(validate.String())))),
		AllowedMediaTypes: formMediaTypes, Metadata: meta,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			providerID := ctx.Params["providerId"]
			callbackPath := ctx.Auth.BaseURL + "/sso/saml2/sp/acs/" + providerID
			appOrigin := appOriginOf(ctx.Auth.BaseURL)
			trusted := func(u string, allow bool) bool { return ctx.Auth.IsTrustedOrigin(u, allow) }
			samlResponse := ctx.BodyString("SAMLResponse")
			if ctx.Method == "GET" && samlResponse == "" {
				session, err := betterauth.GetSessionFromCtx(ctx, nil)
				if err != nil {
					return nil, err
				}
				if session == nil || session.Session == nil {
					errURL := appOrigin + "/error"
					if ctx.Auth.Options.OnAPIError != nil && ctx.Auth.Options.OnAPIError.ErrorURL != "" {
						errURL = ctx.Auth.Options.OnAPIError.ErrorURL
					}
					return nil, redirectWithParams(ctx, errURL, "error", "invalid_request")
				}
				return nil, ctx.Redirect(GetSafeRedirectURL([]string{ctx.QueryString("RelayState")}, callbackPath, appOrigin, trusted))
			}
			if samlResponse == "" {
				return nil, badRequest("SAMLResponse is required for POST requests")
			}
			resolved := ""
			u, err := p.processSAMLResponse(ctx, samlResponse, ctx.BodyString("RelayState"), providerID, callbackPath, func(s string) { resolved = s })
			if err == nil {
				return nil, ctx.Redirect(u)
			}
			if betterauth.IsRedirect(err) {
				return nil, err
			}
			if ae, ok := betterauth.AsAPIError(err); ok && ae.StatusCode == 400 {
				code := strings.ToLower(or(ae.Code(), "saml_error"))
				redirect := resolved
				if redirect == "" {
					var cfg *SAMLConfig
					provider, perr := findSAMLProvider(ctx.Context(), providerID, p.o, ctx.Auth.Adapter)
					if perr != nil {
						ctx.Auth.Logger.Warn("Failed to resolve SAML provider for error redirect", map[string]any{"providerId": providerID})
					} else if provider != nil {
						cfg = provider.SAMLConfig
					}
					redirect = GetSafeRedirectURL(samlRedirectCandidates("", cfg, p.o.saml()), callbackPath, appOrigin, trusted)
				}
				return nil, ctx.Redirect(buildSAMLRedirectURL(redirect, "error", code, "error_description", ae.Message()))
			}
			return nil, err
		},
	}
}

// ---- SLO ----

func sloSchema() validate.Schema {
	return opt(validate.Object(
		validate.F("SAMLRequest", opt(validate.String())), validate.F("SAMLResponse", opt(validate.String())),
		validate.F("RelayState", opt(validate.String())), validate.F("SigAlg", opt(validate.String())), validate.F("Signature", opt(validate.String())),
	))
}

func stringValues(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out[k] = t
		case []any:
			if len(t) > 0 {
				if s, ok := t[0].(string); ok {
					out[k] = s
				}
			}
		case []string:
			if len(t) > 0 {
				out[k] = t[0]
			}
		}
	}
	return out
}

func (p *plugin) sloEndpoint() *betterauth.Endpoint {
	meta := map[string]any{"scope": "server", "allowedMediaTypes": formMediaTypes}
	return &betterauth.Endpoint{
		Key: "sloEndpoint", Path: "/sso/saml2/sp/slo/:providerId", Methods: []string{"GET", "POST"},
		Body: sloSchema(), Query: sloSchema(), AllowedMediaTypes: formMediaTypes, Metadata: meta,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !p.o.saml().EnableSingleLogout {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrSingleLogoutNotEnabled)
			}
			providerID := ctx.Params["providerId"]
			body := stringValues(ctx.BodyMap())
			query := stringValues(ctx.Query)
			samlRequest := or(body["SAMLRequest"], query["SAMLRequest"])
			samlResponse := or(body["SAMLResponse"], query["SAMLResponse"])
			relayState := or(body["RelayState"], query["RelayState"])
			appOrigin := appOriginOf(ctx.Auth.BaseURL)
			trusted := func(u string, allow bool) bool { return ctx.Auth.IsTrustedOrigin(u, allow) }
			sloPath := appOrigin + "/sso/saml2/sp/slo/" + providerID
			safeErr := GetSafeRedirectURL([]string{relayState}, sloPath, appOrigin, trusted)
			if samlRequest == "" && samlResponse == "" {
				return nil, redirectWithParams(ctx, safeErr, "error", "invalid_request", "error_description", "missing_logout_data")
			}
			provider, err := findSAMLProvider(ctx.Context(), providerID, p.o, ctx.Auth.Adapter)
			if err != nil {
				return nil, err
			}
			if provider == nil || provider.SAMLConfig == nil {
				return nil, betterauth.ErrFrom("NOT_FOUND", ErrSAMLProviderNotFound)
			}
			sp, err := createSP(provider.SAMLConfig, ctx.Auth.BaseURL, providerID, &createSPOptions{slo: p.sloOpts()})
			if err != nil {
				return nil, err
			}
			idp, err := createIdP(provider.SAMLConfig)
			if err != nil {
				return nil, err
			}
			req := samlify.RequestInfo{Body: body, Query: query}
			if samlResponse != "" {
				binding := "redirect"
				if ctx.Method == "POST" && body["SAMLResponse"] != "" {
					binding = "post"
				}
				parsed, err := sp.ParseLogoutResponse(idp, binding, req)
				if err != nil {
					ctx.Auth.Logger.Error("LogoutResponse validation failed", map[string]any{"error": err.Error()})
					return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidLogoutResponse)
				}
				if status := samlify.StatusOf(parsed.SAMLContent); status != "" && status != SAMLStatusSuccess {
					ctx.Auth.Logger.Warn("LogoutResponse indicates failure", map[string]any{"statusCode": status})
					return nil, betterauth.ErrFrom("BAD_REQUEST", ErrLogoutFailedAtIdP)
				}
				if irt := parsed.Extract.Response["inResponseTo"]; irt != "" {
					key := LogoutRequestKeyPrefix + irt
					pending, _ := ctx.Auth.InternalAdapter.FindVerificationValue(ctx.Context(), key)
					if pending == nil {
						ctx.Auth.Logger.Warn("LogoutResponse references unknown or expired request", map[string]any{"inResponseTo": irt})
					}
					if err := ctx.Auth.InternalAdapter.DeleteVerificationByIdentifier(ctx.Context(), key); err != nil {
						ctx.Auth.Logger.Warn("Failed to delete logout request verification value", err)
					}
				}
				betterauth.DeleteSessionCookie(ctx, false)
				return nil, ctx.Redirect(GetSafeRedirectURL([]string{relayState}, sloPath, appOrigin, trusted))
			}
			binding := "redirect"
			if ctx.Method == "POST" && body["SAMLRequest"] != "" {
				binding = "post"
			}
			parsed, err := sp.ParseLogoutRequest(idp, binding, req)
			if err != nil {
				ctx.Auth.Logger.Error("LogoutRequest validation failed", map[string]any{"error": err.Error()})
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrInvalidLogoutRequest)
			}
			ia := ctx.Auth.InternalAdapter
			c := ctx.Context()
			nameID := parsed.Extract.NameID.Value
			sessionIndex := parsed.Extract.LogoutSessionIndex.Value
			key := SAMLSessionKeyPrefix + providerID + ":" + nameID
			stored, _ := ia.FindVerificationValue(c, key)
			if stored != nil {
				if v, err := jsonx.Parse([]byte(stored.Value)); err == nil {
					if obj, ok := v.(*jsonx.Object); ok {
						data := obj.Map()
						storedIdx, _ := data["sessionIndex"].(string)
						if sessionIndex == "" || storedIdx == "" || sessionIndex == storedIdx {
							if tok, _ := data["sessionToken"].(string); tok != "" {
								if err := ia.DeleteSession(c, tok); err != nil {
									ctx.Auth.Logger.Warn("Failed to delete session during SLO", map[string]any{"error": err.Error()})
								}
							}
							sid, _ := data["sessionId"].(string)
							if err := ia.DeleteVerificationByIdentifier(c, SAMLSessionByIDPrefix+sid); err != nil {
								ctx.Auth.Logger.Warn("Failed to delete SAML session lookup during SLO", err)
							}
						} else {
							ctx.Auth.Logger.Warn("SessionIndex mismatch in LogoutRequest - skipping session deletion",
								map[string]any{"providerId": providerID, "requestedSessionIndex": sessionIndex, "storedSessionIndex": storedIdx})
						}
					}
				}
				if err := ia.DeleteVerificationByIdentifier(c, key); err != nil {
					ctx.Auth.Logger.Warn("Failed to delete SAML session key during SLO", err)
				}
			}
			current, _ := betterauth.GetSessionFromCtx(ctx, nil)
			if current != nil && current.Session != nil {
				if err := ia.DeleteSession(c, current.Session.Token); err != nil {
					return nil, err
				}
			}
			betterauth.DeleteSessionCookie(ctx, false)
			res, err := sp.CreateLogoutResponse(idp, parsed.Extract.Request["id"], binding, relayState)
			if err != nil {
				return nil, err
			}
			if binding == "post" && res.EntityEndpoint != "" {
				return createSAMLPostForm(res.EntityEndpoint, "SAMLResponse", res.Context, relayState)
			}
			return nil, ctx.Redirect(res.Context)
		},
	}
}

func (p *plugin) initiateSLO() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "initiateSLO", Path: "/sso/saml2/logout/:providerId", Methods: []string{"POST"},
		Body: validate.Object(validate.F("callbackURL", opt(validate.String()))), Use: []betterauth.Middleware{betterauth.SessionMiddleware},
		Metadata: map[string]any{"scope": "server"},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !p.o.saml().EnableSingleLogout {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrSingleLogoutNotEnabled)
			}
			providerID := ctx.Params["providerId"]
			// upstream passes callbackURL inside the logout "user" object, where samlify
			// ignores it: no RelayState is sent.
			_ = or(ctx.BodyString("callbackURL"), ctx.Auth.BaseURL)
			c := ctx.Context()
			provider, err := findSAMLProvider(c, providerID, p.o, ctx.Auth.Adapter)
			if err != nil {
				return nil, err
			}
			if provider == nil || provider.SAMLConfig == nil {
				return nil, betterauth.ErrFrom("NOT_FOUND", ErrSAMLProviderNotFound)
			}
			cfg := provider.SAMLConfig
			if len(cfg.idp().SingleLogoutService) == 0 && !strings.Contains(cfg.idp().Metadata, "SingleLogoutService") {
				return nil, betterauth.ErrFrom("BAD_REQUEST", ErrIdPSLONotSupported)
			}
			sp, err := createSP(cfg, ctx.Auth.BaseURL, providerID, &createSPOptions{slo: p.sloOpts()})
			if err != nil {
				return nil, err
			}
			idp, err := createIdP(cfg)
			if err != nil {
				return nil, err
			}
			ia := ctx.Auth.InternalAdapter
			session := ctx.Session
			lookupKey := SAMLSessionByIDPrefix + session.Session.ID
			lookup, err := ia.FindVerificationValue(c, lookupKey)
			if err != nil {
				return nil, err
			}
			nameID := session.User.Email
			sessionIndex := ""
			samlKey := ""
			if lookup != nil {
				samlKey = lookup.Value
				if stored, _ := ia.FindVerificationValue(c, samlKey); stored != nil {
					if v, err := jsonx.Parse([]byte(stored.Value)); err == nil {
						if obj, ok := v.(*jsonx.Object); ok {
							data := obj.Map()
							if n, _ := data["nameID"].(string); n != "" {
								nameID = n
							}
							sessionIndex, _ = data["sessionIndex"].(string)
						}
					}
				}
			}
			req, err := sp.CreateLogoutRequest(idp, "redirect", samlify.LogoutUser{LogoutNameID: nameID, SessionIndex: sessionIndex}, "")
			if err != nil {
				return nil, err
			}
			ttl := p.o.saml().LogoutRequestTTL
			if ttl == 0 {
				ttl = DefaultLogoutRequestTTL
			}
			if _, err := ia.CreateVerificationValue(c, LogoutRequestKeyPrefix+req.ID, providerID, time.Now().Add(time.Duration(ttl)*time.Millisecond), nil); err != nil {
				return nil, err
			}
			if samlKey != "" {
				if err := ia.DeleteVerificationByIdentifier(c, samlKey); err != nil {
					ctx.Auth.Logger.Warn("Failed to delete SAML session key during logout", err)
				}
			}
			if err := ia.DeleteVerificationByIdentifier(c, lookupKey); err != nil {
				ctx.Auth.Logger.Warn("Failed to delete session lookup key during logout", err)
			}
			if err := ia.DeleteSession(c, session.Session.Token); err != nil {
				return nil, err
			}
			betterauth.DeleteSessionCookie(ctx, false)
			return nil, ctx.Redirect(req.Context)
		},
	}
}
