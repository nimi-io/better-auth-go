package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/validate"
)

var builtInAccountProviderIDs = []string{"credential", "email-otp", "magic-link", "phone-number", "anonymous", "siwe"}

var defaultOIDCScopes = []string{"openid", "email", "profile", "offline_access"}

func isTrustedFn(ctx *betterauth.EndpointContext) func(string) bool {
	return func(u string) bool { return ctx.Auth.IsTrustedOrigin(u, false) }
}

func getOIDCRedirectURI(baseURL, providerID string, o *Options) string {
	if strings.TrimSpace(o.RedirectURI) != "" {
		if u, err := url.Parse(o.RedirectURI); err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "") {
			return o.RedirectURI
		}
		path := o.RedirectURI
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return baseURL + path
	}
	return baseURL + "/sso/callback/" + providerID
}

func discoveryAPIError(err error) error {
	var de *DiscoveryError
	if errors.As(err, &de) {
		return mapDiscoveryErrorToAPIError(de)
	}
	return err
}

// ---- sp metadata ----

func (p *plugin) sloOpts() *sloOptions {
	s := p.o.saml()
	return &sloOptions{wantLogoutRequestSigned: s.WantLogoutRequestSigned, wantLogoutResponseSigned: s.WantLogoutResponseSigned}
}

func (p *plugin) spMetadata() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "spMetadata", Path: "/sso/saml2/sp/metadata", Methods: []string{"GET"},
		Query: validate.Object(validate.F("providerId", validate.String())), Metadata: endpointMeta("spMetadata", false),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			pid := ctx.QueryString("providerId")
			provider, err := findSAMLProvider(ctx.Context(), pid, p.o, ctx.Auth.Adapter)
			if err != nil {
				return nil, err
			}
			if provider == nil {
				return nil, apiErr("NOT_FOUND", "message", "No provider found for the given providerId")
			}
			if provider.SAMLConfig == nil {
				return nil, badRequest("Invalid SAML configuration")
			}
			var slo *sloOptions
			if p.o.saml().EnableSingleLogout {
				slo = p.sloOpts()
			}
			sp, err := createSP(provider.SAMLConfig, ctx.Auth.BaseURL, pid, &createSPOptions{slo: slo})
			if err != nil {
				return nil, err
			}
			h := http.Header{}
			h.Set("Content-Type", "application/xml")
			return &betterauth.Response{Status: 200, Header: h, Body: []byte(sp.GetMetadata())}, nil
		},
	}
}

// ---- register ----

func recordJSON(rec adapter.Record, o *Options) *jsonx.Object {
	out := jsonx.NewObject()
	hidden := map[string]bool{}
	for _, f := range o.additionalFields() {
		if !f.IsReturned() {
			hidden[f.Name] = true
		}
	}
	order := []string{"id", "issuer", "oidcConfig", "samlConfig", "userId", "providerId", "organizationId", "domain", "domainVerified"}
	for _, f := range o.additionalFields() {
		order = append(order, f.Name)
	}
	seen := map[string]bool{}
	for _, k := range order {
		seen[k] = true
		if hidden[k] {
			continue
		}
		if v, ok := rec[k]; ok {
			out.Set(k, v)
		} else if k == "organizationId" {
			out.Set(k, nil)
		}
	}
	for k, v := range rec {
		if !seen[k] && !hidden[k] {
			out.Set(k, v)
		}
	}
	return out
}

func parsedConfigJSON(raw string) any {
	if raw == "" {
		return nil
	}
	v, err := jsonx.Parse([]byte(raw))
	if err != nil {
		return nil
	}
	return v
}

func (p *plugin) registerSSOProvider() *betterauth.Endpoint {
	o := p.o
	return &betterauth.Endpoint{
		Key: "registerSSOProvider", Path: "/sso/register", Methods: []string{"POST"},
		Body: registerBodySchema(o), Use: []betterauth.Middleware{betterauth.SessionMiddleware}, Metadata: endpointMeta("registerSSOProvider", false),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if ctx.Session == nil || ctx.Session.User == nil {
				return nil, betterauth.ErrStatus("UNAUTHORIZED")
			}
			user := ctx.Session.User
			c := ctx.Context()
			a := ctx.Auth.Adapter
			limit := 10
			if o.ProvidersLimitFunc != nil {
				l, err := o.ProvidersLimitFunc(c, user)
				if err != nil {
					return nil, err
				}
				limit = l
			} else if o.ProvidersLimit != nil {
				limit = *o.ProvidersLimit
			}
			if limit == 0 {
				return nil, apiErr("FORBIDDEN", "message", "SSO provider registration is disabled")
			}
			providers, err := a.FindMany(c, adapter.FindManyInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "userId", Value: user.ID}}})
			if err != nil {
				return nil, err
			}
			if len(providers) >= limit {
				return nil, apiErr("FORBIDDEN", "message", "You have reached the maximum number of SSO providers")
			}
			body := ctx.BodyMap()
			additional, err := parseAdditionalFields(o, body, "create")
			if err != nil {
				return nil, err
			}
			providerID, _ := body["providerId"].(string)
			issuer, _ := body["issuer"].(string)
			domain, _ := body["domain"].(string)
			orgID, _ := body["organizationId"].(string)
			overrideUserInfo, _ := body["overrideUserInfo"].(bool)
			samlBody, hasSAML := body["samlConfig"].(map[string]any)
			oidcBody, hasOIDC := body["oidcConfig"].(map[string]any)
			maxSize := o.saml().MaxMetadataSize
			if maxSize == 0 {
				maxSize = DefaultMaxSAMLMetadataSize
			}
			var samlCfg *SAMLConfig
			if hasSAML {
				samlCfg, err = decodeInto[SAMLConfig](samlBody)
				if err != nil {
					return nil, err
				}
				samlCfg.Issuer = issuer
				if err := assertSAMLMetadataSize(samlCfg.idp().Metadata, "IdP", maxSize); err != nil {
					return nil, err
				}
				if err := assertSAMLMetadataSize(samlCfg.sp().Metadata, "SP", maxSize); err != nil {
					return nil, err
				}
			}
			if orgID != "" {
				member, err := a.FindOne(c, adapter.FindOneInput{Model: "member", Where: []adapter.Where{{Field: "userId", Value: user.ID}, {Field: "organizationId", Value: orgID}}})
				if err != nil {
					return nil, err
				}
				if member == nil {
					return nil, badRequest("You are not a member of the organization")
				}
				if ctx.Auth.HasPlugin("organization") && !hasOrgAdminRole(recString(member, "role")) {
					return nil, apiErr("FORBIDDEN", "message", "You must be an organization owner or admin to register SSO providers")
				}
			}
			reserved := append([]string(nil), builtInAccountProviderIDs...)
			for _, sp := range ctx.Auth.Options.SocialProviders {
				reserved = append(reserved, sp.ID())
			}
			for _, sp := range ctx.Auth.SocialProviders {
				reserved = append(reserved, sp.ID())
			}
			reserved = append(reserved, ctx.Auth.TrustedProviders...)
			for _, d := range o.DefaultSSO {
				reserved = append(reserved, d.ProviderID)
			}
			if inList(reserved, providerID) {
				ctx.Auth.Logger.Warn("SSO provider registration rejected for reserved providerId: " + providerID)
				return nil, apiErr("UNPROCESSABLE_ENTITY", "message", "This providerId is reserved and cannot be used for an SSO provider")
			}
			existing, err := findProviderRecord(c, a, providerID)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				ctx.Auth.Logger.Info("SSO provider creation attempt with existing providerId: " + providerID)
				return nil, apiErr("UNPROCESSABLE_ENTITY", "message", "SSO provider with this providerId already exists")
			}
			var oidcIn *OIDCConfig
			skipDiscovery := false
			if hasOIDC {
				oidcIn, err = decodeInto[OIDCConfig](oidcBody)
				if err != nil {
					return nil, err
				}
				skipDiscovery, _ = oidcBody["skipDiscovery"].(bool)
				if err := validateOIDCEndpointURLs(oidcEndpointURLs{AuthorizationEndpoint: oidcIn.AuthorizationEndpoint, TokenEndpoint: oidcIn.TokenEndpoint,
					UserInfoEndpoint: oidcIn.UserInfoEndpoint, JwksEndpoint: oidcIn.JwksEndpoint, DiscoveryEndpoint: oidcIn.DiscoveryEndpoint}, isTrustedFn(ctx)); err != nil {
					return nil, discoveryAPIError(err)
				}
			}
			var hydrated *HydratedOIDCConfig
			if hasOIDC && !skipDiscovery {
				hydrated, err = discoverOIDCConfig(c, DiscoverOIDCConfigParams{Issuer: issuer, ExistingConfig: &HydratedOIDCConfig{
					DiscoveryEndpoint: oidcIn.DiscoveryEndpoint, AuthorizationEndpoint: oidcIn.AuthorizationEndpoint, TokenEndpoint: oidcIn.TokenEndpoint,
					JwksEndpoint: oidcIn.JwksEndpoint, UserInfoEndpoint: oidcIn.UserInfoEndpoint, TokenEndpointAuthentication: oidcIn.TokenEndpointAuthentication,
				}, IsTrustedOrigin: isTrustedFn(ctx)})
				if err != nil {
					return nil, discoveryAPIError(err)
				}
			}
			override := overrideUserInfo || o.DefaultOverrideUserInfo
			var oidcStored *OIDCConfig
			if hasOIDC {
				c := &OIDCConfig{ClientID: oidcIn.ClientID, ClientSecret: oidcIn.ClientSecret, PrivateKeyID: oidcIn.PrivateKeyID,
					PrivateKeyAlgorithm: oidcIn.PrivateKeyAlgorithm, PKCE: oidcIn.PKCE, Mapping: oidcIn.Mapping, Scopes: oidcIn.Scopes, OverrideUserInfo: override}
				if skipDiscovery {
					c.Issuer = issuer
					c.AuthorizationEndpoint, c.TokenEndpoint, c.JwksEndpoint, c.UserInfoEndpoint = oidcIn.AuthorizationEndpoint, oidcIn.TokenEndpoint, oidcIn.JwksEndpoint, oidcIn.UserInfoEndpoint
					c.TokenEndpointAuthentication = oidcIn.TokenEndpointAuthentication
					if c.TokenEndpointAuthentication == "" {
						c.TokenEndpointAuthentication = "client_secret_basic"
					}
					c.DiscoveryEndpoint = oidcIn.DiscoveryEndpoint
					if c.DiscoveryEndpoint == "" {
						c.DiscoveryEndpoint = issuer + "/.well-known/openid-configuration"
					}
				} else if hydrated != nil {
					c.Issuer = hydrated.Issuer
					c.AuthorizationEndpoint, c.TokenEndpoint, c.JwksEndpoint, c.UserInfoEndpoint = hydrated.AuthorizationEndpoint, hydrated.TokenEndpoint, hydrated.JwksEndpoint, hydrated.UserInfoEndpoint
					c.TokenEndpointAuthentication = hydrated.TokenEndpointAuthentication
					c.DiscoveryEndpoint = hydrated.DiscoveryEndpoint
				}
				oidcStored = c
			}
			if samlCfg != nil {
				if err := validateConfigAlgorithms(samlCfg.SignatureAlgorithm, samlCfg.DigestAlgorithm, o.saml().Algorithms); err != nil {
					return nil, err
				}
				if err := validateCertSources(samlCfg); err != nil {
					return nil, err
				}
				if err := assertSAMLIdentityProviderAuthority(samlCfg); err != nil {
					return nil, err
				}
				if err := assertSAMLServiceProviderMetadataPolicy(samlCfg); err != nil {
					return nil, err
				}
				hasEntry := false
				if samlCfg.EntryPoint != "" {
					if u, err := url.Parse(samlCfg.EntryPoint); err == nil && u.Scheme != "" {
						hasEntry = true
					}
				}
				if samlCfg.idp().Metadata == "" && !hasEntry && len(samlCfg.idp().SingleSignOnService) == 0 {
					return nil, badRequest("SAML configuration requires either idpMetadata.metadata (IdP metadata XML), idpMetadata.singleSignOnService, or a valid entryPoint URL")
				}
			}
			data := adapter.Record{"issuer": issuer, "domain": domain}
			if o.domainVerificationEnabled() {
				data["domainVerified"] = false
			}
			for k, v := range additional {
				data[k] = v
			}
			if oidcStored != nil {
				if oidcStored.TokenEndpointAuthentication != "private_key_jwt" && oidcStored.ClientSecret == "" {
					return nil, badRequest("clientSecret is required when using client_secret_basic or client_secret_post authentication")
				}
				if oidcStored.TokenEndpointAuthentication == "private_key_jwt" && o.ResolvePrivateKey == nil && !o.hasDefaultPrivateKey(providerID) {
					return nil, badRequest("private_key_jwt authentication requires either a resolvePrivateKey callback or a privateKey in defaultSSO")
				}
				data["oidcConfig"] = mustJSON(oidcStored)
			} else {
				data["oidcConfig"] = nil
			}
			if samlCfg != nil {
				data["samlConfig"] = mustJSON(samlCfg)
			} else {
				data["samlConfig"] = nil
			}
			if orgID != "" {
				data["organizationId"] = orgID
			}
			data["userId"] = user.ID
			data["providerId"] = providerID
			created, err := a.Create(c, adapter.CreateInput{Model: "ssoProvider", Data: data})
			if err != nil {
				return nil, err
			}
			var token string
			if o.domainVerificationEnabled() {
				token = generateRandomString(24)
				if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(c, verificationIdentifier(o, recString(created, "providerId")), token, time.Now().Add(7*24*time.Hour), nil); err != nil {
					return nil, err
				}
			}
			out := recordJSON(created, o)
			out.Set("oidcConfig", parsedConfigJSON(recString(created, "oidcConfig")))
			out.Set("samlConfig", parsedConfigJSON(recString(created, "samlConfig")))
			out.Set("redirectURI", getOIDCRedirectURI(ctx.Auth.BaseURL, recString(created, "providerId"), o))
			if o.domainVerificationEnabled() {
				out.Set("domainVerified", false)
				out.Set("domainVerificationToken", token)
			}
			return out, nil
		},
	}
}

// ---- sign in ----

var signInBody = validate.Object(
	validate.F("email", opt(d(validate.String(), "The email address to sign in with. Used to resolve the provider via the email domain; optional if providerId, domain, or organizationSlug is provided."))),
	validate.F("organizationSlug", opt(d(validate.String(), "The slug of the organization to sign in with."))),
	validate.F("providerId", opt(d(validate.String(), "The ID of the provider to sign in with. Can be provided instead of email."))),
	validate.F("domain", opt(d(validate.String(), "The email domain of the provider. Can be provided instead of email."))),
	validate.F("callbackURL", d(validate.String(), "The URL to redirect to after successful sign-in.")),
	validate.F("errorCallbackURL", opt(d(validate.String(), "The URL to redirect to if the sign-in flow fails."))),
	validate.F("newUserCallbackURL", opt(d(validate.String(), "The URL to redirect to after sign-in if the user is newly registered."))),
	validate.F("scopes", opt(d(validate.Array(validate.String()), "Scopes to request from the provider."))),
	validate.F("loginHint", opt(d(validate.String(), "Login hint to send to the identity provider (e.g., email or identifier). If supported, sent as 'login_hint'."))),
	validate.F("additionalParams", betterauth.SSOAdditionalParamsSchema),
	validate.F("requestSignUp", opt(d(validate.Boolean(), "Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider."))),
	validate.F("providerType", opt(d(validate.Enum("oidc", "saml"), "The provider protocol to sign in with."))),
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

func stringMapOf(v any) map[string]string {
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

func (p *plugin) providerFromDB(ctx context.Context, a adapter.Adapter, where adapter.Where) (*SSOProvider, error) {
	rec, err := a.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{where}})
	if err != nil || rec == nil {
		return nil, err
	}
	pr, oerr, serr := providerFromRecord(rec)
	if oerr != nil {
		return nil, oerr
	}
	if serr != nil {
		return nil, serr
	}
	return pr, nil
}

func (p *plugin) signInSSO() *betterauth.Endpoint {
	o := p.o
	return &betterauth.Endpoint{
		Key: "signInSSO", Path: "/sign-in/sso", Methods: []string{"POST"}, Body: signInBody, Metadata: endpointMeta("signInSSO", false),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			c := ctx.Context()
			a := ctx.Auth.Adapter
			email := ctx.BodyString("email")
			orgSlug := ctx.BodyString("organizationSlug")
			providerID := ctx.BodyString("providerId")
			domain := ctx.BodyString("domain")
			providerType := ctx.BodyString("providerType")
			if len(o.DefaultSSO) == 0 && email == "" && orgSlug == "" && domain == "" && providerID == "" {
				return nil, badRequest("email, organizationSlug, domain or providerId is required")
			}
			if domain == "" && email != "" {
				if parts := strings.Split(email, "@"); len(parts) > 1 {
					domain = parts[1]
				}
			}
			orgID := ""
			if orgSlug != "" {
				org, err := a.FindOne(c, adapter.FindOneInput{Model: "organization", Where: []adapter.Where{{Field: "slug", Value: orgSlug}}})
				if err != nil {
					return nil, err
				}
				if org != nil {
					orgID = recString(org, "id")
				}
			}
			var provider *SSOProvider
			if len(o.DefaultSSO) > 0 {
				var match *DefaultSSOProvider
				for i := range o.DefaultSSO {
					dp := &o.DefaultSSO[i]
					if providerID != "" {
						if dp.ProviderID == providerID {
							match = dp
							break
						}
					} else if domain != "" && domainMatches(domain, dp.Domain) {
						match = dp
						break
					}
				}
				if match != nil {
					issuer := ""
					if match.SAMLConfig != nil && match.SAMLConfig.Issuer != "" {
						issuer = match.SAMLConfig.Issuer
					} else if match.OIDCConfig != nil {
						issuer = match.OIDCConfig.Issuer
					}
					provider = defaultProvider(*match, issuer, o.domainVerificationEnabled())
				}
			}
			if providerID == "" && orgID == "" && domain == "" {
				return nil, badRequest("providerId, orgId or domain is required")
			}
			if provider == nil {
				var err error
				if providerID != "" || orgID != "" {
					w := adapter.Where{Field: "providerId", Value: providerID}
					if providerID == "" {
						w = adapter.Where{Field: "organizationId", Value: orgID}
					}
					provider, err = p.providerFromDB(c, a, w)
				} else if domain != "" {
					provider, err = p.providerFromDB(c, a, adapter.Where{Field: "domain", Value: domain})
					if err == nil && provider == nil {
						all, ferr := a.FindMany(c, adapter.FindManyInput{Model: "ssoProvider"})
						if ferr != nil {
							return nil, ferr
						}
						for _, r := range all {
							if domainMatches(domain, recString(r, "domain")) {
								pr, oerr, serr := providerFromRecord(r)
								if oerr != nil {
									return nil, oerr
								}
								if serr != nil {
									return nil, serr
								}
								provider = pr
								break
							}
						}
					}
				}
				if err != nil {
					return nil, err
				}
			}
			if provider == nil {
				return nil, apiErr("NOT_FOUND", "message", "No provider found for the issuer")
			}
			if providerType == "oidc" && provider.OIDCConfig == nil {
				return nil, badRequest("OIDC provider is not configured")
			}
			if providerType == "saml" && provider.SAMLConfig == nil {
				return nil, badRequest("SAML provider is not configured")
			}
			if o.domainVerificationEnabled() && !isTrue(provider.DomainVerified) {
				return nil, apiErr("UNAUTHORIZED", "message", "Provider domain has not been verified")
			}
			if provider.OIDCConfig != nil && providerType != "saml" {
				cfg, err := ensureRuntimeDiscovery(c, provider.OIDCConfig, provider.Issuer, isTrustedFn(ctx))
				if err != nil {
					return nil, discoveryAPIError(err)
				}
				if cfg.AuthorizationEndpoint == "" {
					return nil, badRequest("Invalid OIDC configuration. Authorization URL not found.")
				}
				ref := computeProviderReference(provider)
				betterauth.AddOAuthServerContext(c, map[string]any{SSOProviderStateKey: ref.toServerContext()})
				state, verifier, err := betterauth.GenerateState(ctx, nil)
				if err != nil {
					return nil, err
				}
				scopes := stringList(ctx.BodyMap()["scopes"])
				if _, has := ctx.BodyMap()["scopes"]; !has {
					scopes = cfg.Scopes
					if scopes == nil {
						scopes = defaultOIDCScopes
					}
				}
				loginHint := ctx.BodyString("loginHint")
				if loginHint == "" {
					loginHint = email
				}
				ao := oauth2.AuthorizationURLOptions{ID: provider.Issuer, ClientID: cfg.ClientID, AuthorizationEndpoint: cfg.AuthorizationEndpoint,
					RedirectURI: getOIDCRedirectURI(ctx.Auth.BaseURL, provider.ProviderID, o), State: state, Scopes: scopes, LoginHint: loginHint,
					AdditionalParams: stringMapOf(ctx.BodyMap()["additionalParams"]), AdditionalParamsOrder: betterauth.SSOAdditionalParamsOrder(ctx)}
				if cfg.PKCE {
					ao.CodeVerifier = verifier
				}
				u, err := oauth2.CreateAuthorizationURL(ao)
				if err != nil {
					return nil, err
				}
				return jsonx.O("url", u.String(), "redirect", true), nil
			}
			if provider.SAMLConfig != nil {
				if _, has := ctx.BodyMap()["additionalParams"]; has {
					return nil, badRequest("additionalParams is not supported for SAML providers; the SAML AuthnRequest is signed and cannot carry caller-supplied query parameters.")
				}
				cfg := provider.SAMLConfig
				if isTrue(cfg.AuthnRequestsSigned) && cfg.sp().PrivateKey == "" && cfg.PrivateKey == "" {
					return nil, badRequest("authnRequestsSigned is enabled but no privateKey provided in spMetadata or samlConfig")
				}
				ref := computeProviderReference(provider)
				relayState, err := generateRelayState(ctx, ref)
				if err != nil {
					return nil, err
				}
				sp, err := createSP(cfg, ctx.Auth.BaseURL, provider.ProviderID, &createSPOptions{relayState: relayState})
				if err != nil {
					return nil, err
				}
				idp, err := createIdP(cfg)
				if err != nil {
					return nil, err
				}
				req, err := sp.CreateLoginRequest(idp, "redirect", relayState)
				if err != nil {
					return nil, err
				}
				if req.ID != "" && (o.saml().EnableInResponseToValidation == nil || *o.saml().EnableInResponseToValidation) {
					ttl := o.saml().RequestTTL
					if ttl == 0 {
						ttl = DefaultAuthnRequestTTL
					}
					now := time.Now()
					exp := now.Add(time.Duration(ttl) * time.Millisecond)
					record := jsonx.O("id", req.ID, "providerId", provider.ProviderID, "providerReference", ref.jsonObject(),
						"createdAt", float64(now.UnixMilli()), "expiresAt", float64(exp.UnixMilli()))
					if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(c, AuthnRequestKeyPrefix+req.ID, string(jsonx.MustMarshal(record)), exp, nil); err != nil {
						return nil, err
					}
				}
				return jsonx.O("url", req.Context, "redirect", true), nil
			}
			return nil, badRequest("Invalid SSO provider")
		},
	}
}

// ---- OIDC callback ----

func getStringErrorField(v any, field string) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	s, _ := m[field].(string)
	return s
}

func getOIDCErrorDescription(errObj map[string]any, fallback string) string {
	nested := errObj["error"]
	for _, s := range []string{getStringErrorField(nested, "error_description"), getStringErrorField(errObj, "error_description"),
		getStringErrorField(nested, "message"), getStringErrorField(errObj, "message"), getStringErrorField(errObj, "statusText"),
		getStringErrorField(nested, "error"), getStringErrorField(errObj, "error")} {
		if s != "" {
			return s
		}
	}
	if st, ok := errObj["status"].(int); ok {
		return fmt.Sprintf("HTTP %d", st)
	}
	return fallback
}

func fetchErrorObject(fe *fetchError) map[string]any {
	m := map[string]any{"status": fe.Status, "statusText": fe.StatusText}
	for k, v := range fe.Body {
		m[k] = v
	}
	return m
}

func errorPageURL(ctx *betterauth.EndpointContext) string {
	if ctx.Auth.Options.OnAPIError != nil && ctx.Auth.Options.OnAPIError.ErrorURL != "" {
		return ctx.Auth.Options.OnAPIError.ErrorURL
	}
	return ctx.Auth.BaseURL + "/error"
}

func redirectWithParams(ctx *betterauth.EndpointContext, base string, kv ...string) error {
	vals := url.Values{}
	var order []string
	for i := 0; i+1 < len(kv); i += 2 {
		vals.Set(kv[i], kv[i+1])
		order = append(order, kv[i])
	}
	u, err := betterauth.OAuthProxyAppendQueryParams(base, vals, order)
	if err != nil {
		return err
	}
	return ctx.Redirect(u)
}

func (p *plugin) resolveOIDCProvider(ctx context.Context, a adapter.Adapter, providerID string) (*SSOProvider, error) {
	if def := p.o.findDefault(providerID); def != nil {
		issuer := ""
		if def.OIDCConfig != nil {
			issuer = def.OIDCConfig.Issuer
		}
		return defaultProvider(*def, issuer, p.o.domainVerificationEnabled()), nil
	}
	rec, err := findProviderRecord(ctx, a, providerID)
	if err != nil || rec == nil {
		return nil, err
	}
	pr, _, _ := providerFromRecord(rec)
	return pr, nil
}

func readStringClaim(claims map[string]any, claim string) string {
	s, _ := claims[claim].(string)
	return s
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (p *plugin) tokenRequest(ctx *betterauth.EndpointContext, provider *SSOProvider, cfg *OIDCConfig, code, verifier string) (*oauth2.Tokens, error, string) {
	o := p.o
	form := url.Values{}
	var order []string
	set := func(k, v string) {
		form.Set(k, v)
		order = append(order, k)
	}
	set("grant_type", "authorization_code")
	set("code", code)
	if cfg.PKCE && verifier != "" {
		set("code_verifier", verifier)
	}
	set("redirect_uri", getOIDCRedirectURI(ctx.Auth.BaseURL, provider.ProviderID, o))
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	headers.Set("Accept", "application/json")
	switch cfg.TokenEndpointAuthentication {
	case "private_key_jwt":
		var resolved *PrivateKey
		if def := o.findDefault(provider.ProviderID); def != nil && def.PrivateKey != nil {
			resolved = def.PrivateKey
		}
		if resolved == nil && o.ResolvePrivateKey != nil {
			r, err := o.ResolvePrivateKey(ctx.Context(), ResolvePrivateKeyParams{ProviderID: provider.ProviderID, KeyID: cfg.PrivateKeyID, Issuer: cfg.Issuer})
			if err != nil {
				return nil, err, ""
			}
			resolved = r
		}
		if resolved == nil || (resolved.PrivateKeyJWK == nil && resolved.PrivateKeyPEM == "") {
			return nil, nil, "no_private_key_available"
		}
		alg := cfg.PrivateKeyAlgorithm
		if alg == "" {
			alg = resolved.Algorithm
		}
		if !inList(PrivateKeyJWTSigningAlgorithms, alg) {
			alg = ""
		}
		getter, err := privateKeyJWTAssertionGetter(resolved, or(cfg.PrivateKeyID, resolved.Kid), alg)
		if err != nil {
			return nil, err, ""
		}
		assertion, err := getter(cfg.ClientID, cfg.TokenEndpoint, "authorization_code")
		if err != nil {
			return nil, err, ""
		}
		set("client_id", cfg.ClientID)
		set("client_assertion_type", oauth2.ClientAssertionType)
		set("client_assertion", assertion)
	case "client_secret_post":
		set("client_id", cfg.ClientID)
		set("client_secret", cfg.ClientSecret)
	default:
		headers.Set("Authorization", oauth2.EncodeBasicCredentials(cfg.ClientID, cfg.ClientSecret))
	}
	var parts []string
	for _, k := range order {
		parts = append(parts, oauth2.FormEncode(k)+"="+oauth2.FormEncode(form.Get(k)))
	}
	res, err := fetchOIDCEndpoint(ctx.Context(), "tokenEndpoint", cfg.TokenEndpoint, "POST", strings.Join(parts, "&"), headers, 0, isTrustedFn(ctx))
	if err != nil {
		return nil, err, ""
	}
	if res.Err != nil {
		return nil, nil, getOIDCErrorDescription(fetchErrorObject(res.Err), "token_response_error")
	}
	data, ok := res.Data.(map[string]any)
	if !ok {
		return nil, errors.New("Token endpoint returned an empty response"), ""
	}
	return oauth2.TokensFromResponse(data), nil, ""
}

func (p *plugin) handleOIDCCallback(ctx *betterauth.EndpointContext, providerID string, sd *betterauth.StateData, ref *ProviderReference) (any, error) {
	o := p.o
	c := ctx.Context()
	code := ctx.QueryString("code")
	qErr := ctx.QueryString("error")
	qDesc := ctx.QueryString("error_description")
	if sd == nil {
		var err error
		sd, err = betterauth.SSOParseState(ctx)
		if err != nil {
			return nil, err
		}
	}
	if ref == nil {
		ref = parseProviderReference(sd.ServerContext[SSOProviderStateKey])
	}
	redirectErr := func(code, desc string) error {
		base := sd.ErrorURL
		if base == "" {
			base = sd.CallbackURL
		}
		if desc != "" {
			return redirectWithParams(ctx, base, "error", code, "error_description", desc)
		}
		return redirectWithParams(ctx, base, "error", code)
	}
	if code == "" || qErr != "" {
		e := qErr
		if e == "" {
			e = "invalid_request"
		}
		desc := qDesc
		if desc == "" {
			desc = qErr
			if desc == "" {
				desc = "authorization_code_not_found"
			}
		}
		return nil, redirectErr(e, desc)
	}
	provider, err := p.resolveOIDCProvider(c, ctx.Auth.Adapter, providerID)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, redirectErr("invalid_provider", "provider not found")
	}
	if ref == nil {
		return nil, redirectErr("invalid_state", "missing_sso_provider_reference")
	}
	if !isCurrentProviderReference(provider, ref) {
		return nil, redirectErr("invalid_state", "sso_provider_changed_during_authentication")
	}
	if o.domainVerificationEnabled() && !isTrue(provider.DomainVerified) {
		return nil, apiErr("UNAUTHORIZED", "message", "Provider domain has not been verified")
	}
	if provider.OIDCConfig == nil {
		return nil, redirectErr("invalid_provider", "provider not found")
	}
	cfg, err := ensureRuntimeDiscovery(c, provider.OIDCConfig, provider.Issuer, isTrustedFn(ctx))
	if err != nil {
		var de *DiscoveryError
		if errors.As(err, &de) {
			return nil, redirectErr("discovery_failed", de.Message)
		}
		return nil, redirectErr("discovery_failed", "unexpected_discovery_error")
	}
	if cfg.Scopes == nil {
		cfg.Scopes = defaultOIDCScopes
	}
	if cfg.TokenEndpoint == "" {
		return nil, redirectErr("invalid_provider", "token_endpoint_not_found")
	}
	tokens, terr, desc := p.tokenRequest(ctx, provider, cfg, code, sd.CodeVerifier)
	if terr != nil {
		if _, ok := betterauth.AsAPIError(terr); ok {
			return nil, terr
		}
		ctx.Auth.Logger.Error("Error validating authorization code", terr)
		var de *DiscoveryError
		if errors.As(terr, &de) {
			return nil, redirectErr("invalid_provider", de.Message)
		}
		return nil, redirectErr("invalid_provider", or(terr.Error(), "token_response_error"))
	}
	if desc != "" {
		return nil, redirectErr("invalid_provider", desc)
	}
	if tokens == nil {
		return nil, redirectErr("invalid_provider", "token_response_not_found")
	}
	mapping := cfg.Mapping
	if mapping == nil {
		mapping = &OIDCMapping{}
	}
	var verified *verifiedIDToken
	if tokens.IDToken != "" {
		if cfg.JwksEndpoint == "" {
			return nil, redirectErr("invalid_provider", "jwks_endpoint_not_found")
		}
		v, verr := validateOIDCIdToken(c, tokens.IDToken, cfg.JwksEndpoint, cfg.ClientID, provider.Issuer, isTrustedFn(ctx))
		if verr != nil {
			var de *DiscoveryError
			if errors.As(verr, &de) {
				return nil, redirectErr("invalid_provider", de.Message)
			}
			ctx.Auth.Logger.Error(verr.Error())
			return nil, redirectErr("invalid_provider", "token_not_verified")
		}
		if readStringClaim(v.Payload, "sub") == "" {
			return nil, redirectErr("invalid_provider", "id_token_subject_missing")
		}
		verified = v
	}
	if o.ResolveUser != nil && verified == nil {
		return nil, redirectErr("invalid_provider", "id_token_required_for_user_resolution")
	}
	var rawProfile map[string]any
	var source map[string]any
	if cfg.UserInfoEndpoint != "" {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tokens.AccessToken)
		res, ferr := fetchOIDCEndpoint(c, "userInfoEndpoint", cfg.UserInfoEndpoint, "GET", "", h, 0, isTrustedFn(ctx))
		if ferr != nil {
			var de *DiscoveryError
			if errors.As(ferr, &de) {
				return nil, redirectErr("invalid_provider", de.Message)
			}
			return nil, ferr
		}
		if res.Err != nil {
			msg, _ := res.Err.Body["message"].(string)
			return nil, redirectErr("invalid_provider", or(msg, or(res.Err.StatusText, "userinfo_response_error")))
		}
		raw, ok := res.Data.(map[string]any)
		if !ok {
			return nil, redirectErr("invalid_provider", "userinfo_response_not_found")
		}
		if verified != nil && fmt.Sprint(raw["sub"]) != fmt.Sprint(verified.Payload["sub"]) {
			return nil, redirectErr("invalid_provider", "id_token_userinfo_subject_mismatch")
		}
		rawProfile, source = raw, raw
	} else if verified != nil {
		rawProfile, source = verified.Payload, verified.Payload
	} else {
		return nil, redirectErr("invalid_provider", "user_info_endpoint_not_found")
	}
	userInfo := map[string]any{}
	extra := map[string]any{}
	for k, claim := range mapping.ExtraFields {
		userInfo[k] = source[claim]
		extra[k] = source[claim]
	}
	id := readStringClaim(source, "sub")
	if cfg.UserInfoEndpoint == "" {
		if s, ok := source["sub"].(string); ok {
			id = s
		}
	}
	emailClaim := readStringClaim(source, or(mapping.Email, "email"))
	emailVerified := false
	if o.TrustEmailVerified {
		emailVerified = parseProviderEmailVerified(source[or(mapping.EmailVerified, "email_verified")])
	}
	name := readStringClaim(source, or(mapping.Name, "name"))
	image := readStringClaim(source, or(mapping.Image, "picture"))
	userInfo["id"] = id
	userInfo["email"] = emailClaim
	userInfo["emailVerified"] = emailVerified
	userInfo["name"] = name
	userInfo["image"] = image
	if emailClaim == "" || id == "" {
		return nil, redirectErr("invalid_provider", "missing_user_info")
	}
	accountIssuer := provider.Issuer
	if verified != nil {
		accountIssuer = or(readStringClaim(verified.Payload, "iss"), provider.Issuer)
	}
	trusted := isTrue(provider.DomainVerified) && validateEmailDomain(emailClaim, provider.Domain)
	providerUser := ProviderUserProfile{Email: emailClaim, EmailVerified: emailVerified, Name: name, Image: image, Extra: extra}
	scope := strings.Join(tokens.Scopes, ",")
	acc := betterauth.OAuthAccountData{ProviderID: provider.ProviderID, AccountID: id, AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		IDToken: tokens.IDToken, AccessTokenExpiresAt: tokens.AccessTokenExpiresAt, RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt, Scope: scope}
	falseV := false
	var verifiedClaims map[string]any
	if verified != nil {
		verifiedClaims = verified.Payload
	}
	linked, err := p.authenticate(ctx, provider, func(tx context.Context) (*SSOProvider, error) {
		return p.resolveOIDCProvider(tx, ctx.Auth.Adapter, providerID)
	}, ref, func() UserResolutionInput {
		claims := rawProfile
		if claims == nil {
			claims = map[string]any{}
		}
		vc := verifiedClaims
		if vc == nil {
			vc = map[string]any{}
		}
		return UserResolutionInput{Protocol: "oidc", ProviderID: provider.ProviderID, AccountKey: AccountKey{Issuer: accountIssuer, AccountID: id},
			ProviderUser: providerUser, ProviderReference: *ref, ProviderClaims: claims, VerifiedIDTokenClaims: vc}
	}, betterauth.HandleOAuthUserInfoOptions{
		UserInfo:            oauth2.UserInfo{Name: name, Email: emailClaim, Image: image, EmailVerified: emailVerified, Extra: extra},
		Account:             acc,
		CallbackURL:         sd.CallbackURL,
		DisableSignUp:       o.DisableImplicitSignUp && !(sd.RequestSignUp != nil && *sd.RequestSignUp),
		OverrideUserInfo:    cfg.OverrideUserInfo,
		Source:              betterauth.UserInfoSource{Method: "sso-oidc", ProviderID: provider.ProviderID, Profile: rawProfile},
		IsTrustedProvider:   trusted,
		TrustProviderByName: &falseV,
	})
	if err != nil {
		if ae, ok := betterauth.AsAPIError(err); ok && ae.Code() != "" && !betterauth.IsRedirect(err) {
			return nil, redirectErr(ae.Code(), ae.Message())
		}
		return nil, err
	}
	if linked.Error != "" {
		return nil, redirectErr(linked.Error, "")
	}
	session, user := linked.Data.Session, linked.Data.User
	if o.ProvisionUser != nil && (linked.IsRegister || o.ProvisionUserOnEveryLogin) {
		if err := o.ProvisionUser(c, ProvisionUserData{User: user, UserInfo: userInfo, Token: tokens, Provider: provider}); err != nil {
			return nil, err
		}
	}
	if _, err := assignOrganization(ctx, assignOptions{reason: "provider-bound", user: user, provider: provider, token: tokens, provisioning: o.OrganizationProvisioning,
		profile: &normalizedProfile{ProviderType: "oidc", ProviderID: provider.ProviderID, AccountID: id, Email: emailClaim, EmailVerified: emailVerified, RawAttributes: userInfo}}); err != nil {
		return nil, err
	}
	if linked.AccountCookie != nil {
		if err := betterauth.SetAccountCookie(ctx, linked.AccountCookie); err != nil {
			return nil, err
		}
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, nil, nil); err != nil {
		return nil, err
	}
	to := sd.CallbackURL
	if linked.IsRegister && sd.NewUserURL != "" {
		to = sd.NewUserURL
	}
	return nil, ctx.Redirect(to)
}

// authenticate runs the account-linking transaction shared by OIDC and SAML.
func (p *plugin) authenticate(ctx *betterauth.EndpointContext, provider *SSOProvider, reload func(context.Context) (*SSOProvider, error),
	ref *ProviderReference, input func() UserResolutionInput, opts betterauth.HandleOAuthUserInfoOptions) (*betterauth.SSOHandleOAuthUserInfoResult, error) {
	o := p.o
	a := ctx.Auth.Adapter
	if o.ResolveUser != nil {
		if err := assertSSOUserResolutionNativeTransactionSupport(ctx.Context(), a); err != nil {
			return nil, err
		}
		if err := assertSSOUserResolutionSessionStorage(ctx.Auth.Options); err != nil {
			return nil, err
		}
	}
	var result *betterauth.SSOHandleOAuthUserInfoResult
	err := ctx.TransactionOpts(func() error {
		tx := ctx.Context()
		if err := lockSSOProviderForAccountLink(tx, a, provider); err != nil {
			return err
		}
		current, err := reload(tx)
		if err != nil {
			return err
		}
		if current == nil || !isCurrentProviderReference(current, ref) {
			return providerChangedError()
		}
		var selected *betterauth.SSOSelectedUser
		if o.ResolveUser != nil {
			res, err := resolveSSOUser(tx, o.ResolveUser, input(), a, ctx.Auth.Logger)
			if err != nil {
				return err
			}
			switch res.Action {
			case "reject":
				body := jsonx.O("code", res.Code)
				if res.Message != nil {
					body.Set("message", *res.Message)
				}
				return betterauth.NewAPIError("FORBIDDEN", body)
			case "link":
				selected = &betterauth.SSOSelectedUser{UserID: res.UserID, Profile: res.Profile}
			}
		}
		r, err := betterauth.SSOHandleOAuthUserInfo(ctx, betterauth.SSOHandleOAuthUserInfoOptions{
			HandleOAuthUserInfoOptions: opts, SelectedUser: selected,
			DeferNonDatabaseWrites: o.ResolveUser != nil, RequireExactAccountBinding: o.ResolveUser != nil,
		})
		if err != nil {
			return err
		}
		if o.ResolveUser != nil {
			r, err = requireSuccessfulSSOAuthentication(r)
			if err != nil {
				return err
			}
		}
		result = r
		return nil
	}, func(err error) {
		// Upstream onAfterCommitHookError: committed after-hook failures are logged, not thrown.
		ctx.Auth.Logger.Error("Committed SSO authentication after-hook failed", err)
	})
	if err != nil {
		if f := getFailedSSOAuthenticationResult(err); f != nil {
			return f, nil
		}
		return nil, err
	}
	return result, nil
}

var callbackQuery = validate.Object(
	validate.F("code", opt(validate.String())),
	validate.F("state", opt(validate.String())),
	validate.F("error", opt(validate.String())),
	validate.F("error_description", opt(validate.String())),
)

func (p *plugin) bounceIfIdpInitiated(ctx *betterauth.EndpointContext, providerID string) error {
	c := ctx.Context()
	provider, err := p.resolveOIDCProvider(c, ctx.Auth.Adapter, providerID)
	if err != nil || provider == nil || provider.OIDCConfig == nil || !provider.OIDCConfig.AllowIdpInitiated {
		return nil
	}
	cfg, err := ensureRuntimeDiscovery(c, provider.OIDCConfig, provider.Issuer, isTrustedFn(ctx))
	if err != nil {
		ctx.Auth.Logger.Error("IDP-initiated bounce skipped: OIDC discovery failed", map[string]any{"providerId": provider.ProviderID, "issuer": provider.Issuer, "error": err.Error()})
		return nil
	}
	if cfg.AuthorizationEndpoint == "" {
		ctx.Auth.Logger.Error("IDP-initiated bounce skipped: authorizationEndpoint missing after discovery", map[string]any{"providerId": provider.ProviderID, "issuer": provider.Issuer})
		return nil
	}
	betterauth.AddOAuthServerContext(c, map[string]any{SSOProviderStateKey: computeProviderReference(provider).toServerContext()})
	state, verifier, err := betterauth.GenerateState(ctx, nil)
	if err != nil {
		return err
	}
	scopes := cfg.Scopes
	if scopes == nil {
		scopes = defaultOIDCScopes
	}
	ao := oauth2.AuthorizationURLOptions{ID: provider.Issuer, ClientID: cfg.ClientID, AuthorizationEndpoint: cfg.AuthorizationEndpoint,
		RedirectURI: getOIDCRedirectURI(ctx.Auth.BaseURL, provider.ProviderID, p.o), State: state, Scopes: scopes}
	if cfg.PKCE {
		ao.CodeVerifier = verifier
	}
	u, err := oauth2.CreateAuthorizationURL(ao)
	if err != nil {
		return err
	}
	return ctx.Redirect(u.String())
}

func (p *plugin) callbackSSO() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "callbackSSO", Path: "/sso/callback/:providerId", Methods: []string{"GET"}, Query: callbackQuery,
		Metadata: endpointMeta("callbackSSO", true),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			pid := ctx.Params["providerId"]
			if !ctx.HasQuery("state") && ctx.QueryString("code") != "" {
				if err := p.bounceIfIdpInitiated(ctx, pid); err != nil {
					return nil, err
				}
			}
			return p.handleOIDCCallback(ctx, pid, nil, nil)
		},
	}
}

func (p *plugin) callbackSSOShared() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "callbackSSOShared", Path: "/sso/callback", Methods: []string{"GET"}, Query: callbackQuery,
		Metadata: endpointMeta("callbackSSOShared", true),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			sd, err := betterauth.SSOParseState(ctx)
			if err != nil {
				return nil, err
			}
			ref := parseProviderReference(sd.ServerContext[SSOProviderStateKey])
			if ref == nil {
				base := sd.ErrorURL
				if base == "" {
					base = sd.CallbackURL
				}
				return nil, redirectWithParams(ctx, base, "error", "invalid_state", "error_description", "missing_sso_provider_reference")
			}
			return p.handleOIDCCallback(ctx, ref.ProviderID, sd, ref)
		},
	}
}
