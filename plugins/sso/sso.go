// Package sso ports Better Auth's SSO plugin (@better-auth/sso 1.7.7): OIDC and SAML 2.0
// single sign-on with provider registration and management, OIDC discovery, SAML
// metadata, AuthnRequest/ACS/Single Logout handling, DNS domain verification and
// organization provisioning.
//
//	auth, _ := betterauth.New(betterauth.Config{
//		Plugins: []*betterauth.Plugin{sso.New(sso.Options{})},
//	})
package sso

import (
	"fmt"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Version is the upstream package version this port tracks.
const Version = "1.7.7"

// Verification key prefixes and SAML defaults (constants.ts).
const (
	AuthnRequestKeyPrefix   = "saml-authn-request:"
	UsedAssertionKeyPrefix  = "saml-used-assertion:"
	SAMLSessionKeyPrefix    = "saml-session:"
	SAMLSessionByIDPrefix   = "saml-session-by-id:"
	LogoutRequestKeyPrefix  = "saml-logout-request:"
	DefaultAuthnRequestTTL  = 5 * 60 * 1000
	DefaultAssertionTTL     = 15 * 60 * 1000
	DefaultLogoutRequestTTL = 5 * 60 * 1000
	SAMLStatusSuccess       = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

var samlSkipOriginCheckPaths = []string{"/sso/saml2/sp/acs", "/sso/saml2/sp/slo"}

var builtInFieldKeys = []string{"id", "issuer", "oidcConfig", "samlConfig", "userId", "providerId", "organizationId", "domain", "domainVerified"}
var responseFieldKeys = []string{"type", "spMetadataUrl", "redirectURI", "domainVerificationToken"}

type plugin struct {
	o *Options
}

func (f FieldNames) get(key string) string {
	switch key {
	case "issuer":
		return f.Issuer
	case "oidcConfig":
		return f.OIDCConfig
	case "samlConfig":
		return f.SAMLConfig
	case "userId":
		return f.UserID
	case "providerId":
		return f.ProviderID
	case "organizationId":
		return f.OrganizationID
	case "domain":
		return f.Domain
	case "domainVerified":
		return f.DomainVerified
	}
	return ""
}

func (o *Options) fieldName(key string) string {
	if key != "domainVerified" {
		if v := o.Fields.get(key); v != "" {
			return v
		}
	}
	if o.Schema != nil {
		if v := o.Schema.Fields.get(key); v != "" {
			return v
		}
	}
	return key
}

func assertNoAdditionalFieldCollisions(o *Options) error {
	builtIn := map[string]bool{}
	for _, k := range builtInFieldKeys {
		builtIn[o.fieldName(k)] = true
	}
	for _, f := range o.additionalFields() {
		if inList(builtInFieldKeys, f.Name) {
			return fmt.Errorf("ssoProvider additional field %q conflicts with a built-in field", f.Name)
		}
		if inList(responseFieldKeys, f.Name) {
			return fmt.Errorf("ssoProvider additional field %q conflicts with a returned provider field", f.Name)
		}
		name := f.FieldName
		if name == "" {
			name = f.Name
		}
		if builtIn[name] {
			return fmt.Errorf("ssoProvider additional field %q maps to built-in field %q", f.Name, name)
		}
	}
	return nil
}

func (o *Options) schema() []db.PluginTable {
	model := o.ModelName
	if model == "" && o.Schema != nil {
		model = o.Schema.ModelName
	}
	if model == "" {
		model = "ssoProvider"
	}
	fields := []db.Field{
		{Name: "issuer", Type: db.TypeString, Required: db.True, FieldName: o.fieldName("issuer")},
		{Name: "oidcConfig", Type: db.TypeString, Required: db.False, FieldName: o.fieldName("oidcConfig")},
		{Name: "samlConfig", Type: db.TypeString, Required: db.False, FieldName: o.fieldName("samlConfig")},
		{Name: "userId", Type: db.TypeString, References: &db.Reference{Model: "user", Field: "id"}, FieldName: o.fieldName("userId")},
		{Name: "providerId", Type: db.TypeString, Required: db.True, Unique: true, FieldName: o.fieldName("providerId")},
		{Name: "organizationId", Type: db.TypeString, Required: db.False, FieldName: o.fieldName("organizationId")},
		{Name: "domain", Type: db.TypeString, Required: db.True, FieldName: o.fieldName("domain")},
	}
	if o.domainVerificationEnabled() {
		fields = append(fields, db.Field{Name: "domainVerified", Type: db.TypeBoolean, Required: db.False, FieldName: o.fieldName("domainVerified")})
	}
	fields = append(fields, o.additionalFields()...)
	for i := range fields {
		if fields[i].FieldName == fields[i].Name {
			fields[i].FieldName = ""
		}
	}
	return []db.PluginTable{{Key: "ssoProvider", ModelName: model, Fields: fields}}
}

// New creates the sso plugin. It panics when an additional ssoProvider field collides with
// a built-in field (upstream throws at construction).
func New(opts Options) *betterauth.Plugin {
	o := &opts
	if err := assertNoAdditionalFieldCollisions(o); err != nil {
		panic(err)
	}
	p := &plugin{o: o}
	endpoints := []*betterauth.Endpoint{
		p.spMetadata(), p.registerSSOProvider(), p.signInSSO(), p.callbackSSO(), p.callbackSSOShared(),
		p.acsEndpoint(), p.sloEndpoint(), p.initiateSLO(), p.listSSOProviders(), p.getSSOProvider(),
		p.updateSSOProvider(), p.deleteSSOProvider(),
	}
	if o.domainVerificationEnabled() {
		endpoints = append(endpoints, p.requestDomainVerification(), p.verifyDomain())
	}
	return &betterauth.Plugin{
		ID:         "sso",
		Version:    Version,
		Options:    o,
		ErrorCodes: ErrorCodes,
		Endpoints:  endpoints,
		Schema:     o.schema(),
		Init: func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
			if ac.SkipOriginCheck {
				return nil, nil
			}
			ac.SkipOriginCheckPaths = append(append([]string(nil), ac.SkipOriginCheckPaths...), samlSkipOriginCheckPaths...)
			return nil, nil
		},
		Hooks: betterauth.PluginHooks{
			Before: []betterauth.Hook{{
				Matcher: func(ctx *betterauth.EndpointContext) bool { return ctx.Path == "/sign-out" },
				Handler: p.signOutHook,
			}},
			After: []betterauth.Hook{{
				Matcher: func(ctx *betterauth.EndpointContext) bool { return strings.HasPrefix(ctx.Path, "/callback/") },
				Handler: p.callbackHook,
			}},
		},
	}
}

func (p *plugin) signOutHook(ctx *betterauth.EndpointContext) (any, error) {
	if !p.o.saml().EnableSingleLogout {
		return nil, nil
	}
	session, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil || session == nil || session.Session == nil || session.Session.ID == "" {
		return nil, nil
	}
	ia := ctx.Auth.InternalAdapter
	key := SAMLSessionByIDPrefix + session.Session.ID
	lookup, err := ia.FindVerificationValue(ctx.Context(), key)
	if err == nil && lookup != nil && lookup.Value != "" {
		_ = ia.DeleteVerificationByIdentifier(ctx.Context(), lookup.Value)
		_ = ia.DeleteVerificationByIdentifier(ctx.Context(), key)
	}
	return nil, nil
}

func (p *plugin) callbackHook(ctx *betterauth.EndpointContext) (any, error) {
	ns := ctx.NewSession()
	if ns == nil || ns.User == nil || !ctx.Auth.HasPlugin("organization") {
		return nil, nil
	}
	_, err := assignOrganization(ctx, assignOptions{reason: "verified-domain", user: ns.User,
		provisioning: p.o.OrganizationProvisioning, domainVerification: p.o.domainVerificationEnabled()})
	return nil, err
}
