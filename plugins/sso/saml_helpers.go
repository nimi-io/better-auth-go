package sso

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

// routes/helpers.ts

func (o *Options) findDefault(providerID string) *DefaultSSOProvider {
	if o == nil {
		return nil
	}
	for i := range o.DefaultSSO {
		if o.DefaultSSO[i].ProviderID == providerID {
			return &o.DefaultSSO[i]
		}
	}
	return nil
}

// findProviderRecord loads a provider row by providerId.
func findProviderRecord(ctx context.Context, a adapter.Adapter, providerID string) (adapter.Record, error) {
	return a.FindOne(ctx, adapter.FindOneInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "providerId", Value: providerID}}})
}

// findSAMLProvider resolves a provider for SAML flows (DefaultSSO first).
func findSAMLProvider(ctx context.Context, providerID string, o *Options, a adapter.Adapter) (*SSOProvider, error) {
	if def := o.findDefault(providerID); def != nil {
		issuer := ""
		if def.SAMLConfig != nil {
			issuer = def.SAMLConfig.Issuer
		}
		return defaultProvider(*def, issuer, o.domainVerificationEnabled()), nil
	}
	rec, err := findProviderRecord(ctx, a, providerID)
	if err != nil || rec == nil {
		return nil, err
	}
	p, _, serr := providerFromRecord(rec)
	if serr != nil {
		return nil, serr
	}
	return p, nil
}

type sloOptions struct {
	wantLogoutRequestSigned  bool
	wantLogoutResponseSigned bool
}

type createSPOptions struct {
	clockSkew  *int64
	relayState string
	slo        *sloOptions
}

// createSP builds the service provider entity for a provider.
func createSP(config *SAMLConfig, baseURL, providerID string, o *createSPOptions) (*samlify.Entity, error) {
	if o == nil {
		o = &createSPOptions{}
	}
	sp := config.sp()
	sloLocation := baseURL + "/sso/saml2/sp/slo/" + providerID
	acsURL := baseURL + "/sso/saml2/sp/acs/" + providerID
	if err := assertSAMLServiceProviderMetadataPolicy(config); err != nil {
		return nil, err
	}
	metadata := sp.Metadata
	if metadata == "" {
		entityID := sp.EntityID
		if entityID == "" {
			entityID = config.Issuer
		}
		opts := samlify.SPMetadataOptions{
			EntityID:                 entityID,
			AssertionConsumerService: []samlify.Service{{Binding: samlify.BindingPostURN, Location: acsURL}},
			WantAssertionsSigned:     isTrue(config.WantAssertionsSigned),
			AuthnRequestsSigned:      isTrue(config.AuthnRequestsSigned),
		}
		if o.slo != nil {
			opts.SingleLogoutService = []samlify.Service{{Binding: samlify.BindingPostURN, Location: sloLocation}, {Binding: samlify.BindingRedirectURN, Location: sloLocation}}
		}
		if config.IdentifierFormat != "" {
			opts.NameIDFormat = []string{config.IdentifierFormat}
		}
		metadata = samlify.GenerateSPMetadata(opts)
	}
	privateKey := sp.PrivateKey
	if privateKey == "" {
		privateKey = config.PrivateKey
	}
	s := samlify.Setting{
		Metadata:             metadata,
		AllowCreate:          true,
		PrivateKey:           normalizePem(privateKey),
		PrivateKeyPass:       sp.PrivateKeyPass,
		IsAssertionEncrypted: isTrue(sp.IsAssertionEncrypted),
		EncPrivateKey:        normalizePem(sp.EncPrivateKey),
		EncPrivateKeyPass:    sp.EncPrivateKeyPass,
		RelayState:           o.relayState,
	}
	if o.slo != nil {
		s.WantLogoutRequestSigned = o.slo.wantLogoutRequestSigned
		s.WantLogoutResponseSigned = o.slo.wantLogoutResponseSigned
	}
	if o.clockSkew != nil && *o.clockSkew != 0 {
		s.ClockDrifts = &[2]int64{-*o.clockSkew, *o.clockSkew}
	}
	ent, err := samlify.ServiceProvider(s)
	if err != nil {
		return nil, err
	}
	return ent, nil
}

// assertSAMLServiceProviderMetadataPolicy rejects SP metadata that does not require signed
// assertions while wantAssertionsSigned is set.
func assertSAMLServiceProviderMetadataPolicy(config *SAMLConfig) error {
	policy, err := deriveSAMLServiceProviderPolicy(config)
	if err != nil {
		return err
	}
	if !isTrue(config.WantAssertionsSigned) || policy.WantAssertionsSigned {
		return nil
	}
	return apiErr("BAD_REQUEST", "code", "SAML_SP_METADATA_ASSERTION_SIGNATURE_MISMATCH", "message", "SAML service provider metadata must require signed assertions")
}

// SAMLServiceProviderPolicy is the effective SP signing policy.
type SAMLServiceProviderPolicy struct {
	WantAssertionsSigned bool
}

// DeriveSAMLServiceProviderPolicy derives the SP policy from the configuration (SP
// metadata wins over wantAssertionsSigned).
func DeriveSAMLServiceProviderPolicy(config *SAMLConfig) (SAMLServiceProviderPolicy, error) {
	return deriveSAMLServiceProviderPolicy(config)
}

func deriveSAMLServiceProviderPolicy(config *SAMLConfig) (SAMLServiceProviderPolicy, error) {
	metadata := config.sp().Metadata
	if metadata == "" {
		return SAMLServiceProviderPolicy{WantAssertionsSigned: isTrue(config.WantAssertionsSigned)}, nil
	}
	parsed, err := parseSAMLServiceProviderMetadata(metadata)
	if err != nil || len(parsed.PostAssertionConsumerServiceURLs) == 0 {
		return SAMLServiceProviderPolicy{}, apiErr("BAD_REQUEST", "code", "SAML_INVALID_SP_METADATA", "message", "Invalid SAML service provider metadata")
	}
	return SAMLServiceProviderPolicy{WantAssertionsSigned: parsed.WantAssertionsSigned}, nil
}

func assertSAMLMetadataSize(metadata, kind string, max int) error {
	if metadata != "" && len(metadata) > max {
		return badRequest(fmt.Sprintf("%s metadata exceeds maximum allowed size (%d bytes)", kind, max))
	}
	return nil
}

func assertSAMLIdentityProviderAuthority(config *SAMLConfig) error {
	if config.IdpMetadata != nil && (config.IdpMetadata.Metadata != "" || config.IdpMetadata.EntityID != "") {
		return nil
	}
	return badRequest("SAML manual IdP configuration requires idpMetadata.entityID; issuer identifies the service provider and cannot identify the IdP")
}

func toServices(in []SAMLService) []samlify.Service {
	out := make([]samlify.Service, len(in))
	for i, s := range in {
		out[i] = samlify.Service{Binding: s.Binding, Location: s.Location}
	}
	return out
}

// createIdP builds the identity provider entity for a provider.
func createIdP(config *SAMLConfig) (*samlify.Entity, error) {
	if err := assertSAMLIdentityProviderAuthority(config); err != nil {
		return nil, err
	}
	idp := config.IdpMetadata
	if idp.Metadata != "" {
		return samlify.IdentityProvider(samlify.Setting{
			Metadata:             idp.Metadata,
			PrivateKey:           normalizePem(idp.PrivateKey),
			PrivateKeyPass:       idp.PrivateKeyPass,
			IsAssertionEncrypted: isTrue(idp.IsAssertionEncrypted),
			EncPrivateKey:        normalizePem(idp.EncPrivateKey),
			EncPrivateKeyPass:    idp.EncPrivateKeyPass,
		})
	}
	sso := toServices(idp.SingleSignOnService)
	if len(idp.SingleSignOnService) == 0 {
		sso = []samlify.Service{{Binding: samlify.BindingRedirectURN, Location: config.EntryPoint}}
	}
	var certs []string
	for _, c := range resolveSigningCerts(config) {
		certs = append(certs, normalizePem(c))
	}
	return samlify.IdentityProvider(samlify.Setting{
		EntityID:                idp.EntityID,
		SingleSignOnService:     sso,
		SingleLogoutService:     toServices(idp.SingleLogoutService),
		SigningCert:             certs,
		WantAuthnRequestsSigned: isTrue(config.AuthnRequestsSigned),
		IsAssertionEncrypted:    isTrue(idp.IsAssertionEncrypted),
		EncPrivateKey:           normalizePem(idp.EncPrivateKey),
		EncPrivateKeyPass:       idp.EncPrivateKeyPass,
	})
}

// DeriveSAMLIdentityProviderEntityID returns the IdP entity ID of a configuration.
func DeriveSAMLIdentityProviderEntityID(config *SAMLConfig) (string, error) {
	idp, err := createIdP(config)
	if err != nil {
		return "", err
	}
	return idp.Meta.GetEntityID(), nil
}

func escapeHTML(s string) string {
	if s == "" {
		return ""
	}
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func isSAMLPostBindingLocation(v string) bool {
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// createSAMLPostForm renders an auto-submitting POST binding form.
func createSAMLPostForm(action, param, value, relayState string) (*betterauth.Response, error) {
	if !isSAMLPostBindingLocation(action) {
		return nil, badRequest("SAML POST binding location must be an absolute http or https URL")
	}
	rs := ""
	if relayState != "" {
		rs = `<input type="hidden" name="RelayState" value="` + escapeHTML(relayState) + `" />`
	}
	body := `<!DOCTYPE html><html><body onload="document.forms[0].submit();"><form method="POST" action="` + escapeHTML(action) +
		`"><input type="hidden" name="` + escapeHTML(param) + `" value="` + escapeHTML(value) + `" />` + rs +
		`<noscript><input type="submit" value="Continue" /></noscript></form></body></html>`
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	return &betterauth.Response{Status: 200, Header: h, Body: []byte(body)}, nil
}
