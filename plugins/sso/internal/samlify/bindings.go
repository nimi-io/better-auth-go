package samlify

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

// Default templates (libsaml defaults).
const (
	DefaultLoginRequestTemplate   = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" ForceAuthn="{ForceAuthn}" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="{ProtocolBinding}" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}" AssertionConsumerServiceIndex="{AssertionConsumerServiceIndex}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>`
	DefaultLogoutRequestTemplate  = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>`
	DefaultLogoutResponseTemplate = `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>`
	DefaultLoginResponseTemplate  = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>`
)

// BindingContext is the result of creating an outbound message.
type BindingContext struct {
	ID string
	// Context is the redirect URL (redirect binding) or the base64 message (post binding).
	Context        string
	RelayState     string
	EntityEndpoint string
	Type           string
}

func queryParamFor(msgType string) string {
	switch msgType {
	case "LogoutRequest", "SAMLRequest":
		return "SAMLRequest"
	}
	return "SAMLResponse"
}

func buildRedirectURL(baseURL, msgType string, isSigned bool, context string, s *Setting, relayState string) (string, error) {
	noParams := true
	if u, err := url.Parse(baseURL); err == nil && u.RawQuery != "" {
		noParams = false
	}
	param := queryParamFor(msgType)
	samlRequest := EncodeURIComponent(Base64Encode(string(DeflateString(context))))
	rs := ""
	if relayState != "" {
		rs = "&RelayState=" + EncodeURIComponent(relayState)
	}
	sep := "&"
	if noParams {
		sep = "?"
	}
	if isSigned {
		sigAlg := "&SigAlg=" + EncodeURIComponent(s.RequestSignatureAlgorithm)
		octet := samlRequest + rs + sigAlg
		sig, err := ConstructMessageSignature(param+"="+octet, s.PrivateKey, s.PrivateKeyPass, s.RequestSignatureAlgorithm)
		if err != nil {
			return "", err
		}
		return baseURL + sep + param + "=" + octet + "&Signature=" + EncodeURIComponent(sig), nil
	}
	return baseURL + sep + param + "=" + samlRequest + rs, nil
}

// CreateLoginRequest builds an AuthnRequest for the redirect binding
// (ServiceProvider.createLoginRequest(idp, "redirect", { relayState })).
func (sp *Entity) CreateLoginRequest(idp *Entity, binding, relayState string) (*BindingContext, error) {
	if binding == "" {
		binding = BindingRedirect
	}
	spSigned := sp.Meta.IsAuthnRequestSigned()
	idpWants := idp.Meta.IsWantAuthnRequestsSigned()
	if spSigned != idpWants {
		return nil, errors.New("ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG: SP AuthnRequestsSigned=" + boolStr(spSigned) + " but IdP WantAuthnRequestsSigned=" + boolStr(idpWants))
	}
	if binding != BindingRedirect {
		return nil, errors.New("ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING")
	}
	base, ok := idp.Meta.SingleSignOnServiceLocation(BindingRedirect)
	if !ok {
		return nil, errors.New("ERR_NO_REDIRECT_SSO_ENDPOINT")
	}
	id := sp.Setting.GenerateID()
	acs, _ := sp.Meta.GetAssertionConsumerService(BindingPost)
	tags := []Tag{
		T("ID", id),
		T("Destination", base),
		T("Issuer", sp.Meta.GetEntityID()),
		T("IssueInstant", ISOTime(time.Now())),
		Opt("NameIDFormat", sp.nameIDFormat()),
		T("ProtocolBinding", BindingPostURN),
		Opt("AssertionConsumerServiceURL", acs),
		U("AssertionConsumerServiceIndex"),
		T("EntityID", sp.Meta.GetEntityID()),
		T("AllowCreate", boolStr(sp.Setting.AllowCreate)),
		U("ForceAuthn"),
	}
	raw := ReplaceTagsByValue(DefaultLoginRequestTemplate, tags)
	if relayState == "" {
		relayState = sp.Setting.RelayState
	}
	u, err := buildRedirectURL(base, "SAMLRequest", sp.Meta.IsAuthnRequestSigned(), raw, &sp.Setting, relayState)
	if err != nil {
		return nil, err
	}
	return &BindingContext{ID: id, Context: u, RelayState: relayState, Type: "SAMLRequest"}, nil
}

// LogoutUser identifies the session to log out.
type LogoutUser struct {
	LogoutNameID string
	SessionIndex string
}

// CreateLogoutRequest builds a LogoutRequest to target (Entity.createLogoutRequest).
func (e *Entity) CreateLogoutRequest(target *Entity, binding string, user LogoutUser, relayState string) (*BindingContext, error) {
	if relayState == "" {
		relayState = e.Setting.RelayState
	}
	id := e.Setting.GenerateID()
	build := func(dest string) string {
		return ReplaceTagsByValue(DefaultLogoutRequestTemplate, []Tag{
			T("ID", id),
			T("Destination", dest),
			T("EntityID", e.Meta.GetEntityID()),
			T("Issuer", e.Meta.GetEntityID()),
			T("IssueInstant", ISOTime(time.Now())),
			Opt("NameIDFormat", e.nameIDFormat()),
			T("NameID", user.LogoutNameID),
			Opt("SessionIndex", user.SessionIndex),
		})
	}
	switch binding {
	case BindingRedirect:
		base, ok := target.Meta.GetSingleLogoutService(BindingRedirect)
		if !ok {
			return nil, errors.New("ERR_NO_REDIRECT_SLO_ENDPOINT")
		}
		u, err := buildRedirectURL(base, "LogoutRequest", target.Setting.WantLogoutRequestSigned, build(base), &e.Setting, relayState)
		if err != nil {
			return nil, err
		}
		return &BindingContext{ID: id, Context: u}, nil
	case BindingPost:
		base, _ := target.Meta.GetSingleLogoutService(BindingPost)
		raw := build(base)
		if target.Setting.WantLogoutRequestSigned {
			signed, err := ConstructSAMLSignature(raw, SignatureOptions{PrivateKey: e.Setting.PrivateKey, PrivateKeyPass: e.Setting.PrivateKeyPass,
				SignatureAlgorithm: e.Setting.RequestSignatureAlgorithm, SigningCert: first(e.Meta.GetX509Certificates("signing")), AfterLocalName: "Issuer"})
			if err != nil {
				return nil, err
			}
			raw = signed
		}
		return &BindingContext{ID: id, Context: Base64Encode(raw), RelayState: relayState, EntityEndpoint: base, Type: "SAMLRequest"}, nil
	}
	return nil, errors.New("ERR_UNDEFINED_BINDING")
}

func first(l []string) string {
	if len(l) > 0 {
		return l[0]
	}
	return ""
}

// CreateLogoutResponse builds a LogoutResponse to target (Entity.createLogoutResponse).
func (e *Entity) CreateLogoutResponse(target *Entity, requestID string, binding, relayState string) (*BindingContext, error) {
	if relayState == "" {
		relayState = e.Setting.RelayState
	}
	id := e.Setting.GenerateID()
	build := func(dest string, inResponseTo bool) string {
		tags := []Tag{
			T("ID", id),
			T("Destination", dest),
			T("Issuer", e.Meta.GetEntityID()),
			T("EntityID", e.Meta.GetEntityID()),
			T("IssueInstant", ISOTime(time.Now())),
			T("StatusCode", StatusSuccess),
		}
		if inResponseTo {
			tags = append(tags, Opt("InResponseTo", requestID))
		}
		return ReplaceTagsByValue(DefaultLogoutResponseTemplate, tags)
	}
	switch binding {
	case BindingRedirect:
		base, ok := target.Meta.GetSingleLogoutService(BindingRedirect)
		if !ok {
			return nil, errors.New("ERR_NO_REDIRECT_SLO_ENDPOINT")
		}
		u, err := buildRedirectURL(base, "LogoutResponse", target.Setting.WantLogoutResponseSigned, build(base, requestID != ""), &e.Setting, relayState)
		if err != nil {
			return nil, err
		}
		return &BindingContext{ID: id, Context: u}, nil
	case BindingPost:
		base, _ := target.Meta.GetSingleLogoutService(BindingPost)
		raw := build(base, true)
		if target.Setting.WantLogoutResponseSigned {
			signed, err := ConstructSAMLSignature(raw, SignatureOptions{PrivateKey: e.Setting.PrivateKey, PrivateKeyPass: e.Setting.PrivateKeyPass,
				SignatureAlgorithm: e.Setting.RequestSignatureAlgorithm, SigningCert: first(e.Meta.GetX509Certificates("signing")), AfterLocalName: "Issuer"})
			if err != nil {
				return nil, err
			}
			raw = signed
		}
		return &BindingContext{ID: id, Context: Base64Encode(raw), RelayState: relayState, EntityEndpoint: base, Type: "SAMLResponse"}, nil
	}
	return nil, errors.New("ERR_CREATE_LOGOUT_RESPONSE_UNDEFINED_BINDING")
}

// ---- identity-provider side (used by tests and tooling) ----

// LoginResponseUser is the user of an IdP login response.
type LoginResponseUser struct {
	Email string
}

// TemplateCallback customises a login response template (customTagReplacement); it
// returns the response id and XML.
type TemplateCallback func(template string) (id, context string)

// AttributeStatement builds the attribute statement of a login response template
// (SamlLib.attributeStatementBuilder).
func AttributeStatement(attrs []TemplateAttribute) string {
	var b strings.Builder
	for _, a := range attrs {
		line := `<saml:Attribute Name="{Name}" NameFormat="{NameFormat}"><saml:AttributeValue xmlns:xs="{ValueXmlnsXs}" xmlns:xsi="{ValueXmlnsXsi}" xsi:type="{ValueXsiType}">{Value}</saml:AttributeValue></saml:Attribute>`
		line = strings.Replace(line, "{Name}", a.Name, 1)
		line = strings.Replace(line, "{NameFormat}", a.NameFormat, 1)
		line = strings.Replace(line, "{ValueXmlnsXs}", "http://www.w3.org/2001/XMLSchema", 1)
		line = strings.Replace(line, "{ValueXmlnsXsi}", "http://www.w3.org/2001/XMLSchema-instance", 1)
		line = strings.Replace(line, "{ValueXsiType}", a.ValueXsiType, 1)
		line = strings.Replace(line, "{Value}", "{"+tagging("attr", a.ValueTag)+"}", 1)
		b.WriteString(line)
	}
	return "<saml:AttributeStatement>" + b.String() + "</saml:AttributeStatement>"
}

func tagging(prefix, content string) string {
	c := CamelCase(content)
	if c == "" {
		return prefix
	}
	return prefix + strings.ToUpper(c[:1]) + c[1:]
}

// LoginResponseTemplateContext returns the login response template of an IdP with its
// attribute statement expanded (entity-idp's tagPrefixedDefaults / attribute builder).
func (idp *Entity) LoginResponseTemplateContext() string {
	t := idp.Setting.LoginResponseTemplate
	if t == nil {
		return strings.Replace(DefaultLoginResponseTemplate, "{AttributeStatement}", "", 1)
	}
	ctx := t.Context
	if len(t.Attributes) > 0 {
		ctx = strings.Replace(ctx, "{AttributeStatement}", AttributeStatement(t.Attributes), 1)
	} else {
		ctx = strings.Replace(ctx, "{AttributeStatement}", "", 1)
	}
	return ctx
}

// CreateLoginResponse builds a signed (and optionally encrypted) login response for the
// post binding (IdentityProvider.createLoginResponse). When cb is nil the default tags are
// used. It returns the response id and the base64 response.
func (idp *Entity) CreateLoginResponse(sp *Entity, requestID string, user LoginResponseUser, cb TemplateCallback) (string, string, error) {
	var id, raw string
	if cb != nil {
		id, raw = cb(idp.LoginResponseTemplateContext())
	} else {
		id = idp.Setting.GenerateID()
		now := time.Now()
		later := now.Add(5 * time.Minute)
		acs, _ := sp.Meta.GetAssertionConsumerService(BindingPost)
		raw = ReplaceTagsByValue(idp.LoginResponseTemplateContext(), []Tag{
			T("ID", id), T("AssertionID", idp.Setting.GenerateID()), T("Destination", acs),
			T("Audience", sp.Meta.GetEntityID()), T("EntityID", sp.Meta.GetEntityID()), T("SubjectRecipient", acs),
			T("Issuer", idp.Meta.GetEntityID()), T("IssueInstant", ISOTime(now)), T("AssertionConsumerServiceURL", acs),
			T("StatusCode", StatusSuccess), T("ConditionsNotBefore", ISOTime(now)), T("ConditionsNotOnOrAfter", ISOTime(later)),
			T("SubjectConfirmationDataNotOnOrAfter", ISOTime(later)), Opt("NameIDFormat", idp.nameIDFormat()),
			T("NameID", user.Email), T("InResponseTo", requestID), T("AuthnStatement", ""), T("AttributeStatement", ""),
		})
	}
	opts := SignatureOptions{PrivateKey: idp.Setting.PrivateKey, PrivateKeyPass: idp.Setting.PrivateKeyPass,
		SignatureAlgorithm: idp.Setting.RequestSignatureAlgorithm, SigningCert: first(idp.Meta.GetX509Certificates("signing"))}
	var err error
	if sp.Meta.IsWantAssertionsSigned() {
		o := opts
		o.ReferenceLocalPath = []string{"Response", "Assertion"}
		o.AfterLocalName = "Issuer"
		if raw, err = ConstructSAMLSignature(raw, o); err != nil {
			return "", "", err
		}
	}
	if sp.Setting.WantMessageSigned || !sp.Meta.IsWantAssertionsSigned() {
		o := opts
		o.AfterLocalName = "Issuer"
		if raw, err = ConstructSAMLSignature(raw, o); err != nil {
			return "", "", err
		}
	}
	if idp.Setting.IsAssertionEncrypted {
		ctx, err := EncryptAssertion(idp, sp, raw)
		return id, ctx, err
	}
	return id, Base64Encode(raw), nil
}

// ParsedLoginRequest is the extract of an AuthnRequest.
type ParsedLoginRequest struct {
	ID          string
	SAMLContent string
}

// ParseLoginRequest parses a redirect-binding AuthnRequest (IdentityProvider.parseLoginRequest
// without signature checking).
func (idp *Entity) ParseLoginRequest(samlRequest string) (*ParsedLoginRequest, error) {
	xmlStr, err := InflateString(DecodeURIComponent(samlRequest))
	if err != nil {
		return nil, err
	}
	doc, err := ParseDocument(xmlStr)
	if err != nil {
		return nil, err
	}
	out := &ParsedLoginRequest{SAMLContent: xmlStr}
	for _, r := range SelectAbs(doc, "AuthnRequest") {
		out.ID, _ = AttrValue(r, "ID")
	}
	return out, nil
}
