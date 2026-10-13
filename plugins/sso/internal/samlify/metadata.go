package samlify

import (
	"errors"
	"strings"

	"github.com/beevik/etree"
)

// Service is a metadata endpoint (SingleSignOnService, SingleLogoutService,
// AssertionConsumerService).
type Service struct {
	Binding   string `json:"Binding"`
	Location  string `json:"Location"`
	IsDefault bool   `json:"isDefault,omitempty"`
}

// Metadata is the parsed metadata of an entity (samlify Metadata / IdpMetadata /
// SpMetadata). Values follow samlify's extractor semantics.
type Metadata struct {
	xml string

	entityID    string
	hasEntityID bool
	// certificates maps a KeyDescriptor use ("signing", "encryption") to its certificates.
	certificates map[string][]string
	slo          []map[string]string
	nameIDFormat []string

	// SP
	spDescriptorCount    int
	wantAssertionsSigned string
	authnRequestsSigned  string
	acs                  []map[string]string

	// IdP
	wantAuthnRequestsSigned    string
	hasWantAuthnRequestsSigned bool
	sso                        map[string][]string
}

// ParseMetadata extracts the entity metadata fields from xml.
func ParseMetadata(xmlStr string) (*Metadata, error) {
	m := &Metadata{xml: xmlStr, certificates: map[string][]string{}, sso: map[string][]string{}}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		return nil, err
	}
	if ed := SelectAbs(doc, "EntityDescriptor"); len(ed) > 1 {
		return nil, errors.New("ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR")
	}
	for _, e := range SelectAbs(doc, "EntityDescriptor") {
		if v, ok := AttrValue(e, "entityID"); ok {
			m.entityID, m.hasEntityID = v, true
			break
		}
	}
	// sharedCertificate: a single X509Certificate is used for both signing and encryption.
	certNodes := SelectAbs(doc, "EntityDescriptor", "~SSODescriptor", "KeyDescriptor", "KeyInfo", "X509Data", "X509Certificate")
	if len(certNodes) == 1 {
		v, _ := FirstText(certNodes[0])
		m.certificates["signing"] = []string{v}
		m.certificates["encryption"] = []string{v}
	} else {
		parents := SelectAbs(doc, "EntityDescriptor", "~SSODescriptor", "KeyDescriptor")
		var uses []string
		for _, p := range parents {
			if u, ok := AttrValue(p, "use"); ok {
				uses = append(uses, u)
			}
		}
		for i, use := range uses {
			if i >= len(parents) {
				break
			}
			var certs []string
			for _, c := range SelectRel(parents[i], "KeyInfo", "X509Data", "X509Certificate") {
				certs = append(certs, TextNodes(c)...)
			}
			m.certificates[use] = append(m.certificates[use], certs...)
		}
	}
	for _, s := range SelectAbs(doc, "EntityDescriptor", "~SSODescriptor", "SingleLogoutService") {
		m.slo = append(m.slo, attrMap(s, "Binding", "Location"))
	}
	nameIDs := SelectAbs(doc, "EntityDescriptor", "~SSODescriptor", "NameIDFormat")
	if len(nameIDs) == 1 {
		v, _ := FirstText(nameIDs[0])
		m.nameIDFormat = []string{v}
	} else {
		for _, n := range nameIDs {
			if v, ok := FirstText(n); ok {
				m.nameIDFormat = append(m.nameIDFormat, v)
			}
		}
	}
	// SP descriptor
	spd := SelectAbs(doc, "EntityDescriptor", "SPSSODescriptor")
	m.spDescriptorCount = len(spd)
	if len(spd) == 1 {
		m.wantAssertionsSigned, _ = AttrValue(spd[0], "WantAssertionsSigned")
		m.authnRequestsSigned, _ = AttrValue(spd[0], "AuthnRequestsSigned")
	}
	for _, a := range SelectAbs(doc, "EntityDescriptor", "SPSSODescriptor", "AssertionConsumerService") {
		m.acs = append(m.acs, attrMap(a, "Binding", "Location", "isDefault", "index"))
	}
	// IdP descriptor
	for _, idp := range SelectAbs(doc, "EntityDescriptor", "IDPSSODescriptor") {
		if v, ok := AttrValue(idp, "WantAuthnRequestsSigned"); ok {
			m.wantAuthnRequestsSigned, m.hasWantAuthnRequestsSigned = v, true
			break
		}
	}
	ssoNodes := SelectAbs(doc, "EntityDescriptor", "IDPSSODescriptor", "SingleSignOnService")
	var bindings []string
	for _, s := range ssoNodes {
		if b, ok := AttrValue(s, "Binding"); ok {
			bindings = append(bindings, b)
		}
	}
	for i, b := range bindings {
		if i >= len(ssoNodes) {
			break
		}
		if loc, ok := AttrValue(ssoNodes[i], "Location"); ok {
			m.sso[b] = append(m.sso[b], loc)
		}
	}
	return m, nil
}

func attrMap(e *etree.Element, names ...string) map[string]string {
	out := map[string]string{}
	for _, a := range e.Attr {
		if a.Space != "" {
			continue
		}
		for _, n := range names {
			if a.Key == n {
				out[CamelCase(n)] = a.Value
			}
		}
	}
	return out
}

// GetMetadata returns the metadata XML.
func (m *Metadata) GetMetadata() string { return m.xml }

// GetEntityID returns the entityID ("" when missing).
func (m *Metadata) GetEntityID() string { return m.entityID }

// HasEntityID reports whether the EntityDescriptor declares an entityID.
func (m *Metadata) HasEntityID() bool { return m.hasEntityID }

// GetX509Certificates returns the certificates for a use ("signing" / "encryption").
func (m *Metadata) GetX509Certificates(use string) []string {
	return append([]string(nil), m.certificates[use]...)
}

// GetNameIDFormat returns the declared NameID formats.
func (m *Metadata) GetNameIDFormat() []string { return m.nameIDFormat }

// GetSingleLogoutService returns the SingleLogoutService location for a binding.
func (m *Metadata) GetSingleLogoutService(binding string) (string, bool) {
	urn := BindingURN(binding)
	for _, s := range m.slo {
		if s["binding"] == urn {
			loc, ok := s["location"]
			return loc, ok
		}
	}
	return "", false
}

// HasSingleLogoutService reports whether any SingleLogoutService is declared.
func (m *Metadata) HasSingleLogoutService() bool { return len(m.slo) > 0 }

// IsWantAssertionsSigned is SpMetadata.isWantAssertionsSigned.
func (m *Metadata) IsWantAssertionsSigned() bool { return m.wantAssertionsSigned == "true" }

// IsAuthnRequestSigned is SpMetadata.isAuthnRequestSigned.
func (m *Metadata) IsAuthnRequestSigned() bool { return m.authnRequestsSigned == "true" }

// GetAssertionConsumerService returns the (last) AssertionConsumerService location for
// a binding.
func (m *Metadata) GetAssertionConsumerService(binding string) (string, bool) {
	urn := BindingURN(binding)
	loc, found := "", false
	for _, a := range m.acs {
		if a["binding"] == urn {
			loc, found = a["location"], true
		}
	}
	return loc, found
}

// IsWantAuthnRequestsSigned is IdpMetadata.isWantAuthnRequestsSigned.
func (m *Metadata) IsWantAuthnRequestsSigned() bool {
	return m.hasWantAuthnRequestsSigned && m.wantAuthnRequestsSigned == "true"
}

// GetSingleSignOnService returns the SingleSignOnService locations for a binding (a single
// location is required for request creation).
func (m *Metadata) GetSingleSignOnService(binding string) []string {
	return append([]string(nil), m.sso[BindingURN(binding)]...)
}

// SingleSignOnServiceLocation returns the location when exactly one is declared for the
// binding (samlify's `typeof base === "string"`).
func (m *Metadata) SingleSignOnServiceLocation(binding string) (string, bool) {
	l := m.sso[BindingURN(binding)]
	if len(l) == 1 {
		return l[0], true
	}
	return "", false
}

// ---- generation (xml package output) ----

type xmlNode struct {
	name     string
	attrs    [][2]string
	text     *string
	children []*xmlNode
}

func (n *xmlNode) write(b *strings.Builder) {
	b.WriteString("<" + n.name)
	for _, a := range n.attrs {
		b.WriteString(" " + a[0] + "=\"" + escapeForXML(a[1]) + "\"")
	}
	// the xml package always emits explicit end tags
	b.WriteString(">")
	if n.text != nil {
		b.WriteString(escapeForXML(*n.text))
	}
	for _, c := range n.children {
		c.write(b)
	}
	b.WriteString("</" + n.name + ">")
}

func escapeForXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "\"", "&quot;", "'", "&apos;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func textNode(name, text string) *xmlNode { return &xmlNode{name: name, text: &text} }

// NormalizeCerString strips PEM armour and whitespace (utility.normalizeCerString).
func NormalizeCerString(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.Replace(s, "-----BEGIN CERTIFICATE-----", "", 1)
	s = strings.Replace(s, "-----END CERTIFICATE-----", "", 1)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}

func keyDescriptor(use, cert string) *xmlNode {
	return &xmlNode{name: "KeyDescriptor", attrs: [][2]string{{"use", use}}, children: []*xmlNode{
		{name: "ds:KeyInfo", attrs: [][2]string{{"xmlns:ds", NamespaceDSig}}, children: []*xmlNode{
			{name: "ds:X509Data", children: []*xmlNode{textNode("ds:X509Certificate", NormalizeCerString(cert))}},
		}},
	}}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// SPMetadataOptions build SP metadata (samlify SPMetadata settings).
type SPMetadataOptions struct {
	EntityID                 string
	SigningCert              []string
	EncryptCert              []string
	AuthnRequestsSigned      bool
	WantAssertionsSigned     bool
	NameIDFormat             []string
	SingleLogoutService      []Service
	AssertionConsumerService []Service
}

// GenerateSPMetadata builds SP metadata XML (SpMetadata with a settings object).
func GenerateSPMetadata(o SPMetadataOptions) string {
	desc := &xmlNode{name: "SPSSODescriptor", attrs: [][2]string{
		{"AuthnRequestsSigned", boolStr(o.AuthnRequestsSigned)},
		{"WantAssertionsSigned", boolStr(o.WantAssertionsSigned)},
		{"protocolSupportEnumeration", NamespaceProtocol},
	}}
	for _, c := range o.SigningCert {
		desc.children = append(desc.children, keyDescriptor("signing", c))
	}
	for _, c := range o.EncryptCert {
		desc.children = append(desc.children, keyDescriptor("encryption", c))
	}
	formats := o.NameIDFormat
	if len(formats) == 0 {
		formats = []string{NameIDFormatEmailAddress}
	}
	for _, f := range formats {
		desc.children = append(desc.children, textNode("NameIDFormat", f))
	}
	for _, s := range o.SingleLogoutService {
		attrs := [][2]string{{"Binding", s.Binding}, {"Location", s.Location}}
		if s.IsDefault {
			attrs = append(attrs, [2]string{"isDefault", "true"})
		}
		desc.children = append(desc.children, &xmlNode{name: "SingleLogoutService", attrs: attrs})
	}
	for i, s := range o.AssertionConsumerService {
		attrs := [][2]string{{"index", itoa(i)}, {"Binding", s.Binding}, {"Location", s.Location}}
		if s.IsDefault {
			attrs = append(attrs, [2]string{"isDefault", "true"})
		}
		desc.children = append(desc.children, &xmlNode{name: "AssertionConsumerService", attrs: attrs})
	}
	root := &xmlNode{name: "EntityDescriptor", attrs: [][2]string{
		{"entityID", o.EntityID},
		{"xmlns", NamespaceMetadata},
		{"xmlns:assertion", NamespaceAssertion},
		{"xmlns:ds", NamespaceDSig},
	}, children: []*xmlNode{desc}}
	var b strings.Builder
	root.write(&b)
	return b.String()
}

// IdPMetadataOptions build IdP metadata (samlify IdPMetadata settings).
type IdPMetadataOptions struct {
	EntityID                string
	SigningCert             []string
	EncryptCert             []string
	WantAuthnRequestsSigned bool
	NameIDFormat            []string
	SingleSignOnService     []Service
	SingleLogoutService     []Service
}

// GenerateIdPMetadata builds IdP metadata XML (IdpMetadata with a settings object).
func GenerateIdPMetadata(o IdPMetadataOptions) (string, error) {
	desc := &xmlNode{name: "IDPSSODescriptor", attrs: [][2]string{
		{"WantAuthnRequestsSigned", boolStr(o.WantAuthnRequestsSigned)},
		{"protocolSupportEnumeration", NamespaceProtocol},
	}}
	for _, c := range o.SigningCert {
		desc.children = append(desc.children, keyDescriptor("signing", c))
	}
	for _, c := range o.EncryptCert {
		desc.children = append(desc.children, keyDescriptor("encryption", c))
	}
	for _, f := range o.NameIDFormat {
		desc.children = append(desc.children, textNode("NameIDFormat", f))
	}
	if len(o.SingleSignOnService) == 0 {
		return "", errors.New("ERR_IDP_METADATA_MISSING_SINGLE_SIGN_ON_SERVICE")
	}
	for _, s := range o.SingleSignOnService {
		attrs := [][2]string{{"Binding", s.Binding}, {"Location", s.Location}}
		if s.IsDefault {
			attrs = append(attrs, [2]string{"isDefault", "true"})
		}
		desc.children = append(desc.children, &xmlNode{name: "SingleSignOnService", attrs: attrs})
	}
	for _, s := range o.SingleLogoutService {
		var attrs [][2]string
		if s.IsDefault {
			attrs = append(attrs, [2]string{"isDefault", "true"})
		}
		attrs = append(attrs, [2]string{"Binding", s.Binding}, [2]string{"Location", s.Location})
		desc.children = append(desc.children, &xmlNode{name: "SingleLogoutService", attrs: attrs})
	}
	root := &xmlNode{name: "EntityDescriptor", attrs: [][2]string{
		{"xmlns", NamespaceMetadata},
		{"xmlns:assertion", NamespaceAssertion},
		{"xmlns:ds", NamespaceDSig},
		{"entityID", o.EntityID},
	}, children: []*xmlNode{desc}}
	var b strings.Builder
	root.write(&b)
	return b.String(), nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
