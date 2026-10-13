package samlify

import (
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Setting is a samlify entity setting (the subset used by @better-auth/sso and its tests).
type Setting struct {
	// Metadata is the metadata XML; when empty the metadata is generated from the fields
	// below.
	Metadata string

	EntityID                 string
	SigningCert              []string
	EncryptCert              []string
	AuthnRequestsSigned      bool
	WantAssertionsSigned     bool
	WantMessageSigned        bool
	WantAuthnRequestsSigned  bool
	WantLogoutRequestSigned  bool
	WantLogoutResponseSigned bool
	AllowCreate              bool
	IsAssertionEncrypted     bool
	NameIDFormat             []string
	SingleSignOnService      []Service
	SingleLogoutService      []Service
	AssertionConsumerService []Service

	// RequestSignatureAlgorithm defaults to rsa-sha256.
	RequestSignatureAlgorithm string
	DataEncryptionAlgorithm   string
	KeyEncryptionAlgorithm    string

	PrivateKey        string
	PrivateKeyPass    string
	EncPrivateKey     string
	EncPrivateKeyPass string

	RelayState string
	// ClockDrifts are [notBeforeDrift, notOnOrAfterDrift] in milliseconds.
	ClockDrifts *[2]int64

	// GenerateID returns message ids ("_" + uuid by default).
	GenerateID func() string
	// LoginResponseTemplate is an identity-provider login response template.
	LoginResponseTemplate *LoginResponseTemplate
}

// LoginResponseTemplate is samlify's loginResponseTemplate.
type LoginResponseTemplate struct {
	Context    string
	Attributes []TemplateAttribute
}

// TemplateAttribute is one attribute of a login response template.
type TemplateAttribute struct {
	Name         string
	NameFormat   string
	ValueTag     string
	ValueXsiType string
}

// Entity is an identity provider or service provider.
type Entity struct {
	Type    string // "idp" or "sp"
	Setting Setting
	Meta    *Metadata
}

func defaults(s *Setting) {
	if s.RequestSignatureAlgorithm == "" {
		s.RequestSignatureAlgorithm = SignatureRSASHA256
	}
	if s.DataEncryptionAlgorithm == "" {
		s.DataEncryptionAlgorithm = DataEncryptionAES256
	}
	if s.KeyEncryptionAlgorithm == "" {
		s.KeyEncryptionAlgorithm = KeyEncryptionOAEP
	}
	if s.GenerateID == nil {
		s.GenerateID = func() string { return "_" + bacrypto.RandomUUID() }
	}
}

// IdentityProvider builds an identity provider entity (saml.IdentityProvider).
func IdentityProvider(s Setting) (*Entity, error) {
	defaults(&s)
	xmlStr := s.Metadata
	if xmlStr == "" {
		var err error
		xmlStr, err = GenerateIdPMetadata(IdPMetadataOptions{
			EntityID:                s.EntityID,
			SigningCert:             s.SigningCert,
			EncryptCert:             s.EncryptCert,
			WantAuthnRequestsSigned: s.WantAuthnRequestsSigned,
			NameIDFormat:            s.NameIDFormat,
			SingleSignOnService:     s.SingleSignOnService,
			SingleLogoutService:     s.SingleLogoutService,
		})
		if err != nil {
			return nil, err
		}
	}
	meta, err := ParseMetadata(xmlStr)
	if err != nil {
		return nil, err
	}
	s.WantAuthnRequestsSigned = meta.IsWantAuthnRequestsSigned()
	if f := meta.GetNameIDFormat(); len(f) > 0 {
		s.NameIDFormat = f
	}
	return &Entity{Type: "idp", Setting: s, Meta: meta}, nil
}

// ServiceProvider builds a service provider entity (saml.ServiceProvider).
func ServiceProvider(s Setting) (*Entity, error) {
	defaults(&s)
	xmlStr := s.Metadata
	if xmlStr == "" {
		xmlStr = GenerateSPMetadata(SPMetadataOptions{
			EntityID:                 s.EntityID,
			SigningCert:              s.SigningCert,
			EncryptCert:              s.EncryptCert,
			AuthnRequestsSigned:      s.AuthnRequestsSigned,
			WantAssertionsSigned:     s.WantAssertionsSigned,
			NameIDFormat:             s.NameIDFormat,
			SingleLogoutService:      s.SingleLogoutService,
			AssertionConsumerService: s.AssertionConsumerService,
		})
	}
	meta, err := ParseMetadata(xmlStr)
	if err != nil {
		return nil, err
	}
	s.AuthnRequestsSigned = meta.IsAuthnRequestSigned()
	s.WantAssertionsSigned = meta.IsWantAssertionsSigned()
	if f := meta.GetNameIDFormat(); len(f) > 0 {
		s.NameIDFormat = f
	}
	return &Entity{Type: "sp", Setting: s, Meta: meta}, nil
}

// GetMetadata returns the entity metadata XML.
func (e *Entity) GetMetadata() string { return e.Meta.GetMetadata() }

func (e *Entity) nameIDFormat() string {
	if len(e.Setting.NameIDFormat) > 0 {
		return e.Setting.NameIDFormat[0]
	}
	return ""
}

func (e *Entity) clockDrifts() [2]int64 {
	if e.Setting.ClockDrifts != nil {
		return *e.Setting.ClockDrifts
	}
	return [2]int64{0, 0}
}
