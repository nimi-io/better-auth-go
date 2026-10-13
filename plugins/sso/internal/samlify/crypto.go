package samlify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SAML rsa-sha1 interop
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// ---- keys and certificates ----

// ParsePrivateKey parses a PEM private key (PKCS#1, PKCS#8, SEC1, or legacy encrypted PEM
// with passphrase), like utility.readPrivateKey + Node's createPrivateKey.
func ParsePrivateKey(keyPEM, passphrase string) (crypto.Signer, error) {
	data := []byte(normalizeKeyPEM(keyPEM))
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid private key")
		}
		data = rest
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		der := block.Bytes
		//nolint:staticcheck // legacy PEM encryption is what samlify fixtures use
		if x509.IsEncryptedPEMBlock(block) {
			if passphrase == "" {
				return nil, errors.New("private key is encrypted but no passphrase was provided")
			}
			var err error
			//nolint:staticcheck
			der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
			if err != nil {
				return nil, err
			}
		}
		if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
			return k, nil
		}
		if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
			return nil, errors.New("unsupported private key type")
		}
		if k, err := x509.ParseECPrivateKey(der); err == nil {
			return k, nil
		}
		return nil, errors.New("invalid private key")
	}
}

// normalizeKeyPEM trims each line (normalizePem upstream) so indented PEM parses.
func normalizeKeyPEM(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.TrimSpace(strings.Join(lines, "\n")) + "\n"
}

// ParseCertificate parses a certificate given as PEM or bare base64 (whitespace ignored).
func ParseCertificate(s string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(NormalizeCerString(s))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ---- detached message signatures (redirect binding) ----

func hashFor(sigAlg string) (crypto.Hash, bool, error) {
	switch sigAlg {
	case "", SignatureRSASHA256:
		return crypto.SHA256, false, nil
	case SignatureRSASHA1:
		return crypto.SHA1, false, nil
	case SignatureRSASHA512:
		return crypto.SHA512, false, nil
	case "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1":
		return crypto.SHA256, true, nil
	}
	return 0, false, errors.New("ERR_UNSUPPORTED_SIGNATURE_ALGORITHM")
}

func digest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA1:
		s := sha1.Sum(data) //nolint:gosec
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	s := sha256.Sum256(data)
	return s[:]
}

// ConstructMessageSignature signs an octet string (libsaml.constructMessageSignature).
func ConstructMessageSignature(octetString, keyPEM, passphrase, sigAlg string) (string, error) {
	signer, err := ParsePrivateKey(keyPEM, passphrase)
	if err != nil {
		return "", err
	}
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("message signatures require an RSA key")
	}
	h, pss, err := hashFor(sigAlg)
	if err != nil {
		return "", err
	}
	d := digest(h, []byte(octetString))
	var sig []byte
	if pss {
		sig, err = rsa.SignPSS(rand.Reader, key, h, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, h, d)
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyMessageSignature verifies a detached signature with the first signing certificate
// of the metadata (libsaml.verifyMessageSignature).
func VerifyMessageSignature(meta *Metadata, octetString string, signature []byte, sigAlg string) bool {
	certs := meta.GetX509Certificates("signing")
	if len(certs) == 0 || octetString == "" {
		return false
	}
	cert, err := ParseCertificate(certs[0])
	if err != nil {
		return false
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	h, pss, err := hashFor(sigAlg)
	if err != nil {
		return false
	}
	d := digest(h, []byte(octetString))
	if pss {
		return rsa.VerifyPSS(pub, h, d, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}
	return rsa.VerifyPKCS1v15(pub, h, d, signature) == nil
}

// ---- XML signatures ----

// SignatureOptions configure ConstructSAMLSignature.
type SignatureOptions struct {
	// ReferenceLocalPath selects the element to sign by absolute local-name path from the
	// root (e.g. ["Response", "Assertion"]); empty signs the root (isMessageSigned).
	ReferenceLocalPath []string
	PrivateKey         string
	PrivateKeyPass     string
	// SignatureAlgorithm defaults to rsa-sha256.
	SignatureAlgorithm string
	SigningCert        string
	// AfterLocalName places the signature after this child of the signed element
	// (signatureConfig.location { action: "after" }); empty appends it.
	AfterLocalName string
}

// ConstructSAMLSignature signs an element of rawXML with an enveloped exc-c14n signature
// and returns the signed XML (SamlLib.constructSAMLSignature with isBase64Output false).
func ConstructSAMLSignature(rawXML string, o SignatureOptions) (string, error) {
	doc, err := ParseDocument(rawXML)
	if err != nil {
		return "", err
	}
	target := doc.Root()
	if len(o.ReferenceLocalPath) > 0 {
		els := SelectAbs(doc, o.ReferenceLocalPath...)
		if len(els) == 0 {
			return "", errors.New("reference element not found")
		}
		target = els[0]
	}
	signer, err := ParsePrivateKey(o.PrivateKey, o.PrivateKeyPass)
	if err != nil {
		return "", err
	}
	var certs [][]byte
	if o.SigningCert != "" {
		der, err := base64.StdEncoding.DecodeString(NormalizeCerString(o.SigningCert))
		if err != nil {
			return "", err
		}
		certs = [][]byte{der}
	}
	ctx, err := dsig.NewSigningContext(signer, certs)
	if err != nil {
		return "", err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	switch o.SignatureAlgorithm {
	case "", SignatureRSASHA256:
		ctx.Hash = crypto.SHA256
	case SignatureRSASHA1:
		ctx.Hash = crypto.SHA1
	case SignatureRSASHA512:
		ctx.Hash = crypto.SHA512
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
		ctx.Hash = crypto.SHA384
	default:
		if err := ctx.SetSignatureMethod(o.SignatureAlgorithm); err != nil {
			return "", err
		}
	}
	if _, ok := signer.(*ecdsa.PrivateKey); ok && o.SignatureAlgorithm == "" {
		ctx.Hash = crypto.SHA256
	}
	detached := DetachWithNamespaces(target)
	sig, err := ctx.ConstructSignature(detached, true)
	if err != nil {
		return "", err
	}
	pos := len(target.Child)
	if o.AfterLocalName != "" {
		for _, c := range target.ChildElements() {
			if c.Tag == o.AfterLocalName {
				pos = c.Index() + 1
				break
			}
		}
	}
	target.InsertChildAt(pos, sig)
	return DocumentString(doc), nil
}

// VerifyResult is the outcome of VerifySignature: whether a signature verified and the
// verified assertion (or verified Response containing an EncryptedAssertion) XML.
type VerifyResult struct {
	Verified bool
	// Assertion is the authenticated assertion XML ("" when the verified element carries
	// no usable assertion).
	Assertion string
}

// ErrPotentialWrappingAttack is returned when SubjectConfirmationData contains an
// Assertion or Signature (libsaml.verifySignature).
var ErrPotentialWrappingAttack = errors.New("ERR_POTENTIAL_WRAPPING_ATTACK")

func isSignatureEl(e *etree.Element) bool { return e.Tag == "Signature" }

// VerifySignature verifies the message signature (a Signature child of the root
// Response/Request) or the assertion signature (a Signature child of a root
// Response/Assertion), in that order, mirroring samlify's absolute-XPath selection that
// defends against signature wrapping. The certificate embedded in the signature must match
// one of the metadata signing certificates (when the metadata declares any); otherwise the
// first metadata certificate is used.
func VerifySignature(xmlStr string, meta *Metadata) (VerifyResult, error) {
	doc, err := ParseDocument(xmlStr)
	if err != nil {
		return VerifyResult{}, err
	}
	root := doc.Root()
	isMsg := strings.Contains(root.Tag, "Response") || strings.Contains(root.Tag, "Request")
	var selection []*etree.Element
	if isMsg {
		for _, c := range root.ChildElements() {
			if isSignatureEl(c) {
				selection = append(selection, c)
			}
		}
		for _, a := range root.ChildElements() {
			if a.Tag != "Assertion" {
				continue
			}
			for _, c := range a.ChildElements() {
				if isSignatureEl(c) {
					selection = append(selection, c)
				}
			}
		}
	}
	if strings.Contains(root.Tag, "Response") {
		for _, scd := range SelectRel(root, "Assertion", "Subject", "SubjectConfirmation", "SubjectConfirmationData") {
			for _, d := range Descendants(scd) {
				if d.Tag == "Assertion" || d.Tag == "Signature" {
					return VerifyResult{}, ErrPotentialWrappingAttack
				}
			}
		}
	}
	if len(selection) == 0 {
		return VerifyResult{}, nil
	}
	var metaCerts []string
	if meta != nil {
		for _, c := range meta.GetX509Certificates("signing") {
			metaCerts = append(metaCerts, NormalizeCerString(c))
		}
	}
	for _, sigEl := range selection {
		var embedded []*etree.Element
		for _, d := range Descendants(sigEl) {
			if d.Tag == "X509Certificate" {
				embedded = append(embedded, d)
			}
		}
		if len(embedded) == 0 && len(metaCerts) == 0 {
			return VerifyResult{}, errors.New("NO_SELECTED_CERTIFICATE")
		}
		var certStr string
		if len(embedded) > 0 {
			certStr = NormalizeCerString(TextContent(embedded[0]))
			if len(metaCerts) >= 1 {
				found := false
				for _, mc := range metaCerts {
					if strings.TrimSpace(mc) == strings.TrimSpace(certStr) {
						found = true
						break
					}
				}
				if !found {
					return VerifyResult{}, errors.New("ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA")
				}
			}
		} else {
			certStr = metaCerts[0]
		}
		verified, err := validateSignatureElement(doc, sigEl, certStr, len(embedded) == 0)
		if err != nil {
			if errors.Is(err, errDuplicateID) {
				return VerifyResult{}, err
			}
			continue
		}
		switch verified.Tag {
		case "Response":
			var assertions, encrypted []*etree.Element
			for _, c := range verified.ChildElements() {
				switch c.Tag {
				case "Assertion":
					assertions = append(assertions, c)
				case "EncryptedAssertion":
					encrypted = append(encrypted, c)
				}
			}
			if len(assertions) == 1 {
				return VerifyResult{Verified: true, Assertion: ElementString(assertions[0])}, nil
			}
			if len(encrypted) >= 1 {
				return VerifyResult{Verified: true, Assertion: ElementString(verified)}, nil
			}
			return VerifyResult{Verified: true}, nil
		case "Assertion":
			return VerifyResult{Verified: true, Assertion: ElementString(verified)}, nil
		}
		return VerifyResult{Verified: true}, nil
	}
	return VerifyResult{}, nil
}

var errDuplicateID = errors.New("Cannot validate a document which contains multiple elements with the same value for the ID / Id / Id attributes, in order to prevent signature wrapping attack.")

func idOf(e *etree.Element) (string, bool) {
	for _, k := range []string{"ID", "Id", "id"} {
		if v, ok := LocalAttrValue(e, k); ok {
			return v, true
		}
	}
	return "", false
}

// validateSignatureElement validates sigEl with goxmldsig against the single trusted
// certificate certStr and returns the verified (canonicalised) referenced element.
func validateSignatureElement(doc *etree.Document, sigEl *etree.Element, certStr string, stripKeyInfo bool) (*etree.Element, error) {
	var uri string
	for _, si := range sigEl.ChildElements() {
		if si.Tag != "SignedInfo" {
			continue
		}
		for _, ref := range si.ChildElements() {
			if ref.Tag == "Reference" {
				uri, _ = AttrValue(ref, "URI")
				break
			}
		}
	}
	var target *etree.Element
	if uri == "" {
		target = doc.Root()
	} else {
		id := strings.TrimPrefix(uri, "#")
		var matches []*etree.Element
		all := append([]*etree.Element{doc.Root()}, Descendants(doc.Root())...)
		for _, e := range all {
			if v, ok := idOf(e); ok && v == id {
				matches = append(matches, e)
			}
		}
		if len(matches) > 1 {
			return nil, errDuplicateID
		}
		if len(matches) == 0 {
			return nil, errors.New("reference not found")
		}
		target = matches[0]
	}
	// the signature must be enveloped by the referenced element
	inside := false
	for p := sigEl.Parent(); p != nil; p = p.Parent() {
		if p == target {
			inside = true
			break
		}
	}
	if !inside {
		return nil, errors.New("signature is not enveloped by the referenced element")
	}
	cert, err := ParseCertificate(certStr)
	if err != nil {
		return nil, err
	}
	detached := DetachWithNamespaces(target)
	if stripKeyInfo {
		// samlify falls back to the metadata certificate when the signature carries no
		// X509Certificate; goxmldsig would reject a KeyInfo without one.
		if path := pathTo(target, sigEl); path != nil {
			if sigCopy := elementAt(detached, path); sigCopy != nil {
				for _, c := range sigCopy.ChildElements() {
					if c.Tag == "KeyInfo" {
						sigCopy.RemoveChild(c)
					}
				}
			}
		}
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	// samlify does not enforce certificate validity periods.
	vc.Clock = dsig.NewFakeClockAt(cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2))
	for _, k := range []string{"ID", "Id", "id"} {
		if _, ok := AttrValue(target, k); ok {
			vc.IdAttribute = k
			break
		}
	}
	return vc.Validate(detached)
}

func pathTo(root, el *etree.Element) []int {
	var path []int
	for e := el; e != root; e = e.Parent() {
		if e == nil {
			return nil
		}
		path = append([]int{e.Index()}, path...)
	}
	return path
}

func elementAt(root *etree.Element, path []int) *etree.Element {
	cur := root
	for _, i := range path {
		if i >= len(cur.Child) {
			return nil
		}
		e, ok := cur.Child[i].(*etree.Element)
		if !ok {
			return nil
		}
		cur = e
	}
	return cur
}
