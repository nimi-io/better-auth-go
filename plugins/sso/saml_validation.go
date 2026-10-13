package sso

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

// ---- error codes ----

// SAML error codes (SAML_ERROR_CODES).
var (
	ErrSingleLogoutNotEnabled = betterauth.ErrorCode{Code: "SINGLE_LOGOUT_NOT_ENABLED", Message: "Single Logout is not enabled"}
	ErrInvalidLogoutResponse  = betterauth.ErrorCode{Code: "INVALID_LOGOUT_RESPONSE", Message: "Invalid LogoutResponse"}
	ErrInvalidLogoutRequest   = betterauth.ErrorCode{Code: "INVALID_LOGOUT_REQUEST", Message: "Invalid LogoutRequest"}
	ErrLogoutFailedAtIdP      = betterauth.ErrorCode{Code: "LOGOUT_FAILED_AT_IDP", Message: "Logout failed at IdP"}
	ErrIdPSLONotSupported     = betterauth.ErrorCode{Code: "IDP_SLO_NOT_SUPPORTED", Message: "IdP does not support Single Logout Service"}
	ErrSAMLProviderNotFound   = betterauth.ErrorCode{Code: "SAML_PROVIDER_NOT_FOUND", Message: "SAML provider not found"}
	ErrCertSourceMissing      = betterauth.ErrorCode{Code: "CERT_SOURCE_MISSING", Message: "samlConfig requires either a signing certificate (cert or idpMetadata.cert) or an idpMetadata.metadata XML document."}
)

// ErrorCodes lists the plugin error codes.
var ErrorCodes = []betterauth.ErrorCode{ErrSingleLogoutNotEnabled, ErrInvalidLogoutResponse, ErrInvalidLogoutRequest,
	ErrLogoutFailedAtIdP, ErrIdPSLONotSupported, ErrSAMLProviderNotFound, ErrCertSourceMissing}

func apiErr(status string, kv ...any) *betterauth.APIError {
	return betterauth.NewAPIError(status, jsonx.O(kv...))
}

func badRequest(message string) *betterauth.APIError {
	return apiErr("BAD_REQUEST", "message", message)
}

// ---- algorithms ----

// SignatureAlgorithm URIs.
var SignatureAlgorithm = struct {
	RSA_SHA1, RSA_SHA256, RSA_SHA384, RSA_SHA512, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512 string
}{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
}

// DigestAlgorithm URIs.
var DigestAlgorithm = struct{ SHA1, SHA256, SHA384, SHA512 string }{
	"http://www.w3.org/2000/09/xmldsig#sha1",
	"http://www.w3.org/2001/04/xmlenc#sha256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384",
	"http://www.w3.org/2001/04/xmlenc#sha512",
}

// KeyEncryptionAlgorithm URIs.
var KeyEncryptionAlgorithm = struct{ RSA_1_5, RSA_OAEP, RSA_OAEP_SHA256 string }{
	"http://www.w3.org/2001/04/xmlenc#rsa-1_5",
	"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	"http://www.w3.org/2009/xmlenc11#rsa-oaep",
}

// DataEncryptionAlgorithm URIs.
var DataEncryptionAlgorithm = struct {
	TRIPLEDES_CBC, AES_128_CBC, AES_192_CBC, AES_256_CBC, AES_128_GCM, AES_192_GCM, AES_256_GCM string
}{
	"http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
	"http://www.w3.org/2001/04/xmlenc#aes128-cbc",
	"http://www.w3.org/2001/04/xmlenc#aes192-cbc",
	"http://www.w3.org/2001/04/xmlenc#aes256-cbc",
	"http://www.w3.org/2009/xmlenc11#aes128-gcm",
	"http://www.w3.org/2009/xmlenc11#aes192-gcm",
	"http://www.w3.org/2009/xmlenc11#aes256-gcm",
}

func inList(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

var secureSignatureAlgorithms = []string{SignatureAlgorithm.RSA_SHA256, SignatureAlgorithm.RSA_SHA384, SignatureAlgorithm.RSA_SHA512,
	SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.ECDSA_SHA384, SignatureAlgorithm.ECDSA_SHA512}
var secureDigestAlgorithms = []string{DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512}

var shortFormSignature = map[string]string{
	"sha1": SignatureAlgorithm.RSA_SHA1, "sha256": SignatureAlgorithm.RSA_SHA256, "sha384": SignatureAlgorithm.RSA_SHA384,
	"sha512": SignatureAlgorithm.RSA_SHA512, "rsa-sha1": SignatureAlgorithm.RSA_SHA1, "rsa-sha256": SignatureAlgorithm.RSA_SHA256,
	"rsa-sha384": SignatureAlgorithm.RSA_SHA384, "rsa-sha512": SignatureAlgorithm.RSA_SHA512, "ecdsa-sha256": SignatureAlgorithm.ECDSA_SHA256,
	"ecdsa-sha384": SignatureAlgorithm.ECDSA_SHA384, "ecdsa-sha512": SignatureAlgorithm.ECDSA_SHA512,
}

var shortFormDigest = map[string]string{"sha1": DigestAlgorithm.SHA1, "sha256": DigestAlgorithm.SHA256, "sha384": DigestAlgorithm.SHA384, "sha512": DigestAlgorithm.SHA512}

func normalizeSignatureAlgorithm(a string) string {
	if v, ok := shortFormSignature[strings.ToLower(a)]; ok {
		return v
	}
	return a
}

func normalizeDigestAlgorithm(a string) string {
	if v, ok := shortFormDigest[strings.ToLower(a)]; ok {
		return v
	}
	return a
}

// warnf prints SAML security warnings (console.warn upstream).
var warnf = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

func handleDeprecatedAlgorithm(message, behavior, code string) error {
	switch behavior {
	case "reject":
		return apiErr("BAD_REQUEST", "message", message, "code", code)
	case "allow":
		return nil
	}
	warnf("[SAML Security Warning] " + message)
	return nil
}

func algOpts(o *AlgorithmValidationOptions) AlgorithmValidationOptions {
	if o == nil {
		return AlgorithmValidationOptions{OnDeprecated: "warn"}
	}
	c := *o
	if c.OnDeprecated == "" {
		c.OnDeprecated = "warn"
	}
	return c
}

func validateSignatureAlgorithm(algorithm string, o *AlgorithmValidationOptions) error {
	if algorithm == "" {
		return nil
	}
	opts := algOpts(o)
	if opts.AllowedSignatureAlgorithms != nil {
		if !inList(opts.AllowedSignatureAlgorithms, algorithm) {
			return apiErr("BAD_REQUEST", "message", "SAML signature algorithm not in allow-list: "+algorithm, "code", "SAML_ALGORITHM_NOT_ALLOWED")
		}
		return nil
	}
	if algorithm == SignatureAlgorithm.RSA_SHA1 {
		return handleDeprecatedAlgorithm("SAML response uses deprecated signature algorithm: "+algorithm+". Please configure your IdP to use SHA-256 or stronger.", opts.OnDeprecated, "SAML_DEPRECATED_ALGORITHM")
	}
	if !inList(secureSignatureAlgorithms, algorithm) {
		return apiErr("BAD_REQUEST", "message", "SAML signature algorithm not recognized: "+algorithm, "code", "SAML_UNKNOWN_ALGORITHM")
	}
	return nil
}

func validateEncryptionAlgorithms(keyEnc, dataEnc string, o *AlgorithmValidationOptions) error {
	opts := algOpts(o)
	if keyEnc != "" {
		if opts.AllowedKeyEncryptionAlgorithms != nil {
			if !inList(opts.AllowedKeyEncryptionAlgorithms, keyEnc) {
				return apiErr("BAD_REQUEST", "message", "SAML key encryption algorithm not in allow-list: "+keyEnc, "code", "SAML_ALGORITHM_NOT_ALLOWED")
			}
		} else if keyEnc == KeyEncryptionAlgorithm.RSA_1_5 {
			if err := handleDeprecatedAlgorithm("SAML response uses deprecated key encryption algorithm: "+keyEnc+". Please configure your IdP to use RSA-OAEP.", opts.OnDeprecated, "SAML_DEPRECATED_ALGORITHM"); err != nil {
				return err
			}
		}
	}
	if dataEnc != "" {
		if opts.AllowedDataEncryptionAlgorithms != nil {
			if !inList(opts.AllowedDataEncryptionAlgorithms, dataEnc) {
				return apiErr("BAD_REQUEST", "message", "SAML data encryption algorithm not in allow-list: "+dataEnc, "code", "SAML_ALGORITHM_NOT_ALLOWED")
			}
		} else if dataEnc == DataEncryptionAlgorithm.TRIPLEDES_CBC {
			if err := handleDeprecatedAlgorithm("SAML response uses deprecated data encryption algorithm: "+dataEnc+". Please configure your IdP to use AES-GCM.", opts.OnDeprecated, "SAML_DEPRECATED_ALGORITHM"); err != nil {
				return err
			}
		}
	}
	return nil
}

func nodeAttr(v any, name string) string {
	n, ok := v.(*xNode)
	if !ok {
		return ""
	}
	s, _ := n.vals["@_"+name].(string)
	return s
}

func nodeChild(v any, name string) any {
	n, ok := v.(*xNode)
	if !ok {
		return nil
	}
	return n.vals[name]
}

func extractEncryptionAlgorithms(xml string) (string, string) {
	parsed, err := parseXMLObject(xml)
	if err != nil {
		return "", ""
	}
	keyAlg := nodeAttr(nodeChild(findNode(parsed, "EncryptedKey"), "EncryptionMethod"), "Algorithm")
	dataAlg := nodeAttr(nodeChild(findNode(parsed, "EncryptedData"), "EncryptionMethod"), "Algorithm")
	return keyAlg, dataAlg
}

func hasEncryptedAssertion(xml string) bool {
	parsed, err := parseXMLObject(xml)
	if err != nil {
		return false
	}
	return findNode(parsed, "EncryptedAssertion") != nil
}

// validateSAMLAlgorithms checks the response signature and encryption algorithms.
func validateSAMLAlgorithms(sigAlg, samlContent string, o *AlgorithmValidationOptions) error {
	if err := validateSignatureAlgorithm(sigAlg, o); err != nil {
		return err
	}
	if hasEncryptedAssertion(samlContent) {
		k, d := extractEncryptionAlgorithms(samlContent)
		return validateEncryptionAlgorithms(k, d, o)
	}
	return nil
}

// validateConfigAlgorithms checks configured signature/digest algorithms.
func validateConfigAlgorithms(signatureAlgorithm, digestAlgorithm string, o *AlgorithmValidationOptions) error {
	opts := algOpts(o)
	if signatureAlgorithm != "" {
		n := normalizeSignatureAlgorithm(signatureAlgorithm)
		if opts.AllowedSignatureAlgorithms != nil {
			var allowed []string
			for _, a := range opts.AllowedSignatureAlgorithms {
				allowed = append(allowed, normalizeSignatureAlgorithm(a))
			}
			if !inList(allowed, n) {
				return apiErr("BAD_REQUEST", "message", "SAML signature algorithm not in allow-list: "+signatureAlgorithm, "code", "SAML_ALGORITHM_NOT_ALLOWED")
			}
		} else if n == SignatureAlgorithm.RSA_SHA1 {
			if err := handleDeprecatedAlgorithm("SAML config uses deprecated signature algorithm: "+signatureAlgorithm+". Consider using SHA-256 or stronger.", opts.OnDeprecated, "SAML_DEPRECATED_CONFIG_ALGORITHM"); err != nil {
				return err
			}
		} else if !inList(secureSignatureAlgorithms, n) {
			return apiErr("BAD_REQUEST", "message", "SAML signature algorithm not recognized: "+signatureAlgorithm, "code", "SAML_UNKNOWN_ALGORITHM")
		}
	}
	if digestAlgorithm != "" {
		n := normalizeDigestAlgorithm(digestAlgorithm)
		if opts.AllowedDigestAlgorithms != nil {
			var allowed []string
			for _, a := range opts.AllowedDigestAlgorithms {
				allowed = append(allowed, normalizeDigestAlgorithm(a))
			}
			if !inList(allowed, n) {
				return apiErr("BAD_REQUEST", "message", "SAML digest algorithm not in allow-list: "+digestAlgorithm, "code", "SAML_ALGORITHM_NOT_ALLOWED")
			}
		} else if n == DigestAlgorithm.SHA1 {
			if err := handleDeprecatedAlgorithm("SAML config uses deprecated digest algorithm: "+digestAlgorithm+". Consider using SHA-256 or stronger.", opts.OnDeprecated, "SAML_DEPRECATED_CONFIG_ALGORITHM"); err != nil {
				return err
			}
		} else if !inList(secureDigestAlgorithms, n) {
			return apiErr("BAD_REQUEST", "message", "SAML digest algorithm not recognized: "+digestAlgorithm, "code", "SAML_UNKNOWN_ALGORITHM")
		}
	}
	return nil
}

// ---- assertions ----

type assertionCounts struct{ Assertions, EncryptedAssertions, Total int }

func countAssertions(xml string) (assertionCounts, error) {
	parsed, err := parseXMLObject(xml)
	if err != nil {
		return assertionCounts{}, apiErr("BAD_REQUEST", "message", "Failed to parse SAML response XML", "code", "SAML_INVALID_XML")
	}
	a := countAllNodes(parsed, "Assertion")
	e := countAllNodes(parsed, "EncryptedAssertion")
	return assertionCounts{a, e, a + e}, nil
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '\f', '\v', 0xa0, 0xfeff, 0x2028, 0x2029:
			return -1
		}
		return r
	}, s)
}

// validateSingleAssertion requires exactly one (encrypted) assertion.
func validateSingleAssertion(samlResponse string) error {
	raw, decErr := bacrypto.DecodeBase64Loose(stripWhitespace(samlResponse))
	xml := strings.ToValidUTF8(string(raw), "\uFFFD")
	if decErr != nil || !strings.Contains(xml, "<") {
		return apiErr("BAD_REQUEST", "message", "Invalid base64-encoded SAML response", "code", "SAML_INVALID_ENCODING")
	}
	counts, err := countAssertions(xml)
	if err != nil {
		return err
	}
	if counts.Total == 0 {
		return apiErr("BAD_REQUEST", "message", "SAML response contains no assertions", "code", "SAML_NO_ASSERTION")
	}
	if counts.Total > 1 {
		return apiErr("BAD_REQUEST", "message", fmt.Sprintf("SAML response contains %d assertions, expected exactly 1", counts.Total), "code", "SAML_MULTIPLE_ASSERTIONS")
	}
	return nil
}

func assertionSignatureFailure() *betterauth.APIError {
	return apiErr("BAD_REQUEST", "code", "SAML_ASSERTION_SIGNATURE_REQUIRED", "message", "SAML assertion signature is required")
}

// verifySAMLAssertionSignature requires the single assertion of the response to carry its
// own valid signature (response-level signatures are ignored).
func verifySAMLAssertionSignature(samlContent string, meta *samlify.Metadata) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(samlContent); err != nil {
		return assertionSignatureFailure()
	}
	resp := doc.Root()
	if resp == nil || resp.Tag != "Response" || resp.NamespaceURI() != samlify.NamespaceProtocol {
		return assertionSignatureFailure()
	}
	var assertions []*etree.Element
	for _, c := range resp.ChildElements() {
		if c.Tag == "Assertion" && c.NamespaceURI() == samlify.NamespaceAssertion {
			assertions = append(assertions, c)
		}
	}
	if len(assertions) != 1 {
		return assertionSignatureFailure()
	}
	assertion := assertions[0]
	sigs := 0
	for _, c := range assertion.ChildElements() {
		if c.Tag == "Signature" && c.NamespaceURI() == samlify.NamespaceDSig {
			sigs++
		}
	}
	if sigs != 1 {
		return assertionSignatureFailure()
	}
	for _, c := range resp.ChildElements() {
		if c.Tag == "Signature" {
			resp.RemoveChild(c)
		}
	}
	assertionID, ok := samlify.AttrValue(assertion, "ID")
	if !ok || assertionID == "" {
		return assertionSignatureFailure()
	}
	res, err := samlify.VerifySignature(samlify.DocumentString(doc), meta)
	if err != nil || !res.Verified || res.Assertion == "" {
		return assertionSignatureFailure()
	}
	adoc := etree.NewDocument()
	if err := adoc.ReadFromString(res.Assertion); err != nil {
		return assertionSignatureFailure()
	}
	root := adoc.Root()
	if root == nil || root.Tag != "Assertion" || root.NamespaceURI() != samlify.NamespaceAssertion {
		return assertionSignatureFailure()
	}
	if id, _ := samlify.AttrValue(root, "ID"); id != assertionID {
		return assertionSignatureFailure()
	}
	return nil
}

// ---- certificates ----

func resolveSigningCerts(c *SAMLConfig) []string {
	if c.IdpMetadata != nil && c.IdpMetadata.Cert != nil {
		return c.IdpMetadata.Cert.Values
	}
	if c.Cert != nil {
		return c.Cert.Values
	}
	return nil
}

func validateCertSources(c *SAMLConfig) error {
	hasMetadata := c.IdpMetadata != nil && c.IdpMetadata.Metadata != ""
	hasCert := (c.IdpMetadata != nil && c.IdpMetadata.Cert != nil) || c.Cert != nil
	if !hasMetadata && !hasCert {
		return betterauth.ErrFrom("BAD_REQUEST", ErrCertSourceMissing)
	}
	return nil
}

// ---- response binding ----

const samlHTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

func toNodeArray(v any) []*xNode {
	switch t := v.(type) {
	case *xNode:
		return []*xNode{t}
	case []any:
		var out []*xNode
		for _, x := range t {
			if n, ok := x.(*xNode); ok {
				out = append(out, n)
			}
		}
		return out
	}
	return nil
}

func firstXNode(v any) *xNode {
	if a := toNodeArray(v); len(a) > 0 {
		return a[0]
	}
	return nil
}

func toStringArray(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, toStringArray(x)...)
		}
		return out
	case *xNode:
		if s, ok := t.vals["#text"].(string); ok {
			return []string{s}
		}
	}
	return nil
}

func toStringSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		if v != "" {
			out[v] = true
		}
	}
	return out
}

// SAMLServiceProviderMetadata is the parsed SP metadata used for policy decisions.
type parsedSPMetadata struct {
	EntityID                         string
	NameIDFormats                    []string
	PostAssertionConsumerServiceURLs []string
	WantAssertionsSigned             bool
}

func directMetadataChildren(el *etree.Element, local string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == local && c.NamespaceURI() == samlify.NamespaceMetadata {
			out = append(out, c)
		}
	}
	return out
}

func parseXMLSchemaBoolean(v string, present bool) (bool, error) {
	if !present {
		return false, nil
	}
	switch strings.TrimSpace(v) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("Invalid XML Schema boolean")
}

func isAbsoluteHTTPURL(v string) bool {
	if strings.Contains(v, "#") {
		return false
	}
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// parseSAMLServiceProviderMetadata strictly parses SP metadata.
func parseSAMLServiceProviderMetadata(metadata string) (*parsedSPMetadata, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(metadata); err != nil {
		return nil, err
	}
	ed := doc.Root()
	if ed == nil || ed.Tag != "EntityDescriptor" || ed.NamespaceURI() != samlify.NamespaceMetadata {
		return nil, fmt.Errorf("Invalid SAML EntityDescriptor")
	}
	entityID, _ := samlify.AttrValue(ed, "entityID")
	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return nil, fmt.Errorf("Missing SAML entityID")
	}
	spds := directMetadataChildren(ed, "SPSSODescriptor")
	if len(spds) == 0 {
		return nil, fmt.Errorf("SAML metadata must contain an SPSSODescriptor")
	}
	accepted := map[*etree.Element]bool{}
	for _, s := range spds {
		accepted[s] = true
	}
	for _, el := range samlify.Descendants(ed) {
		switch el.Tag {
		case "EntityDescriptor":
			return nil, fmt.Errorf("Invalid nested SAML EntityDescriptor")
		case "SPSSODescriptor":
			if !accepted[el] {
				return nil, fmt.Errorf("Invalid SAML SPSSODescriptor namespace or position")
			}
		case "AssertionConsumerService", "NameIDFormat":
			if el.NamespaceURI() != samlify.NamespaceMetadata || el.Parent() == nil || !accepted[el.Parent()] {
				return nil, fmt.Errorf("Invalid SAML %s namespace or position", el.Tag)
			}
		}
	}
	out := &parsedSPMetadata{EntityID: entityID}
	seenFmt, seenACS := map[string]bool{}, map[string]bool{}
	for _, d := range spds {
		v, present := samlify.AttrValue(d, "WantAssertionsSigned")
		b, err := parseXMLSchemaBoolean(v, present)
		if err != nil {
			return nil, err
		}
		out.WantAssertionsSigned = b || out.WantAssertionsSigned
		for _, n := range directMetadataChildren(d, "NameIDFormat") {
			if v := strings.TrimSpace(samlify.TextContent(n)); v != "" && !seenFmt[v] {
				seenFmt[v] = true
				out.NameIDFormats = append(out.NameIDFormats, v)
			}
		}
		for _, s := range directMetadataChildren(d, "AssertionConsumerService") {
			if b, _ := samlify.AttrValue(s, "Binding"); b != samlHTTPPostBinding {
				continue
			}
			loc, _ := samlify.AttrValue(s, "Location")
			loc = strings.TrimSpace(loc)
			if loc == "" || !isAbsoluteHTTPURL(loc) {
				return nil, fmt.Errorf("Invalid SAML POST AssertionConsumerService")
			}
			if !seenACS[loc] {
				seenACS[loc] = true
				out.PostAssertionConsumerServiceURLs = append(out.PostAssertionConsumerServiceURLs, loc)
			}
		}
	}
	return out, nil
}

func getSAMLPostAssertionConsumerServiceURLs(metadata string) []string {
	if metadata == "" {
		return nil
	}
	p, err := parseSAMLServiceProviderMetadata(metadata)
	if err != nil {
		return nil
	}
	return p.PostAssertionConsumerServiceURLs
}

func hasSAMLEncryptedAssertion(samlContent string) bool {
	parsed, err := parseXMLObject(samlContent)
	if err != nil {
		return false
	}
	return countAllNodes(parsed, "EncryptedAssertion") > 0
}

// validateSAMLResponseBinding checks audience, bearer recipient and destination.
func validateSAMLResponseBinding(samlContent string, expectedAudiences, expectedRecipients []string) error {
	audiences := toStringSet(expectedAudiences)
	recipients := toStringSet(expectedRecipients)
	parsed, err := parseXMLObject(samlContent)
	if err != nil {
		return apiErr("BAD_REQUEST", "message", "SAML response XML could not be parsed", "code", "SAML_RESPONSE_INVALID_XML")
	}
	response := firstXNode(parsed.vals["Response"])
	var assertion *xNode
	if response != nil {
		assertion = firstXNode(response.vals["Assertion"])
	}
	if assertion == nil {
		assertion = firstXNode(parsed.vals["Assertion"])
	}
	if assertion == nil {
		return apiErr("BAD_REQUEST", "message", "SAML response is missing an assertion", "code", "SAML_ASSERTION_MISSING")
	}
	// audience restrictions
	conditions := firstXNode(assertion.vals["Conditions"])
	var groups [][]string
	if conditions != nil {
		for _, r := range toNodeArray(conditions.vals["AudienceRestriction"]) {
			var g []string
			for _, a := range toStringArray(r.vals["Audience"]) {
				if a != "" {
					g = append(g, a)
				}
			}
			groups = append(groups, g)
		}
	}
	allEmpty := true
	for _, g := range groups {
		if len(g) > 0 {
			allEmpty = false
		}
	}
	if len(groups) == 0 || allEmpty {
		return apiErr("BAD_REQUEST", "message", "SAML assertion is missing an AudienceRestriction", "code", "SAML_AUDIENCE_MISSING")
	}
	for _, g := range groups {
		ok := false
		for _, a := range g {
			if audiences[a] {
				ok = true
			}
		}
		if !ok {
			return apiErr("BAD_REQUEST", "message", "SAML assertion audience does not match this Service Provider", "code", "SAML_AUDIENCE_MISMATCH")
		}
	}
	// bearer recipient
	subject := firstXNode(assertion.vals["Subject"])
	var data []*xNode
	if subject != nil {
		for _, c := range toNodeArray(subject.vals["SubjectConfirmation"]) {
			if m, _ := c.vals["@_Method"].(string); m != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
				continue
			}
			if d := firstXNode(c.vals["SubjectConfirmationData"]); d != nil {
				data = append(data, d)
			}
		}
	}
	if len(data) == 0 {
		return apiErr("BAD_REQUEST", "message", "SAML assertion is missing bearer SubjectConfirmationData", "code", "SAML_BEARER_CONFIRMATION_MISSING")
	}
	var recs []string
	for _, d := range data {
		if r, ok := d.vals["@_Recipient"].(string); ok {
			recs = append(recs, r)
		}
	}
	if len(recs) == 0 {
		return apiErr("BAD_REQUEST", "message", "SAML bearer SubjectConfirmationData is missing a Recipient", "code", "SAML_RECIPIENT_MISSING")
	}
	matched := false
	for _, r := range recs {
		if recipients[r] {
			matched = true
		}
	}
	if !matched {
		return apiErr("BAD_REQUEST", "message", "SAML bearer SubjectConfirmationData Recipient does not match this Service Provider", "code", "SAML_RECIPIENT_MISMATCH")
	}
	if response != nil {
		if dest, ok := response.vals["@_Destination"].(string); ok && dest != "" && !recipients[dest] {
			return apiErr("BAD_REQUEST", "message", "SAML response Destination does not match this Service Provider", "code", "SAML_DESTINATION_MISMATCH")
		}
	}
	return nil
}

// ---- timestamps ----

// DefaultClockSkewMS is the default SAML clock skew (5 minutes).
const DefaultClockSkewMS = 5 * 60 * 1000

// DefaultMaxSAMLResponseSize is the default maximum SAMLResponse size (bytes).
const DefaultMaxSAMLResponseSize = 256 * 1024

// DefaultMaxSAMLMetadataSize is the default maximum metadata size (bytes).
const DefaultMaxSAMLMetadataSize = 100 * 1024

// SAMLConditions are assertion validity bounds.
type SAMLConditions struct {
	NotBefore    string
	NotOnOrAfter string
}

// TimestampValidationOptions configure ValidateSAMLTimestamp.
type TimestampValidationOptions struct {
	// ClockSkew in milliseconds (default DefaultClockSkewMS).
	ClockSkew         *int64
	RequireTimestamps bool
	Logger            interface{ Warn(msg string, args ...any) }
}

// ValidateSAMLTimestamp checks NotBefore / NotOnOrAfter with clock skew.
func ValidateSAMLTimestamp(conditions *SAMLConditions, o TimestampValidationOptions) error {
	skew := int64(DefaultClockSkewMS)
	if o.ClockSkew != nil {
		skew = *o.ClockSkew
	}
	if conditions == nil || (conditions.NotBefore == "" && conditions.NotOnOrAfter == "") {
		if o.RequireTimestamps {
			return apiErr("BAD_REQUEST", "message", "SAML assertion missing required timestamp conditions", "details", "Assertions must include NotBefore and/or NotOnOrAfter conditions")
		}
		if o.Logger != nil {
			o.Logger.Warn("SAML assertion accepted without timestamp conditions", slog.Bool("hasConditions", conditions != nil))
		}
		return nil
	}
	now := time.Now().UnixMilli()
	if conditions.NotBefore != "" {
		t, ok := samlify.ParseJSDate(conditions.NotBefore)
		if !ok {
			return apiErr("BAD_REQUEST", "message", "SAML assertion has invalid NotBefore timestamp", "details", "Unable to parse NotBefore value: "+conditions.NotBefore)
		}
		if now < t.UnixMilli()-skew {
			return apiErr("BAD_REQUEST", "message", "SAML assertion is not yet valid", "details", fmt.Sprintf("Current time is before NotBefore (with %dms clock skew tolerance)", skew))
		}
	}
	if conditions.NotOnOrAfter != "" {
		t, ok := samlify.ParseJSDate(conditions.NotOnOrAfter)
		if !ok {
			return apiErr("BAD_REQUEST", "message", "SAML assertion has invalid NotOnOrAfter timestamp", "details", "Unable to parse NotOnOrAfter value: "+conditions.NotOnOrAfter)
		}
		if now > t.UnixMilli()+skew {
			return apiErr("BAD_REQUEST", "message", "SAML assertion has expired", "details", fmt.Sprintf("Current time is after NotOnOrAfter (with %dms clock skew tolerance)", skew))
		}
	}
	return nil
}
