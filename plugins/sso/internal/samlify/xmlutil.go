// Package samlify is a Go port of the parts of the samlify library (v2.13) that
// @better-auth/sso uses: SAML metadata parsing and generation, AuthnRequest / LogoutRequest /
// LogoutResponse creation for the HTTP-Redirect and HTTP-POST bindings, the inbound message
// "flow" (status checks, XML signature verification with signature-wrapping guards,
// assertion decryption, field extraction and time-window checks), plus the identity-provider
// side helpers used by tests (login responses, logout messages, assertion encryption).
//
// XML signatures are verified and produced with github.com/russellhaering/goxmldsig; this
// package only selects which signature/element to validate (mirroring samlify's absolute
// XPath selection) and which certificate to trust.
package samlify

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Binding URNs and short names (Constants.namespace.binding / wording.binding).
const (
	BindingRedirect   = "redirect"
	BindingPost       = "post"
	BindingSimpleSign = "simpleSign"

	BindingRedirectURN   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPostURN       = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingSimpleSignURN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"

	NamespaceMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	NamespaceAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NamespaceProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NamespaceDSig      = "http://www.w3.org/2000/09/xmldsig#"

	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

	NameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

	SignatureRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SignatureRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

	DataEncryptionAES256 = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	KeyEncryptionOAEP    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
)

// BindingURN maps a short binding name to its URN ("" when unknown).
func BindingURN(binding string) string {
	switch binding {
	case BindingRedirect:
		return BindingRedirectURN
	case BindingPost:
		return BindingPostURN
	case BindingSimpleSign:
		return BindingSimpleSignURN
	}
	return ""
}

// ---- parsing ----

// ParseDocument parses XML into an etree document.
func ParseDocument(s string) (*etree.Document, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(s); err != nil {
		return nil, err
	}
	if doc.Root() == nil {
		return nil, errors.New("missing root element")
	}
	return doc, nil
}

// IsValidXML is the schema validator installed upstream (fast-xml-parser's
// XMLValidator.validate with allowBooleanAttributes): the input must be well-formed with a
// single root element.
func IsValidXML(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("ERR_INVALID_XML")
	}
	dec := xml.NewDecoder(strings.NewReader(s))
	dec.Strict = true
	dec.Entity = xml.HTMLEntity
	depth, roots := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("ERR_INVALID_XML")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return errors.New("ERR_INVALID_XML")
			}
		}
	}
	if roots != 1 || depth != 0 {
		return errors.New("ERR_INVALID_XML")
	}
	return nil
}

// ElementString serializes an element (with the namespace declarations it needs from its
// ancestors, like xmldom's node.toString()).
func ElementString(el *etree.Element) string {
	detached := DetachWithNamespaces(el)
	doc := etree.NewDocument()
	doc.SetRoot(detached)
	s, _ := doc.WriteToString()
	return s
}

// DocumentString serializes a whole document.
func DocumentString(doc *etree.Document) string {
	s, _ := doc.WriteToString()
	return s
}

// DetachWithNamespaces copies el and adds the namespace declarations in scope at el that
// are not declared on it.
func DetachWithNamespaces(el *etree.Element) *etree.Element {
	cp := el.Copy()
	declared := map[string]bool{}
	for _, a := range cp.Attr {
		if a.Space == "xmlns" {
			declared[a.Key] = true
		} else if a.Space == "" && a.Key == "xmlns" {
			declared[""] = true
		}
	}
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			var prefix string
			switch {
			case a.Space == "xmlns":
				prefix = a.Key
			case a.Space == "" && a.Key == "xmlns":
				prefix = ""
			default:
				continue
			}
			if declared[prefix] {
				continue
			}
			declared[prefix] = true
			if prefix == "" {
				cp.Attr = append(cp.Attr, etree.Attr{Key: "xmlns", Value: a.Value})
			} else {
				cp.Attr = append(cp.Attr, etree.Attr{Space: "xmlns", Key: prefix, Value: a.Value})
			}
		}
	}
	return cp
}

// ---- element helpers ----

// ChildElements returns the element children of e.
func ChildElements(e *etree.Element) []*etree.Element {
	if e == nil {
		return nil
	}
	return e.ChildElements()
}

// AttrValue returns an unprefixed attribute value.
func AttrValue(e *etree.Element, name string) (string, bool) {
	if e == nil {
		return "", false
	}
	for _, a := range e.Attr {
		if a.Space == "" && a.Key == name {
			return a.Value, true
		}
	}
	return "", false
}

// LocalAttrValue returns the value of an attribute matched by local name (any prefix).
func LocalAttrValue(e *etree.Element, local string) (string, bool) {
	for _, a := range e.Attr {
		if a.Key == local && a.Space != "xmlns" {
			return a.Value, true
		}
	}
	return "", false
}

// FirstText returns the value of the first text node child (string(path/text())).
func FirstText(e *etree.Element) (string, bool) {
	for _, t := range e.Child {
		if cd, ok := t.(*etree.CharData); ok {
			return cd.Data, true
		}
	}
	return "", false
}

// TextNodes returns the values of all text node children.
func TextNodes(e *etree.Element) []string {
	var out []string
	for _, t := range e.Child {
		if cd, ok := t.(*etree.CharData); ok {
			out = append(out, cd.Data)
		}
	}
	return out
}

// TextContent is the DOM textContent (concatenated descendant text).
func TextContent(e *etree.Element) string {
	var b strings.Builder
	var walk func(*etree.Element)
	walk = func(x *etree.Element) {
		for _, t := range x.Child {
			switch v := t.(type) {
			case *etree.CharData:
				b.WriteString(v.Data)
			case *etree.Element:
				walk(v)
			}
		}
	}
	walk(e)
	return b.String()
}

// pathSeg matches an element by local name; a leading "~" matches local names containing
// the rest (contains(local-name(), ...)).
func segMatch(seg, local string) bool {
	if strings.HasPrefix(seg, "~") {
		return strings.Contains(local, seg[1:])
	}
	return local == seg
}

// SelectAbs evaluates an absolute local-name path (/*[local-name()='A']/*[...]) from the
// document root.
func SelectAbs(doc *etree.Document, path ...string) []*etree.Element {
	if doc == nil || len(path) == 0 {
		return nil
	}
	var cur []*etree.Element
	for _, c := range doc.ChildElements() {
		if segMatch(path[0], c.Tag) {
			cur = append(cur, c)
		}
	}
	return selectChildren(cur, path[1:])
}

// SelectRel evaluates a relative child path starting at el's children.
func SelectRel(el *etree.Element, path ...string) []*etree.Element {
	return selectChildren([]*etree.Element{el}, path)
}

func selectChildren(cur []*etree.Element, path []string) []*etree.Element {
	for _, seg := range path {
		var next []*etree.Element
		for _, e := range cur {
			for _, c := range e.ChildElements() {
				if segMatch(seg, c.Tag) {
					next = append(next, c)
				}
			}
		}
		cur = next
	}
	return cur
}

// Descendants returns all descendant elements of e in document order.
func Descendants(e *etree.Element) []*etree.Element {
	var out []*etree.Element
	var walk func(*etree.Element)
	walk = func(x *etree.Element) {
		for _, c := range x.ChildElements() {
			out = append(out, c)
			walk(c)
		}
	}
	walk(e)
	return out
}

// ---- encoding ----

// Base64Encode is utility.base64Encode.
func Base64Encode(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Base64Decode decodes like Node's Buffer.from(s, "base64"): whitespace and invalid
// characters are skipped and decoding stops at padding.
func Base64Decode(s string) []byte {
	var clean strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			clean.WriteByte(c)
		case c == '-':
			clean.WriteByte('+')
		case c == '_':
			clean.WriteByte('/')
		case c == '=':
			i = len(s)
		}
	}
	str := clean.String()
	if r := len(str) % 4; r == 1 {
		str = str[:len(str)-1]
	}
	out, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(str, "="))
	if err != nil {
		return nil
	}
	return out
}

// DeflateString is deflateRawSync.
func DeflateString(s string) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return buf.Bytes()
}

// InflateString is utility.inflateString (base64 + inflateRawSync).
func InflateString(compressed string) (string, error) {
	data := Base64Decode(compressed)
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, 10<<20))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// EncodeURIComponent is JavaScript's encodeURIComponent.
func EncodeURIComponent(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%")
		b.WriteString(strings.ToUpper(hexByte(c)))
	}
	return b.String()
}

func hexByte(c byte) string {
	const h = "0123456789abcdef"
	return string([]byte{h[c>>4], h[c&15]})
}

// DecodeURIComponent is decodeURIComponent (invalid sequences are returned unchanged).
func DecodeURIComponent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// ---- templates ----

// XMLEscape is the xml-escape package.
func XMLEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// Tag is one template tag value; Undefined values drop the attribute/element.
type Tag struct {
	Name      string
	Value     string
	Undefined bool
}

// T is a defined tag.
func T(name, value string) Tag { return Tag{Name: name, Value: value} }

// U is an undefined tag.
func U(name string) Tag { return Tag{Name: name, Undefined: true} }

// Opt is a tag that is undefined when value is empty.
func Opt(name, value string) Tag {
	if value == "" {
		return U(name)
	}
	return T(name, value)
}

var elemOpen = regexp.MustCompile(`<([A-Za-z_:][\w:.-]*)((?:\s+[^>]*)?)>`)

// ReplaceTagsByValue is SamlLib.replaceTagsByValue.
func ReplaceTagsByValue(raw string, tags []Tag) string {
	for _, t := range tags {
		ph := "{" + t.Name + "}"
		if t.Undefined {
			attrRe := regexp.MustCompile(`\s+[A-Za-z_:][\w:.-]*=("` + regexp.QuoteMeta(ph) + `"|'` + regexp.QuoteMeta(ph) + `')`)
			raw = attrRe.ReplaceAllString(raw, "")
			raw = removeOnlyContentElements(raw, ph)
			raw = strings.ReplaceAll(raw, ph, "")
			continue
		}
		raw = strings.ReplaceAll(raw, ph, XMLEscape(t.Value))
	}
	return raw
}

// removeOnlyContentElements drops `<X ...>{Tag}</X>` elements.
func removeOnlyContentElements(raw, ph string) string {
	var out strings.Builder
	i := 0
	for {
		idx := strings.Index(raw[i:], ph)
		if idx < 0 {
			out.WriteString(raw[i:])
			return out.String()
		}
		at := i + idx
		// find the opening tag that ends immediately before the placeholder
		lt := strings.LastIndex(raw[i:at], "<")
		closeTagStart := at + len(ph)
		if lt >= 0 && strings.HasPrefix(raw[closeTagStart:], "</") && at > 0 && raw[at-1] == '>' {
			open := raw[i+lt : at]
			if m := elemOpen.FindStringSubmatch(open); m != nil && m[0] == open {
				name := m[1]
				closeTag := "</" + name + ">"
				if strings.HasPrefix(raw[closeTagStart:], closeTag) {
					out.WriteString(raw[i : i+lt])
					i = closeTagStart + len(closeTag)
					continue
				}
			}
		}
		out.WriteString(raw[i:closeTagStart])
		i = closeTagStart
	}
}

// ISOTime formats like Date.prototype.toISOString.
func ISOTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ParseJSDate parses an ISO-8601 date like `new Date(string)` for SAML timestamps.
func ParseJSDate(s string) (time.Time, bool) {
	layouts := []string{time.RFC3339Nano, "2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02"}
	for _, l := range layouts {
		if t, err := time.Parse(l, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// CamelCase is samlify's camelCase helper.
func CamelCase(input string) string {
	var words []string
	var cur []rune
	rs := []rune(input)
	flush := func() {
		if len(cur) > 0 {
			words = append(words, string(cur))
			cur = nil
		}
	}
	isLower := func(r rune) bool { return r >= 'a' && r <= 'z' }
	isUpper := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	for i, r := range rs {
		if r == ' ' || r == '\t' || r == '\n' || r == '-' || r == '_' || r == '.' {
			flush()
			continue
		}
		if i > 0 && isUpper(r) {
			prev := rs[i-1]
			if isLower(prev) || isDigit(prev) {
				flush()
			} else if isUpper(prev) && i+1 < len(rs) && isLower(rs[i+1]) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	var b strings.Builder
	for i, w := range words {
		lw := strings.ToLower(w)
		if i == 0 {
			b.WriteString(lw)
		} else {
			b.WriteString(strings.ToUpper(lw[:1]) + lw[1:])
		}
	}
	return b.String()
}
