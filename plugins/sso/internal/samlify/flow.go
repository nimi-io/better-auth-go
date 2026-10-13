package samlify

import (
	"errors"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Optional is an extracted string that may be absent (undefined/null upstream).
type Optional struct {
	Value string
	Set   bool
}

// Extract holds the fields samlify extracts from inbound messages (FlowResult.extract).
type Extract struct {
	// Response attributes (ID, IssueInstant, Destination, InResponseTo).
	Response map[string]string
	// Request attributes for LogoutRequest/AuthnRequest.
	Request map[string]string
	// Conditions holds NotBefore / NotOnOrAfter when exactly one Conditions element exists.
	Conditions map[string]string
	// Audience is the list of audiences (nil when none).
	Audience []string
	// AudienceIsArray reports multiple Audience elements.
	AudienceIsArray bool
	Issuer          Optional
	NameID          Optional
	// SessionIndex holds the AuthnStatement attributes (AuthnInstant, SessionNotOnOrAfter,
	// SessionIndex) when exactly one AuthnStatement exists.
	SessionIndex map[string]string
	// LogoutSessionIndex is the LogoutRequest SessionIndex text.
	LogoutSessionIndex Optional
	// Attributes maps attribute names to values; single values are strings, multiple
	// values []string (an attribute with no values maps to an empty []string).
	Attributes map[string]any
	// AttributeOrder is the document order of attribute names.
	AttributeOrder []string
}

// FlowResult is the result of parsing an inbound SAML message.
type FlowResult struct {
	SAMLContent string
	SigAlg      string
	Extract     Extract
}

// RequestInfo carries the inbound HTTP message (body and query values).
type RequestInfo struct {
	Body  map[string]string
	Query map[string]string
}

func zeroAttrValue(els []*etree.Element) (Optional, []string) {
	if len(els) == 1 {
		v, _ := FirstText(els[0])
		return Optional{Value: v, Set: true}, nil
	}
	if len(els) > 1 {
		var out []string
		for _, e := range els {
			if len(e.Child) > 0 {
				if cd, ok := e.Child[0].(*etree.CharData); ok {
					out = append(out, cd.Data)
				}
			}
		}
		return Optional{}, out
	}
	return Optional{}, nil
}

func multiAttr(els []*etree.Element, names ...string) map[string]string {
	if len(els) != 1 {
		return nil
	}
	return attrMap(els[0], names...)
}

func extractLoginResponse(samlContent, assertion string) Extract {
	ex := Extract{}
	if doc, err := ParseDocument(samlContent); err == nil {
		ex.Response = multiAttr(SelectAbs(doc, "Response"), "ID", "IssueInstant", "Destination", "InResponseTo")
	}
	adoc, err := ParseDocument(assertion)
	if err != nil {
		return ex
	}
	ex.Conditions = multiAttr(SelectAbs(adoc, "Assertion", "Conditions"), "NotBefore", "NotOnOrAfter")
	auds := SelectAbs(adoc, "Assertion", "Conditions", "AudienceRestriction", "Audience")
	single, many := zeroAttrValue(auds)
	if single.Set {
		ex.Audience = []string{single.Value}
	} else if len(auds) > 1 {
		ex.Audience = many
		ex.AudienceIsArray = true
	}
	if v, many := zeroAttrValue(SelectAbs(adoc, "Assertion", "Issuer")); v.Set {
		ex.Issuer = v
	} else if len(many) > 0 {
		ex.Issuer = Optional{}
	}
	ex.NameID, _ = zeroAttrValue(SelectAbs(adoc, "Assertion", "Subject", "NameID"))
	ex.SessionIndex = multiAttr(SelectAbs(adoc, "Assertion", "AuthnStatement"), "AuthnInstant", "SessionNotOnOrAfter", "SessionIndex")
	ex.Attributes = map[string]any{}
	parents := SelectAbs(adoc, "Assertion", "AttributeStatement", "Attribute")
	var names []string
	for _, p := range parents {
		if n, ok := AttrValue(p, "Name"); ok {
			names = append(names, n)
		}
	}
	for i, name := range names {
		if i >= len(parents) {
			break
		}
		var vals []string
		for _, v := range SelectRel(parents[i], "AttributeValue") {
			vals = append(vals, TextNodes(v)...)
		}
		var value any
		if len(vals) == 1 {
			value = vals[0]
		} else {
			value = vals
			if vals == nil {
				value = []string{}
			}
		}
		existing, ok := ex.Attributes[name]
		if !ok {
			ex.Attributes[name] = value
			ex.AttributeOrder = append(ex.AttributeOrder, name)
			continue
		}
		var merged []string
		switch t := existing.(type) {
		case string:
			merged = []string{t}
		case []string:
			merged = append(merged, t...)
		}
		switch t := value.(type) {
		case string:
			merged = append(merged, t)
		case []string:
			merged = append(merged, t...)
		}
		ex.Attributes[name] = merged
	}
	return ex
}

func checkStatus(content, parserType string) error {
	if parserType != "SAMLResponse" && parserType != "LogoutResponse" {
		return nil
	}
	root := "Response"
	if parserType == "LogoutResponse" {
		root = "LogoutResponse"
	}
	doc, err := ParseDocument(content)
	if err != nil {
		return err
	}
	var top, second string
	if els := SelectAbs(doc, root, "Status", "StatusCode"); len(els) > 0 {
		top, _ = AttrValue(els[0], "Value")
	}
	if els := SelectAbs(doc, root, "Status", "StatusCode", "StatusCode"); len(els) > 0 {
		second, _ = AttrValue(els[0], "Value")
	}
	if top == StatusSuccess {
		return nil
	}
	if top == "" {
		return errors.New("ERR_UNDEFINED_STATUS")
	}
	return errors.New("ERR_FAILED_STATUS with top tier code: " + top + ", second tier code: " + second)
}

// VerifyTime is validator.verifyTime (drifts in milliseconds).
func VerifyTime(notBefore, notOnOrAfter string, drift [2]int64) bool {
	now := time.Now().UnixMilli()
	nb, nbOK := ParseJSDate(notBefore)
	na, naOK := ParseJSDate(notOnOrAfter)
	if notBefore == "" && notOnOrAfter == "" {
		return true
	}
	if notBefore != "" && notOnOrAfter == "" {
		return nbOK && nb.UnixMilli()+drift[0] <= now
	}
	if notBefore == "" && notOnOrAfter != "" {
		return naOK && now < na.UnixMilli()+drift[1]
	}
	return nbOK && naOK && nb.UnixMilli()+drift[0] <= now && now < na.UnixMilli()+drift[1]
}

// ParseLoginResponse parses, validates and verifies a POST-binding login response
// (ServiceProvider.parseLoginResponse(idp, "post", { body })). The response must be signed.
func (sp *Entity) ParseLoginResponse(idp *Entity, samlResponse string) (*FlowResult, error) {
	samlContent := string(Base64Decode(samlResponse))
	if err := IsValidXML(samlContent); err != nil {
		return nil, err
	}
	if err := checkStatus(samlContent, "SAMLResponse"); err != nil {
		return nil, err
	}
	decryptRequired := idp.Setting.IsAssertionEncrypted
	res, err := VerifySignature(samlContent, idp.Meta)
	if err != nil {
		return nil, err
	}
	var assertion string
	switch {
	case decryptRequired && res.Verified && res.Assertion != "":
		content, plain, err := DecryptAssertion(sp, res.Assertion)
		if err != nil {
			return nil, err
		}
		samlContent, assertion = content, plain
	case decryptRequired && !res.Verified:
		content, _, err := DecryptAssertion(sp, samlContent)
		if err != nil {
			return nil, err
		}
		r2, err := VerifySignature(content, idp.Meta)
		if err != nil {
			return nil, err
		}
		if !r2.Verified {
			return nil, errors.New("FAILED_TO_VERIFY_SIGNATURE")
		}
		samlContent, assertion = content, r2.Assertion
	default:
		if !res.Verified {
			return nil, errors.New("FAILED_TO_VERIFY_SIGNATURE")
		}
		assertion = res.Assertion
	}
	if assertion == "" {
		return nil, errors.New("ERR_EMPTY_ASSERTION")
	}
	ex := extractLoginResponse(samlContent, assertion)
	if !ex.Issuer.Set || ex.Issuer.Value != idp.Meta.GetEntityID() {
		return nil, errors.New("ERR_UNMATCH_ISSUER")
	}
	drift := sp.clockDrifts()
	if v := ex.SessionIndex["sessionNotOnOrAfter"]; v != "" && !VerifyTime("", v, drift) {
		return nil, errors.New("ERR_EXPIRED_SESSION")
	}
	if ex.Conditions != nil && !VerifyTime(ex.Conditions["notBefore"], ex.Conditions["notOnOrAfter"], drift) {
		return nil, errors.New("ERR_SUBJECT_UNCONFIRMED")
	}
	return &FlowResult{SAMLContent: samlContent, Extract: ex}, nil
}

func extractLogout(content, parserType string) Extract {
	ex := Extract{}
	doc, err := ParseDocument(content)
	if err != nil {
		return ex
	}
	if parserType == "LogoutRequest" {
		ex.Request = multiAttr(SelectAbs(doc, "LogoutRequest"), "ID", "IssueInstant", "Destination")
		ex.Issuer, _ = zeroAttrValue(SelectAbs(doc, "LogoutRequest", "Issuer"))
		ex.NameID, _ = zeroAttrValue(SelectAbs(doc, "LogoutRequest", "NameID"))
		ex.LogoutSessionIndex, _ = zeroAttrValue(SelectAbs(doc, "LogoutRequest", "SessionIndex"))
		return ex
	}
	ex.Response = multiAttr(SelectAbs(doc, "LogoutResponse"), "ID", "Destination", "InResponseTo")
	ex.Issuer, _ = zeroAttrValue(SelectAbs(doc, "LogoutResponse", "Issuer"))
	return ex
}

// parseLogout runs the logout flows (Entity.parseLogoutRequest / parseLogoutResponse).
func (e *Entity) parseLogout(from *Entity, binding, parserType string, checkSignature bool, req RequestInfo) (*FlowResult, error) {
	param := queryParamFor(parserType)
	var xmlStr string
	switch binding {
	case BindingRedirect:
		content, ok := req.Query[param]
		if !ok {
			return nil, errors.New("ERR_REDIRECT_FLOW_BAD_ARGS")
		}
		s, err := InflateString(DecodeURIComponent(content))
		if err != nil {
			return nil, err
		}
		xmlStr = s
		if err := IsValidXML(xmlStr); err != nil {
			return nil, errors.New("ERR_INVALID_XML")
		}
		if err := checkStatus(xmlStr, parserType); err != nil {
			return nil, err
		}
		res := &FlowResult{SAMLContent: xmlStr, Extract: extractLogout(xmlStr, parserType)}
		if checkSignature {
			sig, sigAlg := req.Query["Signature"], req.Query["SigAlg"]
			if sig == "" || sigAlg == "" {
				return nil, errors.New("ERR_MISSING_SIG_ALG")
			}
			// upstream passes no octet string for this flow, so verification fails
			if !VerifyMessageSignature(from.Meta, "", Base64Decode(DecodeURIComponent(sig)), sigAlg) {
				return nil, errors.New("ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION")
			}
			res.SigAlg = DecodeURIComponent(sigAlg)
		}
		if parserType == "LogoutResponse" && (!res.Extract.Issuer.Set || res.Extract.Issuer.Value != from.Meta.GetEntityID()) {
			return nil, errors.New("ERR_UNMATCH_ISSUER")
		}
		return res, nil
	case BindingPost:
		encoded, ok := req.Body[param]
		if !ok {
			return nil, errors.New("ERR_POST_FLOW_BAD_ARGS")
		}
		xmlStr = string(Base64Decode(encoded))
		if err := IsValidXML(xmlStr); err != nil {
			return nil, err
		}
		if err := checkStatus(xmlStr, parserType); err != nil {
			return nil, err
		}
		if checkSignature {
			r, err := VerifySignature(xmlStr, from.Meta)
			if err != nil {
				return nil, err
			}
			if !r.Verified {
				return nil, errors.New("FAILED_TO_VERIFY_SIGNATURE")
			}
		}
		res := &FlowResult{SAMLContent: xmlStr, Extract: extractLogout(xmlStr, parserType)}
		if parserType == "LogoutResponse" && (!res.Extract.Issuer.Set || res.Extract.Issuer.Value != from.Meta.GetEntityID()) {
			return nil, errors.New("ERR_UNMATCH_ISSUER")
		}
		return res, nil
	}
	return nil, errors.New("ERR_UNEXPECTED_FLOW")
}

// ParseLogoutRequest parses an inbound LogoutRequest from `from`.
func (e *Entity) ParseLogoutRequest(from *Entity, binding string, req RequestInfo) (*FlowResult, error) {
	return e.parseLogout(from, binding, "LogoutRequest", e.Setting.WantLogoutRequestSigned, req)
}

// ParseLogoutResponse parses an inbound LogoutResponse from `from`.
func (e *Entity) ParseLogoutResponse(from *Entity, binding string, req RequestInfo) (*FlowResult, error) {
	return e.parseLogout(from, binding, "LogoutResponse", e.Setting.WantLogoutResponseSigned, req)
}

// StatusOf returns the top-level status code of a LogoutResponse (for diagnostics).
func StatusOf(content string) string {
	doc, err := ParseDocument(content)
	if err != nil {
		return ""
	}
	for _, root := range []string{"LogoutResponse", "Response"} {
		if els := SelectAbs(doc, root, "Status", "StatusCode"); len(els) > 0 {
			v, _ := AttrValue(els[0], "Value")
			return v
		}
	}
	return ""
}

// HasPrefixFold reports whether s starts with prefix (case-insensitive).
func HasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
