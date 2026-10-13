package sso

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// SSOProviderStateKey is the OAuth/relay state server-context key holding the provider
// reference.
const SSOProviderStateKey = "ssoProviderReference"

// toPlainJSON converts a Go value to plain JSON values (map[string]any, []any, ...).
func toPlainJSON(v any) any {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil
	}
	out, err := jsonx.Parse(bytes.TrimSpace(buf.Bytes()))
	if err != nil {
		return nil
	}
	return jsonx.ToPlain(out)
}

// undefined marks an absent value in canonical serialization input.
type undefinedT struct{}

var undefined = undefinedT{}

// serializeCanonical is the stable JSON serialization used for fingerprints: object keys
// are sorted, undefined members dropped and undefined array entries become null.
func serializeCanonical(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "null", nil
	case undefinedT:
		return "null", nil
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			s, err := serializeCanonical(e)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case []string:
		parts := make([]any, len(t))
		for i, s := range t {
			parts[i] = s
		}
		return serializeCanonical(parts)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k, e := range t {
			if _, isU := e.(undefinedT); isU {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			s, err := serializeCanonical(t[k])
			if err != nil {
				return "", err
			}
			kb, _ := jsonx.Marshal(k)
			parts[i] = string(kb) + ":" + s
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	case string, bool, float64, int, int64:
		b, err := jsonx.Marshal(t)
		return string(b), err
	case json.Number:
		return t.String(), nil
	}
	return "", errNotJSONSerializable
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func withoutOIDCSecret(raw any) any {
	m, ok := raw.(map[string]any)
	if !ok {
		if raw == nil {
			return undefined
		}
		return raw
	}
	out := cloneMap(m)
	out["clientSecret"] = undefined
	return out
}

func withoutSAMLPrivateKeys(raw any) any {
	m, ok := raw.(map[string]any)
	if !ok {
		if raw == nil {
			return undefined
		}
		return raw
	}
	out := cloneMap(m)
	out["privateKey"] = undefined
	idp := map[string]any{}
	if im, ok := m["idpMetadata"].(map[string]any); ok {
		idp = cloneMap(im)
	}
	for _, k := range []string{"privateKey", "privateKeyPass", "encPrivateKey", "encPrivateKeyPass"} {
		idp[k] = undefined
	}
	out["idpMetadata"] = idp
	if sm, ok := m["spMetadata"].(map[string]any); ok {
		sp := cloneMap(sm)
		for _, k := range []string{"privateKey", "privateKeyPass", "encPrivateKey", "encPrivateKeyPass"} {
			sp[k] = undefined
		}
		out["spMetadata"] = sp
	} else {
		out["spMetadata"] = undefined
	}
	return out
}

func providerSource(p *SSOProvider) (string, string) {
	if p.ID != "" {
		return "persisted", p.ID
	}
	return "configured", ""
}

func providerFingerprint(p *SSOProvider) string {
	in := map[string]any{
		"domain":         p.Domain,
		"issuer":         p.Issuer,
		"domainVerified": undefined,
		"organizationId": undefined,
		"oidcConfig":     withoutOIDCSecret(p.oidcRaw()),
		"samlConfig":     withoutSAMLPrivateKeys(p.samlRaw()),
	}
	if p.domainVerifiedPresent {
		if p.DomainVerified == nil {
			in["domainVerified"] = nil
		} else {
			in["domainVerified"] = *p.DomainVerified
		}
	}
	if p.orgPresent {
		if p.orgNull {
			in["organizationId"] = nil
		} else {
			in["organizationId"] = p.OrganizationID
		}
	}
	s, err := serializeCanonical(in)
	if err != nil {
		s = ""
	}
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// computeProviderReference pins the provider's current authentication configuration.
func computeProviderReference(p *SSOProvider) ProviderReference {
	var r ProviderReference
	r.ProviderID = p.ProviderID
	r.Source.Type, r.Source.RecordID = providerSource(p)
	r.AuthenticationConfigurationFingerprint = providerFingerprint(p)
	return r
}

// toServerContext renders a reference for state storage.
func (r ProviderReference) toServerContext() map[string]any {
	src := map[string]any{"type": r.Source.Type}
	if r.Source.Type == "persisted" {
		src["recordId"] = r.Source.RecordID
	}
	return map[string]any{
		"providerId":                             r.ProviderID,
		"source":                                 src,
		"authenticationConfigurationFingerprint": r.AuthenticationConfigurationFingerprint,
	}
}

// jsonObject renders a reference as an ordered JSON object.
func (r ProviderReference) jsonObject() *jsonx.Object {
	src := jsonx.O("type", r.Source.Type)
	if r.Source.Type == "persisted" {
		src.Set("recordId", r.Source.RecordID)
	}
	return jsonx.O("providerId", r.ProviderID, "source", src, "authenticationConfigurationFingerprint", r.AuthenticationConfigurationFingerprint)
}

func asMap(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case *jsonx.Object:
		if t == nil {
			return nil, false
		}
		return t.Map(), true
	}
	return nil, false
}

// parseProviderReference validates a stored provider reference.
func parseProviderReference(v any) *ProviderReference {
	m, ok := asMap(v)
	if !ok {
		return nil
	}
	src, ok := asMap(m["source"])
	if !ok {
		return nil
	}
	pid, _ := m["providerId"].(string)
	fp, _ := m["authenticationConfigurationFingerprint"].(string)
	if pid == "" || fp == "" {
		return nil
	}
	r := &ProviderReference{ProviderID: pid, AuthenticationConfigurationFingerprint: fp}
	switch src["type"] {
	case "configured":
		r.Source.Type = "configured"
		return r
	case "persisted":
		id, _ := src["recordId"].(string)
		if id == "" {
			return nil
		}
		r.Source.Type, r.Source.RecordID = "persisted", id
		return r
	}
	return nil
}

// isCurrentProviderReference reports whether ref still matches the provider.
func isCurrentProviderReference(p *SSOProvider, ref *ProviderReference) bool {
	if ref == nil || p == nil || ref.ProviderID != p.ProviderID {
		return false
	}
	typ, id := providerSource(p)
	if typ != ref.Source.Type {
		return false
	}
	if typ == "persisted" && ref.Source.RecordID != id {
		return false
	}
	return ref.AuthenticationConfigurationFingerprint == providerFingerprint(p)
}

func sameProviderReference(a, b *ProviderReference) bool {
	if a.ProviderID != b.ProviderID || a.AuthenticationConfigurationFingerprint != b.AuthenticationConfigurationFingerprint || a.Source.Type != b.Source.Type {
		return false
	}
	return a.Source.Type == "configured" || a.Source.RecordID == b.Source.RecordID
}

// ---- provider construction ----

func recString(r adapter.Record, k string) string {
	s, _ := r[k].(string)
	return s
}

// providerFromRecord builds a provider from a database row. Config columns that fail to
// parse are reported through the returned errors (callers decide).
func providerFromRecord(r adapter.Record) (*SSOProvider, error, error) {
	p := &SSOProvider{
		ID:         recString(r, "id"),
		Issuer:     recString(r, "issuer"),
		UserID:     recString(r, "userId"),
		ProviderID: recString(r, "providerId"),
		Domain:     recString(r, "domain"),
		Record:     r,
	}
	if v, ok := r["organizationId"]; ok {
		p.orgPresent = true
		if s, ok := v.(string); ok {
			p.OrganizationID = s
		} else {
			p.orgNull = true
		}
	}
	if v, ok := r["domainVerified"]; ok {
		p.domainVerifiedPresent = true
		if b, ok := v.(bool); ok {
			p.DomainVerified = &b
		}
	}
	var oerr, serr error
	if s := recString(r, "oidcConfig"); s != "" {
		p.OIDCConfig, oerr = safeJSONParse[OIDCConfig](s)
		if raw, err := jsonx.Parse([]byte(s)); err == nil {
			p.oidcRawValue = jsonx.ToPlain(raw)
		}
	}
	if s := recString(r, "samlConfig"); s != "" {
		p.SAMLConfig, serr = safeJSONParse[SAMLConfig](s)
		if raw, err := jsonx.Parse([]byte(s)); err == nil {
			p.samlRawValue = jsonx.ToPlain(raw)
		}
	}
	return p, oerr, serr
}

func (p *SSOProvider) oidcRaw() any {
	if p.oidcRawValue != nil {
		return p.oidcRawValue
	}
	if p.OIDCConfig == nil {
		return nil
	}
	return toPlainJSON(p.OIDCConfig)
}

func (p *SSOProvider) samlRaw() any {
	if p.samlRawValue != nil {
		return p.samlRawValue
	}
	if p.SAMLConfig == nil {
		return nil
	}
	return toPlainJSON(p.SAMLConfig)
}

// defaultProvider builds a configured provider from a DefaultSSO entry.
func defaultProvider(d DefaultSSOProvider, issuer string, dv bool) *SSOProvider {
	p := &SSOProvider{Issuer: issuer, ProviderID: d.ProviderID, UserID: "default", OIDCConfig: d.OIDCConfig, SAMLConfig: d.SAMLConfig, Domain: d.Domain}
	if dv {
		t := true
		p.DomainVerified = &t
		p.domainVerifiedPresent = true
	}
	return p
}
