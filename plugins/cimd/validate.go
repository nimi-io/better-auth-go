package cimd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/validate-metadata-document.ts: validation for Client ID
// Metadata Documents (draft-ietf-oauth-client-id-metadata-document-02 §3 and §4).

var dotSegmentRe = regexp.MustCompile(`(?i)/(?:\.|%2e)(?:\.|%2e)?(?:/|$|#|\?)`)

var httpsAuthorityPrefixRe = regexp.MustCompile(`(?i)^https://`)

var symmetricAuthMethods = map[string]bool{"client_secret_post": true, "client_secret_basic": true, "client_secret_jwt": true}

// MetadataProfileMCP20260728 is the "mcp-2026-07-28" metadata profile: client_name and
// redirect_uris are required because that MCP revision pins CIMD draft-00.
const MetadataProfileMCP20260728 = "mcp-2026-07-28"

// MetadataValidationOptions are CimdMetadataValidationOptions.
type MetadataValidationOptions struct {
	// OriginBoundFields lists metadata fields whose URL values must share the client_id
	// origin. nil uses the default ["post_logout_redirect_uris", "client_uri"]; an empty
	// non-nil slice disables origin binding.
	OriginBoundFields []string
	// MetadataProfile is "" or MetadataProfileMCP20260728.
	MetadataProfile string
}

// MetadataValidationResult is CimdMetadataValidationResult: Metadata is set when Valid,
// Error otherwise.
type MetadataValidationResult struct {
	Valid    bool
	Metadata *jsonx.Object
	Error    string
	Warnings []string
}

// clientMetadataFields are the keys of oauthClientMetadataSchema (unknown members are
// stripped like oauthClientMetadataSchema.strip()).
var clientMetadataFields = []string{
	"redirect_uris", "scope", "client_name", "client_uri", "logo_uri", "contacts", "tos_uri", "policy_uri",
	"software_id", "software_version", "software_statement", "post_logout_redirect_uris", "backchannel_logout_uri",
	"backchannel_logout_session_required", "token_endpoint_auth_method", "jwks", "jwks_uri", "grant_types",
	"response_types", "application_type", "subject_type", "dpop_bound_access_tokens", "resources",
	"client_id", "client_secret", "client_secret_expires_at", "client_id_issued_at",
}

var clientMetadataFieldSet = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range clientMetadataFields {
		m[f] = true
	}
	return m
}()

// IsCimdClientIDURLCandidate reports whether clientID is URL-formatted (HTTPS)
// (isCimdClientIdUrlCandidate). It is a routing predicate, not a security gate: callers
// must also run ValidateClientIDURL and a fetch-time policy before fetching.
func IsCimdClientIDURLCandidate(clientID string) bool {
	u, err := parseURL(clientID)
	return err == nil && u.Scheme == "https"
}

// ValidateClientIDURL validates a client_id URL per draft-02 §3 (validateClientIdUrl).
// It returns "" on success and the error description otherwise. Loopback and every other
// non-public host (private, link-local, cloud-metadata, IPv6 tunnels) are rejected.
func ValidateClientIDURL(raw string) string {
	// §3: check the raw URL for dot segments before the URL parser normalizes them.
	if dotSegmentRe.MatchString(raw) {
		return "client_id URL MUST NOT contain dot segments"
	}
	// §3: MUST NOT contain fragments.
	if strings.Contains(raw, "#") {
		return "client_id URL MUST NOT contain a fragment"
	}
	u, err := parseURL(raw)
	if err != nil {
		return "client_id is not a valid URL"
	}
	if u.Scheme != "https" {
		return "client_id URL must use HTTPS"
	}
	prefix := httpsAuthorityPrefixRe.FindString(raw)
	if prefix == "" || strings.Contains(raw, `\`) {
		return "client_id URL MUST use an explicit HTTPS authority form"
	}
	rest := raw[len(prefix):]
	idx := strings.IndexAny(rest, "/?#")
	if idx == 0 {
		return "client_id URL MUST use an explicit HTTPS authority form"
	}
	if idx < 0 || rest[idx] != '/' {
		return "client_id URL MUST contain an explicit path component"
	}
	// §3: MUST NOT contain credentials.
	if urlHasCredentials(u) {
		return "client_id URL MUST NOT contain credentials"
	}
	if !isPublicRoutableHost(u.Hostname()) {
		return "client_id URL must not target a private or reserved address"
	}
	return ""
}

func clientIDURLWarnings(raw string) []string {
	var warnings []string
	u, err := parseURL(raw)
	if err != nil {
		return nil
	}
	if u.EscapedPath() == "/" {
		warnings = append(warnings, "client_id URL path / is NOT RECOMMENDED (§3)")
	}
	if u.RawQuery != "" {
		warnings = append(warnings, "client_id URL SHOULD NOT contain a query string (§3)")
	}
	return warnings
}

func isAbsoluteRedirectURI(uri string) bool {
	u, err := parseURL(uri)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https" || isReverseDomainPrivateUseRedirectURI(uri, u)
}

func invalid(format string, args ...any) MetadataValidationResult {
	return MetadataValidationResult{Error: fmt.Sprintf(format, args...)}
}

func joinPath(path []any) string {
	parts := make([]string, len(path))
	for i, p := range path {
		switch v := p.(type) {
		case string:
			parts[i] = v
		case int:
			parts[i] = strconv.Itoa(v)
		case float64:
			parts[i] = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			parts[i] = fmt.Sprint(v)
		}
	}
	return strings.Join(parts, ".")
}

func toObject(raw any) (*jsonx.Object, bool) {
	switch v := raw.(type) {
	case *jsonx.Object:
		return v, v != nil
	case map[string]any:
		b, err := jsonx.Marshal(v)
		if err != nil {
			return nil, false
		}
		p, err := jsonx.Parse(b)
		if err != nil {
			return nil, false
		}
		o, ok := p.(*jsonx.Object)
		return o, ok
	}
	return nil, false
}

func getString(o *jsonx.Object, k string) (string, bool) {
	v, ok := o.Get(k)
	if !ok {
		return "", false
	}
	s, isStr := v.(string)
	return s, isStr
}

// ValidateCimdMetadata validates a fetched Client ID Metadata Document per §4.1
// (validateCimdMetadata). raw is the parsed JSON body (a *jsonx.Object, map or other
// decoded JSON value).
func ValidateCimdMetadata(clientIDURL string, raw any, options MetadataValidationOptions) MetadataValidationResult {
	obj, isObj := toObject(raw)
	_, isArray := raw.([]any)
	if !isObj && !isArray {
		return invalid("metadata document is not a JSON object")
	}

	// Draft-02 ignores unknown members, but recognized credential, privilege and
	// server-control fields remain fatal even when they are not part of the shared wire
	// schema.
	if isObj {
		for _, field := range obj.Keys() {
			if oauthprovider.IsForbiddenCimdClientMetadataField(field) {
				return invalid(`metadata document MUST NOT contain "%s"`, field)
			}
		}
	}

	var parseInput any = raw
	if isObj {
		parseInput = obj
	}
	parsed, err := oauthprovider.ValidateClientMetadata(parseInput)
	if err != nil {
		path, msg := "", "invalid client metadata"
		if ve, ok := err.(*oauthprovider.ValidationError); ok && len(ve.Issues) > 0 {
			path = joinPath(ve.Issues[0].Path)
			msg = ve.Issues[0].Message
		}
		if path == "" {
			path = "metadata document"
		}
		return invalid("%s: %s", path, msg)
	}
	doc := jsonx.NewObject()
	for _, k := range parsed.Keys() {
		if clientMetadataFieldSet[k] {
			v, _ := parsed.Get(k)
			doc.Set(k, v)
		}
	}
	var warnings []string

	// §4.1: client_id MUST equal the fetch URL (simple string comparison).
	if id, _ := getString(doc, "client_id"); id != clientIDURL {
		return invalid(`client_id "%s" does not match the metadata document URL`, id)
	}

	if options.MetadataProfile == MetadataProfileMCP20260728 {
		if name, _ := getString(doc, "client_name"); strings.TrimSpace(name) == "" {
			return invalid("client_name must be a non-empty string")
		}
	}

	// §4.1: prohibited recognized wire fields MUST NOT be present.
	for _, field := range []string{"backchannel_logout_uri", "backchannel_logout_session_required"} {
		if doc.Has(field) {
			return invalid(`metadata document MUST NOT contain "%s"`, field)
		}
	}

	// §4.1: only non-secret auth methods are allowed.
	if method, ok := getString(doc, "token_endpoint_auth_method"); ok {
		if symmetricAuthMethods[method] {
			return invalid(`symmetric auth method "%s" is prohibited for Client ID Metadata Document clients`, method)
		}
		if method != "none" && method != "private_key_jwt" {
			return invalid(`token_endpoint_auth_method must be "none" or "private_key_jwt" for Client ID Metadata Document clients`)
		}
		if method == "private_key_jwt" && !doc.Has("jwks") && !doc.Has("jwks_uri") {
			return invalid("private_key_jwt requires either jwks or jwks_uri in the metadata document")
		}
	}

	if jwks, ok := doc.Get("jwks"); ok {
		if res := oauthprovider.ValidatePublicClientJwks(jwks); !res.Valid {
			return invalid("jwks must contain only structurally valid public keys")
		}
	}
	if jwksURI, ok := getString(doc, "jwks_uri"); ok {
		u, err := parseURL(jwksURI)
		if err != nil {
			return invalid("jwks_uri must be a valid URL")
		}
		if urlHasCredentials(u) {
			return invalid("jwks_uri must not contain credentials")
		}
		if strings.Contains(jwksURI, "#") {
			return invalid("jwks_uri must not contain a fragment")
		}
	}

	const redirectErr = "redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs"
	redirects, hasRedirects := doc.Get("redirect_uris")
	if options.MetadataProfile == MetadataProfileMCP20260728 && !hasRedirects {
		return invalid(redirectErr)
	}
	if hasRedirects {
		list, _ := redirects.([]any)
		for _, r := range list {
			s, _ := r.(string)
			if !isAbsoluteRedirectURI(s) {
				return invalid(redirectErr)
			}
		}
	}

	for _, field := range []string{"client_uri", "logo_uri", "tos_uri", "policy_uri"} {
		v, ok := doc.Get(field)
		if !ok {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			return invalid("%s must be a string", field)
		}
		u, err := parseURL(s)
		if err != nil {
			return invalid("%s is not a valid URL", field)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return invalid("%s must use HTTP(S)", field)
		}
		if urlHasCredentials(u) {
			return invalid("%s must not contain credentials", field)
		}
		if !isPublicRoutableHost(u.Hostname()) {
			return invalid("%s must not point to a private or reserved address", field)
		}
	}

	// Origin-bound fields: values must share the same origin as the client_id URL.
	fields := options.OriginBoundFields
	if fields == nil {
		fields = []string{"post_logout_redirect_uris", "client_uri"}
	}
	cu, err := parseURL(clientIDURL)
	if err != nil {
		return invalid("client_id is not a valid URL")
	}
	clientIDOrigin := originOf(cu)
	for _, key := range fields {
		value, ok := doc.Get(key)
		if !ok {
			continue
		}
		var values []string
		switch v := value.(type) {
		case string:
			values = []string{v}
		case []any:
			for _, x := range v {
				s, isStr := x.(string)
				if !isStr {
					return invalid("%s must be a string or an array of strings", key)
				}
				values = append(values, s)
			}
		default:
			return invalid("%s must be a string or an array of strings", key)
		}
		for _, val := range values {
			u, err := parseURL(val)
			if err != nil {
				return invalid(`%s contains an invalid URL: "%s"`, key, val)
			}
			isRedirectField := key == "redirect_uris" || key == "post_logout_redirect_uris"
			isPrivateUse := isRedirectField && isReverseDomainPrivateUseRedirectURI(val, u)
			if u.Scheme != "https" && u.Scheme != "http" && !isPrivateUse {
				return invalid("all values for %s must use HTTP(S) or an authority-free private-use scheme", key)
			}
			if isPrivateUse {
				continue
			}
			// Loopback redirect URIs are allowed for local/native app flows (RFC 8252); this
			// exception applies only to redirect URI fields.
			localhostAllowed := isRedirectField && isLoopbackHost(u.Hostname())
			if originOf(u) != clientIDOrigin && !localhostAllowed {
				return invalid(`%s value "%s" must have the same origin as client_id (%s)`, key, val, clientIDOrigin)
			}
		}
	}

	// §3: SHOULD NOT have a query string.
	warnings = append(warnings, clientIDURLWarnings(clientIDURL)...)

	if !doc.Has("token_endpoint_auth_method") {
		doc.Set("token_endpoint_auth_method", "none")
	}
	return MetadataValidationResult{Valid: true, Metadata: doc, Warnings: warnings}
}
