package sso

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

var unsafeSAMLRedirectPathPrefix = regexp.MustCompile(`(?i)^/(?:/|\\|%2f|%5c)`)

// isSafeSAMLRedirectPath reports whether url is a same-origin relative path.
func isSafeSAMLRedirectPath(u string) bool {
	return strings.HasPrefix(u, "/") && !unsafeSAMLRedirectPathPrefix.MatchString(u)
}

// safeJSONParse parses a stored JSON configuration (safeJsonParse). An empty value yields
// (nil, nil); invalid JSON yields an error.
func safeJSONParse[T any](value string) (*T, error) {
	if value == "" {
		return nil, nil
	}
	var out T
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return nil, fmt.Errorf("Failed to parse JSON: %s", err.Error())
	}
	return &out, nil
}

// domainMatches reports whether searchDomain equals or is a subdomain of one of the
// comma-separated provider domains.
func domainMatches(searchDomain, domainList string) bool {
	search := strings.ToLower(strings.TrimSpace(searchDomain))
	domains := parseProviderDomains(domainList)
	if search == "" || domains == nil {
		return false
	}
	for _, d := range domains {
		if search == d || strings.HasSuffix(search, "."+d) {
			return true
		}
	}
	return false
}

// parseProviderEmailVerified treats only true and "true" as verified.
func parseProviderEmailVerified(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}

// validateEmailDomain reports whether the e-mail's domain matches the provider domains.
func validateEmailDomain(email, domain string) bool {
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return false
	}
	emailDomain := strings.ToLower(parts[1])
	if emailDomain == "" || domain == "" {
		return false
	}
	return domainMatches(emailDomain, domain)
}

// certInfo is the sanitized certificate summary returned by provider endpoints.
type certInfo struct {
	FingerprintSha256  string
	NotBefore          string
	NotAfter           string
	PublicKeyAlgorithm string
}

// parseCertificate summarises a PEM certificate (X509Certificate fingerprint256 etc.).
func parseCertificate(certPem string) (certInfo, error) {
	normalized := certPem
	if !strings.Contains(certPem, "-----BEGIN") {
		normalized = "-----BEGIN CERTIFICATE-----\n" + certPem + "\n-----END CERTIFICATE-----"
	}
	cert, err := samlify.ParseCertificate(normalized)
	if err != nil {
		return certInfo{}, err
	}
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	alg := "UNKNOWN"
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		alg = "RSA"
	case x509.ECDSA:
		alg = "EC"
	case x509.Ed25519:
		alg = "ED25519"
	}
	return certInfo{
		FingerprintSha256:  strings.Join(parts, ":"),
		NotBefore:          nodeCertDate(cert.NotBefore),
		NotAfter:           nodeCertDate(cert.NotAfter),
		PublicKeyAlgorithm: alg,
	}, nil
}

// nodeCertDate formats like Node's X509Certificate.validFrom ("Nov 19 12:37:17 2023 GMT").
func nodeCertDate(t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("%s %2d %s %d GMT", t.Format("Jan"), t.Day(), t.Format("15:04:05"), t.Year())
}

// normalizePem trims every line of a PEM value and ends it with a newline.
func normalizePem(key string) string {
	if key == "" {
		return key
	}
	lines := strings.Split(key, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.TrimSpace(strings.Join(lines, "\n")) + "\n"
}

// parseProviderDomains normalises a comma-separated domain list to hostnames (nil when an
// entry cannot be parsed or the list is empty).
func parseProviderDomains(domain string) []string {
	var entries []string
	for _, e := range strings.Split(domain, ",") {
		if e = strings.TrimSpace(e); e != "" {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		h := getHostname(e)
		if h == "" {
			return nil
		}
		h = strings.ToLower(h)
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// maskClientID keeps the last four characters of a client id.
func maskClientID(clientID string) string {
	if len(clientID) <= 4 {
		return "****"
	}
	return "****" + clientID[len(clientID)-4:]
}

// ---- tldts getHostname ----

func isSpecialScheme(s string) int {
	switch strings.ToLower(s) {
	case "http", "https", "ws", "wss", "ftp":
		return 1
	case "file":
		return 2
	}
	return 0
}

// getHostname ports tldts getHostname (extractHostname + hostname validation; IPs are
// returned as is). It returns "" when no valid hostname can be extracted.
func getHostname(input string) string {
	h, ok := extractHostname(input)
	if !ok {
		return ""
	}
	if isIP(h) {
		return h
	}
	if !isValidHostname(h) {
		return ""
	}
	return h
}

func isIP(h string) bool {
	_, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil
}

func extractHostname(url string) (string, bool) {
	if isValidHostname(url) {
		return url, true
	}
	if strings.HasPrefix(url, "data:") {
		return "", false
	}
	url = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(url)
	start, end := 0, len(url)
	for start < len(url) && url[start] <= 32 {
		start++
	}
	for end > start+1 && url[end-1] <= 32 {
		end--
	}
	isSpecial := false
	if strings.HasPrefix(url[start:], "//") {
		start += 2
	} else if idx := strings.Index(url[start:], ":/"); idx >= 0 {
		colon := start + idx
		switch isSpecialScheme(url[start:colon]) {
		case 1:
			isSpecial = true
			start = colon + 2
			for start < len(url) && (url[start] == '/' || url[start] == '\\') {
				start++
			}
		case 2:
			isSpecial = true
			start = colon + 1
			slashes := 0
			for start < len(url) && (url[start] == '/' || url[start] == '\\') && slashes < 2 {
				start++
				slashes++
			}
			if slashes < 2 {
				return "", false
			}
		default:
			for i := start; i < colon; i++ {
				c := url[i] | 32
				if !((c >= 'a' && c <= 'z') || (url[i] >= '0' && url[i] <= '9') || url[i] == '.' || url[i] == '-' || url[i] == '+') {
					return "", false
				}
			}
			if colon+2 < len(url) && url[colon+2] == '/' {
				start = colon + 3
			} else {
				return "", false
			}
		}
	} else if start < len(url) && url[start] != '[' {
		colon := -1
		for i := start; i < end; i++ {
			c := url[i]
			if c == ':' {
				colon = i
				break
			}
			if c == '/' || c == '\\' || c == '?' || c == '#' {
				break
			}
		}
		if colon != -1 {
			hasIdentifier := false
			for i := colon + 1; i < end; i++ {
				c := url[i]
				if c == '/' || c == '\\' || c == '?' || c == '#' {
					break
				}
				if c == '@' {
					hasIdentifier = true
					break
				}
			}
			if !hasIdentifier {
				allDigits := true
				i := colon + 1
				for ; i < end; i++ {
					c := url[i]
					if c == '/' || c == '\\' || c == '?' || c == '#' {
						break
					}
					if c < '0' || c > '9' {
						allDigits = false
						break
					}
				}
				if i == colon+1 {
					allDigits = false
				}
				if !allDigits {
					special := isSpecialScheme(url[start:colon])
					if special == 0 {
						bare := false
						for j := colon + 1; j < end; j++ {
							c := url[j]
							if c == '/' || c == '\\' || c == '?' || c == '#' {
								break
							}
							if c == ':' {
								bare = true
								break
							}
						}
						if !bare {
							return "", false
						}
					} else {
						isSpecial = true
						start = colon + 1
						for start < len(url) && (url[start] == '/' || url[start] == '\\') {
							start++
						}
					}
				}
			}
		}
	}
	identifier, closingBracket, port, firstColon := -1, -1, -1, -1
	for i := start; i < end; i++ {
		c := url[i]
		switch {
		case c == '/' || c == '#' || c == '?':
			end = i
		case c == ':':
			if firstColon == -1 {
				firstColon = i
			}
			port = i
			continue
		case isSpecial && c == '\\':
			end = i
		case c == '@':
			identifier = i
			firstColon = -1
			continue
		case c == ']':
			closingBracket = i
			continue
		default:
			continue
		}
		break
	}
	if identifier != -1 && identifier >= start && identifier < end {
		start = identifier + 1
	}
	if start < len(url) && url[start] == '[' {
		if closingBracket != -1 {
			return strings.ToLower(url[start+1 : closingBracket]), true
		}
		return "", false
	} else if port != -1 && port > start && port < end && firstColon == port {
		end = port
	}
	if start >= end {
		return "", false
	}
	for end > start+1 && url[end-1] == '.' {
		end--
	}
	return strings.ToLower(url[start:end]), true
}

func isValidASCII(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c > 127
}

// isValidHostname is tldts' is-valid.
func isValidHostname(h string) bool {
	if len(h) > 255 || len(h) == 0 {
		return false
	}
	if !isValidASCII(h[0]) && h[0] != '.' && h[0] != '_' {
		return false
	}
	lastDot, last := -1, -1
	for i := 0; i < len(h); i++ {
		c := int(h[i])
		if c == '.' {
			if i-lastDot > 64 || last == '.' || last == '-' {
				return false
			}
			lastDot = i
		} else if !(isValidASCII(h[i]) || c == '-' || c == '_') || (c == '-' && last == '.') {
			return false
		}
		last = c
	}
	return len(h)-lastDot-1 <= 63 && last != '-'
}

var errNotJSONSerializable = errors.New("SSO provider configuration must be JSON-serializable")
