package betterauth

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// CookieOptions are Set-Cookie attributes (better-call CookieOptions).
type CookieOptions struct {
	// MaxAge in seconds; nil omits the attribute (a session cookie).
	MaxAge      *int
	Expires     *time.Time
	Domain      string
	Path        string
	Secure      bool
	HTTPOnly    bool
	SameSite    string // "lax", "strict", "none"
	Partitioned bool
	// Prefix is "secure" or "host" to add __Secure- / __Host-.
	Prefix string
}

// Int returns a pointer to n.
func Int(n int) *int { return &n }

// merge returns o with the non-zero fields of over applied (object spread of attributes).
// MaxAgeSet/explicit nil overrides are handled by callers.
func (o CookieOptions) merge(over *CookieOptions) CookieOptions {
	if over == nil {
		return o
	}
	if over.MaxAge != nil {
		o.MaxAge = over.MaxAge
	}
	if over.Expires != nil {
		o.Expires = over.Expires
	}
	if over.Domain != "" {
		o.Domain = over.Domain
	}
	if over.Path != "" {
		o.Path = over.Path
	}
	if over.Secure {
		o.Secure = true
	}
	if over.HTTPOnly {
		o.HTTPOnly = true
	}
	if over.SameSite != "" {
		o.SameSite = over.SameSite
	}
	if over.Partitioned {
		o.Partitioned = true
	}
	if over.Prefix != "" {
		o.Prefix = over.Prefix
	}
	return o
}

// EncodeURIComponent implements JavaScript's encodeURIComponent.
func EncodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// DecodeURIComponent implements JavaScript's decodeURIComponent, returning an error for
// malformed input.
func DecodeURIComponent(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errors.New("URIError: URI malformed")
		}
		var v byte
		for _, c := range []byte{s[i+1], s[i+2]} {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			default:
				return "", errors.New("URIError: URI malformed")
			}
		}
		out = append(out, v)
		i += 2
	}
	if !utf8.Valid(out) {
		return "", errors.New("URIError: URI malformed")
	}
	return string(out), nil
}

func tryDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	d, err := DecodeURIComponent(s)
	if err != nil {
		return s
	}
	return d
}

const maxCookieAgeSeconds = 34560000

// serializeRaw is better-call's _serialize: value must already be encoded.
func serializeRaw(key, value string, opt CookieOptions) (string, error) {
	var cookie string
	switch opt.Prefix {
	case "secure":
		cookie = "__Secure-" + key + "=" + value
	case "host":
		cookie = "__Host-" + key + "=" + value
	default:
		cookie = key + "=" + value
	}
	if strings.HasPrefix(key, "__Secure-") {
		opt.Secure = true
	}
	if strings.HasPrefix(key, "__Host-") {
		opt.Secure = true
		opt.Path = "/"
		opt.Domain = ""
	}
	if opt.MaxAge != nil && *opt.MaxAge >= 0 {
		if *opt.MaxAge > maxCookieAgeSeconds {
			return "", errors.New("Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration.")
		}
		cookie += fmt.Sprintf("; Max-Age=%d", *opt.MaxAge)
	}
	if opt.Domain != "" && opt.Prefix != "host" {
		cookie += "; Domain=" + opt.Domain
	}
	if opt.Path != "" {
		cookie += "; Path=" + opt.Path
	}
	if opt.Expires != nil {
		if time.Until(*opt.Expires) > maxCookieAgeSeconds*time.Millisecond*1000 {
			return "", errors.New("Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future.")
		}
		cookie += "; Expires=" + opt.Expires.UTC().Format(http.TimeFormat)
	}
	if opt.HTTPOnly {
		cookie += "; HttpOnly"
	}
	if opt.Secure {
		cookie += "; Secure"
	}
	if opt.SameSite != "" {
		cookie += "; SameSite=" + strings.ToUpper(opt.SameSite[:1]) + opt.SameSite[1:]
	}
	if opt.Partitioned {
		cookie += "; Partitioned"
	}
	return cookie, nil
}

// SerializeCookie builds a Set-Cookie header value (value is URL-encoded).
func SerializeCookie(key, value string, opt CookieOptions) (string, error) {
	return serializeRaw(key, EncodeURIComponent(value), opt)
}

// SerializeSignedCookie builds a signed Set-Cookie value: encodeURIComponent(value + "." + sig).
func SerializeSignedCookie(key, value, secret string, opt CookieOptions) (string, error) {
	signed := value + "." + bacrypto.MakeSignature(value, secret)
	return serializeRaw(key, EncodeURIComponent(signed), opt)
}

// parseRequestCookies is better-call's parseCookies (first occurrence of a name wins,
// surrounding quotes removed, values URI-decoded).
func parseRequestCookies(str string) map[string]string {
	cookies := map[string]string{}
	index := 0
	for index < len(str) {
		eq := strings.Index(str[index:], "=")
		if eq == -1 {
			break
		}
		eqIdx := index + eq
		endIdx := strings.Index(str[index:], ";")
		if endIdx == -1 {
			endIdx = len(str)
		} else {
			endIdx += index
			if endIdx < eqIdx {
				index = strings.LastIndex(str[:eqIdx], ";") + 1
				continue
			}
		}
		key := strings.TrimSpace(str[index:eqIdx])
		if _, exists := cookies[key]; !exists {
			val := strings.TrimSpace(str[eqIdx+1 : endIdx])
			if len(val) > 0 && val[0] == '"' {
				if len(val) >= 2 {
					val = val[1 : len(val)-1]
				} else {
					val = ""
				}
			}
			cookies[key] = tryDecode(val)
		}
		index = endIdx + 1
	}
	return cookies
}

var (
	cookieNameRegex  = regexp.MustCompile(`^[\x21\x23-\x27\x2A\x2B\x2D\x2E\x30-\x39\x41-\x5A\x5E\x5F\x60\x61-\x7A\x7C\x7E]+$`)
	cookieValueRegex = regexp.MustCompile(`^[\x20\x21\x23-\x3A\x3C-\x5B\x5D-\x7E]*$`)
)

type orderedCookie struct{ name, value string }

// parseCookieList is better-auth's cookie-utils parseCookies (strict name/value checks,
// last occurrence wins, iteration in first-seen order).
func parseCookieList(cookie string) []orderedCookie {
	var out []orderedCookie
	if len(cookie) < 2 {
		return out
	}
	idx := map[string]int{}
	for _, chunk := range strings.Split(cookie, ";") {
		eq := strings.Index(chunk, "=")
		if eq == -1 {
			continue
		}
		key := strings.Trim(chunk[:eq], " \t")
		val := strings.Trim(chunk[eq+1:], " \t")
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		if cookieNameRegex.MatchString(key) && cookieValueRegex.MatchString(val) {
			if i, ok := idx[key]; ok {
				out[i].value = tryDecode(val)
			} else {
				idx[key] = len(out)
				out = append(out, orderedCookie{key, tryDecode(val)})
			}
		}
	}
	return out
}

// ParseSetCookie parses a Set-Cookie header into name, value and attributes.
func ParseSetCookie(header string) (name, value string, attrs map[string]string) {
	parts := strings.Split(header, ";")
	nv := strings.TrimSpace(parts[0])
	i := strings.Index(nv, "=")
	if i < 0 {
		return nv, "", nil
	}
	name = nv[:i]
	value = tryDecode(strings.Trim(nv[i+1:], `"`))
	attrs = map[string]string{}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		k, v, _ := strings.Cut(p, "=")
		attrs[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return name, value, attrs
}

func floorInt(f float64) int { return int(math.Floor(f)) }
