package cimd

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// WHATWG URL helpers and host classification copied from plugins/oauthprovider/urlutil.go
// (core/utils/url.ts, core/utils/host.ts, core/utils/ip.ts, core/utils/redirect-uri.ts).

var schemePrefixRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):`)

var specialSchemes = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21"}

// parseURL parses an absolute URL approximately like `new URL(raw)`.
func parseURL(raw string) (*url.URL, error) {
	s := strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' })
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return nil, errors.New("Invalid URL")
	}
	// WHATWG special schemes treat "\\" as "/" and ignore any number of slashes before the
	// authority ("https:example.com", "https:///example.com" parse as https://example.com/).
	if m := schemePrefixRe.FindStringSubmatch(s); m != nil {
		if _, special := specialSchemes[strings.ToLower(m[1])]; special && strings.ToLower(m[1]) != "file" {
			rest := strings.ReplaceAll(s[len(m[0]):], `\`, "/")
			s = m[1] + "://" + strings.TrimLeft(rest, "/")
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		// WHATWG accepts some inputs Go rejects (e.g. spaces); retry with escaping.
		u, err = url.Parse(strings.ReplaceAll(s, " ", "%20"))
		if err != nil {
			return nil, errors.New("Invalid URL")
		}
	}
	if u.Scheme == "" {
		return nil, errors.New("Invalid URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if def, special := specialSchemes[u.Scheme]; special {
		if u.Host == "" {
			if u.Opaque != "" {
				return parseURL(u.Scheme + "://" + strings.TrimLeft(u.Opaque, "/"))
			}
			return nil, errors.New("Invalid URL")
		}
		u.Host = strings.ToLower(u.Host)
		if !strings.HasPrefix(u.Host, "[") {
			// WHATWG IPv4 host parsing (e.g. 127.1 -> 127.0.0.1).
			hn, port := u.Host, ""
			if i := strings.LastIndex(hn, ":"); i >= 0 {
				hn, port = hn[:i], hn[i:]
			}
			if v4, isNum, ok := whatwgIPv4(hn); isNum {
				if !ok {
					return nil, errors.New("Invalid URL")
				}
				u.Host = v4 + port
			}
		}
		if strings.HasSuffix(u.Host, ":") || u.Port() == def {
			h := strings.TrimSuffix(u.Hostname(), ":")
			if strings.Contains(h, ":") {
				h = "[" + h + "]"
			}
			u.Host = h
		}
		if p := u.Port(); p != "" {
			if _, err := strconv.Atoi(p); err != nil {
				return nil, errors.New("Invalid URL")
			}
			if n, _ := strconv.Atoi(p); n > 65535 {
				return nil, errors.New("Invalid URL")
			}
			if n, _ := strconv.Atoi(p); strconv.Itoa(n) != p {
				u.Host = u.Hostname() + ":" + strconv.Itoa(n)
			}
		}
		if u.Path == "" {
			u.Path = "/"
		}
	}
	return u, nil
}

// canParseURL is URL.canParse.
func canParseURL(raw string) bool {
	_, err := parseURL(raw)
	return err == nil
}

// urlOrigin is new URL(raw).origin ("null" for opaque origins, "" when unparsable).
func urlOrigin(raw string) string {
	u, err := parseURL(raw)
	if err != nil {
		return ""
	}
	return originOf(u)
}

func originOf(u *url.URL) string {
	if _, special := specialSchemes[u.Scheme]; !special || u.Scheme == "file" {
		return "null"
	}
	return u.Scheme + "://" + u.Host
}

func hrefOf(u *url.URL) string { return u.String() }

// ---- host classification (core/utils/host.ts) ----

var (
	ipv4Re = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$`)
	ipv6Re = regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$`)
)

func isIPv4(ip string) bool { return ipv4Re.MatchString(ip) }

func isIPv6(ip string) bool {
	if ipv6Re.MatchString(ip) {
		return true
	}
	if i := strings.LastIndex(ip, ":"); i >= 0 && isIPv4(ip[i+1:]) {
		return ipv6Re.MatchString(ip[:i+1] + "0:0")
	}
	return false
}

func isValidIP(ip string) bool { return isIPv4(ip) || isIPv6(ip) }

func expandIPv6(ip string) []string {
	// embedded IPv4 tail
	if i := strings.LastIndex(ip, ":"); i >= 0 && isIPv4(ip[i+1:]) {
		parts := strings.Split(ip[i+1:], ".")
		n := func(s string) int { v, _ := strconv.Atoi(s); return v }
		ip = ip[:i+1] + fmt.Sprintf("%x:%x", n(parts[0])<<8|n(parts[1]), n(parts[2])<<8|n(parts[3]))
	}
	pad := func(gs []string) []string {
		out := make([]string, len(gs))
		for i, g := range gs {
			out[i] = strings.Repeat("0", max(0, 4-len(g))) + strings.ToLower(g)
		}
		return out
	}
	if strings.Contains(ip, "::") {
		sides := strings.SplitN(ip, "::", 2)
		var left, right []string
		if sides[0] != "" {
			left = strings.Split(sides[0], ":")
		}
		if sides[1] != "" {
			right = strings.Split(sides[1], ":")
		}
		missing := 8 - len(left) - len(right)
		out := pad(left)
		for i := 0; i < missing; i++ {
			out = append(out, "0000")
		}
		return append(out, pad(right)...)
	}
	return pad(strings.Split(ip, ":"))
}

func extractMappedIPv4(groups []string) string {
	if len(groups) == 8 && groups[0] == "0000" && groups[1] == "0000" && groups[2] == "0000" &&
		groups[3] == "0000" && groups[4] == "0000" && groups[5] == "ffff" {
		b := func(s string) int64 { n, _ := strconv.ParseInt(s, 16, 64); return n }
		return fmt.Sprintf("%d.%d.%d.%d", b(groups[6][0:2]), b(groups[6][2:4]), b(groups[7][0:2]), b(groups[7][2:4]))
	}
	return ""
}

func ipv4ToUint32(ip string) uint32 {
	var out uint32
	for _, p := range strings.Split(ip, ".") {
		n, _ := strconv.Atoi(p)
		out = out<<8 | uint32(n)
	}
	return out
}

func inIPv4Range(v uint32, prefix string, length uint) bool {
	if length == 0 {
		return true
	}
	mask := ^uint32(0) << (32 - length)
	return v&mask == ipv4ToUint32(prefix)&mask
}

func classifyIPv4(ip string) string {
	if ip == "0.0.0.0" {
		return "unspecified"
	}
	if ip == "255.255.255.255" {
		return "broadcast"
	}
	n := ipv4ToUint32(ip)
	switch {
	case inIPv4Range(n, "127.0.0.0", 8):
		return "loopback"
	case inIPv4Range(n, "10.0.0.0", 8), inIPv4Range(n, "172.16.0.0", 12), inIPv4Range(n, "192.168.0.0", 16):
		return "private"
	case inIPv4Range(n, "169.254.0.0", 16):
		return "linkLocal"
	case inIPv4Range(n, "100.64.0.0", 10):
		return "sharedAddressSpace"
	case inIPv4Range(n, "192.0.2.0", 24), inIPv4Range(n, "198.51.100.0", 24), inIPv4Range(n, "203.0.113.0", 24):
		return "documentation"
	case inIPv4Range(n, "198.18.0.0", 15):
		return "benchmarking"
	case inIPv4Range(n, "224.0.0.0", 4):
		return "multicast"
	case inIPv4Range(n, "0.0.0.0", 8), inIPv4Range(n, "192.0.0.0", 24), inIPv4Range(n, "192.88.99.0", 24), inIPv4Range(n, "240.0.0.0", 4):
		return "reserved"
	}
	return "public"
}

func embeddedIPv4(expanded string, startGroup int, xor bool) string {
	off := startGroup * 5
	if len(expanded) < off+9 {
		return ""
	}
	g1, err1 := strconv.ParseUint(expanded[off:off+4], 16, 32)
	g2, err2 := strconv.ParseUint(expanded[off+5:off+9], 16, 32)
	if err1 != nil || err2 != nil {
		return ""
	}
	c := uint32(g1<<16 | g2)
	if xor {
		c ^= 0xffffffff
	}
	return fmt.Sprintf("%d.%d.%d.%d", c>>24&0xff, c>>16&0xff, c>>8&0xff, c&0xff)
}

func classifyIPv6(expanded string) string {
	switch expanded {
	case "0000:0000:0000:0000:0000:0000:0000:0000":
		return "unspecified"
	case "0000:0000:0000:0000:0000:0000:0000:0001":
		return "loopback"
	}
	first, _ := strconv.ParseUint(expanded[0:2], 16, 8)
	second, _ := strconv.ParseUint(expanded[2:4], 16, 8)
	switch {
	case first == 0xff:
		return "multicast"
	case first == 0xfe && second&0xc0 == 0x80:
		return "linkLocal"
	case first == 0xfe && second&0xc0 == 0xc0:
		return "reserved"
	case first&0xfe == 0xfc:
		return "private"
	case strings.HasPrefix(expanded, "2001:0db8:"):
		return "documentation"
	case strings.HasPrefix(expanded, "2001:0002:0000:"):
		return "benchmarking"
	case strings.HasPrefix(expanded, "2002:"):
		if e := embeddedIPv4(expanded, 1, false); e != "" && classifyIPv4(e) != "public" {
			return "reserved"
		}
		return "public"
	case strings.HasPrefix(expanded, "0064:ff9b:0000:0000:0000:0000:"):
		return "reserved"
	case strings.HasPrefix(expanded, "0064:ff9b:0001:"):
		return "reserved"
	case strings.HasPrefix(expanded, "2001:0000:"):
		return "reserved"
	case strings.HasPrefix(expanded, "0100:0000:0000:0000:"):
		return "reserved"
	case strings.HasPrefix(expanded, "3fff:0"):
		return "documentation"
	case strings.HasPrefix(expanded, "5f00:"):
		return "reserved"
	case strings.HasPrefix(expanded, "0000:0000:0000:0000:0000:0000:"):
		return "reserved"
	}
	return "public"
}

var cloudMetadataHosts = map[string]bool{"metadata.google.internal": true, "metadata.goog": true,
	"metadata": true, "instance-data": true, "instance-data.ec2.internal": true}

// classifyHost mirrors core/utils/host.ts classifyHost (returns the kind).
func classifyHost(host string) string {
	h := strings.TrimSpace(host)
	// stripPort
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end != -1 {
			h = h[:end+1]
		}
	} else if first := strings.Index(h, ":"); first != -1 && strings.Index(h[first+1:], ":") == -1 {
		h = h[:first]
	}
	// stripBrackets
	if len(h) >= 2 && strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if z := strings.Index(h, "%"); z != -1 {
		h = h[:z]
	}
	h = strings.TrimRight(h, ".")
	lowered := strings.ToLower(h)
	if lowered == "" {
		return "reserved"
	}
	if !isValidIP(lowered) {
		if lowered == "localhost" || strings.HasSuffix(lowered, ".localhost") {
			return "localhost"
		}
		if cloudMetadataHosts[lowered] {
			return "cloudMetadata"
		}
		return "public"
	}
	if isIPv4(lowered) {
		return classifyIPv4(lowered)
	}
	groups := expandIPv6(lowered)
	if v4 := extractMappedIPv4(groups); v4 != "" {
		return classifyIPv4(v4)
	}
	return classifyIPv6(strings.Join(groups, ":"))
}

func isLoopbackIP(host string) bool { return classifyHost(host) == "loopback" }

func isLoopbackHost(host string) bool {
	k := classifyHost(host)
	return k == "loopback" || k == "localhost"
}

func isPublicRoutableHost(host string) bool { return classifyHost(host) == "public" }

// isPrivateHostname is !isPublicRoutableHost (utils/client-assertion.ts).
func isPrivateHostname(hostname string) bool { return !isPublicRoutableHost(hostname) }

var reverseDomainScheme = regexp.MustCompile(`(?i)^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

// isReverseDomainPrivateUseRedirectURI mirrors core/utils/redirect-uri.ts.
func isReverseDomainPrivateUseRedirectURI(raw string, u *url.URL) bool {
	scheme := u.Scheme
	if scheme == "http" || scheme == "https" || u.Host != "" {
		return false
	}
	i := strings.Index(raw, ":")
	if i < 0 {
		return false
	}
	ssp := raw[i+1:]
	return strings.HasPrefix(ssp, "/") && !strings.HasPrefix(ssp, "//") && reverseDomainScheme.MatchString(scheme)
}

// urlUserinfo reports whether u has a username or password.
func urlHasCredentials(u *url.URL) bool {
	return u.User != nil && (u.User.Username() != "" || func() bool { p, ok := u.User.Password(); return ok && p != "" }())
}

// whatwgIPv4 implements the WHATWG "ends in a number" check and IPv4 parser. isNum
// reports whether host must be parsed as IPv4; ok is false on an IPv4 parse failure.
func whatwgIPv4(host string) (v4 string, isNum, ok bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last == "" {
		return "", false, false
	}
	allDigits := strings.Trim(last, "0123456789") == ""
	if !allDigits {
		if _, okNum := whatwgIPv4Number(last); !okNum {
			return "", false, false
		}
	}
	if len(parts) > 4 {
		return "", true, false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, okNum := whatwgIPv4Number(p)
		if !okNum {
			return "", true, false
		}
		nums[i] = n
	}
	for _, n := range nums[:len(nums)-1] {
		if n > 255 {
			return "", true, false
		}
	}
	lastN := nums[len(nums)-1]
	if lastN >= uint64(1)<<(8*(5-len(nums))) {
		return "", true, false
	}
	ipv4 := lastN
	for i, n := range nums[:len(nums)-1] {
		ipv4 += n << (8 * (3 - i))
	}
	return fmt.Sprintf("%d.%d.%d.%d", ipv4>>24&255, ipv4>>16&255, ipv4>>8&255, ipv4&255), true, true
}

func whatwgIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s, base = s[2:], 16
	} else if len(s) >= 2 && s[0] == '0' {
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
