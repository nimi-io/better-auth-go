package betterauth

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	ipv4Re = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$`)
	ipv6Re = regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$`)
)

func isIPv4(ip string) bool { return ipv4Re.MatchString(ip) }

// isIPv6 uses zod's ipv6 regex, plus the embedded-IPv4 form zod also accepts.
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
	pad := func(gs []string) []string {
		out := make([]string, len(gs))
		for i, g := range gs {
			out[i] = fmt.Sprintf("%04s", g)
			out[i] = strings.ReplaceAll(out[i], " ", "0")
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
		zeros := make([]string, 0, missing)
		for i := 0; i < missing; i++ {
			zeros = append(zeros, "0000")
		}
		out := append(pad(left), zeros...)
		return append(out, pad(right)...)
	}
	return pad(strings.Split(ip, ":"))
}

func extractIPv4FromMapped(ip string) string {
	lower := strings.ToLower(ip)
	if strings.HasPrefix(lower, "::ffff:") {
		if p := lower[7:]; isIPv4(p) {
			return p
		}
	}
	parts := strings.Split(ip, ":")
	if len(parts) == 7 && strings.ToLower(parts[5]) == "ffff" && isIPv4(parts[6]) {
		return parts[6]
	}
	if strings.Contains(lower, "::ffff:") || strings.Contains(lower, ":ffff:") {
		g := expandIPv6(ip)
		if len(g) == 8 && g[0] == "0000" && g[1] == "0000" && g[2] == "0000" && g[3] == "0000" &&
			g[4] == "0000" && g[5] == "ffff" && g[6] != "" && g[7] != "" && len(g[6]) >= 4 && len(g[7]) >= 4 {
			b := func(s string) int64 { n, _ := strconv.ParseInt(s, 16, 64); return n }
			return fmt.Sprintf("%d.%d.%d.%d", b(g[6][0:2]), b(g[6][2:4]), b(g[7][0:2]), b(g[7][2:4]))
		}
	}
	return ""
}

func normalizeIPv6(ip string, prefix int) string {
	groups := expandIPv6(ip)
	if prefix < 128 {
		if prefix < 0 {
			prefix = 0
		}
		bits := prefix
		for i, g := range groups {
			switch {
			case bits <= 0:
				groups[i] = "0000"
			case bits >= 16:
				bits -= 16
			default:
				v, _ := strconv.ParseInt(g, 16, 64)
				mask := (0xffff << (16 - bits)) & 0xffff
				groups[i] = fmt.Sprintf("%04x", int(v)&mask)
				bits = 0
			}
		}
	}
	return strings.ToLower(strings.Join(groups, ":"))
}

// explicitZeroSubnet distinguishes a configured /0 from "unset" (0) internally.
const explicitZeroSubnet = -1

// normalizeIP mirrors core/utils/ip.ts normalizeIP (IPv6 masked to /64 by default).
func normalizeIP(ip string, ipv6Subnet int) string {
	if isIPv4(ip) || !isIPv6(ip) {
		return strings.ToLower(ip)
	}
	if v4 := extractIPv4FromMapped(ip); v4 != "" {
		return strings.ToLower(v4)
	}
	switch {
	case ipv6Subnet == 0:
		ipv6Subnet = 64 // unset
	case ipv6Subnet == explicitZeroSubnet:
		ipv6Subnet = 0
	}
	return normalizeIPv6(ip, ipv6Subnet)
}

func ipToBytes(ip string) []byte {
	if isIPv4(ip) {
		out := make([]byte, 4)
		for i, p := range strings.Split(ip, ".") {
			n, _ := strconv.Atoi(p)
			out[i] = byte(n)
		}
		return out
	}
	if !isIPv6(ip) {
		return nil
	}
	if m := extractIPv4FromMapped(ip); m != "" {
		return ipToBytes(m)
	}
	g := expandIPv6(ip)
	out := make([]byte, 16)
	for i := 0; i < 8 && i < len(g); i++ {
		v, _ := strconv.ParseInt(g[i], 16, 64)
		out[i*2] = byte(v >> 8)
		out[i*2+1] = byte(v)
	}
	return out
}

type cidr struct {
	bytes  []byte
	prefix int
}

var digitsRe = regexp.MustCompile(`^\d+$`)

func parseCIDR(v string) *cidr {
	slash := strings.LastIndex(v, "/")
	addr := v
	if slash != -1 {
		addr = v[:slash]
	}
	b := ipToBytes(addr)
	if b == nil {
		return nil
	}
	maxBits := len(b) * 8
	if slash == -1 {
		return &cidr{b, maxBits}
	}
	p := v[slash+1:]
	if !digitsRe.MatchString(p) {
		return nil
	}
	n, _ := strconv.Atoi(p)
	if n > maxBits {
		return nil
	}
	return &cidr{b, n}
}

func matchesCIDR(ip []byte, n *cidr) bool {
	if len(ip) != len(n.bytes) {
		return false
	}
	bits := n.prefix
	for i := 0; i < len(ip) && bits > 0; i++ {
		take := 8
		if bits < 8 {
			take = bits
		}
		mask := byte(0xff << (8 - take))
		if ip[i]&mask != n.bytes[i]&mask {
			return false
		}
		bits -= 8
	}
	return true
}

func findInvalidTrustedProxies(entries []string) []string {
	var out []string
	for _, e := range entries {
		if parseCIDR(e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func getIPFromHeader(value string, ipv6Subnet int, trustedProxies []string) string {
	var ips []string
	for _, p := range strings.Split(value, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ips = append(ips, p)
		}
	}
	if len(ips) == 0 {
		return ""
	}
	var proxies []*cidr
	for _, t := range trustedProxies {
		if c := parseCIDR(t); c != nil {
			proxies = append(proxies, c)
		}
	}
	if len(proxies) > 0 {
		for i := len(ips) - 1; i >= 0; i-- {
			b := ipToBytes(ips[i])
			if b == nil {
				return ""
			}
			trusted := false
			for _, p := range proxies {
				if matchesCIDR(b, p) {
					trusted = true
					break
				}
			}
			if trusted {
				continue
			}
			return normalizeIP(ips[i], ipv6Subnet)
		}
		return ""
	}
	if len(ips) != 1 || !isValidIP(ips[0]) {
		return ""
	}
	return normalizeIP(ips[0], ipv6Subnet)
}

// isTestOrDev reports NODE_ENV/GO_ENV test or development, or TEST set.
func isTestOrDev() bool {
	env := nodeEnv()
	if env == "test" || env == "dev" || env == "development" {
		return true
	}
	t := os.Getenv("TEST")
	return t != "" && t != "false"
}

func nodeEnv() string {
	if v := os.Getenv("NODE_ENV"); v != "" {
		return v
	}
	return os.Getenv("GO_ENV")
}

func isProduction() bool { return nodeEnv() == "production" }

func isTestEnv() bool {
	if nodeEnv() == "test" {
		return true
	}
	t := os.Getenv("TEST")
	return t != "" && t != "false"
}

// GetIP extracts the client IP like core/utils/ip.ts getIP ("" when unknown).
func GetIP(headers http.Header, cfg *Config) string {
	var ipCfg *IPAddressConfig
	if cfg.Advanced != nil {
		ipCfg = cfg.Advanced.IPAddress
	}
	if ipCfg != nil && ipCfg.DisableIPTracking {
		return ""
	}
	hdrs := []string{"x-forwarded-for"}
	subnet := 0
	var proxies []string
	if ipCfg != nil {
		if len(ipCfg.IPAddressHeaders) > 0 {
			hdrs = ipCfg.IPAddressHeaders
		}
		if ipCfg.IPv6Subnet != nil {
			subnet = *ipCfg.IPv6Subnet
			if subnet == 0 {
				subnet = explicitZeroSubnet
			}
		}
		proxies = ipCfg.TrustedProxies
	}
	if headers != nil {
		for _, h := range hdrs {
			if v := headers.Get(h); v != "" {
				if ip := getIPFromHeader(v, subnet, proxies); ip != "" {
					return ip
				}
			}
		}
	}
	if isTestOrDev() {
		return "127.0.0.1"
	}
	return ""
}
