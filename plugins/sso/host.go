package sso

import (
	"net/netip"
	"strings"
)

// Host classification ported from @better-auth/core/utils/host.

var cloudMetadataHosts = map[string]bool{
	"metadata.google.internal":   true,
	"metadata.goog":              true,
	"metadata":                   true,
	"instance-data":              true,
	"instance-data.ec2.internal": true,
}

type hostClassification struct {
	kind    string // loopback, localhost, unspecified, private, linkLocal, ..., public
	literal string // ipv4, ipv6, fqdn
}

func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		if end == -1 {
			return host
		}
		return host[:end+1]
	}
	first := strings.Index(host, ":")
	if first == -1 {
		return host
	}
	if strings.Contains(host[first+1:], ":") {
		return host
	}
	return host[:first]
}

func classifyIPv4(a netip.Addr) string {
	b := a.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	in := func(prefix string, length int) bool {
		p := netip.MustParseAddr(prefix).As4()
		pv := uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
		if length == 0 {
			return true
		}
		mask := uint32(0xffffffff) << (32 - length)
		return n&mask == pv&mask
	}
	switch {
	case n == 0:
		return "unspecified"
	case n == 0xffffffff:
		return "broadcast"
	case in("127.0.0.0", 8):
		return "loopback"
	case in("10.0.0.0", 8), in("172.16.0.0", 12), in("192.168.0.0", 16):
		return "private"
	case in("169.254.0.0", 16):
		return "linkLocal"
	case in("100.64.0.0", 10):
		return "sharedAddressSpace"
	case in("192.0.2.0", 24), in("198.51.100.0", 24), in("203.0.113.0", 24):
		return "documentation"
	case in("198.18.0.0", 15):
		return "benchmarking"
	case in("224.0.0.0", 4):
		return "multicast"
	case in("0.0.0.0", 8), in("192.0.0.0", 24), in("192.88.99.0", 24), in("240.0.0.0", 4):
		return "reserved"
	}
	return "public"
}

func embeddedV4(b [16]byte, start int, xor bool) netip.Addr {
	v := [4]byte{b[start], b[start+1], b[start+2], b[start+3]}
	if xor {
		for i := range v {
			v[i] ^= 0xff
		}
	}
	return netip.AddrFrom4(v)
}

func classifyIPv6(a netip.Addr) string {
	b := a.As16()
	exp := a.StringExpanded()
	switch {
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLoopback():
		return "loopback"
	case b[0] == 0xff:
		return "multicast"
	case b[0] == 0xfe && b[1]&0xc0 == 0x80:
		return "linkLocal"
	case b[0] == 0xfe && b[1]&0xc0 == 0xc0:
		return "reserved"
	case b[0]&0xfe == 0xfc:
		return "private"
	case strings.HasPrefix(exp, "2001:0db8:"):
		return "documentation"
	case strings.HasPrefix(exp, "2001:0002:0000:"):
		return "benchmarking"
	case strings.HasPrefix(exp, "2002:"):
		if classifyIPv4(embeddedV4(b, 2, false)) != "public" {
			return "reserved"
		}
		return "public"
	case strings.HasPrefix(exp, "0064:ff9b:0000:0000:0000:0000:"), strings.HasPrefix(exp, "0064:ff9b:0001:"), strings.HasPrefix(exp, "2001:0000:"),
		strings.HasPrefix(exp, "0100:0000:0000:0000:"), strings.HasPrefix(exp, "5f00:"), strings.HasPrefix(exp, "0000:0000:0000:0000:0000:0000:"):
		return "reserved"
	case strings.HasPrefix(exp, "3fff:0"):
		return "documentation"
	}
	return "public"
}

func classifyHost(host string) hostClassification {
	h := stripPort(strings.TrimSpace(host))
	if len(h) >= 2 && strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if i := strings.Index(h, "%"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimRight(h, ".")
	lowered := strings.ToLower(h)
	if lowered == "" {
		return hostClassification{"reserved", "fqdn"}
	}
	addr, err := netip.ParseAddr(lowered)
	if err != nil {
		if lowered == "localhost" || strings.HasSuffix(lowered, ".localhost") {
			return hostClassification{"localhost", "fqdn"}
		}
		if cloudMetadataHosts[lowered] {
			return hostClassification{"cloudMetadata", "fqdn"}
		}
		return hostClassification{"public", "fqdn"}
	}
	if addr.Is4() {
		return hostClassification{classifyIPv4(addr), "ipv4"}
	}
	if addr.Is4In6() {
		return hostClassification{classifyIPv4(addr.Unmap()), "ipv4"}
	}
	return hostClassification{classifyIPv6(addr), "ipv6"}
}

func isPublicRoutableHost(host string) bool { return classifyHost(host).kind == "public" }
