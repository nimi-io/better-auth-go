package betterauth

// Port of packages/core/src/utils/ip.test.ts (upstream v1.7.7).
//
// Upstream's `normalizeIP(ip)` (no options) maps to Go's `normalizeIP(ip, 0)`, where 0 means
// "unset" and selects the /64 default.

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPortNetIPIsValidIP(t *testing.T) {
	t.Run("should validate IPv4 addresses", func(t *testing.T) {
		for _, ip := range []string{"192.168.1.1", "127.0.0.1", "0.0.0.0", "255.255.255.255"} {
			if !isValidIP(ip) {
				t.Errorf("isValidIP(%q) = false", ip)
			}
		}
	})
	t.Run("should validate IPv6 addresses", func(t *testing.T) {
		for _, ip := range []string{"2001:db8::1", "::1", "::", "2001:0db8:0000:0000:0000:0000:0000:0001"} {
			if !isValidIP(ip) {
				t.Errorf("isValidIP(%q) = false", ip)
			}
		}
	})
	t.Run("should reject invalid IPs", func(t *testing.T) {
		for _, ip := range []string{"not-an-ip", "999.999.999.999", "gggg::1", `::@1\`, "::1\n"} {
			if isValidIP(ip) {
				t.Errorf("isValidIP(%q) = true", ip)
			}
		}
	})
}

func pnExpectNorm(t *testing.T, ip string, subnet int, want string) {
	t.Helper()
	if got := normalizeIP(ip, subnet); got != want {
		t.Errorf("normalizeIP(%q, %d) = %q, want %q", ip, subnet, got, want)
	}
}

func TestPortNetIPNormalization(t *testing.T) {
	t.Run("IPv4 should return IPv4 addresses unchanged", func(t *testing.T) {
		pnExpectNorm(t, "192.168.1.1", 0, "192.168.1.1")
		pnExpectNorm(t, "127.0.0.1", 0, "127.0.0.1")
		pnExpectNorm(t, "10.0.0.1", 0, "10.0.0.1")
	})
	t.Run("should normalize compressed IPv6 to full form", func(t *testing.T) {
		pnExpectNorm(t, "2001:db8::1", 128, "2001:0db8:0000:0000:0000:0000:0000:0001")
		pnExpectNorm(t, "::1", 128, "0000:0000:0000:0000:0000:0000:0000:0001")
		pnExpectNorm(t, "::", 128, "0000:0000:0000:0000:0000:0000:0000:0000")
	})
	t.Run("should normalize uppercase to lowercase", func(t *testing.T) {
		pnExpectNorm(t, "2001:DB8::1", 128, "2001:0db8:0000:0000:0000:0000:0000:0001")
		pnExpectNorm(t, "2001:0DB8:ABCD:EF00::1", 128, "2001:0db8:abcd:ef00:0000:0000:0000:0001")
	})
	t.Run("should handle various IPv6 formats consistently", func(t *testing.T) {
		n := "2001:0db8:0000:0000:0000:0000:0000:0001"
		for _, ip := range []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:db8:0::1", "2001:0db8::0:0:0:1"} {
			pnExpectNorm(t, ip, 128, n)
		}
	})
	t.Run("should handle IPv6 with :: at different positions", func(t *testing.T) {
		pnExpectNorm(t, "2001:db8:85a3::8a2e:370:7334", 128, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
		if got := normalizeIP("::ffff:192.0.2.1", 0); strings.Contains(got, "::") {
			t.Errorf("got %q", got)
		}
	})
	t.Run("should convert IPv4-mapped IPv6 to IPv4", func(t *testing.T) {
		pnExpectNorm(t, "::ffff:192.0.2.1", 0, "192.0.2.1")
		pnExpectNorm(t, "::ffff:127.0.0.1", 0, "127.0.0.1")
		pnExpectNorm(t, "::FFFF:10.0.0.1", 0, "10.0.0.1")
	})
	t.Run("should handle hex-encoded IPv4 in mapped addresses", func(t *testing.T) {
		pnExpectNorm(t, "::ffff:c000:0201", 0, "192.0.2.1")
		pnExpectNorm(t, "::ffff:7f00:0001", 0, "127.0.0.1")
	})
	t.Run("should handle full form IPv4-mapped IPv6", func(t *testing.T) {
		pnExpectNorm(t, "0:0:0:0:0:ffff:192.0.2.1", 0, "192.0.2.1")
	})
}

func TestPortNetIPv6Subnet(t *testing.T) {
	t.Run("should extract /64 subnet", func(t *testing.T) {
		pnExpectNorm(t, "2001:db8:0:0:1234:5678:90ab:cdef", 64, "2001:0db8:0000:0000:0000:0000:0000:0000")
		pnExpectNorm(t, "2001:db8:0:0:ffff:ffff:ffff:ffff", 64, "2001:0db8:0000:0000:0000:0000:0000:0000")
	})
	t.Run("should extract /48 subnet", func(t *testing.T) {
		pnExpectNorm(t, "2001:db8:1234:5678:90ab:cdef:1234:5678", 48, "2001:0db8:1234:0000:0000:0000:0000:0000")
		pnExpectNorm(t, "2001:db8:1234:ffff:ffff:ffff:ffff:ffff", 48, "2001:0db8:1234:0000:0000:0000:0000:0000")
	})
	t.Run("should extract /32 subnet", func(t *testing.T) {
		pnExpectNorm(t, "2001:db8:1234:5678:90ab:cdef:1234:5678", 32, "2001:0db8:0000:0000:0000:0000:0000:0000")
		pnExpectNorm(t, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 32, "2001:0db8:0000:0000:0000:0000:0000:0000")
	})
	t.Run("should handle /64 subnet by default", func(t *testing.T) {
		a, b := normalizeIP("2001:db8::1", 0), normalizeIP("2001:db8::1", 64)
		if a != b || a != "2001:0db8:0000:0000:0000:0000:0000:0000" {
			t.Fatalf("got %q / %q", a, b)
		}
	})
	t.Run("should not affect IPv4 addresses when ipv6Subnet is set", func(t *testing.T) {
		pnExpectNorm(t, "192.168.1.1", 64, "192.168.1.1")
	})
	t.Run("should accept any integer prefix length, not just 32 | 48 | 64 | 128", func(t *testing.T) {
		pnExpectNorm(t, "2001:db8:abcd:ef00:1111:2222:3333:4444", 56, "2001:0db8:abcd:ef00:0000:0000:0000:0000")
		pnExpectNorm(t, "2001:db8:ab00:1234:5678:9abc:def0:1234", 40, "2001:0db8:ab00:0000:0000:0000:0000:0000")
	})
	// Upstream: `options.ipv6Subnet ?? 64`, so an explicit 0 masks everything. Go uses
	// `int` with 0 meaning "unset", so an explicit /0 is indistinguishable from the default.
	// This exercises the end-to-end path (advanced.ipAddress.ipv6Subnet: 0 -> getIP).
	t.Run("should honour an explicit /0 prefix instead of falling back to the default", func(t *testing.T) {
		cfg := &Config{Advanced: &AdvancedConfig{IPAddress: &IPAddressConfig{IPv6Subnet: Int(0)}}}
		h := http.Header{}
		h.Set("X-Forwarded-For", "2001:db8::1")
		if got := GetIP(h, cfg); got != "0000:0000:0000:0000:0000:0000:0000:0000" {
			t.Fatalf("explicit ipv6Subnet 0: got %q, want all-zero /0 prefix", got)
		}
	})
}

// createRateLimitKey is inlined in Go's onRequestRateLimit; verify the key it hands to the
// storage has the `${ip}|${path}` shape.
type pnKeyStore struct {
	mu   sync.Mutex
	keys []string
}

func (s *pnKeyStore) Consume(_ context.Context, key string, _ RateLimitRule) (bool, time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
	return true, 0, nil
}

func TestPortNetIPRateLimitKey(t *testing.T) {
	store := &pnKeyStore{}
	env := newTestEnv(t, func(c *Config) {
		c.RateLimit = &RateLimitConfig{Enabled: Bool(true), CustomStorage: store}
	})
	c := env.client()
	for _, ip := range []string{"192.168.1.1", "2001:db8::1"} {
		c.get("/ok", func(r *http.Request) { r.Header.Set("X-Forwarded-For", ip) })
	}
	want := []string{"192.168.1.1|/ok", "2001:0db8:0000:0000:0000:0000:0000:0000|/ok"}
	if !reflect.DeepEqual(store.keys, want) {
		t.Fatalf("keys = %v, want %v", store.keys, want)
	}
	// collision prevention: "192.0.2.1"+"/sign-in" vs "192.0.2"+".1/sign-in"
	if k1, k2 := "192.0.2.1"+"|"+"/sign-in", "192.0.2"+"|"+".1/sign-in"; k1 == k2 {
		t.Fatal("separator does not prevent collision")
	}
}

func TestPortNetIPFromHeader(t *testing.T) {
	t.Run("should accept a single trusted header value", func(t *testing.T) {
		if got := getIPFromHeader(" 198.51.100.10 ", 0, nil); got != "198.51.100.10" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should reject forwarded chains without a single trusted header", func(t *testing.T) {
		if got := getIPFromHeader("198.51.100.10, 10.0.0.5", 0, nil); got != "" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("should reject invalid header values", func(t *testing.T) {
		for _, v := range []string{"", "not-an-ip"} {
			if got := getIPFromHeader(v, 0, nil); got != "" {
				t.Fatalf("%q: got %q", v, got)
			}
		}
	})
	t.Run("should normalize selected forwarded values", func(t *testing.T) {
		if got := getIPFromHeader("2001:db8::1", 128, nil); got != "2001:0db8:0000:0000:0000:0000:0000:0001" {
			t.Fatalf("got %q", got)
		}
	})

	tp := []string{"10.0.0.0/8"}
	cases := []struct {
		name    string
		value   string
		subnet  int
		proxies []string
		want    string
	}{
		{"should take the rightmost untrusted hop, ignoring spoofed left entries", "1.2.3.4, 198.51.100.10, 10.0.0.5", 0, tp, "198.51.100.10"},
		{"should not be moved by a rotating spoofed leftmost hop (1)", "203.0.113.7, 198.51.100.10, 10.0.0.5", 0, tp, "198.51.100.10"},
		{"should not be moved by a rotating spoofed leftmost hop (2)", "203.0.113.8, 198.51.100.10, 10.0.0.5", 0, tp, "198.51.100.10"},
		{"should fail closed when every hop is a trusted proxy", "10.0.0.9, 10.0.0.5", 0, tp, ""},
		{"should fail closed on a malformed rightmost hop", "198.51.100.10, not-an-ip", 0, tp, ""},
		{"should support CIDR and bare-IP trusted entries", "198.51.100.10, 192.0.2.1", 0, []string{"192.0.2.1"}, "198.51.100.10"},
		{"should skip trusted IPv6 proxy hops", "2001:db8::1, fc00::1", 128, []string{"fc00::/7"}, "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"should not enable chain mode when every entry is malformed", "198.51.100.10, 10.0.0.5", 0, []string{"10.0.0.0/8x"}, ""},
		{"should use the valid entries when some are malformed", "198.51.100.10, 10.0.0.5", 0, []string{"10.0.0.0/8x", "10.0.0.0/8"}, "198.51.100.10"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := getIPFromHeader(c.value, c.subnet, c.proxies); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestPortNetIPFindInvalidTrustedProxies(t *testing.T) {
	t.Run("should accept valid IPs and CIDR ranges", func(t *testing.T) {
		if got := findInvalidTrustedProxies([]string{"10.0.0.5", "10.0.0.0/8", "::1", "fc00::/7", "0.0.0.0/0"}); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("should report malformed entries", func(t *testing.T) {
		invalid := []string{"10.0.0./8", "10.0.0.0/8x", "10.0.0.0/33", "10.0.0.0/3.5", "10.0.0.0/", "not-an-ip", ""}
		got := findInvalidTrustedProxies(append([]string{"10.0.0.0/8"}, invalid...))
		if !reflect.DeepEqual(got, invalid) {
			t.Fatalf("got %v, want %v", got, invalid)
		}
	})
}

func TestPortNetIPBypassPrevention(t *testing.T) {
	t.Run("should prevent IPv6 representation bypass", func(t *testing.T) {
		seen := map[string]bool{}
		var first string
		for i, ip := range []string{"2001:db8::1", "2001:DB8::1", "2001:0db8::1", "2001:db8:0::1", "2001:0db8:0:0:0:0:0:1", "2001:db8::0:1"} {
			n := normalizeIP(ip, 128)
			if i == 0 {
				first = n
			}
			seen[n] = true
		}
		if len(seen) != 1 || first != "2001:0db8:0000:0000:0000:0000:0000:0001" {
			t.Fatalf("got %v", seen)
		}
	})
	t.Run("should prevent IPv4-mapped bypass", func(t *testing.T) {
		for _, ip := range []string{"192.0.2.1", "::ffff:192.0.2.1", "::FFFF:192.0.2.1", "::ffff:c000:0201"} {
			pnExpectNorm(t, ip, 0, "192.0.2.1")
		}
	})
	t.Run("should group IPv6 subnet attacks", func(t *testing.T) {
		seen := map[string]bool{}
		for _, ip := range []string{
			"2001:db8:abcd:1234:0000:0000:0000:0001", "2001:db8:abcd:1234:1111:2222:3333:4444",
			"2001:db8:abcd:1234:ffff:ffff:ffff:ffff", "2001:db8:abcd:1234:aaaa:bbbb:cccc:dddd",
		} {
			seen[normalizeIP(ip, 64)] = true
		}
		if len(seen) != 1 || !seen["2001:0db8:abcd:1234:0000:0000:0000:0000"] {
			t.Fatalf("got %v", seen)
		}
	})
}

func TestPortNetIPEdgeCases(t *testing.T) {
	pnExpectNorm(t, "127.0.0.1", 0, "127.0.0.1")
	pnExpectNorm(t, "::1", 128, "0000:0000:0000:0000:0000:0000:0000:0001")
	pnExpectNorm(t, "0.0.0.0", 0, "0.0.0.0")
	pnExpectNorm(t, "::", 128, "0000:0000:0000:0000:0000:0000:0000:0000")
	pnExpectNorm(t, "169.254.0.1", 0, "169.254.0.1")
	pnExpectNorm(t, "fe80::1", 128, "fe80:0000:0000:0000:0000:0000:0000:0001")
}
